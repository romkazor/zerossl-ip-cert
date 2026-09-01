/*
 * Copyright [2022] [tinkernels (github.com/tinkernels)]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package zerosslIPCert

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests talk to the live ZeroSSL API and are skipped unless
// ZEROSSL_API_KEY is set:
//
//	ZEROSSL_API_KEY=... go test -run Integration ./...
//
// They only read, cancel drafts they created themselves, and never touch an
// issued certificate: revoking one would break whatever is serving it.
// Mind the quota -- a free account has 3 slots, and draft, pending_validation,
// issued and expired certificates all occupy one.
func integrationClient(t *testing.T) *Client {
	t.Helper()
	key_ := os.Getenv("ZEROSSL_API_KEY")
	if key_ == "" {
		t.Skip("ZEROSSL_API_KEY is not set, skipping live API test")
	}
	return NewClient(key_, DefaultRPS)
}

func TestIntegrationListCerts(t *testing.T) {
	c_ := integrationClient(t)
	rsp_, err := c_.ListCerts("", "", "100", "1")
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	t.Logf("total_count=%d result_count=%d", rsp_.TotalCount, rsp_.ResultCount)
	for _, cert_ := range rsp_.Results {
		t.Logf("  %v %v %v expires=%v", cert_.ID, cert_.Status, cert_.CommonName, cert_.Expires)
	}
}

// The header auth must be enough on its own; the deprecated query parameter is
// off by default.
func TestIntegrationHeaderAuthAlone(t *testing.T) {
	c_ := integrationClient(t)
	prev_ := UseLegacyQueryAuth
	UseLegacyQueryAuth = false
	defer func() { UseLegacyQueryAuth = prev_ }()

	if _, err := c_.ListCerts("", "", "1", "1"); err != nil {
		t.Fatalf("header-only auth rejected: %v", err)
	}
}

// A bad key must surface ZeroSSL's own error object, not a bare status code.
func TestIntegrationInvalidKeyError(t *testing.T) {
	if os.Getenv("ZEROSSL_API_KEY") == "" {
		t.Skip("ZEROSSL_API_KEY is not set, skipping live API test")
	}
	c_ := NewClient("definitely-not-a-valid-key", DefaultRPS)
	_, err := c_.ListCerts("", "", "1", "1")
	if err == nil {
		t.Fatal("err = nil, want an authentication error")
	}
	apiErr_, ok_ := err.(*ApiErrorModel)
	if !ok_ {
		t.Fatalf("err is %T (%v), want *ApiErrorModel", err, err)
	}
	if apiErr_.Type != "invalid_access_key" {
		t.Errorf("error type = %q, want invalid_access_key", apiErr_.Type)
	}
	t.Logf("api error: %v", apiErr_)
}

func TestIntegrationGetCertNotFound(t *testing.T) {
	c_ := integrationClient(t)
	_, err := c_.GetCert("0000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("err = nil, want an error for a non-existent certificate")
	}
	t.Logf("expected error: %v", err)
}

// Full round trip that stays within the free quota: create a draft, confirm it
// is visible, then cancel it so the slot is released again.
func TestIntegrationCreateAndCancelDraft(t *testing.T) {
	c_ := integrationClient(t)
	if os.Getenv("ZEROSSL_ALLOW_WRITE") == "" {
		t.Skip("ZEROSSL_ALLOW_WRITE is not set, skipping quota-consuming test")
	}

	privKey_ := GenEccKey(elliptic.P256())
	subj_ := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"zerossl-ip-cert test"},
		// TEST-NET-3, reserved by IANA: ZeroSSL will never issue for it, which is
		// exactly what we want -- the draft is cancelled right away.
		CommonName: "203.0.113.10",
	}
	csr_, err := GenEccCSR(subj_, privKey_, x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	csrStr_ := GetCSRString(csr_)
	if csrStr_ == "" {
		t.Fatal("empty CSR")
	}

	cert_, err := c_.CreateCert("203.0.113.10", csrStr_, "90", "1", "")
	if err != nil {
		t.Fatalf("CreateCert: %v", err)
	}
	t.Logf("created %v status=%v", cert_.ID, cert_.Status)
	if cert_.ID == "" {
		t.Fatal("no certificate id returned")
	}
	// Always give the quota slot back, even if the assertions below fail.
	defer func() {
		if err := c_.CancelCert(cert_.ID); err != nil {
			t.Errorf("CancelCert(%v): %v", cert_.ID, err)
			return
		}
		t.Logf("cancelled %v", cert_.ID)
	}()

	got_, err := c_.GetCert(cert_.ID)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got_.ID != cert_.ID {
		t.Errorf("GetCert id = %v, want %v", got_.ID, cert_.ID)
	}
	if got_.Status != CertStatus.Draft && got_.Status != CertStatus.PendingValidation {
		t.Errorf("status = %v, want draft or pending_validation", got_.Status)
	}
	// A draft cannot be downloaded; the API must say so rather than return zeros.
	if _, err := c_.DownloadCertInline(cert_.ID, "1"); err == nil {
		t.Error("DownloadCertInline on a draft returned no error")
	} else {
		t.Logf("expected download error: %v", err)
	}
}

// Exercises the rewritten CleanUnfinished pagination against the live API:
// two drafts are created and must both be gone afterwards.
func TestIntegrationCleanUnfinished(t *testing.T) {
	c_ := integrationClient(t)
	if os.Getenv("ZEROSSL_ALLOW_WRITE") == "" {
		t.Skip("ZEROSSL_ALLOW_WRITE is not set, skipping quota-consuming test")
	}

	created_ := make([]string, 0, 2)
	for _, ip_ := range []string{"203.0.113.11", "203.0.113.12"} {
		privKey_ := GenEccKey(elliptic.P256())
		csr_, err := GenEccCSR(pkix.Name{CommonName: ip_}, privKey_, x509.ECDSAWithSHA256)
		if err != nil {
			t.Fatal(err)
		}
		cert_, err := c_.CreateCert(ip_, GetCSRString(csr_), "90", "1", "")
		if err != nil {
			t.Fatalf("CreateCert(%v): %v", ip_, err)
		}
		t.Logf("created %v for %v (%v)", cert_.ID, ip_, cert_.Status)
		created_ = append(created_, cert_.ID)
	}
	// Belt and braces: cancel anything CleanUnfinished might have missed.
	defer func() {
		for _, id_ := range created_ {
			if got_, err := c_.GetCert(id_); err == nil &&
				(got_.Status == CertStatus.Draft || got_.Status == CertStatus.PendingValidation) {
				t.Errorf("cert %v still in %v status, cancelling", id_, got_.Status)
				_ = c_.CancelCert(id_)
			}
		}
	}()

	if err := c_.CleanUnfinished(); err != nil {
		t.Fatalf("CleanUnfinished: %v", err)
	}
	for _, id_ := range created_ {
		got_, err := c_.GetCert(id_)
		if err != nil {
			t.Errorf("GetCert(%v): %v", id_, err)
			continue
		}
		if got_.Status != CertStatus.Cancelled {
			t.Errorf("cert %v status = %v, want cancelled", id_, got_.Status)
			continue
		}
		t.Logf("cleaned %v -> %v", id_, got_.Status)
	}

	// The quota-consuming statuses must be empty now.
	rsp_, err := c_.ListCerts("draft,pending_validation", "", "100", "1")
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if rsp_.ResultCount != 0 {
		t.Errorf("still %d unfinished certificates after cleanup", rsp_.ResultCount)
	}
}

// TestIntegrationIssueAndRevoke covers the one path the offline suite cannot: it
// drives a certificate all the way to issued and then revokes it, which is what
// frees a quota slot on a free account.
//
// It needs a publicly reachable IP on port 80 and a way to publish the challenge
// file. The publisher is invoked with the same environment as a verify hook, so an
// existing hook works as-is:
//
//	ZEROSSL_API_KEY=... ZEROSSL_ALLOW_WRITE=1 \
//	ZEROSSL_TEST_IP=203.0.113.5 \
//	ZEROSSL_CHALLENGE_CMD='ssh myhost /var/local/zerossl/verify-hook.sh' \
//	go test -v -run TestIntegrationIssueAndRevoke ./
//
// The certificate it issues is separate from any production one and is revoked at
// the end, so a live cert is never touched.
func TestIntegrationIssueAndRevoke(t *testing.T) {
	c_ := integrationClient(t)
	ip_ := os.Getenv("ZEROSSL_TEST_IP")
	publisher_ := os.Getenv("ZEROSSL_CHALLENGE_CMD")
	if os.Getenv("ZEROSSL_ALLOW_WRITE") == "" || ip_ == "" || publisher_ == "" {
		t.Skip("needs ZEROSSL_ALLOW_WRITE, ZEROSSL_TEST_IP and ZEROSSL_CHALLENGE_CMD")
	}

	privKey_ := GenEccKey(elliptic.P256())
	csr_, err := GenEccCSR(pkix.Name{CommonName: ip_}, privKey_, x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	certInfo_, err := c_.CreateCert(ip_, GetCSRString(csr_), "90", "1", "")
	if err != nil {
		t.Fatalf("CreateCert: %v", err)
	}
	t.Logf("created %v status=%v", certInfo_.ID, certInfo_.Status)

	// Whatever happens below, give the quota slot back.
	defer func() {
		got_, err := c_.GetCert(certInfo_.ID)
		if err != nil {
			t.Errorf("GetCert during cleanup: %v", err)
			return
		}
		switch got_.Status {
		case CertStatus.Draft, CertStatus.PendingValidation:
			if err := c_.CancelCert(certInfo_.ID); err != nil {
				t.Errorf("cleanup CancelCert: %v", err)
			}
		case CertStatus.Issued:
			if err := c_.RevokeCert(certInfo_.ID, RevokeReason.Superseded); err != nil {
				t.Errorf("cleanup RevokeCert: %v", err)
			}
		}
	}()

	challenge_, ok_ := certInfo_.Validation.OtherMethods[ip_]
	if !ok_ {
		t.Fatalf("no challenge for %v in %+v", ip_, certInfo_.Validation.OtherMethods)
	}
	url_, err := url.Parse(challenge_.FileValidationUrlHttp)
	if err != nil {
		t.Fatal(err)
	}
	port_ := url_.Port()
	if port_ == "" {
		port_ = "80"
	}
	// Same contract as runVerifyHook, so a real verify hook can be reused verbatim.
	cmd_ := exec.Command("/bin/sh", "-c", publisher_)
	cmd_.Env = append(os.Environ(),
		"ZEROSSL_HTTP_FV_HOST="+url_.Host,
		"ZEROSSL_HTTP_FV_PATH="+url_.Path,
		"ZEROSSL_HTTP_FV_PORT="+port_,
		"ZEROSSL_HTTP_FV_CONTENT="+strings.Join(challenge_.FileValidationContent, "\n"),
	)
	out_, err := cmd_.CombinedOutput()
	t.Logf("challenge publisher output:\n%s", out_)
	if err != nil {
		t.Fatalf("challenge publisher failed: %v", err)
	}

	// Verification: ZeroSSL answers success:false here even on the happy path, so
	// the status is what decides.
	if _, err := c_.VerifyDomains(certInfo_.ID, VerifyDomainsMethod.HttpCsrHash, ""); err != nil {
		t.Fatalf("VerifyDomains: %v", err)
	}
	issued_ := false
	for i_ := 0; i_ < 20; i_++ {
		got_, err := c_.GetCert(certInfo_.ID)
		if err != nil {
			t.Fatalf("GetCert: %v", err)
		}
		if got_.Status == CertStatus.Issued {
			t.Logf("issued after %ds, expires %v", i_*15, got_.Expires)
			issued_ = true
			break
		}
		time.Sleep(15 * time.Second)
	}
	if !issued_ {
		t.Fatal("certificate never reached issued status")
	}

	// The actual subject of this test.
	if err := c_.RevokeCert(certInfo_.ID, RevokeReason.Superseded); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	got_, err := c_.GetCert(certInfo_.ID)
	if err != nil {
		t.Fatalf("GetCert after revoke: %v", err)
	}
	if got_.Status != CertStatus.Revoked {
		t.Errorf("status after revoke = %v, want %v", got_.Status, CertStatus.Revoked)
	}
	t.Logf("revoked, status is now %v", got_.Status)

	// Revoking must not leave the slot occupied.
	slots_, err := c_.ListCerts("draft,pending_validation,issued,expired", ip_, "100", "1")
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	for _, cert := range slots_.Results {
		if cert.ID == certInfo_.ID {
			t.Errorf("revoked cert %v still counts against the quota", cert.ID)
		}
	}
}
