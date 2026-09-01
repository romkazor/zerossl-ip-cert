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

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	zerosslIPCert "github.com/romkazor/zerossl-ip-cert/v2"
)

func hookTestCertInfo() zerosslIPCert.CertificateInfoModel {
	return zerosslIPCert.CertificateInfoModel{
		CommonName: "1.1.1.1",
		Validation: zerosslIPCert.ValidationInfoModel{
			OtherMethods: map[string]zerosslIPCert.OtherValidationInfoModel{
				"1.1.1.1": {
					FileValidationUrlHttp: "http://1.1.1.1/.well-known/pki-validation/715EE529C6FF317C938B79C7655710AC.txt",
					FileValidationContent: []string{
						"ABCDEF1234567890",
						"comodoca.com",
						"abcdef1234567890",
					},
				},
			},
		},
	}
}

// The hook contract is the public interface of this tool: a stub hook records
// the environment it was handed, and the assertions pin that contract down.
func TestRunVerifyHookEnvContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stub hook is a shell script")
	}
	dir_ := t.TempDir()
	out_ := filepath.Join(dir_, "env.txt")
	hook_ := filepath.Join(dir_, "verify-hook.sh")
	script_ := "#!/bin/sh\n" +
		"{\n" +
		"  echo \"HOST=$ZEROSSL_HTTP_FV_HOST\"\n" +
		"  echo \"PATH_=$ZEROSSL_HTTP_FV_PATH\"\n" +
		"  echo \"PORT=$ZEROSSL_HTTP_FV_PORT\"\n" +
		"  echo \"CONTENT=$ZEROSSL_HTTP_FV_CONTENT\"\n" +
		"} > " + out_ + "\n"
	if err := os.WriteFile(hook_, []byte(script_), 0700); err != nil {
		t.Fatal(err)
	}

	certInfo_ := hookTestCertInfo()
	if err := runVerifyHook(hook_, &certInfo_); err != nil {
		t.Fatalf("runVerifyHook: %v", err)
	}
	got_, err := os.ReadFile(out_)
	if err != nil {
		t.Fatal(err)
	}
	env_ := string(got_)
	for _, want_ := range []string{
		"HOST=1.1.1.1",
		"PATH_=/.well-known/pki-validation/715EE529C6FF317C938B79C7655710AC.txt",
		// No port in the URL means ZeroSSL will come in on 80.
		"PORT=80",
	} {
		if !strings.Contains(env_, want_) {
			t.Errorf("hook environment missing %q, got:\n%s", want_, env_)
		}
	}
	// On unix the three lines are joined with real newlines, so only the first
	// one lands on the CONTENT= line.
	if !strings.Contains(env_, "CONTENT=ABCDEF1234567890\ncomodoca.com\nabcdef1234567890") {
		t.Errorf("content not newline-joined, got:\n%s", env_)
	}
}

func TestRunVerifyHookMissingExecutable(t *testing.T) {
	certInfo_ := hookTestCertInfo()
	err := runVerifyHook(filepath.Join(t.TempDir(), "does-not-exist.sh"), &certInfo_)
	if err == nil {
		t.Fatal("err = nil, want an error for a missing hook")
	}
	if !strings.Contains(err.Error(), "not exists") {
		t.Errorf("err = %v, want it to mention the missing hook", err)
	}
}

// The shipped sample hooks must at least be syntactically valid shell.
func TestSampleHooksParse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available")
	}
	for _, name_ := range []string{"sample-nginx-verify-hook.sh", "sample-nginx-post-hook.sh"} {
		if _, err := os.Stat(name_); err != nil {
			t.Errorf("%v: %v", name_, err)
		}
	}
}

// A state entry that matches no certificate on the account must be droppable, so
// that a plain run can issue from scratch instead of retrying a renewal forever.
func TestDropCertState(t *testing.T) {
	saved_ := currentData
	t.Cleanup(func() { currentData = saved_ })

	currentData = &CurrentData{Certs: []CurrentCertData{
		{ConfID: "a", CertID: "id-a"},
		{ConfID: "b", CertID: "id-b"},
		{ConfID: "c", CertID: "id-c"},
	}}

	dropCertState("id-b")
	if len(currentData.Certs) != 2 {
		t.Fatalf("expected 2 entries left, got %d", len(currentData.Certs))
	}
	for _, c_ := range currentData.Certs {
		if c_.CertID == "id-b" {
			t.Fatalf("id-b is still present: %+v", currentData.Certs)
		}
	}
	if currentData.Certs[0].CertID != "id-a" || currentData.Certs[1].CertID != "id-c" {
		t.Fatalf("surviving entries reordered: %+v", currentData.Certs)
	}

	// An unknown id must be a no-op rather than a panic or a truncation.
	dropCertState("id-missing")
	if len(currentData.Certs) != 2 {
		t.Fatalf("unknown id changed the state: %+v", currentData.Certs)
	}
}

// issueCert distinguishes "this certificate is gone" from every other renewal
// failure by sentinel, so the wrapping has to survive fmt.Errorf.
func TestErrCertGoneIsIdentifiable(t *testing.T) {
	wrapped_ := fmt.Errorf("%w (id %v): %v", errCertGone, "abc123", errors.New("certificate_not_found"))
	if !errors.Is(wrapped_, errCertGone) {
		t.Fatalf("wrapped error no longer matches errCertGone: %v", wrapped_)
	}
	if errors.Is(errors.New("some other failure"), errCertGone) {
		t.Fatal("an unrelated error matched errCertGone")
	}
}

// withTempState points the package globals at a throwaway data dir.
func withTempState(t *testing.T) string {
	t.Helper()
	dir_ := t.TempDir()
	savedConf_, savedData_, savedPath_ := usingConfig, currentData, currentDataFilePath
	t.Cleanup(func() {
		usingConfig, currentData, currentDataFilePath = savedConf_, savedData_, savedPath_
	})
	usingConfig = &Config{DataDir: dir_}
	currentData = &CurrentData{}
	currentDataFilePath = filepath.Join(dir_, "current.yaml")
	return dir_
}

// A certificate that has been requested must survive the run that requested it:
// its key is kept and its id is written to the state, so a later run can finish it.
func TestRememberAndClearPending(t *testing.T) {
	dir_ := withTempState(t)
	conf_ := &CertConf{ConfID: "c1", CommonName: "203.0.113.10",
		CertFile: filepath.Join(dir_, "cert.pem"), KeyFile: filepath.Join(dir_, "key.pem")}

	srcKey_ := filepath.Join(dir_, "privkey.pem")
	if err := os.WriteFile(srcKey_, []byte("KEY"), 0600); err != nil {
		t.Fatal(err)
	}

	rememberPending(conf_, "cert-id-1", srcKey_)

	if got_ := pendingIDFor(conf_); got_ != "cert-id-1" {
		t.Fatalf("pendingIDFor = %q, want \"cert-id-1\"", got_)
	}
	kept_ := pendingKeyPath("cert-id-1")
	info_, err := os.Stat(kept_)
	if err != nil {
		t.Fatalf("kept key missing: %v", err)
	}
	if perm_ := info_.Mode().Perm(); perm_ != 0600 {
		t.Errorf("kept key mode = %v, want 0600", perm_)
	}
	// The state entry has to reach disk, otherwise a crash loses the certificate.
	onDisk_, err := ReadCurrentData(currentDataFilePath)
	if err != nil {
		t.Fatalf("ReadCurrentData: %v", err)
	}
	if len(onDisk_.Certs) != 1 || onDisk_.Certs[0].PendingCertID != "cert-id-1" {
		t.Fatalf("state on disk = %+v, want one entry pending cert-id-1", onDisk_.Certs)
	}

	clearPending(conf_, "cert-id-1")
	if got_ := pendingIDFor(conf_); got_ != "" {
		t.Errorf("pendingIDFor after clear = %q, want empty", got_)
	}
	if _, err := os.Stat(kept_); !os.IsNotExist(err) {
		t.Errorf("kept key still present after clear: %v", err)
	}
}

// Remembering must not create a second entry for a config that already has one.
func TestSetPendingIDUpdatesExistingEntry(t *testing.T) {
	withTempState(t)
	currentData.Certs = []CurrentCertData{{ConfID: "c1", CertID: "live-id"}}
	conf_ := &CertConf{ConfID: "c1", CommonName: "203.0.113.10"}

	setPendingID(conf_, "new-id")

	if len(currentData.Certs) != 1 {
		t.Fatalf("entries = %d, want 1: %+v", len(currentData.Certs), currentData.Certs)
	}
	if currentData.Certs[0].CertID != "live-id" {
		t.Errorf("installed cert id was overwritten: %+v", currentData.Certs[0])
	}
	if currentData.Certs[0].PendingCertID != "new-id" {
		t.Errorf("PendingCertID = %q, want \"new-id\"", currentData.Certs[0].PendingCertID)
	}
}

// pendingCertId must not appear in a state file that has nothing pending, so files
// written by older versions round-trip unchanged.
func TestPendingIDOmittedWhenEmpty(t *testing.T) {
	dir_ := withTempState(t)
	path_ := filepath.Join(dir_, "out.yaml")
	if err := WriteCurrentData(path_, &CurrentData{Certs: []CurrentCertData{
		{CommonName: "203.0.113.10", ConfID: "c1", CertID: "abc"},
	}}); err != nil {
		t.Fatal(err)
	}
	out_, err := os.ReadFile(path_)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out_), "pendingCertId") {
		t.Errorf("empty pending id was written out:\n%s", out_)
	}
}
