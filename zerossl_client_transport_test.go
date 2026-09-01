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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestRequest builds a request aimed at the test server, mirroring how the
// factory builds a POST with a replayable body.
func newTestRequest(t *testing.T, srvURL, body string) *http.Request {
	t.Helper()
	req_, err := http.NewRequest(http.MethodPost, srvURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req_
}

func TestDoRequestRetriesOn429AndReplaysBody(t *testing.T) {
	var bodies_ []string
	attempts_ := 0
	srv_ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got_, _ := io.ReadAll(r.Body)
		bodies_ = append(bodies_, string(got_))
		attempts_++
		if attempts_ == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, `{"success":1}`)
	}))
	defer srv_.Close()

	c_ := NewClient("k", 100)
	resp_, err := c_.doRequest(newTestRequest(t, srv_.URL, "a=1"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp_.Body.Close()

	if attempts_ != 2 {
		t.Errorf("attempts = %d, want 2", attempts_)
	}
	if len(bodies_) != 2 || bodies_[0] != "a=1" || bodies_[1] != "a=1" {
		t.Errorf("bodies = %q, want the same body on both attempts", bodies_)
	}
	if resp_.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp_.StatusCode)
	}
}

func TestDoRequestGivesUpAfterMaxRetries(t *testing.T) {
	attempts_ := 0
	srv_ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts_++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv_.Close()

	c_ := NewClient("k", 100)
	c_.MaxRetries = 2
	_, err := c_.doRequest(newTestRequest(t, srv_.URL, "a=1"))
	if err == nil {
		t.Fatal("err = nil, want a rate limit error")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("err = %v, want a rate limit error", err)
	}
	if attempts_ != 3 { // the initial attempt plus MaxRetries
		t.Errorf("attempts = %d, want 3", attempts_)
	}
}

func TestRetryDelay(t *testing.T) {
	mk_ := func(h string) *http.Response {
		resp_ := &http.Response{Header: make(http.Header)}
		if h != "" {
			resp_.Header.Set("Retry-After", h)
		}
		return resp_
	}
	if got_ := retryDelay(mk_("7"), 0); got_ != 7*time.Second {
		t.Errorf("Retry-After 7 => %v, want 7s", got_)
	}
	// Sub-second and negative values are floored to one second.
	if got_ := retryDelay(mk_("0"), 0); got_ != time.Second {
		t.Errorf("Retry-After 0 => %v, want 1s", got_)
	}
	// Without the header the delay grows with the attempt number.
	if got_ := retryDelay(mk_(""), 0); got_ != 2*time.Second {
		t.Errorf("attempt 0 => %v, want 2s", got_)
	}
	if got_ := retryDelay(mk_(""), 2); got_ != 8*time.Second {
		t.Errorf("attempt 2 => %v, want 8s", got_)
	}
	// And is capped.
	if got_ := retryDelay(mk_(""), 30); got_ != maxRetryDelay {
		t.Errorf("attempt 30 => %v, want %v", got_, maxRetryDelay)
	}
}

// ZeroSSL reports failures with HTTP 200 and an "error" object in the body.
func TestGetCertRejectsEmbeddedError(t *testing.T) {
	srv_ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"success":false,"error":{"code":101,"type":"invalid_access_key"}}`)
	}))
	defer srv_.Close()

	resp_, err := http.Get(srv_.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp_.Body.Close()

	var cert_ CertificateInfoModel
	err = decodeJSON(resp_, &cert_)
	if err == nil {
		t.Fatal("err = nil, want the embedded API error")
	}
	if got_, want_ := err.Error(), "ZeroSSL API error 101 (invalid_access_key)"; got_ != want_ {
		t.Errorf("err = %q, want %q", got_, want_)
	}
}

func TestDecodeJSONSuccessAndHTTPError(t *testing.T) {
	// A normal certificate payload has no "error" key and must decode cleanly.
	resp_ := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"id":"abc","status":"issued"}`)),
	}
	var cert_ CertificateInfoModel
	if err := decodeJSON(resp_, &cert_); err != nil {
		t.Fatalf("decodeJSON: %v", err)
	}
	if cert_.ID != "abc" || cert_.Status != CertStatus.Issued {
		t.Errorf("cert = %+v, want id=abc status=issued", cert_)
	}

	// An HTTP level failure must surface the body, not just the status code.
	resp_ = &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       io.NopCloser(strings.NewReader(`forbidden: bad key`)),
	}
	err := decodeJSON(resp_, &cert_)
	if err == nil {
		t.Fatal("err = nil, want an HTTP error")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden: bad key") {
		t.Errorf("err = %q, want the status and the body", err)
	}
}

// For HTTP_CSR_HASH ZeroSSL always answers success:false with an error object,
// so VerifyDomains must not treat that as a transport failure.
func TestEmbeddedErrorIgnoresEmptyErrorObject(t *testing.T) {
	if got_ := embeddedError([]byte(`{"success":1}`)); got_ != nil {
		t.Errorf("embeddedError = %v, want nil", got_)
	}
	if got_ := embeddedError([]byte(`{"success":false,"error":{}}`)); got_ != nil {
		t.Errorf("embeddedError on empty error object = %v, want nil", got_)
	}
	if got_ := embeddedError([]byte(`not json`)); got_ != nil {
		t.Errorf("embeddedError on garbage = %v, want nil", got_)
	}
}

// A bare &Client{} must stay usable: the optional fields are filled in lazily.
func TestZeroValueClientGetsDefaults(t *testing.T) {
	c_ := &Client{ApiKey: "k"}
	limiter_, httpClient_, maxRetries_ := c_.deps()
	if limiter_ == nil {
		t.Error("limiter is nil")
	}
	if httpClient_ == nil || httpClient_.Timeout != DefaultTimeout {
		t.Errorf("http client = %+v, want one with %v timeout", httpClient_, DefaultTimeout)
	}
	if maxRetries_ != DefaultMaxRetries {
		t.Errorf("maxRetries = %d, want %d", maxRetries_, DefaultMaxRetries)
	}
}
