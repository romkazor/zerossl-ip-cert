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
	"encoding/json"
	"io"
	"net/url"
	"testing"
)

// withLegacyQueryAuth toggles the package level auth mode and restores it.
func withLegacyQueryAuth(t *testing.T, enabled bool) {
	t.Helper()
	prev_ := UseLegacyQueryAuth
	UseLegacyQueryAuth = enabled
	t.Cleanup(func() { UseLegacyQueryAuth = prev_ })
}

func TestAuthHeaderIsAlwaysSent(t *testing.T) {
	withLegacyQueryAuth(t, false)
	req_ := ApiReqFactory.GetCertificate("secret-key", "abc123")
	if got_ := req_.Header.Get("Authorization"); got_ != "ApiKey secret-key" {
		t.Errorf("Authorization header = %q, want %q", got_, "ApiKey secret-key")
	}
	if req_.URL.Query().Has("access_key") {
		t.Errorf("access_key must not be in the query by default, got %q", req_.URL.RawQuery)
	}
}

func TestLegacyQueryAuthAddsAccessKey(t *testing.T) {
	withLegacyQueryAuth(t, true)
	req_ := ApiReqFactory.GetCertificate("secret-key", "abc123")
	if got_ := req_.Header.Get("Authorization"); got_ != "ApiKey secret-key" {
		t.Errorf("Authorization header = %q, want %q", got_, "ApiKey secret-key")
	}
	if got_ := req_.URL.Query().Get("access_key"); got_ != "secret-key" {
		t.Errorf("access_key = %q, want %q", got_, "secret-key")
	}
}

func TestPostRequestKeepsAuthHeaderAndReplayableBody(t *testing.T) {
	withLegacyQueryAuth(t, false)
	req_ := ApiReqFactory.CreateCertificate("k", "1.2.3.4", "CSR", "90", "1", "old-hash")
	// The Content-Type must not have clobbered the Authorization header.
	if got_ := req_.Header.Get("Authorization"); got_ != "ApiKey k" {
		t.Errorf("Authorization header = %q, want %q", got_, "ApiKey k")
	}
	if got_ := req_.Header.Get("Content-Type"); got_ != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got_)
	}
	if req_.ContentLength <= 0 {
		t.Errorf("ContentLength = %d, want > 0", req_.ContentLength)
	}
	if req_.GetBody == nil {
		t.Fatal("GetBody is nil, the request cannot be replayed on a 429 retry")
	}

	first_, err := io.ReadAll(req_.Body)
	if err != nil {
		t.Fatal(err)
	}
	form_, err := url.ParseQuery(string(first_))
	if err != nil {
		t.Fatal(err)
	}
	if got_ := form_.Get("certificate_domains"); got_ != "1.2.3.4" {
		t.Errorf("certificate_domains = %q", got_)
	}
	if got_ := form_.Get("replacement_for_certificate"); got_ != "old-hash" {
		t.Errorf("replacement_for_certificate = %q, want %q", got_, "old-hash")
	}

	// Replaying the drained request must yield the same body again.
	body_, err := req_.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	second_, err := io.ReadAll(body_)
	if err != nil {
		t.Fatal(err)
	}
	if string(second_) != string(first_) {
		t.Errorf("replayed body = %q, want %q", second_, first_)
	}
}

func TestCreateCertificateOmitsEmptyReplacement(t *testing.T) {
	withLegacyQueryAuth(t, false)
	req_ := ApiReqFactory.CreateCertificate("k", "1.2.3.4", "CSR", "90", "1", "")
	body_, err := io.ReadAll(req_.Body)
	if err != nil {
		t.Fatal(err)
	}
	form_, err := url.ParseQuery(string(body_))
	if err != nil {
		t.Fatal(err)
	}
	if form_.Has("replacement_for_certificate") {
		t.Errorf("replacement_for_certificate must be omitted when empty, got %q", body_)
	}
}

func TestRevokeCertificateRequest(t *testing.T) {
	withLegacyQueryAuth(t, false)
	req_ := ApiReqFactory.RevokeCertificate("k", "abc123", RevokeReason.Superseded)
	if req_.Method != "POST" {
		t.Errorf("method = %q, want POST", req_.Method)
	}
	if got_, want_ := req_.URL.Path, "/certificates/abc123/revoke"; got_ != want_ {
		t.Errorf("path = %q, want %q", got_, want_)
	}
	if got_, want_ := req_.URL.Host, ApiEndpoint; got_ != want_ {
		t.Errorf("host = %q, want %q", got_, want_)
	}
	body_, err := io.ReadAll(req_.Body)
	if err != nil {
		t.Fatal(err)
	}
	form_, err := url.ParseQuery(string(body_))
	if err != nil {
		t.Fatal(err)
	}
	if got_ := form_.Get("reason"); got_ != "Superseded" {
		t.Errorf("reason = %q, want %q", got_, "Superseded")
	}
}

// ZeroSSL answers with HTTP 200 even when the action failed, so the body decides.
func TestActionResultModel(t *testing.T) {
	cases_ := []struct {
		name    string
		body    string
		wantOK  bool
		wantMsg string
	}{
		{name: "success", body: `{"success":1}`, wantOK: true},
		{name: "success bool", body: `{"success":true}`, wantOK: true},
		{name: "success string", body: `{"success":"1"}`, wantOK: true},
		{
			name:    "failure with error object",
			body:    `{"success":false,"error":{"code":2802,"type":"certificate_not_issued"}}`,
			wantOK:  false,
			wantMsg: "ZeroSSL API error 2802 (certificate_not_issued)",
		},
		{name: "failure bare", body: `{"success":false}`, wantOK: false,
			wantMsg: "ZeroSSL API did not acknowledge the action"},
	}
	for _, c_ := range cases_ {
		t.Run(c_.name, func(t *testing.T) {
			var result_ ActionResultModel
			if err := json.Unmarshal([]byte(c_.body), &result_); err != nil {
				t.Fatal(err)
			}
			if got_ := result_.IsSuccess(); got_ != c_.wantOK {
				t.Errorf("IsSuccess() = %v, want %v", got_, c_.wantOK)
			}
			err := result_.Err()
			if c_.wantOK {
				if err != nil {
					t.Errorf("Err() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Err() = nil, want an error")
			}
			if err.Error() != c_.wantMsg {
				t.Errorf("Err() = %q, want %q", err.Error(), c_.wantMsg)
			}
		})
	}
}
