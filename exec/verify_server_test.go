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
	"io"
	"net"
	"net/http"
	"testing"

	zerosslIPCert "github.com/tinkernels/zerossl-ip-cert"
)

func testCertInfo(url string) *zerosslIPCert.CertificateInfoModel {
	return &zerosslIPCert.CertificateInfoModel{
		ID:         "abc",
		CommonName: "1.2.3.4",
		Validation: zerosslIPCert.ValidationInfoModel{
			OtherMethods: map[string]zerosslIPCert.OtherValidationInfoModel{
				"1.2.3.4": {
					FileValidationUrlHttp: url,
					FileValidationContent: []string{"line1", "line2", "comodoca.com"},
				},
			},
		},
	}
}

func TestValidationFiles(t *testing.T) {
	files_, err := validationFiles(testCertInfo("http://1.2.3.4/.well-known/pki-validation/ABC.txt"))
	if err != nil {
		t.Fatal(err)
	}
	content_, ok_ := files_["/.well-known/pki-validation/ABC.txt"]
	if !ok_ {
		t.Fatalf("challenge path missing, got %v", files_)
	}
	// Real newlines here: no environment variable is involved, unlike the hook path.
	if want_ := "line1\nline2\ncomodoca.com"; content_ != want_ {
		t.Errorf("content = %q, want %q", content_, want_)
	}
}

func TestValidationFilesRejectsEmptyChallenge(t *testing.T) {
	if _, err := validationFiles(&zerosslIPCert.CertificateInfoModel{}); err == nil {
		t.Error("err = nil, want an error when there is no http challenge")
	}
}

func TestValidationListenAddr(t *testing.T) {
	// ZeroSSL only reaches port 80, which is also what the URL carries implicitly.
	if got_ := validationListenAddr(testCertInfo("http://1.2.3.4/.well-known/x.txt"), ""); got_ != ":80" {
		t.Errorf("addr = %q, want :80", got_)
	}
	// An explicit port in the URL is honoured.
	if got_ := validationListenAddr(testCertInfo("http://1.2.3.4:8080/.well-known/x.txt"), ""); got_ != ":8080" {
		t.Errorf("addr = %q, want :8080", got_)
	}
	// The config override always wins.
	if got_ := validationListenAddr(testCertInfo("http://1.2.3.4/.well-known/x.txt"), "127.0.0.1:9999"); got_ != "127.0.0.1:9999" {
		t.Errorf("addr = %q, want the override", got_)
	}
}

// End to end over a real socket: the served file must come back as a plain 200.
func TestServeValidationFiles(t *testing.T) {
	ln_, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	path_ := "/.well-known/pki-validation/ABC.txt"
	stop_ := serveValidationFiles(ln_, map[string]string{path_: "line1\nline2"})
	defer stop_()

	base_ := "http://" + ln_.Addr().String()
	// No redirects allowed: ZeroSSL requires a direct 200.
	client_ := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp_, err := client_.Get(base_ + path_)
	if err != nil {
		t.Fatal(err)
	}
	defer resp_.Body.Close()
	if resp_.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp_.StatusCode)
	}
	body_, err := io.ReadAll(resp_.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body_) != "line1\nline2" {
		t.Errorf("body = %q", body_)
	}

	// Anything else is a 404, the server is not a general purpose file server.
	resp404_, err := client_.Get(base_ + "/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	defer resp404_.Body.Close()
	if resp404_.StatusCode != http.StatusNotFound {
		t.Errorf("status for unknown path = %d, want 404", resp404_.StatusCode)
	}
}

// After the stop function returns, the port must be free again.
func TestServeValidationFilesStops(t *testing.T) {
	ln_, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr_ := ln_.Addr().String()
	stop_ := serveValidationFiles(ln_, map[string]string{"/x": "y"})
	stop_()

	ln2_, err := net.Listen("tcp", addr_)
	if err != nil {
		t.Fatalf("port still busy after shutdown: %v", err)
	}
	_ = ln2_.Close()
}
