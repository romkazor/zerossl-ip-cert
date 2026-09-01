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
	"os"
	"testing"
)

// These tests talk to the live ZeroSSL API and are skipped unless
// ZEROSSL_API_KEY is set:
//
//	ZEROSSL_API_KEY=... go test -run Integration ./...
//
// They only read; nothing here creates or cancels a certificate.
func integrationClient(t *testing.T) *Client {
	t.Helper()
	key_ := os.Getenv("ZEROSSL_API_KEY")
	if key_ == "" {
		t.Skip("ZEROSSL_API_KEY is not set, skipping live API test")
	}
	return &Client{ApiKey: key_}
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

func TestIntegrationGetCertNotFound(t *testing.T) {
	c_ := integrationClient(t)
	if _, err := c_.GetCert("0000000000000000000000000000000000000000"); err != nil {
		t.Logf("expected error for a non-existent certificate: %v", err)
	}
}
