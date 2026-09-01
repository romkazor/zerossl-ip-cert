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
	"os"
	"path/filepath"
	"testing"
)

// The shipped sample must stay loadable: it is what users copy.
func TestReadConfigSample(t *testing.T) {
	conf_, err := ReadConfig("sample-config.yaml")
	if err != nil {
		t.Fatalf("ReadConfig(sample-config.yaml): %v", err)
	}
	if conf_.DataDir == "" || conf_.LogFile == "" {
		t.Errorf("sample config is missing dataDir/logFile: %+v", conf_)
	}
	if len(conf_.CertConfigs) == 0 {
		t.Fatal("sample config has no certConfigs")
	}
	for _, c_ := range conf_.CertConfigs {
		if c_.ConfID == "" || c_.CommonName == "" {
			t.Errorf("sample cert config missing confId/commonName: %+v", c_)
		}
	}
}

// Round trip through a temp dir, so the test never mutates a tracked file.
func TestWriteCurrentDataRoundTrip(t *testing.T) {
	path_ := filepath.Join(t.TempDir(), "current.yaml")
	want_ := &CurrentData{Certs: []CurrentCertData{
		{CommonName: "1.2.3.4", ConfID: "xx1", CertID: "hash1", CertFile: "/tmp/c.pem", KeyFile: "/tmp/k.pem"},
		{CommonName: "4.3.2.1", ConfID: "xx2", CertID: "hash2"},
	}}
	if err := WriteCurrentData(path_, want_); err != nil {
		t.Fatalf("WriteCurrentData: %v", err)
	}
	got_, err := ReadCurrentData(path_)
	if err != nil {
		t.Fatalf("ReadCurrentData: %v", err)
	}
	if len(got_.Certs) != len(want_.Certs) {
		t.Fatalf("got %d certs, want %d", len(got_.Certs), len(want_.Certs))
	}
	for i_, c_ := range got_.Certs {
		if c_ != want_.Certs[i_] {
			t.Errorf("cert[%d] = %+v, want %+v", i_, c_, want_.Certs[i_])
		}
	}
}

func TestReadConfigInvalidYaml(t *testing.T) {
	path_ := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path_, []byte("dataDir: [unclosed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(path_); err == nil {
		t.Error("ReadConfig on malformed yaml returned nil error")
	}
}
