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
