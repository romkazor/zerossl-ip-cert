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
	"testing"

	"gopkg.in/yaml.v3"
)

// A config predating the quota/auth options must keep working, with the
// free-account friendly defaults applied.
func TestLegacyConfigDefaults(t *testing.T) {
	const legacyYaml_ = `
dataDir: /var/local/zerossl
logFile: /var/local/zerossl/log.txt
cleanUnfinished: true
certConfigs:
  - commonName: 4.3.2.1
    confId: xx1
    apiKey: xxx-xxx
    days: 90
`
	var conf_ Config
	if err := yaml.Unmarshal([]byte(legacyYaml_), &conf_); err != nil {
		t.Fatal(err)
	}
	if len(conf_.CertConfigs) != 1 || conf_.CertConfigs[0].ConfID != "xx1" {
		t.Fatalf("legacy certConfigs not parsed: %+v", conf_.CertConfigs)
	}
	if conf_.LegacyQueryAuth {
		t.Error("legacyQueryAuth must default to false, so the recommended header auth is used")
	}
	if conf_.RevokeOldOnRenew != nil {
		t.Errorf("RevokeOldOnRenew = %v, want nil when the key is absent", *conf_.RevokeOldOnRenew)
	}
	if !conf_.ShouldRevokeOldOnRenew() {
		t.Error("ShouldRevokeOldOnRenew() must default to true to keep the free quota drainable")
	}
}

func TestRevokeOldOnRenewExplicit(t *testing.T) {
	for _, c_ := range []struct {
		name string
		yaml string
		want bool
	}{
		{name: "explicit true", yaml: "revokeOldOnRenew: true\n", want: true},
		{name: "explicit false", yaml: "revokeOldOnRenew: false\n", want: false},
	} {
		t.Run(c_.name, func(t *testing.T) {
			var conf_ Config
			if err := yaml.Unmarshal([]byte(c_.yaml), &conf_); err != nil {
				t.Fatal(err)
			}
			if conf_.RevokeOldOnRenew == nil {
				t.Fatal("RevokeOldOnRenew is nil, want an explicit value")
			}
			if got_ := conf_.ShouldRevokeOldOnRenew(); got_ != c_.want {
				t.Errorf("ShouldRevokeOldOnRenew() = %v, want %v", got_, c_.want)
			}
		})
	}
}

func TestLegacyQueryAuthParsed(t *testing.T) {
	var conf_ Config
	if err := yaml.Unmarshal([]byte("legacyQueryAuth: true\n"), &conf_); err != nil {
		t.Fatal(err)
	}
	if !conf_.LegacyQueryAuth {
		t.Error("legacyQueryAuth: true was not parsed")
	}
}
