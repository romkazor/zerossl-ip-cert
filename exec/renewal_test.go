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
	"time"

	zerosslIPCert "github.com/romkazor/zerossl-ip-cert/v2"
)

// ZeroSSL reports Expires in UTC with no zone suffix, and time.Parse reads a
// zoneless layout as UTC -- so the fixture has to be built in UTC too, otherwise
// the test silently shifts by the local offset.
func certAt(status string, expiresIn time.Duration) *zerosslIPCert.CertificateInfoModel {
	return &zerosslIPCert.CertificateInfoModel{
		CommonName: "1.2.3.4",
		Status:     status,
		Expires:    time.Now().UTC().Add(expiresIn).Format("2006-01-02 15:04:05"),
	}
}

func TestRenewalNotDue(t *testing.T) {
	day := 24 * time.Hour
	for _, c_ := range []struct {
		name    string
		cert    *zerosslIPCert.CertificateInfoModel
		wantOff bool // true == leave it alone
	}{
		{"issued, 60 days left", certAt(zerosslIPCert.CertStatus.Issued, 60*day), true},
		{"issued, 40 days left", certAt(zerosslIPCert.CertStatus.Issued, 40*day), true},
		{"issued, 20 days left", certAt(zerosslIPCert.CertStatus.Issued, 20*day), false},
		{"issued, already expired", certAt(zerosslIPCert.CertStatus.Issued, -day), false},
		{"expiring_soon", certAt(zerosslIPCert.CertStatus.ExpiringSoon, 60*day), false},

		// The point of the fix: these all carry a future expiry date but are dead.
		// Skipping on the date alone would leave a dead cert installed forever.
		{"revoked with future date", certAt(zerosslIPCert.CertStatus.Revoked, 60*day), false},
		{"cancelled with future date", certAt(zerosslIPCert.CertStatus.Cancelled, 60*day), false},
		{"expired status", certAt(zerosslIPCert.CertStatus.Expired, 60*day), false},
		{"draft", certAt(zerosslIPCert.CertStatus.Draft, 60*day), false},

		{"issued but unparsable expiry", &zerosslIPCert.CertificateInfoModel{
			CommonName: "1.2.3.4", Status: zerosslIPCert.CertStatus.Issued, Expires: ""}, false},
	} {
		t.Run(c_.name, func(t *testing.T) {
			if got_ := renewalNotDue(c_.cert, "1.2.3.4", DefaultRenewBeforeDays); got_ != c_.wantOff {
				t.Errorf("renewalNotDue() = %v, want %v", got_, c_.wantOff)
			}
		})
	}
}

// The 29-day threshold is a boundary, so pin both sides of it.
func TestRenewalThresholdBoundary(t *testing.T) {
	day := 24 * time.Hour
	if renewalNotDue(certAt(zerosslIPCert.CertStatus.Issued, 29*day+time.Hour), "x", DefaultRenewBeforeDays) != true {
		t.Error("just over 29 days should be skipped")
	}
	if renewalNotDue(certAt(zerosslIPCert.CertStatus.Issued, 29*day-time.Hour), "x", DefaultRenewBeforeDays) != false {
		t.Error("just under 29 days should renew")
	}
}

func TestPersistCertID(t *testing.T) {
	dir_ := t.TempDir()
	prevPath_, prevData_ := currentDataFilePath, currentData
	defer func() { currentDataFilePath, currentData = prevPath_, prevData_ }()

	currentDataFilePath = dir_ + "/current.yaml"
	currentData = &CurrentData{Certs: []CurrentCertData{
		{CommonName: "1.2.3.4", ConfID: "c1", CertID: "stale"},
	}}
	conf_ := &CertConf{ConfID: "c1", CommonName: "1.2.3.4",
		CertFile: "/tmp/c.pem", KeyFile: "/tmp/k.pem"}

	persistCertID("stale", "recovered", conf_)

	if got_ := currentData.Certs[0].CertID; got_ != "recovered" {
		t.Errorf("in-memory CertID = %q, want recovered", got_)
	}
	back_, err := ReadCurrentData(currentDataFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if back_.Certs[0].CertID != "recovered" || back_.Certs[0].KeyFile != "/tmp/k.pem" {
		t.Errorf("persisted entry = %+v", back_.Certs[0])
	}

	// A no-op when the ids already agree: nothing to rewrite.
	persistCertID("recovered", "recovered", conf_)
	if currentData.Certs[0].CertID != "recovered" {
		t.Error("no-op call changed the state")
	}
}

// A longer lead time must widen the window, which is what makes a rarely-running
// scheduler safe.
func TestRenewLeadDaysConfigurable(t *testing.T) {
	day := 24 * time.Hour
	cert_ := certAt(zerosslIPCert.CertStatus.Issued, 60*day)

	if !renewalNotDue(cert_, "x", DefaultRenewBeforeDays) {
		t.Error("60 days left with the 29 day default should be skipped")
	}
	if renewalNotDue(cert_, "x", 90) {
		t.Error("60 days left with a 90 day lead time should renew")
	}
}

func TestRenewLeadDaysDefault(t *testing.T) {
	if got_ := (&CertConf{}).RenewLeadDays(); got_ != DefaultRenewBeforeDays {
		t.Errorf("unset RenewBeforeDays = %d, want %d", got_, DefaultRenewBeforeDays)
	}
	if got_ := (&CertConf{RenewBeforeDays: 45}).RenewLeadDays(); got_ != 45 {
		t.Errorf("RenewBeforeDays 45 = %d, want 45", got_)
	}
	// A zero or negative value falls back rather than renewing on every run.
	if got_ := (&CertConf{RenewBeforeDays: -1}).RenewLeadDays(); got_ != DefaultRenewBeforeDays {
		t.Errorf("negative RenewBeforeDays = %d, want the default", got_)
	}
}
