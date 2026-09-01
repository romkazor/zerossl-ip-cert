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
	"testing"
)

func TestDirPermFor(t *testing.T) {
	for _, c_ := range []struct{ in, want os.FileMode }{
		{0600, 0700},
		{0644, 0755},
		{0640, 0750},
		{0400, 0500},
	} {
		if got_ := dirPermFor(c_.in); got_ != c_.want {
			t.Errorf("dirPermFor(%04o) = %04o, want %04o", c_.in, got_, c_.want)
		}
	}
}

// The private key must land on disk as 0600, including when it overwrites an
// existing world-readable file from a previous version.
func TestCopyFileAppliesPermToFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir_ := t.TempDir()
	src_ := filepath.Join(dir_, "src.pem")
	if err := os.WriteFile(src_, []byte("KEY"), 0600); err != nil {
		t.Fatal(err)
	}

	dst_ := filepath.Join(dir_, "nested", "key.pem")
	if err := CopyFile(src_, dst_, 0600); err != nil {
		t.Fatal(err)
	}
	info_, err := os.Stat(dst_)
	if err != nil {
		t.Fatal(err)
	}
	if got_ := info_.Mode().Perm(); got_ != 0600 {
		t.Errorf("key mode = %04o, want 0600", got_)
	}
	if dirInfo_, err := os.Stat(filepath.Dir(dst_)); err != nil {
		t.Fatal(err)
	} else if got_ := dirInfo_.Mode().Perm(); got_ != 0700 {
		t.Errorf("dir mode = %04o, want 0700", got_)
	}

	// Overwriting a permissive leftover must tighten it, not keep 0644.
	loose_ := filepath.Join(dir_, "loose.pem")
	if err := os.WriteFile(loose_, []byte("OLD"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CopyFile(src_, loose_, 0600); err != nil {
		t.Fatal(err)
	}
	info_, err = os.Stat(loose_)
	if err != nil {
		t.Fatal(err)
	}
	if got_ := info_.Mode().Perm(); got_ != 0600 {
		t.Errorf("overwritten key mode = %04o, want 0600", got_)
	}
	content_, err := os.ReadFile(loose_)
	if err != nil {
		t.Fatal(err)
	}
	// O_TRUNC: no leftovers from the longer previous content.
	if string(content_) != "KEY" {
		t.Errorf("content = %q, want %q", content_, "KEY")
	}
}

// current.yaml maps config ids to certificate hashes and must not be world readable.
func TestWriteCurrentDataPerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	path_ := filepath.Join(t.TempDir(), "current.yaml")
	data_ := &CurrentData{Certs: []CurrentCertData{{CommonName: "1.2.3.4", ConfID: "x", CertID: "hash"}}}
	if err := WriteCurrentData(path_, data_); err != nil {
		t.Fatal(err)
	}
	info_, err := os.Stat(path_)
	if err != nil {
		t.Fatal(err)
	}
	if got_ := info_.Mode().Perm(); got_ != 0600 {
		t.Errorf("current.yaml mode = %04o, want 0600", got_)
	}
	back_, err := ReadCurrentData(path_)
	if err != nil {
		t.Fatal(err)
	}
	if len(back_.Certs) != 1 || back_.Certs[0].CertID != "hash" {
		t.Errorf("round trip = %+v", back_.Certs)
	}
}
