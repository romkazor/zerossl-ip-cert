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
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	zerosslIPCert "github.com/tinkernels/zerossl-ip-cert"
)

// validationFiles maps the URL path of every file validation challenge to the
// content ZeroSSL expects to find there.
func validationFiles(certInfo *zerosslIPCert.CertificateInfoModel) (map[string]string, error) {
	files_ := make(map[string]string)
	for domain_, method_ := range certInfo.Validation.OtherMethods {
		if method_.FileValidationUrlHttp == "" {
			continue
		}
		url_, err := url.Parse(method_.FileValidationUrlHttp)
		if err != nil {
			return nil, fmt.Errorf("cannot parse validation url for %v: %w", domain_, err)
		}
		// Always real newlines here: unlike the hook path there is no environment
		// variable in between, so the Windows space-joining workaround is moot.
		files_[url_.Path] = strings.Join(method_.FileValidationContent, "\n")
	}
	if len(files_) == 0 {
		return nil, fmt.Errorf("no http file validation challenge in cert info")
	}
	return files_, nil
}

// validationListenAddr picks the address the built-in server binds to. ZeroSSL
// only ever connects to port 80, so that is the default; listenOverride wins
// when the config sets it.
func validationListenAddr(certInfo *zerosslIPCert.CertificateInfoModel, listenOverride string) string {
	if listenOverride != "" {
		return listenOverride
	}
	port_ := "80"
	for _, method_ := range certInfo.Validation.OtherMethods {
		if method_.FileValidationUrlHttp == "" {
			continue
		}
		if url_, err := url.Parse(method_.FileValidationUrlHttp); err == nil {
			if p_ := url_.Port(); p_ != "" {
				port_ = p_
			}
		}
		break
	}
	return ":" + port_
}

// newValidationHandler serves the challenge files and nothing else.
func newValidationHandler(files map[string]string) http.Handler {
	mux_ := http.NewServeMux()
	mux_.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		content_, ok_ := files[r.URL.Path]
		if !ok_ {
			log.Printf("validation server: 404 for %v\n", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		// ZeroSSL requires a plain 200 with no redirect.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(content_)); err != nil {
			log.Printf("validation server: failed to write %v: %v\n", r.URL.Path, err)
			return
		}
		log.Printf("validation server: served %v\n", r.URL.Path)
	})
	return mux_
}

// serveValidationFiles starts the built-in validation server on ln. The returned
// function shuts it down and must be called by the caller.
func serveValidationFiles(ln net.Listener, files map[string]string) func() {
	srv_ := &http.Server{
		Handler:           newValidationHandler(files),
		ReadHeaderTimeout: 10 * time.Second,
	}
	done_ := make(chan struct{})
	go func() {
		defer close(done_)
		err := srv_.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("validation server stopped: %v\n", err)
		}
	}()
	return func() {
		ctx_, cancel_ := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel_()
		if err := srv_.Shutdown(ctx_); err != nil {
			log.Printf("validation server shutdown: %v\n", err)
			_ = srv_.Close()
		}
		// Shutdown only closes listeners Serve has already registered. If stop is
		// called before the goroutine got that far, the socket would stay bound.
		_ = ln.Close()
		<-done_
	}
}

// startValidationServer brings up the built-in HTTP validation server for
// certInfo. It is the fallback used when no verifyHook is configured.
func startValidationServer(certInfo *zerosslIPCert.CertificateInfoModel, listenOverride string) (stop func(), err error) {
	files_, err := validationFiles(certInfo)
	if err != nil {
		return nil, err
	}
	addr_ := validationListenAddr(certInfo, listenOverride)
	ln_, err := net.Listen("tcp", addr_)
	if err != nil {
		return nil, fmt.Errorf("validation server cannot listen on %v: %w", addr_, err)
	}
	for path_ := range files_ {
		log.Printf("validation server listening on %v, serving %v\n", addr_, path_)
	}
	return serveValidationFiles(ln_, files_), nil
}
