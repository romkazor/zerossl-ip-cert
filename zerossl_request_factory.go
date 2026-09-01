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
	"net/url"
	"strings"
)

// ApiEndpoint is the zerossl api endpoint.
const ApiEndpoint = "api.zerossl.com"

// AuthHeaderPrefix is the only prefix ZeroSSL accepts in the Authorization header.
const AuthHeaderPrefix = "ApiKey "

// UseLegacyQueryAuth additionally sends the access key as the deprecated
// "access_key" query parameter. The header based authentication is always sent,
// so this is only needed to talk to a stale API deployment.
var UseLegacyQueryAuth = false

// setAuth applies authentication to req. The recommended "Authorization: ApiKey <key>"
// header is always set; the deprecated query parameter is added only in legacy mode.
// It must be called before q_ is encoded into the URL.
func setAuth(req *http.Request, q_ url.Values, accessKey string) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Authorization", AuthHeaderPrefix+accessKey)
	if UseLegacyQueryAuth {
		q_.Add("access_key", accessKey)
	}
}

// newFormBody attaches a urlencoded form body to req, keeping it replayable on retry.
func newFormBody(req *http.Request, bodyForm_ url.Values) {
	encoded_ := bodyForm_.Encode()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(encoded_))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(encoded_)), nil
	}
	req.Body, _ = req.GetBody()
}

// ApiReqFactory is a factory for creating API requests.
var ApiReqFactory = struct {
	// Request of creating a new certificate.
	CreateCertificate func(accessKey, certificateDomains, certificateCsr, certificateValidityDays,
		strictDomains, replacementForCertificate string) (req *http.Request)
	// Request of listing all certificates.
	ListCertificates func(accessKey, certificateStatus, search, limit, page string) (req *http.Request)
	// Request of getting a certificate.
	GetCertificate func(accessKey, id string) (req *http.Request)
	// Request of verifying a certificate.
	VerifyDomains func(accessKey, certificateId, validationMethod, validationEmail string) (req *http.Request)
	// Request of verification status.
	VerificationStatus func(accessKey, id string) (req *http.Request)
	// Request of cancelation a certificate.
	CancelCertificate func(accessKey, id string) (req *http.Request)
	// Request of revoking an issued certificate.
	RevokeCertificate func(accessKey, id, reason string) (req *http.Request)
	// Request of downloading a certificate.
	DownloadCertificateInline func(accessKey, certID, includeCrossSigned string) (req *http.Request)
}{
	CreateCertificate: func(accessKey, certificateDomains, certificateCsr, certificateValidityDays,
		strictDomains, replacementForCertificate string) (req *http.Request) {
		req = &http.Request{Method: http.MethodPost}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		url_.RawQuery = q_.Encode()
		req.URL = url_
		bodyForm_ := make(url.Values)
		if certificateDomains != "" {
			bodyForm_.Add("certificate_domains", certificateDomains)
		}
		if certificateCsr != "" {
			bodyForm_.Add("certificate_csr", certificateCsr)
		}
		if certificateValidityDays != "" {
			bodyForm_.Add("certificate_validity_days", certificateValidityDays)
		}
		if strictDomains != "" {
			bodyForm_.Add("strict_domains", strictDomains)
		}
		// Marks the new certificate as the replacement of an existing one, so that
		// ZeroSSL tracks it as a renewal instead of an unrelated certificate.
		if replacementForCertificate != "" {
			bodyForm_.Add("replacement_for_certificate", replacementForCertificate)
		}
		if len(bodyForm_) > 0 {
			newFormBody(req, bodyForm_)
		}
		return
	},
	ListCertificates: func(accessKey, certificateStatus, search, limit, page string) (req *http.Request) {
		req = &http.Request{Method: http.MethodGet}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		if certificateStatus != "" {
			q_.Add("certificate_status", certificateStatus)
		}
		if search != "" {
			q_.Add("search", search)
		}
		if limit != "" {
			q_.Add("limit", limit)
		}
		if page != "" {
			q_.Add("page", page)
		}
		url_.RawQuery = q_.Encode()
		req.URL = url_
		// // Print the entire URL object.
		// fmt.Printf("%+v\n", *url_) //Dereference the pointer to print the struct.

		// // Print individual components.
		// fmt.Println("Scheme:", url_.Scheme)
		// fmt.Println("User:", url_.User)
		// if url_.User != nil {
		// 	fmt.Println("Username:", url_.User.Username())
		// 	password, _ := url_.User.Password() //Password returns password and a bool if password was set.
		// 	fmt.Println("Password:", password)
		// }
		// fmt.Println("Host:", url_.Host)
		// fmt.Println("Hostname:", url_.Hostname())
		// fmt.Println("Port:", url_.Port())
		// fmt.Println("Path:", url_.Path)
		// fmt.Println("RawQuery:", url_.RawQuery)
		// fmt.Println("Fragment:", url_.Fragment)

		// //Print the query parameters as a map
		// queryParams := url_.Query()
		// fmt.Println("Query Parameters:", queryParams)

		// //Constructing a URL from a URL struct.
		// constructedURL := url_.String()
		// fmt.Println("Constructed URL:", constructedURL)
		return
	},
	GetCertificate: func(accessKey, id string) (req *http.Request) {
		req = &http.Request{Method: http.MethodGet}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates/" + id}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		url_.RawQuery = q_.Encode()
		req.URL = url_
		return
	},
	VerifyDomains: func(accessKey, certificateId, validationMethod, validationEmail string) (req *http.Request) {
		req = &http.Request{Method: http.MethodPost}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates/" + certificateId + "/challenges"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		url_.RawQuery = q_.Encode()
		req.URL = url_
		bodyForm_ := make(url.Values)
		if validationMethod != "" {
			bodyForm_.Add("validation_method", validationMethod)
		}
		if validationEmail != "" {
			bodyForm_.Add("validation_email", validationEmail)
		}
		if len(bodyForm_) > 0 {
			newFormBody(req, bodyForm_)
		}
		return
	},
	VerificationStatus: func(accessKey, id string) (req *http.Request) {
		req = &http.Request{Method: http.MethodGet}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates/" + id + "/status"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		url_.RawQuery = q_.Encode()
		req.URL = url_
		return
	},
	CancelCertificate: func(accessKey, id string) (req *http.Request) {
		req = &http.Request{Method: http.MethodPost}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates/" + id + "/cancel"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		url_.RawQuery = q_.Encode()
		req.URL = url_
		return
	},
	RevokeCertificate: func(accessKey, id, reason string) (req *http.Request) {
		req = &http.Request{Method: http.MethodPost}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates/" + id + "/revoke"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		url_.RawQuery = q_.Encode()
		req.URL = url_
		bodyForm_ := make(url.Values)
		if reason != "" {
			bodyForm_.Add("reason", reason)
		}
		if len(bodyForm_) > 0 {
			newFormBody(req, bodyForm_)
		}
		return
	},
	DownloadCertificateInline: func(accessKey, certID, includeCrossSigned string) (req *http.Request) {
		req = &http.Request{Method: http.MethodGet}
		url_ := &url.URL{Scheme: "https", Host: ApiEndpoint, Path: "/certificates/" + certID + "/download/return"}
		q_ := make(url.Values)
		setAuth(req, q_, accessKey)
		if includeCrossSigned != "" {
			q_.Add("include_cross_signed", includeCrossSigned)
		}
		url_.RawQuery = q_.Encode()
		req.URL = url_
		return
	},
}
