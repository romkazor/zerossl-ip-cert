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
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// DefaultRPS is the request rate applied when a Client does not set one.
	DefaultRPS = 5
	// DefaultTimeout bounds a single API call, including connect and body read.
	DefaultTimeout = 60 * time.Second
	// DefaultMaxRetries bounds how often a 429 response is retried.
	DefaultMaxRetries = 5
	// maxRetryDelay caps the backoff between two retries.
	maxRetryDelay = 60 * time.Second
	// maxErrorBodyLen caps how much of a failing body is quoted in an error.
	maxErrorBodyLen = 512
)

// Client is a client for ZeroSSL.
// Refer: https://zerossl.com/documentation/api
type Client struct {
	ApiKey string // API key
	// HTTPClient performs the requests. Optional: a client with DefaultTimeout is
	// installed on first use, so a bare &Client{ApiKey: k} stays usable.
	HTTPClient *http.Client
	// MaxRetries bounds 429 retries. Optional, DefaultMaxRetries when zero;
	// a negative value disables retrying.
	MaxRetries int
	limiter    *rate.Limiter
	mu         sync.Mutex
}

// NewClient initializes a new ZeroSSL client with rate limiting.
func NewClient(apiKey string, rps int) *Client {
	if rps <= 0 {
		rps = DefaultRPS
	}
	return &Client{
		ApiKey:     apiKey,
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
		MaxRetries: DefaultMaxRetries,
		limiter:    rate.NewLimiter(rate.Limit(rps), rps), // rps requests per second
	}
}

// deps lazily fills in the optional fields, so that a zero-value Client works.
func (c *Client) deps() (*rate.Limiter, *http.Client, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.limiter == nil {
		c.limiter = rate.NewLimiter(rate.Limit(DefaultRPS), DefaultRPS)
	}
	if c.HTTPClient == nil {
		// Without an explicit timeout a hung API call would block forever.
		c.HTTPClient = &http.Client{Timeout: DefaultTimeout}
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = DefaultMaxRetries
	}
	return c.limiter, c.HTTPClient, c.MaxRetries
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	limiter_, httpClient_, maxRetries_ := c.deps()

	for attempt_ := 0; ; attempt_++ {
		if err := limiter_.Wait(req.Context()); err != nil {
			return nil, err
		}
		resp, err := httpClient_.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}
		delay_ := retryDelay(resp, attempt_)
		resp.Body.Close()
		if attempt_ >= maxRetries_ {
			return nil, fmt.Errorf("ZeroSSL API rate limit exceeded, giving up after %d attempts", attempt_+1)
		}
		// The body of the previous attempt is already drained, so it has to be
		// rebuilt before replaying the request.
		if req.GetBody != nil {
			if req.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		log.Printf("Rate limit exceeded, retrying in %v (attempt %d/%d)\n", delay_, attempt_+1, maxRetries_)
		select {
		case <-time.After(delay_):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

// retryDelay honours Retry-After when present, otherwise backs off exponentially.
func retryDelay(resp *http.Response, attempt int) time.Duration {
	if v_ := resp.Header.Get("Retry-After"); v_ != "" {
		if secs_, err := strconv.Atoi(strings.TrimSpace(v_)); err == nil && secs_ >= 0 {
			return capDelay(time.Duration(secs_) * time.Second)
		}
		if when_, err := http.ParseTime(v_); err == nil {
			return capDelay(time.Until(when_))
		}
	}
	return capDelay(2 * time.Second << uint(attempt))
}

func capDelay(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	if d > maxRetryDelay {
		return maxRetryDelay
	}
	return d
}

// decodeJSON reads resp into out. It turns both HTTP level failures and the
// application level error object -- which ZeroSSL serves with HTTP 200 -- into
// a Go error.
func decodeJSON(resp *http.Response, out interface{}) error {
	body_, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// ZeroSSL describes the failure in the body on both paths: a 401 carries the
	// same {"success":false,"error":{...}} shape as an HTTP 200 rejection, and it
	// reads far better than a bare status code.
	if apiErr_ := embeddedError(body_); apiErr_ != nil {
		return apiErr_
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ZeroSSL API returned status code %d: %s",
			resp.StatusCode, truncateBody(body_))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body_, out)
}

// embeddedError extracts the "error" object ZeroSSL returns alongside HTTP 200.
func embeddedError(body []byte) *ApiErrorModel {
	var probe_ struct {
		Error *ApiErrorModel `json:"error"`
	}
	if err := json.Unmarshal(body, &probe_); err != nil {
		return nil
	}
	if probe_.Error == nil || (probe_.Error.Code == 0 && probe_.Error.Type == "") {
		return nil
	}
	return probe_.Error
}

func truncateBody(body []byte) string {
	s_ := strings.TrimSpace(string(body))
	if len(s_) > maxErrorBodyLen {
		return s_[:maxErrorBodyLen] + "..."
	}
	return s_
}

// GetCert returns a certificate.
func (c *Client) GetCert(id string) (cert CertificateInfoModel, err error) {
	req := ApiReqFactory.GetCertificate(c.ApiKey, id)
	resp, err := c.doRequest(req)
	if err != nil {
		return CertificateInfoModel{}, err
	}
	defer resp.Body.Close()

	if err = decodeJSON(resp, &cert); err != nil {
		return CertificateInfoModel{}, err
	}
	return
}

// CreateCert creates a certificate with the given parameters. replacementFor is
// the hash of the certificate being renewed and may be empty for a fresh issue.
func (c *Client) CreateCert(domains, csr, days, isStrictDomains, replacementFor string) (cert CertificateInfoModel, err error) {
	req := ApiReqFactory.CreateCertificate(c.ApiKey, domains, csr, days, isStrictDomains, replacementFor)
	resp, err := c.doRequest(req)
	if err != nil {
		return CertificateInfoModel{}, err
	}
	defer resp.Body.Close()

	if err = decodeJSON(resp, &cert); err != nil {
		return CertificateInfoModel{}, err
	}
	return
}

// CancelCert cancels a certificate. Only certificates in draft or
// pending_validation status can be cancelled.
func (c *Client) CancelCert(id string) (err error) {
	req := ApiReqFactory.CancelCertificate(c.ApiKey, id)
	return c.doActionRequest(req)
}

// RevokeCert revokes an issued certificate, freeing up the account quota slot it
// occupies. Only certificates in issued status can be revoked; once a certificate
// has expired neither cancel nor revoke works on it any more. Pass a reason from
// RevokeReason, or an empty string for the ZeroSSL default.
func (c *Client) RevokeCert(id, reason string) (err error) {
	req := ApiReqFactory.RevokeCertificate(c.ApiKey, id, reason)
	return c.doActionRequest(req)
}

// doActionRequest performs a request whose response is a plain acknowledgement.
func (c *Client) doActionRequest(req *http.Request) (err error) {
	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result_ ActionResultModel
	if err = decodeJSON(resp, &result_); err != nil {
		return err
	}
	return result_.Err()
}

// VerifyDomains verifies domains of specified certificate with given validation info.
func (c *Client) VerifyDomains(certID, validationMethod, validationEmail string) (verifyDomainsRsp VerifyDomainsModel, err error) {
	req := ApiReqFactory.VerifyDomains(c.ApiKey, certID, validationMethod, validationEmail)
	resp, err := c.doRequest(req)
	if err != nil {
		return VerifyDomainsModel{}, err
	}
	defer resp.Body.Close()

	// NOTICE: no embedded-error check here. For HTTP_CSR_HASH ZeroSSL always
	// answers success:false with an error object, so decodeJSON would reject
	// every perfectly normal verification response.
	body_, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerifyDomainsModel{}, err
	}
	if resp.StatusCode >= 400 {
		return VerifyDomainsModel{}, fmt.Errorf("ZeroSSL API returned status code %d: %s",
			resp.StatusCode, truncateBody(body_))
	}
	if err = json.Unmarshal(body_, &verifyDomainsRsp); err != nil {
		return VerifyDomainsModel{}, err
	}
	return
}

// VerificationStatus returns the verification status of a certificate.
func (c *Client) VerificationStatus(certID string) (verificationStatusRsp VerificationStatusModel, err error) {
	req := ApiReqFactory.VerificationStatus(c.ApiKey, certID)
	resp, err := c.doRequest(req)
	if err != nil {
		return VerificationStatusModel{}, err
	}
	defer resp.Body.Close()

	if err = decodeJSON(resp, &verificationStatusRsp); err != nil {
		return VerificationStatusModel{}, err
	}
	return
}

// DownloadCertInline returns the certificate in PEM format.
func (c *Client) DownloadCertInline(certID, includeCrossSigned string) (cert CertificateContentModel, err error) {
	req := ApiReqFactory.DownloadCertificateInline(c.ApiKey, certID, includeCrossSigned)
	resp, err := c.doRequest(req)
	if err != nil {
		return CertificateContentModel{}, err
	}
	defer resp.Body.Close()

	if err = decodeJSON(resp, &cert); err != nil {
		return CertificateContentModel{}, err
	}
	return
}

// ListCerts returns a list of certificates with optional filters.
func (c *Client) ListCerts(status, search, limit, page string) (listCertsRsp ListCertsModel, err error) {
	req := ApiReqFactory.ListCertificates(c.ApiKey, status, search, limit, page)
	resp, err := c.doRequest(req)
	if err != nil {
		return ListCertsModel{}, err
	}
	defer resp.Body.Close()

	if err = decodeJSON(resp, &listCertsRsp); err != nil {
		return ListCertsModel{}, err
	}
	return
}

// // CleanUnfinished cleans up unfinished certificates.
// func (c *Client) CleanUnfinished() (err error) {
// 	log.Println("Cleaning unfinished certificates")
// 	perPage := 100
// 	max := 1
// 	for page := 1; page <= max; page++ {
// 		certs, err := c.ListCerts("draft,pending_validation", "", strconv.Itoa(perPage), strconv.Itoa(page))
// 		max = certs.TotalCount / perPage
// 		log.Printf("page: %d max: %d ResultCount: %d TotalCount: %d", page, max, certs.ResultCount, certs.TotalCount)
// 		if err != nil {
// 			log.Println(err)
// 			break
// 		}
// 		for _, cert := range certs.Results {
// 			if cert.Status == CertStatus.Draft || cert.Status == CertStatus.PendingValidation {
// 				log.Printf("Cleaning %s in %s status, id %s", cert.CommonName, cert.Status, cert.ID)
// 				err = c.CancelCert(cert.ID)
// 				if err != nil {
// 					log.Println(err)
// 				}
// 			}
// 		}
// 	}
// 	return
// }

// CleanUnfinished cleans up unfinished certificates.
func (c *Client) CleanUnfinished() (err error) {
	log.Println("Cleaning unfinished certificates")

	const perPage = 100
	// Cancelling removes certificates from the draft,pending_validation result
	// set, so the window shifts under us: advancing the page number would skip
	// entries. Always re-read the first page instead, and stop when either the
	// page comes back empty or a full sweep cancelled nothing.
	for round_ := 0; ; round_++ {
		certs, err := c.ListCerts("draft,pending_validation", "", strconv.Itoa(perPage), "1")
		if err != nil {
			log.Println("Error fetching certificates:", err)
			return err
		}
		if certs.ResultCount == 0 || len(certs.Results) == 0 {
			return nil
		}
		log.Printf("Cleaning round %d, ResultCount: %d, TotalCount: %d",
			round_+1, certs.ResultCount, certs.TotalCount)

		cancelled_ := 0
		for _, cert := range certs.Results {
			if cert.Status != CertStatus.Draft && cert.Status != CertStatus.PendingValidation {
				continue
			}
			log.Printf("Cleaning %s in %s status, ID: %s", cert.CommonName, cert.Status, cert.ID)
			if err := c.CancelCert(cert.ID); err != nil {
				log.Println("Error canceling certificate:", err)
				continue
			}
			cancelled_++
		}
		// Nothing moved: either the page holds only certificates we cannot
		// cancel, or every cancel failed. Retrying would loop forever.
		if cancelled_ == 0 {
			return nil
		}
	}
}
