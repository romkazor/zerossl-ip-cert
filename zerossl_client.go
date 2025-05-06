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
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Client is a client for ZeroSSL.
// Refer: https://zerossl.com/documentation/api
type Client struct {
	ApiKey  string // API key
	limiter *rate.Limiter
	mu      sync.Mutex
}

// NewClient initializes a new ZeroSSL client with rate limiting.
func NewClient(apiKey string, rps int) *Client {
	return &Client{
		ApiKey:  apiKey,
		limiter: rate.NewLimiter(rate.Limit(rps), rps), // rps requests per second
	}
}

func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	// Ensure limiter is initialized to prevent nil pointer dereference
	c.mu.Lock()
	if c.limiter == nil {
		c.limiter = rate.NewLimiter(rate.Limit(5), 5) // Default to 5 rps
	}
	c.mu.Unlock()

	for {
		if err := c.limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 429 {
			log.Println("Rate limit exceeded, retrying after delay...")
			time.Sleep(2 * time.Second) // Backoff before retrying
			continue
		}
		return resp, nil
	}
}

// GetCert returns a certificate.
func (c *Client) GetCert(id string) (cert CertificateInfoModel, err error) {
	req := ApiReqFactory.GetCertificate(c.ApiKey, id)
	resp, err := c.doRequest(req)
	if err != nil {
		return CertificateInfoModel{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return CertificateInfoModel{}, fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&cert)
	if err != nil {
		return CertificateInfoModel{}, err
	}
	return
}

// CreateCert creates a certificate with the given parameters.
func (c *Client) CreateCert(domains, csr, days, isStrictDomains string) (cert CertificateInfoModel, err error) {
	req := ApiReqFactory.CreateCertificate(c.ApiKey, domains, csr, days, isStrictDomains)
	resp, err := c.doRequest(req)
	if err != nil {
		return CertificateInfoModel{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return CertificateInfoModel{}, fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&cert)
	if err != nil {
		return CertificateInfoModel{}, err
	}
	return
}

// CancelCert cancels a certificate.
func (c *Client) CancelCert(id string) (err error) {
	req := ApiReqFactory.CancelCertificate(c.ApiKey, id)
	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}
	return
}

// VerifyDomains verifies domains of specified certificate with given validation info.
func (c *Client) VerifyDomains(certID, validationMethod, validationEmail string) (verifyDomainsRsp VerifyDomainsModel, err error) {
	req := ApiReqFactory.VerifyDomains(c.ApiKey, certID, validationMethod, validationEmail)
	resp, err := c.doRequest(req)
	if err != nil {
		return VerifyDomainsModel{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return VerifyDomainsModel{}, fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&verifyDomainsRsp)
	if err != nil {
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

	if resp.StatusCode >= 400 {
		return VerificationStatusModel{}, fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&verificationStatusRsp)
	if err != nil {
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

	if resp.StatusCode >= 400 {
		return CertificateContentModel{}, fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&cert)
	if err != nil {
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

	if resp.StatusCode >= 400 {
		return ListCertsModel{}, fmt.Errorf("ZeroSSL API returned status code %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&listCertsRsp)
	if err != nil {
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
	page := 1
	max := 1

	for page <= max {
		certs, err := c.ListCerts("draft,pending_validation", "", strconv.Itoa(perPage), strconv.Itoa(page))
		if err != nil {
			log.Println("Error fetching certificates:", err)
			break
		}

		// Update max pages correctly
		if certs.TotalCount > 0 {
			max = (certs.TotalCount + perPage - 1) / perPage // Ensures rounding up
		}

		log.Printf("Processing page %d/%d, ResultCount: %d, TotalCount: %d", page, max, certs.ResultCount, certs.TotalCount)

		for _, cert := range certs.Results {
			if cert.Status == CertStatus.Draft || cert.Status == CertStatus.PendingValidation {
				log.Printf("Cleaning %s in %s status, ID: %s", cert.CommonName, cert.Status, cert.ID)
				if err := c.CancelCert(cert.ID); err != nil {
					log.Println("Error canceling certificate:", err)
				}
			}
		}

		// Stop if there are no more certificates to process
		if certs.ResultCount == 0 {
			break
		}

		page++ // Move to next page
	}

	return nil
}
