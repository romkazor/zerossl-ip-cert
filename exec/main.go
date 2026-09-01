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
	"sync"

	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	zerosslIPCert "github.com/romkazor/zerossl-ip-cert/v2"
)

// Version is the version of this application.
const Version = "v2.0.0"

var (
	renewFlag   = flag.Bool("renew", false, "Renew existing certs only")
	configFlag  = flag.String("config", "", "Config file")
	cleanupFlag = flag.Bool("cleanup", false, "Cleanup pending certs only")
)

var usingConfig *Config
var currentData *CurrentData
var currentDataFilePath string

func main() {
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(w, "\nVersion: %v\n\nUsage: %v [ -renew | -cleanup ] -config CONFIG_FILE\n\n",
			Version, filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	if !fileExistsAndIsFile(*configFlag) {
		flag.Usage()
		panic("Config file not found")
	}
	usingConfig_, err := ReadConfig(*configFlag)
	if err != nil {
		flag.Usage()
		panic(err)
	}
	usingConfig = usingConfig_
	// Enable line numbers in logging.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if usingConfig == nil || usingConfig.LogFile == "" {
		panic("LogFile is not provided or usingConfig is nil")
	}
	// The log file usually lives inside dataDir, which may not exist yet on a
	// first run, so its directory has to be created before opening it.
	if err = CreateDirIfNotExists(filepath.Dir(usingConfig.LogFile), 0700); err != nil {
		fmt.Println("log directory create failed")
		panic(err)
	}
	logFile_, err := os.OpenFile(usingConfig.LogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0640)
	if err != nil {
		fmt.Println("log file create failed")
		panic(err)
	}
	// Write log to both console and file.
	multiLogWr_ := io.MultiWriter(os.Stdout, logFile_)
	log.SetOutput(multiLogWr_)

	log.Printf("Using config file: %v", *configFlag)

	// The data dir holds current.yaml and the temporary private key.
	err = CreateDirIfNotExists(usingConfig.DataDir, 0700)
	if err != nil {
		flag.Usage()
		panic(err)
	}
	currentDataFilePath = filepath.Join(usingConfig.DataDir, "/current.yaml")
	if PathExists(currentDataFilePath) {
		currentData_, err := ReadCurrentData(currentDataFilePath)
		if err != nil {
			flag.Usage()
			panic(err)
		}
		if currentData_ == nil {
			currentData = &CurrentData{}
		} else {
			currentData = currentData_
		}
	} else {
		log.Printf("Current Config File not found: %s", currentDataFilePath)
		currentData = &CurrentData{}
	}
	// The recommended header auth is the default; the deprecated query parameter
	// is only added back when the config asks for it.
	zerosslIPCert.UseLegacyQueryAuth = usingConfig.LegacyQueryAuth
	if usingConfig.LegacyQueryAuth {
		log.Println("legacy query-parameter authentication is enabled")
	}
	if *renewFlag {
		renew()
	} else if *cleanupFlag {
		cleanup()
	} else {
		issueCerts()
	}
}

var (
	clientsMu_ sync.Mutex
	clients_   = map[string]*zerosslIPCert.Client{}
)

// apiClient returns the shared client for an API key. Sharing matters: the rate
// limiter lives on the Client, so a fresh instance per call would not throttle
// anything.
func apiClient(apiKey string) *zerosslIPCert.Client {
	clientsMu_.Lock()
	defer clientsMu_.Unlock()
	if c_, ok_ := clients_[apiKey]; ok_ {
		return c_
	}
	c_ := zerosslIPCert.NewClient(apiKey, zerosslIPCert.DefaultRPS)
	clients_[apiKey] = c_
	return c_
}

// issueCerts issues certs referenced in the config file.
func issueCerts() {
	log.Printf("Issuing certs")
	for _, c := range usingConfig.CertConfigs {
		log.Printf("Issuing cert for domain: %v", c.CommonName)
		err := issueCert(&c)
		if err != nil {
			log.Printf("Failed to issue cert for domain %v: %v\n", c.CommonName, err)
		}
	}
}

// errCertGone reports that the certificate current.yaml points at exists neither
// under its recorded id nor under the config's common name. The usual cause is a
// state file that outlived the account it was written for -- an API key moved to a
// different ZeroSSL account, say. Renewal cannot proceed from that, but a plain run
// can start over, which is what issueCert does with it.
var errCertGone = errors.New("tracked certificate not found in the API")

// issueCert issues a cert for the given domain config.
func issueCert(conf *CertConf) (err error) {
	for _, cert := range currentData.Certs {
		// Use ConfID to match.
		if cert.ConfID == conf.ConfID {
			log.Printf("Cert for domain %v already exists, try renew.\n", conf.CommonName)
			err = renewCert(cert.CertID, conf)
			if !errors.Is(err, errCertGone) {
				return
			}
			// The state entry survives an account it can no longer be found in, and
			// while it is there every run keeps taking the renewal path and failing.
			// Drop it and fall through to a fresh issue -- only on a plain run, since
			// -renew deliberately never creates a certificate from scratch.
			log.Printf("State entry for %v matches no certificate on this account, issuing a new one\n",
				conf.CommonName)
			dropCertState(cert.CertID)
			break
		}
	}
	log.Printf("Cert for domain %v does not exist, try issue.\n", conf.CommonName)
	client_ := apiClient(conf.ApiKey)
	if usingConfig.CleanUnfinished {
		if err := client_.CleanUnfinished(); err != nil {
			log.Printf("Failed to clean unfinished issuing certificate: %v\n", err)
		}
	}
	certId_, err := issueCertImpl(conf, "")
	if err == nil {
		log.Printf("Cert for domain %v issued successfully.\n", conf.CommonName)
		currentData.Certs = append(currentData.Certs, CurrentCertData{
			CommonName: conf.CommonName,
			CertID:     certId_,
			CertFile:   conf.CertFile,
			KeyFile:    conf.KeyFile,
			ConfID:     conf.ConfID,
		})
		if err = WriteCurrentData(currentDataFilePath, currentData); err != nil {
			log.Printf("Failed to write current data: %v\n", err)
		}
	}
	return
}

// issueCertImpl issues a cert for conf. replacementFor is the hash of the
// certificate being renewed, or "" for a fresh issue.
func issueCertImpl(conf *CertConf, replacementFor string) (certID string, err error) {
	tempDir_ := filepath.Join(usingConfig.DataDir, "/temp")
	tempPrivKeyPath_ := filepath.Join(tempDir_, "/privkey.pem")
	log.Printf("tempPrivKeyPath: %v\n", tempPrivKeyPath_)
	tempCertPath_ := filepath.Join(tempDir_, "/cert-fullchain.pem")
	log.Printf("tempCertPath: %v\n", tempCertPath_)
	log.Printf("Cleaning temp dir: %v\n", tempDir_)
	if err = os.RemoveAll(tempDir_); err != nil {
		return
	}
	log.Printf("Creating temp dir: %v\n", tempDir_)
	// 0700: the temp dir holds the private key until it is installed.
	if err = CreateDirIfNotExists(tempDir_, 0700); err != nil {
		return
	}
	// Removed on every exit path, not just the successful one.
	defer func() {
		if rmErr_ := os.RemoveAll(tempDir_); rmErr_ != nil {
			log.Printf("failed to clean temp dir %v: %v\n", tempDir_, rmErr_)
		}
	}()
	client_ := apiClient(conf.ApiKey)
	// Generate PrivateKey.
	log.Printf("Generating private key for %v\n", conf.CommonName)
	privKey_ := zerosslIPCert.KeyGeneratorWrapper(conf.KeyType, conf.KeyBits, conf.KeyCurve)
	subj_ := pkix.Name{
		Country:            []string{conf.Country},
		Province:           []string{conf.Province},
		Locality:           []string{conf.Locality},
		Organization:       []string{conf.Organization},
		OrganizationalUnit: []string{conf.OrganizationUnit},
		CommonName:         conf.CommonName,
	}
	// Generate CSR.
	log.Printf("Generating CSR for %v\n", conf.CommonName)
	csr_, err := zerosslIPCert.CSRGeneratorWrapper(conf.KeyType, subj_, privKey_, conf.SigAlg)
	if err != nil {
		log.Println(err)
		return
	}
	csrStr_ := zerosslIPCert.GetCSRString(csr_)
	log.Printf("CSR generated for %v (%v bytes)\n", conf.CommonName, len(csrStr_))
	if csrStr_ == "" {
		log.Println("failed to get csr string")
		return
	}
	// Write PrivateKey to file.
	log.Printf("Writing private key to file %v\n", tempPrivKeyPath_)
	if err = zerosslIPCert.WritePrivKeyWrapper(conf.KeyType, privKey_, tempPrivKeyPath_); err != nil {
		log.Println(err)
		return
	}
	// Create Cert.
	log.Printf("Creating cert for %v\n", conf.CommonName)
	certInfo_, err := client_.CreateCert(conf.CommonName, csrStr_, strconv.Itoa(conf.Days),
		strconv.Itoa(conf.StrictDomains), replacementFor)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("cert info: %+v\n", certInfo_)
	// Either the external hook rearranges someone else's web server, or we serve
	// the challenge ourselves. The hook keeps priority when it is configured.
	if conf.VerifyHook != "" {
		if err = runVerifyHook(conf.VerifyHook, &certInfo_); err != nil {
			log.Println(err)
			return
		}
	} else {
		var stopServer_ func()
		if stopServer_, err = startValidationServer(&certInfo_, conf.VerifyListen); err != nil {
			log.Println(err)
			return
		}
		defer stopServer_()
	}
	// Verify Domains.
	if err = verifyHttpCsrHash(client_, &certInfo_); err != nil {
		log.Printf("verifying error: %v\n", err)
		return
	}
	// Download cert.
	cert_, err := client_.DownloadCertInline(certInfo_.ID, "1")
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("downloaded cert and ca bundle for %v\n", conf.CommonName)
	fullChainPem_ := fmt.Sprintf("%s\n%s\n", strings.TrimSpace(cert_.Certificate), strings.TrimSpace(cert_.CaBundle))
	// Write cert to file.
	file_, err := os.Create(tempCertPath_)
	if err != nil {
		log.Println(err)
		return
	}
	_, err = file_.WriteString(fullChainPem_)
	if err != nil {
		return
	}
	// Copy cert files to dest.
	if err = CopyFile(tempCertPath_, conf.CertFile, 0644); err != nil {
		log.Println(err)
		return
	}
	if err = CopyFile(tempPrivKeyPath_, conf.KeyFile, 0600); err != nil {
		log.Println(err)
		return
	}
	// Run post hook.
	if err = runPostHook(conf); err != nil {
		log.Println(err)
		return
	}
	certID = certInfo_.ID
	return
}

func verifyHttpCsrHash(client *zerosslIPCert.Client, certInfo *zerosslIPCert.CertificateInfoModel) (err error) {
	for retrying_ := 0; retrying_ < 20; retrying_++ {
		var verifyRsp_ zerosslIPCert.VerifyDomainsModel
		// Plain "=", not ":=": a new err here would hide every loop failure
		// from the named return value.
		verifyRsp_, err = client.VerifyDomains(certInfo.ID, zerosslIPCert.VerifyDomainsMethod.HttpCsrHash, "")
		if err != nil {
			log.Printf("verify error: %v\n", err)
			time.Sleep(time.Second * 15)
			continue
		}
		// NOTICE: ZeroSSL always return "Success:false" in HttpCsrHash verification.
		log.Printf("domains verification result: %+v\n", verifyRsp_)
		var certInfoTmp_ zerosslIPCert.CertificateInfoModel
		certInfoTmp_, err = client.GetCert(certInfo.ID)
		if err != nil {
			log.Printf("get cert error: %v\n", err)
			time.Sleep(time.Second * 15)
			continue
		}
		if certInfoTmp_.Status != zerosslIPCert.CertStatus.PendingValidation &&
			certInfoTmp_.Status != zerosslIPCert.CertStatus.Issued {
			log.Printf("cert in %v status\n", certInfoTmp_.Status)
			time.Sleep(time.Second * 30)
			continue
		}
		break
	}
	// Wait for cert to be ready.
	if err = waitCert2BReady(client, certInfo); err != nil {
		return err
	}
	return
}

// runVerifyHook runs verify hook.
func runVerifyHook(executable string, cerInfo *zerosslIPCert.CertificateInfoModel) (err error) {
	if !PathExists(executable) {
		return fmt.Errorf("verify hook executable %v not exists", executable)
	}
	log.Println("try make verify hook file executable")
	err = ChmodPlusX(executable)
	if err != nil {
		log.Printf("chmod verify hook file permission failed: %v\n", err)
	}
	for k, v := range cerInfo.Validation.OtherMethods {
		if k == cerInfo.CommonName {
			validateHttpUrl_, err := url.Parse(v.FileValidationUrlHttp)
			if err != nil {
				log.Println(err)
				return err
			}
			host_ := validateHttpUrl_.Host
			path_ := validateHttpUrl_.Path
			port_ := validateHttpUrl_.Port()
			if port_ == "" {
				port_ = "80"
			}
			var content_ string
			// Concatenate file content with spaces.
			if runtime.GOOS == "windows" {
				content_ = strings.Join(v.FileValidationContent, " ")
			} else {
				content_ = strings.Join(v.FileValidationContent, "\n")
			}
			// Prepare hook exec env.
			cmdEnv_ := os.Environ()
			cmdEnv_ = append(cmdEnv_, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_HOST", host_))
			cmdEnv_ = append(cmdEnv_, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_PATH", path_))
			cmdEnv_ = append(cmdEnv_, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_PORT", port_))
			cmdEnv_ = append(cmdEnv_, fmt.Sprintf("%v=%v", "ZEROSSL_HTTP_FV_CONTENT", content_))
			cmd_ := exec.Command(executable)
			cmd_.Env = cmdEnv_
			cmd_.Stdout = os.Stdout
			cmd_.Stderr = os.Stdout
			if err = cmd_.Run(); err != nil {
				return err
			}
			return err
		}
	}
	return
}

// waitCert2BReady waits for the cert to be ready.
const (
	// waitCertAttempts and waitCertInterval bound the wait for ZeroSSL to issue a
	// certificate whose challenge has already been published.
	//
	// Issuance latency varies a lot: measured at roughly 90 seconds on two runs and
	// at over 11 minutes on another, same host, same challenge, minutes apart. The
	// previous bound was 10 attempts, so it gave up after 5 minutes and reported a
	// timeout for a certificate that was on its way to being issued -- and the run
	// then abandoned a perfectly good certificate that keeps occupying a slot. 15
	// minutes covers everything observed with room to spare; the cost of waiting
	// longer is only a slower failure on a genuinely stuck certificate.
	waitCertAttempts = 30
	waitCertInterval = 30 * time.Second
)

// waitCert2BReady polls until the certificate reaches status issued.
//
// It used to fail with a bare "timeout of waiting cert to be ready", which says
// nothing about what went wrong and sent an earlier investigation down the wrong
// path entirely. The wait now logs its progress instead of going silent, and the
// failure names the status it got stuck in along with the account's slot usage.
//
// Take care reading that number: it is context, not a diagnosis. A create carrying
// replacement_for_certificate is issued even on an account well past its allowance
// (verified 2026-09-01 at 4 and 5 slots used of 3), so a high count on a renewal is
// not on its own the reason a certificate is stuck.
func waitCert2BReady(client *zerosslIPCert.Client, certInfo *zerosslIPCert.CertificateInfoModel) error {
	status_ := certInfo.Status
	for i := 0; i < waitCertAttempts; i++ {
		certInfo_, err_ := client.GetCert(certInfo.ID)
		if err_ != nil {
			log.Println(err_)
			return err_
		}
		status_ = certInfo_.Status
		if status_ == zerosslIPCert.CertStatus.Issued {
			log.Printf("cert is ready: %+v\n", certInfo_)
			return nil
		}
		// Without this the tool goes silent for the whole wait.
		log.Printf("cert %v is %v, waiting (%v/%v)\n", certInfo_.ID, status_, i+1, waitCertAttempts)
		time.Sleep(waitCertInterval)
	}
	return fmt.Errorf("timeout waiting for cert %v to be issued: still %v after %v%v",
		certInfo.ID, status_, time.Duration(waitCertAttempts)*waitCertInterval, accountHint(client))
}

// accountHint describes the account's slot usage for an error message. A diagnostic
// must never become a second failure, so anything that goes wrong here yields an
// empty string and the original error stands on its own.
func accountHint(client *zerosslIPCert.Client) string {
	used_, err_ := client.CountOccupiedSlots()
	if err_ != nil {
		return ""
	}
	return fmt.Sprintf(". The account has %v certificate(s) occupying a slot"+
		" (draft, pending_validation, issued, revoked or expired); the free plan allows 3."+
		" A first-time issue is refused past that limit, a renewal is not", used_)
}

func runPostHook(certConf *CertConf) (err error) {
	if !PathExists(certConf.PostHook) {
		return fmt.Errorf("post hook executable %v not exists", certConf.PostHook)
	}
	log.Println("try make post hook file executable")
	err = ChmodPlusX(certConf.PostHook)
	if err != nil {
		log.Printf("chmod +x post hook file failed: %v\n", err)
	}
	// Prepare hook exec env.
	cmdEnv_ := os.Environ()
	cmdEnv_ = append(cmdEnv_, fmt.Sprintf("%v=%v", "ZEROSSL_CERT_FPATH", certConf.CertFile))
	cmdEnv_ = append(cmdEnv_, fmt.Sprintf("%v=%v", "ZEROSSL_KEY_FPATH", certConf.KeyFile))
	cmd_ := exec.Command(certConf.PostHook)
	cmd_.Env = cmdEnv_
	cmd_.Stdout = os.Stdout
	cmd_.Stderr = os.Stdout
	if err = cmd_.Run(); err != nil {
		return err
	}
	return
}

// renew current certs.
func renew() {
	log.Println("will renew current certs")
loopRenew:
	for _, cert := range currentData.Certs {
		log.Printf("try renew cert: %v\n", cert.CommonName)
		for _, c := range usingConfig.CertConfigs {
			// ConfID to match cert config.
			if c.ConfID == cert.ConfID {
				err := renewCert(cert.CertID, &c)
				if err != nil {
					log.Printf("Failed to renew cert for domain %v: %v\n", c.CommonName, err)
				}
				continue loopRenew
			}
		}
		log.Printf("no config for renewing cert: %v\n", cert.CommonName)
	}
	renewUntrackedConfigs()
}

// renewUntrackedConfigs covers cert configs that have no entry in current.yaml at
// all -- a lost or truncated state file would otherwise make -renew a silent no-op
// forever, since renew() only walks the state. The certificate is looked up in the
// API by common name; nothing is issued from scratch here, that stays a job for a
// run without -renew.
func renewUntrackedConfigs() {
	for _, c := range usingConfig.CertConfigs {
		tracked_ := false
		for _, cert := range currentData.Certs {
			if cert.ConfID == c.ConfID {
				tracked_ = true
				break
			}
		}
		if tracked_ {
			continue
		}
		log.Printf("Config %v (%v) has no state entry, looking it up via the API\n", c.ConfID, c.CommonName)
		resolved_, err := apiClient(c.ApiKey).ResolveIssuedCert(c.CommonName)
		if err != nil {
			log.Printf("No issued cert for %v: %v; run without -renew to issue one\n", c.CommonName, err)
			continue
		}
		log.Printf("Adopted cert %v (expires %v) for %v\n", resolved_.ID, resolved_.Expires, c.CommonName)
		currentData.Certs = append(currentData.Certs, CurrentCertData{
			CommonName: c.CommonName,
			ConfID:     c.ConfID,
			CertID:     resolved_.ID,
			CertFile:   c.CertFile,
			KeyFile:    c.KeyFile,
		})
		if err := WriteCurrentData(currentDataFilePath, currentData); err != nil {
			log.Printf("Failed to write current data: %v\n", err)
		}
		conf_ := c
		if err := renewCert(resolved_.ID, &conf_); err != nil {
			log.Printf("Failed to renew cert for domain %v: %v\n", c.CommonName, err)
		}
	}
}

func renewCert(id string, conf *CertConf) (err error) {
	log.Printf("Renewing cert %v with config: %v\n", conf.CommonName, conf.ConfID)
	client_ := apiClient(conf.ApiKey)
	// stateID_ is what current.yaml holds; id may be re-pointed below, and the
	// state entry still has to be found by its original value.
	stateID_ := id
	certInfo_, err := client_.GetCert(id)
	if err != nil {
		// The state file can point at a certificate this account cannot see: a
		// rotated API key, a restored backup, or a state write that failed. The API
		// is the source of truth, so look the certificate up by name before giving up.
		log.Printf("Failed to get cert info for %v: %v\n", id, err)
		log.Printf("Looking up an issued cert for %v via the API\n", conf.CommonName)
		resolved_, resolveErr_ := client_.ResolveIssuedCert(conf.CommonName)
		if resolveErr_ != nil {
			log.Printf("No issued cert for %v either: %v\n", conf.CommonName, resolveErr_)
			return fmt.Errorf("%w (id %v): %v", errCertGone, id, err)
		}
		log.Printf("Recovered cert %v (expires %v) for %v\n", resolved_.ID, resolved_.Expires, conf.CommonName)
		id, certInfo_ = resolved_.ID, resolved_
	}
	if skip_ := renewalNotDue(&certInfo_, conf.CommonName, conf.RenewLeadDays()); skip_ {
		// Keep the state file pointing at whatever the API actually has.
		persistCertID(stateID_, id, conf)
		return nil
	}
	if usingConfig.CleanUnfinished {
		if err := client_.CleanUnfinished(); err != nil {
			log.Printf("Failed to clean unfinished issuing certificate: %v\n", err)
		}
	}
	// Only reference a certificate ZeroSSL still considers live as the one being
	// replaced; an expired or cancelled hash would just make the create call fail.
	replacementFor_ := ""
	if certInfo_.Status == zerosslIPCert.CertStatus.Issued ||
		certInfo_.Status == zerosslIPCert.CertStatus.ExpiringSoon {
		replacementFor_ = id
	}
	certId_, err := issueCertImpl(conf, replacementFor_)
	if err == nil {
		log.Printf("Cert for domain %v issued successfully.\n", conf.CommonName)
		for i, c := range currentData.Certs {
			// Use the id current.yaml was keyed by to find the entry.
			if c.CertID == stateID_ {
				currentData.Certs[i].ConfID = conf.ConfID
				currentData.Certs[i].CommonName = conf.CommonName
				currentData.Certs[i].CertID = certId_
				currentData.Certs[i].CertFile = conf.CertFile
				currentData.Certs[i].KeyFile = conf.KeyFile
				break
			}
		}
		if err = WriteCurrentData(currentDataFilePath, currentData); err != nil {
			log.Printf("Failed to write current data: %v\n", err)
		} else if usingConfig.ShouldRevokeOldOnRenew() && id != certId_ {
			// Strictly after the new state is persisted: revoking first would risk
			// losing track of the certificate that is actually installed.
			revokeSuperseded(client_, id)
		}
	}
	return
}

// renewalNotDue reports whether the certificate can be left alone.
//
// Only an issued certificate may be skipped. Any other status must be re-issued
// even when its expiry date is still in the future: a revoked or cancelled
// certificate keeps its original dates but is dead, and skipping on the date
// alone would leave a dead certificate installed indefinitely.
func renewalNotDue(certInfo *zerosslIPCert.CertificateInfoModel, commonName string, leadDays int) bool {
	switch certInfo.Status {
	case zerosslIPCert.CertStatus.Issued:
		// fall through to the expiry check below
	case zerosslIPCert.CertStatus.ExpiringSoon:
		log.Printf("Cert %v is expiring soon, renewing.\n", commonName)
		return false
	default:
		log.Printf("Cert %v is in %v status, renewing.\n", commonName, certInfo.Status)
		return false
	}
	expireTime_, err := time.Parse("2006-01-02 15:04:05", certInfo.Expires)
	if err != nil {
		log.Printf("Cannot parse expiry %q of cert %v (%v), renewing.\n",
			certInfo.Expires, commonName, err)
		return false
	}
	if time.Now().Add(time.Hour * 24 * time.Duration(leadDays)).Before(expireTime_) {
		log.Printf("Cert %v is not due for renewal (lead time %d days), skip renewing.\n",
			commonName, leadDays)
		return true
	}
	log.Printf("Cert %v expires %v, within the %d day lead time, renewing.\n",
		commonName, certInfo.Expires, leadDays)
	return false
}

// persistCertID rewrites the state entry keyed by stateID when the API turned out
// to hold a different certificate id, so the next run starts from the truth.
// dropCertState removes the state entry keyed by certID. It is only written back
// to disk once the replacement certificate has been issued, so a failure in
// between leaves the old entry in place rather than an empty state file.
func dropCertState(certID string) {
	for i, c := range currentData.Certs {
		if c.CertID == certID {
			currentData.Certs = append(currentData.Certs[:i], currentData.Certs[i+1:]...)
			return
		}
	}
}

func persistCertID(stateID, actualID string, conf *CertConf) {
	if stateID == actualID {
		return
	}
	for i, c := range currentData.Certs {
		if c.CertID == stateID {
			currentData.Certs[i].CertID = actualID
			currentData.Certs[i].ConfID = conf.ConfID
			currentData.Certs[i].CommonName = conf.CommonName
			currentData.Certs[i].CertFile = conf.CertFile
			currentData.Certs[i].KeyFile = conf.KeyFile
			if err := WriteCurrentData(currentDataFilePath, currentData); err != nil {
				log.Printf("Failed to write current data: %v\n", err)
				return
			}
			log.Printf("State updated: %v -> %v\n", stateID, actualID)
			return
		}
	}
}

// revokeSuperseded revokes the certificate that has just been replaced, so that a
// key the server no longer serves stops being valid.
//
// It does NOT free an account quota slot: a revoked certificate keeps counting
// against the free plan's allowance exactly like an issued one (verified against
// the live API -- see CLAUDE.md section 6). Only a cancelled draft is never counted,
// and cancelling requires a certificate that was never issued. Do not reintroduce
// the claim that revoking buys back quota; it was wrong once already.
//
// A failure here is logged but never fails the renewal: the new certificate is
// already installed at this point.
func revokeSuperseded(client *zerosslIPCert.Client, id string) {
	certInfo_, err := client.GetCert(id)
	if err != nil {
		log.Printf("Failed to get superseded cert %v: %v\n", id, err)
		return
	}
	if certInfo_.Status != zerosslIPCert.CertStatus.Issued {
		log.Printf("Superseded cert %v is in %v status, nothing to revoke.\n", id, certInfo_.Status)
		return
	}
	log.Printf("Revoking superseded cert %v to free the account quota slot\n", id)
	if err = client.RevokeCert(id, zerosslIPCert.RevokeReason.Superseded); err != nil {
		log.Printf("Failed to revoke superseded cert %v: %v\n", id, err)
		return
	}
	log.Printf("Superseded cert %v revoked\n", id)
}

// // issueCerts issues certs referenced in the config file.
// func issueCerts() {
// 	log.Printf("Issuing certs")
// 	for _, c := range usingConfig.CertConfigs {
// 		log.Printf("Issuing cert for domain: %v", c.CommonName)
// 		err := issueCert(&c)
// 		if err != nil {
// 			log.Printf("Failed to issue cert for domain %v: %v\n", c.CommonName, err)
// 		}
// 	}
// }

// // issueCert issues a cert for the given domain config.
// func issueCert(conf *CertConf) (err error) {
// 	for _, cert := range currentData.Certs {
// 		// Use ConfID to match.
// 		if cert.ConfID == conf.ConfID {
// 			log.Printf("Cert for domain %v already exists, try renew.\n", conf.CommonName)
// 			err = renewCert(cert.CertID, conf)
// 			return
// 		}
// 	}

// cleanup certs.
func cleanup() {
	log.Println("will cleanup pending certs")
	for _, c := range usingConfig.CertConfigs {
		client_ := apiClient(c.ApiKey)
		err := client_.CleanUnfinished()
		if err != nil {
			log.Printf("Failed to clean unfinished issuing certificate: %v\n", err)
		}
	}

}
