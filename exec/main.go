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

	zerosslIPCert "github.com/tinkernels/zerossl-ip-cert"
)

// Version is the version of this application.
const Version = "v1.0.1"

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
		_, _ = fmt.Fprintf(w, "\nVersion: %v\n\nUsage: %v [ -renew ] -config CONFIG_FILE\n\n",
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

// issueCert issues a cert for the given domain config.
func issueCert(conf *CertConf) (err error) {
	for _, cert := range currentData.Certs {
		// Use ConfID to match.
		if cert.ConfID == conf.ConfID {
			log.Printf("Cert for domain %v already exists, try renew.\n", conf.CommonName)
			err = renewCert(cert.CertID, conf)
			return
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
	if err = runVerifyHook(conf.VerifyHook, &certInfo_); err != nil {
		log.Println(err)
		return
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
		verifyRsp_, err := client.VerifyDomains(certInfo.ID, zerosslIPCert.VerifyDomainsMethod.HttpCsrHash, "")
		if err != nil {
			log.Printf("verify error: %v\n", err)
			time.Sleep(time.Second * 15)
			continue
		}
		// NOTICE: ZeroSSL always return "Success:false" in HttpCsrHash verification.
		log.Printf("domains verification result: %+v\n", verifyRsp_)
		certInfoTmp_, err := client.GetCert(certInfo.ID)
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
func waitCert2BReady(client *zerosslIPCert.Client, certInfo *zerosslIPCert.CertificateInfoModel) (err error) {
	for i := 0; i < 10; i++ {
		// loop every other seconds until cert is ready.
		certInfo_, err := client.GetCert(certInfo.ID)
		if err != nil {
			log.Println(err)
			return err
		}
		if certInfo_.Status == zerosslIPCert.CertStatus.Issued {
			log.Printf("cert is ready: %+v\n", certInfo_)
			return nil
		}
		time.Sleep(time.Second * 30)
	}
	return fmt.Errorf("timeout of waiting cert to be ready")
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
}

func renewCert(id string, conf *CertConf) (err error) {
	log.Printf("Renewing cert %v with config: %v\n", conf.CommonName, conf.ConfID)
	client_ := apiClient(conf.ApiKey)
	certInfo_, err := client_.GetCert(id)
	if err != nil {
		log.Printf("Failed to get cert info: %v\n", err)
		return err
	}
	expireTime_, err := time.Parse("2006-01-02 15:04:05", certInfo_.Expires)
	if err != nil {
		log.Printf("Failed to convert expiring time: %v\n", err)
	} else {
		if certInfo_.Status != zerosslIPCert.CertStatus.ExpiringSoon &&
			time.Now().Add(time.Hour*24*29).Before(expireTime_) {
			log.Printf("Cert %v is not due for renewal, skip renewing.\n", conf.CommonName)
			return nil
		}
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
			// Use original cert ID to match cert.
			if c.CertID == id {
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

// revokeSuperseded revokes the certificate that has just been replaced, which
// releases the account quota slot it holds. On a free account draft,
// pending_validation, issued and expired certificates all count against the
// 3-certificate quota, and an expired one can neither be cancelled nor revoked --
// so the old certificate has to be revoked while it is still issued.
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
		break
	}

}
