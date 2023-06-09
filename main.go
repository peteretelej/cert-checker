package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

const appName = "cert-checker"

func main() {
	var (
		domain         = flag.String("domain", "", "domain to validate")
		interval       = flag.Duration("interval", time.Minute, "interval to validate domain (optional)")
		papertrailAddr = flag.String("papertrail", "", "papertrail destination address logsN.papertrailapp.com:XXXXX (optional)")
		domains        = flag.String("domains", "", "text file contain domains to validate, see sample (optional)")
	)
	flag.Parse()

	log.SetPrefix(fmt.Sprintf("[%s] ", appName))

	log.Printf("Checking domain certificate every %s", *interval)
	if *papertrailAddr != "" {
		log.Printf("Certificate failures will be logged to papertrail at %s", *papertrailAddr)
	}
	if *domain == "" && *domains == "" {
		log.Fatalf("You must provide a domain to validate, or domains file")
	}
	var domainsList []string
	if *domains != "" {
		domainsList = getDomains(*domains)
	}
	if *domain != "" {
		domainsList = append(domainsList, *domain)
	}
	var domainsToCheck []string
	seen := make(map[string]bool)
	for _, v := range domainsList {
		v = sanitizeDomain(v)
		if v == "" {
			continue
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		domainsToCheck = append(domainsToCheck, v)
	}
	for {
		runValidation(domainsToCheck, *papertrailAddr)
		time.Sleep(*interval)
	}
}

const maxConcurrentRequests = 100

func runValidation(domainsToCheck []string, papertrailAddr string) {
	var wg sync.WaitGroup
	maxReqs := make(chan bool, maxConcurrentRequests)

	for _, domain := range domainsToCheck {
		wg.Add(1)
		maxReqs <- true
		go func(domain string) {
			defer func() {
				<-maxReqs
				wg.Done()
			}()

			if err := validateDomain(domain); err != nil {
				log.Printf(err.Error())
				if err := paperlog(papertrailAddr, err.Error()); err != nil {
					log.Printf(err.Error())
				}
			} else {
				log.Printf("Domain %s is valid", domain)
			}
		}(domain)
	}
	wg.Wait()
	for i := 0; i < cap(maxReqs); i++ {
		maxReqs <- true
	}
}

func sanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if !strings.HasPrefix(domain, "http") {
		domain = fmt.Sprintf("https://%s", domain)
	}
	parsedURL, err := url.Parse(domain)
	if err != nil {
		return domain
	}
	return parsedURL.Hostname()
}

// getDomains reads a file containing a list of domains to validate and returns a slice of domains
func getDomains(domainsFile string) []string {
	file, err := os.Open(domainsFile)
	if err != nil {
		log.Fatalf("failed to open domains file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("failed to close domains file: %v", err)
		}
	}(file)

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("failed to read domains file: %v", err)
	}
	return domains
}

func validateDomain(domain string) error {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("Failed to resolve domain %s: %v\n", domain, err)
	}

	var errs []string
	for _, ip := range ips {
		if ip.To4() == nil {
			// log.Printf("Skipping IPv6 address %s for domain %s, only IPv4 addresses are supported", ip.String(), domain)
			continue
		}
		if err := checkCertificate(domain, ip.String()); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if errs != nil {
		return fmt.Errorf("%+v", errs)
	}
	return nil
}

func checkCertificate(domain, ip string) error {
	address := fmt.Sprintf("%s:443", ip)
	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect %s - %s: %v\n", domain, address, err)
	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close tls connection: %v", err)
		}
	}(conn)

	connState := conn.ConnectionState()
	certs := connState.PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no certificates found for %s - %s\n", domain, address)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for i, cert := range certs {
		if i == 0 {
			continue // Skip the leaf certificate
		}
		if cert.IsCA {
			roots.AddCert(cert)
		} else {
			intermediates.AddCert(cert)
		}
	}

	opts := x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediates,
		Roots:         roots,
	}

	// Certificate chain validation
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed for %s - %s: %v", domain, address, err)
	}

	// OCSP check for revoked certificates in the chain
	if err := checkOCSPForChain(chains); err != nil {
		return fmt.Errorf("OCSP revocation check failed for %s - %s: %v", domain, address, err)
	}

	// Certificate expiration
	now := time.Now()
	if now.Before(certs[0].NotBefore) || now.After(certs[0].NotAfter) {
		return fmt.Errorf("certificate for %s - %s is expired or not yet valid", domain, address)
	}

	// Key usage and extended key usage
	if certs[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate for %s - %s does not have the Digital Signature key usage", domain, address)
	}
	if len(certs[0].ExtKeyUsage) == 0 || !containsExtKeyUsage(certs[0].ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("certificate for %s - %s is not valid for server authentication", domain, address)
	}

	// Basic constraints
	//if certs[0].BasicConstraintsValid {
	//	return fmt.Errorf("certificate for %s - %s should not have basic constraints", domain, address)
	//}

	// Signature algorithm and key strength
	if certs[0].PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return fmt.Errorf("certificate for %s - %s has an unknown public key algorithm", domain, address)
	}
	if !isKeyStrengthValid(certs[0]) {
		return fmt.Errorf("certificate for %s - %s has insufficient key strength", domain, address)
	}

	return nil
}
func checkOCSPForChain(chains [][]*x509.Certificate) error {
	for _, chain := range chains {
		for i := 0; i < len(chain)-1; i++ {
			issuer := chain[i+1]
			cert := chain[i]

			ocspReq, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{})
			if err != nil {
				return fmt.Errorf("failed to create OCSP request: %v", err)
			}

			ocspRes, err := getOCSPResponse(ocspReq, cert, issuer)
			if err != nil {
				return fmt.Errorf("failed to get OCSP response: %v", err)
			}

			if ocspRes.Status != ocsp.Good {
				return fmt.Errorf("certificate status is not good: %v", ocspRes.Status)
			}
		}
	}
	return nil
}

func getOCSPResponse(req []byte, cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	// This function assumes that the OCSP responder URL is present in the certificate
	// and sends the request to the first responder URL found.

	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("no OCSP responder URL found in the certificate")
	}

	url := cert.OCSPServer[0]
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(req))
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return nil, fmt.Errorf("network timeout while contacting OCSP server: %w", err)
		} else {
			return nil, fmt.Errorf("network error while contacting OCSP server: %w", err)
		}
	}

	httpReq.Header.Add("Content-Type", "application/ocsp-request")
	httpReq.Header.Add("Accept", "application/ocsp-response")

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get HTTP response: %v", err)
	}
	defer httpRes.Body.Close()

	if httpRes.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned a non-200 status code: %d", httpRes.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(httpRes.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response body: %v", err)
	}

	ocspRes, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %v", err)
	}

	return ocspRes, nil
}

func containsExtKeyUsage(extKeyUsages []x509.ExtKeyUsage, extKeyUsage x509.ExtKeyUsage) bool {
	for _, usage := range extKeyUsages {
		if usage == extKeyUsage {
			return true
		}
	}
	return false
}

func isKeyStrengthValid(cert *x509.Certificate) bool {
	// This function assumes the public key algorithm is already known
	// and checks the key strength depending on the algorithm.
	minRSAKeySize := 2048
	minECKeySize := 256

	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pubKey.N.BitLen() >= minRSAKeySize {
			return true
		}
	case *ecdsa.PublicKey:
		if pubKey.Curve.Params().BitSize >= minECKeySize {
			return true
		}
	}

	return false
}

func paperlog(papertrailAddr, message string) error {
	if papertrailAddr == "" {
		return nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = fmt.Sprintf("%s-host", appName)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	logMessage := fmt.Sprintf("<22>1 %s %s %s - - %s", timestamp, hostname, appName, message)

	// Send the message to Papertrail using UDP
	conn, err := net.Dial("udp", papertrailAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to Papertrail: %v", err)
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close connection to Papertrail: %v", err)
		}
	}(conn)

	_, err = conn.Write([]byte(logMessage))
	if err != nil {
		return fmt.Errorf("failed to send log message to Papertrail: %v", err)
	}

	return nil
}
