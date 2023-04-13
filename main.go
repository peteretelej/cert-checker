package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const appName = "cert-checker"

func main() {
	var (
		domain         = flag.String("domain", "", "domain to validate")
		interval       = flag.Duration("interval", time.Second*30, "interval to validate domain (optional, default 30s)")
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

func runValidation(domainsToCheck []string, papertrailAddr string) {
	var wg sync.WaitGroup
	for _, domain := range domainsToCheck {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
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
}

func sanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if !strings.Contains(domain, "http") {
		return ""
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
		ServerName: domain,
	})
	if err != nil {
		return fmt.Errorf("Failed to connect or verify certificate for %s - %s: %v\n", domain, address, err)

	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close tls connection: %v", err)
		}
	}(conn)

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("No certificates found for %s - %s\n", domain, address)
	}
	return nil
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
