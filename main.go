package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const appName = "cert-checker"

func main() {
	var (
		domain         = flag.String("domain", "", "domain to validate")
		interval       = flag.Duration("interval", time.Second*30, "interval to validate domain")
		papertrailAddr = flag.String("papertrail", "", "papertrail destination address logsN.papertrailapp.com:XXXXX (optional)")
	)
	flag.Parse()

	log.SetPrefix(fmt.Sprintf("[%s - %s] ", appName, *domain))

	log.Printf("Checking domain certificate every %s", *interval)
	if *papertrailAddr != "" {
		log.Printf("Certificate failures will be logged to papertrail at %s", *papertrailAddr)
	}

	for {
		if err := validateDomain(*domain); err != nil {
			log.Printf(err.Error())
			if err := paperlog(*papertrailAddr, err.Error()); err != nil {

			}
		}
		time.Sleep(*interval)
	}

}

func validateDomain(domain string) error {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("Failed to resolve domain %s: %v\n", domain, err)

	}

	var errs []string
	for _, ip := range ips {
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
		return fmt.Errorf("Failed to connect or verify certificate for %s: %v\n", address, err)

	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("failed to close tls connection: %v", err)
		}
	}(conn)

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("No certificates found for %s\n", address)
	}
	return nil
}

func paperlog(papertrailAddr, message string) error {
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
