# Cert-Check

Cert-Check is a simple Go application that periodically validates the SSL/TLS certificates for a specified domain. The app checks all the IP addresses associated with the domain, logs any certificate errors, and optionally sends the logs to a Papertrail destination.

## Usage
You can run the app using the following command-line options:
```
Usage of cert-check:
  -domain string
        domain to validate (required)
  -interval duration
        interval to validate domain (default 30s)
  -papertrail string
        papertrail destination address logsN.papertrailapp.com:XXXXX (optional)
```

### Example 
```
./cert-check -domain example.com -interval 1m -papertrail logs123.papertrailapp.com:12345
```

This command will check the SSL/TLS certificates for example.com every minute and send the logs to the specified Papertrail destination (if provided).

Replace `example.com` with the domain you want to check, 30s with the desired check interval (e.g., 1m for one minute), and papertrail.example.com:12345 with your Papertrail logging address and port.