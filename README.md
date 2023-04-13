# Cert-Check
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/peteretelej/cert-checker)](https://github.com/peteretelej/cert-checker/releases)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/peteretelej/cert-checker)](https://goreportcard.com/report/github.com/peteretelej/cert-checker)


Cert-Checker is a simple and efficient Go application that helps you monitor SSL/TLS certificates for specified domains. It checks the validity of certificates at regular intervals and logs certificate failures. 
It also optionally supports logging to Papertrail.

## Installation
### Pre-Built Binaries
You can download the latest release from the [releases page](https://github.com/peteretelej/cert-checker/releases).

### Building from Source
Alternatively, you can build the application from source:
```shell
git clone https://github.com/peteretelej/cert-checker.git
cd cert-checker
go build

# run app
./cert-checker -domain example.com -interval 1m
```

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
./cert-check -domain example.com -interval 1m -papertrail papertrail.example.com:12345
```

This command will check the SSL/TLS certificates for example.com every minute and send the logs to the specified Papertrail destination (if provided).

Replace `example.com` with the domain you want to check, `30s` with the desired check interval (e.g., 1m for one minute,1h etc), and (If you want to log to papertrail) `papertrail.example.com:12345` with your Papertrail logging address and port.


## Contributing
If you would like to contribute to the project, feel free to submit a pull request or open an issue on GitHub.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details


