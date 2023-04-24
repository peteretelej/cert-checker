#!/bin/bash

# Install the required tools (if not already installed)
#sudo apt-get update
#sudo apt-get install -y openssl jq
# go install github.com/peteretelej/tools/paperlog@latest # (optional, for papertrail)
# export PATH="$PATH:$HOME/go/bin"

# Check for --papertrail flag
if [[ "$1" == "--papertrail" ]]; then
    papertrail_flag=true
    papertrail="$2"
else
    papertrail_flag=false
fi

function log_message() {
    local logmessage="$1"

    if [[ "$papertrail_flag" == true ]]; then
        paperlog --addr="$papertrail" --appname="bash_cert-checker" --message="$logmessage"
    else
        echo "$logmessage"
    fi
}

check_hostname() {
    domain=$1
    common_name=$2
    alt_names=$3

    if [[ "$domain" = "$common_name" ]] || [[ "$domain" =~ ${common_name/\*/.*} ]]; then
        return 0
    fi

    for alt_name in $alt_names; do
        if [[ "$domain" = "$alt_name" ]] || [[ "$domain" =~ ${alt_name/\*/.*} ]]; then
            return 0
        fi
    done

    return 1
}
    
while read -r line; do
    if [[ -z "$line" ]] || [[ "$line" =~ ^# ]]; then
        continue
    fi
    domain=$(echo "$line" | awk -F[/:] '{print $4}')
    if [ -z "$domain" ]; then
        domain="$line"
    fi

    echo "Checking certificate for $domain..."

    cert_data=$(echo | openssl s_client -servername "$domain" -connect "$domain":443 -showcerts 2>&1)

    # Check hostname validation
    hostname_valid=$(echo "$cert_data" | openssl x509 -noout -check_host "$domain" 2>&1)
    if [ "$hostname_valid" != "1" ]; then
	common_name=$(echo "$cert_data" | openssl x509 -noout -subject | sed -n 's/.*CN\s*=\s*\([^,]*\).*/\1/p')
	alt_names=$(echo "$cert_data" | openssl x509 -noout -text | grep -A1 "Subject Alternative Name" | tail -n1 | sed 's/DNS://g' | tr ',' '\n' | sed 's/ //g')
	check_hostname "$domain" "$common_name" "$alt_names"
	if [ $? -ne 0 ]; then
	    log_message "[$(date)] - Hostname validation failed for $domain. Common Name (CN): $common_name, Subject Alternative Names (SANs): $alt_names"
	fi
    fi


    # Extract issuer_cert and cert_pem from cert_data
    issuer_cert=$(echo "$cert_data" | awk 'BEGIN {p=0} /-----BEGIN CERTIFICATE-----/ {p=1} p; /-----END CERTIFICATE-----/ {p=0}')
    cert_pem=$(echo "$cert_data" | openssl x509)

    # Check certificate chain validation
    chain_valid=$(echo "$cert_pem" | openssl verify -untrusted <(echo "$issuer_cert") 2>&1)
    if [ "$chain_valid" != "stdin: OK" ]; then
        error_message=$(echo "$chain_valid" | cut -d':' -f2-)
        log_message "[$(date)] - Certificate chain validation failed for $domain. Reason: $error_message"
    fi

    # Check signature algorithm and key strength
    signature_algo=$(echo "$cert_data" | openssl x509 -noout -text | grep "Signature Algorithm")
    key_strength=$(echo "$cert_data" | openssl x509 -noout -text | grep "RSA Public-Key" | awk -F'[()]' '{print $2}' | awk '{print $1}')
    if [[ ! "$signature_algo" =~ "sha256WithRSAEncryption" ]] || [ "$key_strength" -lt 2048 ]; then
        log_message "[$(date)] - Insecure signature algorithm or key strength for $domain"
    fi

    # Check Certificate Transparency (CT)
    ct_result=$(echo "$cert_data" | openssl x509 -noout -text | grep "CT Precertificate SCTs")
    if [ -z "$ct_result" ]; then
        log_message "[$(date)] - Certificate Transparency (CT) not enabled for $domain"
    fi

    # Check for certificate revocation status
    ocsp_url=$(echo "$cert_data" | openssl x509 -noout -ocsp_uri)
    ocsp_response=$(echo -e "issuer\n$issuer_cert\n\nuser\n$cert_pem" | openssl ocsp -issuer /dev/stdin -cert /dev/stdin -url "$ocsp_url" 2>&1)

    if echo "$ocsp_response" | grep -q 'Revoked'; then
        log_message "[$(date)] - Certificate revoked for $domain: $ocsp_response"
    fi

done < domains.txt

