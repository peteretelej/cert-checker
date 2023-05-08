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

    echo "$logmessage"
    echo "$logmessage" >> log_bash_cert-checker.log

    if [[ "$papertrail_flag" == true ]]; then
        paperlog --addr="$papertrail" --appname="bash_cert-checker" --message="$logmessage"
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

    # Check certificate chain validation with retry
    retry_count=0
    max_retries=3
    issuer_cert_file=$(mktemp)
    cert_pem_file=$(mktemp)

    echo "$issuer_cert" > "$issuer_cert_file"
    echo "$cert_pem" > "$cert_pem_file"

    while [ "$retry_count" -lt "$max_retries" ]; do
        chain_valid=$(openssl verify -untrusted "$issuer_cert_file" "$cert_pem_file" 2>&1)
        error_message=$(echo "$chain_valid" | cut -d':' -f2-)

        if [ "$chain_valid" == "${cert_pem_file}: OK" ]; then
            break
        fi

        ((retry_count++))
        
        log_message "[$(date)] - Retry (${retry_count}/${max_retries}) Certificate chain validation failed for $domain (retry $((retry_count - 1))). Reason: $error_message"
        log_message "[$(date)] - Certificate chain validation failed for $domain after $max_retries retries. Reason: $error_message"
        log_message "[$(date)] - Cert PEM: $cert_pem"
        log_message "[$(date)] - Issuer Cert: $issuer_cert"
           
        if [ "$retry_count" -lt "$max_retries" ]; then
            sleep 5 # wait for 5 seconds before retrying
        fi
    done

   


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

    if [ -n "$ocsp_url" ]; then
        ocsp_response=""
        for i in {1..3}; do
            ocsp_response=$(openssl ocsp -no_nonce -issuer "$issuer_cert_file" -cert "$cert_pem_file" -VAfile "$issuer_cert_file" -text -url "$ocsp_url" -header "Host=$(basename "$ocsp_url")" -respout /dev/null 2>&1)
            exit_status=$?
            if [ $exit_status -eq 0 ]; then
                break
            fi
            if [[ $ocsp_response == *"unauthorized (6)"* ]]; then
                log_message "[$(date)] - OCSP Responder Error: unauthorized (6) for $domain (retry $i). The OCSP responder may not be configured correctly for this certificate."
            else
                log_message "[$(date)] - Error when checking certificate revocation status for $domain (retry $i). Exit status: $exit_status. Error: $ocsp_response"
            fi
            sleep 5
        done



        if [ -z "$ocsp_response" ]; then
            log_message "[$(date)] - Failed to check certificate revocation status for $domain due to network issues after 3 retries"
        elif echo "$ocsp_response" | grep -q 'Revoked'; then
            log_message "[$(date)] - Certificate revoked for $domain: $ocsp_response"
        fi
    else
        log_message "[$(date)] - No OCSP URL found for $domain"
    fi


     # Cleanup temporary files
    rm -f "$issuer_cert_file" "$cert_pem_file"

done < domains.txt

