function Get-CertificateChainValidation($cert) {
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.Build($cert)
        return $chain.ChainStatus
    }
    catch [Exception] {
        return @(@{ Status = "Error"; StatusInformation = $_.Exception.ToString() })
    }
    finally {
        $chain.Dispose()
    }
}

function Get-RevocationStatus($cert) {
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    try {
        $chain.Build($cert)
        return $chain.ChainStatus
    }
    catch [Exception] {
        return @(@{ Status = "Error"; StatusInformation = $_.Exception.ToString() })
    }
    finally {
        $chain.Dispose()
    }
}

function Get-CertificateFromDomain($domain) {
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($domain, 443)
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            return $true
        }
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $callback)
        $sslStream.AuthenticateAsClient($domain)

        return $sslStream.RemoteCertificate
    }
    catch {
        Write-Host "Error retrieving certificate for $domain : $_"
        return $null
    }
    finally {
        if ($sslStream -ne $null) {
            $sslStream.Dispose()
        }
        if ($tcpClient -ne $null) {
            $tcpClient.Dispose()
        }
    }
}



function Get-HostnameValidation($cert, $domain) {
    $subjectAltNames = @($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"})

    if ($subjectAltNames.Count -eq 0) {
        return "Error: No Subject Alternative Names found."
    }

    foreach ($subjectAltName in $subjectAltNames) {
        $rawData = $subjectAltName.Format($false).Split("`n")
        $altNames = $rawData | Where-Object {$_ -match "^DNS Name="} | ForEach-Object {$_.TrimStart("DNS Name=")}

        foreach ($altName in $altNames) {
            if ($altName -eq $domain -or ($altName.StartsWith("*") -and $domain.EndsWith($altName.Substring(1)))) {
                return $true
            }
        }
    }

    return "Error: Hostname not found in Subject Alternative Names."
}

$urls = Get-Content domains.txt | Where-Object {($_ -notmatch "^#") -and ($_ -ne "")}

foreach ($url in $urls) {
    $domain = [System.Uri]::new($url).Host
    $ip = [System.Net.Dns]::GetHostAddresses($domain) | Select-Object -ExpandProperty IPAddressToString

    try {
        $req = [System.Net.HttpWebRequest]::Create("https://$domain")
        $req.AllowAutoRedirect = $false
        $req.Timeout = 5000
        $response = $req.GetResponse()
        $response.Close()

        $cert = $req.ServicePoint.Certificate
    }
    catch {
        $errorMessage = "$(Get-Date): $domain ($ip) failed to connect or retrieve certificate. `r`n"
        Add-Content -Path powershell-out.log -Value $errorMessage
        continue
    }

    $chainValidation = Get-CertificateChainValidation($cert)
    if ($chainValidation -ne "Error") {
        foreach ($status in $chainValidation) {
            if ($status.Status -ne "NoError") {
                $errorMessage = "$(Get-Date): $domain ($ip) failed certificate chain validation - $($status.Status). `r`n"
                Add-Content -Path powershell-out.log -Value $errorMessage
            }
        }
    }
    else {
        $errorMessage = "$(Get-Date): $domain ($ip) failed certificate chain validation - $($chainValidation[0].StatusInformation). `r`n"
        Add-Content -Path powershell-out.log -Value $errorMessage
    }

    $revocationStatus = Get-RevocationStatus($cert)
    if ($revocationStatus -ne "Error") {
        foreach ($status in $revocationStatus) {
            if ($status.Status -ne "NoError") {
                $errorMessage = "$(Get-Date): $domain ($ip) failed revocation status check - $($status.Status). `r`n"
                Add-Content -Path powershell-out.log -Value $errorMessage
            }
        }
    }
    else {
        $errorMessage = "$(Get-Date): $domain ($ip) failed revocation status check - $($revocationStatus[0].StatusInformation). `r`n"
        Add-Content -Path powershell-out.log -Value $errorMessage
    }

    $hostnameValidation = Get-HostnameValidation($cert, $domain)
    if ($hostnameValidation -is [string]) {
        $errorMessage = "$(Get-Date): $domain ($ip) failed hostname validation - $hostnameValidation `r`n"
        Add-Content -Path powershell-out.log -Value $errorMessage
    }
}

