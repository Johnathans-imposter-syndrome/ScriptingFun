<#
.SYNOPSIS
    Queries domain registration status and assesses expiration risk with optional SSL certificate analysis.

.DESCRIPTION
    Get-DomainStatus combines RDAP queries with optional WHOIS cross-referencing
    to provide actionable intelligence about domain registration state. Unlike
    simple expiration date lookups, this function interprets EPP status codes
    to assess actual expiration risk.

    With the -SSL switch, it also performs comprehensive SSL/TLS certificate analysis,
    DNS record enumeration, parking detection, and actionable recommendations.

.PARAMETER Domain
    The domain name to query (e.g., "example.com").

.PARAMETER IncludeWhois
    Forces WHOIS cross-reference regardless of risk level. By default, WHOIS
    is only queried when risk is Medium or higher.

.PARAMETER SSL
    Include SSL certificate analysis with parking detection and recommendations.

.PARAMETER IncludeCTLogs
    Include Certificate Transparency log queries (requires -SSL switch).

.EXAMPLE
    Get-DomainStatus "example.com"

    Basic query returning registration status and risk assessment.

.EXAMPLE
    Get-DomainStatus "example.com" -SSL

    Full analysis including SSL certificate, DNS records, and parking detection.

.EXAMPLE
    Get-DomainStatus "example.com" -SSL -IncludeCTLogs

    Complete analysis with Certificate Transparency log history.

.EXAMPLE
    @("example.com", "example.net") | ForEach-Object { Get-DomainStatus $_ -SSL }

    Batch processing multiple domains with SSL analysis.

.OUTPUTS
    PSCustomObject with domain status, dates, registrar info, risk assessment, and optional SSL data.

.NOTES
    Author: Johnathan
    Version: 2.0.0
    Requires: PowerShell 5.1+

    RDAP Bootstrap: https://data.iana.org/rdap/dns.json (RFC 7484)
    Fallback: https://rdap.org
#>

#region SSL Certificate Analysis - Configuration and Helper Functions

$Script:ParkedNSPatterns = @(
    'domaincontrol.com'      # GoDaddy
    'registrar-servers.com'  # Namecheap
    'parkingcrew.net'        # ParkingCrew
    'sedoparking.com'        # Sedo
    'above.com'              # Above.com
    'bodis.com'              # Bodis
    'parklogic.com'          # ParkLogic
    'dsredirection.com'      # Dan.com
    'pendingrenewaldeletion' # Pending deletion
    'yourhosting.nl'         # YourHosting parked
    'wixdns.net'             # Wix (often parked)
)

$Script:ParkedIPPrefixes = @(
    '184.168.131.'   # GoDaddy parking
    '50.63.202.'     # GoDaddy parking
    '52.119.126.'    # GoDaddy parking
    '34.102.136.'    # GoDaddy parking
    '198.54.117.'    # Namecheap parking
    '91.195.240.'    # Sedo parking
    '104.239.207.'   # Bodis
    '199.59.242.'    # Above.com
    '52.71.127.'     # Dan.com redirect
    '127.0.0.1'      # Loopback
    '0.0.0.0'        # Null route
)

$Script:ActiveProviders = @(
    'cloudflare', 'aws', 'azure', 'google', 'cloudns',
    'dnsmadeeasy', 'route53', 'digitalocean', 'akamai',
    'fastly', 'incapsula'
)

$Script:SharedParkingCertPatterns = @(
    'secureserver.net'
    'domaincontrol.com'
    'parkingcrew'
    'sedoparking'
)

function Get-CertificateFingerprint {
    <#
    .SYNOPSIS
        Calculate SHA256 fingerprint of a certificate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($Certificate.RawData)
    $fingerprint = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
    $sha256.Dispose()

    return $fingerprint
}

function ConvertTo-ReadableOID {
    <#
    .SYNOPSIS
        Convert X.500 distinguished name to readable hashtable
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    $result = @{}

    # Parse DN components (CN=, O=, OU=, etc.)
    $components = $DistinguishedName -split ',\s*(?=[A-Z]+=)'

    foreach ($component in $components) {
        if ($component -match '^([A-Z]+)=(.+)$') {
            $key = $Matches[1]
            $value = $Matches[2].Trim('"')
            $result[$key] = $value
        }
    }

    return $result
}

function Get-SSLCertificate {
    <#
    .SYNOPSIS
        Perform live SSL certificate analysis via TLS handshake
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter()]
        [int]$Port = 443,

        [Parameter()]
        [int]$TimeoutSeconds = 10
    )

    # Clean domain input
    $Domain = $Domain.Trim().ToLower()
    $Domain = $Domain -replace '^https?://', ''
    $Domain = ($Domain -split '/')[0] -split ':' | Select-Object -First 1

    $result = [PSCustomObject]@{
        Domain      = $Domain
        Success     = $false
        Certificate = $null
        Error       = $null
        AnalyzedAt  = [DateTime]::UtcNow.ToString('o')
    }

    $tcpClient = $null
    $sslStream = $null

    try {
        # Create TCP connection
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $TimeoutSeconds * 1000
        $tcpClient.SendTimeout = $TimeoutSeconds * 1000

        # Connect synchronously
        $tcpClient.Connect($Domain, $Port)

        # Get the network stream
        $netStream = $tcpClient.GetStream()
        $netStream.ReadTimeout = $TimeoutSeconds * 1000
        $netStream.WriteTimeout = $TimeoutSeconds * 1000

        # Create SSL stream - accept all certificates (we want to see expired ones too)
        $sslStream = New-Object System.Net.Security.SslStream(
            $netStream,
            $false,
            { param($sender, $cert, $chain, $errors) return $true }  # Accept all certs
        )

        # Authenticate as client - synchronous version
        $sslStream.AuthenticateAsClient($Domain)

        # Get certificate
        $remoteCert = $sslStream.RemoteCertificate
        if ($null -eq $remoteCert) {
            throw "No certificate data returned"
        }

        # Convert to X509Certificate2 for full parsing capabilities
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($remoteCert)

        # Parse subject and issuer
        $subject = ConvertTo-ReadableOID -DistinguishedName $cert.Subject
        $issuer = ConvertTo-ReadableOID -DistinguishedName $cert.Issuer

        # Calculate days until expiry
        $daysUntilExpiry = [int]($cert.NotAfter - [DateTime]::Now).TotalDays

        # Extract Subject Alternative Names (SANs)
        $sanList = @()
        $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
        if ($sanExtension) {
            $sanString = $sanExtension.Format($false)
            # Parse DNS entries from SAN string
            $sanList = [regex]::Matches($sanString, 'DNS Name=([^\s,]+)') |
                ForEach-Object { $_.Groups[1].Value }
        }

        # Get fingerprint
        $fingerprint = Get-CertificateFingerprint -Certificate $cert

        # Get public key size safely
        $pubKeySize = $null
        try {
            if ($cert.PublicKey.Key) {
                $pubKeySize = $cert.PublicKey.Key.KeySize
            }
        } catch {
            Write-Verbose "Could not retrieve public key size: $_"
        }

        # Get cipher suite safely (not available in PS 5.1)
        $cipherSuite = "N/A"
        try {
            if ($sslStream.PSObject.Properties['NegotiatedCipherSuite']) {
                $cipherSuite = $sslStream.NegotiatedCipherSuite.ToString()
            }
        } catch {
            Write-Verbose "Could not retrieve cipher suite: $_"
        }

        # Build certificate info object
        $certInfo = [PSCustomObject]@{
            CommonName       = $subject['CN']
            Organization     = $subject['O']
            IssuerCN         = $issuer['CN']
            IssuerOrg        = $issuer['O']
            NotBefore        = $cert.NotBefore.ToUniversalTime().ToString('o')
            NotAfter         = $cert.NotAfter.ToUniversalTime().ToString('o')
            DaysUntilExpiry  = $daysUntilExpiry
            IsExpired        = $daysUntilExpiry -lt 0
            SANCount         = $sanList.Count
            SANList          = $sanList | Select-Object -First 20
            SerialNumber     = $cert.SerialNumber
            Version          = $cert.Version
            Protocol         = $sslStream.SslProtocol.ToString()
            CipherSuite      = $cipherSuite
            KeyExchange      = $sslStream.KeyExchangeAlgorithm.ToString()
            KeySize          = $sslStream.KeyExchangeStrength
            FingerprintSHA256 = $fingerprint
            SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
            PublicKeyAlgorithm = $cert.PublicKey.Oid.FriendlyName
            PublicKeySize    = $pubKeySize
        }

        $result.Success = $true
        $result.Certificate = $certInfo

    }
    catch [System.Net.Sockets.SocketException] {
        $result.Error = "Connection failed: $($_.Exception.Message)"
    }
    catch [System.Security.Authentication.AuthenticationException] {
        $result.Error = "SSL/TLS error: $($_.Exception.Message)"
    }
    catch [System.TimeoutException] {
        $result.Error = "Connection timeout"
    }
    catch {
        $result.Error = "Unexpected error: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
    }

    return $result
}

function Get-DomainDNSRecords {
    <#
    .SYNOPSIS
        Query DNS records using Google DNS-over-HTTPS API
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter()]
        [int]$TimeoutSeconds = 10
    )

    $Domain = $Domain.Trim().ToLower() -replace '^https?://', ''

    $recordTypes = @('NS', 'A', 'AAAA', 'MX', 'CNAME', 'CAA')
    $dnsResults = @{}

    foreach ($type in $recordTypes) {
        $url = "https://dns.google/resolve?name=$Domain&type=$type"

        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec $TimeoutSeconds -Headers @{
                'Accept' = 'application/json'
                'User-Agent' = 'Get-DomainStatus-PowerShell/2.0'
            }

            $records = @()
            if ($response.Answer) {
                $records = $response.Answer | ForEach-Object {
                    $_.data.TrimEnd('.')
                }
            }

            $dnsResults[$type] = $records
        }
        catch {
            $dnsResults[$type] = @()
            Write-Verbose "DNS query failed for $type record: $($_.Exception.Message)"
        }
    }

    # Build structured DNS info object
    [PSCustomObject]@{
        Domain       = $Domain
        NSRecords    = $dnsResults['NS']
        ARecords     = $dnsResults['A']
        AAAARecords  = $dnsResults['AAAA']
        MXRecords    = $dnsResults['MX']
        CNAMERecords = $dnsResults['CNAME']
        CAARecords   = $dnsResults['CAA']
        HasMX        = ($dnsResults['MX']).Count -gt 0
        HasCAA       = ($dnsResults['CAA']).Count -gt 0
    }
}

function Get-CertificateTransparencyLogs {
    <#
    .SYNOPSIS
        Query crt.sh Certificate Transparency logs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter()]
        [int]$MaxResults = 5,

        [Parameter()]
        [int]$TimeoutSeconds = 20,

        [Parameter()]
        [switch]$IncludeExpired
    )

    $Domain = $Domain.Trim().ToLower()
    $url = "https://crt.sh/?q=$Domain&output=json"

    $result = [PSCustomObject]@{
        Domain       = $Domain
        Success      = $false
        Certificates = @()
        TotalFound   = 0
        Error        = $null
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec $TimeoutSeconds -Headers @{
            'User-Agent' = 'Get-DomainStatus-PowerShell/2.0'
        }

        if ($null -eq $response -or $response.Count -eq 0) {
            $result.Success = $true
            return $result
        }

        # Deduplicate by serial number
        $seenSerials = @{}
        $uniqueCerts = @()

        foreach ($cert in $response) {
            $serial = [string]$cert.serial_number

            if ($serial -and -not $seenSerials.ContainsKey($serial)) {
                $seenSerials[$serial] = $true

                # Parse expiry
                $isExpired = $false
                $notAfter = $cert.not_after
                if ($notAfter) {
                    try {
                        $expiryDate = [DateTime]::Parse($notAfter.Replace('Z', '+00:00'))
                        $isExpired = $expiryDate -lt [DateTime]::UtcNow
                    } catch { }
                }

                # Skip expired if not requested
                if ($isExpired -and -not $IncludeExpired) { continue }

                # Parse issuer CN from full name
                $issuerName = $cert.issuer_name
                if ($issuerName -match 'CN=([^,]+)') {
                    $issuerName = $Matches[1]
                }

                $uniqueCerts += [PSCustomObject]@{
                    CommonName   = if ($cert.common_name) { $cert.common_name } else { $Domain }
                    IssuerName   = $issuerName
                    NotBefore    = $cert.not_before
                    NotAfter     = $notAfter
                    SerialNumber = $serial
                    CrtShId      = $cert.id
                    IsExpired    = $isExpired
                }
            }
        }

        # Sort by not_before descending (newest first)
        $uniqueCerts = $uniqueCerts | Sort-Object { [DateTime]::Parse($_.NotBefore) } -Descending

        $result.Success = $true
        $result.Certificates = $uniqueCerts | Select-Object -First $MaxResults
        $result.TotalFound = $seenSerials.Count

    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-DomainParkingAnalysis {
    <#
    .SYNOPSIS
        Analyze domain for parking indicators using multi-signal scoring
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$NSRecords = @(),

        [Parameter()]
        [string[]]$ARecords = @(),

        [Parameter()]
        [string]$CertificateCN,

        [Parameter()]
        [bool]$HasMX = $false
    )

    $score = 0
    $indicators = @()

    # Check NS records against parking patterns
    foreach ($ns in $NSRecords) {
        $nsLower = $ns.ToLower()

        # Check for parking patterns
        foreach ($pattern in $Script:ParkedNSPatterns) {
            if ($nsLower -like "*$pattern*") {
                $indicators += "Registrar default NS: $ns"
                $score += 25
                break
            }
        }

        # Check for active providers (reduces score)
        foreach ($provider in $Script:ActiveProviders) {
            if ($nsLower -like "*$provider*") {
                $score -= 15
                break
            }
        }
    }

    # Check A records for parking IPs
    foreach ($ip in $ARecords) {
        foreach ($prefix in $Script:ParkedIPPrefixes) {
            if ($ip.StartsWith($prefix)) {
                $indicators += "Parking IP detected: $ip"
                $score += 35
                break
            }
        }
    }

    # No MX records is a weak parking signal
    if (-not $HasMX -and $NSRecords.Count -gt 0) {
        $indicators += "No MX records configured"
        $score += 5
    }

    # Check certificate for shared parking patterns
    if ($CertificateCN) {
        foreach ($pattern in $Script:SharedParkingCertPatterns) {
            if ($CertificateCN.ToLower() -like "*$pattern*") {
                $indicators += "Shared parking certificate: $CertificateCN"
                $score += 30
                break
            }
        }
    }

    # Clamp score to 0-100
    $score = [Math]::Max(0, [Math]::Min(100, $score))

    # Determine verdict
    $verdict = switch ($score) {
        { $_ -ge 60 } { 'LIKELY_PARKED'; break }
        { $_ -ge 30 } { 'POSSIBLY_PARKED'; break }
        default { 'ACTIVE' }
    }

    [PSCustomObject]@{
        Score         = $score
        Verdict       = $verdict
        Indicators    = $indicators
        ShouldProcess = ($verdict -eq 'ACTIVE')
    }
}

function Get-SSLRecommendation {
    <#
    .SYNOPSIS
        Generate actionable recommendation based on SSL analysis
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$SSLResult,

        [Parameter(Mandatory)]
        [PSCustomObject]$ParkingAnalysis
    )

    # Handle SSL failures
    if (-not $SSLResult.Success) {
        return [PSCustomObject]@{
            Action                  = 'INVESTIGATE'
            Priority                = 'medium'
            Reason                  = "SSL connection failed: $($SSLResult.Error)"
            EstimatedEffortMinutes  = 30
            AutomationReady         = $false
        }
    }

    $days = $SSLResult.Certificate.DaysUntilExpiry

    # Parked domains get low priority
    if ($ParkingAnalysis.Verdict -eq 'LIKELY_PARKED') {
        return [PSCustomObject]@{
            Action                  = 'LOW_PRIORITY'
            Priority                = 'low'
            Reason                  = "Domain appears parked (score: $($ParkingAnalysis.Score)%)"
            EstimatedEffortMinutes  = 5
            AutomationReady         = $false
        }
    }

    # Expired certificate
    if ($days -lt 0) {
        return [PSCustomObject]@{
            Action                  = 'URGENT_RENEW'
            Priority                = 'critical'
            Reason                  = "Certificate EXPIRED $([Math]::Abs($days)) days ago!"
            EstimatedEffortMinutes  = 45
            AutomationReady         = $true
        }
    }

    # Expiring within 7 days
    if ($days -lt 7) {
        return [PSCustomObject]@{
            Action                  = 'URGENT_RENEW'
            Priority                = 'high'
            Reason                  = "Certificate expires in $days days"
            EstimatedEffortMinutes  = 30
            AutomationReady         = $true
        }
    }

    # Expiring within 30 days
    if ($days -lt 30) {
        return [PSCustomObject]@{
            Action                  = 'SCHEDULE_RENEW'
            Priority                = 'medium'
            Reason                  = "Certificate expires in $days days"
            EstimatedEffortMinutes  = 20
            AutomationReady         = $true
        }
    }

    # Expiring within 60 days
    if ($days -lt 60) {
        return [PSCustomObject]@{
            Action                  = 'PLAN_RENEW'
            Priority                = 'low'
            Reason                  = "Certificate expires in $days days"
            EstimatedEffortMinutes  = 15
            AutomationReady         = $true
        }
    }

    # Healthy certificate
    return [PSCustomObject]@{
        Action                  = 'MONITOR'
        Priority                = 'info'
        Reason                  = "Certificate valid for $days days"
        EstimatedEffortMinutes  = 0
        AutomationReady         = $false
    }
}

function ConvertTo-SSLCertificateSummary {
    <#
    .SYNOPSIS
        Convert SSL certificate result to readable summary string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$SSLResult
    )

    if (-not $SSLResult.Success) {
        return "Failed: $($SSLResult.Error)"
    }

    $cert = $SSLResult.Certificate
    $status = if ($cert.IsExpired) { "EXPIRED" } else { "Valid" }
    return "$status | $($cert.CommonName) | Issuer: $($cert.IssuerCN) | Expires: $($cert.DaysUntilExpiry) days | Protocol: $($cert.Protocol)"
}

function ConvertTo-DNSSummary {
    <#
    .SYNOPSIS
        Convert DNS records to readable summary string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$DNSInfo
    )

    $parts = @()

    if ($DNSInfo.NSRecords.Count -gt 0) {
        $parts += "NS: $($DNSInfo.NSRecords.Count) records"
    }
    if ($DNSInfo.ARecords.Count -gt 0) {
        $parts += "A: $($DNSInfo.ARecords -join ', ')"
    }
    if ($DNSInfo.AAAARecords.Count -gt 0) {
        $parts += "AAAA: $($DNSInfo.AAAARecords.Count) records"
    }
    if ($DNSInfo.HasMX) {
        $parts += "MX: $($DNSInfo.MXRecords.Count) records"
    }
    if ($DNSInfo.HasCAA) {
        $parts += "CAA: Configured"
    }

    if ($parts.Count -eq 0) {
        return "No DNS records found"
    }

    return $parts -join " | "
}

function ConvertTo-CTLogsSummary {
    <#
    .SYNOPSIS
        Convert CT logs to readable summary string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$CTLogs
    )

    if (-not $CTLogs.Success) {
        return "Failed: $($CTLogs.Error)"
    }

    if ($CTLogs.TotalFound -eq 0) {
        return "No certificates found in CT logs"
    }

    return "$($CTLogs.TotalFound) certificates found | Showing latest $($CTLogs.Certificates.Count)"
}

function ConvertTo-ParkingAnalysisSummary {
    <#
    .SYNOPSIS
        Convert parking analysis to readable summary string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ParkingAnalysis
    )

    $verdict = $ParkingAnalysis.Verdict
    $score = $ParkingAnalysis.Score
    $indicators = $ParkingAnalysis.Indicators.Count

    if ($indicators -eq 0) {
        return "$verdict (Score: $score%)"
    }

    return "$verdict (Score: $score%) | $indicators indicators detected"
}

function ConvertTo-RecommendationSummary {
    <#
    .SYNOPSIS
        Convert SSL recommendation to readable summary string
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Recommendation
    )

    return "$($Recommendation.Action) [$($Recommendation.Priority)] - $($Recommendation.Reason)"
}

#endregion

#region Main Domain Status Function

function Get-DomainStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [Parameter()]
        [switch]$IncludeWhois,

        [Parameter()]
        [switch]$SSL,

        [Parameter()]
        [switch]$IncludeCTLogs
    )

    process {
        $tld = ($Domain -split '\.')[-1]
        $rdapServer = $null
        $usedFallback = $false

        # Try IANA bootstrap first (RFC 7484)
        try {
            $bootstrap = Invoke-RestMethod "https://data.iana.org/rdap/dns.json" -ErrorAction Stop
            $rdapServer = ($bootstrap.services | Where-Object { $_[0] -contains $tld })[1][0]
        }
        catch {
            Write-Verbose "IANA bootstrap failed: $_"
        }

        # Fallback to rdap.org if IANA failed or TLD not found
        if (-not $rdapServer) {
            $rdapServer = "https://rdap.org/"
            $usedFallback = $true
            Write-Verbose "Using rdap.org fallback"
        }

        try {
            $rdap = Invoke-RestMethod "$($rdapServer)domain/$Domain" -ErrorAction Stop

            $statuses = $rdap.status
            $events = $rdap.events

            # Extract all relevant dates
            $expiration = ($events | Where-Object eventAction -eq 'expiration').eventDate
            $lastChanged = ($events | Where-Object eventAction -eq 'last changed').eventDate
            $registration = ($events | Where-Object eventAction -eq 'registration').eventDate

            # Calculate days until expiration
            $daysUntilExpiry = if ($expiration) {
                [math]::Round(([datetime]$expiration - (Get-Date)).TotalDays)
            } else { $null }

            # Calculate days since last change
            $daysSinceChange = if ($lastChanged) {
                [math]::Round(((Get-Date) - [datetime]$lastChanged).TotalDays)
            } else { $null }

            # Status flags
            $hasRenewBlock = $statuses -contains 'client renew prohibited'
            $hasHold = $statuses -match 'hold'
            $inRedemption = $statuses -contains 'redemption period'
            $pendingDelete = $statuses -contains 'pending delete'
            $isLocked = ($statuses -match 'prohibited').Count -ge 3

            # Risk assessment logic
            $riskLevel = 'Low'
            $riskReason = 'Domain appears stable'

            if ($pendingDelete) {
                $riskLevel = 'Critical'
                $riskReason = 'Domain will drop within 5 days'
            }
            elseif ($inRedemption) {
                $riskLevel = 'High'
                $riskReason = 'In redemption period - owner can still reclaim'
            }
            elseif ($hasHold) {
                $riskLevel = 'Medium'
                $riskReason = 'Domain on hold - may be expiring or suspended'
            }
            elseif ($hasRenewBlock -and $daysUntilExpiry -le 30) {
                if ($daysSinceChange -le 7) {
                    $riskLevel = 'Low'
                    $riskReason = "Renew prohibited but recently updated ($daysSinceChange days ago) - likely just renewed"
                } else {
                    $riskLevel = 'Medium'
                    $riskReason = 'Renew prohibited near expiration - verify with WHOIS'
                }
            }
            elseif ($daysUntilExpiry -le 0) {
                $riskLevel = 'Medium'
                $riskReason = 'Past expiration date - in grace period or data is stale'
            }

            # Extract registrar info from RDAP
            $registrarEntity = $rdap.entities | Where-Object { $_.roles -contains 'registrar' }
            $registrarName = $registrarEntity.vcardArray[1] |
                Where-Object { $_[0] -eq 'fn' } |
                ForEach-Object { $_[3] }

            # Get nameservers from RDAP
            $nameservers = $rdap.nameservers | ForEach-Object { $_.ldhName }

            $result = [PSCustomObject]@{
                Domain              = $Domain
                Registered          = $true
                Available           = $false

                # Dates
                ExpirationDate      = $expiration
                DaysUntilExpiry     = $daysUntilExpiry
                LastChangedDate     = $lastChanged
                DaysSinceChange     = $daysSinceChange
                RegistrationDate    = $registration

                # Registrar & DNS
                Registrar           = $registrarName
                NameServers         = $nameservers -join ', '

                # Status breakdown
                Statuses            = $statuses -join ', '
                IsLocked            = $isLocked
                RenewProhibited     = $hasRenewBlock
                InRedemption        = $inRedemption
                PendingDelete       = $pendingDelete

                # Risk assessment
                RiskLevel           = $riskLevel
                RiskReason          = $riskReason

                # Source tracking
                RdapSource          = if ($usedFallback) { 'rdap.org (fallback)' } else { $rdapServer }
            }

            # WHOIS cross-reference
            if ($IncludeWhois -or $riskLevel -in @('Medium', 'High')) {
                $whoisData = Get-WhoisRaw -Domain $Domain -ErrorAction SilentlyContinue
                if ($whoisData) {
                    if ($whoisData -match 'Updated Date:\s*(\d{4}-\d{2}-\d{2})') {
                        $whoisUpdated = $matches[1]
                        $result | Add-Member -NotePropertyName 'WhoisUpdatedDate' -NotePropertyValue $whoisUpdated

                        $whoisDaysAgo = [math]::Round(((Get-Date) - [datetime]$whoisUpdated).TotalDays)
                        if ($whoisDaysAgo -le 7 -and $result.RiskLevel -eq 'Medium') {
                            $result.RiskLevel = 'Low'
                            $result.RiskReason = "WHOIS confirms recent update ($whoisDaysAgo days ago)"
                        }
                    }

                    if ($whoisData -match 'Expir.*?Date:\s*(\d{4}-\d{2}-\d{2})') {
                        $whoisExpiry = $matches[1]
                        $result | Add-Member -NotePropertyName 'WhoisExpiryDate' -NotePropertyValue $whoisExpiry

                        if ($expiration -and $whoisExpiry -ne ([datetime]$expiration).ToString('yyyy-MM-dd')) {
                            $result | Add-Member -NotePropertyName 'ExpiryMismatch' -NotePropertyValue $true
                            $result.RiskReason += ' (RDAP/WHOIS expiry mismatch - WHOIS likely more current)'
                        }
                    }

                    $whoisNS = [regex]::Matches($whoisData, 'Name Server:\s*(.+)', 'IgnoreCase') |
                        ForEach-Object { $_.Groups[1].Value.Trim().ToUpper() }

                    if ($whoisNS) {
                        $result | Add-Member -NotePropertyName 'WhoisNameServers' -NotePropertyValue ($whoisNS -join ', ')

                        $rdapNS = ($nameservers | ForEach-Object { $_.ToUpper() }) -join ', '
                        $whoisNSJoined = $whoisNS -join ', '

                        if ($rdapNS -ne $whoisNSJoined) {
                            $result | Add-Member -NotePropertyName 'NameServerMismatch' -NotePropertyValue $true
                        }
                    }
                }
            }

            # SSL Certificate Analysis (if requested)
            if ($SSL) {
                Write-Verbose "[$Domain] Performing SSL certificate analysis..."

                # Get SSL certificate
                $sslResult = Get-SSLCertificate -Domain $Domain

                # Get DNS records via Google DNS-over-HTTPS
                $dnsInfo = Get-DomainDNSRecords -Domain $Domain

                # Certificate Transparency logs (optional)
                $ctLogs = if ($IncludeCTLogs) {
                    Get-CertificateTransparencyLogs -Domain $Domain
                } else {
                    [PSCustomObject]@{ Success = $true; Certificates = @(); TotalFound = 0 }
                }

                # Get certificate CN for parking analysis
                $certCN = $null
                if ($sslResult.Success -and $sslResult.Certificate) {
                    $certCN = $sslResult.Certificate.CommonName
                }

                # Parking analysis
                $parkingAnalysis = Get-DomainParkingAnalysis `
                    -NSRecords $dnsInfo.NSRecords `
                    -ARecords $dnsInfo.ARecords `
                    -CertificateCN $certCN `
                    -HasMX $dnsInfo.HasMX

                # Action recommendation
                $recommendation = Get-SSLRecommendation -SSLResult $sslResult -ParkingAnalysis $parkingAnalysis

                # Generate human-readable summaries
                $sslSummary = ConvertTo-SSLCertificateSummary -SSLResult $sslResult
                $dnsSummary = ConvertTo-DNSSummary -DNSInfo $dnsInfo
                $ctSummary = ConvertTo-CTLogsSummary -CTLogs $ctLogs
                $parkingSummary = ConvertTo-ParkingAnalysisSummary -ParkingAnalysis $parkingAnalysis
                $recommendationSummary = ConvertTo-RecommendationSummary -Recommendation $recommendation

                # Add SSL properties to result - human-readable summaries for display
                $result | Add-Member -NotePropertyName 'SSLCertificate' -NotePropertyValue $sslSummary
                $result | Add-Member -NotePropertyName 'SSLDaysUntilExpiry' -NotePropertyValue $(if ($sslResult.Certificate) { $sslResult.Certificate.DaysUntilExpiry } else { $null })
                $result | Add-Member -NotePropertyName 'SSLIssuer' -NotePropertyValue $(if ($sslResult.Certificate) { $sslResult.Certificate.IssuerCN } else { $null })
                $result | Add-Member -NotePropertyName 'SSLExpired' -NotePropertyValue $(if ($sslResult.Certificate) { $sslResult.Certificate.IsExpired } else { $null })
                $result | Add-Member -NotePropertyName 'SSLProtocol' -NotePropertyValue $(if ($sslResult.Certificate) { $sslResult.Certificate.Protocol } else { $null })
                $result | Add-Member -NotePropertyName 'DNSRecords' -NotePropertyValue $dnsSummary
                $result | Add-Member -NotePropertyName 'CTLogs' -NotePropertyValue $ctSummary
                $result | Add-Member -NotePropertyName 'ParkingAnalysis' -NotePropertyValue $parkingSummary
                $result | Add-Member -NotePropertyName 'SSLRecommendation' -NotePropertyValue $recommendationSummary

                # Add raw detailed objects with 'Raw' prefix for programmatic access
                $result | Add-Member -NotePropertyName 'RawSSLCertificate' -NotePropertyValue $sslResult
                $result | Add-Member -NotePropertyName 'RawDNSRecords' -NotePropertyValue $dnsInfo
                $result | Add-Member -NotePropertyName 'RawCTLogs' -NotePropertyValue $ctLogs
                $result | Add-Member -NotePropertyName 'RawParkingAnalysis' -NotePropertyValue $parkingAnalysis
            }

            return $result
        }
        catch {
            # For certain TLDs (like .au), RDAP may not work even for registered domains
            # Fall back to WHOIS to determine actual registration status
            $tldNeedsWhoisFallback = @('au', 'uk', 'nz')  # TLDs that commonly have RDAP issues

            if ($_.Exception.Response.StatusCode -in @(404, 403) -and $tld -in $tldNeedsWhoisFallback) {
                Write-Verbose "RDAP failed for .$tld domain, attempting WHOIS fallback"

                try {
                    $whoisData = Get-WhoisRaw -Domain $Domain -ErrorAction Stop

                    # Check if domain is registered by looking for common "not found" patterns
                    $notFoundPatterns = @(
                        'No Data Found',
                        'NOT FOUND',
                        'No entries found',
                        'Domain not found',
                        'not found',
                        'No match for',
                        'NOT IN DATABASE'
                    )

                    $isNotRegistered = $false
                    foreach ($pattern in $notFoundPatterns) {
                        if ($whoisData -match $pattern) {
                            $isNotRegistered = $true
                            break
                        }
                    }

                    if ($isNotRegistered) {
                        return [PSCustomObject]@{
                            Domain          = $Domain
                            Registered      = $false
                            Available       = $true
                            RiskLevel       = 'N/A'
                            RiskReason      = 'Domain not registered (verified via WHOIS)'
                            RdapSource      = 'WHOIS fallback (RDAP unavailable)'
                        }
                    }

                    # Domain is registered - parse WHOIS data
                    $registrarName = $null
                    if ($whoisData -match 'Registrar Name:\s*(.+)') {
                        $registrarName = $matches[1].Trim()
                    }
                    elseif ($whoisData -match 'Registrar:\s*(.+)') {
                        $registrarName = $matches[1].Trim()
                    }

                    $lastModified = $null
                    if ($whoisData -match 'Last Modified:\s*(.+)') {
                        $lastModified = $matches[1].Trim()
                    }
                    elseif ($whoisData -match 'Updated Date:\s*(.+)') {
                        $lastModified = $matches[1].Trim()
                    }

                    $nameservers = [regex]::Matches($whoisData, 'Name Server:\s*(.+)', 'IgnoreCase') |
                        ForEach-Object { $_.Groups[1].Value.Trim() }

                    # Parse expiration date from WHOIS
                    $expirationDate = $null
                    $daysUntilExpiry = $null
                    if ($whoisData -match 'Expir.*?Date:\s*(\d{4}-\d{2}-\d{2})') {
                        $expirationDate = $matches[1]
                        $daysUntilExpiry = [math]::Round(([datetime]$expirationDate - (Get-Date)).TotalDays)
                    }

                    # Parse status codes
                    $statuses = [regex]::Matches($whoisData, 'Status:\s*(.+?)(?:\s+https?://|\r|\n|$)', 'IgnoreCase') |
                        ForEach-Object { $_.Groups[1].Value.Trim() }

                    return [PSCustomObject]@{
                        Domain              = $Domain
                        Registered          = $true
                        Available           = $false

                        # Dates
                        ExpirationDate      = $expirationDate
                        DaysUntilExpiry     = $daysUntilExpiry
                        LastChangedDate     = $lastModified
                        DaysSinceChange     = if ($lastModified) {
                            [math]::Round(((Get-Date) - [datetime]$lastModified).TotalDays)
                        } else { $null }
                        RegistrationDate    = $null

                        # Registrar & DNS
                        Registrar           = $registrarName
                        NameServers         = $nameservers -join ', '

                        # Status breakdown
                        Statuses            = $statuses -join ', '
                        IsLocked            = ($statuses -match 'prohibited').Count -ge 3
                        RenewProhibited     = $statuses -contains 'client renew prohibited'
                        InRedemption        = $statuses -contains 'redemption period'
                        PendingDelete       = $statuses -contains 'pending delete'

                        # Risk assessment
                        RiskLevel           = 'Unknown'
                        RiskReason          = 'RDAP unavailable - limited data from WHOIS'

                        # Source tracking
                        RdapSource          = 'WHOIS fallback (RDAP unavailable)'
                    }
                }
                catch {
                    Write-Verbose "WHOIS fallback also failed: $_"
                    # Return null to indicate we couldn't determine status
                    return $null
                }
            }
            elseif ($_.Exception.Response.StatusCode -eq 404) {
                return [PSCustomObject]@{
                    Domain          = $Domain
                    Registered      = $false
                    Available       = $true
                    RiskLevel       = 'N/A'
                    RiskReason      = 'Domain not registered'
                    RdapSource      = if ($usedFallback) { 'rdap.org (fallback)' } else { $rdapServer }
                }
            }
            throw $_
        }
    }
}

#endregion

#region WHOIS Helper Function

function Get-WhoisRaw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain
    )

    $tld = ($Domain -split '\.')[-1]

    $whoisServers = @{
        'com'  = 'whois.verisign-grs.com'
        'net'  = 'whois.verisign-grs.com'
        'org'  = 'whois.pir.org'
        'io'   = 'whois.nic.io'
        'co'   = 'whois.nic.co'
        'info' = 'whois.afilias.net'
        'biz'  = 'whois.biz'
        'us'   = 'whois.nic.us'
        'uk'   = 'whois.nic.uk'
        'ca'   = 'whois.cira.ca'
        'de'   = 'whois.denic.de'
        'au'   = 'whois.auda.org.au'
        'nl'   = 'whois.domain-registry.nl'
        'eu'   = 'whois.eu'
        'fr'   = 'whois.nic.fr'
        'it'   = 'whois.nic.it'
        'es'   = 'whois.nic.es'
        'ch'   = 'whois.nic.ch'
        'at'   = 'whois.nic.at'
        'be'   = 'whois.dns.be'
        'pl'   = 'whois.dns.pl'
        'ru'   = 'whois.tcinet.ru'
        'jp'   = 'whois.jprs.jp'
        'cn'   = 'whois.cnnic.cn'
        'in'   = 'whois.registry.in'
        'br'   = 'whois.registro.br'
        'mx'   = 'whois.mx'
        'tv'   = 'whois.nic.tv'
        'cc'   = 'ccwhois.verisign-grs.com'
        'me'   = 'whois.nic.me'
        'ws'   = 'whois.website.ws'
        'xyz'  = 'whois.nic.xyz'
        'online' = 'whois.nic.online'
        'site' = 'whois.nic.site'
        'app'  = 'whois.nic.google'
        'dev'  = 'whois.nic.google'
    }

    $server = $whoisServers[$tld]
    if (-not $server) {
        Write-Verbose "No WHOIS server mapping for TLD: $tld"
        return $null
    }

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($server, 43)
        $tcp.ReceiveTimeout = 10000
        $stream = $tcp.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)

        $writer.WriteLine($Domain)
        $writer.Flush()

        $response = $reader.ReadToEnd()
        $tcp.Close()

        return $response
    }
    catch {
        Write-Verbose "WHOIS query failed for $Domain : $_"
        return $null
    }
}

#endregion

# Export public functions when loaded as a module
# When dot-sourced, Export-ModuleMember will error, so we catch and ignore
try {
    Export-ModuleMember -Function Get-DomainStatus, Get-WhoisRaw
} catch {
    # Silently ignore - this happens when dot-sourcing the script
    # Functions are still available in the current scope
}
