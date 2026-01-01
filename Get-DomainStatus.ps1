<#
.SYNOPSIS
    Queries domain registration status and assesses expiration risk.

.DESCRIPTION
    Get-DomainStatus combines RDAP queries with optional WHOIS cross-referencing
    to provide actionable intelligence about domain registration state. Unlike
    simple expiration date lookups, this function interprets EPP status codes
    to assess actual expiration risk.

.PARAMETER Domain
    The domain name to query (e.g., "example.com").

.PARAMETER IncludeWhois
    Forces WHOIS cross-reference regardless of risk level. By default, WHOIS
    is only queried when risk is Medium or higher.

.EXAMPLE
    Get-DomainStatus "example.com"
    
    Basic query returning registration status and risk assessment.

.EXAMPLE
    Get-DomainStatus "example.com" -IncludeWhois
    
    Query with forced WHOIS cross-reference for additional validation.

.EXAMPLE
    @("example.com", "example.net") | ForEach-Object { Get-DomainStatus $_ }
    
    Batch processing multiple domains.

.OUTPUTS
    PSCustomObject with domain status, dates, registrar info, and risk assessment.

.NOTES
    Author: Johnathan
    Version: 1.0.0
    Requires: PowerShell 5.1+
    
    RDAP Bootstrap: https://data.iana.org/rdap/dns.json (RFC 7484)
    Fallback: https://rdap.org
#>

function Get-DomainStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,
        
        [switch]$IncludeWhois
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
            
            return $result
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
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

<#
.SYNOPSIS
    Queries raw WHOIS data for a domain.

.DESCRIPTION
    Performs a direct TCP query to the appropriate WHOIS server on port 43.
    Used internally by Get-DomainStatus for cross-referencing.

.PARAMETER Domain
    The domain name to query.

.OUTPUTS
    Raw WHOIS response as string, or $null if query fails.
#>

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

# Export functions
Export-ModuleMember -Function Get-DomainStatus, Get-WhoisRaw
