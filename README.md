# Get-DomainStatus

A comprehensive PowerShell domain monitoring and SSL certificate analysis tool that queries domain registration status via RDAP/WHOIS and performs optional SSL/TLS certificate verification with parking detection.

## Overview

`Get-DomainStatus` provides actionable intelligence about domain registration state and security posture by combining RDAP (Registration Data Access Protocol) queries with optional WHOIS cross-referencing, live SSL/TLS certificate analysis, DNS record enumeration, and Certificate Transparency log queries. Unlike simple expiration date lookups, this function interprets EPP status codes to assess actual expiration risk and provides priority-based recommendations for certificate renewal.

## The Problem

**Domain expiration dates are misleading.** A domain showing "expires tomorrow" will almost always auto-renew silently. Meanwhile, a domain with `clientRenewProhibited` status might be in genuine jeopardy even with time remaining.

**SSL certificates need proactive monitoring.** Expired certificates cause immediate service disruption, but traditional monitoring tools produce noisy alerts or hide certificate details in ugly PowerShell object output.

This function solves both problems by:

- Parsing EPP status codes to determine actual domain risk state
- Cross-referencing RDAP and WHOIS to detect stale data
- Providing risk-level assessments instead of raw dates
- Live SSL/TLS certificate analysis with actionable renewal recommendations
- Multi-signal parking detection to avoid wasting time on inactive domains
- Clean, human-readable output for console display with full data access for scripting

## Features

✅ **Domain Registration Analysis** - Query RDAP (with WHOIS fallback) for registration details
✅ **Intelligent Risk Assessment** - Automatically evaluate domain expiration risk based on EPP status codes
✅ **SSL/TLS Certificate Analysis** - Live certificate validation with detailed cryptographic information
✅ **DNS Record Enumeration** - Query A, AAAA, NS, MX, CNAME, and CAA records via DNS-over-HTTPS
✅ **Certificate Transparency Logs** - Optional CT log queries to view certificate history
✅ **Parking Detection** - Multi-signal analysis to identify parked or inactive domains
✅ **Actionable Recommendations** - Priority-based recommendations for certificate renewal
✅ **Clean Output Format** - Human-readable summaries with `Raw*` properties for full data access

## Requirements

- PowerShell 5.1 or higher
- Internet connectivity for RDAP, DNS, and SSL queries
- Outbound access to ports 443 (HTTPS) and 43 (WHOIS)

## Installation

### Option 1: Dot-Source the Script
```powershell
. .\Get-DomainStatus.ps1
Get-DomainStatus -Domain "example.com"
```

### Option 2: Import as Module
```powershell
Import-Module .\Get-DomainStatus.ps1
Get-DomainStatus -Domain "example.com"
```

### Option 3: Install to PowerShell Modules Directory
```powershell
# Copy to user modules directory
$modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\DomainStatus"
New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item .\Get-DomainStatus.ps1 -Destination "$modulePath\DomainStatus.psm1"

# Import the module
Import-Module DomainStatus
```

## Usage

### Basic Domain Check
```powershell
Get-DomainStatus -Domain "example.com"
```

Returns domain registration status, expiration date, registrar, nameservers, and risk assessment.

### Full SSL Analysis
```powershell
Get-DomainStatus -Domain "example.com" -SSL
```

Includes SSL certificate details, DNS records, parking detection, and actionable recommendations.

### Certificate Transparency Logs
```powershell
Get-DomainStatus -Domain "example.com" -SSL -IncludeCTLogs
```

Adds historical certificate data from Certificate Transparency logs (crt.sh).

### Force WHOIS Cross-Reference
```powershell
Get-DomainStatus -Domain "example.com" -IncludeWhois
```

Forces WHOIS lookup for cross-validation (automatically used for Medium/High risk domains).

### Batch Processing
```powershell
$domains = @("example.com", "example.net", "example.org")
$domains | ForEach-Object { Get-DomainStatus $_ -SSL }
```

### Export to CSV
```powershell
Get-DomainStatus "example.com" -SSL | Export-Csv -Path "domain_report.csv" -NoTypeInformation
```

### Filter by Risk Level
```powershell
$domains | ForEach-Object { Get-DomainStatus $_ } | Where-Object RiskLevel -ne 'Low'
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Domain` | String | Domain name to query (e.g., "example.com") - **Required** |
| `-IncludeWhois` | Switch | Force WHOIS cross-reference regardless of risk level |
| `-SSL` | Switch | Include SSL certificate analysis, DNS records, and parking detection |
| `-IncludeCTLogs` | Switch | Query Certificate Transparency logs (requires `-SSL`) |

## Output Properties

### Core Domain Properties
- **Domain**: Domain name queried
- **Registered**: Boolean indicating if domain is registered
- **Available**: Boolean indicating if domain is available for registration
- **ExpirationDate**: Domain expiration date (ISO 8601)
- **DaysUntilExpiry**: Days until domain expires
- **LastChangedDate**: Last modification date
- **DaysSinceChange**: Days since last change
- **RegistrationDate**: Initial registration date
- **Registrar**: Registrar name
- **NameServers**: Comma-separated list of nameservers
- **Statuses**: All EPP status codes (comma-separated)
- **IsLocked**: Boolean indicating if domain has 3+ prohibit locks
- **RenewProhibited**: Boolean indicating if renewal is blocked
- **InRedemption**: Boolean indicating if in redemption period
- **PendingDelete**: Boolean indicating if pending deletion
- **RiskLevel**: Risk assessment (Low, Medium, High, Critical)
- **RiskReason**: Explanation of risk assessment
- **RdapSource**: RDAP server used for query

### SSL Properties (when `-SSL` is used)
- **SSLCertificate**: Human-readable certificate summary
- **SSLDaysUntilExpiry**: Days until SSL certificate expires
- **SSLIssuer**: Certificate authority
- **SSLExpired**: Boolean indicating if certificate is expired
- **SSLProtocol**: TLS protocol version (e.g., Tls12, Tls13)
- **DNSRecords**: Human-readable DNS summary
- **CTLogs**: Certificate Transparency log summary
- **ParkingAnalysis**: Domain parking detection verdict
- **SSLRecommendation**: Actionable recommendation with priority

### WHOIS Properties (when `-IncludeWhois` is used or risk is Medium/High)
- **WhoisUpdatedDate**: Last update per WHOIS
- **WhoisExpiryDate**: Expiration per WHOIS
- **WhoisNameServers**: Nameservers per WHOIS
- **ExpiryMismatch**: Boolean indicating if RDAP/WHOIS expiry dates differ
- **NameServerMismatch**: Boolean indicating if RDAP/WHOIS nameservers differ

### Raw Data Properties (for scripting - when `-SSL` is used)
When `-SSL` is used, detailed objects are available with `Raw` prefix:
- **RawSSLCertificate**: Full certificate object with all cryptographic details
- **RawDNSRecords**: Complete DNS record arrays (NSRecords, ARecords, etc.)
- **RawCTLogs**: Full CT log data with certificate list
- **RawParkingAnalysis**: Detailed parking indicators and scoring

## Output Format: Clean Display with Full Data Access

The script provides **clean, human-readable output** by default while preserving full data access for programmatic use.

### Display Format (Console/Format-List/Format-Table)
```
SSLCertificate: Valid | example.com | Issuer: Let's Encrypt | Expires: 45 days | Protocol: Tls12
DNSRecords: NS: 2 records | A: 192.0.2.1, 192.0.2.2 | MX: 2 records
ParkingAnalysis: ACTIVE (Score: 0%)
SSLRecommendation: MONITOR [info] - Certificate valid for 45 days
CTLogs: 15 certificates found | Showing latest 5
```

### Accessing Raw Data (Scripting)
```powershell
$result = Get-DomainStatus -Domain "example.com" -SSL

# Access detailed certificate data
$result.RawSSLCertificate.Certificate.SANList
$result.RawSSLCertificate.Certificate.FingerprintSHA256
$result.RawSSLCertificate.Certificate.CipherSuite

# Access DNS record arrays
$result.RawDNSRecords.ARecords
$result.RawDNSRecords.NSRecords
$result.RawDNSRecords.MXRecords

# Access parking indicators
$result.RawParkingAnalysis.Indicators
$result.RawParkingAnalysis.Score
```

**Before this update** (ugly PowerShell output):
```
CTLogs: @{Domain=example.com; Success=False; Certificates=System.Object[]; TotalFound=0; Error=The...
```

**After this update** (clean readable output):
```
CTLogs: No certificates found in CT logs
```

## Risk Level Logic

### Domain Registration Risk

| Level | Condition |
|-------|-----------|
| **Critical** | `pending delete` status present - domain will drop within 5 days |
| **High** | `redemption period` status present - domain expired, owner can still reclaim |
| **Medium** | `hold` status present, OR `clientRenewProhibited` within 30 days of expiry (without recent update), OR past expiration date |
| **Low** | None of the above; domain appears stable |

### Risk Downgrade Conditions

- `clientRenewProhibited` + recent update (≤7 days) → **Low** (likely just renewed)
- WHOIS confirms recent update on Medium risk domain → **Low**

## SSL Recommendation Priorities

When using `-SSL`, the function provides actionable recommendations:

- **URGENT_RENEW** [critical/high]: Certificate expired or expiring within 7 days
- **SCHEDULE_RENEW** [medium]: Certificate expiring within 30 days
- **PLAN_RENEW** [low]: Certificate expiring within 60 days
- **MONITOR** [info]: Certificate healthy (60+ days remaining)
- **LOW_PRIORITY** [low]: Domain appears parked - deprioritize maintenance
- **INVESTIGATE** [medium]: SSL connection failed - requires investigation

## Parking Detection

Multi-signal analysis identifies parked or inactive domains to avoid wasting time on maintenance:

### Detection Signals
- **Registrar default nameservers**: domaincontrol.com (GoDaddy), registrar-servers.com (Namecheap), etc.
- **Known parking IP addresses**: 184.168.131.x (GoDaddy), 198.54.117.x (Namecheap), etc.
- **Shared parking certificates**: secureserver.net, parkingcrew, sedoparking
- **Missing MX records**: Weak signal (5 points)

### Scoring System
- Parking IP detected: +35 points
- Registrar default NS: +25 points
- Shared parking certificate: +30 points
- Active provider NS (Cloudflare, AWS): -15 points
- Score clamped to 0-100 range

### Verdict
- **LIKELY_PARKED** (60+ points): Domain appears parked
- **POSSIBLY_PARKED** (30-59 points): Mixed signals detected
- **ACTIVE** (<30 points): Domain appears active

Parked domains receive **LOW_PRIORITY** SSL recommendations to avoid unnecessary maintenance work.

## EPP Status Codes Reference

| Status | Meaning |
|--------|---------|
| `active` / `ok` | Normal registered state |
| `clientDeleteProhibited` | Registrar locked from deletion |
| `clientTransferProhibited` | Registrar locked from transfer |
| `clientUpdateProhibited` | Registrar locked from updates |
| `clientRenewProhibited` | Renewal blocked (⚠️ investigate) |
| `clientHold` / `serverHold` | Suspended, not resolving |
| `redemptionPeriod` | Expired, owner can reclaim with fee |
| `pendingDelete` | 5-day countdown to release |

## Domain Lifecycle

```
Registered → Expired (Grace ~30-45d) → Redemption (~30d) → Pending Delete (5d) → Available
```

## Data Sources & Architecture

### RDAP Bootstrap
The function uses IANA's official RDAP bootstrap registry per [RFC 7484](https://datatracker.ietf.org/doc/html/rfc7484):
```
https://data.iana.org/rdap/dns.json
```
If IANA is unreachable or the TLD is not found, it falls back to [rdap.org](https://rdap.org), a community-operated RDAP redirector.

### WHOIS Servers
Direct TCP queries to port 43 on registry WHOIS servers:

| TLD | Server |
|-----|--------|
| .com, .net | whois.verisign-grs.com |
| .org | whois.pir.org |
| .io | whois.nic.io |
| .co | whois.nic.co |
| .au | whois.auda.org.au |
| + 30+ additional TLDs | See source code |

### DNS Resolution
Google DNS-over-HTTPS API (https://dns.google) for record queries:
- A, AAAA, NS, MX, CNAME, CAA records

### SSL/TLS Certificate Analysis
Live certificate retrieval via .NET `TcpClient` and `SslStream`:
- Port 443 connection with SNI
- Accepts all certificates (including expired) for analysis
- Extracts cryptographic details, SANs, fingerprints

### Certificate Transparency Logs
crt.sh CT log database (https://crt.sh):
- Historical certificate issuance data
- Deduplication by serial number
- Optional expired certificate filtering

## Why Cross-Reference WHOIS?

RDAP data can be cached or stale. During testing, we encountered a domain showing:

- RDAP: `clientRenewProhibited`, expiring in 3 days
- WHOIS: Updated 2 days ago, expiration extended by 1 year

The domain had renewed, but RDAP hadn't propagated the change. Cross-referencing caught this.

## Examples

### Example 1: Quick Domain Check
```powershell
PS> Get-DomainStatus "google.com"

Domain              : google.com
Registered          : True
DaysUntilExpiry     : 287
Registrar           : MarkMonitor Inc.
RiskLevel           : Low
RiskReason          : Domain appears stable
```

### Example 2: Full SSL Analysis
```powershell
PS> Get-DomainStatus "github.com" -SSL | Format-List

Domain              : github.com
Registered          : True
DaysUntilExpiry     : 512
SSLCertificate      : Valid | github.com | Issuer: DigiCert | Expires: 89 days | Protocol: Tls13
DNSRecords          : NS: 8 records | A: 140.82.113.4 | AAAA: 1 records
ParkingAnalysis     : ACTIVE (Score: 0%)
SSLRecommendation   : MONITOR [info] - Certificate valid for 89 days
RiskLevel           : Low
```

### Example 3: Batch SSL Audit with CSV Export
```powershell
$domains = Get-Content domains.txt
$results = $domains | ForEach-Object { Get-DomainStatus $_ -SSL }
$results | Select-Object Domain, DaysUntilExpiry, SSLDaysUntilExpiry, RiskLevel, SSLRecommendation |
    Export-Csv -Path "ssl_audit.csv" -NoTypeInformation
```

### Example 4: Accessing Raw Certificate Data
```powershell
$result = Get-DomainStatus "example.com" -SSL

# Display Subject Alternative Names
$result.RawSSLCertificate.Certificate.SANList

# Check cipher suite and key exchange
$result.RawSSLCertificate.Certificate.CipherSuite
$result.RawSSLCertificate.Certificate.KeyExchange

# Get certificate fingerprint
$result.RawSSLCertificate.Certificate.FingerprintSHA256
```

### Example 5: Find Domains Needing SSL Renewal
```powershell
$domains = @("example1.com", "example2.com", "example3.com")
$domains | ForEach-Object { Get-DomainStatus $_ -SSL } |
    Where-Object { $_.SSLDaysUntilExpiry -lt 30 } |
    Select-Object Domain, SSLDaysUntilExpiry, SSLRecommendation
```

## Known Limitations

- **TLD RDAP Support**: Some TLDs (.au, .uk, .nz) have limited RDAP support and fall back to WHOIS
- **CT Log Timeouts**: CT log queries may timeout on domains with extensive certificate history
- **WHOIS Rate Limits**: Excessive queries may be throttled or blocked by WHOIS servers
- **WHOIS Format Variations**: Parsing may be incomplete for uncommon TLDs with non-standard formats
- **Port Requirements**: Requires outbound connectivity on ports 443 (HTTPS) and 43 (WHOIS)
- **PowerShell 5.1 Limitations**: Cipher suite detection not available in PS 5.1 (shows "N/A")
- **No Auto-Renew Detection**: Cannot determine if auto-renew is enabled; that's registrar-side configuration

## Troubleshooting

### "RDAP query failed"
- Check internet connectivity
- Some TLDs have unreliable RDAP servers; script will attempt WHOIS fallback
- Use `-IncludeWhois` to force WHOIS validation

### "SSL connection failed"
- Domain may not have an active web server on port 443
- Firewall or network restrictions may block outbound HTTPS
- Domain may be behind a CDN requiring SNI (supported automatically)

### "No Data Found" or "NOT FOUND"
- Domain is not registered (available for registration)
- TLD may not be supported by IANA RDAP bootstrap

### "CT log query timeout"
- Domain has extensive certificate history (100+ certs)
- crt.sh may be under load
- Retry or skip `-IncludeCTLogs` flag

## Version History

- **2.0.0** (Current): Added SSL certificate analysis, parking detection, CT logs, clean output format
- **1.x**: Initial RDAP/WHOIS domain status checking

## Contributing

Contributions welcome! Please test changes against multiple TLDs (.com, .org, .io, .au) before submitting.

Areas for improvement:
- [ ] Additional TLD WHOIS server mappings
- [ ] Async/parallel batch processing for large domain lists
- [ ] Historical tracking / change detection
- [ ] Custom output formatters (JSON, HTML reports)
- [ ] Integration with monitoring platforms (Nagios, Zabbix, etc.)

## License

This project is provided as-is for domain monitoring and SSL certificate management purposes.

## Author

Johnathan Green

## Acknowledgments

- IANA for maintaining the RDAP bootstrap registry (RFC 7484)
- rdap.org for the community-operated RDAP redirector service
- Google for DNS-over-HTTPS API
- crt.sh for Certificate Transparency log access
- Verisign and registry operators for public RDAP/WHOIS access
