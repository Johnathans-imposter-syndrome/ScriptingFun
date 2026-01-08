# Get-DomainStatus

A PowerShell function for querying domain registration status, expiration risk assessment, and WHOIS/RDAP cross-referencing.

## Overview

`Get-DomainStatus` provides actionable intelligence about domain registration state by combining RDAP (Registration Data Access Protocol) queries with optional WHOIS cross-referencing. Unlike simple expiration date lookups, this function interprets EPP status codes to assess actual expiration risk.

## The Problem

Domain expiration dates are misleading. A domain showing "expires tomorrow" will almost always auto-renew silently. Meanwhile, a domain with `clientRenewProhibited` status might be in genuine jeopardy even with time remaining. This function solves that by:

- Parsing EPP status codes to determine actual state
- Cross-referencing RDAP and WHOIS to detect stale data
- Providing risk-level assessments instead of raw dates

## Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/Get-DomainStatus.git

# Dot-source the function
. .\Get-DomainStatus\Get-DomainStatus.ps1
```

Or copy the functions directly into your PowerShell profile or script.

## Usage

### Basic Query

```powershell
Get-DomainStatus "example.com"
```

### With WHOIS Cross-Reference

```powershell
Get-DomainStatus "example.com" -IncludeWhois
```

### Batch Processing

```powershell
$domains = @("example.com", "example.net", "example.org")
$domains | ForEach-Object { Get-DomainStatus $_ }
```

### Filter by Risk Level

```powershell
$domains | ForEach-Object { Get-DomainStatus $_ } | Where-Object RiskLevel -ne 'Low'
```

## Output Properties

| Property | Type | Description |
|----------|------|-------------|
| `Domain` | String | Queried domain name |
| `Registered` | Boolean | Whether domain is currently registered |
| `Available` | Boolean | Whether domain is available for registration |
| `ExpirationDate` | DateTime | Registry expiration date |
| `DaysUntilExpiry` | Int | Days until expiration (negative if past) |
| `LastChangedDate` | DateTime | Last modification date |
| `DaysSinceChange` | Int | Days since last change |
| `RegistrationDate` | DateTime | Original registration date |
| `Registrar` | String | Current registrar name |
| `NameServers` | String | Comma-separated nameservers |
| `Statuses` | String | All EPP status codes |
| `IsLocked` | Boolean | Whether domain has 3+ prohibit locks |
| `RenewProhibited` | Boolean | Whether renewal is blocked |
| `InRedemption` | Boolean | Whether in redemption period |
| `PendingDelete` | Boolean | Whether pending deletion |
| `RiskLevel` | String | Low, Medium, High, or Critical |
| `RiskReason` | String | Explanation of risk assessment |
| `RdapSource` | String | RDAP server used for query |

### Additional Properties (with `-IncludeWhois`)

| Property | Type | Description |
|----------|------|-------------|
| `WhoisUpdatedDate` | String | Last update per WHOIS |
| `WhoisExpiryDate` | String | Expiration per WHOIS |
| `WhoisNameServers` | String | Nameservers per WHOIS |
| `ExpiryMismatch` | Boolean | RDAP/WHOIS expiry dates differ |
| `NameServerMismatch` | Boolean | RDAP/WHOIS nameservers differ |

## Risk Level Logic

| Level | Condition |
|-------|-----------|
| **Critical** | `pending delete` status present |
| **High** | `redemption period` status present |
| **Medium** | `hold` status present, OR `clientRenewProhibited` within 30 days of expiry (without recent update), OR past expiration date |
| **Low** | None of the above; domain appears stable |

### Risk Downgrade Conditions

- `clientRenewProhibited` + recent update (≤7 days) → **Low** (likely just renewed)
- WHOIS confirms recent update on Medium risk domain → **Low**

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

## Architecture

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

## Why Cross-Reference WHOIS?

RDAP data can be cached or stale. During testing, we encountered a domain showing:

- RDAP: `clientRenewProhibited`, expiring in 3 days
- WHOIS: Updated 2 days ago, expiration extended by 1 year

The domain had renewed, but RDAP hadn't propagated the change. Cross-referencing caught this.

## Limitations

- **WHOIS rate limits**: Excessive queries may be throttled or blocked
- **Privacy proxies**: Registrant details hidden behind services like Domains By Proxy
- **TLD coverage**: WHOIS server mapping doesn't cover all TLDs (function returns `$null` for unmapped TLDs)
- **No prediction**: Cannot determine if auto-renew is enabled; that's registrar-side configuration

## Dependencies

- PowerShell 5.1+ or PowerShell Core
- Network access to RDAP servers and WHOIS port 43

## Contributing

Pull requests welcome. Areas for improvement:

- [ ] Additional TLD WHOIS server mappings
- [ ] Async/parallel batch processing
- [ ] Historical tracking / change detection
- [ ] Export to CSV/JSON

## License

MIT License - See [LICENSE](LICENSE) file.

## Author

Johnathan - [GitHub](https://github.com/yourusername)

## Acknowledgments

- IANA for maintaining the RDAP bootstrap registry
- rdap.org for the fallback redirector service
- Verisign and other registry operators for public RDAP/WHOIS access
