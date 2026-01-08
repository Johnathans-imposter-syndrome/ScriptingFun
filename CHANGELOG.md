# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-01

### Added
- Initial release
- `Get-DomainStatus` function with RDAP querying
- `Get-WhoisRaw` helper function for direct WHOIS queries
- IANA RDAP bootstrap with rdap.org fallback
- Risk level assessment (Low, Medium, High, Critical)
- EPP status code interpretation
- WHOIS cross-referencing for stale data detection
- Expiry mismatch detection between RDAP and WHOIS
- Nameserver extraction from both sources
- Support for pipeline input
- Extended WHOIS server mappings (35+ TLDs)

### Technical Details
- Follows RFC 7484 for RDAP bootstrap
- Direct TCP port 43 queries for WHOIS
- Automatic risk downgrade on recent updates
