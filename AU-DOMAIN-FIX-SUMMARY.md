# .AU Domain Fix Summary

## Issue Identified

The `Get-DomainStatus` PowerShell module was incorrectly returning `Registered: False` for **registered** .au domains instead of properly detecting their registration status.

### Root Cause

1. **RDAP Server Issues**: The IANA bootstrap service doesn't list RDAP servers for .au domains
2. **Fallback Failure**: When falling back to rdap.org, it returns 404 for .au domains
3. **AUDA RDAP Blocking**: The official AUDA RDAP server (https://rdap.auda.org.au/) returns 403 Forbidden (Cloudflare error 1014)
4. **Incorrect Error Handling**: The module was treating 404 errors as "domain not registered" for ALL TLDs, even when the error was actually "RDAP service unavailable"

## Solution Implemented

Added intelligent WHOIS fallback for TLDs that commonly have RDAP issues (.au, .uk, .nz):

1. **Detect RDAP Failures**: When RDAP returns 404 or 403 for .au domains, trigger WHOIS fallback
2. **WHOIS Query**: Query the WHOIS server (whois.auda.org.au) which works reliably for .au domains
3. **Parse WHOIS Data**: Extract registration status, registrar, nameservers, and status codes
4. **Return Proper Results**:
   - Registered domains: Return object with `Registered=True` and parsed WHOIS data
   - Unregistered domains: Return object with `Registered=False` and `Available=True`
   - Query failures: Return `null` to indicate inability to determine status

## Changes Made to Get-DomainStatus.ps1

Modified the catch block (lines 217-332) to:
- Check if RDAP failed with 404/403 for .au, .uk, or .nz domains
- Attempt WHOIS fallback for these TLDs
- Parse WHOIS response to detect "not found" patterns
- Build result object from WHOIS data when domain is registered
- Return null only when both RDAP and WHOIS fail

## Testing Results

### All Tests Passed ✓

| Domain Type | Test Domain | Expected | Result | Status |
|-------------|-------------|----------|--------|--------|
| .com.au (registered) | google.com.au | Registered=True | Registered=True | ✓ PASS |
| .net.au (registered) | abc.net.au | Registered=True | Registered=True | ✓ PASS |
| .org.au (registered) | auda.org.au | Registered=True | Registered=True | ✓ PASS |
| .edu.au (registered) | melbourne.edu.au | Registered=True | Registered=True | ✓ PASS |
| .gov.au (registered) | vic.gov.au | Registered=True | Registered=True | ✓ PASS |
| .com.au (unregistered) | notreal12345xyz.com.au | Registered=False | Registered=False | ✓ PASS |
| .net.au (unregistered) | fake99999test.net.au | Registered=False | Registered=False | ✓ PASS |
| Non-.au domain | google.com | Registered=True (via RDAP) | Registered=True | ✓ PASS |

### Sample Output for Registered .au Domain

```
Domain           : google.com.au
Registered       : True
Available        : False
ExpirationDate   :
DaysUntilExpiry  :
LastChangedDate  : 2025-04-28T01:20:18Z
DaysSinceChange  : 255
RegistrationDate :
Registrar        : MarkMonitor Corporate Services Inc
NameServers      : ns1.google.com, ns2.google.com, ns3.google.com, ns4.google.com
Statuses         : clientDeleteProhibited, serverDeleteProhibited, serverRenewProhibited, serverTransferProhibited
IsLocked         : True
RenewProhibited  : False
InRedemption     : False
PendingDelete    : False
RiskLevel        : Unknown
RiskReason       : RDAP unavailable - limited data from WHOIS
RdapSource       : WHOIS fallback (RDAP unavailable)
```

## Benefits

1. **Accurate Results**: .au domains now return correct registration status
2. **No False Positives**: Registered domains no longer incorrectly marked as available
3. **Backward Compatible**: Non-.au domains continue to use RDAP as before
4. **Extensible**: Easy to add more TLDs to the fallback list if needed
5. **Graceful Degradation**: Returns null only when truly unable to determine status

## Additional TLDs Included

The fix also handles:
- **.uk** domains (which also have RDAP availability issues)
- **.nz** domains (similar issues to .au)

These can be easily expanded by adding to the `$tldNeedsWhoisFallback` array on line 220.

## Verification

Run `Verify-AU-Fix.ps1` or `Test-AU-Comprehensive.ps1` to verify the fix is working correctly.
