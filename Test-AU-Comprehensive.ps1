# Comprehensive test for various .au domain types
. "$PSScriptRoot\Get-DomainStatus.ps1"

Write-Host "`nCOMPREHENSIVE .AU DOMAIN TEST" -ForegroundColor Cyan
Write-Host "Testing various .au second-level domains`n" -ForegroundColor Cyan

$testCases = @(
    @{ Domain = 'google.com.au'; ExpectedRegistered = $true; Type = '.com.au' },
    @{ Domain = 'abc.net.au'; ExpectedRegistered = $true; Type = '.net.au' },
    @{ Domain = 'auda.org.au'; ExpectedRegistered = $true; Type = '.org.au' },
    @{ Domain = 'melbourne.edu.au'; ExpectedRegistered = $true; Type = '.edu.au' },
    @{ Domain = 'vic.gov.au'; ExpectedRegistered = $true; Type = '.gov.au' },
    @{ Domain = 'notreal12345xyz.com.au'; ExpectedRegistered = $false; Type = '.com.au unregistered' },
    @{ Domain = 'fake99999test.net.au'; ExpectedRegistered = $false; Type = '.net.au unregistered' }
)

$passCount = 0
$failCount = 0

foreach ($test in $testCases) {
    $domain = $test.Domain
    $expected = $test.ExpectedRegistered
    $type = $test.Type

    Write-Host "Testing: $domain ($type)" -ForegroundColor Yellow

    try {
        $result = Get-DomainStatus -Domain $domain

        if ($null -eq $result) {
            Write-Host "  FAIL: Returned null instead of proper result" -ForegroundColor Red
            $failCount++
        }
        elseif ($result.Registered -eq $expected) {
            Write-Host "  PASS: Registered = $($result.Registered) (as expected)" -ForegroundColor Green
            if ($result.Registered) {
                Write-Host "    Registrar: $($result.Registrar)" -ForegroundColor Gray
                Write-Host "    NameServers: $(($result.NameServers -split ', ' | Select-Object -First 2) -join ', ')..." -ForegroundColor Gray
            }
            $passCount++
        }
        else {
            Write-Host "  FAIL: Expected Registered=$expected but got $($result.Registered)" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host "  FAIL: Exception thrown - $_" -ForegroundColor Red
        $failCount++
    }

    Write-Host ""
}

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "FINAL RESULTS: $passCount PASSED, $failCount FAILED" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Red' })
Write-Host "=" * 80 -ForegroundColor Cyan

if ($failCount -eq 0) {
    Write-Host "`nSUCCESS: All .au domain types are working correctly!" -ForegroundColor Green
    Write-Host "The module now properly handles:" -ForegroundColor Green
    Write-Host "  - Registered .au domains (returns Registered=True with WHOIS data)" -ForegroundColor Green
    Write-Host "  - Unregistered .au domains (returns Registered=False)" -ForegroundColor Green
    Write-Host "  - All .au second-level domains (.com.au, .net.au, .org.au, etc.)" -ForegroundColor Green
}
else {
    Write-Host "`nSome tests failed. Please review the output above." -ForegroundColor Red
}
Write-Host ""
