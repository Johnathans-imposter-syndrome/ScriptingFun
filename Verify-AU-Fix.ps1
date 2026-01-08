# Verification test for the .au domain fix
. "$PSScriptRoot\Get-DomainStatus.ps1"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "VERIFICATION TEST FOR .AU DOMAIN FIX" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Test 1: Known registered .au domain
Write-Host "TEST 1: Known registered domain (google.com.au)" -ForegroundColor Yellow
$result1 = Get-DomainStatus -Domain 'google.com.au'

if ($null -eq $result1) {
    Write-Host "  FAIL: Returned null" -ForegroundColor Red
}
elseif ($result1.Registered -eq $true) {
    Write-Host "  PASS: Correctly identified as registered" -ForegroundColor Green
    Write-Host "  - Registrar: $($result1.Registrar)" -ForegroundColor Gray
    Write-Host "  - NameServers: $($result1.NameServers)" -ForegroundColor Gray
    Write-Host "  - Source: $($result1.RdapSource)" -ForegroundColor Gray
}
elseif ($result1.Registered -eq $false) {
    Write-Host "  FAIL: Incorrectly marked as not registered" -ForegroundColor Red
}
else {
    Write-Host "  FAIL: Registered property has unexpected value: $($result1.Registered)" -ForegroundColor Red
}

Write-Host ""

# Test 2: Known unregistered .au domain
Write-Host "TEST 2: Known unregistered domain (xyz999notreal.com.au)" -ForegroundColor Yellow
$result2 = Get-DomainStatus -Domain 'xyz999notreal.com.au'

if ($null -eq $result2) {
    Write-Host "  FAIL: Returned null (should return object with Registered=false)" -ForegroundColor Red
}
elseif ($result2.Registered -eq $false -and $result2.Available -eq $true) {
    Write-Host "  PASS: Correctly identified as not registered/available" -ForegroundColor Green
    Write-Host "  - Source: $($result2.RdapSource)" -ForegroundColor Gray
}
else {
    Write-Host "  FAIL: Unexpected result - Registered: $($result2.Registered), Available: $($result2.Available)" -ForegroundColor Red
}

Write-Host ""

# Test 3: Another known registered .au domain
Write-Host "TEST 3: Another registered domain (microsoft.com.au)" -ForegroundColor Yellow
$result3 = Get-DomainStatus -Domain 'microsoft.com.au'

if ($null -eq $result3) {
    Write-Host "  FAIL: Returned null" -ForegroundColor Red
}
elseif ($result3.Registered -eq $true) {
    Write-Host "  PASS: Correctly identified as registered" -ForegroundColor Green
    Write-Host "  - Registrar: $($result3.Registrar)" -ForegroundColor Gray
    Write-Host "  - Last Changed: $($result3.LastChangedDate)" -ForegroundColor Gray
    Write-Host "  - Source: $($result3.RdapSource)" -ForegroundColor Gray
}
else {
    Write-Host "  FAIL: Incorrectly marked as not registered" -ForegroundColor Red
}

Write-Host ""

# Test 4: Verify non-.au domains still work (fallback shouldn't affect them)
Write-Host "TEST 4: Non-.au domain (google.com)" -ForegroundColor Yellow
$result4 = Get-DomainStatus -Domain 'google.com'

if ($null -eq $result4) {
    Write-Host "  FAIL: Returned null" -ForegroundColor Red
}
elseif ($result4.Registered -eq $true) {
    Write-Host "  PASS: Correctly identified as registered" -ForegroundColor Green
    Write-Host "  - Source: $($result4.RdapSource)" -ForegroundColor Gray
    Write-Host "  - Has expiration date: $($null -ne $result4.ExpirationDate)" -ForegroundColor Gray
}
else {
    Write-Host "  FAIL: Unexpected result" -ForegroundColor Red
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "VERIFICATION COMPLETE" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Summary
$testResults = @($result1, $result2, $result3, $result4)
$passCount = 0
$failCount = 0

if ($result1 -and $result1.Registered -eq $true) { $passCount++ } else { $failCount++ }
if ($result2 -and $result2.Registered -eq $false) { $passCount++ } else { $failCount++ }
if ($result3 -and $result3.Registered -eq $true) { $passCount++ } else { $failCount++ }
if ($result4 -and $result4.Registered -eq $true) { $passCount++ } else { $failCount++ }

Write-Host "Summary: $passCount PASSED, $failCount FAILED" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Red' })
Write-Host ""

if ($failCount -eq 0) {
    Write-Host "All tests passed! The .au domain fix is working correctly." -ForegroundColor Green
}
else {
    Write-Host "Some tests failed. Please review the results above." -ForegroundColor Red
}
