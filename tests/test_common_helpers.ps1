# ==============================================================================
# File: test_common_helpers.ps1
# Description: Unit tests for Compare-Value.ps1, Parse-SecEdit.ps1, and Parse-AuditPol.ps1.
# Compatibility: PowerShell 2.0+
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$commonDir = Join-Path (Split-Path $scriptDir -Parent) "src\common"

. (Join-Path $commonDir "Compare-Value.ps1")
. (Join-Path $commonDir "Parse-SecEdit.ps1")
. (Join-Path $commonDir "Parse-AuditPol.ps1")

$passCount = 0
$failCount = 0

function Assert-Equal {
    param(
        [string]$TestName,
        [object]$Actual,
        [object]$Expected
    )
    if ($Actual -eq $Expected) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:passCount++
    } else {
        Write-Host "  [FAIL] $TestName (Expected: '$Expected', Actual: '$Actual')" -ForegroundColor Red
        $script:failCount++
    }
}

Write-Host "=== TEST SUITE: Compare-HKValue ===" -ForegroundColor Cyan

# Operator: =
Assert-Equal "Op = (equal numbers)" (Compare-HKValue -Current 1 -Recommended 1 -Operator "=") $true
Assert-Equal "Op = (unequal numbers)" (Compare-HKValue -Current 1 -Recommended 0 -Operator "=") $false
Assert-Equal "Op = (equal strings)" (Compare-HKValue -Current "Disabled" -Recommended "Disabled" -Operator "=") $true
Assert-Equal "Op = (case insensitive)" (Compare-HKValue -Current "disabled" -Recommended "DISABLED" -Operator "=") $true
Assert-Equal "Op = (empty strings)" (Compare-HKValue -Current "" -Recommended "" -Operator "=") $true
Assert-Equal "Op = (null and empty)" (Compare-HKValue -Current $null -Recommended "" -Operator "=") $true

# Operator: Default / empty fallback
Assert-Equal "Op default (omitted operator param)" (Compare-HKValue -Current "Enabled" -Recommended "Enabled") $true
Assert-Equal "Op default (null operator param)" (Compare-HKValue -Current "Enabled" -Recommended "Enabled" -Operator $null) $true
Assert-Equal "Op default (empty operator param)" (Compare-HKValue -Current "Enabled" -Recommended "Enabled" -Operator "") $true
Assert-Equal "Op default (mismatched value)" (Compare-HKValue -Current "Disabled" -Recommended "Enabled" -Operator "") $false

# Operator: = with Regex matching
Assert-Equal "Op = regex (Win2008 R2 pattern match)" (Compare-HKValue -Current "Windows Server 2008 R2 Standard" -Recommended "[a-zA-Z0-9\(\)\s]*2008\s[rR]2[-a-zA-Z0-9\(\)\s]*" -Operator "=") $true
Assert-Equal "Op = regex (Win10 against Win2008 R2 pattern)" (Compare-HKValue -Current "Windows 10 Pro" -Recommended "[a-zA-Z0-9\(\)\s]*2008\s[rR]2[-a-zA-Z0-9\(\)\s]*" -Operator "=") $false
Assert-Equal "Op = regex (screen saver timeout 900)" (Compare-HKValue -Current "900" -Recommended "([1-9]|[1-9][0-9]|[1-8][0-9]{2}|900)" -Operator "=") $true
Assert-Equal "Op = regex (screen saver timeout 901 fail)" (Compare-HKValue -Current "901" -Recommended "([1-9]|[1-9][0-9]|[1-8][0-9]{2}|900)" -Operator "=") $false
Assert-Equal "Op = regex (HardenedPaths mutual auth)" (Compare-HKValue -Current "RequireMutualAuthentication=1,RequireIntegrity=1" -Recommended "[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1.*[Rr]equire([Mm]utual[Aa]uthentication|[Ii]ntegrity)=1" -Operator "=") $true

# Operator: !=
Assert-Equal "Op != (different strings)" (Compare-HKValue -Current "SecAdmin" -Recommended "Administrator" -Operator "!=") $true
Assert-Equal "Op != (identical strings)" (Compare-HKValue -Current "Administrator" -Recommended "Administrator" -Operator "!=") $false
Assert-Equal "Op != (different numbers)" (Compare-HKValue -Current 5 -Recommended 10 -Operator "!=") $true
Assert-Equal "Op != (equal numbers)" (Compare-HKValue -Current 5 -Recommended 5 -Operator "!=") $false

# Operator: >=
Assert-Equal "Op >= (greater number)" (Compare-HKValue -Current 24 -Recommended 24 -Operator ">=") $true
Assert-Equal "Op >= (strictly greater)" (Compare-HKValue -Current 30 -Recommended 24 -Operator ">=") $true
Assert-Equal "Op >= (smaller number)" (Compare-HKValue -Current 10 -Recommended 24 -Operator ">=") $false
Assert-Equal "Op >= (null current)" (Compare-HKValue -Current $null -Recommended 24 -Operator ">=") $false

# Operator: <=
Assert-Equal "Op <= (equal number)" (Compare-HKValue -Current 5 -Recommended 5 -Operator "<=") $true
Assert-Equal "Op <= (smaller number)" (Compare-HKValue -Current 3 -Recommended 5 -Operator "<=") $true
Assert-Equal "Op <= (greater number)" (Compare-HKValue -Current 10 -Recommended 5 -Operator "<=") $false
Assert-Equal "Op <= (null current)" (Compare-HKValue -Current $null -Recommended 5 -Operator "<=") $false

# Operator: <=!0
Assert-Equal "Op <=!0 (Current = 5, Recommended = 5 -> True)" (Compare-HKValue -Current 5 -Recommended 5 -Operator "<=!0") $true
Assert-Equal "Op <=!0 (Current = 3, Recommended = 5 -> True)" (Compare-HKValue -Current 3 -Recommended 5 -Operator "<=!0") $true
Assert-Equal "Op <=!0 (Current = 0, Recommended = 5 -> False)" (Compare-HKValue -Current 0 -Recommended 5 -Operator "<=!0") $false
Assert-Equal "Op <=!0 (Current = '0' string, Recommended = 5 -> False)" (Compare-HKValue -Current "0" -Recommended 5 -Operator "<=!0") $false
Assert-Equal "Op <=!0 (Current = 6, Recommended = 5 -> False)" (Compare-HKValue -Current 6 -Recommended 5 -Operator "<=!0") $false
Assert-Equal "Op <=!0 (Current = null, Recommended = 5 -> False)" (Compare-HKValue -Current $null -Recommended 5 -Operator "<=!0") $false
Assert-Equal "Op <=!0 (Current = empty string, Recommended = 5 -> False)" (Compare-HKValue -Current "" -Recommended 5 -Operator "<=!0") $false
Assert-Equal "Op <=!0 (Current = 42, Recommended = 365 -> True)" (Compare-HKValue -Current 42 -Recommended 365 -Operator "<=!0") $true
Assert-Equal "Op <=!0 (Current = 0, Recommended = 365 -> False)" (Compare-HKValue -Current 0 -Recommended 365 -Operator "<=!0") $false

# Operator: contains
Assert-Equal "Op contains (substring present)" (Compare-HKValue -Current "Success and Failure" -Recommended "Success" -Operator "contains") $true
Assert-Equal "Op contains (substring absent)" (Compare-HKValue -Current "Failure" -Recommended "Success" -Operator "contains") $false
Assert-Equal "Op contains (array contains element)" (Compare-HKValue -Current @("netlogon", "samr", "lsarpc") -Recommended "samr" -Operator "contains") $true
Assert-Equal "Op contains (array misses element)" (Compare-HKValue -Current @("netlogon", "samr") -Recommended "spoolss" -Operator "contains") $false

# Operator: =|0
Assert-Equal "Op =|0 (value matches recommended)" (Compare-HKValue -Current "Disabled" -Recommended "Disabled" -Operator "=|0") $true
Assert-Equal "Op =|0 (value is 0)" (Compare-HKValue -Current 0 -Recommended 15 -Operator "=|0") $true
Assert-Equal "Op =|0 (value is '0' string)" (Compare-HKValue -Current "0" -Recommended 15 -Operator "=|0") $true
Assert-Equal "Op =|0 (value is empty string)" (Compare-HKValue -Current "" -Recommended "Disabled" -Operator "=|0") $true
Assert-Equal "Op =|0 (value is null)" (Compare-HKValue -Current $null -Recommended "Disabled" -Operator "=|0") $true
Assert-Equal "Op =|0 (non-matching non-zero value)" (Compare-HKValue -Current "Manual" -Recommended "Disabled" -Operator "=|0") $false
Assert-Equal "Op =|0 (number matches recommended)" (Compare-HKValue -Current 15 -Recommended 15 -Operator "=|0") $true

Write-Host "`n=== TEST SUITE: Parse-SecEdit ===" -ForegroundColor Cyan

# Test INF file parsing
$sampleInfContent = @"
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
NewAdministratorName = "Administrator"
ClearTextPassword = 0
LSAAnonymousNameLookup = 0

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3

[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544

; End of configuration
"@

$tempInf = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllText($tempInf, $sampleInfContent, [System.Text.Encoding]::Unicode)

try {
    $secEditHash = Parse-SecEditFile -Path $tempInf
    Assert-Equal "Parse INF: System Access\MinimumPasswordAge" $secEditHash["System Access\MinimumPasswordAge"] "1"
    Assert-Equal "Parse INF: System Access\MaximumPasswordAge" $secEditHash["System Access\MaximumPasswordAge"] "60"
    Assert-Equal "Parse INF: System Access\PasswordComplexity" $secEditHash["System Access\PasswordComplexity"] "1"
    Assert-Equal "Parse INF: System Access\NewAdministratorName unquoted" $secEditHash["System Access\NewAdministratorName"] "Administrator"
    Assert-Equal "Parse INF: System Access\ClearTextPassword" $secEditHash["System Access\ClearTextPassword"] "0"
    Assert-Equal "Parse INF: System Access\LSAAnonymousNameLookup" $secEditHash["System Access\LSAAnonymousNameLookup"] "0"
    Assert-Equal "Parse INF: Event Audit\AuditLogonEvents" $secEditHash["Event Audit\AuditLogonEvents"] "3"
    Assert-Equal "Parse INF: Privilege Rights\SeNetworkLogonRight" $secEditHash["Privilege Rights\SeNetworkLogonRight"] "*S-1-1-0,*S-1-5-32-544"
    Assert-Equal "Parse INF: Direct key fallback lookup" $secEditHash["PasswordComplexity"] "1"
}
finally {
    if (Test-Path $tempInf) { Remove-Item $tempInf -Force }
}

Write-Host "`n=== TEST SUITE: Parse-AuditPol ===" -ForegroundColor Cyan

# Test CSV format (/r)
$sampleAuditCsv = @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
TEST-PC,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,
TEST-PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,
TEST-PC,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,
TEST-PC,System,Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Failure,
TEST-PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,
TEST-PC,System,Application Group Management,{0CCE9239-69AE-11D9-BED3-505054503030},Success and Failure,
TEST-PC,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,
TEST-PC,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,
"@

$auditCsvHash = Parse-AuditPolOutput -Lines $sampleAuditCsv
Assert-Equal "AuditPol CSV: Credential Validation" $auditCsvHash["Credential Validation"] "Success and Failure"
Assert-Equal "AuditPol CSV: Logon" $auditCsvHash["Logon"] "Success and Failure"
Assert-Equal "AuditPol CSV: Logoff" $auditCsvHash["Logoff"] "Success"
Assert-Equal "AuditPol CSV: Account Lockout" $auditCsvHash["Account Lockout"] "Failure"
Assert-Equal "AuditPol CSV: Process Creation" $auditCsvHash["Process Creation"] "Success"
Assert-Equal "AuditPol CSV: User Account Management" $auditCsvHash["User Account Management"] "Success and Failure"
Assert-Equal "AuditPol CSV: GUID lookup" $auditCsvHash["{0CCE923F-69AE-11D9-BED3-505054503030}"] "Success and Failure"

# Test Fixed-Width / Tabular format
$sampleAuditTable = @"
System audit policy
Category/Subcategory                      Setting
Account Logon
  Credential Validation                   Success and Failure
  Kerberos Service Ticket Operations      No Auditing
Account Management
  User Account Management                 Success and Failure
Detailed Tracking
  Process Creation                        Success
Logon/Logoff
  Logon                                   Success and Failure
  Logoff                                  Success
  Account Lockout                         Failure
"@

$auditTableHash = Parse-AuditPolOutput -Lines $sampleAuditTable
Assert-Equal "AuditPol Table: Credential Validation" $auditTableHash["Credential Validation"] "Success and Failure"
Assert-Equal "AuditPol Table: Kerberos Service Ticket Operations" $auditTableHash["Kerberos Service Ticket Operations"] "No Auditing"
Assert-Equal "AuditPol Table: User Account Management" $auditTableHash["User Account Management"] "Success and Failure"
Assert-Equal "AuditPol Table: Process Creation" $auditTableHash["Process Creation"] "Success"
Assert-Equal "AuditPol Table: Logon" $auditTableHash["Logon"] "Success and Failure"

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Passed: $passCount" -ForegroundColor Green
Write-Host "Total Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
