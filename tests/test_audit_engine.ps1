# ==============================================================================
# File: test_audit_engine.ps1
# Description: Unit and integration tests for Audit-LegacyWin.ps1.
# Compatibility: PowerShell 2.0+
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$rootDir = Split-Path $scriptDir -Parent
$auditEnginePath = Join-Path $rootDir "src\Audit-LegacyWin.ps1"
$findingListWin7 = Join-Path $rootDir "lists\finding_list_cis_win7_sp1_machine.csv"
$tempOutputDir = Join-Path $rootDir "outputs"

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

function Assert-True {
    param(
        [string]$TestName,
        [bool]$Condition
    )
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:passCount++
    } else {
        Write-Host "  [FAIL] $TestName (Expected: True, Actual: False)" -ForegroundColor Red
        $script:failCount++
    }
}

Write-Host "=== TEST SUITE: Audit-LegacyWin.ps1 Execution & Schema ===" -ForegroundColor Cyan

# 1. Test basic execution with default finding list
$tempReport = Join-Path $tempOutputDir ("test_audit_report_" + [System.Guid]::NewGuid().ToString("N") + ".csv")
& $auditEnginePath -FindingList $findingListWin7 -OutputDir $tempReport -SkipMethods @("secedit", "accountpolicy", "auditpol")

Assert-True "Audit report CSV was created" (Test-Path $tempReport)

if (Test-Path $tempReport) {
    $rows = Import-Csv -Path $tempReport
    $rawRules = Import-Csv -Path $findingListWin7

    Assert-Equal "Report row count matches input rules" $rows.Count $rawRules.Count

    # Verify column schema
    $expectedCols = @("ID", "Category", "Name", "Method", "MethodArgument", "RegistryPath", "RegistryItem", "DefaultValue", "RecommendedValue", "Operator", "Severity", "CurrentValue", "Status")
    $firstRow = $rows[0]
    $allColsPresent = $true
    foreach ($col in $expectedCols) {
        if (-not ($firstRow.PSObject.Properties[$col])) {
            $allColsPresent = $false
            Write-Host "  Missing column: $col" -ForegroundColor Red
        }
    }
    Assert-True "All 13 expected columns are present in report CSV" $allColsPresent

    # Verify status values
    $validStatuses = $true
    foreach ($r in $rows) {
        if ($r.Status -ne "Passed" -and $r.Status -ne "Failed" -and $r.Status -ne "Skipped") {
            $validStatuses = $false
            Write-Host "  Invalid status '$($r.Status)' on ID $($r.ID)" -ForegroundColor Red
        }
    }
    Assert-True "All status values are Passed, Failed, or Skipped" $validStatuses

    # Verify SkipMethods properly marked rows as Skipped
    $skippedMethodsWorking = $true
    foreach ($r in $rows) {
        if ($r.Method -eq "secedit" -or $r.Method -eq "accountpolicy" -or $r.Method -eq "auditpol") {
            if ($r.Status -ne "Skipped") {
                $skippedMethodsWorking = $false
            }
        }
    }
    Assert-True "SkipMethods correctly marked specified methods as Skipped" $skippedMethodsWorking

    # Cleanup temp report
    Remove-Item -Path $tempReport -Force -ErrorAction SilentlyContinue
}

# 2. Test MpPreferenceAsr skipping behavior
Write-Host "`n=== TEST SUITE: MpPreferenceAsr Skipping ===" -ForegroundColor Cyan
$dummyFindingList = [System.IO.Path]::GetTempFileName() + ".csv"
$dummyCsvContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity
TEST-ASR-1,Attack Surface,Block executable content from email,MpPreferenceAsr,AsrRule1,,,0,1,=,High
TEST-REG-1,Security Options,Test Reg Rule,Registry,CrashOnAuditFail,HKLM\SYSTEM\CurrentControlSet\Control\Lsa,CrashOnAuditFail,0,0,=,Low
"@
[System.IO.File]::WriteAllText($dummyFindingList, $dummyCsvContent)
$dummyOutput = [System.IO.Path]::GetTempFileName() + ".csv"

try {
    & $auditEnginePath -FindingList $dummyFindingList -OutputDir $dummyOutput
    Assert-True "Dummy audit report produced" (Test-Path $dummyOutput)

    if (Test-Path $dummyOutput) {
        $dummyRows = Import-Csv -Path $dummyOutput
        Assert-Equal "Dummy finding count" $dummyRows.Count 2
        Assert-Equal "MpPreferenceAsr status is Skipped" $dummyRows[0].Status "Skipped"
        Assert-Equal "Registry rule status evaluated" $dummyRows[1].Status "Passed"
    }
}
finally {
    if (Test-Path $dummyFindingList) { Remove-Item $dummyFindingList -Force -ErrorAction SilentlyContinue }
    if (Test-Path $dummyOutput) { Remove-Item $dummyOutput -Force -ErrorAction SilentlyContinue }
}

# 3. Test Method Adapters (accesschk, accountpolicy, localaccount, command, unknown)
Write-Host "`n=== TEST SUITE: Method Adapters & Unknown Method Safety ===" -ForegroundColor Cyan
$adapterFindingList = [System.IO.Path]::GetTempFileName() + ".csv"
$adapterCsvContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity
TEST-ACC-1,Privilege Rights,Credential Manager,accesschk,SeTrustedCredManAccessPrivilege,,,,,,Low
TEST-ACC-2,Privilege Rights,NonExistentPriv,accesschk,SeNonExistentPrivilege,,,BUILTIN\Administrators,BUILTIN\Administrators,=,Medium
TEST-POL-1,Account Policies,Max Password Age,accountpolicy,MAXIMUM_PASSWORD_AGE,,,42,365,<=!0,Medium
TEST-POL-2,Account Policies,Enforce History,accountpolicy,ENFORCE_PASSWORD_HISTORY,,,0,24,>=,Medium
TEST-USR-1,Security Options,Admin Rename Check,localaccount,500,,,Administrator,Administrator,!=,Medium
TEST-USR-2,Security Options,Guest Status Check,localaccount,501,,,False,False,=,Medium
TEST-CMD-1,Software,EMET Installed Check,command,,,,,EMET 5\.52,=,Medium
TEST-UNK-1,Unknown Area,Unknown Custom Method,unknownmethod,Arg1,,,0,,=,High
"@
[System.IO.File]::WriteAllText($adapterFindingList, $adapterCsvContent)
$adapterOutput = [System.IO.Path]::GetTempFileName() + ".csv"

try {
    & $auditEnginePath -FindingList $adapterFindingList -OutputDir $adapterOutput
    Assert-True "Adapter audit report produced" (Test-Path $adapterOutput)

    if (Test-Path $adapterOutput) {
        $adapterRows = Import-Csv -Path $adapterOutput
        Assert-Equal "Adapter test finding count" $adapterRows.Count 8

        # TEST-ACC-1: empty current vs empty recommended -> Passed
        $rAcc1 = $adapterRows | Where-Object { $_.ID -eq "TEST-ACC-1" }
        Assert-Equal "TEST-ACC-1 status is Passed" $rAcc1.Status "Passed"

        # TEST-ACC-2: non-existent privilege -> current is "" vs recommended BUILTIN\Administrators -> Failed
        $rAcc2 = $adapterRows | Where-Object { $_.ID -eq "TEST-ACC-2" }
        Assert-Equal "TEST-ACC-2 status is Failed" $rAcc2.Status "Failed"

        # TEST-POL-1: MAXIMUM_PASSWORD_AGE via net accounts fallback -> 42 <=!0 365 -> Passed
        $rPol1 = $adapterRows | Where-Object { $_.ID -eq "TEST-POL-1" }
        Assert-Equal "TEST-POL-1 status is Passed" $rPol1.Status "Passed"

        # TEST-USR-1: Administrator name is 'Administrator' -> 'Administrator' != 'Administrator' is False -> Failed
        $rUsr1 = $adapterRows | Where-Object { $_.ID -eq "TEST-USR-1" }
        Assert-Equal "TEST-USR-1 status is Failed" $rUsr1.Status "Failed"

        # TEST-CMD-1: EMET is not installed -> Not Installed -> Failed
        $rCmd1 = $adapterRows | Where-Object { $_.ID -eq "TEST-CMD-1" }
        Assert-Equal "TEST-CMD-1 status is Failed" $rCmd1.Status "Failed"
        Assert-Equal "TEST-CMD-1 CurrentValue is Not Installed" $rCmd1.CurrentValue "Not Installed"

        # TEST-UNK-1: Unknown method MUST be Skipped, NEVER Passed!
        $rUnk1 = $adapterRows | Where-Object { $_.ID -eq "TEST-UNK-1" }
        Assert-Equal "TEST-UNK-1 status is Skipped" $rUnk1.Status "Skipped"
    }
}
finally {
    if (Test-Path $adapterFindingList) { Remove-Item $adapterFindingList -Force -ErrorAction SilentlyContinue }
    if (Test-Path $adapterOutput) { Remove-Item $adapterOutput -Force -ErrorAction SilentlyContinue }
}

# 4. Test running against original 21-column CIS Benchmark file
Write-Host "`n=== TEST SUITE: 21-Column CIS Benchmark Processing & Dual Engine Parity ===" -ForegroundColor Cyan
$findingList21Col = Join-Path $rootDir "lists\CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv"
$tempReport21ColPS = Join-Path $tempOutputDir ("test_audit_report_21col_ps_" + [System.Guid]::NewGuid().ToString("N") + ".csv")
$tempReport21ColVBS = Join-Path $tempOutputDir ("test_audit_report_21col_vbs_" + [System.Guid]::NewGuid().ToString("N") + ".csv")
$vbsEnginePath = Join-Path $rootDir "src\Audit-LegacyWin.vbs"

try {
    # Full run with PS2 Engine (without SkipMethods)
    & $auditEnginePath -FindingList $findingList21Col -OutputDir $tempReport21ColPS
    Assert-True "21-column PS2 audit report CSV created" (Test-Path $tempReport21ColPS)

    # Full run with VBScript Engine
    $psiVbs = New-Object System.Diagnostics.ProcessStartInfo
    $psiVbs.FileName = "cscript.exe"
    $psiVbs.Arguments = "//nologo `"$vbsEnginePath`" `"$findingList21Col`" `"$tempReport21ColVBS`""
    $psiVbs.CreateNoWindow = $true
    $psiVbs.UseShellExecute = $false
    $procVbs = [System.Diagnostics.Process]::Start($psiVbs)
    if ($null -ne $procVbs) { $procVbs.WaitForExit() }
    Assert-True "21-column VBScript audit report CSV created" (Test-Path $tempReport21ColVBS)

    if ((Test-Path $tempReport21ColPS) -and (Test-Path $tempReport21ColVBS)) {
        $rowsPS = @(Import-Csv -Path $tempReport21ColPS)
        $rowsVBS = @(Import-Csv -Path $tempReport21ColVBS)

        Assert-Equal "PS2 report row count is exactly 324" ($rowsPS.Length) 324
        Assert-Equal "VBScript report row count is exactly 324" ($rowsVBS.Length) 324

        # Verify no unknown status values
        $validStatuses = $true
        foreach ($r in $rowsPS) {
            if ($r.Status -ne "Passed" -and $r.Status -ne "Failed" -and $r.Status -ne "Skipped") {
                $validStatuses = $false
            }
        }
        Assert-True "PS2 status values are all Passed/Failed/Skipped" $validStatuses

        # Dual-engine parity verification across all 324 rules
        $discrepancies = 0
        for ($i = 0; $i -lt $rowsPS.Length; $i++) {
            if ($rowsPS[$i].Status -ne $rowsVBS[$i].Status) {
                $discrepancies++
            }
        }
        Assert-Equal "Dual-engine status discrepancies across all 324 rules" $discrepancies 0

        # Verify ID 1.1.2 safe property extraction
        $rule112 = $null
        foreach ($r in $rowsPS) {
            if ($r.ID -eq "1.1.2") { $rule112 = $r; break }
        }
        Assert-True "Found ID 1.1.2 in report" ($null -ne $rule112)
        if ($null -ne $rule112) {
            Assert-Equal "ID 1.1.2 Operator is <=!0" ($rule112.Operator) "<=!0"
            Assert-Equal "ID 1.1.2 RecommendedValue is 365" ($rule112.RecommendedValue) "365"
            Assert-Equal "ID 1.1.2 DefaultValue is 42" ($rule112.DefaultValue) "42"
        }
    }
}
finally {
    if (Test-Path $tempReport21ColPS) { Remove-Item $tempReport21ColPS -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempReport21ColVBS) { Remove-Item $tempReport21ColVBS -Force -ErrorAction SilentlyContinue }
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Passed: $passCount" -ForegroundColor Green
Write-Host "Total Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
