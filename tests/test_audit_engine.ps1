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

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Passed: $passCount" -ForegroundColor Green
Write-Host "Total Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
