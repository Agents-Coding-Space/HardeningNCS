# ==============================================================================
# File: test_vbs_audit.ps1
# Description: Unit and integration tests for Audit-LegacyWin.vbs.
# Compatibility: PowerShell 2.0+
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$rootDir = Split-Path $scriptDir -Parent
$vbsPath = Join-Path $rootDir "src\Audit-LegacyWin.vbs"
$findingListWin7 = Join-Path $rootDir "lists\finding_list_cis_win7_sp1_machine.csv"
$findingList2008 = Join-Path $rootDir "lists\finding_list_cis_server2008r2_machine.csv"
$findingList2012 = Join-Path $rootDir "lists\finding_list_cis_server2012r2_machine.csv"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("vbs_test_" + [System.Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $tempDir -Force)

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

Write-Host "=== TEST SUITE: Audit-LegacyWin.vbs Execution ===" -ForegroundColor Cyan

try {
    # 1. Test running against Win7 finding list
    $win7Out = Join-Path $tempDir "win7_vbs_report.csv"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "cscript.exe"
    $psi.Arguments = "//nologo `"$vbsPath`" `"$findingListWin7`" `"$win7Out`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()

    Assert-Equal "VBScript exit code for Win7" ($proc.ExitCode) 0
    Assert-True "Win7 VBScript report generated" (Test-Path $win7Out)

    if (Test-Path $win7Out) {
        $rows = Import-Csv -Path $win7Out
        $rawRules = Import-Csv -Path $findingListWin7
        Assert-Equal "Win7 row count matches finding list" ($rows.Count) ($rawRules.Count)
        $invalidStatusCount = 0
        foreach ($r in $rows) {
            if ($r.Status -ne "Passed" -and $r.Status -ne "Failed" -and $r.Status -ne "Skipped") {
                $invalidStatusCount++
            }
        }
        Assert-Equal "Status column contains only valid values" $invalidStatusCount 0
    }

    # 2. Test running against Server 2008 R2 finding list
    $s2008Out = Join-Path $tempDir "s2008_vbs_report.csv"
    $psi2 = New-Object System.Diagnostics.ProcessStartInfo
    $psi2.FileName = "cscript.exe"
    $psi2.Arguments = "//nologo `"$vbsPath`" `"$findingList2008`" `"$s2008Out`""
    $psi2.CreateNoWindow = $true
    $psi2.UseShellExecute = $false
    $proc2 = [System.Diagnostics.Process]::Start($psi2)
    $proc2.WaitForExit()

    Assert-Equal "VBScript exit code for Server 2008 R2" ($proc2.ExitCode) 0
    Assert-True "Server 2008 R2 VBScript report generated" (Test-Path $s2008Out)

    if (Test-Path $s2008Out) {
        $rows2 = Import-Csv -Path $s2008Out
        $rawRules2 = Import-Csv -Path $findingList2008
        Assert-Equal "Server 2008 R2 row count matches finding list" ($rows2.Count) ($rawRules2.Count)
    }

    # 3. Test running against Server 2012 R2 finding list
    $s2012Out = Join-Path $tempDir "s2012_vbs_report.csv"
    $psi3 = New-Object System.Diagnostics.ProcessStartInfo
    $psi3.FileName = "cscript.exe"
    $psi3.Arguments = "//nologo `"$vbsPath`" `"$findingList2012`" `"$s2012Out`""
    $psi3.CreateNoWindow = $true
    $psi3.UseShellExecute = $false
    $proc3 = [System.Diagnostics.Process]::Start($psi3)
    $proc3.WaitForExit()

    Assert-Equal "VBScript exit code for Server 2012 R2" ($proc3.ExitCode) 0
    Assert-True "Server 2012 R2 VBScript report generated" (Test-Path $s2012Out)

    if (Test-Path $s2012Out) {
        $rows3 = Import-Csv -Path $s2012Out
        $rawRules3 = Import-Csv -Path $findingList2012
        Assert-Equal "Server 2012 R2 row count matches finding list" ($rows3.Count) ($rawRules3.Count)
    }
}
finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Passed: $passCount" -ForegroundColor Green
Write-Host "Total Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
