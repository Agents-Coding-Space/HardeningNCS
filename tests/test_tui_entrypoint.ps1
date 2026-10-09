# ==============================================================================
# File: test_tui_entrypoint.ps1
# Description: Regression & Unit Test Suite for HardeningNCS entrypoint,
#              interactive TUI controller helpers, and non-interactive batch mode.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = (Get-Location).Path
}

$rootDir = Split-Path $scriptDir -Parent
$commonDir = Join-Path $rootDir "src\common"
$entryPointScript = Join-Path $rootDir "HardeningNCS.ps1"
$cmdWrapper = Join-Path $rootDir "HardeningNCS.cmd"

# Dot-source helpers for unit testing internal functions
. (Join-Path $commonDir "Invoke-WmiCompat.ps1")
. (Join-Path $commonDir "Detect-Environment.ps1")
. (Join-Path $commonDir "Tui-Helpers.ps1")

$passCount = 0
$failCount = 0

function Assert-HKTest {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$Message = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:passCount++
    } else {
        $msg = if ($Message) { " - " + $Message } else { "" }
        Write-Host "  [FAIL] $TestName$msg" -ForegroundColor Red
        $script:failCount++
    }
}

function Assert-HKEqual {
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

Write-Host "=== TEST SUITE: HardeningNCS Entry Point & TUI Controller ===" -ForegroundColor Cyan

# Setup temporary sandbox directory for test artifacts
$testGuid = [System.Guid]::NewGuid().ToString("N")
$testSandbox = Join-Path ([System.IO.Path]::GetTempPath()) ("hk_tui_test_" + $testGuid)
[void](New-Item -ItemType Directory -Path $testSandbox -Force)

$testOutputs = Join-Path $testSandbox "outputs"
[void](New-Item -ItemType Directory -Path $testOutputs -Force)

# Create a minimal test finding list CSV for fast, isolated batch testing
$sampleFindingList = Join-Path $testSandbox "sample_findings.csv"
$csvHeader = "ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity"
$csvRow1 = 'TEST-TUI-1,System,Test Min Password Age,accountpolicy,MinimumPasswordAge,,,,1,>=,Medium'
$csvRow2 = 'TEST-TUI-2,Registry,Test Safe Reg Item,Registry,,HKCU\Software\TestHardeningNCS,SafeValue,0,1,=,High'
[System.IO.File]::WriteAllLines($sampleFindingList, @($csvHeader, $csvRow1, $csvRow2))

# ------------------------------------------------------------------------------
# Test Section 1: System Info Detection & Suggested Checklist
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing System Detection & Recommendation ---" -ForegroundColor Yellow

$sysInfo = Get-HKSystemInfo
Assert-HKTest "SystemInfo is detected" ($null -ne $sysInfo)
Assert-HKTest "System Caption populated" (-not [string]::IsNullOrEmpty($sysInfo.Caption))
Assert-HKTest "PSVersion populated" (-not [string]::IsNullOrEmpty($sysInfo.PSVersion))
Assert-HKTest "DomainRoleName populated" (-not [string]::IsNullOrEmpty($sysInfo.DomainRoleName))

$catalog = Get-HKChecklistCatalog -BaseDir $rootDir
Assert-HKTest "Catalog indexed successfully" ($null -ne $catalog -and @($catalog).Length -gt 10)

$suggested = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $sysInfo
Assert-HKTest "Suggested checklist resolved" ($null -ne $suggested)
if ($null -ne $suggested) {
    Assert-HKTest "Suggested checklist file exists" (Test-Path -Path $suggested.FullPath)
}

# ------------------------------------------------------------------------------
# Test Section 2: Catalog Filtering & Paging Logic
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Catalog Filtering & Navigation Mechanics ---" -ForegroundColor Yellow

$filteredWin = @(Filter-HKChecklists -Checklists $catalog -Keyword "win7")
Assert-HKTest "Filter by 'win7' returns matching items" (@($filteredWin).Length -gt 0)

$filteredNonExistent = Filter-HKChecklists -Checklists $catalog -Keyword "nonexistent_checklist_xyz_999"
$nonExistCount = if ($null -eq $filteredNonExistent) { 0 } else { @($filteredNonExistent).Length }
Assert-HKEqual "Filter non-existent keyword returns 0 items" $nonExistCount 0

$filteredEmpty = @(Filter-HKChecklists -Checklists $catalog -Keyword "")
Assert-HKEqual "Empty filter keyword preserves all items" (@($filteredEmpty).Length) (@($catalog).Length)

$rendered = Render-HKPage -Items $catalog -PageIndex 0 -PageSize 10 -TerminalWidth 80 -SuggestedItem $suggested -PassThru
Assert-HKTest "Render-HKPage produces non-empty output" ($null -ne $rendered -and $rendered.Length -gt 0)

# ------------------------------------------------------------------------------
# Test Section 2.1: Anti-Wrap Terminal Width Compatibility (40-49 Columns)
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Anti-Wrap Protection Across Narrow Terminals (40-49 Cols) ---" -ForegroundColor Yellow

foreach ($w in @(40, 42, 44, 45, 49)) {
    $renderedNarrow = Render-HKPage -Items $catalog -PageIndex 0 -PageSize 5 -TerminalWidth $w -SuggestedItem $suggested -PassThru
    $overflowNarrow = $false
    foreach ($line in $renderedNarrow) {
        if ($line.Length -gt $w) {
            $overflowNarrow = $true
            Write-Host ("Line overflowed " + $w + ": [" + $line.Length + "] " + $line) -ForegroundColor Red
        }
    }
    Assert-HKTest ("Render-HKPage at width " + $w + " has zero overflowing lines") (-not $overflowNarrow)

    $cardLines = Show-HKSystemSummaryCard -SystemInfo $sysInfo -TerminalWidth $w -PassThru
    $cardOverflow = $false
    foreach ($cline in $cardLines) {
        if ($cline.Length -gt $w) {
            $cardOverflow = $true
            Write-Host ("Card line overflowed " + $w + ": [" + $cline.Length + "] " + $cline) -ForegroundColor Red
        }
    }
    Assert-HKTest ("Show-HKSystemSummaryCard at width " + $w + " has zero overflowing lines") (-not $cardOverflow)

    $bannerLines = Show-HKBanner -TerminalWidth $w -PassThru
    $bannerOverflow = $false
    foreach ($bline in $bannerLines) {
        if ($bline.Length -gt $w) {
            $bannerOverflow = $true
            Write-Host ("Banner line overflowed " + $w + ": [" + $bline.Length + "] " + $bline) -ForegroundColor Red
        }
    }
    Assert-HKTest ("Show-HKBanner at width " + $w + " has zero overflowing lines") (-not $bannerOverflow)
}

# Verify compact banner behavior for width < 50 (specifically 40 cols)
$banner40 = Show-HKBanner -TerminalWidth 40 -PassThru
$hasCompactTitle = $false
$hasFullAscii = $false
foreach ($bl in $banner40) {
    if ($bl.Contains("HardeningNCS | PS 2.0+ Edition")) { $hasCompactTitle = $true }
    if ($bl.Contains(".+xXXXXXXX;")) { $hasFullAscii = $true }
}
Assert-HKTest "Show-HKBanner uses compact banner at 40 cols" ($hasCompactTitle -and -not $hasFullAscii)

# Verify standard ASCII banner behavior for width >= 50 (80 cols)
$banner80 = Show-HKBanner -TerminalWidth 80 -PassThru
$hasFullAscii80 = $false
foreach ($bl in $banner80) {
    if ($bl.Contains(".+xXXXXXXX;")) { $hasFullAscii80 = $true }
}
Assert-HKTest "Show-HKBanner uses full ASCII banner at 80 cols" $hasFullAscii80

# ------------------------------------------------------------------------------
# Test Section 3: Batch Mode - Action Audit
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Batch Mode: Action Audit ---" -ForegroundColor Yellow

$proc = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Audit -ChecklistPath `"$sampleFindingList`" -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Batch Audit exit code is 0" $proc.ExitCode 0

$reportCandidates = @(Get-ChildItem -Path $testOutputs -Filter "audit_report_*.csv")
Assert-HKTest "Batch Audit generated audit report CSV" (@($reportCandidates).Length -ge 1)

$latestReport = $reportCandidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$reportRows = @(Import-Csv -Path $latestReport.FullName)
Assert-HKEqual "Audit report contains exactly 2 finding rows" (@($reportRows).Length) 2

# ------------------------------------------------------------------------------
# Test Section 4: Batch Mode - Action ViewReport & Action Report
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Batch Mode: Action ViewReport & Action Report ---" -ForegroundColor Yellow

$procView = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action ViewReport -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Batch ViewReport exit code is 0" $procView.ExitCode 0

$procReport = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Report -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Batch Report exit code is 0" $procReport.ExitCode 0

# ------------------------------------------------------------------------------
# Test Section 5: Batch Mode - Action WhatIf
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Batch Mode: Action WhatIf ---" -ForegroundColor Yellow

$procWhatIf = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action WhatIf -ChecklistPath `"$sampleFindingList`" -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Batch WhatIf exit code is 0" $procWhatIf.ExitCode 0

# Verify WhatIf safety invariant: NO backup session directory created
$backupDirs = @(Get-ChildItem -Path $testOutputs -Filter "backup_session_*")
Assert-HKEqual "WhatIf did not create any backup_session_* directories" (@($backupDirs).Length) 0

# ------------------------------------------------------------------------------
# Test Section 5.1: Non-Interactive Remediation Safety Confirmation
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Non-Interactive Remediation Safety Confirmation ---" -ForegroundColor Yellow

# Attempt non-interactive remediation WITHOUT -ConfirmRemediation
$remErr = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$entryPointScript" `
    -NonInteractive -Action Remediate -ChecklistPath "$sampleFindingList" -OutputDir "$testOutputs" 2>&1

$hasExpectedErr = $false
foreach ($e in $remErr) {
    if ($null -ne $e -and ($e -match "Non-interactive remediation requires explicit -ConfirmRemediation switch" -or ($null -ne $e.Exception -and $e.Exception.Message.Contains("-ConfirmRemediation")))) {
        $hasExpectedErr = $true
        break
    }
}
Assert-HKTest "Non-interactive Remediate without -ConfirmRemediation is rejected" $hasExpectedErr

# Verify non-interactive remediation refusal exits with non-zero exit code (P1 finding)
$procRefuse = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Remediate -ChecklistPath `"$sampleFindingList`" -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKTest "Non-interactive Remediate without confirmation exits with non-zero exit code" ($procRefuse.ExitCode -ne 0)
Assert-HKEqual "Non-interactive Remediate refusal exit code is specifically 1" $procRefuse.ExitCode 1

# Verify no remediation was run: backup dirs still 0
$backupDirsBefore = @(Get-ChildItem -Path $testOutputs -Filter "backup_session_*")
Assert-HKEqual "No backup session directory created when remediation is rejected" (@($backupDirsBefore).Length) 0

# Create dedicated sandbox for confirmed remediation test (uses standard user-safe HKCU registry finding)
$remConfirmDir = Join-Path $testSandbox "rem_confirm_sandbox"
[void](New-Item -ItemType Directory -Path $remConfirmDir -Force)
$regFindingsCsv = Join-Path $remConfirmDir "findings_reg.csv"
$csvHeader = "ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity"
$csvRowReg = "TEST-CONFIRM-REG,Registry,Test Safe HKCU,Registry,,HKCU\Software\TestHardeningNCSConfirm,SafeVal,0,1,=,High"
[System.IO.File]::WriteAllLines($regFindingsCsv, @($csvHeader, $csvRowReg))

New-Item -Path "HKCU:\Software\TestHardeningNCSConfirm" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\TestHardeningNCSConfirm" -Name "SafeVal" -Value 0

# Run audit on this finding to generate audit report in the sandbox
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$entryPointScript" `
    -NonInteractive -Action Audit -ChecklistPath "$regFindingsCsv" -OutputDir "$remConfirmDir" | Out-Null

# Test non-interactive remediation WITH -ConfirmRemediation
$procRemConfirm = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Remediate -ChecklistPath `"$regFindingsCsv`" -OutputDir `"$remConfirmDir`" -ConfirmRemediation" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Non-interactive Remediate with -ConfirmRemediation exits with code 0" $procRemConfirm.ExitCode 0

# Verify backup session was created when confirmed
$backupDirsAfter = @(Get-ChildItem -Path $remConfirmDir -Filter "backup_session_*")
Assert-HKTest "Backup session created when remediation is confirmed" (@($backupDirsAfter).Length -ge 1)

# Cleanup HKCU test reg key
Remove-Item -Path "HKCU:\Software\TestHardeningNCSConfirm" -Recurse -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------------
# Test Section 5.2: Non-Interactive Remediation with -Force Switch
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Non-Interactive Remediation with -Force Switch ---" -ForegroundColor Yellow

# Create dedicated sandbox for -Force remediation test
$remForceDir = Join-Path $testSandbox "rem_force_sandbox"
[void](New-Item -ItemType Directory -Path $remForceDir -Force)
$forceFindingsCsv = Join-Path $remForceDir "findings_force.csv"
$csvHeader = "ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity"
$csvRowForce = "TEST-FORCE-REG,Registry,Test Safe HKCU Force,Registry,,HKCU\Software\TestHardeningNCSForce,ForceVal,0,1,=,High"
[System.IO.File]::WriteAllLines($forceFindingsCsv, @($csvHeader, $csvRowForce))

New-Item -Path "HKCU:\Software\TestHardeningNCSForce" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\TestHardeningNCSForce" -Name "ForceVal" -Value 0

# Run audit on this finding to generate audit report in the sandbox
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$entryPointScript" `
    -NonInteractive -Action Audit -ChecklistPath "$forceFindingsCsv" -OutputDir "$remForceDir" | Out-Null

# Test non-interactive remediation WITH -Force (omitting -ConfirmRemediation)
$procRemForce = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Remediate -ChecklistPath `"$forceFindingsCsv`" -OutputDir `"$remForceDir`" -Force" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Non-interactive Remediate with -Force exits with code 0" $procRemForce.ExitCode 0

# Verify backup session was created when -Force is used
$backupDirsForce = @(Get-ChildItem -Path $remForceDir -Filter "backup_session_*")
Assert-HKTest "Backup session created when remediation is run with -Force" (@($backupDirsForce).Length -ge 1)

# Verify value was actually remediated
$remediatedVal = (Get-ItemProperty -Path "HKCU:\Software\TestHardeningNCSForce" -Name "ForceVal").ForceVal
Assert-HKEqual "Registry value successfully remediated via -Force" $remediatedVal 1

# Cleanup HKCU test reg key for Force test
Remove-Item -Path "HKCU:\Software\TestHardeningNCSForce" -Recurse -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------------
# Test Section 6: Manifest Selection & Discovery
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Manifest Discovery & Rollback Batch Mode ---" -ForegroundColor Yellow

# Create mock backup session 1 (earlier)
$session1Dir = Join-Path $testOutputs "backup_session_20261001_100000_1234_5678"
[void](New-Item -ItemType Directory -Path $session1Dir -Force)
$manifest1File = Join-Path $session1Dir "backup_manifest.txt"
$manContent1 = @"
# HardeningNCS Backup Manifest
Session: backup_session_20261001_100000_1234_5678
Date: 2026-10-01 10:00:00
[Registry]
[Secedit]
[Auditpol]
[Services]
"@
[System.IO.File]::WriteAllText($manifest1File, $manContent1)

# Create mock backup session 2 (later)
$session2Dir = Join-Path $testOutputs "backup_session_20261002_120000_4321_8765"
[void](New-Item -ItemType Directory -Path $session2Dir -Force)
$manifest2File = Join-Path $session2Dir "backup_manifest.txt"
$manContent2 = @"
# HardeningNCS Backup Manifest
Session: backup_session_20261002_120000_4321_8765
Date: 2026-10-02 12:00:00
[Registry]
[Secedit]
[Auditpol]
[Services]
"@
[System.IO.File]::WriteAllText($manifest2File, $manContent2)

# Ensure session 2 is strictly newer in LastWriteTime
(Get-Item $manifest1File).LastWriteTime = (Get-Date).AddMinutes(-10)
(Get-Item $manifest2File).LastWriteTime = (Get-Date)

$manifestsFound = @(Get-ChildItem -Path $testOutputs -Filter "backup_manifest.txt" -Recurse | Sort-Object LastWriteTime -Descending)
Assert-HKEqual "Discovered 2 mock manifests" (@($manifestsFound).Length) 2
Assert-HKTest "Latest manifest is session 2" ($manifestsFound[0].FullName.Contains("backup_session_20261002"))

# Test Batch Action Rollback with explicit -ManifestPath
$procRollbackExp = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Rollback -ManifestPath `"$manifest2File`" -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Batch Rollback with explicit ManifestPath exit code is 0" $procRollbackExp.ExitCode 0

# Test Batch Action Rollback with auto-detected latest manifest (omitting -ManifestPath)
$procRollbackAuto = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Rollback -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "Batch Rollback with auto-detected manifest exit code is 0" $procRollbackAuto.ExitCode 0

# ------------------------------------------------------------------------------
# Test Section 7: HardeningNCS.cmd Wrapper Execution
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing HardeningNCS.cmd Batch Wrapper ---" -ForegroundColor Yellow

Assert-HKTest "HardeningNCS.cmd exists" (Test-Path -Path $cmdWrapper)

# Invoke cmd wrapper with arguments forwarding
$procCmd = Start-Process -FilePath $cmdWrapper `
    -ArgumentList "-NonInteractive -Action ViewReport -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKEqual "HardeningNCS.cmd wrapper executed cleanly with exit code 0" $procCmd.ExitCode 0

# ------------------------------------------------------------------------------
# Test Section 8: Error Handling & Invalid Input Safety
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Error Handling & Safety Invariants ---" -ForegroundColor Yellow

# Non-existent checklist path should fail with non-zero exit code
$procNonExistentList = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$entryPointScript`" -NonInteractive -Action Audit -ChecklistPath `"C:\nonexistent_path\fake.csv`" -OutputDir `"$testOutputs`"" `
    -Wait -Passthru -NoNewWindow

Assert-HKTest "Non-existent checklist path aborts with non-zero exit code" ($procNonExistentList.ExitCode -ne 0)

# ------------------------------------------------------------------------------
# Cleanup Test Sandbox
# ------------------------------------------------------------------------------
try {
    if (Test-Path -Path $testSandbox) {
        Remove-Item -Path $testSandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {
    # Non-critical cleanup
}

# ------------------------------------------------------------------------------
# Test Summary
# ------------------------------------------------------------------------------
Write-Host "`n=== TEST SUMMARY: HardeningNCS Entrypoint & TUI Suite ===" -ForegroundColor Cyan
Write-Host ("Passed: " + $script:passCount) -ForegroundColor Green
Write-Host ("Failed: " + $script:failCount) -ForegroundColor $(if ($script:failCount -gt 0) { "Red" } else { "Green" })

if ($script:failCount -gt 0) {
    exit 1
} else {
    exit 0
}
