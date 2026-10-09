# ==============================================================================
# File: test_remediate_rollback.ps1
# Description: Tests for Remediate-LegacyWin.ps1 and Rollback-LegacyWin.ps1.
# Compatibility: PowerShell 2.0+
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$rootDir = Split-Path $scriptDir -Parent
$remediatePath = Join-Path $rootDir "src\Remediate-LegacyWin.ps1"
$rollbackPath = Join-Path $rootDir "src\Rollback-LegacyWin.ps1"

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

Write-Host "=== TEST SUITE: WhatIf Simulation Mode ===" -ForegroundColor Cyan

# Create a sample audit report with 1 failed item
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("test_harden_" + [System.Guid]::NewGuid().ToString("N"))
[void](New-Item -ItemType Directory -Path $tempDir -Force)

$sampleAuditReport = Join-Path $tempDir "sample_audit.csv"
$sampleAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
CIS-TEST-1,Administrative Templates,Test Reg Setting,Registry,TestItem,HKCU\Software\TestHardenCIS,TestItem,0,1,=,High,0,Failed
CIS-TEST-2,System Services,Test Service,service,SSDPSRV,,,Manual,Disabled,=,Medium,Manual,Failed
CIS-TEST-3,Administrative Templates,Test Passed,Registry,PassedItem,HKLM\SYSTEM\CurrentControlSet\Control\Lsa,CrashOnAuditFail,0,0,=,Low,0,Passed
"@
[System.IO.File]::WriteAllText($sampleAuditReport, $sampleAuditContent)

try {
    # 1. Test WhatIf mode: must NOT generate backup files or manifest
    & $remediatePath -AuditReport $sampleAuditReport -BackupDir $tempDir -WhatIf
    $manifestFiles = @(Get-ChildItem -Path $tempDir -Filter "backup_manifest*.txt" -Recurse)
    $sessionDirs = @(Get-ChildItem -Path $tempDir -Filter "backup_session_*")
    Assert-Equal "WhatIf does not generate session directories" ($sessionDirs.Length) 0
    Assert-Equal "WhatIf does not generate backup manifest file" ($manifestFiles.Length) 0

    # 2. Test Manifest generation & Rollback engine parser
    Write-Host "`n=== TEST SUITE: Rollback-LegacyWin.ps1 Manifest Execution ===" -ForegroundColor Cyan
    
    # Create mock backup artifacts
    $mockReg = Join-Path $tempDir "mock_reg.reg"
    $mockInf = Join-Path $tempDir "mock_secedit.inf"
    $mockAudit = Join-Path $tempDir "mock_auditpol.csv"
    $mockSnapshot = Join-Path $tempDir "mock_snapshot.csv"

    [System.IO.File]::WriteAllText($mockReg, "Windows Registry Editor Version 5.00`r`n`r`n[HKEY_CURRENT_USER\Software\TestHardenCIS]`r`n`"TestItem`"=dword:00000000`r`n")
    [System.IO.File]::WriteAllText($mockInf, "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO$`"`r`n")
    [System.IO.File]::WriteAllText($mockAudit, "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`r`n")
    
    $snapContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
CIS-TEST-2,System Services,Test Service,service,SSDPSRV,,,Manual,Disabled,=,Medium,Manual,Failed
"@
    [System.IO.File]::WriteAllText($mockSnapshot, $snapContent)

    $manifestPath = Join-Path $tempDir "backup_manifest_test.txt"
    $manifestLines = @(
        "# Mock Manifest",
        "Timestamp=2026-03-30 08:00:00",
        "RegistryBackup=$mockReg",
        "SeceditBackup=$mockInf",
        "AuditpolBackup=$mockAudit",
        "StateSnapshot=$mockSnapshot"
    )
    [System.IO.File]::WriteAllLines($manifestPath, $manifestLines)

    Assert-True "Manifest file exists" (Test-Path $manifestPath)

    # Execute Rollback
    & $rollbackPath -ManifestFile $manifestPath
    Assert-True "Rollback executed cleanly without terminating script execution" $true

    # 3. Test Rollback with relative paths in manifest
    Write-Host "`n=== TEST SUITE: Rollback-LegacyWin.ps1 Relative Path Support ===" -ForegroundColor Cyan
    $relManifestPath = Join-Path $tempDir "backup_manifest_rel.txt"
    $relManifestLines = @(
        "RegistryBackup=mock_reg.reg",
        "SeceditBackup=mock_secedit.inf",
        "AuditpolBackup=mock_auditpol.csv",
        "StateSnapshot=mock_snapshot.csv"
    )
    [System.IO.File]::WriteAllLines($relManifestPath, $relManifestLines)

    & $rollbackPath -ManifestFile $relManifestPath
    Assert-True "Rollback handles relative paths relative to manifest location" $true

    # 4. Test Finding P1: Rollback newly created registry values and keys
    Write-Host "`n=== TEST SUITE: Finding P1 Created Registry Items Cleanup ===" -ForegroundColor Cyan
    $testKeyPs = "HKCU:\Software\TestHardenCIS_P1"
    $testKeyRaw = "HKCU\Software\TestHardenCIS_P1"
    $testSubKeyPs = "HKCU:\Software\TestHardenCIS_P1\SubKey"
    $testSubKeyRaw = "HKCU\Software\TestHardenCIS_P1\SubKey"

    [void](New-Item -Path $testKeyPs -Force)
    Set-ItemProperty -Path $testKeyPs -Name "ExistingVal" -Value "OldValue"
    Set-ItemProperty -Path $testKeyPs -Name "CreatedVal" -Value "NewValue"
    [void](New-Item -Path $testSubKeyPs -Force)
    Set-ItemProperty -Path $testSubKeyPs -Name "SubVal" -Value "SubValue"

    $p1ManifestPath = Join-Path $tempDir "backup_manifest_p1.txt"
    $p1ManifestLines = @(
        "# P1 Manifest",
        ("CreatedRegistryValue=" + $testKeyRaw + "|CreatedVal"),
        ("CreatedRegistryKey=" + $testSubKeyRaw)
    )
    [System.IO.File]::WriteAllLines($p1ManifestPath, $p1ManifestLines)

    & $rollbackPath -ManifestFile $p1ManifestPath

    $kObj = Get-Item -LiteralPath $testKeyPs -ErrorAction SilentlyContinue
    $kNames = if ($null -ne $kObj) { $kObj.GetValueNames() } else { @() }
    Assert-True "P1: Existing registry value is retained" ($kNames -icontains "ExistingVal")
    Assert-True "P1: Created registry value is deleted" (-not ($kNames -icontains "CreatedVal"))
    Assert-True "P1: Created registry subkey is deleted" (-not (Test-Path -Path $testSubKeyPs))

    if (Test-Path -Path $testKeyPs) {
        Remove-Item -Path $testKeyPs -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 5. Test Finding P2: Cleanup of session directory when backup fails
    Write-Host "`n=== TEST SUITE: Finding P2 Session Directory Cleanup On Backup Failure ===" -ForegroundColor Cyan
    $failDir = Join-Path $tempDir "fail_backup_test"
    [void](New-Item -ItemType Directory -Path $failDir -Force)

    $failAuditReport = Join-Path $failDir "audit_fail.csv"
    $failAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
FAIL-01,Test,Export Success Key,Registry,,HKCU\Software\Microsoft\Windows,TestSuccess,0,1,=,Low,0,Failed
FAIL-02,Test,Export Fail Key,Registry,,HKLM\SAM\SAM,TestFail,0,1,=,High,0,Failed
"@
    [System.IO.File]::WriteAllText($failAuditReport, $failAuditContent)

    & $remediatePath -AuditReport $failAuditReport -BackupDir $failDir -ErrorAction SilentlyContinue

    $leftoverSessions = @(Get-ChildItem -Path $failDir -Filter "backup_session_*")
    $leftoverArtifacts = @(Get-ChildItem -Path $failDir -Filter "backup_*")
    Assert-Equal "P2: All session directories are cleaned up on backup failure" ($leftoverSessions.Length) 0
    Assert-Equal "P2: All partial backup artifacts are cleaned up on backup failure" ($leftoverArtifacts.Length) 0

    # 6. Test Exact File Ownership: Pre-existing / Foreign Files Must Never Be Deleted
    Write-Host "`n=== TEST SUITE: Exact File Ownership & Pre-existing File Safety ===" -ForegroundColor Cyan
    $safetyDir = Join-Path $tempDir "safety_test"
    [void](New-Item -ItemType Directory -Path $safetyDir -Force)

    $safetyAudit = Join-Path $safetyDir "audit_safety.csv"
    $safetyAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
FAIL-01,Test,Export Success Key,Registry,,HKCU\Software\Microsoft\Windows,TestSuccess,0,1,=,Low,0,Failed
FAIL-02,Test,Export Fail Key,Registry,,HKLM\SAM\SAM,TestFail,0,1,=,High,0,Failed
"@
    [System.IO.File]::WriteAllLines($safetyAudit, @($safetyAuditContent))

    # Pre-create a foreign file and foreign session directory that this session does not own
    $foreignFile = Join-Path $safetyDir "backup_secedit_foreign.inf"
    [System.IO.File]::WriteAllText($foreignFile, "foreign content")
    $foreignSession = Join-Path $safetyDir "backup_session_foreign"
    [void](New-Item -ItemType Directory -Path $foreignSession -Force)
    $foreignSessionFile = Join-Path $foreignSession "foreign_data.txt"
    [System.IO.File]::WriteAllText($foreignSessionFile, "foreign session data")

    & $remediatePath -AuditReport $safetyAudit -BackupDir $safetyDir -ErrorAction SilentlyContinue

    Assert-True "Foreign pre-existing file was NOT deleted during cleanup" (Test-Path $foreignFile)
    if (Test-Path $foreignFile) {
        $foreignContent = [System.IO.File]::ReadAllText($foreignFile)
        Assert-Equal "Foreign pre-existing file content intact" $foreignContent "foreign content"
    }
    Assert-True "Foreign pre-existing session directory was NOT deleted" (Test-Path $foreignSession)
    Assert-True "Foreign pre-existing session file was NOT deleted" (Test-Path $foreignSessionFile)

    # 7. Test Collision-Proof Session Identifier Format & Per-Session Directory Structure
    Write-Host "`n=== TEST SUITE: Collision-Proof Session Identifier Format & Structure ===" -ForegroundColor Cyan
    $successDir = Join-Path $tempDir "success_test"
    [void](New-Item -ItemType Directory -Path $successDir -Force)

    $successAudit = Join-Path $successDir "audit_success.csv"
    $successAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
CIS-TEST-1,Administrative Templates,Test Reg Setting,Registry,TestItem,HKCU\Software\TestHardenCIS,TestItem,0,1,=,High,0,Failed
"@
    [System.IO.File]::WriteAllLines($successAudit, @($successAuditContent))

    & $remediatePath -AuditReport $successAudit -BackupDir $successDir -ErrorAction SilentlyContinue

    $genSessions = @(Get-ChildItem -Path $successDir -Filter "backup_session_*")
    Assert-Equal "One session directory created on successful remediation" ($genSessions.Length) 1
    if ($genSessions.Length -gt 0) {
        $sessionName = $genSessions[0].Name
        # Format: backup_session_<yyyyMMdd_HHmmss>_<PID>_<RND>
        $isMatch = $sessionName -match '^backup_session_\d{8}_\d{6}_\d+_\d{4}$'
        Assert-True "Session directory name includes yyyyMMdd_HHmmss, PID, and Random number ($sessionName)" $isMatch

        $sessDir = $genSessions[0].FullName
        $manifestPath = Join-Path $sessDir "backup_manifest.txt"
        Assert-True "Manifest file exists inside session directory" (Test-Path $manifestPath)

        $stateSnapshot = Join-Path $sessDir "state_snapshot.csv"
        Assert-True "State snapshot exists inside session directory" (Test-Path $stateSnapshot)

        $sessRegs = @(Get-ChildItem -Path $sessDir -Filter "registry_*.reg")
        Assert-True "Session directory contains registry_<hash>.reg backup file" ($sessRegs.Length -gt 0)
        if ($sessRegs.Length -gt 0) {
            $regName = $sessRegs[0].Name
            $isRegMatch = $regName -match '^registry_[0-9a-f]{8}(_\d+)?\.reg$'
            Assert-True "Registry backup file matches registry_<hash>.reg pattern ($regName)" $isRegMatch
        }
    }

    # 8. Test Pre-existing Session Directory Abort Guard
    Write-Host "`n=== TEST SUITE: Pre-existing Session Directory Abort Guard ===" -ForegroundColor Cyan
    $collisionGuardDir = Join-Path $tempDir "guard_test"
    [void](New-Item -ItemType Directory -Path $collisionGuardDir -Force)
    $preExistingSessionName = "backup_session_collision_guard"
    $preExistingSessionDir = Join-Path $collisionGuardDir $preExistingSessionName
    [void](New-Item -ItemType Directory -Path $preExistingSessionDir -Force)
    $sentinelFile = Join-Path $preExistingSessionDir "sentinel.txt"
    [System.IO.File]::WriteAllText($sentinelFile, "original sentinel")

    $guardAudit = Join-Path $collisionGuardDir "audit_guard.csv"
    $guardAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
CIS-TEST-1,Administrative Templates,Test Reg Setting,Registry,TestItem,HKCU\Software\TestHardenCIS,TestItem,0,1,=,High,0,Failed
"@
    [System.IO.File]::WriteAllLines($guardAudit, @($guardAuditContent))

    & $remediatePath -AuditReport $guardAudit -BackupDir $collisionGuardDir -SessionFolderName $preExistingSessionName -ErrorAction SilentlyContinue

    $itemsInPreExisting = @(Get-ChildItem -Path $preExistingSessionDir)
    Assert-Equal "Pre-existing session dir has only sentinel file (no backup files created)" ($itemsInPreExisting.Length) 1
    Assert-True "Sentinel file still exists untouched" (Test-Path $sentinelFile)
    if (Test-Path $sentinelFile) {
        $sentinelText = [System.IO.File]::ReadAllText($sentinelFile)
        Assert-Equal "Sentinel content untouched" $sentinelText "original sentinel"
    }

    # 9. Test Path Traversal Guard for SessionFolderName
    Write-Host "`n=== TEST SUITE: Path Traversal Guard for SessionFolderName ===" -ForegroundColor Cyan
    $traversalTestDir = Join-Path $tempDir "traversal_test"
    [void](New-Item -ItemType Directory -Path $traversalTestDir -Force)

    $traversalAudit = Join-Path $traversalTestDir "audit_traversal.csv"
    $traversalAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
CIS-TEST-1,Administrative Templates,Test Reg Setting,Registry,TestItem,HKCU\Software\TestHardenCIS,TestItem,0,1,=,High,0,Failed
"@
    [System.IO.File]::WriteAllLines($traversalAudit, @($traversalAuditContent))

    # Case A: Relative path traversal with '..\evil'
    $evilTargetDir = Join-Path $tempDir "evil_traversal"
    $traversalOutputA = & $remediatePath -AuditReport $traversalAudit -BackupDir $traversalTestDir -SessionFolderName "..\evil_traversal" 2>&1
    $traversalTextA = [string]::Join(" ", @($traversalOutputA))

    Assert-True "Traversal '..\evil_traversal' is detected and blocked" ($traversalTextA -like "*Path traversal detected*")
    Assert-True "Evil traversal directory was NOT created" (-not (Test-Path $evilTargetDir))

    # Case B: Path separator slash 'sub/evil'
    $subTargetDir = Join-Path $traversalTestDir "sub"
    $traversalOutputB = & $remediatePath -AuditReport $traversalAudit -BackupDir $traversalTestDir -SessionFolderName "sub/evil" 2>&1
    $traversalTextB = [string]::Join(" ", @($traversalOutputB))

    Assert-True "Slash separator 'sub/evil' is detected and blocked" ($traversalTextB -like "*Path traversal detected*")
    Assert-True "Subdirectory was NOT created" (-not (Test-Path $subTargetDir))

    # Case C: Colon separator 'C:evil'
    $traversalOutputC = & $remediatePath -AuditReport $traversalAudit -BackupDir $traversalTestDir -SessionFolderName "C:evil" 2>&1
    $traversalTextC = [string]::Join(" ", @($traversalOutputC))
    Assert-True "Drive separator 'C:evil' is detected and blocked" ($traversalTextC -like "*Path traversal detected*")

    # Verify no backup sessions or lockfiles were created in traversal test directory
    $traversalSessions = @(Get-ChildItem -Path $traversalTestDir -Filter "backup_session_*")
    $traversalLocks = @(Get-ChildItem -Path $traversalTestDir -Filter "*.lock")
    Assert-Equal "No session directories created during traversal attacks" ($traversalSessions.Length) 0
    Assert-Equal "No lockfiles created during traversal attacks" ($traversalLocks.Length) 0

    # 10. Test Atomic Exclusive Ownership via Win32 CreateNew Lockfile
    Write-Host "`n=== TEST SUITE: Atomic Exclusive Ownership Lock Collision Guard ===" -ForegroundColor Cyan
    $atomicLockTestDir = Join-Path $tempDir "atomic_lock_test"
    [void](New-Item -ItemType Directory -Path $atomicLockTestDir -Force)

    $atomicLockAudit = Join-Path $atomicLockTestDir "audit_atomic_lock.csv"
    $atomicLockAuditContent = @"
ID,Category,Name,Method,MethodArgument,RegistryPath,RegistryItem,DefaultValue,RecommendedValue,Operator,Severity,CurrentValue,Status
CIS-TEST-1,Administrative Templates,Test Reg Setting,Registry,TestItem,HKCU\Software\TestHardenCIS,TestItem,0,1,=,High,0,Failed
"@
    [System.IO.File]::WriteAllLines($atomicLockAudit, @($atomicLockAuditContent))

    $lockTestSessionName = "backup_session_atomic_lock_active"
    $lockFilePath = Join-Path $atomicLockTestDir ($lockTestSessionName + ".lock")
    $lockedSessionDirPath = Join-Path $atomicLockTestDir $lockTestSessionName

    # Acquire exclusive kernel lock via Win32 CreateNew / FileShare::None simulating an active concurrent process
    $activeLockStream = [System.IO.File]::Open($lockFilePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        # Attempt to run remediation with colliding session name
        $collisionOutput = & $remediatePath -AuditReport $atomicLockAudit -BackupDir $atomicLockTestDir -SessionFolderName $lockTestSessionName 2>&1
        $collisionText = [string]::Join(" ", @($collisionOutput))

        Assert-True "Collision error detected when lockfile is held" ($collisionText -like "*collision detected*")
        Assert-True "Session directory was NOT created by colliding process" (-not (Test-Path $lockedSessionDirPath))
        Assert-True "Existing exclusive lockfile was NOT deleted or overwritten" (Test-Path $lockFilePath)
    }
    finally {
        if ($null -ne $activeLockStream) {
            $activeLockStream.Close()
            $activeLockStream = $null
        }
        if (Test-Path $lockFilePath) {
            [System.IO.File]::Delete($lockFilePath)
        }
    }

    # Verify that successful remediation leaves 0 leftover lockfiles
    $successLocks = @(Get-ChildItem -Path $successDir -Filter "*.lock")
    Assert-Equal "Successful remediation cleanly removed its lockfile" ($successLocks.Length) 0

    # Verify that failed backup leaves 0 leftover lockfiles
    $failLocks = @(Get-ChildItem -Path $failDir -Filter "*.lock")
    Assert-Equal "Backup failure cleanly removed its lockfile" ($failLocks.Length) 0
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
