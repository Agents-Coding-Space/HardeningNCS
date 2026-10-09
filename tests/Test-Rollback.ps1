# ==============================================================================
# File: Test-Rollback.ps1
# Description: End-to-End integration test for Remediate-LegacyWin.ps1 and
#              Rollback-LegacyWin.ps1 testing both existing value rollback
#              and newly created registry keys/values removal.
# Compatibility: PowerShell 2.0+
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

$rootDir = Split-Path $ScriptDir -Parent
$remediateScript = Join-Path $rootDir "src\Remediate-LegacyWin.ps1"
$rollbackScript = Join-Path $rootDir "src\Rollback-LegacyWin.ps1"
$outputDir = Join-Path $rootDir "outputs"

if (-not (Test-Path -Path $remediateScript)) {
    Write-Error ("Remediate script not found: " + $remediateScript)
    exit 1
}
if (-not (Test-Path -Path $rollbackScript)) {
    Write-Error ("Rollback script not found: " + $rollbackScript)
    exit 1
}
if (-not (Test-Path -Path $outputDir)) {
    [void](New-Item -ItemType Directory -Path $outputDir -Force)
}

$passSymbol = [char]0x2713
$failSymbol = [char]0x2717

# Test registry key parameters
$regKeyPs = "HKCU:\Software\HardeningLegacyWinTest"
$regKeyRaw = "HKCU\Software\HardeningLegacyWinTest"
$regPropExisting = "TestExistingSetting"
$regPropNew = "TestNewSetting"

# Test subkey parameters (Finding P1 newly created key)
$regSubKeyPs = "HKCU:\Software\HardeningLegacyWinTest\NewSubKey"
$regSubKeyRaw = "HKCU\Software\HardeningLegacyWinTest\NewSubKey"
$regSubKeyProp = "SubKeySetting"

# Temporary test CSV file paths
$guid = [System.Guid]::NewGuid().ToString("N")
$testFindingList = Join-Path $outputDir ("test_finding_list_rollback_" + $guid + ".csv")
$testAuditReport = Join-Path $outputDir ("test_audit_report_rollback_" + $guid + ".csv")
$manifestPath = $null
$sessionDir = $null
$testPassed = $false

try {
    # 1. Initialize test registry state:
    # - Ensure parent key exists
    if (-not (Test-Path -Path $regKeyPs)) {
        [void](New-Item -Path $regKeyPs -Force)
    }
    # - Case 1: Existing property initialized with 0
    Set-ItemProperty -Path $regKeyPs -Name $regPropExisting -Value 0
    $initVal = (Get-ItemProperty -Path $regKeyPs -Name $regPropExisting -ErrorAction SilentlyContinue).$regPropExisting
    if ($initVal -ne 0) {
        throw "Failed to initialize test registry key: initial value is '$initVal', expected 0"
    }

    # - Case 2: New property must NOT exist before remediation
    Remove-ItemProperty -Path $regKeyPs -Name $regPropNew -Force -ErrorAction SilentlyContinue
    $preNewProp = Get-ItemProperty -Path $regKeyPs -Name $regPropNew -ErrorAction SilentlyContinue
    if ($null -ne $preNewProp) {
        throw "Failed to initialize test registry: '$regPropNew' already exists prior to test"
    }

    # - Case 3: Subkey must NOT exist before remediation
    if (Test-Path -Path $regSubKeyPs) {
        Remove-Item -Path $regSubKeyPs -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -Path $regSubKeyPs) {
        throw "Failed to initialize test registry: '$regSubKeyPs' already exists prior to test"
    }

    # 2. Create temporary finding list and audit report containing all test cases
    $findingContent = @(
        '"ID","Category","Name","Method","MethodArgument","RegistryPath","RegistryItem","DefaultValue","RecommendedValue","Operator","Severity"',
        ('"' + "TEST-ROLLBACK-01" + '","SafeTest","Test Existing Value Modification","Registry","","' + $regKeyRaw + '","' + $regPropExisting + '","0","1","=","High"'),
        ('"' + "TEST-ROLLBACK-02" + '","SafeTest","Test New Value Creation","Registry","","' + $regKeyRaw + '","' + $regPropNew + '","0","1","=","High"'),
        ('"' + "TEST-ROLLBACK-03" + '","SafeTest","Test New Key Creation","Registry","","' + $regSubKeyRaw + '","' + $regSubKeyProp + '","0","1","=","High"')
    )
    [System.IO.File]::WriteAllLines($testFindingList, $findingContent, [System.Text.Encoding]::UTF8)

    $auditContent = @(
        '"ID","Category","Name","Method","MethodArgument","RegistryPath","RegistryItem","DefaultValue","RecommendedValue","Operator","Severity","CurrentValue","Status"',
        ('"' + "TEST-ROLLBACK-01" + '","SafeTest","Test Existing Value Modification","Registry","","' + $regKeyRaw + '","' + $regPropExisting + '","0","1","=","High","0","Failed"'),
        ('"' + "TEST-ROLLBACK-02" + '","SafeTest","Test New Value Creation","Registry","","' + $regKeyRaw + '","' + $regPropNew + '","0","1","=","High","<not found>","Failed"'),
        ('"' + "TEST-ROLLBACK-03" + '","SafeTest","Test New Key Creation","Registry","","' + $regSubKeyRaw + '","' + $regSubKeyProp + '","0","1","=","High","<not found>","Failed"')
    )
    [System.IO.File]::WriteAllLines($testAuditReport, $auditContent, [System.Text.Encoding]::UTF8)

    # --------------------------------------------------------------------------
    # Step 1: Remediate-LegacyWin.ps1 -WhatIf
    # --------------------------------------------------------------------------
    Write-Host "--- Step 1: Run Remediate-LegacyWin.ps1 -WhatIf ---" -ForegroundColor Cyan
    $sessionsBeforeWhatIf = @{}
    Get-ChildItem -Path $outputDir -Filter "backup_session_*" | ForEach-Object {
        $sessionsBeforeWhatIf[$_.FullName] = $true
    }

    & $remediateScript -AuditReport $testAuditReport -FindingList $testFindingList -BackupDir $outputDir -WhatIf

    $valAfterWhatIf = (Get-ItemProperty -Path $regKeyPs -Name $regPropExisting -ErrorAction SilentlyContinue).$regPropExisting
    if ($valAfterWhatIf -ne 0) {
        throw "Step 1 Failed: WhatIf modified existing registry value to '$valAfterWhatIf' (expected 0)"
    }
    $newValAfterWhatIf = Get-ItemProperty -Path $regKeyPs -Name $regPropNew -ErrorAction SilentlyContinue
    if ($null -ne $newValAfterWhatIf) {
        throw "Step 1 Failed: WhatIf created new registry value unexpectedly."
    }
    if (Test-Path -Path $regSubKeyPs) {
        throw "Step 1 Failed: WhatIf created new registry key unexpectedly."
    }

    $sessionsAfterWhatIf = Get-ChildItem -Path $outputDir -Filter "backup_session_*" | Where-Object {
        -not $sessionsBeforeWhatIf.ContainsKey($_.FullName)
    }
    if ($null -ne $sessionsAfterWhatIf -and $sessionsAfterWhatIf.Count -gt 0) {
        throw "Step 1 Failed: WhatIf simulation generated unexpected session directory(ies)."
    }

    Write-Host ("$passSymbol Step 1 PASS: WhatIf simulation made 0 changes and generated 0 backup files.") -ForegroundColor Green

    # --------------------------------------------------------------------------
    # Step 2: Remediate-LegacyWin.ps1 (Real Remediation)
    # --------------------------------------------------------------------------
    Write-Host "--- Step 2: Run Remediate-LegacyWin.ps1 (real execution) ---" -ForegroundColor Cyan
    $sessionsBefore = @{}
    Get-ChildItem -Path $outputDir -Filter "backup_session_*" | ForEach-Object {
        $sessionsBefore[$_.FullName] = $true
    }

    & $remediateScript -AuditReport $testAuditReport -FindingList $testFindingList -BackupDir $outputDir

    # Check Case 1: Existing value changed to 1
    $valAfterRemediate = (Get-ItemProperty -Path $regKeyPs -Name $regPropExisting -ErrorAction SilentlyContinue).$regPropExisting
    if ($valAfterRemediate -ne 1) {
        throw "Step 2 Failed: Case 1 existing value is '$valAfterRemediate' (expected 1)"
    }

    # Check Case 2: New value created with 1
    $newValAfterRemediate = (Get-ItemProperty -Path $regKeyPs -Name $regPropNew -ErrorAction SilentlyContinue).$regPropNew
    if ($newValAfterRemediate -ne 1) {
        throw "Step 2 Failed: Case 2 new value is '$newValAfterRemediate' (expected 1)"
    }

    # Check Case 3: New subkey created with value 1
    if (-not (Test-Path -Path $regSubKeyPs)) {
        throw "Step 2 Failed: Case 3 new subkey '$regSubKeyPs' was not created"
    }
    $subValAfterRemediate = (Get-ItemProperty -Path $regSubKeyPs -Name $regSubKeyProp -ErrorAction SilentlyContinue).$regSubKeyProp
    if ($subValAfterRemediate -ne 1) {
        throw "Step 2 Failed: Case 3 new subkey value is '$subValAfterRemediate' (expected 1)"
    }

    # Check that session directory was generated in outputs/
    $newSessions = Get-ChildItem -Path $outputDir -Filter "backup_session_*" | Where-Object {
        -not $sessionsBefore.ContainsKey($_.FullName)
    } | Sort-Object LastWriteTime -Descending

    if ($null -eq $newSessions -or $newSessions.Count -eq 0) {
        throw "Step 2 Failed: Backup session directory was not generated in $outputDir"
    }

    $sessionDir = $newSessions[0].FullName
    $manifestPath = Join-Path $sessionDir "backup_manifest.txt"
    if (-not (Test-Path -Path $manifestPath)) {
        throw "Step 2 Failed: Manifest file does not exist: $manifestPath"
    }

    # Check manifest contents, 4-layer backup structure, and Created registry entries
    $manifestLines = [System.IO.File]::ReadAllLines($manifestPath)
    $hasRegistryBackup = $false
    $hasRegistryDeleteBackup = $false
    $hasSeceditBackup = $false
    $hasAuditpolBackup = $false
    $hasSnapshot = $false
    $hasCreatedValue = $false
    $hasCreatedKey = $false
    $regBackupFile = $null
    $regDeleteFile = $null
    $snapshotFile = $null

    foreach ($ml in $manifestLines) {
        if ($ml.StartsWith("RegistryBackup=")) {
            $hasRegistryBackup = $true
            $regBackupVal = $ml.Substring(15).Trim()
            $resolvedReg = if ([System.IO.Path]::IsPathRooted($regBackupVal)) { $regBackupVal } else { Join-Path $sessionDir $regBackupVal }
            if ($regBackupVal -ne "N/A" -and (Test-Path -Path $resolvedReg)) {
                $regBackupFile = $resolvedReg
            }
        }
        if ($ml.StartsWith("RegistryDeleteBackup=")) {
            $hasRegistryDeleteBackup = $true
            $regDelVal = $ml.Substring(21).Trim()
            $resolvedDel = if ([System.IO.Path]::IsPathRooted($regDelVal)) { $regDelVal } else { Join-Path $sessionDir $regDelVal }
            if ($regDelVal -ne "N/A" -and (Test-Path -Path $resolvedDel)) {
                $regDeleteFile = $resolvedDel
            }
        }
        if ($ml.StartsWith("SeceditBackup=")) {
            $hasSeceditBackup = $true
        }
        if ($ml.StartsWith("AuditpolBackup=")) {
            $hasAuditpolBackup = $true
        }
        if ($ml.StartsWith("StateSnapshot=")) {
            $hasSnapshot = $true
            $snapVal = $ml.Substring(14).Trim()
            $resolvedSnap = if ([System.IO.Path]::IsPathRooted($snapVal)) { $snapVal } else { Join-Path $sessionDir $snapVal }
            if ($snapVal -ne "N/A" -and (Test-Path -Path $resolvedSnap)) {
                $snapshotFile = $resolvedSnap
            }
        }
        if ($ml.StartsWith("CreatedRegistryValue=") -or $ml.StartsWith("CreatedRegistryValue:")) {
            $hasCreatedValue = $true
        }
        if ($ml.StartsWith("CreatedRegistryKey=") -or $ml.StartsWith("CreatedRegistryKey:")) {
            $hasCreatedKey = $true
        }
    }

    # Assert 4 layers + P1 manifests
    if (-not $hasRegistryBackup) {
        throw "Step 2 Failed: Manifest missing Layer 1 (RegistryBackup entry)"
    }
    if (-not $hasRegistryDeleteBackup) {
        throw "Step 2 Failed: Manifest missing Finding P1 RegistryDeleteBackup entry"
    }
    if (-not $hasSeceditBackup) {
        throw "Step 2 Failed: Manifest missing Layer 2 (SeceditBackup entry)"
    }
    if (-not $hasAuditpolBackup) {
        throw "Step 2 Failed: Manifest missing Layer 3 (AuditpolBackup entry)"
    }
    if (-not $hasSnapshot) {
        throw "Step 2 Failed: Manifest missing Layer 4 (StateSnapshot entry)"
    }
    if (-not $hasCreatedValue) {
        throw "Step 2 Failed: Manifest missing CreatedRegistryValue entry for '$regPropNew'"
    }
    if (-not $hasCreatedKey) {
        throw "Step 2 Failed: Manifest missing CreatedRegistryKey entry for '$regSubKeyRaw'"
    }

    # Assert active backup files exist on disk
    if ([string]::IsNullOrEmpty($regBackupFile) -or -not (Test-Path -Path $regBackupFile)) {
        throw "Step 2 Failed: Registry backup file (.reg) was not created on disk: $regBackupFile"
    }
    if ([string]::IsNullOrEmpty($regDeleteFile) -or -not (Test-Path -Path $regDeleteFile)) {
        throw "Step 2 Failed: Registry delete undo file (.reg) was not created on disk: $regDeleteFile"
    }
    if ([string]::IsNullOrEmpty($snapshotFile) -or -not (Test-Path -Path $snapshotFile)) {
        throw "Step 2 Failed: State snapshot CSV was not created on disk: $snapshotFile"
    }

    Write-Host ("$passSymbol Step 2 PASS: All values remediated, 4-layer backup + registry undo files created.") -ForegroundColor Green
    Write-Host ("         Manifest: " + $manifestPath) -ForegroundColor Gray

    # --------------------------------------------------------------------------
    # Step 3: Rollback-LegacyWin.ps1 -ManifestFile <manifest_path>
    # --------------------------------------------------------------------------
    Write-Host "--- Step 3: Run Rollback-LegacyWin.ps1 -ManifestFile ---" -ForegroundColor Cyan
    & $rollbackScript -ManifestFile $manifestPath

    # Assert Case 1: Existing value restored to 0
    $valAfterRollback = (Get-ItemProperty -Path $regKeyPs -Name $regPropExisting -ErrorAction SilentlyContinue).$regPropExisting
    if ($valAfterRollback -ne 0) {
        throw "Step 3 Failed: Case 1 existing value is '$valAfterRollback' (expected 0 after rollback)"
    }
    Write-Host ("$passSymbol Step 3 Case 1 PASS: Existing value '$regPropExisting' restored to 0.") -ForegroundColor Green

    # Assert Case 2: Newly created value TestNewSetting must be COMPLETELY DELETED
    $kObj = Get-Item -LiteralPath $regKeyPs -ErrorAction SilentlyContinue
    $propNames = if ($null -ne $kObj) { $kObj.GetValueNames() } else { @() }
    if ($propNames -icontains $regPropNew) {
        throw "Step 3 Failed: Case 2 newly created value '$regPropNew' was NOT deleted during rollback!"
    }
    Write-Host ("$passSymbol Step 3 Case 2 PASS: Newly created value '$regPropNew' completely deleted.") -ForegroundColor Green

    # Assert Case 3: Newly created key NewSubKey must be COMPLETELY DELETED
    if (Test-Path -Path $regSubKeyPs) {
        throw "Step 3 Failed: Case 3 newly created key '$regSubKeyPs' was NOT deleted during rollback!"
    }
    Write-Host ("$passSymbol Step 3 Case 3 PASS: Newly created key '$regSubKeyPs' completely deleted.") -ForegroundColor Green

    $testPassed = $true
}
catch {
    Write-Host ("$failSymbol FAIL: " + $_.Exception.Message) -ForegroundColor Red
}
finally {
    # Cleanup test key and temporary files
    Write-Host "Cleaning up test registry key and temporary files..." -ForegroundColor Gray

    # 1. Delete test registry key
    if (Test-Path -Path $regKeyPs) {
        Remove-Item -Path $regKeyPs -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -Path $regKeyPs) {
        Write-Warning "Cleanup warning: Test registry key could not be deleted."
    } else {
        Write-Host ("$passSymbol Cleanup: Test registry key successfully removed.") -ForegroundColor Green
    }

    # 2. Delete temporary CSV files
    if (Test-Path -Path $testFindingList) {
        Remove-Item -Path $testFindingList -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -Path $testAuditReport) {
        Remove-Item -Path $testAuditReport -Force -ErrorAction SilentlyContinue
    }

    # 3. Delete session directory generated during test
    if (-not [string]::IsNullOrEmpty($sessionDir) -and (Test-Path -Path $sessionDir)) {
        try {
            [System.IO.Directory]::Delete($sessionDir, $true)
        }
        catch {
            Remove-Item -Path $sessionDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($testPassed) {
    Write-Host ("`n$passSymbol PASS: Rollback verified for both existing value restoration and newly created key/value deletion!") -ForegroundColor Green
    exit 0
} else {
    exit 1
}
