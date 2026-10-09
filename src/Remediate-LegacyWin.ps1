# ==============================================================================
# File: Remediate-LegacyWin.ps1
# Description: PowerShell 2.0 Remediation Engine for Legacy Windows.
#              Applies CIS hardening recommendations with mandatory 4-layer backup.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AuditReport = "",

    [Parameter(Mandatory = $false)]
    [string]$FindingList = "",

    [Parameter(Mandatory = $false)]
    [string]$BackupDir = "",

    [Parameter(Mandatory = $false)]
    [string]$SessionFolderName = "",

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Resolve ScriptDir using PS 2.0 compatible invocation logic
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

function Convert-ToPsDrivePath {
    param([string]$RawPath)
    if ([string]::IsNullOrEmpty($RawPath)) { return "" }
    $p = $RawPath.Trim()
    if ($p.StartsWith("HKLM:\", [System.StringComparison]::OrdinalIgnoreCase) -or
        $p.StartsWith("HKCU:\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $p
    }
    if ($p.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKLM:\" + $p.Substring(5)
    }
    if ($p.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKCU:\" + $p.Substring(5)
    }
    if ($p.StartsWith("HKEY_LOCAL_MACHINE\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKLM:\" + $p.Substring(19)
    }
    if ($p.StartsWith("HKEY_CURRENT_USER\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKCU:\" + $p.Substring(18)
    }
    return $p
}

function Convert-ToRegHeaderKey {
    param([string]$RawPath)
    if ([string]::IsNullOrEmpty($RawPath)) { return "" }
    $p = $RawPath.Trim()
    if ($p.StartsWith("HKLM:\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKEY_LOCAL_MACHINE\" + $p.Substring(6)
    }
    if ($p.StartsWith("HKCU:\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKEY_CURRENT_USER\" + $p.Substring(6)
    }
    if ($p.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKEY_LOCAL_MACHINE\" + $p.Substring(5)
    }
    if ($p.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "HKEY_CURRENT_USER\" + $p.Substring(5)
    }
    if ($p.StartsWith("HKEY_LOCAL_MACHINE\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $p
    }
    if ($p.StartsWith("HKEY_CURRENT_USER\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $p
    }
    return $p
}

function Get-RegKeyHash {
    param([string]$KeyPath)
    if ([string]::IsNullOrEmpty($KeyPath)) { return "00000000" }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($KeyPath.ToUpperInvariant())
        $hashBytes = $sha.ComputeHash($bytes)
        return [System.BitConverter]::ToString($hashBytes).Replace("-", "").Substring(0, 8).ToLowerInvariant()
    }
    catch {
        return [Math]::Abs($KeyPath.GetHashCode()).ToString("x8")
    }
}

# Resolve BackupDir
if ([string]::IsNullOrEmpty($BackupDir)) {
    $BackupDir = Join-Path (Split-Path $ScriptDir -Parent) "outputs"
}
$BackupDir = [System.IO.Path]::GetFullPath($BackupDir)
if (-not (Test-Path -Path $BackupDir)) {
    [void](New-Item -ItemType Directory -Path $BackupDir -Force)
}

# Resolve AuditReport path (auto-detect latest audit_report_*.csv if omitted)
if ([string]::IsNullOrEmpty($AuditReport)) {
    $reportCandidates = Get-ChildItem -Path $BackupDir -Filter "audit_report_*.csv" | Sort-Object LastWriteTime -Descending
    if ($null -ne $reportCandidates -and $reportCandidates.Count -gt 0) {
        $AuditReport = $reportCandidates[0].FullName
    } elseif ($null -ne $reportCandidates -and -not [string]::IsNullOrEmpty($reportCandidates.FullName)) {
        $AuditReport = $reportCandidates.FullName
    } else {
        Write-Error "No AuditReport specified and no audit_report_*.csv found in outputs directory."
        return
    }
}
$AuditReport = [System.IO.Path]::GetFullPath($AuditReport)

if (-not (Test-Path -Path $AuditReport)) {
    Write-Error ("AuditReport file not found: " + $AuditReport)
    return
}

# Resolve FindingList path
if ([string]::IsNullOrEmpty($FindingList)) {
    $FindingList = Join-Path (Split-Path $ScriptDir -Parent) "lists\finding_list_cis_win7_sp1_machine.csv"
}
$FindingList = [System.IO.Path]::GetFullPath($FindingList)

Write-Host "Using Audit Report : $AuditReport" -ForegroundColor Cyan
Write-Host "Using Finding List : $FindingList" -ForegroundColor Cyan
Write-Host "Backup Directory   : $BackupDir" -ForegroundColor Cyan

# 1. Filter failed findings from AuditReport
$auditRows = Import-Csv -Path $AuditReport
$failedAuditRows = New-Object System.Collections.ArrayList
foreach ($row in $auditRows) {
    if ($null -ne $row.Status -and $row.Status.Trim() -ieq "Failed") {
        [void]$failedAuditRows.Add($row)
    }
}

if ($failedAuditRows.Count -eq 0) {
    Write-Host "No failed findings found in audit report. System is compliant!" -ForegroundColor Green
    return
}

Write-Host ("Found " + $failedAuditRows.Count + " failed finding(s) to remediate.") -ForegroundColor Yellow

# 2. Map failed items against FindingList for complete baseline metadata
$findingMap = @{}
if (Test-Path -Path $FindingList) {
    $rawFindings = Import-Csv -Path $FindingList
    foreach ($f in $rawFindings) {
        $fId = ""
        if ($null -ne $f.ID) { $fId = "$($f.ID)".Trim() }
        if ([string]::IsNullOrEmpty($fId) -and $null -ne $f."`ufeffID") { $fId = "$($f."`ufeffID")".Trim() }
        if (-not [string]::IsNullOrEmpty($fId)) {
            $findingMap[$fId] = $f
        }
    }
}

$supportedMethods = @("Registry", "service", "accountpolicy", "auditpol", "secedit")
$remediateItems = New-Object System.Collections.ArrayList
$skippedRemediateItems = New-Object System.Collections.ArrayList

foreach ($failed in $failedAuditRows) {
    $failedId = ""
    if ($null -ne $failed.ID) { $failedId = "$($failed.ID)".Trim() }
    if ([string]::IsNullOrEmpty($failedId) -and $null -ne $failed."`ufeffID") { $failedId = "$($failed."`ufeffID")".Trim() }

    $fullItem = $failed
    if ($findingMap.ContainsKey($failedId)) {
        $base = $findingMap[$failedId]
        $fullItem = New-Object PSObject
        $fullItem | Add-Member -MemberType NoteProperty -Name "ID" -Value $failedId
        $fullItem | Add-Member -MemberType NoteProperty -Name "Category" -Value $(if ($null -ne $base.Category) { "$($base.Category)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "Name" -Value $(if ($null -ne $base.Name) { "$($base.Name)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "Method" -Value $(if ($null -ne $base.Method) { "$($base.Method)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "MethodArgument" -Value $(if ($null -ne $base.MethodArgument) { "$($base.MethodArgument)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "RegistryPath" -Value $(if ($null -ne $base.RegistryPath) { "$($base.RegistryPath)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "RegistryItem" -Value $(if ($null -ne $base.RegistryItem) { "$($base.RegistryItem)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "DefaultValue" -Value $(if ($null -ne $base.DefaultValue) { "$($base.DefaultValue)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "RecommendedValue" -Value $(if ($null -ne $base.RecommendedValue) { "$($base.RecommendedValue)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "Operator" -Value $(if ($null -ne $base.Operator) { "$($base.Operator)".Trim() } else { "=" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "Severity" -Value $(if ($null -ne $base.Severity) { "$($base.Severity)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "CurrentValue" -Value $(if ($null -ne $failed.CurrentValue) { "$($failed.CurrentValue)".Trim() } else { "" })
        $fullItem | Add-Member -MemberType NoteProperty -Name "Status" -Value $(if ($null -ne $failed.Status) { "$($failed.Status)".Trim() } else { "Failed" })
    }

    $itemMethod = "$($fullItem.Method)".Trim()
    $isMethodSupported = $false
    foreach ($sm in $supportedMethods) {
        if ($itemMethod -ieq $sm) {
            $isMethodSupported = $true
            break
        }
    }

    if ($isMethodSupported) {
        [void]$remediateItems.Add($fullItem)
    } else {
        Write-Warning ("Skipping remediation for unsupported method '" + $itemMethod + "' (ID " + $failedId + "): No safe automated rollback mechanism.")
        [void]$skippedRemediateItems.Add($fullItem)
    }
}

if ($remediateItems.Count -eq 0) {
    Write-Host "No failed findings with supported remediation methods found." -ForegroundColor Yellow
    if ($skippedRemediateItems.Count -gt 0) {
        Write-Host ("Skipped " + $skippedRemediateItems.Count + " item(s) due to unsupported methods without safe rollback.") -ForegroundColor Yellow
    }
    return
}

# 3. WHAT-IF PREVIEW MODE
if ($WhatIf) {
    Write-Host "================ WHAT-IF SIMULATION MODE ================" -ForegroundColor Cyan
    Write-Host "No system configurations will be modified."
    Write-Host ""
    Write-Host "Backup actions that would be performed:" -ForegroundColor Yellow
    Write-Host "  1. Registry export for affected keys"
    Write-Host "  2. Secedit security policy export to INF"
    Write-Host "  3. Auditpol policy backup to CSV"
    Write-Host "  4. State snapshot export to CSV"
    Write-Host "  5. Manifest generation listing all 4 layers"
    Write-Host ""
    Write-Host "Remediation actions that would be applied:" -ForegroundColor Yellow

    foreach ($item in $remediateItems) {
        $desc = "  [$($item.ID)] $($item.Name) | Method: $($item.Method)"
        if ($item.Method -ieq "Registry") {
            $desc += " | Target: $($item.RegistryPath)\$($item.RegistryItem) = $($item.RecommendedValue)"
        } elseif ($item.Method -ieq "secedit" -or $item.Method -ieq "accountpolicy") {
            $desc += " | Target: $($item.MethodArgument) = $($item.RecommendedValue)"
        } elseif ($item.Method -ieq "auditpol") {
            $desc += " | Target Subcategory: '$($item.MethodArgument)' -> $($item.RecommendedValue)"
        } elseif ($item.Method -ieq "service") {
            $desc += " | Service '$($item.MethodArgument)' Startup -> $($item.RecommendedValue)"
        } else {
            $desc += " | Target: $($item.RecommendedValue)"
        }
        Write-Host $desc
    }
    if ($skippedRemediateItems.Count -gt 0) {
        Write-Host ""
        Write-Host "Items skipped due to unsupported methods without safe rollback:" -ForegroundColor Yellow
        foreach ($sItem in $skippedRemediateItems) {
            Write-Host ("  [$($sItem.ID)] $($sItem.Name) | Method: $($sItem.Method) (Skipped)")
        }
    }
    Write-Host "==========================================================" -ForegroundColor Cyan
    return
}

# 4. MANDATORY 4-LAYER BACKUP
# Path Traversal Guard for SessionFolderName: strictly reject separators or traversal tokens
if (-not [string]::IsNullOrEmpty($SessionFolderName)) {
    if ($SessionFolderName.Contains("\") -or 
        $SessionFolderName.Contains("/") -or 
        $SessionFolderName.Contains(":") -or 
        $SessionFolderName.Contains("..")) {
        Write-Error "Path traversal detected"
        return
    }
}

$procId = [System.Diagnostics.Process]::GetCurrentProcess().Id
$rnd = (New-Object System.Random).Next(1000, 9999)
$timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + $procId + '_' + $rnd
$ts = $timestamp
if ([string]::IsNullOrEmpty($SessionFolderName)) {
    $sessionFolderName = "backup_session_" + $timestamp
} else {
    $sessionFolderName = $SessionFolderName
}

# Path Traversal Guard: Canonicalize paths and verify isolation strictly inside BackupDir
try {
    $fullBackupDir = [System.IO.Path]::GetFullPath($BackupDir)
    $rawSessionDirPath = Join-Path $fullBackupDir $sessionFolderName
    $sessionDirPath = [System.IO.Path]::GetFullPath($rawSessionDirPath)
}
catch {
    Write-Error "Path traversal detected"
    return
}

$expectedPrefix = $fullBackupDir
if (-not $expectedPrefix.EndsWith([System.IO.Path]::DirectorySeparatorChar.ToString())) {
    $expectedPrefix += [System.IO.Path]::DirectorySeparatorChar
}

if (-not $sessionDirPath.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Error "Path traversal detected"
    return
}

# Per-Session Directory Isolation: Check if session dir already exists -> ABORT immediately
if ([System.IO.Directory]::Exists($sessionDirPath)) {
    Write-Error "Session folder or lock already exists / collision detected"
    return
}

# Atomic Exclusive Ownership via Win32 CreateNew Lockfile (.NET 2.0 BCL)
$lockFilePath = Join-Path $fullBackupDir ($sessionFolderName + ".lock")
$lockStream = $null
try {
    $lockStream = [System.IO.File]::Open($lockFilePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
}
catch {
    Write-Error "Session folder or lock already exists / collision detected"
    return
}

# Only after exclusive lock ownership is acquired, create session directory
try {
    [void][System.IO.Directory]::CreateDirectory($sessionDirPath)
}
catch {
    Write-Error ("Failed to create session directory '" + $sessionDirPath + "': " + $_.Exception.Message)
    if ($null -ne $lockStream) {
        try { $lockStream.Close() } catch {}
        $lockStream = $null
    }
    if (Test-Path -Path $lockFilePath) {
        try { [System.IO.File]::Delete($lockFilePath) } catch {}
    }
    return
}

# Define all per-session isolated backup paths
$manifestPath = Join-Path $sessionDirPath "backup_manifest.txt"
$regDeleteBackupPath = Join-Path $sessionDirPath "registry_undo_delete.reg"
$seceditBackupPath = Join-Path $sessionDirPath "secedit.inf"
$auditpolBackupPath = Join-Path $sessionDirPath "auditpol.csv"
$snapshotPath = Join-Path $sessionDirPath "state_snapshot.csv"

# Safety check: Verify no backup files already exist in session directory
if ((Test-Path -Path $manifestPath) -or
    (Test-Path -Path $regDeleteBackupPath) -or
    (Test-Path -Path $seceditBackupPath) -or
    (Test-Path -Path $auditpolBackupPath) -or
    (Test-Path -Path $snapshotPath)) {
    Write-Error "Session directory already contains backup files: aborting."
    if ([System.IO.Directory]::Exists($sessionDirPath)) {
        try { [System.IO.Directory]::Delete($sessionDirPath, $true) } catch {}
    }
    if ($null -ne $lockStream) {
        try { $lockStream.Close() } catch {}
        $lockStream = $null
    }
    if (Test-Path -Path $lockFilePath) {
        try { [System.IO.File]::Delete($lockFilePath) } catch {}
    }
    return
}

$regBackupFiles = New-Object System.Collections.ArrayList
$regBackupNames = New-Object System.Collections.ArrayList
$backupFailed = $false
$backupErrors = New-Object System.Collections.ArrayList

Write-Host "Executing 4-layer backup before applying changes..." -ForegroundColor Yellow
Write-Host ("Session Directory : " + $sessionDirPath) -ForegroundColor Cyan

# Layer 1: Registry Backup & Detection of Created Keys/Values
$uniqueRegKeys = New-Object System.Collections.ArrayList
$createdRegKeys = New-Object System.Collections.ArrayList
$createdRegValues = New-Object System.Collections.ArrayList

foreach ($item in $remediateItems) {
    if ($item.Method -ieq "Registry" -and -not [string]::IsNullOrEmpty($item.RegistryPath)) {
        if (-not $uniqueRegKeys.Contains($item.RegistryPath)) {
            [void]$uniqueRegKeys.Add($item.RegistryPath)
        }

        $psKey = Convert-ToPsDrivePath $item.RegistryPath
        if (-not (Test-Path -Path $psKey)) {
            # The entire registry key does not exist yet; will be created by remediation
            if (-not $createdRegKeys.Contains($item.RegistryPath)) {
                [void]$createdRegKeys.Add($item.RegistryPath)
            }
        } else {
            # The key exists; check whether the specific registry value exists
            $propName = $item.RegistryItem
            if (-not [string]::IsNullOrEmpty($propName)) {
                $keyObj = Get-Item -LiteralPath $psKey -ErrorAction SilentlyContinue
                $valExists = $false
                if ($null -ne $keyObj) {
                    $valNames = $keyObj.GetValueNames()
                    if ($null -ne $valNames -and $valNames -icontains $propName) {
                        $valExists = $true
                    }
                }
                if (-not $valExists) {
                    $entry = $item.RegistryPath + "|" + $propName
                    if (-not $createdRegValues.Contains($entry)) {
                        [void]$createdRegValues.Add($entry)
                    }
                }
            }
        }
    }
}

$keyCounter = 0
$usedRegFileNames = New-Object System.Collections.ArrayList
foreach ($rawKey in $uniqueRegKeys) {
    $psKey = Convert-ToPsDrivePath $rawKey

    if (Test-Path -Path $psKey) {
        $keyHash = Get-RegKeyHash $rawKey
        $regFileName = "registry_" + $keyHash + ".reg"
        if ($usedRegFileNames.Contains($regFileName) -or (Test-Path -Path (Join-Path $sessionDirPath $regFileName))) {
            $regFileName = "registry_" + $keyHash + "_" + $keyCounter + ".reg"
        }
        [void]$usedRegFileNames.Add($regFileName)
        $regFile = Join-Path $sessionDirPath $regFileName
        $keyCounter++

        if (Test-Path -Path $regFile) {
            $backupFailed = $true
            [void]$backupErrors.Add("Registry backup file already exists: " + $regFile)
            continue
        }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "reg.exe"
        $psi.Arguments = "export `"$rawKey`" `"$regFile`" /y"
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -ne $proc) {
            $proc.WaitForExit()
            if ($proc.ExitCode -ne 0 -or -not (Test-Path -Path $regFile)) {
                $backupFailed = $true
                [void]$backupErrors.Add("Failed to export registry key '$rawKey' (exit code $($proc.ExitCode))")
            } else {
                [void]$regBackupFiles.Add($regFile)
                [void]$regBackupNames.Add($regFileName)
            }
        } else {
            $backupFailed = $true
            [void]$backupErrors.Add("Failed to launch reg.exe for key '$rawKey'")
        }
    } else {
        Write-Host ("  Notice: Key does not exist yet (will be created): " + $rawKey)
    }
}

# Generate Registry Undo (.reg) file if new keys or values will be created (Finding P1)
$hasRegDelete = $false
if ($createdRegKeys.Count -gt 0 -or $createdRegValues.Count -gt 0) {
    if (Test-Path -Path $regDeleteBackupPath) {
        $backupFailed = $true
        [void]$backupErrors.Add("Registry delete undo file already exists: " + $regDeleteBackupPath)
    } else {
        $regDelLines = New-Object System.Collections.ArrayList
        [void]$regDelLines.Add("Windows Registry Editor Version 5.00")
        [void]$regDelLines.Add("")

        # 1. Values to delete from existing keys
        $valuesByKey = @{}
        foreach ($vEntry in $createdRegValues) {
            $sepIdx = $vEntry.IndexOf("|")
            if ($sepIdx -gt 0) {
                $kPath = $vEntry.Substring(0, $sepIdx)
                $vName = $vEntry.Substring($sepIdx + 1)
                if (-not $valuesByKey.ContainsKey($kPath)) {
                    $valuesByKey[$kPath] = New-Object System.Collections.ArrayList
                }
                [void]$valuesByKey[$kPath].Add($vName)
            }
        }

        foreach ($kPath in $valuesByKey.Keys) {
            $headerKey = Convert-ToRegHeaderKey $kPath
            [void]$regDelLines.Add("[" + $headerKey + "]")
            foreach ($vName in $valuesByKey[$kPath]) {
                [void]$regDelLines.Add('"' + $vName + '"=-')
            }
            [void]$regDelLines.Add("")
        }

        # 2. Entire keys to delete
        foreach ($kPath in $createdRegKeys) {
            $headerKey = Convert-ToRegHeaderKey $kPath
            [void]$regDelLines.Add("[-" + $headerKey + "]")
            [void]$regDelLines.Add("")
        }

        try {
            [System.IO.File]::WriteAllLines($regDeleteBackupPath, $regDelLines.ToArray(), [System.Text.Encoding]::Unicode)
            if (Test-Path -Path $regDeleteBackupPath) {
                $hasRegDelete = $true
            } else {
                $backupFailed = $true
                [void]$backupErrors.Add("Failed to create registry undo delete file: " + $regDeleteBackupPath)
            }
        }
        catch {
            $backupFailed = $true
            [void]$backupErrors.Add("Failed to create registry undo delete file: " + $_.Exception.Message)
        }
    }
}
if (-not $hasRegDelete) {
    $regDeleteBackupPath = "N/A"
}

# Layer 2: Secedit Backup
$hasSecEdit = $false
foreach ($item in $remediateItems) {
    if ($item.Method -ieq "secedit" -or $item.Method -ieq "accountpolicy") {
        $hasSecEdit = $true
        break
    }
}

if ($hasSecEdit) {
    if (Test-Path -Path $seceditBackupPath) {
        $backupFailed = $true
        [void]$backupErrors.Add("Secedit backup file already exists: " + $seceditBackupPath)
    } else {
        $secLog = [System.IO.Path]::ChangeExtension($seceditBackupPath, ".log")
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "secedit.exe"
            $psi.Arguments = "/export /cfg `"$seceditBackupPath`" /areas SECURITYPOLICY /log `"$secLog`" /quiet"
            $psi.CreateNoWindow = $true
            $psi.UseShellExecute = $false
            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($null -ne $proc) {
                $proc.WaitForExit()
            }
            if (-not (Test-Path -Path $seceditBackupPath)) {
                $backupFailed = $true
                [void]$backupErrors.Add("secedit.exe /export did not produce backup file (administrator privileges required)")
            }
        }
        catch {
            $backupFailed = $true
            [void]$backupErrors.Add("Error running secedit.exe: " + $_.Exception.Message)
        }
        finally {
            if (Test-Path -Path $secLog) { Remove-Item -Path $secLog -Force -ErrorAction SilentlyContinue }
        }
    }
} else {
    $seceditBackupPath = "N/A"
}

# Layer 3: Auditpol Backup
$hasAuditPol = $false
foreach ($item in $remediateItems) {
    if ($item.Method -ieq "auditpol") {
        $hasAuditPol = $true
        break
    }
}

if ($hasAuditPol) {
    if (Test-Path -Path $auditpolBackupPath) {
        $backupFailed = $true
        [void]$backupErrors.Add("Auditpol backup file already exists: " + $auditpolBackupPath)
    } else {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "auditpol.exe"
            $psi.Arguments = "/backup /file:`"$auditpolBackupPath`""
            $psi.CreateNoWindow = $true
            $psi.UseShellExecute = $false
            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($null -ne $proc) {
                $proc.WaitForExit()
                if ($proc.ExitCode -ne 0 -or -not (Test-Path -Path $auditpolBackupPath)) {
                    $backupFailed = $true
                    [void]$backupErrors.Add("auditpol.exe /backup failed with exit code $($proc.ExitCode) (administrator privileges required)")
                }
            } else {
                $backupFailed = $true
                [void]$backupErrors.Add("Failed to launch auditpol.exe")
            }
        }
        catch {
            $backupFailed = $true
            [void]$backupErrors.Add("Error running auditpol.exe: " + $_.Exception.Message)
        }
    }
} else {
    $auditpolBackupPath = "N/A"
}

# Layer 4: State Snapshot
if (Test-Path -Path $snapshotPath) {
    $backupFailed = $true
    [void]$backupErrors.Add("State snapshot file already exists: " + $snapshotPath)
} else {
    try {
        $remediateItems.ToArray() | Export-Csv -Path $snapshotPath -NoTypeInformation
        if (-not (Test-Path -Path $snapshotPath)) {
            $backupFailed = $true
            [void]$backupErrors.Add("Failed to export state snapshot CSV")
        }
    }
    catch {
        $backupFailed = $true
        [void]$backupErrors.Add("Failed to create snapshot: " + $_.Exception.Message)
    }
}

# Check Backup Failure Gate: ABORT IMMEDIATELY IF ANY BACKUP FAILED (Finding P2)
if ($backupFailed) {
    Write-Error "================ BACKUP FAILED - REMEDIATION ABORTED ================"
    foreach ($err in $backupErrors) {
        Write-Error ("  - " + $err)
    }

    Write-Host "Cleaning up session directory due to backup failure..." -ForegroundColor Yellow
    if ([System.IO.Directory]::Exists($sessionDirPath)) {
        try {
            [System.IO.Directory]::Delete($sessionDirPath, $true)
            Write-Host ("  [CLEANED] Removed session directory: " + $sessionDirPath) -ForegroundColor Gray
        }
        catch {
            Write-Warning ("  Failed to remove session directory: " + $sessionDirPath + " - " + $_.Exception.Message)
        }
    }

    if ($null -ne $lockStream) {
        try { $lockStream.Close() } catch {}
        $lockStream = $null
    }
    if (Test-Path -Path $lockFilePath) {
        try { [System.IO.File]::Delete($lockFilePath) } catch {}
    }

    Write-Error "No system modifications were made to ensure stability."
    Write-Error "Please run PowerShell as Administrator and retry."
    return
}

# Layer 5: Write Manifest File
if (Test-Path -Path $manifestPath) {
    Write-Error ("Manifest file already exists: " + $manifestPath)
    if ([System.IO.Directory]::Exists($sessionDirPath)) {
        try { [System.IO.Directory]::Delete($sessionDirPath, $true) } catch {}
    }
    if ($null -ne $lockStream) {
        try { $lockStream.Close() } catch {}
        $lockStream = $null
    }
    if (Test-Path -Path $lockFilePath) {
        try { [System.IO.File]::Delete($lockFilePath) } catch {}
    }
    return
}

$regStr = if ($regBackupNames.Count -gt 0) { [string]::Join(";", $regBackupNames.ToArray()) } else { "N/A" }
$regDeleteEntry = if ($hasRegDelete) { "registry_undo_delete.reg" } else { "N/A" }
$seceditEntry = if ($hasSecEdit) { "secedit.inf" } else { "N/A" }
$auditpolEntry = if ($hasAuditPol) { "auditpol.csv" } else { "N/A" }

$manifestLines = New-Object System.Collections.ArrayList
[void]$manifestLines.Add("# HardeningNCS Backup Manifest")
[void]$manifestLines.Add("Timestamp=" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
[void]$manifestLines.Add("SessionFolder=" + $sessionFolderName)
[void]$manifestLines.Add("RegistryBackup=" + $regStr)
[void]$manifestLines.Add("RegistryDeleteBackup=" + $regDeleteEntry)
[void]$manifestLines.Add("SeceditBackup=" + $seceditEntry)
[void]$manifestLines.Add("AuditpolBackup=" + $auditpolEntry)
[void]$manifestLines.Add("StateSnapshot=state_snapshot.csv")

# Add CreatedRegistryKey and CreatedRegistryValue entries (Finding P1)
foreach ($ck in $createdRegKeys) {
    [void]$manifestLines.Add("CreatedRegistryKey=" + $ck)
}
foreach ($cv in $createdRegValues) {
    [void]$manifestLines.Add("CreatedRegistryValue=" + $cv)
}

try {
    [System.IO.File]::WriteAllLines($manifestPath, $manifestLines.ToArray(), [System.Text.Encoding]::UTF8)
    Write-Host ("Backup complete. Manifest saved: " + $manifestPath) -ForegroundColor Green
}
catch {
    Write-Error ("Failed to write manifest file: " + $_.Exception.Message)
    if ([System.IO.Directory]::Exists($sessionDirPath)) {
        try { [System.IO.Directory]::Delete($sessionDirPath, $true) } catch {}
    }
    if ($null -ne $lockStream) {
        try { $lockStream.Close() } catch {}
        $lockStream = $null
    }
    if (Test-Path -Path $lockFilePath) {
        try { [System.IO.File]::Delete($lockFilePath) } catch {}
    }
    return
}

# 5. EXECUTE REMEDIATION
Write-Host "Applying remediation changes..." -ForegroundColor Cyan
$successCount = 0
$failCount = 0

# A. Remediation: Registry
$registryFailedItems = New-Object System.Collections.ArrayList
foreach ($item in $remediateItems) {
    if ($item.Method -ieq "Registry") {
        [void]$registryFailedItems.Add($item)
    }
}

foreach ($item in $registryFailedItems) {
    $psPath = Convert-ToPsDrivePath $item.RegistryPath

    try {
        if (-not (Test-Path -Path $psPath)) {
            [void](New-Item -Path $psPath -Force -ErrorAction Stop)
        }

        $valStr = $item.RecommendedValue
        $numVal = [int64]0
        if ([int64]::TryParse($valStr, [ref]$numVal)) {
            try {
                Set-ItemProperty -Path $psPath -Name $item.RegistryItem -Value ([int32]$numVal) -ErrorAction Stop
            }
            catch {
                New-ItemProperty -Path $psPath -Name $item.RegistryItem -Value ([int32]$numVal) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
        } else {
            try {
                Set-ItemProperty -Path $psPath -Name $item.RegistryItem -Value $valStr -ErrorAction Stop
            }
            catch {
                New-ItemProperty -Path $psPath -Name $item.RegistryItem -Value $valStr -PropertyType String -Force -ErrorAction Stop | Out-Null
            }
        }
        Write-Host ("  [OK] Registry: " + $item.RegistryPath + "\" + $item.RegistryItem + " -> " + $item.RecommendedValue) -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Warning ("  [FAIL] Registry: " + $item.RegistryPath + "\" + $item.RegistryItem + " -> " + $_.Exception.Message)
        $failCount++
    }
}

# B. Remediation: Secedit / Account Policies
$secItems = New-Object System.Collections.ArrayList
foreach ($item in $remediateItems) {
    if ($item.Method -ieq "secedit" -or $item.Method -ieq "accountpolicy") {
        [void]$secItems.Add($item)
    }
}

if ($secItems.Count -gt 0) {
    $accountPolicyRemediateMap = @{
        "ENFORCE_PASSWORD_HISTORY" = "PasswordHistorySize"
        "MAXIMUM_PASSWORD_AGE"     = "MaximumPasswordAge"
        "MINIMUM_PASSWORD_AGE"     = "MinimumPasswordAge"
        "MINIMUM_PASSWORD_LENGTH"  = "MinimumPasswordLength"
        "COMPLEXITY_REQUIREMENTS"  = "PasswordComplexity"
        "REVERSIBLE_ENCRYPTION"    = "ClearTextPassword"
        "LOCKOUT_DURATION"         = "LockoutDuration"
        "LOCKOUT_THRESHOLD"        = "LockoutBadCount"
        "LOCKOUT_RESET"            = "ResetLockoutCount"
        "FORCE_LOGOFF"             = "ForceLogoffWhenHourExpire"
    }

    $infLines = New-Object System.Collections.ArrayList
    [void]$infLines.Add("[Unicode]")
    [void]$infLines.Add("Unicode=yes")
    [void]$infLines.Add("[Version]")
    [void]$infLines.Add('signature="$CHICAGO$"')
    [void]$infLines.Add("Revision=1")
    [void]$infLines.Add("[System Access]")

    foreach ($sItem in $secItems) {
        $kName = $sItem.MethodArgument
        if ($kName.StartsWith("System Access\", [System.StringComparison]::OrdinalIgnoreCase)) {
            $kName = $kName.Substring(14)
        }
        if ($accountPolicyRemediateMap.ContainsKey($kName)) {
            $kName = $accountPolicyRemediateMap[$kName]
        }
        $valToApply = $sItem.RecommendedValue
        if ($valToApply -ieq "Enabled") {
            $valToApply = "1"
        } elseif ($valToApply -ieq "Disabled") {
            $valToApply = "0"
        }
        [void]$infLines.Add($kName + " = " + $valToApply)
    }

    $tempInf = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "remediate_" + $ts + ".inf")
    $tempSdb = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "remediate_" + $ts + ".sdb")
    $tempLog = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "remediate_" + $ts + ".log")

    try {
        [System.IO.File]::WriteAllLines($tempInf, $infLines.ToArray())
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "secedit.exe"
        $psi.Arguments = "/configure /db `"$tempSdb`" /cfg `"$tempInf`" /log `"$tempLog`" /quiet /areas SECURITYPOLICY"
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -ne $proc) {
            $proc.WaitForExit()
            if ($proc.ExitCode -eq 0) {
                Write-Host ("  [OK] Secedit template applied (" + $secItems.Count + " settings)") -ForegroundColor Green
                $successCount += $secItems.Count
            } else {
                Write-Warning ("  [FAIL] Secedit template failed with code " + $proc.ExitCode)
                $failCount += $secItems.Count
            }
        }
    }
    catch {
        Write-Warning ("  [FAIL] Failed to execute secedit configure: " + $_.Exception.Message)
        $failCount += $secItems.Count
    }
    finally {
        if (Test-Path -Path $tempInf) { Remove-Item -Path $tempInf -Force -ErrorAction SilentlyContinue }
        if (Test-Path -Path $tempSdb) { Remove-Item -Path $tempSdb -Force -ErrorAction SilentlyContinue }
        if (Test-Path -Path $tempLog) { Remove-Item -Path $tempLog -Force -ErrorAction SilentlyContinue }
    }
}

# C. Remediation: Auditpol
$auditItems = New-Object System.Collections.ArrayList
foreach ($item in $remediateItems) {
    if ($item.Method -ieq "auditpol") {
        [void]$auditItems.Add($item)
    }
}

foreach ($aItem in $auditItems) {
    $subCat = $aItem.MethodArgument
    $rec = $aItem.RecommendedValue
    $flags = ""

    if ($rec -ieq "Success and Failure") {
        $flags = "/success:enable /failure:enable"
    } elseif ($rec -ieq "Success") {
        $flags = "/success:enable /failure:disable"
    } elseif ($rec -ieq "Failure") {
        $flags = "/success:disable /failure:enable"
    } elseif ($rec -ieq "No Auditing") {
        $flags = "/success:disable /failure:disable"
    }

    if (-not [string]::IsNullOrEmpty($flags)) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "auditpol.exe"
            $psi.Arguments = "/set /subcategory:`"$subCat`" $flags"
            $psi.CreateNoWindow = $true
            $psi.UseShellExecute = $false
            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($null -ne $proc) {
                $proc.WaitForExit()
                if ($proc.ExitCode -eq 0) {
                    Write-Host ("  [OK] Auditpol: '$subCat' -> $flags") -ForegroundColor Green
                    $successCount++
                } else {
                    Write-Warning ("  [FAIL] Auditpol: '$subCat' failed with exit code " + $proc.ExitCode)
                    $failCount++
                }
            }
        }
        catch {
            Write-Warning ("  [FAIL] Auditpol: '$subCat' -> " + $_.Exception.Message)
            $failCount++
        }
    }
}

# D. Remediation: Services
$svcItems = New-Object System.Collections.ArrayList
foreach ($item in $remediateItems) {
    if ($item.Method -ieq "service") {
        [void]$svcItems.Add($item)
    }
}

foreach ($sItem in $svcItems) {
    $svcName = $sItem.MethodArgument
    $targetMode = $sItem.RecommendedValue
    try {
        $svc = Get-WmiObject Win32_Service -Filter "Name = '$svcName'" -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            Set-Service -Name $svcName -StartupType $targetMode -ErrorAction Stop
            if ($svc.State -eq "Running" -and $targetMode -eq "Disabled") {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            Write-Host ("  [OK] Service '$svcName' set to $targetMode") -ForegroundColor Green
            $successCount++
        } else {
            Write-Host ("  [INFO] Service '$svcName' is not installed (no action needed).")
            $successCount++
        }
    }
    catch {
        Write-Warning ("  [FAIL] Service '$svcName' -> " + $_.Exception.Message)
        $failCount++
    }
}

# Summary
Write-Host "================ REMEDIATION SUMMARY ================" -ForegroundColor Cyan
Write-Host ("Total Attempted : " + ($successCount + $failCount))
Write-Host ("Successful      : " + $successCount) -ForegroundColor Green
Write-Host ("Failed          : " + $failCount) -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
if ($skippedRemediateItems.Count -gt 0) {
    Write-Host ("Skipped         : " + $skippedRemediateItems.Count + " (unsupported methods without safe rollback)") -ForegroundColor Yellow
}
Write-Host ("Manifest File   : " + $manifestPath) -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

# Release exclusive lockfile upon successful completion
if ($null -ne $lockStream) {
    try { $lockStream.Close() } catch {}
    $lockStream = $null
}
if (Test-Path -Path $lockFilePath) {
    try { [System.IO.File]::Delete($lockFilePath) } catch {}
}
