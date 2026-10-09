# ==============================================================================
# File: Rollback-LegacyWin.ps1
# Description: PowerShell 2.0 Rollback Engine for Legacy Windows.
#              Restores system state using manifest produced during remediation.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestFile
)

# Resolve ScriptDir using PS 2.0 compatible invocation logic
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

$wmiHelper = Join-Path (Join-Path $ScriptDir "common") "Invoke-WmiCompat.ps1"
if (Test-Path -Path $wmiHelper) {
    . $wmiHelper
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

function Resolve-BackupPath {
    param(
        [string]$PathValue,
        [string]$BaseDir
    )
    if ([string]::IsNullOrEmpty($PathValue) -or $PathValue -ieq "N/A") {
        return ""
    }
    # If path is relative, resolve against BaseDir
    if (-not [System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::Combine($BaseDir, $PathValue)
    }
    # If path is absolute and exists, return it directly
    if (Test-Path -Path $PathValue) {
        return $PathValue
    }
    # If absolute path does not exist, check if filename exists inside BaseDir
    $fileName = [System.IO.Path]::GetFileName($PathValue)
    $candidate = [System.IO.Path]::Combine($BaseDir, $fileName)
    if (Test-Path -Path $candidate) {
        return $candidate
    }
    return $PathValue
}

# Support passing either directory (containing backup_manifest.txt) or manifest file
if (Test-Path -Path $ManifestFile) {
    if ([System.IO.Directory]::Exists($ManifestFile)) {
        $candidateManifest = Join-Path $ManifestFile "backup_manifest.txt"
        if (Test-Path -Path $candidateManifest) {
            $ManifestFile = $candidateManifest
        }
    }
}

if (-not (Test-Path -Path $ManifestFile)) {
    Write-Error ("Manifest file not found: " + $ManifestFile)
    return
}
$ManifestFile = (Get-Item -LiteralPath $ManifestFile).FullName
$manifestDir = Split-Path $ManifestFile -Parent

Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] ================= STARTING SYSTEM ROLLBACK =================") -ForegroundColor Cyan
Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] Manifest File: " + $ManifestFile) -ForegroundColor Cyan

# Parse manifest file
$regFiles = New-Object System.Collections.ArrayList
$regDeleteFile = ""
$createdKeys = New-Object System.Collections.ArrayList
$createdValues = New-Object System.Collections.ArrayList
$seceditFile = ""
$auditpolFile = ""
$snapshotFile = ""

$lines = [System.IO.File]::ReadAllLines($ManifestFile)
foreach ($rawLine in $lines) {
    if ($null -eq $rawLine) { continue }
    $line = $rawLine.Trim()
    if ($line.Length -eq 0 -or $line.StartsWith("#") -or $line.StartsWith(";")) { continue }

    # Parse CreatedRegistryValue (supports '=' and ':')
    if ($line.StartsWith("CreatedRegistryValue=", [System.StringComparison]::OrdinalIgnoreCase)) {
        $v = $line.Substring(21).Trim()
        if ($v.Length -gt 0 -and $v -ine "N/A") { [void]$createdValues.Add($v) }
        continue
    }
    if ($line.StartsWith("CreatedRegistryValue:", [System.StringComparison]::OrdinalIgnoreCase)) {
        $v = $line.Substring(21).Trim()
        if ($v.Length -gt 0 -and $v -ine "N/A") { [void]$createdValues.Add($v) }
        continue
    }

    # Parse CreatedRegistryKey (supports '=' and ':')
    if ($line.StartsWith("CreatedRegistryKey=", [System.StringComparison]::OrdinalIgnoreCase)) {
        $v = $line.Substring(19).Trim()
        if ($v.Length -gt 0 -and $v -ine "N/A") { [void]$createdKeys.Add($v) }
        continue
    }
    if ($line.StartsWith("CreatedRegistryKey:", [System.StringComparison]::OrdinalIgnoreCase)) {
        $v = $line.Substring(19).Trim()
        if ($v.Length -gt 0 -and $v -ine "N/A") { [void]$createdKeys.Add($v) }
        continue
    }

    $eqIdx = $line.IndexOf("=")
    if ($eqIdx -gt 0) {
        $k = $line.Substring(0, $eqIdx).Trim()
        $v = $line.Substring($eqIdx + 1).Trim()

        if ($k -ieq "RegistryBackup" -or $k -ieq "Registry") {
            if ($v -ine "N/A" -and $v.Length -gt 0) {
                foreach ($part in $v.Split(";,")) {
                    $p = $part.Trim()
                    if ($p.Length -gt 0 -and $p -ine "N/A") {
                        $resolved = Resolve-BackupPath $p $manifestDir
                        if (-not [string]::IsNullOrEmpty($resolved)) {
                            [void]$regFiles.Add($resolved)
                        }
                    }
                }
            }
        } elseif ($k -ieq "RegistryDeleteBackup" -or $k -ieq "RegistryDelete") {
            $regDeleteFile = Resolve-BackupPath $v $manifestDir
        } elseif ($k -ieq "SeceditBackup" -or $k -ieq "Secedit") {
            $seceditFile = Resolve-BackupPath $v $manifestDir
        } elseif ($k -ieq "AuditpolBackup" -or $k -ieq "Auditpol") {
            $auditpolFile = Resolve-BackupPath $v $manifestDir
        } elseif ($k -ieq "StateSnapshot" -or $k -ieq "Snapshot") {
            $snapshotFile = Resolve-BackupPath $v $manifestDir
        }
    }
}

# 1. Rollback Registry
Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] --- Step 1: Rollback Registry ---") -ForegroundColor Cyan

# 1.1 Restore pre-existing registry keys and values from exported .reg files
if ($regFiles.Count -eq 0) {
    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] No Registry backup files recorded in manifest.")
} else {
    foreach ($rf in $regFiles) {
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        if (Test-Path -Path $rf) {
            Write-Host ("[" + $now + "] Restoring Registry: reg.exe import `"" + $rf + "`"") -ForegroundColor Yellow
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "reg.exe"
            $psi.Arguments = "import `"" + $rf + "`""
            $psi.CreateNoWindow = $true
            $psi.UseShellExecute = $false
            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($null -ne $proc) {
                $proc.WaitForExit()
                if ($proc.ExitCode -eq 0) {
                    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Registry imported: " + $rf) -ForegroundColor Green
                } else {
                    Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [FAIL] reg.exe import exit code: " + $proc.ExitCode)
                }
            }
        } else {
            Write-Warning ("[" + $now + "] Registry backup file not found: " + $rf)
        }
    }
}

# 1.2 Import Registry Delete Undo file if present (Finding P1)
if (-not [string]::IsNullOrEmpty($regDeleteFile) -and (Test-Path -Path $regDeleteFile)) {
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ("[" + $now + "] Applying Registry undo delete: reg.exe import `"" + $regDeleteFile + "`"") -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "reg.exe"
    $psi.Arguments = "import `"" + $regDeleteFile + "`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $proc) {
        $proc.WaitForExit()
        if ($proc.ExitCode -eq 0) {
            Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Registry undo delete imported successfully.") -ForegroundColor Green
        } else {
            Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [FAIL] reg.exe import for undo delete exit code: " + $proc.ExitCode)
        }
    }
}

# 1.3 Remove newly created registry values (Finding P1)
if ($createdValues.Count -gt 0) {
    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] Removing " + $createdValues.Count + " newly created registry value(s)...") -ForegroundColor Cyan
    foreach ($entry in $createdValues) {
        $sepIdx = $entry.IndexOf("|")
        if ($sepIdx -gt 0) {
            $rawPath = $entry.Substring(0, $sepIdx).Trim()
            $propName = $entry.Substring($sepIdx + 1).Trim()

            $psPath = Convert-ToPsDrivePath $rawPath
            if (Test-Path -Path $psPath) {
                try {
                    Remove-ItemProperty -Path $psPath -Name $propName -Force -ErrorAction SilentlyContinue
                    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Removed created registry value: " + $rawPath + "\" + $propName) -ForegroundColor Green
                }
                catch {
                    Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [FAIL] Failed to remove value " + $rawPath + "\" + $propName + ": " + $_.Exception.Message)
                }
            }
        }
    }
}

# 1.4 Remove newly created registry keys (Finding P1)
if ($createdKeys.Count -gt 0) {
    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] Removing " + $createdKeys.Count + " newly created registry key(s)...") -ForegroundColor Cyan
    foreach ($rawKey in $createdKeys) {
        $psPath = Convert-ToPsDrivePath $rawKey
        if (Test-Path -Path $psPath) {
            try {
                Remove-Item -Path $psPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Removed created registry key: " + $rawKey) -ForegroundColor Green
            }
            catch {
                Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [FAIL] Failed to remove key " + $rawKey + ": " + $_.Exception.Message)
            }
        }
    }
}

# 2. Rollback Secedit
Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] --- Step 2: Rollback Secedit Security Policy ---") -ForegroundColor Cyan
if (-not [string]::IsNullOrEmpty($seceditFile) -and (Test-Path -Path $seceditFile)) {
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ("[" + $now + "] Restoring Secedit: secedit.exe /configure /cfg `"" + $seceditFile + "`"") -ForegroundColor Yellow
    $tempRollbackId = [System.Guid]::NewGuid().ToString("N")
    $tempDb = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "rollback_" + $tempRollbackId + ".sdb")
    $tempLog = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "rollback_" + $tempRollbackId + ".log")

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "secedit.exe"
    $psi.Arguments = "/configure /db `"" + $tempDb + "`" /cfg `"" + $seceditFile + "`" /log `"" + $tempLog + "`" /quiet /areas SECURITYPOLICY"
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $proc) {
        $proc.WaitForExit()
        if ($proc.ExitCode -eq 0) {
            Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Secedit policy restored successfully.") -ForegroundColor Green
        } else {
            Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [FAIL] secedit.exe exit code: " + $proc.ExitCode)
        }
    }

    if (Test-Path -Path $tempDb) { Remove-Item -Path $tempDb -Force -ErrorAction SilentlyContinue }
    if (Test-Path -Path $tempLog) { Remove-Item -Path $tempLog -Force -ErrorAction SilentlyContinue }
} else {
    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] No Secedit backup file recorded or file not found.")
}

# 3. Rollback Auditpol
Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] --- Step 3: Rollback Audit Policy ---") -ForegroundColor Cyan
if (-not [string]::IsNullOrEmpty($auditpolFile) -and (Test-Path -Path $auditpolFile)) {
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ("[" + $now + "] Restoring Auditpol: auditpol.exe /restore /file:`"" + $auditpolFile + "`"") -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "auditpol.exe"
    $psi.Arguments = "/restore /file:`"" + $auditpolFile + "`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $proc) {
        $proc.WaitForExit()
        if ($proc.ExitCode -eq 0) {
            Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Audit policy restored successfully.") -ForegroundColor Green
        } else {
            Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [FAIL] auditpol.exe restore exit code: " + $proc.ExitCode)
        }
    }
} else {
    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] No Auditpol backup file recorded or file not found.")
}

# 4. Rollback Services from Snapshot (if recorded)
if (-not [string]::IsNullOrEmpty($snapshotFile) -and (Test-Path -Path $snapshotFile)) {
    Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] --- Step 4: Restoring Services from Snapshot ---") -ForegroundColor Cyan
    try {
        $snapRows = Import-Csv -Path $snapshotFile
        foreach ($row in $snapRows) {
            if ($row.Method -ieq "service" -and -not [string]::IsNullOrEmpty($row.CurrentValue)) {
                $svcName = $row.MethodArgument
                $prevMode = $row.CurrentValue
                try {
                    $svc = Invoke-HKWmiQuery -ClassName "Win32_Service" -Filter "Name = '$svcName'"
                    if ($null -ne $svc -and -not [string]::IsNullOrEmpty($prevMode) -and $prevMode -ne "Disabled") {
                        Set-Service -Name $svcName -StartupType $prevMode -ErrorAction SilentlyContinue
                        Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] [OK] Restored service '$svcName' startup to " + $prevMode) -ForegroundColor Green
                    }
                }
                catch {
                    Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] Failed to restore service '" + $svcName + "': " + $_.Exception.Message)
                }
            }
        }
    }
    catch {
        Write-Warning ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] Failed to read snapshot file: " + $_.Exception.Message)
    }
}

Write-Host ("[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] ================= ROLLBACK COMPLETED =================") -ForegroundColor Cyan
