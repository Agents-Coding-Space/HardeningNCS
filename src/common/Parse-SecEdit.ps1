# ==============================================================================
# File: Parse-SecEdit.ps1
# Description: Helper functions to export and parse Windows Local Security Policy
#              using secedit.exe and INF parsing.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

function Export-SecEditPolicy {
    <#
    .SYNOPSIS
        Exports the current local security policy to an INF file using secedit.exe.
    .DESCRIPTION
        Invokes 'secedit.exe /export /cfg <Path> /areas <Areas> /quiet'.
        Returns the path to the exported INF file, or $null on failure.
    .PARAMETER Path
        Optional destination path for the INF file. If omitted, a temporary file is created.
    .PARAMETER Areas
        The security areas to export. Defaults to 'SECURITYPOLICY USER_RIGHTS'.
    .OUTPUTS
        [string] Path of the exported configuration file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Areas = "SECURITYPOLICY USER_RIGHTS"
    )

    if ([string]::IsNullOrEmpty($Path)) {
        $tempDir = [System.IO.Path]::GetTempPath()
        $tempName = "secedit_export_" + [System.Guid]::NewGuid().ToString("N") + ".inf"
        $Path = [System.IO.Path]::Combine($tempDir, $tempName)
    }

    # Delete destination file if already present
    if (Test-Path -Path $Path) {
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
    }

    $logFile = [System.IO.Path]::ChangeExtension($Path, ".log")

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "secedit.exe"
        $psi.Arguments = "/export /cfg `"$Path`" /areas $Areas /log `"$logFile`" /quiet"
        $psi.CreateNoWindow = $true
        $psi.UseShellExecute = $false

        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -ne $proc) {
            $proc.WaitForExit()
        }
    }
    catch {
        Write-Warning ("Failed to execute secedit.exe: " + $_.Exception.Message)
    }
    finally {
        # Clean up temporary secedit log
        if (Test-Path -Path $logFile) {
            Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
        }
    }

    # Fallback to SECURITYPOLICY if combined areas failed to produce an INF
    if ((-not (Test-Path -Path $Path)) -and ($Areas -ne "SECURITYPOLICY")) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "secedit.exe"
            $psi.Arguments = "/export /cfg `"$Path`" /areas SECURITYPOLICY /log `"$logFile`" /quiet"
            $psi.CreateNoWindow = $true
            $psi.UseShellExecute = $false

            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($null -ne $proc) {
                $proc.WaitForExit()
            }
        }
        catch {
            Write-Warning ("Failed to execute fallback secedit.exe: " + $_.Exception.Message)
        }
        finally {
            if (Test-Path -Path $logFile) {
                Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if (Test-Path -Path $Path) {
        return $Path
    } else {
        Write-Warning "secedit export did not produce an output file. Elevated administrator privileges are required."
        return $null
    }
}

function Parse-SecEditFile {
    <#
    .SYNOPSIS
        Parses a secedit INF file line-by-line into a Hashtable.
    .DESCRIPTION
        Reads the INF file (handling UTF-16 LE Unicode encoding produced by secedit),
        processes sections and key-value pairs, and returns a Hashtable mapping
        '[Section\Key]' to Value, as well as '[Key]' to Value.
    .PARAMETER Path
        Path to the INF file to parse.
    .OUTPUTS
        [System.Collections.Hashtable] Hashtable of settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $result = @{}

    if (-not (Test-Path -Path $Path)) {
        Write-Warning ("SecEdit INF file not found: " + $Path)
        return $result
    }

    # SecEdit exports in Unicode (UTF-16 LE) with BOM 0xFF, 0xFE
    $lines = $null
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $lines = [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::Unicode)
        } else {
            $lines = [System.IO.File]::ReadAllLines($Path)
        }
    }
    catch {
        Write-Warning ("Error reading SecEdit file: " + $_.Exception.Message)
        return $result
    }

    if ($null -eq $lines) {
        return $result
    }

    $currentSection = ""

    foreach ($rawLine in $lines) {
        if ($null -eq $rawLine) { continue }
        $line = $rawLine.Trim()

        # Skip empty lines and comments (; or #)
        if ($line.Length -eq 0 -or $line.StartsWith(";") -or $line.StartsWith("#")) {
            continue
        }

        # Section header [SectionName]
        if ($line.StartsWith("[") -and $line.EndsWith("]")) {
            $currentSection = $line.Substring(1, $line.Length - 2).Trim()
            continue
        }

        # Key = Value entry
        $equalIdx = $line.IndexOf("=")
        if ($equalIdx -gt 0) {
            $key = $line.Substring(0, $equalIdx).Trim()
            $val = $line.Substring($equalIdx + 1).Trim()

            # Strip surrounding quotes if present
            if ($val.StartsWith('"') -and $val.EndsWith('"') -and $val.Length -ge 2) {
                $val = $val.Substring(1, $val.Length - 2)
            }

            if ($currentSection.Length -gt 0) {
                $compositeKey = "$currentSection\$key"
                $result[$compositeKey] = $val
            }
            # Also store under direct key if not yet defined
            if (-not $result.ContainsKey($key)) {
                $result[$key] = $val
            }
        }
    }

    return $result
}

function Get-SecEditPolicy {
    <#
    .SYNOPSIS
        Convenience wrapper to export and parse local security policy into a Hashtable.
    .DESCRIPTION
        Exports security policy via secedit, parses the resultant INF file,
        and cleans up temporary files.
    .PARAMETER Path
        Optional pre-existing INF file path. If omitted, performs a live export.
    .PARAMETER Areas
        The security areas to export. Defaults to 'SECURITYPOLICY USER_RIGHTS'.
    .OUTPUTS
        [System.Collections.Hashtable]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string]$Areas = "SECURITYPOLICY USER_RIGHTS"
    )

    $isTemp = $false
    $targetPath = $Path

    if ([string]::IsNullOrEmpty($targetPath)) {
        $targetPath = Export-SecEditPolicy -Areas $Areas
        if ([string]::IsNullOrEmpty($targetPath)) {
            return @{}
        }
        $isTemp = $true
    }

    try {
        $policyData = Parse-SecEditFile -Path $targetPath
        return $policyData
    }
    finally {
        if ($isTemp -and (Test-Path -Path $targetPath)) {
            Remove-Item -Path $targetPath -Force -ErrorAction SilentlyContinue
        }
    }
}
