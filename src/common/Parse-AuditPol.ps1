# ==============================================================================
# File: Parse-AuditPol.ps1
# Description: Helper functions to query and parse Windows Advanced Audit Policy
#              using auditpol.exe (CSV report /r and tabular formats).
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

function Parse-AuditPolOutput {
    <#
    .SYNOPSIS
        Parses raw stdout from auditpol.exe into a Hashtable of [SubCategory] = Setting.
    .DESCRIPTION
        Supports both report format (CSV via /r) and default tabular output.
        Returns a Hashtable mapping Subcategory name (and GUID when available)
        to the effective auditing setting (e.g., 'Success and Failure', 'Success',
        'Failure', 'No Auditing').
    .PARAMETER Lines
        Array of output lines or a multi-line string from auditpol.exe.
    .OUTPUTS
        [System.Collections.Hashtable]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lines
    )

    $result = @{}
    if ($null -eq $Lines) {
        return $result
    }

    $lineArray = @()
    if ($Lines -is [System.String]) {
        $lineArray = $Lines -split "`r?`n"
    } else {
        $lineArray = [string[]]$Lines
    }

    # Determine if output is CSV formatted (auditpol /r)
    $isCsv = $false
    $subCatCol = -1
    $settingCol = -1
    $guidCol = -1

    foreach ($rawLine in $lineArray) {
        if ($null -eq $rawLine) { continue }
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }

        # Check for CSV Header
        if (-not $isCsv -and $line -match "Subcategory" -and $line.IndexOf(",") -ge 0) {
            $isCsv = $true
            $headers = $line.Split(",")
            for ($i = 0; $i -lt $headers.Length; $i++) {
                $hdr = $headers[$i].Trim().Trim('"')
                if ($hdr -ieq "Subcategory") { $subCatCol = $i }
                if ($hdr -ieq "Inclusion Setting") { $settingCol = $i }
                if ($hdr -ieq "Subcategory GUID") { $guidCol = $i }
            }
            continue
        }

        if ($isCsv) {
            # Skip secondary headers or empty lines
            if ($line.StartsWith("Machine Name") -or $line.StartsWith("Policy Target")) {
                continue
            }

            # Split CSV line
            $tokens = $line.Split(",")
            if ($tokens.Length -ge 4) {
                $subCatIdx = if ($subCatCol -ge 0) { $subCatCol } else { 2 }
                $settIdx = if ($settingCol -ge 0) { $settingCol } else { 4 }

                if ($tokens.Length -gt $subCatIdx -and $tokens.Length -gt $settIdx) {
                    $subCat = $tokens[$subCatIdx].Trim().Trim('"')
                    $setting = $tokens[$settIdx].Trim().Trim('"')

                    if ($subCat.Length -gt 0) {
                        $result[$subCat] = $setting
                    }
                }

                # Optional GUID mapping
                if ($guidCol -ge 0 -and $tokens.Length -gt $guidCol) {
                    $guid = $tokens[$guidCol].Trim().Trim('"')
                    if ($guid.Length -gt 0 -and $tokens.Length -gt $settIdx) {
                        $result[$guid] = $tokens[$settIdx].Trim().Trim('"')
                    }
                }
            }
        } else {
            # Tabular / fixed-width format parsing
            # Matches: "  Credential Validation                   Success and Failure"
            if ($line -match '^\s*([A-Za-z0-9\s\(\)\-_/]+?)\s{2,}(Success and Failure|Success|Failure|No Auditing)\s*$') {
                $name = $matches[1].Trim()
                $setting = $matches[2].Trim()
                if ($name.Length -gt 0) {
                    $result[$name] = $setting
                }
            }
        }
    }

    return $result
}

function Get-AuditPolicySettings {
    <#
    .SYNOPSIS
        Executes auditpol.exe and returns current advanced audit policy settings.
    .DESCRIPTION
        Calls 'auditpol.exe /get /category:* /r' to retrieve full audit policy in CSV format,
        falling back to default output if /r fails.
        Elevated privileges (SeSecurityPrivilege) are required.
    .OUTPUTS
        [System.Collections.Hashtable] Mapping of Subcategory to Audit Setting.
    #>
    [CmdletBinding()]
    param()

    $result = @{}

    # First attempt: auditpol /get /category:* /r (CSV mode)
    $output = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "auditpol.exe"
        $psi.Arguments = "/get /category:* /r"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()

        if ($proc.ExitCode -eq 0 -and -not [string]::IsNullOrEmpty($stdout)) {
            $output = $stdout
        }
    }
    catch {
        Write-Warning ("Failed to execute auditpol /r: " + $_.Exception.Message)
    }

    # Fallback attempt: auditpol /get /category:* (Tabular mode)
    if ([string]::IsNullOrEmpty($output)) {
        try {
            $psi2 = New-Object System.Diagnostics.ProcessStartInfo
            $psi2.FileName = "auditpol.exe"
            $psi2.Arguments = "/get /category:*"
            $psi2.RedirectStandardOutput = $true
            $psi2.RedirectStandardError = $true
            $psi2.UseShellExecute = $false
            $psi2.CreateNoWindow = $true

            $proc2 = [System.Diagnostics.Process]::Start($psi2)
            $stdout2 = $proc2.StandardOutput.ReadToEnd()
            $proc2.WaitForExit()

            if ($proc2.ExitCode -eq 0 -and -not [string]::IsNullOrEmpty($stdout2)) {
                $output = $stdout2
            }
        }
        catch {
            Write-Warning ("Failed to execute fallback auditpol: " + $_.Exception.Message)
        }
    }

    if (-not [string]::IsNullOrEmpty($output)) {
        $result = Parse-AuditPolOutput -Lines $output
    } else {
        Write-Warning "auditpol returned no data. Administrative privileges (SeSecurityPrivilege) may be missing."
    }

    return $result
}
