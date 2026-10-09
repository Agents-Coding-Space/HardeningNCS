# ==============================================================================
# File: Audit-LegacyWin.ps1
# Description: PowerShell 2.0 Audit Engine for Legacy Windows (Windows 7 / Server 2008 R2 / 2012 R2).
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FindingList = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory = $false)]
    [string[]]$SkipMethods = @()
)

# Resolve ScriptDir using PS 2.0 compatible invocation logic
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

# Resolve FindingList path
if ([string]::IsNullOrEmpty($FindingList)) {
    $FindingList = Join-Path (Split-Path $ScriptDir -Parent) "lists\finding_list_cis_win7_sp1_machine.csv"
}
$FindingList = [System.IO.Path]::GetFullPath($FindingList)

if (-not (Test-Path -Path $FindingList)) {
    Write-Error ("Finding list file not found: " + $FindingList)
    return
}

# Resolve OutputDir and OutputFile path
if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path (Split-Path $ScriptDir -Parent) "outputs"
}

if ($OutputDir.EndsWith(".csv", [System.StringComparison]::OrdinalIgnoreCase)) {
    $OutputFile = [System.IO.Path]::GetFullPath($OutputDir)
    $parentDir = Split-Path $OutputFile -Parent
    if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path -Path $parentDir)) {
        [void](New-Item -ItemType Directory -Path $parentDir -Force)
    }
} else {
    $OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
    if (-not (Test-Path -Path $OutputDir)) {
        [void](New-Item -ItemType Directory -Path $OutputDir -Force)
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFile = Join-Path $OutputDir ("audit_report_" + $timestamp + ".csv")
}

# Load helper scripts from common directory
$commonDir = Join-Path $ScriptDir "common"
$compareHelper = Join-Path $commonDir "Compare-Value.ps1"
$secEditHelper = Join-Path $commonDir "Parse-SecEdit.ps1"
$auditPolHelper = Join-Path $commonDir "Parse-AuditPol.ps1"

if (Test-Path -Path $compareHelper) {
    . $compareHelper
} else {
    Write-Error ("Missing helper script: " + $compareHelper)
    return
}

if (Test-Path -Path $secEditHelper) {
    . $secEditHelper
} else {
    Write-Error ("Missing helper script: " + $secEditHelper)
    return
}

if (Test-Path -Path $auditPolHelper) {
    . $auditPolHelper
} else {
    Write-Error ("Missing helper script: " + $auditPolHelper)
    return
}

# Secedit export (1 time export using temp file)
$secEditData = @{}
$skipSecEdit = ($SkipMethods -contains "secedit" -and $SkipMethods -contains "accountpolicy")
if (-not $skipSecEdit) {
    try {
        $secEditData = Get-SecEditPolicy
    }
    catch {
        Write-Warning ("Failed to query SecEdit policy: " + $_.Exception.Message)
    }
}

# Auditpol dump (1 time dump)
$auditPolData = @{}
if ($SkipMethods -notcontains "auditpol") {
    try {
        $auditPolData = Get-AuditPolicySettings
    }
    catch {
        Write-Warning ("Failed to query AuditPol policy: " + $_.Exception.Message)
    }
}

# Local accounts cache (1 time WMI query)
$localAccounts = @{}
if ($SkipMethods -notcontains "localaccount") {
    try {
        $accList = Get-WmiObject Win32_UserAccount -Filter "LocalAccount = True" -ErrorAction SilentlyContinue
        if ($null -ne $accList) {
            foreach ($acc in $accList) {
                if ($acc.SID -match "-500$") {
                    $localAccounts["Administrator"] = $acc
                } elseif ($acc.SID -match "-501$") {
                    $localAccounts["Guest"] = $acc
                }
                $localAccounts[$acc.Name] = $acc
            }
        }
    }
    catch {
        Write-Warning ("Failed to query local accounts: " + $_.Exception.Message)
    }
}

# Read finding list
$findings = Import-Csv -Path $FindingList

$results = New-Object System.Collections.ArrayList
$totalCount = 0
$passedCount = 0
$failedCount = 0
$skippedCount = 0

foreach ($item in $findings) {
    $totalCount++
    $method = if ($null -ne $item.Method) { $item.Method.Trim() } else { "" }

    # Check Skip conditions
    $isSkipped = $false
    if ($method -ieq "MpPreferenceAsr") {
        $isSkipped = $true
    } elseif ($SkipMethods -contains $method) {
        $isSkipped = $true
    }

    $currentVal = $null
    $displayVal = ""
    $status = ""

    if ($isSkipped) {
        $status = "Skipped"
        $skippedCount++
        $displayVal = "SKIPPED"
    } else {
        # Dispatch by Method
        switch ($method) {
            "Registry" {
                $regPath = $item.RegistryPath
                if ($regPath.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
                    $regPath = "HKLM:\" + $regPath.Substring(5)
                } elseif ($regPath.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
                    $regPath = "HKCU:\" + $regPath.Substring(5)
                }

                $propName = $item.RegistryItem
                if (Test-Path -Path $regPath) {
                    $propObj = (Get-ItemProperty -Path $regPath -Name $propName -ErrorAction SilentlyContinue)
                    if ($null -ne $propObj -and $null -ne $propObj.$propName) {
                        $currentVal = $propObj.$propName
                    }
                }
            }

            { $_ -eq "secedit" -or $_ -eq "accountpolicy" } {
                $arg = $item.MethodArgument
                if (-not [string]::IsNullOrEmpty($arg)) {
                    if ($secEditData.ContainsKey($arg)) {
                        $currentVal = $secEditData[$arg]
                    } elseif ($secEditData.ContainsKey("System Access\" + $arg)) {
                        $currentVal = $secEditData["System Access\" + $arg]
                    } else {
                        $slashIdx = $arg.IndexOf("\")
                        if ($slashIdx -gt 0 -and $slashIdx -lt ($arg.Length - 1)) {
                            $bareKey = $arg.Substring($slashIdx + 1)
                            if ($secEditData.ContainsKey($bareKey)) {
                                $currentVal = $secEditData[$bareKey]
                            }
                        }
                    }
                }
            }

            "auditpol" {
                $arg = $item.MethodArgument
                if (-not [string]::IsNullOrEmpty($arg) -and $auditPolData.ContainsKey($arg)) {
                    $currentVal = $auditPolData[$arg]
                }
            }

            "localaccount" {
                $arg = $item.MethodArgument
                $acc = $null
                if ($localAccounts.ContainsKey($arg)) {
                    $acc = $localAccounts[$arg]
                }
                if ($null -ne $acc) {
                    if ($item.Name -match "status" -or $item.RecommendedValue -match "^(Enabled|Disabled)$") {
                        $currentVal = if ($acc.Disabled) { "Disabled" } else { "Enabled" }
                    } else {
                        $currentVal = $acc.Name
                    }
                }
            }

            "service" {
                $svcName = $item.MethodArgument
                $svc = Get-WmiObject Win32_Service -Filter "Name = '$svcName'" -ErrorAction SilentlyContinue
                if ($null -ne $svc) {
                    $currentVal = $svc.StartMode
                }
            }

            default {
                Write-Warning ("Unknown audit method '" + $method + "' for ID " + $item.ID)
            }
        }

        # Compare using Compare-HKValue
        $isCompliant = Compare-HKValue -Current $currentVal -Recommended $item.RecommendedValue -Operator $item.Operator
        if ($isCompliant) {
            $status = "Passed"
            $passedCount++
        } else {
            $status = "Failed"
            $failedCount++
        }

        # Format display value for CSV output
        if ($currentVal -is [System.Array] -or $currentVal -is [System.Collections.IList]) {
            $arrStrings = New-Object System.Collections.ArrayList
            foreach ($elem in $currentVal) {
                if ($null -ne $elem) { [void]$arrStrings.Add("$elem".Trim()) }
            }
            $displayVal = [string]::Join(",", $arrStrings.ToArray())
        } else {
            $displayVal = if ($null -eq $currentVal) { "" } else { "$currentVal" }
        }
    }

    # Construct result object using PS 2.0 compatible New-Object PSObject + Add-Member
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "ID" -Value $item.ID
    $obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $item.Category
    $obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $item.Name
    $obj | Add-Member -MemberType NoteProperty -Name "Method" -Value $item.Method
    $obj | Add-Member -MemberType NoteProperty -Name "MethodArgument" -Value $item.MethodArgument
    $obj | Add-Member -MemberType NoteProperty -Name "RegistryPath" -Value $item.RegistryPath
    $obj | Add-Member -MemberType NoteProperty -Name "RegistryItem" -Value $item.RegistryItem
    $obj | Add-Member -MemberType NoteProperty -Name "DefaultValue" -Value $item.DefaultValue
    $obj | Add-Member -MemberType NoteProperty -Name "RecommendedValue" -Value $item.RecommendedValue
    $obj | Add-Member -MemberType NoteProperty -Name "Operator" -Value $item.Operator
    $obj | Add-Member -MemberType NoteProperty -Name "Severity" -Value $item.Severity
    $obj | Add-Member -MemberType NoteProperty -Name "CurrentValue" -Value $displayVal
    $obj | Add-Member -MemberType NoteProperty -Name "Status" -Value $status
    [void]$results.Add($obj)
}

# Export CSV with -NoTypeInformation (PS 2.0 compatible)
$results.ToArray() | Export-Csv -Path $OutputFile -NoTypeInformation

# Print audit summary to screen
Write-Host "================ AUDIT SUMMARY ================" -ForegroundColor Cyan
Write-Host ("Total Findings : " + $totalCount)
Write-Host ("Passed         : " + $passedCount) -ForegroundColor Green
Write-Host ("Failed         : " + $failedCount) -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Green" })
Write-Host ("Skipped        : " + $skippedCount) -ForegroundColor $(if ($skippedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ("Report Output  : " + $OutputFile) -ForegroundColor Cyan
