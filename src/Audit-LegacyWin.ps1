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
    [string[]]$SkipMethods = @(),

    [Parameter(Mandatory = $false)]
    [string]$SecEditFile = ""
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

# Secedit export (1 time export using temp file or pre-supplied SecEditFile)
$secEditData = @{}
$secEditPrivilegeDataAvailable = $false
$skipSecEdit = ($SkipMethods -contains "secedit" -and $SkipMethods -contains "accountpolicy" -and $SkipMethods -contains "accesschk")
if (-not $skipSecEdit) {
    try {
        if (-not [string]::IsNullOrEmpty($SecEditFile)) {
            if (Test-Path -Path $SecEditFile) {
                $secEditData = Get-SecEditPolicy -Path $SecEditFile
            } else {
                Write-Error ("Specified SecEditFile not found: " + $SecEditFile)
                return
            }
        } else {
            $secEditData = Get-SecEditPolicy
        }
        if ($null -ne $secEditData -and $secEditData.Count -gt 0) {
            foreach ($secKey in $secEditData.Keys) {
                if ($secKey.StartsWith("Privilege Rights\", [System.StringComparison]::OrdinalIgnoreCase) -or $secKey.StartsWith("Se", [System.StringComparison]::OrdinalIgnoreCase)) {
                    $secEditPrivilegeDataAvailable = $true
                    break
                }
            }
        }
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

# Net accounts cache (fallback for accountpolicy)
$netAccountsData = @{}
if ($SkipMethods -notcontains "accountpolicy") {
    try {
        $netOutput = cmd.exe /c net accounts 2>$null
        if ($null -ne $netOutput) {
            foreach ($line in $netOutput) {
                $colonIdx = $line.IndexOf(":")
                if ($colonIdx -gt 0) {
                    $k = $line.Substring(0, $colonIdx).Trim()
                    $v = $line.Substring($colonIdx + 1).Trim()
                    if ($k -like "Force user logoff*") {
                        $netAccountsData["FORCE_LOGOFF"] = if ($v -ieq "Never" -or $v -eq "0") { "Disabled" } else { "Enabled" }
                        $netAccountsData["ForceLogoffWhenHourExpire"] = if ($v -ieq "Never" -or $v -eq "0") { "0" } else { "1" }
                    } elseif ($k -like "Minimum password age*") {
                        $netAccountsData["MINIMUM_PASSWORD_AGE"] = $v
                        $netAccountsData["MinimumPasswordAge"] = $v
                    } elseif ($k -like "Maximum password age*") {
                        $netAccountsData["MAXIMUM_PASSWORD_AGE"] = $v
                        $netAccountsData["MaximumPasswordAge"] = $v
                    } elseif ($k -like "Minimum password length*") {
                        $netAccountsData["MINIMUM_PASSWORD_LENGTH"] = $v
                        $netAccountsData["MinimumPasswordLength"] = $v
                    } elseif ($k -like "Length of password history*") {
                        $valHist = if ($v -ieq "None") { "0" } else { $v }
                        $netAccountsData["ENFORCE_PASSWORD_HISTORY"] = $valHist
                        $netAccountsData["PasswordHistorySize"] = $valHist
                    } elseif ($k -like "Lockout threshold*") {
                        $valThresh = if ($v -ieq "Never") { "0" } else { $v }
                        $netAccountsData["LOCKOUT_THRESHOLD"] = $valThresh
                        $netAccountsData["LockoutBadCount"] = $valThresh
                    } elseif ($k -like "Lockout duration*") {
                        $netAccountsData["LOCKOUT_DURATION"] = $v
                        $netAccountsData["LockoutDuration"] = $v
                    } elseif ($k -like "Lockout observation window*") {
                        $netAccountsData["LOCKOUT_RESET"] = $v
                        $netAccountsData["ResetLockoutCount"] = $v
                    }
                }
            }
        }
    }
    catch {
        Write-Warning ("Failed to query net accounts: " + $_.Exception.Message)
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
                    $localAccounts["500"] = $acc
                    $localAccounts["Administrator"] = $acc
                } elseif ($acc.SID -match "-501$") {
                    $localAccounts["501"] = $acc
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

# Standard CIS account policy mapping
$accountPolicyMap = @{
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

# Read finding list
$findings = Import-Csv -Path $FindingList

$results = New-Object System.Collections.ArrayList
$totalCount = 0
$passedCount = 0
$failedCount = 0
$skippedCount = 0

foreach ($item in $findings) {
    $totalCount++

    # Safe extraction of properties (including UTF-8 BOM handling for ID)
    $itemId = ""
    if ($null -ne $item.ID) {
        $itemId = "$($item.ID)".Trim()
    }
    if ([string]::IsNullOrEmpty($itemId) -and $null -ne $item."`ufeffID") {
        $itemId = "$($item."`ufeffID")".Trim()
    }

    $category = if ($null -ne $item.Category) { "$($item.Category)".Trim() } else { "" }
    $name = if ($null -ne $item.Name) { "$($item.Name)".Trim() } else { "" }
    $method = if ($null -ne $item.Method) { "$($item.Method)".Trim() } else { "" }
    $methodArg = if ($null -ne $item.MethodArgument) { "$($item.MethodArgument)".Trim() } else { "" }
    $regPath = if ($null -ne $item.RegistryPath) { "$($item.RegistryPath)".Trim() } else { "" }
    $regItem = if ($null -ne $item.RegistryItem) { "$($item.RegistryItem)".Trim() } else { "" }
    $defVal = if ($null -ne $item.DefaultValue) { "$($item.DefaultValue)".Trim() } else { "" }
    $recVal = if ($null -ne $item.RecommendedValue) { "$($item.RecommendedValue)".Trim() } else { "" }
    $operator = if ($null -ne $item.Operator) { "$($item.Operator)".Trim() } else { "=" }
    if ([string]::IsNullOrEmpty($operator)) { $operator = "=" }
    $severity = if ($null -ne $item.Severity) { "$($item.Severity)".Trim() } else { "" }

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
    $isUnknownMethod = $false

    if ($isSkipped) {
        $status = "Skipped"
        $skippedCount++
        $displayVal = "SKIPPED"
    } else {
        # Dispatch by Method
        switch ($method) {
            "Registry" {
                if (-not [string]::IsNullOrEmpty($regPath) -and -not [string]::IsNullOrEmpty($regItem)) {
                    $normPath = $regPath
                    if ($normPath.StartsWith("HKLM\", [System.StringComparison]::OrdinalIgnoreCase)) {
                        $normPath = "HKLM:\" + $normPath.Substring(5)
                    } elseif ($normPath.StartsWith("HKCU\", [System.StringComparison]::OrdinalIgnoreCase)) {
                        $normPath = "HKCU:\" + $normPath.Substring(5)
                    }

                    if (Test-Path -Path $normPath) {
                        $propObj = (Get-ItemProperty -Path $normPath -Name $regItem -ErrorAction SilentlyContinue)
                        if ($null -ne $propObj -and $null -ne $propObj.$regItem) {
                            $currentVal = $propObj.$regItem
                        }
                    }
                }
            }

            { $_ -eq "secedit" -or $_ -eq "accountpolicy" } {
                $targetKey = $methodArg
                if ($accountPolicyMap.ContainsKey($methodArg)) {
                    $targetKey = $accountPolicyMap[$methodArg]
                }

                if (-not [string]::IsNullOrEmpty($targetKey)) {
                    if ($secEditData.ContainsKey($targetKey)) {
                        $currentVal = $secEditData[$targetKey]
                    } elseif ($secEditData.ContainsKey("System Access\" + $targetKey)) {
                        $currentVal = $secEditData["System Access\" + $targetKey]
                    } elseif ($secEditData.ContainsKey($methodArg)) {
                        $currentVal = $secEditData[$methodArg]
                    } elseif ($secEditData.ContainsKey("System Access\" + $methodArg)) {
                        $currentVal = $secEditData["System Access\" + $methodArg]
                    } else {
                        $slashIdx = $methodArg.IndexOf("\")
                        if ($slashIdx -gt 0 -and $slashIdx -lt ($methodArg.Length - 1)) {
                            $bareKey = $methodArg.Substring($slashIdx + 1)
                            if ($secEditData.ContainsKey($bareKey)) {
                                $currentVal = $secEditData[$bareKey]
                            }
                        }
                    }
                }

                # Fallback to net accounts if not found in secEditData
                if ($null -eq $currentVal) {
                    if ($netAccountsData.ContainsKey($methodArg)) {
                        $currentVal = $netAccountsData[$methodArg]
                    } elseif ($netAccountsData.ContainsKey($targetKey)) {
                        $currentVal = $netAccountsData[$targetKey]
                    }
                }

                # Boolean normalization (Enabled/Disabled vs 1/0)
                if ($null -ne $currentVal) {
                    $currStr = "$currentVal".Trim()
                    if ($recVal -match "^(Enabled|Disabled)$") {
                        if ($currStr -eq "1") {
                            $currentVal = "Enabled"
                        } elseif ($currStr -eq "0") {
                            $currentVal = "Disabled"
                        }
                    } elseif ($recVal -match "^[01]$") {
                        if ($currStr -ieq "Enabled") {
                            $currentVal = "1"
                        } elseif ($currStr -ieq "Disabled") {
                            $currentVal = "0"
                        }
                    }
                }
            }

            "accesschk" {
                if (-not $secEditPrivilegeDataAvailable) {
                    $status = "Skipped"
                    $skippedCount++
                    $displayVal = "SKIPPED: Privilege Rights policy data unavailable (elevated privileges required)"
                } else {
                    $rawVal = $null
                    if ($secEditData.ContainsKey("Privilege Rights\" + $methodArg)) {
                        $rawVal = $secEditData["Privilege Rights\" + $methodArg]
                    } elseif ($secEditData.ContainsKey($methodArg)) {
                        $rawVal = $secEditData[$methodArg]
                    }

                    if ($null -eq $rawVal -or [string]::IsNullOrEmpty("$rawVal".Trim())) {
                        $currentVal = ""
                    } else {
                        $parts = "$rawVal".Split(',')
                        $translatedList = New-Object System.Collections.ArrayList
                        foreach ($part in $parts) {
                            $p = $part.Trim()
                            if ($p.StartsWith("*")) { $p = $p.Substring(1) }
                            if ($p.StartsWith("S-1-", [System.StringComparison]::OrdinalIgnoreCase)) {
                                try {
                                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($p)
                                    $ntAcc = $sidObj.Translate([System.Security.Principal.NTAccount])
                                    [void]$translatedList.Add($ntAcc.Value)
                                }
                                catch {
                                    [void]$translatedList.Add($p)
                                }
                            } else {
                                if (-not [string]::IsNullOrEmpty($p)) {
                                    [void]$translatedList.Add($p)
                                }
                            }
                        }
                        if ($translatedList.Count -eq 0) {
                            $currentVal = ""
                        } else {
                            $currentVal = [string]::Join(";", $translatedList.ToArray())
                        }
                    }
                }
            }

            "auditpol" {
                if (-not [string]::IsNullOrEmpty($methodArg) -and $auditPolData.ContainsKey($methodArg)) {
                    $currentVal = $auditPolData[$methodArg]
                }
            }

            "localaccount" {
                $acc = $null
                if (-not [string]::IsNullOrEmpty($methodArg) -and $localAccounts.ContainsKey($methodArg)) {
                    $acc = $localAccounts[$methodArg]
                }
                if ($null -ne $acc) {
                    if ($recVal -match "^(True|False)$") {
                        $currentVal = $acc.Disabled.ToString()
                    } elseif ($recVal -match "^(Enabled|Disabled)$") {
                        $currentVal = if ($acc.Disabled) { "Disabled" } else { "Enabled" }
                    } elseif ($name -match "status") {
                        $currentVal = if ($acc.Disabled) { "Disabled" } else { "Enabled" }
                    } else {
                        $currentVal = $acc.Name
                    }
                }
            }

            "service" {
                if (-not [string]::IsNullOrEmpty($methodArg)) {
                    $svc = Get-WmiObject Win32_Service -Filter "Name = '$methodArg'" -ErrorAction SilentlyContinue
                    if ($null -ne $svc) {
                        $currentVal = $svc.StartMode
                    }
                }
            }

            "command" {
                if ($itemId -eq "18.9.25.1" -or $name -match "EMET") {
                    $emetFound = $false
                    $emetVer = ""
                    $emetPaths = @("HKLM:\SOFTWARE\Microsoft\EMET", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\EMET")
                    foreach ($ep in $emetPaths) {
                        if (Test-Path -Path $ep) {
                            $emetFound = $true
                            $prop = Get-ItemProperty -Path $ep -Name "InstalledVersion" -ErrorAction SilentlyContinue
                            if ($null -ne $prop -and $null -ne $prop.InstalledVersion) {
                                $emetVer = "$($prop.InstalledVersion)"
                            }
                            break
                        }
                    }
                    if (-not $emetFound) {
                        $uninstPaths = @(
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                        )
                        foreach ($up in $uninstPaths) {
                            if (Test-Path -Path $up) {
                                $subKeys = Get-ChildItem -Path $up -ErrorAction SilentlyContinue
                                if ($null -ne $subKeys) {
                                    foreach ($sk in $subKeys) {
                                        $disp = $sk.GetValue("DisplayName")
                                        if ($null -ne $disp -and "$disp" -match "EMET") {
                                            $emetFound = $true
                                            $emetVer = "$disp"
                                            break
                                        }
                                    }
                                }
                            }
                            if ($emetFound) { break }
                        }
                    }

                    if ($emetFound) {
                        $currentVal = if (-not [string]::IsNullOrEmpty($emetVer)) { $emetVer } else { "Installed" }
                    } else {
                        $currentVal = "Not Installed"
                    }
                } else {
                    $isUnknownMethod = $true
                }
            }

            default {
                Write-Warning ("Unknown audit method '" + $method + "' for ID " + $itemId)
                $isUnknownMethod = $true
            }
        }

        if ($isUnknownMethod) {
            $status = "Skipped"
            $skippedCount++
            $displayVal = "SKIPPED: Unknown method '$method'"
        } elseif ([string]::IsNullOrEmpty($status)) {
            # Compare using Compare-HKValue
            $isCompliant = Compare-HKValue -Current $currentVal -Recommended $recVal -Operator $operator
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
    }

    # Construct result object using PS 2.0 compatible New-Object PSObject + Add-Member
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "ID" -Value $itemId
    $obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $category
    $obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $name
    $obj | Add-Member -MemberType NoteProperty -Name "Method" -Value $method
    $obj | Add-Member -MemberType NoteProperty -Name "MethodArgument" -Value $methodArg
    $obj | Add-Member -MemberType NoteProperty -Name "RegistryPath" -Value $regPath
    $obj | Add-Member -MemberType NoteProperty -Name "RegistryItem" -Value $regItem
    $obj | Add-Member -MemberType NoteProperty -Name "DefaultValue" -Value $defVal
    $obj | Add-Member -MemberType NoteProperty -Name "RecommendedValue" -Value $recVal
    $obj | Add-Member -MemberType NoteProperty -Name "Operator" -Value $operator
    $obj | Add-Member -MemberType NoteProperty -Name "Severity" -Value $severity
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
