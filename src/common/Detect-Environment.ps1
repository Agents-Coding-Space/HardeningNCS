# ==============================================================================
# File: Detect-Environment.ps1
# Description: Environment detection and intelligent checklist recommendation
#              helper for HardeningNCS.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

# Ensure Invoke-HKWmiQuery is available
if (-not (Get-Command -Name "Invoke-HKWmiQuery" -ErrorAction SilentlyContinue)) {
    $scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
    if ([string]::IsNullOrEmpty($scriptDir)) {
        $scriptDir = (Get-Location).Path
    }
    $wmiHelper = Join-Path $scriptDir "Invoke-WmiCompat.ps1"
    if (-not (Test-Path $wmiHelper)) {
        $wmiHelper = Join-Path (Join-Path (Get-Location).Path "src\common") "Invoke-WmiCompat.ps1"
    }
    if (Test-Path $wmiHelper) {
        . $wmiHelper
    }
}

function Get-HKSystemInfo {
    <#
    .SYNOPSIS
        Collects Windows OS details, domain role, and PowerShell runtime environment.
    .DESCRIPTION
        Queries Win32_OperatingSystem and Win32_ComputerSystem via Invoke-HKWmiQuery.
        Falls back to .NET and environment variables if WMI is unavailable.
        PowerShell 2.0 compatible.
    .OUTPUTS
        PSObject with system properties:
        - Caption, Version, BuildNumber, OSArchitecture, Bitness
        - DomainRole, DomainRoleName, IsDomainController, IsServer
        - ComputerName, Domain
        - PSVersion, PSEdition
    #>
    [CmdletBinding()]
    param()

    # Query Operating System details via WMI
    $os = $null
    try {
        $os = Invoke-HKWmiQuery -ClassName "Win32_OperatingSystem"
    } catch {
        $os = $null
    }

    # Query Computer System / Domain Role details via WMI
    $cs = $null
    try {
        $cs = Invoke-HKWmiQuery -ClassName "Win32_ComputerSystem"
    } catch {
        $cs = $null
    }

    # Extract OS Caption
    $caption = ""
    if ($null -ne $os -and -not [string]::IsNullOrEmpty($os.Caption)) {
        $caption = $os.Caption.Trim()
    } elseif (-not [string]::IsNullOrEmpty($env:OS)) {
        $caption = $env:OS
    } else {
        $caption = "Windows"
    }

    # Extract OS Version & Build Number
    $version = ""
    $buildNumber = ""
    if ($null -ne $os) {
        if (-not [string]::IsNullOrEmpty($os.Version)) {
            $version = $os.Version.Trim()
        }
        if (-not [string]::IsNullOrEmpty($os.BuildNumber)) {
            $buildNumber = $os.BuildNumber.Trim()
        }
    }
    if ([string]::IsNullOrEmpty($version)) {
        try {
            $version = [System.Environment]::OSVersion.Version.ToString()
            $buildNumber = [System.Environment]::OSVersion.Version.Build.ToString()
        } catch {
            $version = "0.0.0"
            $buildNumber = "0"
        }
    }

    # Extract Architecture / Bitness
    $osArch = ""
    if ($null -ne $os -and -not [string]::IsNullOrEmpty($os.OSArchitecture)) {
        $rawArch = $os.OSArchitecture.Trim()
        if ($rawArch -match "64") {
            $osArch = "64-bit"
        } elseif ($rawArch -match "32") {
            $osArch = "32-bit"
        } else {
            $osArch = $rawArch
        }
    }
    if ([string]::IsNullOrEmpty($osArch)) {
        if ([IntPtr]::Size -eq 8) {
            $osArch = "64-bit"
        } else {
            $osArch = "32-bit"
        }
    }
    $bitness = if ($osArch -match "64") { 64 } else { 32 }

    # Extract Domain Role
    # 0 = Standalone Workstation
    # 1 = Member Workstation
    # 2 = Standalone Server
    # 3 = Member Server
    # 4 = Backup Domain Controller
    # 5 = Primary Domain Controller
    $domainRole = -1
    if ($null -ne $cs -and $null -ne $cs.DomainRole) {
        $domainRole = [int]$cs.DomainRole
    }
    if ($domainRole -lt 0) {
        # Fallback heuristic
        if ($caption -match "(?i)server") {
            $domainRole = 2
        } else {
            $domainRole = 0
        }
    }

    $roleNameMap = @{
        0 = "Standalone Workstation"
        1 = "Member Workstation"
        2 = "Standalone Server"
        3 = "Member Server"
        4 = "Backup Domain Controller"
        5 = "Primary Domain Controller"
    }

    $domainRoleName = "Unknown"
    if ($roleNameMap.ContainsKey($domainRole)) {
        $domainRoleName = $roleNameMap[$domainRole]
    } else {
        $domainRoleName = "Unknown (" + $domainRole + ")"
    }

    $isDC = ($domainRole -eq 4 -or $domainRole -eq 5)
    $isServer = ($domainRole -ge 2 -and $domainRole -le 5) -or ($caption -match "(?i)server")

    # Extract Computer Name & Domain
    $compName = ""
    if ($null -ne $cs -and -not [string]::IsNullOrEmpty($cs.Name)) {
        $compName = $cs.Name.Trim()
    } elseif (-not [string]::IsNullOrEmpty($env:COMPUTERNAME)) {
        $compName = $env:COMPUTERNAME
    }

    $domain = ""
    if ($null -ne $cs -and -not [string]::IsNullOrEmpty($cs.Domain)) {
        $domain = $cs.Domain.Trim()
    } elseif (-not [string]::IsNullOrEmpty($env:USERDOMAIN)) {
        $domain = $env:USERDOMAIN
    }

    # Extract PowerShell Version & Edition
    $psVer = "2.0"
    if ($null -ne $PSVersionTable -and $null -ne $PSVersionTable.PSVersion) {
        $psVer = $PSVersionTable.PSVersion.ToString()
    }

    $edition = "Desktop"
    if ($null -ne $PSVersionTable -and $null -ne $PSVersionTable.PSEdition) {
        $edition = $PSVersionTable.PSEdition.ToString()
    } elseif ($null -ne $PSVersionTable -and $PSVersionTable.PSVersion.Major -ge 6) {
        $edition = "Core"
    }

    # Construct PS 2.0 compatible PSObject
    $sysInfo = New-Object PSObject
    $sysInfo | Add-Member -MemberType NoteProperty -Name "Caption" -Value $caption
    $sysInfo | Add-Member -MemberType NoteProperty -Name "Version" -Value $version
    $sysInfo | Add-Member -MemberType NoteProperty -Name "BuildNumber" -Value $buildNumber
    $sysInfo | Add-Member -MemberType NoteProperty -Name "OSArchitecture" -Value $osArch
    $sysInfo | Add-Member -MemberType NoteProperty -Name "Bitness" -Value $bitness
    $sysInfo | Add-Member -MemberType NoteProperty -Name "DomainRole" -Value $domainRole
    $sysInfo | Add-Member -MemberType NoteProperty -Name "DomainRoleName" -Value $domainRoleName
    $sysInfo | Add-Member -MemberType NoteProperty -Name "IsDomainController" -Value $isDC
    $sysInfo | Add-Member -MemberType NoteProperty -Name "IsServer" -Value $isServer
    $sysInfo | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $compName
    $sysInfo | Add-Member -MemberType NoteProperty -Name "Domain" -Value $domain
    $sysInfo | Add-Member -MemberType NoteProperty -Name "PSVersion" -Value $psVer
    $sysInfo | Add-Member -MemberType NoteProperty -Name "PSEdition" -Value $edition

    return $sysInfo
}

function Get-SuggestedChecklist {
    <#
    .SYNOPSIS
        Intelligently suggests the most appropriate CIS hardening checklist for the current system.
    .DESCRIPTION
        Scores candidate checklists based on OS caption/version, Domain Role (DC vs MS vs Workstation),
        and directory priority (lists/ core legacy prioritized over lists/Windows/).
        Filters out application-specific benchmarks (Office, browsers, IIS, etc.).
        PowerShell 2.0 compatible.
    .PARAMETER Checklists
        Array of checklist objects from Get-HKChecklistCatalog.
    .PARAMETER SystemInfo
        Optional PSObject from Get-HKSystemInfo. If omitted, Get-HKSystemInfo is called automatically.
    .OUTPUTS
        Checklist object representing the best match, or $null if no match is found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Checklists,

        [Parameter(Mandatory = $false)]
        [object]$SystemInfo = $null
    )

    if ($null -eq $Checklists -or $Checklists.Count -eq 0) {
        return $null
    }

    if ($null -eq $SystemInfo) {
        $SystemInfo = Get-HKSystemInfo
    }

    if ($null -eq $SystemInfo) {
        return $null
    }

    # Extract parameters for OS matching
    $caption = ""
    if ($null -ne $SystemInfo.Caption) { $caption = $SystemInfo.Caption }
    $version = ""
    if ($null -ne $SystemInfo.Version) { $version = $SystemInfo.Version }
    $build = [int64]0
    if ($null -ne $SystemInfo.BuildNumber) {
        [void][int64]::TryParse($SystemInfo.BuildNumber.ToString(), [ref]$build)
    }
    $isServer = [bool]$SystemInfo.IsServer
    $isDC = [bool]$SystemInfo.IsDomainController
    $domainRole = 0
    if ($null -ne $SystemInfo.DomainRole) {
        $domainRole = [int]$SystemInfo.DomainRole
    }

    # Classify OS Family
    $osFamily = ""
    if ($caption -match "(?i)2008\s*R2" -or ($version -like "6.1*" -and $isServer)) {
        $osFamily = "2008R2"
    } elseif ($caption -match "(?i)2008" -or ($version -like "6.0*" -and $isServer)) {
        $osFamily = "2008"
    } elseif ($caption -match "(?i)2012\s*R2" -or ($version -like "6.3*" -and $isServer)) {
        $osFamily = "2012R2"
    } elseif ($caption -match "(?i)2012" -or ($version -like "6.2*" -and $isServer)) {
        $osFamily = "2012"
    } elseif ($caption -match "(?i)2016") {
        $osFamily = "2016"
    } elseif ($caption -match "(?i)2019") {
        $osFamily = "2019"
    } elseif ($caption -match "(?i)2022") {
        $osFamily = "2022"
    } elseif ($caption -match "(?i)2025") {
        $osFamily = "2025"
    } elseif ($caption -match "(?i)Windows\s*7" -or ($version -like "6.1*" -and -not $isServer)) {
        $osFamily = "Win7"
    } elseif ($caption -match "(?i)Windows\s*8\.1" -or ($version -like "6.3*" -and -not $isServer)) {
        $osFamily = "Win8.1"
    } elseif ($caption -match "(?i)Windows\s*8" -or ($version -like "6.2*" -and -not $isServer)) {
        $osFamily = "Win8"
    } elseif ($caption -match "(?i)Windows\s*11" -or ($build -ge 22000 -and -not $isServer)) {
        $osFamily = "Win11"
    } elseif ($caption -match "(?i)Windows\s*10" -or ($build -ge 10240 -and -not $isServer)) {
        $osFamily = "Win10"
    }

    if ([string]::IsNullOrEmpty($osFamily)) {
        return $null
    }

    # Application components to exclude from OS benchmark suggestions
    $nonOsPatterns = @(
        "Office", "Outlook", "Word", "Excel", "PowerPoint", "Access", "OneNote",
        "Publisher", "Project", "Visio", "OneDrive", "Groove", "Lync", "Skype",
        "Chrome", "Firefox", "Edge", "IE9", "IE10", "IE11", "Internet_Explorer",
        "IIS", "Exchange", "SharePoint", "Acrobat", "Reader", "Apache", "McAfee",
        "SQL_Server", "WebSphere", "WebLogic", "Intune", "Defender_Antivirus",
        "Defender_Firewall", "DotNet", "JRE", "Privileged_Access", "EMS_Gateway"
    )

    $bestItem = $null
    $bestScore = -10000

    foreach ($item in $Checklists) {
        $fn = $item.FileName
        $rel = $item.RelativePath

        # Check if non-OS application
        $isApp = $false
        foreach ($app in $nonOsPatterns) {
            if ($fn -match ("(?i)\b" + $app + "\b") -or $fn -match ("(?i)_" + $app + "_")) {
                $isApp = $true
                break
            }
        }
        if ($isApp) {
            continue
        }

        # Check OS family match
        $osMatch = $false
        switch ($osFamily) {
            "2008R2" {
                if ($fn -match "(?i)(2008\s*R2|2008_R2|server2008r2)") { $osMatch = $true }
            }
            "2008" {
                if (($fn -match "(?i)(2008|server2008)") -and ($fn -notmatch "(?i)(2008\s*R2|2008_R2|server2008r2)")) { $osMatch = $true }
            }
            "2012R2" {
                if ($fn -match "(?i)(2012\s*R2|2012_R2|server2012r2)") { $osMatch = $true }
            }
            "2012" {
                if (($fn -match "(?i)(2012|server2012)") -and ($fn -notmatch "(?i)(2012\s*R2|2012_R2|server2012r2)")) { $osMatch = $true }
            }
            "2016" {
                if ($fn -match "(?i)2016") { $osMatch = $true }
            }
            "2019" {
                if ($fn -match "(?i)2019") { $osMatch = $true }
            }
            "2022" {
                if ($fn -match "(?i)2022") { $osMatch = $true }
            }
            "2025" {
                if ($fn -match "(?i)2025") { $osMatch = $true }
            }
            "Win7" {
                if ($fn -match "(?i)(Windows_7|win7)") { $osMatch = $true }
            }
            "Win8.1" {
                if ($fn -match "(?i)(Windows_8\.1|8\.1)") { $osMatch = $true }
            }
            "Win8" {
                if (($fn -match "(?i)(Windows_8\b|Windows_8_)") -and ($fn -notmatch "(?i)8\.1")) { $osMatch = $true }
            }
            "Win11" {
                if ($fn -match "(?i)(Windows_11|win11)") { $osMatch = $true }
            }
            "Win10" {
                if (($fn -match "(?i)(Windows_10|win10)") -and ($fn -notmatch "(?i)(Windows_11|win11)")) { $osMatch = $true }
            }
        }

        if (-not $osMatch) {
            continue
        }

        $score = 1000

        # Location bonus: Root lists/ (core legacy) gets priority
        if ($rel -match "^lists[\\\/][^\\\/]+\.csv$") {
            $score += 400
        }

        # Role scoring
        if ($isDC) {
            if ($fn -match "(?i)(_DC|_DC_|_DC\.csv|DC_Level|DC_CAT)") {
                $score += 500
            } else {
                $score -= 400
            }
        } elseif ($isServer) {
            if ($fn -match "(?i)(_MS|_MS_|_MS\.csv|MS_Level|MS_CAT|machine)") {
                $score += 500
            }
            if ($fn -match "(?i)(_DC|_DC_|_DC\.csv|DC_Level|DC_CAT)") {
                $score -= 600
            }
            if ($domainRole -eq 3 -and $fn -match "(?i)Stand-alone") {
                $score -= 50
            } elseif ($domainRole -eq 2 -and $fn -match "(?i)Stand-alone") {
                $score += 50
            }
        } else {
            # Workstation
            if ($fn -match "(?i)(Server|_DC|_MS)") {
                $score -= 600
            }
            if ($domainRole -eq 1) {
                # Domain joined workstation
                if ($fn -match "(?i)Enterprise") {
                    $score += 400
                } elseif ($fn -match "(?i)Stand-alone") {
                    $score += 250
                }
            } else {
                # Standalone workstation
                if ($fn -match "(?i)Stand-alone") {
                    $score += 400
                } elseif ($fn -match "(?i)Enterprise") {
                    $score += 250
                }
            }
        }

        # Benchmark profile scoring
        if ($fn -match "(?i)^finding_list_cis_") {
            $score += 300
        } elseif ($fn -match "(?i)^CIS_") {
            $score += 200
        } elseif ($fn -match "(?i)^MSCT_") {
            $score += 150
        } elseif ($fn -match "(?i)^DISA_") {
            $score += 100
        }

        # Level 1 preference
        if ($fn -match "(?i)(Level_1|Level1|_L1\b|_L1_)") {
            $score += 150
        } elseif ($fn -match "(?i)(Level_2|Level2|_L2\b|_L2_)") {
            $score += 30
        }

        # Penalize modifiers like Bitlocker, NextGen unless base
        if ($fn -match "(?i)(_BL\b|_BL_|_NG\b|_NG_|Bitlocker)") {
            $score -= 100
        }

        # Penalize cloud VM specific benchmarks
        if ($fn -match "(?i)Azure") {
            $score -= 100
        }

        if ($score -gt $bestScore) {
            $bestScore = $score
            $bestItem = $item
        }
    }

    if ($bestScore -gt 0) {
        return $bestItem
    }
    return $null
}
