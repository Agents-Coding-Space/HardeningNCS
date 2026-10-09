# ==============================================================================
# File: test_detector_and_tui.ps1
# Description: Unit tests for Detect-Environment.ps1 and Tui-Helpers.ps1.
# Compatibility: PowerShell 2.0+
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = (Get-Location).Path
}

$rootDir = Split-Path $scriptDir -Parent
$commonDir = Join-Path $rootDir "src\common"

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

Write-Host "=== TEST SUITE: System Detector & TUI Helpers ===" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# Test Section 1: Get-HKSystemInfo
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Get-HKSystemInfo ---" -ForegroundColor Yellow

$sysInfo = Get-HKSystemInfo

Assert-HKTest "SysInfo is not null" ($null -ne $sysInfo)
Assert-HKTest "Caption is not empty" (-not [string]::IsNullOrEmpty($sysInfo.Caption))
Assert-HKTest "Version is not empty" (-not [string]::IsNullOrEmpty($sysInfo.Version))
Assert-HKTest "BuildNumber is not empty" (-not [string]::IsNullOrEmpty($sysInfo.BuildNumber))
Assert-HKTest "OSArchitecture is valid" ($sysInfo.OSArchitecture -eq "64-bit" -or $sysInfo.OSArchitecture -eq "32-bit")
Assert-HKTest "Bitness is 64 or 32" ($sysInfo.Bitness -eq 64 -or $sysInfo.Bitness -eq 32)
Assert-HKTest "DomainRole is within 0..5" ($sysInfo.DomainRole -ge 0 -and $sysInfo.DomainRole -le 5)
Assert-HKTest "DomainRoleName is populated" (-not [string]::IsNullOrEmpty($sysInfo.DomainRoleName))
Assert-HKTest "IsDomainController is boolean" ($sysInfo.IsDomainController -is [bool])
Assert-HKTest "IsServer is boolean" ($sysInfo.IsServer -is [bool])
Assert-HKTest "ComputerName is not empty" (-not [string]::IsNullOrEmpty($sysInfo.ComputerName))
Assert-HKTest "PSVersion is not empty" (-not [string]::IsNullOrEmpty($sysInfo.PSVersion))
Assert-HKTest "PSEdition is Desktop or Core" ($sysInfo.PSEdition -eq "Desktop" -or $sysInfo.PSEdition -eq "Core")

Write-Host ("  Detected System: " + $sysInfo.Caption + " | Role: " + $sysInfo.DomainRoleName + " | PS: " + $sysInfo.PSVersion + " (" + $sysInfo.PSEdition + ")") -ForegroundColor Gray

# ------------------------------------------------------------------------------
# Test Section 2: Get-HKChecklistCatalog
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Get-HKChecklistCatalog ---" -ForegroundColor Yellow

$catalog = Get-HKChecklistCatalog -BaseDir $rootDir

Assert-HKTest "Catalog is not null" ($null -ne $catalog)
Assert-HKTest "Catalog contains > 300 checklists" (@($catalog).Length -ge 10)

$firstItem = $catalog[0]
Assert-HKTest "Item has RelativePath" (-not [string]::IsNullOrEmpty($firstItem.RelativePath))
Assert-HKTest "Item has FullPath" (-not [string]::IsNullOrEmpty($firstItem.FullPath))
Assert-HKTest "Item FullPath exists" (Test-Path $firstItem.FullPath)
Assert-HKTest "Item has FileName" (-not [string]::IsNullOrEmpty($firstItem.FileName))
Assert-HKTest "Item has Directory" (-not [string]::IsNullOrEmpty($firstItem.Directory))
Assert-HKTest "Item has positive Size" ($firstItem.Size -gt 0)

# Check invalid dir handling
$emptyCat = Get-HKChecklistCatalog -BaseDir (Join-Path $rootDir "non_existent_folder_xyz")
$emptyCatCount = if ($null -eq $emptyCat) { 0 } else { @($emptyCat).Length }
Assert-HKEqual "Empty catalog for invalid path" $emptyCatCount 0

# ------------------------------------------------------------------------------
# Test Section 3: Filter-HKChecklists
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Filter-HKChecklists ---" -ForegroundColor Yellow

# Null/empty keyword returns all
$allFiltered = Filter-HKChecklists -Checklists $catalog -Keyword ""
Assert-HKEqual "Empty keyword returns all items" $allFiltered.Count $catalog.Count

$nullFiltered = Filter-HKChecklists -Checklists $catalog -Keyword $null
Assert-HKEqual "Null keyword returns all items" $nullFiltered.Count $catalog.Count

# Keyword filter: server2008r2
$f2008r2 = Filter-HKChecklists -Checklists $catalog -Keyword "server2008r2"
Assert-HKTest "Filter server2008r2 finds legacy checklist" ($f2008r2.Count -ge 1)
$has2008r2Machine = $false
foreach ($c in $f2008r2) {
    if ($c.FileName -eq "finding_list_cis_server2008r2_machine.csv") {
        $has2008r2Machine = $true
    }
}
Assert-HKTest "Filter server2008r2 includes finding_list_cis_server2008r2_machine.csv" $has2008r2Machine

# Keyword filter: case-insensitive WIN7
$fWin7 = Filter-HKChecklists -Checklists $catalog -Keyword "WIN7"
Assert-HKTest "Filter case-insensitive WIN7 finds items" ($fWin7.Count -ge 1)

# Keyword filter: non-existent keyword
$fNone = Filter-HKChecklists -Checklists $catalog -Keyword "non_existent_keyword_super_califragilistic"
Assert-HKEqual "Filter non-existent keyword returns 0" (@($fNone).Length) 0

# Empty list input
$fEmptyInput = Filter-HKChecklists -Checklists @() -Keyword "test"
$fEmptyCount = if ($null -eq $fEmptyInput) { 0 } else { @($fEmptyInput).Length }
Assert-HKEqual "Filter on empty list returns 0" $fEmptyCount 0

# ------------------------------------------------------------------------------
# Test Section 4: Get-HKTerminalWidth
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Get-HKTerminalWidth ---" -ForegroundColor Yellow

$tw = Get-HKTerminalWidth
Assert-HKTest "Terminal width is >= 40" ($tw -ge 40)
Assert-HKTest "Terminal width is integer" ($tw -is [int])

# ------------------------------------------------------------------------------
# Test Section 5: Format-HKTruncate
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Format-HKTruncate ---" -ForegroundColor Yellow

Assert-HKEqual "Truncate shorter string unchanged" (Format-HKTruncate "Short" 10) "Short"
Assert-HKEqual "Truncate exact length unchanged" (Format-HKTruncate "12345" 5) "12345"

$t1 = Format-HKTruncate "1234567890" 8 "..."
Assert-HKEqual "Truncate longer string with ellipsis" $t1 "12345..."
Assert-HKTest "Truncate result length <= MaxWidth" ($t1.Length -le 8)

$t2 = Format-HKTruncate "ABCDEF" 2
Assert-HKEqual "Truncate MaxWidth smaller than ellipsis" $t2 "AB"
Assert-HKTest "Length <= MaxWidth (small width)" ($t2.Length -le 2)

Assert-HKEqual "Truncate MaxWidth = 0 returns empty" (Format-HKTruncate "ABC" 0) ""
Assert-HKEqual "Truncate negative MaxWidth returns empty" (Format-HKTruncate "ABC" -5) ""
Assert-HKEqual "Truncate null string returns empty" (Format-HKTruncate $null 10) ""

# ------------------------------------------------------------------------------
# Test Section 6: Render-HKPage
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Render-HKPage ---" -ForegroundColor Yellow

# Test render with width 80
$lines80 = Render-HKPage -Items $catalog -PageIndex 0 -PageSize 10 -TerminalWidth 80 -SuggestedItem $catalog[0] -PassThru
Assert-HKTest "Render 80 returned lines" ($lines80.Count -gt 5)

$exceeded80 = $false
foreach ($line in $lines80) {
    if ($line.Length -gt 80) {
        $exceeded80 = $true
        Write-Host ("Line exceeded 80 chars (" + $line.Length + "): " + $line) -ForegroundColor Red
    }
}
Assert-HKTest "Zero lines exceeded 80 characters" (-not $exceeded80)

# Test render with width 60
$lines60 = Render-HKPage -Items $catalog -PageIndex 1 -PageSize 5 -TerminalWidth 60 -PassThru
Assert-HKTest "Render 60 returned lines" ($lines60.Count -gt 5)

$exceeded60 = $false
foreach ($line in $lines60) {
    if ($line.Length -gt 60) {
        $exceeded60 = $true
        Write-Host ("Line exceeded 60 chars (" + $line.Length + "): " + $line) -ForegroundColor Red
    }
}
Assert-HKTest "Zero lines exceeded 60 characters" (-not $exceeded60)

# Test render with width 120
$lines120 = Render-HKPage -Items $catalog -PageIndex 0 -PageSize 10 -TerminalWidth 120 -PassThru
$exceeded120 = $false
foreach ($line in $lines120) {
    if ($line.Length -gt 120) {
        $exceeded120 = $true
    }
}
Assert-HKTest "Zero lines exceeded 120 characters" (-not $exceeded120)

# Test render with narrow width 40
$lines40 = Render-HKPage -Items $catalog -PageIndex 0 -PageSize 5 -TerminalWidth 40 -PassThru
Assert-HKTest "Render 40 returned lines" ($lines40.Count -gt 5)
$exceeded40 = $false
foreach ($line in $lines40) {
    if ($line.Length -gt 40) {
        $exceeded40 = $true
        Write-Host ("Line exceeded 40 chars (" + $line.Length + "): " + $line) -ForegroundColor Red
    }
}
Assert-HKTest "Zero lines exceeded 40 characters" (-not $exceeded40)

# Test render with narrow width 44
$lines44 = Render-HKPage -Items $catalog -PageIndex 0 -PageSize 5 -TerminalWidth 44 -PassThru
$exceeded44 = $false
foreach ($line in $lines44) {
    if ($line.Length -gt 44) {
        $exceeded44 = $true
    }
}
Assert-HKTest "Zero lines exceeded 44 characters" (-not $exceeded44)

# Test render empty items
$emptyLines = Render-HKPage -Items @() -PageIndex 0 -PageSize 10 -TerminalWidth 80 -PassThru
Assert-HKTest "Render empty items does not crash" ($emptyLines.Count -gt 0)

# Test page index clamping
$linesClamped = Render-HKPage -Items $catalog -PageIndex 99999 -PageSize 10 -TerminalWidth 80 -PassThru
Assert-HKTest "Render out-of-range PageIndex clamped safely" ($linesClamped.Count -gt 0)

# ------------------------------------------------------------------------------
# Test Section 7: Get-SuggestedChecklist Across Environments
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Get-SuggestedChecklist Across Environments ---" -ForegroundColor Yellow

function New-HKMockSysInfo {
    param(
        [string]$Caption,
        [string]$Version,
        [string]$BuildNumber,
        [int]$DomainRole
    )
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "Caption" -Value $Caption
    $obj | Add-Member -MemberType NoteProperty -Name "Version" -Value $Version
    $obj | Add-Member -MemberType NoteProperty -Name "BuildNumber" -Value $BuildNumber
    $obj | Add-Member -MemberType NoteProperty -Name "DomainRole" -Value $DomainRole
    $obj | Add-Member -MemberType NoteProperty -Name "IsDomainController" -Value ($DomainRole -eq 4 -or $DomainRole -eq 5)
    $obj | Add-Member -MemberType NoteProperty -Name "IsServer" -Value ($DomainRole -ge 2 -and $DomainRole -le 5)
    return $obj
}

# 1. Windows Server 2008 R2 Member Server (Role 3)
$mock2008R2_MS = New-HKMockSysInfo -Caption "Microsoft Windows Server 2008 R2 Enterprise" -Version "6.1.7601" -BuildNumber "7601" -DomainRole 3
$sug2008R2_MS = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2008R2_MS
Assert-HKTest "Suggest Server 2008 R2 MS is not null" ($null -ne $sug2008R2_MS)
Assert-HKTest "Suggest Server 2008 R2 MS is legacy list" ($sug2008R2_MS.FileName -eq "CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv" -or $sug2008R2_MS.FileName -eq "finding_list_cis_server2008r2_machine.csv")

# 2. Windows Server 2008 R2 Domain Controller (Role 5)
$mock2008R2_DC = New-HKMockSysInfo -Caption "Microsoft Windows Server 2008 R2 Standard" -Version "6.1.7601" -BuildNumber "7601" -DomainRole 5
$sug2008R2_DC = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2008R2_DC
Assert-HKTest "Suggest Server 2008 R2 DC is not null" ($null -ne $sug2008R2_DC)
Assert-HKEqual "Suggest Server 2008 R2 DC matches DC checklist" $sug2008R2_DC.FileName "CIS_MS_Windows_Server_2008_R2_DC_Level_1_v3.3.1.csv"

# 3. Windows Server 2012 R2 Member Server (Role 3)
$mock2012R2_MS = New-HKMockSysInfo -Caption "Microsoft Windows Server 2012 R2 Datacenter" -Version "6.3.9600" -BuildNumber "9600" -DomainRole 3
$sug2012R2_MS = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2012R2_MS
Assert-HKTest "Suggest Server 2012 R2 MS is not null" ($null -ne $sug2012R2_MS)
Assert-HKTest "Suggest Server 2012 R2 MS prefers finding_list or MS L1" ($sug2012R2_MS.FileName -eq "finding_list_cis_server2012r2_machine.csv" -or $sug2012R2_MS.FileName -eq "CIS_MS_SERVER_2012_R2_Level_1_v3.0.0.csv")

# 4. Windows Server 2012 R2 Domain Controller (Role 5)
$mock2012R2_DC = New-HKMockSysInfo -Caption "Microsoft Windows Server 2012 R2 Datacenter" -Version "6.3.9600" -BuildNumber "9600" -DomainRole 5
$sug2012R2_DC = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2012R2_DC
Assert-HKTest "Suggest Server 2012 R2 DC is not null" ($null -ne $sug2012R2_DC)
Assert-HKEqual "Suggest Server 2012 R2 DC matches DC checklist" $sug2012R2_DC.FileName "CIS_DC_SERVER_2012_R2_Level_1_v3.0.0.csv"

# 5. Windows 7 SP1 Workstation (Role 0)
$mockWin7 = New-HKMockSysInfo -Caption "Microsoft Windows 7 Professional" -Version "6.1.7601" -BuildNumber "7601" -DomainRole 0
$sugWin7 = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mockWin7
Assert-HKTest "Suggest Windows 7 is not null" ($null -ne $sugWin7)
Assert-HKEqual "Suggest Windows 7 matches legacy finding_list" $sugWin7.FileName "finding_list_cis_win7_sp1_machine.csv"

# 6. Windows 10 Standalone Workstation (Role 0)
$mockWin10_SA = New-HKMockSysInfo -Caption "Microsoft Windows 10 Pro" -Version "10.0.19045" -BuildNumber "19045" -DomainRole 0
$sugWin10_SA = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mockWin10_SA
Assert-HKTest "Suggest Windows 10 Standalone is not null" ($null -ne $sugWin10_SA)
Assert-HKEqual "Suggest Windows 10 Standalone checklist" $sugWin10_SA.FileName "CIS_Microsoft_Windows_10_Stand-alone_v5.0.0_L1.csv"

# 7. Windows 10 Enterprise Domain-Joined (Role 1)
$mockWin10_Ent = New-HKMockSysInfo -Caption "Microsoft Windows 10 Enterprise" -Version "10.0.19045" -BuildNumber "19045" -DomainRole 1
$sugWin10_Ent = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mockWin10_Ent
Assert-HKTest "Suggest Windows 10 Enterprise is not null" ($null -ne $sugWin10_Ent)
Assert-HKEqual "Suggest Windows 10 Enterprise checklist" $sugWin10_Ent.FileName "CIS_Microsoft_Windows_10_Enterprise_v5.0.0_L1.csv"

# 8. Windows 11 Standalone Workstation (Role 0)
$mockWin11_SA = New-HKMockSysInfo -Caption "Microsoft Windows 11 Pro" -Version "10.0.26200" -BuildNumber "26200" -DomainRole 0
$sugWin11_SA = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mockWin11_SA
Assert-HKTest "Suggest Windows 11 Standalone is not null" ($null -ne $sugWin11_SA)
Assert-HKEqual "Suggest Windows 11 Standalone checklist" $sugWin11_SA.FileName "CIS_Microsoft_Windows_11_Stand-alone_v5.0.0_L1.csv"

# 9. Windows 11 Enterprise Domain-Joined (Role 1)
$mockWin11_Ent = New-HKMockSysInfo -Caption "Microsoft Windows 11 Enterprise" -Version "10.0.22631" -BuildNumber "22631" -DomainRole 1
$sugWin11_Ent = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mockWin11_Ent
Assert-HKTest "Suggest Windows 11 Enterprise is not null" ($null -ne $sugWin11_Ent)
Assert-HKEqual "Suggest Windows 11 Enterprise checklist" $sugWin11_Ent.FileName "CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1.csv"

# 10. Windows Server 2016 Member Server (Role 3)
$mock2016_MS = New-HKMockSysInfo -Caption "Microsoft Windows Server 2016 Standard" -Version "10.0.14393" -BuildNumber "14393" -DomainRole 3
$sug2016_MS = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2016_MS
Assert-HKTest "Suggest Server 2016 MS is not null" ($null -ne $sug2016_MS)
Assert-HKEqual "Suggest Server 2016 MS checklist" $sug2016_MS.FileName "CIS_Microsoft_Windows_Server_2016_v4.0.0_L1_MS.csv"

# 11. Windows Server 2016 Domain Controller (Role 5)
$mock2016_DC = New-HKMockSysInfo -Caption "Microsoft Windows Server 2016 Datacenter" -Version "10.0.14393" -BuildNumber "14393" -DomainRole 5
$sug2016_DC = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2016_DC
Assert-HKTest "Suggest Server 2016 DC is not null" ($null -ne $sug2016_DC)
Assert-HKEqual "Suggest Server 2016 DC checklist" $sug2016_DC.FileName "CIS_Microsoft_Windows_Server_2016_v4.0.0_L1_DC.csv"

# 12. Windows Server 2019 Member Server (Role 3)
$mock2019_MS = New-HKMockSysInfo -Caption "Microsoft Windows Server 2019 Standard" -Version "10.0.17763" -BuildNumber "17763" -DomainRole 3
$sug2019_MS = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2019_MS
Assert-HKTest "Suggest Server 2019 MS is not null" ($null -ne $sug2019_MS)
Assert-HKEqual "Suggest Server 2019 MS checklist" $sug2019_MS.FileName "CIS_Microsoft_Windows_Server_2019_v5.0.0_L1_MS.csv"

# 13. Windows Server 2019 Domain Controller (Role 5)
$mock2019_DC = New-HKMockSysInfo -Caption "Microsoft Windows Server 2019 Datacenter" -Version "10.0.17763" -BuildNumber "17763" -DomainRole 5
$sug2019_DC = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2019_DC
Assert-HKTest "Suggest Server 2019 DC is not null" ($null -ne $sug2019_DC)
Assert-HKEqual "Suggest Server 2019 DC checklist" $sug2019_DC.FileName "CIS_Microsoft_Windows_Server_2019_v5.0.0_L1_DC.csv"

# 14. Windows Server 2022 Member Server (Role 3)
$mock2022_MS = New-HKMockSysInfo -Caption "Microsoft Windows Server 2022 Standard" -Version "10.0.20348" -BuildNumber "20348" -DomainRole 3
$sug2022_MS = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2022_MS
Assert-HKTest "Suggest Server 2022 MS is not null" ($null -ne $sug2022_MS)
Assert-HKEqual "Suggest Server 2022 MS checklist" $sug2022_MS.FileName "CIS_Microsoft_Windows_Server_2022_v5.1.0_L1_MS.csv"

# 15. Windows Server 2022 Domain Controller (Role 5)
$mock2022_DC = New-HKMockSysInfo -Caption "Microsoft Windows Server 2022 Datacenter" -Version "10.0.20348" -BuildNumber "20348" -DomainRole 5
$sug2022_DC = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mock2022_DC
Assert-HKTest "Suggest Server 2022 DC is not null" ($null -ne $sug2022_DC)
Assert-HKEqual "Suggest Server 2022 DC checklist" $sug2022_DC.FileName "CIS_Microsoft_Windows_Server_2022_v5.1.0_L1_DC.csv"

# 16. Current live machine suggestion
$sugLive = Get-SuggestedChecklist -Checklists $catalog
Assert-HKTest "Suggest for live environment is not null" ($null -ne $sugLive)
Write-Host ("  Live Suggestion: " + $sugLive.FileName + " (" + $sugLive.RelativePath + ")") -ForegroundColor Gray

# 17. Null / Unknown system info returns null
$mockUnknown = New-HKMockSysInfo -Caption "Solaris 10 SPARC" -Version "5.10" -BuildNumber "0" -DomainRole 0
$sugUnknown = Get-SuggestedChecklist -Checklists $catalog -SystemInfo $mockUnknown
Assert-HKTest "Unknown OS returns null" ($null -eq $sugUnknown)

# ------------------------------------------------------------------------------
# Final Test Summary
# ------------------------------------------------------------------------------
Write-Host "`n=== TEST SUMMARY ===" -ForegroundColor Cyan
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
