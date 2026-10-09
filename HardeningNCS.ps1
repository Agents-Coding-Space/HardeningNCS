# ==============================================================================
# File: HardeningNCS.ps1
# Description: HardeningNCS Interactive TUI Controller & Automation Entry Point.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$NonInteractive,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Audit", "WhatIf", "Remediate", "Rollback", "ViewReport", "Report")]
    [string]$Action = "",

    [Parameter(Mandatory = $false)]
    [string]$ChecklistPath = "",

    [Parameter(Mandatory = $false)]
    [string]$ManifestPath = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$ConfirmRemediation,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# ------------------------------------------------------------------------------
# 1. Environment & Helper Initialization
# ------------------------------------------------------------------------------

# Resolve root script directory (PowerShell 2.0 compatible)
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}
$ScriptDir = [System.IO.Path]::GetFullPath($ScriptDir)

# Resolve default output directory
if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path $ScriptDir "outputs"
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
if (-not (Test-Path -Path $OutputDir)) {
    [void](New-Item -ItemType Directory -Path $OutputDir -Force)
}

# Dot-source common helper modules
$commonDir = Join-Path (Join-Path $ScriptDir "src") "common"
$wmiHelper = Join-Path $commonDir "Invoke-WmiCompat.ps1"
$detectHelper = Join-Path $commonDir "Detect-Environment.ps1"
$tuiHelper = Join-Path $commonDir "Tui-Helpers.ps1"

if (Test-Path -Path $wmiHelper) {
    . $wmiHelper
} else {
    Write-Error ("WMI helper not found: " + $wmiHelper)
}

if (Test-Path -Path $detectHelper) {
    . $detectHelper
} else {
    Write-Error ("Detect environment helper not found: " + $detectHelper)
}

if (Test-Path -Path $tuiHelper) {
    . $tuiHelper
} else {
    Write-Error ("TUI helpers not found: " + $tuiHelper)
}

# Auto-detect system information and checklist catalog
$sysInfo = Get-HKSystemInfo
$allChecklists = Get-HKChecklistCatalog -BaseDir $ScriptDir
$suggested = Get-SuggestedChecklist -Checklists $allChecklists -SystemInfo $sysInfo

# ------------------------------------------------------------------------------
# 2. TUI Display & Utility Functions
# ------------------------------------------------------------------------------

function Clear-HKScreen {
    try {
        Clear-Host
    } catch {
        # Fallback when running with redirected console
    }
}

function Wait-HKKeyPress {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Message = "Bam Enter de tiep tuc..."
    )
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    try {
        if ([System.Console]::IsInputRedirected) {
            [void][System.Console]::ReadLine()
        } else {
            [void][System.Console]::ReadKey($true)
        }
    } catch {
        try {
            [void][System.Console]::ReadLine()
        } catch {
            # Stdin closed or unavailable
        }
    }
}

function Show-HKBanner {
    param(
        [Parameter(Mandatory = $false)]
        [int]$TerminalWidth = 0,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    if ($TerminalWidth -le 0) {
        $TerminalWidth = Get-HKTerminalWidth
    }

    $bannerLen = [Math]::Max(20, [Math]::Min($TerminalWidth, 80))
    if ($bannerLen -ge $TerminalWidth -and $TerminalWidth -gt 20) {
        $bannerLen = $TerminalWidth - 1
    }

    $rendered = New-Object System.Collections.ArrayList

    if ($TerminalWidth -lt 50) {
        $rawTitle = " HardeningNCS | PS 2.0+ Edition"
        $safeTitle = if ($TerminalWidth -gt 32) {
            $rawTitle
        } elseif (Get-Command Format-HKTruncate -ErrorAction SilentlyContinue) {
            Format-HKTruncate -Text $rawTitle -MaxWidth ($TerminalWidth - 1) -Ellipsis ""
        } elseif ($rawTitle.Length -gt ($TerminalWidth - 1)) {
            $rawTitle.Substring(0, [Math]::Max(0, $TerminalWidth - 1))
        } else {
            $rawTitle
        }
        $sep = "=" * $bannerLen

        [void]$rendered.Add("")
        [void]$rendered.Add($safeTitle)
        [void]$rendered.Add($sep)

        Write-Host ""
        Write-Host $safeTitle -ForegroundColor Cyan
        Write-Host $sep -ForegroundColor DarkCyan

        if ($PassThru) {
            return $rendered.ToArray()
        }
        return
    }

    $fullBanner = @"

   .XXXX      +XXX    .+xXXXXXXX;    ;+xXXXXXXXX.
   .XXXXX.    +XXX   +XXXXXXXXXX+  .XXXXXXXXXXXX.
   .XXXXXX.   +XXX   XXXX          ;XXX:
   .XXXXXXX:  +XXX   XXX+          ;XXX:
   .XXX+:XXX: +XXX   XXX+          .XXXXXXXXXX+
   .XXX+ :XXX;+XXX   XXX+            ;+xXXXXXXXX
   .XXX+  .XXX+xXX   XXX+                   +XXX.
   .XXX+    XXX++X   XXXX:                 .xXXX
   .XXX+     XXXx+   :XXXXXXXXXX;  +XXXXXXXXXXX+
    +++:      +++;     :;+++++++:  ;++++++++;:  

             HardeningNCS | PowerShell 2.0+ Edition
"@
    $sep = "=" * $bannerLen
    $lines = $fullBanner -split "`r?`n"
    foreach ($line in $lines) {
        [void]$rendered.Add($line)
    }
    [void]$rendered.Add($sep)

    Write-Host $fullBanner -ForegroundColor Cyan
    Write-Host $sep -ForegroundColor DarkCyan

    if ($PassThru) {
        return $rendered.ToArray()
    }
}

function Show-HKSystemSummaryCard {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SystemInfo,

        [Parameter(Mandatory = $false)]
        [int]$TerminalWidth = 80,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    $cardWidth = [Math]::Max(40, [Math]::Min($TerminalWidth, 118))
    if ($cardWidth -eq $TerminalWidth -and $TerminalWidth -gt 40) {
        $cardWidth = $TerminalWidth - 1
    }

    $border = "+" + ("-" * ($cardWidth - 2)) + "+"
    $innerLen = $cardWidth - 4

    $cap = if ($null -ne $SystemInfo.Caption) { $SystemInfo.Caption } else { "Windows" }
    $arch = if ($null -ne $SystemInfo.OSArchitecture) { $SystemInfo.OSArchitecture } else { "Unknown" }
    $role = if ($null -ne $SystemInfo.DomainRoleName) { $SystemInfo.DomainRoleName } else { "Unknown" }
    $psv = if ($null -ne $SystemInfo.PSVersion) { $SystemInfo.PSVersion } else { "2.0" }
    $ped = if ($null -ne $SystemInfo.PSEdition) { $SystemInfo.PSEdition } else { "Desktop" }
    $cmp = if ($null -ne $SystemInfo.ComputerName) { $SystemInfo.ComputerName } else { "localhost" }

    $osLineRaw = "OS: " + $cap + " (" + $arch + ") | Role: " + $role
    $psLineRaw = "PowerShell: " + $psv + " (" + $ped + ") | Computer: " + $cmp

    $osLineTrunc = Format-HKTruncate -Text $osLineRaw -MaxWidth $innerLen -Ellipsis ""
    $psLineTrunc = Format-HKTruncate -Text $psLineRaw -MaxWidth $innerLen -Ellipsis ""

    $line1 = "| " + $osLineTrunc.PadRight($innerLen) + " |"
    $line2 = "| " + $psLineTrunc.PadRight($innerLen) + " |"

    Write-Host $border -ForegroundColor DarkGray
    Write-Host $line1 -ForegroundColor White
    Write-Host $line2 -ForegroundColor White
    Write-Host $border -ForegroundColor DarkGray

    if ($PassThru) {
        return @($border, $line1, $line2, $border)
    }
}

function Get-HKLatestAuditReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportDir
    )

    if (-not (Test-Path -Path $ReportDir)) {
        return $null
    }

    $candidates = Get-ChildItem -Path $ReportDir -Filter "audit_report_*.csv" | Sort-Object LastWriteTime -Descending
    if ($null -ne $candidates) {
        $cArr = @($candidates)
        if ($cArr.Length -gt 0) {
            return $cArr[0].FullName
        }
    } elseif ($null -ne $candidates -and -not [string]::IsNullOrEmpty($candidates.FullName)) {
        return $candidates.FullName
    }
    return $null
}

function Get-HKLatestBackupManifests {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseOutputDir
    )

    $manifestList = New-Object System.Collections.ArrayList
    if (-not (Test-Path -Path $BaseOutputDir)) {
        return $manifestList.ToArray()
    }

    $files = Get-ChildItem -Path $BaseOutputDir -Filter "backup_manifest.txt" -Recurse | Sort-Object LastWriteTime -Descending
    if ($null -ne $files) {
        foreach ($f in $files) {
            [void]$manifestList.Add($f)
        }
    }
    return $manifestList.ToArray()
}

function Show-HKReportSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $false)]
        [int]$TerminalWidth = 0
    )

    if (-not (Test-Path -Path $ReportPath)) {
        Write-Host ("File bao cao khong ton tai: " + $ReportPath) -ForegroundColor Red
        return
    }

    if ($TerminalWidth -le 0) {
        $TerminalWidth = Get-HKTerminalWidth
    }

    $hdrWidth = [Math]::Max(40, [Math]::Min($TerminalWidth, 56))
    if ($hdrWidth -eq $TerminalWidth -and $TerminalWidth -gt 40) {
        $hdrWidth = $TerminalWidth - 1
    }

    $rows = Import-Csv -Path $ReportPath
    $total = 0
    $passed = 0
    $failed = 0
    $skipped = 0
    $failedItems = New-Object System.Collections.ArrayList

    if ($null -ne $rows) {
        foreach ($r in $rows) {
            $total++
            $st = ""
            if ($null -ne $r.Status) {
                $st = $r.Status.Trim()
            }
            if ($st -ieq "Passed") {
                $passed++
            } elseif ($st -ieq "Failed") {
                $failed++
                [void]$failedItems.Add($r)
            } elseif ($st -ieq "Skipped") {
                $skipped++
            }
        }
    }

    $repItem = Get-Item -Path $ReportPath
    $timeStr = $repItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

    $headerText = " TOM TAT BAO CAO AUDIT "
    $dashCount = [Math]::Max(0, [int](($hdrWidth - $headerText.Length) / 2))
    $topLine = ("=" * $dashCount) + $headerText + ("=" * [Math]::Max(0, $hdrWidth - $dashCount - $headerText.Length))
    $botLine = "=" * $hdrWidth

    Write-Host ""
    Write-Host $topLine -ForegroundColor Cyan
    Write-Host ("File bao cao   : " + (Format-HKTruncate $ReportPath ($hdrWidth - 17) "...")) -ForegroundColor White
    Write-Host ("Thoi gian tao  : " + $timeStr) -ForegroundColor White
    Write-Host ("Tong so muc    : " + $total) -ForegroundColor White
    Write-Host ("Passed         : " + $passed) -ForegroundColor Green
    Write-Host ("Failed         : " + $failed) -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
    Write-Host ("Skipped        : " + $skipped) -ForegroundColor $(if ($skipped -gt 0) { "Yellow" } else { "Green" })
    Write-Host $botLine -ForegroundColor Cyan

    if (@($failedItems).Length -gt 0) {
        Write-Host ""
        Write-Host "Danh sach cac muc FAILED (Toi da 15 muc dau tien):" -ForegroundColor Yellow
        $showMax = [Math]::Min(15, @($failedItems).Length)
        for ($fi = 0; $fi -lt $showMax; $fi++) {
            $item = $failedItems[$fi]
            $idStr = if ($null -ne $item.ID) { $item.ID } else { "N/A" }
            $nameStr = if ($null -ne $item.Name) { $item.Name } else { "" }
            $recStr = if ($null -ne $item.RecommendedValue) { $item.RecommendedValue } else { "" }
            $curStr = if ($null -ne $item.CurrentValue) { $item.CurrentValue } else { "" }
            Write-Host ("  [" + $idStr + "] " + (Format-HKTruncate $nameStr ($hdrWidth - 10) "...")) -ForegroundColor White
            Write-Host ("       Khuyen nghi: " + $recStr + " | Hien tai: " + $curStr) -ForegroundColor DarkGray
        }
        if (@($failedItems).Length -gt $showMax) {
            Write-Host ("  ... va " + (@($failedItems).Length - $showMax) + " muc failed khac (xem chi tiet trong file CSV).") -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Khong co muc nao bi Failed. He thong dat chuan!" -ForegroundColor Green
    }
}

# ------------------------------------------------------------------------------
# 3. Non-Interactive / Automation Batch Mode
# ------------------------------------------------------------------------------

$isBatchMode = $NonInteractive.IsPresent -or (-not [string]::IsNullOrEmpty($Action))

if ($isBatchMode) {
    if ([string]::IsNullOrEmpty($Action)) {
        $Action = "Audit"
    }

    # Resolve target checklist for batch execution
    $resolvedChecklist = $ChecklistPath
    if ([string]::IsNullOrEmpty($resolvedChecklist)) {
        if ($null -ne $suggested -and -not [string]::IsNullOrEmpty($suggested.FullPath)) {
            $resolvedChecklist = $suggested.FullPath
        } else {
            $resolvedChecklist = Join-Path $ScriptDir "lists\finding_list_cis_win7_sp1_machine.csv"
        }
    }
    if (-not (Test-Path -Path $resolvedChecklist)) {
        Write-Error ("Checklist path not found: " + $resolvedChecklist)
        exit 1
    }

    Write-Host ("HardeningNCS Batch Mode: Action=" + $Action) -ForegroundColor Cyan
    Write-Host ("Checklist: " + $resolvedChecklist) -ForegroundColor Cyan

    switch ($Action) {
        "Audit" {
            $auditScript = Join-Path (Join-Path $ScriptDir "src") "Audit-LegacyWin.ps1"
            & $auditScript -FindingList $resolvedChecklist -OutputDir $OutputDir
            exit $LASTEXITCODE
        }

        "WhatIf" {
            $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Host "Chua co bao cao audit trong outputs. Dang tu dong chay Audit truoc de tao bao cao..." -ForegroundColor Yellow
                $auditScript = Join-Path (Join-Path $ScriptDir "src") "Audit-LegacyWin.ps1"
                & $auditScript -FindingList $resolvedChecklist -OutputDir $OutputDir
                $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            }

            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Error "Khong the tao hoac tim thay audit report cho simulation."
                exit 1
            }

            $remScript = Join-Path (Join-Path $ScriptDir "src") "Remediate-LegacyWin.ps1"
            & $remScript -FindingList $resolvedChecklist -AuditReport $latestReport -BackupDir $OutputDir -WhatIf
            exit $LASTEXITCODE
        }

        "Remediate" {
            if (-not $ConfirmRemediation.IsPresent -and -not $Force.IsPresent) {
                Write-Error "Non-interactive remediation requires explicit -ConfirmRemediation switch to prevent accidental changes."
                $global:LASTEXITCODE = 1
                exit 1
            }

            $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Error "No audit report found in outputs. Run Action Audit first before Remediate."
                exit 1
            }

            $remScript = Join-Path (Join-Path $ScriptDir "src") "Remediate-LegacyWin.ps1"
            & $remScript -FindingList $resolvedChecklist -AuditReport $latestReport -BackupDir $OutputDir
            exit $LASTEXITCODE
        }

        "Rollback" {
            $resolvedManifest = $ManifestPath
            if ([string]::IsNullOrEmpty($resolvedManifest)) {
                $manifests = @(Get-HKLatestBackupManifests -BaseOutputDir $OutputDir)
                if ($manifests.Length -gt 0) {
                    $resolvedManifest = $manifests[0].FullName
                }
            }

            if ([string]::IsNullOrEmpty($resolvedManifest) -or -not (Test-Path -Path $resolvedManifest)) {
                Write-Error "Manifest path not specified and no backup_manifest.txt found in outputs."
                exit 1
            }

            $rbScript = Join-Path (Join-Path $ScriptDir "src") "Rollback-LegacyWin.ps1"
            & $rbScript -ManifestFile $resolvedManifest
            exit $LASTEXITCODE
        }

        "ViewReport" {
            $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Error "No audit report found in outputs directory."
                exit 1
            }

            Show-HKReportSummary -ReportPath $latestReport
            exit 0
        }

        "Report" {
            $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Error "No audit report found in outputs directory."
                exit 1
            }

            Show-HKReportSummary -ReportPath $latestReport
            exit 0
        }
    }

    exit 0
}

# ------------------------------------------------------------------------------
# 4. Interactive TUI Mode (Two Screens)
# ------------------------------------------------------------------------------

$selectedChecklist = $null
$currentPage = 0
$pageSize = 10
$filterKeyword = ""

while ($true) {
    # ==========================================================================
    # MAN HINH 1: CHON CHECKLIST
    # ==========================================================================
    while ($null -eq $selectedChecklist) {
        $tw = Get-HKTerminalWidth
        Clear-HKScreen
        Show-HKBanner -TerminalWidth $tw

        Show-HKSystemSummaryCard -SystemInfo $sysInfo -TerminalWidth $tw

        Write-Host ""
        if ($null -ne $suggested) {
            Write-Host ("[GOI Y] Khuyen nghi cho he thong: " + $suggested.FileName) -ForegroundColor Green
            Write-Host "       (Nhap 'G', 'S' hoac bam ENTER de chon ngay checklist nay)" -ForegroundColor DarkGreen
        } else {
            Write-Host "[GOI Y] Khong xac dinh duoc checklist phu hop tu dong." -ForegroundColor Yellow
        }

        # Apply keyword filter
        $filteredChecklists = Filter-HKChecklists -Checklists $allChecklists -Keyword $filterKeyword
        $totalItems = @($filteredChecklists).Length
        $totalPages = [int][Math]::Ceiling($totalItems / [double]$pageSize)
        if ($totalPages -lt 1) { $totalPages = 1 }

        if ($currentPage -ge $totalPages) {
            $currentPage = $totalPages - 1
        }
        if ($currentPage -lt 0) {
            $currentPage = 0
        }

        if (-not [string]::IsNullOrEmpty($filterKeyword)) {
            Write-Host ""
            Write-Host ("[BO LOC DANG DUNG]: '" + $filterKeyword + "' (" + $totalItems + " ket qua) - Nhap 'C' de xoa bo loc") -ForegroundColor Magenta
        }

        Write-Host ""
        Render-HKPage -Items $filteredChecklists -PageIndex $currentPage -PageSize $pageSize -TerminalWidth $tw -SuggestedItem $suggested

        Write-Host ""
        Write-Host "Phim dieu khien:" -ForegroundColor Cyan
        Write-Host "  [1-10] : Chon muc tren trang | [G/Enter] : Chon goi y | [Q] : Thoat" -ForegroundColor White
        Write-Host "  [N]    : Trang sau            | [P]       : Trang truoc | [C] : Xoa bo loc" -ForegroundColor White
        Write-Host "  [/kw]  : Tim kiem tu khoa     | (go truc tiep tu khoa de loc)" -ForegroundColor White

        $promptStr = if ($null -ne $suggested) { "Nhap lua chon (Mac dinh: [G] Chon goi y): " } else { "Nhap lua chon: " }
        $userInput = Read-Host $promptStr
        $userInput = if ($null -eq $userInput) { "" } else { $userInput.Trim() }

        # 1. Default ENTER or 'G' or 'S' selects suggested checklist
        if ($userInput -eq "" -or $userInput -ieq "G" -or $userInput -ieq "S") {
            if ($null -ne $suggested) {
                $selectedChecklist = $suggested
                break
            } else {
                Write-Host "Khong co checklist goi y phu hop." -ForegroundColor Yellow
                Wait-HKKeyPress
                continue
            }
        }

        # 2. Quit
        if ($userInput -ieq "Q") {
            Write-Host "Tam biet!" -ForegroundColor Cyan
            exit 0
        }

        # 3. Next page
        if ($userInput -ieq "N") {
            if ($currentPage -lt ($totalPages - 1)) {
                $currentPage++
            }
            continue
        }

        # 4. Previous page
        if ($userInput -ieq "P") {
            if ($currentPage -gt 0) {
                $currentPage--
            }
            continue
        }

        # 5. Clear filter
        if ($userInput -ieq "C") {
            $filterKeyword = ""
            $currentPage = 0
            continue
        }

        # 6. Slash search command
        if ($userInput.StartsWith("/")) {
            $kw = $userInput.Substring(1).Trim()
            if ([string]::IsNullOrEmpty($kw)) {
                $kw = Read-Host "Nhap tu khoa tim kiem"
                $kw = if ($null -eq $kw) { "" } else { $kw.Trim() }
            }
            $filterKeyword = $kw
            $currentPage = 0
            continue
        }

        # 7. Explicit keyword search prefix (e.g. "find server" or "s 2008")
        if ($userInput -imatch "^(find|search)\s+(.+)$") {
            $filterKeyword = $matches[2].Trim()
            $currentPage = 0
            continue
        }

        # 8. Numeric selection (item 1-10 on current page OR global STT)
        $numVal = 0
        if ([int]::TryParse($userInput, [ref]$numVal)) {
            $chosenItem = $null

            # Local page item 1..pageSize
            if ($numVal -ge 1 -and $numVal -le $pageSize) {
                $localIdx = ($currentPage * $pageSize) + ($numVal - 1)
                if ($localIdx -ge 0 -and $localIdx -lt $totalItems) {
                    $chosenItem = $filteredChecklists[$localIdx]
                }
            }
            # Global index fallback (e.g. user typed global STT 15)
            elseif ($numVal -gt $pageSize -and $numVal -le $totalItems) {
                $chosenItem = $filteredChecklists[$numVal - 1]
            }

            if ($null -ne $chosenItem) {
                $selectedChecklist = $chosenItem
                break
            } else {
                Write-Host ("Chi so khong hop le: " + $numVal) -ForegroundColor Red
                Wait-HKKeyPress
                continue
            }
        }

        # 9. Free-form text treated directly as search filter
        $filterKeyword = $userInput
        $currentPage = 0
    }

    # ==========================================================================
    # MAN HINH 2: CHE DO THUC THI (CHO CHECKLIST DA CHON)
    # ==========================================================================
    while ($null -ne $selectedChecklist) {
        $tw = Get-HKTerminalWidth
        Clear-HKScreen
        Show-HKBanner -TerminalWidth $tw

        $selPath = $selectedChecklist.FullPath
        $selName = $selectedChecklist.FileName
        $selRel  = $selectedChecklist.RelativePath
        $selSize = $selectedChecklist.Size

        $sepLen = [Math]::Max(40, [Math]::Min($tw, 80))
        if ($sepLen -eq $tw -and $tw -gt 40) {
            $sepLen = $tw - 1
        }
        $sepLine = "-" * $sepLen

        Write-Host "CHE DO THUC THI: HARDENING CHECKLIST" -ForegroundColor Cyan
        Write-Host $sepLine -ForegroundColor DarkCyan
        Write-Host ("  Ten Checklist : " + (Format-HKTruncate $selName ($sepLen - 18) "...")) -ForegroundColor Green
        Write-Host ("  Thu muc       : " + (Format-HKTruncate $selectedChecklist.Directory ($sepLen - 18) "...")) -ForegroundColor White
        Write-Host ("  Duong dan     : " + (Format-HKTruncate $selRel ($sepLen - 18) "...")) -ForegroundColor White
        Write-Host ("  Dung luong    : " + $selSize + " bytes") -ForegroundColor White
        Write-Host $sepLine -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  [1] Audit (Kiem toan & Xuat bao cao CSV)" -ForegroundColor White
        Write-Host "  [2] Simulation / What-If (Mo phong khac phuc - 100% an toan)" -ForegroundColor White
        Write-Host "  [3] Remediation (Khac phuc chon loc cac muc Failed)" -ForegroundColor White
        Write-Host "  [4] Rollback (Hoan tac khoi phuc trang thai cu)" -ForegroundColor White
        Write-Host "  [5] View Latest Report (Xem tom tat bao cao vua quet)" -ForegroundColor White
        Write-Host "  [0] Quay lai chon checklist khac" -ForegroundColor Yellow
        Write-Host "  [Q] Thoat" -ForegroundColor Yellow
        Write-Host ""

        $actChoice = Read-Host "Nhap lua chon [1-5, 0, Q]"
        $actChoice = if ($null -eq $actChoice) { "" } else { $actChoice.Trim() }

        # Option 0: Quay lai man hinh 1
        if ($actChoice -ieq "0") {
            $selectedChecklist = $null
            break
        }

        # Option Q: Thoat
        if ($actChoice -ieq "Q") {
            Write-Host "Tam biet!" -ForegroundColor Cyan
            exit 0
        }

        # Option 1: Audit
        if ($actChoice -ieq "1") {
            Write-Host ""
            Write-Host "Khoi chay Audit kiem toan he thong..." -ForegroundColor Cyan
            $auditScript = Join-Path (Join-Path $ScriptDir "src") "Audit-LegacyWin.ps1"
            & $auditScript -FindingList $selPath -OutputDir $OutputDir
            Wait-HKKeyPress "Hoan tat Audit. Bam Enter de tiep tuc..."
            continue
        }

        # Option 2: Simulation / What-If
        if ($actChoice -ieq "2") {
            Write-Host ""
            $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Host "Chua co bao cao audit trong thu muc outputs." -ForegroundColor Yellow
                $runNow = Read-Host "Ban co muon chay Audit ngay de tao bao cao truoc? (Y/N)"
                if ($runNow -ieq "Y") {
                    $auditScript = Join-Path (Join-Path $ScriptDir "src") "Audit-LegacyWin.ps1"
                    & $auditScript -FindingList $selPath -OutputDir $OutputDir
                    $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
                } else {
                    Wait-HKKeyPress "Vui long chay Audit truoc khi mo phong. Bam Enter de tiep tuc..."
                    continue
                }
            }

            if (-not [string]::IsNullOrEmpty($latestReport) -and (Test-Path -Path $latestReport)) {
                Write-Host "Khoi chay mo phong Remediation (What-If)..." -ForegroundColor Cyan
                $remScript = Join-Path (Join-Path $ScriptDir "src") "Remediate-LegacyWin.ps1"
                & $remScript -FindingList $selPath -AuditReport $latestReport -BackupDir $OutputDir -WhatIf
            }
            Wait-HKKeyPress "Hoan tat mo phong. Bam Enter de tiep tuc..."
            continue
        }

        # Option 3: Remediation
        if ($actChoice -ieq "3") {
            Write-Host ""
            Write-Host "========================== CANH BAO QUAN TRONG ==========================" -ForegroundColor Yellow
            Write-Host "Che do Remediation se truc tiep ap dung cac thiet lap hardening vao he thong." -ForegroundColor Yellow
            Write-Host "He thong se tu dong thuc hien sao luu 4 lop truoc khi ap dung thay doi." -ForegroundColor Yellow
            Write-Host "==========================================================================" -ForegroundColor Yellow
            $confirmRem = Read-Host "Ban co chac chan muon thuc hien Remediation? (Y/N)"
            if ($confirmRem -ieq "Y") {
                $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
                if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                    Write-Host "Chua co bao cao audit. Vui long chay Audit (1) truoc de xac dinh cac muc Failed." -ForegroundColor Red
                    Wait-HKKeyPress
                    continue
                }

                Write-Host "Dang thuc hien Remediation voi bao ve sao luu 4 lop..." -ForegroundColor Cyan
                $remScript = Join-Path (Join-Path $ScriptDir "src") "Remediate-LegacyWin.ps1"
                & $remScript -FindingList $selPath -AuditReport $latestReport -BackupDir $OutputDir
            } else {
                Write-Host "Da huy thao tac Remediation." -ForegroundColor Gray
            }
            Wait-HKKeyPress "Bam Enter de tiep tuc..."
            continue
        }

        # Option 4: Rollback
        if ($actChoice -ieq "4") {
            Write-Host ""
            $manifests = @(Get-HKLatestBackupManifests -BaseOutputDir $OutputDir)
            $chosenManifest = ""

            if ($manifests.Length -eq 0) {
                Write-Host "Khong tim thay phien backup nao trong thu muc outputs." -ForegroundColor Yellow
                $wantCustom = Read-Host "Ban co muon nhap duong dan file backup_manifest.txt thu cong khong? (Y/N)"
                if ($wantCustom -ieq "Y") {
                    $customPath = Read-Host "Nhap duong dan day du toi backup_manifest.txt"
                    if (-not [string]::IsNullOrEmpty($customPath) -and (Test-Path -Path $customPath)) {
                        $chosenManifest = $customPath
                    } else {
                        Write-Host "File khong ton tai!" -ForegroundColor Red
                        Wait-HKKeyPress
                        continue
                    }
                } else {
                    continue
                }
            } else {
                Write-Host "=== DANH SACH PHIEN SAO LUU (BACKUP SESSIONS) ===" -ForegroundColor Cyan
                $maxShow = [Math]::Min(10, $manifests.Length)
                for ($mi = 0; $mi -lt $maxShow; $mi++) {
                    $mItem = $manifests[$mi]
                    $folderName = Split-Path (Split-Path $mItem.FullName -Parent) -Leaf
                    $timeStr = $mItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Write-Host ("  [" + ($mi + 1) + "] " + $folderName + " (" + $timeStr + ")") -ForegroundColor White
                }
                Write-Host "  [M] Nhap duong dan file manifest khac" -ForegroundColor White
                Write-Host "  [0] Quay lai" -ForegroundColor Yellow

                $mChoice = Read-Host ("Chon phien sao luu can khoi phuc [1-" + $maxShow + ", M, 0]")
                $mChoice = if ($null -eq $mChoice) { "" } else { $mChoice.Trim() }

                if ($mChoice -ieq "0" -or $mChoice -eq "") {
                    continue
                } elseif ($mChoice -ieq "M") {
                    $customPath = Read-Host "Nhap duong dan day du toi backup_manifest.txt"
                    if (-not [string]::IsNullOrEmpty($customPath) -and (Test-Path -Path $customPath)) {
                        $chosenManifest = $customPath
                    } else {
                        Write-Host "File khong ton tai!" -ForegroundColor Red
                        Wait-HKKeyPress
                        continue
                    }
                } else {
                    $mNum = 0
                    if ([int]::TryParse($mChoice, [ref]$mNum) -and $mNum -ge 1 -and $mNum -le $maxShow) {
                        $chosenManifest = $manifests[$mNum - 1].FullName
                    } else {
                        Write-Host "Lua chon khong hop le!" -ForegroundColor Red
                        Wait-HKKeyPress
                        continue
                    }
                }
            }

            if (-not [string]::IsNullOrEmpty($chosenManifest)) {
                Write-Host ""
                Write-Host "========================== CANH BAO ROLLBACK ==========================" -ForegroundColor Yellow
                Write-Host ("Ban dang chuan bi khoi phuc he thong theo manifest:") -ForegroundColor Yellow
                Write-Host ("  " + $chosenManifest) -ForegroundColor White
                Write-Host "=======================================================================" -ForegroundColor Yellow
                $confirmRb = Read-Host "Xac nhan khoi phuc he thong ve trang thai cu? (Y/N)"
                if ($confirmRb -ieq "Y") {
                    $rbScript = Join-Path (Join-Path $ScriptDir "src") "Rollback-LegacyWin.ps1"
                    & $rbScript -ManifestFile $chosenManifest
                } else {
                    Write-Host "Da huy thao tac Rollback." -ForegroundColor Gray
                }
            }
            Wait-HKKeyPress "Bam Enter de tiep tuc..."
            continue
        }

        # Option 5: View Latest Report
        if ($actChoice -ieq "5") {
            $latestReport = Get-HKLatestAuditReport -ReportDir $OutputDir
            if ([string]::IsNullOrEmpty($latestReport) -or -not (Test-Path -Path $latestReport)) {
                Write-Host ""
                Write-Host "Khong tim thay file bao cao audit nao trong thu muc outputs." -ForegroundColor Yellow
            } else {
                Show-HKReportSummary -ReportPath $latestReport
            }
            Wait-HKKeyPress "Bam Enter de tiep tuc..."
            continue
        }

        Write-Host ("Lua chon khong hop le: '" + $actChoice + "'") -ForegroundColor Red
        Wait-HKKeyPress
    }
}
