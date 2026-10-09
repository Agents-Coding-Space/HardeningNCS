# ==============================================================================
# File: Tui-Helpers.ps1
# Description: TUI helpers for checklist catalog discovery, filtering, pagination,
#              and anti-wrap console rendering.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

function Get-HKChecklistCatalog {
    <#
    .SYNOPSIS
        Scans and indexes all hardening checklists in the lists directory.
    .DESCRIPTION
        Recursively scans $BaseDir\lists for *.csv files, filtering out temporary,
        hidden, or non-checklist files.
        PowerShell 2.0 compatible.
    .PARAMETER BaseDir
        Root repository path. If omitted, resolved automatically relative to this script.
    .OUTPUTS
        Array of PSObjects with properties: RelativePath, FullPath, FileName, Directory, Size.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BaseDir = ""
    )

    if ([string]::IsNullOrEmpty($BaseDir)) {
        $scriptDir = ""
        if ($null -ne $MyInvocation.MyCommand -and -not [string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)) {
            $scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
        }
        if ([string]::IsNullOrEmpty($scriptDir)) {
            $BaseDir = (Get-Location).Path
        } else {
            $BaseDir = Split-Path (Split-Path $scriptDir -Parent) -Parent
            if (-not (Test-Path (Join-Path $BaseDir "lists"))) {
                $BaseDir = (Get-Location).Path
            }
        }
    }

    $BaseDir = [System.IO.Path]::GetFullPath($BaseDir)
    $listsDir = Join-Path $BaseDir "lists"

    if (-not (Test-Path $listsDir)) {
        return @()
    }

    $csvFiles = Get-ChildItem -Path $listsDir -Filter "*.csv" -Recurse
    $catalogList = New-Object System.Collections.ArrayList
    $baseLen = $BaseDir.TrimEnd('\', '/').Length

    foreach ($file in $csvFiles) {
        # Filter out 0-byte or temp/hidden files
        if ($file.Length -le 0) {
            continue
        }
        if ($file.Name.StartsWith(".") -or $file.Name.StartsWith("~")) {
            continue
        }

        $fullPath = $file.FullName
        $relPath = $fullPath.Substring($baseLen).TrimStart('\', '/')
        $dirRel = Split-Path $relPath -Parent

        $item = New-Object PSObject
        $item | Add-Member -MemberType NoteProperty -Name "RelativePath" -Value $relPath
        $item | Add-Member -MemberType NoteProperty -Name "FullPath" -Value $fullPath
        $item | Add-Member -MemberType NoteProperty -Name "FileName" -Value $file.Name
        $item | Add-Member -MemberType NoteProperty -Name "Directory" -Value $dirRel
        $item | Add-Member -MemberType NoteProperty -Name "Size" -Value $file.Length

        [void]$catalogList.Add($item)
    }

    $sorted = @($catalogList | Sort-Object -Property RelativePath)
    return $sorted
}

function Filter-HKChecklists {
    <#
    .SYNOPSIS
        Filters a list of checklists by keyword.
    .DESCRIPTION
        Performs a case-insensitive search across FileName and RelativePath.
        PowerShell 2.0 compatible.
    .PARAMETER Checklists
        Array of checklist objects from Get-HKChecklistCatalog.
    .PARAMETER Keyword
        Search string. If empty or null, returns all checklists unchanged.
    .OUTPUTS
        Filtered array of checklist objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Checklists,

        [Parameter(Mandatory = $false)]
        [string]$Keyword = ""
    )

    if ($null -eq $Checklists -or @($Checklists).Length -eq 0) {
        return @()
    }

    if ([string]::IsNullOrEmpty($Keyword) -or [string]::IsNullOrEmpty($Keyword.Trim())) {
        return $Checklists
    }

    $kw = $Keyword.Trim().ToLower()
    $resultList = New-Object System.Collections.ArrayList

    foreach ($item in $Checklists) {
        $match = $false
        if ($null -ne $item.FileName -and $item.FileName.ToLower().IndexOf($kw) -ge 0) {
            $match = $true
        } elseif ($null -ne $item.RelativePath -and $item.RelativePath.ToLower().IndexOf($kw) -ge 0) {
            $match = $true
        }
        if ($match) {
            [void]$resultList.Add($item)
        }
    }

    return ,$resultList.ToArray()
}

function Get-HKTerminalWidth {
    <#
    .SYNOPSIS
        Safely retrieves the current terminal window width.
    .DESCRIPTION
        Queries $Host.UI.RawUI.WindowSize.Width. Falls back to 80 columns if unavailable or < 40.
        PowerShell 2.0 compatible.
    .OUTPUTS
        [int] Safe terminal width.
    #>
    [CmdletBinding()]
    param()

    $width = 80
    try {
        if ($null -ne $Host -and $null -ne $Host.UI -and $null -ne $Host.UI.RawUI) {
            $w = $Host.UI.RawUI.WindowSize.Width
            if ($w -ge 40) {
                $width = [int]$w
            }
        }
    } catch {
        $width = 80
    }
    return $width
}

function Format-HKTruncate {
    <#
    .SYNOPSIS
        Truncates a string to fit exactly within a maximum width, appending an ellipsis.
    .DESCRIPTION
        Guarantees the output string length is strictly <= $MaxWidth.
        Never allows strings to overflow and cause line wrap in terminal tables.
        PowerShell 2.0 compatible.
    .PARAMETER Text
        Input string.
    .PARAMETER MaxWidth
        Maximum allowed character length.
    .PARAMETER Ellipsis
        Optional suffix appended when truncated (default '...').
    .OUTPUTS
        [string] Truncated string whose length is <= $MaxWidth.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Text = "",

        [Parameter(Mandatory = $true)]
        [int]$MaxWidth,

        [Parameter(Mandatory = $false)]
        [string]$Ellipsis = "..."
    )

    if ($null -eq $Text) {
        return ""
    }
    if ($MaxWidth -le 0) {
        return ""
    }
    if ($null -eq $Ellipsis) {
        $Ellipsis = "..."
    }

    if ($Text.Length -le $MaxWidth) {
        return $Text
    }

    if ($MaxWidth -le $Ellipsis.Length) {
        return $Text.Substring(0, $MaxWidth)
    }

    $cutLen = $MaxWidth - $Ellipsis.Length
    return ($Text.Substring(0, $cutLen) + $Ellipsis)
}

function Render-HKPage {
    <#
    .SYNOPSIS
        Renders a paginated, anti-wrapping table of checklists.
    .DESCRIPTION
        Draws a structured table containing STT, Checklist Name, and Directory / [SUGGESTED] tag.
        Calculates column widths dynamically to strictly guarantee zero line wrap.
        PowerShell 2.0 compatible.
    .PARAMETER Items
        Array of checklist items to display.
    .PARAMETER PageIndex
        0-based page index to render (default 0).
    .PARAMETER PageSize
        Number of items per page (default 10).
    .PARAMETER TerminalWidth
        Target width constraint. If 0 or omitted, retrieved via Get-HKTerminalWidth.
    .PARAMETER SuggestedItem
        Optional checklist object to highlight as the recommended choice.
    .PARAMETER PassThru
        If specified, returns rendered string lines for verification/testing.
    .OUTPUTS
        Optional array of strings if -PassThru is supplied.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$Items = @(),

        [Parameter(Mandatory = $false)]
        [int]$PageIndex = 0,

        [Parameter(Mandatory = $false)]
        [int]$PageSize = 10,

        [Parameter(Mandatory = $false)]
        [int]$TerminalWidth = 0,

        [Parameter(Mandatory = $false)]
        [object]$SuggestedItem = $null,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Resolve safe terminal width
    $tw = if ($TerminalWidth -gt 0) { $TerminalWidth } else { Get-HKTerminalWidth }
    if ($tw -lt 40) {
        $tw = 80
    }

    # Constrain table width: max 118, prevent margin wrap on standard consoles
    $tableWidth = [Math]::Max(40, [Math]::Min($tw, 118))
    if ($tableWidth -eq $tw -and $tw -gt 40) {
        $tableWidth = $tw - 1
    }

    $totalItems = if ($null -eq $Items) { 0 } else { @($Items).Length }
    if ($PageSize -lt 1) {
        $PageSize = 10
    }
    $totalPages = [int][Math]::Ceiling($totalItems / [double]$PageSize)
    if ($totalPages -lt 1) {
        $totalPages = 1
    }

    # Clamp PageIndex
    if ($PageIndex -lt 0) {
        $PageIndex = 0
    }
    if ($PageIndex -ge $totalPages) {
        $PageIndex = $totalPages - 1
    }

    # Calculate column widths
    # Total row format: "| " + col1 + " | " + col2 + " | " + col3 + " |"
    # Separator chars count: 2 (start) + 3 (mid1) + 3 (mid2) + 2 (end) = 10 chars
    $col1Width = if ($tableWidth -lt 50) { 3 } else { 4 }
    $col3Width = if ($tableWidth -lt 50) { 7 } else { 8 }
    $col2Width = $tableWidth - 10 - $col1Width - $col3Width # Checklist name (maximized)

    # Build ASCII borders
    $borderTop = "+" + ("-" * ($col1Width + 2)) + "+" + ("-" * ($col2Width + 2)) + "+" + ("-" * ($col3Width + 2)) + "+"
    $borderSep = "+" + ("-" * ($col1Width + 2)) + "+" + ("-" * ($col2Width + 2)) + "+" + ("-" * ($col3Width + 2)) + "+"
    $borderBottom = $borderTop

    # Build Header Row
    $hdrStt  = (Format-HKTruncate "STT" $col1Width "").PadLeft($col1Width)
    $hdrName = (Format-HKTruncate "Ten Checklist (CIS Benchmark)" $col2Width "").PadRight($col2Width)
    $hdrDir  = (Format-HKTruncate "Nhom" $col3Width "").PadRight($col3Width)
    $headerRow = "| " + $hdrStt + " | " + $hdrName + " | " + $hdrDir + " |"

    # Header title line
    $titleRaw = "--- DANH SACH CHECKLIST (Trang " + ($PageIndex + 1) + "/" + $totalPages + " - Tong: " + $totalItems + ") ---"
    $titleLine = Format-HKTruncate $titleRaw $tableWidth ""

    # Footer navigation line
    $footerRaw = "[Trang " + ($PageIndex + 1) + "/" + $totalPages + "] [N]ext | [P]rev | [STT] Chon | [Q] Thoat"
    $footerLine = Format-HKTruncate $footerRaw $tableWidth ""

    $renderedLines = New-Object System.Collections.ArrayList
    [void]$renderedLines.Add($titleLine)
    [void]$renderedLines.Add($borderTop)
    [void]$renderedLines.Add($headerRow)
    [void]$renderedLines.Add($borderSep)

    Write-Host $titleLine -ForegroundColor Cyan
    Write-Host $borderTop -ForegroundColor Gray
    Write-Host $headerRow -ForegroundColor White
    Write-Host $borderSep -ForegroundColor Gray

    if ($totalItems -eq 0) {
        $emptyMsg = "Khong co checklist nao phu hop."
        $emptyPad = $tableWidth - 4
        $emptyRow = "| " + (Format-HKTruncate $emptyMsg $emptyPad "").PadRight($emptyPad) + " |"
        [void]$renderedLines.Add($emptyRow)
        Write-Host $emptyRow -ForegroundColor Yellow
    } else {
        $startIndex = $PageIndex * $PageSize
        $endIndex = [Math]::Min($startIndex + $PageSize, $totalItems)

        for ($i = $startIndex; $i -lt $endIndex; $i++) {
            $item = $Items[$i]
            $sttStr = ($i + 1).ToString().PadLeft($col1Width)

            $isSug = $false
            if ($null -ne $SuggestedItem) {
                if ($null -ne $item.FullPath -and $item.FullPath -eq $SuggestedItem.FullPath) {
                    $isSug = $true
                } elseif ($null -ne $item.FileName -and $item.FileName -eq $SuggestedItem.FileName) {
                    $isSug = $true
                }
            }

            $dirStr = ""
            if ($isSug) {
                $dirStr = "[GOI Y]"
            } elseif ($item.Directory -like "*Windows*") {
                $dirStr = "Windows"
            } elseif ($item.Directory -eq "lists") {
                $dirStr = "Core"
            } else {
                $dirStr = Split-Path $item.Directory -Leaf
            }

            # Smart display: if removing redundant '.csv' allows name to fit without truncation, do so
            $rawName = $item.FileName
            $dispName = $rawName
            if ($rawName.Length -gt $col2Width -and $rawName.EndsWith(".csv", [System.StringComparison]::OrdinalIgnoreCase)) {
                $noExt = $rawName.Substring(0, $rawName.Length - 4)
                if ($noExt.Length -le $col2Width) {
                    $dispName = $noExt
                }
            }

            $nameCell = (Format-HKTruncate $dispName $col2Width "...").PadRight($col2Width)
            $dirCell  = (Format-HKTruncate $dirStr $col3Width "...").PadRight($col3Width)
            $rowLine  = "| " + $sttStr + " | " + $nameCell + " | " + $dirCell + " |"

            [void]$renderedLines.Add($rowLine)

            if ($isSug) {
                Write-Host $rowLine -ForegroundColor Green
            } else {
                Write-Host $rowLine -ForegroundColor Gray
            }
        }
    }

    [void]$renderedLines.Add($borderBottom)
    [void]$renderedLines.Add($footerLine)

    Write-Host $borderBottom -ForegroundColor Gray
    Write-Host $footerLine -ForegroundColor Yellow

    if ($PassThru) {
        return $renderedLines.ToArray()
    }
}

function Show-HKBanner {
    <#
    .SYNOPSIS
        Displays the HardeningNCS ASCII banner adapted to the terminal width.
    #>
    [CmdletBinding()]
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
    <#
    .SYNOPSIS
        Displays the system environment summary box card adapted to the terminal width.
    #>
    [CmdletBinding()]
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
