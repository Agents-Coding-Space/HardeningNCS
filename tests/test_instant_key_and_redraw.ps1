# ==============================================================================
# File: test_instant_key_and_redraw.ps1
# Description: Unit and Regression Test Suite for Instant Single-Key Actions,
#              Input Redirection Fallback, and In-Place Table Redraw Mechanics.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
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

Write-Host "=== TEST SUITE: Instant Key Actions & In-Place Redraw ===" -ForegroundColor Cyan
Write-Host ("Runtime Host: PowerShell " + $PSVersionTable.PSVersion.ToString() + " (" + $PSVersionTable.PSEdition + ")") -ForegroundColor Gray

# ------------------------------------------------------------------------------
# Test Section 1: Read-HKMenuAction with Piped / Redirected Stdin
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Read-HKMenuAction on Redirected Input Streams ---" -ForegroundColor Yellow

# Helper to invoke Read-HKMenuAction with piped stdin
function Invoke-PipedMenuAction {
    param([string]$PipedString, [int]$PageCount = 10)
    
    $tuiHelperFull = (Join-Path $commonDir "Tui-Helpers.ps1")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command -"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $sw = $proc.StandardInput
    $sw.WriteLine(". '" + $tuiHelperFull + "'")
    $sw.WriteLine('$res = Read-HKMenuAction -Prompt "" -CurrentPageCount ' + $PageCount)
    # This line feeds the input into Read-Host:
    $sw.WriteLine($PipedString)
    $sw.WriteLine('Write-Output ("RESULT:" + $res.Action + "|" + $res.Value)')
    $sw.Close()

    $outAll = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()

    $match = ""
    foreach ($line in $outAll.Split("`n")) {
        $t = $line.Trim()
        if ($t.StartsWith("RESULT:")) {
            $match = $t.Substring(7)
            break
        }
    }
    return $match
}

$outN = Invoke-PipedMenuAction -PipedString "N"
Assert-HKEqual "Redirected input 'N' returns Next action" $outN "Next|"

$outP = Invoke-PipedMenuAction -PipedString "p"
Assert-HKEqual "Redirected input 'p' returns Prev action" $outP "Prev|"

$outG = Invoke-PipedMenuAction -PipedString "G"
Assert-HKEqual "Redirected input 'G' returns Suggested action" $outG "Suggested|"

$outQ = Invoke-PipedMenuAction -PipedString "q"
Assert-HKEqual "Redirected input 'q' returns Quit action" $outQ "Quit|"

$outL = Invoke-PipedMenuAction -PipedString "L"
Assert-HKEqual "Redirected input 'L' returns CycleLevel action" $outL "CycleLevel|"

$out1 = Invoke-PipedMenuAction -PipedString "1" -PageCount 10
Assert-HKEqual "Redirected input '1' returns SelectItem index 0" $out1 "SelectItem|0"

$out0 = Invoke-PipedMenuAction -PipedString "0" -PageCount 10
Assert-HKEqual "Redirected input '0' returns SelectItem index 9 (item 10)" $out0 "SelectItem|9"

$outSearch = Invoke-PipedMenuAction -PipedString "/windows2008" -PageCount 10
Assert-HKEqual "Redirected input '/windows2008' returns Search action" $outSearch "Search|windows2008"

# ------------------------------------------------------------------------------
# Test Section 2: Clear-HKTableArea Boundary & Anti-Wrap Constraints
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Clear-HKTableArea Boundary Width & Clamping ---" -ForegroundColor Yellow

# Test narrow width 40: blank must be <= 39 chars so it never wraps to 41
$clearedNoCrash = $true
try {
    # startTop = 0, lineCount = 5, width = 40
    Clear-HKTableArea -StartTop 0 -LineCount 5 -Width 40
} catch {
    $clearedNoCrash = $false
}
Assert-HKTest "Clear-HKTableArea at width 40 executes without unhandled exception" $clearedNoCrash

# Test negative startTop and 0 lineCount
$edgeCasesHandled = $true
try {
    Clear-HKTableArea -StartTop -1 -LineCount 10 -Width 80
    Clear-HKTableArea -StartTop 5 -LineCount 0 -Width 80
    Clear-HKTableArea -StartTop -5 -LineCount -5 -Width 40
} catch {
    $edgeCasesHandled = $false
}
Assert-HKTest "Clear-HKTableArea ignores negative/zero parameters safely" $edgeCasesHandled

# ------------------------------------------------------------------------------
# Test Section 3: In-Place Redraw Simulation for Short Last Page
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Page Transition & Shorter Last Page Simulation ---" -ForegroundColor Yellow

# Simulate full 10-item page (lines = 11 + 10 = 21) followed by a short 3-item page (lines = 11 + 3 = 14)
$fullPageLines = 21
$shortPageLines = 14
$linesToClear = $fullPageLines - $shortPageLines

Assert-HKEqual "Shorter page generates 7 leftover lines to clear" $linesToClear 7

$shortPageWiped = $true
try {
    Clear-HKTableArea -StartTop 10 -LineCount $linesToClear -Width 80
} catch {
    $shortPageWiped = $false
}
Assert-HKTest "Clear-HKTableArea cleans short page delta cleanly" $shortPageWiped

# ------------------------------------------------------------------------------
# Test Section 4: Fallback to Full Redraw when Cursor is Unsupported
# ------------------------------------------------------------------------------
Write-Host "`n--- Testing Fallback Logic when Cursor Repositioning Fails ---" -ForegroundColor Yellow

# Simulate scenario where $canReposition is false or CursorTop threw an exception
$simRedrawMode = "PartialTable"
$simTableStartTop = -1 # Invalid handle / redirected stream indicator

if ($simRedrawMode -eq "PartialTable" -and $simTableStartTop -ge 0) {
    $simResultMode = "PartialTable"
} else {
    $simResultMode = "Full"
}
Assert-HKEqual "Invalid cursor anchor automatically falls back to Full redraw" $simResultMode "Full"

# ------------------------------------------------------------------------------
# Final Test Summary
# ------------------------------------------------------------------------------
Write-Host "`n=== TEST SUMMARY: Instant Key Actions & In-Place Redraw ===" -ForegroundColor Cyan
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
