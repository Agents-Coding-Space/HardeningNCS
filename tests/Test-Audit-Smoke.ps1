# ==============================================================================
# File: Test-Audit-Smoke.ps1
# Description: Smoke test for Audit-LegacyWin.ps1 execution, output validation,
#              CSV schema integrity, and status accounting.
# Compatibility: PowerShell 2.0+
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

$rootDir = Split-Path $ScriptDir -Parent
$auditScript = Join-Path $rootDir "src\Audit-LegacyWin.ps1"
$findingList = Join-Path $rootDir "lists\finding_list_cis_win7_sp1_machine.csv"
$outputDir = Join-Path $rootDir "outputs"

if (-not (Test-Path -Path $auditScript)) {
    Write-Error ("Audit script not found: " + $auditScript)
    exit 1
}
if (-not (Test-Path -Path $findingList)) {
    Write-Error ("Finding list not found: " + $findingList)
    exit 1
}
if (-not (Test-Path -Path $outputDir)) {
    [void](New-Item -ItemType Directory -Path $outputDir -Force)
}

$passSymbol = [char]0x2713
$failSymbol = [char]0x2717

# Snapshot existing files in outputs/
$existingFiles = @{}
Get-ChildItem -Path $outputDir -Filter "audit_*.csv" | ForEach-Object {
    $existingFiles[$_.FullName] = $true
}

Write-Host "Running Audit-LegacyWin.ps1 with finding_list_cis_win7_sp1_machine.csv..." -ForegroundColor Cyan
& $auditScript -FindingList $findingList -OutputDir $outputDir

# Locate the newly generated report
$newFiles = Get-ChildItem -Path $outputDir -Filter "audit_*.csv" | Where-Object {
    -not $existingFiles.ContainsKey($_.FullName)
} | Sort-Object LastWriteTime -Descending

$reportFile = $null
if ($null -ne $newFiles -and $newFiles.Count -gt 0) {
    $reportFile = $newFiles[0].FullName
} else {
    $latest = Get-ChildItem -Path $outputDir -Filter "audit_*.csv" | Sort-Object LastWriteTime -Descending
    if ($null -ne $latest -and $latest.Count -gt 0) {
        $reportFile = $latest[0].FullName
    }
}

$hasError = $false

# Assertion 1: File exists and is non-empty
if ([string]::IsNullOrEmpty($reportFile) -or -not (Test-Path -Path $reportFile)) {
    Write-Host ("$failSymbol Assertion Failed: Output report file not found in " + $outputDir) -ForegroundColor Red
    exit 1
}

$fileInfo = Get-Item -Path $reportFile
if ($fileInfo.Length -le 0) {
    Write-Host ("$failSymbol Assertion Failed: Output report file is empty (0 bytes): " + $reportFile) -ForegroundColor Red
    $hasError = $true
} else {
    Write-Host ("$passSymbol Assertion Passed: Output report file exists and is non-empty (" + $fileInfo.Length + " bytes): " + $reportFile) -ForegroundColor Green
}

# Read report and finding list
$reportRows = @(Import-Csv -Path $reportFile)
$findingRows = @(Import-Csv -Path $findingList)

# Assertion 2: Header CSV has required columns
$requiredCols = @("ID", "Category", "Name", "Method", "CurrentValue", "RecommendedValue", "Operator", "Status", "Severity")
$missingCols = New-Object System.Collections.ArrayList
if ($reportRows.Count -gt 0) {
    $firstRow = $reportRows[0]
    foreach ($col in $requiredCols) {
        if (-not $firstRow.PSObject.Properties[$col]) {
            [void]$missingCols.Add($col)
        }
    }
} else {
    [void]$missingCols.Add("<empty report>")
}

if ($missingCols.Count -eq 0) {
    Write-Host ("$passSymbol Assertion Passed: Header CSV contains all required columns: " + [string]::Join(", ", $requiredCols)) -ForegroundColor Green
} else {
    Write-Host ("$failSymbol Assertion Failed: Missing required columns in CSV header: " + [string]::Join(", ", $missingCols.ToArray())) -ForegroundColor Red
    $hasError = $true
}

# Assertion 3: Status column ONLY contains Passed, Failed, or Skipped
$validStatuses = @("Passed", "Failed", "Skipped")
$invalidStatuses = New-Object System.Collections.ArrayList
$passedCount = 0
$failedCount = 0
$skippedCount = 0

foreach ($r in $reportRows) {
    $st = if ($null -ne $r.Status) { $r.Status.Trim() } else { "" }
    if ($validStatuses -notcontains $st) {
        [void]$invalidStatuses.Add("ID " + $r.ID + ": '" + $st + "'")
    }
    if ($st -eq "Passed") { $passedCount++ }
    elseif ($st -eq "Failed") { $failedCount++ }
    elseif ($st -eq "Skipped") { $skippedCount++ }
}

if ($invalidStatuses.Count -eq 0) {
    Write-Host ("$passSymbol Assertion Passed: Status column contains only valid values (Passed, Failed, Skipped).") -ForegroundColor Green
} else {
    Write-Host ("$failSymbol Assertion Failed: Invalid status values found in report:") -ForegroundColor Red
    foreach ($inv in $invalidStatuses) {
        Write-Host ("  " + $inv) -ForegroundColor Red
    }
    $hasError = $true
}

# Assertion 4: Row count matches finding list rule count
if ($reportRows.Count -eq $findingRows.Count) {
    Write-Host ("$passSymbol Assertion Passed: Report row count (" + $reportRows.Count + ") matches finding list rule count (" + $findingRows.Count + ").") -ForegroundColor Green
} else {
    Write-Host ("$failSymbol Assertion Failed: Report row count (" + $reportRows.Count + ") does not match finding list (" + $findingRows.Count + ").") -ForegroundColor Red
    $hasError = $true
}

# Print summary
Write-Host ("Total: " + $reportRows.Count + ", Passed: " + $passedCount + ", Failed: " + $failedCount + ", Skipped: " + $skippedCount)

if ($hasError) {
    exit 1
} else {
    exit 0
}
