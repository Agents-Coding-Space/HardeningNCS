# ==============================================================================
# File: test_csv_schema.ps1
# Description: Validates schema, integrity, and CIS constraints for all CSV files
#              in lists/ and performs PS 2.0 static syntax analysis on src/.
# Compatibility: PowerShell 2.0+
# ==============================================================================

$scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$rootDir = Split-Path $scriptDir -Parent
$listsDir = Join-Path $rootDir "lists"
$srcDir = Join-Path $rootDir "src"

$expectedHeaders = @(
    "ID",
    "Category",
    "Name",
    "Method",
    "MethodArgument",
    "RegistryPath",
    "RegistryItem",
    "DefaultValue",
    "RecommendedValue",
    "Operator",
    "Severity"
)

$allowedMethods = @("Registry", "secedit", "accountpolicy", "auditpol", "localaccount", "service")
$allowedOperators = @("=", "!=", ">=", "<=", "<=!0", "contains", "=|0")
$allowedSeverities = @("High", "Medium", "Low")
$requiredCategories = @("Account Policies", "Security Options", "Audit Policy", "System Services", "Administrative Templates")

$csvFiles = @(
    "finding_list_cis_win7_sp1_machine.csv",
    "finding_list_cis_server2008r2_machine.csv",
    "finding_list_cis_server2012r2_machine.csv"
)

$totalErrors = 0

Write-Host "=== TEST SUITE: CSV Schema & Integrity Validation ===" -ForegroundColor Cyan

foreach ($fileName in $csvFiles) {
    $filePath = Join-Path $listsDir $fileName
    Write-Host "`nValidating: $fileName" -ForegroundColor Yellow

    if (-not (Test-Path $filePath)) {
        Write-Host "  [FAIL] File does not exist: $filePath" -ForegroundColor Red
        $totalErrors++
        continue
    }

    $rawLines = [System.IO.File]::ReadAllLines($filePath)
    if ($rawLines.Length -lt 2) {
        Write-Host "  [FAIL] File is empty or lacks data rows." -ForegroundColor Red
        $totalErrors++
        continue
    }

    # 1. Header Validation
    $headerLine = $rawLines[0].Trim()
    $headers = $headerLine.Split(",")
    if ($headers.Length -ne 11) {
        Write-Host "  [FAIL] Header column count is $($headers.Length), expected 11." -ForegroundColor Red
        $totalErrors++
    } else {
        $headerMismatch = $false
        for ($i = 0; $i -lt 11; $i++) {
            if ($headers[$i].Trim() -ne $expectedHeaders[$i]) {
                Write-Host "  [FAIL] Column $i is '$($headers[$i])', expected '$($expectedHeaders[$i])'." -ForegroundColor Red
                $headerMismatch = $true
                $totalErrors++
            }
        }
        if (-not $headerMismatch) {
            Write-Host "  [PASS] Header columns match exact 11-column schema." -ForegroundColor Green
        }
    }

    # 2. Row Integrity and Rule Count
    $ruleCount = $rawLines.Length - 1
    if ($ruleCount -lt 35) {
        Write-Host "  [FAIL] Rule count is $ruleCount, required at least 35 rules." -ForegroundColor Red
        $totalErrors++
    } else {
        Write-Host "  [PASS] Rule count is $ruleCount (>= 35 requirement met)." -ForegroundColor Green
    }

    # 3. Row Parsing & Constraint Checks
    $seenIds = @{}
    $seenCategories = @{}
    $rowErrors = 0

    for ($idx = 1; $idx -lt $rawLines.Length; $idx++) {
        $line = $rawLines[$idx].Trim()
        if ($line.Length -eq 0) { continue }

        # Simple CSV regex / parser supporting quotes
        $pattern = ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
        $fields = [System.Text.RegularExpressions.Regex]::Split($line, $pattern)

        if ($fields.Length -ne 11) {
            Write-Host "  [FAIL] Line $($idx + 1): Expected 11 fields, got $($fields.Length). Line content: $line" -ForegroundColor Red
            $rowErrors++
            continue
        }

        $id = $fields[0].Trim().Trim('"')
        $cat = $fields[1].Trim().Trim('"')
        $name = $fields[2].Trim().Trim('"')
        $method = $fields[3].Trim().Trim('"')
        $methodArg = $fields[4].Trim().Trim('"')
        $regPath = $fields[5].Trim().Trim('"')
        $regItem = $fields[6].Trim().Trim('"')
        $defVal = $fields[7].Trim().Trim('"')
        $recVal = $fields[8].Trim().Trim('"')
        $op = $fields[9].Trim().Trim('"')
        $sev = $fields[10].Trim().Trim('"')

        # Check unique ID
        if ($seenIds.ContainsKey($id)) {
            Write-Host "  [FAIL] Line $($idx + 1): Duplicate rule ID '$id'." -ForegroundColor Red
            $rowErrors++
        } else {
            $seenIds[$id] = $true
        }

        # Track categories
        $seenCategories[$cat] = $true

        # Check Method
        if ($allowedMethods -notcontains $method) {
            Write-Host "  [FAIL] Line $($idx + 1): Invalid Method '$method'. Allowed: $($allowedMethods -join ', ')" -ForegroundColor Red
            $rowErrors++
        }

        # STRICT: No MpPreferenceAsr
        if ($method -ieq "MpPreferenceAsr" -or $line -match "MpPreferenceAsr") {
            Write-Host "  [FAIL] Line $($idx + 1): Disallowed MpPreferenceAsr detected!" -ForegroundColor Red
            $rowErrors++
        }

        # Check Operator
        if ($allowedOperators -notcontains $op) {
            Write-Host "  [FAIL] Line $($idx + 1): Invalid Operator '$op'. Allowed: $($allowedOperators -join ', ')" -ForegroundColor Red
            $rowErrors++
        }

        # Check Severity
        if ($allowedSeverities -notcontains $sev) {
            Write-Host "  [FAIL] Line $($idx + 1): Invalid Severity '$sev'. Allowed: $($allowedSeverities -join ', ')" -ForegroundColor Red
            $rowErrors++
        }

        # Check Method-specific integrity
        if ($method -eq "Registry") {
            if ([string]::IsNullOrEmpty($regPath) -or [string]::IsNullOrEmpty($regItem)) {
                Write-Host "  [FAIL] Line $($idx + 1): Method 'Registry' requires both RegistryPath and RegistryItem." -ForegroundColor Red
                $rowErrors++
            }
        }
    }

    # Check Required Categories presence
    foreach ($reqCat in $requiredCategories) {
        if (-not $seenCategories.ContainsKey($reqCat)) {
            Write-Host "  [FAIL] Missing required Category '$reqCat' in $fileName." -ForegroundColor Red
            $rowErrors++
        }
    }

    if ($rowErrors -eq 0) {
        Write-Host "  [PASS] All $($ruleCount) rules passed integrity checks without error." -ForegroundColor Green
    } else {
        $totalErrors += $rowErrors
    }
}

# 4. Original 21-Column CIS Benchmark Schema Contract Validation
$cis21File = "CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv"
$cis21Path = Join-Path $listsDir $cis21File
Write-Host "`nValidating 21-Column Original Contract: $cis21File" -ForegroundColor Yellow

if (-not (Test-Path $cis21Path)) {
    Write-Host "  [FAIL] File does not exist: $cis21Path" -ForegroundColor Red
    $totalErrors++
} else {
    $expected21Headers = @(
        "ID", "Category", "Name", "Method", "MethodArgument", "RegistryPath", "RegistryItem",
        "RegistryPathIntune", "RegistryPathDCP", "RegistryItemIntune", "ClassName", "Namespace",
        "Property", "DefaultValue", "DefaultValueIntune", "RecommendedValue", "RecommendedValueIntune",
        "Operator", "OperatorIntune", "Severity", "Filter"
    )
    $cisLines = [System.IO.File]::ReadAllLines($cis21Path)
    if ($cisLines.Length -lt 2) {
        Write-Host "  [FAIL] File is empty or lacks data rows." -ForegroundColor Red
        $totalErrors++
    } else {
        $hLine = $cisLines[0].Trim()
        $hCols = $hLine.Split(",")
        if ($hCols.Length -ne 21) {
            Write-Host "  [FAIL] 21-Column schema mismatch: found $($hCols.Length) columns, expected 21." -ForegroundColor Red
            $totalErrors++
        } else {
            $mismatch21 = $false
            for ($j = 0; $j -lt 21; $j++) {
                if ($hCols[$j].Trim() -ne $expected21Headers[$j]) {
                    Write-Host "  [FAIL] Col $j is '$($hCols[$j])', expected '$($expected21Headers[$j])'." -ForegroundColor Red
                    $mismatch21 = $true
                    $totalErrors++
                }
            }
            if (-not $mismatch21) {
                Write-Host "  [PASS] Header columns match exact 21-column CIS/HardeningKitty schema." -ForegroundColor Green
            }
        }

        $cisRuleCount = $cisLines.Length - 1
        if ($cisRuleCount -ne 324) {
            Write-Host "  [FAIL] Rule count is $cisRuleCount, expected exactly 324 original rules." -ForegroundColor Red
            $totalErrors++
        } else {
            Write-Host "  [PASS] Rule count is 324 (100% original baseline preserved)." -ForegroundColor Green
        }
    }
}

Write-Host "`n=== TEST SUITE: PowerShell 2.0 Static Compatibility Checks ===" -ForegroundColor Cyan

$forbiddenPatterns = @(
    @{ Pattern = '\[ordered\]'; Reason = '[ordered] requires PS 3.0+' },
    @{ Pattern = '\[pscustomobject\]'; Reason = '[pscustomobject] requires PS 3.0+' },
    @{ Pattern = '\bGet-ItemPropertyValue\b'; Reason = 'Get-ItemPropertyValue requires PS 5.0+' },
    @{ Pattern = '\bGet-CimInstance\b'; Reason = 'Get-CimInstance requires PS 3.0+' },
    @{ Pattern = '\bGet-FileHash\b'; Reason = 'Get-FileHash requires PS 4.0+' },
    @{ Pattern = '\bImport-PowerShellDataFile\b'; Reason = 'Import-PowerShellDataFile requires PS 5.0+' },
    @{ Pattern = '\bGet-LocalUser\b'; Reason = 'Get-LocalUser requires PS 5.1+' },
    @{ Pattern = '\bGet-WinSystemLocale\b'; Reason = 'Get-WinSystemLocale requires PS 4.0+' },
    @{ Pattern = '\bGet-NetFirewallRule\b'; Reason = 'Get-NetFirewallRule requires PS 4.0+' },
    @{ Pattern = '\bGet-ProcessMitigation\b'; Reason = 'Get-ProcessMitigation requires PS 5.0+' },
    @{ Pattern = '\$PSScriptRoot\b'; Reason = '$PSScriptRoot requires PS 3.0+ (use Split-Path $MyInvocation.MyCommand.Path -Parent)' }
)

$srcFiles = Get-ChildItem -Path $srcDir -Recurse -Filter "*.ps1"
$compatErrors = 0

foreach ($srcFile in $srcFiles) {
    $content = [System.IO.File]::ReadAllText($srcFile.FullName)
    foreach ($rule in $forbiddenPatterns) {
        if ([System.Text.RegularExpressions.Regex]::IsMatch($content, $rule.Pattern)) {
            Write-Host "  [FAIL] $($srcFile.Name): Found forbidden pattern '$($rule.Pattern)' - $($rule.Reason)" -ForegroundColor Red
            $compatErrors++
        }
    }
}

if ($compatErrors -eq 0) {
    Write-Host "  [PASS] All source files in src/ are 100% compliant with PS 2.0 constraints." -ForegroundColor Green
} else {
    $totalErrors += $compatErrors
}

Write-Host "`n=== OVERALL RESULT ===" -ForegroundColor Cyan
if ($totalErrors -eq 0) {
    Write-Host "ALL CHECKS PASSED PERFECTLY!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "FAILED with $totalErrors error(s)!" -ForegroundColor Red
    exit 1
}
