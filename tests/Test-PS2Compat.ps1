# ==============================================================================
# File: Test-PS2Compat.ps1
# Description: Static analysis test to ensure PowerShell 2.0 compatibility.
#              Scans all *.ps1 files in src/ (or specified directory) for
#              forbidden PowerShell 3.0+ constructs and modern OS cmdlets.
# Compatibility: PowerShell 2.0+
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetDir
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
if ([string]::IsNullOrEmpty($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

$rootDir = Split-Path $ScriptDir -Parent

if ([string]::IsNullOrEmpty($TargetDir)) {
    $TargetDir = Join-Path $rootDir "src"
}

if (-not (Test-Path -Path $TargetDir)) {
    Write-Error ("Target directory not found: " + $TargetDir)
    exit 1
}

# Define forbidden syntax patterns for PowerShell 3.0+ and modern OS modules
$forbiddenRules = @(
    # PS 3.0+ Type Accelerators & Language Syntax
    @{ Pattern = '\[ordered\]'; Name = '[ordered] type accelerator'; Reason = '[ordered] requires PowerShell 3.0+' },
    @{ Pattern = '\[pscustomobject\]'; Name = '[pscustomobject] type accelerator'; Reason = '[pscustomobject] requires PowerShell 3.0+ (use New-Object PSObject)' },
    @{ Pattern = '^\s*class\s+[A-Za-z_]'; Name = 'class keyword'; Reason = 'class keyword requires PowerShell 5.0+' },
    @{ Pattern = '^\s*enum\s+[A-Za-z_]'; Name = 'enum keyword'; Reason = 'enum keyword requires PowerShell 5.0+' },
    @{ Pattern = '^\s*using\s+(namespace|module)\b'; Name = 'using statement'; Reason = 'using statement requires PowerShell 5.0+' },
    @{ Pattern = '\$using:\w+'; Name = '$using: scope modifier'; Reason = '$using: scope modifier requires PowerShell 3.0+' },

    # PS 3.0+ Automatic Variables
    @{ Pattern = '\$PSScriptRoot\b'; Name = '$PSScriptRoot variable'; Reason = '$PSScriptRoot requires PowerShell 3.0+ in scripts (use Split-Path $MyInvocation.MyCommand.Path -Parent)' },
    @{ Pattern = '\$PSCommandPath\b'; Name = '$PSCommandPath variable'; Reason = '$PSCommandPath requires PowerShell 3.0+ (use $MyInvocation.MyCommand.Path)' },

    # PS 3.0+ / PS 4.0+ / PS 5.0+ Core Cmdlets
    @{ Pattern = '\bGet-ItemPropertyValue\b'; Name = 'Get-ItemPropertyValue cmdlet'; Reason = 'Get-ItemPropertyValue requires PowerShell 5.0+' },
    @{ Pattern = '\bGet-FileHash\b'; Name = 'Get-FileHash cmdlet'; Reason = 'Get-FileHash requires PowerShell 4.0+' },
    @{ Pattern = '\bImport-PowerShellDataFile\b'; Name = 'Import-PowerShellDataFile cmdlet'; Reason = 'Import-PowerShellDataFile requires PowerShell 5.0+' },
    @{ Pattern = '\b(ConvertFrom|ConvertTo)-Json\b'; Name = '*-Json cmdlet'; Reason = 'ConvertFrom-Json / ConvertTo-Json require PowerShell 3.0+' },
    @{ Pattern = '\bInvoke-RestMethod\b'; Name = 'Invoke-RestMethod cmdlet'; Reason = 'Invoke-RestMethod requires PowerShell 3.0+' },
    @{ Pattern = '\bInvoke-WebRequest\b'; Name = 'Invoke-WebRequest cmdlet'; Reason = 'Invoke-WebRequest requires PowerShell 3.0+' },

    # CIM Cmdlets (PS 3.0+)
    @{ Pattern = '\b(Get|New|Remove|Set|Invoke)-Cim\w+\b'; Name = 'CIM cmdlets'; Reason = 'CIM cmdlets require PowerShell 3.0+ (use Get-WmiObject / [WmiSearcher])' },

    # Windows 8 / Server 2012+ OS Modules (PS 3.0+ / 4.0+ / 5.1+)
    @{ Pattern = '\b(Get|New|Set|Disable|Enable|Rename|Remove)-Local(User|Group)\b'; Name = 'LocalAccounts cmdlets'; Reason = 'Microsoft.PowerShell.LocalAccounts cmdlets require PowerShell 5.1+ (use ADSI [ADSI]"WinNT://...")' },
    @{ Pattern = '\b(Get|Set)-WinSystemLocale\b'; Name = 'International cmdlets'; Reason = 'Get-WinSystemLocale requires PowerShell 4.0+' },
    @{ Pattern = '\b(Get|New|Set|Remove|Enable|Disable|Show)-NetFirewall\w*\b'; Name = 'NetSecurity cmdlets'; Reason = 'NetFirewall cmdlets require PowerShell 3.0+ (use netsh advfirewall)' },
    @{ Pattern = '\bTest-NetConnection\b'; Name = 'Test-NetConnection cmdlet'; Reason = 'Test-NetConnection requires PowerShell 4.0+' },
    @{ Pattern = '\b(Get|Set)-ProcessMitigation\b'; Name = 'ProcessMitigation cmdlets'; Reason = 'Get-ProcessMitigation requires PowerShell 5.0+' }
)

Write-Host "=== TEST SUITE: PowerShell 2.0 Compatibility Static Analysis ===" -ForegroundColor Cyan
Write-Host ("Scanning directory: " + $TargetDir)

$files = Get-ChildItem -Path $TargetDir -Filter "*.ps1" -Recurse
Write-Host ("Found " + $files.Count + " PowerShell script(s) to analyze.")

$violations = New-Object System.Collections.ArrayList
$totalLinesScanned = 0

foreach ($file in $files) {
    $lines = [System.IO.File]::ReadAllLines($file.FullName)
    $lineNum = 0
    $inBlockComment = $false

    foreach ($line in $lines) {
        $lineNum++
        $totalLinesScanned++
        $trimmed = $line.Trim()

        # Handle multi-line block comments <# ... #>
        if ($inBlockComment) {
            if ($trimmed.Contains("#>")) {
                $inBlockComment = $false
            }
            continue
        }

        if ($trimmed.StartsWith("<#")) {
            if (-not $trimmed.Contains("#>")) {
                $inBlockComment = $true
            }
            continue
        }

        # Skip empty lines and full-line comments
        if ([string]::IsNullOrEmpty($trimmed) -or $trimmed.StartsWith("#")) {
            continue
        }

        foreach ($rule in $forbiddenRules) {
            if ($line -match $rule.Pattern) {
                $item = New-Object PSObject
                $item | Add-Member -MemberType NoteProperty -Name "File" -Value $file.FullName
                $item | Add-Member -MemberType NoteProperty -Name "FileName" -Value $file.Name
                $item | Add-Member -MemberType NoteProperty -Name "LineNumber" -Value $lineNum
                $item | Add-Member -MemberType NoteProperty -Name "Name" -Value $rule.Name
                $item | Add-Member -MemberType NoteProperty -Name "Pattern" -Value $rule.Pattern
                $item | Add-Member -MemberType NoteProperty -Name "Reason" -Value $rule.Reason
                $item | Add-Member -MemberType NoteProperty -Name "LineContent" -Value $trimmed
                [void]$violations.Add($item)
            }
        }
    }
}

$passSymbol = [char]0x2713
$failSymbol = [char]0x2717

Write-Host ("Total lines scanned: " + $totalLinesScanned)

if ($violations.Count -eq 0) {
    Write-Host ("`n$passSymbol PASS: 0 PS3+ constructs found across all " + $files.Count + " files in " + $TargetDir) -ForegroundColor Green
    Write-Host "All scripts are 100% compliant with PowerShell 2.0 static requirements." -ForegroundColor Green
    exit 0
} else {
    Write-Host ("`n$failSymbol FAIL: Found " + $violations.Count + " PS3+ construct violation(s):") -ForegroundColor Red
    foreach ($v in $violations) {
        Write-Host ("  File: " + $v.FileName + ":" + $v.LineNumber) -ForegroundColor Yellow
        Write-Host ("    Rule    : " + $v.Name) -ForegroundColor Yellow
        Write-Host ("    Reason  : " + $v.Reason) -ForegroundColor Yellow
        Write-Host ("    Content : " + $v.LineContent) -ForegroundColor Yellow
    }
    exit 1
}
