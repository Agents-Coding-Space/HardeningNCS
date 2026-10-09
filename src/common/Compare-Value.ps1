# ==============================================================================
# File: Compare-Value.ps1
# Description: Helper function to compare current system values against CIS
#              recommended values using various operators.
# Compatibility: PowerShell 2.0+ (.NET 2.0/3.5 BCL compatible).
# ==============================================================================

function Compare-HKValue {
    <#
    .SYNOPSIS
        Compares a current value against a recommended baseline value.
    .DESCRIPTION
        Evaluates whether $Current satisfies $Recommended based on $Operator.
        Supported operators: '=', '!=', '>=', '<=', 'contains', '=|0'.
        Compatible with PowerShell 2.0 on legacy Windows platforms.
    .PARAMETER Current
        The actual value currently configured on the target system.
    .PARAMETER Recommended
        The recommended CIS Benchmark target value.
    .PARAMETER Operator
        Comparison operator: '=', '!=', '>=', '<=', 'contains', '=|0'.
    .OUTPUTS
        [bool] Returns $true if compliant, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Current,

        [Parameter(Mandatory = $false)]
        [object]$Recommended,

        [Parameter(Mandatory = $true)]
        [string]$Operator
    )

    # Normalize operator string
    $op = if ($Operator) { $Operator.Trim().ToLower() } else { "=" }

    # Normalize nulls to empty string
    $cStr = if ($null -eq $Current) { "" } else { "$Current".Trim() }
    $rStr = if ($null -eq $Recommended) { "" } else { "$Recommended".Trim() }

    # Handle array / collection inputs (e.g., REG_MULTI_SZ)
    if ($Current -is [System.Array] -or $Current -is [System.Collections.IList]) {
        $arrList = New-Object System.Collections.ArrayList
        foreach ($elem in $Current) {
            if ($null -ne $elem) { [void]$arrList.Add("$elem".Trim()) }
        }
        $cStr = [string]::Join(",", $arrList.ToArray())
    }

    # Attempt numeric parsing using int64 (supported in .NET 2.0)
    $cVal = [int64]0
    $rVal = [int64]0
    $cIsNum = [int64]::TryParse($cStr, [ref]$cVal)
    $rIsNum = [int64]::TryParse($rStr, [ref]$rVal)

    switch ($op) {
        "=" {
            if ($cIsNum -and $rIsNum) {
                return ($cVal -eq $rVal)
            }
            return ($cStr -ieq $rStr)
        }

        "!=" {
            if ($cIsNum -and $rIsNum) {
                return ($cVal -ne $rVal)
            }
            return ($cStr -ine $rStr)
        }

        ">=" {
            if (-not $cIsNum -or -not $rIsNum) {
                if ([string]::IsNullOrEmpty($cStr)) { return $false }
                return ([string]::Compare($cStr, $rStr, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
            }
            return ($cVal -ge $rVal)
        }

        "<=" {
            if (-not $cIsNum -or -not $rIsNum) {
                if ([string]::IsNullOrEmpty($cStr)) { return $false }
                return ([string]::Compare($cStr, $rStr, [System.StringComparison]::OrdinalIgnoreCase) -le 0)
            }
            return ($cVal -le $rVal)
        }

        "contains" {
            if ([string]::IsNullOrEmpty($rStr)) {
                return $true
            }
            if ([string]::IsNullOrEmpty($cStr)) {
                return $false
            }
            if ($cStr.IndexOf($rStr, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
            # Also check individual elements if Current was an array
            if ($Current -is [System.Array] -or $Current -is [System.Collections.IList]) {
                foreach ($item in $Current) {
                    if ($null -ne $item -and "$item".IndexOf($rStr, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        return $true
                    }
                }
            }
            return $false
        }

        "=|0" {
            # Compliant if equals recommended value OR equals 0 / empty / not configured
            if ($cIsNum -and $rIsNum) {
                if ($cVal -eq $rVal -or $cVal -eq 0) {
                    return $true
                }
            }
            if ($cStr -ieq $rStr -or $cStr -eq "0" -or [string]::IsNullOrEmpty($cStr)) {
                return $true
            }
            return $false
        }

        default {
            return ($cStr -ieq $rStr)
        }
    }
}
