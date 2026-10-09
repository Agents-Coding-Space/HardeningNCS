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
        Supported operators: '=', '!=', '>=', '<=', '<=!0', 'contains', '=|0'.
        Compatible with PowerShell 2.0 on legacy Windows platforms.
    .PARAMETER Current
        The actual value currently configured on the target system.
    .PARAMETER Recommended
        The recommended CIS Benchmark target value.
    .PARAMETER Operator
        Comparison operator: '=', '!=', '>=', '<=', '<=!0', 'contains', '=|0'. Default is '='.
    .OUTPUTS
        [bool] Returns $true if compliant, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Current,

        [Parameter(Mandatory = $false)]
        [object]$Recommended,

        [Parameter(Mandatory = $false)]
        [string]$Operator = "="
    )

    # Normalize operator string (default to '=' if null or empty)
    $op = if ($Operator) { $Operator.Trim().ToLower() } else { "=" }
    if ([string]::IsNullOrEmpty($op)) {
        $op = "="
    }

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
            if ($cStr -ieq $rStr) {
                return $true
            }
            if ([string]::IsNullOrEmpty($cStr)) {
                return $false
            }
            # Regex fallback matching when string equality fails
            if (-not [string]::IsNullOrEmpty($rStr)) {
                $hasRegex = ($rStr.IndexOfAny(@('[', ']', '(', ')', '*', '+', '?', '^', '$', '|', '{', '}')) -ge 0) -or ($rStr -match '\\[sdwbSDWB]')
                if ($hasRegex) {
                    try {
                        if ($cStr -match ("^(?:" + $rStr + ")$")) {
                            return $true
                        }
                        if (-not $cIsNum -and ($cStr -match $rStr)) {
                            return $true
                        }
                        if ($rStr.IndexOf("||") -ge 0) {
                            $normRegex = $rStr.Replace('"', '').Replace("||", "|")
                            if ($cStr -match ("^(?:" + $normRegex + ")$")) {
                                return $true
                            }
                            $cNorm = $cStr.Replace("BUILTIN\", "")
                            $rNorm = $normRegex.Replace("BUILTIN\", "")
                            if ($cNorm -match ("^(?:" + $rNorm + ")$")) {
                                return $true
                            }
                        }
                    } catch {
                        # Pattern may not be valid regex, treat as non-match
                    }
                }
                # Also handle optional BUILTIN\ domain prefix difference
                if ($cStr.Replace("BUILTIN\", "") -ieq $rStr.Replace("BUILTIN\", "")) {
                    return $true
                }
            }
            return $false
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

        "<=!0" {
            # Compliant if <= recommended value AND not equal to 0 (or '0')
            if (-not $cIsNum -or -not $rIsNum) {
                if ([string]::IsNullOrEmpty($cStr) -or $cStr -eq "0") { return $false }
                return ([string]::Compare($cStr, $rStr, [System.StringComparison]::OrdinalIgnoreCase) -le 0 -and $cStr -ne "0")
            }
            return ($cVal -le $rVal -and $cVal -ne 0)
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
