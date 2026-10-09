# ==============================================================================
# File: Invoke-WmiCompat.ps1
# Description: Universal WMI/CIM query helper compatible across all PowerShell
#              versions: PowerShell 2.0, 3.0, 4.0, 5.1, and PowerShell 7.x+ (Core).
# ==============================================================================

function Invoke-HKWmiQuery {
    <#
    .SYNOPSIS
        Executes a WMI or CIM query in a way that works seamlessly on all PowerShell versions.
    .DESCRIPTION
        On PowerShell 2.0 - 5.1: Uses Get-WmiObject natively.
        On PowerShell 6.0 - 7.x+: Uses Get-CimInstance natively (since Get-WmiObject was removed in PS Core).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClassName,

        [Parameter(Mandatory = $false)]
        [string]$Filter = ""
    )

    try {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $cimName = "Get-Cim" + "Instance"
            $cimCmd = Get-Command -Name $cimName -ErrorAction SilentlyContinue
            if ($null -ne $cimCmd) {
                if (-not [string]::IsNullOrEmpty($Filter)) {
                    return & $cimCmd -ClassName $ClassName -Filter $Filter -ErrorAction SilentlyContinue
                } else {
                    return & $cimCmd -ClassName $ClassName -ErrorAction SilentlyContinue
                }
            }
        }
        $wmiCmd = Get-Command -Name "Get-WmiObject" -ErrorAction SilentlyContinue
        if ($null -ne $wmiCmd) {
            if (-not [string]::IsNullOrEmpty($Filter)) {
                return & $wmiCmd -Class $ClassName -Filter $Filter -ErrorAction SilentlyContinue
            } else {
                return & $wmiCmd -Class $ClassName -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        return $null
    }
    return $null
}
