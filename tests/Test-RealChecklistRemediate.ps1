# ==============================================================================
# File: Test-RealChecklistRemediate.ps1
# Description: End-to-End Live Verification of Remediate and Rollback engines
#              using the real CIS Benchmark checklist on Windows Server 2008 R2.
# Compatibility: PowerShell 2.0+
# ==============================================================================

[CmdletBinding()]
param(
    [string]$AuditReport = "C:\Users\vagrant\HardeningNCS\outputs\audit_report_20261009_011408.csv",
    [string]$FindingList = "C:\Users\vagrant\HardeningNCS\lists\CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.1.csv"
)

# 1. Filter out Windows Firewall rules to preserve remote SSH connectivity
$filteredReport = "C:\Users\vagrant\HardeningNCS\outputs\audit_report_real_filtered.csv"
$rows = @(Import-Csv -Path $AuditReport | Where-Object { $_.Category -ne "Windows Firewall" })
$rows | Export-Csv -Path $filteredReport -NoTypeInformation

Write-Host "Filtered report created with $($rows.Count) real CIS rules (excluded Firewall to protect SSH connection)." -ForegroundColor Cyan

# 2. Query sample pre-remediation values from live registry
$keysToMonitor = @(
    @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "LMCompatibilityLevel"; CIS_Rec = 5; ID = "2.3.11.7" },
    @{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "RequireSecuritySignature"; CIS_Rec = 1; ID = "2.3.8.1" },
    @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; CIS_Rec = 1; ID = "2.3.10.3" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun"; CIS_Rec = 255; ID = "18.9.8.3" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; CIS_Rec = 2; ID = "2.3.17.2" }
)

Write-Host "`n--- PRE-REMEDIATION BASELINE VALUES ---" -ForegroundColor Yellow
foreach ($km in $keysToMonitor) {
    $prop = Get-ItemProperty -Path $km.Path -Name $km.Name -ErrorAction SilentlyContinue
    $val = if ($null -ne $prop) { $prop.$($km.Name) } else { "<NOT_CONFIGURED>" }
    Write-Host "  [$($km.ID)] $($km.Path)\$($km.Name) : Current=$val | CIS Recommended=$($km.CIS_Rec)"
}

# 3. Execute Remediation on real CIS rules
Write-Host "`n--- EXECUTING REAL REMEDIATION (Remediate-LegacyWin.ps1) ---" -ForegroundColor Cyan
& "C:\Users\vagrant\HardeningNCS\src\Remediate-LegacyWin.ps1" -AuditReport $filteredReport -FindingList $FindingList

# Locate latest manifest
$latestManifest = Get-ChildItem -Path "C:\Users\vagrant\HardeningNCS\outputs\backup_session_*\backup_manifest.txt" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($null -eq $latestManifest) {
    Write-Error "Remediation failed to produce backup manifest!"
    exit 1
}

Write-Host "`nLatest Backup Manifest: $($latestManifest.FullName)" -ForegroundColor Green

# 4. Query post-remediation values from live registry
Write-Host "`n--- POST-REMEDIATION VERIFIED VALUES ---" -ForegroundColor Yellow
foreach ($km in $keysToMonitor) {
    $prop = Get-ItemProperty -Path $km.Path -Name $km.Name -ErrorAction SilentlyContinue
    $val = if ($null -ne $prop) { $prop.$($km.Name) } else { "<NOT_CONFIGURED>" }
    $isMatch = ($val -eq $km.CIS_Rec)
    $color = if ($isMatch) { "Green" } else { "Red" }
    Write-Host "  [$($km.ID)] $($km.Path)\$($km.Name) : Value=$val | Match Recommended? $isMatch" -ForegroundColor $color
}

# 5. Execute Rollback to restore the system
Write-Host "`n--- EXECUTING FULL ROLLBACK (Rollback-LegacyWin.ps1) ---" -ForegroundColor Cyan
& "C:\Users\vagrant\HardeningNCS\src\Rollback-LegacyWin.ps1" -ManifestFile $latestManifest.FullName

# 6. Query post-rollback values from live registry
Write-Host "`n--- POST-ROLLBACK RESTORED VALUES ---" -ForegroundColor Yellow
foreach ($km in $keysToMonitor) {
    $prop = Get-ItemProperty -Path $km.Path -Name $km.Name -ErrorAction SilentlyContinue
    $val = if ($null -ne $prop) { $prop.$($km.Name) } else { "<NOT_CONFIGURED>" }
    Write-Host "  [$($km.ID)] $($km.Path)\$($km.Name) : RestoredValue=$val" -ForegroundColor Cyan
}

Write-Host "`n================ FULL END-TO-END REMEDIATION & ROLLBACK TEST COMPLETED ================" -ForegroundColor Green
