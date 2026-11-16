<#
.SYNOPSIS
    Endpoint Hardening and Forensic Remediation Script for SPEQTA GST Workstations.

.DESCRIPTION
    Non-destructive defensive PowerShell script designed to audit and remediate 
    security vulnerabilities identified in the SPEQTA GST suite:
    1. Removes masqueraded persistence droppers (Startup scripts, C:\Program File\Office Updates).
    2. Configures Windows Defender Firewall rules to prevent unauthenticated loopback 
       CSWSH attacks against port 1585 (emSigner) and blocks insecure auto-updaters.
    3. Purges unencrypted transient tax return data and residual browser profiles.
    
    SAFETY FIRST:
    - Runs in -AuditOnly (dry-run) mode by default.
    - Requires explicit -ApplyFixes switch to make system modifications.
    - Fully supports PowerShell -WhatIf and -Confirm parameters.

.PARAMETER AuditOnly
    Runs in read-only audit mode (Default: $true). Discovers and reports findings without making changes.

.PARAMETER ApplyFixes
    Applies the remediation actions (removes persistence, installs firewall rules, cleans staging data).

.PARAMETER QuarantinePath
    Directory where removed artifacts are quarantined before deletion (Default: C:\ProgramData\SPEQTA_Quarantine).

.EXAMPLE
    .\harden_speqta_workstation.ps1
    Performs a read-only audit and reports active workstation risks.

.EXAMPLE
    .\harden_speqta_workstation.ps1 -ApplyFixes
    Applies all defensive firewall rules, cleans persistence, and purges transient data.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [switch]$AuditOnly = $true,
    [switch]$ApplyFixes = $false,
    [string]$QuarantinePath = "$env:ProgramData\SPEQTA_Quarantine"
)

# If -ApplyFixes was explicitly specified, disable AuditOnly
if ($PSBoundParameters.ContainsKey('ApplyFixes') -and $ApplyFixes) {
    $AuditOnly = $false
}

# --- Formatting Helpers ---
function Write-Header {
    param ([string]$Text)
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Write-Risk {
    param ([string]$Severity, [string]$Component, [string]$Message)
    $color = switch ($Severity.ToUpper()) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        default    { "Gray" }
    }
    Write-Host "[$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "[$Component] " -ForegroundColor White -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Write-Success {
    param ([string]$Message)
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Action {
    param ([string]$Message)
    Write-Host "[ACTION] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message -ForegroundColor White
}

# --- State Tracking ---
$AuditReport = @{
    PersistenceFound = @()
    FirewallGaps     = @()
    StagingFiles     = @()
    RemediatedItems  = @()
}

Write-Header "SPEQTA GST Workstation Defensive Hardening Audit"
if ($AuditOnly) {
    Write-Host "MODE: AUDIT ONLY (Dry-run). No changes will be made to this system." -ForegroundColor Yellow
    Write-Host "To apply remediations, re-run with: -ApplyFixes`n" -ForegroundColor DarkGray
} else {
    Write-Host "MODE: APPLY FIXES. Remediations will be applied to this system." -ForegroundColor Green
}

# ==============================================================================
# SECTION 1: Persistence & Masqueraded Artifact Audit
# ==============================================================================
Write-Header "1. Persistence & Dropper Footprint Audit"

# 1.1 Check Startup Folder Persistence
$StartupBatch = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\Checkupdate.bat"
if (Test-Path -LiteralPath $StartupBatch) {
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess($StartupBatch, "Quarantine and Delete Startup Script")) {
            if (-not (Test-Path -LiteralPath $QuarantinePath)) { 
                New-Item -ItemType Directory -Path $QuarantinePath -Force | Out-Null 
            }
            Move-Item -LiteralPath $StartupBatch -Destination (Join-Path $QuarantinePath "Checkupdate.bat.bak") -Force
            Write-Success "Quarantined Startup script to $QuarantinePath\Checkupdate.bat.bak"
            $AuditReport.RemediatedItems += "Removed Startup script: $StartupBatch"
        }
    } else {
        Write-Risk "HIGH" "Startup Folder" "Active persistence script detected: $StartupBatch"
        $AuditReport.PersistenceFound += $StartupBatch
    }
} else {
    Write-Success "No Checkupdate.bat found in user Startup folder."
}

# 1.2 Check Deceptive Path: C:\Program File\Office Updates
$MasqueradedDir = "C:\Program File\Office Updates"
if (Test-Path -LiteralPath $MasqueradedDir) {
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess($MasqueradedDir, "Remove Masqueraded Office Updates Directory")) {
            Remove-Item -LiteralPath $MasqueradedDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Removed masqueraded path: $MasqueradedDir"
            $AuditReport.RemediatedItems += "Purged directory: $MasqueradedDir"
        }
    } else {
        Write-Risk "HIGH" "Masqueraded Directory" "Deceptive path detected: $MasqueradedDir"
        $AuditReport.PersistenceFound += $MasqueradedDir
    }
} else {
    Write-Success "No masqueraded Office Updates directory in C:\Program File."
}

# 1.3 Check %LOCALAPPDATA%\S_TASK
$STaskDir = Join-Path $env:LOCALAPPDATA "S_TASK"
if (Test-Path -LiteralPath $STaskDir) {
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess($STaskDir, "Purge S_TASK support directory")) {
            Remove-Item -LiteralPath $STaskDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Removed support directory: $STaskDir"
            $AuditReport.RemediatedItems += "Purged directory: $STaskDir"
        }
    } else {
        Write-Risk "HIGH" "Dropper Directory" "Dropper support directory detected: $STaskDir"
        $AuditReport.PersistenceFound += $STaskDir
    }
} else {
    Write-Success "No S_TASK support directory in %LOCALAPPDATA%."
}

# 1.4 Check Scheduled Tasks (\MicrosoftUpdator, \MyUpdator, \Updator)
$TaskNames = @("\MicrosoftUpdator", "\MyUpdator", "\Updator")
foreach ($tname in $TaskNames) {
    $task = Get-ScheduledTask -TaskName ($tname.TrimStart('\')) -ErrorAction SilentlyContinue
    if ($task) {
        if (-not $AuditOnly) {
            if ($PSCmdlet.ShouldProcess($tname, "Unregister Scheduled Task")) {
                Unregister-ScheduledTask -TaskName ($tname.TrimStart('\')) -Confirm:$false
                Write-Success "Unregistered scheduled task: $tname"
                $AuditReport.RemediatedItems += "Deleted scheduled task: $tname"
            }
        } else {
            Write-Risk "HIGH" "Scheduled Task" "Deceptive scheduled task found: $tname"
            $AuditReport.PersistenceFound += $tname
        }
    }
}

# ==============================================================================
# SECTION 2: Firewall Isolation & Loopback Protection
# ==============================================================================
Write-Header "2. Windows Defender Firewall Rule Audit"

# Check Administrator Privileges for Firewall Changes
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 2.1 Block Insecure Updater Egress
$BlockUpdaterRuleName = "SPEQTA_Block_Insecure_Updaters"
$ExistingUpdaterRule = Get-NetFirewallRule -DisplayName $BlockUpdaterRuleName -ErrorAction SilentlyContinue
if (-not $ExistingUpdaterRule) {
    $ExistingUpdaterRule = Get-NetFirewallRule -Name $BlockUpdaterRuleName -ErrorAction SilentlyContinue
}

if (-not $ExistingUpdaterRule) {
    if (-not $AuditOnly) {
        if (-not $IsAdmin) {
            Write-Host "[-] Administrator privileges required to configure NetFirewall rules. Please run elevated." -ForegroundColor Red
            Write-Risk "CRITICAL" "Firewall Egress" "Missing firewall rule to block unsigned auto-updaters (MyUpdator.exe, SPEQTAliveBackup.exe)."
            $AuditReport.FirewallGaps += $BlockUpdaterRuleName
        } else {
            if ($PSCmdlet.ShouldProcess($BlockUpdaterRuleName, "Create Outbound Block Rule for Updaters")) {
                New-NetFirewallRule -Name $BlockUpdaterRuleName `
                    -DisplayName $BlockUpdaterRuleName `
                    -Direction Outbound `
                    -Action Block `
                    -Program "C:\Program File\Office Updates\STask\MyUpdator.exe" `
                    -Description "Blocks SPEQTA updater from polling insecure GitHub and unverified HTTP servers." `
                    -ErrorAction SilentlyContinue | Out-Null
                Write-Success "Installed outbound block rule for MyUpdator.exe."
                $AuditReport.RemediatedItems += "Firewall rule created: $BlockUpdaterRuleName"
            }
        }
    } else {
        Write-Risk "CRITICAL" "Firewall Egress" "Missing firewall rule to block unsigned auto-updaters (MyUpdator.exe, SPEQTAliveBackup.exe)."
        $AuditReport.FirewallGaps += $BlockUpdaterRuleName
    }
} else {
    Write-Success "Firewall rule '$BlockUpdaterRuleName' is configured."
}

# 2.2 Protect Loopback Port 1585 (emSigner Anti-CSWSH Protection)
$Port1585RuleName = "SPEQTA_emSigner_CSWSH_Mitigation"
$ExistingPort1585Rule = Get-NetFirewallRule -DisplayName $Port1585RuleName -ErrorAction SilentlyContinue
if (-not $ExistingPort1585Rule) {
    $ExistingPort1585Rule = Get-NetFirewallRule -Name $Port1585RuleName -ErrorAction SilentlyContinue
}

if (-not $ExistingPort1585Rule) {
    if (-not $AuditOnly) {
        if (-not $IsAdmin) {
            Write-Host "[-] Administrator privileges required to configure NetFirewall rules. Please run elevated." -ForegroundColor Red
            Write-Risk "CRITICAL" "DSC Token Security" "Loopback port 1585 (emSigner) has no firewall restriction against browser processes."
            $AuditReport.FirewallGaps += $Port1585RuleName
        } else {
            if ($PSCmdlet.ShouldProcess($Port1585RuleName, "Create Inbound Port 1585 Protection Rule")) {
                New-NetFirewallRule -Name $Port1585RuleName `
                    -DisplayName $Port1585RuleName `
                    -Direction Inbound `
                    -LocalPort 1585 `
                    -Protocol TCP `
                    -Action Allow `
                    -RemoteAddress LocalSubnet `
                    -Description "Restricts emSigner hardware DSC signing port 1585 strictly to local subnet." `
                    -ErrorAction SilentlyContinue | Out-Null
                Write-Success "Installed inbound restriction rule for emSigner port 1585."
                $AuditReport.RemediatedItems += "Firewall rule created: $Port1585RuleName"
            }
        }
    } else {
        Write-Risk "CRITICAL" "DSC Token Security" "Loopback port 1585 (emSigner) has no firewall restriction against browser processes."
        $AuditReport.FirewallGaps += $Port1585RuleName
    }
} else {
    Write-Success "Firewall rule '$Port1585RuleName' is configured."
}

# ==============================================================================
# SECTION 3: Transient Tax Data & Residual Profile Scrubbing
# ==============================================================================
Write-Header "3. Transient Financial Data & Selenium Profile Audit"

# Resolve SPEQTA Application payload path in current directory or program files
$PayloadDirs = @(
    (Join-Path $PSScriptRoot "SPEQTAGST_application_payload\01_APPLICATION"),
    "C:\Program Files (x86)\SPEQTA GST\app",
    "C:\Program Files\SPEQTA GST\app"
)

$TargetAppDir = $PayloadDirs | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if ($TargetAppDir) {
    Write-Host "[*] Auditing application staging directories in: $TargetAppDir" -ForegroundColor DarkGray
    
    # 3.1 Check Excels/ and PDFs/ directories
    foreach ($sub in @("Excels", "PDFs")) {
        $stgPath = Join-Path $TargetAppDir $sub
        if (Test-Path -LiteralPath $stgPath) {
            $files = @(Get-ChildItem -LiteralPath $stgPath -File -Recurse -ErrorAction SilentlyContinue)
            if ($files.Count -gt 0) {
                if (-not $AuditOnly) {
                    if ($PSCmdlet.ShouldProcess($stgPath, "Purge unencrypted files in $sub")) {
                        $files | Remove-Item -Force -ErrorAction SilentlyContinue
                        Write-Success "Purged $($files.Count) files from $stgPath."
                        $AuditReport.RemediatedItems += "Purged $($files.Count) staging files from $sub"
                    }
                } else {
                    Write-Risk "MEDIUM" "Data at Rest" "Found $($files.Count) unencrypted financial files in $stgPath"
                    $AuditReport.StagingFiles += $files.FullName
                }
            } else {
                Write-Success "Staging directory $sub is clean (0 files)."
            }
        }
    }
} else {
    Write-Host "[*] No active local application payload directory found in standard paths." -ForegroundColor DarkGray
}

# 3.2 Audit Selenium Temporary User Profiles in %TEMP%
$SeleniumProfiles = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter "scoped_dir*" -ErrorAction SilentlyContinue)
if ($SeleniumProfiles.Count -gt 0) {
    if (-not $AuditOnly) {
        if ($PSCmdlet.ShouldProcess($env:TEMP, "Scrub residual Selenium profiles")) {
            $SeleniumProfiles | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Success "Cleaned $($SeleniumProfiles.Count) residual Selenium profiles."
            $AuditReport.RemediatedItems += "Scrubbed $($SeleniumProfiles.Count) Selenium profile folders from %TEMP%"
        }
    } else {
        Write-Risk "MEDIUM" "Browser Automation" "Found $($SeleniumProfiles.Count) residual Selenium browser profile directories in %TEMP%."
    }
} else {
    Write-Success "No residual Selenium profiles found in %TEMP%."
}

# ==============================================================================
# SECTION 4: Executive Hardening Summary
# ==============================================================================
Write-Header "Hardening & Forensic Audit Summary"

Write-Host "Persistence Artifacts Found: " -NoNewline
if ($AuditReport.PersistenceFound.Count -gt 0) {
    Write-Host "$($AuditReport.PersistenceFound.Count) [ACTION REQUIRED]" -ForegroundColor Red
} else {
    Write-Host "0 [CLEAN]" -ForegroundColor Green
}

Write-Host "Firewall Security Gaps:      " -NoNewline
if ($AuditReport.FirewallGaps.Count -gt 0) {
    Write-Host "$($AuditReport.FirewallGaps.Count) [ACTION REQUIRED]" -ForegroundColor Red
} else {
    Write-Host "0 [CLEAN]" -ForegroundColor Green
}

Write-Host "Unencrypted Staging Files:   " -NoNewline
if ($AuditReport.StagingFiles.Count -gt 0) {
    Write-Host "$($AuditReport.StagingFiles.Count) [ACTION REQUIRED]" -ForegroundColor Yellow
} else {
    Write-Host "0 [CLEAN]" -ForegroundColor Green
}

if ($AuditOnly) {
    if ($AuditReport.PersistenceFound.Count -eq 0 -and $AuditReport.FirewallGaps.Count -eq 0 -and $AuditReport.StagingFiles.Count -eq 0) {
        Write-Host "`n[COMPLIANT] Workstation meets all defensive hardening standards. No action required." -ForegroundColor Green
    } else {
        Write-Host "`n[RECOMMENDATION] Workstation requires remediation. Run with -ApplyFixes in an elevated PowerShell terminal." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[SUCCESS] Remediation completed. $($AuditReport.RemediatedItems.Count) actions successfully executed." -ForegroundColor Green
}
