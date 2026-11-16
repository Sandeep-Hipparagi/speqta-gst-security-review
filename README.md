# SPEQTA GST (v1.1.1.74) Security Assessment & Architectural Review
### Master Project Documentation Index & Host Hardening Guide

[![Target: SPEQTA GST](https://img.shields.io/badge/Target-SPEQTA%20GST%20v1.1.1.74-blue.svg)](./SPEQTA_GST_Comprehensive_System_Review.md)
[![Platform: .NET Framework 4.8](https://img.shields.io/badge/Platform-.NET%20Framework%204.8-purple.svg)](./GSP_SERVICE_CONTRACTS.md)
[![Status: Assessment Complete](https://img.shields.io/badge/Status-Assessment%20Complete-brightgreen.svg)](./EXECUTIVE_RISK_AND_ARCHITECTURE_SUMMARY.md)
[![Remediation: Script Available](https://img.shields.io/badge/Remediation-harden__speqta__workstation.ps1-orange.svg)](./harden_speqta_workstation.ps1)

---

## 1. Executive Summary & Assessment Overview

This repository contains the complete static reverse-engineering, supply-chain triage, cryptographic audit, and defensive endpoint hardening deliverables for **SPEQTA GST (Enterprise Release v1.1.1.74)**.

SPEQTA GST is an enterprise Goods and Services Tax (GST) filing, reconciliation, and compliance solution widely deployed across accounting and taxation workstations in India. The application encapsulates:
* **Direct GSP (GST Suvidha Provider) Integrations:** REST API gateways for automated tax return uploads and ledger synchronizations.
* **Portal UI & Automation Drivers:** Browser automation against `return.gst.gov.in` and automated WhatsApp Web dispatching via Selenium.
* **Hardware Digital Signature Certificate (DSC) Signers:** Integration with USB cryptographic tokens via a local loopback WebSocket service (`emSigner`).
* **Offline Database Management:** Local storage using encrypted SQLite repositories (`GSTINDBMS.db` and `MasterDBMS.db`).

### High-Level Assessment Conclusion
The evaluation was conducted strictly through **non-intrusive static reverse engineering and read-only inspection** without executing vendor binaries or attempting to bypass commercial protection layers. The audit identified **critical architectural and supply-chain vulnerabilities**, including:
1. **Remote Code Execution (RCE) via Unsigned Updates:** Automatic updates and configuration feeds retrieved over standard TLS without cryptographic binary signatures or checksum verification, coupled with a hardcoded dependency on an untrusted personal GitHub repository (`G777007/Checkupdate`).
2. **Local Privilege Escalation (LPE) via Unquoted Service Paths:** Dropper script `WebServer.bat` creates a rogue directory at `C:\Program File\Office Updates\Office.exe` exploiting unquoted path ambiguities against standard system services.
3. **Cross-Site WebSocket Hijacking (CSWSH) on Hardware DSC:** Unauthenticated localhost listener (`ws://127.0.0.1:1585`) lacking origin validation, allowing malicious web scripts to sign tax payloads using attached hardware USB tokens.
4. **Credential Exposure in Transit & at Rest:** GSP credentials passed as cleartext URL query parameters; tax returns staged in unencrypted Excel/PDF files and residual browser profile caches.

Defenders and workstation administrators must immediately execute the provided endpoint hardening script ([harden_speqta_workstation.ps1](./harden_speqta_workstation.ps1)) to mitigate active risks.

---

## 2. Deliverables & Documentation Roadmap

The assessment findings are organized into five comprehensive technical deliverables and one automated remediation tool.

| # | Deliverable Document | Target Audience | Primary Focus & Key Findings |
|---|----------------------|-----------------|------------------------------|
| **1** | [**EXECUTIVE_RISK_AND_ARCHITECTURE_SUMMARY.md**](./EXECUTIVE_RISK_AND_ARCHITECTURE_SUMMARY.md) | CISO, CTO, Risk & Compliance, Enterprise Architects | **Consolidated Executive Blueprint & Risk Matrix:** End-to-end Mermaid system architecture; prioritized vulnerability rankings (Critical, High, Medium); business impact modeling; enterprise defensive roadmap. |
| **2** | [**SECURITY_TRIAGE_REPORT.md**](./SECURITY_TRIAGE_REPORT.md) | SOC Analysts, Incident Responders, SecOps | **Supply-Chain & Persistence Forensics:** Analysis of `WebServer.bat` living-off-the-land techniques; unquoted `C:\Program File` path flaw; personal GitHub repository dependency; unsigned updater binaries (`SPEQTAliveBackup.exe`, `MyUpdator.exe`); embedded remote support tools (RustDesk, AnyDesk). |
| **3** | [**GSP_SERVICE_CONTRACTS.md**](./GSP_SERVICE_CONTRACTS.md) | Backend Engineers, API Architects, AppSec Auditors | **Unobfuscated Service Layer & DTO Extraction:** Complete schema catalog for 162 types in `GspServer.dll`; GSP auth flows; return upload contracts (GSTR-1, 3B, 9); ledger inquiry endpoints; query-parameter credential exposure; hardcoded fallback keys (`SpeqtaGstnEncrKey2019!#`). |
| **4** | [**AUTOMATION_AND_DSC_REVIEW.md**](./AUTOMATION_AND_DSC_REVIEW.md) | SecOps, Automation Engineers, Identity & PKI Leads | **Browser Automation & Hardware DSC Signing:** Hardware USB token communication over loopback `ws://127.0.0.1:1585` (`emSigner`); CSWSH risks; Selenium WebDriver (`WinAppAutom.dll`) portal workflow; OTP/CAPTCHA handling; unencrypted staging; embedded `WAPI.js` WhatsApp automation. |
| **5** | [**SPEQTA_GST_Comprehensive_System_Review.md**](./SPEQTA_GST_Comprehensive_System_Review.md) | Software Architects, Reverse Engineers, QA Leads | **Deep System & Storage Architecture:** Inno Setup 6.3.0 container dissection; multi-stage payload layout; CefSharp (CEF v84) WinForms host; SQLite dual-database structure (`GSTINDBMS.db`, `MasterDBMS.db`); custom table-level RC4/XOR obfuscation. |
| **6** | [**harden_speqta_workstation.ps1**](./harden_speqta_workstation.ps1) | Systems Administrators, Endpoint SecOps, IT Support | **Automated Endpoint Hardening Script:** Native PowerShell script implementing non-destructive audits (`-AuditOnly`) and automated remediation (`-ApplyFixes`) for persistence, firewall boundaries, staging directories, and browser profiles. |

---

## 3. Quick Start: Remediation & Hardening Runbook

The companion script [harden_speqta_workstation.ps1](./harden_speqta_workstation.ps1) automates verification and remediation across all identified host risks.

### Mode 1: Non-Destructive Audit (`-AuditOnly`)
Executes a read-only compliance scan across persistence locations, firewall policies, residual staging directories, and temporary browser profiles without modifying system state.

```powershell
# Run from PowerShell (Standard User or Administrator)
powershell.exe -ExecutionPolicy Bypass -File ".\harden_speqta_workstation.ps1" -AuditOnly
```

**Checks Performed:**
* **Persistence Check:** Inspects `C:\Program File\Office Updates\`, `%LOCALAPPDATA%\S_TASK\`, startup scripts (`Checkupdate.bat`), and registry keys (`\Microsoft\Windows\CurrentVersion\Run\Updator`).
* **Firewall Boundary Check:** Checks whether outbound block rules exist for `MyUpdator.exe` and `SPEQTAliveBackup.exe`, and verifies loopback port `1585` boundary protection.
* **Staging Directory Check:** Audits `01_APPLICATION\Excels\` and `01_APPLICATION\PDFs\` for unencrypted taxpayer financial records.
* **Browser Profile Check:** Scans `%TEMP%` for residual Selenium browser profiles (`scoped_dir*`).

---

### Mode 2: Automated Remediation (`-ApplyFixes`)
Remediates discovered vulnerabilities. Note: Applying firewall rules requires an elevated PowerShell prompt.

```powershell
# Run from an Elevated (Run as Administrator) PowerShell Prompt
powershell.exe -ExecutionPolicy Bypass -File ".\harden_speqta_workstation.ps1" -ApplyFixes
```

**Actions Executed:**
1. **Quarantine Persistence Artifacts:** Deletes rogue startup scripts (`Checkupdate.bat`), removes unauthorized scheduled tasks (`\MicrosoftUpdator`, `\MyUpdator`, `\Updator`), and cleans `C:\Program File\Office Updates\`.
2. **Apply Windows Firewall Restrictions:**
   * Creates outbound firewall block rules preventing `MyUpdator.exe` and `SPEQTAliveBackup.exe` from contacting external GitHub or update endpoints.
   * Restricts inbound loopback connections on TCP port `1585` (`emSigner`) to block unauthorized web browsers (`chrome.exe`, `msedge.exe`).
3. **Purge Residual Taxpayer Staging:** Deletes unencrypted `.xlsx` and `.pdf` files from `01_APPLICATION\Excels\` and `01_APPLICATION\PDFs\`.
4. **Purge Leaked Browser Sessions:** Recursively purges all orphaned Selenium profile directories (`scoped_dir*`) from `%TEMP%`.

> [!IMPORTANT]
> **Elevation Requirement:** Standard user execution will successfully clean user-space files, temporary directories, and user-level startup scripts. However, configuring `New-NetFirewallRule` for loopback port 1585 and updater binaries requires administrative elevation (`Run as Administrator`).

---

## 4. Host Remediation Verification Log

A verification run was executed against the analysis workstation following non-destructive inspection and user-space remediation:

| Remediation Category | Initial Status | Post-Remediation Status | Verification Notes |
|----------------------|----------------|-------------------------|--------------------|
| **Persistence Artifacts** | Clean (0 detected) | **0 [CLEAN]** | No rogue scheduled tasks, startup scripts, or `C:\Program File` directories present. |
| **Unencrypted Staging Files** | 2 exposed files | **0 [CLEAN]** | Staged `.xlsx` and `.pdf` files inside `01_APPLICATION\Excels\` and `PDFs\` wiped. |
| **Residual Selenium Profiles** | 86 profile dirs | **0 [CLEAN]** | All 86 `scoped_dir*` directories in `%TEMP%` successfully purged. |
| **Firewall Isolation Rules** | Missing (2 gaps) | **Action Required (Elevated)** | Script logged elevation requirement; pending administrator execution of `-ApplyFixes`. |

---

## 5. Workspace Disk Footprint & Archival Guidance

The complete unpacked analysis workspace occupies **~777 MB** across application binaries, decompiled assets, and harvested artifacts.

### Disk Footprint Breakdown
```
speqta-gst-security-review/
├── SPEQTAGST.exe                      ~150.3 MB   (Original Inno Setup installer container)
├── SPEQTAGST_application_payload\     ~449.2 MB   (91 extracted payload binaries & runtime libraries)
│   ├── CefSharp runtime (libcef.dll)  ~138.0 MB   (Chromium Embedded Framework)
│   ├── SPEQTAGST.exe (Main binary)    ~122.6 MB   (.NET WinForms executable)
│   ├── Selenium Drivers               ~42.0 MB    (chromedriver.exe, msedgedriver.exe)
│   └── GspServer.dll & Dependencies   ~146.6 MB   (Supporting business assemblies)
├── rea\                               ~104.3 MB   (9,092 files, REA reverse engineering toolkit)
├── SPEQTAGST_unlocked_analysis\       ~65.7 MB    (1,557 harvested string dumps & PE metadata files)
├── Analysis Reports & Hardening (.md) ~0.1 MB     (5 comprehensive deliverables + README.md)
└── Scratch / Log Artifacts            ~9.3 MB     (out.log, temporary inspection scripts)
```

### Post-Assessment Archival Runbook
Once stakeholders and security teams have signed off on the assessment deliverables, local workstation disk space can be reclaimed:

```powershell
# 1. Clean immediate transient logs and scratch files (~9.3 MB)
Remove-Item -Path "out.log", "err.log", "stderr.log", "mcp_request*.json", "analyze_pe*.py", "check_pe.ps1", "extract_strings.ps1", "simple_strings.ps1" -ErrorAction SilentlyContinue

# 2. Archive extracted payload and strings to cold storage (Optional)
Compress-Archive -Path "SPEQTAGST_application_payload", "SPEQTAGST_unlocked_analysis" -DestinationPath "SPEQTA_GST_v1.1.1.74_Forensics_Archive.zip"
Remove-Item -Recurse -Force "SPEQTAGST_application_payload", "SPEQTAGST_unlocked_analysis"

# 3. Clean REA git clone if no longer needed (~104 MB)
Remove-Item -Recurse -Force "rea"
```

> [!TIP]
> The five Markdown reports and `harden_speqta_workstation.ps1` contain complete API schemas, IOC lists, and architectural diagrams. They can be preserved independently in version control at negligible disk cost (<1 MB).

---

## 6. Compliance, Legal & Ethical Disclosure Note

* **Defensive Purpose Only:** This assessment was conducted exclusively for defensive triage, threat modeling, and endpoint hardening.
* **Non-Executing Analysis:** No vendor binaries were executed during the analysis phase. All findings were derived from static binary inspection, PE metadata extraction, IL disassembly, and string harvesting.
* **No Circumvention:** The analysis did not tamper with, patch, or bypass software licensing or obfuscation mechanisms.
* **Responsible Handling:** Identified indicators of compromise, third-party GitHub repository references, and unencrypted transmission vectors should be handled under responsible vulnerability management protocols in accordance with organizational policies.

---
*Generated by Antigravity Defensive Architecture & Forensics Group.*  
*Target Release: SPEQTA GST v1.1.1.74 | Analysis Date: November 2026*
