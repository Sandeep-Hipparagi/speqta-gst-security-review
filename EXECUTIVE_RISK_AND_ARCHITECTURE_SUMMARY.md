# Executive Architecture & Risk Assessment: SPEQTA GST

> **Target System:** SPEQTA GST Compliance Suite (SPEQTA TAXSOFT AND COMPLIANCE LLP)  
> **Package Analyzed:** Version 1.1.1.74 (`SPEQTAGST.exe` installer payload)  
> **Review Scope:** Enterprise Architecture, Cryptographic Signing, Automation, Supply Chain, and Endpoint Hardening  
> **Synthesis Base:**  
> - `SPEQTA_GST_Comprehensive_System_Review.md` (System Architecture & SQLite Model)  
> - `SECURITY_TRIAGE_REPORT.md` (Persistence, Droppers, & Supply-Chain Endpoints)  
> - `GSP_SERVICE_CONTRACTS.md` (Unobfuscated Service Layer & GSP API Contracts)  
> - `AUTOMATION_AND_DSC_REVIEW.md` (Hardware DSC Signing & Browser Automation)  
> **Date:** November 2026  
> **Overall Security Posture:** **HIGH RISK / CRITICAL VULNERABILITIES IDENTIFIED**  

---

## 1. System Architecture Synthesis (End-to-End Blueprint)

SPEQTA GST is an enterprise tax filing solution combining a traditional Windows desktop shell, embedded Chromium rendering, local encrypted database storage, hardware cryptographic token signing, direct GSP API integration, and automated Selenium-driven portal interactions.

### 1.1 Unified Architecture Blueprint

The diagram below connects all six verified operational subsystems, mapping the complete data lifecycle from local ingestion to government certification:

```mermaid
flowchart TB
    subgraph Packaging ["1. Packaging & Delivery Layer"]
        EXE["SPEQTAGST.exe (150.3 MB Single Executable)"] --> INNO["Inno Setup 6.3.0 Loader (Delphi PE32)"]
        INNO -->|LZMA Decompress| PAYLOAD["93 Shipped Application Files (~450 MB)"]
    end

    subgraph DesktopShell ["2. Presentation & Local Persistence Subsystem"]
        PAYLOAD --> MAIN["SPEQTAGST.exe (.NET Framework 4.x WinForms Main Shell)"]
        MAIN --> BUNIFU["Bunifu UI v1.5.3 (437 Form Interfaces)"]
        MAIN --> CEF["Embedded Chromium (CefSharp / libcef.dll 138 MB)"]
        MAIN --> SQLITE_ENG["System.Data.SQLite.dll / SQLite.Interop"]
        SQLITE_ENG --> DB1[("GSTINDBMS.db (Client Returns - Encrypted)")]
        SQLITE_ENG --> DB2[("MasterDBMS.db (Rates & Codes - Encrypted)")]
        SQLITE_ENG -.->|Static 16-byte IV Vulnerability| DB_LEAK["Known Cryptographic Weakness"]
    end

    subgraph DirectAPI ["3. Direct GSP API Client (GspServer.dll)"]
        MAIN --> GSP_CLIENT["GspServer.dll (Unobfuscated Client Layer)"]
        GSP_CLIENT --> AUTH_SVC["IAuthService (SentOTP / VerifyOTP / RefreshToken)"]
        GSP_CLIENT --> GSTR1_SVC["IGSTR1Service (v2.2 RetSave / B2B / E-Invoice)"]
        GSP_CLIENT --> GSTR2A_SVC["IGSTR2AService (v2.0 Inward Supplies / 2B Match)"]
        GSP_CLIENT --> GSTR3B_SVC["IGSTR3BService (v0.3/v2.0 AutoLiab / Summary)"]
        GSP_CLIENT --> GSTR9_SVC["IGSTR9Service (v1.1 Annual Reconciliation)"]
        GSP_CLIENT --> GSP_UTIL["GspServer.Util (HttpWebRequest Wrapper)"]
        GSP_UTIL -->|HTTPS Query-Param Handshake| GSP_GW["External GSP Cloud Gateway"]
        GSP_GW --> GSTN_API["GSTN Government Gateway"]
    end

    subgraph BrowserAuto ["4. Browser & Messaging Automation (WinAppAutom.dll)"]
        MAIN --> AUTO_ENGINE["WinAppAutom.dll (Speqta.AutoTool.CBrowser)"]
        AUTO_ENGINE --> DRV_CHROME["chromedriver.exe (v155)"]
        AUTO_ENGINE --> DRV_EDGE["msedgedriver.exe (v155)"]
        AUTO_ENGINE --> DRV_IE["IEDriverServer.exe (v3.150)"]
        AUTO_ENGINE --> CDP["CdpCookieClient (Chrome DevTools Protocol)"]
        DRV_CHROME & DRV_EDGE -->|Selenium WebDriver Navigation| GOV_PORTAL["return.gst.gov.in (Official Portal)"]
        AUTO_ENGINE --> WAPI["Embedded WAPI.js (WhatsApp Web Automation)"]
        WAPI -->|Automated Client Dispatch| WHATSAPP["web.whatsapp.com"]
    end

    subgraph DSCSigning ["5. Hardware DSC Signing Subsystem"]
        MAIN --> DSC_TOOL["Proactive.CustomTools.dll (DSCSign)"]
        DSC_TOOL --> CANON["SignJsonClass.JSON_Sort (Deterministic Ordering)"]
        CANON --> HASH["ComputeHashSHA256 (SHA-256 Digest)"]
        HASH --> WS_CLIENT["websocket-sharp.dll"]
        WS_CLIENT <-->|ws://127.0.0.1:1585 (Unauthenticated IPC)| EMSIGNER["emSigner Service (Localhost Listener)"]
        EMSIGNER <-->|PKCS#11 Hardware Token Call| USB_TOKEN["Physical USB Token (SafeNet / eToken)"]
    end

    subgraph MaintenanceInfra ["6. Persistence, Update & Support Infrastructure"]
        PAYLOAD --> WEB_BAT["WebServer.bat (Dropper & Persistence Script)"]
        WEB_BAT -->|Masqueraded Drop| UPD_PATH["C:\\Program File\\Office Updates\\STask\\MyUpdator.exe"]
        WEB_BAT -->|Startup Autostart| STARTUP_BAT["%APPDATA%\\...\\Startup\\Checkupdate.bat"]
        WEB_BAT -->|Anti-Forensic Wipe| DELME["%TEMP%\\_delme.bat"]
        UPD_PATH -->|HTTPS Config Poll| VENDOR_CFG["server2.speqtagst.com/liveproject/api/speqtaconfig.json"]
        PAYLOAD --> LIVE_BACKUP["SPEQTAliveBackup.exe (Namespace: SPEQTAliveUpdate)"]
        LIVE_BACKUP -->|Unauthenticated GitHub Poll| GIT_REPO["raw.githubusercontent.com/G777007/Checkupdate/version.txt"]
        LIVE_BACKUP -->|Remote Desktop Staging| RUSTDESK["DownloadFileToRustDeskConfig -> %APPDATA%\\RustDesk"]
        PAYLOAD --> ANYDESK["AnyDesk.exe (5.3 MB Bundled Remote Desktop)"]
    end
```

---

## 2. Consolidated Risk Matrix

The table below ranks the verified architectural and supply-chain vulnerabilities discovered across all static analysis phases, prioritized by severity, attack feasibility, and enterprise impact:

| # | Severity | Finding & Component | Vulnerability Class / ATT&CK | Exploit Scenario & Business Impact | Remediation Priority |
|---|---|---|---|---|---|
| **1** | **CRITICAL** | **Unauthenticated Remote Code Execution via Update Hijack**<br>`MyUpdator.exe` & `SPEQTAliveBackup.exe` | **T1195.002** (Supply Chain Compromise: Compromise Software Supply Chain)<br>**CWE-494** (Download of Code Without Integrity Check) | **Exploit Scenario:** Neither updater performs Authenticode digital signature validation, SHA-256 hash checking, or TLS certificate pinning. An attacker intercepting traffic or compromising `server2.speqtagst.com` or GitHub account `G777007` can deliver a malicious ZIP archive, which is unpacked and executed directly via `Process.Start`.<br>**Impact:** Complete host takeover with full user rights. | **Immediate (P0)** |
| **2** | **CRITICAL** | **Unauthorized Legal Signing via Localhost WebSocket IPC**<br>`Proactive.CustomTools.dll` & `emSigner` (`127.0.0.1:1585`) | **T1556** (Modify Authentication Process)<br>**CWE-306** (Missing Authentication for Critical Function)<br>**CWE-346** (Origin Validation Error) | **Exploit Scenario:** Port 1585 is an unauthenticated WebSocket listener. While a user has their physical USB token connected and has entered their PIN, any unprivileged local process or external malicious website (via Cross-Site WebSocket Hijacking) can send a `{"action":"sign", "hash":..., "pan":...}` request to obtain legally binding signatures.<br>**Impact:** Forged GST returns, fraudulent financial disclosures, or unauthorized legal documents signed under the company's identity. | **Immediate (P0)** |
| **3** | **HIGH** | **Local Privilege Escalation & Persistence via Masqueraded Dropper**<br>`WebServer.bat` -> `C:\Program File\Office Updates\` | **T1036.005** (Masquerading: Match Legitimate Name)<br>**T1547.001** (Boot or Logon Autostart: Startup Folder)<br>**CWE-732** (Incorrect Permission Assignment for Critical Resource) | **Exploit Scenario:** `WebServer.bat` deploys `MyUpdator.exe` into `C:\Program File\` (singular). On default Windows configurations, root `C:\` permits standard users to create directories. An unprivileged attacker can replace `MyUpdator.exe` with a trojan binary, which executes automatically when the target user logs in via `Checkupdate.bat`.<br>**Impact:** Local privilege escalation, persistent execution, and living-off-the-land evasion. | **High (P1)** |
| **4** | **HIGH** | **Credential Exposure in GSP Query Strings**<br>`GspServer.dll` (`Util.GetApi`, `PostApi`, `PutApi`) | **T1552.001** (Unsecured Credentials in URLs)<br>**CWE-598** (Use of GET Request Method With Sensitive Query Strings) | **Exploit Scenario:** GSP authentication requests pass `aspid`, `password`, `gstin`, and `authtoken` as unencrypted URL query parameters rather than in HTTP headers. Any corporate forward proxy, firewall inspection engine, or local proxy log captures plaintext credentials.<br>**Impact:** GSP account hijacking, unauthorized access to taxpayer records, and data exfiltration. | **High (P1)** |
| **5** | **HIGH** | **Undocumented Remote Support Backdoor Footprint**<br>`AnyDesk.exe` & `DownloadFileToRustDeskConfig` in `SPEQTAliveBackup.exe` | **T1219** (Remote Access Software)<br>**CWE-912** (Hidden Functionality) | **Exploit Scenario:** The installer bundles `AnyDesk.exe` and contains logic in `SPEQTAliveBackup.exe` to configure RustDesk remote access silently. If configured with an unattended access password, attackers or vendor personnel can establish remote desktop sessions bypassing perimeter defenses.<br>**Impact:** Covert lateral movement, workstation surveillance, and corporate network penetration. | **High (P1)** |
| **6** | **MEDIUM** | **Predictable Encryption Key & Fixed IV in Local SQLite Databases**<br>`GSTINDBMS.db` & `MasterDBMS.db` | **T1005** (Data from Local System)<br>**CWE-329** (Generation of Predictable IV with CBC Mode) | **Exploit Scenario:** Both SQLite databases share an identical 16-byte fixed IV (`fd 0b d6 0a a3 89 1b da 48 b8 b3 a5 a8 ae 7c 21`) with hardcoded AES-CBC keys in the vendor code. Any local user or software with read access can decrypt stored client GSTIN accounts and return histories.<br>**Impact:** Financial confidentiality breach and leakage of confidential corporate turnover data. | **Medium (P2)** |
| **7** | **MEDIUM** | **Unencrypted Taxpayer Financial Data in Staging Folders**<br>`01_APPLICATION\Excels\`, `PDFs\`, and `%TEMP%` | **T1005** (Data from Local System)<br>**CWE-312** (Cleartext Storage of Sensitive Information) | **Exploit Scenario:** Reconciled statements, customer invoices, GSTR-2B inward supply caches, and generated PDF filing receipts remain stored indefinitely in unencrypted folders.<br>**Impact:** Data exposure to other workstation users or malware scanning local directories. | **Medium (P2)** |
| **8** | **MEDIUM** | **Session Hijacking via Selenium Profile Contamination & CDP**<br>`WinAppAutom.dll` & `CdpCookieClient` | **T1185** (Browser Session Hijacking)<br>**CWE-250** (Execution with Unnecessary Privileges) | **Exploit Scenario:** `loadDefaultChromeProfile` binds Selenium directly to the user's primary browser profile. If compromised, an attacker can extract live portal cookies and session tokens intercepted by `CdpCookieClient`.<br>**Impact:** Hijacking of active GST portal sessions without requiring credentials or OTP. | **Medium (P2)** |

---

## 3. Architectural & Operational Recommendations

Enterprise accounting firms, tax consultancies, and corporate finance departments must enforce a defense-in-depth security model when running this suite:

### 3.1 Network & Egress Segmentation
- **Isolate Port 1585:** Enforce host firewall rules blocking all local non-tax applications (specifically `chrome.exe`, `msedge.exe`, `firefox.exe`) from initiating TCP connections to `127.0.0.1:1585`, mitigating Cross-Site WebSocket Hijacking.
- **Block External Supply-Chain Endpoints:** Deny egress access to `raw.githubusercontent.com/G777007/*` at the network proxy or firewall.
- **Enforce Centralized Update Management:** Disable automatic in-app updates by blocking outbound HTTP/HTTPS connections from `MyUpdator.exe` and `SPEQTAliveBackup.exe`. All software updates should be packaged and vetted by corporate IT before deployment.

### 3.2 Host & Workstation Hardening
- **Purge Persistence Droppers:** Remove `Checkupdate.bat` from the Startup folder and delete `C:\Program File\Office Updates\` and `%LOCALAPPDATA%\S_TASK\`.
- **Remove Bundled Remote Access Tools:** Disallow execution of `AnyDesk.exe` and block RustDesk configuration directories via AppLocker / Software Restriction Policies.
- **Enforce Dedicated Automation Profiles:** Ensure Selenium browser automation runs strictly with `--user-data-dir` pointed to an isolated temporary sandbox directory that is wiped on exit, preventing contamination of standard user profiles.

### 3.3 Hardware Token & Cryptographic Hygiene
- **Zero-Trust USB Token Handling:** Taxpayers must strictly disconnect USB DSC hardware tokens when not actively signing returns. Tokens should never remain permanently attached to workstations.
- **Per-Transaction PIN Configuration:** Ensure smart card middleware (eMudhra, SafeNet, Watchdata) enforces a PIN prompt for **every single cryptographic operation**, disabling PIN caching in memory.

---

## 4. Remediation Implementation Reference

To operationalize these recommendations immediately, Deliverable 2 provides an automated, non-destructive hardening script:

👉 **[harden_speqta_workstation.ps1](./harden_speqta_workstation.ps1)**  
- Defaults to safe **Audit-Only (`-AuditOnly`)** mode to evaluate posture without making modifications.
- Implements automated cleanup of persistence droppers, installs host-level NetFirewall rules for loopback port 1585 and updater binaries, and securely purges transient financial staging folders.
