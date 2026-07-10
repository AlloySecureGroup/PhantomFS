<p align="center">
  <img src="assets/sticker_logo.png" alt="PhantomFS — Fake Files. Real Security." width="420" />
</p>

<p align="center">
  <strong>Fake Files. Real Security.</strong><br/>
  Virtual honeypot file system for Windows — lure attackers into a directory that looks real, then catch them in the act.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"/></a>
  <a href="https://docs.microsoft.com/en-us/windows/win32/projfs/projected-file-system"><img src="https://img.shields.io/badge/Platform-Windows%2010%2B-blue" alt="Platform"/></a>
  <a href="https://dotnet.microsoft.com/download/dotnet-framework"><img src="https://img.shields.io/badge/.NET%20Framework-4.8-purple" alt=".NET 4.8"/></a>
  <a href="https://github.com/sponsors/secdev02"><img src="https://img.shields.io/badge/Sponsor-%E2%9D%A4-pink" alt="Sponsor"/></a>
</p>

---

## What Is PhantomFS?

PhantomFS uses the **Windows Projected File System (ProjFS)** to surface a virtual directory full of convincing decoy files — financial reports, SSH keys, API credentials, HR spreadsheets, NDAs — that exist only in memory. No data is ever written to disk until an attacker (or insider threat) opens one.

The moment a file is touched, PhantomFS:

- Writes a **Windows Event Log** entry (Application log, source `PhantomFS`)
- Fires a **Toast notification** to the active desktop session
- Logs the exact filename, timestamp, and process context
- When accessed over a network share — captures the **SMB username and source address**

Because legitimate users have no reason to open files they didn't put there, every alert is high-confidence. No tuning, no ML, no cloud dependencies — just a native Windows driver and a single executable.

---

## Features

| Feature | Details |
|---|---|
| **Zero-footprint decoys** | Files are projected on demand — nothing is written to disk unless an attacker reads a file |
| **Windows Event Log** | Event ID 1001 (file read), 1002 (placeholder created), 1003 (started), 1004 (stopped) |
| **Toast alerts** | Immediate desktop notification via Windows PowerShell — works even over RDP |
| **Remote session logging** | SMB username and source address captured via `NetSessionEnum` when PID 4 triggers access |
| **Auto-cleanup** | Hydrated synthetic files deleted after a configurable delay; reverts to virtual on next access |
| **Configurable templates** | PDF, XLSX, DOCX, JSON, CSV, PEM, plain text — all served from XML templates in the config |
| **Per-file cooldown** | Configurable throttle (default 15 s) prevents alert floods when a tool reads multiple chunks |
| **Synthetic file list** | Drop-in XML list of convincing filenames with realistic byte sizes |
| **Single executable** | `PhantomFS.exe` + `PhantomFS.exe.config` — no installer required |

---

## Requirements

- Windows 10 version 1809 (Build 17763) or later — Windows 11 recommended
- .NET Framework 4.8
- **Windows Projected File System** optional feature enabled (`Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`)
- Administrator privileges to start the virtual root

---

## Quick Start

###  Simple Commands (recommended)

1. Download `PhantomFS-v1.1.0-x64.zip` from [Releases](https://github.com/AlloySecureGroup/PhantomFS/releases) and extract it
2. Run as Administrator — enable ProjFS, `Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`
3. Execute `.\PhantomFS.exe --virtroot C:\PhantomFS\Virtual\Documents --syntheticonly`
4. Browse to `C:\PhantomFS\Virtual\Documents` in Explorer — you will see the decoy files
5. Open one — watch the Toast fire and check **Event Viewer → Windows Logs → Application**


---

## Configuration

All settings live in `PhantomFS.exe.config`. **All keys are optional** — omitting a key uses the default shown in the table.

### `<settings>` Section

```xml
<settings>
  <enableEventLog>true</enableEventLog>
  <enableToast>true</enableToast>
  <alertOnOpen>true</alertOnOpen>
  <alertOnRead>true</alertOnRead>
  <toastCooldownSeconds>15</toastCooldownSeconds>
  <verbose>false</verbose>
  <virtRoot></virtRoot>
  <sourceRoot></sourceRoot>
  <syntheticOnly>true</syntheticOnly>

  <!-- v1.1.0 — auto-cleanup -->
  <autoCleanupEnabled>true</autoCleanupEnabled>
  <autoCleanupDelaySeconds>300</autoCleanupDelaySeconds>

  <!-- v1.1.0 — remote session logging -->
  <resolveRemoteIPs>true</resolveRemoteIPs>
</settings>
```

| Key | Default | Since | Description |
|---|---|---|---|
| `enableEventLog` | `true` | 1.0.0 | Write to Windows Application event log |
| `enableToast` | `true` | 1.0.0 | Send desktop Toast notification |
| `alertOnOpen` | `true` | 1.0.0 | Alert when a placeholder is first created (directory browse) |
| `alertOnRead` | `true` | 1.0.0 | Alert when file data is actually read |
| `toastCooldownSeconds` | `15` | 1.0.0 | Minimum seconds between Toasts for the same file path |
| `verbose` | `false` | 1.0.0 | Extra console output for diagnostics |
| `virtRoot` | _(arg 1)_ | 1.0.0 | Override virtual root path from config rather than command line |
| `sourceRoot` | _(empty)_ | 1.0.0 | Optional real backing directory — leave empty for synthetic-only mode |
| `syntheticOnly` | `true` | 1.0.0 | Serve only the files listed in `<syntheticFileList>` |
| `autoCleanupEnabled` | `true` | **1.1.0** | Delete materialized synthetic files after the delay and revert to virtual |
| `autoCleanupDelaySeconds` | `300` | **1.1.0** | Seconds after hydration before the file is deleted (cleanup timer runs every 30 s) |
| `resolveRemoteIPs` | `true` | **1.1.0** | DNS-resolve the SMB client hostname to an IP address; set to `false` if lookup latency is unacceptable |

### Remote Session Logging

When a file is accessed over an SMB share, PhantomFS detects PID 4 (the Windows System process / kernel SMB driver) as the caller and automatically calls `NetSessionEnum` to identify the remote user. The Event Log entry and Toast notification will include:

```
PhantomFS — Honeypot File Content Read
File    : Documents\Q4_Financial_Report_2024.pdf
Process : System (PID 4)
Remote  : CORP\jsmith @ DESKTOP-A1B2C3D  [192.168.1.45]
```

**Requirements for remote logging:**
- The Server service must be running (it starts automatically whenever a share is active)
- PhantomFS must be running on the machine hosting the share
- `resolveRemoteIPs` requires the client machine to be resolvable via DNS

### Auto-Cleanup Behaviour

After a synthetic file is opened and hydrated (content written to disk), a background timer checks every 30 seconds and deletes files whose hydration time exceeds `autoCleanupDelaySeconds`. The deleted file reverts to a virtual ProjFS placeholder — the next access re-triggers the ProjFS callback as if the file had never been opened.

Files that are still open when the cleanup timer fires are skipped without error and retried on the next 30-second cycle.

### Adding Decoy Files

Add entries under `<syntheticFileList>` in the config:

```
\Documents,true,0,1744586986
\Documents\Q4_Financial_Report_2024.pdf,false,8192,1744586986
\Documents\Employee_Salaries_2024.xlsx,false,4096,1743942586
\IT\Keys,true,0,1744586986
\IT\Keys\deploy_key.pem,false,3247,1742354986
```

### Adding Content Templates

```xml
<syntheticTemplates>
  <template name="my_custom_file.txt"><![CDATA[
    ... your file content here ...
  ]]></template>
</syntheticTemplates>
```

---

## Event Log Reference

Open **Event Viewer → Windows Logs → Application** and filter by source `PhantomFS`.

| Event ID | Level | Meaning |
|---|---|---|
| 1001 | Warning | A decoy file's data was read (includes remote user/IP when applicable) |
| 1002 | Warning | A decoy file placeholder was created (file was browsed/stat'd) |
| 1003 | Information | PhantomFS started — virtual root path and settings logged |
| 1004 | Information | PhantomFS stopped cleanly |

---

## CI/CD — GitHub Actions

PhantomFS ships a workflow at `.github/workflows/build.yml` that compiles for **x64** and **ARM64** in parallel, and publishes a GitHub Release on every version tag.


---

## Building from Source

```powershell
# Requires .NET Framework 4.8 SDK or Visual Studio Build Tools
csc.exe /platform:x64 /r:System.Xml.dll /out:PhantomFS.exe src\PhantomFS.cs
```

`csc.exe` is typically at:
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
```

---

## Deployment Ideas

- **Workstation trap** — run as a scheduled task at logon; any lateral movement to `\\hostname\PhantomFS\Virtual` fires an immediate alert with the attacker's username and source IP
- **File server canary** — place a `\Finance` share pointing at the virtual root alongside the real finance share; remote session logging identifies exactly which account browsed the bait
- **Developer machine** — surface fake AWS keys and SSH keys in `~\Documents`; insider or supply-chain attacks trigger alerts before exfiltration
- **Air-gapped segment** — set `resolveRemoteIPs=false` to skip DNS in environments where external lookups are blocked; the NetBIOS machine name is still captured

---


---

## Sponsorship

PhantomFS is free, open-source, and MIT-licensed. If it has saved you time — or caught a real attacker — please consider sponsoring continued development.

**[❤ Sponsor on GitHub](https://github.com/sponsors/secdev02)**

Sponsors receive:

- Priority issue responses
- Early access to new templates and features
- A mention in the release notes

Corporate sponsors ($500+/month) receive a private Slack channel for direct support and feature requests.

---

## License

```
MIT License

Copyright (c) 2026 Alloy Secure

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```


> **Trademark Notice:** PhantomFS™ is a trademark of Alloy Secure. All rights reserved.


---

## Disclaimer — Acceptable Use

PhantomFS is provided **for lawful defensive security purposes only** — including intrusion detection, threat research, and authorized penetration testing on systems you own or have explicit written permission to monitor.

**You are solely responsible for ensuring your use of PhantomFS complies with all applicable local, national, and international laws**, including but not limited to computer fraud, wiretapping, privacy, and employment law. Deploying PhantomFS on systems or networks without proper authorization may be illegal.

The authors and contributors of PhantomFS:

- Make **no warranties**, express or implied, regarding fitness for any particular purpose
- Accept **no liability** for any direct, indirect, incidental, or consequential damages arising from the use or misuse of this software
- Are **not responsible** for any data loss, system damage, legal liability, or harm to third parties resulting from deployment of PhantomFS in any environment

**Use at your own risk.** By using PhantomFS you acknowledge that you have read this disclaimer, understand it, and agree to be bound by its terms.


> **Trademark Notice:** PhantomFS™ is a trademark of Alloy Secure. All rights reserved.


---

## Acknowledgments

Built on the [Windows Projected File System API](https://docs.microsoft.com/en-us/windows/win32/projfs/projected-file-system) — the same technology that powers WSL2 and OneDrive Files On-Demand.

Inspired by my work as a researcher at Thinkst 💚 `https://citation.thinkst.com/talk/94782`
