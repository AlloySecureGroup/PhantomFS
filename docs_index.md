# PhantomFS — Documentation

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [How ProjFS Works](#2-how-projfs-works)
3. [Alert Flow](#3-alert-flow)
4. [Remote Session Logging](#4-remote-session-logging)
5. [Auto-Cleanup](#5-auto-cleanup)
6. [Event Log Reference](#6-event-log-reference)
7. [Toast Notifications](#7-toast-notifications)
8. [Configuration Reference](#8-configuration-reference)
9. [Synthetic File List](#9-synthetic-file-list)
10. [Content Templates](#10-content-templates)
11. [Deployment Patterns](#11-deployment-patterns)
12. [Building from Source](#12-building-from-source)
13. [Troubleshooting](#13-troubleshooting)
14. [FAQ](#14-faq)

---

## 1. Architecture Overview

```
┌────────────────────────────────────────────────────────────┐
│                      PhantomFS.exe                        │
│                                                            │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │ PhantomFSProvider│    │        AlertManager          │  │
│  │                  │    │                              │  │
│  │  OnStartDir      │───▶│  OnPlaceholderCreated        │  │
│  │  OnGetEntries    │    │  OnFileAccessed              │  │
│  │  OnEndDir        │    │                              │  │
│  │  OnGetPhi        │    │  ┌──────────────────────┐   │  │
│  │  OnData          │    │  │  EventLog writer      │   │  │
│  └──────┬───────────┘    │  │  Toast (PS1)          │   │  │
│         │                │  └──────────────────────┘   │  │
│         │  remote?       └──────────────────────────────┘  │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │RemoteSession     │    │       CleanupTimer           │  │
│  │Helper            │    │  (System.Threading.Timer)    │  │
│  │                  │    │                              │  │
│  │  NetSessionEnum  │    │  Every 30 s: delete files    │  │
│  │  DNS resolution  │    │  hydrated > N seconds ago    │  │
│  └──────────────────┘    └──────────────────────────────┘  │
│                                                            │
│  ┌──────────────────┐                                      │
│  │  ConfigLoader    │                                      │
│  │  (XML config)    │                                      │
│  └──────────────────┘                                      │
└──────────────────┬─────────────────────────────────────────┘
                   │  ProjFS callbacks
                   ▼
┌────────────────────────────────────────────────────────────┐
│            Windows ProjFS Kernel Driver                   │
│          (ProjectedFSLib.dll / projectedfslib.sys)        │
└──────────────────┬─────────────────────────────────────────┘
                   │  File I/O
                   ▼
          C:\PhantomFS\Virtual\
          └── Documents\
              ├── Q4_Financial_Report_2024.pdf      (projected)
              ├── Employee_Salaries_2024.xlsx        (projected)
              ├── Board_Meeting_Notes_Confidential.docx
              └── ...
```

PhantomFS sits entirely in user space. The ProjFS kernel driver intercepts file system calls to the virtual root and issues callbacks to `PhantomFSProvider`. The provider answers each callback from in-memory state — no real files exist on disk until a caller reads one.

Two background subsystems run alongside the callback path. `RemoteSessionHelper` is invoked synchronously within `OnGetPhi` and `OnData` whenever the triggering process is PID 4, and enumerates active SMB sessions via `NetSessionEnum`. The cleanup timer runs on a thread-pool thread every 30 seconds and deletes hydrated synthetic files whose age exceeds the configured threshold, reverting them to virtual placeholders.

---

## 2. How ProjFS Works

Windows Projected File System (ProjFS) is a kernel-mode file system filter that ships as an optional Windows component (`Client-ProjFS`). It allows a user-mode provider to project a virtual directory tree that is indistinguishable from a real directory to any application.

**Key concepts:**

- **Placeholder** — A sparse on-disk entry created the first time a file is stat'd or browsed. It stores metadata (name, size, timestamps) but no data. The callback that creates it is `GetPlaceholderInfo` — abbreviated `GetPhi` in ProjFS convention, since "Phi" is shorthand for "PlaceholderInfo."
- **Hydration** — When an application actually reads bytes from a placeholder, ProjFS calls `GetFileData`. The provider streams the content; ProjFS caches it on disk. This is the primary alert trigger.
- **Dehydration (v1.1.0)** — PhantomFS's cleanup timer deletes hydrated placeholder files after a configurable delay, reverting them to their unhydrated virtual state. The next read will trigger a fresh `GetFileData` callback as normal. This keeps disk footprint minimal and ensures the honeypot resets automatically after each access.
- **Virtualization instance** — Identified by a GUID stored in the root reparse point. PhantomFS wipes and re-marks the root on every start to avoid stale state.

Because placeholders look identical to real files in Explorer, `dir`, `Get-ChildItem`, and every other enumeration tool, the decoys are indistinguishable from real files to any attacker — even those who avoid Explorer entirely.

---

## 3. Alert Flow

```
Explorer / attacker tool
        │
        │  CreateFile / FindFirstFile / GetFileInformationByHandle
        ▼
ProjFS kernel driver
        │
        ├─── Directory enumeration ──▶ OnStartDir / OnGetEntries / OnEndDir
        │                               (no alert — browsing alone is not conclusive)
        │
        ├─── File stat / metadata ───▶ OnGetPlaceholderInfo (OnGetPhi)
        │                               │
        │                               ├─ PID 4? ──▶ RemoteSessionHelper
        │                               │              .GetActiveSessions()
        │                               │
        │                               └─▶ AlertManager.OnPlaceholderCreated
        │                                    → EventLog Warning 1002 (alertOnOpen=true)
        │
        └─── File read (ReadFile) ───▶ OnData (GetFileData)
                                        │
                                        ├─ PID 4? ──▶ RemoteSessionHelper
                                        │              .GetActiveSessions()
                                        │
                                        ├─▶ AlertManager.OnFileAccessed
                                        │    → EventLog Warning 1001
                                        │    → Toast notification (if cooldown expired)
                                        │
                                        └─▶ _materializedFiles.TryAdd(rel, UtcNow)
                                             (starts cleanup countdown)
```

**Why two alert levels?**

- **1002 — Placeholder created:** Fires when a file is stat'd or its metadata is queried — e.g., an attacker running `dir` with metadata flags, or a tool enumerating ACLs. Lower confidence; useful for audit trails.
- **1001 — File read:** Fires when bytes are actually read. High confidence — no legitimate user touches files they don't know about. This is the primary actionable alert.

The per-file cooldown (`toastCooldownSeconds`) prevents alert storms when a tool reads a large file in multiple `ReadFile` chunks. The EventLog entry is written on every read regardless of cooldown; only the Toast is throttled.

---

## 4. Remote Session Logging

When a honeypot file is accessed over an SMB share, the Windows kernel SMB driver (`srv2.sys`) is the entity that opens the file — not the remote user's process. ProjFS reports this as PID 4, which is the Windows System process. PhantomFS v1.1.0 detects this and queries the SMB Server service for active sessions.

### Detection

In both `OnGetPhi` and `OnData`, the triggering PID and process image name are checked:

```
PID == 4               → likely SMB kernel driver
processName is empty   → likely kernel-mode caller
```

When either condition is true, `RemoteSessionHelper.GetActiveSessions()` is called before the alert fires.

### Session Enumeration

`GetActiveSessions` calls `NetSessionEnum` (level 10) from `Netapi32.dll`, which returns all active SMB sessions on the local machine. For each session:

- `sesi10_username` — the domain or local account that authenticated to the share (e.g., `CORP\jsmith`)
- `sesi10_cname` — the client machine name reported by the SMB server (e.g., `\\DESKTOP-A1B2C3D`), stripped of leading backslashes

If `resolveRemoteIPs` is `true`, PhantomFS attempts a DNS forward lookup (`Dns.GetHostAddresses`) to resolve the hostname to an IP address. If the client connected by IP rather than hostname, the IP appears directly in `sesi10_cname` and no DNS lookup is needed.

### Alert Output

When remote sessions are present, the Event Log message gains a `Remote  :` line and the console output appends `[REMOTE]`:

```
[ALERT:READ]  Documents\Q4_Financial_Report_2024.pdf — System (PID 4)  [REMOTE]
```

Event Log entry (Event ID 1001):

```
PhantomFS — Honeypot File Content Read
File    : Documents\Q4_Financial_Report_2024.pdf
Process : System (PID 4)
Remote  : CORP\jsmith @ DESKTOP-A1B2C3D  [192.168.1.45]
```

The Toast body is rewritten when sessions are present:

```
Documents\Q4_Financial_Report_2024.pdf
User: CORP\jsmith  From: DESKTOP-A1B2C3D  [192.168.1.45]
```

### Multiple concurrent sessions

If more than one SMB session is active when the alert fires, all sessions are listed in the Event Log entry — one `Remote  :` line per session. The Toast shows only the first session. In most environments a single session is active at any given moment; multiple sessions indicate either legitimate concurrent users or a more complex attack.

### Requirements

- The **Server** service (`LanmanServer`) must be running. It starts automatically when any share is published and remains running as long as shares exist.
- PhantomFS must run on the **same machine** that hosts the share — it calls `NetSessionEnum` against the local server.
- `resolveRemoteIPs` requires the SMB client machine to be resolvable via the DNS server configured on the honeypot host. In air-gapped or split-DNS environments, set `resolveRemoteIPs` to `false` — the NetBIOS machine name is still captured.

---

## 5. Auto-Cleanup

When ProjFS hydrates a placeholder (streams content to disk via `GetFileData`), the file's bytes are written to the virtual root directory. Left indefinitely, hydrated files accumulate and could signal to an attacker that their access was detected and the file was left behind as evidence. v1.1.0 reverses hydration automatically.

### Mechanism

On every successful `PrjWriteFileData` call for a synthetic file, `OnData` records the current UTC time in `_materializedFiles`:

```
_materializedFiles.TryAdd(relativePath, DateTime.UtcNow)
```

`TryAdd` is used rather than a plain dictionary set so that only the time of **first** hydration is recorded — subsequent partial reads of the same file (e.g., a tool reading in 64 KB chunks) do not reset the clock.

A `System.Threading.Timer` fires every 30 seconds. For each entry in `_materializedFiles`, if `(UtcNow − materialized) ≥ autoCleanupDelaySeconds`, the file is deleted with `File.Delete`. On success, the entry is removed from the dictionary. If the file is still open (held by the attacker's process), `File.Delete` throws an access-denied exception — the entry is left in the dictionary and retried on the next 30-second cycle.

After deletion, the file reverts to a virtual ProjFS placeholder. The next access triggers a fresh `GetPlaceholderInfo` callback and the full alert cycle begins again.

### Timing

The actual deletion occurs at most `autoCleanupDelaySeconds + 30` seconds after first hydration (the 30-second jitter comes from the fixed timer interval). The default is 300 seconds, so files are cleaned up between 5 minutes and 5 minutes 30 seconds after being opened.

### Real files are not affected

The cleanup tracker is populated only inside the synthetic content branch of `OnData`. Files served from the real source directory (`--sourceroot` mode) are never added to `_materializedFiles` and are never deleted by the cleanup timer.

### Disabling cleanup

Set `autoCleanupEnabled` to `false` in `<settings>`. The timer is not started and no files are ever deleted. This is useful when you want to preserve hydrated files for forensic examination.

---

## 6. Event Log Reference

All events are written to **Windows Logs → Application** with source `PhantomFS`.

To view in PowerShell:

```powershell
Get-EventLog -LogName Application -Source PhantomFS -Newest 50
```

To export to CSV:

```powershell
Get-EventLog -LogName Application -Source PhantomFS |
    Select-Object TimeGenerated, EventID, EntryType, Message |
    Export-Csv -Path phantomfs_alerts.csv -NoTypeInformation
```

### Event ID Table

| ID | Level | Trigger | Notes |
|---|---|---|---|
| 1001 | Warning | File data read (`GetFileData`) | Primary actionable alert; includes `Remote  :` line for SMB access |
| 1002 | Warning | Placeholder created (`GetPlaceholderInfo`) | Lower-confidence; useful for audit trails; includes `Remote  :` line for SMB access |
| 1003 | Information | Provider started | Logs virtual root, EventLog/Toast status, and cleanup configuration |
| 1004 | Information | Provider stopped | Logs virtual root |

### Local access — Event ID 1001 message format

```
PhantomFS — Honeypot File Content Read
File    : Documents\Q4_Financial_Report_2024.pdf
Process : explorer.exe (PID 13428)
```

### Remote (SMB) access — Event ID 1001 message format

```
PhantomFS — Honeypot File Content Read
File    : Documents\Q4_Financial_Report_2024.pdf
Process : System (PID 4)
Remote  : CORP\jsmith @ DESKTOP-A1B2C3D  [192.168.1.45]
```

### Forwarding to a SIEM

Use Windows Event Forwarding (WEF) or a log shipper (Winlogbeat, NXLog) to forward events to your SIEM. Filter on:

```
Source = "PhantomFS" AND EventID IN (1001, 1002)
```

---

## 7. Toast Notifications

PhantomFS sends Toast notifications via PowerShell using the Windows Runtime `ToastNotificationManager` API. No external dependencies are required beyond Windows PowerShell 5.1, which ships with every supported Windows version.

**Local access notification:**

- **Title:** `PhantomFS — Honeypot File Accessed`
- **Body:** `<filepath>  (<processName> PID <pid>)`

**Remote (SMB) access notification:**

- **Title:** `PhantomFS — Honeypot File Accessed`
- **Body:** `<filepath>\r\nUser: <username>  From: <hostname>  [<ip>]`

The IP address is omitted from the Toast body when DNS resolution is disabled or fails — the hostname is always present when a remote session is detected.

Toasts are sent using a PowerShell `-EncodedCommand` launched in a detached process so they do not block the alert path. The AUMID used is the Windows PowerShell shell entry, which is guaranteed to be registered on all supported Windows versions.

**Cooldown behavior:**

Each unique file path has its own cooldown timer tracked in a `ConcurrentDictionary<string, DateTime>`. When a file is read:

1. Check if the path is in the dictionary and the last alert was within `toastCooldownSeconds`
2. If within cooldown — skip Toast, still write EventLog
3. If outside cooldown (or first access) — send Toast, update dictionary

**Disabling Toasts:**

Set `enableToast` to `false` in `<settings>`. EventLog alerts continue regardless.

---

## 8. Configuration Reference

All settings live in `PhantomFS.exe.config` as child elements of `<settings>`. **Every key is optional** — omitting a key uses the default shown in the table. A v1.0.0 config file requires no modification to work with v1.1.0.

### Full annotated `<settings>` block

```xml
<settings>
  <!-- Alert channels -->
  <enableEventLog>true</enableEventLog>
  <enableToast>true</enableToast>

  <!-- alertOnOpen : fire when a placeholder is first created (file stat / metadata query) -->
  <!-- alertOnRead : fire when file data is actually read — primary alert                 -->
  <alertOnOpen>true</alertOnOpen>
  <alertOnRead>true</alertOnRead>

  <!-- Minimum seconds between Toast alerts for the same file path -->
  <toastCooldownSeconds>15</toastCooldownSeconds>

  <!-- Extra console output for diagnostics -->
  <verbose>false</verbose>

  <!-- Override paths — leave empty to use command-line arguments -->
  <virtRoot></virtRoot>
  <sourceRoot></sourceRoot>
  <syntheticOnly>true</syntheticOnly>

  <!-- v1.1.0 — auto-cleanup of hydrated synthetic placeholders -->
  <autoCleanupEnabled>true</autoCleanupEnabled>
  <autoCleanupDelaySeconds>300</autoCleanupDelaySeconds>

  <!-- v1.1.0 — DNS resolution of SMB client hostnames -->
  <resolveRemoteIPs>true</resolveRemoteIPs>
</settings>
```

### Settings reference table

| Key | Default | Since | Description |
|---|---|---|---|
| `enableEventLog` | `true` | 1.0.0 | Write to Windows Application event log |
| `enableToast` | `true` | 1.0.0 | Send desktop Toast notification on file access |
| `alertOnOpen` | `true` | 1.0.0 | Alert when a placeholder is first created (file stat / metadata query) |
| `alertOnRead` | `true` | 1.0.0 | Alert when file data is actually read (primary alert) |
| `toastCooldownSeconds` | `15` | 1.0.0 | Minimum seconds between Toasts for the same file path |
| `verbose` | `false` | 1.0.0 | Extra console output for diagnostics |
| `virtRoot` | _(arg 1)_ | 1.0.0 | Override virtual root path from config rather than CLI |
| `sourceRoot` | _(empty)_ | 1.0.0 | Optional real backing directory — leave empty for synthetic-only mode |
| `syntheticOnly` | `true` | 1.0.0 | Serve only files listed in `<syntheticFileList>` |
| `autoCleanupEnabled` | `true` | **1.1.0** | Delete hydrated synthetic files after the delay and revert to virtual |
| `autoCleanupDelaySeconds` | `300` | **1.1.0** | Seconds after first hydration before the file is deleted (cleanup check runs every 30 s) |
| `resolveRemoteIPs` | `true` | **1.1.0** | DNS forward-lookup of the SMB client hostname to an IP address; set `false` if lookup latency is unacceptable or DNS is unavailable |

---

## 9. Synthetic File List

The `<syntheticFileList>` CDATA section defines the virtual directory tree using a simple CSV-like line format:

```
\Path\To\Entry,isDirectory,fileSize,unixTimestamp
```

Lines beginning with `#` are comments; blank lines are ignored. Parent directories must appear before their children. `fileSize` is in bytes; use `0` for directories. `unixTimestamp` is applied to all four NTFS timestamps (created, accessed, written, changed).

```xml
<syntheticFileList><![CDATA[
\Documents,true,0,1744586986
\Documents\Q4_Financial_Report_2024.pdf,false,8192,1744586986
\Documents\Employee_Salaries_2024.xlsx,false,4096,1743942586
\Documents\Board_Meeting_Notes_Confidential.docx,false,6144,1741508986
\IT\Keys,true,0,1744586986
\IT\Keys\id_rsa,false,3247,1742354986
\IT\Keys\deploy_key.pem,false,3247,1742354986
\IT\Keys\github_pat.txt,false,93,1745674186
]]></syntheticFileList>
```

**Naming tips for convincing decoys:**

- Use realistic years in filenames — `2024`, `2025`, `Q3`, `FY25`
- Mix formats — a directory with only PDFs looks staged; mix XLSX, DOCX, PDF, and TXT
- Use department names — `\HR`, `\Finance`, `\Legal`, `\IT\Keys`
- For developer machines — `\repos\deploy_keys`, `\.aws\credentials`, `\.ssh`

---

## 10. Content Templates

Templates define the raw bytes returned when a file is read. They are stored in `<syntheticTemplates>` as CDATA blocks and matched against file names in the order: exact filename match → file extension fallback → built-in generic text.

### Built-in templates

| Template match | Mimics | Notes |
|---|---|---|
| `name="credentials"` | AWS credentials file | `[default]` block with fake access key and secret |
| `name="id_rsa"` | RSA private key | PEM block with deterministic base64 payload |
| `name="id_ed25519"` | OpenSSH private key | PEM block (`OPENSSH PRIVATE KEY` label) |
| `name="api_keys.json"` | JSON API key store | Fake OpenAI, Stripe, Twilio, PagerDuty keys |
| `name="github_pat.txt"` | GitHub PAT | `ghp_` prefixed token |
| `extension=".pdf"` | PDF 1.4 document | Minimal valid PDF; renders in Edge, Chrome, Acrobat |
| `extension=".xlsx"` | Excel spreadsheet | HTML with Office namespace headers — see note below |
| `extension=".docx"` | Word document | HTML with Word namespace headers — see note below |
| `extension=".pem"` | Generic PEM key | `type="pem"` — deterministic base64 sized to fileSize |
| `extension=".json"` | Generic JSON | Minimal honeypot-labeled JSON object |
| `extension=".csv"` | Generic CSV | Header row + sample user/access rows |
| `extension=".txt"` | Plain text | "CONFIDENTIAL" stub |

### Adding a custom template

```xml
<syntheticTemplates>
  <template name="corp-vpn.conf"><![CDATA[
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = vpn.corp-internal.example.com:51820
AllowedIPs = 0.0.0.0/0
  ]]></template>
</syntheticTemplates>
```

Reference it in `<syntheticFileList>`:

```
\IT\corp-vpn.conf,false,312,1744586986
```

PhantomFS matches by the exact filename `corp-vpn.conf` (case-insensitive) and serves the CDATA content, padded or trimmed to the declared `fileSize`.

### Why Office files use HTML

The XLSX and DOCX templates are HTML documents with Office XML namespace headers. When Office opens them it displays a format-mismatch warning — the user must click **Yes** to proceed. That click triggers a second `ReadFile` call, which fires the `GetFileData` callback and generates an Event ID 1001 alert. This produces a deliberate two-stage signal: the first `GetPlaceholderInfo` call (1002) tells you a file was browsed, and the subsequent read (1001) tells you someone deliberately opened it despite the warning.

---

## 11. Deployment Patterns

### Workstation canary

Run PhantomFS as a scheduled task that starts at logon under the `SYSTEM` account. Place the virtual root at a path that looks like a legitimate user directory:

```
C:\Users\Public\Documents\Finance
```

Any lateral movement tool that enumerates shares or user directories will browse the decoys and trigger a 1002. If it reads a file — full alert.

### File server share

Create a share alongside your real finance or HR share:

```powershell
New-SmbShare -Name "Finance_Archive" -Path "C:\PhantomFS\Virtual" -ReadAccess "Everyone"
```

Name it something archival — `Finance_Archive`, `HR_2022`, `Legal_Backup`. Legitimate users will not go looking in old archives. Attackers doing reconnaissance will. With v1.1.0 remote session logging, every access over this share captures the authenticated domain account and source IP — even if the attacker was using a compromised service account or pass-the-hash credentials.

### Developer machine — credential canary

Mirror the layout an attacker expects after compromising a developer's machine:

```
\.aws,true,0,1744586986
\.aws\credentials,false,186,1741508986
\.ssh,true,0,1744586986
\.ssh\id_rsa,false,3247,1738927786
\.ssh\id_ed25519,false,411,1740680986
```

Set `virtRoot` to `C:\Users\%USERNAME%\PhantomFS` and expose it via a junction:

```cmd
mklink /J C:\Users\%USERNAME%\.aws C:\Users\%USERNAME%\PhantomFS\.aws
```

### Air-gapped or split-DNS environments

If the honeypot host cannot resolve SMB client hostnames — common in isolated segments or when DNS and NetBIOS are separated — set `resolveRemoteIPs` to `false`. Remote session logging continues to capture the domain username and machine name reported by the SMB server; only the IP resolution step is skipped.

---

## 12. Building from Source

### Prerequisites

- Windows 10 / 11 (64-bit)
- [.NET Framework 4.8 Developer Pack](https://dotnet.microsoft.com/download/dotnet-framework/net48)
- Visual Studio 2022 (any edition) **or** standalone `csc.exe` from the SDK

### Command-line build

```powershell
# From the repo root
csc.exe /platform:x64 /r:System.Xml.dll /out:PhantomFS.exe src\PhantomFS.cs
```

`csc.exe` is typically at:
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
```

### Visual Studio build

Open `PhantomFS.sln` → **Build → Build Solution**. The output lands in `bin\Release\net48\`.

---

## 13. Troubleshooting

### `HR_ERROR_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_NOT_FOUND` (0x80004005)

ProjFS is not enabled. Run:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart
```

Then reboot.

### `HR_NOT_A_REPARSE_POINT` (0x80071126)

The virtual root directory exists from a previous run but the reparse point was not cleaned up. PhantomFS normally handles this automatically on startup by wiping and re-marking the root. If it persists:

```powershell
Remove-Item -Recurse -Force C:\PhantomFS\Virtual
New-Item -ItemType Directory -Path C:\PhantomFS\Virtual
```

### Toasts not appearing

- Confirm Windows PowerShell 5.1 is installed: `$PSVersionTable.PSVersion`
- Confirm Do Not Disturb / Focus Assist is not active
- Confirm the session is interactive (Toasts do not fire for non-interactive service sessions)
- Set `verbose` to `true` in config and check console output for PowerShell error text

### EventLog source not registered

```powershell
New-EventLog -LogName Application -Source PhantomFS
```

Requires elevation.

### Decoy files not visible in Explorer

- Confirm PhantomFS.exe is running
- Confirm the virtual root path matches the path you are browsing
- Try `dir C:\PhantomFS\Virtual\Documents` from an elevated command prompt
- Enable `verbose` and check for callback errors

### Remote session fields missing from Event Log

The `Remote  :` line appears only when PhantomFS detects PID 4 as the triggering process **and** `NetSessionEnum` returns at least one active session. Possible causes for a missing remote line:

- The file was accessed locally, not over SMB — local accesses correctly show the calling process name and PID rather than remote session info
- No SMB session was active at the exact moment of the alert — a very short-lived connection that closed before `NetSessionEnum` ran; this is rare in practice
- The Server service (`LanmanServer`) is stopped — verify with `Get-Service LanmanServer`
- The share is hosted on a different machine — PhantomFS must run on the machine that hosts the share

### Hydrated files not being deleted

- Confirm `autoCleanupEnabled` is `true` (the default) in `<settings>`
- Confirm the delay has elapsed — the cleanup timer runs every 30 seconds, so deletion may lag up to 30 seconds past the configured delay
- The file may still be open — a process holding the file handle will cause `File.Delete` to fail; PhantomFS retries on the next 30-second cycle
- Enable `verbose` and check for `[CLEANUP]` log lines confirming timer activity

---

## 14. FAQ

**Q: Does PhantomFS write any real data to disk?**

A: No data is written during enumeration or stat operations. When a file is hydrated (read), ProjFS caches the synthetic template content on disk inside the placeholder. With auto-cleanup enabled (the default), this cached content is deleted after the configured delay and the placeholder reverts to virtual. The cached data is always synthetic template content — never real sensitive information.

---

**Q: Will antivirus flag PhantomFS?**

A: PhantomFS does not inject code, modify other processes, or write to system locations. The ProjFS API is a documented, signed Microsoft API. Some heuristic engines may flag the PowerShell Toast launcher — add an exclusion for `PhantomFS.exe` if needed.

---

**Q: Can I run multiple instances for different virtual roots?**

A: Yes — each instance needs a unique virtual root path. Run multiple copies of `PhantomFS.exe` with different `--virtroot` arguments. Each instance registers independently with ProjFS and maintains its own cleanup timer and session tracking.

---

**Q: Does this work on Windows Server?**

A: ProjFS ships as `FS-FileServer-PROJFS` on Windows Server 2019+:

```powershell
Install-WindowsFeature -Name FS-FileServer-PROJFS
```

All other PhantomFS functionality, including remote session logging and auto-cleanup, is identical.

---

**Q: Can attackers detect that a file is a ProjFS placeholder?**

A: Technically yes — a process with sufficient privileges can query the reparse point tag on a file and identify it as a ProjFS placeholder. In practice, no standard reconnaissance tool performs this check. The files are indistinguishable from real files to Explorer, PowerShell, cmd, Python `os.stat`, and every common attacker toolchain.

---

**Q: Is the honeypot data convincing enough to fool a sophisticated attacker?**

A: The filenames, directory structure, and file sizes are convincing. The content templates are plausible stubs — a sophisticated attacker who reads the full text of a "PDF" will notice it is not a real financial report. The goal is not to fool a human reading the file; it is to trigger the alert the moment the file is opened, before any human review occurs. At that point the attacker has already revealed themselves.

---

**Q: What if the attacker's session closes before `NetSessionEnum` runs?**

A: `NetSessionEnum` is called synchronously inside the `OnData` callback — immediately when the `GetFileData` request arrives, before the file content is returned to the caller. The session cannot close before the call completes because the attacker's process is blocked waiting for the file data. In practice, the session is always present when queried.

---

**Q: Will the auto-cleanup interfere with a live forensic investigation?**

A: If you want to preserve hydrated files for examination — to capture attacker tool artifacts, for example — set `autoCleanupEnabled` to `false` before the honeypot is accessed, or increase `autoCleanupDelaySeconds` to a value large enough for your response team to collect the files. The Event Log entry and Toast fire regardless of cleanup configuration; cleanup only affects the on-disk state of the hydrated placeholder.

---

**Q: Does remote session logging work when the attacker uses pass-the-hash or token impersonation?**

A: Yes — `NetSessionEnum` reports the credentials that authenticated to the SMB Server service, not the original credentials on the attacker's machine. If an attacker uses a stolen NTLM hash to authenticate as `CORP\svc_backup`, the Event Log will show `CORP\svc_backup`. This can be more useful than a hostname in detecting lateral movement via compromised service accounts.
