; PhantomFS.iss - Inno Setup 6 installer script
; https://jrsoftware.org/isinfo.php
;
; This script lives in src\, alongside PhantomFS.cs and PhantomFS.exe.config.
; It packages the build output from bin\x64\ (produced by
; .github\workflows\build.yml or a local build), not files from src\
; directly, so the installer always ships exactly what was compiled and
; staged, not whatever happens to be sitting in the source tree.
;
; Compile with:  ISCC.exe PhantomFS.iss
; Output:        src\Output\PhantomFSSetup-1.4.0.exe

#define AppName      "PhantomFS"
; AppVersion defaults to 1.4.0 for a local "double-click ISCC.exe on this
; file" compile. CI passes /DAppVersion=<actual release version> instead,
; which wins over this default since #ifndef only defines it when the
; command line has not already done so, keeping the installer's version
; in lockstep with whatever version the release workflow is actually
; building rather than needing to be bumped here by hand every release.
#ifndef AppVersion
  #define AppVersion "1.4.0"
#endif
#define AppPublisher "Alloy Secure"
#define AppURL       "https://github.com/AlloySecureGroup/PhantomFS"
#define AppExeName   "PhantomFS.exe"
#define AppGUID      "{{A3F7C2D1-84BE-4E9A-B0C5-123456789ABC}"

; Default virtual root used by the post-install launch and the startup task.
; Defined once here so the [Run] entry, the [Code] task creation, and the
; directory-creation step cannot drift apart.
#define DefaultVirtRoot "C:\PhantomFS\Virtual"

[Setup]
AppId                    = {#AppGUID}
AppName                  = {#AppName}
AppVersion               = {#AppVersion}
AppPublisher             = {#AppPublisher}
AppPublisherURL          = {#AppURL}
AppSupportURL            = {#AppURL}/issues
AppUpdatesURL            = {#AppURL}/releases
DefaultDirName           = {autopf}\{#AppName}
DefaultGroupName         = {#AppName}
OutputDir                = Output
OutputBaseFilename       = PhantomFSSetup-{#AppVersion}
; No SetupIconFile: the repo's assets folder currently only has .png logos
; (phantomfs-logo.png, sticker_logo.png), and Inno Setup requires an actual
; .ico resource here. Add a real .ico under assets\ and uncomment the line
; below once one exists, rather than reference a file that doesn't exist.
; SetupIconFile          = ..\assets\phantomfs.ico
Compression              = lzma2/ultra64
SolidCompression         = yes
WizardStyle              = modern
PrivilegesRequired       = admin
PrivilegesRequiredOverridesAllowed = commandline
MinVersion               = 10.0.17763
; Windows 10 v1809 (Build 17763) required for ProjFS
UninstallDisplayIcon     = {app}\{#AppExeName}
UninstallDisplayName     = {#AppName} {#AppVersion}
VersionInfoVersion       = {#AppVersion}
VersionInfoCompany       = {#AppPublisher}
VersionInfoDescription   = PhantomFS - Virtual Honeypot File System
VersionInfoCopyright     = Copyright (C) 2026 {#AppPublisher}
ArchitecturesInstallIn64BitMode = x64compatible
ArchitecturesAllowed     = x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "Create a &Desktop shortcut";    GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startuptask";    Description: "Run at &Windows startup (Task Scheduler)"; GroupDescription: "Autostart:"; Flags: unchecked

[Files]
; Main executable and its config, taken from the build output (bin\x64\),
; not from src\, so the installer ships exactly what CI compiled and
; staged together, config drift between src\ and the shipped binary is
; not possible this way.
Source: "..\bin\x64\PhantomFS.exe";           DestDir: "{app}";  Flags: ignoreversion
Source: "..\bin\x64\PhantomFS.exe.config";    DestDir: "{app}";  Flags: ignoreversion onlyifdoesntexist
; Documentation
Source: "..\README.md";                        DestDir: "{app}";  Flags: ignoreversion
Source: "..\docs_index.md";                    DestDir: "{app}\docs"; DestName: "index.md"; Flags: ignoreversion
; Assets
; No .ico currently exists in assets\ (only .png). Add one and uncomment
; once available; shortcuts below already work fine without it, they use
; the compiled exe's own embedded icon via {app}\{#AppExeName}.
; Source: "..\assets\phantomfs.ico";           DestDir: "{app}";  Flags: ignoreversion

[Icons]
Name: "{group}\PhantomFS";                   Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\PhantomFS";           Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{group}\Configuration";               Filename: "{app}\PhantomFS.exe.config"
Name: "{group}\Documentation";               Filename: "{app}\docs\index.md"

[Run]
; -- Enable ProjFS --------------------------------------------------------
; Check whether Client-ProjFS is already enabled before attempting to enable
; it - the Enable cmdlet returns an error code if the feature is already on.
; Each entry below is a single physical line: Inno Setup parses one line
; per [Run]/[UninstallRun] entry, it does not support continuing a single
; entry's Filename/Parameters/Description/Flags across multiple lines the
; way earlier revisions of this script assumed.
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -WindowStyle Hidden -Command ""$f=(Get-WindowsOptionalFeature -Online -FeatureName Client-ProjFS); if($f.State -ne 'Enabled') {{ Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart }}"""; Description: "Enabling Windows ProjFS optional feature"; StatusMsg: "Enabling Windows Projected File System..."; Flags: runhidden waituntilterminated

; -- Register EventLog source ---------------------------------------------
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -WindowStyle Hidden -Command ""if(-not [System.Diagnostics.EventLog]::SourceExists('PhantomFS')) {{ [System.Diagnostics.EventLog]::CreateEventSource('PhantomFS','Application') }}"""; Description: "Registering Windows Event Log source"; StatusMsg: "Registering Event Log source..."; Flags: runhidden waituntilterminated

; -- Create default virtual root -------------------------------------------
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -Command ""New-Item -ItemType Directory -Force -Path '{#DefaultVirtRoot}' | Out-Null"""; Description: "Creating default virtual root directory"; Flags: runhidden waituntilterminated

; -- Launch PhantomFS after install (optional) -----------------------------
; Interactive post-install launch: no --service here, this runs in the
; installing user's session where a console/desktop exists.
Filename: "{app}\{#AppExeName}"; Parameters: "--syntheticonly --virtroot ""{#DefaultVirtRoot}"""; Description: "Launch PhantomFS now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop any running PhantomFS instances gracefully before uninstall.
Filename: "taskkill.exe"; Parameters: "/IM PhantomFS.exe /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillPhantomFS"

; Remove scheduled startup task if it was created.
Filename: "schtasks.exe"; Parameters: "/Delete /TN ""PhantomFS"" /F"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveStartupTask"

; Remove the EventLog source.
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -WindowStyle Hidden -Command ""try{{ [System.Diagnostics.EventLog]::DeleteEventSource('PhantomFS') }}catch{{}}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveEventLog"

[Code]
// -- Inno Setup Pascal code -------------------------------------------------

// Reads the OS build number from the registry. Defined before
// InitializeSetup below since Inno's Pascal Script has no forward
// declarations, a function must appear before its first use in the file.
function GetWindowsBuildNumber(): Cardinal;
var
  S: String;
begin
  Result := 0;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
       'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
       'CurrentBuildNumber', S) then
    Result := StrToIntDef(S, 0);
end;

// Checks for Windows 10 v1809 (Build 17763) or later.
// ProjFS is only available from this build onward.
function InitializeSetup(): Boolean;
begin
  Result := True;
  if GetWindowsBuildNumber() < 17763 then
  begin
    MsgBox(
      'PhantomFS requires Windows 10 version 1809 (Build 17763) or later.'  + #13#10
    + 'Windows Projected File System (ProjFS) is not available on this system.' + #13#10#13#10
    + 'Please upgrade Windows and try again.',
      mbError, MB_OK);
    Result := False;
  end;
end;

// Xml-escape a string for embedding in the task definition below.
// Only the characters that are actually produced by ExpandConstant on our
// paths (& < > " ') are handled, which is sufficient for an install path.
function XmlEscape(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '&', '&amp;',  True);
  StringChangeEx(Result, '<', '&lt;',   True);
  StringChangeEx(Result, '>', '&gt;',   True);
  StringChangeEx(Result, '"', '&quot;', True);
  StringChangeEx(Result, '''', '&apos;', True);
end;

// Builds the Task Scheduler XML for the startup task.
//
// Why XML instead of the plain "schtasks /Create /SC ONLOGON /TR ..." form
// the previous revision used:
//   1. Quoting. The old /TR value nested doubled and backslash-escaped quotes
//      around the virtroot path, which schtasks does not parse reliably; the
//      trailing \" before the closing quote escaped the quote and corrupted
//      the path. A Command/Arguments split in XML removes all nested quoting.
//   2. Working directory. A SYSTEM task with no working directory defaults to
//      C:\Windows\System32, so any relative path resolves there.
//      WorkingDirectory pins it to the install folder.
//   3. Restart on failure. At logon the ProjFS filter or the target volume may
//      not be ready when the task fires, so PrjStartVirtualizing can fail.
//      RestartOnFailure retries automatically. schtasks command-line flags
//      cannot express this; the XML form can.
//   4. --service. The provider is launched with --service so it runs
//      non-interactively (blocks until stopped) instead of reading a stdin
//      that does not exist under a SYSTEM task and exiting immediately.
function BuildTaskXml(const ExePath, WorkDir, VirtRoot: String): String;
var
  Args: String;
begin
  // Arguments are XML text, not a shell string, so no surrounding quotes are
  // needed except the inner quotes for a path that may contain spaces.
  Args := '--service --syntheticonly --virtroot "' + VirtRoot + '"';

  Result :=
    '<?xml version="1.0" encoding="UTF-16"?>' + #13#10 +
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + #13#10 +
    '  <RegistrationInfo>' + #13#10 +
    '    <Description>PhantomFS virtual honeypot file system provider.</Description>' + #13#10 +
    '    <URI>\PhantomFS</URI>' + #13#10 +
    '  </RegistrationInfo>' + #13#10 +
    '  <Triggers>' + #13#10 +
    '    <LogonTrigger>' + #13#10 +
    '      <Enabled>true</Enabled>' + #13#10 +
    // 30s delay so ProjFS and the volume are ready before we start.
    '      <Delay>PT30S</Delay>' + #13#10 +
    '    </LogonTrigger>' + #13#10 +
    '  </Triggers>' + #13#10 +
    '  <Principals>' + #13#10 +
    '    <Principal id="Author">' + #13#10 +
    '      <UserId>S-1-5-18</UserId>' + #13#10 +        // SYSTEM
    '      <RunLevel>HighestAvailable</RunLevel>' + #13#10 +
    '    </Principal>' + #13#10 +
    '  </Principals>' + #13#10 +
    '  <Settings>' + #13#10 +
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>' + #13#10 +
    '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>' + #13#10 +
    '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>' + #13#10 +
    '    <AllowHardTerminate>true</AllowHardTerminate>' + #13#10 +
    '    <StartWhenAvailable>true</StartWhenAvailable>' + #13#10 +
    // Long-running provider: no execution time limit, and do not auto-stop it.
    '    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>' + #13#10 +
    '    <Enabled>true</Enabled>' + #13#10 +
    '    <Hidden>false</Hidden>' + #13#10 +
    '    <RestartOnFailure>' + #13#10 +
    '      <Interval>PT1M</Interval>' + #13#10 +
    '      <Count>3</Count>' + #13#10 +
    '    </RestartOnFailure>' + #13#10 +
    '  </Settings>' + #13#10 +
    '  <Actions Context="Author">' + #13#10 +
    '    <Exec>' + #13#10 +
    '      <Command>' + XmlEscape(ExePath) + '</Command>' + #13#10 +
    '      <Arguments>' + XmlEscape(Args) + '</Arguments>' + #13#10 +
    '      <WorkingDirectory>' + XmlEscape(WorkDir) + '</WorkingDirectory>' + #13#10 +
    '    </Exec>' + #13#10 +
    '  </Actions>' + #13#10 +
    '</Task>' + #13#10;
end;

// Register the startup scheduled task if the user chose that option.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  ExePath: String;
  WorkDir: String;
  XmlPath: String;
  TaskXml: String;
begin
  if CurStep = ssPostInstall then
  begin
    if IsTaskSelected('startuptask') then
    begin
      ExePath := ExpandConstant('{app}\PhantomFS.exe');
      WorkDir := ExpandConstant('{app}');
      TaskXml := BuildTaskXml(ExePath, WorkDir, '{#DefaultVirtRoot}');

      // Task Scheduler expects the imported XML as UTF-16. Inno Setup 6 is
      // Unicode-only, so SaveStringToFile writes UTF-16LE with a BOM, which
      // matches the encoding="UTF-16" declaration in the XML.
      XmlPath := ExpandConstant('{tmp}\PhantomFS-task.xml');
      if SaveStringToFile(XmlPath, TaskXml, False) then
      begin
        // /XML imports the full definition; /F overwrites any existing task.
        if not Exec('schtasks.exe',
             '/Create /TN "PhantomFS" /XML "' + XmlPath + '" /F',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
          ResultCode := -1;

        if ResultCode <> 0 then
          MsgBox(
            'PhantomFS was installed, but the startup task could not be created'
            + ' (schtasks exit code ' + IntToStr(ResultCode) + ').' + #13#10
            + 'You can create it manually or re-run the installer.',
            mbInformation, MB_OK);
      end
      else
        MsgBox(
          'PhantomFS was installed, but the startup task definition could not'
          + ' be written to a temporary file. The task was not created.',
          mbInformation, MB_OK);
    end;
  end;
end;
