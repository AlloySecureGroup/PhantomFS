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

; Default virtual root, pre-filled into the installer's Virtualization Path
; page. The user can override it there; the chosen value then drives the
; create-directory step, the post-install launch, and the scheduled task,
; so all three always agree on one path.
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
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -WindowStyle Hidden -Command ""$ErrorActionPreference='Stop'; $f=Get-WindowsOptionalFeature -Online -FeatureName Client-ProjFS; if($f.State -ne 'Enabled') {{ Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart | Out-Null }}"""; Description: "Enabling Windows ProjFS optional feature"; StatusMsg: "Enabling Windows Projected File System..."; Flags: runhidden waituntilterminated

; -- Register EventLog source ---------------------------------------------
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -WindowStyle Hidden -Command ""if(-not [System.Diagnostics.EventLog]::SourceExists('PhantomFS')) {{ [System.Diagnostics.EventLog]::CreateEventSource('PhantomFS','Application') }}"""; Description: "Registering Windows Event Log source"; StatusMsg: "Registering Event Log source..."; Flags: runhidden waituntilterminated

; NOTE: The default virtual root directory is created from [Code]
; (CurStepChanged, ssPostInstall) instead of here, because it needs the
; virtualization path the user chose on the custom wizard page and must
; exist before the launch entry below runs.

; -- Launch PhantomFS after install (optional) -----------------------------
; This is the "Launch PhantomFS now" checkbox on the Finished page.
; postinstall entries run after the user clicks Finish, so the directory
; created in CurStepChanged already exists by the time this fires.
; {code:GetVirtRootParam} reads the path from the wizard page at run time,
; since [Run] Parameters cannot embed a Pascal value directly, but can call
; into [Code] through the {code:...} constant.
; No --service here, this launches interactively in the installing user's
; own session, where a console/desktop exists.
Filename: "{app}\{#AppExeName}"; Parameters: "--syntheticonly --virtroot ""{code:GetVirtRootParam}"""; Description: "Launch PhantomFS now"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
; Stop any running PhantomFS instances gracefully before uninstall.
Filename: "taskkill.exe"; Parameters: "/IM PhantomFS.exe /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillPhantomFS"

; Remove scheduled startup task if it was created.
Filename: "schtasks.exe"; Parameters: "/Delete /TN ""PhantomFS"" /F"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveStartupTask"

; Remove the EventLog source.
Filename: "powershell.exe"; Parameters: "-NonInteractive -NoProfile -WindowStyle Hidden -Command ""try{{ [System.Diagnostics.EventLog]::DeleteEventSource('PhantomFS') }}catch{{}}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveEventLog"

[Code]
// -- Inno Setup Pascal code -------------------------------------------------

// Custom wizard page holding the virtualization path input. Declared at
// module scope so CreateVirtRootPage (which builds it) and GetVirtRoot
// (which reads it) can both reach it.
var
  VirtRootPage: TInputDirWizardPage;

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

// Returns the virtualization path the user entered, trimmed of surrounding
// whitespace and any trailing backslash. Falls back to the compile-time
// default if the page has not been created yet (e.g. a silent install that
// skipped the wizard) or the field was left blank.
function GetVirtRoot(): String;
begin
  if VirtRootPage <> nil then
    Result := Trim(VirtRootPage.Values[0])
  else
    Result := '';

  if Result = '' then
    Result := '{#DefaultVirtRoot}';

  // Strip a single trailing backslash so path joins downstream are clean.
  if (Length(Result) > 0) and (Result[Length(Result)] = '\') then
    Result := Copy(Result, 1, Length(Result) - 1);
end;

// Wrapper for GetVirtRoot with the single-String-parameter signature that
// the {code:...} constant requires. Used by the [Run] Parameters field for
// the "Launch PhantomFS now" checkbox, since [Run] cannot call a Pascal
// function directly except through this constant form. Param is unused;
// Inno always passes it, empty here since {code:GetVirtRootParam} has no
// colon-separated argument.
function GetVirtRootParam(Param: String): String;
begin
  Result := GetVirtRoot();
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

// Builds the custom "Virtualization Path" wizard page. Placed after the
// welcome/license pages and before "Select Additional Tasks" so the user
// sets the path before choosing whether to create the startup task that
// depends on it. TInputDirWizardPage gives a labelled input box plus a
// Browse button and folder validation for free.
procedure InitializeWizard();
begin
  VirtRootPage := CreateInputDirPage(
    wpSelectTasks,
    'Virtualization Path',
    'Where should PhantomFS project its virtual honeypot files?',
    'PhantomFS will create and monitor its virtual files under the folder'
      + ' below. This path is used both for the post-install launch and for'
      + ' the scheduled startup task, if you choose to create one.'
      + #13#10#13#10
      + 'It should be a dedicated, empty (or not-yet-existing) folder, not a'
      + ' directory that already holds real data.',
    False,      // not "append app name"
    '');        // no new-folder name
  VirtRootPage.Add('');
  VirtRootPage.Values[0] := ExpandConstant('{#DefaultVirtRoot}');
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

// Builds the Task Scheduler XML for the startup task, running as SYSTEM.
//
// Why XML instead of the plain "schtasks /Create /SC ONSTART /TR ..." form
// an earlier revision used:
//   1. Quoting. A plain /TR value nesting doubled and backslash-escaped
//      quotes around the virtroot path is not parsed reliably by schtasks.
//      A Command/Arguments split in XML removes all nested quoting.
//   2. Working directory. A scheduled task with no working directory
//      defaults to C:\Windows\System32, so any relative path resolves
//      there. WorkingDirectory pins it to the install folder.
//   3. Restart on failure. At boot the ProjFS filter or the target volume
//      may not be ready when the task fires, so PrjStartVirtualizing can
//      fail. RestartOnFailure retries automatically. schtasks command-line
//      flags cannot express this; the XML form can.
//   4. --service. The provider is launched with --service so it runs
//      non-interactively (blocks until stopped) instead of reading a stdin
//      that does not exist under a SYSTEM task and exiting immediately.
//
// Why SYSTEM instead of the installing user's InteractiveToken:
//   1. No logon dependency. SYSTEM runs the task at boot without any user
//      ever logging on, so a machine that reboots to the lock screen still
//      gets the provider running. This is why the trigger below is a
//      BootTrigger rather than a LogonTrigger.
//   2. No visible window. SYSTEM has no interactive desktop session, so
//      there is nothing for a console window to attach to, this holds
//      even if the target exe is a console app.
//   3. ServiceAccount logon type. SYSTEM does not authenticate via a
//      logon token the way a real user does, so LogonType must be
//      ServiceAccount rather than InteractiveToken. UserId is given as the
//      literal account name "NT AUTHORITY\SYSTEM" rather than the raw SID
//      S-1-5-18: this is the form Task Scheduler's own exported SYSTEM-task
//      XML uses, and SID-form UserId has been observed to fail import in
//      some environments depending on account lookup availability at
//      import time, while the literal name is resolved consistently.
//
// Encoding note: the declaration below is UTF-8, matching what
// SaveStringToFile writes for this content, since every character this
// function produces (the literal markup, plus whatever XmlEscape lets
// through from the paths) stays within plain ASCII, and ASCII bytes are
// identical whether read as ANSI or UTF-8.
function BuildTaskXml(const ExePath, WorkDir, VirtRoot: String): String;
var
  AppArgs: String;
begin
  AppArgs := '--service --syntheticonly --virtroot "' + VirtRoot + '"';

  Result :=
    '<?xml version="1.0" encoding="UTF-8"?>' + #13#10 +
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + #13#10 +
    '  <RegistrationInfo>' + #13#10 +
    '    <Description>PhantomFS virtual honeypot file system provider.</Description>' + #13#10 +
    '    <URI>\PhantomFS</URI>' + #13#10 +
    '  </RegistrationInfo>' + #13#10 +
    '  <Triggers>' + #13#10 +
    '    <BootTrigger>' + #13#10 +
    '      <Enabled>true</Enabled>' + #13#10 +
    // Give ProjFS and the target volume time to come up before start.
    '      <Delay>PT30S</Delay>' + #13#10 +
    '    </BootTrigger>' + #13#10 +
    '  </Triggers>' + #13#10 +
    '  <Principals>' + #13#10 +
    '    <Principal id="Author">' + #13#10 +
    '      <UserId>NT AUTHORITY\SYSTEM</UserId>' + #13#10 +
    '      <LogonType>ServiceAccount</LogonType>' + #13#10 +
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
    '    <Hidden>true</Hidden>' + #13#10 +
    '    <RestartOnFailure>' + #13#10 +
    '      <Interval>PT1M</Interval>' + #13#10 +
    '      <Count>3</Count>' + #13#10 +
    '    </RestartOnFailure>' + #13#10 +
    '  </Settings>' + #13#10 +
    '  <Actions Context="Author">' + #13#10 +
    '    <Exec>' + #13#10 +
    '      <Command>' + XmlEscape(ExePath) + '</Command>' + #13#10 +
    '      <Arguments>' + XmlEscape(AppArgs) + '</Arguments>' + #13#10 +
    '      <WorkingDirectory>' + XmlEscape(WorkDir) + '</WorkingDirectory>' + #13#10 +
    '    </Exec>' + #13#10 +
    '  </Actions>' + #13#10 +
    '</Task>' + #13#10;
end;

// Post-install actions that depend on the chosen virtualization path:
//   1. create the virtual root directory
//   2. register the startup scheduled task, if selected
// The interactive "Launch PhantomFS now" step is handled separately by the
// [Run] postinstall entry via GetVirtRootParam, since it belongs on the
// Finished page checkbox rather than firing unconditionally here.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  ExePath: String;
  WorkDir: String;
  XmlPath: String;
  TaskXml: String;
  VirtRoot: String;
  LogPath: String;
  LogText: AnsiString;
  ErrDetail: String;
  CmdLine: String;
begin
  if CurStep = ssPostInstall then
  begin
    VirtRoot := GetVirtRoot();
    ExePath  := ExpandConstant('{app}\PhantomFS.exe');
    WorkDir  := ExpandConstant('{app}');

    // 1. Create the virtual root directory. Must happen here (before the
    // Finished page) so it exists by the time the postinstall launch entry
    // runs, since that entry fires after CurStep reaches ssDone.
    ForceDirectories(VirtRoot);

    // 2. Startup scheduled task, if the user ticked it. Runs as SYSTEM via
    // BuildTaskXml, so no installing-user identity is needed here.
    if IsTaskSelected('startuptask') then
    begin
      TaskXml := BuildTaskXml(ExePath, WorkDir, VirtRoot);

      // SaveStringToFile is the real built-in (there is no
      // SaveStringToUTF8File in Inno's Pascal Script). It writes the
      // system ANSI codepage, which for this purely-ASCII XML content
      // is byte-identical to UTF-8, matching the encoding declared in
      // BuildTaskXml above.
      XmlPath := ExpandConstant('{tmp}\PhantomFS-task.xml');
      LogPath := ExpandConstant('{tmp}\PhantomFS-schtasks.log');

      if SaveStringToFile(XmlPath, TaskXml, False) then
      begin
        // schtasks.exe does not parse "> file 2>&1" redirection itself,
        // only cmd.exe does, so the call is wrapped in cmd /c to actually
        // capture stderr/stdout instead of discarding it as before.
        CmdLine := '/c schtasks.exe /Create /TN "PhantomFS" /XML "'
          + XmlPath + '" /F > "' + LogPath + '" 2>&1';

        if not Exec(ExpandConstant('{cmd}'), CmdLine, '', SW_HIDE,
             ewWaitUntilTerminated, ResultCode) then
          ResultCode := -1;

        if ResultCode <> 0 then
        begin
          ErrDetail := '';
          if LoadStringFromFile(LogPath, LogText) then
            ErrDetail := #13#10#13#10 + 'Details:' + #13#10 + String(LogText);

          MsgBox(
            'PhantomFS was installed, but the startup task could not be created'
            + ' (schtasks exit code ' + IntToStr(ResultCode) + ').' + #13#10
            + 'You can create it manually or re-run the installer.'
            + ErrDetail,
            mbInformation, MB_OK);
        end;
      end
      else
        MsgBox(
          'PhantomFS was installed, but the startup task definition could not'
          + ' be written to a temporary file. The task was not created.',
          mbInformation, MB_OK);
    end;
  end;
end;
