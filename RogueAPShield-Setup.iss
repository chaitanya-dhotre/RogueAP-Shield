; RogueAP Shield — Inno Setup Script
; Publisher: Chaitanya Dhotre
; Version: 1.0.0

#define AppName "RogueAP Shield"
#define AppVersion "1.0.0"
#define AppPublisher "Chaitanya Dhotre"
#define AppExeName "RogueAP.Gui.exe"
#define ServiceExeName "RogueAP.Service.exe"
#define ServiceName "RogueAPShield"
#define ServiceDisplayName "RogueAP Shield Protection Service"
#define AppId "{{A3F9B2C8-D1E4-F7A0-B3C6-D9E2F5A8B1C4}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/chaitanya-dhotre/RogueAP-Shield
AppSupportURL=https://github.com/chaitanya-dhotre/RogueAP-Shield
AppUpdatesURL=https://github.com/chaitanya-dhotre/RogueAP-Shield
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=no
OutputDir=.\installer
OutputBaseFilename=RogueAP Shield - Setup
SetupIconFile=.\publish\gui\Assets\logo.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
MinVersion=10.0.17763
UninstallDisplayIcon={app}\Gui\{#AppExeName}
UninstallDisplayName={#AppName}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=RogueAP Shield — Wi-Fi Protection
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
; Prevent non-admin uninstall
UninstallLogMode=append
; Show license if you have one
; LicenseFile=LICENSE.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; \
  Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; \
  Flags: unchecked
Name: "startmenuicon"; \
  Description: "Create a Start Menu shortcut"; \
  GroupDescription: "{cm:AdditionalIcons}"; \
  Flags: checkedonce

[Files]
; GUI files
Source: ".\publish\gui\*"; \
  DestDir: "{app}\Gui"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

; Service files
Source: ".\publish\service\*"; \
  DestDir: "{app}\Service"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

; Icon for uninstaller and shortcuts
Source: ".\publish\gui\Assets\logo.ico"; \
  DestDir: "{app}"; \
  Flags: ignoreversion

[Dirs]
; Create data directory with correct permissions
; SYSTEM account (service) needs full access
; Users get read-only
Name: "{commonappdata}\RogueAP"; \
  Permissions: system-full users-readexec

[Icons]
; Desktop shortcut — GUI only
Name: "{autodesktop}\{#AppName}"; \
  Filename: "{app}\Gui\{#AppExeName}"; \
  IconFilename: "{app}\logo.ico"; \
  Tasks: desktopicon

; Start Menu shortcuts
Name: "{group}\{#AppName}"; \
  Filename: "{app}\Gui\{#AppExeName}"; \
  IconFilename: "{app}\logo.ico"; \
  Tasks: startmenuicon
Name: "{group}\Uninstall {#AppName}"; \
  Filename: "{uninstallexe}"; \
  Tasks: startmenuicon

[Registry]
; Register AUMID for Windows toast notifications
; This makes notifications show "RogueAP Shield" 
; instead of "RogueAP.Service" in the notification center
Root: HKLM; \
  Subkey: "SOFTWARE\Classes\AppUserModelId\RogueAPShield"; \
  ValueType: string; \
  ValueName: "DisplayName"; \
  ValueData: "RogueAP Shield"; \
  Flags: uninsdeletekey

Root: HKLM; \
  Subkey: "SOFTWARE\Classes\AppUserModelId\RogueAPShield"; \
  ValueType: string; \
  ValueName: "IconUri"; \
  ValueData: "{app}\logo.ico"; \
  Flags: uninsdeletekey

; Allow notifications to break through Do Not Disturb
Root: HKCU; \
  Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\RogueAPShield"; \
  ValueType: dword; \
  ValueName: "Enabled"; \
  ValueData: "1"; \
  Flags: uninsdeletekey

Root: HKCU; \
  Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\RogueAPShield"; \
  ValueType: dword; \
  ValueName: "ShowInActionCenter"; \
  ValueData: "1"; \
  Flags: uninsdeletekey

; Register app for Add/Remove Programs
Root: HKLM; \
  Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#AppId}_is1"; \
  ValueType: string; \
  ValueName: "DisplayIcon"; \
  ValueData: "{app}\logo.ico"

[Run]
; Create Windows Event Log source
Filename: "{sys}\cmd.exe"; \
  Parameters: "/c eventcreate /T INFORMATION /ID 1 /L APPLICATION /SO ""RogueAP Shield"" /D ""RogueAP Shield installed"" > nul 2>&1"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Registering event log source..."

; Stop existing service if upgrading
Filename: "{sys}\sc.exe"; \
  Parameters: "stop ""{#ServiceName}"""; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Stopping existing service..."

; Wait for service to stop
Filename: "{sys}\cmd.exe"; \
  Parameters: "/c timeout /t 3 /nobreak > nul"; \
  Flags: runhidden waituntilterminated

; Delete old service if upgrading
Filename: "{sys}\sc.exe"; \
  Parameters: "delete ""{#ServiceName}"""; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Removing old service..."

; Wait before reinstalling
Filename: "{sys}\cmd.exe"; \
  Parameters: "/c timeout /t 2 /nobreak > nul"; \
  Flags: runhidden waituntilterminated

; Install Windows service
Filename: "{sys}\sc.exe"; \
  Parameters: "create ""{#ServiceName}"" binPath= ""{app}\Service\{#ServiceExeName}"" start= auto DisplayName= ""{#ServiceDisplayName}"" obj= LocalSystem"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Installing protection service..."

; Set service description
Filename: "{sys}\sc.exe"; \
  Parameters: "description ""{#ServiceName}"" ""Monitors Wi-Fi networks for rogue access points and enforces network security policies. Part of RogueAP Shield by {#AppPublisher}."""; \
  Flags: runhidden waituntilterminated

; Set service to restart on failure
Filename: "{sys}\sc.exe"; \
  Parameters: "failure ""{#ServiceName}"" reset= 86400 actions= restart/5000/restart/10000/restart/30000"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Configuring service recovery..."

; Create firewall rule to allow service
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall add rule name=""RogueAP Shield Service"" dir=in action=allow program=""{app}\Service\{#ServiceExeName}"" enable=yes profile=any"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Configuring firewall exception..."

; Start the service
Filename: "{sys}\sc.exe"; \
  Parameters: "start ""{#ServiceName}"""; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Starting protection service..."

; Wait for service to start
Filename: "{sys}\cmd.exe"; \
  Parameters: "/c timeout /t 3 /nobreak > nul"; \
  Flags: runhidden waituntilterminated

; Launch GUI after install
Filename: "{app}\Gui\{#AppExeName}"; \
  Description: "Launch {#AppName}"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop service first
Filename: "{sys}\sc.exe"; \
  Parameters: "stop ""{#ServiceName}"""; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "StopService"

; Wait for service to stop fully
Filename: "{sys}\cmd.exe"; \
  Parameters: "/c timeout /t 5 /nobreak > nul"; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "WaitStop"

; Remove all RogueAP firewall rules
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall delete rule name=""RogueAP Shield Service"""; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveFirewallService"

Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall delete rule name=""RogueAP_KS_BlockOutbound"""; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveKsOut"

Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall delete rule name=""RogueAP_KS_BlockInbound"""; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveKsIn"

; Delete the service
Filename: "{sys}\sc.exe"; \
  Parameters: "delete ""{#ServiceName}"""; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "DeleteService"

[UninstallDelete]
; Remove app data directory on uninstall
; IMPORTANT: Ask user first via code below
Type: filesandordirs; Name: "{commonappdata}\RogueAP"

[Code]
// ─────────────────────────────────────────────
// Check .NET 9 runtime is installed
// ─────────────────────────────────────────────
function IsDotNet9Installed(): Boolean;
var
  ResultCode: Integer;
begin
  // Check for .NET 9 runtime via dotnet CLI
  Result := Exec(
    ExpandConstant('{sys}\cmd.exe'),
    '/c dotnet --list-runtimes 2>nul | find "Microsoft.NETCore.App 9."',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) and (ResultCode = 0);
end;

// ─────────────────────────────────────────────
// Check .NET 9 Desktop Runtime for GUI
// ─────────────────────────────────────────────  
function IsDotNet9DesktopInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(
    ExpandConstant('{sys}\cmd.exe'),
    '/c dotnet --list-runtimes 2>nul | find "Microsoft.WindowsDesktop.App 9."',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) and (ResultCode = 0);
end;

// ─────────────────────────────────────────────
// Pre-install checks
// ─────────────────────────────────────────────
function InitializeSetup(): Boolean;
var
  MissingRuntime: Boolean;
  MsgText: String;
  DownloadResult: Integer;
begin
  Result := True;
  MissingRuntime := False;
  MsgText := '';

  if not IsDotNet9Installed() then
  begin
    MissingRuntime := True;
    MsgText := MsgText + #13#10 + '  • .NET 9 Runtime';
  end;

  if not IsDotNet9DesktopInstalled() then
  begin
    MissingRuntime := True;
    MsgText := MsgText + #13#10 + '  • .NET 9 Desktop Runtime';
  end;

  if MissingRuntime then
  begin
    if MsgBox(
      'RogueAP Shield requires the following components:' +
      MsgText + #13#10#13#10 +
      'These are free downloads from Microsoft.' + #13#10 +
      'Would you like to open the download page?',
      mbConfirmation,
      MB_YESNO
    ) = IDYES then
    begin
      ShellExec(
        'open',
        'https://dotnet.microsoft.com/download/dotnet/9.0',
        '',
        '',
        SW_SHOW,
        ewNoWait,
        DownloadResult
      );
    end;
    
    MsgBox(
      'Installation cannot continue without .NET 9 Runtime.' +
      Chr(13) + Chr(10) + Chr(13) + Chr(10) +
      'Please download and install .NET 9 Desktop Runtime from Microsoft, then run this setup again.',
      mbError,
      MB_OK);
    Result := False;
  end;
end;

// ─────────────────────────────────────────────
// Ask about data deletion on uninstall
// ─────────────────────────────────────────────
function InitializeUninstall(): Boolean;
begin
  Result := True;
  
  if MsgBox(
    'RogueAP Shield is about to be uninstalled.' + 
    Chr(13) + Chr(10) + Chr(13) + Chr(10) +
    'Your trusted network data and configuration ' +
    'will also be removed.' + #13#10#13#10 +
    'Are you sure you want to uninstall RogueAP Shield?',
    mbConfirmation,
    MB_YESNO
  ) = IDNO then
    Result := False;
end;

// ─────────────────────────────────────────────
// Set ProgramData directory permissions
// so SYSTEM service can write to it
// ─────────────────────────────────────────────
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  DataPath: String;
begin
  if CurStep = ssPostInstall then
  begin
    DataPath := ExpandConstant('{commonappdata}\RogueAP');
    
    // Grant SYSTEM full control
    Exec(
      ExpandConstant('{sys}\icacls.exe'),
      '"' + DataPath + '" /grant "SYSTEM:(OI)(CI)F" /T /Q',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
    
    // Grant Administrators full control
    Exec(
      ExpandConstant('{sys}\icacls.exe'),
      '"' + DataPath + '" /grant "Administrators:(OI)(CI)F" /T /Q',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
    
    // Remove standard Users write access
    // (they can read logs but not modify data)
    Exec(
      ExpandConstant('{sys}\icacls.exe'),
      '"' + DataPath + '" /remove "Users" /T /Q',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
  end;
end;
