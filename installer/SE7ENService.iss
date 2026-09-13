#ifndef MaintenanceBundleDir
#error Define MaintenanceBundleDir with the verified service bundle directory.
#endif

#ifndef ServiceVersion
#define ServiceVersion "1.0.2"
#endif

[Setup]
AppId={{846CF93F-AC92-4A47-9A4A-959B44C95CF4}
AppName=SE7EN Service
AppVerName=SE7EN Service {#ServiceVersion}
AppVersion={#ServiceVersion}
AppPublisher=SE7EN Solutions
AppPublisherURL=https://se7en.ws/
AppSupportURL=https://se7en.ws/
DefaultDirName={autopf}\7Launcher\Service
UsePreviousAppDir=no
MinVersion=10.0
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
Uninstallable=yes
CreateUninstallRegKey=yes
UninstallFilesDir={app}\Uninstall
UninstallDisplayName=SE7EN Service
UninstallDisplayIcon={app}\Se7enService.exe
SetupIconFile=..\assets\service.ico
VersionInfoCompany=SE7EN Solutions
VersionInfoCopyright=Copyright (c) 2026 SE7EN Solutions. All rights reserved.
VersionInfoDescription=7Launcher Maintenance Service Installer
VersionInfoOriginalFileName=se7en-service-setup.exe
VersionInfoProductName=7Launcher Maintenance Service
VersionInfoProductVersion={#ServiceVersion}.0
VersionInfoVersion={#ServiceVersion}.0
OutputBaseFilename=se7en-service-setup
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=no
RestartIfNeededByRun=no
SetupLogging=yes
SetupMutex=Global\SE7ENServiceSetup-846CF93F-AC92-4A47-9A4A-959B44C95CF4
WizardStyle=modern
#ifndef MAINTENANCE_TEST_UNSIGNED_DO_NOT_RELEASE
#ifdef MAINTENANCE_POSTBUILD_SIGN
SignTool=SE7ENPostBuild $f
#else
SignTool=GlobalSign $f
#endif
SignedUninstaller=yes
#endif

[Languages]
#include "SE7ENServiceLanguages.iss"

[CustomMessages]
#include "SE7ENServiceMessages.iss"

[Files]
; Temporary signed lifecycle bundle. The client installs the fixed service path itself.
Source: "{#MaintenanceBundleDir}\Se7enServiceManager.exe"; DestDir: "{tmp}"; Flags: dontcopy noencryption
Source: "{#MaintenanceBundleDir}\Se7enService.exe"; DestDir: "{tmp}"; Flags: dontcopy noencryption
Source: "{#MaintenanceBundleDir}\file-set-v1.json"; DestDir: "{tmp}"; Flags: dontcopy noencryption
Source: "{#MaintenanceBundleDir}\keyring-v1.json"; DestDir: "{tmp}"; Flags: dontcopy noencryption

[UninstallDelete]
; These are fixed component-owned paths. Per-game uninstallers never contain these entries.
Type: files; Name: "{app}\Se7enService.exe"
Type: files; Name: "{app}\Se7enService.candidate.exe"
Type: files; Name: "{app}\Se7enService.previous.exe"
Type: filesandordirs; Name: "{commonappdata}\SE7EN\Service"
Type: dirifempty; Name: "{commonappdata}\SE7EN"
Type: dirifempty; Name: "{app}"

[Code]
function QuoteMaintenanceArgument(const Value: String): String;
begin
  Result := '"' + Value + '"';
end;

function EnsureSE7ENService(): String;
var
  BundleRoot: String;
  ClientPath: String;
  DiagnosticPath: String;
  MaintenanceDiagnostic: AnsiString;
  MaintenanceExitCode: Integer;
  Parameters: String;
begin
  Result := '';
  try
    ExtractTemporaryFile('Se7enServiceManager.exe');
    ExtractTemporaryFile('Se7enService.exe');
    ExtractTemporaryFile('file-set-v1.json');
    ExtractTemporaryFile('keyring-v1.json');
  except
    Result := CustomMessage('ServiceBundleExtractFailed');
    Exit;
  end;

  BundleRoot := ExpandConstant('{tmp}');
  ClientPath := ExpandConstant('{tmp}\Se7enServiceManager.exe');
  DiagnosticPath := ExpandConstant('{tmp}\SE7ENService-ensure-service.log');
  DeleteFile(DiagnosticPath);
  Parameters := 'ensure-service ' + QuoteMaintenanceArgument(BundleRoot) + ' ' +
    QuoteMaintenanceArgument(ExpandConstant('{tmp}\file-set-v1.json')) + ' ' +
    QuoteMaintenanceArgument(ExpandConstant('{tmp}\keyring-v1.json'));

  if not Exec(ClientPath, Parameters, BundleRoot, SW_HIDE,
    ewWaitUntilTerminated, MaintenanceExitCode) then
  begin
    Result := CustomMessage('ServiceClientStartFailed');
    Exit;
  end;
  if MaintenanceExitCode <> 0 then
  begin
    Result := FmtMessage(CustomMessage('ServiceInstallUpgradeFailed'), [IntToStr(MaintenanceExitCode)]);
    if LoadStringFromFile(DiagnosticPath, MaintenanceDiagnostic) and
      (MaintenanceDiagnostic <> '') then
      Result := Result + #13#10#13#10 + MaintenanceDiagnostic;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := EnsureSE7ENService();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ExitCode: Integer;
  ServicePath: String;
begin
  if CurUninstallStep <> usUninstall then
    Exit;

  ServicePath := ExpandConstant('{app}\Se7enService.exe');
  if not FileExists(ServicePath) then
  begin
    { A service image that is already gone cannot stop or unregister itself. An SCM entry
      still pointing at it is dropped here, and [UninstallDelete] removes the component's
      remaining files and its release record -- the record above all, since one left behind
      without an SCM entry refuses every later install. A missing SCM entry makes sc.exe
      report 1060; that is the state wanted, so its exit code is not checked. }
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete SE7ENService', ExpandConstant('{app}'),
      SW_HIDE, ewWaitUntilTerminated, ExitCode);
    Exit;
  end;
  if (not Exec(ServicePath, 'uninstall-service', ExpandConstant('{app}'), SW_HIDE,
      ewWaitUntilTerminated, ExitCode)) or (ExitCode <> 0) then
  begin
    MsgBox(CustomMessage('ServiceRemovalFailed'), mbCriticalError, MB_OK);
    Abort;
  end;
end;
