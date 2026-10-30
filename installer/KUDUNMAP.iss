; KUDUNMAP installer (Inno Setup 6)
; Installs for the current Windows user only, so it never asks for administrator rights.
; Nmap is NOT included: KUDUNMAP asks the user to install it from nmap.org.

#ifndef MyAppVersion
  #define MyAppVersion "1.0.2"
#endif
#ifndef SourceDir
  #define SourceDir "..\out\KUDUNMAP"
#endif

#define MyAppName "KUDUNMAP"
#define MyAppExe "KUDUNMAP.exe"
#define MyAppUrl "https://github.com/azeembukhariprivate/kudunmap"

[Setup]
AppId={{4B7E2C91-6A3D-4F0E-9D25-7C1A8B3E5F42}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=Azeem Bukhari
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}/issues
AppUpdatesURL={#MyAppUrl}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=Output
OutputBaseFilename=KUDUNMAP-{#MyAppVersion}-setup
SetupIconFile=..\src\KUDUNMAP\Assets\KUDUNMAP.ico
UninstallDisplayIcon={app}\{#MyAppExe}
UninstallDisplayName={#MyAppName}
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany=Azeem Bukhari
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppName} Setup

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "self-test.log"

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "Open KUDUNMAP now"; Flags: nowait postinstall skipifsilent

[Registry]
; Remove saved settings when uninstalling. Scan history in %LOCALAPPDATA%\KUDUNMAP is kept.
Root: HKCU; Subkey: "Software\KUDUNMAP"; Flags: uninsdeletekey dontcreatekey
