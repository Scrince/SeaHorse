#define MyAppName "SeaHorse"
#define MyAppVersion "0.2.0"
#define MyAppExeName "SeaHorse.exe"
[Setup]
AppId={{C45DAD10-2B19-4C61-8F1C-4C6101D78190}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=SeaHorse
DefaultDirName={localappdata}\Programs\SeaHorse
DefaultGroupName=SeaHorse
OutputDir=..\release\windows
OutputBaseFilename=SeaHorse-Setup-0.2.0
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
Uninstallable=yes

[Files]
Source: "..\dist\SeaHorse\SeaHorse.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\SeaHorse\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SeaHorse"; Filename: "{app}\SeaHorse.exe"

