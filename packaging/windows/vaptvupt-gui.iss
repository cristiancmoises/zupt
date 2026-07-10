; SPDX-License-Identifier: AGPL-3.0-or-later
; Inno Setup script for the VaptVupt GUI Windows installer.
;
; Compiled by the cross-platform CI (.github/workflows/cross-platform.yml) with:
;   ISCC.exe /DAppVersion=<version> packaging/windows/vaptvupt-gui.iss
; after PyInstaller has produced dist\vaptvupt-gui.exe (a onefile bundle that
; already contains Python, PySide6 and vaptvupt.exe). Requires Inno Setup 6+.
;
; To build locally on Windows: install Inno Setup, then run the same ISCC line
; from the repo root (with dist\vaptvupt-gui.exe present).

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppName=VaptVupt
AppVersion={#AppVersion}
AppPublisher=Cristian Cezar Moises
AppPublisherURL=https://git.securityops.co/cristiancmoises/vaptvupt
DefaultDirName={autopf}\VaptVupt
DefaultGroupName=VaptVupt
UninstallDisplayIcon={app}\vaptvupt-gui.exe
OutputDir=packaging\windows\Output
OutputBaseFilename=VaptVupt-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
LicenseFile=LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; PyInstaller onefile bundle (Python + PySide6 + the GUI + vaptvupt.exe).
Source: "dist\vaptvupt-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
; Ship the raw CLI too so it can be added to PATH and used from a terminal.
Source: "vaptvupt.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\VaptVupt"; Filename: "{app}\vaptvupt-gui.exe"
Name: "{group}\Uninstall VaptVupt"; Filename: "{uninstallexe}"
Name: "{autodesktop}\VaptVupt"; Filename: "{app}\vaptvupt-gui.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
Name: "addtopath"; Description: "Add the vaptvupt CLI to PATH (current user)"; GroupDescription: "Command line:"

[Registry]
; Optionally add the install dir to the user PATH (for the vaptvupt.exe CLI).
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
Filename: "{app}\vaptvupt-gui.exe"; Description: "Launch VaptVupt"; \
  Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + ExpandConstant(Param) + ';', ';' + OrigPath + ';') = 0;
end;
