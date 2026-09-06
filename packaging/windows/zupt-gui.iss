; SPDX-License-Identifier: AGPL-3.0-or-later
; Inno Setup 6 recipe for target-built ZUPT Windows artifacts.
;
; All paths are mandatory command-line definitions. This prevents the recipe
; from silently picking up a stale or placeholder executable from the tree.

#ifndef AppVersion
  #error AppVersion must be defined
#endif
#ifndef GuiExecutable
  #error GuiExecutable must name a tested PyInstaller GUI executable
#endif
#ifndef CliExecutable
  #error CliExecutable must name a tested source-built zupt.exe
#endif
#ifndef BuildOutputDir
  #error BuildOutputDir must be an external output directory
#endif
#ifndef RuntimeNoticesDir
  #error RuntimeNoticesDir must contain notices for the exact bundled GUI runtime
#endif

[Setup]
AppId={{59AD35E4-1860-445D-8E89-4563DB9ED4E2}
AppName=ZUPT
AppVersion={#AppVersion}
AppPublisher=Cristian Cezar Moises
AppPublisherURL=https://github.com/cristiancmoises/zupt
AppSupportURL=https://github.com/cristiancmoises/zupt/issues
DefaultDirName={autopf}\ZUPT
DefaultGroupName=ZUPT
UninstallDisplayIcon={app}\zupt-gui.exe
OutputDir={#BuildOutputDir}
OutputBaseFilename=ZUPT-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
LicenseFile=..\..\LICENSE
ChangesAssociations=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#GuiExecutable}"; DestDir: "{app}"; DestName: "zupt-gui.exe"; Flags: ignoreversion
Source: "{#CliExecutable}"; DestDir: "{app}"; DestName: "zupt.exe"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-AGPL-3.0"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-GPL-3.0"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-BSD-2-Clause"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-BSD-3-Clause"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-CC0-1.0"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\gui\LICENSE-GUI"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\gui\assets\README.md"; DestDir: "{app}"; DestName: "GUI-ASSET-PROVENANCE.md"; Flags: ignoreversion
Source: "{#RuntimeNoticesDir}\*"; DestDir: "{app}\third-party-runtime-notices"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\..\README.pt-BR.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\DOCUMENTACAO.pt-BR.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ZUPT GUI"; Filename: "{app}\zupt-gui.exe"
Name: "{group}\ZUPT command prompt"; Filename: "{cmd}"; Parameters: "/K cd /d ""{app}"""
Name: "{group}\Uninstall ZUPT"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ZUPT GUI"; Filename: "{app}\zupt-gui.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
Name: "addtopath"; Description: "Add the ZUPT command to PATH for this user"; GroupDescription: "Command line:"

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')
Root: HKCU; Subkey: "Software\Classes\.zupt"; ValueType: string; ValueName: ""; \
  ValueData: "ZUPT.Archive"; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\ZUPT.Archive"; ValueType: string; \
  ValueName: ""; ValueData: "ZUPT archive"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\ZUPT.Archive\shell\open\command"; \
  ValueType: string; ValueName: ""; ValueData: """{app}\zupt-gui.exe"" --extract ""%1"""

[Run]
Filename: "{app}\zupt-gui.exe"; Description: "Launch ZUPT GUI"; \
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
