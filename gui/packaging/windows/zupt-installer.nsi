; Zupt GUI — NSIS Installer Script
; Builds: ZuptGUI-Setup.exe
;
; Prerequisites on the build machine:
;   1. NSIS 3.x installed (https://nsis.sourceforge.io)
;   2. Run build-windows.bat first to create dist/ZuptGUI.exe
;   3. Place zupt.exe in this directory
;   4. Then: makensis zupt-installer.nsi

!include "MUI2.nsh"
!include "FileFunc.nsh"

; ── Config ──
!define APPNAME     "Zupt"
!define APPVERSION  "2.1.6"
!define GUIVERSION  "1.0.0"
!define PUBLISHER   "Cristian Cezar Moises"
!define HELPURL     "https://github.com/cristiancmoises/zupt"
!define EXE         "ZuptGUI.exe"
!define CLI         "zupt.exe"

Name "${APPNAME} ${APPVERSION}"
OutFile "ZuptGUI-${APPVERSION}-Setup.exe"
InstallDir "$PROGRAMFILES\${APPNAME}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel admin

; ── UI ──
!define MUI_ICON "..\..\assets\zupt.ico"
!define MUI_UNICON "..\..\assets\zupt.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Install ${APPNAME} ${APPVERSION}"
!define MUI_WELCOMEPAGE_TEXT "Post-quantum backup compression with ML-KEM-768 + X25519 hybrid encryption.$\r$\n$\r$\nThis will install the Zupt GUI and CLI tools."

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ── Install ──
Section "Install"
    SetOutPath $INSTDIR

    ; Copy files
    File "dist\${EXE}"
    File "${CLI}"
    File "..\..\assets\zupt.ico"
    File "..\..\LICENSE"
    File "..\..\README.md"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Start Menu
    CreateDirectory "$SMPROGRAMS\${APPNAME}"
    CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\zupt.ico"
    CreateShortcut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; Desktop shortcut
    CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\zupt.ico"

    ; Add to PATH (so zupt.exe is available system-wide)
    EnVar::AddValue "PATH" "$INSTDIR"

    ; Register .zupt file association
    WriteRegStr HKCR ".zupt" "" "ZuptArchive"
    WriteRegStr HKCR "ZuptArchive" "" "Zupt Archive"
    WriteRegStr HKCR "ZuptArchive\DefaultIcon" "" "$INSTDIR\zupt.ico"
    WriteRegStr HKCR "ZuptArchive\shell\open\command" "" '"$INSTDIR\${EXE}" --extract "%1"'
    WriteRegStr HKCR "ZuptArchive\shell\verify\command" "" '"$INSTDIR\${CLI}" test "%1"'
    WriteRegStr HKCR "ZuptArchive\shell\verify" "" "Verify Integrity"

    ; Right-click "Compress with Zupt" on any file
    WriteRegStr HKCR "*\shell\ZuptCompress" "" "Compress with Zupt"
    WriteRegStr HKCR "*\shell\ZuptCompress\Icon" "" "$INSTDIR\zupt.ico"
    WriteRegStr HKCR "*\shell\ZuptCompress\command" "" '"$INSTDIR\${EXE}" --compress "%1"'

    ; Right-click on directories
    WriteRegStr HKCR "Directory\shell\ZuptCompress" "" "Compress with Zupt"
    WriteRegStr HKCR "Directory\shell\ZuptCompress\Icon" "" "$INSTDIR\zupt.ico"
    WriteRegStr HKCR "Directory\shell\ZuptCompress\command" "" '"$INSTDIR\${EXE}" --compress "%1"'

    ; Add/Remove Programs entry
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME} — Post-Quantum Backup"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$INSTDIR\zupt.ico"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${APPVERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "URLInfoAbout" "${HELPURL}"

    ; Calculate installed size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "EstimatedSize" "$0"
SectionEnd

; ── Uninstall ──
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\${EXE}"
    Delete "$INSTDIR\${CLI}"
    Delete "$INSTDIR\zupt.ico"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove shortcuts
    Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
    Delete "$SMPROGRAMS\${APPNAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${APPNAME}"
    Delete "$DESKTOP\${APPNAME}.lnk"

    ; Remove from PATH
    EnVar::DeleteValue "PATH" "$INSTDIR"

    ; Remove file associations
    DeleteRegKey HKCR ".zupt"
    DeleteRegKey HKCR "ZuptArchive"
    DeleteRegKey HKCR "*\shell\ZuptCompress"
    DeleteRegKey HKCR "Directory\shell\ZuptCompress"

    ; Remove Add/Remove Programs entry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
    DeleteRegKey HKLM "Software\${APPNAME}"
SectionEnd
