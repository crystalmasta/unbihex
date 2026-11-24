; Установщик Unbihex для Windows (NSIS 3, Unicode).
Unicode true
SetCompressor /SOLID lzma
ManifestDPIAware true

!define APPNAME "Unbihex"
!define VERSION "0.2.12"
!define PUBLISHER "Crystalmasta"
!define COPYRIGHT "© 2026 Crystalmasta (github.com/crystalmasta)"
!define HOMEPAGE "https://github.com/crystalmasta"
!define EXE "Unbihex.exe"
!define DATADIR "com.unbihex.client"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
!define WV2GUID "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

Name "${APPNAME}"
OutFile "Unbihex-${VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel admin
BrandingText "${APPNAME} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=1049 "ProductName" "${APPNAME}"
VIAddVersionKey /LANG=1049 "FileDescription" "Установка ${APPNAME}"
VIAddVersionKey /LANG=1049 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1049 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1049 "CompanyName" "${PUBLISHER}"
VIAddVersionKey /LANG=1049 "LegalCopyright" "${COPYRIGHT}"

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"

!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\${EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить ${APPNAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; Закрывает запущенный клиент и выключает системный прокси, если он остался от него.
!macro StopApp
  nsExec::Exec 'taskkill /F /IM ${EXE}'
  Pop $0
  Sleep 500
  ReadRegDWORD $1 HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable"
  ReadRegStr $2 HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
  StrCpy $3 $2 10
  ${If} $0 == 0
  ${AndIf} $1 == 1
  ${AndIf} $3 == "127.0.0.1:"
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
  ${EndIf}
!macroend

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "${APPNAME} работает только на 64-битной Windows."
    Abort
  ${EndIf}
  SetRegView 64
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

Section "${APPNAME}" SecMain
  SectionIn RO
  !insertmacro StopApp
  SetOutPath "$INSTDIR"
  File "${EXE}"
  ; Older GNU builds needed it next to the exe; the MSVC build links it statically.
  Delete "$INSTDIR\WebView2Loader.dll"
  File "wintun.dll"
  File "wintun-LICENSE.txt"
  File "icon.ico"

  ; WebView2 есть в Windows 11 и обновлённой Windows 10; если нет — ставим.
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\${WV2GUID}" "pv"
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    ReadRegStr $0 HKCU "Software\Microsoft\EdgeUpdate\Clients\${WV2GUID}" "pv"
  ${EndIf}
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    DetailPrint "Установка Microsoft Edge WebView2..."
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "MicrosoftEdgeWebview2Setup.exe"
    ExecWait '"$PLUGINSDIR\MicrosoftEdgeWebview2Setup.exe" /silent /install' $1
    ${If} $1 != 0
      MessageBox MB_ICONEXCLAMATION "Не удалось установить Microsoft Edge WebView2 (код $1). Без него окно ${APPNAME} не откроется. Скачайте его с сайта Microsoft."
    ${EndIf}
    SetOutPath "$INSTDIR"
  ${EndIf}

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${UNINSTKEY}" "URLInfoAbout" "${HOMEPAGE}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" 15000

  SetShellVarContext all
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Удалить ${APPNAME}.lnk" "$INSTDIR\uninstall.exe"
  ; SHCNE_ASSOCCHANGED: Explorer drops cached icons.
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
SectionEnd

Section "Ярлык на рабочем столе" SecDesktop
  SetShellVarContext all
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${EXE}" "" "$INSTDIR\icon.ico"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Клиент ${APPNAME} и драйвер Wintun для режима TUN."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Ярлык для запуска с рабочего стола."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Выгружает HKU\${APPNAME}Uninstall. Реестр может держать куст ещё мгновение после
; чтения, поэтому до 10 попыток с паузой 300 мс. $R9 — код последней попытки (0 — выгружен).
; Портит $R2.
Function un.UnloadHive
  StrCpy $R2 0
  ${Do}
    nsExec::Exec '"$SYSDIR\reg.exe" unload "HKU\${APPNAME}Uninstall"'
    Pop $R9
    ${If} $R9 == 0
      ${ExitDo}
    ${EndIf}
    IntOp $R2 $R2 + 1
    ${If} $R2 >= 10
      ${ExitDo}
    ${EndIf}
    Sleep 300
  ${Loop}
FunctionEnd

; Убирает автозапуск из ветки HKU\$R1, если запись ведёт в $INSTDIR. Портит $R2–$R6.
Function un.ClearRun
  StrLen $R2 "$INSTDIR"
  IntOp $R5 $R2 + 1
  ReadRegStr $R3 HKU "$R1\Software\Microsoft\Windows\CurrentVersion\Run" "${APPNAME}"
  ; Значение: "<папка>\Unbihex.exe" --autostart
  StrCpy $R4 $R3 $R2 1
  StrCpy $R6 $R3 1 $R5
  ${If} $R4 == "$INSTDIR"
  ${AndIf} $R6 == "\"
    DeleteRegValue HKU "$R1\Software\Microsoft\Windows\CurrentVersion\Run" "${APPNAME}"
    DeleteRegValue HKU "$R1\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "${APPNAME}"
  ${EndIf}
FunctionEnd

Section "Uninstall"
  !insertmacro StopApp
  Delete "$INSTDIR\${EXE}"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\wintun-LICENSE.txt"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  SetShellVarContext all
  Delete "$DESKTOP\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\Удалить ${APPNAME}.lnk"
  RMDir "$SMPROGRAMS\${APPNAME}"

  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "Software\${APPNAME}"
  ; Автозапуск (HKCU\...\Run, issue #39) включает пользователь, а удаление идёт с правами
  ; администратора — возможно, под другой учётной записью. Поэтому запись убирается у всех
  ; вошедших пользователей (их ветки загружены в HKU), если она ведёт в $INSTDIR.
  ; By Finorion (github.com/Finorion), PR #43.
  StrCpy $R0 0
  ${Do}
    EnumRegKey $R1 HKU "" $R0
    ${If} $R1 == ""
      ${ExitDo}
    ${EndIf}
    IntOp $R0 $R0 + 1
    Call un.ClearRun
  ${Loop}
  ; У тех, кто сейчас не в системе, ветка не загружена, и запись осталась бы вести в
  ; удалённую папку: если $INSTDIR был вне Program Files, любой пользователь мог бы
  ; положить туда свой Unbihex.exe. Их NTUSER.DAT загружается на время очистки.
  ; Куст, оставшийся от прерванного удаления, выгружается сначала (ошибка — не наш случай).
  nsExec::Exec '"$SYSDIR\reg.exe" unload "HKU\${APPNAME}Uninstall"'
  Pop $R9
  StrCpy $R0 0
  ${Do}
    EnumRegKey $R7 HKLM "Software\Microsoft\Windows NT\CurrentVersion\ProfileList" $R0
    ${If} $R7 == ""
      ${ExitDo}
    ${EndIf}
    IntOp $R0 $R0 + 1
    ; Ветка уже в HKU — очищена выше.
    ClearErrors
    EnumRegKey $R8 HKU "$R7" 0
    ${IfNot} ${Errors}
      ${Continue}
    ${EndIf}
    ReadRegStr $R8 HKLM "Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$R7" "ProfileImagePath"
    ExpandEnvStrings $R8 $R8
    ${IfNot} ${FileExists} "$R8\NTUSER.DAT"
      ${Continue}
    ${EndIf}
    nsExec::Exec '"$SYSDIR\reg.exe" load "HKU\${APPNAME}Uninstall" "$R8\NTUSER.DAT"'
    Pop $R9
    ${If} $R9 == 0
      StrCpy $R1 "${APPNAME}Uninstall"
      Call un.ClearRun
      Call un.UnloadHive
      ${If} $R9 != 0
        ; Так и не выгрузился: следующий профиль на его место не загрузится. Чистка
        ; остальных профилей пропускается, само удаление продолжается.
        DetailPrint "Не удалось выгрузить $R8\NTUSER.DAT (reg unload: $R9)"
        ${ExitDo}
      ${EndIf}
    ${EndIf}
  ${Loop}

  ; Автозапуск с правами администратора — задания Планировщика «Unbihex autostart (…)» в
  ; корневой папке, по одному на пользователя (issue #39). Удаляются те, что запускают
  ; программу из $INSTDIR. Путь передаётся через переменную окружения, а не в тексте
  ; команды, — так кавычки и апострофы в нём ничего не ломают.
  System::Call 'kernel32::SetEnvironmentVariable(t "UNBIHEX_DIR", t "$INSTDIR")'
  nsExec::Exec `"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:UNBIHEX_DIR.TrimEnd('\') + '\'; $$s = New-Object -ComObject Schedule.Service; $$s.Connect(); $$f = $$s.GetFolder('\'); foreach ($$t in $$f.GetTasks(1)) { if ($$t.Name -like 'Unbihex autostart*') { foreach ($$a in $$t.Definition.Actions) { if ($$a.Type -eq 0 -and $$a.Path.StartsWith($$d, [StringComparison]::OrdinalIgnoreCase)) { $$f.DeleteTask($$t.Name, 0); break } } } }"`
  Pop $R9

  ; Подписки и настройки пользователя удаляются только по согласию.
  SetShellVarContext current
  IfFileExists "$APPDATA\${DATADIR}\*.*" 0 done
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Удалить также подписки, серверы и настройки ${APPNAME}?" /SD IDNO IDNO done
    RMDir /r "$APPDATA\${DATADIR}"
    RMDir /r "$LOCALAPPDATA\${DATADIR}"
  done:
SectionEnd
