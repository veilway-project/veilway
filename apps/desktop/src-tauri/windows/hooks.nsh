; The helper refuses to run as an administrator from a folder others can write (check_install_dir in veilway-windows), so a chosen folder is replaced by Program Files.
!macro NSIS_HOOK_PREINSTALL
  ${If} $INSTDIR != "$PROGRAMFILES64\${PRODUCTNAME}"
    ${If} $PassiveMode != 1
      MessageBox MB_OK|MB_ICONINFORMATION "${PRODUCTNAME} runs with administrator rights, so it installs in $PROGRAMFILES64\${PRODUCTNAME}, where only administrators can change it." /SD IDOK
    ${EndIf}
    StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
    SetOutPath $INSTDIR
  ${EndIf}
!macroend
