@echo off
title KillWin10 - v0.1 - Welcome: %username%
MODE CON cols=70 lines=15
color b
echo.
::: ,--. ,--.,--.,--.,--.,--.   ,--.,--.         ,--.  ,--.  
::: |  .'   /`--'|  ||  ||  |   |  |`--',--,--, /   | /    \ 
::: |  .   ' ,--.|  ||  ||  |.'.|  |,--.|      \`|  ||    |
::: |  |\   \|  ||  ||  ||   ,'.   ||  ||  ||  | |  | \    / 
::: `--' '--'`--'`--'`--''--'   '--'`--'`--''--' `--'  `--'          

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A

echo.
echo.
echo.
echo.
goto check_Permissions

color b
:check_Permissions
    net session > nul 2>&1
    if %errorLevel% == 0 (
        echo SUCCESS: Bienvenid@ %username%!
        ping -n 3 localhost > nul
        goto:verificado
    ) else (
        echo ERROR: Ejecuta el script como Administrador
        ping -n 5 localhost > nul
        exit
    )

    pause > nul

SET var = 0
ping -n 5 localhost > nul
echo.
cls
echo iniciando espera...
ping -n  1 localhost > nul
echo.

:verificado
color b
MODE CON cols=110 lines=30
cls
:pag1
cls
:inicio
echo                                         ========================================
echo                                         =                                      
echo                                         =     KillWin10 creado por MrRecoveryy       
echo                                         =          Usuario: %username%             
echo                                         ========================================
echo.
echo                                                        Pag (1/1)
echo.
echo                              +-------------------------------+-----------------------------+
echo                              +  1. Enable HPET               +     9. Reparar Fallos de Red
echo                              +-------------------------------+-----------------------------+
echo                              +  2. Disable HPET              +     10. Test     
echo                              +-------------------------------+-----------------------------+
echo                              +  3. Disable Superfetch        +     11. N/A
echo                              +-------------------------------+-----------------------------+
echo                              +  4. Disable Xbox DVR          +     12. N/A
echo                              +-------------------------------+-----------------------------+
echo                              +  5. *Remove Win 10 Debloat*   +     13. N/A
echo                              +-------------------------------+-----------------------------+
echo                              +  6. Uninstall OneDrive        +     14. N/A
echo                              +-------------------------------+-----------------------------+
echo                              +  7. Disable Telemetry         +     15. N/A
echo                              +-------------------------------+-----------------------------+
echo                              +  8. Remove Cortana            +     16. N/A
echo                              +-------------------------------+-----------------------------+
echo.
SET /p var=$ 
if "%var%" == "0" goto inicio
if "%var%" == "1" goto opcion1
if "%var%" == "2" goto opcion2
if "%var%" == "3" goto opcion3
if "%var%" == "4" goto opcion4
if "%var%" == "5" goto opcion4
if "%var%" == "6" goto opcion4
if "%var%" == "7" goto opcion4
if "%var%" == "8" goto opcion4
if "%var%" == "9" goto opcion4
if "%var%" == ">" goto pag2
if "%var%" == "s" goto salir
::Mensaje de error, validación cuando se selecciona una opción fuera de rango
echo. ERROR "%var%" no existe
ping -n 2 localhost > nul
echo.
cls
goto:inicio

:opcion1
    echo.
    echo.
        ::
		cls
        echo Restaurando HPET...
        ping -n 2 localhost>nul
        bcdedit /set useplatformclock true
        echo Status... OK
        bcdedit /set disabledynamictick no
        echo Status... OK
        cls
        echo HPET ha sido habilitado en el sistema,para que se apliquen los cambios reinicie el sistema.
        pause
        goto:inicio

:://////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

:opcion2
    echo.
    echo.
        ::
		cls
        echo Deshabilitando HPET del sistema...
        ping -n 2 localhost>nul
        cls
        bcdedit /deletevalue useplatformclock
        echo Status... OK
        bcdedit /set disabledynamictick yes
        echo Status... OK
        cls
        echo HPET ha sido deshabilitado en el sistema,para que se apliquen los cambios reinicie el sistema.
        pause
        goto:inicio

:opcion3
    echo.
    echo.
        ::
		cls
        net.exe stop superfetch
        sc config sysmain start=disabled”
        cls
        echo Superfetch ha sido deshabilitado.
        echo.
        pause
        goto:inicio

:opcion4
    echo.
    echo.
        ::
		cls
        echo Deshabilitando Xbox DVR
        ping -n 2 localhost>nul
        cls
        reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
        sc config XblAuthManager start= disabled
        sc config XblGameSave start= disabled
        sc config XboxGipSvc start= disabled
        sc config XboxNetApiSvc start= disabled
        schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
        takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
        icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
        taskkill /im GameBarPresenceWriter.exe /f
        move "C:\Windows\System32\GameBarPresenceWriter.exe" "C:\Windows\System32\GameBarPresenceWriter.OLD"
        schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
        takeown /f "%WinDir%\System32\bcastdvr.exe" /a
        icacls "%WinDir%\System32\bcastdvr.exe" /grant:r Administrators:F /c
        taskkill /im bcastdvr.exe /f
        move C:\Windows\System32\bcastdvr.exe C:\Windows\System32\bcastdvr.OLD
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
        reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
        reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
        reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
        reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
        reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
        cls
        echo Xbox DVR ha sido deshabilitado de Windows 10
        echo.
        pause
        goto:inicio


:opcion5
    echo.
    echo Removing Bloat Windows 10
    ping -n 4 localhost>nul
    cls
    @rem *** Disable Some Service ***
    sc stop DiagTrack
    sc stop diagnosticshub.standardcollector.service
    sc stop dmwappushservice
    sc stop WMPNetworkSvc
    sc stop WSearch

    sc config DiagTrack start= disabled
    sc config diagnosticshub.standardcollector.service start= disabled
    sc config dmwappushservice start= disabled
    REM sc config RemoteRegistry start= disabled
    REM sc config TrkWks start= disabled
    sc config WMPNetworkSvc start= disabled
    sc config WSearch start= disabled
    REM sc config SysMain start= disabled

    REM *** SCHEDULED TASKS tweaks ***
    REM schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
    schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
    schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
    schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
    schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
    schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
    schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
    schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
    schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
    schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
    schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
    schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

    REM schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
    REM schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
    REM The stubborn task Microsoft\Windows\SettingSync\BackgroundUploadTask can be Disabled using a simple bit change. I use a REG file for that (attached to this post).
    REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
    REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable

    REM *** Remove Cortana ***
    REM Currently MS doesn't allow to uninstall Cortana using the above step claiming it's a required OS component (hah!)
    REM We will have to rename the Cortana App folder (add ".bak" to its name), but this can be done only if Cortana is not running.
    REM The issue is that when Cortana process (SearchUI) is killed, it respawns very quickly
    REM So the following code needs to be quick (and it is) so we can manage to rename the folder
    REM
    REM Disabling Cortana this way on Version 1703 (RS2) will render all items in the Start Menu unavailable.
    REM So this is commented out for now until a better solution is found.
    REM taskkill /F /IM SearchUI.exe
    REM move "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy.bak"

    @rem *** Remove Telemetry & Data Collection ***
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

    @REM Settings -> Privacy -> General -> Let apps use my advertising ID...
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
    REM - SmartScreen Filter for Store Apps: Disable
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
    REM - Let websites provide locally...
    reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

    @REM WiFi Sense: HotSpot Sharing: Disable
    reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
    @REM WiFi Sense: Shared HotSpot Auto-Connect: Disable
    reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f

    @REM Change Windows Updates to "Notify to schedule restart"
    reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
    @REM Disable P2P Update downlods outside of local network
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

    @REM *** Disable Cortana & Telemetry ***
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0

    REM *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
    REM 0 = hide completely, 1 = show only icon, 2 = show long search box
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

    REM *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

    REM *** Set Windows Explorer to start on This PC instead of Quick Access ***
    REM 1 = This PC, 2 = Quick access
    REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

    REM *** Disable Suggestions in the Start Menu ***
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f 

    @rem Remove Apps
    PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Cortana* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
    REM PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
    REM PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *ContentDeliveryManager* | Remove-AppxPackage"
    PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage"


    @rem NOW JUST SOME TWEAKS
    REM *** Show hidden files in Explorer ***
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
    
    REM *** Show super hidden system files in Explorer ***
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

    REM *** Show file extensions in Explorer ***
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f
    cls
    echo Complete!
    echo.
    pause
    goto:inicio


:opcion6
    echo.
    echo.
        ::
		cls
        echo Desinstalando One Drive del sistema...
        ping -n 3 localhost>nul
        cls
        REM *** Uninstall OneDrive ***
        start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
        rd C:\OneDriveTemp /Q /S >NUL 2>&1
        rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
        rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
        rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
        reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
        reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
        cls
        echo One Drive ha sido eliminado del sistema,se requiere reiniciar el explorador,espere...
        ping -n 2 localhost>nul
        start /wait TASKKILL /F /IM explorer.exe
        start explorer.exe
        goto:inicio

:opcion7
    echo.
    echo.
        ::
		cls
        echo Deshabilitando Telemetria de Windows...
        ping -n 3 localhost>nul
        cls
        sc stop DiagTrack
        sc config DiagTrack start= disabled
        sc stop dmwappushservice
        sc config dmwappushservice start= disabled
        reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\ /v Start /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ /v AllowTelemetry /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility\ /v DiagnosticErrorText /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticErrorText /t REG_SZ /d "" /f
        reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticLinkText /t REG_SZ /d "" /f
        cls
        echo One Drive ha sido desinstalado del sistema.
        echo.
        pause
        goto:inicio

:opcion8
    echo.
    echo.
        ::
		cls
        echo Deshabilitando Cortana...
        ping -n 3 localhost>nul
        cls
        taskkill /f /IM "SearchUI.exe"
        "%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
        "%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setowner -ownr "n:%USERNAME%"
        "%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:%USERNAME%;p:full"
        "%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:System;p:read"
        ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak"
        cls
        echo Cortana ha sido deshabilitada del sistema.
        echo.
        pause
        goto:inicio

:opcion10
    echo.
    echo.
        ::
        cls
        echo Test




:salir
    @cls&exit
