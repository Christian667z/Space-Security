@echo off
setlocal enabledelayedexpansion

echo =========================================================================
echo Space Security - Kernel Minifilter Compilation Script (WDK / MSBuild)
echo =========================================================================

:: Check if MSBuild is in PATH or Visual Studio environment
where msbuild >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] msbuild.exe introuvable dans le PATH.
    echo [*] Recherche de l'environnement Visual Studio 2022...
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else (
        echo [ERROR] Visual Studio 2022 et Windows Driver Kit (WDK) introuvables.
        echo Veuillez installer le WDK depuis https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
        exit /b 1
    )
)

echo [*] Verification des fichiers sources du pilote...
if not exist "spacesec_minifilter.c" (
    echo [ERROR] Fichier spacesec_minifilter.c manquant.
    exit /b 1
)
if not exist "spacesec_minifilter.inf" (
    echo [ERROR] Fichier spacesec_minifilter.inf manquant.
    exit /b 1
)

echo [*] Cible : Windows 10/11 x64 Release
echo [*] Altitude Minifilter : 320500 (FSFilter Anti-Virus)
echo [*] Compilation de spacesec_minifilter.sys via CL / WDK include headers...

:: Standard WDK compilation command
cl.exe /nologo /W4 /WX /kernel /Gz /O2 /Oi /D_AMD64_ /D_WIN64 /DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DPOOL_NX_OPTIN=1 /I"%WindowsSdkDir%Include\%WindowsSDKVersion%km" /I"%WindowsSdkDir%Include\%WindowsSDKVersion%km\crt" /c spacesec_minifilter.c /Fospacesec_minifilter.obj

if %ERRORLEVEL% equ 0 (
    echo [*] Linkage du pilote binaire...
    link.exe /nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /SECTION:.rsrc,!d /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /NODEFAULTLIB /LIBPATH:"%WindowsSdkDir%Lib\%WindowsSDKVersion%km\x64" fltMgr.lib ntoskrnl.lib hal.lib BufferOverflowK.lib /OUT:spacesec_minifilter.sys spacesec_minifilter.obj
    
    if exist "spacesec_minifilter.sys" (
        echo [SUCCESS] spacesec_minifilter.sys compile avec succes !
        echo [*] Pour tester localement : bcdedit /set testsigning on ^&^& fltmc load SpaceSecMinifilter
    )
) else (
    echo [INFO] Pour la compilation automatique complete, ouvrez la solution dans Visual Studio avec le profil WDK Driver.
)

exit /b 0
