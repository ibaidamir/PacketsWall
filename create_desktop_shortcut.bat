@echo off
title Create PacketsWall Desktop Shortcut

echo ========================================
echo      Create PacketsWall Shortcut
echo ========================================
echo.

REM Check if PacketsWall.py exists
if not exist "PacketsWall.py" (
    echo ERROR: PacketsWall.py not found in current directory
    echo Please make sure the file exists in the same folder as this script
    pause
    exit /b 1
)

REM Check if icons folder exists
if not exist "icons" (
    echo WARNING: icons folder not found
    mkdir icons
    echo Created icons folder
)

REM Check if icon file exists
if not exist "icons\molotov1.ico" (
    echo WARNING: molotov1.ico icon file not found
    echo Shortcut will be created without custom icon
)

echo Creating desktop shortcut...
echo.

REM Try PowerShell first
echo Trying PowerShell method...
powershell -ExecutionPolicy Bypass -File "create_shortcut.ps1" 2>nul

if %errorlevel% equ 0 (
    echo SUCCESS: Shortcut created using PowerShell!
    goto success
)

REM If PowerShell fails, try VBScript
echo Trying VBScript method...
cscript //nologo "create_shortcut.vbs"

if %errorlevel% equ 0 (
    echo SUCCESS: Shortcut created using VBScript!
    goto success
)

REM If both methods fail
echo ERROR: Failed to create shortcut
echo Please try manually or check permissions
goto end

:success
echo.
echo SUCCESS: PacketsWall shortcut created on desktop!
echo The shortcut includes molotov custom icon
echo.
echo You can now:
echo   - Find the shortcut on your desktop
echo   - Double-click it to run PacketsWall
echo   - See molotov icon in taskbar when running

:end
echo.
echo Press any key to exit...
pause >nul

