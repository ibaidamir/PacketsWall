@echo off
title Refresh Icon Cache - Fix Blurry Icons

echo ========================================
echo      Refreshing Windows Icon Cache
echo ========================================
echo.

echo This will fix blurry/unclear icons on desktop shortcuts
echo.

REM Stop Windows Explorer
echo Step 1: Stopping Windows Explorer...
taskkill /f /im explorer.exe >nul 2>&1

REM Wait a moment
timeout /t 2 /nobreak >nul

REM Clear icon cache files
echo Step 2: Clearing icon cache files...

REM Navigate to icon cache location
cd /d "%localappdata%"

REM Delete icon cache files
del /a /q IconCache.db >nul 2>&1
del /a /f /q "%localappdata%\Microsoft\Windows\Explorer\iconcache*" >nul 2>&1

REM Clear thumbnail cache as well
echo Step 3: Clearing thumbnail cache...
del /a /f /q "%localappdata%\Microsoft\Windows\Explorer\thumbcache*" >nul 2>&1

REM Restart Windows Explorer
echo Step 4: Restarting Windows Explorer...
start explorer.exe

REM Wait for Explorer to fully load
timeout /t 3 /nobreak >nul

echo.
echo ========================================
echo      Icon Cache Refresh Complete!
echo ========================================
echo.
echo Your desktop icons should now appear clear and sharp.
echo If the icon is still blurry, try:
echo   1. Right-click on desktop and select "Refresh"
echo   2. Restart your computer
echo   3. Recreate the shortcut
echo.

pause

