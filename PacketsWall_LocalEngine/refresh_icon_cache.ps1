# PowerShell script to refresh icon cache and fix blurry icons
# Run as Administrator for best results

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "      Windows Icon Cache Refresh" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "This script will fix blurry/unclear desktop icons" -ForegroundColor Yellow
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator" -ForegroundColor Red
    Write-Host "For best results, run PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host ""
}

try {
    # Step 1: Stop Windows Explorer
    Write-Host "Step 1: Stopping Windows Explorer..." -ForegroundColor Green
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Step 2: Clear icon cache
    Write-Host "Step 2: Clearing icon cache files..." -ForegroundColor Green
    
    $iconCachePath = "$env:LOCALAPPDATA"
    $iconCacheFiles = @(
        "$iconCachePath\IconCache.db",
        "$iconCachePath\Microsoft\Windows\Explorer\iconcache*.db",
        "$iconCachePath\Microsoft\Windows\Explorer\thumbcache*.db"
    )
    
    foreach ($pattern in $iconCacheFiles) {
        Get-ChildItem -Path $pattern -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # Step 3: Clear additional cache locations
    Write-Host "Step 3: Clearing additional cache locations..." -ForegroundColor Green
    
    # Clear registry icon cache
    if ($isAdmin) {
        try {
            Remove-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" -Name "*" -ErrorAction SilentlyContinue
        } catch {
            # Ignore errors
        }
    }

    # Step 4: Restart Windows Explorer
    Write-Host "Step 4: Restarting Windows Explorer..." -ForegroundColor Green
    Start-Process "explorer.exe"
    Start-Sleep -Seconds 3

    # Step 5: Refresh desktop
    Write-Host "Step 5: Refreshing desktop..." -ForegroundColor Green
    
    # Force desktop refresh
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class Win32 {
            [DllImport("user32.dll", SetLastError = true)]
            public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
            
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool InvalidateRect(IntPtr hWnd, IntPtr lpRect, bool bErase);
            
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool UpdateWindow(IntPtr hWnd);
        }
"@
    
    $desktop = [Win32]::FindWindow("Progman", "Program Manager")
    [Win32]::InvalidateRect($desktop, [IntPtr]::Zero, $true)
    [Win32]::UpdateWindow($desktop)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "      Icon Cache Refresh Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your desktop icons should now appear clear and sharp." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "If icons are still blurry, try:" -ForegroundColor Yellow
    Write-Host "  1. Right-click desktop and select 'Refresh'" -ForegroundColor White
    Write-Host "  2. Log off and log back in" -ForegroundColor White
    Write-Host "  3. Restart your computer" -ForegroundColor White
    Write-Host "  4. Recreate the shortcut" -ForegroundColor White

} catch {
    Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Try running as Administrator or use the .bat file instead" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

