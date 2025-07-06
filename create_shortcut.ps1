$currentDir = Get-Location
$desktopPath = "C:\Users\ASUS\OneDrive\Desktop"
$targetPath = Join-Path $currentDir "dist\PacketsWall.exe"
$shortcutPath = Join-Path $desktopPath "PacketsWall.lnk"
$iconPath = "C:\Users\ASUS\OneDrive\Desktop\PK\p\icons\logopacketswall.ico"

# حذف الاختصار القديم إذا موجود
try {
    if (Test-Path $shortcutPath) {
        Remove-Item $shortcutPath -Force -ErrorAction Stop
        Write-Host "Old shortcut deleted." -ForegroundColor Yellow
    }
} catch {
    Write-Host "ERROR: Couldn't delete existing shortcut. Close any apps using it." -ForegroundColor Red
    exit 1
}

# تحقق من ملفات البرنامج والأيقونة
if (-not (Test-Path $targetPath)) {
    Write-Host "ERROR: PacketsWall.exe not found!" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $iconPath)) {
    Write-Host "WARNING: Icon not found, will proceed without it." -ForegroundColor Yellow
    $iconPath = ""
}

# إنشاء الاختصار
try {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $targetPath
    $shortcut.WorkingDirectory = $currentDir.Path
    $shortcut.Description = "PacketsWall - DDoS Detection"
    $shortcut.WindowStyle = 1
    if ($iconPath -ne "") {
        $shortcut.IconLocation = $iconPath
    }
    $shortcut.Save()
    Write-Host "SUCCESS: Shortcut created at $shortcutPath" -ForegroundColor Green
} catch {
    Write-Host ("ERROR: Unable to save shortcut: " + $_.Exception.Message) -ForegroundColor Red
}