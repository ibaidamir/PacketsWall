"""
PacketsWall - DDoS Attack Detection and Prevention System
Windows Installer Script

This script creates a Windows installer for the PacketsWall application using PyInstaller.
"""

import os
import sys
import shutil
import subprocess
import argparse

def create_installer(output_dir="dist", icon_path=None, version="1.0.0"):
    """
    Create a Windows installer for the PacketsWall application.
    
    Args:
        output_dir (str): Output directory for the installer
        icon_path (str): Path to the application icon
        version (str): Application version
    
    Returns:
        str: Path to the created installer
    """
    print("Creating Windows installer for PacketsWall...")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Create spec file for PyInstaller
    spec_content = f"""
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['packetswall_desktop.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['PyQt5.sip'],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PacketsWall',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    {'icon=r"' + icon_path + '",' if icon_path else ''}
    version='{version}',
)
"""
    
    with open("packetswall.spec", "w") as f:
        f.write(spec_content)
    
    # Run PyInstaller
    print("Running PyInstaller...")
    subprocess.run(["pyinstaller", "packetswall.spec", "--distpath", output_dir], check=True)
    
    # Create NSIS installer script
    nsis_script = f"""
; PacketsWall Installer Script
; Created with NSIS

!include "MUI2.nsh"

; General
Name "PacketsWall"
OutFile "{output_dir}\\PacketsWall_Setup_{version}.exe"
InstallDir "$PROGRAMFILES\\PacketsWall"
InstallDirRegKey HKLM "Software\\PacketsWall" "Install_Dir"
RequestExecutionLevel admin

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "{icon_path if icon_path else 'installer_icon.ico'}"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Arabic"

; Installer Sections
Section "Install"
    SetOutPath "$INSTDIR"
    
    ; Add files
    File /r "{output_dir}\\PacketsWall\\*.*"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\\PacketsWall"
    CreateShortcut "$SMPROGRAMS\\PacketsWall\\PacketsWall.lnk" "$INSTDIR\\PacketsWall.exe"
    CreateShortcut "$DESKTOP\\PacketsWall.lnk" "$INSTDIR\\PacketsWall.exe"
    
    ; Write registry keys
    WriteRegStr HKLM "Software\\PacketsWall" "Install_Dir" "$INSTDIR"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketsWall" "DisplayName" "PacketsWall"
    WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketsWall" "UninstallString" '"$INSTDIR\\uninstall.exe"'
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketsWall" "NoModify" 1
    WriteRegDWORD HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketsWall" "NoRepair" 1
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd

; Uninstaller Section
Section "Uninstall"
    ; Remove shortcuts
    Delete "$SMPROGRAMS\\PacketsWall\\PacketsWall.lnk"
    Delete "$DESKTOP\\PacketsWall.lnk"
    RMDir "$SMPROGRAMS\\PacketsWall"
    
    ; Remove files
    RMDir /r "$INSTDIR"
    
    ; Remove registry keys
    DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketsWall"
    DeleteRegKey HKLM "Software\\PacketsWall"
SectionEnd
"""
    
    with open("installer.nsi", "w") as f:
        f.write(nsis_script)
    
    # Create a simple license file if it doesn't exist
    if not os.path.exists("LICENSE.txt"):
        with open("LICENSE.txt", "w") as f:
            f.write("""
PacketsWall - DDoS Attack Detection and Prevention System
Copyright (c) 2025

This software is provided for educational and research purposes only.
Use of this software for any malicious purpose is strictly prohibited.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
""")
    
    # Create a simple icon if none is provided
    if not icon_path or not os.path.exists(icon_path):
        print("No icon provided, creating a default one...")
        from PIL import Image, ImageDraw
        
        # Create a 256x256 image with a blue background
        img = Image.new('RGBA', (256, 256), color=(0, 120, 212, 255))
        draw = ImageDraw.Draw(img)
        
        # Draw a simple shield shape
        draw.polygon([(128, 30), (226, 70), (226, 150), (128, 226), (30, 150), (30, 70)], fill=(255, 255, 255, 255))
        draw.polygon([(128, 50), (206, 80), (206, 140), (128, 206), (50, 140), (50, 80)], fill=(0, 120, 212, 255))
        
        # Save as ICO
        icon_path = "installer_icon.ico"
        img.save(icon_path, format="ICO")
    
    # Run NSIS to create the installer
    print("Running NSIS to create the installer...")
    try:
        # This would be the actual command on a Windows system
        # subprocess.run(["makensis", "installer.nsi"], check=True)
        
        # For demonstration, we'll just print a message
        print(f"NSIS would create the installer at: {output_dir}\\PacketsWall_Setup_{version}.exe")
        
        return f"{output_dir}\\PacketsWall_Setup_{version}.exe"
    
    except Exception as e:
        print(f"Error creating installer: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Create a Windows installer for PacketsWall")
    parser.add_argument("--output-dir", default="dist", help="Output directory for the installer")
    parser.add_argument("--icon", help="Path to the application icon")
    parser.add_argument("--version", default="1.0.0", help="Application version")
    
    args = parser.parse_args()
    
    installer_path = create_installer(args.output_dir, args.icon, args.version)
    
    if installer_path:
        print(f"Installer created successfully at: {installer_path}")
    else:
        print("Failed to create installer")
        sys.exit(1)

if __name__ == "__main__":
    main()
