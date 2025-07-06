' VBScript to create PacketsWall desktop shortcut
' Works on all Windows versions without additional libraries

Dim objShell, objFSO, currentDir, desktopPath
Dim targetPath, iconPathHQ, iconPathOriginal, iconPathPNG, iconPath, shortcutPath, shortcut

' Create system objects
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Get current directory
currentDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Get desktop path
desktopPath = objShell.SpecialFolders("Desktop")

' Define file paths
targetPath = currentDir & "\PacketsWall.py"
iconPathHQ = currentDir & "\icons\molotov1_hq.ico"
iconPathOriginal = currentDir & "\icons\molotov1.ico"
iconPathPNG = currentDir & "\icons\molotov1.png"
shortcutPath = desktopPath & "\PacketsWall.lnk"

' Check if PacketsWall.py exists
If Not objFSO.FileExists(targetPath) Then
    WScript.Echo "ERROR: PacketsWall.py not found in current directory"
    WScript.Quit 1
End If

' Determine which icon to use (prefer high quality)
iconPath = ""
If objFSO.FileExists(iconPathHQ) Then
    iconPath = iconPathHQ
    WScript.Echo "Using high quality icon: molotov1_hq.ico"
ElseIf objFSO.FileExists(iconPathOriginal) Then
    iconPath = iconPathOriginal
    WScript.Echo "Using original icon: molotov1.ico"
ElseIf objFSO.FileExists(iconPathPNG) Then
    iconPath = iconPathPNG
    WScript.Echo "Using PNG icon: molotov1.png"
Else
    WScript.Echo "WARNING: No icon file found"
End If

' Try to create shortcut
On Error Resume Next

' Create shortcut
Set shortcut = objShell.CreateShortcut(shortcutPath)

' Set shortcut properties
shortcut.TargetPath = "python"
shortcut.Arguments = """" & targetPath & """"
shortcut.WorkingDirectory = currentDir
shortcut.Description = "PacketsWall - DDoS Detection and Prevention System"
shortcut.WindowStyle = 1

' Set icon if available
If iconPath <> "" Then
    shortcut.IconLocation = iconPath
End If

' Save shortcut
shortcut.Save

' Check if successful
If Err.Number = 0 Then
    WScript.Echo "SUCCESS: PacketsWall shortcut created on desktop!"
    WScript.Echo "Shortcut path: " & shortcutPath
    
    If iconPath <> "" Then
        WScript.Echo "Icon set successfully"
    End If
    
    WScript.Echo ""
    WScript.Echo "You can now:"
    WScript.Echo "  - Find the shortcut on your desktop"
    WScript.Echo "  - Double-click it to run PacketsWall"
    WScript.Echo "  - See molotov icon in taskbar when running"
Else
    WScript.Echo "ERROR creating shortcut: " & Err.Description
    WScript.Quit 1
End If

' Clean up objects
Set shortcut = Nothing
Set objShell = Nothing
Set objFSO = Nothing

