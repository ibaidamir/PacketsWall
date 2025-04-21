import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt, QTimer, QSettings
try:
    from scapy.all import *
except ImportError:
    print("Installing Scapy package...")
    os.system("pip install scapy")
    try:
        from scapy.all import *
    except ImportError:
        print("Error: Could not install Scapy. Please install it manually using 'pip install scapy'")

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
except ImportError:
    print("Installing PyQt5 package...")
    os.system("pip install PyQt5")
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui
    except ImportError:
        print("Error: Could not install PyQt5. Please install it manually using 'pip install PyQt5'")

print("بدء تشغيل نظام كشف هجمات DDoS...")
print("Starting PacketsWall DDoS Detection System...")
print("Loading from current directory:", os.getcwd())

# Check if the file exists in the current directory
if os.path.exists("packetswall_real_debug.py"):
    print("Found packetswall_real_debug.py in current directory")
    # Import the main code
    exec(open("packetswall_real_debug.py", encoding="utf-8").read())
else:
    # Try to find the file in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_file = os.path.join(script_dir, "packetswall_real_debug.py")
    
    if os.path.exists(target_file):
        print(f"Found packetswall_real_debug.py at: {target_file}")
        # Import the main code
        exec(open(target_file, encoding="utf-8").read())
    else:
        print("Error: Could not find packetswall_real_debug.py")
        print("Please make sure this launcher is in the same directory as packetswall_real_debug.py")
        print("Current directory:", os.getcwd())
        print("Script directory:", script_dir)
        input("Press Enter to exit...")
