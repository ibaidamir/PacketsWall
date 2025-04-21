import sys
import os
import threading
import time
import logging
import socket
import ctypes
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QProgressBar, QComboBox, QLineEdit, QGroupBox,
                            QFormLayout, QSpinBox, QDoubleSpinBox, QCheckBox, QMessageBox,
                            QFileDialog)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QIcon, QPixmap
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
import queue
import collections

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('PacketsWall')

# Packet processing thread class
class PacketProcessorThread(QThread):
    packet_processed = pyqtSignal()
    
    def __init__(self, detection_system):
        super().__init__()
        self.detection_system = detection_system
        self.packet_queue = queue.Queue(maxsize=10000)  # Increased queue size
        self.running = False
    
    def add_packet(self, packet):
        try:
            # Non-blocking put with timeout to prevent queue from growing too large
            self.packet_queue.put(packet, block=True, timeout=0.01)
        except queue.Full:
            # If queue is full, log and discard packet
            logger.warning("Packet queue full, discarding packet")
    
    def run(self):
        self.running = True
        while self.running:
            try:
                # Get packet with timeout to allow thread to check running flag
                packet = self.packet_queue.get(block=True, timeout=0.1)
                self.detection_system._process_packet(packet)
                self.packet_processed.emit()
            except queue.Empty:
                # No packet available, just continue
                pass
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    def stop(self):
        self.running = False
        self.wait()

# Real DDoS detection system using Scapy
class DDoSDetectionSystem:
    def __init__(self, interface=None):
        self.interface = interface
        self.running = False
        self.stats = {
            'start_time': None,
            'packets_processed': 0,
            'attacks_detected': {
                'tcp': 0,
                'udp': 0,
                'http': 0,
                'icmp': 0
            },
            'ips_blocked': 0,
            'blocked_ips': []
        }
        self.alerts = []
        
        # Use deque with max length for packet counts to limit memory usage
        self.packet_counts = {}
        self.last_cleanup_time = time.time()
        self.cleanup_interval = 10  # seconds
        
        # Adaptive threshold settings
        self.allowed_increase_percent = 20  # Default: 20% increase allowed
        
        # Historical traffic data for adaptive thresholds
        self.historical_traffic = {
            'tcp': collections.deque(maxlen=10),  # Store last 10 intervals
            'udp': collections.deque(maxlen=10),
            'http': collections.deque(maxlen=10),
            'icmp': collections.deque(maxlen=10)
        }
        
        # Initial baseline thresholds (will be adjusted dynamically)
        self.baseline_thresholds = {
            'tcp': 100,
            'udp': 100,
            'http': 50,
            'icmp': 30
        }
        
        # Current adaptive thresholds
        self.adaptive_thresholds = self.baseline_thresholds.copy()
        
        # Lock for thread safety
        self.lock = threading.RLock()  # Use RLock to allow nested acquisitions
        
        # Sniffer thread
        self.sniffer_thread = None
        
        # Packet processor thread
        self.processor_thread = PacketProcessorThread(self)
        
        # Traffic data for chart
        self.traffic_data = collections.deque(maxlen=60)  # Store last 60 seconds of data
        self.last_traffic_update = time.time()
        
    def start(self):
        try:
            self.running = True
            self.stats['start_time'] = time.time()
            
            # Start packet processor thread
            self.processor_thread.start()
            
            # Start packet sniffer in a separate thread
            self.sniffer_thread = threading.Thread(target=self._start_sniffer, daemon=True)
            self.sniffer_thread.start()
            
            logger.info("DDoS detection system started")
            return True
        except Exception as e:
            logger.error(f"Error starting DDoS detection system: {e}")
            self.running = False
            return False
        
    def stop(self):
        try:
            self.running = False
            
            # Stop processor thread
            if self.processor_thread.isRunning():
                self.processor_thread.stop()
            
            # Stop sniffer thread
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(timeout=1.0)
            
            logger.info("DDoS detection system stopped")
            return True
        except Exception as e:
            logger.error(f"Error stopping DDoS detection system: {e}")
            return False
    
    def _start_sniffer(self):
        """Start the packet sniffer using Scapy"""
        try:
            # Define the BPF filter if needed
            filter_str = ""
            
            # Use AsyncSniffer instead of sniff for better performance
            sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "All Interfaces" else None,
                prn=self._packet_callback,
                filter=filter_str if filter_str else None,
                store=0  # Don't store packets in memory
            )
            
            # Start sniffing
            sniffer.start()
            
            # Keep checking if we should stop
            while self.running:
                time.sleep(0.1)
            
            # Stop sniffing
            sniffer.stop()
            
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
    
    def _packet_callback(self, packet):
        """Initial callback for captured packets - just queue them for processing"""
        if not self.running:
            return
        
        # Add packet to processing queue without rate limiting
        self.processor_thread.add_packet(packet)
    
    def _process_packet(self, packet):
        """Process each captured packet - called from processor thread"""
        try:
            # Use a shorter lock scope to reduce contention
            with self.lock:
                # Increment packet counter
                self.stats['packets_processed'] += 1
                
                # Update traffic data
                current_time = time.time()
                if current_time - self.last_traffic_update >= 1.0:
                    self.traffic_data.append(self.stats['packets_processed'])
                    self.last_traffic_update = current_time
            
            # Check if packet has IP layer
            if IP in packet:
                src_ip = packet[IP].src
                
                # Process packet details without holding the lock
                packet_info = {
                    'tcp': 0,
                    'udp': 0,
                    'http': 0,
                    'icmp': 0,
                    'total': 1,
                    'last_seen': time.time()
                }
                
                # TCP SYN Flood detection
                if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag is set
                    packet_info['tcp'] = 1
                    
                # UDP Flood detection
                elif UDP in packet:
                    packet_info['udp'] = 1
                    
                # HTTP Flood detection
                elif TCP in packet and packet[TCP].dport == 80:
                    if Raw in packet and b'HTTP' in packet[Raw].load:
                        packet_info['http'] = 1
                
                # ICMP Flood detection
                elif ICMP in packet:
                    packet_info['icmp'] = 1
                
                # Now update counters with lock
                with self.lock:
                    # Initialize counter for this IP if not exists
                    if src_ip not in self.packet_counts:
                        self.packet_counts[src_ip] = {
                            'tcp': 0,
                            'udp': 0,
                            'http': 0,
                            'icmp': 0,
                            'total': 0,
                            'last_seen': time.time()
                        }
                    
                    # Update counters
                    counts = self.packet_counts[src_ip]
                    counts['tcp'] += packet_info['tcp']
                    counts['udp'] += packet_info['udp']
                    counts['http'] += packet_info['http']
                    counts['icmp'] += packet_info['icmp']
                    counts['total'] += 1
                    counts['last_seen'] = packet_info['last_seen']
                
                # Check if it's time to analyze traffic patterns
                current_time = time.time()
                if current_time - self.last_cleanup_time >= self.cleanup_interval:
                    self._analyze_traffic()
                    self.last_cleanup_time = current_time
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_adaptive_thresholds(self):
        """Update adaptive thresholds based on historical traffic data"""
        try:
            # Calculate total packets for each protocol in this interval
            current_totals = {
                'tcp': 0,
                'udp': 0,
                'http': 0,
                'icmp': 0
            }
            
            # Sum up packets from all IPs
            for ip, counts in self.packet_counts.items():
                current_totals['tcp'] += counts['tcp']
                current_totals['udp'] += counts['udp']
                current_totals['http'] += counts['http']
                current_totals['icmp'] += counts['icmp']
            
            # Add current totals to historical data
            for protocol, total in current_totals.items():
                self.historical_traffic[protocol].append(total)
            
            # Calculate new adaptive thresholds
            for protocol in ['tcp', 'udp', 'http', 'icmp']:
                if len(self.historical_traffic[protocol]) > 0:
                    # Calculate average traffic
                    avg_traffic = sum(self.historical_traffic[protocol]) / len(self.historical_traffic[protocol])
                    
                    # Set new threshold with allowed increase
                    if avg_traffic > 0:
                        self.adaptive_thresholds[protocol] = avg_traffic * (1 + self.allowed_increase_percent / 100.0)
                    else:
                        # If no traffic, use baseline
                        self.adaptive_thresholds[protocol] = self.baseline_thresholds[protocol]
                else:
                    # If no historical data, use baseline
                    self.adaptive_thresholds[protocol] = self.baseline_thresholds[protocol]
                
                # Log the new threshold
                logger.info(f"Updated adaptive threshold for {protocol}: {self.adaptive_thresholds[protocol]:.2f}")
        
        except Exception as e:
            logger.error(f"Error updating adaptive thresholds: {e}")
    
    def _analyze_traffic(self):
        """Analyze traffic patterns to detect DDoS attacks"""
        try:
            with self.lock:
                # First update adaptive thresholds based on historical data
                self._update_adaptive_thresholds()
                
                # Then check each IP against the adaptive thresholds
                for ip, counts in list(self.packet_counts.items()):
                    # Skip already blocked IPs
                    if ip in self.stats['blocked_ips']:
                        continue
                    
                    # Check for TCP SYN Flood using adaptive threshold
                    if counts['tcp'] > self.adaptive_thresholds['tcp']:
                        self._detect_attack(ip, 'tcp')
                    
                    # Check for UDP Flood using adaptive threshold
                    if counts['udp'] > self.adaptive_thresholds['udp']:
                        self._detect_attack(ip, 'udp')
                    
                    # Check for HTTP Flood using adaptive threshold
                    if counts['http'] > self.adaptive_thresholds['http']:
                        self._detect_attack(ip, 'http')
                    
                    # Check for ICMP Flood using adaptive threshold
                    if counts['icmp'] > self.adaptive_thresholds['icmp']:
                        self._detect_attack(ip, 'icmp')
                    
                    # Reset counters
                    counts['tcp'] = 0
                    counts['udp'] = 0
                    counts['http'] = 0
                    counts['icmp'] = 0
                    
                    # Remove old entries
                    current_time = time.time()
                    if current_time - counts['last_seen'] > 60:  # 1 minute
                        del self.packet_counts[ip]
        except Exception as e:
            logger.error(f"Error analyzing traffic: {e}")
    
    def _detect_attack(self, ip, attack_type):
        """Record a detected attack"""
        try:
            self.stats['attacks_detected'][attack_type] += 1
            
            # Add to blocked IPs if not already blocked
            if ip not in self.stats['blocked_ips']:
                self.stats['blocked_ips'].append(ip)
                self.stats['ips_blocked'] += 1
                
                # Add alert
                self.alerts.append({
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'attack_type': f"{attack_type.upper()} Flood",
                    'source_ip': ip
                })
                
                # In a real implementation, this would call system commands to block the IP
                self._block_ip_in_system(ip)
        except Exception as e:
            logger.error(f"Error detecting attack: {e}")
    
    def _block_ip_in_system(self, ip):
        """Block an IP address at the system level"""
        try:
            # For Windows, use Windows Firewall
            if os.name == 'nt':
                os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
            # For Linux, use iptables
            else:
                os.system(f'iptables -A INPUT -s {ip} -j DROP')
            
            logger.info(f"Blocked IP: {ip}")
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
    
    def get_uptime(self):
        if self.stats['start_time'] is None:
            return "00:00:00"
        
        uptime_seconds = int(time.time() - self.stats['start_time'])
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def get_statistics(self):
        with self.lock:
            stats = self.stats.copy()
            stats['uptime'] = self.get_uptime()
            stats['traffic_data'] = list(self.traffic_data)
            stats['adaptive_thresholds'] = self.adaptive_thresholds.copy()
            return stats
    
    def block_ip(self, ip):
        with self.lock:
            if ip not in self.stats['blocked_ips']:
                self.stats['blocked_ips'].append(ip)
                self.stats['ips_blocked'] += 1
                self._block_ip_in_system(ip)
                return True
            return False
    
    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.stats['blocked_ips']:
                self.stats['blocked_ips'].remove(ip)
                self.stats['ips_blocked'] -= 1
                
                # Unblock IP at system level
                try:
                    # For Windows, use Windows Firewall
                    if os.name == 'nt':
                        os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')
                    # For Linux, use iptables
                    else:
                        os.system(f'iptables -D INPUT -s {ip} -j DROP')
                    
                    logger.info(f"Unblocked IP: {ip}")
                except Exception as e:
                    logger.error(f"Error unblocking IP {ip}: {e}")
                
                return True
            return False

# Check if the application is running with admin privileges
def is_admin():
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # For non-Windows platforms, check if effective user ID is 0 (root)
            return os.geteuid() == 0
    except:
        return False

# Function to restart the application with admin privileges
def run_as_admin():
    if os.name == 'nt':  # Windows
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

# Custom matplotlib canvas for embedding in Qt
class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        # Increase figure size slightly to accommodate labels
        fig = Figure(figsize=(width, height), dpi=dpi)
        # Add more padding to ensure labels are visible
        fig.subplots_adjust(left=0.15, right=0.95, top=0.9, bottom=0.15)
        self.axes = fig.add_subplot(111)
        super(MplCanvas, self).__init__(fig)

# Main application window
class PacketsWallApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("PacketsWall - DDoS Detection and Prevention System")
        self.setGeometry(100, 100, 1200, 800)
        
        # Check for admin privileges
        if not is_admin():
            reply = QMessageBox.question(
                self, 
                'Administrator Privileges Required',
                'This application requires administrator privileges to capture network packets. '
                'Do you want to restart with administrator privileges?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            
            if reply == QMessageBox.Yes:
                run_as_admin()
                sys.exit()
        
        # Get available network interfaces
        self.interfaces = self._get_network_interfaces()
        
        # Initialize the DDoS detection system
        self.detection_system = DDoSDetectionSystem()
        
        # Create the main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create the tab widget
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.dashboard_tab = QWidget()
        self.settings_tab = QWidget()
        self.logs_tab = QWidget()
        self.about_tab = QWidget()
        
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.addTab(self.about_tab, "About")
        
        # Set up each tab
        self._setup_dashboard_tab()
        self._setup_settings_tab()
        self._setup_logs_tab()
        self._setup_about_tab()
        
        # Create a status bar
        self.statusBar().showMessage("Ready")
        
        # Set up a timer to update the UI
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_ui)
        self.update_timer.start(1000)  # Update every second
        
        # Initialize system status
        self.system_running = False
        
        # Initialize the attack chart with an empty pie chart
        self._initialize_attack_chart()
        
        # Initialize log
        self._add_log("Application started")
        if is_admin():
            self._add_log("Running with administrator privileges")
        else:
            self._add_log("WARNING: Not running with administrator privileges")
    
    def _get_network_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = ["All Interfaces"]
        
        try:
            # For Windows
            if os.name == 'nt':
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    if 'name' in iface:
                        interfaces.append(iface['name'])
            # For Linux/Unix
            else:
                from scapy.arch import get_if_list
                interfaces.extend(get_if_list())
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            self._add_log(f"Error getting network interfaces: {e}")
        
        return interfaces
    
    def _setup_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Top section with status and controls
        top_layout = QHBoxLayout()
        layout.addLayout(top_layout)
        
        # Status group
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
        status_layout.addWidget(self.status_label)
        
        self.start_stop_button = QPushButton("Start System")
        self.start_stop_button.clicked.connect(self._toggle_system)
        status_layout.addWidget(self.start_stop_button)
        
        top_layout.addWidget(status_group)
        
        # Statistics group
        stats_group = QGroupBox("Statistics")
        stats_layout = QFormLayout(stats_group)
        
        self.uptime_label = QLabel("00:00:00")
        self.packets_label = QLabel("0")
        self.attacks_label = QLabel("0")
        self.blocked_label = QLabel("0")
        
        stats_layout.addRow("Uptime:", self.uptime_label)
        stats_layout.addRow("Packets Processed:", self.packets_label)
        stats_layout.addRow("Attacks Detected:", self.attacks_label)
        stats_layout.addRow("IPs Blocked:", self.blocked_label)
        
        top_layout.addWidget(stats_group)
        
        # Middle section with charts
        charts_layout = QHBoxLayout()
        layout.addLayout(charts_layout)
        
        # Traffic chart
        traffic_group = QGroupBox("Network Traffic")
        traffic_layout = QVBoxLayout(traffic_group)
        
        # Increase height for traffic chart to ensure labels are visible
        self.traffic_canvas = MplCanvas(self, width=5, height=4.5, dpi=100)
        traffic_layout.addWidget(self.traffic_canvas)
        
        charts_layout.addWidget(traffic_group)
        
        # Attack distribution chart
        attack_group = QGroupBox("Attack Distribution")
        attack_layout = QVBoxLayout(attack_group)
        
        # Increase height for attack chart to ensure labels are visible
        self.attack_canvas = MplCanvas(self, width=5, height=4.5, dpi=100)
        attack_layout.addWidget(self.attack_canvas)
        
        charts_layout.addWidget(attack_group)
        
        # Bottom section with tables
        tables_layout = QHBoxLayout()
        layout.addLayout(tables_layout)
        
        # Blocked IPs table
        blocked_group = QGroupBox("Blocked IP Addresses")
        blocked_layout = QVBoxLayout(blocked_group)
        
        self.blocked_table = QTableWidget()
        self.blocked_table.setColumnCount(3)
        self.blocked_table.setHorizontalHeaderLabels(["IP Address", "Block Time", "Action"])
        self.blocked_table.horizontalHeader().setStretchLastSection(True)
        blocked_layout.addWidget(self.blocked_table)
        
        # Manual IP blocking
        block_layout = QHBoxLayout()
        self.block_ip_input = QLineEdit()
        self.block_ip_input.setPlaceholderText("Enter IP address to block")
        block_layout.addWidget(self.block_ip_input)
        
        self.block_ip_button = QPushButton("Block IP")
        self.block_ip_button.clicked.connect(self._block_ip)
        block_layout.addWidget(self.block_ip_button)
        
        blocked_layout.addLayout(block_layout)
        
        tables_layout.addWidget(blocked_group)
        
        # Alerts table
        alerts_group = QGroupBox("Recent Alerts")
        alerts_layout = QVBoxLayout(alerts_group)
        
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(3)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Attack Type", "Source IP"])
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        alerts_layout.addWidget(self.alerts_table)
        
        tables_layout.addWidget(alerts_group)
    
    def _setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout(network_group)
        
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interfaces)
        network_layout.addRow("Network Interface:", self.interface_combo)
        
        layout.addWidget(network_group)
        
        # Detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QFormLayout(detection_group)
        
        self.time_window_spin = QSpinBox()
        self.time_window_spin.setRange(5, 60)
        self.time_window_spin.setValue(10)
        self.time_window_spin.setSingleStep(5)
        detection_layout.addRow("Time Window (seconds):", self.time_window_spin)
        
        # Adaptive threshold percentage setting
        self.allowed_increase_spin = QSpinBox()
        self.allowed_increase_spin.setRange(5, 100)
        self.allowed_increase_spin.setValue(20)
        self.allowed_increase_spin.setSingleStep(5)
        detection_layout.addRow("Allowed Traffic Increase (%):", self.allowed_increase_spin)
        
        layout.addWidget(detection_group)
        
        # Prevention settings
        prevention_group = QGroupBox("Prevention Settings")
        prevention_layout = QFormLayout(prevention_group)
        
        self.block_duration_spin = QSpinBox()
        self.block_duration_spin.setRange(60, 3600)
        self.block_duration_spin.setValue(300)
        self.block_duration_spin.setSingleStep(60)
        prevention_layout.addRow("Block Duration (seconds):", self.block_duration_spin)
        
        self.auto_block_check = QCheckBox("Automatically block detected attacks")
        self.auto_block_check.setChecked(True)
        prevention_layout.addRow("", self.auto_block_check)
        
        layout.addWidget(prevention_group)
        
        # Alert settings
        alert_group = QGroupBox("Alert Settings")
        alert_layout = QFormLayout(alert_group)
        
        self.email_check = QCheckBox("Send email alerts")
        alert_layout.addRow("", self.email_check)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("admin@example.com")
        alert_layout.addRow("Email Address:", self.email_input)
        
        layout.addWidget(alert_group)
        
        # Save button
        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self._save_settings)
        layout.addWidget(self.save_settings_button)
        
        # Add stretch to push everything to the top
        layout.addStretch()
    
    def _setup_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self._clear_logs)
        controls_layout.addWidget(self.clear_logs_button)
        
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self._save_logs)
        controls_layout.addWidget(self.save_logs_button)
        
        layout.addLayout(controls_layout)
    
    def _setup_about_tab(self):
        layout = QVBoxLayout(self.about_tab)
        
        # Logo
        logo_label = QLabel()
        logo_pixmap = QPixmap(100, 100)  # Create an empty pixmap as placeholder
        logo_pixmap.fill(Qt.white)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Title
        title_label = QLabel("PacketsWall")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 20, QFont.Bold))
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("DDoS Attack Detection and Prevention System")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setFont(QFont("Arial", 14))
        layout.addWidget(subtitle_label)
        
        # Version
        version_label = QLabel("Version 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        # Description
        description = QLabel(
            "PacketsWall is a comprehensive DDoS attack detection and prevention system "
            "designed to protect networks from various types of DDoS attacks. "
            "The system can detect and prevent TCP SYN Flood, UDP Flood, HTTP Flood, and ICMP Flood attacks."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description)
        
        # Features
        features_group = QGroupBox("Key Features")
        features_layout = QVBoxLayout(features_group)
        
        features = [
            "Real-time network traffic monitoring using Scapy",
            "Adaptive threshold-based detection for multiple attack types",
            "Automatic blocking of malicious IP addresses",
            "Email alerts for detected attacks",
            "Comprehensive dashboard for system monitoring",
            "Detailed logs for forensic analysis"
        ]
        
        for feature in features:
            feature_label = QLabel(f"• {feature}")
            features_layout.addWidget(feature_label)
        
        layout.addWidget(features_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
    
    def _toggle_system(self):
        if not self.system_running:
            try:
                # Start the system
                self.detection_system.interface = self.interface_combo.currentText()
                
                # Update settings from UI
                self.detection_system.cleanup_interval = self.time_window_spin.value()
                self.detection_system.allowed_increase_percent = self.allowed_increase_spin.value()
                
                if self.detection_system.start():
                    self.system_running = True
                    self.status_label.setText("Running")
                    self.status_label.setStyleSheet("color: green; font-weight: bold; font-size: 16px;")
                    self.start_stop_button.setText("Stop System")
                    self._add_log("System started")
                    self.statusBar().showMessage("System started")
                else:
                    QMessageBox.warning(self, "Error", "Failed to start the system. Check logs for details.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to start the system: {e}")
                logger.error(f"Error starting system: {e}")
        else:
            try:
                # Stop the system
                if self.detection_system.stop():
                    self.system_running = False
                    self.status_label.setText("Stopped")
                    self.status_label.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
                    self.start_stop_button.setText("Start System")
                    self._add_log("System stopped")
                    self.statusBar().showMessage("System stopped")
                else:
                    QMessageBox.warning(self, "Error", "Failed to stop the system. Check logs for details.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to stop the system: {e}")
                logger.error(f"Error stopping system: {e}")
    
    def _save_settings(self):
        try:
            # Update detection system settings
            self.detection_system.cleanup_interval = self.time_window_spin.value()
            self.detection_system.allowed_increase_percent = self.allowed_increase_spin.value()
            
            self._add_log(f"Settings saved (Allowed increase: {self.detection_system.allowed_increase_percent}%)")
            self.statusBar().showMessage("Settings saved")
            
            # Show confirmation message
            QMessageBox.information(self, "Settings Saved", "Your settings have been saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save settings: {e}")
            logger.error(f"Error saving settings: {e}")
    
    def _block_ip(self):
        ip = self.block_ip_input.text().strip()
        
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            QMessageBox.warning(self, "Invalid IP", "Please enter a valid IP address.")
            return
        
        if self.detection_system.block_ip(ip):
            self._add_log(f"Manually blocked IP: {ip}")
            self.statusBar().showMessage(f"Blocked IP: {ip}")
            self.block_ip_input.clear()
        else:
            self.statusBar().showMessage(f"IP already blocked: {ip}")
    
    def _clear_logs(self):
        self.log_display.clear()
        self._add_log("Logs cleared")
    
    def _save_logs(self):
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Logs", "", "Text Files (*.txt);;All Files (*)")
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(self.log_display.toPlainText())
                self.statusBar().showMessage(f"Logs saved to {file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save logs: {e}")
            logger.error(f"Error saving logs: {e}")
    
    def _add_log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_display.append(log_entry)
        
        # Limit log size to prevent memory issues
        if self.log_display.document().lineCount() > 1000:
            cursor = self.log_display.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, 100)  # Remove oldest 100 lines
            cursor.removeSelectedText()
    
    def _initialize_attack_chart(self):
        """Initialize the attack chart with an empty pie chart"""
        self.attack_canvas.axes.clear()
        
        # Create labels for all possible attack types
        labels = ['TCP SYN', 'UDP', 'HTTP', 'ICMP']
        
        # Create a pie chart with equal values (25% each)
        values = [25, 25, 25, 25]
        
        # Set figure title
        self.attack_canvas.axes.set_title('Attack Distribution')
        
        # Create the pie chart with muted colors to indicate no actual data
        colors = ['#e6e6e6', '#d9d9d9', '#cccccc', '#bfbfbf']  # Light gray colors
        wedges, texts, autotexts = self.attack_canvas.axes.pie(
            values, 
            labels=labels, 
            colors=colors,
            autopct='%1.1f%%', 
            startangle=90,
            textprops={'fontsize': 9, 'color': '#666666'},  # Gray text
            labeldistance=1.15,  # Move labels further from the pie
            pctdistance=0.85     # Move percentages closer to center
        )
        
        # Add a text overlay to indicate no attacks
        self.attack_canvas.axes.text(0.5, 0.5, "No attacks detected", 
                                    horizontalalignment='center',
                                    verticalalignment='center',
                                    transform=self.attack_canvas.axes.transAxes,
                                    bbox=dict(facecolor='white', alpha=0.7, boxstyle='round,pad=0.5'))
        
        self.attack_canvas.axes.axis('equal')
        self.attack_canvas.draw()
    
    def _update_ui(self):
        try:
            if not self.system_running:
                return
            
            # Get current statistics
            stats = self.detection_system.get_statistics()
            
            # Update statistics labels
            self.uptime_label.setText(stats['uptime'])
            self.packets_label.setText(str(stats['packets_processed']))
            
            total_attacks = sum(stats['attacks_detected'].values())
            self.attacks_label.setText(str(total_attacks))
            
            self.blocked_label.setText(str(stats['ips_blocked']))
            
            # Update traffic chart (only every 5 seconds to reduce CPU usage)
            if int(time.time()) % 5 == 0:
                self._update_traffic_chart(stats.get('traffic_data', []))
            
            # Update attack distribution chart (only every 5 seconds)
            if int(time.time()) % 5 == 0:
                self._update_attack_chart(stats['attacks_detected'])
            
            # Update blocked IPs table
            self._update_blocked_table(stats['blocked_ips'])
            
            # Update alerts table
            self._update_alerts_table(self.detection_system.alerts)
        except Exception as e:
            logger.error(f"Error updating UI: {e}")
    
    def _update_traffic_chart(self, traffic_data):
        try:
            self.traffic_canvas.axes.clear()
            
            # Use actual traffic data if available
            if traffic_data and len(traffic_data) > 1:
                # Calculate packets per second
                packets_per_second = []
                for i in range(1, len(traffic_data)):
                    packets_per_second.append(traffic_data[i] - traffic_data[i-1])
                
                # Create x-axis (time points)
                x = list(range(len(packets_per_second)))
                
                # Plot the data
                self.traffic_canvas.axes.plot(x, packets_per_second, 'b-')
            else:
                # Generate some placeholder data
                x = np.arange(10)
                y = np.random.randint(0, 10, size=10)  # Use smaller random values to reduce visual noise
                self.traffic_canvas.axes.plot(x, y, 'b-')
            
            # Set title and labels with larger font size to ensure visibility
            self.traffic_canvas.axes.set_title('Network Traffic (packets/sec)', fontsize=12, pad=10)
            self.traffic_canvas.axes.set_xlabel('Time', fontsize=10, labelpad=10)
            self.traffic_canvas.axes.set_ylabel('Packets', fontsize=10, labelpad=10)
            self.traffic_canvas.axes.grid(True)
            
            # Ensure there's enough padding around the plot
            self.traffic_canvas.figure.tight_layout(pad=2.0)
            self.traffic_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating traffic chart: {e}")
    
    def _update_attack_chart(self, attacks):
        try:
            self.attack_canvas.axes.clear()
            
            # Extract attack counts
            labels = []
            values = []
            
            # Only include attacks with non-zero values
            if attacks['tcp'] > 0:
                labels.append('TCP SYN')
                values.append(attacks['tcp'])
            if attacks['udp'] > 0:
                labels.append('UDP')
                values.append(attacks['udp'])
            if attacks['http'] > 0:
                labels.append('HTTP')
                values.append(attacks['http'])
            if attacks['icmp'] > 0:
                labels.append('ICMP')
                values.append(attacks['icmp'])
            
            # Set figure title with larger font size and padding
            self.attack_canvas.axes.set_title('Attack Distribution', fontsize=12, pad=10)
            
            # Create pie chart even if there are no attacks
            if sum(values) > 0:
                # Create the pie chart with actual attack data
                # Adjust label distance based on number of attack types
                label_distance = 1.15  # Default distance
                pct_distance = 0.85    # Default percentage distance
                
                # Adjust distances based on number of attack types
                if len(values) == 2:
                    # For exactly 2 attack types, move labels further out
                    label_distance = 1.3
                    pct_distance = 0.7
                elif len(values) == 3:
                    # For 3 attack types, adjust slightly
                    label_distance = 1.25
                    pct_distance = 0.75
                
                wedges, texts, autotexts = self.attack_canvas.axes.pie(
                    values, 
                    labels=labels, 
                    autopct='%1.1f%%', 
                    startangle=90,
                    textprops={'fontsize': 10},  # Increase font size
                    labeldistance=label_distance,  # Move labels further from the pie
                    pctdistance=pct_distance       # Move percentages closer to center
                )
                
                # Improve label visibility
                for text in texts:
                    text.set_horizontalalignment('center')
                
                # If there's only one type of attack, adjust the label position
                if len(values) == 1:
                    # Move the label to the center
                    texts[0].set_position((0, 0))
                    texts[0].set_horizontalalignment('center')
                    
                    # Make the percentage text smaller and move it below the label
                    autotexts[0].set_position((0, -0.2))
                    autotexts[0].set_fontsize(8)
            else:
                # Create an empty pie chart with placeholder data
                placeholder_labels = ['TCP SYN', 'UDP', 'HTTP', 'ICMP']
                placeholder_values = [25, 25, 25, 25]  # Equal distribution
                colors = ['#e6e6e6', '#d9d9d9', '#cccccc', '#bfbfbf']  # Light gray colors
                
                wedges, texts, autotexts = self.attack_canvas.axes.pie(
                    placeholder_values, 
                    labels=placeholder_labels, 
                    colors=colors,
                    autopct='%1.1f%%', 
                    startangle=90,
                    textprops={'fontsize': 10, 'color': '#666666'},  # Gray text with larger font
                    labeldistance=1.15,  # Move labels further from the pie
                    pctdistance=0.85     # Move percentages closer to center
                )
                
                # Add a text overlay to indicate no attacks
                self.attack_canvas.axes.text(0.5, 0.5, "No attacks detected", 
                                          horizontalalignment='center',
                                          verticalalignment='center',
                                          transform=self.attack_canvas.axes.transAxes,
                                          bbox=dict(facecolor='white', alpha=0.7, boxstyle='round,pad=0.5'))
            
            self.attack_canvas.axes.axis('equal')
            # Ensure there's enough padding around the plot
            self.attack_canvas.figure.tight_layout(pad=2.0)
            self.attack_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating attack chart: {e}")
    
    def _update_blocked_table(self, blocked_ips):
        try:
            self.blocked_table.setRowCount(len(blocked_ips))
            
            for i, ip in enumerate(blocked_ips):
                # IP Address
                self.blocked_table.setItem(i, 0, QTableWidgetItem(ip))
                
                # Block Time
                self.blocked_table.setItem(i, 1, QTableWidgetItem(time.strftime("%Y-%m-%d %H:%M:%S")))
                
                # Unblock Button
                unblock_button = QPushButton("Unblock")
                unblock_button.clicked.connect(lambda checked, ip=ip: self._unblock_ip(ip))
                self.blocked_table.setCellWidget(i, 2, unblock_button)
        except Exception as e:
            logger.error(f"Error updating blocked table: {e}")
    
    def _update_alerts_table(self, alerts):
        try:
            # Show only the last 10 alerts
            recent_alerts = alerts[-10:] if len(alerts) > 10 else alerts
            
            self.alerts_table.setRowCount(len(recent_alerts))
            
            for i, alert in enumerate(recent_alerts):
                self.alerts_table.setItem(i, 0, QTableWidgetItem(alert['timestamp']))
                self.alerts_table.setItem(i, 1, QTableWidgetItem(alert['attack_type']))
                self.alerts_table.setItem(i, 2, QTableWidgetItem(alert['source_ip']))
        except Exception as e:
            logger.error(f"Error updating alerts table: {e}")
    
    def _unblock_ip(self, ip):
        try:
            if self.detection_system.unblock_ip(ip):
                self._add_log(f"Manually unblocked IP: {ip}")
                self.statusBar().showMessage(f"Unblocked IP: {ip}")
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            QMessageBox.warning(self, "Error", f"Failed to unblock IP {ip}: {e}")
    
    def closeEvent(self, event):
        try:
            # Stop the system when closing the application
            if self.system_running:
                self.detection_system.stop()
            event.accept()
        except Exception as e:
            logger.error(f"Error during application close: {e}")
            event.accept()  # Accept the close event anyway

# Create a Windows shortcut with admin privileges
def create_admin_shortcut():
    if os.name == 'nt':  # Windows
        try:
            import win32com.client
            
            # Get the path to the current script
            script_path = os.path.abspath(sys.argv[0])
            
            # Create a shortcut in the same directory
            shortcut_path = os.path.join(os.path.dirname(script_path), "PacketsWall (Admin).lnk")
            
            # Create shortcut
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = f'"{script_path}"'
            shortcut.WorkingDirectory = os.path.dirname(script_path)
            shortcut.Description = "Run PacketsWall with administrator privileges"
            shortcut.IconLocation = sys.executable
            shortcut.WindowStyle = 1  # Normal window
            shortcut.RunAs = 2  # Run as administrator
            shortcut.save()
            
            return True
        except Exception as e:
            logger.error(f"Error creating admin shortcut: {e}")
            return False
    return False

if __name__ == "__main__":
    # Set up exception handling
    def exception_hook(exctype, value, traceback):
        logger.error(f"Uncaught exception: {exctype.__name__}: {value}")
        sys.__excepthook__(exctype, value, traceback)
    
    sys.excepthook = exception_hook
    
    # Create admin shortcut if not already exists
    shortcut_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "PacketsWall (Admin).lnk")
    if os.name == 'nt' and not os.path.exists(shortcut_path):
        try:
            import win32com.client
            create_admin_shortcut()
        except ImportError:
            logger.warning("pywin32 not installed, cannot create admin shortcut")
    
    app = QApplication(sys.argv)
    window = PacketsWallApp()
    window.show()
    sys.exit(app.exec_())
