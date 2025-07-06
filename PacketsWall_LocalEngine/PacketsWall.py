import gc
import sys
import psutil, os
import os
import threading
import time
import logging
import socket
import struct
import ctypes

from log_manager import log_to_cloud_or_buffer, start_periodic_upload
from baseline_manager import BaselineManager
from PyQt5.QtGui import QIcon

import firebase_admin
from firebase_admin import credentials, firestore


# Start periodic upload loop
start_periodic_upload()



from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QProgressBar, QComboBox, QLineEdit, QGroupBox,
                            QFormLayout, QSpinBox, QDoubleSpinBox, QCheckBox, QMessageBox,
                            QFileDialog, QHeaderView, QGridLayout) # Added QGridLayout
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
from collections import defaultdict # Import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('PacketsWall')

# Packet processing thread class - SIMPLIFIED VERSION
class PacketProcessorThread(QThread):
    packet_processed = pyqtSignal()
    
    def __init__(self, detection_system):
        super().__init__()
        
        self.detection_system = detection_system
        self.packet_queue = queue.Queue(maxsize=50000)  # Smaller but faster queue
        self.running = False
        self.batch_size = 500  # Larger batches for better performance
    
    def add_packet(self, packet):
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # ✅ ENHANCED: More aggressive queue management when full
            # Remove more old packets to prevent queue overflow during attacks
            try:
                for _ in range(self.packet_queue.qsize() // 2):
                    self.packet_queue.get_nowait()
                self.packet_queue.put_nowait(packet)
            except queue.Empty:
                pass
            except queue.Full:
                # If still full after cleanup, just discard the packet
                # This prevents system freeze during heavy attacks
                pass
    
    def run(self):
        self.running = True
        packet_batch = []
        
        while self.running:
            try:
                # ✅ ULTRA-FAST batch collection with minimal timeout
                while len(packet_batch) < self.batch_size and self.running:
                    try:
                        packet = self.packet_queue.get(block=True, timeout=0.001)  # Very short timeout
                        packet_batch.append(packet)
                        self.packet_queue.task_done()
                    except queue.Empty:
                        break
                
                # Process the batch if we have packets
                if packet_batch:
                    self.detection_system._process_packet_batch(packet_batch)
                    self.packet_processed.emit()
                    packet_batch.clear()
                    
            except Exception as e:
                logger.error(f"Error processing packet batch: {e}")
                packet_batch.clear()
    
    def stop(self):
        self.running = False
        self.wait()

# Real DDoS detection system using Scapy
class DDoSDetectionSystem:
    def __init__(self, interface=None):
        self.interface = interface
        self.pcap_file = None # Added to store PCAP file path
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
            'blocked_ips': {} # Changed to dictionary to store IP -> timestamp
        }
        self.packets_processed_window = 0 # Counter for the current time window
        self.last_reset_time = time.time() # Timestamp of the last window reset
        self.time_window = 10 # Default time window in seconds, will be updated from UI
        self.alerts = []
        
        # Use deque with max length for packet counts to limit memory usage
        # Use defaultdict for potentially faster IP counter creation
        self.packet_counts = defaultdict(lambda: {
            "tcp": 0,
            "udp": 0,
            "http": 0,
            "icmp": 0,
            "total": 0,
            "last_seen": 0
        })
        self.last_cleanup_time = time.time()
        self.cleanup_interval = 5  # Reduced to 5 seconds for more frequent cleanup
        
        # Memory optimization settings
        self.max_ip_entries = 20000  # Reasonable limit
        self.ip_cleanup_threshold = 60  # Remove IPs not seen for 1 minute
        
        # High-performance settings
        self.cleanup_interval = 5  # More frequent cleanup for better performance
        
        # Adaptive threshold settings
        self.allowed_increase_percent = 20  # Default: 20% increase allowed
        
        # ✅ إعدادات DDoS detection قابلة للتعديل من Settings
        self.max_ip_percentage = 90  # النسبة المئوية المسموحة لـ IP واحد من threshold الكلي (افتراضي: 90%)
        self.buffer_zone_udp = 1000  # هامش الأمان لـ UDP (افتراضي: 1000 packets/sec)
        self.buffer_zone_tcp = 100   # هامش الأمان لـ TCP (افتراضي: 100 packets/sec)
        self.buffer_zone_http = 50   # هامش الأمان لـ HTTP (افتراضي: 50 packets/sec)
        self.buffer_zone_icmp = 30   # هامش الأمان لـ ICMP (افتراضي: 30 packets/sec)
        
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
        
        # Initialize blocked IPs cache for ultra-fast filtering
        self._blocked_ips_cache = set()
        
        # ✅ إضافة Firebase Baseline Manager
        self.baseline_manager = BaselineManager(alpha=0.1)
        
        # Lock for thread safety
        self.lock = threading.RLock()  # Use RLock to allow nested acquisitions
        
        # Sniffer or PCAP reader thread
        self.input_thread = None # Renamed from sniffer_thread
        
        # Packet processor thread
        self.processor_thread = PacketProcessorThread(self)
        
        # --- New data structures for Protocols tab --- 
        # Traffic data per protocol (packets/sec)
        self.protocol_traffic_data = {
            'tcp': collections.deque(maxlen=60),
            'udp': collections.deque(maxlen=60),
            'http': collections.deque(maxlen=60),
            'icmp': collections.deque(maxlen=60)
        }
        # Current second packet counts per protocol
        self.current_second_protocol_counts = {
            'tcp': 0,
            'udp': 0,
            'http': 0,
            'icmp': 0
        }
        # Total packet counts per protocol for the last completed interval
        self.last_interval_protocol_counts = {
            'tcp': 0,
            'udp': 0,
            'http': 0,
            'icmp': 0
        }
        self.last_protocol_traffic_update = time.time()
        # --- End of new data structures ---
        
    def start(self):
        try:
            self.running = True
            self.stats['start_time'] = time.time()
            
            # Reset data structures on start
            self.last_protocol_traffic_update = time.time()
            for proto in self.protocol_traffic_data:
                self.protocol_traffic_data[proto].clear()
                self.current_second_protocol_counts[proto] = 0
                self.last_interval_protocol_counts[proto] = 0
            for proto in self.historical_traffic:
                self.historical_traffic[proto].clear()
            
            # ✅ تحميل max adaptive thresholds من Firebase وتحديث النظام
            for protocol in ['tcp', 'udp', 'http', 'icmp']:
                firebase_max_threshold = self.baseline_manager.load_max_adaptive_threshold(protocol)
                if firebase_max_threshold > 0:
                    self.adaptive_thresholds[protocol] = firebase_max_threshold
                    logger.info(f"Loaded {protocol.upper()} max adaptive threshold from Firebase: {firebase_max_threshold:.2f}")
                    
                    # ✅ حساب قيمة مناسبة للـ historical_traffic بناءً على max adaptive threshold
                    # adaptive_threshold = avg_traffic * (1 + allowed_increase_percent / 100)
                    # إذن: avg_traffic = adaptive_threshold / (1 + allowed_increase_percent / 100)
                    calculated_avg = firebase_max_threshold / (1 + self.allowed_increase_percent / 100.0)
                    
                    # إضافة قيم متعددة للـ historical_traffic لتكون نقطة بداية جيدة
                    # نضع 5 قيم حول المتوسط المحسوب
                    base_values = [
                        calculated_avg * 0.9,  # 90% من المتوسط
                        calculated_avg * 0.95, # 95% من المتوسط
                        calculated_avg,        # المتوسط نفسه
                        calculated_avg * 1.05, # 105% من المتوسط
                        calculated_avg * 1.1   # 110% من المتوسط
                    ]
                    
                    # إضافة القيم للـ historical_traffic
                    for value in base_values:
                        self.historical_traffic[protocol].append(max(0, value))
                    
                    logger.info(f"Initialized {protocol.upper()} historical traffic with avg: {calculated_avg:.2f} (from max: {firebase_max_threshold:.2f})")
                    
                else:
                    self.adaptive_thresholds[protocol] = self.baseline_thresholds[protocol]
                    logger.info(f"Using default {protocol.upper()} threshold: {self.baseline_thresholds[protocol]}")
            
            self.packet_counts.clear()
            self.stats['packets_processed'] = 0
            self.stats['attacks_detected'] = {'tcp': 0, 'udp': 0, 'http': 0, 'icmp': 0}
            self.stats['ips_blocked'] = 0
            self.stats['blocked_ips'].clear()
            self.alerts.clear()
            
            # ✅ تهيئة متغيرات تتبع الهجمات لكل بروتوكول
            for protocol in ["tcp", "udp", "http", "icmp"]:
                setattr(self, f'_last_attacks_{protocol}', 0)

            # Start packet processor thread
            self.processor_thread.start()
            
            # Start packet input thread (either live sniffer or PCAP reader)
            if self.pcap_file:
                logger.info(f"Starting PCAP reader for file: {self.pcap_file}")
                self.input_thread = threading.Thread(target=self._start_pcap_reader, daemon=True)
            else:
                logger.info(f"Starting live sniffer on interface: {self.interface}")
                self.input_thread = threading.Thread(target=self._start_sniffer, daemon=True)
            
            self.input_thread.start()
            
            # ✅ تفعيل Garbage Collection يدويًا بشكل دوري
            QTimer.singleShot(15000, gc.collect)

            logger.info("DDoS detection system started")
            # ✅ تحديد أولوية المعالجة العالية للبرنامج
            p = psutil.Process(os.getpid())
            try:
                p.nice(psutil.HIGH_PRIORITY_CLASS)  # على ويندوز
                logger.info("Process priority set to HIGH_PRIORITY_CLASS")
            except Exception as e:
                logger.warning(f"Could not set process priority: {e}")
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
            
            # Stop input thread (sniffer or pcap reader)
            if self.input_thread and self.input_thread.is_alive():
                # For PCAP reader, it might finish on its own, but join helps ensure clean exit
                self.input_thread.join(timeout=1.0) 
            
            logger.info("DDoS detection system stopped")
            
            logger.info("DDoS detection system stopped")
            return True
        except Exception as e:
            logger.error(f"Error stopping DDoS detection system: {e}")
            return False
    
    def _start_sniffer(self):
        """Start the packet sniffer using Scapy with dynamic BPF filtering"""
        try:
            # ✅ DYNAMIC BPF FILTER: Start with no filter, update dynamically
            self.current_bpf_filter = ""
            
            # Use AsyncSniffer for better performance
            self.sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "All Interfaces" else None,
                prn=self._packet_callback,
                filter=self.current_bpf_filter if self.current_bpf_filter else None,
                store=0,  # Don't store packets in memory
                count=0   # Infinite capture
            )
            
            # Start sniffing
            self.sniffer.start()
            logger.info("Live sniffer started with dynamic filtering")
            
            # Keep checking if we should stop and update BPF filter
            while self.running:
                time.sleep(0.1)
                # Update BPF filter if needed
                self._update_bpf_filter()
            
            # Stop sniffing
            self.sniffer.stop()
            
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
    
    def _update_bpf_filter(self):
        """Update BPF filter to block known attacking IPs"""
        try:
            if not hasattr(self, '_last_bpf_update'):
                self._last_bpf_update = 0
            
            # Update filter every 2 seconds
            current_time = time.time()
            if current_time - self._last_bpf_update < 2.0:
                return
            
            # Build filter to exclude blocked IPs
            blocked_ips = list(self._blocked_ips_cache)
            if blocked_ips and len(blocked_ips) <= 50:  # Limit filter complexity
                # Create filter to exclude blocked IPs
                filter_parts = [f"not src host {ip}" for ip in blocked_ips[:50]]
                new_filter = " and ".join(filter_parts)
                
                if new_filter != self.current_bpf_filter:
                    self.current_bpf_filter = new_filter
                    logger.info(f"Updated BPF filter to exclude {len(blocked_ips)} blocked IPs")
                    
                    # Restart sniffer with new filter (if possible)
                    # Note: Some systems may not support dynamic filter updates
                    
            self._last_bpf_update = current_time
            
        except Exception as e:
            logger.debug(f"BPF filter update error: {e}")
    
    def _start_pcap_reader(self):
        """Read packets from a PCAP file and pass them to the callback"""
        if not self.pcap_file:
            logger.error("PCAP file path is not set.")
            return
        
        try:
            logger.info(f"Starting to read packets from {self.pcap_file}")
            # Use sniff with offline parameter to read from file
            # prn calls _packet_callback for
            logger.info(f"Finished reading packets from {self.pcap_file}. Waiting for processing queue to empty...")
            # Wait for the processing queue to be completely processed
            self.processor_thread.packet_queue.join()
            logger.info("Packet processing queue is empty. PCAP processing complete.")
            # Signal that processing might be done (or let the processor queue empty naturally)
            # Optionally, could add a special marker or signal to the processor queue
            # For now, just let the processor finish its queue.
            # We might need to add logic to stop the system automatically after PCAP processing
            # or indicate completion in the UI.
            # Consider setting self.running = False here if we want it to stop automatically.
            # For now, let it run until manually stopped, allowing UI updates to complete.
            
        except FileNotFoundError:
            logger.error(f"PCAP file not found: {self.pcap_file}")
            # Optionally signal UI about the error
        except Scapy_Exception as e:
            logger.error(f"Error reading PCAP file {self.pcap_file}: {e}")
            # Optionally signal UI about the error
        except Exception as e:
            logger.error(f"An unexpected error occurred while reading PCAP file: {e}")
            # Optionally signal UI about the error
        finally:
            # Ensure the system knows processing might be ending if it was reading a file
            # This thread will terminate here. The main app/processor thread keeps running.
            pass 

    def _packet_callback(self, packet):
        """Ultra-fast packet callback with minimal processing"""
        if not self.running:
            return
        
        # ✅ ULTRA-FAST filtering - minimal lock time
        if IP in packet:
            src_ip = packet[IP].src
            # Quick check without lock first (may have false positives but prevents most blocked packets)
            if hasattr(self, '_blocked_ips_cache') and src_ip in self._blocked_ips_cache:
                return
        
        # Add to queue with ultra-fast non-blocking approach
        try:
            self.processor_thread.packet_queue.put_nowait(packet)
        except:
            # If queue is full, aggressively drop old packets
            try:
                # Drop 100 packets at once for maximum speed
                for _ in range(100):
                    self.processor_thread.packet_queue.get_nowait()
                self.processor_thread.packet_queue.put_nowait(packet)
            except:
                pass  # Discard if still problems
    
    def _process_packet(self, packet):
        """Process each captured packet - called from processor thread"""
        try:
            current_time = time.time()
            protocol_type = None # Track which protocol this packet belongs to

            # Check if packet has IP layer
            if IP in packet:
                # Get the real source IP, not the router IP
                real_src_ip = None
                
                # For HTTP packets, check for X-Forwarded-For header
                is_http = False
                if TCP in packet and packet[TCP].dport == 80 and Raw in packet and b'HTTP' in packet[Raw].load:
                    is_http = True
                    protocol_type = 'http'
                    try:
                        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        # Look for X-Forwarded-For header
                        for line in raw_data.split('\r\n'):
                            if 'X-Forwarded-For:' in line or 'X-Real-IP:' in line:
                                header_ip = line.split(':', 1)[1].strip().split(',')[0].strip()
                                if self._is_valid_ip(header_ip):
                                    real_src_ip = header_ip
                                    break
                    except Exception as e:
                        logger.debug(f"Error parsing HTTP headers: {e}")
                
                # If we couldn't find a real IP from headers, use the packet source IP
                if not real_src_ip:
                    src_ip = packet[IP].src
                    if self._is_private_ip(src_ip):
                        if 'X-Real-IP' in packet:
                            real_src_ip = packet['X-Real-IP']
                        else:
                            real_src_ip = src_ip  # logger.debug(f"Using potentially NAT'd IP: {src_ip}")
                    else:
                        real_src_ip = src_ip
                
                # Process packet details without holding the lock initially
                src_ip = real_src_ip # Use the determined real source IP
                
                # ✅ CRITICAL FIX: Skip processing packets from blocked IPs
                # This prevents blocked IPs from affecting adaptive thresholds
                if src_ip in self.stats['blocked_ips']:
                    return  # Completely ignore packets from blocked IPs
                
                packet_info = {
                    'tcp': 0,
                    'udp': 0,
                    'http': 0,
                    'icmp': 0,
                    'total': 1,
                    'last_seen': current_time
                }
                
                # --- Start Refined Protocol Detection ---
                protocol_type = None
                is_http = False # Flag to avoid double counting TCP if HTTP is detected

                if TCP in packet:
                    # Check for HTTP on standard port 80 first
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        # Try using Scapy's HTTP layer
                        if HTTPRequest in packet:
                            is_http = True
                            protocol_type = 'http'
                            packet_info['http'] = 1
                        # Fallback: Check Raw payload for GET/POST
                        elif Raw in packet and packet.haslayer(Raw):
                            try:
                                # Check only the beginning for efficiency and relevance
                                payload_start = packet[Raw].load[:10]
                                if payload_start.startswith(b'GET ') or payload_start.startswith(b'POST '):
                                    is_http = True
                                    protocol_type = 'http'
                                    packet_info['http'] = 1
                                # Optional: Add check for b'HTTP/' for responses?
                                # elif payload_start.startswith(b'HTTP/'):
                                #    is_http = True
                                #    protocol_type = 'http'
                                #    packet_info['http'] = 1 # Count responses too if needed
                            except Exception as e:
                                logger.debug(f"Error checking Raw payload for HTTP: {e}")

                    # If not identified as HTTP on port 80, check for other TCP types
                    if not is_http:
                        if packet[TCP].flags & 0x02: # SYN flag
                            packet_info['tcp'] = 1
                            protocol_type = 'tcp'
                        else: # Generic TCP packet (non-SYN, not HTTP on port 80)
                            packet_info['tcp'] = 1
                            protocol_type = 'tcp' # Count as TCP traffic
                    # If it *was* HTTP, ensure TCP is also counted if needed for total TCP count.
                    if is_http:
                        packet_info['tcp'] = 1 # Count HTTP as TCP as well for TCP total

                elif UDP in packet:
                    packet_info['udp'] = 1
                    protocol_type = 'udp'
                elif ICMP in packet:
                    packet_info['icmp'] = 1
                    protocol_type = 'icmp'

                # --- End Refined Protocol Detection ---

                # Now update shared counters with lock
                with self.lock:
                    # Increment overall packet counter
                    self.stats["packets_processed"] += 1
                    # Increment window packet counter
                    self.packets_processed_window += 1

                    # Update per-second protocol counts
                    if protocol_type:
                        self.current_second_protocol_counts[protocol_type] += 1

                    # Update per-IP counters for analysis
                    # Using defaultdict might simplify this, but direct check is okay for now
                    if src_ip not in self.packet_counts:
                        self.packet_counts[src_ip] = {
                            "tcp": 0,
                            "udp": 0,
                            "http": 0,
                            "icmp": 0,
                            "total": 0,
                            "last_seen": 0 # Initialize last_seen
                        }
                    
                    counts = self.packet_counts[src_ip]
                    counts["tcp"] += packet_info["tcp"]
                    counts["udp"] += packet_info["udp"]
                    counts["http"] += packet_info["http"]
                    counts["icmp"] += packet_info["icmp"]
                    counts["total"] += 1
                    counts["last_seen"] = current_time # Update last_seen time

                    # Update per-second traffic data for charts (keep inside lock as it modifies shared state)
                    if current_time - self.last_protocol_traffic_update >= 2.0:
                        for proto, count in self.current_second_protocol_counts.items():
                            self.protocol_traffic_data[proto].append(count)
                        # Reset counters for the next second
                        self.current_second_protocol_counts = {p: 0 for p in self.current_second_protocol_counts}
                        self.last_protocol_traffic_update = current_time
                
                # Check if it's time to analyze traffic patterns (outside the lock)
                if current_time - self.last_cleanup_time >= self.cleanup_interval:
                    self._analyze_traffic()
                    self.last_cleanup_time = current_time
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_packet_batch(self, packet_batch):
        """Process a batch of packets efficiently"""
        try:
            current_time = time.time()
            
            # Batch processing variables
            batch_stats = {
                'packets_processed': 0,
                'protocol_counts': {'tcp': 0, 'udp': 0, 'http': 0, 'icmp': 0}
            }
            
            # IP counters for this batch
            batch_ip_counts = defaultdict(lambda: {'tcp': 0, 'udp': 0, 'http': 0, 'icmp': 0, 'total': 0})
            
            # Process all packets in the batch quickly
            for packet in packet_batch:
                if not IP in packet:
                    continue
                    
                src_ip = packet[IP].src
                
                # ✅ CRITICAL FIX: Skip processing packets from blocked IPs
                # This prevents blocked IPs from affecting adaptive thresholds
                if src_ip in self.stats['blocked_ips']:
                    continue  # Completely ignore packets from blocked IPs
                
                protocol_type = None
                
                # Quick protocol detection
                if TCP in packet:
                    if (packet[TCP].dport == 80 or packet[TCP].sport == 80) and Raw in packet:
                        try:
                            payload_start = packet[Raw].load[:10]
                            if payload_start.startswith(b'GET ') or payload_start.startswith(b'POST '):
                                protocol_type = 'http'
                                batch_ip_counts[src_ip]['http'] += 1
                                batch_stats['protocol_counts']['http'] += 1
                            else:
                                protocol_type = 'tcp'
                                batch_ip_counts[src_ip]['tcp'] += 1
                                batch_stats['protocol_counts']['tcp'] += 1
                        except:
                            protocol_type = 'tcp'
                            batch_ip_counts[src_ip]['tcp'] += 1
                            batch_stats['protocol_counts']['tcp'] += 1
                    else:
                        protocol_type = 'tcp'
                        batch_ip_counts[src_ip]['tcp'] += 1
                        batch_stats['protocol_counts']['tcp'] += 1
                elif UDP in packet:
                    protocol_type = 'udp'
                    batch_ip_counts[src_ip]['udp'] += 1
                    batch_stats['protocol_counts']['udp'] += 1
                elif ICMP in packet:
                    protocol_type = 'icmp'
                    batch_ip_counts[src_ip]['icmp'] += 1
                    batch_stats['protocol_counts']['icmp'] += 1
                
                batch_ip_counts[src_ip]['total'] += 1
                batch_stats['packets_processed'] += 1
            
            # Update shared data structures with lock
            with self.lock:
                # Update overall stats
                self.stats["packets_processed"] += batch_stats['packets_processed']
                self.packets_processed_window += batch_stats['packets_processed']
                
                # Update per-second protocol counts
                for proto, count in batch_stats['protocol_counts'].items():
                    self.current_second_protocol_counts[proto] += count
                
                # Update per-IP counters
                for ip, counts in batch_ip_counts.items():
                    if ip not in self.packet_counts:
                        self.packet_counts[ip] = {
                            "tcp": 0, "udp": 0, "http": 0, "icmp": 0,
                            "total": 0, "last_seen": 0
                        }
                    
                    ip_counts = self.packet_counts[ip]
                    ip_counts["tcp"] += counts["tcp"]
                    ip_counts["udp"] += counts["udp"]
                    ip_counts["http"] += counts["http"]
                    ip_counts["icmp"] += counts["icmp"]
                    ip_counts["total"] += counts["total"]
                    ip_counts["last_seen"] = current_time
                
                # Update per-second traffic data for charts
                if current_time - self.last_protocol_traffic_update >= 2.0:
                    for proto, count in self.current_second_protocol_counts.items():
                        self.protocol_traffic_data[proto].append(count)
                    self.current_second_protocol_counts = {p: 0 for p in self.current_second_protocol_counts}
                    self.last_protocol_traffic_update = current_time
            
            # Check if it's time to analyze traffic patterns (outside the lock)
            if current_time - self.last_cleanup_time >= self.cleanup_interval:
                self._analyze_traffic()
                self.last_cleanup_time = current_time
                
        except Exception as e:
            logger.error(f"Error processing packet batch: {e}")
    
    def _update_adaptive_thresholds(self):
        """Update adaptive thresholds based on historical traffic data (Called within lock)"""
        try:
            # Calculate total packets for each protocol in this interval
            current_interval_totals = {
                'tcp': 0,
                'udp': 0,
                'http': 0,
                'icmp': 0
            }
            
            # ✅ ENHANCED FIX: Calculate totals excluding blocked IPs
            # This prevents blocked IPs from affecting adaptive thresholds
            for ip, counts in self.packet_counts.items():
                # Skip blocked IPs when calculating totals for adaptive thresholds
                if ip not in self.stats['blocked_ips']:
                    current_interval_totals['tcp'] += counts['tcp']
                    current_interval_totals['udp'] += counts['udp']
                    current_interval_totals['http'] += counts['http']
                    current_interval_totals['icmp'] += counts['icmp']
            
            # Store these totals for display
            self.last_interval_protocol_counts = current_interval_totals.copy()
            
            # Add current interval totals to historical data for threshold calculation
            for protocol, total in current_interval_totals.items():
                self.historical_traffic[protocol].append(total)
            
            # ✅ النظام الأصلي لحساب adaptive thresholds
            for protocol in ['tcp', 'udp', 'http', 'icmp']:
                if len(self.historical_traffic[protocol]) > 0:
                    avg_traffic = sum(self.historical_traffic[protocol]) / len(self.historical_traffic[protocol])
                    if avg_traffic > 0:
                        # Ensure threshold is at least 1
                        self.adaptive_thresholds[protocol] = max(1, avg_traffic * (1 + self.allowed_increase_percent / 100.0))
                    else:
                        self.adaptive_thresholds[protocol] = max(1, self.baseline_thresholds[protocol]) # Ensure baseline is >= 1
                else:
                    self.adaptive_thresholds[protocol] = max(1, self.baseline_thresholds[protocol]) # Ensure baseline is >= 1
                
                # ✅ حفظ max adaptive threshold في Firebase (مع استثناء DDoS)
                # تحقق من وجود هجمات في هذا البروتوكول
                current_attacks = self.stats['attacks_detected'][protocol]
                previous_attacks = getattr(self, f'_last_attacks_{protocol}', 0)
                
                # إذا لم تزد الهجمات، يعني لا يوجد DDoS في هذه الفترة
                if current_attacks == previous_attacks:
                    # حفظ adaptive threshold كـ max إذا كان أعلى
                    self.baseline_manager.save_max_adaptive_threshold(protocol, self.adaptive_thresholds[protocol])
                else:
                    logger.debug(f"[DDoS] Skipping max update for {protocol.upper()} - attacks detected: {current_attacks - previous_attacks}")
                
                # حفظ عدد الهجمات الحالي للمقارنة في المرة القادمة
                setattr(self, f'_last_attacks_{protocol}', current_attacks)
                
#                logger.debug(f"Updated adaptive threshold for {protocol}: {self.adaptive_thresholds[protocol]:.2f}")
        
        except Exception as e:
            logger.error(f"Error updating adaptive thresholds: {e}")
    
    def _analyze_traffic(self):
        """Analyze traffic patterns to detect DDoS attacks"""
        try:
            with self.lock:
                # First update adaptive thresholds based on historical data
                # This also calculates and stores last_interval_protocol_counts
                self._update_adaptive_thresholds()
                
                # Then check each IP against the adaptive thresholds
                current_time = time.time()
                ips_to_remove = []
                
                # ✅ إصلاح منطق DDoS detection
                # بدلاً من مقارنة IP واحد مع threshold الكلي، استخدم نسبة معقولة + buffer zone
                # جميع القيم قابلة للتعديل من Settings
                
                for ip, counts in self.packet_counts.items():
                    # Skip already blocked IPs
                    if ip in self.stats['blocked_ips']:
                        continue
                    
                    # ✅ حساب threshold مناسب لـ IP واحد باستخدام المتغيرات القابلة للتعديل
                    tcp_ip_threshold = (self.adaptive_thresholds['tcp'] * self.max_ip_percentage / 100.0) + self.buffer_zone_tcp
                    udp_ip_threshold = (self.adaptive_thresholds['udp'] * self.max_ip_percentage / 100.0) + self.buffer_zone_udp
                    http_ip_threshold = (self.adaptive_thresholds['http'] * self.max_ip_percentage / 100.0) + self.buffer_zone_http
                    icmp_ip_threshold = (self.adaptive_thresholds['icmp'] * self.max_ip_percentage / 100.0) + self.buffer_zone_icmp
                    
                    # Check for attacks using adjusted thresholds
                    if counts['tcp'] > tcp_ip_threshold:
                        logger.info(f"TCP attack detected from {ip}: {counts['tcp']} > {tcp_ip_threshold:.2f} ({self.max_ip_percentage}% of {self.adaptive_thresholds['tcp']:.2f} + {self.buffer_zone_tcp} buffer)")
                        self._detect_attack(ip, 'tcp')
                    if counts['udp'] > udp_ip_threshold:
                        logger.info(f"UDP attack detected from {ip}: {counts['udp']} > {udp_ip_threshold:.2f} ({self.max_ip_percentage}% of {self.adaptive_thresholds['udp']:.2f} + {self.buffer_zone_udp} buffer)")
                        self._detect_attack(ip, 'udp')
                    if counts['http'] > http_ip_threshold:
                        logger.info(f"HTTP attack detected from {ip}: {counts['http']} > {http_ip_threshold:.2f} ({self.max_ip_percentage}% of {self.adaptive_thresholds['http']:.2f} + {self.buffer_zone_http} buffer)")
                        self._detect_attack(ip, 'http')
                    if counts['icmp'] > icmp_ip_threshold:
                        logger.info(f"ICMP attack detected from {ip}: {counts['icmp']} > {icmp_ip_threshold:.2f} ({self.max_ip_percentage}% of {self.adaptive_thresholds['icmp']:.2f} + {self.buffer_zone_icmp} buffer)")
                        self._detect_attack(ip, 'icmp')
                    
                    # Reset counters for the next interval
                    counts['tcp'] = 0
                    counts['udp'] = 0
                    counts['http'] = 0
                    counts['icmp'] = 0
                    
                    # Mark old entries for removal with improved memory management
                    if current_time - counts['last_seen'] > self.ip_cleanup_threshold:
                        ips_to_remove.append(ip)
                
                # Enhanced memory management: Remove old IP entries and limit total entries
                for ip in ips_to_remove:
                    if ip in self.packet_counts:
                        del self.packet_counts[ip]
                
                # Standard memory management: Remove old IP entries and limit total entries
                if len(self.packet_counts) > self.max_ip_entries:
                    # Sort IPs by last_seen time and remove the oldest ones
                    sorted_ips = sorted(self.packet_counts.items(), 
                                      key=lambda x: x[1]['last_seen'])
                    
                    # Remove the oldest 20% of entries
                    entries_to_remove = len(self.packet_counts) - int(self.max_ip_entries * 0.8)
                    for i in range(entries_to_remove):
                        if i < len(sorted_ips):
                            ip_to_remove = sorted_ips[i][0]
                            if ip_to_remove in self.packet_counts:
                                del self.packet_counts[ip_to_remove]
                
                # Reset overall packets_processed counter for the dashboard (if needed, or adjust logic)
                # self.stats['packets_processed'] = 0 # This seems incorrect, dashboard shows total since start?
                # Let's keep packets_processed as a running total since start.

                # الضغط على الذاكرة بشكل دوري عند عدم وجود هجمات
                if (self.stats['attacks_detected']['tcp'] == 0 and
                    self.stats['attacks_detected']['udp'] == 0 and
                    self.stats['attacks_detected']['http'] == 0 and
                    self.stats['attacks_detected']['icmp'] == 0):
                    
                    current_time = time.time()
                    ips_to_compress = []
                    for ip, counts in list(self.packet_counts.items()): # Use list() to allow modification during iteration
                        # حذف IPs التي تحتوي على عدد قليل من الحزم ولم يتم رؤيتها مؤخرًا
                        if counts['total'] < 5 and (current_time - counts['last_seen'] > 60):
                            ips_to_compress.append(ip)
                    
                    for ip in ips_to_compress:
                        if ip in self.packet_counts:
                            del self.packet_counts[ip]
                    if ips_to_compress:
                        logger.info(f"Memory compressed: Removed {len(ips_to_compress)} inactive IPs.")

        except Exception as e:
            logger.error(f"Error analyzing traffic: {e}")
    
    def _detect_attack(self, ip, attack_type):
        """Record a detected attack (Called within lock)"""
        try:
            self.stats['attacks_detected'][attack_type] += 1
    
            

                




            # Add to blocked IPs if not already blocked
            if ip not in self.stats['blocked_ips']:
                block_time = time.strftime("%Y-%m-%d %H:%M:%S")
                self.stats['blocked_ips'][ip] = block_time # Store IP and timestamp
                
                # ✅ CRITICAL: Update cache immediately for ultra-fast filtering
                self._blocked_ips_cache.add(ip)
                
                self.stats['ips_blocked'] += 1
                
                # Add alert
                self.alerts.append({
                    'timestamp': block_time, # Use the same timestamp for alert
                    'attack_type': f"{attack_type.upper()} Flood",
                    'source_ip': ip
                })

                # Upload alert to Firebase
                log_to_cloud_or_buffer({
                    "timestamp": block_time,
                    "type": "DDoS Alert",
                    "suspect_ip": ip,
                    "protocol": attack_type.upper()
                })

                
                # In a real implementation, this would call system commands to block the IP
                # Check if auto-blocking is enabled before calling system block
                auto_block = True # Default to true if setting not yet applied
                if hasattr(self, 'auto_block_enabled_flag'): # Check for the flag set by GUI
                    auto_block = self.auto_block_enabled_flag
                
                if auto_block:
                    # Run blocking in a separate thread to avoid blocking the detection loop
                    block_thread = threading.Thread(target=self._block_ip_in_system, args=(ip,), daemon=True)
                    block_thread.start()

        except Exception as e:
            logger.error(f"Error detecting attack: {e}")
    
    def _is_valid_ip(self, ip):
        """Check if a string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    def _is_private_ip(self, ip):
        """Check if an IP address is private/internal"""
        try:
            private_ranges = [
                ('10.0.0.0', '10.255.255.255'),     # 10.0.0.0/8
                ('172.16.0.0', '172.31.255.255'),   # 172.16.0.0/12
                ('192.168.0.0', '192.168.255.255'), # 192.168.0.0/16
                ('127.0.0.0', '127.255.255.255')    # 127.0.0.0/8 (localhost)
            ]
            
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            
            for start_range, end_range in private_ranges:
                start_int = struct.unpack('!I', socket.inet_aton(start_range))[0]
                end_int = struct.unpack('!I', socket.inet_aton(end_range))[0]
                if start_int <= ip_int <= end_int:
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking if IP is private: {e}")
            return False
            
    def _block_ip_in_system(self, ip):
        """Block an IP address at the system level"""
        try:
            if not self._is_valid_ip(ip):
                logger.warning(f"Skipping blocking of invalid IP: {ip}")
                return
            
            if not is_admin():
                logger.warning(f"Cannot block IP {ip}: Administrative privileges required")
                if not hasattr(self, 'pending_blocks'):
                    self.pending_blocks = []
                if ip not in self.pending_blocks:
                    self.pending_blocks.append(ip)
                return
                
            import subprocess
            if os.name == 'nt':
                rule_name = f"PacketsWall_Block_{ip}_{int(time.time())}"
                try:
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                    result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                    verify_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
                    
                    if "No rules match the specified criteria" in verify_result.stdout:
                        logger.error(f"Failed to verify firewall rule for IP {ip}")
                        return
                    
                    logger.info(f"Successfully blocked IP: {ip} with rule: {rule_name}")
                    with self.lock:
                        if not hasattr(self, 'rule_names'):
                            self.rule_names = {}
                        self.rule_names[ip] = rule_name
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error executing firewall command: {e.stderr}")
                    return
            else:
                try:
                    cmd = f'iptables -A INPUT -s {ip} -j DROP'
                    result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                    verify_cmd = f'iptables -C INPUT -s {ip} -j DROP'
                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
                    
                    if verify_result.returncode != 0:
                        logger.error(f"Failed to verify iptables rule for IP {ip}")
                        return
                    
                    logger.info(f"Successfully blocked IP: {ip}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error executing iptables command: {e.stderr}")
                    return
            
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
            # Dashboard traffic data (overall packets processed per second)
            # Let's redefine traffic_data to be total packets/sec like protocol data
            # stats['traffic_data'] = list(self.traffic_data) # Old way
            
            # New way: Calculate total packets/sec from protocol data
            total_traffic_data = collections.deque(maxlen=60)
            max_len = 0
            for proto in self.protocol_traffic_data:
                max_len = max(max_len, len(self.protocol_traffic_data[proto]))
            
            for i in range(max_len):
                sec_total = 0
                for proto in self.protocol_traffic_data:
                    if i < len(self.protocol_traffic_data[proto]):
                        sec_total += self.protocol_traffic_data[proto][i]
                total_traffic_data.append(sec_total)
            stats['traffic_data'] = list(total_traffic_data)
            
            # Add protocol-specific data
            stats['protocol_traffic_data'] = {p: list(d) for p, d in self.protocol_traffic_data.items()}
            stats['last_interval_protocol_counts'] = self.last_interval_protocol_counts.copy()
            stats['adaptive_thresholds'] = self.adaptive_thresholds.copy()
            stats['blocked_ips'] = self.stats['blocked_ips'].copy()
            stats['alerts'] = self.alerts[:50] # Return only last 50 alerts
            
            # Calculate overall adaptive threshold for dashboard display (e.g., average or max? Let's use average)
        
        total_traffic_data_list = stats["traffic_data"]
        if total_traffic_data_list:
            max_total = max(total_traffic_data_list)
            stats["overall_adaptive_threshold"] = max_total * (1 + self.allowed_increase_percent / 100.0)
        else:
            stats["overall_adaptive_threshold"] = 0


                
            return stats
    
    def block_ip(self, ip):
        with self.lock:
            if self._is_private_ip(ip):
                logger.warning(f"Skipping blocking of internal IP: {ip}")
                return False
                
            if ip not in self.stats['blocked_ips']:
                block_time = time.strftime("%Y-%m-%d %H:%M:%S")
                self.stats['blocked_ips'][ip] = block_time
                self.stats['ips_blocked'] += 1
                
                # Run blocking in a separate thread
                block_thread = threading.Thread(target=self._block_ip_in_system, args=(ip,), daemon=True)
                block_thread.start()
                
                # Verification might need adjustment due to async blocking
                # Maybe verify later or provide feedback based on thread start
                logger.info(f"Initiated blocking for IP: {ip}")
                return True
            return False
    
    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.stats['blocked_ips']:
                del self.stats['blocked_ips'][ip] # Remove from dictionary
                self.stats['ips_blocked'] -= 1
                
                # Run unblocking in a separate thread
                unblock_thread = threading.Thread(target=self._unblock_ip_in_system, args=(ip,), daemon=True)
                unblock_thread.start()
                logger.info(f"Initiated unblocking for IP: {ip}")
                return True # Indicate initiation, actual result is async
            return False

    def _unblock_ip_in_system(self, ip):
        """Unblock an IP address at the system level"""
        if not is_admin():
            logger.warning(f"Cannot unblock IP {ip}: Administrative privileges required")
            return False
        
        try:
            import subprocess
            if os.name == 'nt':
                rule_name = None
                with self.lock: # Access rule_names safely
                    if hasattr(self, 'rule_names') and ip in self.rule_names:
                        rule_name = self.rule_names[ip]
                
                if rule_name:
                    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                    with self.lock:
                        if ip in self.rule_names: del self.rule_names[ip]
                else:
                    # Fallback: Find and delete rules matching the IP (less precise)
                    list_cmd = f'netsh advfirewall firewall show rule name=all | findstr /C:"{ip}"'
                    list_result = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)
                    import re
                    rule_pattern = r'Rule Name:\s+(PacketsWall_Block_[^\r\n]+)'
                    matches = re.findall(rule_pattern, list_result.stdout)
                    for match_rule in matches:
                        del_cmd = f'netsh advfirewall firewall delete rule name="{match_rule}"'
                        subprocess.run(del_cmd, shell=True, capture_output=True, text=True)
            else:
                # Check if rule exists before deleting to avoid errors
                check_cmd = f'iptables -C INPUT -s {ip} -j DROP'
                check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
                if check_result.returncode == 0:
                    cmd = f'iptables -D INPUT -s {ip} -j DROP'
                    subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
                else:
                    logger.warning(f"iptables rule for IP {ip} not found for deletion.")
            
            logger.info(f"Unblocked IP: {ip}")
            return True
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False
            
    def verify_ip_blocked(self, ip):
        """Verify if an IP is actually blocked at the system level"""
        if not is_admin():
            logger.warning("Cannot verify IP blocking: Administrative privileges required")
            return False
                
        try:
            import subprocess
            if os.name == 'nt':
                rule_name = None
                with self.lock:
                    if hasattr(self, 'rule_names') and ip in self.rule_names:
                        rule_name = self.rule_names[ip]
                
                if rule_name:
                    verify_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
                    return "No rules match the specified criteria" not in verify_result.stdout
                else:
                    # Fallback check (less reliable)
                    verify_cmd = f'netsh advfirewall firewall show rule name=all | findstr /C:"{ip}"'
                    verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
                    # Check if output contains the IP and 'Action: Block'
                    return ip in verify_result.stdout and 'Action: Block' in verify_result.stdout
            else:
                verify_cmd = f'iptables -C INPUT -s {ip} -j DROP'
                verify_result = subprocess.run(verify_cmd, shell=True, capture_output=True, text=True)
                return verify_result.returncode == 0
        except Exception as e:
            logger.error(f"Error verifying IP block for {ip}: {e}")
            return False

    def update_settings(self, time_window, allowed_increase_percent, auto_block_enabled):
        """Update detection settings like time window from the UI."""
        with self.lock:
            # Only update time_window if it's different to avoid resetting unnecessarily
            if self.time_window != time_window:
                self.time_window = time_window
                # Reset window counter immediately when time window changes
                self.packets_processed_window = 0
                self.last_reset_time = time.time()
                logger.info(f"Updated analysis time window to: {self.time_window} seconds and reset window counter.")
            
            self.allowed_increase_percent = allowed_increase_percent
            self.auto_block_enabled_flag = auto_block_enabled # Store auto-block status
            logger.info(f"Updated allowed traffic increase to: {self.allowed_increase_percent}%")
            logger.info(f"Updated auto-blocking enabled status to: {self.auto_block_enabled_flag}")

    def check_and_reset_window_counter(self):
        """Check if the time window has passed and reset the window packet counter."""
        current_time = time.time()
        reset_occurred = False
        with self.lock:
            if current_time - self.last_reset_time >= self.time_window:
                self.packets_processed_window = 0
                self.last_reset_time = current_time
                reset_occurred = True
                # logger.debug(f"Resetting packets_processed_window at {current_time}") # Optional debug log
        return reset_occurred # Return whether a reset happened

    def get_statistics(self):
        """Return the current system statistics."""
        with self.lock:
            stats = self.stats.copy()
            stats["uptime"] = self.get_uptime()

            # Step 1: إعادة حساب الترافيك العام بناءً على مجموع البروتوكولات
            total_traffic_data = collections.deque(maxlen=self.time_window)
            max_len = 0
            for proto in self.protocol_traffic_data:
                max_len = max(max_len, len(self.protocol_traffic_data[proto]))

            for i in range(max_len):
                sec_total = 0
                for proto in self.protocol_traffic_data:
                    if i < len(self.protocol_traffic_data[proto]):
                        sec_total += self.protocol_traffic_data[proto][i]
                total_traffic_data.append(sec_total)

            # Step 2: حفظ البيانات للواجهة
            stats["traffic_data"] = list(total_traffic_data)
            stats["protocol_traffic_data"] = {p: list(d) for p, d in self.protocol_traffic_data.items()}
            stats["last_interval_protocol_counts"] = self.last_interval_protocol_counts.copy()
            stats["adaptive_thresholds"] = self.adaptive_thresholds.copy()
            stats["blocked_ips"] = self.stats["blocked_ips"].copy()
            stats["alerts"] = self.alerts[:50]

            # Debug: طباعة بيانات البروتوكولات
            for proto, data in self.protocol_traffic_data.items():
                if data:
                    max_val = max(data)
                    threshold_val = max_val * (1 + self.allowed_increase_percent / 100.0)
                    print(f"[DEBUG] {proto.upper()} max = {max_val:.2f}, Threshold = {threshold_val:.2f}")

            # Debug: طباعة بيانات الترافيك العام
            total_traffic_data_list = stats["traffic_data"]
            if total_traffic_data_list:
                max_total = max(total_traffic_data_list)
                stats["overall_adaptive_threshold"] = max_total * (1 + self.allowed_increase_percent / 100.0)
                print(f"[DEBUG] Total Traffic max = {max_total:.2f}, Threshold = {stats['overall_adaptive_threshold']:.2f}")
            else:
                stats["overall_adaptive_threshold"] = 0

            return stats





def is_admin():
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
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
    def __init__(self, parent=None, width=5, height=3, dpi=100): # Reduced default height
        fig = Figure(figsize=(width, height), dpi=dpi)
        # Adjust subplot parameters for tighter layout
        fig.subplots_adjust(left=0.15, right=0.95, top=0.9, bottom=0.2) 
        self.axes = fig.add_subplot(111)
        super(MplCanvas, self).__init__(fig)

# Main application window
class PacketsWallApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # تعيين أيقونة النافذة مع إمكانية استخدام أيقونة بديلة
        icon_path = "icons/logopacketswall.ico"
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            # استخدام الأيقونة الأصلية كبديل
            original_icon_path = "icons/logopacketswall.ico"
            if os.path.exists(original_icon_path):
                self.setWindowIcon(QIcon(original_icon_path))
                logger.info(f"Using original logopacketswall.ico as window icon (logopacketswall icon not found)")
            else:
                logger.warning(f"Neither logopacketswall icon nor original icon found")

        self.setWindowTitle("PacketsWall - DDoS Detection and Prevention System")
        # Adjusted size for potentially more content
        self.setGeometry(100, 100, 1300, 850) 
        
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
        
        self.interfaces = self._get_network_interfaces()
        self.detection_system = DDoSDetectionSystem()
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.dashboard_tab = QWidget()
        self.protocols_tab = QWidget() # New Protocols Tab
        self.settings_tab = QWidget()
        self.logs_tab = QWidget()
        self.about_tab = QWidget()
        
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.protocols_tab, "Protocols") # Add Protocols Tab
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.addTab(self.about_tab, "About")
        
        # Set up each tab
        self._setup_dashboard_tab()
        self._setup_protocols_tab() # Setup Protocols Tab
        self._setup_settings_tab()
        self._setup_logs_tab()
        self._setup_about_tab()
        
        self.statusBar().showMessage("Ready")
        
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_ui)
        self.update_timer.start(1000)  # Update every second
        
        self.system_running = False
        self._initialize_attack_chart() # Initialize chart on startup
        self._add_log("Application started")
        if is_admin():
            self._add_log("Running with administrator privileges")
        else:
            self._add_log("WARNING: Not running with administrator privileges")
    
    def _get_network_interfaces(self):
        interfaces = ["All Interfaces", "Read from PCAP file..."]
        try:
            if os.name == 'nt':
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    if 'name' in iface:
                        interfaces.append(iface['name'])
            else:
                from scapy.arch import get_if_list
                interfaces.extend(get_if_list())
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            self._add_log(f"Error getting network interfaces: {e}")
        return interfaces
    
    def _setup_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        top_layout = QHBoxLayout()
        layout.addLayout(top_layout)
        
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout(status_group)
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
        status_layout.addWidget(self.status_label)
        self.start_stop_button = QPushButton("Start System")
        self.start_stop_button.clicked.connect(self._toggle_system)
        status_layout.addWidget(self.start_stop_button)
        top_layout.addWidget(status_group)
        
        stats_group = QGroupBox("Statistics")
        stats_layout = QFormLayout(stats_group)
        self.uptime_label = QLabel("00:00:00")
        self.packets_label = QLabel("0")
        self.attacks_label = QLabel("0")
        # Changed label to show overall adaptive threshold (average)
        self.threshold_label = QLabel("N/A") 
        stats_layout.addRow("Uptime:", self.uptime_label)
        stats_layout.addRow("Packets Processed:", self.packets_label)
        stats_layout.addRow("Attacks Detected:", self.attacks_label)
        stats_layout.addRow("Avg. Adaptive Threshold:", self.threshold_label) 
        top_layout.addWidget(stats_group)
        
        charts_layout = QHBoxLayout()
        layout.addLayout(charts_layout)
        
        traffic_group = QGroupBox("Network Traffic (packets/sec)") # Clarified title
        traffic_layout = QVBoxLayout(traffic_group)
        # Use standard MplCanvas size
        self.traffic_canvas = MplCanvas(self, width=5, height=4, dpi=100) 
        traffic_layout.addWidget(self.traffic_canvas)
        charts_layout.addWidget(traffic_group)
        
        attack_group = QGroupBox("Attack Distribution")
        attack_layout = QVBoxLayout(attack_group)
        self.attack_canvas = MplCanvas(self, width=5, height=4, dpi=100)
        attack_layout.addWidget(self.attack_canvas)
        charts_layout.addWidget(attack_group)
        
        tables_layout = QHBoxLayout()
        layout.addLayout(tables_layout)
        
        blocked_group = QGroupBox("Blocked IP Addresses")
        blocked_layout = QVBoxLayout(blocked_group)
        self.blocked_table = QTableWidget()
        self.blocked_table.setColumnCount(3)
        self.blocked_table.setHorizontalHeaderLabels(["IP Address", "Block Time", "Action"])
        self.blocked_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        blocked_layout.addWidget(self.blocked_table)
        block_layout = QHBoxLayout()
        self.block_ip_input = QLineEdit()
        self.block_ip_input.setPlaceholderText("Enter IP address to block")
        block_layout.addWidget(self.block_ip_input)
        self.block_ip_button = QPushButton("Block IP")
        self.block_ip_button.clicked.connect(self._block_ip)
        block_layout.addWidget(self.block_ip_button)
        blocked_layout.addLayout(block_layout)
        tables_layout.addWidget(blocked_group)
        
        alerts_group = QGroupBox("Recent Alerts")
        alerts_layout = QVBoxLayout(alerts_group)
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(3)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Attack Type", "Source IP"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        alerts_layout.addWidget(self.alerts_table)
        tables_layout.addWidget(alerts_group)

    # --- New function to setup Protocols tab --- 
    def _setup_protocols_tab(self):
        main_layout = QVBoxLayout(self.protocols_tab)
        grid_layout = QGridLayout()
        main_layout.addLayout(grid_layout)

        # Store canvases and labels in dictionaries for easier access
        self.protocol_canvases = {}
        self.protocol_packet_labels = {}
        self.protocol_threshold_labels = {}

        protocols = [
            ('tcp', 'TCP Traffic'), 
            ('udp', 'UDP Traffic'), 
            ('icmp', 'ICMP Traffic'), 
            ('http', 'HTTP Traffic')
        ]

        positions = [(i, j) for i in range(2) for j in range(2)] # 2x2 grid

        for (proto_key, proto_name), pos in zip(protocols, positions):
            group_box = QGroupBox(proto_name)
            group_layout = QVBoxLayout(group_box)

            # Create canvas
            canvas = MplCanvas(self, width=5, height=3, dpi=100) # Use smaller height for grid
            self.protocol_canvases[proto_key] = canvas
            group_layout.addWidget(canvas)

            # Create labels layout
            labels_layout = QHBoxLayout()
            
            packets_label_title = QLabel("Packets (Interval):")
            packets_value_label = QLabel("0")
            self.protocol_packet_labels[proto_key] = packets_value_label
            
            threshold_label_title = QLabel("Adaptive Threshold:")
            threshold_value_label = QLabel("0.00")
            self.protocol_threshold_labels[proto_key] = threshold_value_label

            labels_layout.addWidget(packets_label_title)
            labels_layout.addWidget(packets_value_label)
            labels_layout.addStretch()
            labels_layout.addWidget(threshold_label_title)
            labels_layout.addWidget(threshold_value_label)
            
            group_layout.addLayout(labels_layout)
            grid_layout.addWidget(group_box, pos[0], pos[1])
            
        # Initialize charts
        self._initialize_protocol_charts()
    # --- End of new function --- 

    def _setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        
        interface_group = QGroupBox("Network Interface / Input Source") # Updated title
        interface_layout = QVBoxLayout(interface_group) # Use QVBoxLayout
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.interfaces)
        interface_layout.addWidget(self.interface_combo)

        # --- Add PCAP file selection widgets ---
        self.pcap_file_widget = QWidget() # Container widget
        pcap_layout = QHBoxLayout(self.pcap_file_widget)
        pcap_layout.setContentsMargins(0, 5, 0, 0) # Add some top margin
        self.pcap_file_path_edit = QLineEdit()
        self.pcap_file_path_edit.setPlaceholderText("Select PCAP file...")
        self.pcap_file_path_edit.setReadOnly(True) # Make it read-only, path set via browse
        pcap_layout.addWidget(self.pcap_file_path_edit)
        self.browse_pcap_button = QPushButton("Browse...")
        self.browse_pcap_button.clicked.connect(self._browse_pcap_file)
        pcap_layout.addWidget(self.browse_pcap_button)
        interface_layout.addWidget(self.pcap_file_widget)
        self.pcap_file_widget.setVisible(False) # Initially hidden
        # --- End PCAP file selection widgets ---

        # Connect signal to handler
        self.interface_combo.currentIndexChanged.connect(self._handle_interface_selection)

        layout.addWidget(interface_group)
        
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QFormLayout(detection_group)
        self.time_window_spin = QSpinBox()
        self.time_window_spin.setRange(1, 60)
        self.time_window_spin.setValue(10)
        self.time_window_spin.setSuffix(" seconds")
        detection_layout.addRow("Analysis Time Window:", self.time_window_spin)
        self.allowed_increase_spin = QDoubleSpinBox()
        self.allowed_increase_spin.setRange(1, 100)
        self.allowed_increase_spin.setValue(20)
        self.allowed_increase_spin.setSuffix("%")
        detection_layout.addRow("Allowed Traffic Increase:", self.allowed_increase_spin)
        layout.addWidget(detection_group)
        
        prevention_group = QGroupBox("Prevention Settings")
        prevention_layout = QFormLayout(prevention_group)
        self.auto_block_checkbox = QCheckBox("Enable Automatic Blocking") # Renamed for clarity
        self.auto_block_checkbox.setChecked(True) # Default to enabled
        prevention_layout.addRow(self.auto_block_checkbox)
        layout.addWidget(prevention_group)
        
        email_group = QGroupBox("Email Notifications")
        email_layout = QFormLayout(email_group)
        self.email_enabled = QCheckBox("Enable Email Notifications")
        email_layout.addRow(self.email_enabled)
        self.email_address = QLineEdit()
        self.email_address.setPlaceholderText("Enter email address")
        email_layout.addRow("Email Address:", self.email_address)
        layout.addWidget(email_group)
        

        self.save_settings_button = QPushButton("Save Settings")
        self.save_settings_button.clicked.connect(self._save_settings)
        layout.addWidget(self.save_settings_button)
        layout.addStretch()
    
    def _setup_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)
        log_controls = QHBoxLayout()
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self._clear_logs)
        log_controls.addWidget(self.clear_logs_button)
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self._save_logs)
        log_controls.addWidget(self.save_logs_button)
        layout.addLayout(log_controls)
    

    def _setup_about_tab(self):
        layout = QVBoxLayout(self.about_tab)
        # Create a horizontal layout for centering the logo and title
        center_header_layout = QHBoxLayout()
        center_header_layout.addStretch() # Add stretch to the left

        # Logo (logopacketswall-removebg-preview.png)
        logopacketswall_label = QLabel()
        logopacketswall_path = "icons/logopacketswall-removebg-preview.png"
        if os.path.exists(logopacketswall_path):
            logopacketswall_pixmap = QPixmap(logopacketswall_path)
            if not logopacketswall_pixmap.isNull():
                logopacketswall_label.setPixmap(logopacketswall_pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                center_header_layout.addWidget(logopacketswall_label)
        else:
            logger.warning(f"logopacketswall image file not found: {logopacketswall_path}")
        
        # Add a small spacer between logo and text
        # Create a horizontal layout for centering the logo and title
        center_header_layout = QHBoxLayout()
        center_header_layout.setSpacing(0) # Set spacing between widgets to 0
        center_header_layout.setContentsMargins(0, 0, 0, 0) # Remove any margins from the layout itself
        center_header_layout.addStretch() # Add stretch to the left to push content to center

        # Logo (logopacketswall-removebg-preview.png)
        logopacketswall_label = QLabel()
        logopacketswall_path = "icons/logopacketswall-removebg-preview.png"
        if os.path.exists(logopacketswall_path):
            logopacketswall_pixmap = QPixmap(logopacketswall_path)
            if not logopacketswall_pixmap.isNull():
                logopacketswall_label.setPixmap(logopacketswall_pixmap.scaled(130, 130, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                center_header_layout.addWidget(logopacketswall_label)
        else:
            logger.warning(f"logopacketswall image file not found: {logopacketswall_path}")
        
        # Title (PacketsWall)
        title = QLabel("PacketsWall")
        title.setFont(QFont("Arial", 40, QFont.Bold))
        center_header_layout.addWidget(title)
        
        center_header_layout.addStretch() # Add stretch to the right to push content to center
        layout.addLayout(center_header_layout)

        description = QLabel(
            "PacketsWall is a DDoS detection and prevention system "
            "designed to protect networks from various types of DDoS attacks. "
            "The system can detect and prevent TCP SYN Flood, UDP Flood, HTTP Flood, and ICMP Flood attacks."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description)
        features_group = QGroupBox("System Capabilities")
        features_layout = QVBoxLayout(features_group)
        features = [
            "Real-time network traffic monitoring",
            "Adaptive threshold-based detection for multiple attack types",
            "Per-protocol traffic monitoring",
            "Automatic blocking of malicious IP addresses",
            "Manual IP blocking",
            "Internal IP address detection and prevention from blocking",
            "Email alerts for detected attacks",
            "Comprehensive dashboard and protocol-specific views",
            "Detailed logs for forensic analysis",
            "Live Logs and Real-time Updates -Web Admin Page-",
        ]
        for feature in features:
            feature_label = QLabel(f"• {feature}")
            features_layout.addWidget(feature_label)
            layout.addSpacing(5)
        layout.addWidget(features_group)
        layout.addStretch()

    # --- Handler for interface selection change ---
    def _handle_interface_selection(self, index):
        selected_option = self.interface_combo.itemText(index)
        if selected_option == "Read from PCAP file...":
            self.pcap_file_widget.setVisible(True)
        else:
            self.pcap_file_widget.setVisible(False)

    # --- Handler for browsing PCAP file ---
    def _browse_pcap_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getOpenFileName(self, 
                                                 "Select PCAP File", 
                                                 "", 
                                                 "PCAP Files (*.pcap *.pcapng);;All Files (*)", 
                                                 options=options)
        if file_name:
            self.pcap_file_path_edit.setText(file_name)
            self._add_log(f"Selected PCAP file: {file_name}")

    def _toggle_system(self):
        if not self.system_running:
            try:
                selected_interface = self.interface_combo.currentText()
                self.detection_system.interface = selected_interface
                self.detection_system.pcap_file = None # Reset pcap file path

                # Check if PCAP option is selected
                if selected_interface == "Read from PCAP file...":
                    pcap_path = self.pcap_file_path_edit.text().strip()
                    if not pcap_path or not os.path.exists(pcap_path):
                        QMessageBox.warning(self, "Input Error", "Please select a valid PCAP file.")
                        return # Stop if no valid PCAP file selected
                    self.detection_system.pcap_file = pcap_path
                    self.detection_system.interface = None # Ensure interface is None when reading from file
                    self._add_log(f"Starting system with PCAP file: {pcap_path}")
                else:
                    self._add_log(f"Starting system on interface: {selected_interface}")

                self._apply_settings() # Apply settings before starting
                
                if self.detection_system.start():
                    self.system_running = True
                    self.status_label.setText("Running")
                    self.status_label.setStyleSheet("color: green; font-weight: bold; font-size: 16px;")
                    self.start_stop_button.setText("Stop System")
                    self.statusBar().showMessage("System started")
                    self._add_log("System started")
                    # Disable interface selection while running
                    self.interface_combo.setEnabled(False)
                    # Disable settings save button while running
                    self.save_settings_button.setEnabled(False)
                else:
                    QMessageBox.critical(self, "Error", "Failed to start the detection system. Check logs.")
                    self.statusBar().showMessage("Failed to start system")
                    self._add_log("Failed to start system")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred while starting: {e}")
                logger.error(f"Error starting system: {e}")
                self._add_log(f"Error starting system: {e}")
        else:
            try:
                if self.detection_system.stop():
                    self.system_running = False
                    self.status_label.setText("Stopped")
                    self.status_label.setStyleSheet("color: red; font-weight: bold; font-size: 16px;")
                    self.start_stop_button.setText("Start System")
                    self.statusBar().showMessage("System stopped")
                    self._add_log("System stopped")
                    # Re-enable interface selection and settings save
                    self.interface_combo.setEnabled(True)
                    self.save_settings_button.setEnabled(True)
                    # Reset UI elements to initial state
                    self._reset_ui_on_stop()
                else:
                    QMessageBox.warning(self, "Warning", "Failed to stop the detection system properly. Check logs.")
                    self.statusBar().showMessage("Failed to stop system")
                    self._add_log("Failed to stop system")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred while stopping: {e}")
                logger.error(f"Error stopping system: {e}")
                self._add_log(f"Error stopping system: {e}")

    def _reset_ui_on_stop(self):
        """Resets relevant UI elements when the system stops."""
        self.uptime_label.setText("00:00:00")
        self.packets_label.setText("0")
        self.attacks_label.setText("0")
        self.threshold_label.setText("N/A")
        self.blocked_table.setRowCount(0)
        self.alerts_table.setRowCount(0)
        self._initialize_attack_chart() # Reset attack chart
        self._initialize_traffic_chart() # Reset traffic chart
        self._initialize_protocol_charts() # Reset protocol charts

    def _apply_settings(self):
        """Apply settings from the UI to the detection system"""
        try:
            self.detection_system.cleanup_interval = self.time_window_spin.value()
            self.detection_system.allowed_increase_percent = self.allowed_increase_spin.value()
            # Pass the state of the checkbox directly
            self.detection_system.auto_block_enabled_flag = self.auto_block_checkbox.isChecked()
            
            # Apply other settings if needed (e.g., email)
            # self.email_notification_enabled = self.email_enabled.isChecked()
            # self.notification_email_address = self.email_address.text()
            
            logger.info("Settings applied")
            self._add_log("Settings applied")
        except Exception as e:
            logger.error(f"Error applying settings: {e}")
            self._add_log(f"Error applying settings: {e}")

    def _save_settings(self):
        """Save current settings (could be to a file, or just apply them)"""
            # Currently, just applies them to the running instance if stopped
            # If running, settings are applied before start
        if not self.system_running:
            self._apply_settings()
            

        # Save email settings to Firebase Firestore
        if not firebase_admin._apps:
            cred = credentials.Certificate("packetswall-firebase-adminsdk-fbsvc-1802e73161.json")
            firebase_admin.initialize_app(cred)
            self.firestore_initialized = True

        try:
            db = firestore.client()
            doc_ref = db.collection("settings").document("email_notifications")
            doc_ref.set({
                "enabled": self.email_enabled.isChecked(),
                "email": self.email_address.text().strip(),
                

            })
            logger.info("Email settings saved to Firestore")
        except Exception as e:
            print(f"Failed to save email settings to Firestore: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save to Firebase:\n{e}")


            QMessageBox.information(self, "Settings Saved", "Settings have been applied.")
        else:
            QMessageBox.information(self, "Settings Info", "Settings will be applied the next time the system is started.")

    def _update_ui(self):
        """Update the UI elements based on the latest statistics"""
        if not self.system_running:
            return
            
        try:
            # Check and reset the window counter *before* getting stats for display
            self.detection_system.check_and_reset_window_counter()

            stats = self.detection_system.get_statistics()
            
            # Update Dashboard tab
            self.uptime_label.setText(stats['uptime'])
            self.packets_label.setText(str(self.detection_system.packets_processed_window))
            total_attacks = sum(stats['attacks_detected'].values())
            self.attacks_label.setText(str(total_attacks))
            # Display average threshold on dashboard
            self.threshold_label.setText(f"{stats.get('overall_adaptive_threshold', 0):.2f}") 
            
            self._update_traffic_chart(stats)
            self._update_attack_chart(stats)
            self._update_blocked_table(stats)
            self._update_alerts_table(stats)
            
            # Update Protocols tab
            self._update_protocol_charts(stats)
            
        except Exception as e:
            logger.error(f"Error updating UI: {e}")
            # Consider adding a log entry or status bar message about UI update error
            # self._add_log(f"Error updating UI: {e}")
            # self.statusBar().showMessage("Error updating UI")

    def _update_traffic_chart(self, stats):
        """Update the main network traffic chart"""
        try:
            data = stats.get('traffic_data', [])
            threshold = stats.get('overall_adaptive_threshold', 0) # Use overall threshold for main chart
            
            ax = self.traffic_canvas.axes
            ax.cla() # Clear previous plot
            
            if data:
                ax.plot(range(len(data)), data, marker='.', linestyle='-', label='Packets/sec')
                # Plot overall adaptive threshold line
                ax.axhline(y=threshold, color='r', linestyle='--', label=f'Avg Threshold ({threshold:.2f})')
            else:
                ax.plot([], [], marker='.', linestyle='-', label='Packets/sec') # Plot empty if no data
                ax.axhline(y=threshold, color='r', linestyle='--', label=f'Avg Threshold ({threshold:.2f})')

            ax.set_title("Network Traffic (packets/sec)")
            ax.set_xlabel("Time (seconds ago)")
            ax.set_ylabel("Packets")
            ax.legend(loc='upper right')
            ax.grid(True)
            # Dynamically adjust y-axis limit
            if data:
                max_val = max(max(data) if data else 0, threshold)
                ax.set_ylim(bottom=0, top=max(10, max_val * 1.2)) # Ensure minimum height
            else:
                 ax.set_ylim(bottom=0, top=max(10, threshold * 1.2))
            
            # Set x-axis limits based on data length (max 60 seconds)
            ax.set_xlim(left=0, right=max(10, len(data) -1 if data else 10)) # Ensure minimum width

            self.traffic_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating traffic chart: {e}")

    def _initialize_traffic_chart(self):
        """Initialize the traffic chart to an empty state."""
        try:
            ax = self.traffic_canvas.axes
            ax.cla()
            ax.plot([], [], marker='.', linestyle='-', label='Packets/sec')
            ax.axhline(y=0, color='r', linestyle='--', label='Avg Threshold (0.00)')
            ax.set_title("Network Traffic (packets/sec)")
            ax.set_xlabel("Time (seconds ago)")
            ax.set_ylabel("Packets")
            ax.legend(loc='upper right')
            ax.grid(True)
            ax.set_ylim(bottom=0, top=10)
            ax.set_xlim(left=0, right=10)
            self.traffic_canvas.draw()
        except Exception as e:
            logger.error(f"Error initializing traffic chart: {e}")

    def _update_attack_chart(self, stats):
        """Update the attack distribution pie chart"""
        try:
            attacks = stats.get('attacks_detected', {})
            # Filter out attack types with 0 count
            valid_attacks = {k: v for k, v in attacks.items() if v > 0}
            labels = [k.upper() for k in valid_attacks.keys()]
            sizes = list(valid_attacks.values())
            
            ax = self.attack_canvas.axes
            ax.cla()
            
            if sizes: # If there are attacks with counts > 0
                ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')  # Equal aspect ratio ensures a circular pie chart
                ax.set_title("Attack Distribution")
            else: # If no attacks detected or all counts are 0
                # Draw placeholder pie chart (gray donut)
                placeholder_sizes = [1, 1, 1, 1]
                placeholder_labels = ['TCP', 'UDP', 'ICMP', 'HTTP'] # Show labels for context
                placeholder_colors = ['#d3d3d3'] * 4 # Light gray for all slices

                # Draw the pie chart without percentage labels, make it a donut
                wedges, texts = ax.pie(placeholder_sizes, labels=placeholder_labels,
                                       colors=placeholder_colors, startangle=90,
                                       wedgeprops=dict(width=0.5)) # Donut chart

                # Add text in the center
                ax.text(0, 0, 'No attacks detected', ha='center', va='center', fontsize=10,
                        bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="gray", lw=1))

                ax.axis('equal')  # Equal aspect ratio ensures a circular pie chart
                ax.set_title("Attack Distribution")
            
            self.attack_canvas.draw()
        except Exception as e:
            logger.error(f"Error updating attack chart: {e}")

    def _initialize_attack_chart(self):
        """Initialize the attack chart to the placeholder state."""
        try:
            ax = self.attack_canvas.axes
            ax.cla()
            
            # Draw placeholder pie chart (gray donut)
            placeholder_sizes = [1, 1, 1, 1]
            placeholder_labels = ['TCP', 'UDP', 'ICMP', 'HTTP'] # Show labels for context
            placeholder_colors = ['#d3d3d3'] * 4 # Light gray for all slices

            # Draw the pie chart without percentage labels, make it a donut
            wedges, texts = ax.pie(placeholder_sizes, labels=placeholder_labels,
                                   colors=placeholder_colors, startangle=90,
                                   wedgeprops=dict(width=0.5)) # Donut chart

            # Add text in the center
            ax.text(0, 0, 'No attacks detected', ha='center', va='center', fontsize=10,
                    bbox=dict(boxstyle="round,pad=0.5", fc="white", ec="gray", lw=1))

            ax.axis('equal')  # Equal aspect ratio ensures a circular pie chart
            ax.set_title("Attack Distribution")
            
            self.attack_canvas.draw()
        except Exception as e:
            logger.error(f"Error initializing attack chart: {e}")
            
    # --- New function to update Protocol charts --- 
    def _update_protocol_charts(self, stats):
        protocols = ['tcp', 'udp', 'icmp', 'http']
        traffic_data = stats.get('protocol_traffic_data', {p: [] for p in protocols})
        thresholds = stats.get('adaptive_thresholds', {p: 0 for p in protocols})
        interval_counts = stats.get('last_interval_protocol_counts', {p: 0 for p in protocols})

        for proto in protocols:
            try:
                canvas = self.protocol_canvases.get(proto)
                packet_label = self.protocol_packet_labels.get(proto)
                threshold_label = self.protocol_threshold_labels.get(proto)
                
                if not canvas or not packet_label or not threshold_label:
                    logger.warning(f"UI elements for protocol {proto} not found.")
                    continue

                data = traffic_data.get(proto, [])
                threshold = thresholds.get(proto, 0)
                interval_count = interval_counts.get(proto, 0)
                
                ax = canvas.axes
                ax.cla()

                if data:
                    ax.plot(range(len(data)), data, marker='.', linestyle='-', label='Packets/sec')
                    ax.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.2f})')
                else:
                    ax.plot([], [], marker='.', linestyle='-', label='Packets/sec') # Plot empty if no data
                    ax.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.2f})')

                # Use protocol name from setup for title
                proto_title = f"{proto.upper()} Traffic"
                for p_key, p_name in [
                    ('tcp', 'TCP Traffic'), ('udp', 'UDP Traffic'), 
                    ('icmp', 'ICMP Traffic'), ('http', 'HTTP Traffic')]:
                    if p_key == proto:
                        proto_title = p_name
                        break
                ax.set_title(proto_title)
                ax.set_xlabel("Time (seconds ago)")
                ax.set_ylabel("Packets/sec") # Changed label
                ax.legend(loc='upper right', fontsize='small') # Smaller font for legend
                ax.grid(True)

                # Dynamic Y-axis
                if data:
                    max_val = max(max(data) if data else 0, threshold)
                    ax.set_ylim(bottom=0, top=max(5, max_val * 1.2)) # Min height 5
                else:
                    ax.set_ylim(bottom=0, top=max(5, threshold * 1.2))
                
                # Dynamic X-axis
                ax.set_xlim(left=0, right=max(10, len(data) - 1 if data else 10))

                canvas.draw()

                # Update labels
                packet_label.setText(str(interval_count))
                threshold_label.setText(f"{threshold:.2f}")

            except Exception as e:
                logger.error(f"Error updating {proto} protocol chart: {e}")
    # --- End of new function ---

    # --- New function to initialize Protocol charts --- 
    def _initialize_protocol_charts(self):
        protocols = ['tcp', 'udp', 'icmp', 'http']
        for proto in protocols:
            try:
                canvas = self.protocol_canvases.get(proto)
                packet_label = self.protocol_packet_labels.get(proto)
                threshold_label = self.protocol_threshold_labels.get(proto)
                
                if not canvas or not packet_label or not threshold_label:
                    continue

                ax = canvas.axes
                ax.cla()
                ax.plot([], [], marker='.', linestyle='-', label='Packets/sec')
                ax.axhline(y=0, color='r', linestyle='--', label='Threshold (0.00)')
                
                proto_title = f"{proto.upper()} Traffic"
                for p_key, p_name in [
                    ('tcp', 'TCP Traffic'), ('udp', 'UDP Traffic'), 
                    ('icmp', 'ICMP Traffic'), ('http', 'HTTP Traffic')]:
                    if p_key == proto:
                        proto_title = p_name
                        break
                ax.set_title(proto_title)
                ax.set_xlabel("Time (seconds ago)")
                ax.set_ylabel("Packets/sec")
                ax.legend(loc='upper right', fontsize='small')
                ax.grid(True)
                ax.set_ylim(bottom=0, top=10)
                ax.set_xlim(left=0, right=10)
                canvas.draw()

                packet_label.setText("0")
                threshold_label.setText("0.00")
            except Exception as e:
                logger.error(f"Error initializing {proto} protocol chart: {e}")
    # --- End of new function ---

    def _update_blocked_table(self, stats):
        """Update the table of blocked IP addresses"""
        try:
            blocked_ips = stats.get('blocked_ips', {})
            self.blocked_table.setRowCount(len(blocked_ips))
            
            row = 0
            # Sort IPs for consistent display order
            sorted_ips = sorted(blocked_ips.keys())
            
            for ip in sorted_ips:
                block_time = blocked_ips[ip]
                self.blocked_table.setItem(row, 0, QTableWidgetItem(ip))
                self.blocked_table.setItem(row, 1, QTableWidgetItem(block_time))
                
                # Add unblock button
                unblock_button = QPushButton("Unblock")
                # Use lambda to capture the correct IP for the button click
                unblock_button.clicked.connect(lambda checked, ip=ip: self._unblock_ip(ip))
                self.blocked_table.setCellWidget(row, 2, unblock_button)
                
                row += 1
        except Exception as e:
            logger.error(f"Error updating blocked table: {e}")

    def _update_alerts_table(self, stats):
        """Update the table of recent alerts"""
        try:
            alerts = stats.get('alerts', [])
            self.alerts_table.setRowCount(len(alerts))
            
            row = 0
            # Display latest alerts first
            for alert in reversed(alerts):
                self.alerts_table.setItem(row, 0, QTableWidgetItem(alert['timestamp']))
                self.alerts_table.setItem(row, 1, QTableWidgetItem(alert['attack_type']))
                self.alerts_table.setItem(row, 2, QTableWidgetItem(alert['source_ip']))
                row += 1
        except Exception as e:
            logger.error(f"Error updating alerts table: {e}")

    def _block_ip(self):
        """Handle manual IP blocking from the dashboard"""
        ip_to_block = self.block_ip_input.text().strip()
        if not ip_to_block:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address to block.")
            return
            
        if not self.detection_system._is_valid_ip(ip_to_block):
            QMessageBox.warning(self, "Input Error", f"Invalid IP address format: {ip_to_block}")
            return
            
        if self.detection_system._is_private_ip(ip_to_block):
             QMessageBox.warning(self, "Block Skipped", f"Cannot manually block private/internal IP address: {ip_to_block}")
             return

        if self.detection_system.block_ip(ip_to_block):
            self._add_log(f"Manually blocked IP: {ip_to_block}")
            self.statusBar().showMessage(f"IP {ip_to_block} blocked")
            self.block_ip_input.clear()
            # Force UI update to show the newly blocked IP immediately
            self._update_ui()
        else:
            # Check if already blocked
            with self.detection_system.lock:
                if ip_to_block in self.detection_system.stats['blocked_ips']:
                    QMessageBox.information(self, "Already Blocked", f"IP address {ip_to_block} is already blocked.")
                else:
                     QMessageBox.warning(self, "Error", f"Failed to block IP: {ip_to_block}. Check logs.")
            self._add_log(f"Failed to manually block IP: {ip_to_block}")
            self.statusBar().showMessage(f"Failed to block IP {ip_to_block}")

    def _unblock_ip(self, ip):
        """Handle unblocking IP from the table button"""
        reply = QMessageBox.question(
            self, 
            'Confirm Unblock',
            f'Are you sure you want to unblock IP address {ip}?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.detection_system.unblock_ip(ip):
                self._add_log(f"Unblocked IP: {ip}")
                self.statusBar().showMessage(f"IP {ip} unblocked")
                # Force UI update immediately
                self._update_ui()
            else:
                QMessageBox.warning(self, "Error", f"Failed to unblock IP: {ip}. Check logs or permissions.")
                self._add_log(f"Failed to unblock IP: {ip}")
                self.statusBar().showMessage(f"Failed to unblock IP {ip}")

    def _add_log(self, message):
        """Add a message to the log display and logger"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_display.append(log_entry)
        logger.info(message) # Also log to file/console via logging setup

    def _clear_logs(self):
        """Clear the log display"""
        self.log_display.clear()
        self._add_log("Log display cleared")

    def _save_logs(self):
        """Save the log display content to a file"""
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Logs", "packetswall_log.txt", "Text Files (*.txt);;All Files (*)", options=options)
        
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    f.write(self.log_display.toPlainText())
                self.statusBar().showMessage(f"Logs saved to {file_name}")
                self._add_log(f"Logs saved to {file_name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save logs: {e}")
                self.statusBar().showMessage("Failed to save logs")
                self._add_log(f"Failed to save logs: {e}")

    def closeEvent(self, event):
        """Handle application closing"""
        # Stop the detection system if running
        if self.system_running:
            self.detection_system.stop()
        
        # Ask for confirmation
        reply = QMessageBox.question(
            self, 
            'Confirm Exit',
            'Are you sure you want to exit PacketsWall?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            event.accept() # Proceed with closing
        else:
            event.ignore() # Cancel closing

# Entry point
if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # تعيين أيقونة التطبيق على مستوى QApplication لضمان ظهورها في شريط المهام
    app_icon_path = "icons/logopacketswall.ico"
    if os.path.exists(app_icon_path):
        app.setWindowIcon(QIcon(app_icon_path))
    else:
        # استخدام الأيقونة الأصلية كبديل
        original_app_icon_path = "icons/logopacketswall.ico"
        if os.path.exists(original_app_icon_path):
            app.setWindowIcon(QIcon(original_app_icon_path))
    
    # Apply a style if desired (e.g., 'Fusion', 'Windows', 'WindowsVista')
    # app.setStyle('Fusion') 
    
    main_window = PacketsWallApp()
    main_window.show()
    sys.exit(app.exec_())

