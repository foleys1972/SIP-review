import sys
import json
import os
import re
import logging
import time
from queue import Queue
import csv
from datetime import datetime
from fpdf import FPDF
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QFileDialog, QTextEdit, QLabel, QGraphicsView, QGraphicsScene, 
                             QGraphicsRectItem, QSplitter, QGraphicsLineItem, QLineEdit, 
                             QTreeWidget, QTreeWidgetItem, QTabWidget, QProgressBar, 
                             QComboBox, QCheckBox, QGroupBox, QMainWindow, QStatusBar,
                             QMenu, QAction, QMessageBox, QGraphicsPolygonItem, QDialog, 
                             QInputDialog, QGraphicsTextItem, QGraphicsItemGroup, 
                             QGraphicsPixmapItem, QButtonGroup, QRadioButton, QSlider)
from PyQt5.QtCore import Qt, QRectF, QThread, pyqtSignal, QSize, QPointF, QUrl
from PyQt5.QtGui import QColor, QPen, QBrush, QFont, QIcon, QPolygonF, QPainter, QImage
from PyQt5.QtSvg import QSvgGenerator
from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent
from scapy.all import rdpcap, IP, TCP, UDP, RTP
import numpy as np
import wave
import tempfile

# Setting up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('sip_log_parser.log', mode='w')
    ]
)

CONFIG_FILE = 'highlight_config.json'
MAX_MSG_DISPLAY = 1000
current_call_flows = {}

SIP_METHODS = [
    "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", 
    "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", 
    "MESSAGE", "UPDATE"
]

sip_status_explanations = {
    "100": "Trying",
    "180": "Ringing",
    "181": "Call is Being Forwarded",
    "182": "Queued",
    "183": "Session Progress",
    "199": "Early Dialog Terminated",
    "200": "OK",
    "202": "Accepted",
    "204": "No Notification",
    "300": "Multiple Choices",
    "301": "Moved Permanently",
    "302": "Moved Temporarily",
    "305": "Use Proxy",
    "380": "Alternative Service",
    "400": "Bad Request",
    "401": "Unauthorized",
    "402": "Payment Required",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "406": "Not Acceptable",
    "407": "Proxy Authentication Required",
    "408": "Request Timeout",
    "409": "Conflict",
    "410": "Gone",
    "411": "Length Required",
    "412": "Conditional Request Failed",
    "413": "Request Entity Too Large",
    "414": "Request-URI Too Long",
    "415": "Unsupported Media Type",
    "416": "Unsupported URI Scheme",
    "417": "Unknown Resource-Priority",
    "420": "Bad Extension",
    "421": "Extension Required",
    "422": "Session Interval Too Small",
    "423": "Interval Too Brief",
    "424": "Bad Location Information",
    "425": "Bad Alert Message",
    "428": "Use Identity Header",
    "429": "Provide Referrer Identity",
    "430": "Flow Failed",
    "433": "Anonymity Disallowed",
    "436": "Bad Identity-Info",
    "437": "Unsupported Certificate",
    "438": "Invalid Identity Header",
    "439": "First Hop Lacks Outbound Support",
    "440": "Max-Breadth Exceeded",
    "469": "Bad Info",
    "470": "Consent Needed",
    "480": "Temporarily Unavailable",
    "481": "Call/Transaction Does Not Exist",
    "482": "Loop Detected",
    "483": "Too Many Hops",
    "484": "Address Incomplete",
    "485": "Ambiguous",
    "486": "Busy Here",
    "487": "Request Terminated",
    "488": "Not Acceptable Here",
    "489": "Bad Event",
    "491": "Request Pending",
    "493": "Undecipherable",
    "494": "Security Agreement Required",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "502": "Bad Gateway",
    "503": "Service Unavailable",
    "504": "Server Time-out",
    "505": "Version Not Supported",
    "513": "Message Too Large",
    "555": "Push Notification Service Not Supported",
    "580": "Precondition Failure",
    "600": "Busy Everywhere",
    "603": "Decline",
    "604": "Does Not Exist Anywhere",
    "606": "Not Acceptable",
    "607": "Unwanted",
    "608": "Rejected"
}

sip_issue_causes = {
    "100": [
        {"cause": "Normal provisional response", "details": "The server is processing the request but has not yet reached a final response. No action needed."},
        {"cause": "Delayed processing", "details": "Check server load or network latency if this response is unusually delayed."}
    ],
    "180": [
        {"cause": "Call is ringing", "details": "The destination is being alerted. Ensure the endpoint is reachable."},
        {"cause": "Delayed ringing", "details": "Check for network issues or endpoint configuration if ringing is not timely."}
    ],
    "183": [
        {"cause": "Session progress", "details": "Early media or session setup in progress. Verify media paths and codecs."},
        {"cause": "Media negotiation issue", "details": "Check SDP for codec mismatches or unsupported media types."}
    ],
    "200": [
        {"cause": "Successful request", "details": "The request was completed successfully. No issues detected."}
    ],
    "300": [
        {"cause": "Multiple choices", "details": "Multiple destinations are possible. Check routing configuration."},
        {"cause": "Ambiguous routing", "details": "Verify the SIP URI or routing rules in the proxy."}
    ],
    "301": [
        {"cause": "Moved permanently", "details": "The contact has changed permanently. Update the contact URI in the configuration."}
    ],
    "302": [
        {"cause": "Moved temporarily", "details": "The contact is temporarily unavailable. Check the temporary redirect configuration."}
    ],
    "400": [
        {"cause": "Bad request", "details": "The request is malformed. Verify the SIP message syntax and headers."},
        {"cause": "Invalid headers", "details": "Check for missing or incorrect headers like Call-ID or CSeq."}
    ],
    "401": [
        {"cause": "Unauthorized", "details": "Authentication required. Verify credentials or authentication configuration."},
        {"cause": "Incorrect credentials", "details": "Check username/password or digest authentication settings."}
    ],
    "403": [
        {"cause": "Forbidden", "details": "The server refuses the request. Check access policies or permissions."},
        {"cause": "Policy restriction", "details": "Verify server policies or ACLs restricting the request."}
    ],
    "404": [
        {"cause": "Not found", "details": "The requested resource or user is not found. Verify the SIP URI or destination."},
        {"cause": "Routing issue", "details": "Check routing tables or DNS resolution for the destination."}
    ],
    "408": [
        {"cause": "Request timeout", "details": "The server did not receive a response in time. Check network connectivity or server availability."},
        {"cause": "Endpoint unreachable", "details": "Verify the destination endpoint is online and reachable."}
    ],
    "480": [
        {"cause": "Temporarily unavailable", "details": "The endpoint is temporarily unavailable. Check endpoint status or registration."},
        {"cause": "Registration expired", "details": "Verify the endpoint's registration status with the registrar."}
    ],
    "486": [
        {"cause": "Busy here", "details": "The destination is busy. The user or endpoint is engaged in another call."},
        {"cause": "Resource limitation", "details": "Check if the endpoint has reached its call capacity."}
    ],
    "487": [
        {"cause": "Request terminated", "details": "The request was canceled or terminated. Check for CANCEL or BYE messages."},
        {"cause": "User action", "details": "The user may have ended the call prematurely."}
    ],
    "500": [
        {"cause": "Internal server error", "details": "The server encountered an unexpected issue. Check server logs for details."},
        {"cause": "Server misconfiguration", "details": "Verify server configuration and resource availability."}
    ],
    "503": [
        {"cause": "Service unavailable", "details": "The server is temporarily unable to process the request. Check server status or load."},
        {"cause": "Overloaded server", "details": "Reduce server load or scale resources."}
    ],
    "600": [
        {"cause": "Busy everywhere", "details": "All possible destinations are busy. Check endpoint availability."},
        {"cause": "System-wide issue", "details": "Verify system-wide resource availability or configuration."}
    ],
    "603": [
        {"cause": "Decline", "details": "The destination declined the call. The user or endpoint explicitly rejected the request."},
        {"cause": "User preference", "details": "Check user settings or Do Not Disturb configurations."}
    ],
    "604": [
        {"cause": "Does not exist anywhere", "details": "The requested resource does not exist. Verify the SIP URI or destination."},
        {"cause": "Configuration error", "details": "Check configuration for the requested resource."}
    ],
}

def load_config():
    default_config = {
        'highlight_codes': [],
        'recent_files': [],
        'sip_ports': [5060, 5061, 5062, 5063],
        'current_theme': 'light',
        'themes': {
            'light': {
                'good': [100, 200, 100],
                'info': [100, 150, 255],
                'amber': [255, 200, 0],
                'warning': [255, 170, 0],
                'bad': [255, 100, 100],
                'critical': [180, 0, 0],
                'method': [150, 150, 250],
                'unknown': [200, 200, 200],
                'background': [255, 255, 255]
            },
            'dark': {
                'good': [50, 150, 50],
                'info': [50, 100, 200],
                'amber': [200, 150, 0],
                'warning': [200, 120, 0],
                'bad': [200, 50, 50],
                'critical': [150, 0, 0],
                'method': [100, 100, 200],
                'unknown': [150, 150, 150],
                'background': [30, 30, 30]
            }
        },
        'hide_provisional': False
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                for key, value in default_config.items():
                    if key not in config:
                        logging.warning(f"Missing key '{key}' in config file. Using default value.")
                        config[key] = value
                if 'themes' not in config or not isinstance(config['themes'], dict):
                    logging.warning("Invalid or missing 'themes' in config file. Using default themes.")
                    config['themes'] = default_config['themes']
                if config.get('current_theme') not in config['themes']:
                    logging.warning(f"Invalid theme '{config.get('current_theme')}'. Defaulting to 'light'.")
                    config['current_theme'] = 'light'
                return config
        except (json.JSONDecodeError, Exception) as e:
            logging.error(f"Error loading {CONFIG_FILE}: {str(e)}. Using default config and saving to disk.")
            save_config(default_config)
            return default_config
    else:
        logging.info(f"No config file found at {CONFIG_FILE}. Creating with default config.")
        save_config(default_config)
        return default_config

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving config to {CONFIG_FILE}: {str(e)}")

def classify_sip_message(code):
    try:
        code_int = int(code)
        if 100 <= code_int < 200:
            return 'info', "Provisional response"
        elif 200 <= code_int < 300:
            return 'good', "Successful response"
        elif 300 <= code_int < 400:
            return 'amber', "Redirection response"
        elif 400 <= code_int < 500:
            return 'warning', "Client error response"
        elif 500 <= code_int < 600:
            return 'bad', "Server error response"
        elif 600 <= code_int < 700:
            return 'critical', "Global failure response"
        else:
            return 'unknown', "Unrecognized status code"
    except ValueError:
        return 'method', "SIP method"

def explain_sip_message_simple(code):
    return sip_status_explanations.get(code, "Unknown status")

def extract_sip_headers(payload_str):
    headers = {}
    header_patterns = {
        'call_id': r'Call-ID:\s*([^\r\n]+)',
        'from': r'From:\s*([^\r\n]+)',
        'to': r'To:\s*([^\r\n]+)',
        'via': r'Via:\s*([^\r\n]+)',
        'cseq': r'CSeq:\s*([^\r\n]+)',
        'contact': r'Contact:\s*([^\r\n]+)',
        'content_type': r'Content-Type:\s*([^\r\n]+)',
        'content_length': r'Content-Length:\s*(\d+)',
        'user_agent': r'User-Agent:\s*([^\r\n]+)'
    }
    for key, pattern in header_patterns.items():
        match = re.search(pattern, payload_str, re.IGNORECASE)
        if match:
            headers[key] = match.group(1).strip()
    # Extract SDP for RTP ports
    if 'm=audio' in payload_str:
        sdp_match = re.search(r'm=audio\s+(\d+)\s+RTP', payload_str, re.IGNORECASE)
        if sdp_match:
            headers['rtp_port'] = int(sdp_match.group(1))
    return headers

def is_sip_packet(packet, sip_ports):
    if not packet.haslayer(IP):
        return False
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        if udp_layer.sport in sip_ports or udp_layer.dport in sip_ports:
            return True
    elif packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.sport in sip_ports or tcp_layer.dport in sip_ports:
            return True
    return False

def extract_sip_info(payload_str):
    for method in SIP_METHODS:
        if payload_str.startswith(method):
            return method, None
    response_match = re.match(r'SIP/\d\.\d\s+(\d{3})\s+', payload_str)
    if response_match:
        return None, response_match.group(1)
    return None, None

def ulaw_to_linear(ulaw):
    """Convert G.711 µ-law byte to 16-bit linear PCM."""
    ulaw = ~ulaw  # Invert bits
    sign = (ulaw & 0x80) >> 7
    exponent = (ulaw & 0x70) >> 4
    mantissa = ulaw & 0x0F
    sample = mantissa | (16 if exponent else 0)
    sample = sample << (exponent + 3 if exponent else 2)
    sample += 33
    if sign:
        sample = -sample
    return sample

def rtp_to_wav(rtp_packets, output_file):
    """Convert RTP packets (G.711 PCMU) to WAV file."""
    audio_data = []
    for pkt in rtp_packets:
        if pkt.haslayer(RTP) and pkt[RTP].payload_type == 0:  # PCMU
            payload = bytes(pkt[RTP].payload)
            # Convert each µ-law byte to 16-bit linear PCM
            audio_data.extend([ulaw_to_linear(byte) for byte in payload])
    
    if not audio_data:
        return False
    
    # Convert to numpy array
    audio_array = np.array(audio_data, dtype=np.int16)
    
    # Write to WAV file
    with wave.open(output_file, 'wb') as wav_file:
        wav_file.setnchannels(1)  # Mono
        wav_file.setsampwidth(2)  # 16-bit
        wav_file.setframerate(8000)  # 8 kHz
        wav_file.writeframes(audio_array.tobytes())
    
    return True

class ParserThread(QThread):
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)
    
    def __init__(self, file_path, file_type, sip_ports):
        super().__init__()
        self.file_path = file_path
        self.file_type = file_type
        self.sip_ports = sip_ports
        self.rtp_streams = {}  # Store RTP packets per Call-ID
    
    def run(self):
        try:
            if self.file_type == 'pcap':
                result = self.parse_pcap(self.file_path)
            else:
                result = self.parse_text_file(self.file_path)
            self.finished_signal.emit(result)
        except Exception as e:
            logging.exception("Error in parser thread")
            self.status_signal.emit(f"Error: {str(e)}")
    
    def parse_pcap(self, file_path):
        self.status_signal.emit(f"Loading PCAP file: {os.path.basename(file_path)}...")
        try:
            packets = rdpcap(file_path)
        except Exception as e:
            logging.error(f"Error reading PCAP file: {str(e)}")
            self.status_signal.emit(f"Error reading PCAP file: {str(e)}")
            return {}
            
        total_packets = len(packets)
        self.status_signal.emit(f"Analyzing {total_packets} packets...")
        
        call_flows = {}
        processed = 0
        rtp_port_map = {}  # Map Call-ID to RTP ports
        
        for i, packet in enumerate(packets):
            if i % 100 == 0:
                self.progress_signal.emit(int(i / total_packets * 100))
                
            if is_sip_packet(packet, self.sip_ports):
                try:
                    if packet.haslayer(TCP):
                        payload = bytes(packet[TCP].payload)
                    else:
                        payload = bytes(packet[UDP].payload)
                        
                    if not payload:
                        continue
                        
                    payload_str = payload.decode("utf-8", errors="ignore")
                    if "SIP" not in payload_str:
                        continue
                        
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    timestamp = datetime.fromtimestamp(float(packet.time))
                    formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    method, code = extract_sip_info(payload_str)
                    headers = extract_sip_headers(payload_str)
                    call_id = headers.get('call_id', "Unknown")
                    
                    if 'rtp_port' in headers:
                        rtp_port_map.setdefault(call_id, set()).add(headers['rtp_port'])
                    
                    if code:
                        status, suggestion = classify_sip_message(code)
                        explanation = explain_sip_message_simple(code)
                        message_type = f"SIP {code}"
                    else:
                        status, suggestion = classify_sip_message(method)
                        explanation = method
                        message_type = method
                        code = method
                    
                    message = {
                        "timestamp": formatted_time,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "message_type": message_type,
                        "status_code": code,
                        "headers": headers,
                        "full_message": payload_str,
                        "status": status,
                        "explanation": explanation,
                        "annotation": ""
                    }
                    
                    if call_id not in call_flows:
                        call_flows[call_id] = []
                    
                    call_flows[call_id].append(message)
                    
                except Exception as e:
                    logging.error(f"Error processing packet {i}: {e}")
            
            # Check for RTP packets
            if packet.haslayer(UDP) and packet.haslayer(RTP):
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    # Find matching Call-ID based on RTP ports
                    for call_id, ports in rtp_port_map.items():
                        if src_port in ports or dst_port in ports:
                            self.rtp_streams.setdefault(call_id, []).append(packet)
                            break
                except Exception as e:
                    logging.error(f"Error processing RTP packet {i}: {e}")
            
            processed += 1
            
        self.progress_signal.emit(100)
        self.status_signal.emit(f"Completed! Found {len(call_flows)} SIP dialogs and {sum(len(p) for p in self.rtp_streams.values())} RTP packets.")
        return call_flows
    
    def parse_text_file(self, file_path):
        self.status_signal.emit(f"Loading text file: {os.path.basename(file_path)}...")
        call_flows = {}
        try:
            file_size = os.path.getsize(file_path)
            processed_size = 0
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            self.status_signal.emit("Analyzing SIP messages...")
            sip_messages = []
            response_matches = re.finditer(r'(SIP/\d\.\d\s+(\d{3}).*?)(?=\r\n\r\n|\n\n|$)', content, re.DOTALL)
            for match in response_matches:
                full_msg = match.group(1)
                code = match.group(2)
                sip_messages.append((full_msg, code, None))
                
            for method in SIP_METHODS:
                method_matches = re.finditer(f'({method}\\s+sip:.*?)(?=\\r\\n\\r\\n|\\n\\n|$)', content, re.DOTALL | re.IGNORECASE)
                for match in method_matches:
                    full_msg = match.group(1)
                    sip_messages.append((full_msg, None, method))
            
            total_messages = len(sip_messages)
            for i, (full_msg, code, method) in enumerate(sip_messages):
                try:
                    if i % 10 == 0:
                        self.progress_signal.emit(int(i / total_messages * 100) if total_messages else 100)
                    headers = extract_sip_headers(full_msg)
                    call_id = headers.get('call_id', "Unknown")
                    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', full_msg)
                    timestamp = timestamp_match.group(1) if timestamp_match else "Unknown Time"
                    
                    if code:
                        status, suggestion = classify_sip_message(code)
                        explanation = explain_sip_message_simple(code)
                        message_type = f"SIP {code}"
                    else:
                        status, suggestion = classify_sip_message(method)
                        explanation = method
                        message_type = method
                        code = method
                    
                    message = {
                        "timestamp": timestamp,
                        "message_type": message_type,
                        "status_code": code,
                        "headers": headers,
                        "full_message": full_msg.strip(),
                        "status": status,
                        "explanation": explanation,
                        "annotation": ""
                    }
                    
                    if call_id not in call_flows:
                        call_flows[call_id] = []
                    
                    call_flows[call_id].append(message)
                    
                except Exception as e:
                    logging.error(f"Error processing SIP message {i}: {e}")
            
            self.progress_signal.emit(100)
            self.status_signal.emit(f"Completed! Found {len(call_flows)} SIP dialogs.")
            
        except Exception as e:
            logging.exception(f"Error parsing text file: {e}")
            self.status_signal.emit(f"Error: {str(e)}")
            
        return call_flows

class CallFlowDiagram(QGraphicsView):
    message_selected = pyqtSignal(int)
    
    def __init__(self, parent=None, main_window=None):
        super().__init__(parent)
        self.main_window = main_window
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.node_width = 120
        self.node_height = 30
        self.horizontal_spacing = 180
        self.message_font = QFont("Arial", 8)
        self.timestamp_font = QFont("Arial", 6)
        self.seq_font = QFont("Arial", 7)
        self.colors = {}
        self.set_theme('light')
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.message_items = []
        self.selected_index = None
        self.hide_provisional = False
        self.annotation_icon = QGraphicsRectItem(0, 0, 8, 8)
        self.annotation_icon.setBrush(QBrush(QColor(255, 255, 0)))
        self.annotation_icon.setPen(QPen(Qt.NoPen))
        self.annotation_icon.setVisible(False)
        self.call_flow = None
    
    def set_theme(self, theme_name):
        config = load_config()
        default_theme = {
            'good': [100, 200, 100],
            'info': [100, 150, 255],
            'amber': [255, 200, 0],
            'warning': [255, 170, 0],
            'bad': [255, 100, 100],
            'critical': [180, 0, 0],
            'method': [150, 150, 250],
            'unknown': [200, 200, 200],
            'background': [255, 255, 255]
        }
        themes = config.get('themes', {'light': default_theme})
        theme = themes.get(theme_name, default_theme)
        self.colors = {k: QColor(*v) for k, v in theme.items() if k != 'background'}
        self.setBackgroundBrush(QBrush(QColor(*theme['background'])))
        
    def wheelEvent(self, event):
        zoomInFactor = 1.25
        zoomOutFactor = 1 / zoomInFactor
        oldPos = self.mapToScene(event.pos())
        if event.angleDelta().y() > 0:
            zoomFactor = zoomInFactor
        else:
            zoomFactor = zoomOutFactor
        self.scale(zoomFactor, zoomFactor)
        newPos = self.mapToScene(event.pos())
        delta = newPos - oldPos
        self.translate(delta.x(), delta.y())
        if self.main_window:
            self.main_window.status_bar.showMessage(f"Zoom: {self.transform().m11() * 100:.0f}%")
        
    def zoom_in(self):
        self.scale(1.25, 1.25)
        if self.main_window:
            self.main_window.status_bar.showMessage(f"Zoom: {self.transform().m11() * 100:.0f}%")
    
    def zoom_out(self):
        self.scale(0.8, 0.8)
        if self.main_window:
            self.main_window.status_bar.showMessage(f"Zoom: {self.transform().m11() * 100:.0f}%")
    
    def fit_to_view(self):
        self.fitInView(self.sceneRect(), Qt.KeepAspectRatio)
        if self.main_window:
            self.main_window.status_bar.showMessage(f"Zoom: {self.transform().m11() * 100:.0f}%")
    
    def mousePressEvent(self, event):
        if event.button() == Qt.RightButton:
            item = self.itemAt(event.pos())
            if item and hasattr(item, 'message_index'):
                self.show_context_menu(item.message_index, event.pos())
        elif event.button() == Qt.LeftButton:
            item = self.itemAt(event.pos())
            if item and hasattr(item, 'message_index'):
                self.message_selected.emit(item.message_index)
        super().mousePressEvent(event)
    
    def show_context_menu(self, msg_index, pos):
        menu = QMenu(self)
        annotate_action = QAction("Add/Edit Annotation", self)
        annotate_action.triggered.connect(lambda: self.add_annotation(msg_index))
        menu.addAction(annotate_action)
        if self.message_items[msg_index][0].message['annotation']:
            remove_action = QAction("Remove Annotation", self)
            remove_action.triggered.connect(lambda: self.remove_annotation(msg_index))
            menu.addAction(remove_action)
        menu.exec_(self.mapToGlobal(pos))
    
    def add_annotation(self, msg_index):
        text, ok = QInputDialog.getText(self, "Add Annotation", "Enter annotation:")
        if ok and text:
            self.message_items[msg_index][0].message['annotation'] = text
            self.update_annotations()
    
    def remove_annotation(self, msg_index):
        self.message_items[msg_index][0].message['annotation'] = ""
        self.update_annotations()
    
    def update_annotations(self):
        for group, _, _, _, _, annotation_icon in self.message_items:
            msg = group.message
            annotation_icon.setVisible(bool(msg['annotation']))
            annotation_icon.setToolTip(msg['annotation'] if msg['annotation'] else "")
    
    def display_call_flow(self, call_flow, selected_index=None):
        self.scene.clear()
        self.message_items = []
        self.selected_index = selected_index
        self.call_flow = call_flow
        
        if not call_flow:
            return
        
        filtered_flow = [msg for msg in call_flow if not self.hide_provisional or not msg['status_code'].startswith('1')]
        message_count = len(filtered_flow)
        self.vertical_spacing = max(60, min(100, 1500 / (message_count + 1)))
        
        ips = set()
        for msg in call_flow:
            if 'src_ip' in msg:
                ips.add(msg['src_ip'])
            if 'dst_ip' in msg:
                ips.add(msg['dst_ip'])
        if not ips:
            nodes = ["User Agent 1", "Proxy", "User Agent 2"]
        else:
            nodes = sorted(list(ips))
        
        node_x_positions = {}
        scene_width = 800
        for i, node in enumerate(nodes):
            x = i * self.horizontal_spacing + 150
            node_x_positions[node] = x
            label = QGraphicsTextItem(node)
            label.setPos(x - self.node_width/2, 20)
            label.setFont(QFont("Arial", 10))
            self.scene.addItem(label)
            line = QGraphicsLineItem(x, 60, x, message_count * self.vertical_spacing + 150)
            line.setPen(QPen(Qt.DashLine))
            self.scene.addItem(line)
            scene_width = max(scene_width, x + self.node_width)
        
        separator = QGraphicsLineItem(0, 60, scene_width, 60)
        separator.setPen(QPen(Qt.DashLine))
        self.scene.addItem(separator)
        
        y = 100
        for i, msg in enumerate(filtered_flow):
            src = msg.get('src_ip', nodes[0])
            dst = msg.get('dst_ip', nodes[-1])
            if src not in node_x_positions:
                src = nodes[0]
            if dst not in node_x_positions:
                dst = nodes[-1]
            x1 = node_x_positions.get(src, 150)
            x2 = node_x_positions.get(dst, 300)
            
            group = QGraphicsItemGroup()
            group.message = msg
            group.message_index = call_flow.index(msg)
            
            arrow = QGraphicsLineItem(x1, y, x2, y)
            color = self.colors.get(msg['status'], QColor(200, 200, 200))
            pen = QPen(color, 2)
            if i == selected_index:
                pen.setWidth(4)
                pen.setStyle(Qt.DashLine)
            arrow.setPen(pen)
            self.scene.addItem(arrow)
            
            arrow_size = 10
            if x1 < x2:
                points = [QPointF(x2 - arrow_size, y - arrow_size/2),
                         QPointF(x2, y),
                         QPointF(x2 - arrow_size, y + arrow_size/2)]
            else:
                points = [QPointF(x2 + arrow_size, y - arrow_size/2),
                         QPointF(x2, y),
                         QPointF(x2 + arrow_size, y + arrow_size/2)]
            arrowhead = QGraphicsPolygonItem(QPolygonF(points))
            arrowhead.setBrush(QBrush(color))
            arrowhead.setPen(QPen(color))
            self.scene.addItem(arrowhead)
            
            msg_label = f"{msg['status_code']} {msg['explanation']}"
            if len(msg_label) > 30:
                display_label = msg_label[:27] + "..."
            else:
                display_label = msg_label
            text = QGraphicsTextItem(display_label)
            text.setFont(self.message_font)
            text.setDefaultTextColor(QColor(0, 0, 0))
            text_width = text.boundingRect().width()
            text.setPos((x1 + x2) / 2 - text_width / 2, y - 25)
            bg_rect = QGraphicsRectItem(text.boundingRect().adjusted(-3, -3, 3, 3))
            bg_rect.setPos(text.pos())
            bg_rect.setBrush(QBrush(QColor(255, 255, 255, 200)))
            bg_rect.setPen(QPen(Qt.NoPen))
            self.scene.addItem(bg_rect)
            self.scene.addItem(text)
            text.setToolTip(msg_label)
            
            seq_text = QGraphicsTextItem(str(call_flow.index(msg) + 1))
            seq_text.setFont(self.seq_font)
            seq_width = seq_text.boundingRect().width()
            seq_text.setPos(10, y - 25)
            seq_bg = QGraphicsRectItem(seq_text.boundingRect().adjusted(-3, -3, 3, 3))
            seq_bg.setPos(seq_text.pos())
            seq_bg.setBrush(QBrush(QColor(255, 255, 255, 200)))
            seq_bg.setPen(QPen(Qt.NoPen))
            self.scene.addItem(seq_bg)
            self.scene.addItem(seq_text)
            
            annotation_icon = QGraphicsRectItem(0, 0, 8, 8)
            annotation_icon.setBrush(QBrush(QColor(255, 255, 0)))
            annotation_icon.setPen(QPen(Qt.NoPen))
            annotation_icon.setPos(text.pos().x() + text_width + 10, y - 25)
            annotation_icon.setVisible(bool(msg['annotation']))
            annotation_icon.setToolTip(msg['annotation'] if msg['annotation'] else "")
            self.scene.addItem(annotation_icon)
            
            group.addToGroup(arrow)
            group.addToGroup(arrowhead)
            group.addToGroup(text)
            group.addToGroup(bg_rect)
            group.addToGroup(seq_text)
            group.addToGroup(seq_bg)
            group.addToGroup(annotation_icon)
            group.message_index = call_flow.index(msg)
            self.scene.addItem(group)
            
            if 'timestamp' in msg:
                time_text = QGraphicsTextItem(msg['timestamp'])
                time_text.setFont(self.timestamp_font)
                time_text.setDefaultTextColor(QColor(100, 100, 100))
                time_width = time_text.boundingRect().width()
                time_text.setPos(scene_width - time_width - 10, y - 25)
                time_bg = QGraphicsRectItem(time_text.boundingRect().adjusted(-3, -3, 3, 3))
                time_bg.setPos(time_text.pos())
                time_bg.setBrush(QBrush(QColor(255, 255, 255, 200)))
                time_bg.setPen(QPen(Qt.NoPen))
                self.scene.addItem(time_bg)
                self.scene.addItem(time_text)
            
            self.message_items.append((group, arrow, arrowhead, text, bg_rect, annotation_icon))
            
            y += self.vertical_spacing
        
        self.scene.setSceneRect(self.scene.itemsBoundingRect())
    
    def highlight_message(self, index):
        self.selected_index = index
        if not self.call_flow:
            return
        for i, (group, arrow, arrowhead, text, bg_rect, annotation_icon) in enumerate(self.message_items):
            pen = arrow.pen()
            if index is None or self.call_flow.index(group.message) != index:
                pen.setWidth(2)
                pen.setStyle(Qt.SolidLine)
                text.setDefaultTextColor(QColor(0, 0, 0))
                bg_rect.setBrush(QBrush(QColor(255, 255, 255, 200)))
            else:
                pen.setWidth(4)
                pen.setStyle(Qt.DashLine)
                text.setDefaultTextColor(QColor(0, 0, 255))
                bg_rect.setBrush(QBrush(QColor(200, 200, 255, 200)))
            arrow.setPen(pen)
            arrowhead.setPen(pen)

class MessageDetailsWidget(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Courier", 10))
    
    def display_message(self, message):
        if not message:
            self.clear()
            return
        html = "<pre>"
        full_msg = message.get('full_message', '')
        lines = full_msg.split('\n')
        for line in lines:
            if ': ' in line:
                parts = line.split(': ', 1)
                html += f"<span style='color:blue;font-weight:bold;'>{parts[0]}</span>: {parts[1]}<br>"
            elif line.startswith('SIP') and len(line) > 10:
                html += f"<span style='color:green;font-weight:bold;'>{line}</span><br>"
            elif any(line.startswith(method) for method in SIP_METHODS):
                html += f"<span style='color:purple;font-weight:bold;'>{line}</span><br>"
            else:
                html += f"{line}<br>"
        if message.get('annotation'):
            html += f"<br><b>Annotation:</b> {message['annotation']}<br>"
        html += "</pre>"
        self.setHtml(html)

class SipAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.sip_ports = self.config.get('sip_ports', [5060, 5061, 5062, 5063])
        self.current_call_flows = {}
        self.rtp_streams = {}  # Store RTP packets per Call-ID
        self.audio_file = None  # Temporary WAV file for playback
        self.initUI()
        self.updateRecentFilesMenu()
        
    def initUI(self):
        self.setWindowTitle('SIP Log Analyzer')
        self.showMaximized()
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        self.setCentralWidget(central_widget)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_path_edit)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_button)
        main_layout.addLayout(file_layout)
        
        # Search/filter
        search_layout = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Call-ID", "Status Code", "Source IP", "Timestamp"])
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Enter search term...")
        self.search_edit.textChanged.connect(self.filter_calls)
        search_layout.addWidget(QLabel("Filter by:"))
        search_layout.addWidget(self.filter_combo)
        search_layout.addWidget(self.search_edit)
        main_layout.addLayout(search_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        main_splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(main_splitter)
        
        # Left panel: Call tree, message details, and reference panel
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        self.call_tree = QTreeWidget()
        self.call_tree.setHeaderLabels(["Call ID", "Messages", "Status"])
        self.call_tree.itemClicked.connect(self.on_call_selected)
        left_layout.addWidget(QLabel("SIP Dialogs:"))
        left_layout.addWidget(self.call_tree)
        left_layout.addWidget(QLabel("Message Details:"))
        self.message_details = MessageDetailsWidget()
        left_layout.addWidget(self.message_details)
        left_layout.addWidget(QLabel("Likely Causes:"))
        self.reference_panel = QTextEdit()
        self.reference_panel.setReadOnly(True)
        self.reference_panel.setFont(QFont("Arial", 10))
        left_layout.addWidget(self.reference_panel)
        main_splitter.addWidget(left_widget)
        
        # Right panel: Call flow diagram, audio player, and controls
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        self.call_flow_diagram = CallFlowDiagram(main_window=self)
        self.call_flow_diagram.message_selected.connect(self.on_diagram_message_selected)
        self.call_flow_diagram.set_theme(self.config.get('current_theme', 'light'))
        
        # Zoom controls
        zoom_layout = QHBoxLayout()
        zoom_in_btn = QPushButton("+")
        zoom_out_btn = QPushButton("-")
        fit_btn = QPushButton("Fit to View")
        zoom_in_btn.clicked.connect(self.call_flow_diagram.zoom_in)
        zoom_out_btn.clicked.connect(self.call_flow_diagram.zoom_out)
        fit_btn.clicked.connect(self.call_flow_diagram.fit_to_view)
        zoom_layout.addWidget(zoom_in_btn)
        zoom_layout.addWidget(zoom_out_btn)
        zoom_layout.addWidget(fit_btn)
        right_layout.addLayout(zoom_layout)
        
        # Toggle provisional responses
        self.provisional_cb = QCheckBox("Hide Provisional Responses (1xx)")
        self.provisional_cb.setChecked(self.config.get('hide_provisional', False))
        self.provisional_cb.stateChanged.connect(self.toggle_provisional)
        right_layout.addWidget(self.provisional_cb)
        
        # Audio player controls
        audio_layout = QHBoxLayout()
        self.play_btn = QPushButton("Play")
        self.play_btn.setEnabled(False)
        self.play_btn.clicked.connect(self.play_audio)
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.pause_audio)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_audio)
        self.volume_slider = QSlider(Qt.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(50)
        self.volume_slider.valueChanged.connect(self.set_volume)
        audio_layout.addWidget(QLabel("Audio Playback:"))
        audio_layout.addWidget(self.play_btn)
        audio_layout.addWidget(self.pause_btn)
        audio_layout.addWidget(self.stop_btn)
        audio_layout.addWidget(QLabel("Volume:"))
        audio_layout.addWidget(self.volume_slider)
        right_layout.addLayout(audio_layout)
        
        right_layout.addWidget(QLabel("Call Flow Diagram:"))
        right_layout.addWidget(self.call_flow_diagram)
        
        # Summary statistics
        self.stats_label = QLabel("No call selected")
        right_layout.addWidget(self.stats_label)
        
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([400, 800])
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Initialize media player
        self.media_player = QMediaPlayer()
        self.media_player.stateChanged.connect(self.on_media_state_changed)
        
        self.create_menus()
        
    def create_menus(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('&File')
        open_action = QAction('&Open', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self.browse_file)
        file_menu.addAction(open_action)
        self.recent_menu = file_menu.addMenu('Recent Files')
        file_menu.addSeparator()
        export_action = QAction('&Export Report', self)
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        export_csv_action = QAction('Export to &CSV', self)
        export_csv_action.triggered.connect(self.export_csv)
        file_menu.addAction(export_csv_action)
        export_diagram_action = QAction('Export &Diagram', self)
        export_diagram_action.triggered.connect(self.export_diagram)
        file_menu.addAction(export_diagram_action)
        file_menu.addSeparator()
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        settings_menu = menubar.addMenu('&Settings')
        ports_action = QAction('Configure SIP &Ports', self)
        ports_action.triggered.connect(self.configure_ports)
        settings_menu.addAction(ports_action)
        highlight_action = QAction('Configure &Highlights', self)
        highlight_action.triggered.connect(self.configure_highlights)
        settings_menu.addAction(highlight_action)
        theme_action = QAction('Configure &Theme', self)
        theme_action.triggered.connect(self.configure_theme)
        settings_menu.addAction(theme_action)
        
        help_menu = menubar.addMenu('&Help')
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def updateRecentFilesMenu(self):
        self.recent_menu.clear()
        recent_files = self.config.get('recent_files', [])
        for file_path in recent_files:
            if os.path.exists(file_path):
                action = QAction(os.path.basename(file_path), self)
                action.setData(file_path)
                action.triggered.connect(self.open_recent_file)
                self.recent_menu.addAction(action)
    
    def open_recent_file(self):
        action = self.sender()
        if action:
            file_path = action.data()
            self.load_file(file_path)
    
    def add_recent_file(self, file_path):
        recent_files = self.config.get('recent_files', [])
        if file_path in recent_files:
            recent_files.remove(file_path)
        recent_files.insert(0, file_path)
        if len(recent_files) > 10:
            recent_files = recent_files[:10]
        self.config['recent_files'] = recent_files
        save_config(self.config)
        self.updateRecentFilesMenu()
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Open SIP Log File", 
            "", 
            "All Files (*);;PCAP Files (*.pcap *.pcapng);;Text Files (*.txt *.log)"
        )
        if file_path:
            self.load_file(file_path)
    
    def load_file(self, file_path):
        self.file_path_edit.setText(file_path)
        self.status_bar.showMessage(f"Loading file: {os.path.basename(file_path)}...")
        file_ext = os.path.splitext(file_path)[1].lower()
        file_type = 'pcap' if file_ext in ['.pcap', '.pcapng'] else 'text'
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.parser_thread = ParserThread(file_path, file_type, self.sip_ports)
        self.parser_thread.progress_signal.connect(self.update_progress)
        self.parser_thread.status_signal.connect(self.update_status)
        self.parser_thread.finished_signal.connect(self.display_call_flows)
        self.parser_thread.start()
        self.add_recent_file(file_path)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_status(self, message):
        self.status_bar.showMessage(message)
    
    def toggle_provisional(self):
        self.config['hide_provisional'] = self.provisional_cb.isChecked()
        save_config(self.config)
        self.call_flow_diagram.hide_provisional = self.config['hide_provisional']
        current_item = self.call_tree.currentItem()
        if current_item:
            self.on_call_selected(current_item, 0)
    
    def extract_audio(self, call_id):
        """Extract RTP audio for the given Call-ID and save to a temporary WAV file."""
        rtp_packets = self.rtp_streams.get(call_id, [])
        if not rtp_packets:
            return False
        
        # Create a temporary WAV file
        if self.audio_file:
            try:
                os.remove(self.audio_file)
            except:
                pass
        self.audio_file = tempfile.NamedTemporaryFile(suffix=".wav", delete=False).name
        
        # Convert RTP to WAV
        success = rtp_to_wav(rtp_packets, self.audio_file)
        return success
    
    def play_audio(self):
        if self.audio_file and os.path.exists(self.audio_file):
            self.media_player.setMedia(QMediaContent(QUrl.fromLocalFile(self.audio_file)))
            self.media_player.play()
    
    def pause_audio(self):
        self.media_player.pause()
    
    def stop_audio(self):
        self.media_player.stop()
    
    def set_volume(self, value):
        self.media_player.setVolume(value)
    
    def on_media_state_changed(self, state):
        self.play_btn.setEnabled(state != QMediaPlayer.PlayingState)
        self.pause_btn.setEnabled(state == QMediaPlayer.PlayingState)
        self.stop_btn.setEnabled(state != QMediaPlayer.StoppedState)
    
    def display_call_flows(self, call_flows):
        self.current_call_flows = call_flows
        self.rtp_streams = getattr(self.parser_thread, 'rtp_streams', {})
        self.progress_bar.setVisible(False)
        self.call_tree.clear()
        
        if not call_flows:
            self.status_bar.showMessage("No SIP dialogs found in the file.")
            return
            
        for call_id, messages in call_flows.items():
            overall_status = "good"
            for msg in messages:
                if msg['status'] in ['bad', 'critical']:
                    overall_status = "bad"
                    break
                elif msg['status'] in ['warning', 'amber'] and overall_status != "bad":
                    overall_status = "warning"
            
            item = QTreeWidgetItem([
                call_id[:40] + "..." if len(call_id) > 40 else call_id,
                str(len(messages)),
                ""
            ])
            status_color = QColor(100, 200, 100)
            if overall_status == "bad":
                status_color = QColor(255, 100, 100)
            elif overall_status == "warning":
                status_color = QColor(255, 200, 0)
            item.setBackground(2, QBrush(status_color))
            
            for i, msg in enumerate(messages):
                code = msg['status_code']
                message_type = msg['message_type']
                child = QTreeWidgetItem([
                    f"{i+1}. {message_type}",
                    msg.get('timestamp', ''),
                    ""
                ])
                msg_color = self.call_flow_diagram.colors.get(msg['status'], QColor(200, 200, 200))
                child.setBackground(2, QBrush(msg_color))
                child.setData(0, Qt.UserRole, i)
                item.addChild(child)
            
            self.call_tree.addTopLevelItem(item)
        
        if self.call_tree.topLevelItemCount() > 0:
            self.call_tree.topLevelItem(0).setExpanded(True)
            self.call_tree.setCurrentItem(self.call_tree.topLevelItem(0))
            self.on_call_selected(self.call_tree.topLevelItem(0), 0)
            
        self.status_bar.showMessage(f"Loaded {len(call_flows)} SIP dialogs.")
        self.filter_calls()
    
    def filter_calls(self):
        search_text = self.search_edit.text().lower()
        filter_type = self.filter_combo.currentText()
        
        for i in range(self.call_tree.topLevelItemCount()):
            item = self.call_tree.topLevelItem(i)
            call_id = list(self.current_call_flows.keys())[i]
            messages = self.current_call_flows[call_id]
            visible = False

            if not search_text:
                visible = True
            else:
                if filter_type == "Call-ID":
                    visible = search_text in call_id.lower()
                elif filter_type == "Status Code":
                    visible = any(search_text in msg['status_code'].lower() for msg in messages)
                elif filter_type == "Source IP":
                    visible = any(search_text in msg.get('src_ip', '').lower() for msg in messages)
                elif filter_type == "Timestamp":
                    visible = any(search_text in msg.get('timestamp', '').lower() for msg in messages)

            item.setHidden(not visible)
    
    def on_call_selected(self, item, column=0):
        if item.parent():
            call_item = item.parent()
            call_id = call_item.text(0)
            if "..." in call_id:
                call_id = list(self.current_call_flows.keys())[self.call_tree.indexOfTopLevelItem(call_item)]
            msg_index = item.data(0, Qt.UserRole)
            messages = self.current_call_flows.get(call_id, [])
            if 0 <= msg_index < len(messages):
                self.message_details.display_message(messages[msg_index])
                # Populate reference panel
                status_code = messages[msg_index]['status_code']
                causes = sip_issue_causes.get(status_code, [{"cause": "Unknown", "details": "No causes available for this status code."}])
                html = "<h3>Likely Causes for {} ({})</h3><ul>".format(
                    status_code, sip_status_explanations.get(status_code, "Unknown")
                )
                for cause in causes:
                    html += f"<li><b>{cause['cause']}</b>: {cause['details']}</li>"
                html += "</ul>"
                self.reference_panel.setHtml(html)
            self.call_flow_diagram.display_call_flow(messages, selected_index=msg_index)
            self.call_flow_diagram.highlight_message(msg_index)
            error_count = sum(1 for msg in messages if msg['status_code'].isdigit() and int(msg['status_code']) >= 400)
            timestamps = [msg.get('timestamp') for msg in messages if msg.get('timestamp')]
            duration = "N/A"
            if len(timestamps) >= 2:
                try:
                    t_start = datetime.strptime(timestamps[0], '%Y-%m-%d %H:%M:%S.%f')
                    t_end = datetime.strptime(timestamps[-1], '%Y-%m-%d %H:%M:%S.%f')
                    duration = str(t_end - t_start)
                except ValueError:
                    pass
            self.stats_label.setText(f"Messages: {len(messages)} | Errors: {error_count} | Duration: {duration}")
        else:
            call_id = item.text(0)
            if "..." in call_id:
                call_id = list(self.current_call_flows.keys())[self.call_tree.indexOfTopLevelItem(item)]
            messages = self.current_call_flows.get(call_id, [])
            self.call_flow_diagram.display_call_flow(messages, selected_index=None)
            self.call_flow_diagram.highlight_message(None)
            self.message_details.clear()
            self.reference_panel.setHtml("<h3>No Message Selected</h3><p>Select a message to view likely causes.</p>")
            self.stats_label.setText("Select a message for stats")
            
            # Extract and prepare audio for the selected call
            self.stop_audio()
            if self.extract_audio(call_id):
                self.play_btn.setEnabled(True)
                self.status_bar.showMessage("Audio extracted for playback.")
            else:
                self.play_btn.setEnabled(False)
                self.pause_btn.setEnabled(False)
                self.stop_btn.setEnabled(False)
                self.status_bar.showMessage("No audio available for this call.")
    
    def on_diagram_message_selected(self, msg_index):
        current_item = self.call_tree.currentItem()
        if current_item and current_item.parent():
            call_item = current_item.parent()
        else:
            call_item = current_item
        if call_item:
            call_id = call_item.text(0)
            if "..." in call_id:
                call_id = list(self.current_call_flows.keys())[self.call_tree.indexOfTopLevelItem(call_item)]
            for i in range(call_item.childCount()):
                child = call_item.child(i)
                if child.data(0, Qt.UserRole) == msg_index:
                    self.call_tree.setCurrentItem(child)
                    self.on_call_selected(child, 0)
                    break
    
    def export_report(self):
        if not self.current_call_flows:
            QMessageBox.warning(self, "No Data", "There is no call flow data to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save PDF Report", "", "PDF Files (*.pdf)")
        if not file_path:
            return
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "SIP Call Flow Analysis Report", 0, 1, "C")
            pdf.set_font("Arial", "", 12)
            pdf.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
            pdf.ln(10)
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "File Information", 0, 1)
            pdf.set_font("Arial", "", 12)
            pdf.cell(0, 10, f"File: {self.file_path_edit.text()}", 0, 1)
            pdf.cell(0, 10, f"Total SIP Dialogs: {len(self.current_call_flows)}", 0, 1)
            pdf.ln(10)
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "SIP Dialog Details", 0, 1)
            for call_id, messages in self.current_call_flows.items():
                pdf.ln(5)
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, f"Call ID: {call_id}", 0, 1)
                pdf.set_font("Arial", "", 12)
                pdf.cell(0, 10, f"Total Messages: {len(messages)}", 0, 1)
                pdf.ln(5)
                pdf.set_font("Arial", "B", 10)
                pdf.cell(20, 10, "Seq", 1, 0, "C")
                pdf.cell(40, 10, "Time", 1, 0, "C")
                pdf.cell(60, 10, "Type", 1, 0, "C")
                pdf.cell(70, 10, "Status", 1, 0, "C")
                pdf.cell(50, 10, "Annotation", 1, 1, "C")
                pdf.set_font("Arial", "", 10)
                for i, msg in enumerate(messages):
                    pdf.cell(20, 10, str(i+1), 1, 0, "C")
                    pdf.cell(40, 10, msg.get('timestamp', 'N/A')[:20], 1, 0, "L")
                    pdf.cell(60, 10, str(msg['message_type'])[:20], 1, 0, "L")
                    pdf.cell(70, 10, f"{msg['status']} - {msg['explanation']}"[:30], 1, 0, "L")
                    pdf.cell(50, 10, msg.get('annotation', '')[:20], 1, 1, "L")
                    if pdf.get_y() > 250:
                        pdf.add_page()
            pdf.output(file_path)
            self.status_bar.showMessage(f"Report exported to {os.path.basename(file_path)}")
            reply = QMessageBox.question(
                self, 
                "PDF Created", 
                "PDF report was created successfully. Do you want to open it now?",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                import webbrowser
                webbrowser.open(file_path)
        except Exception as e:
            logging.exception("Error exporting PDF report")
            QMessageBox.critical(self, "Error", f"Failed to create PDF report: {str(e)}")
    
    def export_csv(self):
        if not self.current_call_flows:
            QMessageBox.warning(self, "No Data", "There is no call flow data to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv)")
        if not file_path:
            return
        try:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Call ID', 'Sequence', 'Timestamp', 'Message Type', 'Status Code', 
                                'Status', 'Explanation', 'From', 'To', 'Annotation'])
                for call_id, messages in self.current_call_flows.items():
                    for i, msg in enumerate(messages):
                        writer.writerow([
                            call_id,
                            i+1,
                            msg.get('timestamp', 'N/A'),
                            msg['message_type'],
                            msg['status_code'],
                            msg['status'],
                            msg['explanation'],
                            msg.get('headers', {}).get('from', 'N/A'),
                            msg.get('headers', {}).get('to', 'N/A'),
                            msg.get('annotation', '')
                        ])
            self.status_bar.showMessage(f"Data exported to {os.path.basename(file_path)}")
        except Exception as e:
            logging.exception("Error exporting CSV file")
            QMessageBox.critical(self, "Error", f"Failed to create CSV file: {str(e)}")
    
    def export_diagram(self):
        if not self.current_call_flows:
            QMessageBox.warning(self, "No Data", "There is no call flow diagram to export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Diagram", "", "PNG Files (*.png);;SVG Files (*.svg)")
        if file_path:
            try:
                if file_path.endswith('.png'):
                    image = QImage(self.call_flow_diagram.sceneRect().size().toSize(), QImage.Format_ARGB32)
                    image.fill(Qt.white)
                    painter = QPainter(image)
                    self.call_flow_diagram.scene().render(painter)
                    painter.end()
                    image.save(file_path)
                else:
                    generator = QSvgGenerator()
                    generator.setFileName(file_path)
                    generator.setSize(self.call_flow_diagram.sceneRect().size().toSize())
                    painter = QPainter(generator)
                    self.call_flow_diagram.scene().render(painter)
                    painter.end()
                self.status_bar.showMessage(f"Diagram exported to {os.path.basename(file_path)}")
            except Exception as e:
                logging.exception("Error exporting diagram")
                QMessageBox.critical(self, "Error", f"Failed to export diagram: {str(e)}")
    
    def configure_ports(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Configure SIP Ports")
        layout = QVBoxLayout(dialog)
        ports_layout = QVBoxLayout()
        port_edits = []
        current_ports = self.config.get('sip_ports', self.sip_ports)
        for port in current_ports:
            port_edit = QLineEdit(str(port))
            port_edit.setValidator(QIntValidator(1, 65535))
            port_edits.append(port_edit)
            ports_layout.addWidget(port_edit)
        add_button = QPushButton("Add Port")
        def add_port():
            port_edit = QLineEdit("5060")
            port_edit.setValidator(QIntValidator(1, 65535))
            port_edits.append(port_edit)
            ports_layout.addWidget(port_edit)
            port_edit.show()
        add_button.clicked.connect(add_port)
        group_box = QGroupBox("SIP Ports")
        group_box.setLayout(ports_layout)
        layout.addWidget(group_box)
        layout.addWidget(add_button)
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        
        if dialog.exec_() == QDialog.Accepted:
            new_ports = []
            for edit in port_edits:
                try:
                    port = int(edit.text())
                    if 1 <= port <= 65535 and port not in new_ports:
                        new_ports.append(port)
                except ValueError:
                    pass
            if not new_ports:
                QMessageBox.warning(self, "Invalid Ports", "No valid ports provided. Reverting to default.")
                new_ports = [5060]
            self.config['sip_ports'] = new_ports
            self.sip_ports = new_ports
            save_config(self.config)
            self.status_bar.showMessage(f"SIP ports updated: {', '.join(map(str, new_ports))}")
    
    def configure_highlights(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Configure Highlights")
        layout = QVBoxLayout(dialog)
        grid_layout = QGridLayout()
        checkboxes = {}
        current_highlights = self.config.get('highlight_codes', [])
        common_codes = ['100', '180', '183', '200', '400', '401', '403', '404', '486', '487', '500', '503', '603', '604']
        row, col = 0, 0
        for code in common_codes:
            cb = QCheckBox(f"{code} - {sip_status_explanations.get(code, 'Unknown')}")
            cb.setChecked(code in current_highlights)
            checkboxes[code] = cb
            grid_layout.addWidget(cb, row, col)
            col += 1
            if col > 2:
                col = 0
                row += 1
        custom_layout = QHBoxLayout()
        custom_layout.addWidget(QLabel("Add custom code:"))
        custom_edit = QLineEdit()
        custom_edit.setValidator(QIntValidator(100, 699))
        custom_layout.addWidget(custom_edit)
        add_button = QPushButton("Add")
        def add_custom_code():
            code = custom_edit.text()
            if code and code not in checkboxes:
                cb = QCheckBox(f"{code} - {sip_status_explanations.get(code, 'Unknown')}")
                cb.setChecked(True)
                checkboxes[code] = cb
                grid_layout.addWidget(cb, row, col)
                custom_edit.clear()
        add_button.clicked.connect(add_custom_code)
        custom_layout.addWidget(add_button)
        group_box = QGroupBox("SIP Status Codes to Highlight")
        group_box.setLayout(grid_layout)
        layout.addWidget(group_box)
        layout.addLayout(custom_layout)
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        if dialog.exec_() == QDialog.Accepted:
            highlight_codes = []
            for code, cb in checkboxes.items():
                if cb.isChecked():
                    highlight_codes.append(code)
            self.config['highlight_codes'] = highlight_codes
            save_config(self.config)
            self.status_bar.showMessage(f"Highlight settings updated")
    
    def configure_theme(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Configure Diagram Theme")
        layout = QVBoxLayout(dialog)
        group = QButtonGroup(dialog)
        current_theme = self.config.get('current_theme', 'light')
        for theme in self.config.get('themes', {'light': {}}):
            rb = QRadioButton(theme.capitalize())
            rb.setChecked(theme == current_theme)
            group.addButton(rb)
            layout.addWidget(rb)
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)
        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        
        if dialog.exec_() == QDialog.Accepted:
            selected_theme = group.checkedButton().text().lower()
            self.config['current_theme'] = selected_theme
            save_config(self.config)
            self.call_flow_diagram.set_theme(selected_theme)
            current_item = self.call_tree.currentItem()
            if current_item:
                self.on_call_selected(current_item, 0)
            self.status_bar.showMessage(f"Theme set to {selected_theme}")
    
    def show_about(self):
        QMessageBox.about(
            self, 
            "About SIP Log Analyzer",
            "SIP Log Analyzer\nVersion 5.0\n\nA tool for analyzing SIP logs, visualizing call flows, and playing call audio.\n\nDeveloped with PyQt5, Scapy, and NumPy.\n\n© 2025"
        )

def main():
    app = QApplication(sys.argv)
    main_window = SipAnalyzerApp()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()