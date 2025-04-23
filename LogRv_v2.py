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
                             QMenu, QAction, QMessageBox, QGraphicsPolygonItem, QDialog, QInputDialog)
from PyQt5.QtCore import Qt, QRectF, QThread, pyqtSignal, QSize, QPointF
from PyQt5.QtGui import QColor, QPen, QBrush, QFont, QIcon, QPolygonF, QPainter
from scapy.all import rdpcap, IP, TCP, UDP

# Setting up full logging to log both to the console and a log file
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

# Common SIP ports moved to config
SIP_METHODS = [
    "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", 
    "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", 
    "MESSAGE", "UPDATE"
]

# Mapping of SIP Status Codes to Simple Descriptions
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

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Error decoding {CONFIG_FILE}. Using default config.")
            return {'highlight_codes': [], 'recent_files': [], 'sip_ports': [5060, 5061, 5062, 5063]}
    return {'highlight_codes': [], 'recent_files': [], 'sip_ports': [5060, 5061, 5062, 5063]}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

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

class ParserThread(QThread):
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)
    
    def __init__(self, file_path, file_type, sip_ports):
        super().__init__()
        self.file_path = file_path
        self.file_type = file_type
        self.sip_ports = sip_ports
        
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
            logging.error(f"Error reading PCAP file: {e}")
            self.status_signal.emit(f"Error reading PCAP file: {str(e)}")
            return {}
            
        total_packets = len(packets)
        self.status_signal.emit(f"Analyzing {total_packets} packets...")
        
        call_flows = {}
        processed = 0
        
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
                        "explanation": explanation
                    }
                    
                    if call_id not in call_flows:
                        call_flows[call_id] = []
                    
                    call_flows[call_id].append(message)
                    
                except Exception as e:
                    logging.error(f"Error processing packet {i}: {e}")
            
            processed += 1
            
        self.progress_signal.emit(100)
        self.status_signal.emit(f"Completed! Found {len(call_flows)} SIP dialogs.")
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
                method_matches = re.finditer(f'({method}\\s+sip:.*?)(?=\r\n\r\n|\n\n|$)', content, re.DOTALL | re.IGNORECASE)
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
                        "explanation": explanation
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
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.node_width = 120
        self.node_height = 30
        self.vertical_spacing = 40
        self.horizontal_spacing = 180
        self.message_font = QFont("Arial", 9)
        self.colors = {
            'good': QColor(100, 200, 100),
            'info': QColor(100, 150, 255),
            'amber': QColor(255, 200, 0),
            'warning': QColor(255, 170, 0),
            'bad': QColor(255, 100, 100),
            'critical': QColor(180, 0, 0),
            'method': QColor(150, 150, 250),
            'unknown': QColor(200, 200, 200)
        }
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        
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
        
    def display_call_flow(self, call_flow):
        self.scene.clear()
        if not call_flow:
            return
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
        for i, node in enumerate(nodes):
            x = i * self.horizontal_spacing + 50
            node_x_positions[node] = x
            label = self.scene.addText(node)
            label.setPos(x - self.node_width/2, 10)
            line = QGraphicsLineItem(x, 50, x, len(call_flow) * self.vertical_spacing + 100)
            line.setPen(QPen(Qt.DashLine))
            self.scene.addItem(line)
        y = 50
        for i, msg in enumerate(call_flow):
            src = msg.get('src_ip', nodes[0])
            dst = msg.get('dst_ip', nodes[-1])
            if src not in node_x_positions:
                src = nodes[0]
            if dst not in node_x_positions:
                dst = nodes[-1]
            x1 = node_x_positions.get(src, 50)
            x2 = node_x_positions.get(dst, 200)
            arrow = QGraphicsLineItem(x1, y, x2, y)
            color = self.colors.get(msg['status'], QColor(0, 0, 0))
            arrow.setPen(QPen(color, 2))
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
            text = self.scene.addText(msg_label, self.message_font)
            text.setPos((x1 + x2) / 2 - text.boundingRect().width() / 2, y - 20)
            if 'timestamp' in msg:
                time_text = self.scene.addText(msg['timestamp'], QFont("Arial", 7))
                time_text.setPos(10, y - 10)
            y += self.vertical_spacing
        self.scene.setSceneRect(self.scene.itemsBoundingRect())
        
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
        html += "</pre>"
        self.setHtml(html)

class SipAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = load_config()  # NEW: Load config early
        self.sip_ports = self.config.get('sip_ports', [5060, 5061, 5062, 5063])  # NEW: Initialize sip_ports
        self.current_call_flows = {}
        self.initUI()
        self.updateRecentFilesMenu()
        
    def initUI(self):
        self.setWindowTitle('SIP Log Analyzer')
        self.setGeometry(100, 100, 1200, 800)
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        self.setCentralWidget(central_widget)
        
        # File controls
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_path_edit)
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_button)
        main_layout.addLayout(file_layout)
        
        # NEW: Search and filter controls
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
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Main splitter
        main_splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(main_splitter)
        
        # Left side
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
        main_splitter.addWidget(left_widget)
        
        # Right side
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.addWidget(QLabel("Call Flow Diagram:"))
        self.call_flow_diagram = CallFlowDiagram()
        right_layout.addWidget(self.call_flow_diagram)
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([400, 800])
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create menu bar
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
        self.parser_thread = ParserThread(file_path, file_type, self.sip_ports)  # MODIFIED: Pass sip_ports
        self.parser_thread.progress_signal.connect(self.update_progress)
        self.parser_thread.status_signal.connect(self.update_status)
        self.parser_thread.finished_signal.connect(self.display_call_flows)
        self.parser_thread.start()
        self.add_recent_file(file_path)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_status(self, message):
        self.status_bar.showMessage(message)
    
    def display_call_flows(self, call_flows):
        self.current_call_flows = call_flows
        self.progress_bar.setVisible(False)
        self.call_tree.clear()
        
        if not call_flows:
            self.status_bar.showMessage("No SIP dialogs found in the file.")
            return
            
        # NEW: Track transactions and identify failures
        transactions = track_transactions(call_flows)
        failures = identify_failed_transactions(transactions)
        
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
            
            # NEW: Highlight failed transactions
            if call_id in failures and failures[call_id]:
                item.setBackground(0, QBrush(QColor(255, 200, 200)))  # Light red for failed transactions
                item.setText(0, f"{item.text(0)} [Failed Tx]")
            
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
        self.filter_calls()  # NEW: Apply any existing search filter
    
    # NEW: Filter calls based on search input
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
            self.call_flow_diagram.display_call_flow(messages)
        else:
            call_id = item.text(0)
            if "..." in call_id:
                call_id = list(self.current_call_flows.keys())[self.call_tree.indexOfTopLevelItem(item)]
            messages = self.current_call_flows.get(call_id, [])
            self.call_flow_diagram.display_call_flow(messages)
            self.message_details.clear()
    
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
                pdf.cell(70, 10, "Status", 1, 1, "C")
                pdf.set_font("Arial", "", 10)
                for i, msg in enumerate(messages):
                    pdf.cell(20, 10, str(i+1), 1, 0, "C")
                    pdf.cell(40, 10, msg.get('timestamp', 'N/A')[:20], 1, 0, "L")
                    pdf.cell(60, 10, str(msg['message_type'])[:20], 1, 0, "L")
                    pdf.cell(70, 10, f"{msg['status']} - {msg['explanation']}"[:30], 1, 1, "L")
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
                                'Status', 'Explanation', 'From', 'To'])
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
                            msg.get('headers', {}).get('to', 'N/A')
                        ])
            self.status_bar.showMessage(f"Data exported to {os.path.basename(file_path)}")
        except Exception as e:
            logging.exception("Error exporting CSV file")
            QMessageBox.critical(self, "Error", f"Failed to create CSV file: {str(e)}")
    
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
            # NEW: Validate ports
            if not new_ports:
                QMessageBox.warning(self, "Invalid Ports", "No valid ports provided. Reverting to default.")
                new_ports = [5060]
            self.config['sip_ports'] = new_ports
            self.sip_ports = new_ports  # MODIFIED: Update instance variable
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
    
    def show_about(self):
        QMessageBox.about(
            self, 
            "About SIP Log Analyzer",
            """<h1>SIP Log Analyzer</h1>
            <p>Version 2.0</p>
            <p>A tool for analyzing SIP packet captures and log files.</p>
            <p>Features:</p>
            <ul>
            <li>PCAP file analysis using Scapy</li>
            <li>Text log file parsing</li>
            <li>Call flow visualization</li>
            <li>SIP message detail viewing</li>
            <li>CSV and PDF export</li>
            </ul>
            """
        )

# Additional utility functions for transaction tracking
def extract_transaction_id(msg):
    cseq = msg.get('headers', {}).get('cseq', '')
    if cseq:
        parts = cseq.split()
        if len(parts) >= 2:
            seq_num = parts[0]
            method = parts[1]
            return f"{seq_num}-{method}"
    return None

def track_transactions(call_flows):
    transactions = {}
    for call_id, messages in call_flows.items():
        transactions[call_id] = {}
        for msg in messages:
            trans_id = extract_transaction_id(msg)
            if trans_id:
                if trans_id not in transactions[call_id]:
                    transactions[call_id][trans_id] = []
                transactions[call_id][trans_id].append(msg)
    return transactions

def identify_failed_transactions(transactions):
    failures = {}
    for call_id, trans in transactions.items():
        failures[call_id] = []
        for trans_id, messages in trans.items():
            has_error = False
            final_status = None
            for msg in messages:
                code = msg.get('status_code')
                if code and code.isdigit():
                    code_int = int(code)
                    if 400 <= code_int:
                        has_error = True
                        final_status = code
            if has_error:
                failures[call_id].append({
                    'transaction': trans_id,
                    'status': final_status,
                    'messages': messages
                })
    return failures

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    main_window = SipAnalyzerApp()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()