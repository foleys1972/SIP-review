import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import io
import wave
import os
import numpy as np
import tempfile

# Initialize pygame mixer for audio playback
try:
    import pygame
    pygame.mixer.init()
except ImportError:
    print("Warning: pygame not installed. Audio playback will be disabled.")

# Try to import packet capture libraries
try:
    import pyshark
except ImportError:
    print("Warning: pyshark not installed. Please install with: pip install pyshark")
    pyshark = None

try:
    from scapy.all import rdpcap, wrpcap, sniff, RTP, get_if_list, Raw
except ImportError:
    print("Warning: scapy not installed. Please install with: pip install scapy")
    rdpcap = None
    wrpcap = None
    sniff = None
    RTP = None
    get_if_list = None
    Raw = None

class PacketAnalyzer(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Packet Analyzer")
        self.geometry("1400x900")

        # Initialize state
        self.is_capturing = False
        self.live_capture = None
        self.sip_calls = {}
        self.rtp_streams = {}
        self.packets = []
        self.audio_temp_files = {}
        self.selected_packet_index = None
        self.current_zoom = 1.0  # For SIP call flow zooming
        self.current_call_id = None

        # Create UI components
        self.create_menu()
        self.create_main_content()
        self.create_status_bar()

    def create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP", command=self.open_pcap_file)
        file_menu.add_command(label="Start Live Capture", command=self.start_live_capture)
        file_menu.add_command(label="Stop Live Capture", command=self.stop_live_capture, state=tk.DISABLED)
        file_menu.add_command(label="Save Live Capture", command=self.save_live_capture, state=tk.DISABLED)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)

        analysis_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Show Protocol Distribution", command=self.show_protocol_distribution)

        tools_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Find in Packets", command=self.show_find_dialog)
        tools_menu.add_command(label="Highlight Issues", command=self.highlight_pcap_issues)

        self.bind("<Control-p>", lambda e: self.open_pcap_file())

    def enable_stop_capture_menu(self):
        menu_bar = self.nametowidget(self['menu'])
        file_menu = menu_bar.winfo_children()[0]
        file_menu.entryconfig("Stop Live Capture", state="normal")
        file_menu.entryconfig("Save Live Capture", state="normal")

    def create_main_content(self):
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        top_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        main_pane.add(top_pane, weight=2)
        
        packet_frame = ttk.LabelFrame(top_pane, text="Packet List")
        top_pane.add(packet_frame, weight=1)
        
        # Add filter options above the packet list
        filter_frame = ttk.Frame(packet_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_var = tk.StringVar(value="Any")
        protocol_combo = ttk.Combobox(filter_frame, textvariable=self.protocol_var, width=10, state="readonly")
        protocol_combo['values'] = ["Any", "SIP", "RTP", "RTCP", "UDP", "TCP", "IP"]
        protocol_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        self.ip_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.ip_var, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Src Port:").pack(side=tk.LEFT, padx=5)
        self.src_port_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.src_port_var, width=8).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Dst Port:").pack(side=tk.LEFT, padx=5)
        self.dst_port_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.dst_port_var, width=8).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Contains:").pack(side=tk.LEFT, padx=5)
        self.text_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.text_var, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_packet_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_packet_filter).pack(side=tk.LEFT, padx=5)
        
        columns = ("No.", "Time", "Source", "Source Port", "Destination", "Destination Port", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            if col == "Info":
                self.packet_tree.column(col, width=300)
            elif col == "No.":
                self.packet_tree.column(col, width=50)
            elif col in ["Time", "Length", "Source Port", "Destination Port"]:
                self.packet_tree.column(col, width=80)
            else:
                self.packet_tree.column(col, width=120)
        
        # Move both scrollbars to the right side
        scrollbar_frame = ttk.Frame(packet_frame)
        scrollbar_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        packet_y_scroll = ttk.Scrollbar(scrollbar_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        packet_y_scroll.pack(side=tk.TOP, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=packet_y_scroll.set)
        
        packet_x_scroll = ttk.Scrollbar(scrollbar_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        packet_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_tree.configure(xscrollcommand=packet_x_scroll.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        self.packet_tree.bind("<MouseWheel>", self.on_mouse_wheel)
        
        details_frame = ttk.LabelFrame(top_pane, text="Packet Details")
        top_pane.add(details_frame, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        bottom_frame = ttk.LabelFrame(main_pane, text="Analysis")
        main_pane.add(bottom_frame, weight=1)
        
        self.notebook = ttk.Notebook(bottom_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.call_flow_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.call_flow_frame, text="SIP Call Flow")
        
        call_select_frame = ttk.Frame(self.call_flow_frame)
        call_select_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(call_select_frame, text="Select Call:").pack(side=tk.LEFT, padx=5)
        self.call_id_var = tk.StringVar()
        self.call_id_combo = ttk.Combobox(call_select_frame, textvariable=self.call_id_var, state="readonly", width=50)
        self.call_id_combo.pack(side=tk.LEFT, padx=5)
        self.call_id_combo.bind("<<ComboboxSelected>>", self.on_call_selected)
        
        ttk.Button(call_select_frame, text="Zoom In", command=self.zoom_in).pack(side=tk.LEFT, padx=5)
        ttk.Button(call_select_frame, text="Zoom Out", command=self.zoom_out).pack(side=tk.LEFT, padx=5)
        ttk.Button(call_select_frame, text="Reset Zoom", command=self.reset_zoom).pack(side=tk.LEFT, padx=5)
        
        self.call_flow_container = ttk.Frame(self.call_flow_frame)
        self.call_flow_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.call_flow_canvas = tk.Canvas(self.call_flow_container)
        self.call_flow_scrollbar = ttk.Scrollbar(self.call_flow_container, orient=tk.VERTICAL, command=self.call_flow_canvas.yview)
        self.call_flow_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.call_flow_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.call_flow_canvas.configure(yscrollcommand=self.call_flow_scrollbar.set)
        
        self.call_flow_canvas_frame = ttk.Frame(self.call_flow_canvas)
        self.call_flow_canvas.create_window((0, 0), window=self.call_flow_canvas_frame, anchor="nw")
        
        self.call_flow_canvas_frame.bind("<Configure>", lambda e: self.call_flow_canvas.configure(scrollregion=self.call_flow_canvas.bbox("all")))
        
        self.rtp_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rtp_frame, text="RTP Analysis")
        
        rtp_select_frame = ttk.Frame(self.rtp_frame)
        rtp_select_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(rtp_select_frame, text="Select RTP Stream:").pack(side=tk.LEFT, padx=5)
        self.rtp_stream_var = tk.StringVar()
        self.rtp_stream_combo = ttk.Combobox(rtp_select_frame, textvariable=self.rtp_stream_var, state="readonly", width=50)
        self.rtp_stream_combo.pack(side=tk.LEFT, padx=5)
        self.rtp_stream_combo.bind("<<ComboboxSelected>>", self.on_rtp_stream_selected)
        
        rtp_control_frame = ttk.Frame(self.rtp_frame)
        rtp_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(rtp_control_frame, text="Play", command=self.play_rtp_stream).pack(side=tk.LEFT, padx=5)
        ttk.Button(rtp_control_frame, text="Stop", command=self.stop_rtp_playback).pack(side=tk.LEFT, padx=5)
        ttk.Button(rtp_control_frame, text="Save WAV", command=self.save_rtp_as_wav).pack(side=tk.LEFT, padx=5)
        
        self.rtp_waveform_frame = ttk.Frame(self.rtp_frame)
        self.rtp_waveform_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.rtp_flow_frame = ttk.Frame(self.rtp_frame)
        self.rtp_flow_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.issues_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.issues_frame, text="Issues")
        
        self.issues_text = scrolledtext.ScrolledText(self.issues_frame, wrap=tk.WORD)
        self.issues_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_status_bar(self):
        status_frame = ttk.Frame(self, relief=tk.SUNKEN)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=2)
        
        self.packets_count_var = tk.StringVar(value="Packets: 0")
        packets_count_label = ttk.Label(status_frame, textvariable=self.packets_count_var)
        packets_count_label.pack(side=tk.RIGHT, padx=10, pady=2)
        
        self.calls_count_var = tk.StringVar(value="SIP Calls: 0")
        calls_count_label = ttk.Label(status_frame, textvariable=self.calls_count_var)
        calls_count_label.pack(side=tk.RIGHT, padx=10, pady=2)

    def on_mouse_wheel(self, event):
        scroll_amount = -1 * (event.delta // 120) * 5
        self.packet_tree.yview_scroll(scroll_amount, "units")

    def open_pcap_file(self):
        file_path = filedialog.askopenfilename(
            title="Open PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if file_path:
            self.pcap_file = file_path
            self.status_var.set(f"Loading PCAP file: {os.path.basename(file_path)}")
            self.update()
            self.load_pcap_file(file_path)

    def load_pcap_file(self, file_path):
        self.status_var.set(f"Loading PCAP file: {os.path.basename(file_path)}")
        self.update()

        try:
            packets = rdpcap(file_path)
            if not packets:
                raise ValueError("PCAP file is empty or invalid.")

            self.packets.clear()
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.details_text.delete(1.0, tk.END)
            self.sip_calls.clear()
            self.rtp_streams.clear()

            for i, packet in enumerate(packets):
                try:
                    time_delta = packet.time - packets[0].time if i > 0 else 0.0
                    src = packet.getlayer('IP').src if packet.haslayer('IP') else "N/A"
                    dst = packet.getlayer('IP').dst if packet.haslayer('IP') else "N/A"
                    src_port = packet.getlayer('UDP').sport if packet.haslayer('UDP') else packet.getlayer('TCP').sport if packet.haslayer('TCP') else "N/A"
                    dst_port = packet.getlayer('UDP').dport if packet.haslayer('UDP') else packet.getlayer('TCP').dport if packet.haslayer('TCP') else "N/A"
                    proto = self.get_highest_protocol(packet)
                    length = len(packet)
                    info = self.get_packet_info(packet, proto)

                    self.packet_tree.insert("", "end", values=(i+1, f"{time_delta:.6f}", src, src_port, dst, dst_port, proto, length, info))
                    self.packets.append(packet)
                except Exception as e:
                    print(f"Error parsing packet {i}: {e}")
                    continue

            self.status_var.set(f"Loaded {len(self.packets)} packets.")
            self.packets_count_var.set(f"Packets: {len(self.packets)}")
            self.extract_sip_calls()
            self.extract_rtp_streams()
            self.highlight_pcap_issues()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load PCAP file: {str(e)}")
            self.status_var.set("Ready")

    def start_live_capture(self):
        if self.is_capturing:
            messagebox.showinfo("Live Capture", "Already capturing packets.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Select Network Interface")
        dialog.geometry("400x150")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Select Network Interface:").pack(pady=10)
        
        interface_var = tk.StringVar()
        interfaces = get_if_list() if get_if_list else ["eth0", "Wi-Fi"]
        interface_combo = ttk.Combobox(dialog, textvariable=interface_var, values=interfaces, state="readonly")
        interface_combo.pack(pady=5)
        if interfaces:
            interface_combo.current(0)

        def start_capture():
            interface = interface_var.get()
            if not interface:
                messagebox.showerror("Error", "Please select a network interface.")
                return
            dialog.destroy()
            
            self.is_capturing = True
            self.status_var.set(f"Starting live capture on {interface}...")
            self.enable_stop_capture_menu()

            self.packet_tree.delete(*self.packet_tree.get_children())
            self.details_text.delete(1.0, tk.END)
            self.packets.clear()
            self.sip_calls.clear()
            self.rtp_streams.clear()

            def capture_packets():
                try:
                    sniff(iface=interface, prn=self.process_live_packet, store=False, 
                          stop_filter=lambda p: not self.is_capturing)
                except Exception as e:
                    self.after(0, lambda: messagebox.showerror("Error", f"Live capture failed: {str(e)}"))
                    self.after(0, lambda: self.stop_live_capture())

            import threading
            threading.Thread(target=capture_packets, daemon=True).start()

        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Start Capture", command=start_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def process_live_packet(self, packet):
        self.after(0, lambda: self.add_live_packet(packet))

    def add_live_packet(self, packet):
        try:
            i = len(self.packets) + 1
            time_delta = packet.time - self.packets[0].time if self.packets else 0.0
            src = packet.getlayer('IP').src if packet.haslayer('IP') else "N/A"
            dst = packet.getlayer('IP').dst if packet.haslayer('IP') else "N/A"
            src_port = packet.getlayer('UDP').sport if packet.haslayer('UDP') else packet.getlayer('TCP').sport if packet.haslayer('TCP') else "N/A"
            dst_port = packet.getlayer('UDP').dport if packet.haslayer('UDP') else packet.getlayer('TCP').dport if packet.haslayer('TCP') else "N/A"
            proto = self.get_highest_protocol(packet)
            length = len(packet)
            info = self.get_packet_info(packet, proto)

            tag = "even" if i % 2 == 0 else "odd"
            self.packet_tree.insert("", "end", values=(i, f"{time_delta:.6f}", src, src_port, dst, dst_port, proto, length, info), tags=(tag,))
            self.packets.append(packet)
            self.packets_count_var.set(f"Packets: {len(self.packets)}")
        except Exception as e:
            print(f"Error processing live packet: {e}")

    def stop_live_capture(self):
        if not self.is_capturing:
            return
        self.is_capturing = False
        self.status_var.set("Live capture stopped.")
        menu_bar = self.nametowidget(self['menu'])
        file_menu = menu_bar.winfo_children()[0]
        file_menu.entryconfig("Stop Live Capture", state="disabled")
        file_menu.entryconfig("Save Live Capture", state="normal")

    def save_live_capture(self):
        if not self.packets:
            messagebox.showinfo("Save Live Capture", "No packets to save.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save PCAP File",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if file_path:
            try:
                wrpcap(file_path, self.packets)
                self.status_var.set(f"Saved live capture to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save PCAP file: {str(e)}")

    def get_highest_protocol(self, packet):
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
            if 'SIP/' in raw_data:
                return "SIP"
        if self.is_rtp_packet(packet):
            return "RTP"
        if packet.haslayer('UDP'):
            return "UDP"
        if packet.haslayer('TCP'):
            return "TCP"
        if packet.haslayer('IP'):
            return "IP"
        return "Other"

    def get_packet_info(self, packet, protocol):
        if protocol == "SIP":
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
                first_line = raw_data.split('\n')[0]
                return first_line.strip() if first_line else "SIP Message"
        elif protocol == "RTP":
            if packet.haslayer('RTP'):
                rtp = packet['RTP']
                return f"Seq={rtp.sequence}, TS={rtp.timestamp}"
            elif packet.haslayer('Raw'):
                # Attempt to parse RTP header manually
                payload = packet['Raw'].load
                if len(payload) >= 12:  # Minimum RTP header length
                    version = (payload[0] >> 6) & 0x03
                    pt = payload[1] & 0x7F
                    seq = int.from_bytes(payload[2:4], byteorder='big')
                    ts = int.from_bytes(payload[4:8], byteorder='big')
                    return f"Seq={seq}, TS={ts} (Manual RTP Parse)"
                return "RTP (Potential SRTP)"
        elif protocol in ["UDP", "TCP"]:
            layer = packet['UDP'] if packet.haslayer('UDP') else packet['TCP'] if packet.haslayer('TCP') else None
            if layer:
                return f"{layer.sport} → {layer.dport}"
        return f"{protocol} Packet"

    def on_packet_select(self, event):
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return

        item = selected_items[0]
        packet_index = int(self.packet_tree.item(item, "values")[0]) - 1
        self.selected_packet_index = packet_index

        if packet_index >= len(self.packets):
            return

        packet = self.packets[packet_index]
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, f"Packet {packet_index + 1}\n")
        self.details_text.insert(tk.END, "=" * 50 + "\n\n")

        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
            if 'SIP/' in raw_data and '180 Ringing' in raw_data:
                self.details_text.insert(tk.END, "Explanation:\n")
                self.details_text.insert(tk.END, "The '180 Ringing' response in SIP indicates that the called party's device has received the INVITE request and is alerting the user (e.g., the phone is ringing). It informs the caller that the call is being processed but not yet answered.\n\n")

        layer = packet
        while layer:
            self.details_text.insert(tk.END, f"Layer: {layer.name}\n")
            self.details_text.insert(tk.END, "-" * 40 + "\n")
            for field, value in layer.fields.items():
                self.details_text.insert(tk.END, f"{field}: {value}\n")
            self.details_text.insert(tk.END, "\n")
            layer = layer.payload if layer.payload else None

        self.packet_tree.tag_configure("selected", background="light blue")
        self.packet_tree.tag_configure("error", background="light pink")
        for item in self.packet_tree.get_children():
            tags = list(self.packet_tree.item(item, "tags"))
            if "selected" in tags:
                tags.remove("selected")
            self.packet_tree.item(item, tags=tags)
        current_tags = list(self.packet_tree.item(selected_items[0], "tags"))
        self.packet_tree.item(selected_items[0], tags=current_tags + ["selected"])

        if self.call_id_var.get():
            call_id = self.call_id_var.get().split(" ")[0]
            self.draw_call_flow(call_id)

    def extract_sip_calls(self):
        if not self.packets:
            messagebox.showinfo("Info", "Please load a PCAP file first.")
            return

        self.sip_calls = {}
        base_time = self.packets[0].time if self.packets else 0

        for i, packet in enumerate(self.packets):
            try:
                if packet.haslayer('Raw'):
                    raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
                    if 'SIP/' not in raw_data:
                        continue

                    call_id = None
                    method = None
                    status_code = None
                    cseq = None
                    from_field = "Unknown"
                    to_field = "Unknown"
                    src_port = packet.getlayer('UDP').sport if packet.haslayer('UDP') else packet.getlayer('TCP').sport if packet.haslayer('TCP') else "N/A"
                    dst_port = packet.getlayer('UDP').dport if packet.haslayer('UDP') else packet.getlayer('TCP').dport if packet.haslayer('TCP') else "N/A"
                    sdp_media = None
                    rtpmap = {}
                    is_srtp = False

                    # Parse SIP headers and SDP
                    in_sdp = False
                    for line in raw_data.split('\n'):
                        line = line.strip()
                        if line.startswith('Call-ID:'):
                            call_id = line.split(':', 1)[1].strip()
                        elif line.startswith('CSeq:'):
                            cseq = line.split(':', 1)[1].strip()
                        elif line.startswith('From:'):
                            from_field = line.split(':', 1)[1].strip()
                        elif line.startswith('To:'):
                            to_field = line.split(':', 1)[1].strip()
                        elif line.startswith('SIP/'):
                            parts = line.split()
                            if len(parts) > 1 and parts[0] in ['INVITE', 'ACK', 'BYE', 'CANCEL', 'REGISTER']:
                                method = parts[0]
                            elif len(parts) > 1 and parts[1].isdigit():
                                status_code = parts[1]
                        elif line.startswith('v='):
                            in_sdp = True
                        elif in_sdp and line.startswith('m=audio'):
                            sdp_media = line
                        elif in_sdp and line.startswith('a=rtpmap:'):
                            try:
                                rtpmap_parts = line.split(':', 1)[1].strip().split()
                                pt = int(rtpmap_parts[0])
                                codec = rtpmap_parts[1].split('/')[0]
                                rtpmap[pt] = codec
                            except (IndexError, ValueError) as e:
                                print(f"Error parsing rtpmap in packet {i}: {line}, Error: {e}")
                        elif in_sdp and line.startswith('a=crypto:'):
                            is_srtp = True

                    if not call_id:
                        continue

                    if call_id not in self.sip_calls:
                        self.sip_calls[call_id] = {
                            'messages': [],
                            'from': from_field,
                            'to': to_field,
                            'start_time': None,
                            'end_time': None,
                            'status': 'Unknown',
                            'associated_rtp': [],
                            'rtp_ports': set(),
                            'rtpmap': rtpmap,
                            'is_srtp': is_srtp,
                            'src_ip': None,
                            'dst_ip': None
                        }

                    message = {
                        'packet_index': i,
                        'timestamp': float(packet.time),
                        'src': packet['IP'].src if packet.haslayer('IP') else 'Unknown',
                        'dst': packet['IP'].dst if packet.haslayer('IP') else 'Unknown',
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'method': method,
                        'status_code': status_code,
                        'cseq': cseq,
                        'raw': raw_data,
                        'sdp_media': sdp_media
                    }

                    self.sip_calls[call_id]['messages'].append(message)

                    # Store IPs for later RTP association
                    if self.sip_calls[call_id]['src_ip'] is None:
                        self.sip_calls[call_id]['src_ip'] = message['src']
                    if self.sip_calls[call_id]['dst_ip'] is None:
                        self.sip_calls[call_id]['dst_ip'] = message['dst']

                    if sdp_media:
                        try:
                            port = int(sdp_media.split()[1])
                            self.sip_calls[call_id]['rtp_ports'].add(port)
                            print(f"Packet {i}: Call-ID {call_id}, SDP Media: {sdp_media}, RTP Port: {port}, rtpmap: {rtpmap}, SRTP: {is_srtp}")
                        except (IndexError, ValueError) as e:
                            print(f"Error parsing SDP media line in packet {i}: {e}")

                    if self.sip_calls[call_id]['start_time'] is None or message['timestamp'] < self.sip_calls[call_id]['start_time']:
                        self.sip_calls[call_id]['start_time'] = message['timestamp']
                    if self.sip_calls[call_id]['end_time'] is None or message['timestamp'] > self.sip_calls[call_id]['end_time']:
                        self.sip_calls[call_id]['end_time'] = message['timestamp']

                    if message['method'] == 'INVITE' and self.sip_calls[call_id]['status'] == 'Unknown':
                        self.sip_calls[call_id]['status'] = 'Ringing'
                    elif message['status_code'] == '200' and cseq and 'INVITE' in cseq:
                        self.sip_calls[call_id]['status'] = 'Answered'
                    elif message['method'] == 'BYE':
                        self.sip_calls[call_id]['status'] = 'Terminated'

            except Exception as e:
                print(f"Error processing SIP packet {i}: {e}")
                continue

        self.call_id_combo['values'] = [f"{cid} ({call['from']} to {call['to']})" for cid, call in self.sip_calls.items()]
        self.calls_count_var.set(f"SIP Calls: {len(self.sip_calls)}")

        if self.call_id_combo['values']:
            self.call_id_combo.current(0)
            self.on_call_selected(None)

        self.status_var.set(f"Extracted {len(self.sip_calls)} SIP calls")

    def is_rtp_packet(self, packet):
        """
        Check if a packet is an RTP packet, either using Scapy's RTP layer or manual header parsing.
        """
        if packet.haslayer('RTP'):
            return True

        # Manual RTP header check for UDP packets
        if not packet.haslayer('UDP') or not packet.haslayer('Raw'):
            return False

        payload = packet['Raw'].load
        if len(payload) < 12:  # Minimum RTP header length
            return False

        # Parse RTP header fields
        version = (payload[0] >> 6) & 0x03
        padding = (payload[0] >> 5) & 0x01
        extension = (payload[0] >> 4) & 0x01
        csrc_count = payload[0] & 0x0F
        marker = (payload[1] >> 7) & 0x01
        payload_type = payload[1] & 0x7F
        sequence = int.from_bytes(payload[2:4], byteorder='big')
        timestamp = int.from_bytes(payload[4:8], byteorder='big')
        ssrc = int.from_bytes(payload[8:12], byteorder='big')

        # Basic validation of RTP header
        if version != 2:  # RTP version should be 2
            print(f"Packet {packet.summary()}: Invalid RTP version ({version})")
            return False
        if payload_type > 127:  # Payload type should be 0-127
            print(f"Packet {packet.summary()}: Invalid payload type ({payload_type})")
            return False
        if csrc_count > 15:  # CSRC count should be 0-15
            print(f"Packet {packet.summary()}: Invalid CSRC count ({csrc_count})")
            return False

        # Additional heuristic: sequence and timestamp should be reasonable
        if sequence == 0 and timestamp == 0:
            print(f"Packet {packet.summary()}: Sequence and timestamp are both 0")
            return False

        return True

    def extract_rtp_streams(self):
        if not self.packets:
            messagebox.showinfo("Info", "Please load a PCAP file first.")
            return

        if rdpcap is None or RTP is None:
            messagebox.showerror("Missing Library", "The scapy library is required for RTP analysis.\nPlease install with: pip install scapy")
            return

        self.rtp_streams = {}

        # Collect potential RTP ports and payload type mappings from SIP calls
        rtp_ports = set()
        for call_id, call in self.sip_calls.items():
            rtp_ports.update(call['rtp_ports'])
        print(f"Potential RTP ports from SIP SDP: {rtp_ports}")

        for i, packet in enumerate(self.packets):
            try:
                if not packet.haslayer('UDP'):
                    continue

                src_ip = packet['IP'].src if packet.haslayer('IP') else "Unknown"
                dst_ip = packet['IP'].dst if packet.haslayer('IP') else "Unknown"
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport

                # Check if this packet could be RTP based on ports or heuristic
                is_rtp_candidate = (src_port in rtp_ports or dst_port in rtp_ports) or self.is_rtp_packet(packet)
                if not is_rtp_candidate:
                    # Broaden the search: check if IPs match a SIP call
                    for call_id, call in self.sip_calls.items():
                        if (src_ip == call['src_ip'] and dst_ip == call['dst_ip']) or \
                           (src_ip == call['dst_ip'] and dst_ip == call['src_ip']):
                            is_rtp_candidate = True
                            break
                if not is_rtp_candidate:
                    continue

                # Check if it's an RTP packet (either via Scapy or manual parsing)
                if not self.is_rtp_packet(packet):
                    print(f"Packet {i}: UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} - Not an RTP packet")
                    # Check if it might be SRTP by associating with a SIP call
                    associated_call_id = None
                    for call_id, call in self.sip_calls.items():
                        if call.get('is_srtp', False):
                            if (src_ip == call['src_ip'] and dst_ip == call['dst_ip']) or \
                               (src_ip == call['dst_ip'] and dst_ip == call['src_ip']):
                                if src_port in call['rtp_ports'] or dst_port in call['rtp_ports']:
                                    associated_call_id = call_id
                                    break
                        if associated_call_id:
                            break
                    if associated_call_id:
                        print(f"Packet {i}: UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} - Potential SRTP (Associated Call ID: {associated_call_id})")
                    continue

                stream_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

                if stream_key not in self.rtp_streams:
                    self.rtp_streams[stream_key] = {
                        'packets': [],
                        'src': f"{src_ip}:{src_port}",
                        'dst': f"{dst_ip}:{dst_port}",
                        'start_time': None,
                        'end_time': None,
                        'payload_type': None,
                        'sample_rate': 8000,
                        'channels': 1,
                        'duration': 0,
                        'associated_call_id': None,
                        'is_srtp': False
                    }

                # Extract RTP header fields
                if packet.haslayer('RTP'):
                    rtp_hdr = packet['RTP']
                    payload_type = rtp_hdr.payload_type
                    timestamp = rtp_hdr.timestamp
                    sequence = rtp_hdr.sequence
                    marker = rtp_hdr.marker
                    payload = bytes(rtp_hdr.payload) if hasattr(rtp_hdr, 'payload') and rtp_hdr.payload else b''
                else:
                    # Manual parsing
                    raw_payload = packet['Raw'].load
                    payload_type = raw_payload[1] & 0x7F
                    sequence = int.from_bytes(raw_payload[2:4], byteorder='big')
                    timestamp = int.from_bytes(raw_payload[4:8], byteorder='big')
                    marker = (raw_payload[1] >> 7) & 0x01
                    # RTP header is 12 bytes + CSRCs + extensions; assume no extensions for now
                    header_len = 12 + 4 * ((raw_payload[0] & 0x0F))  # CSRC count
                    payload = raw_payload[header_len:] if len(raw_payload) > header_len else b''

                # Check if payload type is supported, considering rtpmap from SIP
                is_supported = False
                associated_call_id = None
                for call_id, call in self.sip_calls.items():
                    rtpmap = call.get('rtpmap', {})
                    if payload_type in rtpmap:
                        codec = rtpmap[payload_type]
                        if codec in ['PCMU', 'PCMA']:
                            is_supported = True
                            associated_call_id = call_id
                            break
                    elif payload_type in [0, 8]:  # Fallback to standard payload types
                        is_supported = True
                        associated_call_id = call_id
                        break
                    if call.get('is_srtp', False) and (src_port in call['rtp_ports'] or dst_port in call['rtp_ports']):
                        self.rtp_streams[stream_key]['is_srtp'] = True

                if not is_supported:
                    print(f"Packet {i}: RTP stream {stream_key} - Unsupported payload type {payload_type}")
                    continue

                if self.rtp_streams[stream_key]['payload_type'] is None:
                    self.rtp_streams[stream_key]['payload_type'] = payload_type
                    if payload_type in [0, 8]:
                        self.rtp_streams[stream_key]['sample_rate'] = 8000

                rtp_packet = {
                    'packet_index': i,
                    'timestamp': float(packet.time),
                    'rtp_timestamp': timestamp,
                    'sequence': sequence,
                    'marker': marker,
                    'payload': payload
                }

                self.rtp_streams[stream_key]['packets'].append(rtp_packet)

                if self.rtp_streams[stream_key]['start_time'] is None or packet.time < self.rtp_streams[stream_key]['start_time']:
                    self.rtp_streams[stream_key]['start_time'] = packet.time
                if self.rtp_streams[stream_key]['end_time'] is None or packet.time > self.rtp_streams[stream_key]['end_time']:
                    self.rtp_streams[stream_key]['end_time'] = packet.time

                # Associate RTP stream with SIP call
                for call_id, call in self.sip_calls.items():
                    if (src_ip == call['src_ip'] and dst_ip == call['dst_ip']) or \
                       (src_ip == call['dst_ip'] and dst_ip == call['src_ip']):
                        if src_port in call['rtp_ports'] or dst_port in call['rtp_ports'] or call_id == associated_call_id:
                            self.rtp_streams[stream_key]['associated_call_id'] = call_id
                            if stream_key not in call['associated_rtp']:
                                call['associated_rtp'].append(stream_key)

            except Exception as e:
                print(f"Error processing RTP packet {i}: {e}")
                continue

        for stream_key, stream in list(self.rtp_streams.items()):
            if not stream['packets'] or stream['payload_type'] is None:
                print(f"Skipping RTP stream {stream_key}: No packets or unsupported payload type")
                del self.rtp_streams[stream_key]
                continue
            if stream['start_time'] is not None and stream['end_time'] is not None:
                stream['duration'] = stream['end_time'] - stream['start_time']
            print(f"RTP Stream {stream_key}: Payload Type={stream['payload_type']}, Packets={len(stream['packets'])}, Duration={stream['duration']:.2f}s, Associated Call ID={stream['associated_call_id']}, SRTP: {stream['is_srtp']}")

        self.rtp_stream_combo['values'] = [f"{key} (PT={stream['payload_type']}, {stream['duration']:.2f}s)" for key, stream in self.rtp_streams.items()]

        if self.rtp_stream_combo['values']:
            self.rtp_stream_combo.current(0)
            self.on_rtp_stream_selected(None)
        else:
            print("No RTP streams detected with supported payload types.")

        self.status_var.set(f"Extracted {len(self.rtp_streams)} RTP streams")

    def zoom_in(self):
        self.current_zoom *= 1.2
        if self.current_call_id:
            self.draw_call_flow(self.current_call_id)

    def zoom_out(self):
        self.current_zoom /= 1.2
        if self.current_zoom < 0.1:
            self.current_zoom = 0.1
        if self.current_call_id:
            self.draw_call_flow(self.current_call_id)

    def reset_zoom(self):
        self.current_zoom = 1.0
        if self.current_call_id:
            self.draw_call_flow(self.current_call_id)

    def on_call_selected(self, event):
        selection = self.call_id_var.get()
        if selection:
            call_id = selection.split(" ")[0]
            self.current_call_id = call_id
            self.draw_call_flow(call_id)

    def draw_call_flow(self, call_id):
        if call_id not in self.sip_calls:
            return
        
        for widget in self.call_flow_canvas_frame.winfo_children():
            widget.destroy()
        
        call_data = self.sip_calls[call_id]
        messages = call_data['messages']
        
        if not messages:
            return
        
        fig_width = 12 * self.current_zoom
        fig_height = max(8, len(messages) * 0.5) * self.current_zoom
        fig, ax = plt.subplots(figsize=(fig_width, fig_height))
        
        endpoints = set()
        for msg in messages:
            src_label = f"{msg['src']}:{msg['src_port']}"
            dst_label = f"{msg['dst']}:{msg['dst_port']}"
            endpoints.add(src_label)
            endpoints.add(dst_label)
        
        endpoints = sorted(list(endpoints))
        x_positions = {endpoint: i * self.current_zoom for i, endpoint in enumerate(endpoints)}
        
        for endpoint, x_pos in x_positions.items():
            ax.axvline(x=x_pos, color='gray', linestyle='--', alpha=0.5)
            ax.text(x_pos, -0.5 * self.current_zoom, endpoint, rotation=45, ha='right', fontsize=8 * self.current_zoom)
        
        base_time = messages[0]['timestamp'] if messages else 0
        message_counter = 1
        y_pos = 0
        
        for i, msg in enumerate(messages):
            src_x = x_positions[f"{msg['src']}:{msg['src_port']}"]
            dst_x = x_positions[f"{msg['dst']}:{msg['dst_port']}"]
            y_pos = i * self.current_zoom
            
            color = 'blue'
            annotation = ""
            try:
                if msg['status_code']:
                    status_code = int(msg['status_code'])
                    if status_code >= 400:
                        color = 'red'
                        annotation = "GSS_S_CONTINUE_NEEDED" if "401" in msg['status_code'] else ""
                    elif status_code >= 300:
                        color = 'orange'
                    elif status_code >= 100:
                        color = 'green'
                        annotation = "GSS_S_COMPLETE" if "200" in msg['status_code'] else ""
                elif msg['method']:
                    annotation = "GSS_INIT_SEC_context()" if msg['method'] == "REGISTER" else ""
            except (ValueError, TypeError) as e:
                print(f"Error processing SIP status code in message {i}: {e}")
                color = 'blue'
            
            linewidth = 2.5 * self.current_zoom if msg['packet_index'] == self.selected_packet_index else 1.5 * self.current_zoom
            alpha = 1.0 if msg['packet_index'] == self.selected_packet_index else 0.7
            
            ax.annotate('', 
                xy=(dst_x, y_pos), 
                xytext=(src_x, y_pos),
                arrowprops=dict(arrowstyle='->', color=color, lw=linewidth, alpha=alpha),
            )
            
            label_text = ""
            if msg['method']:
                label_text = f"{msg['method']} ({message_counter})"
            elif msg['status_code']:
                label_text = f"{msg['status_code']} ({message_counter})"
            
            if 'cseq' in msg and msg['cseq']:
                label_text += f" ({msg['cseq']})"
            
            text_x = (src_x + dst_x) / 2
            ax.text(text_x, y_pos, label_text, ha='center', va='bottom', fontsize=8 * self.current_zoom, 
                   bbox=dict(facecolor='white', alpha=0.7, edgecolor='none'))
            
            if annotation:
                ax.text(text_x, y_pos - 0.3 * self.current_zoom, annotation, ha='center', va='top', fontsize=7 * self.current_zoom, color='purple')
            
            time_diff = msg['timestamp'] - base_time
            ax.text(max(x_positions.values()) + 0.5 * self.current_zoom, y_pos, f"+{time_diff:.3f}s", 
                   fontsize=7 * self.current_zoom, va='center')
            
            message_counter += 1
        
        if call_data['associated_rtp']:
            for stream_key in call_data['associated_rtp']:
                stream = self.rtp_streams.get(stream_key)
                if not stream:
                    continue
                src_x = x_positions.get(stream['src'])
                dst_x = x_positions.get(stream['dst'])
                if src_x is None or dst_x is None:
                    continue
                y_pos += self.current_zoom
                ax.annotate('',
                    xy=(dst_x, y_pos),
                    xytext=(src_x, y_pos),
                    arrowprops=dict(arrowstyle='-', color='gray', linestyle='--', lw=1.0 * self.current_zoom),
                )
                text_x = (src_x + dst_x) / 2
                ax.text(text_x, y_pos, f"RTP Stream (PT={stream['payload_type']})", ha='center', va='bottom', fontsize=8 * self.current_zoom,
                        bbox=dict(facecolor='white', alpha=0.7, edgecolor='none'))
        
        ax.set_xlim(-0.5 * self.current_zoom, max(x_positions.values()) + 2 * self.current_zoom)
        ax.set_ylim(-1 * self.current_zoom, y_pos + 1 * self.current_zoom)
        ax.axis('off')
        
        plt.title(f"SIP Call Flow: {call_id}", fontsize=12 * self.current_zoom)
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=self.call_flow_canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.call_flow_canvas.configure(scrollregion=self.call_flow_canvas.bbox("all"))

    def on_rtp_stream_selected(self, event):
        selection = self.rtp_stream_var.get()
        if selection:
            stream_key = selection.split(" ")[0]
            self.display_rtp_waveform(stream_key)
            self.draw_rtp_flow(stream_key)

    def display_rtp_waveform(self, stream_key):
        if stream_key not in self.rtp_streams:
            return
        
        for widget in self.rtp_waveform_frame.winfo_children():
            widget.destroy()
        
        stream_data = self.rtp_streams[stream_key]
        packets = stream_data['packets']
        
        if not packets:
            return
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6))
        
        audio_data = self.extract_audio_from_rtp(stream_key)
        
        if audio_data is not None:
            ax1.plot(audio_data)
            ax1.set_title("RTP Audio Waveform")
            ax1.set_xlabel("Sample")
            ax1.set_ylabel("Amplitude")
            
            sequences = [p['sequence'] for p in packets if 'sequence' in p]
            timestamps = [p['timestamp'] - packets[0]['timestamp'] for p in packets]
            
            if sequences:
                ax2.plot(timestamps, sequences, 'o-')
                ax2.set_title("RTP Sequence Numbers")
                ax2.set_xlabel("Time (seconds)")
                ax2.set_ylabel("Sequence Number")
        else:
            ax1.text(0.5, 0.5, "Audio extraction failed or not supported", 
                    ha='center', va='center', transform=ax1.transAxes)
            ax2.text(0.5, 0.5, "No sequence data available", 
                    ha='center', va='center', transform=ax2.transAxes)
        
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=self.rtp_waveform_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        details_frame = ttk.LabelFrame(self.rtp_waveform_frame, text="Stream Details")
        details_frame.pack(fill=tk.X, expand=False, padx=5, pady=5)
        
        ttk.Label(details_frame, text=f"Source: {stream_data['src']}").pack(anchor=tk.W, padx=5)
        ttk.Label(details_frame, text=f"Destination: {stream_data['dst']}").pack(anchor=tk.W, padx=5)
        ttk.Label(details_frame, text=f"Payload Type: {stream_data['payload_type']}").pack(anchor=tk.W, padx=5)
        ttk.Label(details_frame, text=f"Duration: {stream_data['duration']:.2f} seconds").pack(anchor=tk.W, padx=5)
        ttk.Label(details_frame, text=f"Packets: {len(packets)}").pack(anchor=tk.W, padx=5)
        ttk.Label(details_frame, text=f"SRTP: {stream_data['is_srtp']}").pack(anchor=tk.W, padx=5)
        if stream_data['associated_call_id']:
            ttk.Label(details_frame, text=f"Associated SIP Call: {stream_data['associated_call_id']}").pack(anchor=tk.W, padx=5)
        
        sequences = [p['sequence'] for p in packets if 'sequence' in p]
        if len(sequences) > 1:
            expected_packets = max(sequences) - min(sequences) + 1
            received_packets = len(sequences)
            loss_rate = (expected_packets - received_packets) / expected_packets * 100 if expected_packets > 0 else 0
            ttk.Label(details_frame, text=f"Packet Loss: {loss_rate:.2f}%").pack(anchor=tk.W, padx=5)

    def draw_rtp_flow(self, stream_key):
        if stream_key not in self.rtp_streams:
            return
        
        for widget in self.rtp_flow_frame.winfo_children():
            widget.destroy()
        
        stream_data = self.rtp_streams[stream_key]
        packets = stream_data['packets']
        
        if not packets:
            return
        
        fig, ax = plt.subplots(figsize=(10, 4))
        
        endpoints = {stream_data['src'], stream_data['dst']}
        endpoints = sorted(list(endpoints))
        x_positions = {endpoint: i for i, endpoint in enumerate(endpoints)}
        
        for endpoint, x_pos in x_positions.items():
            ax.axvline(x=x_pos, color='gray', linestyle='--', alpha=0.5)
            ax.text(x_pos, -0.5, endpoint, rotation=45, ha='right', fontsize=8)
        
        base_time = packets[0]['timestamp'] if packets else 0
        y_pos = 0
        
        for i, pkt in enumerate(packets):
            src = stream_data['src']
            dst = stream_data['dst']
            src_x = x_positions[src]
            dst_x = x_positions[dst]
            y_pos = i
            
            ax.annotate('', 
                xy=(dst_x, y_pos), 
                xytext=(src_x, y_pos),
                arrowprops=dict(arrowstyle='->', color='purple', lw=1.5, alpha=0.7),
            )
            
            label_text = f"Seq={pkt['sequence']}"
            text_x = (src_x + dst_x) / 2
            ax.text(text_x, y_pos, label_text, ha='center', va='bottom', fontsize=8,
                   bbox=dict(facecolor='white', alpha=0.7, edgecolor='none'))
            
            time_diff = pkt['timestamp'] - base_time
            ax.text(max(x_positions.values()) + 0.5, y_pos, f"+{time_diff:.3f}s", 
                   fontsize=7, va='center')
        
        ax.set_xlim(-0.5, max(x_positions.values()) + 2)
        ax.set_ylim(-1, y_pos + 1)
        ax.axis('off')
        
        plt.title(f"RTP Packet Flow: {stream_key}")
        plt.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, master=self.rtp_flow_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def extract_audio_from_rtp(self, stream_key):
        if stream_key not in self.rtp_streams:
            print(f"Error: Stream key {stream_key} not found in rtp_streams")
            return None
        
        stream = self.rtp_streams[stream_key]
        if stream['is_srtp']:
            print(f"Error: Stream {stream_key} is SRTP - audio extraction not supported")
            return None

        packets = sorted(stream['packets'], key=lambda p: p['sequence'] if 'sequence' in p else 0)
        
        if not packets:
            print(f"Error: No packets in RTP stream {stream_key}")
            return None
        
        payload_type = stream['payload_type']
        
        if payload_type is None:
            print(f"Error: No payload type defined for RTP stream {stream_key}")
            return None
        
        audio_data = []
        total_payload_length = 0
        
        try:
            if payload_type == 0:  # PCMU (G.711 µ-law)
                for packet in packets:
                    if 'payload' not in packet or not packet['payload']:
                        print(f"Warning: Packet {packet['packet_index']} in stream {stream_key} has no payload")
                        continue
                    total_payload_length += len(packet['payload'])
                    for byte in packet['payload']:
                        audio_data.append(self.ulaw2linear(byte))
            
            elif payload_type == 8:  # PCMA (G.711 A-law)
                for packet in packets:
                    if 'payload' not in packet or not packet['payload']:
                        print(f"Warning: Packet {packet['packet_index']} in stream {stream_key} has no payload")
                        continue
                    total_payload_length += len(packet['payload'])
                    for byte in packet['payload']:
                        audio_data.append(self.alaw2linear(byte))
            
            else:
                print(f"Error: Unsupported payload type {payload_type} for RTP stream {stream_key}")
                return None
            
            if not audio_data:
                print(f"Error: No audio data extracted from RTP stream {stream_key}. Total payload length: {total_payload_length} bytes")
                return None
            
            print(f"Successfully extracted {len(audio_data)} audio samples from RTP stream {stream_key}")
            return np.array(audio_data)
        
        except Exception as e:
            print(f"Error extracting audio from stream {stream_key}: {str(e)}")
            return None

    def ulaw2linear(self, u_val):
        u_val = ~u_val & 0xFF
        sign = (u_val & 0x80)
        u_val = u_val & 0x7F
        exponent = (u_val & 0x70) >> 4
        mantissa = u_val & 0x0F
        sample = mantissa << (exponent + 3)
        sample += (1 << (exponent + 3))
        if sign != 0:
            sample = -sample
        return sample

    def alaw2linear(self, a_val):
        a_val ^= 0x55
        sign = (a_val & 0x80)
        exponent = (a_val & 0x70) >> 4
        mantissa = a_val & 0x0F
        sample = mantissa << 4
        if exponent > 0:
            sample = (sample + 0x108) << (exponent - 1)
        else:
            sample += 8
        if sign != 0:
            sample = -sample
        return sample

    def play_rtp_stream(self):
        selection = self.rtp_stream_var.get()
        if not selection:
            messagebox.showinfo("Info", "Please select an RTP stream to play.")
            return
        
        stream_key = selection.split(" ")[0]
        audio_data = self.extract_audio_from_rtp(stream_key)
        if audio_data is None:
            stream = self.rtp_streams.get(stream_key, {})
            payload_type = stream.get('payload_type', 'Unknown')
            packet_count = len(stream.get('packets', []))
            is_srtp = stream.get('is_srtp', False)
            messagebox.showinfo("Info", f"Could not extract audio from stream {stream_key}.\n"
                                       f"Payload Type: {payload_type}\n"
                                       f"Packet Count: {packet_count}\n"
                                       f"SRTP: {is_srtp}\n"
                                       f"Check the console for more details.")
            return
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tmp_file:
                temp_wav_path = tmp_file.name
            
            max_val = max(abs(max(audio_data)), abs(min(audio_data)))
            if max_val > 0:
                audio_data = audio_data / max_val * 32767
            
            with wave.open(temp_wav_path, 'wb') as wav_file:
                wav_file.setnchannels(self.rtp_streams[stream_key]['channels'])
                wav_file.setsampwidth(2)
                wav_file.setframerate(self.rtp_streams[stream_key]['sample_rate'])
                audio_bytes = audio_data.astype(np.int16).tobytes()
                wav_file.writeframes(audio_bytes)
            
            pygame.mixer.music.load(temp_wav_path)
            pygame.mixer.music.play()
            self.status_var.set("Playing RTP stream audio...")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to play audio: {str(e)}")

    def stop_rtp_playback(self):
        pygame.mixer.music.stop()
        self.status_var.set("Audio playback stopped")

    def save_rtp_as_wav(self):
        selection = self.rtp_stream_var.get()
        if not selection:
            messagebox.showinfo("Info", "Please select an RTP stream to save.")
            return
        
        stream_key = selection.split(" ")[0]
        audio_data = self.extract_audio_from_rtp(stream_key)
        if audio_data is None:
            stream = self.rtp_streams.get(stream_key, {})
            payload_type = stream.get('payload_type', 'Unknown')
            packet_count = len(stream.get('packets', []))
            is_srtp = stream.get('is_srtp', False)
            messagebox.showinfo("Info", f"Could not extract audio from stream {stream_key}.\n"
                                       f"Payload Type: {payload_type}\n"
                                       f"Packet Count: {packet_count}\n"
                                       f"SRTP: {is_srtp}\n"
                                       f"Check the console for more details.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save WAV File",
            defaultextension=".wav",
            filetypes=[("WAV files", "*.wav"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            max_val = max(abs(max(audio_data)), abs(min(audio_data)))
            if max_val > 0:
                audio_data = audio_data / max_val * 32767
            
            with wave.open(file_path, 'wb') as wav_file:
                wav_file.setnchannels(self.rtp_streams[stream_key]['channels'])
                wav_file.setsampwidth(2)
                wav_file.setframerate(self.rtp_streams[stream_key]['sample_rate'])
                audio_bytes = audio_data.astype(np.int16).tobytes()
                wav_file.writeframes(audio_bytes)
            
            self.status_var.set(f"Saved RTP stream to {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save WAV file: {str(e)}")

    def apply_packet_filter(self):
        if not self.packets:
            messagebox.showinfo("Filter", "No packets to filter.")
            return

        protocol = self.protocol_var.get()
        ip_addr = self.ip_var.get()
        src_port = self.src_port_var.get()
        dst_port = self.dst_port_var.get()
        text = self.text_var.get()

        self.packet_tree.delete(*self.packet_tree.get_children())
        filtered_count = 0

        for i, packet in enumerate(self.packets):
            try:
                time_delta = packet.time - self.packets[0].time if i > 0 else 0.0
                src = packet.getlayer('IP').src if packet.haslayer('IP') else "N/A"
                dst = packet.getlayer('IP').dst if packet.haslayer('IP') else "N/A"
                pkt_src_port = str(packet.getlayer('UDP').sport if packet.haslayer('UDP') else packet.getlayer('TCP').sport if packet.haslayer('TCP') else "N/A")
                pkt_dst_port = str(packet.getlayer('UDP').dport if packet.haslayer('UDP') else packet.getlayer('TCP').dport if packet.haslayer('TCP') else "N/A")
                proto = self.get_highest_protocol(packet)
                length = len(packet)
                info = self.get_packet_info(packet, proto)

                protocol_match = protocol == "Any" or proto == protocol
                ip_match = not ip_addr or ip_addr in [src, dst]
                src_port_match = not src_port or pkt_src_port == src_port
                dst_port_match = not dst_port or pkt_dst_port == dst_port
                text_match = not text or text.lower() in info.lower()

                if protocol_match and ip_match and src_port_match and dst_port_match and text_match:
                    tags = []
                    if self.is_packet_with_error(i):
                        tags.append("error")
                    self.packet_tree.insert("", "end", values=(i+1, f"{time_delta:.6f}", src, pkt_src_port, dst, pkt_dst_port, proto, length, info), tags=tags)
                    filtered_count += 1

            except Exception as e:
                print(f"Error filtering packet {i}: {e}")
                continue

        self.status_var.set(f"Filtered to {filtered_count} packets.")

    def clear_packet_filter(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        for i, packet in enumerate(self.packets):
            try:
                time_delta = packet.time - self.packets[0].time if i > 0 else 0.0
                src = packet.getlayer('IP').src if packet.haslayer('IP') else "N/A"
                dst = packet.getlayer('IP').dst if packet.haslayer('IP') else "N/A"
                src_port = packet.getlayer('UDP').sport if packet.haslayer('UDP') else packet.getlayer('TCP').sport if packet.haslayer('TCP') else "N/A"
                dst_port = packet.getlayer('UDP').dport if packet.haslayer('UDP') else packet.getlayer('TCP').dport if packet.haslayer('TCP') else "N/A"
                proto = self.get_highest_protocol(packet)
                length = len(packet)
                info = self.get_packet_info(packet, proto)

                tags = []
                if self.is_packet_with_error(i):
                    tags.append("error")
                self.packet_tree.insert("", "end", values=(i+1, f"{time_delta:.6f}", src, src_port, dst, dst_port, proto, length, info), tags=tags)
            except Exception as e:
                print(f"Error restoring packet {i}: {e}")
                continue

        self.status_var.set(f"Filter cleared. Showing {len(self.packets)} packets.")
        self.protocol_var.set("Any")
        self.ip_var.set("")
        self.src_port_var.set("")
        self.dst_port_var.set("")
        self.text_var.set("")

    def show_find_dialog(self):
        find_window = tk.Toplevel(self)
        find_window.title("Find in Packets")
        find_window.geometry("400x150")
        find_window.transient(self)
        find_window.grab_set()
        
        ttk.Label(find_window, text="Enter search text:").pack(pady=10)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(find_window, textvariable=search_var, width=30)
        search_entry.pack(pady=5)
        search_entry.focus()

        def perform_search():
            text = search_var.get().strip()
            if not text:
                messagebox.showinfo("Find", "Please enter text to search.")
                return

            for item in self.packet_tree.get_children():
                current_tags = self.packet_tree.item(item, "tags")
                if "found" in current_tags:
                    self.packet_tree.item(item, tags=[tag for tag in current_tags if tag != "found"])

            match_count = 0
            for item in self.packet_tree.get_children():
                values = self.packet_tree.item(item, "values")
                if any(text.lower() in str(value).lower() for value in values):
                    current_tags = self.packet_tree.item(item, "tags")
                    self.packet_tree.item(item, tags=list(current_tags) + ["found"])
                    match_count += 1

            if match_count == 0:
                messagebox.showinfo("Find", f"No packets found containing '{text}'.")
            else:
                messagebox.showinfo("Find", f"Found {match_count} matching packets.")

            self.packet_tree.tag_configure("found", background="lightblue")

        button_frame = ttk.Frame(find_window)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Search", command=perform_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=find_window.destroy).pack(side=tk.LEFT, padx=5)

    def show_protocol_distribution(self):
        if not self.packets:
            messagebox.showinfo("Info", "Please load a PCAP file first.")
            return

        # Count protocols
        protocol_counts = {}
        for packet in self.packets:
            proto = self.get_highest_protocol(packet)
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        # Create a pie chart
        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())
        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.title("Protocol Distribution")

        # Display the chart in a new window
        chart_window = tk.Toplevel(self)
        chart_window.title("Protocol Distribution")
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def is_packet_with_error(self, packet_index):
        packet = self.packets[packet_index]
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
            if 'SIP/' in raw_data:
                for line in raw_data.split('\n'):
                    if line.startswith('SIP/'):
                        parts = line.split()
                        if len(parts) > 1 and parts[1].isdigit():
                            status_code = int(parts[1])
                            if 400 <= status_code <= 699:
                                return True
        return False

    def highlight_pcap_issues(self):
        self.issues_text.delete(1.0, tk.END)
        self.packet_tree.tag_configure("error", background="light pink")

        issues_found = 0
        for i, packet in enumerate(self.packets):
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
                if 'SIP/' in raw_data:
                    for line in raw_data.split('\n'):
                        if line.startswith('SIP/'):
                            parts = line.split()
                            if len(parts) > 1 and parts[1].isdigit():
                                status_code = int(parts[1])
                                if 400 <= status_code <= 699:
                                    issues_found += 1
                                    error_msg = f"Packet {i+1}: SIP Error - {line.strip()}\n"
                                    self.issues_text.insert(tk.END, error_msg)
                                    for item in self.packet_tree.get_children():
                                        values = self.packet_tree.item(item, "values")
                                        if int(values[0]) - 1 == i:
                                            current_tags = list(self.packet_tree.item(item, "tags"))
                                            if "error" not in current_tags:
                                                self.packet_tree.item(item, tags=current_tags + ["error"])
                                            break

        if issues_found == 0:
            self.issues_text.insert(tk.END, "No SIP errors found in the packets.\n")

# Main entry point to run the application standalone
if __name__ == "__main__":
    try:
        root = tk.Tk()
        root.title("Packet Analyzer Application")
        app = PacketAnalyzer(root)
        root.mainloop()
    except Exception as e:
        print(f"Failed to start application: {e}")
        import sys
        sys.exit(1)