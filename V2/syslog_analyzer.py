import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re
import os
from datetime import datetime

class SyslogAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Syslog Analyzer")
        self.geometry("1200x800")
        self.configure(bg='#f0f0f0')
        
        # Application state
        self.left_file_path = None
        self.right_file_path = None
        self.error_keywords_file = None
        self.error_keywords = []
        self.left_log_data = []
        self.right_log_data = []
        
        # Build the UI
        self.create_menu()
        self.create_toolbar()
        self.create_main_content()
        self.create_status_bar()
        
    def create_menu(self):
        """Create the application menu bar"""
        menu_bar = tk.Menu(self)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Open Left Log", command=self.open_left_log, accelerator="Ctrl+O")
        file_menu.add_command(label="Open Right Log", command=self.open_right_log, accelerator="Ctrl+Shift+O")
        file_menu.add_separator()
        file_menu.add_command(label="Load Error Keywords", command=self.load_error_keywords, accelerator="Ctrl+K")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit, accelerator="Alt+F4")
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Find in Logs", command=self.show_find_dialog, accelerator="Ctrl+F")
        tools_menu.add_command(label="Highlight Errors", command=self.highlight_errors, accelerator="Ctrl+E")
        tools_menu.add_command(label="Clear Highlights", command=self.clear_highlights, accelerator="Ctrl+L")
        tools_menu.add_separator()
        tools_menu.add_command(label="Sync Logs by Time", command=self.sync_logs_time, accelerator="Ctrl+T")
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Quick Help", command=self.show_quick_help, accelerator="F1")
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.config(menu=menu_bar)
        
        # Bind keyboard shortcuts
        self.bind("<Control-o>", lambda e: self.open_left_log())
        self.bind("<Control-O>", lambda e: self.open_right_log())  # Ctrl+Shift+O
        self.bind("<Control-k>", lambda e: self.load_error_keywords())
        self.bind("<Control-f>", lambda e: self.show_find_dialog())
        self.bind("<Control-e>", lambda e: self.highlight_errors())
        self.bind("<Control-l>", lambda e: self.clear_highlights())
        self.bind("<Control-t>", lambda e: self.sync_logs_time())
        self.bind("<F1>", lambda e: self.show_quick_help())
    
    def create_toolbar(self):
        """Create the toolbar with filter controls"""
        toolbar_frame = ttk.Frame(self, padding="5")
        toolbar_frame.pack(fill=tk.X, pady=5)
        
        # Filters
        ttk.Label(toolbar_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(toolbar_frame, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)
        filter_entry.bind("<Return>", lambda e: self.apply_filter())
        
        ttk.Button(toolbar_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar_frame, text="Clear Filter", command=self.clear_filter).pack(side=tk.LEFT, padx=5)
        
        # Time sync
        ttk.Label(toolbar_frame, text="Time Format:").pack(side=tk.LEFT, padx=(20, 5))
        self.time_format_var = tk.StringVar(value="%b %d %H:%M:%S")
        time_format_entry = ttk.Entry(toolbar_frame, textvariable=self.time_format_var, width=20)
        time_format_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="Sync Time", command=self.sync_logs_time).pack(side=tk.LEFT, padx=5)
    
    def create_main_content(self):
        """Create the main content area with two log viewers"""
        # Main panel with Panedwindow
        main_panel = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel
        left_frame = ttk.LabelFrame(main_panel, text="Left Log")
        main_panel.add(left_frame, weight=1)
        
        # Left log controls
        left_controls = ttk.Frame(left_frame)
        left_controls.pack(fill=tk.X, pady=5)
        
        ttk.Button(left_controls, text="Open Log", command=self.open_left_log).pack(side=tk.LEFT, padx=5)
        ttk.Label(left_controls, text="Search:").pack(side=tk.LEFT, padx=5)
        self.left_search_var = tk.StringVar()
        ttk.Entry(left_controls, textvariable=self.left_search_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(left_controls, text="Find", command=lambda: self.find_in_text("left")).pack(side=tk.LEFT, padx=5)
        
        # Left log content
        self.left_text = scrolledtext.ScrolledText(left_frame, wrap=tk.NONE, undo=True, width=50, height=30)
        self.left_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.left_text.bind("<ButtonRelease-1>", self.handle_text_click)
        
        # Horizontal scrollbar for left text
        left_h_scroll = ttk.Scrollbar(left_frame, orient=tk.HORIZONTAL, command=self.left_text.xview)
        self.left_text.configure(xscrollcommand=left_h_scroll.set)
        left_h_scroll.pack(fill=tk.X, padx=5)
        
        # Right panel
        right_frame = ttk.LabelFrame(main_panel, text="Right Log")
        main_panel.add(right_frame, weight=1)
        
        # Right log controls
        right_controls = ttk.Frame(right_frame)
        right_controls.pack(fill=tk.X, pady=5)
        
        ttk.Button(right_controls, text="Open Log", command=self.open_right_log).pack(side=tk.LEFT, padx=5)
        ttk.Label(right_controls, text="Search:").pack(side=tk.LEFT, padx=5)
        self.right_search_var = tk.StringVar()
        ttk.Entry(right_controls, textvariable=self.right_search_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(right_controls, text="Find", command=lambda: self.find_in_text("right")).pack(side=tk.LEFT, padx=5)
        
        # Right log content
        self.right_text = scrolledtext.ScrolledText(right_frame, wrap=tk.NONE, undo=True, width=50, height=30)
        self.right_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.right_text.bind("<ButtonRelease-1>", self.handle_text_click)
        
        # Horizontal scrollbar for right text
        right_h_scroll = ttk.Scrollbar(right_frame, orient=tk.HORIZONTAL, command=self.right_text.xview)
        self.right_text.configure(xscrollcommand=right_h_scroll.set)
        right_h_scroll.pack(fill=tk.X, padx=5)
    
    def create_status_bar(self):
        """Create the status bar"""
        status_frame = ttk.Frame(self, relief=tk.SUNKEN, padding=(5, 2))
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.error_count_var = tk.StringVar(value="Errors: 0")
        ttk.Label(status_frame, textvariable=self.error_count_var).pack(side=tk.RIGHT, padx=10)
    
    def open_left_log(self):
        """Open a log file in the left panel"""
        file_path = filedialog.askopenfilename(
            title="Open Left Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.left_file_path = file_path
            self.load_log("left", file_path)
    
    def open_right_log(self):
        """Open a log file in the right panel"""
        file_path = filedialog.askopenfilename(
            title="Open Right Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.right_file_path = file_path
            self.load_log("right", file_path)
    
    def load_log(self, side, file_path):
        """Load a log file into the specified text widget"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            # Clear existing content
            if side == "left":
                self.left_text.delete(1.0, tk.END)
                self.left_text.insert(tk.END, content)
                self.left_log_data = self.parse_log_entries(content)
                self.status_var.set(f"Loaded left log: {os.path.basename(file_path)}")
            else:
                self.right_text.delete(1.0, tk.END)
                self.right_text.insert(tk.END, content)
                self.right_log_data = self.parse_log_entries(content)
                self.status_var.set(f"Loaded right log: {os.path.basename(file_path)}")
            
            # Highlight errors if keywords loaded
            if self.error_keywords:
                self.highlight_errors()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load log file: {str(e)}")
    
    def load_error_keywords(self):
        """Load a file containing error keywords"""
        file_path = filedialog.askopenfilename(
            title="Open Error Keywords File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.error_keywords = [line.strip() for line in f if line.strip()]
                self.error_keywords_file = file_path
                self.status_var.set(f"Loaded {len(self.error_keywords)} error keywords")
                
                # Apply highlighting if logs are loaded
                if self.left_file_path or self.right_file_path:
                    self.highlight_errors()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load error keywords: {str(e)}")
    
    def parse_log_entries(self, log_content):
        """Parse log entries from content and extract timestamp info"""
        log_entries = []
        for line_num, line in enumerate(log_content.splitlines(), 1):
            # Try to extract timestamp based on common syslog formats
            timestamp = self.extract_timestamp(line)
            log_entries.append({
                'line_num': line_num,
                'content': line,
                'timestamp': timestamp,
                'datetime_obj': self.parse_timestamp(timestamp) if timestamp else None
            })
        return log_entries
    
    def extract_timestamp(self, line):
        """Extract timestamp from a log line"""
        # Common syslog format: MMM DD HH:MM:SS
        timestamp_pattern = r'(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        match = re.search(timestamp_pattern, line)
        if match:
            return match.group(0)
        return None
    
    def parse_timestamp(self, timestamp_str):
        """Parse a timestamp string into a datetime object"""
        if not timestamp_str:
            return None
            
        try:
            format_str = self.time_format_var.get()
            dt = datetime.strptime(timestamp_str, format_str)
            # Add current year since syslog often omits it
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            return None
    
    def handle_text_click(self, event):
        """Handle click events in the text widgets"""
        # Determine which text widget was clicked
        clicked_widget = event.widget
        
        # Get the line number at the mouse position
        index = clicked_widget.index(f"@{event.x},{event.y}")
        line_num = int(index.split('.')[0])
        
        # Highlight the clicked line
        self.highlight_line(clicked_widget, line_num)
        
        # Find and highlight corresponding timestamp in the other log
        if clicked_widget == self.left_text and self.right_log_data:
            self.sync_by_timestamp("left", "right", line_num)
        elif clicked_widget == self.right_text and self.left_log_data:
            self.sync_by_timestamp("right", "left", line_num)
    
    def highlight_line(self, text_widget, line_num):
        """Highlight a specific line in a text widget"""
        # Clear previous highlight
        text_widget.tag_remove("highlight", "1.0", tk.END)
        
        # Add highlight to the new line
        start = f"{line_num}.0"
        end = f"{line_num}.end"
        text_widget.tag_add("highlight", start, end)
        text_widget.tag_config("highlight", background="yellow")
        
        # Ensure the highlighted line is visible
        text_widget.see(start)
    
    def sync_by_timestamp(self, from_side, to_side, line_num):
        """Sync the other log to show the same timestamp"""
        # Get the data for both sides
        from_data = self.left_log_data if from_side == "left" else self.right_log_data
        to_data = self.right_log_data if to_side == "right" else self.left_log_data
        to_widget = self.right_text if to_side == "right" else self.left_text
        
        # Guard against empty data
        if not from_data or not to_data or line_num > len(from_data):
            return
            
        # Get timestamp of clicked line
        clicked_entry = from_data[line_num - 1]
        clicked_timestamp = clicked_entry.get('datetime_obj')
        
        if not clicked_timestamp:
            return
        
        # Find the closest matching timestamp in the other log
        closest_line = None
        min_time_diff = float('inf')
        
        for i, entry in enumerate(to_data):
            if entry['datetime_obj']:
                time_diff = abs((clicked_timestamp - entry['datetime_obj']).total_seconds())
                if time_diff < min_time_diff:
                    min_time_diff = time_diff
                    closest_line = i + 1  # +1 because line numbers start at 1
        
        # Highlight the matching line if found
        if closest_line:
            self.highlight_line(to_widget, closest_line)
            self.status_var.set(f"Synced logs. Time difference: {min_time_diff:.2f} seconds")
    
    def apply_filter(self):
        """Apply filter to both log views"""
        filter_text = self.filter_var.get().strip()
        if not filter_text:
            return
            
        # Apply to left log
        if self.left_file_path:
            self.filter_log("left", filter_text)
            
        # Apply to right log
        if self.right_file_path:
            self.filter_log("right", filter_text)
            
        self.status_var.set(f"Applied filter: '{filter_text}'")
    
    def filter_log(self, side, filter_text):
        """Filter log content and display only matching lines"""
        # Determine which data and widget to use
        data = self.left_log_data if side == "left" else self.right_log_data
        widget = self.left_text if side == "left" else self.right_text
        
        # Clear the widget
        widget.delete(1.0, tk.END)
        
        # Add only matching lines
        for entry in data:
            if filter_text.lower() in entry['content'].lower():
                widget.insert(tk.END, entry['content'] + '\n')
    
    def clear_filter(self):
        """Clear filters and reload the original logs"""
        if self.left_file_path:
            self.load_log("left", self.left_file_path)
        if self.right_file_path:
            self.load_log("right", self.right_file_path)
        self.filter_var.set("")
        self.status_var.set("Filters cleared")
    
    def find_in_text(self, side):
        """Find text in the specified log view"""
        # Determine which widget and search text to use
        widget = self.left_text if side == "left" else self.right_text
        search_text = self.left_search_var.get() if side == "left" else self.right_search_var.get()
        
        if not search_text:
            return
        
        # Remove existing search highlights
        widget.tag_remove("search", "1.0", tk.END)
        
        # Start searching from the beginning
        pos = "1.0"
        count = 0
        
        # Find all occurrences and highlight them
        while True:
            pos = widget.search(search_text, pos, stopindex=tk.END, nocase=1)
            if not pos:
                break
                
            end_pos = f"{pos}+{len(search_text)}c"
            widget.tag_add("search", pos, end_pos)
            widget.tag_config("search", background="light blue")
            
            # Move position for next search
            pos = end_pos
            count += 1
        
        # Update status
        self.status_var.set(f"Found {count} matches for '{search_text}' in {side} log")
        
        # If matches found, scroll to the first one
        if count > 0:
            widget.see("search.first")
    
    def show_find_dialog(self):
        """Show a dialog for advanced find options"""
        find_window = tk.Toplevel(self)
        find_window.title("Find in Logs")
        find_window.geometry("400x200")
        find_window.transient(self)
        find_window.grab_set()
        
        ttk.Label(find_window, text="Find what:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        search_var = tk.StringVar()
        ttk.Entry(find_window, textvariable=search_var, width=30).grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        
        # Options
        options_frame = ttk.LabelFrame(find_window, text="Options")
        options_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky=tk.W+tk.E)
        
        case_sensitive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Case sensitive", variable=case_sensitive_var).grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        
        whole_word_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Match whole word", variable=whole_word_var).grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        
        search_scope_var = tk.StringVar(value="both")
        ttk.Radiobutton(options_frame, text="Search both logs", variable=search_scope_var, value="both").grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        ttk.Radiobutton(options_frame, text="Search left log", variable=search_scope_var, value="left").grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        ttk.Radiobutton(options_frame, text="Search right log", variable=search_scope_var, value="right").grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(find_window)
        button_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Find All", command=lambda: self.find_all(
            search_var.get(), 
            search_scope_var.get(),
            case_sensitive_var.get(),
            whole_word_var.get(),
            find_window
        )).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Cancel", command=find_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def find_all(self, search_text, scope, case_sensitive, whole_word, dialog):
        """Find all occurrences with advanced options"""
        if not search_text:
            return
            
        dialog.destroy()
        
        # Clear previous search highlights
        self.left_text.tag_remove("search", "1.0", tk.END)
        self.right_text.tag_remove("search", "1.0", tk.END)
        
        count = 0
        
        # Helper function for the actual search
        def search_in_widget(widget):
            nonlocal count
            pos = "1.0"
            
            while True:
                if case_sensitive:
                    pos = widget.search(search_text, pos, stopindex=tk.END)
                else:
                    pos = widget.search(search_text, pos, stopindex=tk.END, nocase=1)
                    
                if not pos:
                    break
                    
                # Check for whole word if needed
                if whole_word:
                    word_start = widget.get(pos, f"{pos} wordstart")
                    word_end = widget.get(f"{pos} wordend", f"{pos}+{len(search_text)}c")
                    if word_start or word_end:
                        pos = f"{pos}+1c"
                        continue
                
                end_pos = f"{pos}+{len(search_text)}c"
                widget.tag_add("search", pos, end_pos)
                widget.tag_config("search", background="light blue")
                
                pos = end_pos
                count += 1
        
        # Perform search based on scope
        if scope in ["both", "left"]:
            search_in_widget(self.left_text)
            
        if scope in ["both", "right"]:
            search_in_widget(self.right_text)
        
        # Update status
        self.status_var.set(f"Found {count} matches for '{search_text}'")
        
        # Scroll to first match if found
        if count > 0:
            if scope in ["both", "left"] and self.left_text.tag_ranges("search"):
                self.left_text.see(self.left_text.tag_ranges("search")[0])
            elif scope == "right" and self.right_text.tag_ranges("search"):
                self.right_text.see(self.right_text.tag_ranges("search")[0])
    
    def highlight_errors(self):
        """Highlight error patterns in both logs"""
        if not self.error_keywords:
            messagebox.showinfo("Info", "No error keywords loaded. Please load error keywords first.")
            return
        
        # Clear previous error highlights
        self.left_text.tag_remove("error", "1.0", tk.END)
        self.right_text.tag_remove("error", "1.0", tk.END)
        
        total_errors = 0
        
        # Highlight in left log
        if self.left_file_path:
            left_errors = self.highlight_errors_in_widget(self.left_text)
            total_errors += left_errors
            
        # Highlight in right log
        if self.right_file_path:
            right_errors = self.highlight_errors_in_widget(self.right_text)
            total_errors += right_errors
            
        # Update status
        self.error_count_var.set(f"Errors: {total_errors}")
        self.status_var.set(f"Found {total_errors} errors based on {len(self.error_keywords)} keywords")
    
    def highlight_errors_in_widget(self, widget):
        """Highlight error keywords in a specific text widget"""
        count = 0
        content = widget.get("1.0", tk.END)
        
        for keyword in self.error_keywords:
            pos = "1.0"
            while True:
                pos = widget.search(keyword, pos, stopindex=tk.END, nocase=1)
                if not pos:
                    break
                    
                end_pos = f"{pos}+{len(keyword)}c"
                widget.tag_add("error", pos, end_pos)
                widget.tag_config("error", foreground="red", underline=True)
                
                line_start = pos.split('.')[0] + ".0"
                line_end = pos.split('.')[0] + ".end"
                widget.tag_add("error_line", line_start, line_end)
                widget.tag_config("error_line", background="#ffe6e6")
                
                pos = end_pos
                count += 1
                
        return count
    
    def clear_highlights(self):
        """Clear all highlights from both logs"""
        self.left_text.tag_remove("highlight", "1.0", tk.END)
        self.right_text.tag_remove("highlight", "1.0", tk.END)
        self.left_text.tag_remove("search", "1.0", tk.END)
        self.right_text.tag_remove("search", "1.0", tk.END)
        self.left_text.tag_remove("error", "1.0", tk.END)
        self.right_text.tag_remove("error", "1.0", tk.END)
        self.left_text.tag_remove("error_line", "1.0", tk.END)
        self.right_text.tag_remove("error_line", "1.0", tk.END)
        
        self.status_var.set("All highlights cleared")
    
    def sync_logs_time(self):
        """Sync both logs to display the same timeframe"""
        if not self.left_log_data or not self.right_log_data:
            messagebox.showinfo("Info", "Please load both logs first.")
            return
            
        # Find the earliest common time in both logs
        earliest_left = None
        earliest_right = None
        
        for entry in self.left_log_data:
            if entry['datetime_obj']:
                earliest_left = entry
                break
                
        for entry in self.right_log_data:
            if entry['datetime_obj']:
                earliest_right = entry
                break
        
        if not earliest_left or not earliest_right:
            messagebox.showinfo("Info", "Could not find timestamps in one or both logs.")
            return
            
        # Determine which log starts later and scroll to that point
        if earliest_left['datetime_obj'] > earliest_right['datetime_obj']:
            # Left log starts later, find matching point in right log
            self.highlight_line(self.left_text, earliest_left['line_num'])
            self.sync_by_timestamp("left", "right", earliest_left['line_num'])
        else:
            # Right log starts later, find matching point in left log
            self.highlight_line(self.right_text, earliest_right['line_num'])
            self.sync_by_timestamp("right", "left", earliest_right['line_num'])
        
        self.status_var.set("Logs synchronized by starting time")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        Syslog Analyzer
        
        A tool for comparing and analyzing syslog files
        with synchronized time view and error detection.
        
        Features:
        - Side-by-side log comparison
        - Time synchronization between logs
        - Error detection with keyword highlighting
        - Advanced search and filtering
        """
        messagebox.showinfo("About Syslog Analyzer", about_text.strip())
        
    def show_quick_help(self):
        """Show quick help dialog with keyboard shortcuts"""
        help_text = """
        Keyboard Shortcuts:
        
        File Operations:
        - Ctrl+O: Open left log file
        - Ctrl+Shift+O: Open right log file
        - Ctrl+K: Load error keywords file
        
        Analysis Tools:
        - Ctrl+F: Find in logs
        - Ctrl+E: Highlight errors
        - Ctrl+L: Clear all highlights
        - Ctrl+T: Sync logs by time
        
        Navigation:
        - Click on any line to highlight it
        - Click syncs to the same timestamp in the other log
        
        Tips:
        - Load error keywords before analyzing logs
        - Use filtering to focus on specific issues
        - When comparing, open both logs first
        """
        help_dialog = tk.Toplevel(self)
        help_dialog.title("Quick Help")
        help_dialog.geometry("500x400")
        help_dialog.transient(self)
        
        help_text_widget = scrolledtext.ScrolledText(help_dialog, wrap=tk.WORD)
        help_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        help_text_widget.insert(tk.END, help_text.strip())
        help_text_widget.config(state=tk.DISABLED)
        
        ttk.Button(help_dialog, text="Close", command=help_dialog.destroy).pack(pady=10)

if __name__ == "__main__":
    app = SyslogAnalyzer()
    app.mainloop()