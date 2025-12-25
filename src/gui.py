import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading
import logging
import os
from datetime import datetime

from pcap_parser import PCAPParser
from analyzer import NetworkAnalyzer
from detector import ThreatDetector
from reporter import ForensicReporter


class NetworkInvestigatorGUI:
    """
    Main GUI application for Network Packet Investigator.
    
    Provides an intuitive interface for loading PCAP files, analyzing
    network traffic, detecting threats, and generating forensic reports.
    """
    
    def __init__(self, root):
        """
        Initialize the GUI application.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("◢ NETWORK PACKET INVESTIGATOR ◣ Digital Forensics Suite")
        self.root.geometry("1400x850")
        
        # Dark theme colors
        self.colors = {
            'bg_dark': '#0a0e1a',           # Very dark blue-black
            'bg_medium': '#121829',          # Dark blue-gray
            'bg_light': '#1a2332',           # Lighter blue-gray
            'accent_cyan': '#00d9ff',        # Bright cyan
            'accent_purple': '#a855f7',      # Purple
            'accent_green': '#00ff9d',       # Bright green
            'accent_red': '#ff2e63',         # Bright red
            'accent_orange': '#ff8906',      # Orange
            'text_primary': '#e4e4e7',       # Light gray
            'text_secondary': '#94a3b8',     # Medium gray
            'border': '#2d3748'              # Border gray
        }
        
        # Configure root window
        self.root.configure(bg=self.colors['bg_dark'])
        
        # Data storage
        self.pcap_file = None
        self.packet_info = None
        self.analysis_results = None
        self.detection_results = None
        
        # Setup logging
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Apply custom styles
        self.setup_custom_styles()
        
        # Create UI
        self.create_menu()
        self.create_main_interface()
        
        # Status
        self.is_analyzing = False
    
    def setup_logging(self):
        """Configure logging for the application."""
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join('logs', 'forensic_analysis.log')),
                logging.StreamHandler()
            ]
        )
    
    def setup_custom_styles(self):
        """Configure custom dark theme styles."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure general colors
        style.configure('.', 
                       background=self.colors['bg_medium'],
                       foreground=self.colors['text_primary'],
                       fieldbackground=self.colors['bg_light'],
                       bordercolor=self.colors['border'])
        
        # Frame styles
        style.configure('TFrame', background=self.colors['bg_dark'])
        style.configure('Dark.TFrame', background=self.colors['bg_dark'])
        style.configure('Medium.TFrame', background=self.colors['bg_medium'])
        
        # Label styles
        style.configure('TLabel', 
                       background=self.colors['bg_dark'],
                       foreground=self.colors['text_primary'])
        style.configure('Title.TLabel',
                       background=self.colors['bg_dark'],
                       foreground=self.colors['accent_cyan'],
                       font=('Segoe UI', 14, 'bold'))
        style.configure('Subtitle.TLabel',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['accent_green'],
                       font=('Segoe UI', 11, 'bold'))
        style.configure('Info.TLabel',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['text_secondary'],
                       font=('Consolas', 9))
        
        # Button styles
        style.configure('TButton',
                       background=self.colors['bg_light'],
                       foreground=self.colors['text_primary'],
                       borderwidth=1,
                       focuscolor=self.colors['accent_cyan'],
                       font=('Segoe UI', 9))
        style.map('TButton',
                 background=[('active', self.colors['accent_cyan'])],
                 foreground=[('active', self.colors['bg_dark'])])
        
        style.configure('Accent.TButton',
                       background=self.colors['accent_cyan'],
                       foreground=self.colors['bg_dark'],
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'))
        style.map('Accent.TButton',
                 background=[('active', self.colors['accent_purple'])],
                 foreground=[('active', '#ffffff')])
        
        style.configure('Danger.TButton',
                       background=self.colors['accent_red'],
                       foreground='#ffffff',
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'))
        
        # Entry styles
        style.configure('TEntry',
                       fieldbackground=self.colors['bg_light'],
                       foreground=self.colors['text_primary'],
                       bordercolor=self.colors['border'],
                       insertcolor=self.colors['accent_cyan'])
        
        # Notebook (tabs) styles
        style.configure('TNotebook',
                       background=self.colors['bg_dark'],
                       borderwidth=0)
        style.configure('TNotebook.Tab',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['text_secondary'],
                       borderwidth=0,
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['bg_light'])],
                 foreground=[('selected', self.colors['accent_cyan'])],
                 expand=[('selected', [1, 1, 1, 0])])
        
        # LabelFrame styles
        style.configure('TLabelframe',
                       background=self.colors['bg_medium'],
                       bordercolor=self.colors['border'],
                       borderwidth=1)
        style.configure('TLabelframe.Label',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['accent_cyan'],
                       font=('Segoe UI', 10, 'bold'))
        
        # Progressbar styles
        style.configure('TProgressbar',
                       background=self.colors['accent_cyan'],
                       troughcolor=self.colors['bg_light'],
                       borderwidth=0,
                       thickness=8)
        
        # Treeview styles
        style.configure('Treeview',
                       background=self.colors['bg_light'],
                       foreground=self.colors['text_primary'],
                       fieldbackground=self.colors['bg_light'],
                       borderwidth=0,
                       rowheight=25,
                       font=('Consolas', 9))
        style.configure('Treeview.Heading',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['accent_green'],
                       borderwidth=1,
                       relief='flat',
                       padding=[5, 5],
                       font=('Segoe UI', 10, 'bold'))
        style.map('Treeview.Heading',
                 background=[('active', self.colors['accent_cyan'])],
                 foreground=[('active', self.colors['bg_dark'])])
        style.map('Treeview',
                 background=[('selected', self.colors['accent_purple'])],
                 foreground=[('selected', '#ffffff')])
    
    def create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root,
                         bg=self.colors['bg_medium'],
                         fg=self.colors['text_primary'],
                         activebackground=self.colors['accent_cyan'],
                         activeforeground=self.colors['bg_dark'],
                         borderwidth=0)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0,
                           bg=self.colors['bg_medium'],
                           fg=self.colors['text_primary'],
                           activebackground=self.colors['accent_cyan'],
                           activeforeground=self.colors['bg_dark'])
        menubar.add_cascade(label="◈ FILE", menu=file_menu)
        file_menu.add_command(label="📂 Open PCAP", command=self.load_pcap_file)
        file_menu.add_separator()
        file_menu.add_command(label="📄 Export TXT Report", command=self.export_txt_report)
        file_menu.add_command(label="📊 Export CSV Report", command=self.export_csv_report)
        file_menu.add_command(label="📕 Export PDF Report", command=self.export_pdf_report)
        file_menu.add_separator()
        file_menu.add_command(label="✖ Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0,
                           bg=self.colors['bg_medium'],
                           fg=self.colors['text_primary'],
                           activebackground=self.colors['accent_cyan'],
                           activeforeground=self.colors['bg_dark'])
        menubar.add_cascade(label="◈ HELP", menu=help_menu)
        help_menu.add_command(label="ℹ About", command=self.show_about)
    
    def create_main_interface(self):
        """Create the main user interface."""
        # Header banner
        header_frame = tk.Frame(self.root, bg=self.colors['bg_medium'], height=80)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)
        
        # Title with cyber style
        title_label = ttk.Label(header_frame, 
                               text="◢◤ NETWORK PACKET INVESTIGATOR ◥◣",
                               style='Title.TLabel')
        title_label.pack(side=tk.TOP, pady=(15, 5))
        
        subtitle_label = ttk.Label(header_frame,
                                  text="DIGITAL FORENSICS | THREAT DETECTION | PACKET ANALYSIS",
                                  style='Info.TLabel')
        subtitle_label.pack(side=tk.TOP)
        
        # Control panel frame
        control_frame = tk.Frame(self.root, bg=self.colors['bg_dark'], height=90)
        control_frame.pack(fill=tk.X, side=tk.TOP, padx=15, pady=10)
        control_frame.pack_propagate(False)
        
        # File selection area
        file_frame = tk.Frame(control_frame, bg=self.colors['bg_light'], bd=1, relief=tk.SOLID)
        file_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(file_frame, text="⚡ TARGET FILE:", 
                 style='Subtitle.TLabel').pack(side=tk.LEFT, padx=(15, 10), pady=10)
        
        self.file_entry = tk.Entry(file_frame, 
                                   bg=self.colors['bg_dark'],
                                   fg=self.colors['text_primary'],
                                   insertbackground=self.colors['accent_cyan'],
                                   relief=tk.FLAT,
                                   font=('Consolas', 10))
        self.file_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True)
        
        browse_btn = tk.Button(file_frame, text="⊕ BROWSE",
                              command=self.load_pcap_file,
                              bg=self.colors['accent_cyan'],
                              fg=self.colors['bg_dark'],
                              activebackground=self.colors['accent_purple'],
                              activeforeground='#ffffff',
                              relief=tk.FLAT,
                              font=('Segoe UI', 10, 'bold'),
                              cursor='hand2',
                              padx=20, pady=8)
        browse_btn.pack(side=tk.LEFT, padx=5)
        
        self.analyze_button = tk.Button(file_frame, text="▶ ANALYZE",
                                        command=self.start_analysis,
                                        bg=self.colors['accent_green'],
                                        fg=self.colors['bg_dark'],
                                        activebackground=self.colors['accent_purple'],
                                        activeforeground='#ffffff',
                                        relief=tk.FLAT,
                                        font=('Segoe UI', 10, 'bold'),
                                        cursor='hand2',
                                        padx=25, pady=8)
        self.analyze_button.pack(side=tk.LEFT, padx=5)
        
        # Progress area
        progress_container = tk.Frame(self.root, bg=self.colors['bg_dark'])
        progress_container.pack(fill=tk.X, side=tk.TOP, padx=15, pady=(0, 10))
        
        self.progress_label = tk.Label(progress_container,
                                      text="⬢ STATUS: READY",
                                      bg=self.colors['bg_dark'],
                                      fg=self.colors['accent_green'],
                                      font=('Consolas', 10, 'bold'))
        self.progress_label.pack(side=tk.LEFT, padx=10)
        
        self.progress_bar = ttk.Progressbar(progress_container, mode='determinate', length=400)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        
        # Main content area with notebook
        content_frame = tk.Frame(self.root, bg=self.colors['bg_dark'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_overview_tab()
        self.create_dns_tab()
        self.create_http_tab()
        self.create_tcp_tab()
        self.create_findings_tab()
        self.create_charts_tab()
        
        # Status bar with cyber style
        status_frame = tk.Frame(self.root, bg=self.colors['bg_medium'], height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        self.status_bar = tk.Label(status_frame, 
                                   text="⬢ READY | AWAITING INPUT",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['text_secondary'],
                                   anchor=tk.W,
                                   font=('Consolas', 9),
                                   padx=15)
        self.status_bar.pack(fill=tk.BOTH)
    
    def create_overview_tab(self):
        """Create the overview/summary tab."""
        tab = tk.Frame(self.notebook, bg=self.colors['bg_dark'])
        self.notebook.add(tab, text="⬢ OVERVIEW")
        
        # Tool information frame
        info_frame = tk.LabelFrame(tab, 
                                  text=" ⚡ SYSTEM INFORMATION ",
                                  bg=self.colors['bg_medium'],
                                  fg=self.colors['accent_cyan'],
                                  font=('Segoe UI', 11, 'bold'),
                                  bd=2,
                                  relief=tk.GROOVE)
        info_frame.pack(fill=tk.BOTH, padx=15, pady=15)
        
        tool_info = """◈ NETWORK PACKET INVESTIGATOR - DIGITAL FORENSICS SUITE

⬢ MISSION:
Comprehensive forensic analysis of network packet captures to identify security threats,
suspicious activities, and indicators of compromise (IOCs).

⬢ CAPABILITIES:
• Advanced PCAP file parsing and analysis
• Real-time threat detection algorithms
• DNS tunneling and exfiltration detection  
• HTTP/HTTPS traffic inspection
• TCP session analysis and reconstruction
• Automated IOC extraction
• Multi-format forensic reporting (TXT/CSV/PDF)

⬢ USE CASES:
Incident response, malware analysis, data exfiltration detection, phishing investigations,
network forensics, security monitoring, and threat hunting operations."""
        
        info_text = tk.Text(info_frame, 
                           height=15,
                           wrap=tk.WORD,
                           bg=self.colors['bg_light'],
                           fg=self.colors['text_primary'],
                           insertbackground=self.colors['accent_cyan'],
                           relief=tk.FLAT,
                           font=('Consolas', 9),
                           padx=15,
                           pady=10)
        info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        info_text.insert(1.0, tool_info)
        info_text.config(state=tk.DISABLED)
        
        # Summary frame
        summary_frame = tk.LabelFrame(tab,
                                     text=" 📊 ANALYSIS RESULTS ",
                                     bg=self.colors['bg_medium'],
                                     fg=self.colors['accent_green'],
                                     font=('Segoe UI', 11, 'bold'),
                                     bd=2,
                                     relief=tk.GROOVE)
        summary_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame,
                                                      wrap=tk.WORD,
                                                      bg=self.colors['bg_light'],
                                                      fg=self.colors['text_primary'],
                                                      insertbackground=self.colors['accent_cyan'],
                                                      relief=tk.FLAT,
                                                      font=('Consolas', 9),
                                                      padx=15,
                                                      pady=10)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_dns_tab(self):
        """Create the DNS analysis tab."""
        tab = tk.Frame(self.notebook, bg=self.colors['bg_dark'])
        self.notebook.add(tab, text="⬢ DNS")
        
        # DNS statistics
        stats_frame = tk.LabelFrame(tab,
                                   text=" 🔍 DNS STATISTICS ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_cyan'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        stats_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.dns_stats_text = tk.Text(stats_frame,
                                      height=5,
                                      wrap=tk.WORD,
                                      bg=self.colors['bg_light'],
                                      fg=self.colors['text_primary'],
                                      relief=tk.FLAT,
                                      font=('Consolas', 9),
                                      padx=10,
                                      pady=8)
        self.dns_stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # DNS queries table
        table_frame = tk.LabelFrame(tab,
                                   text=" 📡 TOP DNS QUERIES ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_green'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        # Create treeview for DNS data
        tree_container = tk.Frame(table_frame, bg=self.colors['bg_light'])
        tree_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Domain", "Query Count", "Status")
        self.dns_tree = ttk.Treeview(tree_container, columns=columns, show='headings', height=15)
        
        # Configure columns with proper alignment
        self.dns_tree.heading("Domain", text="Domain", anchor=tk.W)
        self.dns_tree.heading("Query Count", text="Query Count", anchor=tk.CENTER)
        self.dns_tree.heading("Status", text="Status", anchor=tk.CENTER)
        
        self.dns_tree.column("Domain", width=500, anchor=tk.W, stretch=True)
        self.dns_tree.column("Query Count", width=150, anchor=tk.CENTER, stretch=False)
        self.dns_tree.column("Status", width=200, anchor=tk.CENTER, stretch=False)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.dns_tree.yview)
        self.dns_tree.configure(yscroll=scrollbar.set)
        
        self.dns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_http_tab(self):
        """Create the HTTP analysis tab."""
        tab = tk.Frame(self.notebook, bg=self.colors['bg_dark'])
        self.notebook.add(tab, text="⬢ HTTP")
        
        # HTTP statistics
        stats_frame = tk.LabelFrame(tab,
                                   text=" 🌐 HTTP STATISTICS ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_cyan'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        stats_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.http_stats_text = tk.Text(stats_frame,
                                       height=5,
                                       wrap=tk.WORD,
                                       bg=self.colors['bg_light'],
                                       fg=self.colors['text_primary'],
                                       relief=tk.FLAT,
                                       font=('Consolas', 9),
                                       padx=10,
                                       pady=8)
        self.http_stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # HTTP requests table
        table_frame = tk.LabelFrame(tab,
                                   text=" 📨 HTTP REQUESTS ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_green'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        tree_container = tk.Frame(table_frame, bg=self.colors['bg_light'])
        tree_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Method", "Host", "URL")
        self.http_tree = ttk.Treeview(tree_container, columns=columns, show='headings', height=15)
        
        # Configure columns with proper alignment
        self.http_tree.heading("Method", text="Method", anchor=tk.CENTER)
        self.http_tree.heading("Host", text="Host", anchor=tk.W)
        self.http_tree.heading("URL", text="URL", anchor=tk.W)
        
        self.http_tree.column("Method", width=80, anchor=tk.CENTER, stretch=False)
        self.http_tree.column("Host", width=300, anchor=tk.W, stretch=False)
        self.http_tree.column("URL", width=600, anchor=tk.W, stretch=True)
        
        scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.http_tree.yview)
        self.http_tree.configure(yscroll=scrollbar.set)
        
        self.http_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_tcp_tab(self):
        """Create the TCP analysis tab."""
        tab = tk.Frame(self.notebook, bg=self.colors['bg_dark'])
        self.notebook.add(tab, text="⬢ TCP")
        
        # TCP statistics
        stats_frame = tk.LabelFrame(tab,
                                   text=" 🔌 TCP STATISTICS ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_cyan'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        stats_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.tcp_stats_text = tk.Text(stats_frame,
                                      height=5,
                                      wrap=tk.WORD,
                                      bg=self.colors['bg_light'],
                                      fg=self.colors['text_primary'],
                                      relief=tk.FLAT,
                                      font=('Consolas', 9),
                                      padx=10,
                                      pady=8)
        self.tcp_stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # TCP connections table
        table_frame = tk.LabelFrame(tab,
                                   text=" 🔗 TCP CONNECTIONS ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_green'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        tree_container = tk.Frame(table_frame, bg=self.colors['bg_light'])
        tree_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Connection", "Packets", "Bytes")
        self.tcp_tree = ttk.Treeview(tree_container, columns=columns, show='headings', height=15)
        
        # Configure columns with proper alignment
        self.tcp_tree.heading("Connection", text="Connection", anchor=tk.W)
        self.tcp_tree.heading("Packets", text="Packets", anchor=tk.CENTER)
        self.tcp_tree.heading("Bytes", text="Bytes", anchor=tk.CENTER)
        
        self.tcp_tree.column("Connection", width=600, anchor=tk.W, stretch=True)
        self.tcp_tree.column("Packets", width=150, anchor=tk.CENTER, stretch=False)
        self.tcp_tree.column("Bytes", width=200, anchor=tk.CENTER, stretch=False)
        
        scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tcp_tree.yview)
        self.tcp_tree.configure(yscroll=scrollbar.set)
        
        self.tcp_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_findings_tab(self):
        """Create the security findings tab."""
        tab = tk.Frame(self.notebook, bg=self.colors['bg_dark'])
        self.notebook.add(tab, text="⚠ FINDINGS")
        
        # Findings summary
        summary_frame = tk.LabelFrame(tab,
                                     text=" 🚨 THREAT SUMMARY ",
                                     bg=self.colors['bg_medium'],
                                     fg=self.colors['accent_red'],
                                     font=('Segoe UI', 11, 'bold'),
                                     bd=2,
                                     relief=tk.GROOVE)
        summary_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.findings_summary_text = tk.Text(summary_frame,
                                            height=4,
                                            wrap=tk.WORD,
                                            bg=self.colors['bg_light'],
                                            fg=self.colors['text_primary'],
                                            relief=tk.FLAT,
                                            font=('Consolas', 9),
                                            padx=10,
                                            pady=8)
        self.findings_summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Findings table
        table_frame = tk.LabelFrame(tab,
                                   text=" ⚡ DETAILED FINDINGS ",
                                   bg=self.colors['bg_medium'],
                                   fg=self.colors['accent_orange'],
                                   font=('Segoe UI', 11, 'bold'),
                                   bd=2,
                                   relief=tk.GROOVE)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        tree_container = tk.Frame(table_frame, bg=self.colors['bg_light'])
        tree_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Severity", "Type", "Description")
        self.findings_tree = ttk.Treeview(tree_container, columns=columns, show='headings', height=15)
        
        # Configure columns with proper alignment
        self.findings_tree.heading("Severity", text="Severity", anchor=tk.CENTER)
        self.findings_tree.heading("Type", text="Type", anchor=tk.W)
        self.findings_tree.heading("Description", text="Description", anchor=tk.W)
        
        self.findings_tree.column("Severity", width=100, anchor=tk.CENTER, stretch=False)
        self.findings_tree.column("Type", width=250, anchor=tk.W, stretch=False)
        self.findings_tree.column("Description", width=700, anchor=tk.W, stretch=True)
        
        # Configure tags for severity coloring
        self.findings_tree.tag_configure('HIGH', foreground=self.colors['accent_red'])
        self.findings_tree.tag_configure('MEDIUM', foreground=self.colors['accent_orange'])
        self.findings_tree.tag_configure('LOW', foreground=self.colors['accent_cyan'])
        
        scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.findings_tree.yview)
        self.findings_tree.configure(yscroll=scrollbar.set)
        
        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to show details
        self.findings_tree.bind('<Double-1>', self.show_finding_details)
    
    def create_charts_tab(self):
        """Create the charts/visualization tab."""
        tab = tk.Frame(self.notebook, bg=self.colors['bg_dark'])
        self.notebook.add(tab, text="⬢ CHARTS")
        
        # Create frame for charts
        self.charts_frame = tk.Frame(tab, bg=self.colors['bg_medium'])
        self.charts_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def load_pcap_file(self):
        """Open file dialog to select PCAP file."""
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("PCAP files", "*.pcap"),
                ("PCAPNG files", "*.pcapng"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            self.pcap_file = filename
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
            self.update_status(f"⬢ LOADED: {os.path.basename(filename)}")
            self.logger.info(f"PCAP file selected: {filename}")
    
    def start_analysis(self):
        """Start the forensic analysis in a separate thread."""
        if not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file first.")
            return
        
        if self.is_analyzing:
            messagebox.showwarning("Warning", "Analysis is already in progress.")
            return
        
        # Disable analyze button
        self.analyze_button.config(state=tk.DISABLED)
        self.is_analyzing = True
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=self.run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def run_analysis(self):
        """Execute the complete forensic analysis."""
        try:
            # Phase 1: Load PCAP
            self.update_progress(10, "Loading PCAP file...")
            parser = PCAPParser(self.pcap_file)
            
            if not parser.load_pcap(self.update_progress):
                self.show_error("Failed to load PCAP file.")
                return
            
            # Phase 2: Extract packet information
            self.update_progress(30, "Extracting packet information...")
            self.packet_info = parser.extract_packet_info(self.update_progress)
            
            # Phase 3: Run analysis
            self.update_progress(60, "Analyzing network traffic...")
            analyzer = NetworkAnalyzer(self.packet_info)
            self.analysis_results = analyzer.run_full_analysis()
            
            # Phase 4: Run threat detection
            self.update_progress(80, "Detecting threats...")
            safe_domains_file = os.path.join('data', 'safe_domains.txt')
            detector = ThreatDetector(self.analysis_results, safe_domains_file)
            self.detection_results = detector.run_all_detections()
            
            # Phase 5: Update UI
            self.update_progress(95, "Updating display...")
            self.root.after(0, self.display_results)
            
            self.update_progress(100, "Analysis complete!")
            self.logger.info("Forensic analysis completed successfully")
            
        except Exception as e:
            self.logger.error(f"Analysis error: {str(e)}")
            self.show_error(f"Analysis failed: {str(e)}")
        finally:
            self.is_analyzing = False
            self.root.after(0, lambda: self.analyze_button.config(state=tk.NORMAL))
    
    def display_results(self):
        """Display analysis results in the GUI."""
        try:
            # Update overview
            self.update_overview_tab()
            
            # Update DNS tab
            self.update_dns_tab()
            
            # Update HTTP tab
            self.update_http_tab()
            
            # Update TCP tab
            self.update_tcp_tab()
            
            # Update findings tab
            self.update_findings_tab()
            
            # Update charts
            self.update_charts()
            
            self.update_status("⬢ ANALYSIS COMPLETE | RESULTS READY FOR REVIEW")
            messagebox.showinfo("Success", "Forensic analysis completed successfully!")
            
        except Exception as e:
            self.logger.error(f"Error displaying results: {str(e)}")
            self.show_error(f"Failed to display results: {str(e)}")
    
    def update_overview_tab(self):
        """Update the overview tab with summary information."""
        if not self.analysis_results:
            return
        
        summary = "FORENSIC ANALYSIS SUMMARY\n"
        summary += "=" * 60 + "\n\n"
        
        proto_analysis = self.analysis_results.get('protocol_analysis', {})
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        http_analysis = self.analysis_results.get('http_analysis', {})
        tcp_analysis = self.analysis_results.get('tcp_analysis', {})
        
        summary += f"Total Packets: {proto_analysis.get('total_packets', 0):,}\n"
        summary += f"DNS Queries: {dns_analysis.get('total_queries', 0):,}\n"
        summary += f"Unique Domains: {dns_analysis.get('unique_domains', 0):,}\n"
        summary += f"HTTP Requests: {http_analysis.get('total_requests', 0):,}\n"
        summary += f"TCP Sessions: {tcp_analysis.get('total_sessions', 0):,}\n"
        summary += f"Data Transferred: {tcp_analysis.get('total_data_transferred', 0):,} bytes\n\n"
        
        if self.detection_results:
            summary += "THREAT DETECTION RESULTS\n"
            summary += "-" * 60 + "\n"
            summary += f"Total Findings: {self.detection_results.get('total_findings', 0)}\n"
            summary += f"High Severity: {self.detection_results.get('high_severity_count', 0)}\n"
            summary += f"Medium Severity: {self.detection_results.get('medium_severity_count', 0)}\n"
            summary += f"Low Severity: {self.detection_results.get('low_severity_count', 0)}\n"
        
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, summary)
    
    def update_dns_tab(self):
        """Update the DNS analysis tab."""
        if not self.analysis_results:
            return
        
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        
        # Update statistics
        stats = f"Total DNS Queries: {dns_analysis.get('total_queries', 0):,}\n"
        stats += f"Unique Domains: {dns_analysis.get('unique_domains', 0):,}\n"
        stats += f"Domains with Excessive Queries: {len(dns_analysis.get('excessive_queries', {}))}\n"
        
        self.dns_stats_text.delete(1.0, tk.END)
        self.dns_stats_text.insert(1.0, stats)
        self.dns_stats_text.config(state=tk.DISABLED)
        
        # Clear existing data
        for item in self.dns_tree.get_children():
            self.dns_tree.delete(item)
        
        # Add top domains
        top_domains = dns_analysis.get('top_domains', [])[:50]
        excessive = dns_analysis.get('excessive_queries', {})
        
        for domain, count in top_domains:
            status = "EXCESSIVE" if domain in excessive else "Normal"
            tag = 'excessive' if domain in excessive else ''
            self.dns_tree.insert('', tk.END, values=(domain, count, status), tags=(tag,))
        
        self.dns_tree.tag_configure('excessive', foreground='red')
    
    def update_http_tab(self):
        """Update the HTTP analysis tab."""
        if not self.analysis_results:
            return
        
        http_analysis = self.analysis_results.get('http_analysis', {})
        
        # Update statistics
        stats = f"Total HTTP Requests: {http_analysis.get('total_requests', 0):,}\n"
        stats += f"Unique URLs: {http_analysis.get('unique_urls', 0):,}\n"
        stats += f"Unique Hosts: {http_analysis.get('unique_hosts', 0):,}\n"
        stats += f"POST Requests: {len(http_analysis.get('post_requests', []))}\n"
        
        self.http_stats_text.delete(1.0, tk.END)
        self.http_stats_text.insert(1.0, stats)
        self.http_stats_text.config(state=tk.DISABLED)
        
        # Clear existing data
        for item in self.http_tree.get_children():
            self.http_tree.delete(item)
        
        # Add HTTP requests (limited to first 100)
        requests = http_analysis.get('raw_requests', [])[:100]
        for req in requests:
            self.http_tree.insert('', tk.END, 
                                 values=(req['method'], req['host'], req['url']))
    
    def update_tcp_tab(self):
        """Update the TCP analysis tab."""
        if not self.analysis_results:
            return
        
        tcp_analysis = self.analysis_results.get('tcp_analysis', {})
        
        # Update statistics
        stats = f"Total TCP Sessions: {tcp_analysis.get('total_sessions', 0):,}\n"
        stats += f"Unique Connections: {tcp_analysis.get('unique_connections', 0):,}\n"
        stats += f"Total Data Transferred: {tcp_analysis.get('total_data_transferred', 0):,} bytes\n"
        
        self.tcp_stats_text.delete(1.0, tk.END)
        self.tcp_stats_text.insert(1.0, stats)
        self.tcp_stats_text.config(state=tk.DISABLED)
        
        # Clear existing data
        for item in self.tcp_tree.get_children():
            self.tcp_tree.delete(item)
        
        # Add top connections
        top_connections = tcp_analysis.get('top_connections', [])[:50]
        for conn, stats in top_connections:
            self.tcp_tree.insert('', tk.END,
                               values=(conn, stats['packet_count'], 
                                      f"{stats['total_bytes']:,}"))
    
    def update_findings_tab(self):
        """Update the security findings tab."""
        if not self.detection_results:
            return
        
        # Update summary
        summary = f"Total Findings: {self.detection_results.get('total_findings', 0)}\n"
        summary += f"High Severity: {self.detection_results.get('high_severity_count', 0)}\n"
        summary += f"Medium Severity: {self.detection_results.get('medium_severity_count', 0)}\n"
        summary += f"Low Severity: {self.detection_results.get('low_severity_count', 0)}\n"
        
        self.findings_summary_text.delete(1.0, tk.END)
        self.findings_summary_text.insert(1.0, summary)
        self.findings_summary_text.config(state=tk.DISABLED)
        
        # Clear existing data
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        
        # Add findings
        findings = self.detection_results.get('all_findings', [])
        for finding in findings:
            self.findings_tree.insert('', tk.END,
                                     values=(finding['severity'], 
                                            finding['type'],
                                            finding['description']),
                                     tags=(finding['severity'],))
    
    def update_charts(self):
        """Create and display charts."""
        # Clear existing charts
        for widget in self.charts_frame.winfo_children():
            widget.destroy()
        
        if not self.analysis_results:
            return
        
        # Create figure with dark theme
        plt.style.use('dark_background')
        fig = Figure(figsize=(12, 8), dpi=100, facecolor=self.colors['bg_medium'])
        
        # Protocol distribution pie chart
        ax1 = fig.add_subplot(221, facecolor=self.colors['bg_light'])
        proto_analysis = self.analysis_results.get('protocol_analysis', {})
        protocol_counts = proto_analysis.get('protocol_counts', {})
        
        if protocol_counts:
            labels = list(protocol_counts.keys())
            sizes = list(protocol_counts.values())
            colors_pie = [self.colors['accent_cyan'], self.colors['accent_purple'], 
                         self.colors['accent_green'], self.colors['accent_orange']]
            ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, 
                   colors=colors_pie, textprops={'color': self.colors['text_primary']})
            ax1.set_title('PROTOCOL DISTRIBUTION', color=self.colors['accent_cyan'], 
                         fontweight='bold', fontsize=11)
        
        # Top domains bar chart
        ax2 = fig.add_subplot(222, facecolor=self.colors['bg_light'])
        dns_analysis = self.analysis_results.get('dns_analysis', {})
        top_domains = dns_analysis.get('top_domains', [])[:10]
        
        if top_domains:
            domains = [d[0][:20] for d in top_domains]  # Truncate long domains
            counts = [d[1] for d in top_domains]
            ax2.barh(domains, counts, color=self.colors['accent_green'])
            ax2.set_xlabel('Query Count', color=self.colors['text_primary'])
            ax2.set_title('TOP 10 DNS QUERIES', color=self.colors['accent_cyan'], 
                         fontweight='bold', fontsize=11)
            ax2.tick_params(colors=self.colors['text_secondary'])
            ax2.invert_yaxis()
        
        # Findings by severity bar chart
        ax3 = fig.add_subplot(223, facecolor=self.colors['bg_light'])
        if self.detection_results:
            findings_by_sev = self.detection_results.get('findings_by_severity', {})
            severities = ['HIGH', 'MEDIUM', 'LOW']
            counts = [len(findings_by_sev.get(sev, [])) for sev in severities]
            colors_bar = [self.colors['accent_red'], self.colors['accent_orange'], 
                         self.colors['accent_cyan']]
            ax3.bar(severities, counts, color=colors_bar)
            ax3.set_ylabel('Count', color=self.colors['text_primary'])
            ax3.set_title('FINDINGS BY SEVERITY', color=self.colors['accent_cyan'], 
                         fontweight='bold', fontsize=11)
            ax3.tick_params(colors=self.colors['text_secondary'])
        
        # HTTP methods pie chart
        ax4 = fig.add_subplot(224, facecolor=self.colors['bg_light'])
        http_analysis = self.analysis_results.get('http_analysis', {})
        methods = http_analysis.get('method_distribution', {})
        
        if methods:
            labels = list(methods.keys())
            sizes = list(methods.values())
            colors_pie2 = [self.colors['accent_orange'], self.colors['accent_purple'], 
                          self.colors['accent_cyan'], self.colors['accent_green']]
            ax4.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90,
                   colors=colors_pie2, textprops={'color': self.colors['text_primary']})
            ax4.set_title('HTTP METHODS', color=self.colors['accent_cyan'], 
                         fontweight='bold', fontsize=11)
        
        fig.tight_layout(pad=2.0)
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.charts_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def show_finding_details(self, event):
        """Show detailed information for a finding."""
        selection = self.findings_tree.selection()
        if not selection:
            return
        
        item = self.findings_tree.item(selection[0])
        values = item['values']
        
        if not values:
            return
        
        # Find the full finding
        findings = self.detection_results.get('all_findings', [])
        finding = None
        for f in findings:
            if f['description'] == values[2]:
                finding = f
                break
        
        if finding:
            details = f"Finding Details\n{'=' * 60}\n\n"
            for key, value in finding.items():
                if isinstance(value, list) and len(value) > 10:
                    details += f"{key}: {len(value)} items\n"
                elif isinstance(value, list):
                    details += f"{key}:\n"
                    for item in value:
                        details += f"  - {item}\n"
                else:
                    details += f"{key}: {value}\n"
            
            # Show in a new window
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Finding Details")
            detail_window.geometry("600x400")
            
            text_widget = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert(1.0, details)
            text_widget.config(state=tk.DISABLED)
    
    def export_txt_report(self):
        """Export analysis results to TXT report."""
        if not self.analysis_results or not self.detection_results:
            messagebox.showwarning("Warning", "No analysis results to export. Please run analysis first.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save TXT Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                reporter = ForensicReporter(self.analysis_results, self.detection_results)
                if reporter.generate_txt_report(filename):
                    messagebox.showinfo("Success", f"Report exported to:\n{filename}")
                    self.logger.info(f"TXT report exported: {filename}")
                else:
                    messagebox.showerror("Error", "Failed to export report.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                self.logger.error(f"Export error: {str(e)}")
    
    def export_csv_report(self):
        """Export findings to CSV file."""
        if not self.detection_results:
            messagebox.showwarning("Warning", "No findings to export. Please run analysis first.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save CSV Report",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                reporter = ForensicReporter(self.analysis_results, self.detection_results)
                if reporter.export_findings_to_csv(filename):
                    messagebox.showinfo("Success", f"CSV exported to:\n{filename}")
                    self.logger.info(f"CSV report exported: {filename}")
                else:
                    messagebox.showerror("Error", "Failed to export CSV.")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
                self.logger.error(f"Export error: {str(e)}")
    
    def export_pdf_report(self):
        """Export analysis results to PDF report with case information."""
        if not self.analysis_results or not self.detection_results:
            messagebox.showwarning("Warning", "No analysis results to export. Please run analysis first.")
            return
        
        # Create dialog to collect case information
        case_dialog = tk.Toplevel(self.root)
        case_dialog.title("PDF Report - Case Information")
        case_dialog.geometry("500x350")
        case_dialog.resizable(False, False)
        case_dialog.transient(self.root)
        case_dialog.grab_set()
        
        # Center the dialog
        case_dialog.update_idletasks()
        x = (case_dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (case_dialog.winfo_screenheight() // 2) - (350 // 2)
        case_dialog.geometry(f'500x350+{x}+{y}')
        
        # Header
        header_frame = ttk.Frame(case_dialog, padding="10")
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="Enter Case Information for PDF Report", 
                 font=('Arial', 12, 'bold')).pack()
        
        # Form frame
        form_frame = ttk.Frame(case_dialog, padding="20")
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        # Case Number
        ttk.Label(form_frame, text="Case/Ticket Number:").grid(row=0, column=0, sticky=tk.W, pady=5)
        case_number_entry = ttk.Entry(form_frame, width=40)
        case_number_entry.grid(row=0, column=1, pady=5, padx=5)
        case_number_entry.insert(0, "CASE-2024-001")
        
        # Investigator
        ttk.Label(form_frame, text="Investigator Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        investigator_entry = ttk.Entry(form_frame, width=40)
        investigator_entry.grid(row=1, column=1, pady=5, padx=5)
        investigator_entry.insert(0, "Forensic Analyst")
        
        # Date
        ttk.Label(form_frame, text="Investigation Date:").grid(row=2, column=0, sticky=tk.W, pady=5)
        date_entry = ttk.Entry(form_frame, width=40)
        date_entry.grid(row=2, column=1, pady=5, padx=5)
        from datetime import datetime
        date_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))
        
        # Description
        ttk.Label(form_frame, text="Case Description:").grid(row=3, column=0, sticky=tk.W + tk.N, pady=5)
        desc_text = tk.Text(form_frame, width=40, height=6, wrap=tk.WORD)
        desc_text.grid(row=3, column=1, pady=5, padx=5)
        desc_text.insert("1.0", "Network forensic analysis investigating potential security incident. "
                        "Analyzing captured network traffic for indicators of compromise and suspicious activities.")
        
        # Variable to store result
        case_info = {}
        
        def generate_pdf():
            """Generate PDF with collected case information."""
            case_info['case_number'] = case_number_entry.get().strip()
            case_info['investigator'] = investigator_entry.get().strip()
            case_info['date'] = date_entry.get().strip()
            case_info['description'] = desc_text.get("1.0", tk.END).strip()
            
            case_dialog.destroy()
            
            # Now open file save dialog
            filename = filedialog.asksaveasfilename(
                title="Save PDF Report",
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
            )
            
            if filename:
                try:
                    # Show progress
                    progress_label = ttk.Label(self.root, text="Generating PDF report...", 
                                             font=('Arial', 10))
                    progress_label.pack(pady=10)
                    self.root.update()
                    
                    reporter = ForensicReporter(self.analysis_results, self.detection_results)
                    
                    # Generate PDF with case info
                    if reporter.generate_pdf_report(filename, case_info):
                        progress_label.destroy()
                        messagebox.showinfo("Success", f"PDF Report exported to:\n{filename}")
                        self.logger.info(f"PDF report exported: {filename}")
                    else:
                        progress_label.destroy()
                        messagebox.showerror("Error", "Failed to export PDF report.\n\n"
                                           "Make sure reportlab is installed:\npip install reportlab")
                except Exception as e:
                    if 'progress_label' in locals():
                        progress_label.destroy()
                    messagebox.showerror("Error", f"Export failed: {str(e)}\n\n"
                                       "Make sure reportlab is installed:\npip install reportlab")
                    self.logger.error(f"PDF export error: {str(e)}")
        
        # Buttons frame
        button_frame = ttk.Frame(case_dialog, padding="10")
        button_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ttk.Button(button_frame, text="Generate PDF", command=generate_pdf, 
                  style='Accent.TButton').pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=case_dialog.destroy).pack(side=tk.RIGHT)
    
    def show_about(self):
        """Show about dialog."""
        about_text = """Network Packet Investigator
Digital Forensics Tool

Version: 1.0.0
Date: December 23, 2025

A comprehensive Python-based forensic tool for analyzing
network packet captures to detect suspicious activities.

Features:
- PCAP file analysis
- DNS/HTTP/TCP session analysis
- Threat detection algorithms
- Forensic reporting

Developed by: Digital Forensics Team
"""
        messagebox.showinfo("About", about_text)
    
    def update_progress(self, value, message):
        """Update progress bar and message."""
        self.root.after(0, lambda: self.progress_bar.config(value=value))
        self.root.after(0, lambda: self.progress_label.config(text=f"⬢ STATUS: {message}"))
        self.root.after(0, lambda: self.update_status(f"⬢ {message}"))
    
    def update_status(self, message):
        """Update status bar."""
        self.status_bar.config(text=message)
    
    def show_error(self, message):
        """Show error message."""
        self.root.after(0, lambda: messagebox.showerror("Error", message))


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    app = NetworkInvestigatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
