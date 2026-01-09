import sys
import os
import traceback
from datetime import datetime
import random
import requests
import json
import time
if sys.version_info < (3, 7):
    print("Error: Python 3.7 or newer is required")
    print(f"Current version: {sys.version}")
    input("Press Enter to exit...")
    sys.exit(1)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
except ImportError as e:
    print(f"Error: Cannot import tkinter: {e}")
    print("Make sure Python is installed with tkinter")
    input("Press Enter to exit...")
    sys.exit(1)
try:
    import threading
except ImportError as e:
    print(f"Error: Cannot import system modules: {e}")
    input("Press Enter to exit...")
    sys.exit(1)
try:
    from port_scanner import PortScanner
    from cms_scanner import CMSScanner
    from report_generator import ReportGenerator
except ImportError as e:
    print(f"Error: Cannot import scanner modules: {e}")
    print("Make sure all files are in the same directory")
    print("Missing files:")
    missing_files = []
    for module in ['port_scanner.py', 'cms_scanner.py', 'report_generator.py']:
        if not os.path.exists(module):
            missing_files.append(module)
    if missing_files:
        for file in missing_files:
            print(f"  - {file}")
    input("Press Enter to exit...")
    sys.exit(1)
BG_COLOR = "#0a0a0a"
FG_COLOR = "#e0d7ff"
ACCENT_COLOR = "#a259f7"
FRAME_COLOR = "#1a1026"
BUTTON_BG = "#2d1846"
BUTTON_FG = "#e0d7ff"
FONT_MONO = ("Consolas", 11)
FONT_HEADER = ("Consolas", 16, "bold")
FONT_ASCII = ("Consolas", 10, "bold")
ASCII_ART = """
      .-\"\"\"\"-.        | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |
     / -   -  \\       |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
    |  .-. .- |       | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 |
    |  \\o| |o (      |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
    \\     ^    /      | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 |
     '.  )--' /       |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
       '-...-'        | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 |
"""
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
class HackerStyle(ttk.Style):
    def __init__(self):
        super().__init__()
        self.theme_use('clam')
        self.configure('.',
            background=BG_COLOR,
            foreground=FG_COLOR,
            font=FONT_MONO,
            borderwidth=0,
            relief='flat')
        self.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR, font=FONT_MONO)
        self.configure('TButton',
            background=BUTTON_BG,
            foreground=BUTTON_FG,
            font=FONT_MONO,
            borderwidth=1,
            focusthickness=3,
            focuscolor=ACCENT_COLOR,
            relief="flat",
            highlightbackground=BG_COLOR,
            highlightcolor=BG_COLOR
        )
        self.map('TButton',
            background=[
                ('active', BUTTON_BG),
                ('pressed', BUTTON_BG),
                ('focus', BUTTON_BG),
                ('!disabled', BUTTON_BG)
            ],
            foreground=[
                ('active', BUTTON_FG),
                ('pressed', BUTTON_FG),
                ('focus', BUTTON_FG),
                ('!disabled', BUTTON_FG)
            ]
        )
        self.configure('TFrame', background=BG_COLOR)
        self.configure('TLabelframe', background=FRAME_COLOR, foreground=ACCENT_COLOR, font=FONT_MONO, borderwidth=2)
        self.configure('TLabelframe.Label', background=FRAME_COLOR, foreground=ACCENT_COLOR, font=FONT_MONO)
        self.configure('TNotebook', background=BG_COLOR, borderwidth=0)
        self.configure('TNotebook.Tab', background=FRAME_COLOR, foreground=ACCENT_COLOR, font=FONT_MONO)
        self.map('TNotebook.Tab', background=[('selected', ACCENT_COLOR)], foreground=[('selected', BG_COLOR)])
        self.configure('TRadiobutton',
            background=BG_COLOR,
            foreground=FG_COLOR,
            font=FONT_MONO,
            indicatorcolor=ACCENT_COLOR,
            relief="flat",
            highlightbackground=BG_COLOR,
            highlightcolor=BG_COLOR
        )
        self.map('TRadiobutton',
            background=[
                ('active', BG_COLOR),
                ('selected', BG_COLOR),
                ('!disabled', BG_COLOR)
            ],
            foreground=[
                ('active', FG_COLOR),
                ('selected', FG_COLOR),
                ('!disabled', FG_COLOR)
            ]
        )
        self.configure('TCheckbutton',
            background=BG_COLOR,
            foreground=FG_COLOR,
            font=FONT_MONO,
            indicatorcolor=ACCENT_COLOR,
            relief="flat",
            highlightbackground=BG_COLOR,
            highlightcolor=BG_COLOR
        )
        self.map('TCheckbutton',
            background=[
                ('active', BG_COLOR),
                ('selected', BG_COLOR),
                ('!disabled', BG_COLOR)
            ],
            foreground=[
                ('active', FG_COLOR),
                ('selected', FG_COLOR),
                ('!disabled', FG_COLOR)
            ]
        )
class MatrixRain(tk.Canvas):
    def __init__(self, master, width, height, **kwargs):
        super().__init__(master, **kwargs)
        self.config(width=width, height=height, bg=BG_COLOR, highlightthickness=0)
        self.width = width
        self.height = height
        self.columns = width // 16
        self.drops = [random.randint(0, height // 16) for _ in range(self.columns)]
        self.text_color = ACCENT_COLOR
        self.font = ("Consolas", 14, "bold")
        self.after_id = None
        self.running = True
        self.animate()
    def animate(self):
        if not self.running:
            return
        self.delete("all")
        for i in range(self.columns):
            char = random.choice(["0", "1"])
            x = i * 16
            y = self.drops[i] * 16
            self.create_text(x, y, text=char, fill=self.text_color, font=self.font, anchor="nw")
            if y > self.height and random.random() > 0.975:
                self.drops[i] = 0
            else:
                self.drops[i] += 1
        self.after_id = self.after(500, self.animate)
    def stop(self):
        self.running = False
        if self.after_id:
            self.after_cancel(self.after_id)
class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ShieldEye – Automated Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.configure(bg=BG_COLOR)
        HackerStyle()
        self.matrix_rain = MatrixRain(self.root, 950, 750)
        self.matrix_rain.place(relx=0, rely=0, relwidth=1, relheight=1)
        import os
        from tkinter import PhotoImage
        logo_frame = tk.Frame(self.root, bg=BG_COLOR)
        logo_frame.grid(row=0, column=0, columnspan=2, pady=(0, 0), sticky="nsew")
        logo_path = os.path.join("branding", "shieldeye_logo_horizontal.png")
        if os.path.exists(logo_path):
            try:
                logo_img = PhotoImage(file=logo_path)
                logo_label = tk.Label(logo_frame, image=logo_img, bg=BG_COLOR)
                setattr(logo_label, '_image', logo_img)
                logo_label.pack()
            except Exception:
                logo_label = tk.Label(logo_frame, text="ShieldEye", fg=ACCENT_COLOR, bg=BG_COLOR, font=("Consolas", 28, "bold"))
                logo_label.pack()
        else:
            logo_label = tk.Label(logo_frame, text="ShieldEye", fg=ACCENT_COLOR, bg=BG_COLOR, font=("Consolas", 28, "bold"))
            logo_label.pack()
        slogan_label = tk.Label(logo_frame, text="See the threats before they see you", fg="#e0d7ff", bg=BG_COLOR, font=("Consolas", 14))
        slogan_label.pack()
        ascii_label = tk.Label(self.root, text=ASCII_ART, fg=FG_COLOR, bg=BG_COLOR, font=FONT_ASCII, justify="left")
        ascii_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 0), padx=10)
        self.port_scanner = PortScanner()
        self.cms_scanner = CMSScanner()
        self.report_generator = ReportGenerator()
        self.scanning = False
        self.port_results = []
        self.cms_results = []
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    def on_closing(self):
        self.matrix_rain.stop()
        if self.scanning:
            if messagebox.askokcancel("Close", "A scan is in progress. Are you sure you want to close?"):
                self.scanning = False
                self.root.destroy()
        else:
            self.root.destroy()
    def setup_ui(self):
        try:
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(2, weight=1)
            main_frame.columnconfigure(0, weight=1)
            main_frame.columnconfigure(1, weight=1)
            main_frame.rowconfigure(2, weight=1)
            title_label = ttk.Label(main_frame, text="ShieldEye", font=FONT_HEADER, foreground=ACCENT_COLOR)
            title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky="ew")
            self.setup_config_section(main_frame)
            self.setup_results_section(main_frame)
            self.setup_control_section(main_frame)
        except Exception as e:
            messagebox.showerror("UI Error", f"Cannot create interface:\n{str(e)}")
            raise
    def setup_config_section(self, parent):
        config_frame = ttk.LabelFrame(parent, text="ShieldEye – Scan Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        ttk.Label(config_frame, text="Scan type:").grid(row=0, column=0, sticky="w", pady=5)
        self.scan_type = tk.StringVar(value="single")
        scan_frame = ttk.Frame(config_frame)
        scan_frame.grid(row=0, column=1, sticky="ew", pady=5, padx=(10, 0))
        ttk.Radiobutton(scan_frame, text="Single host", variable=self.scan_type, value="single").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(scan_frame, text="Network", variable=self.scan_type, value="network").pack(side=tk.LEFT)
        ttk.Label(config_frame, text="Target:").grid(row=1, column=0, sticky="w", pady=5)
        self.target_var = tk.StringVar()
        target_entry = tk.Entry(config_frame, textvariable=self.target_var, width=40, font=FONT_MONO, fg=FG_COLOR, bg=BG_COLOR, insertbackground=FG_COLOR, highlightbackground=ACCENT_COLOR, highlightcolor=ACCENT_COLOR, highlightthickness=1, relief="flat")
        target_entry.grid(row=1, column=1, sticky="ew", pady=5)
        examples_frame = ttk.Frame(config_frame)
        examples_frame.grid(row=2, column=1, sticky="ew", pady=5)
        ttk.Label(examples_frame, text="Examples: 192.168.1.1 (host) or 192.168.1.0/24 (network)", font=("Consolas", 9), foreground=ACCENT_COLOR).pack(side=tk.LEFT)
        ttk.Label(config_frame, text="Options:").grid(row=3, column=0, sticky="w", pady=5)
        options_frame = ttk.Frame(config_frame)
        options_frame.grid(row=3, column=1, sticky="ew", pady=5, padx=(10, 0))
        self.scan_ports_var = tk.BooleanVar(value=True)
        self.scan_cms_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Scan ports", variable=self.scan_ports_var).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Checkbutton(options_frame, text="Scan CMS", variable=self.scan_cms_var).pack(side=tk.LEFT)
        self.stealth_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Stealth mode", variable=self.stealth_mode_var).pack(side=tk.LEFT, padx=(20, 0))
        ttk.Label(config_frame, text="URL (CMS):").grid(row=4, column=0, sticky="w", pady=5)
        self.cms_url_var = tk.StringVar()
        cms_entry = tk.Entry(config_frame, textvariable=self.cms_url_var, width=40, font=FONT_MONO, fg=FG_COLOR, bg=BG_COLOR, insertbackground=FG_COLOR, highlightbackground=ACCENT_COLOR, highlightcolor=ACCENT_COLOR, highlightthickness=1, relief="flat")
        cms_entry.grid(row=4, column=1, sticky="ew", pady=5)
        ttk.Label(config_frame, text="Example: http://example.com", font=("Consolas", 9), foreground=ACCENT_COLOR).grid(row=5, column=1, sticky="w", pady=2)
        ttk.Label(config_frame, text="Scan mode:").grid(row=6, column=0, sticky="w", pady=5)
        self.scan_mode_var = tk.StringVar(value="safe")
        mode_frame = ttk.Frame(config_frame)
        mode_frame.grid(row=6, column=1, sticky="ew", pady=5)
        ttk.Radiobutton(mode_frame, text="Quick/Safe", variable=self.scan_mode_var, value="safe").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Aggressive/Fast", variable=self.scan_mode_var, value="aggressive").pack(side=tk.LEFT)
        self.web_vulns_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Web vulnerabilities", variable=self.web_vulns_var).pack(side=tk.LEFT, padx=(20, 0))
        ttk.Label(parent, text="Shodan API key:").grid(row=7, column=0, sticky="w", pady=5)
        self.shodan_api_var = tk.StringVar()
        shodan_entry = tk.Entry(parent, textvariable=self.shodan_api_var, width=40, font=FONT_MONO, fg=FG_COLOR, bg=BG_COLOR, insertbackground=FG_COLOR, highlightbackground=ACCENT_COLOR, highlightcolor=ACCENT_COLOR, highlightthickness=1, relief="flat")
        shodan_entry.grid(row=7, column=1, sticky="ew", pady=5)
    def setup_results_section(self, parent):
        results_frame = ttk.LabelFrame(parent, text="ShieldEye – Scan Results", padding="10")
        results_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        min_height = 220
        self.notebook = ttk.Notebook(results_frame, height=min_height)
        self.notebook.grid(row=0, column=0, sticky="nsew")
        self.notebook.enable_traversal()
        self.root.rowconfigure(2, weight=1)
        self.root.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        parent.columnconfigure(0, weight=1)
        for i in range(self.notebook.index("end")):
            self.notebook.tab(i, sticky="nsew")
        self.log_frame = ttk.Frame(self.notebook, padding=0, style='Log.TFrame')
        self.notebook.add(self.log_frame, text="Logs")
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=15, width=80, font=("Consolas", 12, "bold"))
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=4, pady=(0,4))
        self.log_text.config(bg=BG_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, relief="solid", bd=2, highlightbackground=ACCENT_COLOR, highlightcolor=ACCENT_COLOR, highlightthickness=2)
        style = ttk.Style()
        style.configure('Log.TFrame', background=BG_COLOR, borderwidth=2, relief="solid")
        self.ports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ports_frame, text="Ports")
        self.ports_frame.columnconfigure(0, weight=1)
        self.ports_frame.rowconfigure(0, weight=1)
        self.ports_text = scrolledtext.ScrolledText(self.ports_frame, height=15, width=80, font=FONT_MONO)
        self.ports_text.grid(row=0, column=0, sticky="nsew")
        self.ports_text.config(bg=BG_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, relief="flat", highlightbackground=ACCENT_COLOR, highlightcolor=ACCENT_COLOR, highlightthickness=1)
        self.ports_text.bind("<Button-1>", self.on_port_click)
        self.cms_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cms_frame, text="CMS")
        self.cms_frame.columnconfigure(0, weight=1)
        self.cms_frame.rowconfigure(0, weight=1)
        self.cms_text = scrolledtext.ScrolledText(self.cms_frame, height=15, width=80, font=FONT_MONO)
        self.cms_text.grid(row=0, column=0, sticky="nsew")
        self.cms_text.config(bg=BG_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, relief="flat", highlightbackground=ACCENT_COLOR, highlightcolor=ACCENT_COLOR, highlightthickness=1)
        self.cms_text.bind("<Button-1>", self.on_cms_click)
        self.charts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.charts_frame, text="Charts")
        self.charts_frame.columnconfigure(0, weight=1)
        self.charts_frame.rowconfigure(0, weight=1)
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="History")
        self.history_frame.columnconfigure(0, weight=1)
        self.history_frame.rowconfigure(0, weight=1)
        self.history_listbox = tk.Listbox(self.history_frame, font=FONT_MONO, bg=BG_COLOR, fg=FG_COLOR, selectbackground=ACCENT_COLOR, selectforeground=BG_COLOR)
        self.history_listbox.grid(row=0, column=0, sticky="nsew")
        self.load_button = ttk.Button(self.history_frame, text="Load", command=self.load_selected_history)
        self.load_button.grid(row=1, column=0, pady=5, sticky="ew")
    def setup_control_section(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        control_frame.columnconfigure(1, weight=1)
        self.start_button = ttk.Button(control_frame, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_scan, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=(0, 10))
        self.export_button = ttk.Button(control_frame, text="Export ShieldEye Report (PDF)", command=self.export_report)
        self.export_button.grid(row=0, column=2, padx=(0, 10))
        self.clear_button = ttk.Button(control_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=3, padx=(0, 10))
        self.update_cve_button = ttk.Button(control_frame, text="Update CVE database", command=self.update_cve_database)
        self.update_cve_button.grid(row=0, column=4, padx=(0, 10))
        self.about_button = ttk.Button(control_frame, text="About", command=self.show_about_window)
        self.about_button.grid(row=0, column=5, padx=(0, 10))
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('green.Horizontal.TProgressbar', troughcolor=FRAME_COLOR, background=ACCENT_COLOR, bordercolor=BG_COLOR, lightcolor=ACCENT_COLOR, darkcolor=ACCENT_COLOR)
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate', style='green.Horizontal.TProgressbar')
        self.progress.grid(row=1, column=0, columnspan=5, sticky="ew", pady=(10, 0))
    def log_message(self, message):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] {message}\n"
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)
            self.root.update_idletasks()
        except Exception as e:
            print(f"Error logging: {e}")
    def start_scan(self):
        if self.scanning:
            return
        if not self.target_var.get().strip():
            messagebox.showerror("Error", "Please provide a scan target")
            return
        if self.scan_cms_var.get() and not self.cms_url_var.get().strip():
            messagebox.showerror("Error", "Please provide a CMS URL")
            return
        self.scanning = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress.start()
        scan_thread = threading.Thread(target=self.perform_scan)
        scan_thread.daemon = True
        scan_thread.start()
    def stop_scan(self):
        self.scanning = False
        self.log_message("Scan stopped by user")
        self.finish_scan()
    def perform_scan(self):
        try:
            self.log_message("Scan started...")
            target = self.target_var.get().strip()
            scan_type = self.scan_type.get()
            stealth = self.stealth_mode_var.get()
            scan_mode = self.scan_mode_var.get()
            if self.scan_ports_var.get():
                self.log_message(f"Starting port scan for: {target}")
                if scan_type == "single":
                    self.port_results = [self.scan_single_host_stealth(target, stealth, scan_mode)]
                else:
                    self.port_results = self.scan_network_stealth(target, stealth, scan_mode)
                api_key = self.shodan_api_var.get().strip()
                if api_key:
                    for host_result in self.port_results:
                        host_result['shodan'] = self.get_shodan_info(host_result['target'], api_key)
                self.log_message(f"Port scan completed. Found {len(self.port_results)} hosts")
                self.display_port_results()
            if self.scan_cms_var.get() and self.scanning:
                cms_url = self.cms_url_var.get().strip()
                self.log_message(f"Starting CMS scan for: {cms_url}")
                web_vulns = self.web_vulns_var.get()
                self.cms_results = [self.scan_cms_stealth(cms_url, stealth, scan_mode, web_vulns)]
                self.log_message("CMS scan completed")
                self.display_cms_results()
            if self.scanning:
                self.log_message("Scan completed successfully")
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.log_message(error_msg)
            messagebox.showerror("Error", f"An error occurred during scanning:\n{str(e)}")
        finally:
            self.finish_scan()
    def finish_scan(self):
        self.scanning = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress.stop()
    def display_port_results(self):
        try:
            self.ports_text.delete(1.0, tk.END)
            self.ports_text.tag_configure("critical", foreground=ACCENT_COLOR)
            if not self.port_results:
                self.ports_text.insert(tk.END, "No port scan results\n")
                return
            for host_result in self.port_results:
                self.ports_text.insert(tk.END, f"Host: {host_result['target']}\n")
                self.ports_text.insert(tk.END, f"Status: {host_result.get('status', 'unknown')}\n")
                if host_result.get('open_ports'):
                    self.ports_text.insert(tk.END, "Open ports:\n")
                    for port_info in host_result['open_ports']:
                        line = f"  Port {port_info['port']}: {port_info['service']} - {port_info['description']}\n"
                        if port_info.get('description', '').lower() == 'critical' or port_info.get('service', '').lower() in ['rdp', 'vnc', 'telnet']:
                            self.ports_text.insert(tk.END, line, "critical")
                        else:
                            self.ports_text.insert(tk.END, line)
                else:
                    self.ports_text.insert(tk.END, "No open ports\n")
                self.ports_text.insert(tk.END, "\n")
            self.display_charts()
            self.save_scan_to_history()
        except Exception as e:
            self.log_message(f"Error displaying port results: {e}")
    def display_cms_results(self):
        try:
            self.cms_text.delete(1.0, tk.END)
            self.cms_text.tag_configure("critical", foreground=ACCENT_COLOR)
            if not self.cms_results:
                self.cms_text.insert(tk.END, "No CMS scan results\n")
                return
            for cms_result in self.cms_results:
                self.cms_text.insert(tk.END, f"URL: {cms_result['url']}\n")
                if cms_result.get('cms_detected'):
                    cms_info = cms_result['cms_detected']
                    self.cms_text.insert(tk.END, f"Detected CMS: {cms_info['cms']} {cms_info['version']}\n")
                    if cms_result.get('vulnerabilities'):
                        self.cms_text.insert(tk.END, "Vulnerabilities:\n")
                        for vuln in cms_result['vulnerabilities']:
                            line = f"  - {vuln['description']}\n"
                            if vuln.get('severity', '').upper() in ['HIGH', 'CRITICAL']:
                                self.cms_text.insert(tk.END, line, "critical")
                            else:
                                self.cms_text.insert(tk.END, line)
                    if cms_result.get('security_issues'):
                        self.cms_text.insert(tk.END, "Security issues:\n")
                        for issue in cms_result['security_issues']:
                            self.cms_text.insert(tk.END, f"  - {issue['description']}\n")
                else:
                    self.cms_text.insert(tk.END, "No known CMS detected\n")
                self.cms_text.insert(tk.END, "\n")
                if cms_result.get('web_vulns'):
                    self.cms_text.insert(tk.END, "Web vulnerabilities:\n")
                    for vuln in cms_result['web_vulns']:
                        tag = "critical" if vuln['type'] in ["XSS", "SQLi", "Directory Traversal"] else None
                        line = f"  - {vuln['type']}: {vuln['description']}\n"
                        if tag:
                            self.cms_text.insert(tk.END, line, tag)
                        else:
                            self.cms_text.insert(tk.END, line)
            self.display_charts()
            self.save_scan_to_history()
        except Exception as e:
            self.log_message(f"Error displaying CMS results: {e}")
    def export_report(self):
        if not self.port_results and not self.cms_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
            title="Save report as"
        )
        if filename:
            try:
                self.log_message("Generating PDF report...")
                report_file = self.report_generator.generate_vulnerability_report(
                    self.port_results, self.cms_results, filename
                )
                self.log_message(f"Report saved as: {report_file}")
                messagebox.showinfo("Success", f"Report has been saved as:\n{report_file}")
            except Exception as e:
                error_msg = f"Error: {str(e)}"
                self.log_message(error_msg)
                messagebox.showerror("Error", f"Failed to generate report:\n{str(e)}")
    def clear_results(self):
        self.port_results = []
        self.cms_results = []
        self.log_text.delete(1.0, tk.END)
        self.ports_text.delete(1.0, tk.END)
        self.cms_text.delete(1.0, tk.END)
        self.log_message("Results have been cleared")
    def update_cve_database(self):
        self.log_message("Updating CVE database...")
        try:
            response = requests.get("https://cve.circl.lu/api/last", timeout=20)
            if response.status_code == 200:
                cve_data = response.json()
                with open("cve_db.json", "w", encoding="utf-8") as f:
                    json.dump(cve_data, f, indent=2)
                self.log_message("CVE database updated successfully ({} entries)".format(len(cve_data)))
                messagebox.showinfo("CVE Update", "CVE database updated successfully!")
            else:
                self.log_message(f"Failed to update CVE database: HTTP {response.status_code}")
                messagebox.showerror("CVE Update", f"Failed to update CVE database: HTTP {response.status_code}")
        except Exception as e:
            self.log_message(f"Failed to update CVE database: {e}")
            messagebox.showerror("CVE Update", f"Failed to update CVE database:\n{e}")
    def scan_single_host_stealth(self, target, stealth, scan_mode):
        scanner = self.port_scanner
        ports = None
        if scan_mode == "aggressive":
            ports = list(scanner.common_ports.keys()) + [i for i in range(1, 1024) if i not in scanner.common_ports]
        if stealth:
            if ports is None:
                ports = list(scanner.common_ports.keys())
            random.shuffle(ports)
        result = scanner.scan_single_host(target, ports=ports, scan_mode=scan_mode)
        if stealth or scan_mode == "safe":
            time.sleep(random.uniform(0.5, 2.0))
        return result
    def scan_network_stealth(self, network, stealth, scan_mode):
        scanner = self.port_scanner
        ports = None
        if scan_mode == "aggressive":
            ports = list(scanner.common_ports.keys()) + [i for i in range(1, 1024) if i not in scanner.common_ports]
        if stealth:
            if ports is None:
                ports = list(scanner.common_ports.keys())
            random.shuffle(ports)
        results = scanner.scan_network(network, ports=ports, scan_mode=scan_mode)
        if stealth or scan_mode == "safe":
            for _ in range(len(results)):
                time.sleep(random.uniform(0.5, 2.0))
        return results
    def scan_cms_stealth(self, url, stealth, scan_mode, web_vulns=False):
        scanner = self.cms_scanner
        if stealth:
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                'Mozilla/5.0 (X11; Linux x86_64)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
                'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
                'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
            ]
            random.shuffle(user_agents)
            scanner.session.headers['User-Agent'] = random.choice(user_agents)
            time.sleep(random.uniform(0.5, 2.0))
        result = scanner.scan_cms(url)
        if web_vulns:
            result['web_vulns'] = self.test_web_vulnerabilities(url)
        return result
    def test_web_vulnerabilities(self, url):
        vulns = []
        xss_payload = "<script>alert(1)</script>"
        try:
            resp = requests.get(url, params={"xss": xss_payload}, timeout=5)
            if xss_payload in resp.text:
                vulns.append({"type": "XSS", "description": "Reflected XSS detected via ?xss=..."})
        except Exception:
            pass
        sqli_payload = "' OR '1'='1"
        try:
            resp = requests.get(url, params={"id": sqli_payload}, timeout=5)
            if "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                vulns.append({"type": "SQLi", "description": "Possible SQL Injection via ?id=..."})
        except Exception:
            pass
        dt_payload = "../../../../etc/passwd"
        try:
            resp = requests.get(url, params={"file": dt_payload}, timeout=5)
            if "root:x:" in resp.text:
                vulns.append({"type": "Directory Traversal", "description": "Possible directory traversal via ?file=..."})
        except Exception:
            pass
        return vulns
    def display_charts(self):
        for widget in self.charts_frame.winfo_children():
            widget.destroy()
        if not MATPLOTLIB_AVAILABLE:
            label = tk.Label(self.charts_frame, text="matplotlib is not installed. Charts unavailable.", fg=FG_COLOR, bg=BG_COLOR, font=FONT_MONO)
            label.grid(row=0, column=0, sticky="nsew")
        else:
            hosts = [r['target'] for r in self.port_results]
            open_ports = [len(r.get('open_ports', [])) for r in self.port_results]
            vuln_types = {}
            for cms in self.cms_results:
                for vuln in cms.get('vulnerabilities', []):
                    t = vuln.get('type', 'other')
                    vuln_types[t] = vuln_types.get(t, 0) + 1
            fig, axs = plt.subplots(2, 1, figsize=(7, 5), facecolor=BG_COLOR)
            axs[0].bar(hosts, open_ports, color=ACCENT_COLOR)
            axs[0].set_title('Open ports per host', color=FG_COLOR)
            axs[0].set_xlabel('Host', color=FG_COLOR)
            axs[0].set_ylabel('Open ports', color=FG_COLOR)
            axs[0].tick_params(axis='x', colors=FG_COLOR)
            axs[0].tick_params(axis='y', colors=FG_COLOR)
            axs[0].set_facecolor(BG_COLOR)
            if vuln_types:
                axs[1].pie(list(vuln_types.values()), labels=list(vuln_types.keys()), autopct='%1.0f%%', colors=[ACCENT_COLOR, FRAME_COLOR, BUTTON_BG, FG_COLOR])
                axs[1].set_title('Vulnerability types', color=FG_COLOR)
            else:
                axs[1].text(0.5, 0.5, 'No vulnerabilities', ha='center', va='center', color=FG_COLOR)
            axs[1].set_facecolor(BG_COLOR)
            fig.tight_layout()
            self.charts_canvas = FigureCanvasTkAgg(fig, master=self.charts_frame)
            self.charts_canvas.draw()
            self.charts_canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")
            plt.close(fig)
        if self.port_results:
            canvas = tk.Canvas(self.charts_frame, width=600, height=180, bg=BG_COLOR, highlightthickness=0)
            canvas.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
            n = len(self.port_results)
            margin = 40
            radius = 14
            if n > 1:
                step = (600 - 2 * margin) // (n - 1)
            else:
                step = 0
            for i, host in enumerate(self.port_results):
                x = margin + i * step
                y = 90
                canvas.create_oval(x-radius, y-radius, x+radius, y+radius, fill=ACCENT_COLOR, outline=FRAME_COLOR, width=2)
                canvas.create_text(x, y, text=str(i+1), fill=BG_COLOR, font=("Consolas", 12, "bold"))
                canvas.create_text(x, y+radius+12, text=host['target'], fill=FG_COLOR, font=("Consolas", 9))
            canvas.create_text(300, 20, text="Network map (detected hosts)", fill=ACCENT_COLOR, font=("Consolas", 12, "bold"))
    def on_port_click(self, event):
        index = self.ports_text.index(f"@{event.x},{event.y}")
        line = self.ports_text.get(f"{index} linestart", f"{index} lineend")
        if line.strip().startswith("Port"):
            port_info = line.strip().split()
            port_num = port_info[1].replace(":", "")
            service = port_info[2] if len(port_info) > 2 else "?"
            desc = " ".join(port_info[4:]) if len(port_info) > 4 else ""
            host = None
            for h in self.port_results:
                if f"Port {port_num}" in line:
                    host = h
                    break
            shodan_info = host.get('shodan') if host and 'shodan' in host else None
            details = f"Service: {service}\nDescription: {desc}"
            if shodan_info:
                details += "\n\n[Shodan info]"
                for k, v in shodan_info.items():
                    details += f"\n{k}: {v}"
            self.show_detail_window(f"Port {port_num}", details)
    def on_cms_click(self, event):
        index = self.cms_text.index(f"@{event.x},{event.y}")
        line = self.cms_text.get(f"{index} linestart", f"{index} lineend")
        if line.strip().startswith("- ") or line.strip().startswith("  - "):
            self.show_detail_window("Vulnerability details", line.strip()[2:].strip())
    def show_detail_window(self, title, content):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=BG_COLOR)
        label = tk.Label(win, text=title, font=FONT_HEADER, fg=ACCENT_COLOR, bg=BG_COLOR)
        label.pack(padx=10, pady=10)
        text = tk.Text(win, height=10, width=60, bg=BG_COLOR, fg=FG_COLOR, font=FONT_MONO, wrap="word")
        text.insert("1.0", content)
        text.config(state="disabled")
        text.pack(padx=10, pady=10)
        btn = ttk.Button(win, text="Close", command=win.destroy)
        btn.pack(pady=(0, 10))
    def save_scan_to_history(self):
        history_file = "scan_history.json"
        entry = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "port_results": self.port_results,
            "cms_results": self.cms_results
        }
        history = []
        if os.path.exists(history_file):
            try:
                with open(history_file, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.append(entry)
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
        self.load_history()
        self.refresh_history_listbox()
    def load_history(self):
        self.history = []
        history_file = "scan_history.json"
        if os.path.exists(history_file):
            try:
                with open(history_file, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
            except Exception:
                self.history = []
    def refresh_history_listbox(self):
        self.history_listbox.delete(0, tk.END)
        for i, entry in enumerate(self.history):
            label = f"{i+1}. {entry['date']} | Ports: {len(entry.get('port_results', []))} | CMS: {len(entry.get('cms_results', []))}"
            self.history_listbox.insert(tk.END, label)
    def load_selected_history(self, event=None):
        selection = self.history_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        entry = self.history[idx]
        self.port_results = entry.get('port_results', [])
        self.cms_results = entry.get('cms_results', [])
        self.display_port_results()
        self.display_cms_results()
        self.log_message(f"Loaded scan from history: {entry['date']}")
    def get_shodan_info(self, ip, api_key):
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'org': data.get('org'),
                    'os': data.get('os'),
                    'ports': data.get('ports'),
                    'hostnames': data.get('hostnames'),
                    'data': [d.get('data') for d in data.get('data', []) if 'data' in d]
                }
            else:
                return {'error': f"HTTP {resp.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    def show_about_window(self):
        win = tk.Toplevel(self.root)
        win.title("About ShieldEye")
        win.configure(bg=BG_COLOR)
        logo_path = os.path.join("branding", "shieldeye_logo_square.png")
        if os.path.exists(logo_path):
            try:
                logo_img = tk.PhotoImage(file=logo_path)
                logo_label = tk.Label(win, image=logo_img, bg=BG_COLOR)
                setattr(logo_label, '_image', logo_img)
                logo_label.pack(pady=(10, 0))
            except Exception:
                logo_label = tk.Label(win, text="ShieldEye", fg=ACCENT_COLOR, bg=BG_COLOR, font=("Consolas", 28, "bold"))
                logo_label.pack(pady=(10, 0))
        else:
            logo_label = tk.Label(win, text="ShieldEye", fg=ACCENT_COLOR, bg=BG_COLOR, font=("Consolas", 28, "bold"))
            logo_label.pack(pady=(10, 0))
        slogan_label = tk.Label(win, text="See the threats before they see you", fg="#e0d7ff", bg=BG_COLOR, font=("Consolas", 14))
        slogan_label.pack(pady=(0, 10))
        info = "ShieldEye Application\nAutomated vulnerability scanner for local businesses\nVersion 1.0\n© 2024 ShieldEye Team"
        info_label = tk.Label(win, text=info, fg=FG_COLOR, bg=BG_COLOR, font=FONT_MONO, justify="center")
        info_label.pack(padx=10, pady=10)
        btn = ttk.Button(win, text="Close", command=win.destroy)
        btn.pack(pady=(0, 10))
def main():
    try:
        print("Starting Automated Vulnerability Scanner...")
        if not hasattr(sys, 'ps1'):
            root = tk.Tk()
            app = VulnerabilityScannerGUI(root)
            app.log_message("ShieldEye – application started successfully")
            app.log_message("Provide scan target and click 'Start Scan'")
            root.mainloop()
        else:
            print("Application requires GUI mode")
    except Exception as e:
        print(f"Critical application error: {e}")
        print("Error details:")
        traceback.print_exc()
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Critical error", 
                               f"The application cannot start:\n{str(e)}\n\nCheck if all dependencies are installed.")
            root.destroy()
        except:
            pass
        input("Press Enter to exit...")
        sys.exit(1)
if __name__ == "__main__":
    main() 