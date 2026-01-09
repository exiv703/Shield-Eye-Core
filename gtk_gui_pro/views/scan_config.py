import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from gtk_gui_pro.widgets.status_indicator import StatusIndicator

class ScanConfigView(Gtk.ScrolledWindow):
    def __init__(self, backend, on_scan_start):
        super().__init__()
        self.backend = backend
        self.on_scan_start = on_scan_start  # callback when scan starts
        
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main_box.set_margin_start(24)
        main_box.set_margin_end(24)
        main_box.set_margin_top(24)
        main_box.set_margin_bottom(24)
        
        header = self._create_header()
        main_box.append(header)
        
        # two-column layout for config
        config_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
        config_box.set_margin_bottom(24)
        
        left_col = self._create_target_config()
        config_box.append(left_col)
        
        right_col = self._create_scan_options()
        config_box.append(right_col)
        
        main_box.append(config_box)
        
        actions = self._create_action_buttons()
        main_box.append(actions)
        
        self.progress_section = self._create_progress_section()
        main_box.append(self.progress_section)
        self.progress_section.set_visible(False)
        
        self.set_child(main_box)
    
    def _create_header(self):
        header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        header.set_margin_bottom(32)
        
        title = Gtk.Label(label="Configure Network Scan")
        title.add_css_class("header-title")
        title.set_halign(Gtk.Align.START)
        header.append(title)
        
        subtitle = Gtk.Label(label="Set target parameters and scan options")
        subtitle.add_css_class("header-subtitle")
        subtitle.set_halign(Gtk.Align.START)
        header.append(subtitle)
        
        return header
    
    def _create_target_config(self):
        # left panel - target configuration
        panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        panel.add_css_class("chart-panel")
        panel.set_hexpand(True)
        
        header = Gtk.Label(label="Target Configuration")
        header.add_css_class("chart-header")
        header.set_halign(Gtk.Align.START)
        panel.append(header)
        
        type_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        type_label = Gtk.Label(label="Scan Type")
        type_label.add_css_class("metric-label")
        type_label.set_halign(Gtk.Align.START)
        type_box.append(type_label)
        
        self.scan_type_combo = Gtk.ComboBoxText()
        self.scan_type_combo.append("single", "Single Host")
        self.scan_type_combo.append("network", "Network Range")
        self.scan_type_combo.append("full", "Full Scan (Ports + CMS)")
        self.scan_type_combo.set_active(0)
        self.scan_type_combo.set_tooltip_text("Choose between scanning a single host, network range, or comprehensive scan")
        type_box.append(self.scan_type_combo)
        panel.append(type_box)
        
        target_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        target_label = Gtk.Label(label="Target Address")
        target_label.add_css_class("metric-label")
        target_label.set_halign(Gtk.Align.START)
        target_box.append(target_label)
        
        self.target_entry = Gtk.Entry()
        self.target_entry.set_placeholder_text("e.g., 192.168.1.10 or 192.168.1.0/24")
        self.target_entry.set_tooltip_text("Enter IP address or network range in CIDR notation")
        target_box.append(self.target_entry)
        panel.append(target_box)
        
        url_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        url_label = Gtk.Label(label="Target URL (for CMS scan)")
        url_label.add_css_class("metric-label")
        url_label.set_halign(Gtk.Align.START)
        url_box.append(url_label)
        
        self.url_entry = Gtk.Entry()
        self.url_entry.set_placeholder_text("e.g., https://example.com")
        self.url_entry.set_tooltip_text("Website URL to scan for CMS vulnerabilities (WordPress, Joomla, Drupal)")
        url_box.append(self.url_entry)
        panel.append(url_box)
        
        return panel
    
    def _create_scan_options(self):
        
        panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        panel.add_css_class("chart-panel")
        panel.set_hexpand(True)
        
        header = Gtk.Label(label="Scan Options")
        header.add_css_class("chart-header")
        header.set_halign(Gtk.Align.START)
        panel.append(header)
        
        port_mode_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        port_mode_label = Gtk.Label(label="Port Scan Mode")
        port_mode_label.add_css_class("metric-label")
        port_mode_label.set_halign(Gtk.Align.START)
        port_mode_box.append(port_mode_label)
        
        self.port_mode_combo = Gtk.ComboBoxText()
        self.port_mode_combo.append("common", "Common Ports (Fast)")
        self.port_mode_combo.append("critical", "Critical Ports Only")
        self.port_mode_combo.append("full_1k", "Full 1-1024 (Thorough)")
        self.port_mode_combo.append("full_64k", "Full 1-65535 (Comprehensive)")
        self.port_mode_combo.set_tooltip_text("Select port range to scan - more ports = longer scan time")
        self.port_mode_combo.append("custom", "Custom Port List")
        self.port_mode_combo.set_active(0)
        self.port_mode_combo.connect("changed", self._on_port_mode_changed)
        port_mode_box.append(self.port_mode_combo)
        panel.append(port_mode_box)
        
        self.custom_ports_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        custom_label = Gtk.Label(label="Custom Ports (comma-separated)")
        custom_label.add_css_class("metric-label")
        custom_label.set_halign(Gtk.Align.START)
        self.custom_ports_box.append(custom_label)
        
        self.custom_ports_entry = Gtk.Entry()
        self.custom_ports_entry.set_placeholder_text("e.g., 22,80,443,8080")
        self.custom_ports_entry.set_tooltip_text("Specify individual ports separated by commas")
        self.custom_ports_box.append(self.custom_ports_entry)
        self.custom_ports_box.set_visible(False)
        panel.append(self.custom_ports_box)
        
        scan_mode_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        scan_mode_label = Gtk.Label(label="Scan Intensity")
        scan_mode_label.add_css_class("metric-label")
        scan_mode_label.set_halign(Gtk.Align.START)
        scan_mode_box.append(scan_mode_label)
        
        self.scan_mode_combo = Gtk.ComboBoxText()
        self.scan_mode_combo.append("safe", "Safe (Slower, Less Intrusive)")
        self.scan_mode_combo.append("aggressive", "Aggressive (Faster, More Detectable)")
        self.scan_mode_combo.set_active(0)
        self.scan_mode_combo.set_tooltip_text("Safe mode is stealthier but slower; Aggressive is faster but more noticeable")
        scan_mode_box.append(self.scan_mode_combo)
        panel.append(scan_mode_box)
        
        options_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        options_box.set_margin_top(16)
        
        self.web_vulns_check = Gtk.CheckButton(label="Enable Web Vulnerability Checks")
        self.web_vulns_check.set_active(True)
        self.web_vulns_check.set_tooltip_text("Scan for common web vulnerabilities and misconfigurations")
        options_box.append(self.web_vulns_check)
        
        self.save_report_check = Gtk.CheckButton(label="Auto-save Report After Scan")
        self.save_report_check.set_active(True)
        self.save_report_check.set_tooltip_text("Automatically save scan results to history for dashboard tracking")
        options_box.append(self.save_report_check)
        
        panel.append(options_box)
        
        return panel
    
    def _create_action_buttons(self):
        
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions.set_halign(Gtk.Align.END)
        actions.set_margin_top(24)
        
        clear_btn = Gtk.Button(label="Clear")
        clear_btn.add_css_class("secondary-button")
        clear_btn.set_tooltip_text("Reset all fields to default values")
        clear_btn.connect("clicked", self._on_clear_clicked)
        actions.append(clear_btn)
        
        self.start_btn = Gtk.Button(label="▶ Start Scan")
        self.start_btn.add_css_class("primary-button")
        self.start_btn.set_tooltip_text("Begin security scan with current configuration")
        self.start_btn.connect("clicked", self._on_start_clicked)
        actions.append(self.start_btn)
        
        return actions
    
    def _create_progress_section(self):
        
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        section.add_css_class("chart-panel")
        section.set_margin_top(24)
        
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        self.progress_status = StatusIndicator("Scanning in progress...", "active")
        header_box.append(self.progress_status)
        
        section.append(header_box)
        
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_margin_top(12)
        section.append(self.progress_bar)
        
        self.progress_label = Gtk.Label(label="Initializing scan...")
        self.progress_label.set_halign(Gtk.Align.START)
        self.progress_label.set_margin_top(8)
        section.append(self.progress_label)
        
        return section
    
    def _on_port_mode_changed(self, combo):
        
        mode = combo.get_active_id()
        self.custom_ports_box.set_visible(mode == "custom")
    
    def _on_clear_clicked(self, button):
        
        self.target_entry.set_text("")
        self.url_entry.set_text("")
        self.custom_ports_entry.set_text("")
        self.scan_type_combo.set_active(0)
        self.port_mode_combo.set_active(0)
        self.scan_mode_combo.set_active(0)
    
    def _on_start_clicked(self, button):
        
        target = self.target_entry.get_text().strip()
        if not target:
            self._show_error("Please enter a target address")
            return
        
        config = {
            "target": target,
            "url": self.url_entry.get_text().strip(),
            "scan_type": self.scan_type_combo.get_active_id(),
            "port_mode": self.port_mode_combo.get_active_id(),
            "scan_mode": self.scan_mode_combo.get_active_id(),
            "web_vulns": self.web_vulns_check.get_active(),
            "save_report": self.save_report_check.get_active(),
        }
        
        if config["port_mode"] == "custom":
            custom_ports_str = self.custom_ports_entry.get_text().strip()
            if not custom_ports_str:
                self._show_error("Please enter custom ports")
                return
            try:
                config["custom_ports"] = [int(p.strip()) for p in custom_ports_str.split(",")]
            except ValueError:
                self._show_error("Invalid port format. Use comma-separated numbers.")
                return
        
        self.progress_section.set_visible(True)
        self.start_btn.set_sensitive(False)
        
        if self.on_scan_start:
            self.on_scan_start(config)
    
    def _show_error(self, message):
        
        dialog = Gtk.MessageDialog(
            transient_for=self.get_root(),
            modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Configuration Error"
        )
        dialog.set_property("secondary-text", message)
        dialog.connect("response", lambda d, r: d.destroy())
        dialog.present()
    
    def update_progress(self, fraction, message):
        
        self.progress_bar.set_fraction(fraction)
        self.progress_label.set_text(message)
    
    def scan_complete(self):
        
        self.progress_section.set_visible(False)
        self.start_btn.set_sensitive(True)
        self.progress_bar.set_fraction(0)
