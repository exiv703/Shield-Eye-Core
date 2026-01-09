import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Gio, GLib
import sys
import os
import threading
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend import ShieldEyeBackend
from gtk_gui_pro.views.dashboard import DashboardView
from gtk_gui_pro.views.scan_config import ScanConfigView
from gtk_gui_pro.views.results import ResultsView
from gtk_gui_pro.views.history import HistoryView
from gtk_gui_pro.views.ecosystem import EcosystemView

class ShieldEyeMainWindow(Gtk.ApplicationWindow):
    def __init__(self, app, backend):
        super().__init__(application=app)
        self.backend = backend
        self.current_scan_results = None
        
        self.set_title("ShieldEye Core Professional")
        self.set_default_size(1700, 1111)
        self.set_decorated(False)
        self.set_resizable(True)
        
        self._load_styles()
        
        root_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        titlebar = self._create_titlebar()
        root_box.append(titlebar)
        
        main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        
        sidebar = self._create_sidebar()
        main_box.append(sidebar)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content_box.set_hexpand(True)
        
        self.view_stack = Gtk.Stack()
        self.view_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.view_stack.set_transition_duration(200)
        
        self.dashboard_view = DashboardView(self.backend)
        self.view_stack.add_named(self.dashboard_view, "dashboard")
        
        self.scan_view = ScanConfigView(self.backend, self._on_scan_start)
        self.view_stack.add_named(self.scan_view, "scan")
        
        self.results_view = ResultsView(self.backend)
        self.view_stack.add_named(self.results_view, "results")
        
        self.history_view = HistoryView(self.backend, self._on_view_history_scan)
        self.view_stack.add_named(self.history_view, "history")
        
        self.ecosystem_view = EcosystemView()
        self.view_stack.add_named(self.ecosystem_view, "ecosystem")
        
        settings_placeholder = self._build_settings_placeholder("Settings", "Configure application preferences")
        self.view_stack.add_named(settings_placeholder, "settings")
        
        content_box.append(self.view_stack)
        
        main_box.append(content_box)
        
        root_box.append(main_box)
        
        self.set_child(root_box)
        
        self.view_stack.set_visible_child_name("dashboard")
        self._update_nav_buttons("dashboard")
    
    def _create_titlebar(self):
        window_handle = Gtk.WindowHandle()
        window_handle.add_css_class("custom-titlebar")
        window_handle.set_size_request(-1, 50)
        
        titlebar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        button_box.set_valign(Gtk.Align.CENTER)
        button_box.set_margin_start(12)
        
        close_btn = Gtk.Button(label="X")
        close_btn.add_css_class("titlebar-button")
        close_btn.add_css_class("titlebar-close")
        close_btn.set_tooltip_text("Close")
        close_btn.connect("clicked", lambda _: self.close())
        button_box.append(close_btn)
        
        minimize_btn = Gtk.Button(label="_")
        minimize_btn.add_css_class("titlebar-button")
        minimize_btn.set_tooltip_text("Minimize")
        minimize_btn.connect("clicked", lambda _: self.minimize())
        button_box.append(minimize_btn)
        
        self.maximize_btn = Gtk.Button(label="[ ]")
        self.maximize_btn.add_css_class("titlebar-button")
        self.maximize_btn.set_tooltip_text("Maximize")
        self.maximize_btn.connect("clicked", self._on_maximize_clicked)
        button_box.append(self.maximize_btn)
        
        titlebar.append(button_box)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        title_box.set_hexpand(True)
        title_box.set_valign(Gtk.Align.CENTER)
        
        title_label = Gtk.Label(label="ShieldEye Core")
        title_label.add_css_class("titlebar-title")
        title_label.set_halign(Gtk.Align.CENTER)
        title_box.append(title_label)
        
        subtitle_label = Gtk.Label(label="Network Security Scanner")
        subtitle_label.add_css_class("titlebar-subtitle")
        subtitle_label.set_halign(Gtk.Align.CENTER)
        title_box.append(subtitle_label)
        
        titlebar.append(title_box)
        
        spacer = Gtk.Box()
        spacer.set_size_request(124, -1)
        titlebar.append(spacer)
        
        window_handle.set_child(titlebar)
        
        return window_handle
    
    def _on_maximize_clicked(self, button):
        # toggle maximize state
        if self.is_maximized():
            self.unmaximize()
            self.maximize_btn.set_label("□")
        else:
            self.maximize()
            self.maximize_btn.set_label("[x]")
    
    def _load_styles(self):
        css_provider = Gtk.CssProvider()
        css_path = os.path.join(os.path.dirname(__file__), "styles.css")
        
        try:
            css_provider.load_from_path(css_path)
            Gtk.StyleContext.add_provider_for_display(
                self.get_display(),
                css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        except Exception as e:
            logger.warning(f"Could not load CSS: {e}")
    
    def _create_sidebar(self):
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.add_css_class("sidebar")
        sidebar.set_size_request(260, -1)
        
        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        header_box.add_css_class("sidebar-header")
        
        app_title = Gtk.Label(label="ShieldEye Core")
        app_title.add_css_class("sidebar-title")
        app_title.set_halign(Gtk.Align.START)
        header_box.append(app_title)
        
        app_subtitle = Gtk.Label(label="Professional Scanner")
        app_subtitle.add_css_class("sidebar-subtitle")
        app_subtitle.set_halign(Gtk.Align.START)
        header_box.append(app_subtitle)
        
        sidebar.append(header_box)
        
        nav_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        nav_box.set_margin_top(24)
        
        nav_label = Gtk.Label(label="NAVIGATION")
        nav_label.add_css_class("metric-label")
        nav_label.set_halign(Gtk.Align.START)
        nav_label.set_margin_start(20)
        nav_label.set_margin_bottom(8)
        nav_box.append(nav_label)
        
        self.nav_buttons = {}
        
        # navigation menu items
        nav_items = [
            ("dashboard", "Dashboard", "View security metrics and scan analytics"),
            ("scan", "New Scan", "Configure and start a new security scan"),
            ("results", "Results", "View detailed results from the latest scan"),
            ("history", "History", "Browse all previous scan results"),
            ("ecosystem", "Ecosystem", "Explore other ShieldEye security tools"),
        ]
        
        for view_id, label, tooltip in nav_items:
            btn = Gtk.Button(label=label)
            btn.add_css_class("nav-button")
            btn.set_halign(Gtk.Align.FILL)
            btn.set_tooltip_text(tooltip)
            btn.connect("clicked", lambda b, v=view_id: self._switch_view(v))
            nav_box.append(btn)
            self.nav_buttons[view_id] = btn
        
        sidebar.append(nav_box)
        
        actions_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        actions_box.set_margin_top(32)
        
        actions_label = Gtk.Label(label="QUICK ACTIONS")
        actions_label.add_css_class("metric-label")
        actions_label.set_halign(Gtk.Align.START)
        actions_label.set_margin_start(20)
        actions_label.set_margin_bottom(8)
        actions_box.append(actions_label)
        
        quick_scan_btn = Gtk.Button(label="Quick Scan")
        quick_scan_btn.add_css_class("secondary-button")
        quick_scan_btn.set_margin_start(12)
        quick_scan_btn.set_margin_end(12)
        quick_scan_btn.set_tooltip_text("Run a fast scan on localhost with default settings")
        quick_scan_btn.connect("clicked", self._on_quick_scan)
        actions_box.append(quick_scan_btn)
        
        sidebar.append(actions_box)
        
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        sidebar.append(spacer)
        
        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        status_box.set_margin_start(20)
        status_box.set_margin_end(20)
        status_box.set_margin_bottom(20)
        
        status_label = Gtk.Label(label="SYSTEM STATUS")
        status_label.add_css_class("metric-label")
        status_label.set_halign(Gtk.Align.START)
        status_box.append(status_label)
        
        from gtk_gui_pro.widgets.status_indicator import StatusIndicator
        
        self.scanner_status = StatusIndicator("Scanner Ready", "active")
        self.scanner_status.set_tooltip_text("Current scanner engine status")
        status_box.append(self.scanner_status)
        
        db_status = StatusIndicator("CVE Database", "active")
        db_status.set_tooltip_text("Vulnerability database connection status")
        status_box.append(db_status)
        
        sidebar.append(status_box)
        
        version = Gtk.Label(label="Version 2.0.0")
        version.add_css_class("metric-change")
        version.set_margin_bottom(12)
        sidebar.append(version)
        
        return sidebar
    
    def _create_header(self):
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header.add_css_class("header-bar")
        
        self.header_title = Gtk.Label(label="Dashboard")
        self.header_title.add_css_class("header-title")
        self.header_title.set_halign(Gtk.Align.START)
        self.header_title.set_hexpand(True)
        header.append(self.header_title)
        
        settings_btn = Gtk.Button(label="Settings")
        settings_btn.add_css_class("secondary-button")
        settings_btn.connect("clicked", lambda _: self._switch_view("settings"))
        header.append(settings_btn)
        
        menu_btn = Gtk.Button(label="Menu")
        menu_btn.add_css_class("secondary-button")
        header.append(menu_btn)
        
        return header
    
    def _build_settings_placeholder(self, title, subtitle):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)
        
        title_label = Gtk.Label(label=title)
        title_label.add_css_class("header-title")
        box.append(title_label)
        
        subtitle_label = Gtk.Label(label=subtitle)
        subtitle_label.add_css_class("header-subtitle")
        box.append(subtitle_label)
        
        return box
    
    def _switch_view(self, view_id):
        self.view_stack.set_visible_child_name(view_id)
        self._update_nav_buttons(view_id)  # update active button styling
    
    def _update_nav_buttons(self, active_view):
        # highlight active nav button
        for view_id, btn in self.nav_buttons.items():
            if view_id == active_view:
                btn.add_css_class("active")
            else:
                btn.remove_css_class("active")
    
    def _on_quick_scan(self, button):
        # TODO: implement actual quick scan with defaults
        self._switch_view("scan")
    
    def _on_scan_start(self, config):
        # update UI to show scanning state
        self.scanner_status.set_status("warning")
        self.scanner_status.label_widget.set_text("Scanning...")
        
        # run scan in background thread
        thread = threading.Thread(target=self._run_scan, args=(config,))
        thread.daemon = True
        thread.start()
    
    def _run_scan(self, config):
        try:
            GLib.idle_add(self.scan_view.update_progress, 0.1, "Initializing scan...")
            
            results = {}
            
            # handle port scanning
            if config["scan_type"] in ["single", "network", "full"]:
                GLib.idle_add(self.scan_view.update_progress, 0.3, "Scanning ports...")
                
                port_mode = config.get("port_mode", "common")
                custom_ports = config.get("custom_ports")
                
                # determine scan type and execute
                if config["scan_type"] == "single":
                    port_results = self.backend.scan_ports(
                        target=config["target"],
                        scan_type="single",
                        scan_mode=config.get("scan_mode", "safe"),
                        port_mode=port_mode,
                        custom_ports=custom_ports
                    )
                else:
                    port_results = self.backend.scan_ports(
                        target=config["target"],
                        scan_type="network",
                        scan_mode=config.get("scan_mode", "safe"),
                        port_mode=port_mode,
                        custom_ports=custom_ports
                    )
                results["port_results"] = port_results
            
            # CMS scan if full scan with URL
            if config["scan_type"] == "full" and config.get("url"):
                GLib.idle_add(self.scan_view.update_progress, 0.6, "Scanning CMS...")
                cms_results = self.backend.scan_cms(
                    url=config["url"],
                    scan_mode=config.get("scan_mode", "safe"),
                    web_vulns=config.get("web_vulns", True)
                )
                results["cms_results"] = [cms_results]
            
            # calculate risk score
            if "port_results" in results or "cms_results" in results:
                GLib.idle_add(self.scan_view.update_progress, 0.8, "Analyzing risk...")
                risk_summary = self.backend.summarize_risk(
                    results.get("port_results", []),
                    results.get("cms_results", [])
                )
                results["risk_summary"] = risk_summary
            
            import datetime
            results["target"] = config["target"]
            results["timestamp"] = datetime.datetime.now().isoformat()
            results["config"] = config
            
            # save to history if enabled
            if config.get("save_report", True):
                GLib.idle_add(self.scan_view.update_progress, 0.9, "Saving results...")
                self.backend.save_scan_to_history(
                    port_results=results.get("port_results", []),
                    cms_results=results.get("cms_results", []),
                    metadata={
                        "target": results.get("target"),
                        "timestamp": results.get("timestamp"),
                        "config": results.get("config"),
                        "risk_summary": results.get("risk_summary")
                    }
                )
            
            GLib.idle_add(self._on_scan_complete, results)
        except Exception as e:
            GLib.idle_add(self._on_scan_error, str(e))
    def _on_scan_complete(self, results):
        self.current_scan_results = results
        
        # reset scanner status
        self.scanner_status.set_status("active")
        self.scanner_status.label_widget.set_text("Scanner Ready")
        
        self.scan_view.update_progress(1.0, "Scan complete!")
        self.history_view.refresh_history()
        self.results_view.display_results(results)
        self._switch_view("results")
        
    def _on_view_history_scan(self, scan):
        self.results_view.display_results(scan)
        self._switch_view("results")
    
    def _on_scan_error(self, error_msg):
        self.scanner_status.set_status("error")
        self.scanner_status.label_widget.set_text("Scan Failed")
        
        self.scan_view.scan_complete()
        
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            text="Scan Error"
        )
        dialog.set_property("secondary-text", f"An error occurred during scanning: {error_msg}")
        dialog.connect("response", lambda d, r: d.destroy())
        dialog.present()
        
        return False

class ShieldEyeGtkApp(Gtk.Application):
    
    def __init__(self, **kwargs):
        super().__init__(application_id="com.shieldeye.professional", **kwargs)
        self.backend = ShieldEyeBackend()
        self.connect("activate", self.on_activate)
    
    def on_activate(self, app: Gtk.Application) -> None:
        window = ShieldEyeMainWindow(app, self.backend)
        window.present()

def main() -> None:
    app = ShieldEyeGtkApp()
    app.run()

if __name__ == "__main__":
    main()
