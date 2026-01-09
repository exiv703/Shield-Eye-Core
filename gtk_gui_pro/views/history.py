import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib
from datetime import datetime

class HistoryView(Gtk.ScrolledWindow):
    def __init__(self, backend, on_view_results):
        super().__init__()
        self.backend = backend
        self.on_view_results = on_view_results  # callback to view scan details
        
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_vexpand(True)
        self.set_hexpand(True)
        
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.main_box.set_margin_start(24)
        self.main_box.set_margin_end(24)
        self.main_box.set_margin_top(24)
        self.main_box.set_margin_bottom(24)
        
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header_box.set_margin_bottom(24)
        
        title = Gtk.Label(label="Scan History")
        title.add_css_class("header-title")
        title.set_halign(Gtk.Align.START)
        title.set_hexpand(True)
        header_box.append(title)
        
        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.add_css_class("secondary-button")
        refresh_btn.connect("clicked", lambda _: self.refresh_history())
        header_box.append(refresh_btn)
        
        self.main_box.append(header_box)
        
        self.history_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.main_box.append(self.history_container)
        
        self.set_child(self.main_box)
        
        # load history on init
        self.refresh_history()
    
    def refresh_history(self):
        # clear existing items
        while self.history_container.get_first_child():
            self.history_container.remove(self.history_container.get_first_child())
        
        history = self.backend.load_history()
        
        if not history:
            self._show_empty_state()
            return
        
        # show most recent first
        for scan in reversed(history):
            scan_card = self._create_scan_card(scan)
            self.history_container.append(scan_card)
    
    def _show_empty_state(self):
        
        empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        empty_box.set_valign(Gtk.Align.CENTER)
        empty_box.set_vexpand(True)
        empty_box.set_margin_top(100)
        
        icon = Gtk.Label(label="No Data")
        icon.add_css_class("empty-icon")
        empty_box.append(icon)
        
        message = Gtk.Label(label="No scan history yet")
        message.add_css_class("empty-message")
        empty_box.append(message)
        
        hint = Gtk.Label(label="Run your first scan to see results here")
        hint.add_css_class("empty-hint")
        empty_box.append(hint)
        
        self.history_container.append(empty_box)
    
    def _create_scan_card(self, scan):
        
        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        card.add_css_class("history-card")
        card.set_size_request(-1, 60)  # Fixed compact height
        
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        left_box.set_hexpand(True)
        
        target = scan.get("target", "Unknown")
        target_label = Gtk.Label(label=f"🎯 {target}")
        target_label.add_css_class("metric-label")
        target_label.set_halign(Gtk.Align.START)
        left_box.append(target_label)
        
        timestamp = scan.get("timestamp", scan.get("date", "Unknown"))
        try:
            if "T" in timestamp:
                dt = datetime.fromisoformat(timestamp)
                time_str = dt.strftime("%Y-%m-%d %H:%M")
            else:
                time_str = timestamp
        except:
            time_str = timestamp
        
        time_label = Gtk.Label(label=f"🕐 {time_str}")
        time_label.add_css_class("body-text")
        time_label.set_halign(Gtk.Align.START)
        left_box.append(time_label)
        
        card.append(left_box)
        
        risk_summary = scan.get("risk_summary", {})
        level = risk_summary.get("level", "UNKNOWN")
        score = risk_summary.get("score", 0)
        metrics = risk_summary.get("metrics", {})
        
        metrics_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        metrics_box.set_valign(Gtk.Align.CENTER)
        
        score_label = Gtk.Label(label=f"Risk: {score}")
        score_label.add_css_class("body-text")
        score_label.add_css_class(level.lower())
        metrics_box.append(score_label)
        
        open_ports = metrics.get("total_open_ports", 0)
        ports_label = Gtk.Label(label=f"Ports: {open_ports}")
        ports_label.add_css_class("body-text")
        metrics_box.append(ports_label)
        
        vulns = metrics.get("total_cms_vulnerabilities", 0)
        issues = metrics.get("total_cms_issues", 0)
        total_issues = vulns + issues
        issues_label = Gtk.Label(label=f"Issues: {total_issues}")
        issues_label.add_css_class("body-text")
        if total_issues > 0:
            issues_label.add_css_class("warning-text")
        metrics_box.append(issues_label)
        
        card.append(metrics_box)
        
        right_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        right_box.set_valign(Gtk.Align.CENTER)
        
        risk_badge = Gtk.Label(label=level)
        risk_badge.add_css_class("risk-badge")
        risk_badge.add_css_class(level.lower())
        right_box.append(risk_badge)
        
        view_btn = Gtk.Button(label="View")
        view_btn.add_css_class("secondary-button")
        view_btn.connect("clicked", lambda _: self.on_view_results(scan))
        right_box.append(view_btn)
        
        card.append(right_box)
        
        return card
