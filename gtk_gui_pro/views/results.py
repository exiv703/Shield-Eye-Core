import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from gtk_gui_pro.widgets.status_indicator import RiskBadge
from gtk_gui_pro.widgets.chart_panel import ChartPanel

class ResultsView(Gtk.ScrolledWindow):
    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.set_vexpand(True)
        self.set_hexpand(True)
        
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        self.main_box.set_margin_start(24)
        self.main_box.set_margin_end(24)
        self.main_box.set_margin_top(24)
        self.main_box.set_margin_bottom(24)
        self.main_box.set_vexpand(True)
        self.main_box.set_hexpand(True)
        
        # show empty state initially
        self._show_empty_state()
        
        self.set_child(self.main_box)
        self.current_results = None
    
    def _show_empty_state(self):
        # clear existing content
        while self.main_box.get_first_child():
            self.main_box.remove(self.main_box.get_first_child())
        
        empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        empty_box.set_valign(Gtk.Align.CENTER)
        empty_box.set_vexpand(True)
        
        icon = Gtk.Label(label="No Results")
        icon.set_css_classes(["metric-value"])
        empty_box.append(icon)
        
        message = Gtk.Label(label="No scan results yet")
        message.set_css_classes(["header-subtitle"])
        empty_box.append(message)
        
        hint = Gtk.Label(label="Start a scan to see detailed results here")
        hint.set_css_classes(["metric-change"])
        empty_box.append(hint)
        
        self.main_box.append(empty_box)
    
    def display_results(self, results):
        self.current_results = results
        
        # clear previous results
        while self.main_box.get_first_child():
            self.main_box.remove(self.main_box.get_first_child())
        
        header = self._create_results_header(results)
        header.set_visible(True)
        self.main_box.append(header)
        
        # show risk summary if available
        risk_summary = results.get("risk_summary")
        if isinstance(risk_summary, dict):
            risk_section = self._create_risk_summary(risk_summary)
            risk_section.set_visible(True)
            self.main_box.append(risk_section)
        
        port_results = results.get("port_results")
        if isinstance(port_results, list) and port_results:
            port_section = self._create_port_results(port_results)
            port_section.set_visible(True)
            self.main_box.append(port_section)
        
        cms_results = results.get("cms_results")
        if isinstance(cms_results, list) and cms_results:
            cms_section = self._create_cms_results(cms_results)
            cms_section.set_visible(True)
            self.main_box.append(cms_section)
        
        export_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        export_box.set_halign(Gtk.Align.END)
        export_box.set_margin_top(24)
        
        export_btn = Gtk.Button(label="📄 Export Report")
        export_btn.add_css_class("primary-button")
        export_btn.connect("clicked", self._on_export_clicked)
        export_box.append(export_btn)
        
        export_box.set_visible(True)
        self.main_box.append(export_box)
        
        self.main_box.set_visible(True)
    
    def _create_results_header(self, results):
        
        header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        header.set_margin_bottom(24)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        
        title = Gtk.Label(label="Scan Results")
        title.add_css_class("header-title")
        title.set_halign(Gtk.Align.START)
        title.set_hexpand(True)
        title_box.append(title)
        
        if "risk_summary" in results:
            risk_level = results["risk_summary"].get("level", "LOW")
            badge = RiskBadge(risk_level)
            title_box.append(badge)
        
        header.append(title_box)
        
        meta_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
        
        target = results.get("target", "Unknown")
        target_label = Gtk.Label(label=f"Target: {target}")
        target_label.add_css_class("header-subtitle")
        meta_box.append(target_label)
        
        timestamp = results.get("timestamp", "Unknown")
        time_label = Gtk.Label(label=f"Scanned: {timestamp.split('T')[0] if 'T' in timestamp else timestamp}")
        time_label.add_css_class("header-subtitle")
        meta_box.append(time_label)
        
        header.append(meta_box)
        
        return header
    
    def _create_risk_summary(self, risk_summary):
        
        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        container.set_margin_bottom(20)
        
        section_header = Gtk.Label(label="RISK ASSESSMENT")
        section_header.add_css_class("section-header")
        section_header.set_halign(Gtk.Align.START)
        section_header.set_margin_bottom(12)
        container.append(section_header)
        
        panel = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        
        metrics_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        metrics_box.add_css_class("chart-panel")
        metrics_box.set_hexpand(True)
        
        score = risk_summary.get("score", 0)
        level = risk_summary.get("level", "LOW")
        
        score_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        
        score_label = Gtk.Label(label="RISK SCORE")
        score_label.add_css_class("metric-label")
        score_label.set_halign(Gtk.Align.START)
        score_container.append(score_label)
        
        score_value = Gtk.Label(label=str(score))
        score_value.add_css_class("metric-value")
        score_value.add_css_class(level.lower())
        score_value.set_halign(Gtk.Align.START)
        score_container.append(score_value)
        
        metrics_box.append(score_container)
        
        reasons = risk_summary.get("reasons", [])
        if reasons:
            reasons_header = Gtk.Label(label="RISK FACTORS")
            reasons_header.add_css_class("metric-label")
            reasons_header.set_halign(Gtk.Align.START)
            reasons_header.set_margin_top(8)
            metrics_box.append(reasons_header)
            
            reasons_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            reasons_list.set_margin_top(12)
            for reason in reasons:
                reason_item = Gtk.Label(label=f"• {reason}")
                reason_item.set_halign(Gtk.Align.START)
                reason_item.set_wrap(True)
                reason_item.set_xalign(0)
                reason_item.add_css_class("body-text")
                reasons_list.append(reason_item)
            metrics_box.append(reasons_list)
        else:
            no_issues = Gtk.Label(label="✓ No significant risk factors detected")
            no_issues.set_halign(Gtk.Align.START)
            no_issues.add_css_class("success-text")
            no_issues.set_margin_top(12)
            metrics_box.append(no_issues)
        
        panel.append(metrics_box)
        
        gauge_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        gauge_box.set_size_request(280, -1)
        gauge_box.add_css_class("chart-panel")
        
        gauge_header = Gtk.Label(label="RISK LEVEL")
        gauge_header.add_css_class("metric-label")
        gauge_header.set_halign(Gtk.Align.CENTER)
        gauge_box.append(gauge_header)
        
        gauge = ChartPanel("", "radial")
        gauge.set_data([min(score, 100)])
        gauge_box.append(gauge)
        
        panel.append(gauge_box)
        
        container.append(panel)
        return container
    
    def _create_port_results(self, port_results):
        
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        section.set_margin_bottom(20)
        
        total_open = sum(len(h.get('open_ports', [])) for h in port_results)
        
        header = Gtk.Label(label=f"OPEN PORTS ({total_open} FOUND)")
        header.add_css_class("section-header")
        header.set_halign(Gtk.Align.START)
        section.append(header)
        
        if total_open == 0:
            no_ports_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            no_ports_box.add_css_class("chart-panel")
            no_ports_box.set_margin_top(8)
            no_ports_box.set_valign(Gtk.Align.START)
            
            icon_label = Gtk.Label(label="✓")
            icon_label.add_css_class("success-icon")
            no_ports_box.append(icon_label)
            
            no_ports_msg = Gtk.Label(label="No open ports detected on scanned targets")
            no_ports_msg.set_halign(Gtk.Align.CENTER)
            no_ports_msg.add_css_class("success-text")
            no_ports_box.append(no_ports_msg)
            
            section.append(no_ports_box)
            return section
        
        table_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        table_box.add_css_class("results-table")
        
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header_row.add_css_class("table-header")
        
        headers = [("Host", 200), ("Port", 80), ("Service", 150), ("Version", 200), ("Description", -1)]
        for label, width in headers:
            h = Gtk.Label(label=label)
            h.set_halign(Gtk.Align.START)
            if width > 0:
                h.set_size_request(width, -1)
            else:
                h.set_hexpand(True)
            header_row.append(h)
        
        table_box.append(header_row)
        
        for host in port_results:
            target = host.get("target", "Unknown")
            for port_info in host.get("open_ports", []):
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
                row.add_css_class("table-row")
                
                host_label = Gtk.Label(label=target)
                host_label.set_halign(Gtk.Align.START)
                host_label.set_size_request(200, -1)
                row.append(host_label)
                
                port_label = Gtk.Label(label=str(port_info.get("port", "")))
                port_label.set_halign(Gtk.Align.START)
                port_label.set_size_request(80, -1)
                row.append(port_label)
                
                service_label = Gtk.Label(label=port_info.get("service", "unknown"))
                service_label.set_halign(Gtk.Align.START)
                service_label.set_size_request(150, -1)
                row.append(service_label)
                
                version_label = Gtk.Label(label=port_info.get("version", ""))
                version_label.set_halign(Gtk.Align.START)
                version_label.set_size_request(200, -1)
                row.append(version_label)
                
                desc_label = Gtk.Label(label=port_info.get("description", ""))
                desc_label.set_halign(Gtk.Align.START)
                desc_label.set_hexpand(True)
                desc_label.set_wrap(True)
                row.append(desc_label)
                
                table_box.append(row)
        
        section.append(table_box)
        
        return section
    
    def _create_cms_results(self, cms_results):
        
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        section.set_margin_bottom(20)
        
        header = Gtk.Label(label="CMS & WEB SECURITY ANALYSIS")
        header.add_css_class("section-header")
        header.set_halign(Gtk.Align.START)
        section.append(header)
        
        for cms in cms_results:
            cms_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            cms_panel.add_css_class("chart-panel")
            cms_panel.set_margin_bottom(12)
            
            url = cms.get("url", "Unknown")
            url_label = Gtk.Label(label=f"URL: {url}")
            url_label.set_halign(Gtk.Align.START)
            cms_panel.append(url_label)
            
            cms_detected = cms.get("cms_detected")
            if cms_detected:
                cms_name = cms_detected.get('cms', cms_detected.get('name', 'Unknown'))
                cms_version = cms_detected.get('version', '')
                cms_info = Gtk.Label(label=f"CMS: {cms_name} {cms_version}")
                cms_info.set_halign(Gtk.Align.START)
                cms_panel.append(cms_info)
            else:
                no_cms = Gtk.Label(label="No CMS detected (or site is not WordPress/Joomla)")
                no_cms.set_halign(Gtk.Align.START)
                no_cms.add_css_class("metric-change")
                cms_panel.append(no_cms)
            
            vulns = cms.get("vulnerabilities", [])
            if vulns:
                vuln_header = Gtk.Label(label=f"Vulnerabilities ({len(vulns)}):")
                vuln_header.add_css_class("metric-label")
                vuln_header.set_halign(Gtk.Align.START)
                vuln_header.set_margin_top(12)
                cms_panel.append(vuln_header)
                
                for vuln in vulns[:5]:  # Show first 5
                    vuln_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                    vuln_box.set_margin_start(12)
                    
                    severity = vuln.get("severity", "MEDIUM")
                    badge = RiskBadge(severity)
                    vuln_box.append(badge)
                    
                    vuln_label = Gtk.Label(label=vuln.get("description", "Unknown vulnerability"))
                    vuln_label.set_halign(Gtk.Align.START)
                    vuln_label.set_wrap(True)
                    vuln_label.set_hexpand(True)
                    vuln_box.append(vuln_label)
                    
                    cms_panel.append(vuln_box)
            
            issues = cms.get("security_issues", [])
            if issues:
                issue_header = Gtk.Label(label=f"SECURITY ISSUES ({len(issues)})")
                issue_header.add_css_class("metric-label")
                issue_header.set_halign(Gtk.Align.START)
                issue_header.set_margin_top(16)
                cms_panel.append(issue_header)
                
                issues_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
                issues_list.set_margin_top(12)
                for issue in issues[:10]:  # Show first 10
                    issue_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    
                    bullet = Gtk.Label(label="•")
                    bullet.set_halign(Gtk.Align.START)
                    bullet.add_css_class("warning-text")
                    issue_box.append(bullet)
                    
                    issue_label = Gtk.Label(label=issue.get('description', 'Unknown issue'))
                    issue_label.set_halign(Gtk.Align.START)
                    issue_label.set_wrap(True)
                    issue_label.set_xalign(0)
                    issue_label.set_hexpand(True)
                    issue_label.add_css_class("body-text")
                    issue_box.append(issue_label)
                    
                    issues_list.append(issue_box)
                cms_panel.append(issues_list)
            
            section.append(cms_panel)
        
        return section
    
    def _on_export_clicked(self, button):
        
        if not self.current_results:
            return
        
        dialog = Gtk.FileDialog()
        dialog.set_title("Export Scan Report")
        dialog.set_initial_name(f"scan_report_{self.current_results.get('timestamp', 'unknown')}.json")
        
        dialog.save(self.get_root(), None, self._on_export_complete)
    
    def _on_export_complete(self, dialog, result):
        
        try:
            file = dialog.save_finish(result)
            if file:
                import json
                path = file.get_path()
                with open(path, 'w') as f:
                    json.dump(self.current_results, f, indent=2)
                
                msg_dialog = Gtk.MessageDialog(
                    transient_for=self.get_root(),
                    modal=True,
                    message_type=Gtk.MessageType.INFO,
                    buttons=Gtk.ButtonsType.OK,
                    text="Export Successful"
                )
                msg_dialog.set_property("secondary-text", f"Report saved to {path}")
                msg_dialog.connect("response", lambda d, r: d.destroy())
                msg_dialog.present()
        except Exception as e:
            pass
