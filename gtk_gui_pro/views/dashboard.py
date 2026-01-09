import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from gtk_gui_pro.widgets.metric_card import MetricCard
from gtk_gui_pro.widgets.chart_panel import ChartPanel
from gtk_gui_pro.widgets.status_indicator import StatusIndicator, RiskBadge

class DashboardView(Gtk.ScrolledWindow):
    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.use_demo_data = False  # Set to True for screenshots
        
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        # main container
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main_box.set_margin_start(16)
        main_box.set_margin_end(16)
        main_box.set_margin_top(16)
        main_box.set_margin_bottom(16)
        
        header_box = self._create_header()
        main_box.append(header_box)
        
        content_wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        
        metrics_grid = self._create_metrics_grid()
        content_wrapper.append(metrics_grid)
        
        analytics_box = self._create_analytics_section()
        content_wrapper.append(analytics_box)
        
        main_box.append(content_wrapper)
        
        self.set_child(main_box)
        
        # auto-refresh every 5 seconds
        GLib.timeout_add_seconds(5, self._refresh_dashboard)
    
    def _create_header(self):
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header.set_margin_bottom(16)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title_box.set_hexpand(True)
        
        title = Gtk.Label(label="Network Security Dashboard")
        title.add_css_class("header-title")
        title.set_halign(Gtk.Align.START)
        title_box.append(title)
        
        subtitle = Gtk.Label(label="Real-time network and CMS vulnerability monitoring")
        subtitle.add_css_class("header-subtitle")
        subtitle.set_halign(Gtk.Align.START)
        title_box.append(subtitle)
        
        header.append(title_box)
        
        self.status_indicator = StatusIndicator("Scanner Ready", "active")
        self.status_indicator.set_tooltip_text("Current system status based on recent scan results")
        header.append(self.status_indicator)
        
        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.add_css_class("secondary-button")
        refresh_btn.set_tooltip_text("Update dashboard with latest scan data")
        refresh_btn.connect("clicked", lambda _: self._refresh_dashboard())
        header.append(refresh_btn)
        
        return header
    
    def _create_metrics_grid(self):
        # create metric cards grid
        grid = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        grid.set_homogeneous(True)
        
        self.total_scans_card, total_overlay = self._create_card_with_info(
            "Total Scans", "0", "All time", "low",
            "Total number of security scans performed across all targets"
        )
        grid.append(total_overlay)
        
        self.vulnerabilities_card, vuln_overlay = self._create_card_with_info(
            "Vulnerabilities", "0", "Detected", "high",
            "Known CMS vulnerabilities found in scanned websites"
        )
        grid.append(vuln_overlay)
        
        self.threats_card, threat_overlay = self._create_card_with_info(
            "Active Threats", "0", "Critical ports", "critical",
            "Critical management ports exposed (SSH, Telnet, RDP, VNC)"
        )
        grid.append(threat_overlay)
        
        self.risk_score_card, risk_overlay = self._create_card_with_info(
            "Avg Risk Score", "0.0", "No data", "low",
            "Average security risk score calculated from all scans"
        )
        grid.append(risk_overlay)
        
        self._update_metrics_from_backend()
        
        return grid
    
    def _create_card_with_info(self, label, value, subtitle, severity, tooltip_text):
        
        card = MetricCard(label, value, subtitle, severity)
        
        info_btn = Gtk.Button(label="i")
        info_btn.add_css_class("info-icon")
        info_btn.set_tooltip_text(tooltip_text)
        info_btn.set_has_frame(False)
        info_btn.set_valign(Gtk.Align.START)
        info_btn.set_halign(Gtk.Align.END)
        info_btn.set_size_request(24, 24)
        
        overlay = Gtk.Overlay()
        overlay.set_child(card)
        overlay.add_overlay(info_btn)
        
        return card, overlay
    
    def _get_demo_data(self):
        """Generate fake data for screenshots"""
        import datetime
        import random
        demo_history = []
        base_date = datetime.datetime.now() - datetime.timedelta(days=10)
        
        # Create varied scan activity pattern with peaks and valleys
        daily_scans = [1, 2, 1, 4, 6, 3, 2, 5, 8, 4]  # Varied activity
        
        scan_id = 0
        for day_offset, num_scans in enumerate(daily_scans):
            scan_date = base_date + datetime.timedelta(days=day_offset)
            
            for scan_num in range(num_scans):
                scan_id += 1
                
                # Create more varied risk distribution
                # 38% Critical, 24% High, 33% Medium, 4% Low
                rand = random.random()
                if rand < 0.38:
                    risk_score = random.randint(85, 100)
                    level = "CRITICAL"
                    vulns = random.randint(8, 15)
                    threats = random.randint(2, 4)
                elif rand < 0.62:
                    risk_score = random.randint(65, 84)
                    level = "HIGH"
                    vulns = random.randint(4, 8)
                    threats = random.randint(1, 2)
                elif rand < 0.95:
                    risk_score = random.randint(35, 64)
                    level = "MEDIUM"
                    vulns = random.randint(2, 4)
                    threats = random.randint(0, 1)
                else:
                    risk_score = random.randint(10, 34)
                    level = "LOW"
                    vulns = random.randint(0, 2)
                    threats = 0
                
                scan = {
                    "timestamp": (scan_date + datetime.timedelta(hours=scan_num * 2)).strftime("%Y-%m-%dT%H:%M:%S"),
                    "target": f"192.168.1.{10 + (scan_id % 50)}",
                    "risk_summary": {
                        "score": risk_score,
                        "level": level,
                        "metrics": {
                            "total_cms_vulnerabilities": vulns,
                            "critical_open_ports": threats,
                            "total_open_ports": random.randint(5, 15)
                        }
                    }
                }
                demo_history.append(scan)
        
        return demo_history
    
    def _update_metrics_from_backend(self):
        
        try:
            if self.use_demo_data:
                history = self._get_demo_data()
            else:
                history = self.backend.load_history()
            total_scans = len(history)
            
            total_vulns = 0
            total_threats = 0
            total_open_ports = 0
            total_risk_score = 0
            
            scan_trend = []
            vuln_trend = []
            threat_trend = []
            risk_trend = []
            
            from collections import defaultdict
            import datetime
            
            date_metrics = defaultdict(lambda: {"scans": 0, "vulns": 0, "threats": 0, "risk": 0})
            
            for scan in history:
                timestamp = scan.get("timestamp") or scan.get("date") or ""
                if timestamp:
                    date = timestamp.split("T")[0] if "T" in timestamp else timestamp.split()[0]
                else:
                    date = "unknown"
                
                date_metrics[date]["scans"] += 1
                
                if "risk_summary" in scan:
                    risk = scan["risk_summary"]
                    vulns = risk.get("metrics", {}).get("total_cms_vulnerabilities", 0)
                    threats = risk.get("metrics", {}).get("critical_open_ports", 0)
                    score = risk.get("score", 0)
                    
                    total_vulns += vulns
                    total_threats += threats
                    total_open_ports += risk.get("metrics", {}).get("total_open_ports", 0)
                    total_risk_score += score
                    
                    date_metrics[date]["vulns"] += vulns
                    date_metrics[date]["threats"] += threats
                    date_metrics[date]["risk"] += score
                    
                elif "port_results" in scan or "cms_results" in scan:
                    port_results = scan.get("port_results", [])
                    cms_results = scan.get("cms_results", [])
                    risk = self.backend.summarize_risk(port_results, cms_results)
                    
                    vulns = risk.get("metrics", {}).get("total_cms_vulnerabilities", 0)
                    threats = risk.get("metrics", {}).get("critical_open_ports", 0)
                    score = risk.get("score", 0)
                    
                    total_vulns += vulns
                    total_threats += threats
                    total_open_ports += risk.get("metrics", {}).get("total_open_ports", 0)
                    total_risk_score += score
                    
                    date_metrics[date]["vulns"] += vulns
                    date_metrics[date]["threats"] += threats
                    date_metrics[date]["risk"] += score
            
            sorted_dates = sorted(date_metrics.keys())[-20:]
            for date in sorted_dates:
                metrics = date_metrics[date]
                scan_trend.append(metrics["scans"])
                vuln_trend.append(metrics["vulns"])
                threat_trend.append(metrics["threats"])
                risk_trend.append(metrics["risk"] / metrics["scans"] if metrics["scans"] > 0 else 0)
            
            avg_risk = total_risk_score / total_scans if total_scans > 0 else 0
            
            if avg_risk <= 20:
                risk_level = "low"
                risk_text = "Low Risk"
            elif avg_risk <= 50:
                risk_level = "medium"
                risk_text = "Medium Risk"
            elif avg_risk <= 100:
                risk_level = "high"
                risk_text = "High Risk"
            else:
                risk_level = "critical"
                risk_text = "Critical Risk"
            
            self.total_scans_card.update_value(str(total_scans))
            if scan_trend:
                self.total_scans_card.update_sparkline(scan_trend)
            
            self.vulnerabilities_card.update_value(str(total_vulns))
            if vuln_trend:
                self.vulnerabilities_card.update_sparkline(vuln_trend)
            
            self.threats_card.update_value(str(total_threats))
            if threat_trend:
                self.threats_card.update_sparkline(threat_trend)
            
            self.risk_score_card.update_value(f"{avg_risk:.1f}")
            self.risk_score_card.update_subtitle(risk_text)
            if risk_trend:
                self.risk_score_card.update_sparkline(risk_trend)
            
            if total_scans == 0:
                self.status_indicator.set_status("idle")
                self.status_indicator.label_widget.set_text("No scans yet")
            elif avg_risk > 100:
                self.status_indicator.set_status("error")
                self.status_indicator.label_widget.set_text("Critical risks detected")
            elif avg_risk > 50:
                self.status_indicator.set_status("warning")
                self.status_indicator.label_widget.set_text("Risks detected")
            else:
                self.status_indicator.set_status("active")
                self.status_indicator.label_widget.set_text("System healthy")
                
        except Exception as e:
            logger.debug(f"Dashboard refresh error: {e}")
    
    def _create_analytics_section(self):
        
        analytics = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        
        self.scan_trend_chart = ChartPanel("Scan Activity Trend", "area")
        self.scan_trend_chart.set_tooltip_text("Number of scans performed over the last 10 days")
        
        trend_info = Gtk.Button(label="i")
        trend_info.add_css_class("info-icon")
        trend_info.set_tooltip_text("Number of scans performed over the last 10 days")
        trend_info.set_has_frame(False)
        
        analytics.append(self.scan_trend_chart)
        
        right_col = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        right_col.set_vexpand(False)
        right_col.set_hexpand(True)
        
        self.risk_distribution_chart = ChartPanel("Risk Distribution", "donut")
        self.risk_distribution_chart.set_tooltip_text("Breakdown of scans by risk level: Critical, High, Medium, and Low")
        right_col.append(self.risk_distribution_chart)
        
        self.health_gauge = ChartPanel("Security Health Score", "radial")
        self.health_gauge.set_tooltip_text("Overall security health: 100 minus average risk score")
        right_col.append(self.health_gauge)
        
        analytics.append(right_col)
        
        self._update_charts_from_backend()
        
        return analytics
    
    def _update_charts_from_backend(self):
        
        try:
            if self.use_demo_data:
                history = self._get_demo_data()
            else:
                history = self.backend.load_history()
            
            if history:
                from collections import defaultdict
                import datetime
                
                date_counts = defaultdict(int)
                for scan in history:
                    timestamp = scan.get("timestamp") or scan.get("date") or ""
                    if timestamp:
                        date = timestamp.split("T")[0] if "T" in timestamp else timestamp.split()[0]
                        date_counts[date] += 1
                
                if date_counts:
                    dates = sorted(date_counts.keys())[-10:]  # Last 10 days
                    counts = [date_counts[d] for d in dates]
                    formatted_dates = []
                    for d in dates:
                        try:
                            dt = datetime.datetime.strptime(d, "%Y-%m-%d")
                            formatted_dates.append(dt.strftime("%m/%d"))
                        except:
                            formatted_dates.append(d[-5:])  # Last 5 chars (MM-DD)
                    self.scan_trend_chart.set_data(counts, formatted_dates)
                else:
                    self.scan_trend_chart.set_data([0], ["No data"])
            else:
                self.scan_trend_chart.set_data([0], ["No scans"])
            
            risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            total_risk_score = 0
            scans_with_risk = 0
            
            for scan in history:
                if "risk_summary" in scan:
                    level = scan["risk_summary"].get("level", "LOW").upper()
                    if level in risk_counts:
                        risk_counts[level] += 1
                    total_risk_score += scan["risk_summary"].get("score", 0)
                    scans_with_risk += 1
                elif "port_results" in scan or "cms_results" in scan:
                    port_results = scan.get("port_results", [])
                    cms_results = scan.get("cms_results", [])
                    risk = self.backend.summarize_risk(port_results, cms_results)
                    level = risk.get("level", "LOW").upper()
                    if level in risk_counts:
                        risk_counts[level] += 1
                    total_risk_score += risk.get("score", 0)
                    scans_with_risk += 1
            
            self.risk_distribution_chart.set_data(
                [risk_counts["CRITICAL"], risk_counts["HIGH"], 
                 risk_counts["MEDIUM"], risk_counts["LOW"]],
                ["Critical", "High", "Medium", "Low"]
            )
            
            if scans_with_risk > 0:
                avg_risk = total_risk_score / scans_with_risk
                avg_health = max(0, 100 - min(avg_risk, 100))
            else:
                avg_health = 100
            
            self.health_gauge.set_data([avg_health])
            
        except Exception as e:
            logger.debug(f"Chart update error: {e}")
    
    def _create_activity_section(self):
        
        section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        
        header = Gtk.Label(label="Recent Scan Activity")
        header.add_css_class("chart-header")
        header.set_halign(Gtk.Align.START)
        section.append(header)
        
        activity_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        
        history = self.backend.load_history()
        recent_scans = history[-5:] if len(history) > 5 else history
        recent_scans.reverse()
        
        if not recent_scans:
            no_data = Gtk.Label(label="No scan history available")
            no_data.set_margin_top(20)
            no_data.set_margin_bottom(20)
            activity_list.append(no_data)
        else:
            for scan in recent_scans:
                activity_item = self._create_activity_item(scan)
                activity_list.append(activity_item)
        
        section.append(activity_list)
        
        return section
    
    def _create_activity_item(self, scan):
        
        item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        item.add_css_class("expander-header")
        item.set_margin_top(4)
        item.set_margin_bottom(4)
        
        timestamp = scan.get("timestamp", "Unknown")
        time_label = Gtk.Label(label=timestamp.split("T")[0] if "T" in timestamp else timestamp)
        time_label.set_size_request(120, -1)
        time_label.set_halign(Gtk.Align.START)
        item.append(time_label)
        
        target = scan.get("target", "Unknown")
        target_label = Gtk.Label(label=f"Target: {target}")
        target_label.set_hexpand(True)
        target_label.set_halign(Gtk.Align.START)
        item.append(target_label)
        
        if "risk_summary" in scan:
            risk_level = scan["risk_summary"].get("level", "LOW")
            risk_badge = RiskBadge(risk_level)
            item.append(risk_badge)
            
            score = scan["risk_summary"].get("score", 0)
            score_label = Gtk.Label(label=f"Score: {score}")
            score_label.set_size_request(100, -1)
            item.append(score_label)
        
        return item
    
    def _refresh_dashboard(self):
        
        try:
            self._update_metrics_from_backend()
            self._update_charts_from_backend()
        except Exception as e:
            logger.debug(f"Auto-refresh error: {e}")
        return True
    
    def update_metrics(self):
        
        GLib.idle_add(self._refresh_dashboard)
