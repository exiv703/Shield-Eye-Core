import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

class EcosystemView(Gtk.ScrolledWindow):
    def __init__(self):
        super().__init__()
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main_box.set_margin_top(32)
        main_box.set_margin_bottom(32)
        main_box.set_margin_start(40)
        main_box.set_margin_end(40)
        
        title = Gtk.Label(label="ShieldEye Ecosystem")
        title.add_css_class("header-title")
        title.set_halign(Gtk.Align.START)
        main_box.append(title)
        
        subtitle = Gtk.Label(label="Comprehensive security toolkit for modern applications")
        subtitle.add_css_class("header-subtitle")
        subtitle.set_halign(Gtk.Align.START)
        subtitle.set_margin_bottom(32)
        main_box.append(subtitle)
        
        # related projects in the ecosystem
        projects = [
            {
                "name": "ShieldEye Core",
                "icon": "🛡️",
                "tagline": "Network Security Scanner",
                "description": "Professional network security scanner with port scanning, CMS vulnerability detection, and security headers analysis. The foundation of the ShieldEye security toolkit.",
                "features": [
                    "Advanced port scanning (Nmap)",
                    "CMS vulnerability detection",
                    "Security headers analysis",
                    "GTK 4.0 desktop interface"
                ],
                "tech": "Python • GTK4 • Nmap • CVE Database",
                "url": "https://github.com/exiv703/ShieldEye-Core"
            },
            {
                "name": "ShieldEye SurfaceScan",
                "icon": "🌐",
                "tagline": "Web Application Surface Scanner",
                "description": "Analyzes web applications for vulnerabilities using headless browser automation, intelligent dependency analysis, and AI-powered threat intelligence.",
                "features": [
                    "Playwright browser automation",
                    "CVE/vulnerability mapping",
                    "AI-powered insights (Ollama)",
                    "GTK3 desktop interface"
                ],
                "tech": "TypeScript • Node.js • Python • Docker",
                "url": "https://github.com/exiv703/ShieldEye-SurfaceScan"
            },
            {
                "name": "ShieldEye NeuralScan",
                "icon": "🤖",
                "tagline": "AI-Powered Code Security Analyzer",
                "description": "Combines traditional static analysis with cutting-edge AI technology for comprehensive code security review using local transformer models.",
                "features": [
                    "50+ security patterns",
                    "Local AI models (StarCoder2)",
                    "Container scanning (Trivy)",
                    "100% local-first architecture"
                ],
                "tech": "Python • GTK4 • AI/ML • Docker",
                "url": "https://github.com/exiv703/ShieldEye-NeuralScan"
            },
            {
                "name": "ShieldEye ComplianceScan",
                "icon": "📋",
                "tagline": "Enterprise Compliance Scanner",
                "description": "Security and compliance scanning platform for enterprise environments with multi-standard support and professional reporting.",
                "features": [
                    "SSL/TLS & headers analysis",
                    "GDPR, PCI-DSS, ISO 27001",
                    "CVSS v3.1 scoring",
                    "Professional PDF reports"
                ],
                "tech": "Python • GTK4 • Enterprise",
                "url": "https://github.com/exiv703/ShieldEye_ComplianceScan"
            }
        ]
        
        # create cards for each project
        for project in projects:
            card = self._create_project_card(project)
            main_box.append(card)
        
        footer = Gtk.Label(label="All projects are open-source and available on GitHub")
        footer.add_css_class("metric-label")
        footer.set_halign(Gtk.Align.CENTER)
        footer.set_margin_top(32)
        main_box.append(footer)
        
        self.set_child(main_box)
    
    def _create_project_card(self, project):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        card.add_css_class("ecosystem-card")
        card.set_margin_bottom(24)
        
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header_box.set_margin_bottom(12)
        
        icon_label = Gtk.Label(label=project["icon"])
        icon_label.add_css_class("ecosystem-icon")
        header_box.append(icon_label)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title_box.set_hexpand(True)
        
        name_label = Gtk.Label(label=project["name"])
        name_label.add_css_class("ecosystem-title")
        name_label.set_halign(Gtk.Align.START)
        title_box.append(name_label)
        
        tagline_label = Gtk.Label(label=project["tagline"])
        tagline_label.add_css_class("ecosystem-tagline")
        tagline_label.set_halign(Gtk.Align.START)
        title_box.append(tagline_label)
        
        header_box.append(title_box)
        card.append(header_box)
        
        desc_label = Gtk.Label(label=project["description"])
        desc_label.add_css_class("ecosystem-description")
        desc_label.set_wrap(True)
        desc_label.set_halign(Gtk.Align.START)
        desc_label.set_xalign(0)
        desc_label.set_margin_bottom(16)
        card.append(desc_label)
        
        features_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        features_box.set_margin_bottom(16)
        
        for feature in project["features"]:
            feature_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            
            bullet = Gtk.Label(label="•")
            bullet.add_css_class("ecosystem-bullet")
            feature_row.append(bullet)
            
            feature_label = Gtk.Label(label=feature)
            feature_label.add_css_class("ecosystem-feature")
            feature_label.set_halign(Gtk.Align.START)
            feature_row.append(feature_label)
            
            features_box.append(feature_row)
        
        card.append(features_box)
        
        footer_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        
        tech_label = Gtk.Label(label=project["tech"])
        tech_label.add_css_class("ecosystem-tech")
        tech_label.set_halign(Gtk.Align.START)
        tech_label.set_hexpand(True)
        footer_box.append(tech_label)
        
        link_button = Gtk.Button(label="View on GitHub →")
        link_button.add_css_class("secondary-button")
        link_button.connect("clicked", lambda b: self._open_url(project["url"]))
        footer_box.append(link_button)
        
        card.append(footer_box)
        
        return card
    
    def _open_url(self, url):
        import webbrowser
        webbrowser.open(url)
