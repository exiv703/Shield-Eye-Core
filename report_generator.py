from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from typing import Dict, List
import datetime
import os

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):

        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomSubHeading',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.darkgreen
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            alignment=TA_LEFT
        ))
        
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            textColor=colors.red,
            backColor=colors.lightyellow
        ))
        
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            textColor=colors.darkgreen,
            backColor=colors.lightgreen
        ))
    
    def generate_vulnerability_report(self, port_scan_results: List[Dict], 
                                   cms_scan_results: List[Dict], 
                                   output_filename: str = "shieldeye_report.pdf") -> str:

        doc = SimpleDocTemplate(output_filename, pagesize=A4)
        story = []
        
        story.extend(self.create_title_page())
        story.append(PageBreak())
        
        story.extend(self.create_executive_summary(port_scan_results, cms_scan_results))
        story.append(PageBreak())
        
        if port_scan_results:
            story.extend(self.create_port_scan_section(port_scan_results))
            story.append(PageBreak())
        
        if cms_scan_results:
            story.extend(self.create_cms_scan_section(cms_scan_results))
            story.append(PageBreak())
        
        doc.build(story, onFirstPage=self.add_footer, onLaterPages=self.add_footer)
        return output_filename
    
    def create_title_page(self) -> List:

        elements = []
        

        logo_path = os.path.join("branding", "shieldeye_logo_square.png")
        if os.path.exists(logo_path):
            try:
                img = Image(logo_path, width=120, height=120)
                elements.append(img)
                elements.append(Spacer(1, 20))
            except Exception:
                elements.append(Paragraph("<b>ShieldEye</b>", self.styles['CustomTitle']))
        else:
            elements.append(Paragraph("<b>ShieldEye</b>", self.styles['CustomTitle']))
        

        elements.append(Paragraph("ShieldEye Security Report", self.styles['CustomTitle']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("See the threats before they see you", self.styles['CustomHeading']))
        elements.append(Spacer(1, 30))
        
        subtitle = Paragraph("Automated Vulnerability Scanner for Local Businesses", self.styles['CustomHeading'])
        elements.append(subtitle)
        elements.append(Spacer(1, 40))
        
        report_info = [
            ["Generated on:", datetime.datetime.now().strftime("%d.%m.%Y %H:%M")],
            ["Tool:", "ShieldEye v1.0"],
            ["Scan type:", "Comprehensive security audit"],
            ["Scope:", "Port scanning + CMS analysis"]
        ]
        
        info_table = Table(report_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 40))
        
        warning_text = """
        <b>SECURITY NOTICE:</b><br/>
        This report contains sensitive information about system security. 
        These should be treated as confidential and shared only with authorized personnel. All recommendations should be 
        implemented in a timely manner.
        """
        warning = Paragraph(warning_text, self.styles['Warning'])
        elements.append(warning)
        
        return elements
    
    def create_executive_summary(self, port_scan_results: List[Dict], 
                               cms_scan_results: List[Dict]) -> List:
        elements = []
        
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['CustomHeading']))
        elements.append(Spacer(1, 20))
        
        total_hosts = len(port_scan_results)
        total_open_ports = sum(len(host.get('open_ports', [])) for host in port_scan_results)
        total_cms_sites = len([r for r in cms_scan_results if r.get('cms_detected')])
        total_vulnerabilities = sum(len(r.get('vulnerabilities', [])) for r in cms_scan_results)
        
        risk_level = "LOW"
        if total_open_ports > 10 or total_vulnerabilities > 5:
            risk_level = "HIGH"
        elif total_open_ports > 5 or total_vulnerabilities > 2:
            risk_level = "MEDIUM"
        
        stats_data = [
            ["Metric", "Value"],
            ["Number of scanned hosts", str(total_hosts)],
            ["Total open ports", str(total_open_ports)],
            ["Detected CMS systems", str(total_cms_sites)],
            ["Detected vulnerabilities", str(total_vulnerabilities)],
            ["<b>Overall risk level</b>", f"<b>{risk_level}</b>"]
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(stats_table)
        elements.append(Spacer(1, 20))
        
        elements.append(Paragraph("KEY FINDINGS:", self.styles['CustomSubHeading']))
        elements.append(Spacer(1, 10))
        
        findings = []
        
        critical_ports = []
        for host in port_scan_results:
            for port_info in host.get('open_ports', []):
                if port_info['port'] in [22, 23, 3389, 5900]:
                    critical_ports.append(f"{host['target']}:{port_info['port']}")
        
        if critical_ports:
            findings.append(f"• {len(critical_ports)} critical open ports (SSH, Telnet, RDP, VNC)")
        
        if total_open_ports > 0:
            findings.append(f"• Total {total_open_ports} open ports requiring attention")
        
        if total_cms_sites > 0:
            findings.append(f"• {total_cms_sites} CMS systems requiring updates")
        
        if total_vulnerabilities > 0:
            findings.append(f"• {total_vulnerabilities} known vulnerabilities detected")
        
        if not findings:
            findings.append("• No significant security issues detected")
        
        for finding in findings:
            elements.append(Paragraph(finding, self.styles['CustomBody']))
        
        return elements
    
    def create_port_scan_section(self, port_scan_results: List[Dict]) -> List:
        elements = []
        
        elements.append(Paragraph("PORT SCAN RESULTS", self.styles['CustomHeading']))
        elements.append(Spacer(1, 20))
        
        for host_result in port_scan_results:
            host_title = f"Host: {host_result['target']}"
            elements.append(Paragraph(host_title, self.styles['CustomSubHeading']))
            elements.append(Spacer(1, 10))
            
            status_text = f"Status: {host_result.get('status', 'unknown')}"
            elements.append(Paragraph(status_text, self.styles['CustomBody']))
            
            if host_result.get('open_ports'):
                port_data = [["Port", "Service", "Version", "Description"]]
                for port_info in host_result['open_ports']:
                    port_data.append([
                        str(port_info['port']),
                        port_info.get('service', 'unknown'),
                        port_info.get('version', ''),
                        port_info.get('description', 'Unknown')
                    ])
                
                port_table = Table(port_data, colWidths=[0.8*inch, 1.5*inch, 1.5*inch, 2.2*inch])
                port_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                
                elements.append(port_table)
            else:
                elements.append(Paragraph("No open ports detected", self.styles['CustomBody']))
            
            elements.append(Spacer(1, 15))
        
        return elements
    
    def create_cms_scan_section(self, cms_scan_results: List[Dict]) -> List:
        elements = []
        
        elements.append(Paragraph("CMS SCAN RESULTS", self.styles['CustomHeading']))
        elements.append(Spacer(1, 20))
        
        for cms_result in cms_scan_results:
            url_title = f"URL: {cms_result['url']}"
            elements.append(Paragraph(url_title, self.styles['CustomSubHeading']))
            elements.append(Spacer(1, 10))
            
            if cms_result.get('cms_detected'):
                cms_info = cms_result['cms_detected']
                cms_text = f"Detected CMS: {cms_info['cms']} {cms_info['version']}"
                elements.append(Paragraph(cms_text, self.styles['CustomBody']))
                
                if cms_result.get('vulnerabilities'):
                    elements.append(Paragraph("Detected vulnerabilities:", self.styles['CustomBody']))
                    for vuln in cms_result['vulnerabilities']:
                        vuln_text = f"• {vuln['description']} (Severity: {vuln.get('severity', 'UNKNOWN')})"
                        elements.append(Paragraph(vuln_text, self.styles['Warning']))
                
                if cms_result.get('security_issues'):
                    elements.append(Paragraph("Security issues:", self.styles['CustomBody']))
                    for issue in cms_result['security_issues']:
                        issue_text = f"• {issue['description']} (Severity: {issue.get('severity', 'UNKNOWN')})"
                        elements.append(Paragraph(issue_text, self.styles['Warning']))
            else:
                elements.append(Paragraph("No detected CMS", self.styles['CustomBody']))
            
            elements.append(Spacer(1, 15))
        
        return elements
    
    def add_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.purple)
        canvas.drawString(40, 20, "ShieldEye – See the threats before they see you")
        canvas.restoreState() 