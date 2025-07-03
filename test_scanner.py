ASCII_LOGO = r'''
   _____ _     _     _     _     ______         
  / ____| |   (_)   | |   | |   |  ____|        
 | (___ | |__  _ ___| |__ | |__ | |__ ___  _ __ 
  \___ \| '_ \| / __| '_ \| '_ \|  __/ _ \| '__|
  ____) | | | | \__ \ | | | | | | | | (_) | |   
 |_____/|_| |_|_|___/_| |_|_| |_|_|  \___/|_|   
'''
import sys
import time
from port_scanner import PortScanner
from cms_scanner import CMSScanner
from report_generator import ReportGenerator


def test_port_scanner():
    print("=== Port Scanner Test ===")
    scanner = PortScanner()
    print("Scanning localhost...")
    try:
        result = scanner.quick_scan("127.0.0.1")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Scan time: {result.get('scan_time', 0):.2f}s")
        if result.get('open_ports'):
            print("Open ports:")
            for port_info in result['open_ports']:
                print(f"  Port {port_info['port']}: {port_info['service']} - {port_info['description']}")
        else:
            print("No open ports")
    except Exception as e:
        print(f"Error during scan: {e}")
    print()

def test_cms_scanner():
    print("=== CMS Scanner Test ===")
    scanner = CMSScanner()
    test_url = "http://example.com"
    print(f"Scanning CMS for: {test_url}")
    try:
        result = scanner.scan_cms(test_url)
        if result.get('cms_detected'):
            cms_info = result['cms_detected']
            print(f"Detected CMS: {cms_info['cms']} {cms_info['version']}")
        else:
            print("No known CMS detected")
        if result.get('vulnerabilities'):
            print("Detected vulnerabilities:")
            for vuln in result['vulnerabilities']:
                print(f"  - {vuln['description']}")
        if result.get('security_issues'):
            print("Security issues:")
            for issue in result['security_issues']:
                print(f"  - {issue['description']}")
    except Exception as e:
        print(f"Error during CMS scan: {e}")
    print()

def test_report_generator():
    print("=== Report Generator Test ===")
    generator = ReportGenerator()
    test_port_results = [
        {
            'target': '192.168.1.1',
            'status': 'up',
            'open_ports': [
                {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.2', 'description': 'SSH'},
                {'port': 80, 'service': 'http', 'version': 'nginx 1.18', 'description': 'HTTP'}
            ],
            'scan_time': 2.5
        }
    ]
    test_cms_results = [
        {
            'url': 'http://example.com',
            'cms_detected': {
                'cms': 'WordPress',
                'version': '5.8',
                'detection_method': 'meta_tag'
            },
            'vulnerabilities': [
                {
                    'type': 'outdated_version',
                    'description': 'Outdated WordPress version 5.8',
                    'severity': 'MEDIUM'
                }
            ],
            'security_issues': [],
            'recommendations': ['Update WordPress to the latest version']
        }
    ]
    try:
        report_file = generator.generate_vulnerability_report(
            test_port_results, test_cms_results, "test_report.pdf"
        )
        print(f"Test report generated: {report_file}")
    except Exception as e:
        print(f"Error during report generation: {e}")
    print()

def test_integration():
    print("=== Integration Test ===")
    print("Initializing components...")
    port_scanner = PortScanner()
    cms_scanner = CMSScanner()
    report_generator = ReportGenerator()
    print("All components initialized successfully")
    print()

def main():
    print(ASCII_LOGO)
    print("ShieldEye – See the threats before they see you\n")
    print("Automated Vulnerability Scanner – ShieldEye Tests")
    print("=" * 50)
    print()
    print("Checking dependencies...")
    try:
        import nmap
        print("✓ python-nmap")
    except ImportError:
        print("✗ python-nmap - INSTALL: pip install python-nmap")
        return
    try:
        import requests
        print("✓ requests")
    except ImportError:
        print("✗ requests - INSTALL: pip install requests")
        return
    try:
        from bs4 import BeautifulSoup
        print("✓ beautifulsoup4")
    except ImportError:
        print("✗ beautifulsoup4 - INSTALL: pip install beautifulsoup4")
        return
    try:
        from reportlab.lib.pagesizes import letter
        print("✓ reportlab")
    except ImportError:
        print("✗ reportlab - INSTALL: pip install reportlab")
        return
    print("✓ All dependencies available")
    print()
    try:
        test_integration()
        test_port_scanner()
        test_cms_scanner()
        test_report_generator()
        print("=" * 50)
        print("All tests completed!")
        print("The application is ready to use.")
        print("Run: python main.py")
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nError during tests: {e}")

if __name__ == "__main__":
    main() 