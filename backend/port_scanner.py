import logging
import nmap
import socket
import threading
import time
import ssl
import re
from typing import List, Dict, Tuple, Optional

from .config import PORT_SCAN_CONFIG, TIMEOUT_CONFIG

logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        # common service ports
        self.common_ports = {
            20: "FTP-Data",
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            119: "NNTP",
            123: "NTP",
            135: "MS-RPC",
            137: "NetBIOS",
            138: "NetBIOS",
            139: "NetBIOS",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-Trap",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            465: "SMTPS",
            514: "Syslog",
            587: "SMTP-Submission",
            636: "LDAPS",
            873: "rsync",
            993: "IMAPS",
            995: "POP3S",
            1080: "SOCKS",
            1194: "OpenVPN",
            1433: "MSSQL",
            1521: "Oracle",
            1723: "PPTP",
            2049: "NFS",
            2082: "cPanel",
            2083: "cPanel-SSL",
            2086: "WHM",
            2087: "WHM-SSL",
            3000: "Node.js",
            3306: "MySQL",
            3389: "RDP",
            4444: "Metasploit",
            5000: "UPnP",
            5432: "PostgreSQL",
            5555: "Android-Debug",
            5900: "VNC",
            5984: "CouchDB",
            6379: "Redis",
            6660: "IRC",
            6661: "IRC",
            6662: "IRC",
            6663: "IRC",
            6664: "IRC",
            6665: "IRC",
            6666: "IRC",
            6667: "IRC",
            7001: "WebLogic",
            8000: "HTTP-Alt",
            8008: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8081: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            9000: "SonarQube",
            9090: "Openfire",
            9200: "Elasticsearch",
            9300: "Elasticsearch",
            10000: "Webmin",
            11211: "Memcached",
            27017: "MongoDB",
            27018: "MongoDB",
            50000: "SAP",
            50070: "Hadoop"
        }
        
        self.critical_ports = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 11211, 27017}
        self.suspicious_ports = {4444, 5555, 6666, 31337, 12345, 54321}
        
    def scan_single_host(self, target, ports=None, scan_mode='safe'):
        if ports is None:
            ports = list(self.common_ports.keys())
        
        # configure scan parameters based on mode
        if scan_mode == 'aggressive':
            timeout = PORT_SCAN_CONFIG.get('aggressive_timeout', 2)
            max_retries = 4
            nmap_args = '-sS -sV -O -T4 --version-intensity 5'  # faster, more aggressive
        else:
            timeout = PORT_SCAN_CONFIG.get('safe_timeout', 5)
            max_retries = 2
            nmap_args = '-sS -sV -T3 --version-intensity 3'  # slower, safer
            
        results = {
            'target': target,
            'open_ports': [],
            'scan_time': None,
            'status': 'unknown',
            'os_detection': None,
            'hostname': None,
            'mac_address': None
        }
        
        try:
            start_time = time.time()
            
            # run nmap scan
            port_str = ','.join(map(str, ports))
            self.nm.scan(target, port_str, arguments=f'{nmap_args} --max-retries {max_retries} --host-timeout {timeout}s')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                results['status'] = host_info.state()
                
                if 'hostnames' in host_info and host_info['hostnames']:
                    results['hostname'] = host_info['hostnames'][0].get('name', None)
                
                if 'addresses' in host_info and 'mac' in host_info['addresses']:
                    results['mac_address'] = host_info['addresses']['mac']
                
                if 'osmatch' in host_info and host_info['osmatch']:
                    best_match = host_info['osmatch'][0]
                    results['os_detection'] = {
                        'name': best_match.get('name', 'Unknown'),
                        'accuracy': best_match.get('accuracy', 0),
                        'type': best_match.get('osclass', [{}])[0].get('type', 'Unknown') if best_match.get('osclass') else 'Unknown'
                    }
                
                for proto in host_info.all_protocols():
                    ports_info = host_info[proto]
                    for port in ports_info:
                        port_data = ports_info[port]
                        if port_data['state'] == 'open':
                            service = port_data.get('name', 'unknown')
                            version = port_data.get('version', '')
                            product = port_data.get('product', '')
                            extrainfo = port_data.get('extrainfo', '')
                            
                            banner = self._grab_banner(target, port)
                            risk_level = self._assess_port_risk(port, service)
                            
                            port_info = {
                                'port': port,
                                'service': service,
                                'version': version,
                                'product': product,
                                'extrainfo': extrainfo,
                                'description': self.common_ports.get(port, 'Unknown'),
                                'banner': banner,
                                'risk_level': risk_level,
                                'protocol': proto
                            }
                            
                            if port in self.suspicious_ports:
                                port_info['warning'] = 'Suspicious port commonly used by malware'
                            
                            results['open_ports'].append(port_info)
            
            results['scan_time'] = time.time() - start_time
            
        except nmap.PortScannerError as e:
            logger.error("Nmap error: %s", e)
            results['error'] = str(e)
        except Exception as e:
            results['error'] = str(e)
            logger.error("Scan failed for %s: %s", target, e)
            
        return results
    
    def _grab_banner(self, target, port, timeout=None):
        """Attempt to grab service banner from the specified port."""
        if timeout is None:
            timeout = TIMEOUT_CONFIG.get('banner_grab', 3)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((target, port))

                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner[:200]
                except socket.timeout:
                    logger.debug("Banner grab timeout for %s:%d", target, port)
                except Exception as exc:
                    logger.debug("Banner grab failed for %s:%d: %s", target, port, exc)

                if port in [80, 8080, 8000, 8888]:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        match = re.search(r'Server: ([^\r\n]+)', banner)
                        if match:
                            return match.group(1)

                return None
        except socket.timeout:
            logger.debug("Connection timeout for banner grab %s:%d", target, port)
            return None
        except Exception as exc:
            logger.debug("Banner grab error for %s:%d: %s", target, port, exc)
            return None
    
    def _assess_port_risk(self, port: int, service: str) -> str:
        """Assess the security risk level of an open port based on port number and service."""
        if port in self.suspicious_ports:
            return 'CRITICAL'
        elif port in self.critical_ports:
            return 'HIGH'
        elif service.lower() in ['telnet', 'ftp', 'rsh', 'rlogin']:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def scan_network(self, network: str, ports: Optional[List[int]] = None, scan_mode: str = 'safe') -> List[Dict]:
        """Scan a network to discover active hosts and open ports.
        
        Args:
            network: Network address to scan (CIDR notation).
            ports: List of ports to scan. If None, uses common ports.
            scan_mode: Scanning mode - either 'safe' or 'aggressive'.
        
        Returns:
            List of scan results for each host in the network.
        """
        if ports is None:
            ports = list(self.common_ports.keys())
        if scan_mode == 'aggressive':
            timeout = PORT_SCAN_CONFIG.get('aggressive_timeout', 2)
            max_retries = 4
        else:
            timeout = PORT_SCAN_CONFIG.get('safe_timeout', 5)
            max_retries = 2
        results = []
        
        try:
            self.nm.scan(hosts=network, arguments='-sn')
            active_hosts = self.nm.all_hosts()
            
            logger.info("Found %d active hosts in network %s", len(active_hosts), network)
            
            for host in active_hosts:
                logger.info("Scanning host: %s", host)
                host_result = self.scan_single_host(host, ports, scan_mode=scan_mode)
                results.append(host_result)
                
        except nmap.PortScannerError as e:
            logger.error("Nmap error: %s", e)
        except Exception as e:
            logger.error("Network scan failed: %s", e)
            
        return results
    
    def quick_scan(self, target: str) -> Dict:
        from .config import CRITICAL_PORTS_LIST
        return self.scan_single_host(target, CRITICAL_PORTS_LIST)
    
    def get_vulnerability_assessment(self, scan_results: List[Dict]) -> Dict:
        assessment = {
            'risk_level': 'LOW',
            'critical_issues': [],
            'warnings': [],
            'recommendations': []
        }
        
        for host_result in scan_results:
            if 'open_ports' not in host_result:
                continue
                
            for port_info in host_result['open_ports']:
                port = port_info['port']
                service = port_info['service']
                
                if port in [22, 23, 3389, 5900]:
                    assessment['critical_issues'].append({
                        'host': host_result['target'],
                        'port': port,
                        'service': service,
                        'description': f"Critical port {port} ({service}) is open"
                    })
                    
                if service in ['telnet', 'ftp', 'rsh']:
                    assessment['warnings'].append({
                        'host': host_result['target'],
                        'port': port,
                        'service': service,
                        'description': f"Dangerous service {service} on port {port}"
                    })
        
        if len(assessment['critical_issues']) > 0:
            assessment['risk_level'] = 'HIGH'
        elif len(assessment['warnings']) > 0:
            assessment['risk_level'] = 'MEDIUM'
            
        if assessment['risk_level'] == 'HIGH':
            assessment['recommendations'].append("Immediately close critical ports (SSH, Telnet, RDP, VNC)")
        if len(assessment['warnings']) > 0:
            assessment['recommendations'].append("Consider replacing dangerous services with safer alternatives")
        assessment['recommendations'].append("Enable firewall and configure access rules")
        assessment['recommendations'].append("Regularly update software and systems")
        
        return assessment 