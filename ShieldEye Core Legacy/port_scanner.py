import nmap
import socket
import threading
import time
from typing import List, Dict, Tuple, Optional

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_ports = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }
        
    def scan_single_host(self, target: str, ports: Optional[List[int]] = None, scan_mode: str = 'safe') -> Dict:

        if ports is None:
            ports = list(self.common_ports.keys())
        if scan_mode == 'aggressive':
            timeout = 2
            max_retries = 4
        else:
            timeout = 5
            max_retries = 2
        results = {
            'target': target,
            'open_ports': [],
            'scan_time': None,
            'status': 'unknown'
        }
        
        try:
            start_time = time.time()
            
            port_str = ','.join(map(str, ports))
            self.nm.scan(target, port_str, arguments=f'-sS -T4 --max-retries {max_retries} --host-timeout {timeout}s')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                results['status'] = host_info.state()
                
                for proto in host_info.all_protocols():
                    ports_info = host_info[proto]
                    for port in ports_info:
                        if ports_info[port]['state'] == 'open':
                            service = ports_info[port].get('name', 'unknown')
                            version = ports_info[port].get('version', '')
                            results['open_ports'].append({
                                'port': port,
                                'service': service,
                                'version': version,
                                'description': self.common_ports.get(port, 'Unknown')
                            })
            
            results['scan_time'] = time.time() - start_time
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def scan_network(self, network: str, ports: Optional[List[int]] = None, scan_mode: str = 'safe') -> List[Dict]:

        if ports is None:
            ports = list(self.common_ports.keys())
        if scan_mode == 'aggressive':
            timeout = 2
            max_retries = 4
        else:
            timeout = 5
            max_retries = 2
        results = []
        
        try:
            self.nm.scan(hosts=network, arguments='-sn')
            active_hosts = self.nm.all_hosts()
            
            print(f"Znaleziono {len(active_hosts)} aktywnych hostów w sieci {network}")
            
            for host in active_hosts:
                print(f"Skanowanie hosta: {host}")
                host_result = self.scan_single_host(host, ports, scan_mode=scan_mode)
                results.append(host_result)
                
        except Exception as e:
            print(f"Błąd podczas skanowania sieci: {e}")
            
        return results
    
    def quick_scan(self, target: str) -> Dict:

        critical_ports = [22, 23, 80, 443, 3389, 5900]
        return self.scan_single_host(target, critical_ports)
    
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