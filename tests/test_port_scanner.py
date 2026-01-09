
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.port_scanner import PortScanner

class TestPortScanner:
    
    def setup_method(self):
        
        self.scanner = PortScanner()
    
    def test_initialization(self):
        
        assert len(self.scanner.common_ports) > 0
        assert len(self.scanner.critical_ports) > 0
        assert len(self.scanner.suspicious_ports) > 0
    
    def test_assess_port_risk_suspicious(self):
        
        risk = self.scanner._assess_port_risk(4444, 'metasploit')
        assert risk == 'CRITICAL'
    
    def test_assess_port_risk_critical(self):
        
        risk = self.scanner._assess_port_risk(22, 'ssh')
        assert risk == 'HIGH'
    
    def test_assess_port_risk_telnet(self):
        
        risk = self.scanner._assess_port_risk(23, 'telnet')
        assert risk == 'HIGH'
    
    def test_assess_port_risk_http(self):
        
        risk = self.scanner._assess_port_risk(80, 'http')
        assert risk == 'MEDIUM'
    
    def test_assess_port_risk_low(self):
        
        risk = self.scanner._assess_port_risk(12345, 'unknown')
        assert risk == 'CRITICAL'
    
    @patch('backend.port_scanner.nmap.PortScanner')
    def test_scan_single_host_success(self, mock_nmap):
        
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ['192.168.1.1']
        
        mock_host = MagicMock()
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']
        mock_host.__getitem__.return_value = {
            80: {
                'state': 'open',
                'name': 'http',
                'version': '2.4',
                'product': 'Apache',
                'extrainfo': ''
            }
        }
        mock_nm.__getitem__.return_value = mock_host
        
        self.scanner.nm = mock_nm
        
        result = self.scanner.scan_single_host('192.168.1.1', [80])
        
        assert result['target'] == '192.168.1.1'
        assert result['status'] == 'up'
        assert len(result['open_ports']) > 0
    
    def test_quick_scan_uses_critical_ports(self):
        
        with patch.object(self.scanner, 'scan_single_host') as mock_scan:
            mock_scan.return_value = {'target': '192.168.1.1', 'open_ports': []}
            
            self.scanner.quick_scan('192.168.1.1')
            
            mock_scan.assert_called_once()
            args = mock_scan.call_args[0]
            assert args[0] == '192.168.1.1'
    
    def test_get_vulnerability_assessment_high_risk(self):
        
        scan_results = [{
            'target': '192.168.1.1',
            'open_ports': [
                {'port': 22, 'service': 'ssh'},
                {'port': 3389, 'service': 'rdp'}
            ]
        }]
        
        assessment = self.scanner.get_vulnerability_assessment(scan_results)
        
        assert assessment['risk_level'] == 'HIGH'
        assert len(assessment['critical_issues']) == 2
    
    def test_get_vulnerability_assessment_medium_risk(self):
        
        scan_results = [{
            'target': '192.168.1.1',
            'open_ports': [
                {'port': 23, 'service': 'telnet'}
            ]
        }]
        
        assessment = self.scanner.get_vulnerability_assessment(scan_results)
        
        assert assessment['risk_level'] in ['HIGH', 'MEDIUM']
        assert len(assessment['warnings']) > 0
    
    def test_get_vulnerability_assessment_low_risk(self):
        
        scan_results = [{
            'target': '192.168.1.1',
            'open_ports': []
        }]
        
        assessment = self.scanner.get_vulnerability_assessment(scan_results)
        
        assert assessment['risk_level'] == 'LOW'

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
