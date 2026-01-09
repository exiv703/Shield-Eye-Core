
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import ShieldEyeBackend
from backend.exceptions import ValidationError, SecurityPolicyError

class TestShieldEyeBackendInit:
    
    def test_default_initialization(self):
        
        backend = ShieldEyeBackend()
        
        assert backend.port_scanner is not None
        assert backend.cms_scanner is not None
        assert backend.report_generator is not None
    
    def test_dependency_injection(self):
        
        mock_port_scanner = Mock()
        mock_cms_scanner = Mock()
        mock_report_gen = Mock()
        
        backend = ShieldEyeBackend(
            port_scanner=mock_port_scanner,
            cms_scanner=mock_cms_scanner,
            report_generator=mock_report_gen
        )
        
        assert backend.port_scanner is mock_port_scanner
        assert backend.cms_scanner is mock_cms_scanner
        assert backend.report_generator is mock_report_gen
    
    def test_custom_config(self):
        
        custom_security = {
            'max_concurrent_scans': 5,
            'rate_limit': 2.0,
            'whitelist_ips': ['192.168.1.0/24'],
            'blacklist_ips': ['10.0.0.0/8']
        }
        
        backend = ShieldEyeBackend(security_config=custom_security)
        
        assert backend.max_concurrent_scans == 5
        assert backend.rate_limit == 2.0
        assert len(backend.whitelist) == 1
        assert len(backend.blacklist) == 1

class TestValidation:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    def test_validate_target_valid_ip(self):
        
        self.backend._validate_target('192.168.1.1')
    
    def test_validate_target_valid_cidr(self):
        
        self.backend._validate_target('192.168.1.0/24')
    
    def test_validate_target_valid_hostname(self):
        
        self.backend._validate_target('example.com')
    
    def test_validate_target_empty(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_target('')
    
    def test_validate_target_invalid_chars(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_target('192.168.1.1; rm -rf /')
    
    def test_validate_target_too_large_network(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_target('10.0.0.0/8')
    
    def test_validate_url_valid_http(self):
        
        self.backend._validate_url('http://example.com')
    
    def test_validate_url_valid_https(self):
        
        self.backend._validate_url('https://example.com')
    
    def test_validate_url_missing_scheme(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_url('example.com')
    
    def test_validate_url_invalid_scheme(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_url('ftp://example.com')
    
    def test_validate_ports_valid(self):
        
        ports = self.backend._validate_ports([80, 443, 8080])
        assert len(ports) == 3
        assert 80 in ports
    
    def test_validate_ports_empty(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_ports([])
    
    def test_validate_ports_out_of_range(self):
        
        with pytest.raises(ValidationError):
            self.backend._validate_ports([80, 70000])
    
    def test_validate_ports_deduplicates(self):
        
        ports = self.backend._validate_ports([80, 80, 443])
        assert len(ports) == 2

class TestSecurityPolicy:
    
    def test_ensure_target_allowed_no_restrictions(self):
        
        backend = ShieldEyeBackend()
        backend._ensure_target_allowed('192.168.1.1')
    
    def test_ensure_target_allowed_whitelist(self):
        
        config = {
            'whitelist_ips': ['192.168.1.0/24'],
            'blacklist_ips': []
        }
        backend = ShieldEyeBackend(security_config=config)
        
        backend._ensure_target_allowed('192.168.1.100')
    
    def test_ensure_target_blocked_by_whitelist(self):
        
        config = {
            'whitelist_ips': ['192.168.1.0/24'],
            'blacklist_ips': []
        }
        backend = ShieldEyeBackend(security_config=config)
        
        with pytest.raises(SecurityPolicyError):
            backend._ensure_target_allowed('10.0.0.1')
    
    def test_ensure_target_blocked_by_blacklist(self):
        
        config = {
            'whitelist_ips': [],
            'blacklist_ips': ['10.0.0.0/8']
        }
        backend = ShieldEyeBackend(security_config=config)
        
        with pytest.raises(SecurityPolicyError):
            backend._ensure_target_allowed('10.0.0.1')
    
    def test_ensure_target_hostname_allowed(self):
        
        backend = ShieldEyeBackend()
        backend._ensure_target_allowed('example.com')

class TestScanning:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    @patch.object(ShieldEyeBackend, '_scan_single_host_stealth')
    def test_scan_ports_single_host(self, mock_scan):
        
        mock_scan.return_value = {
            'target': '192.168.1.1',
            'open_ports': [{'port': 80, 'service': 'http'}]
        }
        
        results = self.backend.scan_ports('192.168.1.1', scan_type='single')
        
        assert len(results) == 1
        assert results[0]['target'] == '192.168.1.1'
    
    def test_scan_ports_invalid_scan_type(self):
        
        with pytest.raises(ValidationError):
            self.backend.scan_ports('192.168.1.1', scan_type='invalid')
    
    def test_scan_ports_invalid_scan_mode(self):
        
        with pytest.raises(ValidationError):
            self.backend.scan_ports('192.168.1.1', scan_mode='invalid')
    
    @patch('backend.CMSScanner.scan_cms')
    def test_scan_cms_success(self, mock_scan):
        
        mock_scan.return_value = {
            'url': 'http://example.com',
            'cms_detected': {'cms': 'WordPress', 'version': '6.0'}
        }
        
        result = self.backend.scan_cms('http://example.com')
        
        assert result['url'] == 'http://example.com'
        assert 'scan_mode' in result
        assert 'stealth' in result

class TestRiskAssessment:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    def test_summarize_risk_no_issues(self):
        
        port_results = []
        cms_results = []
        
        risk = self.backend.summarize_risk(port_results, cms_results)
        
        assert risk['score'] == 0
        assert risk['level'] == 'LOW'
    
    def test_summarize_risk_critical_ports(self):
        
        port_results = [{
            'open_ports': [
                {'port': 22, 'service': 'ssh'},
                {'port': 3389, 'service': 'rdp'}
            ]
        }]
        cms_results = []
        
        risk = self.backend.summarize_risk(port_results, cms_results)
        
        assert risk['score'] > 0
        assert risk['metrics']['critical_open_ports'] == 2
    
    def test_summarize_risk_cms_vulnerabilities(self):
        
        port_results = []
        cms_results = [{
            'vulnerabilities': [
                {'severity': 'CRITICAL'},
                {'severity': 'HIGH'}
            ]
        }]
        
        risk = self.backend.summarize_risk(port_results, cms_results)
        
        assert risk['score'] > 0
        assert risk['level'] in ['HIGH', 'CRITICAL']

class TestAlerts:
    
    def test_check_alert_needed_disabled(self):
        
        config = {'enabled': False}
        backend = ShieldEyeBackend(alert_config=config)
        
        scan_result = {'risk_summary': {'score': 100, 'level': 'CRITICAL'}}
        alert = backend.check_alert_needed(scan_result)
        
        assert alert['alert'] is False
    
    def test_check_alert_needed_by_score(self):
        
        config = {'enabled': True, 'score_threshold': 50, 'min_level': 'HIGH'}
        backend = ShieldEyeBackend(alert_config=config)
        
        scan_result = {'risk_summary': {'score': 80, 'level': 'MEDIUM'}}
        alert = backend.check_alert_needed(scan_result)
        
        assert alert['alert'] is True
    
    def test_check_alert_needed_by_level(self):
        
        config = {'enabled': True, 'score_threshold': 100, 'min_level': 'HIGH'}
        backend = ShieldEyeBackend(alert_config=config)
        
        scan_result = {'risk_summary': {'score': 50, 'level': 'CRITICAL'}}
        alert = backend.check_alert_needed(scan_result)
        
        assert alert['alert'] is True

class TestHistory:
    
    def test_save_and_load_history(self, tmp_path):
        
        backend = ShieldEyeBackend()
        history_file = tmp_path / "test_history.json"
        
        port_results = [{'target': '192.168.1.1', 'open_ports': []}]
        cms_results = []
        
        backend.save_scan_to_history(port_results, cms_results, str(history_file))
        history = backend.load_history(str(history_file))
        
        assert len(history) == 1
        assert 'date' in history[0]
    
    def test_summarize_history_empty(self, tmp_path):
        
        backend = ShieldEyeBackend()
        history_file = tmp_path / "empty_history.json"
        
        summary = backend.summarize_history(str(history_file))
        
        assert summary['total_scans'] == 0
        assert summary['average_score'] == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
