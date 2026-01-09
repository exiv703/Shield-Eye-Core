
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.cms_scanner import CMSScanner

class TestCMSScanner:
    
    def setup_method(self):
        
        self.scanner = CMSScanner()
    
    def test_initialization(self):
        
        assert len(self.scanner.cms_signatures) > 0
        assert 'WordPress' in self.scanner.cms_signatures
        assert 'Joomla' in self.scanner.cms_signatures
    
    @patch('backend.cms_scanner.requests.Session.get')
    def test_detect_wordpress_from_meta(self, mock_get):
        
        mock_response = Mock()
        mock_response.text = '<meta name="generator" content="WordPress 6.4" />'
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = self.scanner.detect_wordpress('http://example.com')
        
        assert result is not None
        assert result['cms'] == 'WordPress'
    
    @patch('backend.cms_scanner.requests.Session.get')
    def test_detect_joomla_from_meta(self, mock_get):
        
        mock_response = Mock()
        mock_response.text = '<meta name="generator" content="Joomla! 4.0" />'
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = self.scanner.detect_joomla('http://example.com')
        
        assert result is not None
        assert result['cms'] == 'Joomla'
    
    def test_severity_from_cvss_critical(self):
        
        severity = self.scanner._severity_from_cvss(9.5)
        assert severity == 'CRITICAL'
    
    def test_severity_from_cvss_high(self):
        
        severity = self.scanner._severity_from_cvss(7.5)
        assert severity == 'HIGH'
    
    def test_severity_from_cvss_medium(self):
        
        severity = self.scanner._severity_from_cvss(5.0)
        assert severity == 'MEDIUM'
    
    def test_severity_from_cvss_low(self):
        
        severity = self.scanner._severity_from_cvss(2.0)
        assert severity == 'LOW'
    
    def test_severity_from_cvss_none(self):
        
        severity = self.scanner._severity_from_cvss(None)
        assert severity == 'MEDIUM'
    
    @patch('backend.cms_scanner.requests.Session.get')
    def test_check_wordpress_security_exposed_config(self, mock_get):
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        issues = self.scanner.check_wordpress_security('http://example.com')
        
        assert len(issues) > 0
        assert any(issue['type'] == 'exposed_config' for issue in issues)
    
    @patch('backend.cms_scanner.CVEClient')
    def test_check_wordpress_vulnerabilities_with_cves(self, mock_cve_client):
        
        mock_client = Mock()
        mock_client.get_cves_for_cms.return_value = [
            {
                'id': 'CVE-2023-12345',
                'summary': 'XSS vulnerability',
                'cvss_score': 7.5,
                'source': 'external_cve',
                'provider': 'circl.lu',
                'match_confidence': 'heuristic'
            }
        ]
        self.scanner.cve_client = mock_client
        
        vulns = self.scanner.check_wordpress_vulnerabilities('6.0')
        
        assert len(vulns) > 0
        cve_vulns = [v for v in vulns if v.get('cve')]
        assert len(cve_vulns) > 0
    
    def test_check_wordpress_vulnerabilities_unknown_version(self):
        
        vulns = self.scanner.check_wordpress_vulnerabilities('unknown')
        
        assert len(vulns) == 1
        assert vulns[0]['type'] == 'unknown_version'
    
    @patch('backend.cms_scanner.requests.Session.get')
    @patch('backend.cms_scanner.requests.Session.head')
    def test_analyze_http_security_headers(self, mock_head, mock_get):
        
        mock_response = Mock()
        mock_response.headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY'
        }
        mock_response.status_code = 200
        mock_head.return_value = mock_response
        
        result = self.scanner.analyze_http_security_headers('http://example.com')
        
        assert 'score' in result
        assert 'grade' in result
        assert isinstance(result['score'], int)
    
    def test_generate_recommendations_wordpress(self):
        
        scan_result = {
            'cms_detected': {'cms': 'WordPress', 'version': '6.0'},
            'vulnerabilities': [],
            'security_issues': []
        }
        
        recommendations = self.scanner.generate_recommendations(scan_result)
        
        assert len(recommendations) > 0
        assert any('WordPress' in rec or 'plugins' in rec for rec in recommendations)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
