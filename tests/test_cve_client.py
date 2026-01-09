
import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.cve_client import CVEClient

class TestCVEClient:
    
    def setup_method(self):
        
        self.client = CVEClient()
    
    def test_initialization(self):
        
        assert self.client.base_url == "https://cve.circl.lu/api"
        assert self.client._cache == {}
        assert self.client._min_request_interval == 0.5

class TestCVEFetching:
    
    def setup_method(self):
        
        self.mock_session = Mock()
        self.client = CVEClient(session=self.mock_session)
    
    @patch('time.time')
    def test_successful_fetch(self, mock_time):
        
        mock_time.return_value = 1000.0
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "CVE-2023-12345",
                "summary": "Test vulnerability",
                "cvss": 7.5,
                "Published": "2023-01-01"
            }
        ]
        self.mock_session.get.return_value = mock_response
        
        result = self.client._fetch_vendor_product("wordpress", "wordpress")
        
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2023-12345"
        
        assert ("wordpress", "wordpress") in self.client._cache
        assert self.client._cache[("wordpress", "wordpress")] == result
    
    @patch('time.time')
    def test_cache_hit(self, mock_time):
        
        mock_time.return_value = 1000.0
        
        cached_data = [{"id": "CVE-2023-99999"}]
        self.client._cache[("wordpress", "wordpress")] = cached_data
        
        result = self.client._fetch_vendor_product("wordpress", "wordpress")
        
        self.mock_session.get.assert_not_called()
        assert result == cached_data
    
    @patch('time.time')
    def test_http_error(self, mock_time):
        
        mock_time.return_value = 1000.0
        
        mock_response = Mock()
        mock_response.status_code = 500
        self.mock_session.get.return_value = mock_response
        
        result = self.client._fetch_vendor_product("wordpress", "wordpress")
        
        assert result == []
        assert self.client._cache[("wordpress", "wordpress")] == []
    
    @patch('backend.cve_client.time.time')
    @patch('backend.cve_client.time.sleep')
    def test_rate_limiting(self, mock_sleep, mock_time):
        
        mock_time.side_effect = [1000.0, 1000.2, 1000.5, 1000.7]
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        self.mock_session.get.return_value = mock_response
        
        self.client._fetch_vendor_product("wordpress", "wordpress")
        
        self.client._fetch_vendor_product("joomla", "joomla")
        
        mock_sleep.assert_called()
        sleep_time = mock_sleep.call_args[0][0]
        assert 0.20 <= sleep_time <= 0.35

class TestCVEForCMS:
    
    def setup_method(self):
        
        self.mock_session = Mock()
        self.client = CVEClient(session=self.mock_session)
    
    @patch('time.time')
    def test_wordpress_cves(self, mock_time):
        
        mock_time.return_value = 1000.0
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "id": "CVE-2023-12345",
                "summary": "XSS vulnerability",
                "cvss": 6.5,
                "Published": "2023-01-01"
            }
        ]
        self.mock_session.get.return_value = mock_response
        
        result = self.client.get_cves_for_cms("WordPress", "5.0")
        
        assert len(result) > 0
        cve = result[0]
        assert "id" in cve
        assert "summary" in cve
        assert "cvss_score" in cve
        assert "source" in cve
        assert cve["source"] == "external_cve"
    
    def test_unknown_cms(self):
        
        result = self.client.get_cves_for_cms("UnknownCMS", "1.0")
        assert result == []
    
    def test_no_version(self):
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        self.mock_session.get.return_value = mock_response
        
        result = self.client.get_cves_for_cms("WordPress", None)
        assert isinstance(result, list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
