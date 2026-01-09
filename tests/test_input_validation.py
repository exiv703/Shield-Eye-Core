
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import ShieldEyeBackend
from backend.exceptions import ValidationError, SecurityPolicyError

class TestTargetValidation:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    def test_valid_ip_address(self):
        
        self.backend._validate_target("192.168.1.1")
    
    def test_valid_hostname(self):
        
        self.backend._validate_target("example.com")
        self.backend._validate_target("sub.example.com")
    
    def test_valid_cidr_network(self):
        
        self.backend._validate_target("192.168.1.0/24")
        self.backend._validate_target("10.0.0.0/16")
    
    def test_empty_target(self):
        
        with pytest.raises(ValidationError, match="empty"):
            self.backend._validate_target("")
    
    def test_whitespace_target(self):
        
        with pytest.raises(ValidationError, match="empty"):
            self.backend._validate_target("   ")
    
    def test_none_target(self):
        
        with pytest.raises(ValidationError, match="non-empty string"):
            self.backend._validate_target(None)
    
    def test_invalid_characters(self):
        
        with pytest.raises(ValidationError, match="invalid characters"):
            self.backend._validate_target("192.168.1.1; rm -rf /")
        
        with pytest.raises(ValidationError, match="invalid characters"):
            self.backend._validate_target("example.com<script>")
    
    def test_invalid_cidr(self):
        
        with pytest.raises(ValidationError, match="Invalid network"):
            self.backend._validate_target("192.168.1.0/33")
        
        with pytest.raises(ValidationError, match="Invalid network"):
            self.backend._validate_target("999.999.999.999/24")
    
    def test_network_too_large(self):
        
        with pytest.raises(ValidationError, match="too large"):
            self.backend._validate_target("10.0.0.0/8")
    
    def test_invalid_hostname(self):
        
        with pytest.raises(ValidationError, match="Invalid hostname"):
            self.backend._validate_target("example..com")
        
        with pytest.raises(ValidationError, match="Invalid hostname"):
            self.backend._validate_target(".example.com")

class TestURLValidation:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    def test_valid_http_url(self):
        
        self.backend._validate_url("http://example.com")
    
    def test_valid_https_url(self):
        
        self.backend._validate_url("https://example.com")
        self.backend._validate_url("https://example.com/path")
    
    def test_empty_url(self):
        
        with pytest.raises(ValidationError, match="empty"):
            self.backend._validate_url("")
    
    def test_none_url(self):
        
        with pytest.raises(ValidationError, match="non-empty string"):
            self.backend._validate_url(None)
    
    def test_missing_scheme(self):
        
        with pytest.raises(ValidationError, match="missing scheme"):
            self.backend._validate_url("example.com")
    
    def test_invalid_scheme(self):
        
        with pytest.raises(ValidationError, match="must be http or https"):
            self.backend._validate_url("ftp://example.com")
        
        with pytest.raises(ValidationError, match="must be http or https"):
            self.backend._validate_url("javascript://alert(1)")
    
    def test_missing_netloc(self):
        
        with pytest.raises(ValidationError, match="missing network location"):
            self.backend._validate_url("http://")
    
    def test_control_characters(self):
        
        with pytest.raises(ValidationError, match="control characters"):
            self.backend._validate_url("http://example.com\x00")

class TestPortValidation:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    def test_valid_ports(self):
        
        result = self.backend._validate_ports([80, 443, 22])
        assert result == [22, 80, 443]  # Sorted and deduplicated
    
    def test_port_deduplication(self):
        
        result = self.backend._validate_ports([80, 80, 443, 443])
        assert result == [80, 443]
    
    def test_empty_port_list(self):
        
        with pytest.raises(ValidationError, match="cannot be empty"):
            self.backend._validate_ports([])
    
    def test_non_list_ports(self):
        
        with pytest.raises(ValidationError, match="must be a list"):
            self.backend._validate_ports("80,443")
    
    def test_non_integer_port(self):
        
        with pytest.raises(ValidationError, match="must be integer"):
            self.backend._validate_ports([80, "443", 22])
    
    def test_port_out_of_range_low(self):
        
        with pytest.raises(ValidationError, match="out of range"):
            self.backend._validate_ports([0, 80])
    
    def test_port_out_of_range_high(self):
        
        with pytest.raises(ValidationError, match="out of range"):
            self.backend._validate_ports([80, 65536])
    
    def test_too_many_ports(self):
        
        with pytest.raises(ValidationError, match="Too many ports"):
            self.backend._validate_ports(list(range(1, 10002)))

class TestScanTypeValidation:
    
    def setup_method(self):
        
        self.backend = ShieldEyeBackend()
    
    def test_invalid_scan_type(self):
        
        with pytest.raises(ValidationError, match="Invalid scan_type"):
            self.backend.scan_ports("127.0.0.1", scan_type="invalid")
    
    def test_invalid_scan_mode(self):
        
        with pytest.raises(ValidationError, match="Invalid scan_mode"):
            self.backend.scan_ports("127.0.0.1", scan_mode="turbo")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
