
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.security_headers import SecurityHeadersAnalyzer, analyze_security_headers

class TestSecurityHeadersAnalyzer:
    
    def setup_method(self):
        
        self.analyzer = SecurityHeadersAnalyzer()
    
    def test_initialization(self):
        
        assert len(self.analyzer.HEADER_CHECKS) == 10
        assert self.analyzer.total_weight == 100
    
    def test_header_weights_sum_to_100(self):
        
        total = sum(check.weight for check in self.analyzer.HEADER_CHECKS)
        assert total == 100

class TestHeaderScoring:
    
    def setup_method(self):
        
        self.analyzer = SecurityHeadersAnalyzer()
    
    def test_perfect_score(self):
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin"
        }
        
        result = self.analyzer.analyze(headers)
        
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["status"] == "Excellent"
    
    def test_no_headers_zero_score(self):
        
        result = self.analyzer.analyze({})
        
        assert result["score"] == 0
        assert result["grade"] == "F"
        assert result["status"] == "Critical"
        assert result["headers_missing"] == 10
    
    def test_partial_headers(self):
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
        
        result = self.analyzer.analyze(headers)
        
        assert result["score"] == 45
        assert result["grade"] == "F"
        assert result["headers_present"] == 3
        assert result["headers_missing"] == 7
    
    def test_case_insensitive_headers(self):
        
        headers = {
            "strict-transport-security": "max-age=31536000",
            "X-FRAME-OPTIONS": "DENY",
            "x-content-type-options": "nosniff"
        }
        
        result = self.analyzer.analyze(headers)
        
        assert result["headers_present"] == 3
        assert result["score"] == 45

class TestValueQuality:
    
    def setup_method(self):
        
        self.analyzer = SecurityHeadersAnalyzer()
    
    def test_good_csp_value(self):
        
        headers = {"Content-Security-Policy": "default-src 'self'"}
        result = self.analyzer.analyze(headers)
        
        assert result["score"] >= 20
        
        csp_detail = next(d for d in result["header_details"] if d["name"] == "Content-Security-Policy")
        assert csp_detail["status"] == "good"
        assert csp_detail["score"] == 20
    
    def test_bad_csp_value(self):
        
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        result = self.analyzer.analyze(headers)
        
        assert result["score"] == 6
        
        assert any(issue["type"] == "weak_header_value" for issue in result["issues"])
        
        csp_detail = next(d for d in result["header_details"] if d["name"] == "Content-Security-Policy")
        assert csp_detail["status"] == "weak"
    
    def test_good_hsts_value(self):
        
        headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        result = self.analyzer.analyze(headers)
        
        hsts_detail = next(d for d in result["header_details"] if d["name"] == "Strict-Transport-Security")
        assert hsts_detail["status"] == "good"
        assert hsts_detail["score"] == 20
    
    def test_bad_hsts_value(self):
        
        headers = {"Strict-Transport-Security": "max-age=0"}
        result = self.analyzer.analyze(headers)
        
        hsts_detail = next(d for d in result["header_details"] if d["name"] == "Strict-Transport-Security")
        assert hsts_detail["status"] == "weak"
        assert hsts_detail["score"] == 6  # 30% of 20

class TestGrading:
    
    def setup_method(self):
        
        self.analyzer = SecurityHeadersAnalyzer()
    
    def test_grade_a(self):
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block"
        }
        
        result = self.analyzer.analyze(headers)
        assert result["grade"] == "B"
        assert result["status"] == "Good"
    
    def test_grade_b(self):
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer"
        }
        
        result = self.analyzer.analyze(headers)
        assert result["grade"] == "C"
        assert result["status"] == "Fair"
    
    def test_grade_c(self):
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
        
        result = self.analyzer.analyze(headers)
        assert result["grade"] == "D"
        assert result["status"] == "Poor"
    
    def test_grade_f(self):
        
        headers = {
            "X-Content-Type-Options": "nosniff"
        }
        
        result = self.analyzer.analyze(headers)
        assert result["grade"] == "F"
        assert result["status"] == "Critical"

class TestIssuesAndRecommendations:
    
    def setup_method(self):
        
        self.analyzer = SecurityHeadersAnalyzer()
    
    def test_missing_required_header_high_severity(self):
        
        result = self.analyzer.analyze({})
        
        hsts_issue = next(i for i in result["issues"] if i["header"] == "Strict-Transport-Security")
        assert hsts_issue["severity"] == "HIGH"
        assert hsts_issue["type"] == "missing_header"
    
    def test_missing_optional_header_medium_severity(self):
        
        result = self.analyzer.analyze({})
        
        pp_issue = next(i for i in result["issues"] if i["header"] == "Permissions-Policy")
        assert pp_issue["severity"] == "MEDIUM"
    
    def test_recommendations_for_missing_headers(self):
        
        result = self.analyzer.analyze({})
        
        assert len(result["recommendations"]) > 0
        assert any("Strict-Transport-Security" in rec for rec in result["recommendations"])
    
    def test_recommendations_for_low_score(self):
        
        headers = {"X-Content-Type-Options": "nosniff"}
        result = self.analyzer.analyze(headers)
        
        assert any("missing security headers" in rec.lower() for rec in result["recommendations"])

class TestConvenienceFunction:
    
    def test_analyze_security_headers_function(self):
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY"
        }
        
        result = analyze_security_headers(headers)
        
        assert "score" in result
        assert "grade" in result
        assert "issues" in result
        assert isinstance(result["score"], int)

class TestHeaderInfo:
    
    def setup_method(self):
        
        self.analyzer = SecurityHeadersAnalyzer()
    
    def test_get_existing_header_info(self):
        
        info = self.analyzer.get_header_info("Strict-Transport-Security")
        
        assert info is not None
        assert info["name"] == "Strict-Transport-Security"
        assert info["weight"] == 20
        assert info["required"] is True
    
    def test_get_nonexistent_header_info(self):
        
        info = self.analyzer.get_header_info("Nonexistent-Header")
        assert info is None
    
    def test_case_insensitive_header_info(self):
        
        info = self.analyzer.get_header_info("strict-transport-security")
        assert info is not None
        assert info["name"] == "Strict-Transport-Security"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
