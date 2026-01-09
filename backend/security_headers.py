import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class HeaderCheck:
    name: str
    weight: int  # importance weight (0-100)
    required: bool
    description: str
    good_values: List[str] = None
    bad_values: List[str] = None

class SecurityHeadersAnalyzer:
    # security headers to check
    HEADER_CHECKS = [
        HeaderCheck(
            name="Strict-Transport-Security",
            weight=20,
            required=True,
            description="Enforces HTTPS connections",
            good_values=["max-age=31536000", "includeSubDomains", "preload"],
            bad_values=["max-age=0"]
        ),
        HeaderCheck(
            name="Content-Security-Policy",
            weight=20,
            required=True,
            description="Prevents XSS and injection attacks",
            good_values=["default-src 'self'"],
            bad_values=["unsafe-inline", "unsafe-eval", "*"]
        ),
        HeaderCheck(
            name="X-Frame-Options",
            weight=15,
            required=True,
            description="Prevents clickjacking attacks",
            good_values=["DENY", "SAMEORIGIN"],
            bad_values=["ALLOW-FROM"]
        ),
        HeaderCheck(
            name="X-Content-Type-Options",
            weight=10,
            required=True,
            description="Prevents MIME-sniffing attacks",
            good_values=["nosniff"],
            bad_values=[]
        ),
        HeaderCheck(
            name="Referrer-Policy",
            weight=10,
            required=True,
            description="Controls referrer information",
            good_values=["no-referrer", "strict-origin-when-cross-origin"],
            bad_values=["unsafe-url"]
        ),
        HeaderCheck(
            name="Permissions-Policy",
            weight=8,
            required=False,
            description="Controls browser features and APIs",
            good_values=["geolocation=()", "microphone=()"],
            bad_values=["*"]
        ),
        HeaderCheck(
            name="X-XSS-Protection",
            weight=5,
            required=False,
            description="Legacy XSS protection (deprecated but useful)",
            good_values=["1; mode=block"],
            bad_values=["0"]
        ),
        HeaderCheck(
            name="Cross-Origin-Embedder-Policy",
            weight=5,
            required=False,
            description="Controls cross-origin resource embedding",
            good_values=["require-corp"],
            bad_values=[]
        ),
        HeaderCheck(
            name="Cross-Origin-Opener-Policy",
            weight=4,
            required=False,
            description="Isolates browsing context",
            good_values=["same-origin", "same-origin-allow-popups"],
            bad_values=[]
        ),
        HeaderCheck(
            name="Cross-Origin-Resource-Policy",
            weight=3,
            required=False,
            description="Controls cross-origin resource loading",
            good_values=["same-origin", "same-site"],
            bad_values=[]
        ),
    ]
    
    def __init__(self):
        self.total_weight = sum(check.weight for check in self.HEADER_CHECKS)
    
    def analyze(self, headers):
        # normalize header names to lowercase
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        score = 0
        issues = []
        recommendations = []
        header_details = []
        
        for check in self.HEADER_CHECKS:
            header_name_lower = check.name.lower()
            header_value = normalized_headers.get(header_name_lower)
            
            detail = {
                "name": check.name,
                "present": header_value is not None,
                "value": header_value,
                "weight": check.weight,
                "score": 0,
                "status": "missing"
            }
            
            # check if header is missing
            if header_value is None:
                severity = "HIGH" if check.required else "MEDIUM"
                issues.append({
                    "type": "missing_header",
                    "header": check.name,
                    "description": f"Missing security header: {check.name}",
                    "severity": severity,
                    "recommendation": f"Add {check.name} header: {check.description}"
                })
                recommendations.append(f"Add {check.name} header")
                detail["status"] = "missing"
            else:
                value_lower = header_value.lower()
                
                # check for bad/weak values
                has_bad_value = False
                if check.bad_values:
                    for bad in check.bad_values:
                        if bad.lower() in value_lower:
                            has_bad_value = True
                            issues.append({
                                "type": "weak_header_value",
                                "header": check.name,
                                "description": f"{check.name} has weak/unsafe value: '{bad}'",
                                "severity": "MEDIUM",
                                "recommendation": f"Remove '{bad}' from {check.name}"
                            })
                            detail["status"] = "weak"
                            break
                
                if has_bad_value:
                    detail["score"] = check.weight * 0.3  # partial credit
                    score += detail["score"]
                else:
                    # check for good values
                    has_good_value = False
                    if check.good_values:
                        for good in check.good_values:
                            if good.lower() in value_lower:
                                has_good_value = True
                                break
                    
                    if has_good_value or not check.good_values:
                        detail["score"] = check.weight
                        detail["status"] = "good"
                        score += check.weight
                    else:
                        detail["score"] = check.weight * 0.6
                        detail["status"] = "suboptimal"
                        score += detail["score"]
                        issues.append({
                            "type": "suboptimal_header",
                            "header": check.name,
                            "description": f"{check.name} could be improved",
                            "severity": "LOW",
                            "recommendation": f"Consider strengthening {check.name} configuration"
                        })
            
            header_details.append(detail)
        
        # calculate final score and grade
        final_score = int((score / self.total_weight) * 100)
        
        if final_score >= 90:
            grade = "A"
            overall_status = "Excellent"
        elif final_score >= 80:
            grade = "B"
            overall_status = "Good"
        elif final_score >= 70:
            grade = "C"
            overall_status = "Fair"
        elif final_score >= 60:
            grade = "D"
            overall_status = "Poor"
        else:
            grade = "F"
            overall_status = "Critical"
        
        if final_score < 80:
            recommendations.append("Review and implement missing security headers")
        if any(issue["severity"] == "HIGH" for issue in issues):
            recommendations.append("Prioritize fixing HIGH severity header issues")
        
        return {
            "score": final_score,
            "grade": grade,
            "status": overall_status,
            "issues": issues,
            "recommendations": list(set(recommendations)),
            "header_details": header_details,
            "total_headers_checked": len(self.HEADER_CHECKS),
            "headers_present": sum(1 for d in header_details if d["present"]),
            "headers_missing": sum(1 for d in header_details if not d["present"])
        }
    
    def get_header_info(self, header_name):
        # get info about specific header
        for check in self.HEADER_CHECKS:
            if check.name.lower() == header_name.lower():
                return {
                    "name": check.name,
                    "weight": check.weight,
                    "required": check.required,
                    "description": check.description,
                    "good_values": check.good_values,
                    "bad_values": check.bad_values
                }
        return None

def analyze_security_headers(headers):
    # convenience function
    analyzer = SecurityHeadersAnalyzer()
    return analyzer.analyze(headers)
