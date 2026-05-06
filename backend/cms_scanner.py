import logging
import requests
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

from .cve_client import CVEClient
from .security_headers import SecurityHeadersAnalyzer
from .config import CMS_SCAN_CONFIG, TIMEOUT_CONFIG, COMMON_SUBDOMAINS
from .http_client import safe_request

logger = logging.getLogger(__name__)

class CMSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.cve_client = CVEClient(session=self.session)
        self.security_headers_analyzer = SecurityHeadersAnalyzer()
        
        # CMS detection signatures
        self.cms_signatures = {
            'WordPress': {
                'paths': ['/wp-content/', '/wp-includes/', '/wp-admin/', '/wp-login.php'],
                'meta': 'WordPress',
                'files': ['/readme.html', '/license.txt'],
                'version_regex': r'wordpress\s+(\d+\.\d+(?:\.\d+)?)',
            },
            'Joomla': {
                'paths': ['/administrator/', '/components/', '/modules/', '/templates/'],
                'meta': 'Joomla',
                'files': ['/administrator/manifests/files/joomla.xml'],
                'version_regex': r'joomla!\s+(\d+\.\d+(?:\.\d+)?)',
            },
            'Drupal': {
                'paths': ['/sites/default/', '/core/', '/modules/', '/themes/'],
                'meta': 'Drupal',
                'files': ['/CHANGELOG.txt', '/core/CHANGELOG.txt'],
                'version_regex': r'drupal\s+(\d+\.\d+(?:\.\d+)?)',
            },
            'Magento': {
                'paths': ['/skin/frontend/', '/media/catalog/', '/js/mage/'],
                'meta': 'Magento',
                'files': ['/RELEASE_NOTES.txt'],
            },
            'PrestaShop': {
                'paths': ['/themes/', '/modules/', '/classes/'],
                'files': ['/docs/CHANGELOG.txt'],
            },
            'Ghost': {
                'meta': 'Ghost',
                'paths': ['/ghost/', '/content/'],
            },
            'TYPO3': {
                'paths': ['/typo3/', '/typo3conf/'],
                'meta': 'TYPO3',
            },
        }
        
    def detect_cms(self, url: str) -> Optional[Dict]:
        cms_result = None
        max_confidence = 0
        
        # check each CMS signature
        for cms, signature in self.cms_signatures.items():
            confidence = 0
            
            # check meta tags
            try:
                response = safe_request("GET", url, session=self.session, timeout_key="cms_scan")
                soup = BeautifulSoup(response.text, 'html.parser')
                generator_meta = soup.find('meta', attrs={'name': 'generator'})
                if generator_meta and signature.get('meta') and signature['meta'].lower() in generator_meta.get('content', '').lower():
                    confidence += 1
            except requests.RequestException:
                pass
            except Exception as exc:
                logger.warning("Meta tag check error for %s: %s", cms, exc)
            
            for path in signature.get('paths', []):
                try:
                    response = safe_request("HEAD", urljoin(url, path), session=self.session, timeout_key="cms_scan")
                    if response.status_code < 400:
                        confidence += 1
                except requests.RequestException:
                    continue
                except Exception:
                    continue
            
            for file in signature.get('files', []):
                try:
                    response = safe_request("HEAD", urljoin(url, file), session=self.session, timeout_key="cms_scan")
                    if response.status_code < 400:
                        confidence += 1
                except requests.RequestException:
                    continue
                except Exception:
                    continue
            
            if 'version_regex' in signature:
                try:
                    response = safe_request("GET", url, session=self.session, timeout_key="cms_scan")
                    version_match = re.search(signature['version_regex'], response.text)
                    if version_match:
                        confidence += 1
                except requests.RequestException:
                    pass
                except Exception:
                    pass
            
            if confidence > max_confidence:
                max_confidence = confidence
                cms_result = {
                    'cms': cms,
                    'confidence': confidence,
                }
        
        return cms_result
    
    def detect_wordpress(self, url: str) -> Optional[Dict]:
        try:
            wordpress_result = self.detect_cms(url)
            if wordpress_result and wordpress_result['cms'] == 'WordPress':
                return wordpress_result
            else:
                response = safe_request("GET", url, session=self.session, timeout_key="cms_scan")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                generator_meta = soup.find('meta', attrs={'name': 'generator'})
                content = None
                if generator_meta is not None:
                    try:
                        from bs4 import Tag
                        if isinstance(generator_meta, Tag):
                            content = generator_meta.get('content', None)
                    except ImportError:
                        content = None
                if isinstance(content, str) and 'wordpress' in content.lower():
                    version_match = re.search(r'wordpress\s+(\d+\.\d+)', content, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        return {
                            'cms': 'WordPress',
                            'version': version,
                            'detection_method': 'meta_tag'
                        }
                
                if 'wp-content' in response.text:
                    readme_url = urljoin(url, 'readme.html')
                    try:
                        readme_response = safe_request("GET", readme_url, session=self.session, timeout_key="cms_scan")
                        version_match = re.search(r'Version\s+(\d+\.\d+)', readme_response.text)
                        if version_match:
                            return {
                                'cms': 'WordPress',
                                'version': version_match.group(1),
                                'detection_method': 'readme.html'
                            }
                    except requests.RequestException:
                        pass
                    except Exception:
                        pass
                    
                    version_url = urljoin(url, 'wp-includes/version.php')
                    try:
                        version_response = safe_request("GET", version_url, session=self.session, timeout_key="cms_scan")
                        version_match = re.search(r'\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]', version_response.text)
                        if version_match:
                            return {
                                'cms': 'WordPress',
                                'version': version_match.group(1),
                                'detection_method': 'version.php'
                            }
                    except requests.RequestException:
                        pass
                    except Exception:
                        pass
                    
                    return {
                        'cms': 'WordPress',
                        'version': 'unknown',
                        'detection_method': 'wp-content_detected'
                    }
                    
        except Exception as e:
            logger.error("WordPress detection failed: %s", e)
            return None
            
        return None
    
    def detect_joomla(self, url: str) -> Optional[Dict]:

        try:
            response = safe_request("GET", url, session=self.session, timeout_key="cms_scan")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            generator_meta = soup.find('meta', attrs={'name': 'generator'})
            content = None
            if generator_meta is not None:
                try:
                    from bs4 import Tag
                    if isinstance(generator_meta, Tag):
                        content = generator_meta.get('content', None)
                except ImportError:
                    content = None
            if isinstance(content, str) and 'joomla' in content.lower():
                version_match = re.search(r'joomla!\s*(\d+\.\d+)', content, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                    return {
                        'cms': 'Joomla',
                        'version': version,
                        'detection_method': 'meta_tag'
                    }
            
            joomla_indicators = [
                'joomla',
                'mod_',
                'com_',
                'Joomla!'
            ]
            
            if any(indicator in response.text for indicator in joomla_indicators):
                manifest_url = urljoin(url, 'administrator/manifests/files/joomla.xml')
                try:
                    manifest_response = safe_request("GET", manifest_url, session=self.session, timeout_key="cms_scan")
                    version_match = re.search(r'<version>([^<]+)</version>', manifest_response.text)
                    if version_match:
                        return {
                            'cms': 'Joomla',
                            'version': version_match.group(1),
                            'detection_method': 'manifest.xml'
                        }
                except requests.RequestException:
                    pass
                except Exception:
                    pass
                
                return {
                    'cms': 'Joomla',
                    'version': 'unknown',
                    'detection_method': 'indicators_detected'
                }
                
        except Exception as e:
            logger.error("Joomla detection failed: %s", e)
            return None
            
        return None
    
    def scan_cms(self, url: str) -> Dict:

        result = {
            'url': url,
            'cms_detected': None,
            'vulnerabilities': [],
            'security_issues': [],
            'recommendations': []
        }
        
        wp_result = self.detect_wordpress(url)
        if wp_result:
            result['cms_detected'] = wp_result
            result['vulnerabilities'] = self.check_wordpress_vulnerabilities(wp_result['version'])
            result['security_issues'] = self.check_wordpress_security(url)
            
        joomla_result = self.detect_joomla(url)
        if joomla_result:
            result['cms_detected'] = joomla_result
            result['vulnerabilities'] = self.check_joomla_vulnerabilities(joomla_result['version'])
            result['security_issues'] = self.check_joomla_security(url)
        
        header_analysis = self.analyze_http_security_headers(url)
        result['security_headers'] = header_analysis
        
        if header_analysis.get('issues'):
            result['security_issues'].extend(header_analysis['issues'])
        
        result['recommendations'] = self.generate_recommendations(result)
        
        if header_analysis.get('recommendations'):
            result['recommendations'].extend(header_analysis['recommendations'])
        
        return result

    def analyze_http_security_headers(self, url: str) -> Dict:
        try:
            try:
                response = safe_request("HEAD", url, session=self.session, timeout_key="cms_scan", allow_redirects=True)
                if response.status_code >= 400:
                    raise requests.RequestException("HEAD request failed")
            except requests.RequestException:
                logger.debug("HEAD request failed, using GET instead")
                response = safe_request("GET", url, session=self.session, timeout_key="cms_scan", allow_redirects=True)

            analysis = self.security_headers_analyzer.analyze(response.headers)
            
            logger.info("Security headers score for %s: %d/100 (Grade: %s)", 
                       url, analysis["score"], analysis["grade"])
            
            return analysis

        except Exception as exc:
            logger.error("HTTP security header analysis failed: %s", exc)
            return {
                "score": 0,
                "grade": "F",
                "status": "Error",
                "issues": [{"type": "analysis_error", "description": str(exc), "severity": "LOW"}],
                "recommendations": [],
                "header_details": []
            }
    
    def check_wordpress_vulnerabilities(self, version: str) -> List[Dict]:
        vulnerabilities: List[Dict] = []
        seen_cves = set()
        
        if version == 'unknown':
            logger.info("WordPress version unknown, skipping CVE lookup")
            return [{'type': 'unknown_version', 'description': 'Cannot determine WordPress version', 'severity': 'LOW'}]
        
        try:
            latest_version = self.get_latest_wordpress_version()
            if latest_version and version < latest_version:
                vulnerabilities.append({
                    'type': 'outdated_version',
                    'description': f'Outdated WordPress version {version} (latest: {latest_version})',
                    'severity': 'MEDIUM'
                })
        except Exception as exc:
            logger.warning("Failed to check latest WordPress version: %s", exc)
        
        try:
            external_cves = self.cve_client.get_cves_for_cms('WordPress', version)
            logger.info("Found %d external CVEs for WordPress %s", len(external_cves), version)
            for item in external_cves:
                cve_id = item.get('id')
                if not cve_id or cve_id in seen_cves:
                    continue
                sev = self._severity_from_cvss(item.get('cvss_score'))
                vulnerabilities.append({
                    'cve': cve_id,
                    'type': 'external_cve',
                    'description': item.get('summary') or 'External CVE',
                    'severity': sev,
                    'source': item.get('source'),
                    'provider': item.get('provider'),
                    'cvss_score': item.get('cvss_score'),
                    'match_confidence': item.get('match_confidence'),
                })
                seen_cves.add(cve_id)
        except Exception as exc:
            logger.error("External CVE lookup for WordPress %s failed: %s", version, exc)
            
        return vulnerabilities
    
    def check_joomla_vulnerabilities(self, version: str) -> List[Dict]:
        vulnerabilities: List[Dict] = []
        seen_cves = set()
        
        if version == 'unknown':
            logger.info("Joomla version unknown, skipping CVE lookup")
            return [{'type': 'unknown_version', 'description': 'Cannot determine Joomla version', 'severity': 'LOW'}]
        
        try:
            external_cves = self.cve_client.get_cves_for_cms('Joomla', version)
            logger.info("Found %d external CVEs for Joomla %s", len(external_cves), version)
            for item in external_cves:
                cve_id = item.get('id')
                if not cve_id or cve_id in seen_cves:
                    continue
                sev = self._severity_from_cvss(item.get('cvss_score'))
                vulnerabilities.append({
                    'cve': cve_id,
                    'type': 'external_cve',
                    'description': item.get('summary') or 'External CVE',
                    'severity': sev,
                    'source': item.get('source'),
                    'provider': item.get('provider'),
                    'cvss_score': item.get('cvss_score'),
                    'match_confidence': item.get('match_confidence'),
                })
                seen_cves.add(cve_id)
        except Exception as exc:
            logger.error("External CVE lookup for Joomla %s failed: %s", version, exc)
        
        return vulnerabilities

    def _severity_from_cvss(self, score: Optional[float]) -> str:
        if score is None:
            return 'MEDIUM'
        try:
            value = float(score)
        except (TypeError, ValueError):
            return 'MEDIUM'
        if value >= 9.0:
            return 'CRITICAL'
        if value >= 7.0:
            return 'HIGH'
        if value >= 4.0:
            return 'MEDIUM'
        return 'LOW'
    
    def check_wordpress_security(self, url: str) -> List[Dict]:

        issues = []
        
        try:
            config_url = urljoin(url, 'wp-config.php')
            response = safe_request("GET", config_url, session=self.session, timeout_key="cms_scan")
            if response.status_code == 200:
                issues.append({
                    'type': 'exposed_config',
                    'description': 'wp-config.php file is publicly accessible',
                    'severity': 'CRITICAL'
                })
        except requests.RequestException as exc:
            logger.debug("WordPress config check failed: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error in WordPress config check: %s", exc)
        
        try:
            admin_url = urljoin(url, 'wp-admin/')
            response = safe_request("GET", admin_url, session=self.session, timeout_key="cms_scan")
            if response.status_code == 200:
                issues.append({
                    'type': 'admin_accessible',
                    'description': 'Admin panel is publicly accessible',
                    'severity': 'HIGH'
                })
        except requests.RequestException as exc:
            logger.debug("WordPress admin check failed: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error in WordPress admin check: %s", exc)
            
        return issues
    
    def check_joomla_security(self, url: str) -> List[Dict]:

        issues = []
        
        try:
            admin_url = urljoin(url, 'administrator/')
            response = safe_request("GET", admin_url, session=self.session, timeout_key="cms_scan")
            if response.status_code == 200:
                issues.append({
                    'type': 'admin_accessible',
                    'description': 'Joomla admin panel is publicly accessible',
                    'severity': 'HIGH'
                })
        except requests.RequestException as exc:
            logger.debug("Joomla admin check failed: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error in Joomla admin check: %s", exc)
            
        return issues
    
    def get_latest_wordpress_version(self) -> Optional[str]:

        try:
            response = safe_request(
                "GET",
                'https://api.wordpress.org/core/version-check/1.7/',
                session=self.session,
                timeout_key="cms_scan",
            )
            data = response.json()
            return data.get('offers', [{}])[0].get('version')
        except requests.RequestException as exc:
            logger.warning("Failed to fetch latest WordPress version: %s", exc)
            return None
        except Exception as exc:
            logger.error("Unexpected error fetching WordPress version: %s", exc)
            return None
    
    def generate_recommendations(self, scan_result: Dict) -> List[str]:

        recommendations = []
        
        if not scan_result['cms_detected']:
            return ["No known CMS detected"]
        
        cms = scan_result['cms_detected']['cms']
        version = scan_result['cms_detected']['version']
        
        recommendations.append(f"Regularly update {cms} to the latest version")
        recommendations.append("Use strong passwords for all admin accounts")
        recommendations.append("Enable two-factor authentication")
        recommendations.append("Regularly create backups")
        
        if cms == 'WordPress':
            recommendations.append("Use only plugins from the official WordPress repository")
            recommendations.append("Regularly update plugins and themes")
            recommendations.append("Consider using a security plugin (e.g. Wordfence, Sucuri)")
            recommendations.append("Hide WordPress version in source code")
        
        if cms == 'Joomla':
            recommendations.append("Use only extensions from the official Joomla directory")
            recommendations.append("Regularly update extensions")
            recommendations.append("Consider using an extension security")
            recommendations.append("Hide Joomla version in source code")
        
        if scan_result['vulnerabilities']:
            recommendations.append("Immediately update CMS to the latest version")
            
        if scan_result['security_issues']:
            recommendations.append("Fix detected security issues")
            
        return recommendations 