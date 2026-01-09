import requests
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

class CMSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.wordpress_vulnerabilities = {
            '4.0': ['CVE-2014-9031', 'CVE-2014-9032'],
            '4.1': ['CVE-2015-2213', 'CVE-2015-2214'],
            '4.2': ['CVE-2015-3440', 'CVE-2015-3441'],
            '4.3': ['CVE-2015-5622', 'CVE-2015-5623'],
            '4.4': ['CVE-2016-1564', 'CVE-2016-1565'],
            '4.5': ['CVE-2016-2167', 'CVE-2016-2168'],
            '4.6': ['CVE-2016-6896', 'CVE-2016-6897'],
            '4.7': ['CVE-2017-5613', 'CVE-2017-5614'],
            '4.8': ['CVE-2017-9061', 'CVE-2017-9062'],
            '4.9': ['CVE-2018-10101', 'CVE-2018-10102'],
            '5.0': ['CVE-2018-19470', 'CVE-2018-19471'],
            '5.1': ['CVE-2019-6977', 'CVE-2019-6978'],
            '5.2': ['CVE-2019-17671', 'CVE-2019-17672'],
            '5.3': ['CVE-2020-11025', 'CVE-2020-11026'],
            '5.4': ['CVE-2020-11027', 'CVE-2020-11028'],
            '5.5': ['CVE-2020-11029', 'CVE-2020-11030'],
            '5.6': ['CVE-2021-29447', 'CVE-2021-29448'],
            '5.7': ['CVE-2021-29449', 'CVE-2021-29450'],
            '5.8': ['CVE-2021-29451', 'CVE-2021-29452'],
            '5.9': ['CVE-2022-21663', 'CVE-2022-21664'],
            '6.0': ['CVE-2022-21665', 'CVE-2022-21666'],
            '6.1': ['CVE-2022-21667', 'CVE-2022-21668'],
            '6.2': ['CVE-2023-28121', 'CVE-2023-28122'],
            '6.3': ['CVE-2023-28123', 'CVE-2023-28124'],
            '6.4': ['CVE-2023-28125', 'CVE-2023-28126']
        }
        
        self.joomla_vulnerabilities = {
            '3.0': ['CVE-2013-2134', 'CVE-2013-2135'],
            '3.1': ['CVE-2014-7222', 'CVE-2014-7223'],
            '3.2': ['CVE-2014-7224', 'CVE-2014-7225'],
            '3.3': ['CVE-2014-7226', 'CVE-2014-7227'],
            '3.4': ['CVE-2015-8562', 'CVE-2015-8563'],
            '3.5': ['CVE-2016-8869', 'CVE-2016-8870'],
            '3.6': ['CVE-2016-8871', 'CVE-2016-8872'],
            '3.7': ['CVE-2017-8917', 'CVE-2017-8918'],
            '3.8': ['CVE-2018-6376', 'CVE-2018-6377'],
            '3.9': ['CVE-2019-10945', 'CVE-2019-10946'],
            '4.0': ['CVE-2021-23132', 'CVE-2021-23133'],
            '4.1': ['CVE-2022-23708', 'CVE-2022-23709'],
            '4.2': ['CVE-2022-23710', 'CVE-2022-23711'],
            '4.3': ['CVE-2023-23752', 'CVE-2023-23753'],
            '4.4': ['CVE-2023-23754', 'CVE-2023-23755']
        }
    
    def detect_wordpress(self, url: str) -> Optional[Dict]:

        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            generator_meta = soup.find('meta', attrs={'name': 'generator'})
            content = None
            if generator_meta is not None:
                try:
                    from bs4 import Tag
                    if isinstance(generator_meta, Tag):
                        content = generator_meta.get('content', None)
                except ImportError:
                    pass
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
                    readme_response = self.session.get(readme_url, timeout=5)
                    version_match = re.search(r'Version\s+(\d+\.\d+)', readme_response.text)
                    if version_match:
                        return {
                            'cms': 'WordPress',
                            'version': version_match.group(1),
                            'detection_method': 'readme.html'
                        }
                except:
                    pass
                
                version_url = urljoin(url, 'wp-includes/version.php')
                try:
                    version_response = self.session.get(version_url, timeout=5)
                    version_match = re.search(r'\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]', version_response.text)
                    if version_match:
                        return {
                            'cms': 'WordPress',
                            'version': version_match.group(1),
                            'detection_method': 'version.php'
                        }
                except:
                    pass
                
                return {
                    'cms': 'WordPress',
                    'version': 'unknown',
                    'detection_method': 'wp-content_detected'
                }
                
        except Exception as e:
            return None
            
        return None
    
    def detect_joomla(self, url: str) -> Optional[Dict]:

        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            generator_meta = soup.find('meta', attrs={'name': 'generator'})
            content = None
            if generator_meta is not None:
                try:
                    from bs4 import Tag
                    if isinstance(generator_meta, Tag):
                        content = generator_meta.get('content', None)
                except ImportError:
                    pass
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
                    manifest_response = self.session.get(manifest_url, timeout=5)
                    version_match = re.search(r'<version>([^<]+)</version>', manifest_response.text)
                    if version_match:
                        return {
                            'cms': 'Joomla',
                            'version': version_match.group(1),
                            'detection_method': 'manifest.xml'
                        }
                except:
                    pass
                
                return {
                    'cms': 'Joomla',
                    'version': 'unknown',
                    'detection_method': 'indicators_detected'
                }
                
        except Exception as e:
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
        
        result['recommendations'] = self.generate_recommendations(result)
        
        return result
    
    def check_wordpress_vulnerabilities(self, version: str) -> List[Dict]:

        vulnerabilities = []
        
        if version == 'unknown':
            return [{'type': 'unknown_version', 'description': 'Cannot determine WordPress version'}]
        
        if version in self.wordpress_vulnerabilities:
            for cve in self.wordpress_vulnerabilities[version]:
                vulnerabilities.append({
                    'cve': cve,
                    'type': 'known_vulnerability',
                    'description': f'Known vulnerability {cve} in WordPress {version}',
                    'severity': 'HIGH'
                })
        
        try:
            latest_version = self.get_latest_wordpress_version()
            if latest_version and version < latest_version:
                vulnerabilities.append({
                    'type': 'outdated_version',
                    'description': f'Outdated WordPress version {version} (latest: {latest_version})',
                    'severity': 'MEDIUM'
                })
        except:
            pass
            
        return vulnerabilities
    
    def check_joomla_vulnerabilities(self, version: str) -> List[Dict]:

        vulnerabilities = []
        
        if version == 'unknown':
            return [{'type': 'unknown_version', 'description': 'Cannot determine Joomla version'}]
        
        if version in self.joomla_vulnerabilities:
            for cve in self.joomla_vulnerabilities[version]:
                vulnerabilities.append({
                    'cve': cve,
                    'type': 'known_vulnerability',
                    'description': f'Known vulnerability {cve} in Joomla {version}',
                    'severity': 'HIGH'
                })
        
        return vulnerabilities
    
    def check_wordpress_security(self, url: str) -> List[Dict]:

        issues = []
        
        try:
            config_url = urljoin(url, 'wp-config.php')
            response = self.session.get(config_url, timeout=5)
            if response.status_code == 200:
                issues.append({
                    'type': 'exposed_config',
                    'description': 'wp-config.php file is publicly accessible',
                    'severity': 'CRITICAL'
                })
            
            admin_url = urljoin(url, 'wp-admin/')
            response = self.session.get(admin_url, timeout=5)
            if response.status_code == 200:
                issues.append({
                    'type': 'admin_accessible',
                    'description': 'Admin panel is publicly accessible',
                    'severity': 'HIGH'
                })
                
        except:
            pass
            
        return issues
    
    def check_joomla_security(self, url: str) -> List[Dict]:

        issues = []
        
        try:
            admin_url = urljoin(url, 'administrator/')
            response = self.session.get(admin_url, timeout=5)
            if response.status_code == 200:
                issues.append({
                    'type': 'admin_accessible',
                    'description': 'Joomla admin panel is publicly accessible',
                    'severity': 'HIGH'
                })
                
        except:
            pass
            
        return issues
    
    def get_latest_wordpress_version(self) -> Optional[str]:

        try:
            response = self.session.get('https://api.wordpress.org/core/version-check/1.7/', timeout=10)
            data = response.json()
            return data.get('offers', [{}])[0].get('version')
        except:
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