import ssl
import socket
import dns.resolver
import dns.zone
import dns.query
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import subprocess
import re

from .config import TIMEOUT_CONFIG

class SSLDNSScanner:
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        dns_timeout = TIMEOUT_CONFIG.get('dns_lookup', 5)
        self.dns_resolver.timeout = dns_timeout
        self.dns_resolver.lifetime = dns_timeout
    
    def scan_ssl_certificate(self, hostname, port=443):
        results = {
            'hostname': hostname,
            'port': port,
            'certificate': None,
            'chain': [],
            'vulnerabilities': [],
            'security_issues': [],
            'grade': None
        }
        
        try:
            # setup SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # accept self-signed certs
            
            connect_timeout = TIMEOUT_CONFIG.get('socket_connect', 5)
            with socket.create_connection((hostname, port), timeout=connect_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    cert_info = {
                        'subject': self._get_cert_subject(cert),
                        'issuer': self._get_cert_issuer(cert),
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_before': cert.not_valid_before.isoformat(),
                        'not_after': cert.not_valid_after.isoformat(),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key_algorithm': cert.public_key().__class__.__name__,
                        'key_size': self._get_key_size(cert),
                        'san': self._get_san(cert)
                    }
                    
                    results['certificate'] = cert_info
                    
                    # check certificate expiration
                    now = datetime.utcnow()
                    if cert.not_valid_after < now:
                        results['security_issues'].append({
                            'type': 'expired_certificate',
                            'severity': 'CRITICAL',
                            'description': 'SSL certificate has expired'
                        })
                    elif (cert.not_valid_after - now).days < 30:
                        results['security_issues'].append({
                            'type': 'expiring_soon',
                            'severity': 'HIGH',
                            'description': f'SSL certificate expires in {(cert.not_valid_after - now).days} days'
                        })
                    
                    # check key size
                    key_size = self._get_key_size(cert)
                    if key_size and key_size < 2048:
                        results['security_issues'].append({
                            'type': 'weak_key',
                            'severity': 'HIGH',
                            'description': f'Weak key size: {key_size} bits (minimum recommended: 2048)'
                        })
                    
                    if 'sha1' in cert.signature_algorithm_oid._name.lower():
                        results['security_issues'].append({
                            'type': 'weak_signature',
                            'severity': 'HIGH',
                            'description': 'Certificate uses weak SHA-1 signature algorithm'
                        })
                    
                    # check protocol version
                    protocol_version = ssock.version()
                    results['protocol_version'] = protocol_version
                    
                    if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        results['security_issues'].append({
                            'type': 'outdated_protocol',
                            'severity': 'HIGH',
                            'description': f'Outdated protocol version: {protocol_version}'
                        })
                    
                    # check cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        results['cipher_suite'] = {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        }
                        
                        weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']  # known weak ciphers
                        if any(weak in cipher[0] for weak in weak_ciphers):
                            results['security_issues'].append({
                                'type': 'weak_cipher',
                                'severity': 'HIGH',
                                'description': f'Weak cipher suite: {cipher[0]}'
                            })
            
            results['grade'] = self._calculate_ssl_grade(results)
            
        except ssl.SSLError as e:
            results['error'] = f"SSL Error: {str(e)}"
        except socket.timeout:
            results['error'] = "Connection timeout"
        except Exception as e:
            results['error'] = f"Error: {str(e)}"
        
        return results
    
    def _get_cert_subject(self, cert) -> str:
        try:
            return cert.subject.rfc4514_string()
        except Exception as e:
            logger.debug("Failed to extract subject from certificate: %s", e)
            return "Unknown"
    
    def _get_cert_issuer(self, cert) -> str:
        try:
            return cert.issuer.rfc4514_string()
        except Exception as e:
            logger.debug("Failed to extract issuer from certificate: %s", e)
            return "Unknown"
    
    def _get_key_size(self, cert):
        try:
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                return public_key.key_size
        except Exception as e:
            logger.debug("Failed to extract key size from certificate: %s", e)
        return None
    
    def _get_san(self, cert):
        """Extract Subject Alternative Names from certificate."""
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return [name.value for name in san_ext.value]
        except Exception as e:
            logger.debug("No SAN extension found in certificate: %s", e)
            return []
    
    def _calculate_ssl_grade(self, results):
        # calculate SSL grade based on issues
        score = 100
        
        for issue in results.get('security_issues', []):
            if issue['severity'] == 'CRITICAL':
                score -= 40
            elif issue['severity'] == 'HIGH':
                score -= 20
            elif issue['severity'] == 'MEDIUM':
                score -= 10
        
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def enumerate_dns_records(self, domain):
        results = {
            'domain': domain,
            'records': {},
            'nameservers': [],
            'mail_servers': [],
            'subdomains': [],
            'security_issues': []
        }
        
        # common DNS record types to check
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
        
        for record_type in record_types:
            try:
                answers = self.dns_resolver.resolve(domain, record_type)
                results['records'][record_type] = [str(rdata) for rdata in answers]
                
                if record_type == 'NS':
                    results['nameservers'] = results['records'][record_type]
                elif record_type == 'MX':
                    results['mail_servers'] = results['records'][record_type]
                    
            except dns.resolver.NoAnswer:
                results['records'][record_type] = []
            except dns.resolver.NXDOMAIN:
                results['error'] = f"Domain {domain} does not exist"
                return results
            except Exception as e:
                results['records'][record_type] = []
        
        # check for DNSSEC
        try:
            answers = self.dns_resolver.resolve(domain, 'DNSKEY')
            results['dnssec_enabled'] = True
        except:
            results['dnssec_enabled'] = False
            results['security_issues'].append({
                'type': 'no_dnssec',
                'severity': 'MEDIUM',
                'description': 'DNSSEC not enabled'
            })
        
        # check for SPF record
        if 'TXT' in results['records']:
            spf_found = any('v=spf1' in record for record in results['records']['TXT'])
            if not spf_found:
                results['security_issues'].append({
                    'type': 'no_spf',
                    'severity': 'MEDIUM',
                    'description': 'No SPF record found (email spoofing risk)'
                })
        
        # check for DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.dns_resolver.resolve(dmarc_domain, 'TXT')
            results['dmarc_record'] = [str(rdata) for rdata in answers]
        except:
            results['dmarc_record'] = []
            results['security_issues'].append({
                'type': 'no_dmarc',
                'severity': 'MEDIUM',
                'description': 'No DMARC record found (email security risk)'
            })
        
        from config import COMMON_SUBDOMAINS
        
        # enumerate common subdomains
        for subdomain in COMMON_SUBDOMAINS:
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = self.dns_resolver.resolve(full_domain, 'A')
                if answers:
                    results['subdomains'].append({
                        'subdomain': full_domain,
                        'ips': [str(rdata) for rdata in answers]
                    })
            except Exception as e:
                logger.debug("Subdomain enumeration failed for %s: %s", full_domain, e)
        
        return results
    
    def check_dns_security(self, domain):
        results = {
            'domain': domain,
            'security_checks': [],
            'recommendations': []
        }
        
        try:
            ns_records = self.dns_resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_name = str(ns).rstrip('.')
                try:
                    dns_timeout = TIMEOUT_CONFIG.get('dns_lookup', 5)
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain, timeout=dns_timeout))
                    results['security_checks'].append({
                        'check': 'zone_transfer',
                        'status': 'VULNERABLE',
                        'severity': 'HIGH',
                        'description': f'Zone transfer allowed on nameserver {ns_name}',
                        'nameserver': ns_name
                    })
                except Exception:
                    results['security_checks'].append({
                        'check': 'zone_transfer',
                        'status': 'SECURE',
                        'description': f'Zone transfer properly restricted on {ns_name}',
                        'nameserver': ns_name
                    })
        except Exception as e:
            logger.debug("Zone transfer check failed for %s: %s", domain, e)
        
        try:
            random_subdomain = f"random-test-{datetime.now().timestamp()}.{domain}"
            answers = self.dns_resolver.resolve(random_subdomain, 'A')
            if answers:
                results['security_checks'].append({
                    'check': 'wildcard_dns',
                    'status': 'WARNING',
                    'severity': 'LOW',
                    'description': 'Wildcard DNS record detected'
                })
        except Exception:
            # Expected to fail for most domains - wildcard test
            logger.debug("No wildcard DNS detected for %s (expected)", domain)
        
        if any(check['status'] == 'VULNERABLE' for check in results['security_checks']):
            results['recommendations'].append('Disable zone transfers or restrict to authorized servers only')
        
        results['recommendations'].extend([
            'Enable DNSSEC for domain validation',
            'Configure SPF, DKIM, and DMARC records for email security',
            'Use CAA records to restrict certificate issuance',
            'Regularly audit DNS records for unauthorized changes'
        ])
        
        return results
