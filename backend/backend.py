import json
import logging
import random
import time
from collections import defaultdict
from ipaddress import ip_address, ip_network, AddressValueError
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from .config import SECURITY_CONFIG, ALERT_CONFIG, PORT_SCAN_CONFIG, TIMEOUT_CONFIG
from .port_scanner import PortScanner
from .cms_scanner import CMSScanner
from .report_generator import ReportGenerator
from .exceptions import (
    SecurityPolicyError,
    InvalidTargetError,
    ValidationError,
    ScanTimeoutError,
)

logger = logging.getLogger(__name__)

class ShieldEyeBackend:
    def __init__(
        self,
        port_scanner: Optional[PortScanner] = None,
        cms_scanner: Optional[CMSScanner] = None,
        report_generator: Optional[ReportGenerator] = None,
        security_config: Optional[Dict] = None,
        alert_config: Optional[Dict] = None,
    ) -> None:
        self.port_scanner = port_scanner if port_scanner else PortScanner()
        self.cms_scanner = cms_scanner if cms_scanner else CMSScanner()
        self.report_generator = report_generator if report_generator else ReportGenerator()
        
        sec_config = security_config if security_config else SECURITY_CONFIG
        alert_cfg = alert_config if alert_config else ALERT_CONFIG
        
        self.max_concurrent_scans = sec_config.get("max_concurrent_scans", 3)
        self.rate_limit = float(sec_config.get("rate_limit", 1.0))
        self.per_target_rate_limit = float(sec_config.get("per_target_rate_limit", 2.0))
        self.rate_limit_window = sec_config.get("rate_limit_window", 60)
        self.max_requests_per_target = sec_config.get("max_requests_per_target", 100)
        self.whitelist = sec_config.get("whitelist_ips", [])
        self.blacklist = sec_config.get("blacklist_ips", [])
        self.require_authorization = sec_config.get("require_authorization", False)
        self.alert_enabled = alert_cfg.get("enabled", True)
        self.alert_score_threshold = alert_cfg.get("score_threshold", 70)
        self.alert_min_level = alert_cfg.get("min_level", "HIGH").upper()
        
        self._target_request_times: Dict[str, List[float]] = defaultdict(list)
        self._target_request_counts: Dict[str, int] = defaultdict(int)

    def _sleep_rate_limit(self):
        if self.rate_limit > 0:
            delay = 1.0 / self.rate_limit
            if delay > 0:
                time.sleep(delay)
    
    def _check_per_target_rate_limit(self, target: str):
        if self.per_target_rate_limit <= 0:
            return
        
        current_time = time.time()
        target_key = target.lower()
        
        cutoff_time = current_time - self.rate_limit_window
        self._target_request_times[target_key] = [
            t for t in self._target_request_times[target_key] if t > cutoff_time
        ]
        
        if len(self._target_request_times[target_key]) >= self.max_requests_per_target:
            raise SecurityPolicyError(
                f"Rate limit exceeded for target {target}: "
                f"{len(self._target_request_times[target_key])} requests in {self.rate_limit_window}s window"
            )
        
        if self._target_request_times[target_key]:
            time_since_last = current_time - self._target_request_times[target_key][-1]
            min_interval = 1.0 / self.per_target_rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                logger.debug("Per-target rate limiting %s: sleeping %.2fs", target, sleep_time)
                time.sleep(sleep_time)
                current_time = time.time()
        
        self._target_request_times[target_key].append(current_time)
        self._target_request_counts[target_key] += 1
    
    def get_target_stats(self, target: str) -> Dict:
        target_key = target.lower()
        current_time = time.time()
        cutoff_time = current_time - self.rate_limit_window
        
        recent_requests = [
            t for t in self._target_request_times[target_key] if t > cutoff_time
        ]
        
        return {
            "target": target,
            "total_requests": self._target_request_counts[target_key],
            "recent_requests": len(recent_requests),
            "window_seconds": self.rate_limit_window,
            "rate_limit": self.per_target_rate_limit,
            "max_requests": self.max_requests_per_target
        }

    def _parse_networks(self, entries):
        # TODO: maybe cache this if it gets slow?
        nets = []
        for entry in entries:
            try:
                nets.append(ip_network(entry, strict=False))
            except ValueError:
                pass
        return nets

    def _validate_target(self, target: str):
        if not target:
            raise ValidationError('Target cannot be empty')
        
        target = target.strip()
        
        # basic sanity check
        if any(c in target for c in ['<', '>', ';', '|']):
            raise ValidationError(f'Invalid characters in target: {target}')
        
        if '/' in target:
            try:
                network = ip_network(target, strict=False)
                if network.num_addresses > 65536:  # /16 is max
                    raise ValidationError(f'Network too large (max /16): {target}')
            except ValueError as e:
                raise ValidationError(f"Invalid network CIDR notation: {target}") from e
        else:
            try:
                ip_address(target)
            except ValueError:
                # probably a hostname, check length
                if len(target) > 253:
                    raise ValidationError(f"Hostname too long: {target}")
    
    def _ensure_target_allowed(self, target: str):
        try:
            if "/" in target:
                network = ip_network(target, strict=False)
                ip_candidates = [network.network_address, network.broadcast_address]
            else:
                ip_candidates = [ip_address(target)]
        except (AddressValueError, ValueError):
            return  # not an IP, skip
        
        blacklist_nets = self._parse_networks(self.blacklist)
        for ip_candidate in ip_candidates:
            for net in blacklist_nets:
                if ip_candidate in net:
                    raise SecurityPolicyError("Target is blocked by security policy")
        
        if self.whitelist:
            whitelist_nets = self._parse_networks(self.whitelist)
            for ip_candidate in ip_candidates:
                if not any(ip_candidate in net for net in whitelist_nets):
                    raise SecurityPolicyError("Target is not in allowed ranges")

    def _validate_url(self, url: str):
        if not url:
            raise ValidationError('URL cannot be empty')
        
        url = url.strip()
        parsed = urlparse(url)
        
        if not parsed.scheme:
            raise ValidationError(f'URL missing scheme (http/https): {url}')
        if parsed.scheme not in ('http', 'https'):
            raise ValidationError(f"URL scheme must be http or https, got: {parsed.scheme}")
        if not parsed.netloc:
            raise ValidationError(f"URL missing domain: {url}")

    def scan_ports(
        self,
        target: str,
        scan_type: str = "single",
        stealth: bool = False,
        scan_mode: str = "safe",
        shodan_api_key: Optional[str] = None,
        port_mode: str = "common",
        custom_ports: Optional[List[int]] = None,
    ) -> List[Dict]:
        self._validate_target(target)
        self._ensure_target_allowed(target)
        
        if scan_type not in ('single', 'network'):
            raise ValidationError(f"Invalid scan_type: {scan_type}. Must be 'single' or 'network'")
        
        if scan_mode not in ('safe', 'aggressive'):
            raise ValidationError(f"Invalid scan_mode: {scan_mode}. Must be 'safe' or 'aggressive'")
        
        self._sleep_rate_limit()
        self._check_per_target_rate_limit(target)
        ports = self._select_ports(port_mode, custom_ports)
        if scan_type == "single":
            results = [self._scan_single_host_stealth(target, stealth, scan_mode, ports)]
        else:
            results = self._scan_network_stealth(target, stealth, scan_mode, ports)
        if shodan_api_key:
            for host_result in results:
                ip_value = host_result.get("target")
                if ip_value:
                    host_result["shodan"] = self.get_shodan_info(ip_value, shodan_api_key)
        return results

    def _validate_ports(self, ports):
        if not ports or not isinstance(ports, list):
            raise ValidationError("Invalid port list")
        
        valid_ports = []
        for p in ports:
            if not isinstance(p, int) or p < 1 or p > 65535:
                raise ValidationError(f"Invalid port: {p}")
            valid_ports.append(p)
        
        if len(valid_ports) > 10000:  # sanity check
            raise ValidationError(f"Too many ports: {len(valid_ports)}")
        
        return sorted(list(set(valid_ports)))  # dedupe and sort
    
    def _select_ports(self, port_mode, custom_ports=None):
        if port_mode == "custom" and custom_ports:
            return self._validate_ports(custom_ports)
        elif port_mode == "critical":
            return list(PORT_SCAN_CONFIG.get("critical_ports", []))
        elif port_mode == "full_1k":
            return list(range(1, 1025))
        elif port_mode == "full_64k":
            return list(range(1, 65536))  # takes forever
        else:
            return list(PORT_SCAN_CONFIG.get("common_ports", []))

    def _scan_single_host_stealth(self, target, stealth, scan_mode, ports=None):
        scanner = self.port_scanner
        if ports is None and scan_mode == "aggressive":
            ports = list(scanner.common_ports.keys()) + [i for i in range(1, 1024) if i not in scanner.common_ports]
        
        if stealth:
            if ports is None:
                ports = list(scanner.common_ports.keys())
            random.shuffle(ports)  # randomize order
        
        result = scanner.scan_single_host(target, ports=ports, scan_mode=scan_mode)
        
        if stealth or scan_mode == "safe":
            time.sleep(random.uniform(0.5, 2.0))  # delay to avoid detection
        return result

    def _scan_network_stealth(self, network, stealth, scan_mode, ports=None):
        scanner = self.port_scanner
        if ports is None and scan_mode == "aggressive":
            ports = list(scanner.common_ports.keys()) + [i for i in range(1, 1024) if i not in scanner.common_ports]
        
        if stealth:
            if ports is None:
                ports = list(scanner.common_ports.keys())
            random.shuffle(ports)
        
        results = scanner.scan_network(network, ports=ports, scan_mode=scan_mode)
        
        if stealth or scan_mode == "safe":
            for _ in range(len(results)):
                time.sleep(random.uniform(0.5, 2.0))  # delay between hosts
        return results

    def scan_cms(self, url, stealth=False, scan_mode="safe", web_vulns=False):
        self._validate_url(url)
        parsed = urlparse(url)
        target = parsed.netloc
        
        self._sleep_rate_limit()
        self._check_per_target_rate_limit(target)
        
        scanner = self.cms_scanner
        
        if stealth:
            from .config import STEALTH_USER_AGENTS
            scanner.session.headers["User-Agent"] = random.choice(STEALTH_USER_AGENTS)
            time.sleep(random.uniform(0.5, 2.0))
        
        result = scanner.scan_cms(url)
        
        if web_vulns:
            result["web_vulns"] = self.test_web_vulnerabilities(url)
        
        result["scan_mode"] = scan_mode
        result["stealth"] = stealth
        return result

    def summarize_risk(self, port_results, cms_results):
        score = 0
        reasons = []
        
        severity_weights = {
            "CRITICAL": 40,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
        }
        
        critical_ports = {22, 23, 3389, 5900}
        total_open_ports = 0
        critical_open_ports = 0
        for host in port_results:
            for port_info in host.get("open_ports", []):
                total_open_ports += 1
                port = port_info.get("port")
                if port in critical_ports:
                    critical_open_ports += 1
                    score += 20
                else:
                    score += 5
        if critical_open_ports:
            reasons.append(f"{critical_open_ports} critical management ports exposed (SSH/Telnet/RDP/VNC)")
        elif total_open_ports:
            reasons.append(f"{total_open_ports} open ports detected")
        
        total_cms_vulns = 0
        total_cms_issues = 0
        for cms in cms_results:
            for vuln in cms.get("vulnerabilities", []):
                total_cms_vulns += 1
                sev = str(vuln.get("severity", "MEDIUM")).upper()
                score += severity_weights.get(sev, 5)
            for issue in cms.get("security_issues", []):
                total_cms_issues += 1
                sev = str(issue.get("severity", "MEDIUM")).upper()
                score += severity_weights.get(sev, 5)
        if total_cms_vulns:
            reasons.append(f"{total_cms_vulns} known CMS vulnerabilities")
        if total_cms_issues:
            reasons.append(f"{total_cms_issues} CMS security misconfigurations")
        
        if score <= 20:
            level = "LOW"
        elif score <= 50:
            level = "MEDIUM"
        elif score <= 100:
            level = "HIGH"
        else:
            level = "CRITICAL"
        return {
            "score": score,
            "level": level,
            "reasons": reasons,
            "metrics": {
                "total_open_ports": total_open_ports,
                "critical_open_ports": critical_open_ports,
                "total_cms_vulnerabilities": total_cms_vulns,
                "total_cms_issues": total_cms_issues,
            },
        }

    def test_web_vulnerabilities(self, url):
        # basic heuristic checks - not comprehensive
        vulns = []
        
        # XSS check
        xss_payload = "<script>alert(1)</script>"
        try:
            resp = requests.get(url, params={"xss": xss_payload}, timeout=5)
            if resp.ok and xss_payload in resp.text:
                vulns.append({
                    "type": "XSS",
                    "description": "Reflected XSS detected via ?xss=... (heuristic check)",
                })
        except requests.RequestException:
            pass  # ignore errors
        
        # SQL injection check
        sqli_payload = "' OR '1'='1"
        try:
            resp = requests.get(url, params={"id": sqli_payload}, timeout=5)
            if resp.ok:
                body_lower = resp.text.lower()
                if "sql" in body_lower or "syntax" in body_lower:
                    vulns.append({
                        "type": "SQLi",
                        "description": "Possible SQL Injection via ?id=... (error-based heuristic)",
                    })
        except requests.RequestException:
            pass
        
        # directory traversal
        dt_payload = "../../../../etc/passwd"
        try:
            resp = requests.get(url, params={"file": dt_payload}, timeout=5)
            if resp.ok and "root:x:" in resp.text:
                vulns.append({
                    "type": "Directory Traversal",
                    "description": "Possible directory traversal via ?file=... (Linux /etc/passwd pattern)",
                })
        except requests.RequestException:
            pass
        
        return vulns

    def full_scan(
        self,
        target: str,
        scan_type: str = "single",
        url: Optional[str] = None,
        scan_mode: str = "safe",
        stealth: bool = False,
        web_vulns: bool = False,
        shodan_api_key: Optional[str] = None,
        port_mode: str = "common",
        custom_ports: Optional[List[int]] = None,
    ) -> Dict:

        port_results = self.scan_ports(
            target=target,
            scan_type=scan_type,
            stealth=stealth,
            scan_mode=scan_mode,
            shodan_api_key=shodan_api_key,
            port_mode=port_mode,
            custom_ports=custom_ports,
        )
        cms_results: List[Dict] = []
        if url:
            try:
                cms_result = self.scan_cms(
                    url=url,
                    stealth=stealth,
                    scan_mode=scan_mode,
                    web_vulns=web_vulns,
                )
                cms_results = [cms_result]
            except Exception as exc:
                logger.error("CMS scan failed for %s: %s", url, exc)
                cms_results = []
        risk_summary = self.summarize_risk(port_results, cms_results)
        result = {
            "target": target,
            "url": url,
            "scan_type": scan_type,
            "scan_mode": scan_mode,
            "stealth": stealth,
            "port_results": port_results,
            "cms_results": cms_results,
            "risk_summary": risk_summary,
        }
        result["alert"] = self.check_alert_needed(result)
        return result

    def generate_report(
        self,
        port_results: List[Dict],
        cms_results: List[Dict],
        output_filename: str = "shieldeye_report.pdf",
    ) -> str:
        return self.report_generator.generate_vulnerability_report(port_results, cms_results, output_filename)

    def save_scan_to_history(self, port_results: List[Dict], cms_results: List[Dict], history_file: str = "scan_history.json", metadata: Optional[Dict] = None) -> None:
        entry = {
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "port_results": port_results,
            "cms_results": cms_results,
        }
        if metadata:
            entry["timestamp"] = metadata.get("timestamp", entry["date"])
            entry["target"] = metadata.get("target", "Unknown")
            entry["config"] = metadata.get("config", {})
            if "risk_summary" in metadata:
                entry["risk_summary"] = metadata["risk_summary"]
        
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                history = json.load(f)
        except FileNotFoundError:
            history = []
        except json.JSONDecodeError:
            logger.warning("Failed to parse history file, starting fresh")
            history = []
        except OSError as e:
            logger.error(f"Failed to read history file: {e}")
            history = []
        
        history.append(entry)
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def load_history(self, history_file: str = "scan_history.json") -> List[Dict]:
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return []
        except json.JSONDecodeError:
            logger.warning("Failed to parse history file, returning empty")
            return []
        except OSError:
            return []
    
    def summarize_history(self, history_file: str = "scan_history.json") -> Dict:
        history = self.load_history(history_file=history_file)
        total_scans = len(history)
        if total_scans == 0:
            return {
                "total_scans": 0,
                "average_score": 0,
                "max_score": 0,
                "min_score": 0,
                "levels": {},
            }
        
        scores = []
        levels = {}
        for entry in history:
            port_results = entry.get("port_results", [])
            cms_results = entry.get("cms_results", [])
            risk = self.summarize_risk(port_results, cms_results)
            score = int(risk.get("score", 0))
            level = str(risk.get("level", "UNKNOWN"))
            scores.append(score)
            levels[level] = levels.get(level, 0) + 1
        
        scores_sorted = sorted(scores)
        avg = sum(scores_sorted) / len(scores_sorted)
        return {
            "total_scans": total_scans,
            "average_score": avg,
            "max_score": scores_sorted[-1],
            "min_score": scores_sorted[0],
            "levels": levels,
        }

    def check_alert_needed(self, full_scan_result: Dict) -> Dict:
        if not self.alert_enabled:
            return {"alert": False}
        
        risk = full_scan_result.get("risk_summary") or self.summarize_risk(
            full_scan_result.get("port_results", []),
            full_scan_result.get("cms_results", []),
        )
        score = int(risk.get("score", 0))
        level = str(risk.get("level", "LOW"))
        
        level_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        current_rank = level_order.get(level.upper(), 0)
        required_rank = level_order.get(self.alert_min_level.upper(), 0)
        
        by_score = score >= self.alert_score_threshold
        by_level = current_rank >= required_rank
        triggered = bool(by_score or by_level)
        
        reason_parts = []
        if by_score:
            reason_parts.append(f"score {score} >= threshold {self.alert_score_threshold}")
        if by_level:
            reason_parts.append(f"level {level} >= minimum {self.alert_min_level}")
        reason = "; ".join(reason_parts) if triggered else ""
        
        return {
            "alert": triggered,
            "reason": reason,
            "score": score,
            "level": level,
            "score_threshold": self.alert_score_threshold,
            "min_level": self.alert_min_level,
        }

    def get_shodan_info(self, ip_value: str, api_key: str) -> Dict:
        try:
            timeout = TIMEOUT_CONFIG.get('shodan_api', 10)
            url = f"https://api.shodan.io/shodan/host/{ip_value}?key={api_key}"
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports"),
                    "hostnames": data.get("hostnames"),
                    "data": [d.get("data") for d in data.get("data", []) if "data" in d],
                }
            return {"error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            logger.error(f"Shodan query failed: {e}")
            return {"error": str(e)}

    def update_cve_database(self, output_file: str = "cve_db.json") -> int:
        url = "https://cve.circl.lu/api/last"
        try:
            timeout = TIMEOUT_CONFIG.get('cve_api', 20)
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                raise RuntimeError(f"Failed to update CVE database: HTTP {resp.status_code}")
            cve_data = resp.json()
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(cve_data, f, indent=2)
            logger.info(f"Updated CVE cache with {len(cve_data)} entries")
            return len(cve_data)
        except Exception as e:
            logger.error(f"CVE update failed: {e}")
            raise
