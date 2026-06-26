import json
import logging
import random
import re
import time
from collections import defaultdict
from ipaddress import ip_address, ip_network, AddressValueError
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from .config import SECURITY_CONFIG, ALERT_CONFIG, PORT_SCAN_CONFIG, TIMEOUT_CONFIG
from .http_client import safe_request
from .port_scanner import PortScanner
from .cms_scanner import CMSScanner
from .history_store import HistoryStore
from .report_generator import ReportGenerator
from backend.cache import TTLCache
from backend.web_checks import (
    TRAVERSAL_PAYLOADS,
    analyze_sqli_responses,
    analyze_traversal_response,
    analyze_xss_response,
)
from backend.validators import validate_scan_url
from .exceptions import (
    SecurityPolicyError,
    InvalidTargetError,
    ValidationError,
    ScanTimeoutError,
)

logger = logging.getLogger(__name__)


def validate_api_key(api_key: str, min_length: int = 32) -> None:
    """Raise ValidationError if a Shodan key is empty or too short."""
    if not api_key or len(api_key.strip()) < min_length:
        raise ValidationError(f"Invalid API key: must be at least {min_length} characters")


def redact_secret(value: str, visible_chars: int = 4) -> str:
    """Mask a secret for logging, e.g. 'abcd****************'."""
    if not value:
        return ""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)


def apply_scan_jitter(base_delay: float, jitter: float = 0.2) -> float:
    # base_delay +/- jitter, so scans don't fire on an exact cadence
    return base_delay + random.uniform(-jitter, jitter)

class ShieldEyeBackend:
    def __init__(
        self,
        port_scanner: Optional[PortScanner] = None,
        cms_scanner: Optional[CMSScanner] = None,
        report_generator: Optional[ReportGenerator] = None,
        security_config: Optional[Dict] = None,
        alert_config: Optional[Dict] = None,
        history_store: Optional[HistoryStore] = None,
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
        self.allow_private_targets = bool(sec_config.get("allow_private_targets", False))
        # CMS/web requests follow redirects; keep them SSRF-safe under the same policy.
        try:
            self.cms_scanner.allow_private_redirects = self.allow_private_targets
        except (AttributeError, TypeError):
            pass
        self.alert_enabled = alert_cfg.get("enabled", True)
        self.alert_score_threshold = alert_cfg.get("score_threshold", 70)
        self.alert_min_level = alert_cfg.get("min_level", "HIGH").upper()
        
        self._target_request_times: Dict[str, List[float]] = defaultdict(list)
        self._target_request_counts: Dict[str, int] = defaultdict(int)

        self.history_store = history_store if history_store else HistoryStore()
        self.cache = TTLCache(default_ttl=3600)
        legacy_path = Path(__file__).parent / "data" / "scan_history.json"
        if legacy_path.exists():
            imported = self.history_store.import_json_legacy(str(legacy_path))
            if imported > 0:
                logger.info("Imported %s entries from legacy JSON history", imported)
                archive_path = legacy_path.with_suffix(".json.imported")
                try:
                    legacy_path.replace(archive_path)
                except OSError as exc:
                    logger.warning("Failed to archive legacy history file: %s", exc)

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

    _HOSTNAME_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

    def _validate_hostname(self, hostname: str) -> None:
        if len(hostname) > 253:
            raise ValidationError(f"Hostname too long: {hostname}")
        labels = hostname.split(".")
        for label in labels:
            if not label or not self._HOSTNAME_LABEL.match(label):
                raise ValidationError(f"Invalid hostname: {hostname}")

    def _validate_target(self, target: str):
        if not isinstance(target, str):
            raise ValidationError("Target must be a non-empty string")
        if not target.strip():
            raise ValidationError("Target cannot be empty")

        target = target.strip()

        # Reject shell/argument-injection metacharacters. A leading '-' or any
        # whitespace would let a target be smuggled in as an extra nmap argument
        # (e.g. "--script ..." / "-oN /etc/x"), so block those explicitly.
        if target.startswith("-") or any(
            c in target for c in ('<', '>', ';', '|', '&', '$', '`', '\\', ' ', '\t', '\n', '\r')
        ):
            raise ValidationError(f'Target contains invalid characters: {target}')

        if '/' in target:
            try:
                network = ip_network(target, strict=False)
            except ValueError as e:
                raise ValidationError(f"Invalid network CIDR notation: {target}") from e
            if network.num_addresses > 65536:  # /16 is max
                raise ValidationError(f'Network too large (max /16): {target}')
        else:
            try:
                ip_address(target)
            except ValueError:
                # Not an IP literal: validate as a hostname.
                self._validate_hostname(target)
    
    def _ensure_target_allowed(self, target: str):
        if "/" not in target:
            try:
                # A port-scan target is explicitly chosen by the operator, so
                # private/LAN ranges are allowed here (that is the scanner's main
                # use case). Loopback, link-local, and cloud-metadata stay blocked,
                # and whitelist/blacklist policy below still applies.
                validate_scan_url(
                    f"http://{target.strip()}",
                    allow_private=True,
                )
            except ValidationError as exc:
                raise SecurityPolicyError(str(exc)) from exc

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
        validate_scan_url(url, allow_private=self.allow_private_targets)

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
        """Port-scan a single host or a CIDR network.

        Validates the target, enforces policy/rate limits, picks the port list,
        then runs the host or network scan. Returns one result dict per host.
        Raises ValidationError / SecurityPolicyError on bad or blocked input.
        """
        self._validate_target(target)

        if scan_type not in ('single', 'network'):
            raise ValidationError(f"Invalid scan_type: {scan_type}. Must be 'single' or 'network'")

        if scan_mode not in ('safe', 'aggressive'):
            raise ValidationError(f"Invalid scan_mode: {scan_mode}. Must be 'safe' or 'aggressive'")

        self._ensure_target_allowed(target)

        self._sleep_rate_limit()
        self._check_per_target_rate_limit(target)
        ports = self._select_ports(port_mode, custom_ports)
        rate_limited = stealth
        if scan_type == "single":
            results = [self._scan_single_host_rate_limited(target, rate_limited, scan_mode, ports)]
        else:
            results = self._scan_network_rate_limited(target, rate_limited, scan_mode, ports)
        if shodan_api_key:
            for host_result in results:
                ip_value = host_result.get("target")
                if ip_value:
                    host_result["shodan"] = self.get_shodan_info(ip_value, shodan_api_key)
        return results

    def _validate_ports(self, ports):
        if not isinstance(ports, list):
            raise ValidationError("Ports must be a list")
        if not ports:
            raise ValidationError("Port list cannot be empty")

        valid_ports = []
        for p in ports:
            if not isinstance(p, int) or isinstance(p, bool):
                raise ValidationError(f"Port must be integer: {p!r}")
            if p < 1 or p > 65535:
                raise ValidationError(f"Port out of range (1-65535): {p}")
            valid_ports.append(p)

        if len(valid_ports) > 10000:  # sanity check
            raise ValidationError(f"Too many ports: {len(valid_ports)}")

        return sorted(set(valid_ports))  # dedupe and sort
    
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

    def _scan_single_host_rate_limited(self, target, rate_limited, scan_mode, ports=None):
        scanner = self.port_scanner
        if ports is None and scan_mode == "aggressive":
            ports = list(scanner.common_ports.keys()) + [i for i in range(1, 1024) if i not in scanner.common_ports]
        
        if rate_limited:
            if ports is None:
                ports = list(scanner.common_ports.keys())
            random.shuffle(ports)  # randomize order
        
        result = scanner.scan_single_host(target, ports=ports, scan_mode=scan_mode)
        
        if rate_limited or scan_mode == "safe":
            delay = apply_scan_jitter(base_delay=1.0, jitter=0.3)
            time.sleep(max(0, delay))  # rate limiting to reduce load and avoid triggering IDS
        return result

    def _scan_network_rate_limited(self, network, rate_limited, scan_mode, ports=None):
        scanner = self.port_scanner
        if ports is None and scan_mode == "aggressive":
            ports = list(scanner.common_ports.keys()) + [i for i in range(1, 1024) if i not in scanner.common_ports]
        
        if rate_limited:
            if ports is None:
                ports = list(scanner.common_ports.keys())
            random.shuffle(ports)
        
        results = scanner.scan_network(network, ports=ports, scan_mode=scan_mode)
        
        if rate_limited or scan_mode == "safe":
            for _ in range(len(results)):
                delay = apply_scan_jitter(base_delay=1.0, jitter=0.3)
                time.sleep(max(0, delay))  # rate limiting between hosts to reduce target load
        return results

    _scan_single_host_stealth = _scan_single_host_rate_limited
    _scan_network_stealth = _scan_network_rate_limited

    def scan_cms(
        self,
        url: str,
        stealth: bool = False,
        scan_mode: str = "safe",
        web_vulns: bool = False,
    ) -> Dict:
        """Fingerprint the CMS at a URL and, if web_vulns, run the heuristic
        XSS/SQLi/traversal checks on top. Validates URL safety and rate-limits first."""
        self._validate_url(url)
        parsed = urlparse(url)
        target = parsed.netloc
        
        self._sleep_rate_limit()
        self._check_per_target_rate_limit(target)
        
        scanner = self.cms_scanner
        rate_limited = stealth
        
        if rate_limited:
            from .config import STEALTH_USER_AGENTS
            scanner.session.headers["User-Agent"] = random.choice(STEALTH_USER_AGENTS)
            delay = apply_scan_jitter(base_delay=1.0, jitter=0.3)
            time.sleep(max(0, delay))
        
        result = scanner.scan_cms(url)
        
        if web_vulns:
            result["web_vulns"] = self.test_web_vulnerabilities(url)
        
        result["scan_mode"] = scan_mode
        result["stealth"] = stealth
        return result

    def summarize_risk(self, port_results: List[Dict], cms_results: List[Dict]) -> Dict[str, Any]:
        """Roll up open ports + CMS findings into a weighted score and level.

        Returns score, level, human-readable reasons, a per-factor breakdown,
        deduped recommendations, and aggregate metrics.
        """
        score = 0
        reasons = []
        breakdown: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        
        severity_weights = {
            "CRITICAL": 40,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
        }
        
        critical_ports = {22, 23, 3389, 5900}
        critical_port_labels = {
            22: "SSH exposed",
            23: "Telnet exposed",
            3389: "RDP exposed",
            5900: "VNC exposed",
        }
        total_open_ports = 0
        critical_open_ports = 0
        for host in port_results:
            for port_info in host.get("open_ports", []):
                total_open_ports += 1
                port = port_info.get("port")
                if port in critical_ports:
                    critical_open_ports += 1
                    weight = 20
                    score += weight
                    remediation = f"Firewall port {port}"
                    breakdown.append(
                        {
                            "factor": "critical_port_exposed",
                            "port": port,
                            "weight": weight,
                            "description": critical_port_labels.get(int(port), "Critical management port exposed"),
                            "remediation": remediation,
                        }
                    )
                    recommendations.append(remediation)
                else:
                    weight = 5
                    score += weight
                    service = port_info.get("service")
                    service_desc = f" ({service})" if service else ""
                    remediation = f"Review necessity of port {port} exposure"
                    breakdown.append(
                        {
                            "factor": "open_port_exposed",
                            "port": port,
                            "weight": weight,
                            "description": f"Open port {port}{service_desc}",
                            "remediation": remediation,
                        }
                    )
                    recommendations.append(remediation)
        if critical_open_ports:
            reasons.append(f"{critical_open_ports} critical management ports exposed (SSH/Telnet/RDP/VNC)")
        elif total_open_ports:
            reasons.append(f"{total_open_ports} open ports detected")
        
        total_cms_vulns = 0
        total_cms_issues = 0
        for cms in cms_results:
            cms_name = str(cms.get("cms", "")).strip() or str(cms.get("name", "")).strip()
            if not cms_name:
                cms_detected = cms.get("cms_detected", {})
                if isinstance(cms_detected, dict):
                    cms_name = str(cms_detected.get("cms", "")).strip()
            cms_name = cms_name or "CMS"

            for vuln in cms.get("vulnerabilities", []):
                total_cms_vulns += 1
                sev = str(vuln.get("severity", "MEDIUM")).upper()
                weight = severity_weights.get(sev, 5)
                score += weight
                cve = vuln.get("cve") or vuln.get("id")
                remediation = str(vuln.get("remediation", "")).strip() or f"Update {cms_name}"
                description = str(vuln.get("description", "")).strip() or f"{sev.title()} vulnerability in {cms_name}"
                item: Dict[str, Any] = {
                    "factor": "cms_vulnerability",
                    "weight": weight,
                    "description": description,
                    "remediation": remediation,
                }
                if cve:
                    item["cve"] = cve
                breakdown.append(item)
                recommendations.append(remediation)

            for issue in cms.get("security_issues", []):
                total_cms_issues += 1
                sev = str(issue.get("severity", "MEDIUM")).upper()
                weight = severity_weights.get(sev, 5)
                score += weight
                remediation = str(issue.get("remediation", "")).strip() or f"Harden {cms_name} security configuration"
                description = str(issue.get("description", "")).strip() or f"{sev.title()} CMS security misconfiguration"
                breakdown.append(
                    {
                        "factor": "cms_security_issue",
                        "weight": weight,
                        "description": description,
                        "remediation": remediation,
                    }
                )
                recommendations.append(remediation)
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

        deduped_recommendations: List[str] = []
        for recommendation in recommendations:
            if recommendation and recommendation not in deduped_recommendations:
                deduped_recommendations.append(recommendation)

        return {
            "score": score,
            "level": level,
            "reasons": reasons,
            "breakdown": breakdown,
            "recommendations": deduped_recommendations,
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
            resp = safe_request("GET", url, params={"xss": xss_payload}, timeout_key="web_vuln", validate_redirects=True, allow_private=self.allow_private_targets)
            if resp.ok:
                finding = analyze_xss_response(resp.text, xss_payload)
                if finding:
                    vulns.append(finding)
        except requests.RequestException:
            pass  # ignore errors
        
        # SQL injection check
        try:
            redirect_guard = {"validate_redirects": True, "allow_private": self.allow_private_targets}
            base_resp = safe_request("GET", url, params={"id": "1"}, timeout_key="web_vuln", **redirect_guard)
            true_resp = safe_request("GET", url, params={"id": "1' AND 1=1--"}, timeout_key="web_vuln", **redirect_guard)
            false_resp = safe_request("GET", url, params={"id": "1' AND 1=2--"}, timeout_key="web_vuln", **redirect_guard)
            error_resp = safe_request("GET", url, params={"id": "'"}, timeout_key="web_vuln", **redirect_guard)

            finding = analyze_sqli_responses(
                base_resp.text,
                true_resp.text,
                false_resp.text,
                error_text=error_resp.text if error_resp else None,
                base_time=base_resp.elapsed.total_seconds(),
                false_time=false_resp.elapsed.total_seconds(),
            )
            if finding:
                vulns.append(finding)
        except requests.RequestException:
            pass
        
        # directory traversal
        for payload in TRAVERSAL_PAYLOADS:
            try:
                resp = safe_request("GET", url, params={"file": payload}, timeout_key="web_vuln", validate_redirects=True, allow_private=self.allow_private_targets)
                if not resp.ok:
                    continue

                finding = analyze_traversal_response(resp.text)
                payload_reflected = payload.lower() in resp.text.lower()
                if finding and payload_reflected:
                    vulns.append(finding)
                    break
            except requests.RequestException:
                continue
        
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
        """Port scan, then optional CMS scan, then risk summary + alert check.

        Returns a dict with port_results, cms_results, risk_summary, and alert.
        """

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
        _ = history_file
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
        if "timestamp" not in entry:
            entry["timestamp"] = entry["date"]
        if "target" not in entry:
            entry["target"] = "Unknown"

        self.history_store.save_entry(
            {
                "timestamp": entry["timestamp"],
                "target": entry["target"],
                "result": entry,
            }
        )

    def load_history(self, history_file: str = "scan_history.json", limit: Optional[int] = None) -> List[Dict]:
        _ = history_file
        entries = self.history_store.load_entries(limit=limit)
        history: List[Dict] = []
        for item in entries:
            result = item.get("result", {})
            if isinstance(result, dict):
                entry = dict(result)
            else:
                entry = {}
            entry.setdefault("timestamp", item.get("timestamp"))
            entry.setdefault("target", item.get("target", "Unknown"))
            entry.setdefault("date", entry.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")))
            history.append(entry)
        return history
    
    def summarize_history(self, history_file: str = "scan_history.json", limit: int = 10) -> Dict:
        _ = history_file
        history = self.load_history(limit=limit)
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
        """Look up host metadata from Shodan (cached 24h). Returns an
        {'error': ...} dict instead of raising on a bad key or failed request."""
        cached = self.cache.get("shodan", ttl=86400, ip=ip_value)
        if cached is not None:
            return cached

        try:
            validate_api_key(api_key)
            url = f"https://api.shodan.io/shodan/host/{ip_value}"
            resp = safe_request("GET", url, params={"key": api_key}, timeout_key="api_request")
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports"),
                    "hostnames": data.get("hostnames"),
                    "data": [d.get("data") for d in data.get("data", []) if "data" in d],
                }
                self.cache.set("shodan", result, ttl=86400, ip=ip_value)
                return result
            return {"error": f"HTTP {resp.status_code}"}
        except ValidationError:
            logger.error("Shodan query failed for %s: invalid API key", redact_secret(ip_value))
            return {"error": "Invalid API key"}
        except requests.RequestException as e:
            error_message = str(e)
            if api_key:
                error_message = error_message.replace(api_key, redact_secret(api_key))
            logger.error("Shodan query failed for %s: %s", redact_secret(ip_value), error_message)
            return {"error": "API request failed"}

    def update_cve_database(self, output_file: str = "cve_db.json") -> int:
        url = "https://cve.circl.lu/api/last"
        try:
            resp = safe_request("GET", url, timeout_key="api_request")
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
