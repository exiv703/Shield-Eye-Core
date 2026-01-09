from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Data models for scan results

@dataclass
class PortScanHostResult:
    target: str
    status: str
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    scan_time: Optional[float] = None
    shodan: Optional[Dict[str, Any]] = None

@dataclass
class CmsScanResult:
    url: str
    cms_detected: Optional[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    web_vulns: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class FullScanResult:
    target: str
    ports: List[PortScanHostResult] = field(default_factory=list)
    cms: List[CmsScanResult] = field(default_factory=list)
