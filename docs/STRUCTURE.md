# Project Structure

## Directory Layout

```
ShieldEye-Core/
├── backend/                    # Core scanning functionality
│   ├── __init__.py            # Package initialization
│   ├── backend.py             # Main orchestration layer
│   ├── port_scanner.py        # Network port scanning
│   ├── cms_scanner.py         # CMS detection and analysis
│   ├── cve_client.py          # CVE database integration
│   ├── ssl_dns_scanner.py     # SSL/TLS and DNS analysis
│   ├── security_headers.py    # HTTP security header validation
│   ├── async_scanner.py       # Asynchronous scanning
│   ├── report_generator.py    # PDF report generation
│   ├── config.py              # Configuration settings
│   ├── logging_config.py      # Logging configuration
│   └── exceptions.py          # Custom exception types
│
├── gtk_gui_pro/               # GTK 4.0 GUI
│   ├── __init__.py
│   ├── app.py                 # Main application window
│   ├── styles.css             # UI styling
│   ├── views/                 # Different screens
│   │   ├── dashboard.py
│   │   ├── scan_config.py
│   │   ├── results.py
│   │   └── history.py
│   └── widgets/               # Reusable UI components
│       ├── chart_panel.py
│       └── metric_card.py
│
├── shared/                    # Shared models and utilities
│   ├── __init__.py
│   └── models.py
│
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── test_backend_basic.py
│   ├── test_input_validation.py
│   ├── test_port_scanner.py
│   └── test_cms_scanner.py
│
├── main.py                    # Legacy Tkinter GUI
├── cli.py                     # Command-line interface
├── run_gui.py                 # Fires up the GTK interface
├── metrics.py                 # Performance metrics
├── generate_sample_data.py    # Test data generation
│
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Development dependencies
├── pytest.ini                 # Test runner config
│
├── README.md                  # Project overview
├── STRUCTURE.md              # This document
├── PRODUCTION_ENHANCEMENTS.md # Cool features we added
└── PRODUCTION_FEATURES.md     # Quick reference card
```

## What's What

### Backend

**`backend.py`** - Coordinates everything, rate limiting, security policies, scan history

**`port_scanner.py`** - Nmap wrapper, service detection, banner grabbing, OS fingerprinting

**`cms_scanner.py`** - Detects WordPress/Joomla/Drupal, checks security headers, looks up CVEs

**`ssl_dns_scanner.py`** - SSL/TLS certificates, DNS records, DNSSEC/SPF/DMARC

**`security_headers.py`** - Scores HTTP security headers

**`async_scanner.py`** - Scans multiple targets concurrently

**`cve_client.py`** - Talks to CVE databases, caches results

**`report_generator.py`** - Generates PDF reports

**`config.py`** - Timeouts, security settings, tunable parameters

**`logging_config.py`** - Logging setup

**`exceptions.py`** - Custom exception types

## Imports

```python
# Main usage
from backend import ShieldEyeBackend
from backend import PortScanner, CMSScanner, AsyncScanner
from backend.exceptions import ValidationError, SecurityPolicyError
from backend.config import SECURITY_CONFIG, TIMEOUT_CONFIG

# Inside backend modules, use relative imports
from .config import SECURITY_CONFIG
from .port_scanner import PortScanner
```

## Usage

```python
from backend import ShieldEyeBackend

backend = ShieldEyeBackend()
results = backend.scan_ports("192.168.1.1")
cms_result = backend.scan_cms("http://example.com")
full_result = backend.full_scan(target="192.168.1.1", url="http://example.com")
```

For multiple targets:

```python
from backend.async_scanner import run_async_scan

targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
results = run_async_scan(targets, ports=[80, 443, 22])
```

## Tests

```bash
pytest tests/
pytest tests/test_input_validation.py
pytest --cov=backend tests/
```

## Why This Structure

Backend, GUI, and tests are separate. Everything imports from `backend` package. Related code is grouped together. Adding new scanners is straightforward - create a file in `backend/`, export it in `__init__.py`.

## Old vs New Imports

Old:
```python
from port_scanner import PortScanner
from config import SECURITY_CONFIG
```

New:
```python
from backend import PortScanner
from backend.config import SECURITY_CONFIG
```

## What You Can Import

Check `backend/__init__.py` for the full list:

```python
from backend import (
    ShieldEyeBackend,
    PortScanner,
    CMSScanner,
    CVEClient,
    SSLDNSScanner,
    SecurityHeadersAnalyzer,
    ReportGenerator,
    AsyncScanner,
    run_async_scan,
    run_async_cms_scan,
    ValidationError,
    SecurityPolicyError,
)
```

## Adding New Scanners

1. Create `backend/your_scanner.py`
2. Export it in `backend/__init__.py`
3. Add tests in `tests/test_your_scanner.py`

## Notes

- Backend modules use relative imports (`.` syntax)
- Config is in `backend/config.py`
- Logging setup is in `backend/logging_config.py`
- Exceptions are in `backend/exceptions.py`

---
