<div align="center">

# 🛡️ ShieldEye Core

**Professional Network Security Scanner**

*Real-time port scanning • CMS vulnerability detection • Security headers analysis*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![GTK](https://img.shields.io/badge/GTK-4.0-4A86CF?logo=gtk&logoColor=white)](https://www.gtk.org/)
[![Nmap](https://img.shields.io/badge/Nmap-Powered-4682B4?logo=linux&logoColor=white)](https://nmap.org/)

[Features](#-key-features) • [Quick Start](#-quick-start) • [Screenshots](#-screenshots) • [Documentation](#-documentation) • [Architecture](#-architecture)

---

<!-- 
  📸 SCREENSHOT: Main application window showing the Dashboard view
  Recommended size: 900x600px or similar widescreen ratio
  Show: Dashboard with metrics, charts, and recent scans
-->
![ShieldEye Core Dashboard](docs/screenshots/dashboard.png)

</div>

---

## 🎯 What is ShieldEye Core?

ShieldEye Core is a **comprehensive network security scanner** that identifies vulnerabilities, misconfigurations, and security risks across network infrastructure and web applications. It combines:

- 🔍 **Advanced port scanning** with nmap integration for service detection
- 🌐 **CMS vulnerability detection** with real CVE database integration
- 🔐 **Security headers analysis** with weighted scoring (0-100)
- 🖥️ **Native GTK 4.0 desktop GUI** with professional dark theme

Whether you're a security researcher, penetration tester, or system administrator, ShieldEye Core provides actionable insights into your network's security posture.

---

## ✨ Key Features

<table>
<tr>
<td width="50%">

### 🔍 Advanced Scanning
- **Flexible port ranges**: Common, critical, full 1-65535, custom
- **Service detection**: Version fingerprinting and banner grabbing
- **OS fingerprinting**: Identify target operating systems
- **Network scanning**: CIDR notation support (e.g., 192.168.1.0/24)
- **Stealth modes**: Safe and aggressive scan profiles

</td>
<td width="50%">

### 🌐 Web Security Analysis
- **CMS detection**: WordPress, Joomla, Drupal identification
- **CVE integration**: Real-time vulnerability data from CIRCL API
- **Security headers**: 10 headers analyzed with quality scoring
- **SSL/TLS analysis**: Certificate validation and security grading
- **DNS enumeration**: Subdomain discovery and DNSSEC checks

</td>
</tr>
<tr>
<td width="50%">

### 📊 Professional Interface
- **Modern GTK 4.0**: Native Linux desktop application
- **Dark theme**: Cybersecurity-focused professional design
- **Real-time charts**: Area charts, donut charts, radial gauges
- **Scan history**: Persistent storage with trend analysis
- **Export reports**: JSON format with detailed findings

</td>
<td width="50%">

### 🔐 Production-Grade Security
- **Input validation**: Injection attack prevention
- **Rate limiting**: Per-target and global request throttling
- **Custom exceptions**: 9 specific error types
- **Comprehensive logging**: Structured logging with file output
- **Test coverage**: 50+ test cases with pytest

</td>
</tr>
</table>

---

## 🖼️ Screenshots

<div align="center">

<!-- 
  📸 SCREENSHOT: Dashboard view
  Show: Overall security metrics, recent scans list, key statistics
-->
| Dashboard | Scan Configuration |
|:---------:|:------------------:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Scan Config](docs/screenshots/scan-config.png) |
| *High-level security posture and activity* | *Intuitive scan setup with multiple modes* |

<!-- 
  📸 SCREENSHOT: Results view with detailed findings
  Show: Port scan results, risk assessment, vulnerability details
-->

<!-- 
  📸 SCREENSHOT: History view with scan timeline
  Show: Previous scans list, trend charts, filters
-->
| Results | History |
|:-------:|:-------:|
| ![Results](docs/screenshots/results.png) | ![History](docs/screenshots/history.png) |
| *Detailed findings with severity levels* | *Scan timeline and trend analysis* |

</div>

---

## 🏗️ Architecture

ShieldEye Core uses a **modular backend architecture** with a native GTK frontend:

```
┌──────────────────────────────────────────────────────────────┐
│                    GTK 4.0 Desktop GUI                        │
│                  (Python 3.10+ + PyGObject)                   │
└─────────────────────────────┬────────────────────────────────┘
                              │ Direct Integration
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                   ShieldEye Core Backend                      │
│              Orchestration • Validation • History             │
└───────┬─────────────────────┬─────────────────────┬──────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Port Scanner  │    │  CMS Scanner  │    │ SSL/DNS Scan  │
│    (Nmap)     │    │  (CVE Check)  │    │ (Certificate) │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └──────────┬──────────┴─────────────────────┘
                   ▼
    ┌─────────────────────────────────┐
    │   CIRCL CVE API  •  Nmap Engine │
    │   (External)       (System)     │
    └─────────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | GTK 4.0, Python 3.10+, PyGObject |
| **Backend** | Python 3.10+, Nmap, Requests |
| **Scanning** | python-nmap, BeautifulSoup4 |
| **Security** | OpenSSL, cryptography, dnspython |
| **Reports** | ReportLab (PDF generation) |
| **CVE Data** | CIRCL CVE Search API |

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | With venv support |
| GTK | 4.0+ | Desktop environment required |
| Nmap | Latest | System installation required |
| Linux | Any | Arch, Ubuntu, Debian, Fedora tested |

### 1. Clone and Install Dependencies

```bash
git clone https://github.com/exiv703/ShieldEye-Core.git
cd ShieldEye-Core

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Install System Dependencies

**Arch Linux:**
```bash
sudo pacman -S gtk4 python-gobject nmap
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install libgtk-4-1 python3-gi nmap
```

**Fedora:**
```bash
sudo dnf install gtk4 python3-gobject nmap
```

### 3. Grant Nmap Permissions (Required)

Nmap requires elevated privileges for advanced scanning features. Grant capabilities once:

```bash
# Grant network capabilities to Nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

**Alternative:** Run the application with sudo (less secure):
```bash
sudo ./run.sh
```

### 4. Launch the GUI

```bash
# Activate virtual environment
source venv/bin/activate

# Run GUI
python run_gui.py

# Or make executable and run directly
chmod +x run_gui.py
./run_gui.py
```

### 5. (Optional) Use CLI Mode

```bash
# Port scan
python cli.py scan-ports --target 192.168.1.10 --port-mode common

# CMS scan
python cli.py scan-cms --url https://example.com --web-vulns

# Full scan
python cli.py full-scan --target 192.168.1.0/24 --url https://example.com
```

---

## 🎮 Using `run.sh`

ShieldEye Core includes a convenient launcher script for managing the application:

```bash
# Interactive menu
./run.sh

# Direct commands
./run.sh install    # Install dependencies
./run.sh gui        # Launch GUI
./run.sh test       # Run tests
./run.sh clean      # Clean cache and logs
```

---

## ⚙️ Configuration

### Configuration

Edit `backend/config.py` to customize scan parameters, security policies, and alert thresholds. See [STRUCTURE.md](docs/STRUCTURE.md) for detailed configuration options.

### Requirements

Core dependencies: `python-nmap`, `requests`, `beautifulsoup4`, `PyGObject`, `cryptography`, `reportlab`. See `requirements.txt` for full list.

---

## 📖 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[README_GUI.md](docs/README_GUI.md)** - Detailed GUI usage guide
- **[STRUCTURE.md](docs/STRUCTURE.md)** - Project architecture and organization
- **[FINAL_STATUS.md](docs/FINAL_STATUS.md)** - Production-grade features overview

---

## 🔌 API Usage

```python
from backend import ShieldEyeBackend

backend = ShieldEyeBackend()

# Port scan
results = backend.scan_ports(
    target="192.168.1.10",
    port_mode="common",
    scan_mode="safe"
)

# CMS scan with CVE lookup
cms_result = backend.scan_cms(
    url="https://example.com",
    web_vulns=True
)

# Full scan (port + CMS)
full_result = backend.full_scan(
    target="192.168.1.10",
    url="https://example.com"
)
```

---

## 🛠️ Development

```bash
# Clone and setup
git clone https://github.com/exiv703/ShieldEye-Core.git
cd ShieldEye-Core
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest
pytest --cov=backend --cov-report=html
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add tests for new features
- Update documentation

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**For educational and authorized security testing only.**

---

## 🙏 Acknowledgments

- **Nmap** - Network scanning engine
- **CIRCL** - CVE database API
- **GTK Project** - GUI framework
- **Python Community** - Amazing libraries and tools

---

## 🔗 Related Projects

Part of the **ShieldEye Security Toolkit** series:

- **[ShieldEye SurfaceScan](https://github.com/exiv703/ShieldEye-SurfaceScan)** - Web application surface scanner
- **ShieldEye ComplianceScan** - Compliance and standards checker
- **ShieldEye NeuralScan** - ML-powered threat detection

---

<div align="center">

**Built with ❤️ for the security community**

*Version 2.0.0 - Production Grade*

[Report Bug](https://github.com/exiv703/ShieldEye-Core/issues) • [Request Feature](https://github.com/exiv703/ShieldEye-Core/issues)

</div>
