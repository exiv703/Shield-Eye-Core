# 🛡️ ShieldEye Core

**Professional Network Security Scanner**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![GTK](https://img.shields.io/badge/GTK-4.0-4A86CF?logo=gtk&logoColor=white)](https://www.gtk.org/)

## 📦 Versions

This repository contains two versions of ShieldEye Core:

### 🚀 **Version 2.0** (Current - Recommended)
**Location:** Root directory

Modern GTK 4.0 application with professional interface, advanced scanning capabilities, and comprehensive security analysis.

**Features:**
- 🖥️ Native GTK 4.0 desktop GUI with dark theme
- 🔍 Advanced port scanning with Nmap integration
- 🌐 CMS vulnerability detection (WordPress, Joomla, Drupal)
- 🔐 Security headers analysis with scoring
- 📊 Real-time dashboards and analytics
- 📈 Scan history with trend analysis
- 🎯 Risk assessment and reporting

**Quick Start:**
```bash
# Install dependencies
pip install -r requirements.txt

# Grant Nmap permissions (required once)
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Launch GUI
./run.sh
```

📖 **[Full Documentation →](README.md)**

---

### 📚 **Version 1.0** (Legacy)
**Location:** [`ShieldEye Core Legacy/`](ShieldEye%20Core%20Legacy/)

Original command-line version with basic scanning functionality.

**Note:** This version is maintained for compatibility purposes. New users should use Version 2.0.

---

## 🔗 ShieldEye Ecosystem

Part of the **ShieldEye Security Toolkit** series:

- **[ShieldEye Core](https://github.com/exiv703/Shield-Eye-Core)** - Network security scanner (this project)
- **[ShieldEye SurfaceScan](https://github.com/exiv703/ShieldEye-SurfaceScan)** - Web application surface scanner
- **[ShieldEye NeuralScan](https://github.com/exiv703/ShieldEye-NeuralScan)** - AI-powered code security analyzer
- **[ShieldEye ComplianceScan](https://github.com/exiv703/ShieldEye_ComplianceScan)** - Enterprise compliance scanner

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

**For educational and authorized security testing only.**
