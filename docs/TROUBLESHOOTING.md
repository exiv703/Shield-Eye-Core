# Troubleshooting

## Installation

**Missing nmap module:**
```bash
pip install python-nmap
```

If that fails, install system nmap first:
```bash
sudo apt-get install nmap  # Ubuntu/Debian
sudo pacman -S nmap        # Arch
brew install nmap          # macOS
```

**Permission denied:**
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

Or run with sudo.

**GTK won't start:**
```bash
sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-4.0  # Ubuntu
sudo pacman -S python-gobject gtk4  # Arch
```

## Runtime Errors

**Requires root privileges:** Use `scan_mode="safe"` or grant nmap capabilities.

**ValidationError:** Input validation failed. Don't pass shell commands or weird characters.

**SecurityPolicyError:** Target is blacklisted. Check `SECURITY_CONFIG['blacklist_ips']` or override:
```python
backend = ShieldEyeBackend(security_config={'blacklist_ips': []})
```

**Rate limit exceeded:** Wait or increase limits in security_config.

**Timeouts:** Use `scan_mode="safe"` for longer timeouts, or retry with delays.

## Performance

**Slow scans:** Use `port_mode="critical"` or async scanning:
```python
from backend.async_scanner import run_async_scan
results = run_async_scan(targets, ports=[80, 443, 22])
```

**High memory:** Clean up `scan_history.json` or just delete it.

**Laggy GUI:** Restart it or clean scan history.

## Data Issues

**Corrupted history file:** Delete `scan_history.json` and start fresh.

**Wrong dashboard metrics:** Check `backend.load_history()` to see raw data.

**PDF generation fails:** Install reportlab (`pip install reportlab`) and check write permissions.

## Network

**Connection refused:** Target is down, firewalled, or wrong IP. Test with `nc -zv IP PORT`.

**DNS resolution failed:** Use IP directly or check DNS with `nslookup`.

**Docker networking:** Use `network_mode: host` in docker-compose and don't scan `localhost`.

## Tests

**Warnings:** Run `pytest -W error tests/` to find them. Fix the root cause.

**Unclosed socket:** Use context managers (`with socket.socket() as sock:`).

**Coroutine not awaited:** Use `AsyncMock` instead of `Mock` for async functions.

## Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check logs: `cat logs/shieldeye.log`

Create minimal reproduction to isolate the issue.

When filing bugs, include Python version, OS, error message, and code to reproduce.

## Common Mistakes

- Forgot to activate venv (`source .venv/bin/activate`)
- Wrong Python version (need 3.11+)
- Using `sudo pip install` instead of installing in venv
- Scanning localhost without proper permissions
- Not reading error messages

## Clean Install

If nothing works:

1. Delete everything
2. Clone fresh
3. Create new venv
4. Install dependencies
5. Run tests
6. If tests pass, it's your environment
7. If tests fail, report the bug

---
