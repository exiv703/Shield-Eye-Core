# Integration Guide

## Basic Usage

```python
from backend import ShieldEyeBackend

backend = ShieldEyeBackend()
results = backend.scan_ports("192.168.1.1")
```

That's the basic pattern. Import, instantiate, call methods.

## Integration Patterns

### 1. As a Library

```python
from backend import ShieldEyeBackend
from backend.exceptions import ValidationError

class YourSecurityTool:
    def __init__(self):
        self.scanner = ShieldEyeBackend()
    
    def scan_target(self, target):
        try:
            return self.scanner.full_scan(target=target, scan_mode="safe")
        except ValidationError as e:
            return {"error": str(e)}
```

Wrap it in your own classes, handle exceptions as needed.

### 2. REST API

Flask example:

```python
from flask import Flask, request, jsonify
from backend import ShieldEyeBackend
from backend.exceptions import ValidationError

app = Flask(__name__)
backend = ShieldEyeBackend()

@app.route('/scan/ports', methods=['POST'])
def scan_ports():
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "Missing target"}), 400
    
    try:
        return jsonify(backend.scan_ports(target))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan/cms', methods=['POST'])
def scan_cms():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    
    try:
        return jsonify(backend.scan_cms(url))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

For production: use gunicorn, add auth, rate limit properly. Long scans should go through a task queue.

### 3. Task Queue

Celery example:

```python
from celery import Celery
from backend import ShieldEyeBackend

app = Celery('tasks', broker='redis://localhost:6379')
backend = ShieldEyeBackend()

@app.task
def scan_target_async(target, scan_type='full'):
    if scan_type == 'ports':
        return backend.scan_ports(target)
    return backend.full_scan(target)

# Usage:
# result = scan_target_async.delay("192.168.1.1", "ports")
# data = result.get(timeout=300)
```

### 4. Database Storage

```python
from sqlalchemy import create_engine, Column, Integer, String, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from backend import ShieldEyeBackend

Base = declarative_base()
engine = create_engine('postgresql://user:pass@localhost/scans')
Session = sessionmaker(bind=engine)

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    target = Column(String)
    scan_type = Column(String)
    results = Column(JSON)
    risk_score = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

def scan_and_store(target):
    backend = ShieldEyeBackend()
    results = backend.full_scan(target)
    
    session = Session()
    scan = ScanResult(
        target=target,
        scan_type='full',
        results=results,
        risk_score=results.get('risk_summary', {}).get('score', 0)
    )
    session.add(scan)
    session.commit()
    session.close()
    
    return results
```

## Configuration

Use environment variables:

```python
import os
from backend import ShieldEyeBackend

# From environment
security_config = {
    'rate_limit': float(os.getenv('SCAN_RATE_LIMIT', '1.0')),
    'max_concurrent_scans': int(os.getenv('MAX_CONCURRENT', '3')),
    'whitelist_ips': os.getenv('WHITELIST_IPS', '').split(','),
}

backend = ShieldEyeBackend(security_config=security_config)
```

Or use a proper config file:

```python
import yaml
from backend import ShieldEyeBackend

with open('config.yml') as f:
    config = yaml.safe_load(f)

backend = ShieldEyeBackend(
    security_config=config['security'],
    alert_config=config['alerts']
)
```

## Docker

Basic Dockerfile:

```dockerfile
FROM python:3.11-slim

# Install nmap (required)
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "api:app"]
```

Docker Compose:

```yaml
version: '3.8'

services:
  shieldeye-api:
    build: .
    ports:
      - "5000:5000"
    environment:
      - SCAN_RATE_LIMIT=2.0
      - MAX_CONCURRENT=5
    volumes:
      - ./scan_history.json:/app/scan_history.json
    depends_on:
      - redis
  
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
  
  worker:
    build: .
    command: celery -A tasks worker --loglevel=info
    depends_on:
      - redis
```

## CI/CD Integration

Run scans in your pipeline:

```yaml
# GitHub Actions example
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          sudo apt-get install -y nmap
          pip install -r requirements.txt
      
      - name: Run scan
        run: |
          python -c "
          from backend import ShieldEyeBackend
          backend = ShieldEyeBackend()
          results = backend.scan_ports('${{ secrets.TARGET_IP }}')
          print(results)
          "
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: scan_history.json
```

## Monitoring and Alerts

Hook into your monitoring stack:

```python
from backend import ShieldEyeBackend
import logging
from prometheus_client import Counter, Histogram

# Prometheus metrics
scan_counter = Counter('scans_total', 'Total scans performed')
scan_duration = Histogram('scan_duration_seconds', 'Scan duration')
high_risk_counter = Counter('high_risk_scans', 'Scans with high risk')

backend = ShieldEyeBackend()

@scan_duration.time()
def monitored_scan(target):
    scan_counter.inc()
    results = backend.full_scan(target)
    
    risk_score = results.get('risk_summary', {}).get('score', 0)
    if risk_score > 70:
        high_risk_counter.inc()
        logging.warning(f"High risk detected: {target} (score: {risk_score})")
    
    return results
```

## Common Issues

**Nmap permissions:** Grant capabilities with `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)`

**Rate limiting:** Per-instance by default. Use Redis for shared rate limiting across workers.

**Scan history:** The `scan_history.json` file grows. Rotate it or use a database.

**Timeouts:** Check `TIMEOUT_CONFIG` if scans timeout:

```python
from backend.config import TIMEOUT_CONFIG

# Check current values
print(TIMEOUT_CONFIG)

# Or override
backend = ShieldEyeBackend()
# Modify backend.port_scanner timeout if needed
```

## Security

**Add authentication if you expose the API publicly.**

```python
from functools import wraps
from flask import request, abort

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key')
        if key != os.getenv('API_KEY'):
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route('/scan/ports', methods=['POST'])
@require_api_key
def scan_ports():
    # ... your code
```

**Validate inputs** even though ShieldEye does some validation:

```python
import ipaddress

def is_safe_target(target):
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private:
            return False
        return True
    except ValueError:
        return target in ALLOWED_DOMAINS
```

## More Info

See `STRUCTURE.md` for code organization, `TROUBLESHOOTING.md` for common issues, and `README.md` for overview.

---
