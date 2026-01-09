import argparse
import json
import sys
from typing import Any, Dict, List

from backend import ShieldEyeBackend
from backend.exceptions import SecurityPolicyError

def print_scan_results(data):
    text = json.dumps(data, indent=2)
    sys.stdout.write(text + "\n")

def _parse_ports(value):
    if not value:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    ports = []
    for p in parts:
        try:
            num = int(p)
        except ValueError:
            continue  # skip invalid ports
        if 1 <= num <= 65535:
            ports.append(num)
    return ports or None

def cmd_scan_ports(args, backend):
    try:
        results = backend.scan_ports(
            target=args.target,
            scan_type=args.scan_type,
            stealth=args.stealth,
            scan_mode=args.mode,
            shodan_api_key=args.shodan_api_key,
            port_mode=args.port_mode,
            custom_ports=_parse_ports(args.ports),
        )
    except SecurityPolicyError as exc:
        sys.stderr.write(f"Security policy error: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"Scan failed: {exc}\n")
        return 1
    
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    else:
        print_scan_results(results)
    return 0

def cmd_scan_cms(args, backend):
    try:
        result = backend.scan_cms(
            url=args.url,
            stealth=args.stealth,
            scan_mode=args.mode,
            web_vulns=args.web_vulns,
        )
    except SecurityPolicyError as exc:
        sys.stderr.write(f"Security policy error: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"CMS scan failed: {exc}\n")
        return 1
    
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    else:
        print_scan_results(result)
    return 0

def cmd_full_scan(args, backend):
    try:
        full = backend.full_scan(
            target=args.target,
            scan_type=args.scan_type,
            url=args.url,
            scan_mode=args.mode,
            stealth=args.stealth,
            web_vulns=args.web_vulns,
            shodan_api_key=args.shodan_api_key,
            port_mode=args.port_mode,
            custom_ports=_parse_ports(args.ports),
        )
    except SecurityPolicyError as exc:
        sys.stderr.write(f"Security policy error: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"Full scan failed: {exc}\n")
        return 1
    
    # prepare summary output
    summary = {
        "target": full.get("target"),
        "port_results": full.get("port_results", []),
        "cms_results": full.get("cms_results", []),
        "risk_summary": full.get("risk_summary", {}),
    }
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    else:
        print_scan_results(summary)
    
    # generate PDF if requested
    if args.output_pdf:
        try:
            backend.generate_report(
                full.get("port_results", []),
                full.get("cms_results", []),
                args.output_pdf,
            )
        except Exception as exc:
            sys.stderr.write(f"Failed to generate PDF report: {exc}\n")
            return 1
    return 0

def cmd_update_cve(args, backend):
    try:
        count = backend.update_cve_database(args.output)
    except Exception as exc:
        sys.stderr.write(f"Failed to update CVE database: {exc}\n")
        return 1
    sys.stdout.write(f"CVE database updated successfully ({count} entries)\n")
    return 0

def cmd_history_summary(args, backend):
    summary = backend.summarize_history(history_file=args.file)
    print_scan_results(summary)
    return 0

def build_parser():
    parser = argparse.ArgumentParser(prog="shieldeye", description="ShieldEye vulnerability scanner CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # port scanning command
    scan_ports = subparsers.add_parser("scan-ports", help="Scan ports on a host or network")
    scan_ports.add_argument("--target", required=True, help="Target IP or CIDR, for example 192.168.1.1 or 192.168.1.0/24")
    scan_ports.add_argument("--scan-type", choices=["single", "network"], default="single")
    scan_ports.add_argument("--mode", choices=["safe", "aggressive"], default="safe")
    scan_ports.add_argument("--stealth", action="store_true", help="Enable simple stealth mode")
    scan_ports.add_argument("--shodan-api-key", help="Optional Shodan API key")
    scan_ports.add_argument("--port-mode", choices=["common", "critical", "full_1k", "full_64k", "custom"], default="common", help="Port selection mode")
    scan_ports.add_argument("--ports", help="Custom port list for port-mode=custom, e.g. 22,80,443")
    scan_ports.add_argument("--output-json", help="Save results to JSON file instead of printing")
    scan_ports.set_defaults(func=cmd_scan_ports)
    
    # CMS scanning command
    scan_cms = subparsers.add_parser("scan-cms", help="Scan CMS for vulnerabilities")
    scan_cms.add_argument("--url", required=True, help="Target CMS URL, for example https://example.com")
    scan_cms.add_argument("--mode", choices=["safe", "aggressive"], default="safe")
    scan_cms.add_argument("--stealth", action="store_true", help="Enable simple stealth mode")
    scan_cms.add_argument("--web-vulns", action="store_true", help="Run basic web vulnerability checks")
    scan_cms.add_argument("--output-json", help="Save results to JSON file instead of printing")
    scan_cms.set_defaults(func=cmd_scan_cms)
    
    # full scan command (port + CMS)
    full_scan = subparsers.add_parser("full-scan", help="Run port and optional CMS scan and optionally generate PDF report")
    full_scan.add_argument("--target", required=True, help="Target IP or CIDR, for example 192.168.1.1 or 192.168.1.0/24")
    full_scan.add_argument("--scan-type", choices=["single", "network"], default="single")
    full_scan.add_argument("--url", help="Optional CMS URL, for example https://example.com")
    full_scan.add_argument("--mode", choices=["safe", "aggressive"], default="safe")
    full_scan.add_argument("--stealth", action="store_true", help="Enable simple stealth mode")
    full_scan.add_argument("--web-vulns", action="store_true", help="Run basic web vulnerability checks")
    full_scan.add_argument("--shodan-api-key", help="Optional Shodan API key")
    full_scan.add_argument("--port-mode", choices=["common", "critical", "full_1k", "full_64k", "custom"], default="common", help="Port selection mode")
    full_scan.add_argument("--ports", help="Custom port list for port-mode=custom, e.g. 22,80,443")
    full_scan.add_argument("--output-json", help="Save combined results to JSON file")
    full_scan.add_argument("--output-pdf", help="Generate PDF report to given path")
    full_scan.set_defaults(func=cmd_full_scan)
    
    # CVE database update command
    update_cve = subparsers.add_parser("update-cve", help="Update local CVE database file")
    update_cve.add_argument("--output", default="cve_db.json", help="Output JSON file for CVE database")
    update_cve.set_defaults(func=cmd_update_cve)
    
    # history summary command
    history_summary = subparsers.add_parser("history-summary", help="Show aggregate statistics for past scans")
    history_summary.add_argument("--file", default="scan_history.json", help="History JSON file to analyze")
    history_summary.set_defaults(func=cmd_history_summary)
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    
    backend = ShieldEyeBackend()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    
    code = func(args, backend)
    raise SystemExit(code)

if __name__ == "__main__":
    main()
