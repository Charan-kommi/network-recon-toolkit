#!/usr/bin/env python3
"""
Network Recon Toolkit
=====================
A fast TCP port scanner with:
  - Concurrent scanning (ThreadPoolExecutor)
  - Banner grabbing & service detection
  - OS TTL fingerprinting
  - JSON + HTML report output

Author : Sai Charan Kommi
GitHub : https://github.com/Charan-kommi

DISCLAIMER: For authorized use only. Only scan hosts you own or have
explicit written permission to test.
"""

import socket
import json
import datetime
import argparse
import ipaddress
import concurrent.futures
from pathlib import Path

# ─────────────────────────────────────────────
# Well-known port → service name map
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCbind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "Kubernetes API",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# Risk levels per service (for report colouring)
HIGH_RISK_PORTS  = {21, 23, 135, 139, 445, 512, 513, 514, 3389, 5900}
MEDIUM_RISK_PORTS = {22, 1433, 1521, 3306, 5432, 6379, 9200, 27017}


def risk_level(port: int) -> str:
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in MEDIUM_RISK_PORTS:
        return "MEDIUM"
    return "INFO"


# ─────────────────────────────────────────────
# Core scanning functions
# ─────────────────────────────────────────────
def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send HTTP probe for web ports
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH sends banner automatically
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            # Return first meaningful line
            first_line = banner.split("\n")[0][:120]
            return first_line
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0, grab: bool = True) -> dict | None:
    """Attempt TCP connect to a single port. Returns result dict or None."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result = {
                "port"    : port,
                "state"   : "open",
                "service" : COMMON_PORTS.get(port, "unknown"),
                "banner"  : "",
                "risk"    : risk_level(port),
            }
            if grab:
                result["banner"] = grab_banner(host, port)
            return result
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def resolve_host(target: str) -> tuple[str, str]:
    """Resolve hostname to IP. Returns (ip, hostname)."""
    try:
        ipaddress.ip_address(target)
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except socket.herror:
            hostname = target
        return target, hostname
    except ValueError:
        ip = socket.gethostbyname(target)
        return ip, target


def get_ttl(host: str) -> int | None:
    """Attempt ICMP ping via subprocess to get TTL (Linux/macOS only)."""
    import subprocess, re, platform
    cmd = ["ping", "-c", "1", "-W", "1", host] if platform.system() != "Windows" \
          else ["ping", "-n", "1", "-w", "1000", host]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=3).decode()
        match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return int(match.group(1)) if match else None
    except Exception:
        return None


def guess_os(ttl: int | None) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux / Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device / Cisco"


# ─────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────
RISK_COLOR = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "INFO": "#2563eb"}


def generate_html_report(scan_result: dict, output_path: str = "scan_report.html"):
    target   = scan_result["target"]
    ip       = scan_result["ip"]
    hostname = scan_result["hostname"]
    os_guess = scan_result["os_guess"]
    open_ports = scan_result["open_ports"]
    ts       = scan_result["scanned_at"]

    rows = ""
    for p in open_ports:
        color = RISK_COLOR.get(p["risk"], "#6b7280")
        rows += f"""
        <tr>
          <td><b>{p['port']}</b></td>
          <td>{p['service']}</td>
          <td><span class="badge" style="background:{color}">{p['risk']}</span></td>
          <td class="banner">{p['banner'] or '—'}</td>
        </tr>"""

    high_count = sum(1 for p in open_ports if p['risk']=='HIGH')
    med_count = sum(1 for p in open_ports if p['risk']=='MEDIUM')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Recon Report — {target}</title>
  <style>
    body  {{ font-family:'Segoe UI',sans-serif; background:#0f172a; color:#e2e8f0; padding:24px; margin:0; }}
    h1    {{ color:#38bdf8; }}
    .meta {{ background:#1e293b; border-radius:8px; padding:16px 24px; display:inline-block; margin-bottom:24px; }}
    .meta span {{ color:#94a3b8; font-size:0.85rem; }}
    table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; }}
    th    {{ background:#0ea5e9; color:#fff; padding:10px; text-align:left; }}
    td    {{ padding:10px; border-bottom:1px solid #334155; font-size:0.85rem; }}
    tr:hover td {{ background:#273549; }}
    .badge {{ padding:3px 10px; border-radius:999px; color:#fff; font-size:0.75rem; font-weight:600; }}
    .banner {{ font-family:monospace; font-size:0.8rem; color:#94a3b8; word-break:break-all; }}
    .summary {{ display:flex; gap:12px; margin-bottom:24px; }}
    .card {{ background:#1e293b; border-radius:8px; padding:12px 20px; text-align:center; }}
    .card .num {{ font-size:1.8rem; font-weight:700; color:#38bdf8; }}
  </style>
</head>
<body>
  <h1>Network Recon Report</h1>
  <div class="meta">
    <b>Target:</b> {target} &nbsp;|&nbsp;
    <b>IP:</b> {ip} &nbsp;|&nbsp;
    <b>Hostname:</b> {hostname} &nbsp;|&nbsp;
    <b>OS Guess:</b> {os_guess} &nbsp;|&nbsp;
    <span>{ts}</span>
  </div>
  <div class="summary">
    <div class="card"><div class="num">{len(open_ports)}</div><div>Open Ports</div></div>
    <div class="card"><div class="num" style="color:#dc2626">{high_count}</div><div>High Risk</div></div>
    <div class="card"><div class="num" style="color:#d97706">{med_count}</div><div>Medium Risk</div></div>
  </div>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="4" style="text-align:center;color:#64748b">No open ports found</td></tr>'}</tbody>
  </table>
  <p style="color:#475569;font-size:0.75rem;margin-top:16px">
    For authorized use only. Generated by Network Recon Toolkit.
  </p>
</body>
</html>"""

    from pathlib import Path
    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[+] HTML report -> {output_path}")


def generate_json_report(scan_result: dict, output_path: str = "scan_report.json"):
    from pathlib import Path
    Path(output_path).write_text(json.dumps(scan_result, indent=2), encoding="utf-8")
    print(f"[+] JSON report -> {output_path}")


# ─────────────────────────────────────────────
# Port list helpers
# ─────────────────────────────────────────────
def parse_ports(port_str: str) -> list[int]:
    """Parse '80,443,8000-8080' into a list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


TOP_1000 = list(COMMON_PORTS.keys()) + [
    8000, 8008, 9000, 9090, 9999, 10000, 10443,
    11211, 15672, 50000, 50070, 61616,
]


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Recon Toolkit -- fast TCP port scanner with banner grabbing"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Ports to scan: 'common' (default), 'all' (1-65535), or '22,80,443,8000-8080'"
    )
    parser.add_argument("-t", "--threads",  type=int,   default=100,   help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout",        type=float, default=1.0,   help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("--no-banner",      action="store_true",       help="Skip banner grabbing (faster)")
    parser.add_argument("--output",         default="html",            choices=["html", "json", "both", "none"])
    args = parser.parse_args()

    print("=" * 55)
    print("   Network Recon Toolkit -- by Sai Charan Kommi")
    print("   Authorized use only")
    print("=" * 55)

    # Resolve target
    try:
        ip, hostname = resolve_host(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve: {args.target}")
        return

    print(f"\n[*] Target  : {args.target}")
    print(f"[*] IP      : {ip}")
    print(f"[*] Host    : {hostname}")

    # TTL / OS guess
    ttl = get_ttl(ip)
    os_guess = guess_os(ttl)
    print(f"[*] TTL     : {ttl}  ->  OS Guess: {os_guess}")

    # Build port list
    if args.ports == "common":
        ports = sorted(set(TOP_1000))
    elif args.ports == "all":
        ports = list(range(1, 65536))
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print("[!] Invalid port specification")
            return

    print(f"[*] Ports   : {len(ports)} to scan")
    print(f"[*] Threads : {args.threads}\n")

    # Scan
    open_ports = []
    grab = not args.no_banner

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, p, args.timeout, grab): p for p in ports}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                open_ports.append(result)
                risk_col = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "INFO": "\033[94m"}.get(result["risk"], "")
                reset = "\033[0m"
                banner_short = f"  [{result['banner'][:60]}]" if result["banner"] else ""
                print(f"  {risk_col}[OPEN]{reset}  {result['port']:5d}/tcp  {result['service']:15s}{banner_short}")
            # Progress indicator every 500 ports
            if done % 500 == 0:
                print(f"  ... scanned {done}/{len(ports)} ports", end="\r")

    open_ports.sort(key=lambda x: x["port"])

    print(f"\n[=] Scan complete -- {len(open_ports)} open port(s) found")

    scan_result = {
        "target"     : args.target,
        "ip"         : ip,
        "hostname"   : hostname,
        "os_guess"   : os_guess,
        "ttl"        : ttl,
        "scanned_at" : datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "open_ports" : open_ports,
    }

    if args.output in ("html", "both"):
        generate_html_report(scan_result)
    if args.output in ("json", "both"):
        generate_json_report(scan_result)


if __name__ == "__main__":
    main()
