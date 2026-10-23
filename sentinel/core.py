"""Defensive network visibility helpers. No payload decryption or credential extraction."""
from __future__ import annotations
import ipaddress, json, socket, subprocess, shutil, platform
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

def interfaces() -> list[dict]:
    """Return interface names via portable system APIs/commands where available."""
    if shutil.which("ip") and platform.system() != "Windows":
        p = subprocess.run(["ip", "-brief", "addr"], capture_output=True, text=True, timeout=4)
        rows = []
        for line in p.stdout.splitlines():
            parts = line.split()
            if parts:
                rows.append({"name": parts[0], "state": parts[1] if len(parts)>1 else "unknown",
                             "addresses": parts[2:]})
        return rows
    if platform.system() == "Windows":
        p = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=4)
        return [{"name": "Windows network configuration", "state": "available",
                 "addresses": [], "details": p.stdout[:12000]}]
    return [{"name": "unknown", "state": "unavailable", "addresses": []}]

def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as exc:
        raise ValueError("Enter one IPv4 or IPv6 address.") from exc

def resolve_domain(domain: str) -> dict:
    host = domain.strip()
    if not host or "/" in host or "://" in host:
        raise ValueError("Enter a hostname only, e.g. example.com")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({i[4][0] for i in infos})
    except OSError as exc:
        return {"hostname": host, "addresses": [], "error": str(exc)}
    return {"hostname": host, "addresses": addresses}

def tcp_probe(ip: str, ports: list[int] | None = None, timeout: float = 0.35) -> dict:
    ip = validate_ip(ip)
    if not 0.1 <= timeout <= 2:
        raise ValueError("timeout must be 0.1–2 seconds")
    ports = ports or [22, 53, 80, 135, 139, 443, 445, 3000, 3306, 3389, 5432, 8080, 8443]
    results = []
    for port in ports[:40]:
        if not 1 <= int(port) <= 65535:
            continue
        try:
            with socket.create_connection((ip, int(port)), timeout=timeout):
                results.append({"port": int(port), "state": "open"})
        except (OSError, TimeoutError):
            results.append({"port": int(port), "state": "no-response"})
    return {"target": ip, "checked": len(results), "results": results,
            "note": "No-response does not prove closed; firewall and timeout can affect results."}

def write_json(data: dict, path: str) -> str:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

def now() -> str:
    return datetime.now(timezone.utc).isoformat()
