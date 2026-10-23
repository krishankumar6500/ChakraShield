"""Offline PCAP parser. Scapy is an optional dependency; payloads are not decoded into private messages."""
from __future__ import annotations
from collections import Counter
from pathlib import Path

def analyze_pcap(path: str, limit: int = 50000) -> dict:
    try:
        from scapy.utils import PcapReader
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.dns import DNS
    except ImportError as exc:
        raise RuntimeError("PCAP analysis requires optional dependency: pip install -e '.[capture]'") from exc
    p = Path(path)
    if not p.is_file():
        raise ValueError("PCAP path must be an existing file.")
    protocols, endpoints, rows = Counter(), Counter(), []
    count = 0
    with PcapReader(str(p)) as reader:
        for pkt in reader:
            count += 1
            if count > limit:
                break
            src = dst = "unknown"
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            proto = "OTHER"
            sport = dport = None
            if TCP in pkt:
                proto = "TCP"; sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
            elif UDP in pkt:
                proto = "UDP"; sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            if DNS in pkt:
                proto = "DNS"
            protocols[proto] += 1
            endpoints[(src, dst)] += 1
            rows.append({"time": float(pkt.time), "src": src, "dst": dst, "protocol": proto,
                         "src_port": sport, "dst_port": dport, "bytes": len(pkt)})
    return {"file": p.name, "packets_analyzed": len(rows), "truncated_at_limit": count > limit,
            "protocol_counts": dict(protocols),
            "top_endpoint_pairs": [{"src": a, "dst": b, "packets": n} for (a,b),n in endpoints.most_common(20)],
            "packets": rows,
            "limitations": ["Offline metadata analysis only.", "TLS-encrypted application payloads are not decrypted or presented as private messages.",
                            "Packet capture may contain sensitive metadata; store files securely."]}

def capture_live(interface: str, seconds: int = 10, packet_limit: int = 5000) -> dict:
    """Bounded live capture metadata using Scapy. Must be run only on an authorized interface."""
    if not 1 <= seconds <= 60:
        raise ValueError("Capture duration must be 1–60 seconds.")
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS
    except ImportError as exc:
        raise RuntimeError("Live capture requires optional dependency: pip install -e '.[capture]'") from exc
    packets = sniff(iface=interface, timeout=seconds, count=packet_limit, store=True)
    protocols, rows = Counter(), []
    for pkt in packets:
        src = dst = "unknown"; sport = dport = None; proto = "OTHER"
        if IP in pkt: src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt: src, dst = pkt[IPv6].src, pkt[IPv6].dst
        if TCP in pkt: proto = "TCP"; sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt: proto = "UDP"; sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
        if DNS in pkt: proto = "DNS"
        protocols[proto] += 1
        rows.append({"time": float(pkt.time), "src": src, "dst": dst, "protocol": proto,
                     "src_port": sport, "dst_port": dport, "bytes": len(pkt)})
    return {"interface": interface, "packets_analyzed": len(rows), "protocol_counts": dict(protocols),
            "packets": rows, "note": "Metadata only. HTTPS/TLS payloads are not decrypted."}
