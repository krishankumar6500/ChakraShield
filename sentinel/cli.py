import argparse, json, sys
from .core import interfaces, resolve_domain, tcp_probe, write_json
from .pcap import analyze_pcap, capture_live

def main():
    p = argparse.ArgumentParser(prog="chakrashield")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("interfaces")
    d = sub.add_parser("dns"); d.add_argument("hostname")
    n = sub.add_parser("probe"); n.add_argument("ip"); n.add_argument("--output", default="chakrashield-probe.json")
    a = sub.add_parser("pcap"); a.add_argument("path"); a.add_argument("--output", default="chakrashield-pcap.json")
    c = sub.add_parser("capture"); c.add_argument("interface"); c.add_argument("--seconds", type=int, default=10); c.add_argument("--output", default="chakrashield-capture.json")
    args = p.parse_args()
    try:
        if args.cmd == "interfaces": data = {"interfaces": interfaces()}
        elif args.cmd == "dns": data = resolve_domain(args.hostname)
        elif args.cmd == "probe": data = tcp_probe(args.ip); write_json(data, args.output); print("Report:", args.output); return 0
        elif args.cmd == "pcap": data = analyze_pcap(args.path); write_json(data, args.output); print("Report:", args.output); return 0
        else: data = capture_live(args.interface, args.seconds); write_json(data, args.output); print("Report:", args.output); return 0
        print(json.dumps(data, indent=2))
        return 0
    except (ValueError, RuntimeError, OSError) as e:
        print("error:", e, file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
