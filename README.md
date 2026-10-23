# ChakraShield — All-in-One Defensive Cybersecurity GUI

ChakraShield is an open-source, cross-platform defensive network visibility and PCAP metadata analysis MVP, inspired by the protective symbolism of the Sudarshan Chakra. It is designed for learning and authorized security monitoring.

## Current features
- Desktop GUI built with PySide6: overview, network tools, offline PCAP forensics, and bounded live packet capture.
- Basic network interface inventory and DNS resolution.
- Bounded TCP checks against a small list of common ports. Only scan systems you own or are explicitly authorized to assess.
- PCAP/PCAPNG metadata analysis with optional Scapy.
- Live packet metadata capture limited to 1–60 seconds, with authorization confirmation.
- CLI commands and JSON output.
- Unit tests.

## Important limitations
This is an early MVP, not a full Bettercap replacement, commercial scanner, or production IDS. It does not decrypt HTTPS/TLS, read Instagram/WhatsApp private messages, or extract passwords, cookies, tokens, or credentials. It does not perform MITM, ARP spoofing, Wi-Fi deauthentication, exploitation, stealth, brute force, or destructive actions. Alerts and metadata are not proof of an attack. Live capture may require administrator/root permissions; Windows may require Npcap.

## Ubuntu / Debian / Kali Linux
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd ChakraShield
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[gui,capture,test]"
pytest -q
chakrashield-gui
```

## Windows
Install Python 3.10+; install Npcap if live capture is needed. Open PowerShell in this folder:
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[gui,capture,test]"
pytest -q
chakrashield-gui
```

## CLI examples
```bash
chakrashield interfaces
chakrashield dns example.com
chakrashield probe 192.168.1.1 --output probe.json
chakrashield pcap sample.pcap --output pcap-report.json
chakrashield capture eth0 --seconds 10 --output capture.json
```
Use your actual interface name (list it first). Only capture traffic on devices/networks you own or have explicit permission to monitor.

## Public GitHub repository setup
Create a **public** repository named `ChakraShield` on your GitHub account, without initializing it with a README/license. Then, from this folder:
```bash
git init
git add .
git commit -m "Initial ChakraShield defensive cybersecurity GUI"
git branch -M main
git remote add origin https://github.com/krishankumar6500/ChakraShield.git
git push -u origin main
```
GitHub will prompt you to authenticate; use GitHub's browser/device login or a credential manager. Never put access tokens or passwords in this repository. If the repository already exists, inspect its contents before pushing.

## Roadmap (not implemented yet)
- Rich protocol/flow tables and timeline.
- Trusted vulnerability advisory matching.
- Website/source-code analysis integration.
- HTML/PDF report export and packaged installers.
- More tests and verified Windows packaging.

## License
MIT — see `LICENSE`.
