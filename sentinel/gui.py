"""ChakraShield — defensive network visibility and PCAP metadata GUI."""
from __future__ import annotations

import html
import json
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QPlainTextEdit, QSpinBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .core import interfaces, resolve_domain, tcp_probe
from .pcap import analyze_pcap, capture_live
from .intelligence import public_ip_location, website_hosting

APP_NAME = "ChakraShield"


class WorkerSignals(QObject):
    result = Signal(str, object)
    error = Signal(str, str)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChakraShield — Defensive Security Workbench")
        self.resize(1240, 820)
        self.last_results: dict[str, object] = {}
        self.signals = WorkerSignals()
        self.signals.result.connect(self.show_result)
        self.signals.error.connect(self.show_error)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.make_overview(), "Overview")
        self.tabs.addTab(self.make_network(), "Network")
        self.tabs.addTab(self.make_pcap(), "PCAP Forensics")
        self.tabs.addTab(self.make_capture(), "Live Capture")
        self.tabs.addTab(self.make_website(), "Website Security")
        self.tabs.addTab(self.make_reports(), "Reports")
        self.tabs.addTab(self.make_settings(), "Settings")
        self.tabs.addTab(self.make_ip_intel(), "IP Intelligence")
        self.tabs.addTab(self.make_hosting(), "Hosting Intelligence")
        self.tabs.addTab(self.make_cctv_security(), "CCTV Security")
        self.setCentralWidget(self.tabs)
        self.setStyleSheet("""
            QMainWindow, QWidget { background:#111827; color:#e5e7eb; font-size:13px; }
            QTabWidget::pane { border:1px solid #374151; }
            QTabBar::tab { background:#1f2937; color:#e5e7eb; padding:9px 13px; margin-right:2px; }
            QTabBar::tab:selected { background:#2563eb; }
            QPushButton { background:#2563eb; color:white; padding:9px 12px; border-radius:5px; }
            QPushButton:hover { background:#1d4ed8; }
            QPushButton:disabled { background:#4b5563; color:#d1d5db; }
            QLineEdit, QComboBox, QPlainTextEdit, QTableWidget, QSpinBox {
                background:#1f2937; color:#f9fafb; border:1px solid #4b5563; padding:5px;
            }
            QHeaderView::section { background:#374151; color:white; padding:7px; border:1px solid #4b5563; }
            QLabel#muted { color:#9ca3af; }
        """)
        self.statusBar().showMessage("Ready — monitor only authorized systems")
        self.refresh_overview()

    def base(self, title: str, description: str):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(11)
        heading = QLabel(title)
        heading.setStyleSheet("font-size:23px;font-weight:700;")
        layout.addWidget(heading)
        desc = QLabel(description)
        desc.setWordWrap(True)
        desc.setObjectName("muted")
        layout.addWidget(desc)
        return widget, layout

    @staticmethod
    def output_box():
        box = QPlainTextEdit()
        box.setReadOnly(True)
        box.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        return box

    @staticmethod
    def table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def make_overview(self):
        w, lay = self.base(APP_NAME, "One workspace for defensive network visibility, website checks and offline packet metadata analysis.")
        lay.addWidget(QLabel("Only assess devices and services you own or have explicit permission to test."))
        self.summary = QLabel("Interfaces: —     Active: —     IP addresses: —")
        self.summary.setStyleSheet("font-size:16px;font-weight:600;padding:10px;background:#1f2937;border-radius:6px;")
        lay.addWidget(self.summary)
        row = QHBoxLayout()
        refresh = QPushButton("Refresh interfaces")
        refresh.clicked.connect(self.refresh_overview)
        report = QPushButton("Export latest report")
        report.clicked.connect(self.export_report)
        row.addWidget(refresh)
        row.addWidget(report)
        row.addStretch(1)
        lay.addLayout(row)
        self.overview_table = self.table(["Interface", "State", "IP / Address"])
        lay.addWidget(self.overview_table)
        self.topology = QLabel("LOCAL GATEWAY  ───  THIS DEVICE  ───  AUTHORIZED PEERS\nExternal endpoints appear only when discovered from available metadata.")
        self.topology.setStyleSheet("font-family:monospace;font-size:14px;padding:16px;background:#0b1220;color:#4ade80;border:1px solid #334155;border-radius:8px;")
        self.topology.setWordWrap(True)
        lay.addWidget(self.topology)
        self.overview_note = QLabel("No scan is running. Choose a module above to begin.")
        self.overview_note.setObjectName("muted")
        lay.addWidget(self.overview_note)
        return w

    def make_network(self):
        w, lay = self.base("Network tools", "Resolve DNS and run bounded TCP connectivity checks against a single authorized IP address.")
        row = QHBoxLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText("Hostname, e.g. example.com")
        dns = QPushButton("Resolve DNS"); dns.clicked.connect(self.resolve_dns)
        row.addWidget(self.host, 1); row.addWidget(dns); lay.addLayout(row)
        row = QHBoxLayout()
        self.ip = QLineEdit(); self.ip.setPlaceholderText("Authorized single IP, e.g. 192.168.1.1")
        probe = QPushButton("Check common TCP ports"); probe.clicked.connect(self.probe_host)
        row.addWidget(self.ip, 1); row.addWidget(probe); lay.addLayout(row)
        self.network_table = self.table(["Item", "Result"])
        lay.addWidget(self.network_table)
        self.network_out = self.output_box(); self.network_out.setMaximumHeight(170); lay.addWidget(self.network_out)
        return w

    def make_pcap(self):
        w, lay = self.base("PCAP forensics", "Load a PCAP/PCAPNG file you are authorized to analyze. This module reports metadata only; it does not decrypt TLS.")
        row = QHBoxLayout()
        open_btn = QPushButton("Open PCAP / PCAPNG")
        open_btn.clicked.connect(self.open_pcap)
        row.addWidget(open_btn); row.addStretch(1); lay.addLayout(row)
        self.pcap_summary = QLabel("No capture file loaded.")
        self.pcap_summary.setStyleSheet("font-size:15px;font-weight:600;")
        lay.addWidget(self.pcap_summary)
        self.pcap_table = self.table(["Protocol", "Packets"])
        lay.addWidget(self.pcap_table)
        self.pcap_out = self.output_box(); lay.addWidget(self.pcap_out)
        return w

    def make_capture(self):
        w, lay = self.base("Live capture", "Bounded capture of packet metadata for 1–60 seconds. Use only on interfaces and networks you are authorized to monitor.")
        row = QHBoxLayout()
        self.interface = QComboBox(); self.interface.setMinimumWidth(160)
        refresh = QPushButton("Refresh interfaces"); refresh.clicked.connect(self.refresh_capture_interfaces)
        self.duration = QSpinBox(); self.duration.setRange(1, 60); self.duration.setValue(10); self.duration.setSuffix(" seconds")
        self.capture_button = QPushButton("Start capture"); self.capture_button.clicked.connect(self.start_capture)
        row.addWidget(self.interface, 1); row.addWidget(refresh); row.addWidget(self.duration); row.addWidget(self.capture_button)
        lay.addLayout(row)
        self.capture_summary = QLabel("Capture idle")
        lay.addWidget(self.capture_summary)
        self.capture_table = self.table(["Protocol", "Packets"]); lay.addWidget(self.capture_table)
        self.capture_out = self.output_box(); lay.addWidget(self.capture_out)
        return w

    def make_website(self):
        w, lay = self.base("Website security", "Basic, non-invasive checks for a public HTTP(S) URL: response status, redirect destination, security headers and TLS certificate validity. No exploitation or crawling.")
        row = QHBoxLayout()
        self.website_url = QLineEdit(); self.website_url.setPlaceholderText("https://example.com")
        check = QPushButton("Inspect URL"); check.clicked.connect(self.inspect_website)
        row.addWidget(self.website_url, 1); row.addWidget(check); lay.addLayout(row)
        self.website_out = self.output_box(); lay.addWidget(self.website_out)
        source_btn = QPushButton("Analyze authorized source file")
        source_btn.clicked.connect(self.analyze_source_file)
        lay.addWidget(source_btn)
        self.source_out = self.output_box(); self.source_out.setMaximumHeight(180); lay.addWidget(self.source_out)
        return w

    def make_reports(self):
        w, lay = self.base("Reports", "Export the latest completed module result as JSON or a readable HTML report. Reports may contain sensitive network metadata; store them securely.")
        json_btn = QPushButton("Export JSON report"); json_btn.clicked.connect(self.export_report)
        html_btn = QPushButton("Export HTML report"); html_btn.clicked.connect(self.export_html_report)
        row = QHBoxLayout(); row.addWidget(json_btn); row.addWidget(html_btn); row.addStretch(1); lay.addLayout(row)
        self.report_status = QLabel("No results to export yet."); self.report_status.setWordWrap(True); lay.addWidget(self.report_status)
        self.report_out = self.output_box(); lay.addWidget(self.report_out)
        return w

    def make_settings(self):
        w, lay = self.base("Settings", "Local preferences and safety information for this workstation.")
        form = QFormLayout()
        self.default_duration = QSpinBox(); self.default_duration.setRange(1, 60); self.default_duration.setValue(10); self.default_duration.setSuffix(" seconds")
        self.default_duration.valueChanged.connect(self.duration.setValue)
        form.addRow("Default capture duration", self.default_duration)
        self.confirm_checks = QCheckBox("Ask for authorization confirmation before active network checks")
        self.confirm_checks.setChecked(True); self.confirm_checks.setEnabled(False)
        form.addRow("Safety confirmation", self.confirm_checks)
        lay.addLayout(form)
        info = QLabel("ChakraShield does not decrypt HTTPS/TLS, read private social-media messages, extract credentials, or perform MITM, deauthentication, brute-force or exploitation actions. Website inspection makes one bounded HTTP(S) request.")
        info.setWordWrap(True); info.setStyleSheet("padding:12px;background:#1f2937;border-radius:6px;")
        lay.addWidget(info)
        lay.addStretch(1)
        return w

    def make_ip_intel(self):
        w, lay = self.base("Public IP Intelligence", "Approximate public-IP location only. This is not phone GPS. The IP is sent to the displayed lookup provider.")
        row = QHBoxLayout()
        self.geo_ip = QLineEdit(); self.geo_ip.setPlaceholderText("Public IP address, e.g. 8.8.8.8")
        btn = QPushButton("Lookup approximate location")
        btn.clicked.connect(self.lookup_public_ip)
        row.addWidget(self.geo_ip, 1); row.addWidget(btn); lay.addLayout(row)
        self.geo_out = self.output_box(); lay.addWidget(self.geo_out)
        return w, lay

    def make_hosting(self):
        w, lay = self.base("Website Hosting Intelligence", "Checks public DNS resolution. A resolved IP is not proof of an origin server; CDN/reverse-proxy infrastructure may hide the origin.")
        row = QHBoxLayout()
        self.hosting_url = QLineEdit(); self.hosting_url.setPlaceholderText("https://example.com")
        btn = QPushButton("Inspect DNS / hosting clues")
        btn.clicked.connect(self.inspect_hosting)
        row.addWidget(self.hosting_url, 1); row.addWidget(btn); lay.addLayout(row)
        self.hosting_out = self.output_box(); lay.addWidget(self.hosting_out)
        return w, lay

    def make_cctv_security(self):
        w, lay = self.base("CCTV Security Audit", "For cameras and recorders you own or are authorized to administer. No jamming, credential attacks, interception or unauthorized access.")
        checklist = QLabel("SECURITY CHECKLIST\n• Change default passwords and use unique credentials.\n• Update camera/NVR firmware from the vendor.\n• Disable UPnP and unnecessary remote access.\n• Prefer VPN for remote administration; avoid exposing camera ports publicly.\n• Use a separate IoT/VLAN network and restrict outbound traffic.\n• Review vendor logs and enable MFA where supported.\n• Verify RTSP/HTTPS exposure only on systems you administer.")
        checklist.setWordWrap(True)
        checklist.setStyleSheet("padding:16px;background:#1f2937;border-radius:8px;font-size:14px;")
        lay.addWidget(checklist)
        self.cctv_ip = QLineEdit(); self.cctv_ip.setPlaceholderText("One authorized camera/NVR IP")
        btn = QPushButton("Check common web/RTSP ports")
        btn.clicked.connect(self.audit_cctv_ports)
        row = QHBoxLayout(); row.addWidget(self.cctv_ip, 1); row.addWidget(btn); lay.addLayout(row)
        self.cctv_out = self.output_box(); lay.addWidget(self.cctv_out)
        return w, lay

    def lookup_public_ip(self):
        value = self.geo_ip.text().strip()
        if not value:
            self.show_error("geo", "Enter a public IP address first."); return
        if not self.authorize("The public IP will be sent to ipapi.co for approximate geolocation. Continue?"):
            return
        self.run_async("geo", lambda: public_ip_location(value))

    def inspect_hosting(self):
        value = self.hosting_url.text().strip()
        if not value:
            self.show_error("hosting", "Enter a complete website URL."); return
        self.run_async("hosting", lambda: website_hosting(value))

    def audit_cctv_ports(self):
        value = self.cctv_ip.text().strip()
        if not value:
            self.show_error("cctv", "Enter one camera/NVR IP you are authorized to assess."); return
        if not self.authorize(f"Confirm you administer or have explicit permission to check common ports on {value}."):
            return
        ports = [80, 443, 554, 8000, 8080, 8443]
        self.run_async("cctv", lambda: tcp_probe(value, ports=ports, timeout=0.5))

    def run_async(self, target, function):
        self.statusBar().showMessage(f"Working: {target}…")
        def worker():
            try:
                self.signals.result.emit(target, function())
            except Exception as exc:
                self.signals.error.emit(target, f"{type(exc).__name__}: {exc}")
        threading.Thread(target=worker, daemon=True).start()

    def refresh_overview(self):
        self.run_async("overview", interfaces)

    def refresh_capture_interfaces(self):
        self.run_async("capture_interfaces", interfaces)

    def resolve_dns(self):
        host = self.host.text().strip()
        if not host:
            self.show_error("network", "Enter a hostname first."); return
        self.run_async("network_dns", lambda: resolve_domain(host))

    def probe_host(self):
        host = self.ip.text().strip()
        if not host:
            self.show_error("network", "Enter one IP address first."); return
        if not self.authorize(f"Confirm you are authorized to check common TCP ports on {host}."):
            return
        self.run_async("network_probe", lambda: tcp_probe(host))

    def authorize(self, message):
        answer = QMessageBox.question(self, "Authorization required", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select packet capture", "",
            "Packet captures (*.pcap *.pcapng *.cap);;All files (*)")
        if path:
            self.run_async("pcap", lambda: analyze_pcap(path))

    def start_capture(self):
        iface = self.interface.currentText().strip()
        if not iface:
            self.show_error("capture", "No interface selected."); return
        if not self.authorize(f"Confirm you are authorized to capture metadata on '{iface}'."):
            return
        seconds = self.duration.value()
        self.capture_button.setEnabled(False)
        self.capture_summary.setText(f"Capturing on {iface} for up to {seconds} seconds…")
        self.run_async("capture", lambda: capture_live(iface, seconds))

    @staticmethod
    def inspect_url(url):
        parsed = urlsplit(url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Enter a complete http:// or https:// URL.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded usernames/passwords are not accepted.")
        request = Request(url.strip(), headers={"User-Agent": "ChakraShield/0.2 (defensive URL inspection)"}, method="GET")
        result = {"requested_url": url.strip(), "hostname": parsed.hostname, "scheme": parsed.scheme,
                  "checked_at_utc": datetime.now(timezone.utc).isoformat(), "checks": [],
                  "limitations": ["Single request only; no crawling or exploitation.", "Header checks are indicators, not a complete security audit."]}
        context = ssl.create_default_context()
        try:
            with urlopen(request, timeout=8, context=context) as response:
                result["status"] = response.status
                result["final_url"] = response.geturl()
                headers = {k.lower(): v for k, v in response.headers.items()}
                result["headers"] = {k: headers[k] for k in sorted(headers) if k in {
                    "content-type", "server", "strict-transport-security", "content-security-policy",
                    "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"}}
                for header in ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"):
                    result["checks"].append({"check": f"Header: {header}", "status": "present" if header in headers else "not observed"})
                if parsed.scheme == "https":
                    result["checks"].append({"check": "TLS certificate validation", "status": "valid for this connection"})
                else:
                    result["checks"].append({"check": "HTTPS", "status": "URL uses HTTP, not HTTPS"})
                # Read only a small amount; do not save or display page content.
                response.read(1024)
        except (URLError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
            raise RuntimeError(f"Request failed: {exc}") from exc
        return result

    def inspect_website(self):
        url = self.website_url.text().strip()
        if not url:
            self.show_error("website", "Enter a complete HTTP(S) URL."); return
        self.run_async("website", lambda: self.inspect_url(url))

    @staticmethod
    def inspect_source(path):
        p = Path(path)
        if not p.is_file() or p.stat().st_size > 2_000_000:
            raise ValueError("Choose a source/text file smaller than 2 MB.")
        text = p.read_text(encoding="utf-8", errors="replace")
        patterns = {
            "possible hard-coded secret marker": ("api_key", "apikey", "secret_key", "password =", "token ="),
            "debug marker": ("debug=true", "debug = true", "print(", "console.log("),
            "insecure transport marker": ("http://", "verify=false", "verify = false"),
            "unsafe HTML marker": ("dangerouslysetinnerhtml", "innerhtml ="),
        }
        findings = []
        lower = text.lower()
        for label, terms in patterns.items():
            matches = [term for term in terms if term in lower]
            findings.append({"category": label, "matches": matches,
                             "status": "review suggested" if matches else "no marker found"})
        return {"file": p.name, "bytes": p.stat().st_size, "lines": len(text.splitlines()),
                "findings": findings,
                "note": "Heuristic text scan only; matches can be false positives and do not prove a vulnerability."}

    def analyze_source_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select authorized source/text file", "",
            "Source and text files (*.py *.js *.ts *.html *.css *.java *.go *.php *.txt *.yaml *.yml *.json);;All files (*)")
        if path:
            self.run_async("source", lambda: self.inspect_source(path))

    def show_result(self, target, data):
        self.last_results[target] = data
        rendered = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        self.statusBar().showMessage(f"Completed: {target}")
        self.report_status.setText(f"Latest completed result: {target}")
        self.report_out.setPlainText(rendered)

        if target == "overview":
            self.populate_interfaces(data)
        elif target == "capture_interfaces":
            self.set_interfaces(data)
        elif target.startswith("network_"):
            self.network_out.setPlainText(rendered)
            self.network_table.setRowCount(0)
            rows = []
            if isinstance(data, dict) and "addresses" in data:
                rows = [(data.get("hostname", "Hostname"), ", ".join(data.get("addresses", [])) or data.get("error", "No addresses"))]
            elif isinstance(data, dict) and "results" in data:
                rows = [(f"TCP/{r.get('port')}", r.get("state", "unknown")) for r in data["results"]]
            for a, b in rows:
                self.add_row(self.network_table, [str(a), str(b)])
        elif target == "pcap":
            protocols = data.get("protocol_counts", {}) if isinstance(data, dict) else {}
            self.pcap_summary.setText(f"File: {data.get('file', 'capture')}   |   Packets analyzed: {data.get('packets_analyzed', 0)}")
            self.fill_count_table(self.pcap_table, protocols)
            self.pcap_out.setPlainText(rendered)
        elif target == "capture":
            self.capture_button.setEnabled(True)
            protocols = data.get("protocol_counts", {}) if isinstance(data, dict) else {}
            self.capture_summary.setText(f"Capture complete — {data.get('packets_analyzed', 0)} packets analyzed")
            self.fill_count_table(self.capture_table, protocols)
            self.capture_out.setPlainText(rendered)
        elif target == "website":
            self.website_out.setPlainText(rendered)
        elif target == "source":
            self.source_out.setPlainText(rendered)
        elif target == "geo":
            self.geo_out.setPlainText(rendered)
        elif target == "hosting":
            self.hosting_out.setPlainText(rendered)
        elif target == "cctv":
            self.cctv_out.setPlainText(rendered)

    @staticmethod
    def add_row(table, values):
        row = table.rowCount(); table.insertRow(row)
        for col, value in enumerate(values):
            table.setItem(row, col, QTableWidgetItem(value))

    def fill_count_table(self, table, counts):
        table.setRowCount(0)
        for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            self.add_row(table, [str(name), str(count)])

    def populate_interfaces(self, data):
        if not isinstance(data, list):
            self.show_error("overview", "Unexpected interface result format."); return
        self.overview_table.setRowCount(0)
        active = 0; addresses_count = 0
        for item in data:
            if not isinstance(item, dict):
                continue
            state = str(item.get("state", "unknown"))
            addresses = item.get("addresses", [])
            if not isinstance(addresses, list): addresses = []
            active += int(state.upper() in {"UP", "UNKNOWN", "AVAILABLE"})
            addresses_count += len(addresses)
            self.add_row(self.overview_table, [str(item.get("name", "unknown")), state, ", ".join(map(str, addresses)) or "—"])
        self.summary.setText(f"Interfaces: {len(data)}     Active / unknown: {active}     IP addresses: {addresses_count}")
        self.overview_note.setText(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.set_interfaces(data)

    def set_interfaces(self, data):
        current = self.interface.currentText() if hasattr(self, "interface") else ""
        self.interface.clear()
        for item in data if isinstance(data, list) else []:
            if isinstance(item, dict) and item.get("name"):
                self.interface.addItem(str(item["name"]))
        idx = self.interface.findText(current)
        if idx >= 0: self.interface.setCurrentIndex(idx)

    def export_report(self):
        if not self.last_results:
            QMessageBox.information(self, APP_NAME, "Run a module first; then export its result."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON report", "chakrashield-report.json", "JSON (*.json)")
        if not path: return
        try:
            Path(path).write_text(json.dumps({"application": APP_NAME, "exported_at": datetime.now(timezone.utc).isoformat(), "results": self.last_results}, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            self.report_status.setText(f"JSON report saved: {path}")
        except OSError as exc:
            self.show_error("report", str(exc))

    def export_html_report(self):
        if not self.last_results:
            QMessageBox.information(self, APP_NAME, "Run a module first; then export its result."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML report", "chakrashield-report.html", "HTML (*.html)")
        if not path: return
        body = html.escape(json.dumps(self.last_results, indent=2, ensure_ascii=False, default=str))
        page = "<!doctype html><html><head><meta charset='utf-8'><title>ChakraShield Report</title><style>body{font:15px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;background:#111827;color:#e5e7eb}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1f2937;padding:1rem;border-radius:8px}h1{color:#93c5fd}</style></head><body><h1>ChakraShield Security Report</h1><p>Exported at " + html.escape(datetime.now(timezone.utc).isoformat()) + "</p><pre>" + body + "</pre><p>Defensive metadata report; findings require human validation.</p></body></html>"
        try:
            Path(path).write_text(page, encoding="utf-8")
            self.report_status.setText(f"HTML report saved: {path}")
        except OSError as exc:
            self.show_error("report", str(exc))

    def show_error(self, target, message):
        self.statusBar().showMessage(f"Failed: {target}")
        if target == "capture":
            self.capture_button.setEnabled(True); self.capture_summary.setText("Capture failed")
            self.capture_out.setPlainText(message)
        elif target == "website": self.website_out.setPlainText("Error: " + message)
        elif target == "source": self.source_out.setPlainText("Error: " + message)
        elif target == "geo": self.geo_out.setPlainText("Error: " + message)
        elif target == "hosting": self.hosting_out.setPlainText("Error: " + message)
        elif target == "cctv": self.cctv_out.setPlainText("Error: " + message)
        elif target == "pcap": self.pcap_out.setPlainText("Error: " + message)
        elif target.startswith("network_"): self.network_out.setPlainText("Error: " + message)
        QMessageBox.warning(self, APP_NAME, message)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
