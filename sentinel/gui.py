"""PySide6 desktop GUI. Live capture is explicitly user-started and bounded."""
from __future__ import annotations
import json, sys, threading
from pathlib import Path
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QFileDialog, QPlainTextEdit, QMessageBox, QSpinBox)
from .core import interfaces, resolve_domain, tcp_probe, write_json
from .pcap import analyze_pcap, capture_live

class WorkerSignals(QObject):
    result = Signal(object)
    error = Signal(str)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChakraShield — Defensive Network Workbench")
        self.resize(1180, 760)
        self.signals = WorkerSignals()
        self.signals.result.connect(self.show_result)
        self.signals.error.connect(self.show_error)
        tabs = QTabWidget()
        tabs.addTab(self.make_overview(), "Overview")
        tabs.addTab(self.make_network(), "Network")
        tabs.addTab(self.make_pcap(), "PCAP Forensics")
        tabs.addTab(self.make_capture(), "Live Capture")
        self.setCentralWidget(tabs)
        self.setStyleSheet("""
        QMainWindow,QWidget { background:#111827;color:#e5e7eb;font-size:13px }
        QTabWidget::pane { border:1px solid #374151 }
        QPushButton { background:#2563eb;color:white;padding:8px 12px;border-radius:5px }
        QLineEdit,QComboBox,QPlainTextEdit,QTableWidget,QSpinBox { background:#1f2937;color:#f9fafb;border:1px solid #4b5563;padding:5px }
        QLabel#muted { color:#9ca3af }
        """)
    def base(self, title, description):
        w = QWidget(); lay = QVBoxLayout(w)
        h = QLabel(title); h.setStyleSheet("font-size:22px;font-weight:700")
        lay.addWidget(h); desc = QLabel(description); desc.setWordWrap(True); desc.setObjectName("muted"); lay.addWidget(desc)
        return w, lay
    def make_overview(self):
        w, lay = self.base("ChakraShield", "Cross-platform defensive network visibility, packet metadata, and offline PCAP analysis.")
        lay.addWidget(QLabel("Only monitor networks and devices you own or have explicit permission to assess."))
        btn = QPushButton("Refresh interfaces"); btn.clicked.connect(lambda: self.run_async(lambda: {"interfaces": interfaces()})); lay.addWidget(btn)
        self.overview = QPlainTextEdit(); self.overview.setReadOnly(True); self.overview.setPlainText("Choose a module from the tabs above.")
        lay.addWidget(self.overview); return w
    def make_network(self):
        w, lay = self.base("Network tools", "DNS resolution and bounded common-port connectivity checks. These checks are not a full vulnerability scan.")
        row = QHBoxLayout(); self.host = QLineEdit(); self.host.setPlaceholderText("Hostname, e.g. example.com")
        b = QPushButton("Resolve DNS"); b.clicked.connect(lambda: self.run_async(lambda: resolve_domain(self.host.text())))
        row.addWidget(self.host); row.addWidget(b); lay.addLayout(row)
        row2 = QHBoxLayout(); self.ip = QLineEdit(); self.ip.setPlaceholderText("Authorized single IP, e.g. 192.168.1.1")
        b2 = QPushButton("Probe common TCP ports"); b2.clicked.connect(lambda: self.run_async(lambda: tcp_probe(self.ip.text())))
        row2.addWidget(self.ip); row2.addWidget(b2); lay.addLayout(row2)
        self.network_out = QPlainTextEdit(); self.network_out.setReadOnly(True); lay.addWidget(self.network_out); return w
    def make_pcap(self):
        w, lay = self.base("PCAP forensics", "Load a PCAP/PCAPNG file you are authorized to analyze. This view focuses on metadata; encrypted messages remain encrypted.")
        btn = QPushButton("Open PCAP file"); btn.clicked.connect(self.open_pcap); lay.addWidget(btn)
        self.pcap_out = QPlainTextEdit(); self.pcap_out.setReadOnly(True); lay.addWidget(self.pcap_out); return w
    def make_capture(self):
        w, lay = self.base("Live capture", "Capture is bounded to 1–60 seconds and requires a valid interface and appropriate OS permissions. Use only on authorized interfaces.")
        row = QHBoxLayout(); self.interface = QComboBox()
        try:
            for item in interfaces(): self.interface.addItem(item["name"])
        except Exception: pass
        refresh = QPushButton("Refresh interfaces"); refresh.clicked.connect(self.refresh_interfaces)
        self.duration = QSpinBox(); self.duration.setRange(1,60); self.duration.setValue(10); self.duration.setSuffix(" seconds")
        start = QPushButton("Start bounded capture"); start.clicked.connect(self.start_capture)
        row.addWidget(self.interface); row.addWidget(refresh); row.addWidget(self.duration); row.addWidget(start); lay.addLayout(row)
        self.capture_out = QPlainTextEdit(); self.capture_out.setReadOnly(True); lay.addWidget(self.capture_out); return w
    def refresh_interfaces(self):
        self.interface.clear()
        for item in interfaces(): self.interface.addItem(item["name"])
    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select PCAP", "", "Packet captures (*.pcap *.pcapng *.cap);;All files (*)")
        if path: self.run_async(lambda: analyze_pcap(path))
    def start_capture(self):
        iface = self.interface.currentText()
        if not iface: return self.show_error("No interface selected.")
        if QMessageBox.question(self, "Authorized capture", f"Confirm you are authorized to capture traffic on interface '{iface}'?") != QMessageBox.Yes:
            return
        self.run_async(lambda: capture_live(iface, self.duration.value()))
    def run_async(self, fn):
        def worker():
            try: self.signals.result.emit(fn())
            except Exception as exc: self.signals.error.emit(f"{type(exc).__name__}: {exc}")
        threading.Thread(target=worker, daemon=True).start()
    def show_result(self, data):
        rendered = json.dumps(data, indent=2, ensure_ascii=False)
        self.overview.setPlainText(rendered)
        self.network_out.setPlainText(rendered)
        self.pcap_out.setPlainText(rendered)
        self.capture_out.setPlainText(rendered)
    def show_error(self, error):
        QMessageBox.warning(self, "ChakraShield", error)

def main():
    app = QApplication(sys.argv)
    window = MainWindow(); window.show()
    sys.exit(app.exec())
if __name__ == "__main__": main()
