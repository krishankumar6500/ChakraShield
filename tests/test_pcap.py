import pytest
from sentinel.pcap import analyze_pcap

def test_missing_pcap():
    with pytest.raises((ValueError, RuntimeError)):
        analyze_pcap("/path/that/does/not/exist.pcap")
