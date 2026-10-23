import pytest
from sentinel.core import validate_ip, resolve_domain, tcp_probe

@pytest.mark.parametrize("ip", ["192.168.1.1", "127.0.0.1", "::1"])
def test_validate_ip(ip):
    assert validate_ip(ip) == ip

@pytest.mark.parametrize("ip", ["example.com", "192.168.1.1/24", "nope"])
def test_invalid_ip(ip):
    with pytest.raises(ValueError):
        validate_ip(ip)

def test_probe_bad_timeout():
    with pytest.raises(ValueError):
        tcp_probe("127.0.0.1", timeout=5)

def test_dns_reject_url():
    with pytest.raises(ValueError):
        resolve_domain("https://example.com")
