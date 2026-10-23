import pytest
from sentinel.intelligence import public_ip_location, website_hosting


def test_geolocation_rejects_private_ip_without_network_call():
    with pytest.raises(ValueError, match="public global IP"):
        public_ip_location("192.168.1.10")


def test_geolocation_rejects_invalid_ip():
    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        public_ip_location("not-an-ip")


def test_hosting_rejects_incomplete_url():
    with pytest.raises(ValueError, match="complete http"):
        website_hosting("example.com")


def test_hosting_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="embedded credentials"):
        website_hosting("https://user:pass@example.com")
