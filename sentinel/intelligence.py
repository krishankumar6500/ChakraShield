"""Public IP and website hosting intelligence using non-invasive lookups."""
from __future__ import annotations
import ipaddress, json, socket, ssl
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

def public_ip_location(value: str) -> dict:
    """Query ipapi.co for a public IP only. This sends the IP to the provider."""
    try: ip = ipaddress.ip_address(value.strip())
    except ValueError as exc: raise ValueError("Enter one valid IPv4 or IPv6 address.") from exc
    if not ip.is_global:
        raise ValueError("Geolocation lookup only supports public global IP addresses; private, loopback and reserved IPs are not eligible.")
    url = f"https://ipapi.co/{ip}/json/"
    req = Request(url, headers={"User-Agent":"ChakraShield/0.3 defensive-intelligence"})
    try:
        with urlopen(req, timeout=8, context=ssl.create_default_context()) as response:
            data = json.loads(response.read(100_000).decode("utf-8", "replace"))
    except Exception as exc:
        raise RuntimeError(f"Public IP lookup failed: {exc}") from exc
    if data.get("error"):
        raise RuntimeError(str(data.get("reason", "Geolocation provider returned an error")))
    fields = ("ip", "city", "region", "country_name", "latitude", "longitude", "org", "asn", "timezone")
    return {"lookup_type":"approximate public-IP geolocation", "provider":"ipapi.co", "checked_at_utc":datetime.now(timezone.utc).isoformat(), "result":{k:data.get(k) for k in fields}, "limitations":["This is an approximate IP/network location, not phone GPS.", "VPNs, mobile carrier NAT, proxies and shared IPs can make the estimate inaccurate.", "The public IP is sent to the geolocation provider for this lookup."]}

def website_hosting(url: str) -> dict:
    """Inspect public DNS resolution and infer hosting/CDN only from visible clues."""
    parsed = urlsplit(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a complete http:// or https:// website URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    host = parsed.hostname
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({i[4][0] for i in infos})
    except OSError as exc:
        addresses=[]; dns_error=str(exc)
    else: dns_error=None
    parsed_ips=[]
    for addr in addresses:
        try:
            ip=ipaddress.ip_address(addr); parsed_ips.append({"ip":addr,"public":ip.is_global})
        except ValueError: pass
    note = "DNS did not return an address." if not addresses else "DNS addresses are visible endpoints; they do not prove the origin server."
    return {"hostname":host,"scheme":parsed.scheme,"checked_at_utc":datetime.now(timezone.utc).isoformat(),"dns_addresses":parsed_ips,"dns_error":dns_error,"hosting_assessment":"Inconclusive","evidence":["DNS resolution only; this module does not bypass CDNs, reverse proxies, authentication or access controls."],"limitations":[note,"Provider/ASN enrichment can be added separately; an IP address alone does not prove the physical hosting location.","Only public, non-invasive checks are performed."]}
