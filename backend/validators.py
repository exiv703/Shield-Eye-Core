import ipaddress
import socket
from urllib.parse import urlparse

from .exceptions import ValidationError


def resolve_target_ips(target: str) -> list[str]:
    """Resolve a hostname/URL to its IPs (empty list if it doesn't resolve)."""
    parsed = urlparse(target)
    candidate: str = parsed.hostname or target.strip()

    if not candidate:
        return []

    try:
        ip_obj = ipaddress.ip_address(candidate)
        return [str(ip_obj)]
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(candidate, None)
    except socket.gaierror:
        return []

    resolved_ips: set[str] = set()
    for entry in addr_info:
        sockaddr = entry[4]
        if not sockaddr:
            continue
        resolved_ips.add(sockaddr[0])

    return sorted(resolved_ips)


def is_forbidden_ip(ip_str: str, allow_private: bool = False) -> bool:
    """True if an IP shouldn't be scanned (loopback/link-local/metadata, or
    private unless allow_private)."""
    ip_obj = ipaddress.ip_address(ip_str)

    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        return True
    if ip_obj == ipaddress.ip_address("169.254.169.254"):  # cloud metadata
        return True
    if not allow_private and ip_obj.is_private:
        return True
    return False


def validate_scan_url(url: str, allow_private: bool = False) -> None:
    """Reject malformed URLs and ones whose host resolves to a forbidden IP.

    Raises ValidationError on anything we won't fetch (bad scheme, control
    chars, missing host, or an internal/metadata address).
    """
    if not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")

    if not url.strip():
        raise ValidationError("URL cannot be empty")

    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in url):
        raise ValidationError("URL contains control characters")

    parsed = urlparse(url.strip())

    if not parsed.scheme:
        raise ValidationError(f"URL missing scheme (http/https): {url}")

    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"URL scheme must be http or https, got: {parsed.scheme}")

    if not parsed.netloc:
        raise ValidationError(f"URL missing network location (host): {url}")

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError(f"URL missing network location (host): {url}")

    candidate_ips = resolve_target_ips(hostname)

    for resolved_ip in candidate_ips:
        if is_forbidden_ip(resolved_ip, allow_private=allow_private):
            raise ValidationError(
                f"Target resolves to forbidden IP range: {resolved_ip}"
            )


def is_safe_request_url(url: str, allow_private: bool = False) -> bool:
    """True if a URL is safe to fetch. Used to re-check redirect hops so a
    target can't bounce us into loopback/metadata/private addresses."""
    try:
        validate_scan_url(url, allow_private=allow_private)
    except ValidationError:
        return False
    return True
