import ipaddress
import socket
from urllib.parse import urlparse

from .exceptions import ValidationError


def resolve_target_ips(target: str) -> list[str]:
    """Resolve hostname to IP addresses.

    Args:
        target: URL or hostname string.

    Returns:
        List of resolved IP address strings, or empty list if unresolvable.
    """
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
    """Check if IP is in a forbidden range for scanning.

    Args:
        ip_str: IP address string.
        allow_private: If True, allow RFC1918 ranges for lab environments.

    Returns:
        True if IP should be blocked, False otherwise.
    """
    ip_obj = ipaddress.ip_address(ip_str)

    if ip_obj.is_loopback:
        return True

    if ip_obj.is_link_local:
        return True

    if ip_obj.is_multicast:
        return True

    if ip_obj == ipaddress.ip_address("169.254.169.254"):
        return True

    if not allow_private and ip_obj.is_private:
        return True

    return False


def validate_scan_url(url: str, allow_private: bool = False) -> None:
    """Validate that a scan target URL does not point to forbidden IPs.

    Args:
        url: Target URL to validate.
        allow_private: If True, allow private IP ranges for lab mode.

    Raises:
        ValidationError: If URL is invalid or resolves to forbidden IP.
    """
    if not url:
        raise ValidationError("URL cannot be empty")

    parsed = urlparse(url.strip())

    if not parsed.scheme:
        raise ValidationError(f"URL missing scheme (http/https): {url}")

    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"URL scheme must be http or https, got: {parsed.scheme}")

    if not parsed.netloc:
        raise ValidationError(f"URL missing domain: {url}")

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError(f"URL missing domain: {url}")

    candidate_ips = resolve_target_ips(hostname)

    for resolved_ip in candidate_ips:
        if is_forbidden_ip(resolved_ip, allow_private=allow_private):
            raise ValidationError(
                f"Target resolves to forbidden IP range: {resolved_ip}"
            )
