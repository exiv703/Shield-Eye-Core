import socket
from unittest.mock import patch

import pytest

from backend.exceptions import ValidationError
from backend.validators import is_forbidden_ip, resolve_target_ips, validate_scan_url


def test_resolve_target_ips_hostname_returns_mocked_ips():
    mocked_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("93.184.216.34", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
    ]

    with patch("backend.validators.socket.getaddrinfo", return_value=mocked_addrinfo):
        ips = resolve_target_ips("example.com")

    assert ips == ["2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"]


def test_resolve_target_ips_direct_ipv4_returns_self():
    with patch("backend.validators.socket.getaddrinfo") as mocked_getaddrinfo:
        ips = resolve_target_ips("127.0.0.1")

    assert ips == ["127.0.0.1"]
    mocked_getaddrinfo.assert_not_called()


def test_is_forbidden_ip_loopback_true():
    assert is_forbidden_ip("127.0.0.1") is True


def test_is_forbidden_ip_cloud_metadata_true():
    assert is_forbidden_ip("169.254.169.254") is True


def test_is_forbidden_ip_private_allowed_false_forbidden_check():
    assert is_forbidden_ip("10.0.0.5", allow_private=True) is False


def test_is_forbidden_ip_private_disallowed_true():
    assert is_forbidden_ip("10.0.0.5", allow_private=False) is True


def test_validate_scan_url_localhost_raises_validation_error():
    with patch("backend.validators.resolve_target_ips", return_value=["127.0.0.1"]):
        with pytest.raises(ValidationError):
            validate_scan_url("http://localhost")


def test_validate_scan_url_https_example_com_passes():
    with patch("backend.validators.resolve_target_ips", return_value=["93.184.216.34"]):
        validate_scan_url("https://example.com")


def test_validate_scan_url_unresolvable_hostname_graceful_pass():
    with patch("backend.validators.resolve_target_ips", return_value=[]):
        validate_scan_url("https://does-not-resolve.invalid")
