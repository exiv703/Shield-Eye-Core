import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "backend"))

from web_checks import (
    analyze_sqli_responses,
    analyze_traversal_response,
    analyze_xss_response,
)


def test_analyze_xss_response_safe_reflection_returns_none() -> None:
    payload = "<script>alert(1)</script>"
    response = "<html><body><p>Input was escaped: &lt;script&gt;alert(1)&lt;/script&gt;</p></body></html>"

    finding = analyze_xss_response(response, payload)

    assert finding is None


def test_analyze_xss_response_dangerous_script_context_detected() -> None:
    payload = "<script>alert(1)</script>"
    response = f"<html><body><script>const p = '{payload}'</script></body></html>"

    finding = analyze_xss_response(response, payload)

    assert finding is not None
    assert finding["type"] == "XSS"
    assert finding["context"] == "reflected_in_dangerous_context"


def test_analyze_sqli_responses_error_based_detected() -> None:
    finding = analyze_sqli_responses(
        base_text="normal product listing",
        true_text="normal product listing",
        false_text="normal product listing",
        error_text="You have an error in your SQL syntax near '' at line 1",
        base_time=0.2,
        false_time=0.3,
    )

    assert finding is not None
    assert finding["type"] == "SQL Injection"
    assert finding["context"] == "error_based"


def test_analyze_sqli_responses_boolean_based_detected() -> None:
    base_text = " ".join(["result"] * 250)
    true_text = base_text + " extra"
    false_text = "blocked " * 12

    finding = analyze_sqli_responses(
        base_text=base_text,
        true_text=true_text,
        false_text=false_text,
        error_text=None,
        base_time=0.25,
        false_time=0.3,
    )

    assert finding is not None
    assert finding["type"] == "SQL Injection"
    assert finding["context"] == "boolean_based"


def test_analyze_sqli_responses_time_based_detected() -> None:
    text = "normal dashboard content"

    finding = analyze_sqli_responses(
        base_text=text,
        true_text=text,
        false_text=text,
        error_text=None,
        base_time=0.2,
        false_time=3.1,
    )

    assert finding is not None
    assert finding["type"] == "SQL Injection"
    assert finding["context"] == "time_based_anomaly"


def test_analyze_traversal_response_linux_disclosure_detected() -> None:
    response = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"

    finding = analyze_traversal_response(response)

    assert finding is not None
    assert finding["type"] == "Path Traversal"
    assert finding["context"] == "file_content_disclosed"


def test_analyze_traversal_response_windows_disclosure_detected() -> None:
    response = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS"

    finding = analyze_traversal_response(response)

    assert finding is not None
    assert finding["type"] == "Path Traversal"


def test_analyze_traversal_response_safe_content_no_false_positive() -> None:
    response = """
    Welcome to the app configuration page.
    This page does not expose system files.
    User profile loaded successfully.
    """

    finding = analyze_traversal_response(response)

    assert finding is None
