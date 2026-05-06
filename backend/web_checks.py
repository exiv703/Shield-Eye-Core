import html
import re
from typing import Dict, List, Optional, Tuple

import requests


def detect_reflected_xss(
    response_text: str,
    payload: str,
    max_body_bytes: int = 1048576,
) -> Optional[Dict[str, str]]:
    """Detect if XSS payload is reflected in a dangerous execution context.

    Args:
        response_text: Full HTTP response body.
        payload: XSS payload that was sent.
        max_body_bytes: Max bytes to analyze before truncation.

    Returns:
        A finding dictionary when dangerous reflected XSS is detected, otherwise None.
    """
    if len(response_text) > max_body_bytes:
        response_text = response_text[:max_body_bytes]

    response_lower = response_text.lower()
    payload_lower = payload.lower()

    try:
        unescaped_response = html.unescape(response_text).lower()
    except Exception:
        unescaped_response = response_lower

    if payload_lower not in response_lower and payload_lower not in unescaped_response:
        return None

    dangerous_patterns: List[str] = [
        r"<script[^>]*>.*?" + re.escape(payload_lower) + r".*?</script>",
        r"\bon(?:error|load|click|focus)\s*=\s*['\"][^'\"]*"
        + re.escape(payload_lower)
        + r"[^'\"]*['\"]",
        r"\b(?:src|href)\s*=\s*['\"]\s*javascript\s*:[^'\"]*"
        + re.escape(payload_lower)
        + r"[^'\"]*['\"]",
        r"\b\w+\s*=\s*['\"][^'\"]*"
        + re.escape(payload_lower)
        + r"[^'\"]*['\"]",
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, response_lower, flags=re.IGNORECASE | re.DOTALL):
            sample = payload[:50] + ("..." if len(payload) > 50 else "")
            return {
                "type": "XSS",
                "severity": "high",
                "context": "reflected_in_dangerous_context",
                "payload_sample": sample,
            }

    return None


def analyze_xss_response(
    response_text: str,
    payload: str,
    max_bytes: int = 1048576,
) -> Optional[Dict[str, str]]:
    """Analyze reflected XSS risk from response body and payload.

    Args:
        response_text: HTTP response body already fetched by caller.
        payload: XSS payload used in the request.
        max_bytes: Maximum number of bytes to analyze.

    Returns:
        Finding dictionary if dangerous reflection is detected, else None.
    """
    return detect_reflected_xss(response_text, payload, max_body_bytes=max_bytes)


SQL_ERROR_PATTERNS: List[str] = [
    r"sql\s*syntax",
    r"unclosed\s+quotation\s+mark",
    r"quoted\s+string\s+not\s+properly\s+terminated",
    r"mysql_fetch_",
    r"sqlite3\.operationalerror",
    r"ora-\d{5}",
    r"postgresql\s+error",
    r"mysqli?_query\(\)",
    r"valid\s+mysql\s+result",
    r"you\s+have\s+an\s+error\s+in\s+your\s+sql",
]


def match_sql_error(text: str) -> Optional[str]:
    """Check if response contains common SQL error patterns.

    Args:
        text: Response body text to analyze.

    Returns:
        Matched pattern descriptor if found, otherwise None.
    """
    text_lower = text.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return f"sql_error_pattern:{pattern}"
    return None


def compare_boolean_sqli(
    base_response: requests.Response,
    true_payload_response: requests.Response,
    false_payload_response: requests.Response,
    similarity_threshold: float = 0.85,
) -> bool:
    """Detect boolean-based SQLi by comparing response consistency.

    Args:
        base_response: Response with neutral payload.
        true_payload_response: Response with true boolean condition.
        false_payload_response: Response with false boolean condition.
        similarity_threshold: Minimum overlap ratio to treat two responses as similar.

    Returns:
        True when boolean-based SQLi is likely, otherwise False.
    """

    def response_signature(resp: requests.Response) -> Tuple[int, int, int]:
        content_sample = resp.text[:500].encode("utf-8", errors="ignore")
        return (resp.status_code, len(resp.text), hash(content_sample))

    def token_overlap_ratio(left: str, right: str) -> float:
        left_tokens = set(re.findall(r"\w+", left.lower()))
        right_tokens = set(re.findall(r"\w+", right.lower()))
        if not left_tokens or not right_tokens:
            return 1.0
        union = left_tokens | right_tokens
        if not union:
            return 1.0
        return len(left_tokens & right_tokens) / len(union)

    base_sig = response_signature(base_response)
    true_sig = response_signature(true_payload_response)
    false_sig = response_signature(false_payload_response)

    true_overlap = token_overlap_ratio(base_response.text[:1000], true_payload_response.text[:1000])
    false_overlap = token_overlap_ratio(true_payload_response.text[:1000], false_payload_response.text[:1000])

    true_matches_base = (
        base_sig[0] == true_sig[0]
        and abs(base_sig[1] - true_sig[1]) < 50
        and true_overlap >= similarity_threshold
    )
    false_differs = (
        false_sig[0] != true_sig[0]
        or abs(false_sig[1] - true_sig[1]) > 100
        or false_overlap < similarity_threshold
    )
    return true_matches_base and false_differs


def detect_sqli_from_responses(
    base_resp: requests.Response,
    true_resp: requests.Response,
    false_resp: requests.Response,
    error_resp: Optional[requests.Response] = None,
    time_threshold: float = 2.5,
) -> Optional[Dict[str, str]]:
    """Aggregate SQLi detection using error, boolean, and time signals.

    Args:
        base_resp: Baseline response with neutral input.
        true_resp: Response with true boolean payload.
        false_resp: Response with false boolean payload.
        error_resp: Optional response using an error-triggering payload.
        time_threshold: Delay threshold in seconds for anomaly detection.

    Returns:
        SQLi finding details when detected, otherwise None.
    """
    for resp in (base_resp, true_resp, false_resp, error_resp):
        if resp is None:
            continue
        matched_pattern = match_sql_error(resp.text)
        if matched_pattern:
            return {
                "type": "SQL Injection",
                "severity": "high",
                "context": "error_based",
                "details": matched_pattern,
            }

    if compare_boolean_sqli(base_resp, true_resp, false_resp):
        return {
            "type": "SQL Injection",
            "severity": "high",
            "context": "boolean_based",
            "details": "response_differs_on_boolean_condition",
        }

    if false_resp.elapsed.total_seconds() - base_resp.elapsed.total_seconds() > time_threshold:
        return {
            "type": "SQL Injection",
            "severity": "medium",
            "context": "time_based_anomaly",
            "details": f"response_delay_{false_resp.elapsed.total_seconds():.1f}s",
        }
    return None


def analyze_sqli_responses(
    base_text: str,
    true_text: str,
    false_text: str,
    error_text: Optional[str] = None,
    base_time: float = 0.0,
    false_time: float = 0.0,
) -> Optional[Dict[str, str]]:
    """Analyze SQLi signals from response texts and timings.

    Args:
        base_text: Response text from neutral payload.
        true_text: Response text from true boolean payload.
        false_text: Response text from false boolean payload.
        error_text: Optional response text from error payload.
        base_time: Request duration for base response in seconds.
        false_time: Request duration for false response in seconds.

    Returns:
        Finding dictionary if SQLi is detected, else None.
    """

    def overlap(left: str, right: str) -> float:
        left_tokens = set(re.findall(r"\w+", left.lower()))
        right_tokens = set(re.findall(r"\w+", right.lower()))
        if not left_tokens or not right_tokens:
            return 1.0
        union = left_tokens | right_tokens
        return 1.0 if not union else len(left_tokens & right_tokens) / len(union)

    for text in (base_text, true_text, false_text, error_text):
        if text is not None:
            matched_pattern = match_sql_error(text)
            if matched_pattern:
                return {
                    "type": "SQL Injection",
                    "severity": "high",
                    "context": "error_based",
                    "details": matched_pattern,
                }

    true_overlap = overlap(base_text[:1000], true_text[:1000])
    false_overlap = overlap(true_text[:1000], false_text[:1000])
    true_matches_base = abs(len(base_text) - len(true_text)) < 50 and true_overlap >= 0.85
    false_differs = abs(len(false_text) - len(true_text)) > 100 or false_overlap < 0.85
    if true_matches_base and false_differs:
        return {
            "type": "SQL Injection",
            "severity": "high",
            "context": "boolean_based",
            "details": "response_differs_on_boolean_condition",
        }

    if false_time - base_time > 2.5:
        return {
            "type": "SQL Injection",
            "severity": "medium",
            "context": "time_based_anomaly",
            "details": f"response_delay_{false_time:.1f}s",
        }
    return None


TRAVERSAL_PAYLOADS: List[str] = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "....//....//etc/passwd",
]


FILE_DISCLOSURE_PATTERNS: List[str] = [
    r"^root:x:0:0:",
    r"^daemon:x:\d+:\d+:",
    r"^/bin/bash$",
    r"^\[boot loader\]",
    r"^\[fonts\]",
    r"for 16-bit app support",
    r"extensions=php",
    r"^(uid|gid|groups)=\d+",
    r"^[a-zA-Z0-9_]+:[x*]:\d+:\d+:",
]


def analyze_traversal_response(
    response_text: str,
    max_bytes: int = 524288,
) -> Optional[Dict[str, str]]:
    """Analyze whether response body indicates path traversal file disclosure.

    Args:
        response_text: HTTP response body already fetched by caller.
        max_bytes: Maximum number of bytes to analyze before truncation.

    Returns:
        Finding dictionary when high-confidence file disclosure is detected, else None.
    """
    if len(response_text) > max_bytes:
        response_text = response_text[:max_bytes]

    for line in response_text.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        for pattern in FILE_DISCLOSURE_PATTERNS:
            if re.match(pattern, line_stripped, re.IGNORECASE):
                return {
                    "type": "Path Traversal",
                    "severity": "high",
                    "context": "file_content_disclosed",
                    "pattern_matched": pattern,
                }

    return None
