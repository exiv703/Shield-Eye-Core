import logging
import time
from typing import Optional
from urllib.parse import urljoin

import requests

from .config import TIMEOUT_CONFIG
from .validators import is_safe_request_url

logger = logging.getLogger(__name__)

_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_MAX_REDIRECT_HOPS = 5


def _parse_retry_after(retry_after: Optional[str]) -> Optional[float]:
    if not retry_after:
        return None
    try:
        seconds = float(retry_after.strip())
    except (TypeError, ValueError, AttributeError):
        return None
    if seconds < 0:
        return 0.0
    return min(seconds, 300.0)


def safe_request(
    method: str,
    url: str,
    *,
    session: Optional[requests.Session] = None,
    timeout_key: str = "http_request",
    max_retries: int = 3,
    validate_redirects: bool = False,
    allow_private: bool = False,
    **kwargs
) -> requests.Response:
    """HTTP request with retry/backoff and, optionally, SSRF-safe redirects.

    With validate_redirects=True we follow redirects by hand and re-check each
    hop with is_safe_request_url, so a user-controlled target can't bounce us
    into loopback/metadata/private addresses. Leave it off for trusted API hosts.
    """
    if not validate_redirects:
        return _request_with_retry(
            method, url, session=session, timeout_key=timeout_key,
            max_retries=max_retries, **kwargs,
        )

    kwargs["allow_redirects"] = False
    current_method = method
    current_url = url
    for _hop in range(_MAX_REDIRECT_HOPS + 1):
        response = _request_with_retry(
            current_method, current_url, session=session, timeout_key=timeout_key,
            max_retries=max_retries, **kwargs,
        )
        if response.status_code not in _REDIRECT_STATUS:
            return response

        location = response.headers.get("Location")
        if not location:
            return response

        next_url = urljoin(current_url, location)
        if not is_safe_request_url(next_url, allow_private=allow_private):
            raise requests.exceptions.RequestException(
                f"Blocked redirect to forbidden address: {next_url}"
            )

        # Per RFC, 303 (and legacy 301/302 from POST) downgrade to GET.
        if response.status_code == 303 or (
            response.status_code in (301, 302) and current_method.upper() == "POST"
        ):
            current_method = "GET"
            kwargs.pop("data", None)
            kwargs.pop("json", None)
        current_url = next_url

    raise requests.exceptions.RequestException(
        f"Too many redirects for {method} {url}"
    )


def _request_with_retry(
    method: str,
    url: str,
    *,
    session: Optional[requests.Session] = None,
    timeout_key: str = "http_request",
    max_retries: int = 3,
    **kwargs
) -> requests.Response:
    """Single request with retry + exponential backoff on transient errors."""
    retryable_exceptions = (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
    )
    timeout_value = TIMEOUT_CONFIG.get(timeout_key, TIMEOUT_CONFIG.get("http_request", 10))
    request_func = session.request if session is not None else requests.request

    backoff_delay = 2.0
    attempts = max(1, int(max_retries))

    for attempt in range(1, attempts + 1):
        try:
            response = request_func(method, url, timeout=timeout_value, **kwargs)
        except retryable_exceptions as exc:
            if attempt >= attempts:
                raise
            logger.warning(
                "HTTP request retry %d/%d for %s %s due to %s; waiting %.1fs",
                attempt,
                attempts,
                method,
                url,
                exc.__class__.__name__,
                backoff_delay,
            )
            time.sleep(backoff_delay)
            backoff_delay = min(backoff_delay * 2.0, 10.0)
            continue

        status_code = response.status_code
        should_retry = status_code == 429 or 500 <= status_code < 600
        if not should_retry:
            return response

        if attempt >= attempts:
            response.raise_for_status()

        wait_seconds = backoff_delay
        if status_code == 429:
            retry_after_seconds = _parse_retry_after(response.headers.get("Retry-After"))
            if retry_after_seconds is not None:
                wait_seconds = retry_after_seconds

        logger.warning(
            "HTTP request retry %d/%d for %s %s due to status %d; waiting %.1fs",
            attempt,
            attempts,
            method,
            url,
            status_code,
            wait_seconds,
        )
        time.sleep(wait_seconds)
        backoff_delay = min(backoff_delay * 2.0, 10.0)

    raise requests.exceptions.RequestException(f"Request failed for {method} {url}")
