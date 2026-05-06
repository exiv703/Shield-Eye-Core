import logging
import time
from typing import Optional

import requests

from .config import TIMEOUT_CONFIG

logger = logging.getLogger(__name__)


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
    **kwargs
) -> requests.Response:
    """Make an HTTP request with retry, backoff, and timeout handling.

    Args:
        method: HTTP method (GET, POST, etc.).
        url: Target URL.
        session: Optional requests Session to reuse connections.
        timeout_key: Key in TIMEOUT_CONFIG for timeout value.
        max_retries: Maximum retry attempts.
        **kwargs: Extra arguments forwarded to requests request.

    Returns:
        requests.Response: Response object on success.

    Raises:
        requests.exceptions.RequestException: If retries are exhausted.
    """
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
