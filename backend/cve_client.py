import logging
import time
from typing import Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .cache import TTLCache
from .exceptions import CVEFetchError

logger = logging.getLogger(__name__)

class CVEClient:
    def __init__(self, base_url="https://cve.circl.lu/api", session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or self._create_session_with_retry()
        self.cache = TTLCache(default_ttl=3600)
        self._last_request_time = 0.0
        self._min_request_interval = 0.5  # rate limiting
    
    def _create_session_with_retry(self):
        session = requests.Session()
        
        # retry on common errors
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _rate_limit(self):
        # simple rate limiting to avoid hammering the API
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            sleep_time = self._min_request_interval - elapsed
            logger.debug("Rate limiting: sleeping %.2fs", sleep_time)
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _fetch_vendor_product(self, vendor, product):
        vendor_key = str(vendor).lower().strip()
        product_key = str(product).lower().strip()
        # check cache first
        cached = self.cache.get(
            "cve_search",
            ttl=21600,
            vendor=vendor_key,
            product=product_key,
            base_url=self.base_url,
        )
        if cached is not None:
            logger.debug("CVE cache hit for %s/%s", vendor, product)
            return cached

        self._rate_limit()
        
        url = f"{self.base_url}/search/{vendor}/{product}"
        try:
            logger.info("Fetching CVEs for %s/%s from CIRCL API", vendor, product)
            resp = self.session.get(url, timeout=20)
            
            # handle rate limiting
            if resp.status_code == 429:
                logger.warning("Rate limited by CIRCL API, waiting 5s")
                time.sleep(5)
                resp = self.session.get(url, timeout=20)
            
            if resp.status_code != 200:
                logger.warning("CIRCL CVE search failed for %s/%s with HTTP %s", vendor, product, resp.status_code)
                self.cache.set(
                    "cve_search",
                    [],
                    ttl=21600,
                    vendor=vendor_key,
                    product=product_key,
                    base_url=self.base_url,
                )
                return []
            
            data = resp.json()
            cached_result = []
            if isinstance(data, list):
                cached_result = data
            else:
                cached_result = data.get("results", []) if isinstance(data, dict) else []

            self.cache.set(
                "cve_search",
                cached_result,
                ttl=21600,
                vendor=vendor_key,
                product=product_key,
                base_url=self.base_url,
            )
            
            logger.info("Cached %d CVEs for %s/%s", len(cached_result), vendor, product)
            return cached_result
            
        except requests.Timeout as exc:
            logger.error("CIRCL CVE search timeout for %s/%s: %s", vendor, product, exc)
            self.cache.set(
                "cve_search",
                [],
                ttl=21600,
                vendor=vendor_key,
                product=product_key,
                base_url=self.base_url,
            )
            return []
        except requests.RequestException as exc:
            logger.error("CIRCL CVE search error for %s/%s: %s", vendor, product, exc)
            self.cache.set(
                "cve_search",
                [],
                ttl=21600,
                vendor=vendor_key,
                product=product_key,
                base_url=self.base_url,
            )
            return []

    def get_latest_cves(self) -> List[Dict]:
        cached = self.cache.get("cve_latest", ttl=3600, base_url=self.base_url)
        if cached is not None:
            return cached

        self._rate_limit()
        url = f"{self.base_url}/last"
        try:
            logger.info("Fetching latest CVEs from CIRCL API")
            resp = self.session.get(url, timeout=20)

            if resp.status_code == 429:
                logger.warning("Rate limited by CIRCL API, waiting 5s")
                time.sleep(5)
                resp = self.session.get(url, timeout=20)

            if resp.status_code != 200:
                logger.warning("CIRCL latest CVE fetch failed with HTTP %s", resp.status_code)
                self.cache.set("cve_latest", [], ttl=3600, base_url=self.base_url)
                return []

            data = resp.json()
            latest = data if isinstance(data, list) else []
            self.cache.set("cve_latest", latest, ttl=3600, base_url=self.base_url)
            return latest
        except requests.Timeout as exc:
            logger.error("CIRCL latest CVE fetch timeout: %s", exc)
            self.cache.set("cve_latest", [], ttl=3600, base_url=self.base_url)
            return []
        except requests.RequestException as exc:
            logger.error("CIRCL latest CVE fetch error: %s", exc)
            self.cache.set("cve_latest", [], ttl=3600, base_url=self.base_url)
            return []

    def get_cves_for_cms(self, cms_name, version=None):
        cms_key = cms_name.lower()
        # map CMS names to vendor/product for API
        mapping = {
            "wordpress": ("wordpress", "wordpress"),
            "joomla": ("joomla", "joomla"),
            "drupal": ("drupal", "drupal"),
            "magento": ("magento", "magento"),
            "prestashop": ("prestashop", "prestashop"),
            "typo3": ("typo3", "typo3"),
        }

        if cms_key not in mapping:
            return []

        vendor, product = mapping[cms_key]
        raw_cves = self._fetch_vendor_product(vendor, product)
        if not raw_cves:
            return []

        normalized = []
        version_str = (version or "").strip()
        major_minor = None
        if version_str:
            parts = version_str.split(".")
            if len(parts) >= 2:
                major_minor = f"{parts[0]}.{parts[1]}"  # extract major.minor

        for item in raw_cves:
            cve_id = item.get("id") or item.get("cveid") or item.get("cve")
            if not cve_id:
                continue

            summary = item.get("summary") or item.get("description") or ""
            cvss = item.get("cvss") or item.get("cvss3") or item.get("cvss2")
            try:
                cvss_score = float(cvss) if cvss is not None else None
            except (ValueError, TypeError):
                cvss_score = None  # invalid score

            published = item.get("Published") or item.get("published") or item.get("Modified") or item.get("modified")

            # try to match version in summary
            match_confidence = "generic"
            if major_minor and isinstance(summary, str) and major_minor in summary:
                match_confidence = "heuristic"
            elif version_str and isinstance(summary, str) and version_str in summary:
                match_confidence = "heuristic"

            normalized.append(
                {
                    "id": cve_id,
                    "summary": summary,
                    "cvss_score": cvss_score,
                    "published": published,
                    "source": "external_cve",
                    "provider": "circl.lu",
                    "match_confidence": match_confidence,
                }
            )

        return normalized
