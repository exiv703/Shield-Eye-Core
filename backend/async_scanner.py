import asyncio
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

import aiohttp
from aiohttp import ClientSession, ClientTimeout

from .port_scanner import PortScanner
from .cms_scanner import CMSScanner
from .config import ASYNC_CONFIG, TIMEOUT_CONFIG

logger = logging.getLogger(__name__)

class AsyncScanner:
    def __init__(self, port_scanner=None, cms_scanner=None, max_concurrent=None, timeout=None):
        self.port_scanner = port_scanner or PortScanner()
        self.cms_scanner = cms_scanner or CMSScanner()
        
        # setup async config
        if max_concurrent is None:
            max_concurrent = ASYNC_CONFIG.get('max_concurrent_connections', 10)
        if timeout is None:
            timeout = TIMEOUT_CONFIG.get('http_request', 30)
        
        self.max_concurrent = max_concurrent
        self.timeout = ClientTimeout(total=timeout)
        self.semaphore = asyncio.Semaphore(ASYNC_CONFIG.get('semaphore_limit', 5))
        
    async def scan_multiple_hosts(self, targets, ports=None, scan_mode='safe'):
        logger.info("Starting async scan of %d hosts", len(targets))
        
        # use thread pool for blocking port scans
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            loop = asyncio.get_event_loop()
            tasks = [
                loop.run_in_executor(
                    executor,
                    self.port_scanner.scan_single_host,
                    target,
                    ports,
                    scan_mode
                )
                for target in targets
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
        # filter out failed scans
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("Scan failed for target %s: %s", targets[i], result)
            else:
                valid_results.append(result)
        
        logger.info("Completed async scan: %d/%d successful", len(valid_results), len(targets))
        return valid_results
    
    async def scan_multiple_cms(self, urls, stealth=False, scan_mode='safe'):
        logger.info("Starting async CMS scan of %d URLs", len(urls))
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = [
                self._scan_cms_async(session, url, stealth, scan_mode)
                for url in urls
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("CMS scan failed for %s: %s", urls[i], result)
            else:
                valid_results.append(result)
        
        logger.info("Completed async CMS scan: %d/%d successful", len(valid_results), len(urls))
        return valid_results
    
    async def _scan_cms_async(self, session, url, stealth, scan_mode):
        async with self.semaphore:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self.cms_scanner.scan_cms,
                url
            )
            
            result['scan_mode'] = scan_mode
            result['stealth'] = stealth
            
            return result
    
    async def check_multiple_urls_alive(self, urls: List[str]) -> Dict[str, bool]:
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            tasks = [self._check_url_alive(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            url: result if not isinstance(result, Exception) else False
            for url, result in zip(urls, results)
        }
    
    async def _check_url_alive(self, session: ClientSession, url: str) -> bool:
        try:
            async with session.head(url, allow_redirects=True) as response:
                return response.status < 500
        except Exception as exc:
            logger.debug("URL check failed for %s: %s", url, exc)
            return False

def run_async_scan(
    targets: List[str],
    ports: Optional[List[int]] = None,
    scan_mode: str = 'safe',
    max_concurrent: Optional[int] = None
) -> List[Dict]:
    if max_concurrent is None:
        max_concurrent = ASYNC_CONFIG.get('max_concurrent_connections', 10)
    scanner = AsyncScanner(max_concurrent=max_concurrent)
    return asyncio.run(scanner.scan_multiple_hosts(targets, ports, scan_mode))

def run_async_cms_scan(
    urls: List[str],
    stealth: bool = False,
    scan_mode: str = 'safe',
    max_concurrent: Optional[int] = None
) -> List[Dict]:
    if max_concurrent is None:
        max_concurrent = ASYNC_CONFIG.get('max_concurrent_connections', 10)
    scanner = AsyncScanner(max_concurrent=max_concurrent)
    return asyncio.run(scanner.scan_multiple_cms(urls, stealth, scan_mode))
