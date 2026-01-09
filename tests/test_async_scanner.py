
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.async_scanner import AsyncScanner, run_async_scan, run_async_cms_scan

class TestAsyncScanner:
    
    def setup_method(self):
        
        self.scanner = AsyncScanner(max_concurrent=5)
    
    def test_initialization(self):
        
        assert self.scanner.max_concurrent == 5
        assert self.scanner.port_scanner is not None
        assert self.scanner.cms_scanner is not None
    
    @pytest.mark.asyncio
    async def test_scan_multiple_hosts(self):
        
        targets = ['192.168.1.1', '192.168.1.2']
        
        with patch.object(self.scanner.port_scanner, 'scan_single_host') as mock_scan:
            mock_scan.return_value = {
                'target': '192.168.1.1',
                'open_ports': [],
                'status': 'up'
            }
            
            results = await self.scanner.scan_multiple_hosts(targets, [80, 443])
            
            assert len(results) == 2
            assert mock_scan.call_count == 2
    
    @pytest.mark.asyncio
    async def test_scan_multiple_hosts_with_exception(self):
        
        targets = ['192.168.1.1', '192.168.1.2']
        
        with patch.object(self.scanner.port_scanner, 'scan_single_host') as mock_scan:
            mock_scan.side_effect = [
                {'target': '192.168.1.1', 'open_ports': []},
                Exception("Scan failed")
            ]
            
            results = await self.scanner.scan_multiple_hosts(targets)
            
            assert len(results) == 1
    
    @pytest.mark.asyncio
    async def test_check_multiple_urls_alive(self):
        
        urls = ['http://example.com', 'http://test.com']
        
        # Patch internal helper instead of aiohttp itself to avoid
        # unawaited AsyncMock coroutines and unraisable warnings
        with patch.object(self.scanner, '_check_url_alive', new_callable=AsyncMock) as mock_check:
            mock_check.side_effect = [True, False]

            results = await self.scanner.check_multiple_urls_alive(urls)

            assert len(results) == 2
            assert all(isinstance(v, bool) for v in results.values())
            assert mock_check.call_count == 2
    
    @pytest.mark.asyncio
    async def test_check_url_alive_success(self):
        
        # Use a lightweight manual stub instead of AsyncMock on aiohttp
        class DummyResponse:
            def __init__(self, status: int):
                self.status = status

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        class DummySession:
            def __init__(self, status: int = 200):
                self._status = status

            def head(self, url, allow_redirects=True):  # type: ignore[override]
                return DummyResponse(self._status)

        session = DummySession(status=200)
        result = await self.scanner._check_url_alive(session, 'http://example.com')

        assert result is True
    
    @pytest.mark.asyncio
    async def test_scan_multiple_cms(self):
        
        urls = ['http://example.com', 'http://test.com']
        
        with patch.object(self.scanner.cms_scanner, 'scan_cms') as mock_scan:
            mock_scan.return_value = {
                'url': 'http://example.com',
                'cms_detected': None,
                'vulnerabilities': []
            }
            
            results = await self.scanner.scan_multiple_cms(urls)
            
            assert len(results) == 2
            assert mock_scan.call_count == 2

class TestConvenienceFunctions:
    
    @patch('backend.async_scanner.AsyncScanner.scan_multiple_hosts')
    def test_run_async_scan(self, mock_scan):
        
        mock_scan.return_value = [{'target': '192.168.1.1'}]
        
        targets = ['192.168.1.1']
        
        with patch('asyncio.run') as mock_run:
            mock_run.return_value = [{'target': '192.168.1.1'}]
            results = run_async_scan(targets)
            
            assert mock_run.called
    
    @patch('backend.async_scanner.AsyncScanner.scan_multiple_cms')
    def test_run_async_cms_scan(self, mock_scan):
        
        mock_scan.return_value = [{'url': 'http://example.com'}]
        
        urls = ['http://example.com']
        
        with patch('asyncio.run') as mock_run:
            mock_run.return_value = [{'url': 'http://example.com'}]
            results = run_async_cms_scan(urls)
            
            assert mock_run.called

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
