"""Async HTTP client with UA rotation, retry, stealth helpers, and proxy support."""



from __future__ import annotations







import asyncio



import random



from typing import Any







import httpx









_USER_AGENTS = [



    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",



    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",



    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",



    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",



    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",



    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",



    "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",



]







_STEALTH_AGENTS = [



    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",



    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",



]











class AsyncHTTPClient:



    """
    Reusable async HTTP client for wp-Hijack.

    Wraps httpx.AsyncClient with:
    - UA rotation
    - Semaphore-based concurrency limiting
    - Exponential-backoff retry
    - Stealth mode (randomised delays, subtle UA)
    - Proxy support
    - Per-request timeout override
    """







    def __init__(self, cfg: dict[str, Any]) -> None:



        scanner = cfg.get("scanner", {})



        self._timeout_default = scanner.get("timeout", 15)



        self._rotate_ua = scanner.get("user_agent_rotation", True)



        self._stealth = scanner.get("stealth_mode", False)



        self._delay = float(scanner.get("delay_between_requests", 0.0))



        self._threads = scanner.get("threads", 10)



        self._verify_ssl = scanner.get("verify_ssl", False)



        proxy_url: str | None = scanner.get("proxy")







        self._semaphore = asyncio.Semaphore(self._threads)



        self._client: httpx.AsyncClient | None = None



        self._proxy: str | None = proxy_url









    async def __aenter__(self) -> "AsyncHTTPClient":



        self._client = httpx.AsyncClient(



            http2=True,



            verify=self._verify_ssl,



            follow_redirects=True,



            timeout=httpx.Timeout(self._timeout_default),



            **( {"proxy": self._proxy} if self._proxy else {} ),



        )



        return self







    async def __aexit__(self, *_: object) -> None:



        if self._client:



            await self._client.aclose()









    async def get(



        self,



        url: str,



        *,



        timeout: int | None = None,



        allow_redirects: bool = True,



        extra_headers: dict[str, str] | None = None,



    ) -> httpx.Response:



        assert self._client, "Client not started — use `async with`"







        headers = {"User-Agent": self._pick_ua()}



        if extra_headers:



            headers.update(extra_headers)







        async with self._semaphore:



            if self._delay > 0:



                jitter = random.uniform(0, self._delay * 0.5) if self._stealth else 0.0



                await asyncio.sleep(self._delay + jitter)







            _retries = 3



            _backoff = 1.0



            for _attempt in range(_retries):



                try:



                    return await self._client.get(



                        url,



                        headers=headers,



                        timeout=timeout or self._timeout_default,



                        follow_redirects=allow_redirects,



                    )



                except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError) as _exc:



                    if _attempt == _retries - 1:



                        raise



                    await asyncio.sleep(_backoff)



                    _backoff *= 2



            raise RuntimeError("unreachable")







    async def post(



        self,



        url: str,



        *,



        data: dict[str, str] | None = None,



        content: bytes | None = None,



        extra_headers: dict[str, str] | None = None,



        timeout: int | None = None,



    ) -> httpx.Response:



        assert self._client, "Client not started"



        headers = {"User-Agent": self._pick_ua()}



        if extra_headers:



            headers.update(extra_headers)







        async with self._semaphore:



            return await self._client.post(



                url,



                data=data,



                content=content,



                headers=headers,



                timeout=timeout or self._timeout_default,



            )









    async def head(self, url: str, *, timeout: int | None = None) -> httpx.Response:



        assert self._client, "Client not started"



        headers = {"User-Agent": self._pick_ua()}



        async with self._semaphore:



            return await self._client.head(



                url,



                headers=headers,



                timeout=timeout or self._timeout_default,



            )









    async def get_many(self, urls: list[str], **kwargs: Any) -> list[httpx.Response | Exception]:



        tasks = [self.get(url, **kwargs) for url in urls]



        results = await asyncio.gather(*tasks, return_exceptions=True)



        return list(results)









    def _pick_ua(self) -> str:



        pool = _STEALTH_AGENTS if self._stealth else _USER_AGENTS



        return random.choice(pool) if self._rotate_ua else pool[0]







    @staticmethod



    def is_ok(resp: httpx.Response | Exception) -> bool:



        return isinstance(resp, httpx.Response) and resp.status_code < 400



