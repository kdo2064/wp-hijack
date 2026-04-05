"""Safe injection probes — SQLi error probes, reflected XSS indicators (SAFE only)."""
from __future__ import annotations
import asyncio
import re
from dataclasses import dataclass, field

# Safe payloads that won't write data or cause DoS
_SQLI_SAFE = [
    "1'",
    "1\"",
    "1 AND 1=1",
    "1 OR 1=1",
    "' OR '1'='1",
]

_SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"supplied argument is not a valid mysql",
    r"syntax error.*sql",
]

_XSS_REFLECTED_RE = re.compile(
    r'<script>alert\(', re.I
)

_SAFE_XSS_PAYLOAD = "<script>alert(1)</script>"
_SAFE_XSS_RE = re.compile(r"<script>alert\(1\)</script>", re.I)


@dataclass
class InjectionResult:
    sqli_indicators: list[str] = field(default_factory=list)
    xss_indicators: list[str] = field(default_factory=list)
    endpoint_tested: list[str] = field(default_factory=list)


async def probe_injections(http, base_url: str) -> InjectionResult:
    base = base_url.rstrip("/")
    result = InjectionResult()

    # Common injection entry points
    test_params = [
        f"{base}/?id=",
        f"{base}/?p=",
        f"{base}/?page_id=",
        f"{base}/?cat=",
        f"{base}/?s=",
        f"{base}/?tag=",
    ]

    sqli_error_res = [re.compile(p, re.I) for p in _SQLI_ERROR_PATTERNS]

    async def _sqli_probe(url: str) -> None:
        for payload in _SQLI_SAFE[:3]:  # Limit to 3 safe payloads
            try:
                r = await http.get(url + payload, timeout=7)
                body_lower = r.text.lower()
                for pattern in sqli_error_res:
                    if pattern.search(body_lower):
                        result.sqli_indicators.append(f"{url} → SQLi error pattern")
                        result.endpoint_tested.append(url)
                        return
            except Exception:
                pass

    async def _xss_probe(url: str) -> None:
        try:
            r = await http.get(url + _SAFE_XSS_PAYLOAD, timeout=7)
            if _SAFE_XSS_RE.search(r.text):
                result.xss_indicators.append(f"{url} → reflected XSS unfiltered")
        except Exception:
            pass

    await asyncio.gather(
        *(_sqli_probe(u) for u in test_params),
        *(_xss_probe(u) for u in test_params),
    )

    return result
