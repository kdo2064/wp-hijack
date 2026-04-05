"""REST API security checks — user enumeration, WooCommerce, media, open endpoints."""
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field


@dataclass
class RestAPIResult:
    reachable: bool = False
    users_exposed: bool = False
    namespaces: list[str] = field(default_factory=list)
    woocommerce_exposed: bool = False
    media_exposed: bool = False
    details: list[str] = field(default_factory=list)


async def test_rest_api(http, base_url: str) -> RestAPIResult:
    base = base_url.rstrip("/")
    result = RestAPIResult()

    async def _root():
        try:
            r = await http.get(f"{base}/wp-json/", timeout=8)
            if r.status_code == 200:
                result.reachable = True
                data = r.json()
                ns = data.get("namespaces", [])
                result.namespaces = ns
                result.details.append(f"REST API reachable, {len(ns)} namespaces")
        except Exception:
            pass

    async def _users():
        try:
            r = await http.get(f"{base}/wp-json/wp/v2/users", timeout=8)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    result.users_exposed = True
                    result.details.append(f"REST /users exposes {len(data)} user(s)")
        except Exception:
            pass

    async def _woo():
        try:
            r = await http.get(f"{base}/wp-json/wc/v3/products", timeout=8)
            if r.status_code == 200:
                result.woocommerce_exposed = True
                result.details.append("WooCommerce REST API /products endpoint unauthenticated")
        except Exception:
            pass

    async def _media():
        try:
            r = await http.get(f"{base}/wp-json/wp/v2/media", timeout=8)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    result.media_exposed = True
                    result.details.append(f"REST /media exposes {len(data)} media item(s)")
        except Exception:
            pass

    await asyncio.gather(_root(), _users(), _woo(), _media())
    return result
