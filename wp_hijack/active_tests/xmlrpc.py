"""XML-RPC active tests — enabled check, listMethods, multicall abuse, pingback."""
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field


@dataclass
class XMLRPCResult:
    enabled: bool = False
    list_methods_allowed: bool = False
    multicall_allowed: bool = False
    pingback_enabled: bool = False
    methods: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)


_LIST_METHODS_PAYLOAD = b"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""

_PINGBACK_PAYLOAD = b"""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://127.0.0.1</string></value></param>
    <param><value><string>http://127.0.0.1</string></value></param>
  </params>
</methodCall>"""

_MULTICALL_PAYLOAD = b"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param><value><array><data>
      <value><struct>
        <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
        <member><name>params</name><value><array><data>
          <value><string>admin</string></value>
          <value><string>test</string></value>
        </data></array></value></member>
      </struct></value>
    </data></array></value></param>
  </params>
</methodCall>"""

_XML_HEADERS = {
    "Content-Type": "text/xml",
    "Accept": "text/xml",
}


async def test_xmlrpc(http, base_url: str) -> XMLRPCResult:
    base = base_url.rstrip("/")
    result = XMLRPCResult()
    endpoint = f"{base}/xmlrpc.php"

    # ── Is XML-RPC enabled? ────────────────────────────────────────────────────
    try:
        r = await http.get(endpoint, timeout=8)
        if r.status_code == 405 or "XML-RPC server accepts POST requests only" in r.text:
            result.enabled = True
            result.details.append("XML-RPC endpoint responds to GET (405 or text)")
        elif r.status_code == 200 and "xmlrpc" in r.text.lower():
            result.enabled = True
    except Exception:
        return result

    if not result.enabled:
        return result

    # ── system.listMethods ─────────────────────────────────────────────────────
    try:
        r = await http.post(
            endpoint,
            content=_LIST_METHODS_PAYLOAD,
            extra_headers=_XML_HEADERS,
            timeout=10,
        )
        if r.status_code == 200 and "<string>" in r.text:
            result.list_methods_allowed = True
            # Extract method names
            import re
            result.methods = re.findall(r"<string>([\w.]+)</string>", r.text)
            result.details.append(f"system.listMethods returned {len(result.methods)} methods")
            if "pingback.ping" in result.methods:
                result.pingback_enabled = True
    except Exception:
        pass

    # ── system.multicall ──────────────────────────────────────────────────────
    try:
        r = await http.post(
            endpoint,
            content=_MULTICALL_PAYLOAD,
            extra_headers=_XML_HEADERS,
            timeout=10,
        )
        if r.status_code == 200 and "<fault>" not in r.text:
            result.multicall_allowed = True
            result.details.append("system.multicall accepted (potential brute-force vector)")
    except Exception:
        pass

    return result
