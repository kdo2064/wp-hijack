"""
Pre-scan passive recon: IP resolution, GeoIP, HTTP headers, page title, SSL cert.
All operations are read-only and make no intrusive requests.
"""



from __future__ import annotations







import asyncio



import datetime



import re



import socket



import ssl



from dataclasses import dataclass, field



from typing import Any



from urllib.parse import urlparse











@dataclass



class ReconInfo:



    hostname: str





    ip: str | None = None



    reverse_dns: str | None = None





    country: str | None = None



    region: str | None = None



    city: str | None = None



    org: str | None = None





    status_code: int | None = None



    server: str | None = None



    powered_by: str | None = None



    x_generator: str | None = None



    content_type: str | None = None





    page_title: str | None = None



    meta_description: str | None = None



    tech_stack: list[str] = field(default_factory=list)





    ssl_issuer: str | None = None



    ssl_expiry: str | None = None



    ssl_valid: bool | None = None



    ssl_days_left: int | None = None





    home_html: str = ""





    ip_error: str | None = None











async def run_recon(http_client: Any, target: str) -> ReconInfo:



    """Gather passive recon info for a target URL."""



    parsed = urlparse(target)



    hostname = parsed.hostname or re.sub(r'^https?://', '', target).split("/")[0]







    info = ReconInfo(hostname=hostname)









    try:



        info.ip = await asyncio.get_event_loop().run_in_executor(



            None, socket.gethostbyname, hostname



        )



    except Exception as _dns_exc:



        info.ip_error = str(_dns_exc)









    if info.ip:



        try:



            rdns = await asyncio.get_event_loop().run_in_executor(



                None, socket.gethostbyaddr, info.ip



            )



            rdns_name = rdns[0]



            if rdns_name != hostname:



                info.reverse_dns = rdns_name



        except Exception:



            pass









    try:



        r = await http_client.get(target)



        info.status_code = r.status_code



        info.home_html = r.text or ""







        hdrs = r.headers



        info.server      = hdrs.get("server") or hdrs.get("Server")



        info.powered_by  = hdrs.get("x-powered-by") or hdrs.get("X-Powered-By")



        info.x_generator = hdrs.get("x-generator") or hdrs.get("X-Generator")



        info.content_type = (hdrs.get("content-type") or "").split(";")[0].strip() or None









        from bs4 import BeautifulSoup



        soup = BeautifulSoup(info.home_html, "lxml")







        title_tag = soup.find("title")



        if title_tag:



            info.page_title = title_tag.get_text(strip=True)[:200]







        meta_desc = soup.find("meta", attrs={"name": "description"})



        if meta_desc and meta_desc.get("content"):



            info.meta_description = str(meta_desc["content"])[:250]









        tech: list[str] = []



        gen_meta = soup.find("meta", attrs={"name": "generator"})



        if gen_meta and gen_meta.get("content"):



            tech.append(str(gen_meta["content"]))







        html_lower = info.home_html.lower()



        if "wp-content" in html_lower and not any("wordpress" in t.lower() for t in tech):



            tech.append("WordPress")



        if "joomla" in html_lower:



            tech.append("Joomla")



        if "drupal" in html_lower:



            tech.append("Drupal")



        if "shopify" in html_lower:



            tech.append("Shopify")



        if "woocommerce" in html_lower:



            tech.append("WooCommerce")







        info.tech_stack = list(dict.fromkeys(tech))



    except Exception:



        pass









    if info.ip:



        try:



            import httpx as _httpx



            async with _httpx.AsyncClient(timeout=6, verify=False) as geo_client:



                geo_r = await geo_client.get(



                    f"https://ipinfo.io/{info.ip}/json",



                    headers={"Accept": "application/json"},



                )



                if geo_r.status_code == 200:



                    geo = geo_r.json()



                    info.country = geo.get("country")



                    info.region  = geo.get("region")



                    info.city    = geo.get("city")



                    info.org     = geo.get("org")



        except Exception:



            pass









    if parsed.scheme == "https":



        try:



            def _get_ssl_info() -> tuple[str | None, str | None, bool | None, int | None]:



                ctx = ssl.create_default_context()



                ctx.check_hostname = False



                ctx.verify_mode = ssl.CERT_NONE



                port = parsed.port or 443



                with socket.create_connection((hostname, port), timeout=8) as raw_sock:



                    with ctx.wrap_socket(raw_sock, server_hostname=hostname) as ssock:



                        cert = ssock.getpeercert()



                        issuer_dict = dict(x[0] for x in cert.get("issuer", []))



                        issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName")



                        not_after = cert.get("notAfter")



                        expiry_str = None



                        valid = None



                        days_left = None



                        if not_after:



                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")



                            expiry_str = exp.strftime("%Y-%m-%d")



                            now = datetime.datetime.utcnow()



                            valid = exp > now



                            days_left = (exp - now).days



                        return issuer, expiry_str, valid, days_left







            (



                info.ssl_issuer,



                info.ssl_expiry,



                info.ssl_valid,



                info.ssl_days_left,



            ) = await asyncio.get_event_loop().run_in_executor(None, _get_ssl_info)



        except Exception:



            pass







    return info



