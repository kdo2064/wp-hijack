"""Drupal version detection."""



from __future__ import annotations



import re



import httpx



from .detector import CMSInfo, CMSType







_DRUPAL_VER_RE   = re.compile(r'Drupal\s+([\d.]+)', re.I)



_DRUPAL_CLOG_RE  = re.compile(r'^Drupal\s+([\d.x]+)', re.M)











async def detect_drupal(http, base_url: str, home_resp: httpx.Response | None = None) -> CMSInfo:



    info = CMSInfo(cms=CMSType.DRUPAL)



    signals: list[tuple[str, int]] = []



    base = base_url.rstrip("/")









    if home_resp and isinstance(home_resp, httpx.Response):



        xgen = home_resp.headers.get("x-generator", "")



        if "Drupal" in xgen:



            signals.append(("X-Generator header", 30))



            if (m := _DRUPAL_VER_RE.search(xgen)):



                info.version = m.group(1)



                signals.append(("header version", 20))





        try:



            html = home_resp.text



            if "Drupal" in html and "/sites/default/" in html:



                signals.append(("Drupal path patterns", 20))



        except Exception:



            pass









    for path in ("/CHANGELOG.txt", "/core/CHANGELOG.txt"):



        try:



            r = await http.get(f"{base}{path}", timeout=8)



            if r.status_code == 200 and "Drupal" in r.text:



                signals.append(("CHANGELOG.txt", 25))



                if (m := _DRUPAL_CLOG_RE.search(r.text)) and not info.version:



                    info.version = m.group(1).rstrip(".x")



                    signals.append(("CHANGELOG version", 20))



                break



        except Exception:



            pass







    info.confidence = min(sum(p for _, p in signals), 100)



    info.signals = [n for n, _ in signals]



    return info



