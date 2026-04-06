"""
CVE Document Researcher — fetches NVD + advisory/PoC pages so AI can
generate an accurate, evidence-based exploit rather than guessing.

Flow
────
1. Query NVD API v2 for the official CVE record (description, CWEs, CVSS,
   references).
2. Collect any extra `references` the vulndb already has for the finding.
3. Prioritise advisory / PoC URLs (GitHub, ExploitDB, WPScan, Wordfence …).
4. Fetch up to _MAX_REFS pages and strip HTML to plain text.
5. Return a CVEDocument whose .as_context_block() is ready to paste into
   an AI prompt.
"""



from __future__ import annotations



import asyncio

import logging

import re

from dataclasses import dataclass, field

from typing import Any



import httpx



log = logging.getLogger(__name__)



                                                                             

_NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_TIMEOUT      = 12                                    

_MAX_REFS     = 4                                        

_MAX_REF_CHARS = 4_000                                    



                                                                       

_PRIORITY_HOSTS = (

    "github.com",

    "exploit-db.com",

    "packetstormsecurity.com",

    "wpscan.com",

    "wordfence.com",

    "patchstack.com",

    "nvd.nist.gov",

    "cve.mitre.org",

)





@dataclass

class CVEDocument:

    """All research material gathered for one CVE."""



    cve_id: str

    nvd_description: str = ""

    nvd_references:  list[str] = field(default_factory=list)

    nvd_cwes:        list[str] = field(default_factory=list)

    nvd_cvss_vector: str = ""



                                                       

    advisory_texts: list[dict[str, str]] = field(default_factory=list)

                                           



    fetch_errors: list[str] = field(default_factory=list)



    @property

    def has_data(self) -> bool:

        return bool(

            self.nvd_description or self.advisory_texts

        )



    def as_context_block(self) -> str:

        """
        Returns a structured text block that can be injected verbatim into
        an AI exploit-generation prompt as additional grounding evidence.
        """

        lines: list[str] = [

            f"╔══════════════════════════════════════════════════════",

            f"║  CVE RESEARCH DOCUMENT — {self.cve_id}",

            f"╚══════════════════════════════════════════════════════",

        ]



        if self.nvd_description:

            lines.append(f"\n[NVD Official Description]\n{self.nvd_description}")



        if self.nvd_cwes:

            lines.append(f"\n[Weakness Types] {', '.join(self.nvd_cwes)}")



        if self.nvd_cvss_vector:

            lines.append(f"\n[CVSS Vector] {self.nvd_cvss_vector}")



        if self.nvd_references:

            lines.append(f"\n[Known References] ({len(self.nvd_references)} URLs)")

            for url in self.nvd_references[:8]:

                lines.append(f"  • {url}")



        if self.advisory_texts:

            lines.append(

                f"\n[Advisory / PoC Content — {len(self.advisory_texts)} sources fetched]"

            )

            for i, entry in enumerate(self.advisory_texts, 1):

                lines.append(

                    f"\n--- Source {i}: {entry['url']} ---\n"

                    + entry["text"][:_MAX_REF_CHARS]

                )



        lines.append("\n══════════════════════════════════════════════════════")

        return "\n".join(lines)





                                                                             



async def _fetch_nvd(cve_id: str) -> dict[str, Any]:

    """Query NVD CVE 2.0 API; returns raw JSON or empty dict on failure."""

    try:

        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as c:

            r = await c.get(_NVD_API, params={"cveId": cve_id})

            if r.status_code == 200:

                return r.json()

            log.debug("NVD returned HTTP %s for %s", r.status_code, cve_id)

    except Exception as exc:

        log.debug("NVD fetch error for %s: %s", cve_id, exc)

    return {}





def _parse_nvd_response(data: dict[str, Any], cve_id: str) -> CVEDocument:

    doc = CVEDocument(cve_id=cve_id)

    vulns = data.get("vulnerabilities", [])

    if not vulns:

        return doc



    cve_data = vulns[0].get("cve", {})



                         

    for d in cve_data.get("descriptions", []):

        if d.get("lang") == "en":

            doc.nvd_description = d.get("value", "").strip()

            break



                       

    doc.nvd_references = [

        r["url"]

        for r in cve_data.get("references", [])

        if r.get("url")

    ]



          

    seen_cwes: set[str] = set()

    for w in cve_data.get("weaknesses", []):

        for d in w.get("description", []):

            val = d.get("value", "")

            if val.startswith("CWE-") and val not in seen_cwes:

                doc.nvd_cwes.append(val)

                seen_cwes.add(val)



                                           

    metrics = cve_data.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):

        entries = metrics.get(key, [])

        if entries:

            vec = entries[0].get("cvssData", {}).get("vectorString", "")

            if vec:

                doc.nvd_cvss_vector = vec

                break



    return doc





                                                                             



def _strip_html(html: str) -> str:

    """Very lightweight HTML → plain text (no BeautifulSoup needed)."""

                                      

    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)

                          

    html = re.sub(r"<[^>]+>", " ", html)

                         

    html = re.sub(r"[ \t]+", " ", html)

    html = re.sub(r"\n{3,}", "\n\n", html)

    return html.strip()





_ROBOTS = re.compile(r"robots\.txt|sitemap\.xml", re.I)





async def _fetch_advisory(url: str) -> str:

    """Fetch one advisory URL and return stripped plain text (or empty string)."""

    if _ROBOTS.search(url):

        return ""

    try:

        async with httpx.AsyncClient(

            timeout=_TIMEOUT,

            follow_redirects=True,

            headers={"User-Agent": "Mozilla/5.0 (SecurityResearcher/WPHijack)"},

        ) as c:

            r = await c.get(url)

            ct = r.headers.get("content-type", "")

            if r.status_code != 200:

                return ""

            if "html" in ct or "text" in ct:

                return _strip_html(r.text)

                                   

            if len(r.text) < 300_000:

                return r.text.strip()

    except Exception as exc:

        log.debug("Advisory fetch error [%s]: %s", url, exc)

    return ""





def _rank_refs(refs: list[str]) -> list[str]:

    """Sort references so known PoC / advisory hosts come first."""

    def _score(u: str) -> int:

        for i, host in enumerate(_PRIORITY_HOSTS):

            if host in u.lower():

                return i

        return len(_PRIORITY_HOSTS)



    return sorted(refs, key=_score)





                                                                             



async def fetch_cve_document(

    cve_id: str,

    extra_references: list[str] | None = None,

) -> CVEDocument:

    """
    Fetch a complete CVE research document for *cve_id*.

    Parameters
    ----------
    cve_id : str
        e.g. "CVE-2024-1234"
    extra_references : list[str], optional
        Additional URLs already known (e.g. from vulndb finding.references).
        These are merged with NVD references before advisory fetching.

    Returns
    -------
    CVEDocument
        Populated with NVD metadata + scraped advisory / PoC text.
        Call .as_context_block() to get a prompt-ready string.
    """

                         

    nvd_raw = await _fetch_nvd(cve_id)

    doc = _parse_nvd_response(nvd_raw, cve_id)



                             

    all_refs: list[str] = list(doc.nvd_references)

    if extra_references:

        for ref in extra_references:

            if ref and ref not in all_refs:

                all_refs.append(ref)



                     

    ranked = _rank_refs(all_refs)[:_MAX_REFS]



                                          

    if ranked:

        tasks = [_fetch_advisory(url) for url in ranked]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, result in zip(ranked, results):

            if isinstance(result, str) and result.strip():

                doc.advisory_texts.append({"url": url, "text": result})

            elif isinstance(result, Exception):

                doc.fetch_errors.append(f"{url}: {result}")



    return doc

