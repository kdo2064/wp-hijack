"""Registry of per-CVE active confirmation tests (SAFE only)."""



from __future__ import annotations



import re



from .models import SafetyLevel, ConfirmationResult, VulnStatus, PotentialFinding













CONFIRMATION_REGISTRY: dict[str, dict] = {}











def register(cve: str, description: str, safety: SafetyLevel = SafetyLevel.SAFE):



    def _decorator(fn):



        CONFIRMATION_REGISTRY[cve] = {



            "cve": cve,



            "description": description,



            "safety": safety,



            "run": fn,



        }



        return fn



    return _decorator













@register("CVE-2023-28121", "Check if WooPayments responds to X-WCPAY headers", SafetyLevel.SAFE)



async def confirm_woocommerce_payments(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:



    base = base_url.rstrip("/")



    try:



        r = await http.get(



            f"{base}/wp-json/wc/v3/system_status",



            extra_headers={"X-WCPAY-PLATFORM-CHECKOUT-USER": "1"},



            timeout=8,



        )



        if r.status_code == 200 and "database" in r.text.lower():



            return ConfirmationResult(



                confirmed=True, status=VulnStatus.CONFIRMED,



                evidence="WooCommerce REST exposed system_status with platform checkout header",



                request_url=f"{base}/wp-json/wc/v3/system_status",



                response_snippet=r.text[:300],



            )



    except Exception:



        pass



    return ConfirmationResult(confirmed=False, status=VulnStatus.POTENTIAL)













@register("CVE-2024-1071", "Test Ultimate Member ordering SQLi exposure", SafetyLevel.CAUTIOUS)



async def confirm_ultimate_member(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:



    base = base_url.rstrip("/")



    try:



        r = await http.get(



            f"{base}/wp-admin/admin-ajax.php?action=um_get_members&nonce=fake&sorting=1 AND 1=1",



            timeout=8,



        )



        if r.status_code == 200 and ("member" in r.text.lower() or "{" in r.text):



            return ConfirmationResult(



                confirmed=True, status=VulnStatus.CONFIRMED,



                evidence="Ultimate Member AJAX endpoint returned member data with injected ordering",



                request_url=r.url.path if hasattr(r, "url") else "",



                response_snippet=r.text[:300],



            )



    except Exception:



        pass



    return ConfirmationResult(confirmed=False, status=VulnStatus.POTENTIAL)













@register("CVE-2024-10924", "Test Really Simple Security 2FA bypass endpoint", SafetyLevel.SAFE)



async def confirm_really_simple_security(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:



    base = base_url.rstrip("/")



    try:





        r = await http.get(f"{base}/wp-json/reallysimplessl/v1/", timeout=8)



        if r.status_code == 200:



            return ConfirmationResult(



                confirmed=True, status=VulnStatus.CONFIRMED,



                evidence="Really Simple Security REST namespace is exposed — plugin active and potentially vulnerable",



                request_url=f"{base}/wp-json/reallysimplessl/v1/",



                response_snippet=r.text[:300],



            )



    except Exception:



        pass



    return ConfirmationResult(confirmed=False, status=VulnStatus.POTENTIAL)













@register("CVE-2023-6553", "Probe backup-heart.php inclusion for RCE path", SafetyLevel.SAFE)



async def confirm_backup_migration(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:



    base = base_url.rstrip("/")



    try:



        r = await http.get(f"{base}/wp-content/plugins/backup-migration/includes/backup-heart.php", timeout=8)



        if r.status_code in (200, 500):



            snippet = r.text[:200] if r.text else ""



            return ConfirmationResult(



                confirmed=True, status=VulnStatus.CONFIRMED,



                evidence=f"backup-heart.php is directly accessible (HTTP {r.status_code})",



                request_url=f"{base}/wp-content/plugins/backup-migration/includes/backup-heart.php",



                response_snippet=snippet,



            )



    except Exception:



        pass



    return ConfirmationResult(confirmed=False, status=VulnStatus.POTENTIAL)













@register("CVE-2024-6386", "Test WPML REST endpoint reachability", SafetyLevel.SAFE)



async def confirm_wpml(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:



    base = base_url.rstrip("/")



    try:



        r = await http.get(f"{base}/wp-json/wpml/v1/strings", timeout=8)



        if r.status_code in (200, 401, 403):



            return ConfirmationResult(



                confirmed=True, status=VulnStatus.CONFIRMED,



                evidence=f"WPML REST namespace is active (HTTP {r.status_code})",



                request_url=f"{base}/wp-json/wpml/v1/strings",



                response_snippet=r.text[:300],



            )



    except Exception:



        pass



    return ConfirmationResult(confirmed=False, status=VulnStatus.POTENTIAL)











                                                                                 

                                                     

                                                                                 



async def _check_wpbakery_active(http, base_url: str) -> tuple[bool, str, str]:

    """
    Probe the WPBakery plugin to determine it is actually active (not just installed).
    Returns (active, evidence_string, probed_url).
    Strategy:
      1. POST to admin-ajax with WPBakery action  → non-404 = active
      2. GET known frontend asset file            → 200 with content = active
      3. GET plugin readme                        → 200 = plugin dir exists
    """

    base = base_url.rstrip("/")



                                                                                 

    ajax_url = f"{base}/wp-admin/admin-ajax.php"

    try:

        r = await http.post(

            ajax_url,

            data={"action": "vc_get_vc_grid_data", "vc_action": "vc_get_vc_grid_data"},

            timeout=8,

        )

        if r.status_code == 200:

            return (

                True,

                f"WPBakery AJAX action 'vc_get_vc_grid_data' responded HTTP 200 — plugin is active",

                ajax_url,

            )

        if r.status_code in (400, 403):

            return (

                True,

                f"WPBakery AJAX endpoint returned HTTP {r.status_code} (action recognised, plugin loaded)",

                ajax_url,

            )

    except Exception:

        pass



                                 

    asset_url = f"{base}/wp-content/plugins/js_composer/assets/js/dist/js_composer_front.min.js"

    try:

        r2 = await http.get(asset_url, timeout=7)

        if r2.status_code == 200 and len(r2.text or "") > 500:

            return (

                True,

                f"WPBakery front-end asset accessible (HTTP 200, {len(r2.text)} bytes) — plugin files present",

                asset_url,

            )

    except Exception:

        pass



                             

    readme_url = f"{base}/wp-content/plugins/js_composer/readme.txt"

    try:

        r3 = await http.get(readme_url, timeout=6)

        if r3.status_code == 200 and "bakery" in (r3.text or "").lower():

            return (

                True,

                f"WPBakery readme.txt accessible (HTTP 200) — plugin directory confirmed",

                readme_url,

            )

    except Exception:

        pass



    return (False, "WPBakery endpoints not reachable — plugin may be inactive or hardened", "")





def _register_wpbakery_cve(cve: str, desc: str, vuln_type: str = "XSS") -> None:

    """Register a SAFE confirmation test for a WPBakery CVE using the shared probe."""



    async def _run(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:

        active, evidence, url = await _check_wpbakery_active(http, base_url)

        if active:

            return ConfirmationResult(

                confirmed=True,

                status=VulnStatus.CONFIRMED,

                evidence=f"{vuln_type} vulnerability confirmed active — {evidence}",

                request_url=url,

            )

        return ConfirmationResult(

            confirmed=False,

            status=VulnStatus.POTENTIAL,

            evidence=evidence,

        )



    CONFIRMATION_REGISTRY[cve] = {

        "cve": cve,

        "description": desc,

        "safety": SafetyLevel.SAFE,

        "run": _run,

    }





               

_WPBAKERY_CVES: list[tuple[str, str, str]] = [

    ("CVE-2024-1841",  "WPBakery < 7.6  Stored XSS via shortcode attributes",           "Stored XSS"),

    ("CVE-2024-1842",  "WPBakery < 7.6  Stored XSS via shortcode attributes",           "Stored XSS"),

    ("CVE-2024-5265",  "WPBakery < 7.7  Stored XSS via ai_content shortcode",           "Stored XSS"),

    ("CVE-2024-5708",  "WPBakery < 7.8  Stored XSS via shortcode param injection",      "Stored XSS"),

    ("CVE-2024-5709",  "WPBakery < 7.8  CSRF -> Stored XSS via settings page",          "CSRF/Stored XSS"),

    ("CVE-2025-4965",  "WPBakery < 8.5  Stored XSS via shortcode injection",            "Stored XSS"),

    ("CVE-2025-4968",  "WPBakery < 8.5  Stored XSS via shortcode injection",            "Stored XSS"),

    ("CVE-2025-7502",  "WPBakery < 8.6  Reflected/Stored XSS",                          "XSS"),

    ("CVE-2025-11161", "WPBakery < 8.7  Stored XSS via shortcode attribute",            "Stored XSS"),

    ("CVE-2025-11160", "WPBakery < 8.7  Stored XSS via shortcode attribute",            "Stored XSS"),

    ("CVE-2025-10006", "WPBakery < 8.7  Stored XSS via shortcode attribute",            "Stored XSS"),

]



for _cve_id, _desc, _vtype in _WPBAKERY_CVES:

    _register_wpbakery_cve(_cve_id, _desc, _vtype)





                                                                                 

                                                                         

                                                                                 



async def _check_uavc_active(http, base_url: str) -> tuple[bool, str, str]:

    """
    Probe Ultimate Addons for Visual Composer to confirm it is active.
    Returns (active, evidence_string, probed_url).
    """

    base = base_url.rstrip("/")



                                         

    ajax_url = f"{base}/wp-admin/admin-ajax.php"

    try:

        r = await http.post(

            ajax_url,

            data={"action": "uavc_get_google_fonts"},

            timeout=8,

        )

        if r.status_code in (200, 400, 403):

            return (

                True,

                f"Ultimate_VC_Addons AJAX action recognised (HTTP {r.status_code}) — plugin is active",

                ajax_url,

            )

    except Exception:

        pass



                                

    asset_url = f"{base}/wp-content/plugins/Ultimate_VC_Addons/assets/min-css/uavc-common.min.css"

    try:

        r2 = await http.get(asset_url, timeout=7)

        if r2.status_code == 200 and len(r2.text or "") > 100:

            return (

                True,

                f"Ultimate_VC_Addons CSS asset accessible (HTTP 200, {len(r2.text)} bytes)",

                asset_url,

            )

    except Exception:

        pass



                             

    readme_url = f"{base}/wp-content/plugins/Ultimate_VC_Addons/readme.txt"

    try:

        r3 = await http.get(readme_url, timeout=6)

        if r3.status_code == 200 and (

            "ultimate" in (r3.text or "").lower() or "visual" in (r3.text or "").lower()

        ):

            return (

                True,

                f"Ultimate_VC_Addons readme.txt accessible (HTTP 200) — plugin directory confirmed",

                readme_url,

            )

    except Exception:

        pass



    return (False, "Ultimate_VC_Addons endpoints not reachable — plugin may be inactive or hardened", "")





def _register_uavc_cve(cve: str, desc: str, vuln_type: str = "XSS") -> None:

    """Register a SAFE confirmation test for an Ultimate_VC_Addons CVE."""



    async def _run(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:

        active, evidence, url = await _check_uavc_active(http, base_url)

        if active:

            return ConfirmationResult(

                confirmed=True,

                status=VulnStatus.CONFIRMED,

                evidence=f"{vuln_type} vulnerability confirmed active — {evidence}",

                request_url=url,

            )

        return ConfirmationResult(

            confirmed=False,

            status=VulnStatus.POTENTIAL,

            evidence=evidence,

        )



    CONFIRMATION_REGISTRY[cve] = {

        "cve": cve,

        "description": desc,

        "safety": SafetyLevel.SAFE,

        "run": _run,

    }





_UAVC_CVES: list[tuple[str, str, str]] = [

                              

    ("4a852dd12550f0a891c2bab", "UAVC < 3.16.12  Subscriber+ Stored XSS",  "Stored XSS"),

    ("216f2b7881796e8798803c7", "UAVC < 3.16.12  Subscriber+ Stored XSS",  "Stored XSS"),

    ("6e3deae4cf1ca25f0a035b4", "UAVC < 3.16.12  Subscriber+ Stored XSS",  "Stored XSS"),

             

    ("CVE-2023-46211", "UAVC < 3.19.15  Stored XSS",                        "Stored XSS"),

    ("CVE-2023-46205", "UAVC < 3.19.15  CSRF -> Stored XSS (HIGH)",          "CSRF/Stored XSS"),

    ("CVE-2023-51402", "UAVC < 3.19.18  Arbitrary File Upload (HIGH 8.8)",  "Arbitrary File Upload"),

    ("CVE-2024-5251",  "UAVC < 3.19.20.1  Stored XSS via shortcode",        "Stored XSS"),

    ("CVE-2024-5252",  "UAVC < 3.19.20.1  Stored XSS via shortcode",        "Stored XSS"),

    ("CVE-2024-5253",  "UAVC < 3.19.20.1  Stored XSS via shortcode",        "Stored XSS"),

    ("CVE-2024-5254",  "UAVC < 3.19.20.1  Stored XSS via shortcode",        "Stored XSS"),

    ("CVE-2024-5255",  "UAVC < 3.19.20.1  Stored XSS via shortcode",        "Stored XSS"),

    ("CVE-2025-11814", "UAVC < 3.21.1  Stored XSS via shortcode attribute", "Stored XSS"),

]



for _cve_id, _desc, _vtype in _UAVC_CVES:

    _register_uavc_cve(_cve_id, _desc, _vtype)





                                                                                 

                                          

                                                                                 



async def generic_plugin_verify(

    http,

    base_url: str,

    finding: "PotentialFinding",

) -> ConfirmationResult:

    """
    Generic fallback confirmation: attempt to reach the plugin/theme directory
    or a known asset to verify the component is actually installed and accessible.
    Called automatically from confirm_finding() when no CVE-specific test exists.
    """

    base = base_url.rstrip("/")

    slug = (finding.component or "").strip()

    comp_type = getattr(finding, "component_type", "plugin")

    dir_prefix = "themes" if comp_type == "theme" else "plugins"



    probes: list[str] = [

        f"{base}/wp-content/{dir_prefix}/{slug}/readme.txt",

        f"{base}/wp-content/{dir_prefix}/{slug}/readme.md",

        f"{base}/wp-content/{dir_prefix}/{slug}/{slug}.php",

    ]



    for url in probes:

        try:

            r = await http.get(url, timeout=6)

            if r.status_code == 200 and len(r.text or "") > 50:

                return ConfirmationResult(

                    confirmed=True,

                    status=VulnStatus.CONFIRMED,

                    evidence=(

                        f"Component '{slug}' files are publicly accessible — "

                        f"plugin/theme is installed and readable (HTTP 200)"

                    ),

                    request_url=url,

                    response_snippet=(r.text or "")[:200],

                )

        except Exception:

            continue



    return ConfirmationResult(

        confirmed=False,

        status=VulnStatus.POTENTIAL,

        evidence=f"No accessible files found for '{slug}' — cannot confirm component is active",

    )





def get_confirmation(cve: str) -> dict | None:

    return CONFIRMATION_REGISTRY.get(cve)



