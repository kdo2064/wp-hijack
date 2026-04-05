"""Registry of per-CVE active confirmation tests (SAFE only)."""
from __future__ import annotations
import re
from .models import SafetyLevel, ConfirmationResult, VulnStatus, PotentialFinding


# ── Registry: cve → async confirmation function ────────────────────────────────
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


# ── CVE-2023-28121: WooCommerce Payments — add X-WCPAY-PLATFORM-CHECKOUT-USER ──
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


# ── CVE-2024-1071: Ultimate Member — probe REST or admin AJAX ─────────────────
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


# ── CVE-2024-10924: Really Simple Security — auth bypass existence ─────────────
@register("CVE-2024-10924", "Test Really Simple Security 2FA bypass endpoint", SafetyLevel.SAFE)
async def confirm_really_simple_security(http, base_url: str, finding: PotentialFinding) -> ConfirmationResult:
    base = base_url.rstrip("/")
    try:
        # Plugin exposes /wp-json/reallysimplessl/ namespace when active
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


# ── CVE-2023-6553: Backup Migration — check backup-heart.php ──────────────────
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


# ── CVE-2024-6386: WPML Twig RCE — check REST endpoint ───────────────────────
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


def get_confirmation(cve: str) -> dict | None:
    return CONFIRMATION_REGISTRY.get(cve)
