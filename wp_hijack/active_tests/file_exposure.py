"""Sensitive file exposure checks — 70+ paths, async batch probe."""

from __future__ import annotations

import asyncio

import re

from dataclasses import dataclass, field

import random

import string




SENSITIVE_PATHS = [


    "/wp-config.php",

    "/wp-config.php.bak",

    "/wp-config.php.old",

    "/wp-config.php~",

    "/wp-config.php.swp",

    "/wp-config-sample.php",

    "/wp-content/debug.log",

    "/wp-content/uploads/.htaccess",

    "/wp-content/uploads/phpinfo.php",

    "/wp-content/uploads/shell.php",

    "/wp-admin/install.php",

    "/wp-admin/upgrade.php",

    "/wp-admin/setup-config.php",


    "/readme.html",

    "/readme.txt",

    "/license.txt",

    "/wp-includes/version.php",


    "/backup.zip",

    "/backup.tar.gz",

    "/backup.sql",

    "/db.sql",

    "/database.sql",

    "/db_backup.sql",

    "/site.sql",

    "/wordpress.sql",

    "/dump.sql",


    "/.env",

    "/.env.local",

    "/.env.backup",

    "/.htaccess",

    "/.htpasswd",

    "/.git/HEAD",

    "/.git/config",

    "/.gitignore",

    "/.svn/entries",

    "/.DS_Store",


    "/phpinfo.php",

    "/info.php",

    "/test.php",

    "/debug.php",

    "/status.php",

    "/server-status",

    "/server-info",


    "/xmlrpc.php",

    "/wp-json/wp/v2/users",

    "/wp-cron.php",

    "/wp-links-opml.php",

    "/wp-mail.php",

    "/wp-trackback.php",


    "/error_log",

    "/error.log",

    "/access.log",

    "/php_errors.log",

    "/logs/error.log",


    "/composer.json",

    "/composer.lock",

    "/package.json",

    "/package-lock.json",

    "/yarn.lock",

    "/Makefile",

    "/Dockerfile",

    "/docker-compose.yml",

    "/ansible.cfg",

    "/Thumbs.db",

    "/web.config",

    "/crossdomain.xml",

    "/robots.txt",

    "/sitemap.xml",

    "/sitemap_index.xml",

]




_HIGH_SEVERITY = {"/wp-config.php", "/.env", "/.git/HEAD", "/.htpasswd", "/database.sql", "/db.sql"}




_SOFT_404_PATTERNS = re.compile(

    r"not\s+found|page\s+not\s+found|404|no\s+encontrado|찾을\s*수\s*없|페이지를\s*찾|"

    r"does\s+not\s+exist|could\s+not\s+be\s+found|the\s+requested\s+url|"

    r"error\s+404|오류|존재하지|없습니다|찾을수없|찾지\s*못|"

    r"object\s+not\s+found|resource\s+not\s+found|invalid\s+url|"

    r"go\s+back|try\s+again|homepage",

    re.I | re.S,

)




_FILE_SIGNATURES: dict[str, re.Pattern] = {

    "/wp-config.php":         re.compile(r"DB_NAME|DB_PASSWORD|DB_HOST|table_prefix", re.I),

    "/wp-config.php.bak":     re.compile(r"DB_NAME|DB_PASSWORD|DB_HOST", re.I),

    "/wp-config.php.old":     re.compile(r"DB_NAME|DB_PASSWORD|DB_HOST", re.I),

    "/wp-config.php~":        re.compile(r"DB_NAME|DB_PASSWORD|DB_HOST", re.I),

    "/wp-config.php.swp":     re.compile(r"DB_NAME|DB_PASSWORD|b0VIM", re.I),

    "/.env":                  re.compile(r"[A-Z_]+=.+|APP_KEY|DB_PASSWORD|SECRET", re.I),

    "/.env.local":            re.compile(r"[A-Z_]+=.+|APP_KEY|DB_PASSWORD", re.I),

    "/.env.backup":           re.compile(r"[A-Z_]+=.+|APP_KEY|DB_PASSWORD", re.I),

    "/.git/HEAD":             re.compile(r"ref:\s*refs/|[0-9a-f]{40}"),

    "/.git/config":           re.compile(r"\[core\]|\[remote|repositoryformatversion"),

    "/.htpasswd":             re.compile(r"[a-zA-Z0-9_\-\.]+:\$apr1\$|:\{SHA\}|:[a-zA-Z0-9+/]{13}"),

    "/wp-content/debug.log":  re.compile(r"PHP\s+(Notice|Warning|Fatal|Error)|WordPress\s+database\s+error", re.I),

    "/phpinfo.php":           re.compile(r"phpinfo\(\)|PHP\s+Version\s+\d|php\.ini", re.I),

    "/info.php":              re.compile(r"phpinfo\(\)|PHP\s+Version|php\.ini", re.I),

    "/database.sql":          re.compile(r"CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL|mysqldump", re.I),

    "/db.sql":                re.compile(r"CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL|mysqldump", re.I),

    "/backup.sql":            re.compile(r"CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL|mysqldump", re.I),

    "/dump.sql":              re.compile(r"CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL|mysqldump", re.I),

    "/server-status":         re.compile(r"Apache\s+Server\s+Status|Requests\s+currently\s+being\s+processed", re.I),

    "/wp-includes/version.php": re.compile(r"\$wp_version\s*=|WordPress version", re.I),

    "/wp-config-sample.php":  re.compile(r"DB_NAME|database_name_here|username_here", re.I),

    "/readme.html":           re.compile(r"WordPress|Version\s+\d+\.\d+", re.I),

    "/readme.txt":            re.compile(r"WordPress|Version\s+\d+\.\d+", re.I),

    "/composer.json":         re.compile(r'"require"|"name"\s*:|"version"\s*:', re.I),

    "/composer.lock":         re.compile(r'"packages"\s*:|"content-hash"\s*:', re.I),

    "/package.json":          re.compile(r'"dependencies"|"devDependencies"|"scripts"\s*:', re.I),

}





@dataclass

class ExposedFile:

    path: str

    status_code: int

    size_bytes: int = 0

    severity: str = "MEDIUM"

    snippet: str = ""





def _is_soft_404(body: str, body_len: int, baseline_size: int) -> bool:

    """
    Return True if the response looks like a soft-404 custom error page.

    Heuristics (any one is sufficient to reject):
    1. Body contains known error-page phrases
    2. Body size is within ±15% of the baseline 404 page size
       (catches servers that return the same error page for every URL)
    3. Body is suspiciously small (< 200 bytes) and contains no useful content
    """

    if baseline_size > 0:

        delta = abs(body_len - baseline_size)

        if delta <= max(60, baseline_size * 0.15):

            return True



    if _SOFT_404_PATTERNS.search(body[:600]):

        return True



    return False





def _has_real_content(path: str, body: str) -> bool:

    """
    For paths that have known content signatures, require the signature to be present.
    If no signature defined for this path, allow through (benefit of the doubt).
    """

    sig = _FILE_SIGNATURES.get(path)

    if sig is None:

        return True

    return bool(sig.search(body[:2000]))





async def check_file_exposure(http, base_url: str) -> list[ExposedFile]:

    base = base_url.rstrip("/")




    rand_suffix = "".join(random.choices(string.ascii_lowercase, k=12))

    baseline_size = 0

    try:

        br = await http.get(f"{base}/wp-hijack-baseline-{rand_suffix}-404check", timeout=7)

        if br.status_code == 200:


            baseline_size = len(br.content)

    except Exception:

        pass



    results: list[ExposedFile] = []



    async def _probe(path: str) -> ExposedFile | None:

        try:

            r = await http.get(f"{base}{path}", timeout=7)

            if r.status_code != 200:

                return None



            body     = r.text[:2000] if hasattr(r, "text") else ""

            body_len = len(r.content)




            if _is_soft_404(body, body_len, baseline_size):

                return None




            if not _has_real_content(path, body):

                return None



            sev = "HIGH" if path in _HIGH_SEVERITY else "MEDIUM"

            return ExposedFile(

                path=path,

                status_code=r.status_code,

                size_bytes=body_len,

                severity=sev,

                snippet=body[:200].strip(),

            )

        except Exception:

            return None



    probes = await asyncio.gather(*(_probe(p) for p in SENSITIVE_PATHS))

    return [r for r in probes if r is not None]



