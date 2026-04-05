from .db      import init_db, load_bundled, query_by_component, query_by_cve, get_all
from .matcher import is_version_affected
from .updater import update_vulndb
from .wpvulnerability_api import (
    fetch_core_vulns,
    fetch_plugin_vulns,
    fetch_theme_vulns,
    fetch_bulk,
)

__all__ = [
    "init_db", "load_bundled", "query_by_component", "query_by_cve", "get_all",
    "is_version_affected",
    "update_vulndb",
    "fetch_core_vulns",
    "fetch_plugin_vulns",
    "fetch_theme_vulns",
    "fetch_bulk",
]
