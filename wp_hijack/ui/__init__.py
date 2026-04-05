# wp_hijack/ui/__init__.py
from .banner import print_banner
from .theme import console, SEVERITY_COLORS, SEVERITY_BADGES, BRAND_GREEN, ACCENT_BLUE, BRAND_ORANGE
from .display import scan_header_panel, findings_table, scan_summary_panel, finding_card
from .progress import ScanProgress
from .status import PhaseSpinner

__all__ = [
    "print_banner",
    "console",
    "SEVERITY_COLORS",
    "SEVERITY_BADGES",
    "BRAND_GREEN",
    "ACCENT_BLUE",
    "BRAND_ORANGE",
    "scan_header_panel",
    "findings_table",
    "scan_summary_panel",
    "finding_card",
    "ScanProgress",
    "PhaseSpinner",
]
