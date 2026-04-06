"""Central design system — all colors, theme, and global console for wp-Hijack."""



from rich.theme import Theme



from rich.console import Console









SEVERITY_COLORS: dict[str, str] = {



    "CRITICAL": "#E74C3C",



    "HIGH":     "#E67E22",



    "MEDIUM":   "#F39C12",



    "LOW":      "#2ECC71",



    "INFO":     "#3498DB",



}







SEVERITY_BADGES: dict[str, tuple[str, str]] = {



    "CRITICAL": ("🔴 CRITICAL", "#E74C3C"),



    "HIGH":     ("🟠 HIGH",     "#E67E22"),



    "MEDIUM":   ("🟡 MEDIUM",   "#F39C12"),



    "LOW":      ("🟢 LOW",      "#2ECC71"),



    "INFO":     ("🔵 INFO",     "#3498DB"),



}









BRAND_GREEN  = "#00FF41"



ACCENT_BLUE  = "#00D4FF"



BRAND_ORANGE = "#FF6B35"







BANNER_GRADIENT = [



    "#FF2222",



    "#FF4500",



    "#FF6B35",



    "#FF8C00",



    "#FFB300",



    "#FFD700",



]









WPHIJACK_THEME = Theme({





    "vuln.critical": "bold #E74C3C",



    "vuln.high":     "bold #E67E22",



    "vuln.medium":   "bold #F39C12",



    "vuln.low":      "bold #2ECC71",



    "vuln.info":     "#3498DB",



    "vuln.clean":    "dim #2ECC71",





    "finding.title":  "bold #FF6B35 underline",



    "finding.cve":    "cyan",



    "finding.cvss":   "bold white",



    "finding.plugin": "bold white",



    "finding.desc":   "white",



    "finding.remed":  "#2ECC71",





    "scan.header":    "bold #00FF41",



    "scan.target":    "bold #00D4FF",



    "scan.label":     "dim white",



    "scan.value":     "white",



    "scan.phase":     "bold #00D4FF",



    "scan.done":      "bold #00FF41",



    "scan.error":     "bold #E74C3C",



    "scan.warn":      "bold #FFD700",





    "brand":          "bold #00FF41",



    "accent":         "bold #00D4FF",



    "dim.text":       "dim #555555",





    "stage.detect":   "bold #3498DB",



    "stage.confirm":  "bold #F39C12",



    "stage.exploit":  "bold #E74C3C",



    "status.confirmed": "bold #00FF41",



    "status.patched":   "dim #2ECC71",



    "status.potential": "bold #F39C12",



})









console = Console(theme=WPHIJACK_THEME)
