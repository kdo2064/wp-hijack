"""wp-Hijack ASCII banner with fire gradient and developer credit."""



from __future__ import annotations



from rich.text import Text



from rich.align import Align



from rich.panel import Panel



from rich.rule import Rule



from .theme import console, BRAND_GREEN, ACCENT_BLUE, BRAND_ORANGE









_BANNER_LINES = [



    r" ██╗    ██╗██████╗       ██╗  ██╗██╗     ██╗ █████╗  ██████╗██╗  ██╗",



    r" ██║    ██║██╔══██╗      ██║  ██║██║     ██║██╔══██╗██╔════╝██║ ██╔╝",



    r" ██║ █╗ ██║██████╔╝█████╗███████║██║     ██║███████║██║     █████╔╝ ",



    r" ██║███╗██║██╔═══╝ ╚════╝██╔══██║██║██   ██║██╔══██║██║     ██╔═██╗ ",



    r" ╚███╔███╔╝██║           ██║  ██║██║╚█████╔╝██║  ██║╚██████╗██║  ██╗",



    r"  ╚══╝╚══╝ ╚═╝           ╚═╝  ╚═╝╚═╝ ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝",



]









_GRADIENT_COLORS = [



    "#FF2020",



    "#FF4500",



    "#FF6B35",



    "#FF8C00",



    "#FFB300",



    "#FFD700",



]











def _gradient_banner() -> Text:



    """Build the ASCII banner with a per-row fire gradient."""



    result = Text()



    for idx, line in enumerate(_BANNER_LINES):



        color = _GRADIENT_COLORS[min(idx, len(_GRADIENT_COLORS) - 1)]



        result.append(line + "\n", style=f"bold {color}")



    return result











def print_banner(version: str = "1.0.0") -> None:



    """Print the full wp-Hijack startup banner."""



    console.print()





    console.print(Align.center(_gradient_banner()))









    sub = Text(justify="center")



    sub.append("    ◈ ", style="dim #555555")



    sub.append("WordPress Vulnerability Scanner & Exploitation Framework", style=f"bold {ACCENT_BLUE}")



    sub.append(" ◈\n", style="dim #555555")



    sub.append("    Developer: ", style="dim white")



    sub.append("KDO || Xpert Exploit", style=f"bold {BRAND_ORANGE}")



    sub.append("  |  ", style="dim #555555")



    sub.append("github.com/kdo2064/wp-Hijack", style=f"italic {ACCENT_BLUE}")



    sub.append(f"  |  ", style="dim #555555")



    sub.append(f"v{version}", style=f"bold {BRAND_GREEN}")



    sub.append("\n")



    console.print(Align.center(sub))



    console.print(Align.center(Rule(style=f"dim {BRAND_GREEN}")))



    console.print()



