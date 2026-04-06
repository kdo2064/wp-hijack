"""
AgentMemory — persistent fact tracker for the autonomous agent.

Collects structured discoveries from tool output across all steps
and injects a compact context block into every AI prompt so the AI
never forgets what it has already found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentMemory:
    """
    Mutable store of everything the agent has discovered so far.
    Updated after every tool result.  Serialised as a plain-text
    context block that is appended to each AI feedback message.
    """

    target: str = ""

    # Network
    open_ports:  list[str] = field(default_factory=list)   # ["80/tcp http nginx", ...]
    ip_address:  str       = ""

    # Web / WP
    cms:         str       = ""          # "WordPress 6.4.2"
    php_version: str       = ""
    server:      str       = ""          # "nginx 1.24"
    wp_plugins:  list[str] = field(default_factory=list)   # ["plugin-slug (v1.2 – VULNERABLE)"]
    wp_themes:   list[str] = field(default_factory=list)
    wp_users:    list[str] = field(default_factory=list)

    # Security
    waf:         str       = ""          # "Cloudflare" | "None detected"
    xmlrpc:      bool      = False
    rest_api:    bool      = False

    # Exploitation
    credentials: list[str] = field(default_factory=list)   # ["admin:password123"]
    exploited:   list[str] = field(default_factory=list)   # short descriptions
    shells:      list[str] = field(default_factory=list)   # shell paths / URLs
    sqli_params: list[str] = field(default_factory=list)   # "http://...?id=1 (column 3)"

    # Generic key facts (AI can add arbitrary short strings)
    notes: list[str] = field(default_factory=list)

    # ── parsers ───────────────────────────────────────────────────────────── #

    def update_from_tool(self, tool: str, output: str) -> None:
        """
        Extract key facts from raw tool output and merge them into memory.
        Called automatically after every tool runs.
        """
        if not output:
            return

        t = tool.lower()

        if t == "nmap":
            self._parse_nmap(output)
        elif t in ("curl", "whatweb"):
            self._parse_http_headers(output)
        elif t == "wpscan":
            self._parse_wpscan(output)
        elif t == "hydra":
            self._parse_hydra(output)
        elif t == "sqlmap":
            self._parse_sqlmap(output)

        # Generic patterns that apply to any tool output
        self._parse_generic(output)

    def _parse_nmap(self, out: str) -> None:
        # IP
        m = re.search(r"Nmap scan report for .+?\((\d+\.\d+\.\d+\.\d+)\)", out)
        if m:
            self.ip_address = m.group(1)

        # Ports:  "80/tcp  open  http   nginx"
        for line in out.splitlines():
            pm = re.match(r"(\d+/\w+)\s+open\s+(\S+)\s*(.*)", line)
            if pm:
                port_entry = f"{pm.group(1)} {pm.group(2)} {pm.group(3).strip()}".strip()
                if port_entry not in self.open_ports:
                    self.open_ports.append(port_entry)

        # PHP version banner
        pv = re.search(r"PHP[/ ]([\d.]+)", out, re.IGNORECASE)
        if pv and not self.php_version:
            self.php_version = pv.group(1)

    def _parse_http_headers(self, out: str) -> None:
        sv = re.search(r"(?i)^Server:\s*(.+)", out, re.MULTILINE)
        if sv and not self.server:
            self.server = sv.group(1).strip()

        pv = re.search(r"PHP[/ ]([\d.]+)", out, re.IGNORECASE)
        if pv and not self.php_version:
            self.php_version = pv.group(1)

        if re.search(r"wp-json|wp-content|wordpress", out, re.IGNORECASE) and not self.cms:
            self.cms = "WordPress"

        if re.search(r"xmlrpc\.php", out, re.IGNORECASE):
            self.xmlrpc = True

    def _parse_wpscan(self, out: str) -> None:
        # WP version
        wv = re.search(r"WordPress version ([\d.]+)", out, re.IGNORECASE)
        if wv:
            self.cms = f"WordPress {wv.group(1)}"

        # Plugins
        for m in re.finditer(
            r"\[.*?\]\s+([\w-]+)\n.*?Version: ([\d.]+)(.*?)(Vulnerability|VULNERABILITY|CVE)",
            out, re.IGNORECASE | re.DOTALL,
        ):
            entry = f"{m.group(1)} v{m.group(2)} [VULNERABLE]"
            if entry not in self.wp_plugins:
                self.wp_plugins.append(entry)

        # plain plugin names
        for m in re.finditer(r"Plugin: ([\w-]+)", out, re.IGNORECASE):
            entry = m.group(1)
            if not any(entry in p for p in self.wp_plugins):
                self.wp_plugins.append(entry)

        # Users
        for m in re.finditer(r"Username: (\S+)", out, re.IGNORECASE):
            u = m.group(1)
            if u not in self.wp_users:
                self.wp_users.append(u)

        # xmlrpc / rest
        if "xmlrpc.php" in out.lower():
            self.xmlrpc = True
        if "wp-json" in out.lower():
            self.rest_api = True

    def _parse_hydra(self, out: str) -> None:
        for m in re.finditer(
            r"login:\s*(\S+)\s+password:\s*(\S+)", out, re.IGNORECASE
        ):
            cred = f"{m.group(1)}:{m.group(2)}"
            if cred not in self.credentials:
                self.credentials.append(cred)

    def _parse_sqlmap(self, out: str) -> None:
        for m in re.finditer(
            r"Parameter '(\S+)' is vulnerable", out, re.IGNORECASE
        ):
            param = m.group(1)
            if param not in self.sqli_params:
                self.sqli_params.append(param)

    def _parse_generic(self, out: str) -> None:
        # Detect web shell uploads
        for m in re.finditer(
            r"(?:shell|webshell|cmd\.php|shell\.php)\s+(?:uploaded?|planted|accessible)\s+(?:at|to|via)?\s*(\S+)",
            out, re.IGNORECASE,
        ):
            s = m.group(1).strip()
            if s not in self.shells:
                self.shells.append(s)

    # ── memory injection API ──────────────────────────────────────────────── #

    def record_exploit(self, description: str) -> None:
        """Called by the agent when an exploit step succeeds."""
        if description not in self.exploited:
            self.exploited.append(description)

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    def to_context_block(self) -> str:
        """
        Compact text block appended to every AI feedback message.
        Keeps the AI oriented without ballooning the context.
        """
        lines = ["\n━━ SESSION MEMORY (do not repeat already-done work) ━━"]

        if self.ip_address:
            lines.append(f"  IP         : {self.ip_address}")
        if self.server:
            lines.append(f"  Server     : {self.server}")
        if self.php_version:
            lines.append(f"  PHP        : {self.php_version}")
        if self.cms:
            lines.append(f"  CMS        : {self.cms}")
        if self.waf:
            lines.append(f"  WAF        : {self.waf}")

        if self.open_ports:
            lines.append(f"  Open ports : {', '.join(self.open_ports[:10])}")
        if self.xmlrpc:
            lines.append("  xmlrpc.php : ACCESSIBLE")
        if self.rest_api:
            lines.append("  REST API   : ACCESSIBLE (/wp-json)")

        if self.wp_users:
            lines.append(f"  WP Users   : {', '.join(self.wp_users)}")
        if self.wp_plugins:
            lines.append("  WP Plugins :")
            for p in self.wp_plugins[:10]:
                lines.append(f"    • {p}")
        if self.wp_themes:
            lines.append(f"  WP Themes  : {', '.join(self.wp_themes[:5])}")

        if self.credentials:
            lines.append(f"  Creds found: {', '.join(self.credentials)}")
        if self.sqli_params:
            lines.append(f"  SQLi params: {', '.join(self.sqli_params)}")
        if self.shells:
            lines.append(f"  Shells     : {', '.join(self.shells)}")
        if self.exploited:
            lines.append("  Exploited  :")
            for e in self.exploited:
                lines.append(f"    ✓ {e}")
        if self.notes:
            lines.append("  Notes      :")
            for n in self.notes:
                lines.append(f"    • {n}")

        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":      self.target,
            "ip":          self.ip_address,
            "server":      self.server,
            "php":         self.php_version,
            "cms":         self.cms,
            "waf":         self.waf,
            "open_ports":  self.open_ports,
            "xmlrpc":      self.xmlrpc,
            "rest_api":    self.rest_api,
            "wp_users":    self.wp_users,
            "wp_plugins":  self.wp_plugins,
            "wp_themes":   self.wp_themes,
            "credentials": self.credentials,
            "sqli_params": self.sqli_params,
            "shells":      self.shells,
            "exploited":   self.exploited,
            "notes":       self.notes,
        }
