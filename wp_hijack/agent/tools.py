"""
Tool registry — metadata for every external pentesting tool the agent can use.

The AI reads this registry to decide which tool to call and how to form
valid arguments.  check_available() tells the agent which tools are
actually installed on the current system so it never tries to call a
missing binary.
"""



from __future__ import annotations



import shutil

from typing import TypedDict





class ToolMeta(TypedDict):

    description: str

    usage: str

    example: str

    platform_hint: str                             





                                                                                

TOOL_REGISTRY: dict[str, ToolMeta] = {

    "nmap": {

        "description": (

            "Network port scanner. Discovers open ports, running services, "

            "service versions, and OS info. Essential first recon step."

        ),

        "usage": "nmap [options] <target>",

        "example": "nmap -sV -sC -p 1-1000 --open target.com",

        "platform_hint": "",

    },

    "whatweb": {

        "description": (

            "Web technology fingerprinter. Detects CMS, frameworks, server "

            "versions, plugins, and libraries from HTTP responses."

        ),

        "usage": "whatweb [options] <url>",

        "example": "whatweb -a 3 --log-brief=- http://target.com",

        "platform_hint": "",

    },

    "nikto": {

        "description": (

            "Web vulnerability scanner. Checks for dangerous files, "

            "outdated server software, and common web misconfigs."

        ),

        "usage": "nikto -h <url> [options]",

        "example": "nikto -h http://target.com -nointeractive -maxtime 120",

        "platform_hint": "",

    },

    "gobuster": {

        "description": (

            "Directory and file brute-forcer. Finds hidden paths, backup "

            "files, admin panels, and upload endpoints."

        ),

        "usage": "gobuster dir -u <url> -w <wordlist> [options]",

        "example": (

            "gobuster dir -u http://target.com "

            "-w /usr/share/wordlists/dirb/common.txt "

            "-x php,txt,bak,zip --no-progress -q"

        ),

        "platform_hint": "",

    },

    "ffuf": {

        "description": (

            "Fast web fuzzer. Fuzz URLs, headers, POST bodies. "

            "Great for finding hidden endpoints and parameter injection points."

        ),

        "usage": "ffuf -u <url/FUZZ> -w <wordlist> [options]",

        "example": (

            "ffuf -u http://target.com/FUZZ "

            "-w /usr/share/wordlists/dirb/common.txt "

            "-mc 200,301,302,403 -s"

        ),

        "platform_hint": "",

    },

    "wpscan": {

        "description": (

            "WordPress-specific vulnerability scanner. Enumerates plugins, "

            "themes, users, and checks for known CVEs via WPVulnDB."

        ),

        "usage": "wpscan --url <url> [options]",

        "example": (

            "wpscan --url http://target.com "

            "--enumerate p,t,u --plugins-detection aggressive "

            "--no-banner 2>&1"

        ),

        "platform_hint": "",

    },

    "curl": {

        "description": (

            "HTTP client. Send custom requests, test endpoints, upload files, "

            "exploit SSRF/LFI, test auth bypasses. Use -s for silent, "

            "-L to follow redirects, -k to skip TLS."

        ),

        "usage": "curl [options] <url>",

        "example": (

            "curl -sk -X POST http://target.com/wp-admin/admin-ajax.php "

            "-d 'action=test' -H 'Content-Type: application/x-www-form-urlencoded'"

        ),

        "platform_hint": "",

    },

    "sqlmap": {

        "description": (

            "Automated SQL injection detection and exploitation. "

            "Can dump databases, bypass WAFs, and test blind SQLi."

        ),

        "usage": "sqlmap -u <url> [options]",

        "example": (

            "sqlmap -u 'http://target.com/page?id=1' "

            "--batch --level=2 --risk=1 --dbs --no-logging"

        ),

        "platform_hint": "",

    },

    "hydra": {

        "description": (

            "Network login brute-forcer. Test HTTP forms, SSH, FTP for "

            "weak credentials using username/password lists."

        ),

        "usage": "hydra [options] <target> <service>",

        "example": (

            "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt "

            "target.com http-post-form "

            "'/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:ERROR'"

        ),

        "platform_hint": "",

    },

    "python": {

        "description": (

            "Run custom Python exploit/PoC code. Use for custom HTTP exploits, "

            "web shell upload, authentication bypass, data extraction, "

            "or anything the other tools cannot do. "

            "Use the run_python action instead of this tool entry."

        ),

        "usage": "Internal — use action=run_python",

        "example": "",

        "platform_hint": "",

    },

}





                                                                                 



def check_available(

    requested: list[str] | None = None,

) -> dict[str, bool]:

    """
    Return a dict of {tool_name: is_installed} for every tool in the registry
    (or for the subset named in *requested*).

    Uses shutil.which() — works on Windows and POSIX without needing to
    actually invoke the binary.
    """

    names = requested if requested else list(TOOL_REGISTRY.keys())

    result: dict[str, bool] = {}

    for name in names:

        if name == "python":

            result[name] = True                                               

            continue

                                                                     

        result[name] = shutil.which(name) is not None

    return result





def available_tools_block(requested: list[str] | None = None) -> str:

    """
    Build a human-readable (AI-readable) block listing every available tool
    with its description and usage.  Tools not found in PATH are listed as
    UNAVAILABLE so the AI skips them.
    """

    avail = check_available(requested)

    lines: list[str] = ["AVAILABLE PENTESTING TOOLS:"]

    for name, meta in TOOL_REGISTRY.items():

        if name == "python":

            lines.append(

                f"\n  [ALWAYS AVAILABLE] run_python\n"

                f"    Write and execute custom Python 3 exploit code.\n"

                f"    Use action=run_python with a 'code' field."

            )

            continue

        status = "✓ INSTALLED" if avail.get(name) else "✗ NOT FOUND — DO NOT USE"

        lines.append(

            f"\n  [{status}] {name}\n"

            f"    {meta['description']}\n"

            f"    Usage : {meta['usage']}\n"

            f"    Example: {meta['example']}"

        )

    return "\n".join(lines)

