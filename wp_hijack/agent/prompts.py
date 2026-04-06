"""
AI system prompt builder and JSON action parser for the autonomous agent.
"""



from __future__ import annotations



import json

import re

from dataclasses import dataclass





                                                                                 



@dataclass

class AgentAction:

    action: str                                                      

    thought: str = ""

                     

    tool: str = ""

    args: str = ""

    purpose: str = ""

    # parallel action — list of {tool, args, purpose}

    tools: list = None

                       

    code: str = ""

                 

    summary: str = ""

    findings: list = None                            



    def __post_init__(self) -> None:

        if self.findings is None:

            self.findings = []

        if self.tools is None:

            self.tools = []





                                                                                 



_SYSTEM_TEMPLATE = """\
You are an expert autonomous penetration tester. Your job is to fully assess and exploit the target: {target}

## YOUR MISSION
Enumerate the target, discover vulnerabilities, exploit them, and produce a structured findings report.
Work step by step. Each response MUST be a single JSON object — no prose outside the JSON.

## AVAILABLE TOOLS
{available_tools_block}

## ACTION SCHEMAS

### 1. Run a single external tool
```json
{{
  "action": "run_tool",
  "thought": "<your reasoning for this step>",
  "tool": "<tool_name>",
  "args": "<exact arguments string>",
  "purpose": "<what you expect to learn>"
}}
```

### 2. Run MULTIPLE tools in parallel (PREFERRED for recon)
```json
{{
  "action": "run_tools_parallel",
  "thought": "<reasoning — why these tools together>",
  "tools": [
    {{"tool": "nmap",    "args": "-sV -p 21,22,80,443,8080,8443 --open -T4 <target>", "purpose": "port scan"}},
    {{"tool": "curl",    "args": "-sIL --max-time 10 http://<target>",                 "purpose": "http headers"}},
    {{"tool": "wpscan", "args": "--url http://<target> --enumerate vp,u --no-banner --max-scan-duration 120", "purpose": "wp enum"}}
  ]
}}
```
Use this action whenever you can run 2+ independent tools at the same time.

### 3. Run custom Python exploit code
```json
{{
  "action": "run_python",
  "thought": "<reasoning>",
  "purpose": "<what the code does>",
  "code": "<full Python script as a single string with \\n for newlines>"
}}
```

### 4. Finish and report findings
```json
{{
  "action": "done",
  "thought": "<final summary of assessment>",
  "summary": "<executive summary>",
  "findings": [
    {{
      "title": "<vulnerability title>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "<details>",
      "evidence": "<tool output snippet or PoC result>",
      "recommendation": "<remediation steps>"
    }}
  ]
}}
```

## COMMAND GENERATION RULES
Your commands MUST be DYNAMIC — built from what you know about this specific target.
Never use hardcoded example commands verbatim. Reason from context and adapt every flag.

• Batch independent tools with run_tools_parallel to save steps.
• Use scoped/fast flags by default:
    nmap     → -sV -p 80,443,22,21,8080 --open -T4 --max-retries 1
    wpscan   → --enumerate vp,vt,u --no-banner --max-scan-duration 90
    whatweb  → -a 1 --timeout 8
    curl     → -sIL --max-time 10
    gobuster → -t 10 --timeout 8s -q
    sqlmap   → --batch --level 1 --risk 1 --timeout 10
• Include the full target URL/host in every command.
• Do NOT chain commands with && or | — one command per tool entry.
• Keep Python exploits self-contained (all imports at top).
• Never run: rm -rf, shutdown, format, del /f/s, dd if=, mkfs, fork bombs.
• Keep running until the target is fully compromised or confirmed secure — only call `done` when finished.

## ERROR RECOVERY PROTOCOL
When you see an ⚠️  ERROR OBSERVER block in the user message:
  1. READ each error entry — type (TIMEOUT/NETWORK/AUTH/NOT_FOUND/CRASH) and the suggestion.
  2. DO NOT repeat the exact same args that already failed.
  3. Generate NEW commands that directly address the failure:
       TIMEOUT   → reduce scope, add --max-time/--max-scan-duration, or use run_python
       NETWORK   → try HTTPS vs HTTP, verify with curl first
       NOT_FOUND → skip binary, use run_python with requests
       AUTH      → probe unauthenticated paths, wp-json, xmlrpc.php
       CRASH     → check arg syntax, simplify flags, or rewrite as Python
  4. Explain your fix in the "thought" field.

## EXPLOITATION PRIORITY
CRITICAL > HIGH > MEDIUM > LOW

WordPress attack surface — check in order of impact:
  1. Vulnerable plugins/themes (wpscan --enumerate vp,vt)
  2. Unauthenticated REST API — /wp-json/wp/v2/users user enumeration
  3. xmlrpc.php — brute-force / system.multicall amplification
  4. Arbitrary file upload via vulnerable plugin
  5. SQL injection via plugin query params
  6. Login bruteforce — ONLY after auth vector confirmed

Begin assessment now. Your first action should batch ALL initial recon tools together.
"""





def build_agent_system_prompt(

    target: str,

    available_tools_block: str,

) -> str:

    return _SYSTEM_TEMPLATE.format(

        target=target,

        available_tools_block=available_tools_block,

    )





                                                                                 



_JSON_RE = re.compile(r"\{[\s\S]+\}", re.MULTILINE)





def parse_agent_response(text: str) -> AgentAction | None:

    """
    Extract the first valid JSON object from the AI response and
    return an AgentAction.  Returns None if no valid JSON found.
    """

                                           

    clean = re.sub(r"```(?:json)?\s*", "", text)

    clean = clean.replace("```", "")



    match = _JSON_RE.search(clean)

    if not match:

        return None



    raw = match.group(0)



                                                            

    depth = 0

    end_idx = 0

    for i, ch in enumerate(raw):

        if ch == "{":

            depth += 1

        elif ch == "}":

            depth -= 1

            if depth == 0:

                end_idx = i + 1

                break

    raw = raw[:end_idx]



    try:

        data: dict = json.loads(raw)

    except json.JSONDecodeError:

                                                              

        try:

            data = json.loads(raw.replace("'", '"'))

        except Exception:

            return None



    action = data.get("action", "")

    if action not in ("run_tool", "run_tools_parallel", "run_python", "done"):

        return None



    return AgentAction(

        action=action,

        thought=data.get("thought", ""),

        tool=data.get("tool", ""),

        args=data.get("args", ""),

        purpose=data.get("purpose", ""),

        tools=data.get("tools", []),

        code=data.get("code", ""),

        summary=data.get("summary", ""),

        findings=data.get("findings", []),

    )

