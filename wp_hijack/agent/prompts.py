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

                       

    code: str = ""

                 

    summary: str = ""

    findings: list[dict] = None                            



    def __post_init__(self) -> None:

        if self.findings is None:

            self.findings = []





                                                                                 



_SYSTEM_TEMPLATE = """\
You are an expert autonomous penetration tester. Your job is to fully assess and exploit the target: {target}

## YOUR MISSION
Enumerate the target, discover vulnerabilities, exploit them, and produce a structured findings report.
Work step by step. Each response MUST be a single JSON object — no prose outside the JSON.

## AVAILABLE TOOLS
{available_tools_block}

## ACTION SCHEMAS

### 1. Run an external tool
```json
{{
  "action": "run_tool",
  "thought": "<your reasoning for this step>",
  "tool": "<tool_name>",
  "args": "<exact arguments string>",
  "purpose": "<what you expect to learn>"
}}
```

### 2. Run custom Python exploit code
```json
{{
  "action": "run_python",
  "thought": "<reasoning>",
  "purpose": "<what the code does>",
  "code": "<full Python script as a single string with \\n for newlines>"
}}
```

### 3. Finish and report findings
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

## RULES
1. Always start with nmap port scan, then whatweb, then wpscan (if WordPress detected).
2. After recon, run nikto for web vulns, then enumerate further based on results.
3. If wpscan finds vulnerable plugins/themes, generate Python exploit code to confirm.
4. If login page found, try hydra with common credentials only after getting confirmation.
5. NEVER run: rm -rf, shutdown, format, del /f/s, dd if=, mkfs, fork bombs.
6. Truncate tool args to one logical command — no chaining with && or | to shell.
7. Stop and report `done` if: all recon completed + exploits attempted + {max_steps} steps reached.
8. Be specific in args — always include the target URL/IP in every command.
9. If a tool returns an error or is missing, note it in thought and try another approach.
10. Keep Python exploit code self-contained with all imports included.

## EXPLOITATION PRIORITY
CRITICAL > HIGH > MEDIUM > LOW

Focus on WordPress-specific vectors first:
- Vulnerable plugins/themes (wpscan --enumerate vp,vt)
- Unauthenticated REST API exposure
- xmlrpc.php brute-force / amplification
- File inclusion / upload vulnerabilities
- SQL injection via vulnerable plugins
- Login bruteforce (only if explicitly vulnerable auth found)

Begin your assessment now. Start with nmap.
"""





def build_agent_system_prompt(

    target: str,

    available_tools_block: str,

    max_steps: int = 30,

) -> str:

    return _SYSTEM_TEMPLATE.format(

        target=target,

        available_tools_block=available_tools_block,

        max_steps=max_steps,

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

    if action not in ("run_tool", "run_python", "done"):

        return None



    return AgentAction(

        action=action,

        thought=data.get("thought", ""),

        tool=data.get("tool", ""),

        args=data.get("args", ""),

        purpose=data.get("purpose", ""),

        code=data.get("code", ""),

        summary=data.get("summary", ""),

        findings=data.get("findings", []),

    )

