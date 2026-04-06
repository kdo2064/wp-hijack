"""
AgentPostChat — interactive session that auto-launches after `wp-hijack pwn`
finishes.  Lets the user ask questions, reverify findings, or run extra tools
against the target, with full session context injected into every AI message.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.text import Text

from ..ai.client import ask_stream       # async streaming generator
from .memory import AgentMemory
from .session import AgentSession
from .tool_runner import run_tool, ToolResult

console = Console()

_CHAT_SYSTEM = """\
You are an elite offensive-security expert reviewing the completed autonomous \
hack session described below.  You have access to every finding the agent made.

TARGET : {target}
SESSION: {step_count} steps executed

{memory_block}

## SESSION FINDINGS (last 40 steps)
{findings_block}

## YOUR ROLE
- Answer questions about findings, techniques, and exploitation paths
- Suggest follow-up attacks, privilege escalation routes, or persistence methods
- When the user asks to "reverify" a finding, produce a concrete shell command
- When the user asks to "run <tool> <args>", confirm the command and execute it
- Be direct, technical, and offense-focused

IMPORTANT: the session is OVER — do not re-run the full scan.  Focus on \
targeted follow-up actions based on what was already discovered.
"""


def _build_system_prompt(
    session: AgentSession,
    memory: AgentMemory,
) -> str:
    """Compile the static system prompt from session + memory data."""

    # Last 40 step summaries
    findings_lines: list[str] = []
    for st in session.steps[-40:]:
        tool_note = f"  [{st.tool}] {st.args}" if st.tool else ""
        result_snip = ""
        if st.result:
            snip = st.result.stdout[:400] if hasattr(st.result, "stdout") else str(st.result)[:400]
            result_snip = f"\n  OUTPUT: {snip}" if snip.strip() else ""
        findings_lines.append(
            f"Step {st.step}: {st.thought or st.purpose or '—'}{tool_note}{result_snip}"
        )

    return _CHAT_SYSTEM.format(
        target=session.target,
        step_count=len(session.steps),
        memory_block=memory.to_context_block(),
        findings_block="\n".join(findings_lines) or "No steps recorded.",
    )


def _help_text() -> None:
    console.print(Panel(
        "[bold cyan]POST-SESSION INTERACTIVE CHAT[/bold cyan]\n\n"
        "[green]Commands:[/green]\n"
        "  [yellow]<question>[/yellow]           Ask anything about the session\n"
        "  [yellow]run <tool> <args>[/yellow]    Execute a shell tool (curl, nmap, sqlmap …)\n"
        "  [yellow]reverify <n>[/yellow]         Ask AI to reverify step N finding\n"
        "  [yellow]findings[/yellow]             Print session memory summary\n"
        "  [yellow]tools[/yellow]                List quick-run examples\n"
        "  [yellow]clear[/yellow]                Clear conversation history\n"
        "  [yellow]quit / exit / q[/yellow]      Exit chat\n",
        title="[bold white]Help[/bold white]",
        border_style="cyan",
    ))


def _print_memory(memory: AgentMemory) -> None:
    console.print(Panel(
        memory.to_context_block(),
        title="[bold green]SESSION MEMORY[/bold green]",
        border_style="green",
    ))


class AgentPostChat:
    """
    Interactive post-exploitation REPL.

    Usage (async):
        chat = AgentPostChat(session, memory, ai_cfg)
        await chat.run()
    """

    def __init__(
        self,
        session: AgentSession,
        memory: AgentMemory,
        ai_cfg: dict[str, Any],
    ) -> None:
        self.session = session
        self.memory = memory
        self.ai_cfg = ai_cfg
        self._system = _build_system_prompt(session, memory)
        self._history: list[dict[str, str]] = []   # [{role, content}, ...]

    # ── quick-run tools ────────────────────────────────────────────────────── #

    async def _exec_tool(self, line: str) -> None:
        """Parse `run <tool> <args>` and stream the output."""
        parts = line.strip().split(None, 2)  # ["run", "tool", "rest of args"]
        if len(parts) < 3:
            console.print("[red]Usage: run <tool> <args>[/red]")
            return

        tool_name = parts[1]
        args = parts[2]

        console.print(
            f"\n[dim]▶ Running:[/dim] [yellow]{tool_name} {args}[/yellow]"
        )

        result: ToolResult = await run_tool(
            {"name": tool_name, "args": args},
            timeout=120,
        )

        output = result.stdout or result.stderr or "(no output)"
        console.print(Panel(
            output[:3000] + ("  …[truncated]" if len(output) > 3000 else ""),
            title=f"[bold]{tool_name}[/bold]",
            border_style="yellow",
        ))

        # Feed result back to AI
        self._history.append({
            "role": "user",
            "content": f"I ran: {tool_name} {args}\n\nOutput:\n{output[:2000]}",
        })
        await self._ai_respond("What does this output tell us?  Highlight anything actionable.")

    # ── reverify shortcut ─────────────────────────────────────────────────── #

    def _reverify_prompt(self, line: str) -> str:
        parts = line.strip().split(None, 1)
        step_ref = parts[1] if len(parts) > 1 else ""
        if step_ref.isdigit():
            idx = int(step_ref) - 1
            if 0 <= idx < len(self.session.steps):
                st = self.session.steps[idx]
                return (
                    f"Give me a single curl/nmap/sqlmap command to independently "
                    f"verify the finding from step {step_ref}: "
                    f"{st.thought or st.purpose or '(no description)'}.  "
                    f"Just the command, then a short explanation."
                )
        return f"Give me a command to reverify: {step_ref}"

    # ── AI streaming response ─────────────────────────────────────────────── #

    async def _ai_respond(self, question: str) -> None:
        """Stream the AI answer to the console."""
        self._history.append({"role": "user", "content": question})

        full_reply = ""
        console.print()
        try:
            async for chunk in ask_stream(
                question=question,
                system=self._system,
                history=self._history[:-1],  # exclude the message we just appended
                config=self.ai_cfg,
            ):
                console.print(chunk, end="", markup=False)
                full_reply += chunk
        except Exception as exc:
            console.print(f"\n[red]AI error: {exc}[/red]")
            return

        console.print()  # newline after streaming
        self._history.append({"role": "assistant", "content": full_reply})

    # ── main REPL ─────────────────────────────────────────────────────────── #

    async def run(self) -> None:
        """Main interactive loop.  Blocks until user exits."""

        console.print(Rule("[bold cyan]POST-PWN INTERACTIVE SESSION[/bold cyan]", style="cyan"))
        console.print(
            f"\n[bold green]Target:[/bold green] {self.session.target}  "
            f"[bold blue]Steps:[/bold blue] {len(self.session.steps)}  "
            f"[bold magenta]Findings:[/bold magenta] {len(self.memory.exploited)} exploited\n"
        )
        console.print(
            "[dim]Type [bold white]help[/bold white] for commands, "
            "[bold white]findings[/bold white] to see memory, "
            "[bold white]quit[/bold white] to exit.[/dim]\n"
        )

        # Opening AI briefing
        opening_q = (
            "Give a 3-bullet executive summary of what was found and exploited.  "
            "Then list the single highest-impact follow-up action the attacker should take next."
        )
        await self._ai_respond(opening_q)
        console.print()

        while True:
            try:
                raw = Prompt.ask("[bold yellow]chat[/bold yellow]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Exiting chat …[/dim]")
                break

            line = raw.strip()
            if not line:
                continue

            low = line.lower()

            if low in ("quit", "exit", "q", "bye"):
                console.print("[dim]Goodbye.[/dim]")
                break

            if low == "help":
                _help_text()
                continue

            if low == "findings":
                _print_memory(self.memory)
                continue

            if low == "clear":
                self._history.clear()
                console.print("[dim]Conversation history cleared.[/dim]")
                continue

            if low == "tools":
                console.print(
                    Panel(
                        "run curl -si http://target/wp-login.php\n"
                        "run nmap -sV -p 80,443,8080 target\n"
                        "run sqlmap -u 'http://target/?id=1' --dbs\n"
                        "run wpscan --url http://target --enumerate vp\n"
                        "run hydra -L users.txt -P pass.txt target http-post-form …",
                        title="Quick-run examples",
                        border_style="dim",
                    )
                )
                continue

            if low.startswith("run "):
                await self._exec_tool(line)
                continue

            if low.startswith("reverify"):
                question = self._reverify_prompt(line)
                await self._ai_respond(question)
                continue

            # Default: plain AI chat
            await self._ai_respond(line)
