"""
AutonomousAgent — the main agent loop.

Drives the AI through a plan → act → observe → plan cycle until
the assessment is complete or the step budget is exhausted.

Usage:
    agent = AutonomousAgent(target="http://target.com", ai_cfg=cfg["ai"], agent_cfg=cfg["agent"])
    session = await agent.run()
"""



from __future__ import annotations



import asyncio

from dataclasses import dataclass, field

from typing import Any



from rich.console import Console

from rich.live import Live

from rich.panel import Panel

from rich.spinner import Spinner

from rich.text import Text



from ..ai.client import ask_stream as ai_ask_stream

from .prompts import AgentAction, build_agent_system_prompt, parse_agent_response

from .session import AgentSession, AgentStep

from .tool_runner import ToolResult, run_python_exploit, run_tool

from .tools import available_tools_block, check_available



console = Console()





                                                                                

_SEV_COLOUR = {

    "CRITICAL": "bold red",

    "HIGH": "bold #FF6B35",

    "MEDIUM": "bold yellow",

    "LOW": "bold cyan",

    "INFO": "dim",

}





def _sev(sev: str) -> str:

    colour = _SEV_COLOUR.get(sev.upper(), "white")

    return f"[{colour}]{sev}[/{colour}]"





                                                                                



class AutonomousAgent:

    """
    Fully autonomous AI pentesting agent.

    Parameters
    ----------
    target : str
        URL or hostname of the target.
    ai_cfg : dict
        AI provider config (base_url, model, api_key, temperature, max_tokens, timeout).
    agent_cfg : dict
        Agent behaviour config (max_steps, tool_timeout, python_exploit_timeout,
        max_output_chars, allowed_tools).
    """



    def __init__(

        self,

        target: str,

        ai_cfg: dict[str, Any],

        agent_cfg: dict[str, Any],

    ) -> None:

        self.target = target

        self.ai_cfg = ai_cfg

        self.agent_cfg = agent_cfg



        self.max_steps: int = agent_cfg.get("max_steps", 30)

        self.tool_timeout: int = agent_cfg.get("tool_timeout", 120)

        self.python_timeout: int = agent_cfg.get("python_exploit_timeout", 45)

        self.max_output_chars: int = agent_cfg.get("max_output_chars", 3000)

        self.allowed_tools: list[str] = agent_cfg.get(

            "allowed_tools",

            ["nmap", "whatweb", "nikto", "gobuster", "ffuf", "wpscan", "curl", "sqlmap", "hydra"],

        )



                                                                     

        self._system_prompt: str = ""

        self._history: list[dict[str, str]] = []

        self._session: AgentSession | None = None



                                                                                



    def _print_step_header(self, step: int, thought: str) -> None:

        console.print(

            Panel(

                Text(thought, style="italic"),

                title=f"[bold #00d7d7]Step {step}[/] — Thought",

                border_style="#00d7d7",

                padding=(0, 1),

            )

        )



    def _print_tool_call(self, tool: str, args: str, purpose: str) -> None:

        cmd_text = Text(f"$ {tool} {args}", style="bold green")

        purpose_text = Text(f"Purpose: {purpose}", style="dim")

        console.print(Panel(cmd_text, subtitle=str(purpose_text), border_style="green", padding=(0, 1)))



    def _print_python_run(self, code: str, purpose: str) -> None:

        preview = code[:400] + ("..." if len(code) > 400 else "")

        console.print(

            Panel(

                Text(preview, style="bold #87d7ff"),

                title="[bold #87d7ff]Python Exploit[/]",

                subtitle=f"Purpose: {purpose}",

                border_style="#87d7ff",

                padding=(0, 1),

            )

        )



    def _print_result(self, result: ToolResult) -> None:

        output = result.combined_output(self.max_output_chars)

        colour = "green" if result.returncode == 0 else "yellow"

        status = (

            "[bold red]TIMEOUT[/]" if result.timed_out

            else f"[{colour}]exit {result.returncode}[/{colour}]"

        )

        console.print(

            Panel(

                Text(output, overflow="fold"),

                title=f"Output — {status} ({result.duration:.1f}s)",

                border_style=colour,

                padding=(0, 1),

            )

        )



    def _print_findings(self, findings: list[dict]) -> None:

        if not findings:

            console.print("[dim]No findings reported.[/dim]")

            return

        console.print(f"\n[bold]Findings ({len(findings)} total)[/bold]\n")

        for i, f in enumerate(findings, 1):

            sev = f.get("severity", "INFO")

            title = f.get("title", "Unknown")

            desc = f.get("description", "")

            evidence = f.get("evidence", "")

            rec = f.get("recommendation", "")

            body = Text()

            body.append(f"{desc}\n", style="white")

            if evidence:

                body.append(f"\nEvidence: {evidence[:300]}\n", style="dim")

            if rec:

                body.append(f"\nRecommendation: {rec}", style="italic")

            console.print(

                Panel(

                    body,

                    title=f"[{i}] {_sev(sev)} — {title}",

                    border_style=_SEV_COLOUR.get(sev.upper(), "white").replace("bold ", ""),

                    padding=(0, 1),

                )

            )



    async def _ask_ai(self, user_message: str) -> str:

        """Send a message and collect the full AI response."""

        self._history.append({"role": "user", "content": user_message})

                                                                                   

        prior_history = self._history[:-1]

        buf = ""

        with Live(Spinner("dots", text="Agent thinking…"), refresh_per_second=8,

                  transient=True, console=console):

            async for chunk in ai_ask_stream(

                user_message,

                system=self._system_prompt,

                history=prior_history,

                config=self.ai_cfg,

            ):

                buf += chunk

        self._history.append({"role": "assistant", "content": buf})

        return buf



    async def _execute_action(self, action: AgentAction, step_idx: int) -> tuple[AgentStep, str]:

        """Execute an action and return (AgentStep, feedback_for_next_ai_message)."""

        step = AgentStep(

            step=step_idx,

            thought=action.thought,

            action=action.action,

            tool=action.tool or None,

            args=action.args or None,

            code=action.code or None,

            purpose=action.purpose or None,

        )



        if action.action == "run_tool":

            tool_name = action.tool.strip().lower()



                                              

            if tool_name not in self.allowed_tools and tool_name != "python":

                result = ToolResult(

                    tool=tool_name, returncode=-1,

                    stdout="", stderr=f"Tool '{tool_name}' not in allowed_tools list.",

                    duration=0.0,

                )

            else:

                self._print_tool_call(tool_name, action.args, action.purpose)

                result = await run_tool(

                    tool_name, action.args, timeout=self.tool_timeout

                )

                self._print_result(result)



            step.result = result

            output_summary = result.combined_output(self.max_output_chars)

            feedback = (

                f"[Tool: {tool_name}] [exit: {result.returncode}] "

                f"[duration: {result.duration:.1f}s]\n\n{output_summary}\n\n"

                "What is your next action? Respond with a valid JSON action object."

            )



        elif action.action == "run_python":

            self._print_python_run(action.code, action.purpose)

            result = await run_python_exploit(

                action.code, timeout=self.python_timeout,

                extra_vars={"TARGET": self.target},

            )

            self._print_result(result)

            step.result = result

            output_summary = result.combined_output(self.max_output_chars)

            feedback = (

                f"[Python exploit] [exit: {result.returncode}] "

                f"[duration: {result.duration:.1f}s]\n\n{output_summary}\n\n"

                "What is your next action? Respond with a valid JSON action object."

            )

        else:

            feedback = "Unexpected action. Continue assessment and respond with a JSON object."



        return step, feedback



                                                                                



    async def run(self) -> AgentSession:

        """
        Run the autonomous agent loop and return a completed AgentSession.
        """

        session = AgentSession(target=self.target)

        self._session = session



                                         

        availability = check_available(self.allowed_tools)

        tools_block = available_tools_block(self.allowed_tools)



        console.print(

            Panel(

                f"Target: [bold #FF6B35]{self.target}[/]\n"

                f"Max steps: [bold]{self.max_steps}[/]\n"

                f"Available tools: {', '.join(t for t, ok in availability.items() if ok) or 'none'}",

                title="[bold]Autonomous Agent Starting[/]",

                border_style="#FF6B35",

            )

        )



                             

        system_prompt = build_agent_system_prompt(

            target=self.target,

            available_tools_block=tools_block,

            max_steps=self.max_steps,

        )

        self._system_prompt = system_prompt

        self._history = []                                                      



                                           

        initial_msg = (

            f"Begin autonomous security assessment of target: {self.target}\n"

            f"Start with an nmap scan. Respond with a valid JSON action object."

        )



        step_idx = 1

        consecutive_failures = 0

        max_consecutive_failures = 3

        next_message: str = initial_msg



        while step_idx <= self.max_steps:

            console.rule(f"[dim]Step {step_idx} / {self.max_steps}[/dim]")



                             

            ai_text = await self._ask_ai(next_message)



                              

            action = parse_agent_response(ai_text)



            if action is None:

                consecutive_failures += 1

                console.print(

                    f"[yellow]Could not parse JSON action (attempt {consecutive_failures}/{max_consecutive_failures})[/yellow]"

                )

                console.print(Panel(ai_text[:500], title="Raw AI response", border_style="yellow"))



                if consecutive_failures >= max_consecutive_failures:

                    session.finish(

                        summary="Agent aborted: AI failed to produce valid actions repeatedly.",

                        findings=[],

                        aborted=True,

                        reason="parse_failure",

                    )

                    break

                                             

                next_message = (

                    "Your last response was not valid JSON. "

                    "Please respond with ONLY a single JSON action object. No prose."

                )

                continue



            consecutive_failures = 0



                             

            self._print_step_header(step_idx, action.thought or "(no thought)")



                                          

            if action.action == "done":

                session.finish(

                    summary=action.summary,

                    findings=action.findings,

                )

                console.print(

                    Panel(

                        action.summary or "Assessment complete.",

                        title="[bold green]Assessment Complete[/]",

                        border_style="green",

                    )

                )

                self._print_findings(action.findings)

                break



                                

            agent_step, next_message = await self._execute_action(action, step_idx)

            session.add_step(agent_step)

            step_idx += 1



        else:

                                   

            console.print(

                f"[yellow]Step budget ({self.max_steps}) exhausted. Requesting final report…[/yellow]"

            )

            final_text = await self._ask_ai(

                f"You have used all {self.max_steps} steps. "

                "Summarise your findings and respond with a 'done' JSON action now."

            )

            final_action = parse_agent_response(final_text)

            if final_action and final_action.action == "done":

                session.finish(

                    summary=final_action.summary,

                    findings=final_action.findings,

                )

                self._print_findings(final_action.findings)

            else:

                session.finish(

                    summary="Step budget exhausted — partial assessment.",

                    findings=[],

                    aborted=True,

                    reason="max_steps_reached",

                )



        return session

