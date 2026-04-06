"""
Data models for the autonomous agent session.
"""



from __future__ import annotations



import json

from dataclasses import dataclass, field

from datetime import datetime, timezone

from typing import Any



from .tool_runner import ToolResult





def _now_iso() -> str:

    return datetime.now(timezone.utc).isoformat(timespec="seconds")





@dataclass

class AgentStep:

    step: int

    thought: str

    action: str                                                             

    tool: str | None = None

    args: str | None = None

    code: str | None = None

    purpose: str | None = None

    result: ToolResult | None = None

    timestamp: str = field(default_factory=_now_iso)



    def to_dict(self) -> dict[str, Any]:

        d: dict[str, Any] = {

            "step": self.step,

            "timestamp": self.timestamp,

            "action": self.action,

            "thought": self.thought,

        }

        if self.tool:

            d["tool"] = self.tool

        if self.args:

            d["args"] = self.args

        if self.code:

            d["code"] = self.code[:500] + "..." if len(self.code or "") > 500 else self.code

        if self.purpose:

            d["purpose"] = self.purpose

        if self.result:

            d["result"] = {

                "returncode": self.result.returncode,

                "duration_s": round(self.result.duration, 2),

                "timed_out": self.result.timed_out,

                "stdout_preview": self.result.stdout[:300],

            }

        return d





@dataclass

class AgentSession:

    target: str

    steps: list[AgentStep] = field(default_factory=list)

    findings: list[dict[str, Any]] = field(default_factory=list)

    summary: str = ""

    started_at: str = field(default_factory=_now_iso)

    ended_at: str | None = None

    aborted: bool = False

    abort_reason: str = ""



    def add_step(self, step: AgentStep) -> None:

        self.steps.append(step)



    def finish(self, summary: str, findings: list[dict], aborted: bool = False, reason: str = "") -> None:

        self.summary = summary

        self.findings = findings

        self.ended_at = _now_iso()

        self.aborted = aborted

        self.abort_reason = reason



    def to_dict(self) -> dict[str, Any]:

        return {

            "target": self.target,

            "started_at": self.started_at,

            "ended_at": self.ended_at,

            "aborted": self.aborted,

            "abort_reason": self.abort_reason,

            "summary": self.summary,

            "total_steps": len(self.steps),

            "findings": self.findings,

            "steps": [s.to_dict() for s in self.steps],

        }



    def to_json(self, indent: int = 2) -> str:

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

