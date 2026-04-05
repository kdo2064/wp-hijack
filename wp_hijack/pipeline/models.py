"""Pipeline data models — SafetyLevel, VulnStatus, ConfirmedFinding, ExploitCode."""

from __future__ import annotations

from dataclasses import dataclass, field

from enum import Enum

from typing import Any





class SafetyLevel(str, Enum):

    SAFE      = "SAFE"

    CAUTIOUS  = "CAUTIOUS"

    UNSAFE    = "UNSAFE"





class VulnStatus(str, Enum):

    DETECTED   = "DETECTED"

    CONFIRMED  = "CONFIRMED"

    POTENTIAL  = "POTENTIAL"

    PATCHED    = "PATCHED"

    FALSE_POS  = "FALSE_POS"





@dataclass

class ConfirmationTest:

    cve: str

    description: str

    safety: SafetyLevel


    run: Any = None





@dataclass

class ConfirmationResult:

    confirmed: bool

    status: VulnStatus

    evidence: str = ""

    request_url: str = ""

    response_snippet: str = ""





@dataclass

class PotentialFinding:

    cve: str

    title: str

    description: str

    severity: str

    cvss: float

    component: str

    component_type: str

    installed_version: str | None

    affected_versions: list[str]

    fixed_version: str | None

    references: list[str] = field(default_factory=list)

    remediation: str = ""

    status: VulnStatus = VulnStatus.DETECTED

    raw: dict = field(default_factory=dict)





@dataclass

class ExploitCode:

    cve: str

    python_poc: str = ""

    curl_command: str = ""

    manual_steps: list[str] = field(default_factory=list)

    impact: str = ""

    prerequisites: str = ""

    disclaimer: str = (

        "This exploit code is generated for authorized security testing and "

        "educational purposes only. Unauthorized use is illegal."

    )





@dataclass

class ConfirmedFinding:

    finding: PotentialFinding

    confirmation: ConfirmationResult | None = None

    exploit: ExploitCode | None = None



    @property

    def status(self) -> VulnStatus:

        if self.confirmation:

            return self.confirmation.status

        return self.finding.status



    def to_dict(self) -> dict:

        f = self.finding

        c = self.confirmation

        e = self.exploit

        return {

            "cve":               f.cve,

            "title":             f.title,

            "description":       f.description,

            "severity":          f.severity,

            "cvss":              f.cvss,

            "component":         f.component,

            "component_type":    f.component_type,

            "installed_version": f.installed_version,

            "affected_versions": f.affected_versions,

            "fixed_version":     f.fixed_version,

            "references":        f.references,

            "remediation":       f.remediation,

            "status":            self.status.value,

            "confirmation_evidence": c.evidence if c else None,

            "confirmation_url":      c.request_url if c else None,

            "exploit_python":    e.python_poc    if e else None,

            "exploit_curl":      e.curl_command  if e else None,

            "exploit_manual":    e.manual_steps  if e else None,

            "exploit_impact":    e.impact        if e else None,

        }

