"""
Async subprocess executor for pentesting tools and AI-generated Python exploits.
"""



from __future__ import annotations



import asyncio

import os

import sys

import tempfile

import time

from dataclasses import dataclass, field

from pathlib import Path





@dataclass

class ToolResult:

    tool: str

    returncode: int

    stdout: str

    stderr: str

    duration: float

    timed_out: bool = False



    def combined_output(self, max_chars: int = 3000) -> str:

        """Return stdout + stderr merged, truncated to max_chars."""

        out = self.stdout.strip()

        err = self.stderr.strip()

        combined = out

        if err:

            combined = combined + ("\n\n[STDERR]\n" + err if combined else err)

        if len(combined) > max_chars:

            half = max_chars // 2

            combined = (

                combined[:half]

                + f"\n\n... [TRUNCATED — {len(combined)} chars total] ...\n\n"

                + combined[-half:]

            )

        return combined or "(no output)"





                                                     

_BLOCKLIST: list[str] = [

    "rm -rf",

    "rm -r /",

    "format c:",

    "format /",

    "del /f /s",

    "del /q /f",

    "shutdown",

    "mkfs",

    "dd if=",

    ":(){:|:&};:",              

    ">(dev/null",

]





def _is_safe(args_str: str) -> tuple[bool, str]:

    """Return (True, '') if safe, (False, reason) if dangerous."""

    lower = args_str.lower()

    for pattern in _BLOCKLIST:

        if pattern in lower:

            return False, f"Blocked pattern detected: '{pattern}'"

    return True, ""


# Per-tool timeouts (seconds).  Slow scanners get extra time.
_TOOL_TIMEOUTS: dict[str, int] = {
    "nmap":      90,
    "whatweb":   30,
    "nikto":    300,
    "gobuster":  90,
    "ffuf":      90,
    "wpscan":   300,
    "curl":      20,
    "sqlmap":   180,
    "hydra":    180,
    "python":    60,
}


def get_tool_timeout(name: str, default: int = 120) -> int:
    """Return the configured timeout for *name*, falling back to *default*."""
    return _TOOL_TIMEOUTS.get(name.lower(), default)



async def run_tool(

    name: str,

    args_str: str,

    timeout: int = 120,

    env: dict[str, str] | None = None,

) -> ToolResult:

    """
    Run an external tool by name with the given argument string.

    name      — tool binary name (e.g. 'nmap')
    args_str  — raw argument string appended after the binary
    timeout   — kill after this many seconds
    env       — optional extra environment variables
    """

    safe, reason = _is_safe(args_str)

    if not safe:

        return ToolResult(

            tool=name,

            returncode=-1,

            stdout="",

            stderr=f"[BLOCKED] {reason}",

            duration=0.0,

        )



    cmd = f"{name} {args_str}"

    run_env = {**os.environ}

    if env:

        run_env.update(env)



    start = time.monotonic()

    timed_out = False

    try:

        proc = await asyncio.create_subprocess_shell(

            cmd,

            stdout=asyncio.subprocess.PIPE,

            stderr=asyncio.subprocess.PIPE,

            env=run_env,

        )

        try:

            stdout_b, stderr_b = await asyncio.wait_for(

                proc.communicate(), timeout=timeout

            )

        except asyncio.TimeoutError:

            timed_out = True

            try:

                proc.kill()

            except Exception:

                pass

            stdout_b, stderr_b = b"", b"[TIMEOUT] Tool exceeded time limit."

            returncode = -9

        else:

            returncode = proc.returncode or 0

    except FileNotFoundError:

        stdout_b = b""

        stderr_b = f"[ERROR] Binary '{name}' not found on PATH.".encode()

        returncode = 127



    duration = time.monotonic() - start

    return ToolResult(

        tool=name,

        returncode=returncode,

        stdout=stdout_b.decode("utf-8", errors="replace"),

        stderr=stderr_b.decode("utf-8", errors="replace") if isinstance(stderr_b, bytes) else str(stderr_b),

        duration=duration,

        timed_out=timed_out,

    )





async def run_tools_parallel(
    tools: list[dict],
    default_timeout: int = 120,
) -> list[ToolResult]:
    """
    Run multiple (tool, args) pairs concurrently and return a list of
    ToolResult in the same order.

    Each element of *tools* must be a dict with keys:
        name      — binary name
        args_str  — argument string
        timeout   — (optional) per-tool override in seconds
    """
    async def _one(item: dict) -> ToolResult:
        name = item["name"]
        args_str = item.get("args_str", "")
        timeout = item.get("timeout", get_tool_timeout(name, default_timeout))
        return await run_tool(name, args_str, timeout=timeout)

    return list(await asyncio.gather(*(_one(t) for t in tools)))


async def run_tools_streaming(
    tools: list[dict],
    on_complete,
    default_timeout: int = 120,
) -> list[tuple[dict, ToolResult]]:
    """
    Run tools concurrently like run_tools_parallel, but call ``on_complete``
    as soon as each individual tool finishes — without waiting for the rest.

    ``on_complete`` signature:  async def on_complete(spec: dict, result: ToolResult)

    Returns a list of (spec, ToolResult) pairs in completion order.
    """
    async def _one(item: dict) -> tuple[dict, ToolResult]:
        name = item["name"]
        args_str = item.get("args_str", "")
        timeout = item.get("timeout", get_tool_timeout(name, default_timeout))
        result = await run_tool(name, args_str, timeout=timeout)
        await on_complete(item, result)
        return item, result

    # asyncio.as_completed fires the callback inside _one as each coroutine ends
    tasks = [asyncio.create_task(_one(t)) for t in tools]
    return [await t for t in asyncio.as_completed(tasks)]


# ── Error Classification ──────────────────────────────────────────────────── #

_TIMEOUT_KW = ("timeout", "timed out", "time limit", "deadline exceeded", "took too long")
_NETWORK_KW = (
    "connection refused", "no route to host", "name or service not known",
    "could not connect", "failed to connect", "network unreachable",
    "errno 111", "errno 101", "host unreachable",
)
_AUTH_KW    = ("permission denied", "authentication failed", "forbidden", "401", "403 forbidden")
_NOTFOUND_KW = ("not found", "no such file", "command not found", "127", "binary", "error 404")


@dataclass
class ErrorContext:
    """Structured failure description injected into the AI error-observer prompt."""
    error_type:  str    # TIMEOUT | NETWORK | AUTH | NOT_FOUND | CRASH | EMPTY
    tool:        str
    args:        str
    suggestion:  str    # actionable fix hint for the AI
    raw_snippet: str    # first ~300 chars of stderr for context


def classify_tool_error(result: ToolResult, args: str = "") -> "ErrorContext | None":
    """
    Analyse a ToolResult.
    Returns an ErrorContext when an actionable problem is detected, else None.
    """
    # Genuine success — output present, no timeout, clean exit
    if result.returncode == 0 and not result.timed_out and result.stdout.strip():
        return None

    combined = (result.stdout + " " + result.stderr).lower()
    snippet  = (result.stderr[:200] + result.stdout[:100]).strip()

    if result.timed_out or any(k in combined for k in _TIMEOUT_KW):
        # Give a flag-specific hint where possible
        hints: dict[str, str] = {
            "nmap":     "Use fewer ports (-p 80,443,22) and add -T4 --max-retries 1",
            "wpscan":   "Add --max-scan-duration 60 and reduce enumerate flags (use vp only)",
            "whatweb":  "Switch to -a 1 and add --timeout 8",
            "nikto":    "Add -maxtime 90 and -Tuning 123",
            "gobuster":  "Reduce -t threads to 10 and add --timeout 8s",
            "sqlmap":   "Add --timeout 10 --retries 1 --level 1 --risk 1",
            "hydra":    "Reduce -t to 4 and add -W 3",
        }
        extra = hints.get(result.tool, "Try adding a shorter timeout flag or reducing scan scope")
        return ErrorContext(
            error_type="TIMEOUT",
            tool=result.tool,
            args=args,
            suggestion=(
                f"'{result.tool}' hit the time limit. {extra}. "
                "Alternatively use run_python with requests for a lightweight probe."
            ),
            raw_snippet=snippet,
        )

    if any(k in combined for k in _NOTFOUND_KW):
        return ErrorContext(
            error_type="NOT_FOUND",
            tool=result.tool,
            args=args,
            suggestion=(
                f"'{result.tool}' binary not found or target path returned 404. "
                "Skip this tool or replace with run_python (requests/urllib)."
            ),
            raw_snippet=snippet,
        )

    if any(k in combined for k in _NETWORK_KW):
        return ErrorContext(
            error_type="NETWORK",
            tool=result.tool,
            args=args,
            suggestion=(
                f"'{result.tool}' hit a network error. "
                "Try HTTPS instead of HTTP, verify the target is reachable with curl first, "
                "or try a Python requests probe."
            ),
            raw_snippet=snippet,
        )

    if any(k in combined for k in _AUTH_KW):
        return ErrorContext(
            error_type="AUTH",
            tool=result.tool,
            args=args,
            suggestion=(
                f"'{result.tool}' received an auth/permission error. "
                "Try unauthenticated paths, REST API, or xmlrpc.php instead."
            ),
            raw_snippet=snippet,
        )

    if not result.stdout.strip():
        return ErrorContext(
            error_type="EMPTY",
            tool=result.tool,
            args=args,
            suggestion=(
                f"'{result.tool}' produced no output (exit {result.returncode}). "
                "Check the args are correct; try run_python for manual verification."
            ),
            raw_snippet=snippet,
        )

    if result.returncode not in (0, None):
        return ErrorContext(
            error_type="CRASH",
            tool=result.tool,
            args=args,
            suggestion=(
                f"'{result.tool}' crashed (exit {result.returncode}). "
                "Review the args for syntax errors or unsupported flags."
            ),
            raw_snippet=snippet,
        )

    return None


async def run_python_exploit(

    code: str,

    timeout: int = 45,

    extra_vars: dict[str, str] | None = None,

) -> ToolResult:

    """
    Write AI-generated Python exploit code to a temp file and execute it with
    the current interpreter.  The temp file is deleted afterwards.

    extra_vars — optional dict injected as env vars (e.g. TARGET=...)
    """

    safe, reason = _is_safe(code)

    if not safe:

        return ToolResult(

            tool="python_exploit",

            returncode=-1,

            stdout="",

            stderr=f"[BLOCKED] {reason}",

            duration=0.0,

        )



                               

    tmp_path: Path | None = None

    try:

        fd, tmp = tempfile.mkstemp(suffix=".py", prefix="wp_exploit_")

        os.close(fd)

        tmp_path = Path(tmp)

        tmp_path.write_text(code, encoding="utf-8")



        run_env = {**os.environ}

        if extra_vars:

            run_env.update(extra_vars)



        start = time.monotonic()

        timed_out = False

        try:

            proc = await asyncio.create_subprocess_exec(

                sys.executable, str(tmp_path),

                stdout=asyncio.subprocess.PIPE,

                stderr=asyncio.subprocess.PIPE,

                env=run_env,

            )

            try:

                stdout_b, stderr_b = await asyncio.wait_for(

                    proc.communicate(), timeout=timeout

                )

            except asyncio.TimeoutError:

                timed_out = True

                try:

                    proc.kill()

                except Exception:

                    pass

                stdout_b, stderr_b = b"", b"[TIMEOUT] Python exploit exceeded time limit."

                returncode = -9

            else:

                returncode = proc.returncode or 0

        except Exception as exc:

            stdout_b = b""

            stderr_b = f"[ERROR] Failed to execute exploit: {exc}".encode()

            returncode = -1

            start = time.monotonic()



        duration = time.monotonic() - start

        return ToolResult(

            tool="python_exploit",

            returncode=returncode,

            stdout=stdout_b.decode("utf-8", errors="replace"),

            stderr=stderr_b.decode("utf-8", errors="replace") if isinstance(stderr_b, bytes) else str(stderr_b),

            duration=duration,

            timed_out=timed_out,

        )

    finally:

        if tmp_path and tmp_path.exists():

            try:

                tmp_path.unlink()

            except Exception:

                pass

