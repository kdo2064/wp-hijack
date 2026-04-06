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

