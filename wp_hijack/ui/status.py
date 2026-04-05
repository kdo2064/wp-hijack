"""PhaseSpinner — contextmanager for per-phase status messages."""

from __future__ import annotations

from contextlib import contextmanager

from rich.spinner import Spinner

from rich.live import Live

from rich.text import Text

from .theme import console, BRAND_GREEN, ACCENT_BLUE, BRAND_ORANGE





@contextmanager

def PhaseSpinner(message: str, *, success_msg: str | None = None):

    """
    Context manager that shows a spinner while work is in progress, then
    prints a single completion line when done.

    Usage::

        with PhaseSpinner("Enumerating plugins", success_msg="Found 4 plugins"):
            await enumerate_plugins(...)
    """

    status = console.status(

        f"[scan.phase]{message}[/]",

        spinner="dots",

        spinner_style=f"bold {BRAND_GREEN}",

    )

    try:

        with status:

            yield status

        done = success_msg or message

        console.print(f"[scan.done]  ✔[/]  [white]{done}[/]")

    except Exception as exc:

        console.print(f"[scan.error]  ✖[/]  [white]{message}[/]  [dim]— {exc}[/]")

        raise





def phase_header(title: str, *, color: str = ACCENT_BLUE) -> None:

    """Print a phase divider line."""

    from rich.rule import Rule

    console.print(Rule(f"[bold {color}]{title}[/]", style=f"dim {color}"))

