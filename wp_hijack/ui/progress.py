"""ScanProgress — rich progress bar wrapper with wp-Hijack branding."""

from __future__ import annotations

from contextlib import contextmanager

from rich.progress import (

    Progress,

    SpinnerColumn,

    TextColumn,

    BarColumn,

    TaskProgressColumn,

    TimeElapsedColumn,

    MofNCompleteColumn,

)

from .theme import BRAND_GREEN, ACCENT_BLUE, console





def _build_progress() -> Progress:

    return Progress(

        SpinnerColumn(spinner_name="dots", style=f"bold {BRAND_GREEN}"),

        TextColumn("[scan.phase]{task.description}[/]", justify="right"),

        BarColumn(

            bar_width=40,

            style=f"dim {BRAND_GREEN}",

            complete_style=BRAND_GREEN,

            finished_style=f"bold {BRAND_GREEN}",

        ),

        TaskProgressColumn(style=f"bold {ACCENT_BLUE}"),

        MofNCompleteColumn(),

        TimeElapsedColumn(),

        console=console,

        transient=False,

    )





class ScanProgress:

    """Context-manager around rich Progress for wp-Hijack scan phases."""



    def __init__(self) -> None:

        self._progress = _build_progress()

        self._tasks: dict[str, int] = {}



    def __enter__(self) -> "ScanProgress":

        self._progress.start()

        return self



    def __exit__(self, *_: object) -> None:

        self._progress.stop()



    def add_task(self, name: str, total: int = 100) -> int:

        tid = self._progress.add_task(name, total=total)

        self._tasks[name] = tid

        return tid



    def advance(self, task_id: int, amount: int = 1) -> None:

        self._progress.advance(task_id, amount)



    def update(self, task_id: int, *, advance: int = 0, description: str | None = None, completed: int | None = None) -> None:

        kwargs: dict = {}

        if description is not None:

            kwargs["description"] = description

        if completed is not None:

            kwargs["completed"] = completed

        self._progress.update(task_id, advance=advance, **kwargs)



    def complete(self, task_id: int) -> None:

        task = self._progress.tasks[task_id]

        self._progress.update(task_id, completed=task.total)

