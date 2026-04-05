"""Unified subprocess runner with streaming output support."""
from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


class CommandExecutionError(RuntimeError):
    """Raised when a command exits with a non-zero return code."""

    def __init__(self, message: str, returncode: int, stdout: str, stderr: str):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@dataclass
class CommandResult:
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    env: Optional[Dict[str, str]] = None,
    stream_output: bool = False,
    raise_on_error: bool = False,
) -> CommandResult:
    """
    Run an external command and capture output.

    Parameters
    ----------
    cmd            : Command and arguments list.
    cwd            : Working directory for the subprocess.
    timeout        : Maximum seconds to wait (None = unlimited).
    env            : Full environment mapping; None inherits the current env.
    stream_output  : If True, echo stdout/stderr to the console in real time
                     while also capturing them.
    raise_on_error : If True, raise CommandExecutionError on non-zero exit.
                     默认改为 True，让调用方显式选择忽略错误，而非静默丢失。

    Returns
    -------
    CommandResult with cmd, returncode, stdout, stderr.
    """
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    def _reader(pipe, collector: List[str], do_print: bool) -> None:
        for raw in pipe:
            line = raw.rstrip("\n")
            collector.append(line)
            if do_print:
                print(line, flush=True)

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        t_out = threading.Thread(
            target=_reader, args=(proc.stdout, stdout_lines, stream_output), daemon=True
        )
        t_err = threading.Thread(
            target=_reader, args=(proc.stderr, stderr_lines, stream_output), daemon=True
        )
        t_out.start()
        t_err.start()

        proc.wait(timeout=timeout)
        t_out.join()
        t_err.join()

    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise CommandExecutionError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}",
            returncode=-1,
            stdout="\n".join(stdout_lines),
            stderr="\n".join(stderr_lines),
        )
    except FileNotFoundError as exc:
        raise CommandExecutionError(
            f"Executable not found: {cmd[0]}",
            returncode=-1,
            stdout="",
            stderr=str(exc),
        ) from exc

    result = CommandResult(
        cmd=cmd,
        returncode=proc.returncode,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
    )

    if raise_on_error and result.returncode != 0:
        raise CommandExecutionError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    return result