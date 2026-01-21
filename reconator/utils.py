import json
import os
import random
import re
import shlex
import string
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


VALID_ENGAGEMENT_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class CommandResult:
    command: List[str]
    returncode: Optional[int]
    duration_s: float
    stdout_path: Path
    stderr_path: Path
    timed_out: bool


class ReconatorError(Exception):
    pass


_SUBPROCESS_SEMAPHORE = None


def set_subprocess_semaphore(semaphore) -> None:
    global _SUBPROCESS_SEMAPHORE
    _SUBPROCESS_SEMAPHORE = semaphore


def normalize_engagement_name(name: str) -> str:
    normalized = name.strip().replace(" ", "_")
    if not normalized:
        raise ReconatorError("Engagement name cannot be empty")
    if not VALID_ENGAGEMENT_RE.match(normalized):
        raise ReconatorError("Engagement name must match [a-zA-Z0-9_-]")
    return normalized


def ensure_writable_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    test_file = path / ".reconator_write_test"
    try:
        test_file.write_text("ok", encoding="utf-8")
    finally:
        if test_file.exists():
            test_file.unlink()


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def read_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def random_label(length: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def safe_command(command: Sequence[str]) -> List[str]:
    return [str(item) for item in command]


def run_command(
    command: Sequence[str],
    stdout_path: Path,
    stderr_path: Path,
    timeout_s: Optional[int],
    env: Optional[dict] = None,
) -> CommandResult:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    timed_out = False
    returncode: Optional[int] = None
    semaphore = _SUBPROCESS_SEMAPHORE
    if semaphore is None:
        semaphore_cm = _nullcontext()
    else:
        semaphore_cm = semaphore
    with semaphore_cm:
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            try:
                proc = subprocess.run(
                    safe_command(command),
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout_s,
                    env=env,
                    check=False,
                )
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
    duration = time.time() - start
    return CommandResult(
        command=list(command),
        returncode=returncode,
        duration_s=duration,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        timed_out=timed_out,
    )


def format_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(item)) for item in command)


def dedupe_sorted(items: Iterable[str]) -> List[str]:
    return sorted(set(items))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _nullcontext:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, exc_tb):
        return False
