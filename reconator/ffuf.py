import json
from pathlib import Path
from typing import Dict, List

from .state import HostState, init_module_state, mark_finished, mark_running
from .utils import format_command, run_command, write_json


def discover_wordlist() -> Path:
    candidates = [
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"),
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError("No default wordlist found")


def run_ffuf(host_dir: Path, host: str, urls: List[str], timeout_s: int, resume: bool) -> None:
    state_path = host_dir / "state.json"
    state = HostState.load(state_path, engagement_name=host, host=host)
    module = init_module_state(state, "ffuf")
    web_dir = host_dir / "web"
    web_dir.mkdir(parents=True, exist_ok=True)

    if module.status == "RUNNING":
        mark_finished(module, "INTERRUPTED", exit_code=module.exit_code, error="Previous run interrupted")
        state.save(state_path)

    if resume and module.status == "OK":
        return

    (web_dir / "urls.txt").write_text("\n".join(urls), encoding="utf-8")
    stdout_path = web_dir / "stdout.log"
    stderr_path = web_dir / "stderr.log"
    mark_running(module, "ffuf", stdout_path, stderr_path)
    state.save(state_path)

    hits = []
    try:
        wordlist = discover_wordlist()
    except FileNotFoundError as exc:
        mark_finished(module, "SKIPPED", exit_code=None, error=str(exc))
        state.save(state_path)
        return

    for url in urls:
        port = url.split(":")[2].split("/")[0]
        output_path = web_dir / f"ffuf_{port}.json"
        command = [
            "ffuf",
            "-u",
            f"{url}FUZZ",
            "-w",
            str(wordlist),
            "-of",
            "json",
            "-o",
            str(output_path),
            "-t",
            "5",
            "-timeout",
            str(timeout_s),
        ]
        run_command(command, stdout_path, stderr_path, timeout_s)
        if output_path.exists():
            try:
                data = json.loads(output_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            for item in data.get("results", []):
                hits.append(
                    {
                        "url": item.get("url"),
                        "status": item.get("status"),
                        "length": item.get("length"),
                        "words": item.get("words"),
                    }
                )
    write_json(web_dir / "ffuf_hits.json", hits)
    mark_finished(module, "OK", exit_code=0)
    state.save(state_path)
