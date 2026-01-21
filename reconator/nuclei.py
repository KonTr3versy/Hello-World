import json
from pathlib import Path
from typing import Dict, List

from .state import HostState, init_module_state, mark_finished, mark_running
from .utils import format_command, run_command, write_json

PROFILE_FLAGS = {
    "safe": ["-severity", "critical,high,medium"],
    "standard": ["-severity", "critical,high,medium,low"],
    "aggressive": ["-severity", "critical,high,medium,low,info"],
}


def rollup_findings(results_path: Path) -> Dict[str, List[dict]]:
    findings: Dict[str, List[dict]] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    if not results_path.exists():
        return findings
    for line in results_path.read_text(encoding="utf-8").splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        severity = data.get("severity", "info")
        findings.setdefault(severity, []).append(
            {
                "template_id": data.get("template-id"),
                "name": data.get("info", {}).get("name"),
                "matched_at": data.get("matched-at"),
            }
        )
    return findings


def run_nuclei(host_dir: Path, host: str, urls: List[str], profile: str, timeout_s: int, resume: bool) -> None:
    state_path = host_dir / "state.json"
    state = HostState.load(state_path, engagement_name=host, host=host)
    module = init_module_state(state, "nuclei")
    nuclei_dir = host_dir / "nuclei"
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    if module.status == "RUNNING":
        mark_finished(module, "INTERRUPTED", exit_code=module.exit_code, error="Previous run interrupted")
        state.save(state_path)

    if resume and module.status == "OK":
        return

    urls_path = host_dir / "web" / "urls.txt"
    urls_path.write_text("\n".join(urls), encoding="utf-8")
    stdout_path = nuclei_dir / "stdout.log"
    stderr_path = nuclei_dir / "stderr.log"
    command = [
        "nuclei",
        "-l",
        str(urls_path),
        "-jsonl",
        "-o",
        str(nuclei_dir / "results.jsonl"),
        "-rate-limit",
        "10",
    ]
    command.extend(PROFILE_FLAGS.get(profile, PROFILE_FLAGS["safe"]))
    mark_running(module, format_command(command), stdout_path, stderr_path)
    state.save(state_path)

    run_command(command, stdout_path, stderr_path, timeout_s)
    findings = rollup_findings(nuclei_dir / "results.jsonl")
    write_json(nuclei_dir / "findings.json", findings)
    mark_finished(module, "OK", exit_code=0)
    state.save(state_path)
