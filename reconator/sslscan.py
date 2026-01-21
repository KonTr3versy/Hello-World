from pathlib import Path
from typing import Dict, List

from .state import HostState, init_module_state, mark_finished, mark_running
from .utils import format_command, run_command, write_json

TLS_PORTS = {443, 8443, 993, 995, 465, 587, 636, 990, 993, 995, 464, 8443}


def tls_ports_from_services(services: Dict[int, Dict[str, str]]) -> List[int]:
    ports = set()
    for port, meta in services.items():
        name = (meta.get("name") or "").lower()
        tunnel = (meta.get("tunnel") or "").lower()
        if port in TLS_PORTS:
            ports.add(port)
        if "ssl" in name or "https" in name or tunnel == "ssl":
            ports.add(port)
    return sorted(ports)


def run_sslscan(host_dir: Path, host: str, services: Dict[int, Dict[str, str]], timeout_s: int, resume: bool) -> List[int]:
    state_path = host_dir / "state.json"
    state = HostState.load(state_path, engagement_name=host, host=host)
    module = init_module_state(state, "sslscan")
    tls_dir = host_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)

    if module.status == "RUNNING":
        mark_finished(module, "INTERRUPTED", exit_code=module.exit_code, error="Previous run interrupted")
        state.save(state_path)

    ports = tls_ports_from_services(services)
    if resume and module.status == "OK":
        return ports

    stdout_path = tls_dir / "stdout.log"
    stderr_path = tls_dir / "stderr.log"
    command = ["sslscan", "--no-colour", host]
    mark_running(module, format_command(command), stdout_path, stderr_path)
    state.save(state_path)

    for port in ports:
        command = ["sslscan", "--no-colour", f"{host}:{port}"]
        run_command(command, tls_dir / f"sslscan_{port}.txt", tls_dir / f"sslscan_{port}_err.txt", timeout_s)

    write_json(tls_dir / "tls_summary.json", {"ports": ports})
    mark_finished(module, "OK", exit_code=0)
    state.save(state_path)
    return ports
