import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

from .state import HostState, init_module_state, mark_finished, mark_running
from .utils import format_command, run_command, write_json


def parse_nmap_xml_ports(path: Path) -> Dict[int, Dict[str, str]]:
    ports: Dict[int, Dict[str, str]] = {}
    if not path.exists():
        return ports
    tree = ET.parse(path)
    root = tree.getroot()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port in ports_elem.findall("port"):
            if port.get("protocol") != "tcp":
                continue
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = int(port.get("portid"))
            service = port.find("service")
            entry = {
                "name": service.get("name") if service is not None else "",
                "product": service.get("product") if service is not None else "",
                "version": service.get("version") if service is not None else "",
                "tunnel": service.get("tunnel") if service is not None else "",
            }
            ports[port_id] = entry
    return ports


def host_is_down(path: Path) -> bool:
    if not path.exists():
        return False
    tree = ET.parse(path)
    root = tree.getroot()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            return True
    return False


def derive_web_urls(host: str, ports: Dict[int, Dict[str, str]]) -> List[str]:
    urls: List[str] = []
    for port, meta in ports.items():
        name = (meta.get("name") or "").lower()
        tunnel = (meta.get("tunnel") or "").lower()
        if "http" in name:
            scheme = "https" if "https" in name or tunnel == "ssl" else "http"
        elif name in {"ssl", "https"} or tunnel == "ssl":
            scheme = "https"
        else:
            continue
        urls.append(f"{scheme}://{host}:{port}/")
    return sorted(set(urls))


def run_nmap(
    host_dir: Path,
    host: str,
    timeout_s: int,
    resume: bool,
) -> Dict[int, Dict[str, str]]:
    state_path = host_dir / "state.json"
    state = HostState.load(state_path, engagement_name=host, host=host)
    module = init_module_state(state, "nmap")
    nmap_dir = host_dir / "nmap"
    triage_xml = nmap_dir / "triage.xml"
    followup_xml = nmap_dir / "followup.xml"

    if module.status == "RUNNING":
        mark_finished(module, "INTERRUPTED", exit_code=module.exit_code, error="Previous run interrupted")
        state.save(state_path)

    if resume and module.status == "OK" and followup_xml.exists():
        return parse_nmap_xml_ports(followup_xml)

    nmap_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = nmap_dir / "stdout.log"
    stderr_path = nmap_dir / "stderr.log"

    command = ["nmap", "-sV", "-T3", "-oX", str(triage_xml), host]
    mark_running(module, format_command(command), stdout_path, stderr_path)
    state.save(state_path)
    result = run_command(command, stdout_path, stderr_path, timeout_s)

    if result.timed_out:
        mark_finished(module, "TIMEOUT", result.returncode, "nmap triage timeout")
        state.save(state_path)
        return {}

    ports = parse_nmap_xml_ports(triage_xml)
    if host_is_down(triage_xml):
        module.artifacts["host_state"] = "down"
        mark_finished(module, "OK", result.returncode)
        write_json(host_dir / "services.json", {})
        state.save(state_path)
        return {}
    if not ports:
        mark_finished(module, "OK", result.returncode)
        state.save(state_path)
        return {}

    ports_list = ",".join(str(port) for port in ports)
    followup_cmd = [
        "nmap",
        "-sV",
        "-sC",
        "-T3",
        "-p",
        ports_list,
        "-oX",
        str(followup_xml),
        host,
    ]
    followup_stdout = nmap_dir / "stdout.log"
    followup_stderr = nmap_dir / "stderr.log"
    result = run_command(followup_cmd, followup_stdout, followup_stderr, timeout_s)
    if result.timed_out:
        mark_finished(module, "TIMEOUT", result.returncode, "nmap followup timeout")
    else:
        mark_finished(module, "OK", result.returncode)
    state.save(state_path)
    ports = parse_nmap_xml_ports(followup_xml)
    (nmap_dir / "ports.txt").write_text("\n".join(str(p) for p in ports), encoding="utf-8")
    write_json(host_dir / "services.json", ports)
    return ports
