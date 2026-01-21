import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .state import HostState, init_module_state, mark_finished, mark_running
from .utils import ReconatorError, now_iso, random_label, run_command, write_json


@dataclass
class DomainReconResult:
    fqdn: str
    derived_ips: List[str]
    resolved: Dict[str, List[str]]
    wildcard_detected: bool


def detect_wildcard(resolve_func, fqdn: str, attempts: int = 3) -> bool:
    base = fqdn.strip(".")
    hits = 0
    for _ in range(attempts):
        label = random_label()
        name = f"{label}.{base}"
        try:
            if resolve_func(name):
                hits += 1
        except Exception:
            continue
    return hits == attempts


def resolve_host_simple(hostname: str) -> List[str]:
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    ips = {item[4][0] for item in results}
    return sorted(ips)


def collect_dns_records(fqdn: str) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return records

    resolver = dns.resolver.Resolver()
    types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]
    for rtype in types:
        try:
            answers = resolver.resolve(fqdn, rtype)
        except Exception:
            continue
        values = []
        for answer in answers:
            values.append(str(answer))
        records[rtype] = values
    return records


def run_domain_recon(
    base_dir: Path,
    fqdn: str,
    subdomain_mode: str,
    dns_servers: Optional[List[str]],
    wordlist_subdomains: Optional[Path],
    timeout_s: int,
    resume: bool,
    max_procs: int,
) -> DomainReconResult:
    domain_dir = base_dir / "domain" / fqdn
    domain_dir.mkdir(parents=True, exist_ok=True)
    state_path = domain_dir / "state.json"
    state = HostState.load(state_path, engagement_name=fqdn, host=fqdn)
    module = init_module_state(state, "domain_recon")
    if module.status == "RUNNING":
        mark_finished(module, "INTERRUPTED", exit_code=module.exit_code, error="Previous run interrupted")
        state.save(state_path)
    if resume and module.status == "OK" and (domain_dir / "derived_targets.txt").exists():
        derived = (domain_dir / "derived_targets.txt").read_text(encoding="utf-8").splitlines()
        resolved = json.loads((domain_dir / "resolved.json").read_text(encoding="utf-8"))
        wildcard = json.loads((domain_dir / "state.json").read_text(encoding="utf-8")).get("wildcard_detected", False)
        return DomainReconResult(fqdn=fqdn, derived_ips=derived, resolved=resolved, wildcard_detected=wildcard)

    stdout_path = domain_dir / "stdout.log"
    stderr_path = domain_dir / "stderr.log"
    mark_running(module, "domain_recon", stdout_path, stderr_path)
    state.save(state_path)

    wildcard_detected = detect_wildcard(resolve_host_simple, fqdn)
    dns_records = collect_dns_records(fqdn)
    write_json(domain_dir / "dns_records.json", dns_records)

    subdomains: List[str] = []
    tool_used = None
    if subdomain_mode in {"passive", "both"}:
        tool_used = _run_passive_subdomain_enum(
            fqdn,
            domain_dir,
            timeout_s,
            max_procs,
        )
        if tool_used:
            subdomains.extend(_read_lines(domain_dir / "subdomains.txt"))
    if subdomain_mode in {"active", "both"}:
        if not wordlist_subdomains:
            raise ReconatorError("--wordlist-subdomains is required for active mode")
        tool_used = _run_active_subdomain_enum(
            fqdn,
            domain_dir,
            wordlist_subdomains,
            dns_servers,
            timeout_s,
        )
        if tool_used:
            subdomains.extend(_read_lines(domain_dir / "subdomains.txt"))

    subdomains = sorted(set(subdomains))
    (domain_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")

    resolved = {name: resolve_host_simple(name) for name in subdomains}
    write_json(domain_dir / "resolved.json", resolved)
    derived_ips = sorted({ip for ips in resolved.values() for ip in ips})
    (domain_dir / "derived_targets.txt").write_text("\n".join(derived_ips), encoding="utf-8")

    mark_finished(module, "OK", exit_code=0)
    state_data = state.to_dict()
    state_data["wildcard_detected"] = wildcard_detected
    state_data["last_run"] = now_iso()
    write_json(state_path, state_data)
    return DomainReconResult(
        fqdn=fqdn,
        derived_ips=derived_ips,
        resolved=resolved,
        wildcard_detected=wildcard_detected,
    )


def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _run_passive_subdomain_enum(
    fqdn: str,
    domain_dir: Path,
    timeout_s: int,
    max_procs: int,
) -> Optional[str]:
    candidates: List[Sequence[str]] = []
    if _has_tool("subfinder"):
        candidates.append(["subfinder", "-d", fqdn, "-silent"])
    if _has_tool("assetfinder"):
        candidates.append(["assetfinder", "--subs-only", fqdn])
    if _has_tool("amass"):
        candidates.append(["amass", "enum", "-passive", "-d", fqdn])

    if not candidates:
        return None
    command = candidates[0]
    stdout_path = domain_dir / "stdout.log"
    stderr_path = domain_dir / "stderr.log"
    run_command(command, stdout_path, stderr_path, timeout_s)
    subdomains = _read_lines(stdout_path)
    (domain_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
    return command[0]


def _run_active_subdomain_enum(
    fqdn: str,
    domain_dir: Path,
    wordlist: Path,
    dns_servers: Optional[List[str]],
    timeout_s: int,
) -> Optional[str]:
    if _has_tool("dnsx"):
        command = ["dnsx", "-d", fqdn, "-w", str(wordlist), "-silent"]
        if dns_servers:
            command.extend(["-r", ",".join(dns_servers)])
        stdout_path = domain_dir / "stdout.log"
        stderr_path = domain_dir / "stderr.log"
        run_command(command, stdout_path, stderr_path, timeout_s)
        subdomains = _read_lines(stdout_path)
        (domain_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
        return command[0]
    if _has_tool("massdns"):
        command = [
            "massdns",
            "-r",
            ",".join(dns_servers) if dns_servers else "/etc/resolv.conf",
            "-t",
            "A",
            "-o",
            "S",
            str(wordlist),
        ]
        stdout_path = domain_dir / "stdout.log"
        stderr_path = domain_dir / "stderr.log"
        run_command(command, stdout_path, stderr_path, timeout_s)
        subdomains = _read_lines(stdout_path)
        (domain_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
        return command[0]
    return None


def _has_tool(name: str) -> bool:
    return bool(__import__("shutil").which(name))
