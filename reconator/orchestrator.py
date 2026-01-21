import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import BoundedSemaphore
from typing import Dict, List, Optional

from .domain_recon import run_domain_recon
from .ffuf import run_ffuf
from .nmap import derive_web_urls, run_nmap
from .nuclei import run_nuclei
from .parsing import filter_targets_by_scope, parse_targets_file
from .reporting import build_summary
from .sslscan import run_sslscan
from .state import HostState, init_module_state, mark_finished
from .utils import (
    ReconatorError,
    ensure_writable_dir,
    normalize_engagement_name,
    set_subprocess_semaphore,
    write_json,
)


def detect_tools() -> Dict[str, Optional[str]]:
    tools = ["nmap", "sslscan", "ffuf", "nuclei", "subfinder", "assetfinder", "amass", "dnsx", "massdns"]
    versions = {}
    for tool in tools:
        path = shutil.which(tool)
        versions[tool] = path
    return versions


def orchestrate(args) -> None:
    engagement_name = normalize_engagement_name(args.engagement_name)
    output_dir = Path(args.output).expanduser().resolve() / engagement_name
    ensure_writable_dir(output_dir)

    errors: List[dict] = []
    meta_dir = output_dir / "_meta"
    meta_dir.mkdir(parents=True, exist_ok=True)

    tools = detect_tools()
    (meta_dir / "tool_versions.txt").write_text(
        "\n".join(f"{name}: {path or 'missing'}" for name, path in tools.items()),
        encoding="utf-8",
    )

    if args.input is None and args.fqdn is None:
        raise ReconatorError("--input or --fqdn must be provided")

    targets: List[str] = []
    if args.input:
        parse_result = parse_targets_file(Path(args.input), args.allow_cidr_expand, args.cidr_cap)
        targets = parse_result.targets
        (meta_dir / "targets_resolved.txt").write_text("\n".join(targets), encoding="utf-8")
        if parse_result.skipped:
            errors.append(
                {
                    "module": "input",
                    "message": "Skipped invalid targets",
                    "items": parse_result.skipped,
                }
            )

    derived_targets: List[str] = []
    if args.fqdn:
        if args.only and args.only != "domain_recon":
            pass
        else:
            domain_result = run_domain_recon(
                output_dir,
                args.fqdn,
                args.subdomain_mode,
                args.dns_servers,
                Path(args.wordlist_subdomains) if args.wordlist_subdomains else None,
                args.timeout_nmap,
                args.resume,
                args.max_procs,
            )
            derived_targets = domain_result.derived_ips

    final_targets = list(targets)
    if args.scan_derived and derived_targets:
        scoped = filter_targets_by_scope(derived_targets, args.scope_allow_cidrs)
        if args.scope_allow_regex:
            import re

            allow_re = re.compile(args.scope_allow_regex)
            scoped = [target for target in scoped if allow_re.search(target)]
        if args.scope_deny_regex:
            import re

            deny_re = re.compile(args.scope_deny_regex)
            scoped = [target for target in scoped if not deny_re.search(target)]
        final_targets.extend(scoped)
        out_of_scope = sorted(set(derived_targets) - set(scoped))
        if out_of_scope:
            errors.append(
                {
                    "module": "domain_recon",
                    "message": "Derived targets out of scope",
                    "items": out_of_scope,
                }
            )
    (meta_dir / "final_targets.txt").write_text("\n".join(sorted(set(final_targets))), encoding="utf-8")

    run_meta = {
        "engagement_name": engagement_name,
        "profile": args.profile,
        "inputs": {"input": args.input, "fqdn": args.fqdn},
        "scan_derived": args.scan_derived,
    }
    write_json(meta_dir / "run.json", run_meta)

    if args.dry_run:
        return

    semaphore = BoundedSemaphore(args.max_procs)
    set_subprocess_semaphore(semaphore)

    def process_host(host: str) -> None:
        host_dir = output_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        state_path = host_dir / "state.json"
        state = HostState.load(state_path, engagement_name=engagement_name, host=host)
        state.save(state_path)

        if args.only and args.only != "nmap":
            return
        if args.skip_nmap or not tools.get("nmap"):
            module = init_module_state(state, "nmap")
            status = "SKIPPED_MISSING_TOOL" if not tools.get("nmap") else "SKIPPED"
            mark_finished(module, status, exit_code=None, error="nmap unavailable")
            state.save(state_path)
            errors.append({"module": "nmap", "host": host, "message": status})
            return
        services = run_nmap(host_dir, host, args.timeout_nmap, args.resume)
        if not services:
            return

        if args.only and args.only != "sslscan":
            return
        if not args.skip_ssl and tools.get("sslscan"):
            run_sslscan(host_dir, host, services, args.timeout_sslscan, args.resume)
        elif args.skip_ssl:
            module = init_module_state(state, "sslscan")
            mark_finished(module, "SKIPPED", exit_code=None, error="sslscan skipped")
            state.save(state_path)
            errors.append({"module": "sslscan", "host": host, "message": "SKIPPED"})
        elif not tools.get("sslscan"):
            module = init_module_state(state, "sslscan")
            mark_finished(
                module, "SKIPPED_MISSING_TOOL", exit_code=None, error="sslscan missing"
            )
            state.save(state_path)
            errors.append(
                {"module": "sslscan", "host": host, "message": "SKIPPED_MISSING_TOOL"}
            )

        urls = derive_web_urls(host, services)

        if args.only and args.only != "ffuf":
            return
        if not args.skip_ffuf and tools.get("ffuf"):
            run_ffuf(host_dir, host, urls, args.timeout_ffuf, args.resume)
        elif args.skip_ffuf:
            module = init_module_state(state, "ffuf")
            mark_finished(module, "SKIPPED", exit_code=None, error="ffuf skipped")
            state.save(state_path)
            errors.append({"module": "ffuf", "host": host, "message": "SKIPPED"})
        elif not tools.get("ffuf"):
            module = init_module_state(state, "ffuf")
            mark_finished(
                module, "SKIPPED_MISSING_TOOL", exit_code=None, error="ffuf missing"
            )
            state.save(state_path)
            errors.append(
                {"module": "ffuf", "host": host, "message": "SKIPPED_MISSING_TOOL"}
            )

        if args.only and args.only != "nuclei":
            return
        if not args.skip_nuclei and tools.get("nuclei"):
            run_nuclei(host_dir, host, urls, args.profile, args.timeout_nuclei, args.resume)
        elif args.skip_nuclei:
            module = init_module_state(state, "nuclei")
            mark_finished(module, "SKIPPED", exit_code=None, error="nuclei skipped")
            state.save(state_path)
            errors.append({"module": "nuclei", "host": host, "message": "SKIPPED"})
        elif not tools.get("nuclei"):
            module = init_module_state(state, "nuclei")
            mark_finished(
                module, "SKIPPED_MISSING_TOOL", exit_code=None, error="nuclei missing"
            )
            state.save(state_path)
            errors.append(
                {"module": "nuclei", "host": host, "message": "SKIPPED_MISSING_TOOL"}
            )

    with ThreadPoolExecutor(max_workers=args.max_hosts) as executor:
        futures = {executor.submit(process_host, host): host for host in final_targets}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                errors.append(
                    {
                        "module": "host",
                        "host": futures[future],
                        "message": str(exc),
                    }
                )

    build_summary(
        output_dir,
        engagement_name,
        args.profile,
        {"input": args.input or "", "fqdn": args.fqdn or ""},
        args.scan_derived,
        args.scope_allow_cidrs or [],
        final_targets,
        errors,
    )
