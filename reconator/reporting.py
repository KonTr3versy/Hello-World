import csv
import json
from pathlib import Path
from typing import Dict, List

from .utils import now_iso, write_json


def build_summary(
    output_dir: Path,
    engagement_name: str,
    profile: str,
    inputs: Dict[str, str],
    scan_derived: bool,
    scope_allow_cidrs: List[str],
    hosts: List[str],
    errors: List[dict],
) -> None:
    summary_dir = output_dir / "summary"
    summary_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "engagement_name": engagement_name,
        "generated_at": now_iso(),
        "profile": profile,
        "inputs": inputs,
        "scan_derived": scan_derived,
        "scope_allow_cidrs": scope_allow_cidrs,
        "hosts": [],
        "errors": errors,
    }

    csv_rows = []
    for host in hosts:
        host_dir = output_dir / host
        services_path = host_dir / "services.json"
        services = {}
        if services_path.exists():
            services = json.loads(services_path.read_text(encoding="utf-8"))
        tls_summary = {}
        tls_path = host_dir / "tls" / "tls_summary.json"
        if tls_path.exists():
            tls_summary = json.loads(tls_path.read_text(encoding="utf-8"))
        nuclei_path = host_dir / "nuclei" / "findings.json"
        findings = {}
        if nuclei_path.exists():
            findings = json.loads(nuclei_path.read_text(encoding="utf-8"))

        ports = sorted(int(p) for p in services.keys())
        summary["hosts"].append(
            {
                "host": host,
                "open_ports": ports,
                "tls_ports": tls_summary.get("ports", []),
                "nuclei_findings": {k: len(v) for k, v in findings.items()},
            }
        )
        csv_rows.append(
            {
                "host": host,
                "open_ports": ";".join(str(p) for p in ports),
                "tls_ports": ";".join(str(p) for p in tls_summary.get("ports", [])),
                "nuclei_critical": len(findings.get("critical", [])),
                "nuclei_high": len(findings.get("high", [])),
                "nuclei_medium": len(findings.get("medium", [])),
                "nuclei_low": len(findings.get("low", [])),
                "nuclei_info": len(findings.get("info", [])),
            }
        )

    write_json(summary_dir / "summary.json", summary)
    write_json(summary_dir / "errors.json", errors)

    with (summary_dir / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host",
                "open_ports",
                "tls_ports",
                "nuclei_critical",
                "nuclei_high",
                "nuclei_medium",
                "nuclei_low",
                "nuclei_info",
            ],
        )
        writer.writeheader()
        writer.writerows(csv_rows)

    md_lines = [
        f"# Reconator Summary: {engagement_name}",
        "",
        f"Generated: {summary['generated_at']}",
        f"Profile: {profile}",
        f"Scan Derived: {scan_derived}",
        f"Scope Allow CIDRs: {', '.join(scope_allow_cidrs) if scope_allow_cidrs else 'None'}",
        "",
        "## Hosts",
    ]
    for entry in summary["hosts"]:
        md_lines.append(
            f"- {entry['host']} | Open Ports: {entry['open_ports']} | TLS Ports: {entry['tls_ports']}"
        )
    if errors:
        md_lines.append("\n## Errors/Skips")
        for err in errors:
            md_lines.append(f"- {err.get('module')}: {err.get('message')}")
    (summary_dir / "summary.md").write_text("\n".join(md_lines), encoding="utf-8")

