import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from .utils import ReconatorError, dedupe_sorted


@dataclass
class TargetParseResult:
    targets: List[str]
    skipped: List[str]


def parse_targets_file(
    path: Path,
    allow_cidr_expand: bool,
    cidr_cap: int,
) -> TargetParseResult:
    if not path.exists():
        raise ReconatorError(f"Targets file does not exist: {path}")
    targets: List[str] = []
    skipped: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "/" in line:
                if not allow_cidr_expand:
                    skipped.append(line)
                    continue
                network = ipaddress.ip_network(line, strict=False)
                hosts = list(network.hosts())
                if len(hosts) > cidr_cap:
                    raise ReconatorError(
                        f"CIDR {line} exceeds cap of {cidr_cap} hosts"
                    )
                targets.extend(str(ip) for ip in hosts)
            else:
                ipaddress.ip_address(line)
                targets.append(line)
        except ValueError:
            skipped.append(line)
    return TargetParseResult(targets=dedupe_sorted(targets), skipped=skipped)


def filter_targets_by_scope(
    targets: Iterable[str],
    allow_cidrs: Optional[List[str]],
) -> List[str]:
    if not allow_cidrs:
        return []
    networks = [ipaddress.ip_network(item, strict=False) for item in allow_cidrs]
    filtered = []
    for target in targets:
        ip = ipaddress.ip_address(target)
        if any(ip in network for network in networks):
            filtered.append(target)
    return dedupe_sorted(filtered)

