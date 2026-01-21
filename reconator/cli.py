import argparse

from .orchestrator import orchestrate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reconator: authorized recon orchestration")
    parser.add_argument("--engagement-name", required=True)
    parser.add_argument("--input")
    parser.add_argument("--fqdn")
    parser.add_argument("--output", default="./output")
    parser.add_argument("--profile", choices=["safe", "standard", "aggressive"], default="safe")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--dry-run", action="store_true")

    parser.add_argument("--max-hosts", type=int, default=5)
    parser.add_argument("--max-procs", type=int, default=10)

    parser.add_argument("--timeout-nmap", type=int, default=900)
    parser.add_argument("--timeout-sslscan", type=int, default=300)
    parser.add_argument("--timeout-ffuf", type=int, default=300)
    parser.add_argument("--timeout-nuclei", type=int, default=900)

    parser.add_argument("--subdomain-mode", choices=["passive", "active", "both"], default="passive")
    parser.add_argument("--dns-servers")
    parser.add_argument("--wordlist-subdomains")
    parser.add_argument("--scan-derived", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--scope-allow-cidrs")
    parser.add_argument("--scope-allow-regex")
    parser.add_argument("--scope-deny-regex")

    parser.add_argument("--skip-nmap", action="store_true")
    parser.add_argument("--skip-ssl", action="store_true")
    parser.add_argument("--skip-ffuf", action="store_true")
    parser.add_argument("--skip-nuclei", action="store_true")
    parser.add_argument("--only", choices=["domain_recon", "nmap", "sslscan", "ffuf", "nuclei"])

    parser.add_argument("--allow-cidr-expand", action="store_true")
    parser.add_argument("--cidr-cap", type=int, default=4096)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.dns_servers = args.dns_servers.split(",") if args.dns_servers else None
    args.scope_allow_cidrs = (
        [item.strip() for item in args.scope_allow_cidrs.split(",") if item.strip()]
        if args.scope_allow_cidrs
        else None
    )
    orchestrate(args)


if __name__ == "__main__":
    main()
