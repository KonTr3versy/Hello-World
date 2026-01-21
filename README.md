# Reconator

Reconator is a Python 3 CLI tool for orchestrating **authorized** reconnaissance and scanning workflows. It focuses on reliability, resumability, and structured outputs suitable for reporting.

## Installation

```bash
pip install -e .
```

### Prerequisites

Reconator shells out to external tools when available:

- `nmap`
- `sslscan`
- `ffuf`
- `nuclei`
- Optional for domain recon: `subfinder`, `assetfinder`, `amass`, `dnsx`, `massdns`

If a tool is missing, Reconator marks the module as skipped and continues where possible.

## Usage

> **Warning:** Only run this tool against systems you are explicitly authorized to test.

### IP-only scan

```bash
reconator \
  --engagement-name "Acme_Internal" \
  --input targets.txt
```

### FQDN recon only (no scanning of derived targets)

```bash
reconator \
  --engagement-name "Acme_DNS" \
  --fqdn example.com \
  --only domain_recon
```

### Combined scan (inputs + domain recon)

```bash
reconator \
  --engagement-name "Acme_Combined" \
  --input targets.txt \
  --fqdn example.com
```

### Scan derived targets with scope controls

```bash
reconator \
  --engagement-name "Acme_Scoped" \
  --fqdn example.com \
  --scan-derived \
  --scope-allow-cidrs 203.0.113.0/24,198.51.100.0/24
```

## Output Layout

All outputs live under `<output>/<engagement-name>/`.

```
<output>/<engagement-name>/
  _meta/
    run.json
    tool_versions.txt
    targets_resolved.txt
    final_targets.txt
  domain/
    <fqdn>/
      state.json
      dns_records.json
      subdomains.txt
      resolved.json
      derived_targets.txt
      stdout.log
      stderr.log
  <ip>/
    state.json
    nmap/
      triage.xml
      followup.xml
      ports.txt
      stdout.log
      stderr.log
    services.json
    tls/
      sslscan_<port>.txt
      tls_summary.json
    web/
      urls.txt
      ffuf_<port>.json
      ffuf_hits.json
    nuclei/
      results.jsonl
      findings.json
  summary/
    summary.json
    summary.md
    summary.csv
    errors.json
```

## Notes

- Derived targets from domain recon are **not** scanned unless `--scan-derived` is set.
- When `--scan-derived` is enabled, only targets within `--scope-allow-cidrs` are scanned.
- Use `--resume/--no-resume` to control resumability.

