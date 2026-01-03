# Nuclei

**Category:** Web

**Official Docs:** https://github.com/projectdiscovery/nuclei

**Description:** Executes fast, template-based HTTP checks for known patterns and exposures.

**Common authorized scenarios:**
- Running a scoped baseline scan on pre-approved targets.
- Validating remediation of known issues.
- Supporting asset hygiene checks during engagements.

**Minimal usage examples:**
```bash
nuclei -u https://target.example -severity low,medium,high
```
