# BloodHound

**Category:** Active Directory

**Official Docs:** https://github.com/BloodHoundAD/BloodHound

**Description:** Graphs Active Directory relationships to identify high-value attack paths for authorized assessments.

**Common authorized scenarios:**
- Mapping domain trust relationships during a scoped internal assessment.
- Identifying misconfigurations that enable excessive privilege paths.
- Supporting remediation planning with visualized access paths.

**Minimal usage examples:**
```bash
bloodhound-python -u USER -p PASS -d DOMAIN -c All
```
