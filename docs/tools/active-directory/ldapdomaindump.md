# LDAPDomainDump

**Category:** Active Directory

**Official Docs:** https://github.com/dirkjanm/ldapdomaindump

**Description:** Exports LDAP objects to HTML/JSON for quick domain inventory review.

**Common authorized scenarios:**
- Capturing user and group listings for access review.
- Exporting machine accounts to validate scope coverage.
- Documenting baseline identity data for reporting.

**Minimal usage examples:**
```bash
ldapdomaindump -u 'DOMAIN\\USER' -p 'PASSWORD' ldap://DC_HOST
```
