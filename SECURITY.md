# Security policy

## Supported versions
Only the latest 1.x release receives security fixes.

## Reporting a vulnerability
Please **do not open a public issue**. Report it privately through GitHub Security Advisories
("Security" tab → "Report a vulnerability") with the affected version, steps to reproduce and impact.
You will get an answer within 7 days; a fix and an advisory will be published once a patched release is available.

## Security design
Reference: OWASP ASVS 4.0 level 2.
- No hand-built SQL: all queries go through the GLPI DB iterator.
- Every POST/AJAX entry point checks the CSRF token and the user's rights server-side.
- Polymorphic `itemtype` values are validated against a whitelist before use.
- Immutable fields are dropped from input; the entity of a child record always comes from its parent.
- Grants and audit notes are never purged.
- No secrets or personal data in logs.
- Twig templates do not use `|raw` unless the content went through GLPI's sanitizer.
