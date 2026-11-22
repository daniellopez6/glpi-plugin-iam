# IAM - Identity & Access Governance for GLPI

![logo](iam.png) Role-based access governance for **GLPI 12**, aligned with **ISO/IEC 27001:2022**.
Answer "who should have access to what, who actually has it, and who approved it" for the business applications
and resources already registered in your GLPI inventory.

> Status: **1.0.0 (beta)**. Available in English, Spanish (Argentina) and Spanish (Spain).

![Access matrix with the people of a cell open](docs/screenshots/matrix.png)

## What 1.0 does

- **Positions** (organisation functions grouped in areas, tree) and **person-to-position assignments** with
  holder / substitute / temporary type and active period. A person may hold several positions; only active ones
  count for the expected access.
- **Resources**: any GLPI inventory item (computer, software, appliance, network equipment, custom assets...) is
  registered as a protected resource with an owner (user or group), criticality and review frequency. A tab on the
  inventory item shows its roles and accesses.
- **Roles** per resource with level (standard / sensitive / privileged) and break-glass flag.
- **Access matrix** (position x resource/role): allowed, on request or forbidden. The visual matrix collapses to
  resource level, expands per resource, filters by area/resource/privileged and opens a **nominal panel per cell**
  (the people behind it, loaded on demand). It highlights gaps between the expected and the real access, computed
  at request time. Cells can be edited in place by users with the right.
- **Access register (grants)**: a named access of a person on a role with ticket, approver, security approver,
  expiry, MFA flag and justification. Grants are never deleted: they are revoked. Tabs on users and tickets.
- **Permanent audit notes**: append-only notes on grants, resources and assignments. Nobody can edit or delete them.
- **Quick case search** across grants, people, resources and tickets.
- **In-app help and glossary** by role, "What is this?" boxes with ISO 27001:2022 references.
- **Role-based access** per profile and entity, with an "own resources" scope for asset owners, and four
  ready-to-assign profiles (see below). Entity of every record follows the entity of the resource.
- **REST API** (`GlpiPlugin\Iam\*`) with stable `[code]` error prefixes for AI agents, same authorization as the UI
  (see [docs/api-agente.md](docs/api-agente.md), Spanish).

## ISO/IEC 27001:2022 controls covered

| Control | How 1.0 supports it |
| --- | --- |
| A.5.3 Segregation of duties | Registrar, beneficiary, approver and security approver must differ; forbidden cells in the matrix. |
| A.5.15 Access control | Expected access by position (RBAC matrix) and the register of what was granted. |
| A.5.16 Identity management | Link between GLPI persons, positions and their accesses. |
| A.5.18 Access rights | Request ticket, approval, expiry, revocation and append-only history of each grant. |
| A.8.2 Privileged access rights | Privileged roles are flagged and shown (shield icon, filter). **Not enforced or validated in 1.0.** |

The plugin supports your ISMS evidence; it does not make an organisation compliant on its own.

## Profiles and rights

The installer creates four profiles (existing profiles are never modified):

| Profile | Purpose |
| --- | --- |
| IAM - Analista | Maintains catalogue, matrix and register. Does not review or approve. |
| IAM - Dueño de activo | Sees and updates only the resources they own. |
| IAM - Auditor | Read-only on everything, including the catalogue. |
| IAM - Agente | Registers requests and grants, reads the catalogue (for API/AI agents). Cannot review or approve. |

Rights: `plugin_iam` (access), `plugin_iam_config` (catalogue and matrix), `plugin_iam_review`,
`plugin_iam_approve` and `plugin_iam_report`, configurable in Administration > Profiles > "Access governance (IAM)".
Tabs on core items (User, Ticket, inventory) additionally need the core read right of that item type.

## What 1.0 does NOT do (yet)

- No persistent **deviation engine** (segregation-of-duties rules, orphan and mover detection, expired grants): the
  matrix only highlights gaps live.
- No **exceptions/waivers** through GLPI GRC Manager.
- No **recertification campaigns** by owners.
- No **reports** (owner report, global PDF, point-in-time matrix, CSV).
- No **privileged access (A.8.2) checks**: expiry, MFA, separate account and security approval are recorded but not
  validated or blocking.
- No automatic joiner/mover/leaver lifecycle and no CSV import.

## Roadmap

| Release | Scope |
| --- | --- |
| 1.1 | Full deviation engine, GRC Manager exceptions, privileged-access checks, segregation-of-duties rules, dashboard, point-in-time matrix (CSV). |
| 1.2 | "My assets" for owners, recertification campaigns, GRC evidence, owner and global PDF reports with fingerprint. |
| 1.3 | Automatic lifecycle (movers/leavers), CSV import, per-control evidence package and sampling. |

## Screenshots

![Quick case search](docs/screenshots/search.png)

![In-app help](docs/screenshots/help.png)

(Screenshots show the Spanish interface with fictitious demo data.)

## Installation

Requirements: **GLPI 12.0.x**, **PHP 8.2** or later.

```bash
cd /path/to/glpi/plugins
tar xjf glpi-iam-x.y.z.tar.bz2          # creates the "iam" directory
php ../bin/console plugin:install -u glpi iam
php ../bin/console plugin:activate iam
php ../bin/console cache:clear
```

Logged-in users must log in again (or switch profile) to see the new menu. Upgrade note: the installer never
modifies existing role profiles; an existing "IAM - Agente" profile needs the core right `user` READ set manually.

Documentation (Spanish): [user manual](docs/manual-usuario.md), [AI-agent API guide](docs/api-agente.md).

## Security

The plugin follows OWASP ASVS 4.0 level 2 practices: parameterised queries only, CSRF and rights checked on every
write, whitelisted item types, immutable fields, append-only evidence and no personal data in logs. See the
[security review](docs/revision-seguridad.md) (Spanish) and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Development

```bash
composer install
composer lint        # PSR-12
composer analyse     # PHPStan (needs the parent GLPI sources)
composer test        # PHPUnit
python3 tools/extract_locales.py && python3 tools/build_po.py   # refresh locales (requires Babel)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the release checklist.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
