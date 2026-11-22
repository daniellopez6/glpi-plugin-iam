# Integration tests (live GLPI)

`api_authz.py` checks authorization of the IAM plugin against a running GLPI 12 with the demo data loaded
(`demo_iam.php` and `demo_iam.php --profiles` from the separate demo repository). Python 3 standard library only.

**The suite needs a seeded GLPI**: two demo companies (Empresa A and Empresa B), their positions, resources, roles,
matrix, grants and the IAM test users. The record ids in the script refer to that data set. The demo seeder is not
published yet, so the suite cannot be run against an empty GLPI. It is not part of the release archive.

## Credentials (never in this repository)

| Variable | Meaning |
| --- | --- |
| `IAM_AUTHZ_TOKENS` | JSON written by `demo_iam.php --profiles` (default `../glpi-plugin-iam-demo/tokens.json`). Per user: `password`, `api_token`. Users: `iam.analista`, `iam.dueno`, `iam.auditor`, `iam.agente`, `iam.tecnico` (company A) and the company-B analyst (IAM - Analista, company B only; see `IAM_ENTITY_B_USER`). |
| `IAM_APP_TOKEN` | App token of the GLPI API client (or `"app_token"` in the JSON). |
| `IAM_ADMIN_TOKEN` | User token of a Super-Admin (or `"admin": {"api_token": ...}` in the JSON). Used for reference reads and to remove/restore a group membership. |
| `IAM_GLPI_URL` | GLPI base URL, **required** (or `"base_url"` in the JSON). |
| `IAM_ENTITY_A`, `IAM_ENTITY_B` | Entity ids of the two demo companies (default 1 and 2, or `"entities": {"a": .., "b": ..}` in the JSON). |
| `IAM_ENTITY_A_NAME`, `IAM_ENTITY_B_NAME` | Labels used in the output (default `Empresa A (demo)`, `Empresa B (demo)`). |
| `IAM_ENTITY_B_USER` | Login of the company-B analyst in the JSON (default `iam.empresab`, or `"entity_b_user"`). |

Keep the JSON with mode 600. Do not pass tokens on the command line: export them from a file you source.

## Run

```
python3 tests/Integration/api_authz.py
```

Prints one line per case (case, user, expected, got, PASS/FAIL), then the known plugin bugs (XFAIL, or XPASS once
fixed). Exit code 0 when every non-XFAIL case passes, 1 on any failure, 2 on a configuration error.

## Side effects (by design)

The cases never assume fixed row counts: lists are compared with what an administrator reads in the same run, so the
rows left by earlier runs do not change the result.

- Each run adds one grant (`source=agent`, justification `[iam-authz] T13 run ...`) and one note on it: the register is
  append-only by design and cannot be purged.
- The Review Focus 4 case removes `iam.dueno` from the owner group of SAP-FI and restores it in a `finally` block
  (new `Group_User` row with the same flags).
- Three temporary positions (one with a matrix cell, removed through the matrix) and one temporary resource linked to
  a Software item are created and purged in each run.
- The leaver cases remove every authorization (`Profile_User`) of the inactive person of grant 17 and restore them in
  a `finally` block (new rows with the same profile, entity and flags).
- Re-running `demo_iam.php --profiles` rotates every password and token.
