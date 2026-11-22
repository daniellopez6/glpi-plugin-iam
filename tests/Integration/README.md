# Integration tests (live GLPI)

`api_authz.py` checks authorization of the IAM plugin against a running GLPI 12 with the demo data loaded
(`demo_iam.php` and `demo_iam.php --profiles` from the separate demo repository). Python 3 standard library only.

## Credentials (never in this repository)

| Variable | Meaning |
| --- | --- |
| `IAM_AUTHZ_TOKENS` | JSON written by `demo_iam.php --profiles` (default `../glpi-plugin-iam-demo/tokens.json`). Per user: `password`, `api_token`. Users: `iam.analista`, `iam.dueno`, `iam.auditor`, `iam.agente`, `iam.tecnico` (entity 1) and `iam.clinica` (IAM - Analista, entity 2 only). |
| `IAM_APP_TOKEN` | App token of the GLPI API client (or `"app_token"` in the JSON). |
| `IAM_ADMIN_TOKEN` | User token of a Super-Admin (or `"admin": {"api_token": ...}` in the JSON). Used for reference reads and to remove/restore a group membership. |
| `IAM_GLPI_URL` | GLPI base URL (default `http://192.168.88.4`). |

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
- Two temporary positions are created and purged in each run.
- Re-running `demo_iam.php --profiles` rotates every password and token.
