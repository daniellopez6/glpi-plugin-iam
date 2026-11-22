# Contributing

Thanks for your interest in improving the IAM plugin.

## Workflow
1. Open an issue describing the bug or the feature before large changes.
2. Fork the repository and create a branch from `main` (`fix/...`, `feat/...`).
3. Keep pull requests small and focused; update `CHANGELOG.md`.

## Coding rules
- PSR-12 (`composer lint`) and PHPStan level 6 (`composer analyse`); both run in CI, together with Semgrep.
- New PHP classes in `src/` under the `GlpiPlugin\Iam` namespace, with a docblock on every method.
- Database access only through the GLPI DB iterator. No raw SQL.
- Every `front/` or `ajax/` entry point must check CSRF and rights.
- Templates in Twig (`templates/`); do not use `|raw`.
- User-facing strings in English through `__('...', 'iam')` / `_n(...)`; then run `tools/extract_locales.py`,
  add the Spanish translation in `tools/translations_es.py` and run `tools/build_po.py`.

## Release checklist
1. `phpcbf`, then `phpcs`.
2. `phpunit`.
3. PHPStan (read the output; a docker chain does not stop on errors).
4. Semgrep (`semgrep --config p/php --config p/owasp-top-ten --config .semgrep.yml --exclude .github --error`).
5. Regenerate locales after any string change.
6. Push and wait for CI to be green.
7. Only then `gh release create 1.0.0`.
