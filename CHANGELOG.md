# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## 1.0.0 - 2026-11-22
- Positions (tree by area), person-to-position assignments with type and active period, resources linked to any
  GLPI inventory item with owner and criticality, and roles per resource (standard, sensitive, privileged, break-glass).
- Position x role access matrix (allowed, on request, forbidden) with a visual, collapsible view, filters, in-place
  editing and an on-demand nominal panel per cell.
- Access register (grants) with ticket, approver, security approver, expiry, MFA and justification; revoke instead of
  delete; segregation of duties between registrar, beneficiary and approvers.
- Append-only permanent audit notes on grants, resources and assignments.
- Quick case search, tabs on users, tickets and inventory items.
- Four role profiles (Analista, Dueño de activo, Auditor, Agente), rights per profile and entity, "own resources" scope.
- REST API for AI agents with stable `[code]` error prefixes; authorization identical to the UI.
- In-app help: "Help and glossary" page by role, collapsible "What is this?" boxes and field tooltips (ISO 27001:2022 references), matrix legend; user manual (`docs/manual-usuario.md`) and AI-agent API guide (`docs/api-agente.md`).
- Security review (OWASP ASVS 4.0 L2) in `docs/revision-seguridad.md` and live API authorization tests (`tests/Integration`).
- Plugin tooling: PHPUnit, PHPCS, PHPStan, Semgrep and CI. Locales: es_AR, es_ES.
- Not included yet (planned for 1.1-1.3): deviation engine, GRC Manager waivers, recertification campaigns, reports, privileged access (A.8.2) checks.
- Upgrade note: the installer never modifies existing role profiles. An existing "IAM - Agente" profile needs the core right `user` READ set manually (Administration > Profiles > Assets/Administration > Users: read).
