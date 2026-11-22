# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## 1.0.0 - unreleased
- Plugin skeleton, tooling (PHPUnit, PHPCS, PHPStan, Semgrep) and CI.
- In-app help: "Help and glossary" page by role, collapsible "What is this?" boxes and field tooltips (ISO 27001:2022 references), matrix legend; user manual (`docs/manual-usuario.md`) and AI-agent API guide (`docs/api-agente.md`).
- Upgrade note: the installer never modifies existing role profiles. An existing "IAM - Agente" profile needs the core right `user` READ set manually (Administration > Profiles > Assets/Administration > Users: read).
