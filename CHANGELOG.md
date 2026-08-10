# Changelog

All notable changes to **dastcore** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, the CLI and rule format may still change between
minor releases.

## [Unreleased]

### Added

- **CSV / Formula Injection** detection (CWE-1236): a new `formula_injection` oracle,
  gated on spreadsheet content types and cell boundaries so the standard `'`-prefix
  mitigation reads as safe. Added to the accuracy benchmark (now 22 vulns + 22 decoys,
  still 1.00 / 1.00 / 1.00).
- **JWT signature-not-verified / alg:none** (CWE-347): active check that forges an
  unsigned variant of a JWT bearer, with a bad-signature control so it only fires when
  the server really does verify signatures but accepts the unsigned token.
- **Serialized-object exposure** (CWE-502): passive detector for Java/PHP/pickle
  serialized objects handed to the client (an insecure-deserialization sink).
- **Cleartext credential submission** (CWE-319): passive detector for a password form
  whose action posts to an absolute `http://` URL.
- **XML Injection** (CWE-91): error-based rule that flags user input breaking XML
  parsing (SAX/lxml/expat signatures). Added to the benchmark (23 vulns + 23 decoys).
- **Dangerous HTTP methods** (CWE-749): a safe OPTIONS probe that flags PUT/DELETE/
  PATCH/CONNECT advertised in the Allow header.
- Remediation "How to fix" guides (steps + code + references) for every new class.

## [0.5.0] - 2026-08-09

A consolidated release covering the engine, precision work, the AI/LLM module, rich
reporting, the local dashboard, the cloud control-plane, and a hardened CI.

### Added

- **Detection engine**: YAML rule engine with injection points (query, body, JSON,
  header, cookie, path) and oracles (reflected, response-match, differential,
  time-based, OAST/out-of-band), with `confirm_reproducible` re-checks.
- **Vulnerability coverage**: SQLi (error + boolean-blind + time-based), reflected &
  stored/second-order XSS (`--stored`), open redirect, path traversal / LFI, SSTI,
  NoSQLi, in-band & blind OS command injection, XPath and LDAP injection, XXE, SSRF,
  Log4Shell, host-header injection, CRLF, CORS misconfiguration, HTTP TRACE / XST,
  sensitive-file & secret exposure, and passive header/cookie/info-leak checks.
- **Authorization testing**: multi-session BOLA/IDOR, BFLA and missing-auth detection
  via role identities (`--roles-file`).
- **AI/LLM module** (`dastcore ai`): OWASP LLM Top 10 coverage — prompt & indirect
  injection, jailbreak/crescendo, system-prompt leak, PII/sensitive disclosure, data
  exfiltration, insecure output, excessive agency, denial-of-wallet — with provider
  presets (OpenAI, Anthropic, Ollama, …) and streaming-endpoint support.
- **OAST**: local self-hosted collaborator and Interactsh client, correlated by a
  unique token-in-path per payload for zero-false-positive blind findings.
- **Discovery**: static HTTP crawler, headless (Playwright) engine for SPAs, plus
  OpenAPI/Swagger ingestion and GraphQL introspection.
- **Reporting**: JSON, SARIF 2.1.0 (GitHub code scanning) and a self-contained HTML
  report; CVSS 3.1 base scores/vectors, per-finding curl repro, dedup/correlation
  into issues, and cross-technique confirmation. Rich, actionable **"How to fix"**
  guidance (steps, vulnerable→secure code, references) in the HTML report, the web UI
  and SARIF `help.markdown`, from a single remediation knowledge base.
- **Local dashboard** (`dastcore serve`): run/track scans, triage suppressions
  (`.dastcore-ignore`), one-click retest, scan-to-scan diff and recurring schedules.
- **Cloud control-plane** (SaaS foundation): multi-tenant API, self-hosted runner
  protocol (claim/result/heartbeat), scheduler, and a server-rendered UI. Optional
  **PostgreSQL** backend with a durable job queue (attempts, visibility-timeout
  requeue, `FOR UPDATE SKIP LOCKED` claims).
- **Packaging**: PyPI distribution, container images (app + cloud), a Tauri desktop
  shell bundling dastcore as a PyInstaller sidecar, and a visual user manual.
- **Accuracy benchmark**: a labeled target (21 planted vulns + 21 decoys) scored for
  precision / recall / F1 — currently 1.00 / 1.00 / 1.00.
- **Retest mode**: re-verify a prior scan's findings to see what was fixed.

### Changed

- Findings deduplicate and correlate into issues; confidence is scored from oracle
  agreement plus cross-technique corroboration at the same injection point.
- Remediation guidance is centralized so HTML, SARIF and the web UI never drift.

### Fixed

- Reduced false positives: baseline/jitter timing, context-aware reflected XSS,
  soft-404 / catch-all guard for file-path rules, and two engine FPs found by
  dogfooding (JSON-response XSS, echoed-payload response-match).

### Security

- Security headers, `Secure`/`HttpOnly`/`SameSite` cookies and HSTS on the served
  apps, hardened per code-review findings.

### CI / Quality

- Lint (ruff), format check, mypy, and a test matrix on Python 3.11 / 3.12.
- Coverage gate (`pytest-cov`, 80% floor; ~86% measured).
- Dependency audit (Dependabot + `pip-audit`) and secret scanning (gitleaks).
- A **self-scan** job that runs the shipped CLI against the bundled vulnerable target
  and fails on any detection regression.
- A **PostgreSQL-backed** cloud-store job exercising the real Postgres code paths.
- A **CycloneDX SBOM** generated on release and attached to the GitHub Release
  alongside the wheel and sdist.
- `python -m dastcore` entry point; version consolidated to a single source.

## [0.1.0] - 2026-08-04

- Initial scaffold: project structure, authorization gate (`--i-have-authorization`),
  scope enforcement, async HTTP client, and the first rules.

[Unreleased]: https://github.com/Proaso17/Dastcore/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Proaso17/Dastcore/releases/tag/v0.5.0
[0.1.0]: https://github.com/Proaso17/Dastcore/releases/tag/v0.1.0
