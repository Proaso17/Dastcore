# Changelog

All notable changes to **dastcore** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, the CLI and rule format may still change between
minor releases.

## [Unreleased]

### Changed

- **LLM improper output handling (LLM05) precision**: the insecure-output check now confirms
  via a `markup` oracle that verifies the canary landed inside an *executable* HTML/markdown
  sink in the model's answer (a `<script>` body, an `on*` event handler, a `javascript:`/
  `data:` URL) — not merely that the token appeared as text (which a refusal or paraphrase
  produces). Payloads cover script, event-handler, SVG and markdown-link sinks.
- **PII-disclosure oracle precision**: the phone detector no longer treats a bare digit
  run (an order number, an account id, a unix timestamp) as a phone number — a match now
  needs 10–15 digits *and* an international `+` prefix or human formatting (space/dash/
  paren/dot). Formatted phones and the other PII types (email, card via Luhn, SSN) are
  unaffected.
- **System-prompt-leak (LLM07) precision**: the loose persona pattern (`You are [A-Z]…`,
  which matched conversational "You are asking/right/welcome") now requires a role keyword
  to follow; strong signals (leaked instructions/rules, `SECRET_KEY`, `sk-…`) are kept.
- **Resilient multi-probe LLM scans**: an embedded-chatbot scan (`ai --discover`) no longer
  aborts if a single probe hits a transient network error/timeout — the chat client is
  `tolerant` in discovery (empty answer for that probe), while the direct `ai <url>` mode
  still surfaces an unreachable endpoint. Fixes a flaky web-dashboard AI scan under load.
- **Time-based blind SQLi precision (proportional-delay confirmation)**: a single slow
  response is no longer enough. The scanner now sends the same injection with three sleep
  values — 0 (control), D and 2D — and confirms only when the *added* delay both clears the
  threshold/jitter and **scales with the injected sleep** (SLEEP(2D) adds clearly more than
  SLEEP(D)). A constantly-slow endpoint, a network spike, or heavy payload parsing can't
  produce that proportionality, so they no longer false-positive; the timing probe is also
  removed from the in-band payload loop so timing is confirmed only through this path. A
  real time-based positive was added to the accuracy benchmark (1.00 / 1.00 / 1.00, now
  25 vulns + 25 decoys).
- **Boolean-blind SQLi precision**: the boolean oracle now abstains when the page isn't
  stable across repeated identical requests (after masking known volatile regions). A
  page with its own rotating content (a "promo of the day" banner, a shifting widget)
  could otherwise make the FALSE-vs-baseline difference look like an injection signal —
  a false positive. The baseline is now sampled for boolean rules too (not only timing),
  so stability can be judged. The benchmark's stable boolean positive still detects
  (1.00 / 1.00 / 1.00 unchanged).
- **Open-redirect precision**: a new target-host oracle confirms the redirect's actual
  destination host is the injected probe, instead of matching the probe string anywhere
  in the `Location` header. A same-origin URL that reflects the probe in a query param
  (`Location: /login?next=https://probe/`) — a common "return to" pattern — is no longer
  a false positive; backslash/tab bypasses and the `Refresh` header are normalized like a
  browser, and a protocol-relative probe payload was added for recall. A dedicated decoy
  in the accuracy benchmark locks it in (still 1.00 / 1.00 / 1.00, now 24 vulns + 25 decoys).

### Added

- **Embedded-chatbot auto-discovery** (`dastcore ai <app-url> --discover`): crawls a
  web app (headless when available, else static), auto-detects the chat endpoint from
  captured traffic — inferring the prompt field / `messages[]` template, the answer
  dot-path, and streaming — and runs the LLM rule set against it, no hand-config. The
  detector is conservative (requires a request-side *and* a response-side chat signal)
  so ordinary CRUD/login JSON APIs are never mistaken for a chatbot.
- **Stored / second-order indirect prompt injection** (CWE-77, LLM01): the flagship
  check for RAG assistants. Plants a hidden instruction through an app write endpoint
  (a message, a maintenance note, a profile field) and confirms the assistant *executes
  it on retrieval* by returning a fresh per-attempt canary — false-positive-free like
  OAST (echoing/summarizing the note can't produce the canary). Wired into `--discover`
  (write endpoints are inferred from the crawl) and unit-tested against a multi-tenant
  chatbot fixture, including a hardened-assistant negative control.
- **Cross-tenant data leakage via the assistant** (BOLA through the LLM, CWE-639,
  API1:2023): with two authenticated identities (`--victim-bearer` + `--victim-ref`),
  the victim plants a fresh canary in their own data and the attacker's assistant is
  steered to read it; a finding fires only when the attacker's answer returns the
  victim's canary — proving the retrieval layer isn't scoped per tenant. Same-tenant and
  unknown-reference negative controls keep it false-positive-free.
- **Unauthorized cross-tenant action via the assistant** (excessive agency / BFLA through
  the LLM, CWE-862, API5:2023): for assistants that can *act* (post, cancel, message), the
  attacker steers the assistant to write a fresh canary into the **victim's** account, and
  the effect is verified out-of-band by reading the victim's own state — a finding fires
  only when the canary actually landed there, proving the tool has no per-tenant
  authorization or confirmation gate. Silent against an assistant that refuses tool calls
  and against actions targeting the attacker's own account.
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
- **JWT weak HMAC secret** (CWE-347): re-signs the bearer with a list of common secrets
  (HS256/384/512) and reports if one is accepted, with the same bad-signature control.
- **Session token in URL** (CWE-598): passive detector for a session/auth token carried
  in a query string (leaks via history/logs/Referer).
- **Shellshock** (CVE-2014-6271, CWE-78): active check that injects a bash env-function
  payload into request headers and confirms by the marker echo (in-band).
- **LFI via PHP filter wrapper** (CWE-98): a `php_filter` oracle that confirms source
  disclosure by decoding a `php://filter` base64 response to a `<?php` tag. In the
  benchmark (24 vulns + 24 decoys).
- **Known-vulnerable component detection** (SCA-lite, A06:2021): fingerprints product +
  version (Server/X-Powered-By headers, generator meta, client-side jQuery/Bootstrap
  assets) and matches a bundled, offline advisory DB (`dastcore/vulndb/advisories.yaml`)
  with a version-range matcher. Reported at medium confidence (version-banner based).
  Extensible by adding a YAML entry.
- **NVD sync** for the advisory DB: `scripts/sync_nvd.py` refreshes `advisories.yaml`
  from the NVD API 2.0 (run by hand, never at scan time). The CVE→advisory translation
  (`dastcore/vulndb/nvd.py`) is pure and unit-tested; the merge de-dupes and preserves
  curated entries. `--since-days` / `--min-severity` keep the diff small. A weekly CI
  workflow (`.github/workflows/nvd-sync.yml`) opens a review PR — never auto-merges.
- **Embedded-chatbot scan in the web dashboard** (`dastcore serve`): the new form mode
  "Chatbot embebido (IA / OWASP LLM)" launches the `ai --discover` pipeline from the UI —
  crawl, auto-detect the bot, run the LLM checks — with an optional second identity
  (victim bearer + references) for the cross-tenant read/action checks. Results, the
  attack-chain narrative and remediation appear in the same panel/report as any other
  scan; the run is labelled "chatbot IA" in history.
- **Chatbot discovery hardening** (precision + recall): GraphQL endpoints (whose `query`
  field looks prompt-like) are now excluded outright; prompt fields nested one level deep
  (`{"data":{"message":…}}`) are detected and driven via a generated `{{prompt}}` template;
  an OpenAI-style `messages[]` body now counts as a strong signal even at an unhinted URL.
  Confidence is graded and the `--discover` flow no longer auto-attacks `low`-confidence
  (ambiguous) candidates — it reports them for a human to confirm, so a translate/search
  API is never fuzzed as if it were a chatbot. Covered by adversarial detector tests.
- **Stored-injection oracle robustness**: the planted note stacks several equivalent
  instruction phrasings and the retrieval triggers are more varied, so the check lands
  against bots that obey one wording but not another — recall up, confirmation still
  canary-gated (no false positives).
- **Attack-chain narrative** in the HTML report: multi-stage findings (stored prompt
  injection, cross-tenant read/action) now carry an ordered `attack_chain` (actor →
  action → detail) rendered as a numbered flow, so the report tells the story
  (plant → retrieve → execute; victim plants → attacker reads/writes → verify) instead
  of listing disconnected evidence. Ordinary findings are unchanged.
- Remediation "How to fix" guides (steps + code + references) for every new class,
  now including rich, class-specific guidance for the **LLM findings** (prompt injection,
  stored/second-order injection, cross-tenant read (BOLA) and action (BFLA/excessive
  agency), plus a generic LLM guide) with OWASP LLM Top 10 / API Security references —
  shared across the HTML report, SARIF `help.markdown` and the web UI.

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
