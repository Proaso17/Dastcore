# PROMPT — Construcción de `dastcore` (Dynamic Application Security Testing)

> **Instrucciones de uso:** Este archivo es un prompt maestro para Claude Code. Está diseñado para construir de forma **incremental por fases**, con salidas completas y ejecutables en cada fase (nada de esqueletos vacíos ni `TODO`).

---

## 0. Contexto de producto

`dastcore` es un escáner de seguridad de aplicaciones **dinámico** (caja negra) escrito en **Python 3.11+**. Es el gemelo dinámico de `sastcore` (mismo autor, mismo estilo de motor de reglas YAML) con el objetivo de correlacionar hallazgos estáticos y dinámicos en un futuro.

- **Problema que resuelve:** las herramientas open source generales (ZAP, Wapiti) tienen muchos falsos positivos, mala cobertura de SPAs modernas y casi nula detección de fallos de autorización a nivel de objeto (BOLA/IDOR). Los equipos que trabajan con stacks modernos (Next.js + Supabase, GraphQL, APIs REST) no tienen una opción ligera y precisa.
- **Diferenciadores (no negociables):**
  1. **Crawler dual**: HTTP estático + headless (Playwright) para SPAs y endpoints XHR/fetch.
  2. **Descubrimiento de API por esquema**: OpenAPI/Swagger 2.0/3.x + introspección GraphQL.
  3. **OAST**: confirmación out-of-band de vulnerabilidades ciegas (blind SSRF/RCE/XXE) → cero falsos positivos en esa clase.
  4. **Multi-sesión BOLA/BFLA/IDOR**: dos sesiones autenticadas con roles distintos para detectar fallos de autorización.
  5. **Bajo ruido**: cada hallazgo debe pasar un oráculo de validación (diferencial, temporal o OAST) antes de reportarse.
- **Salidas:** JSON, **SARIF 2.1.0** (para CI/CD), y reporte HTML autocontenido.
- **Cliente objetivo:** consultoras de pentesting, equipos DevSecOps de pymes/startups, freelances de seguridad. Modelo: CLI open source + versión SaaS/Cloud (reportes, scheduling, multi-target) monetizable.

---

## 1. Reglas de trabajo (para el agente)

1. **Ética y legalidad ANTES que nada.** DAST es intrusivo. El escaneo NO arranca sin un flag explícito de autorización (`--i-have-authorization`) y una configuración de *scope* con allowlist de dominios. Cualquier request fuera de scope se bloquea a nivel de motor, no de configuración. Incluye un banner legal al inicio de cada scan.
2. **Construcción incremental.** Completa una fase, deja el proyecto ejecutable y con tests que pasan, y solo entonces pasa a la siguiente. Nunca dejes `pass`, `NotImplementedError` ni funciones vacías salvo que se indique explícitamente.
3. **Scripts `.py`, no notebooks.** OOP y tipado (`typing`, `pydantic` para modelos).
4. **Async por defecto** para el motor de red (`httpx.AsyncClient` + `asyncio`). Rate limiting y concurrencia configurables.
5. **Reglas en YAML** con el mismo espíritu que `sastcore` (motor genérico + reglas declarativas). Un detector nuevo debería poder añadirse escribiendo un YAML, no código.
6. **Tests con `pytest`** por fase, usando un target vulnerable local (ver Fase 0.5). Nada de golpear internet en los tests.
7. **Salida directa y usable.** Al terminar cada fase, muéstrame cómo ejecutarlo (`README` sección "cómo probar la Fase N").

---

## 2. Stack técnico

| Área | Elección |
|---|---|
| Lenguaje | Python 3.11+ |
| HTTP async | `httpx` |
| Headless browser | `playwright` (Chromium) |
| Parsing HTML | `selectolax` o `beautifulsoup4` |
| Esquemas API | `openapi-core` / parser propio + introspección GraphQL |
| Modelos/validación | `pydantic` v2 |
| Reglas | `PyYAML` |
| CLI | `typer` + `rich` (progreso/tablas) |
| Reportes | `jinja2` (HTML), `json`, SARIF propio |
| Tests | `pytest`, `pytest-asyncio` |
| OAST | integración con Interactsh (cliente) + modo self-hosted opcional |

---

## 3. Arquitectura y estructura de carpetas

```
dastcore/
├── pyproject.toml
├── README.md
├── CLAUDE.md
├── dastcore/
│   ├── __init__.py
│   ├── cli.py                 # entrypoint Typer
│   ├── config.py              # config de scan (pydantic): scope, auth, rate, oast
│   ├── core/
│   │   ├── scope.py           # enforcement de allowlist/denylist (a nivel de motor)
│   │   ├── http_client.py     # cliente async con rate limit, retry, proxy
│   │   ├── session.py         # gestión de auth/sesiones (cookie, bearer, oauth2, form-login)
│   │   └── models.py          # Request, Response, InjectionPoint, Finding, Evidence
│   ├── discovery/
│   │   ├── crawler_http.py     # crawler estático (links, forms, params)
│   │   ├── crawler_headless.py # Playwright: SPA, XHR/fetch, DOM
│   │   ├── openapi.py          # ingesta OpenAPI/Swagger → endpoints + params
│   │   └── graphql.py          # introspección GraphQL → queries/mutations
│   ├── engine/
│   │   ├── injection_points.py # extrae puntos de inyección: query, body, header, cookie, path
│   │   ├── rule_engine.py      # carga y ejecuta reglas YAML
│   │   ├── scanner.py          # orquestador: pasivo + activo
│   │   └── oast.py             # cliente Interactsh / colaborador OOB
│   ├── detectors/              # lógica de familias que no encaja en YAML puro
│   │   ├── passive.py          # headers, CORS, cookies inseguras, info leak
│   │   ├── authz.py            # BOLA/IDOR/BFLA multi-sesión
│   │   └── dom_xss.py          # XSS basado en DOM (requiere headless)
│   ├── validation/
│   │   └── oracles.py          # diferencial, temporal (time-based), OAST, reflected
│   ├── rules/                  # *.yaml declarativos por familia
│   │   ├── sqli.yaml
│   │   ├── xss.yaml
│   │   ├── ssrf.yaml
│   │   ├── ssti.yaml
│   │   ├── lfi.yaml
│   │   ├── cmdi.yaml
│   │   ├── xxe.yaml
│   │   ├── open_redirect.yaml
│   │   └── crlf.yaml
│   └── report/
│       ├── sarif.py
│       ├── html.py
│       └── templates/report.html.j2
└── tests/
    ├── conftest.py            # levanta el target vulnerable local
    ├── targets/vuln_app/      # Flask app deliberadamente vulnerable (fixture)
    └── test_*.py
```

### Modelo de datos mínimo (`core/models.py`)
- `HttpRequest`, `HttpResponse` (con timing).
- `InjectionPoint`: `location` (`query|body|header|cookie|path|json`), `name`, `base_value`, `request_template`.
- `Payload`: `value`, `family`, `oob` (bool).
- `Evidence`: `type` (`reflected|differential|time_based|oob|status`), `data`, `confidence`.
- `Finding`: `id`, `name`, `severity`, `cwe`, `owasp` (WSTG/API Top 10), `injection_point`, `evidence[]`, `request/response`, `remediation`.

### Formato de regla YAML (objetivo de diseño)
```yaml
id: sqli-error-based
name: SQL Injection (error-based)
family: sqli
severity: high
cwe: CWE-89
owasp: WSTG-INPV-05
inject_into: [query, body, json]           # dónde inyectar
payloads:
  - "'"
  - "1' OR '1'='1"
  - "1) OR SLEEP(5)-- -"                    # candidato time-based
oracle:
  type: any_of
  checks:
    - type: response_match                  # error-based
      part: body
      patterns: ["SQL syntax", "mysql_fetch", "ORA-\\d+", "SQLite3::"]
    - type: time_based                      # blind
      payload: "1) OR SLEEP({{delay}})-- -"
      delay: 5
      threshold_ms: 4500
confirm_reproducible: true                  # repite para descartar ruido
```

---

## 4. Familias de vulnerabilidad a cubrir (MVP → completo)

**MVP (Fases 1–4):**
- Pasivas: cabeceras de seguridad ausentes, cookies sin `HttpOnly`/`Secure`/`SameSite`, CORS mal configurado, filtración de info (stack traces, versiones).
- SQL Injection (error-based + time-based/blind).
- XSS reflejado.
- Open redirect.
- Path traversal / LFI.

**Fase 5–6 (diferenciación):**
- Blind SSRF, blind RCE (CMDi), XXE → **vía OAST**.
- SSTI.
- CRLF injection.
- DOM-based XSS (headless).

**Fase 7 (el valor real):**
- **BOLA/IDOR** (multi-sesión, enumeración de IDs de objeto + acceso cross-account).
- **BFLA** (llamada a funciones/endpoints admin desde rol de usuario).
- Autenticación rota / endpoints sin auth expuestos.

---

## 5. Plan de fases

### Fase 0 — Bootstrap
- `pyproject.toml`, dependencias, estructura de carpetas, `cli.py` con `typer` que solo imprime versión y banner legal.
- `config.py` con modelos pydantic para `ScanConfig` (target, scope allow/deny, auth, rate limit, oast, output).
- `core/scope.py`: función `is_in_scope(url)` que TODO request debe consultar. Tests unitarios de scope (allow/deny, subdominios, puertos).
- **Gate de autorización**: sin `--i-have-authorization`, el CLI aborta.

### Fase 0.5 — Target vulnerable local (fixture de tests)
- App Flask mínima en `tests/targets/vuln_app/` con endpoints deliberadamente vulnerables (SQLi reflejado, XSS reflejado, open redirect, IDOR en `/api/orders/<id>`). Sirve como banco de pruebas reproducible y offline.
- `conftest.py` la levanta en un puerto libre para la suite.

### Fase 1 — Motor de red y descubrimiento HTTP
- `core/http_client.py`: `AsyncClient` con rate limit (token bucket), reintentos, timeout, soporte proxy (para encadenar con Burp), captura de timing.
- `discovery/crawler_http.py`: crawl estático respetando scope; extrae links, formularios (método, action, inputs) y parámetros de query. Deduplicación por "firma" de request (método+path+set de params).
- `engine/injection_points.py`: dado un request, deriva la lista de `InjectionPoint`.
- Tests contra el target local.

### Fase 2 — Motor de reglas + escaneo activo básico
- `engine/rule_engine.py`: carga YAML, valida esquema de regla, genera requests mutados por `InjectionPoint`.
- `validation/oracles.py`: oráculos `reflected`, `response_match`, `differential` (compara respuesta base vs mutada), `time_based`.
- `engine/scanner.py`: orquesta pasivo + activo, aplica `confirm_reproducible`, produce `Finding`.
- Reglas: `sqli.yaml`, `xss.yaml`, `open_redirect.yaml`, `lfi.yaml`.
- `detectors/passive.py`: cabeceras, cookies, CORS, info leak.
- Salida JSON. Tests: debe encontrar las vulns plantadas en el target local **sin** falsos positivos en rutas limpias.

### Fase 3 — Autenticación y sesiones
- `core/session.py`: soporte cookie/header estáticos, bearer, OAuth2 (client credentials), y **form-login** (POST de credenciales → captura de cookie/token) con detección de sesión caída y re-login automático.
- Crawler y scanner deben poder operar autenticados.
- Tests con endpoint protegido en el target local.

### Fase 4 — Reportes
- `report/sarif.py` (SARIF 2.1.0 válido, con `ruleId`, `level`, `locations`), `report/json`, `report/html.py` (Jinja2, autocontenido, con severidad, CWE, request/response de evidencia, remediación).
- CLI: `--output json|sarif|html`, exit code ≠ 0 si hay hallazgos ≥ umbral de severidad (para CI/CD).

### Fase 5 — Crawler headless (SPA)
- `discovery/crawler_headless.py` con Playwright: renderiza JS, captura endpoints **XHR/fetch**, extrae formularios del DOM, reutiliza la sesión autenticada.
- `detectors/dom_xss.py`: sinks/sources en DOM.
- Modo configurable: `--engine http|headless|both`.

### Fase 6 — OAST y vulnerabilidades ciegas
- `engine/oast.py`: cliente Interactsh (registro de dominio de colaboración, polling de interacciones DNS/HTTP), con mapeo interacción→request que la disparó (correlación por subdominio único por payload).
- Reglas `ssrf.yaml`, `cmdi.yaml`, `xxe.yaml`, `ssti.yaml`, `crlf.yaml` con payloads OOB (`{{oast_domain}}`).
- Oráculo `oob`: un hallazgo solo se confirma si llega la interacción correlacionada → cero falsos positivos.

### Fase 7 — API y autorización (BOLA/BFLA)
- `discovery/openapi.py`: parsea OpenAPI/Swagger 2.0 y 3.x → endpoints, métodos, parámetros, esquemas de body. Genera requests válidos desde el esquema.
- `discovery/graphql.py`: introspección → queries/mutations.
- `detectors/authz.py`:
  - **BOLA/IDOR**: con dos sesiones (usuario A y usuario B), identifica endpoints con identificadores de objeto, y prueba si A accede a objetos de B (comparación de respuestas y códigos).
  - **BFLA**: intenta invocar funciones/endpoints de rol superior desde un rol inferior.
  - Detección de endpoints sensibles sin autenticación.
- Requiere config de **dos juegos de credenciales/roles** en `ScanConfig`.

### Fase 8 — Pulido y empaquetado
- CLI final con perfiles de escaneo (`--profile quick|full|api`), reanudación, y resumen `rich`.
- `Dockerfile`, GitHub Action de ejemplo (`dastcore` contra staging con salida SARIF → *code scanning*).
- Documentación: `README` con quickstart, `RULES.md` (cómo escribir una regla), `SECURITY.md` (uso responsable).

---

## 6. Criterios de aceptación globales

- Contra el target vulnerable local, `dastcore` detecta **todas** las vulns plantadas y reporta **cero** falsos positivos en las rutas limpias.
- Ningún request sale del scope declarado (test que lo verifica interceptando el cliente HTTP).
- SARIF válido (verificable con validador oficial del esquema).
- Cada `Finding` incluye evidencia reproducible + remediación + CWE + referencia OWASP.
- Añadir una nueva regla de inyección simple = escribir un YAML, sin tocar el motor.

---

## 7. Estado actual

Ver `README.md` para el estado de fases y cómo probar cada una. Al terminar cada fase: proyecto ejecutable, suite de tests en verde, y comando exacto de prueba documentado en el README. Luego parar y esperar confirmación antes de seguir con la siguiente fase.
