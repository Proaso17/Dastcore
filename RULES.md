# Escribir una regla en dastcore

El motor de reglas es genérico: **añadir un detector de inyección nuevo es escribir un YAML** en `dastcore/rules/`, sin tocar código Python. Cada regla se valida contra el modelo `Rule` (pydantic) al cargarse.

## Formato

```yaml
id: sqli-injection                 # id único de la regla (referenciado como ruleId en SARIF)
name: SQL Injection                # nombre legible del hallazgo
family: sqli                       # familia lógica
severity: high                     # info | low | medium | high | critical
cwe: CWE-89                        # referencia CWE
owasp: WSTG-INPV-05                # referencia OWASP (WSTG o API Top 10)
inject_into: [query, body, json]   # dónde inyectar: query | body | json | header | fragment
payloads:                          # valores a probar en cada punto de inyección
  - "'"
  - "1' OR '1'='1"
oracle:                            # cómo se confirma el hallazgo
  type: any_of                     # any_of (basta un check) | all_of (todos los checks)
  checks:
    - type: response_match         # busca patrones (regex) en el cuerpo o cabeceras
      part: body                   # body | headers
      patterns: ["SQL syntax", "SQLite3::error", "ORA-\\d{5}"]
    - type: time_based             # inyección ciega por tiempo
      payload: "1) OR SLEEP({{delay}})-- -"
      delay: 3
      threshold_ms: 2500
confirm_reproducible: true         # repite la petición mutada; solo reporta si vuelve a confirmar
remediation: >-                    # texto de remediación incluido en cada hallazgo
  Usa consultas parametrizadas / prepared statements para toda llamada a la BD.
```

## Tipos de oráculo (checks)

| type | Qué comprueba | Campos |
|---|---|---|
| `reflected` | El payload aparece tal cual en la respuesta | — |
| `response_match` | Una regex casa en `body` o `headers` | `part`, `patterns` |
| `differential` | La respuesta mutada pasó a error 5xx (base < 500) | — |
| `time_based` | La respuesta tardó `>= threshold_ms` sobre la base | `payload`, `delay`, `threshold_ms` |
| `oob` | Llegó una interacción OAST correlacionada (ver abajo) | — |

`confirm_reproducible: true` hace que un hallazgo in-band solo se reporte si el oráculo confirma **dos veces** en peticiones independientes — así se descarta ruido (timing flaky, respuestas no deterministas).

## Reglas out-of-band (OAST)

Para vulnerabilidades ciegas (SSRF/RCE/XXE/SSTI/CRLF) usa un oráculo `oob` y payloads con placeholders:

- `{{oast_url}}` → URL de callback completa y única por payload (p. ej. `http://<host>/<token>`).
- `{{oast_domain}}` → solo el host del colaborador.

```yaml
id: ssrf-oob
name: Server-Side Request Forgery (blind, OAST-confirmed)
family: ssrf
severity: high
cwe: CWE-918
owasp: WSTG-INPV-19
inject_into: [query, body, json]
payloads:
  - "{{oast_url}}"
oracle:
  type: any_of
  checks:
    - type: oob
confirm_reproducible: false
remediation: >-
  No hagas fetch de URLs controladas por el usuario; valida contra un allowlist.
```

El scanner sustituye el placeholder por un callback único por payload, envía la petición, y **solo reporta si llega la interacción correlacionada** al proveedor OAST (`--oast local|interactsh`). Sin callback, no hay hallazgo → cero falsos positivos en esta clase.

## Probar tu regla

1. Añade el YAML a `dastcore/rules/`.
2. Si quieres cobertura, planta el caso en `tests/targets/vuln_app/app.py` y añade un test.
3. `pytest tests/test_rule_engine.py` valida que el YAML carga y tiene la forma esperada.
