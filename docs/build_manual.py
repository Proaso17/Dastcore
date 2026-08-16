"""Genera el manual de uso de dastcore en PDF (docs/dastcore-manual.pdf) con fpdf2."""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

VERSION = "0.5.0"
OUT = Path(__file__).parent / "dastcore-manual.pdf"

_REPL = {"→": "->", "—": "-", "–": "-", "•": "-", "…": "...", "⛓": "", "✅": "[OK]", "🎯": "", "🔒": "", "«": '"', "»": '"'}


def _t(s: str) -> str:
    for k, v in _REPL.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "ignore").decode("latin-1")


def mc(pdf, *args, **kwargs):
    """multi_cell that always starts at the left margin (avoids cursor drift to the right edge)."""
    pdf.set_x(pdf.l_margin)
    return pdf.multi_cell(*args, **kwargs)


class Manual(FPDF):
    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, _t(f"dastcore v{VERSION} - Manual de uso  ·  pagina {self.page_no()}"), align="C")


def h1(pdf: Manual, text: str) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(20, 40, 90)
    mc(pdf, 0, 9, _t(text))
    pdf.set_draw_color(20, 40, 90)
    pdf.set_line_width(0.5)
    y = pdf.get_y() + 1
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)


def h2(pdf: Manual, text: str) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 60, 120)
    mc(pdf, 0, 7, _t(text))
    pdf.ln(1)
    pdf.set_text_color(0, 0, 0)


def h3(pdf: Manual, text: str) -> None:
    pdf.ln(1)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(50, 50, 50)
    mc(pdf, 0, 6, _t(text))
    pdf.set_text_color(0, 0, 0)


def p(pdf: Manual, text: str) -> None:
    pdf.set_font("Helvetica", "", 10)
    mc(pdf, 0, 5, _t(text))
    pdf.ln(1)


def bullet(pdf: Manual, text: str) -> None:
    pdf.set_font("Helvetica", "", 10)
    mc(pdf, 0, 5, _t("   -  " + text), wrapmode="WORD")


def code(pdf: Manual, lines: list[str]) -> None:
    pdf.ln(1)
    pdf.set_font("Courier", "", 8.5)
    pdf.set_fill_color(244, 245, 248)
    pdf.set_text_color(20, 20, 20)
    for line in lines:
        mc(pdf, 0, 4.6, _t(line) or " ", fill=True, wrapmode="CHAR")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def kv_table(pdf: Manual, rows: list[tuple[str, str]], w1: float = 55) -> None:
    for key, val in rows:
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(25, 55, 110)
        mc(pdf, 0, 4.8, _t(key), wrapmode="CHAR")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9.5)
        mc(pdf, 0, 4.8, _t("     " + val), wrapmode="WORD")
        pdf.ln(0.8)
    pdf.ln(1)


def build() -> None:
    pdf = Manual()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(16, 16, 16)
    pdf.add_page()

    # --- Portada ---
    pdf.ln(60)
    pdf.set_font("Helvetica", "B", 34)
    pdf.set_text_color(20, 40, 90)
    mc(pdf, 0, 16, "dastcore", align="C")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(80, 80, 80)
    mc(pdf, 0, 8, _t("Manual de uso"), align="C")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 11)
    mc(pdf, 0, 6, _t(f"Escaner dinamico de seguridad (DAST) + asistente de bug bounty  ·  v{VERSION}"), align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(150, 30, 30)
    mc(pdf, 
        0, 5,
        _t("Herramienta activa e intrusiva. Uso EXCLUSIVO sobre sistemas para los que tienes autorizacion "
           "explicita y por escrito. El escaneo no arranca sin --i-have-authorization."),
        align="C",
    )
    pdf.set_text_color(0, 0, 0)

    # --- 1. Introduccion ---
    pdf.add_page()
    h1(pdf, "1. Que es dastcore")
    p(pdf, "dastcore es un escaner de seguridad de aplicaciones dinamico (caja negra) escrito en Python 3.11+. "
           "Descubre la superficie, cruza cada peticion con reglas y detectores, y confirma cada hallazgo con un "
           "oraculo (diferencial, temporal, out-of-band o de reflexion) antes de reportarlo.")
    h3(pdf, "Diferenciadores")
    bullet(pdf, "Crawler dual: HTTP estatico + headless (Playwright) para SPAs y llamadas XHR/fetch.")
    bullet(pdf, "Descubrimiento de API por esquema: OpenAPI/Swagger + introspeccion GraphQL.")
    bullet(pdf, "OAST: confirmacion out-of-band de vulns ciegas (SSRF/RCE/XXE/Log4Shell) -> cero falsos positivos.")
    bullet(pdf, "Autorizacion multi-sesion (BOLA/IDOR/BFLA) con varias identidades/roles.")
    bullet(pdf, "Prueba de impacto: extrae, de forma acotada y de solo lectura, lo que un atacante obtendria.")
    bullet(pdf, "Cadenas de explotacion: correlaciona hallazgos en rutas de ataque con severidad compuesta.")
    bullet(pdf, "Capa de bug bounty: programa (scope con comodines), recon externo, hunt, triaje VRT y reportes.")
    bullet(pdf, "Bajo ruido: cada hallazgo pasa un oraculo de validacion antes de reportarse.")
    h3(pdf, "Salidas")
    p(pdf, "JSON, SARIF 2.1.0 (para CI/CD), reporte HTML autocontenido, PDF, DefectDojo, y borradores Markdown "
           "de submission por plataforma de bounty.")

    # --- 2. Instalacion ---
    h1(pdf, "2. Instalacion")
    p(pdf, "Requiere Python 3.11+. En Windows (PowerShell), desde la raiz del repo:")
    code(pdf, [
        "python -m venv .venv",
        ".venv\\Scripts\\pip install -e \".[dev,headless,oast,web,pdf]\"",
        "",
        "# Playwright (motor headless) - descarga Chromium:",
        ".venv\\Scripts\\python -m playwright install chromium",
    ])
    p(pdf, "Extras opcionales: headless (Playwright), oast (colaborador OOB), web (panel), pdf (fpdf2), "
           "ai (anthropic). Todos se cargan de forma perezosa: si falta uno, dastcore degrada con aviso.")
    p(pdf, "Comprueba la instalacion:")
    code(pdf, [".venv\\Scripts\\dastcore version", ".venv\\Scripts\\dastcore demo   # escanea un objetivo vulnerable incluido"])

    # --- 3. Uso responsable ---
    h1(pdf, "3. Uso responsable: gate legal y scope")
    p(pdf, "dastcore es intrusivo. Dos mecanismos, no negociables, protegen el uso:")
    h3(pdf, "Gate de autorizacion")
    p(pdf, "Ningun escaneo, recon ni hunt arranca sin el flag --i-have-authorization. Al inicio se muestra un "
           "banner legal. Sin el flag, el comando aborta.")
    h3(pdf, "Scope a nivel de motor")
    p(pdf, "El ScopeChecker se aplica ANTES de enviar cada peticion (y antes de guardar cada asset en recon). "
           "Deny-by-default; out-of-scope siempre gana sobre in-scope. Soporta:")
    bullet(pdf, "Dominios exactos (target.com, incluye el apex).")
    bullet(pdf, "Wildcards de subdominio (*.target.com -> subdominios, no el apex).")
    bullet(pdf, "Rangos CIDR (10.0.0.0/8).")
    code(pdf, [
        "# Ampliar / restringir scope en un scan:",
        "dastcore scan https://staging.example.com --i-have-authorization \\",
        "   --allow-domain \"*.example.com\" --deny-domain admin.example.com",
    ])

    # --- 4. Comandos ---
    pdf.add_page()
    h1(pdf, "4. Comandos")
    p(pdf, "Todos los comandos comparten el estilo `dastcore <comando> [opciones]`. Usa `dastcore <comando> --help` "
           "para ver el detalle completo de flags.")

    h2(pdf, "version / demo")
    p(pdf, "version imprime la version y el banner. demo levanta un objetivo vulnerable incluido y lo escanea "
           "(web + IA) para ver resultados al instante, sin objetivo propio.")
    code(pdf, ["dastcore version", "dastcore demo --output demo.html"])

    h2(pdf, "scan - el comando principal")
    p(pdf, "Escanea un objetivo web: crawlea, ejecuta detectores activos y pasivos, y produce hallazgos "
           "confirmados por oraculo.")
    code(pdf, [
        "dastcore scan https://staging.example.com --i-have-authorization \\",
        "   --profile full --engine both -f sarif -o report.sarif",
    ])
    h3(pdf, "Perfiles y motor")
    kv_table(pdf, [
        ("--profile", "quick | full | api. Fija defaults sensatos (motor, max-pages, oast)."),
        ("--engine", "http (estatico) | headless (SPA/JS) | both."),
        ("-f / --format", "json | sarif | html | defectdojo | pdf."),
        ("-o / --output", "Ruta del reporte (por defecto stdout; pdf requiere --output)."),
        ("--audience", "developer | executive (nivel de detalle del HTML)."),
    ])
    h3(pdf, "Descubrimiento y ritmo")
    kv_table(pdf, [
        ("--max-pages", "Maximo de paginas a crawlear (def. 200)."),
        ("--rps", "Peticiones por segundo (def. 5)."),
        ("--concurrency", "Peticiones en paralelo (def. 5)."),
        ("--max-requests", "Presupuesto total de peticiones (0 = sin limite)."),
        ("--time-budget", "Presupuesto de tiempo en segundos (0 = sin limite)."),
        ("--openapi", "URL de un OpenAPI/Swagger para generar requests desde el esquema."),
        ("--graphql", "URL de un endpoint GraphQL (introspeccion + sondas)."),
        ("--stored", "Activa deteccion de XSS/inyeccion almacenada (2 orden)."),
    ])
    h3(pdf, "Autenticacion")
    kv_table(pdf, [
        ("--auth-bearer", "Token Bearer (JWT/opaco)."),
        ("--auth-cookie", "Cookie de sesion (name=value)."),
        ("--auth-header", "Cabecera arbitraria (Name: value)."),
        ("--login-url / --login-field", "Form-login: URL + campos de credenciales (user=.. pass=..)."),
        ("--oauth-token-url / --oauth-client-id / ...", "OAuth2 client-credentials."),
        ("--auth-macro / --auth-macro-var", "Login por macro (secuencia de peticiones)."),
        ("--roles-file", "JSON con identidades (name/role/auth) para BOLA/BFLA."),
    ])
    h3(pdf, "OAST (vulns ciegas)")
    p(pdf, "Para SSRF/RCE/XXE/SSTI/CRLF/Log4shell ciegos, activa un colaborador out-of-band. Sin OAST, esos "
           "detectores son no-op (nunca inventan un hallazgo).")
    kv_table(pdf, [("--oast", "local | interactsh."), ("--oast-server", "URL del servidor Interactsh propio.")])
    h3(pdf, "Prueba de impacto (--prove-impact)")
    p(pdf, "Sobre cada hallazgo YA confirmado, intenta una extraccion de solo lectura y acotada que demuestre el "
           "impacto real. Nunca crea hallazgos nuevos; si falla, el hallazgo queda intacto. Cubre:")
    bullet(pdf, "SQLi -> lee la version/valor de la base de datos (UNION o error-based).")
    bullet(pdf, "LFI -> muestra un fragmento del fichero leido (solo si casa una firma sensible).")
    bullet(pdf, "SSTI / code injection -> muestra la expresion evaluada.")
    bullet(pdf, "Command injection -> muestra la salida de `id`/`uname`.")
    bullet(pdf, "BOLA/IDOR -> muestra el registro ajeno accedido, redactado (emails/numeros enmascarados).")
    h3(pdf, "Pruebas intrusivas (tras flag, nunca en quick)")
    p(pdf, "Detectores mas agresivos o con estado, desactivados por defecto:")
    kv_table(pdf, [
        ("--waf-evasion", "Si un payload se bloquea, reintenta con tampers/encoders por familia."),
        ("--test-race", "Condiciones de carrera (reejecuta escrituras concurrentes)."),
        ("--test-csrf", "CSRF: token no verificado."),
        ("--test-proto-pollution", "Prototype pollution server-side (Node)."),
        ("--test-cache-poisoning", "Web cache poisoning."),
        ("--test-weak-creds", "Credenciales por defecto/debiles (requiere --login-url)."),
        ("--test-upload", "Subida de ficheros peligrosos (sube -> recupera -> confirma)."),
        ("--test-dos", "XML entity expansion (billion laughs) + ReDoS, por diferencial temporal."),
        ("--test-smuggling", "HTTP request smuggling (CL.TE) por diferencial temporal."),
    ])
    h3(pdf, "CI/CD, reanudacion y triaje")
    kv_table(pdf, [
        ("--fail-on", "Umbral de severidad para exit != 0 (gate de CI)."),
        ("--resume", "Persiste el progreso por request; reanuda si se interrumpe."),
        ("--baseline", "Compara contra una linea base y solo reporta lo nuevo."),
        ("--suppress", "Aplica un .dastcore-ignore (falsos positivos aceptados)."),
        ("--config", "Fichero YAML/JSON unificado (los flags explicitos ganan)."),
    ])

    h2(pdf, "retest / diff")
    p(pdf, "retest reejecuta solo las peticiones de hallazgos previos para ver que sigue vivo y que se corrigio. "
           "diff compara dos ejecuciones y muestra nuevos/corregidos/persistentes.")
    code(pdf, [
        "dastcore retest prev-findings.json --i-have-authorization",
        "dastcore diff base.json head.json",
    ])

    h2(pdf, "ai - chatbot embebido (OWASP LLM)")
    p(pdf, "Escanea aplicaciones con un asistente/chatbot: autodescubre el endpoint del chat (--discover), corre "
           "prompt injection e inyeccion almacenada, y pruebas cross-tenant (BOLA/BFLA via el asistente) con una "
           "segunda identidad.")
    code(pdf, [
        "dastcore ai https://app.example.com --discover --i-have-authorization \\",
        "   --auth-bearer eyJ... --victim-bearer eyJ_otra_cuenta --victim-ref \"unit 4B\"",
    ])

    h2(pdf, "serve - panel web local")
    p(pdf, "Levanta un panel local (FastAPI + SQLite) con asistente guiado de escaneo, historial y tendencias, "
           "triaje, reverificacion, diff, programados y alertas. Autocontenido (sin assets externos).")
    code(pdf, ["dastcore serve --host 127.0.0.1 --port 8000", "# abre http://127.0.0.1:8000"])

    h2(pdf, "baseline / cloud-serve / runner")
    bullet(pdf, "baseline promote: fija la linea base para CI (a partir de un escaneo).")
    bullet(pdf, "cloud-serve: control-plane (cola de escaneos, proyectos, tokens de runner, programados, webhooks).")
    bullet(pdf, "runner: agente self-hosted que toma trabajos del control-plane y ejecuta escaneos.")

    # --- 5. Bug bounty ---
    pdf.add_page()
    h1(pdf, "5. Flujo de bug bounty (programa -> recon -> hunt -> reporte)")
    p(pdf, "La capa de bug bounty convierte un scope-con-comodines en una campana completa, reutilizando el motor "
           "de escaneo. Todo sigue bajo el gate --i-have-authorization y el scope a nivel de motor.")

    h2(pdf, "5.1 El programa (program.yaml)")
    p(pdf, "Describe el scope autorizado y los limites del programa. Ejemplo minimo:")
    code(pdf, [
        "platform: hackerone       # hackerone|bugcrowd|intigriti|immunefi|self",
        "handle: acme",
        "scope:",
        "  domains:  [acme.com]",
        "  wildcards: ['*.acme.com']   # subdominios (no el apex)",
        "  cidrs:    [203.0.113.0/24]",
        "  out_of_scope: [blog.acme.com]",
        "limits:",
        "  requests_per_second: 3.0",
        "  no_automated_scanning: false  # true => solo recon/pasivo",
        "seeds: [acme.com]           # de donde arranca el recon",
        "payouts: { sqli: 2000, idor: 1500 }  # opcional (prioriza)",
    ])

    h2(pdf, "5.2 recon - descubrir la superficie")
    p(pdf, "De un scope con comodines a assets vivos e in-scope, orquestando herramientas del ecosistema en "
           "adaptadores (crt.sh, subfinder, httpx). Si una herramienta no esta instalada, se salta con aviso. "
           "Todo asset pasa por el scope ANTES de guardarse en el asset store (SQLite, con first_seen/last_seen).")
    code(pdf, [
        "dastcore recon --program program.yaml --i-have-authorization \\",
        "   --profile standard --db assets.db -o assets.json",
    ])
    kv_table(pdf, [
        ("--profile", "passive (solo OSINT) | standard | deep."),
        ("--db", "Asset store SQLite (attack-surface monitoring)."),
        ("-o", "Exporta los assets a JSON."),
    ])

    h2(pdf, "5.3 hunt - recon + escaneo")
    p(pdf, "Descubre la superficie y escanea cada asset vivo in-scope reutilizando el pipeline de scan. Cada asset "
           "se re-verifica contra el scope antes de escanearse. Es resumible por asset (--resume). Si el programa "
           "marca no_automated_scanning, hace solo recon.")
    code(pdf, [
        "dastcore hunt --program program.yaml --i-have-authorization \\",
        "   --profile standard --engine http --resume hunt.json -f json -o hunt.json",
    ])

    h2(pdf, "5.4 report - borrador de submission")
    p(pdf, "Genera un borrador Markdown impact-first para una plataforma, a partir de los hallazgos (salida de "
           "scan/hunt -f json). Human-in-the-loop: nunca se envia automaticamente. Incluye titulo, activo, "
           "severidad (CVSS vector + VRT + CWE), reproduccion numerada, PoC minima y no destructiva, impacto y "
           "remediacion.")
    code(pdf, [
        "dastcore report --input hunt.json --platform bugcrowd \\",
        "   --program program.yaml -o draft.md",
        "",
        "# con correlacion SAST (SARIF de SastScore): sube confianza y prioridad",
        "dastcore report --input hunt.json --sast sastscore.sarif --platform hackerone",
    ])
    kv_table(pdf, [
        ("--platform", "hackerone | bugcrowd | generic."),
        ("--finding", "ID del hallazgo (vacio = el de mayor prioridad)."),
        ("--sast", "SARIF de SAST; marca 'confirmado por SAST+DAST' y sube confianza."),
    ])
    p(pdf, "El triaje bounty (bajo el capo del report) mapea cada hallazgo a prioridad VRT (P1-P5), deduplica "
           "reincidencias del mismo (clase + host + parametro), aplica un gate de falsos positivos y ordena por "
           "banda VRT y por impacto real (explotabilidad x payout esperado).")

    # --- 6. Clases cubiertas ---
    pdf.add_page()
    h1(pdf, "6. Clases de vulnerabilidad cubiertas (~62 CWE)")
    p(pdf, "Cada clase se confirma con un oraculo (cero falsos positivos por diseno). Resumen por grupo:")
    h3(pdf, "Inyeccion (A03)")
    p(pdf, "SQLi (error/boolean/time) - XSS (reflejado/DOM/almacenado) - Command injection (in-band + OAST) - "
           "NoSQL - LDAP - XPath - XML - SSTI - Code/Expression-Language injection - SSI - CRLF - HTTP response "
           "splitting - CSV/Formula - Path traversal/LFI - RFI (php wrapper).")
    h3(pdf, "Control de acceso y autenticacion (A01/A07)")
    p(pdf, "BOLA/IDOR, BFLA, missing-auth (REST + GraphQL) - Bypass de acceso por cabeceras de confianza "
           "(X-Forwarded-For, X-Original-URL) - Session fixation - Credenciales debiles/por defecto - Mass "
           "assignment - JWT (alg:none, secreto debil, kid, confusion RS256->HS256, jku/x5u SSRF).")
    h3(pdf, "SSRF, XXE, deserializacion, integridad (A08/A10)")
    p(pdf, "SSRF (OAST) - XXE (OAST) - Deserializacion insegura (pasiva + activa OAST) - Prototype pollution - "
           "Log4Shell/JNDI - Subida de ficheros peligrosos.")
    h3(pdf, "Configuracion y exposicion (A05/A02)")
    p(pdf, "Cabeceras de seguridad ausentes - CORS mal configurado - Clickjacking - Cookies inseguras / "
           "SameSite=None - Reverse tabnabbing - Open redirect - Host header injection - Web cache poisoning - "
           "HTTP request smuggling - Directory listing - Metodos peligrosos - Exposicion de secretos/ficheros/"
           "source maps - Cleartext - Token de sesion en URL - Subdomain takeover - Version vulnerable conocida.")
    h3(pdf, "Denegacion de servicio (acotada, tras --test-dos)")
    p(pdf, "XML entity expansion (billion laughs) - ReDoS (backtracking catastrofico), ambos por diferencial "
           "temporal con triple guarda anti-falsos-positivos.")
    h3(pdf, "IA / OWASP LLM")
    p(pdf, "Prompt injection - inyeccion almacenada - fuga cross-tenant (BOLA/BFLA) via el asistente.")

    # --- 7. Ejemplos de flujo ---
    h1(pdf, "7. Ejemplos de flujo completo")
    h3(pdf, "A. Escaneo de una app conocida en CI (SARIF -> code scanning)")
    code(pdf, [
        "dastcore scan https://staging.example.com --i-have-authorization \\",
        "   --profile full --oast local -f sarif -o results.sarif --fail-on high",
    ])
    h3(pdf, "B. Escaneo autenticado con prueba de impacto y evasion de WAF")
    code(pdf, [
        "dastcore scan https://app.example.com --i-have-authorization \\",
        "   --login-url https://app.example.com/login --login-field user=admin --login-field pass=... \\",
        "   --prove-impact --waf-evasion -f html -o report.html",
    ])
    h3(pdf, "C. BOLA/BFLA con dos identidades sobre una API")
    code(pdf, [
        "dastcore scan https://api.example.com --i-have-authorization \\",
        "   --openapi https://api.example.com/openapi.json --roles-file roles.json",
    ])
    h3(pdf, "D. Bug bounty de punta a punta")
    code(pdf, [
        "dastcore recon --program program.yaml --i-have-authorization --db assets.db",
        "dastcore hunt  --program program.yaml --i-have-authorization -f json -o hunt.json",
        "dastcore report --input hunt.json --sast sast.sarif --platform bugcrowd -o draft.md",
    ])

    h1(pdf, "8. Notas finales")
    bullet(pdf, "Cero falsos positivos por oraculo: si dastcore reporta algo, un oraculo lo confirmo.")
    bullet(pdf, "Los detectores intrusivos van tras flag y nunca en el perfil quick.")
    bullet(pdf, "Recon y correlacion SAST solo refuerzan; nunca inventan un hallazgo.")
    bullet(pdf, "Todo reporte de bounty es un borrador para tu revision; nunca hay envio automatico.")
    bullet(pdf, "Usa `dastcore <comando> --help` para el detalle exhaustivo de cada flag.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(OUT))
    print(f"OK -> {OUT}")


if __name__ == "__main__":
    build()
