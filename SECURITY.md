# Uso responsable y seguridad

## dastcore es una herramienta ofensiva

`dastcore` realiza pruebas de seguridad **activas e intrusivas**: envía payloads de inyección, provoca callbacks out-of-band, y prueba accesos de autorización cruzados. Puede causar efectos secundarios en el sistema objetivo (registros de error, datos de prueba, carga adicional, e incluso ejecución de acciones si hay vulnerabilidades explotables).

**Úsalo únicamente contra sistemas para los que tengas autorización explícita y por escrito.**

## Autorización obligatoria

- El escaneo **no arranca** sin el flag `--i-have-authorization`.
- El *scope* se declara con una allowlist de dominios y se **impone a nivel de motor**: toda petición pasa por el `ScopeChecker` antes de salir; una URL fuera de scope nunca se envía (lanza `OutOfScopeError`). Esto no es una sugerencia de configuración, es un control del núcleo.
- `--deny-domain` siempre gana sobre `--allow-domain`.

## Marco legal (no exhaustivo)

Escanear sistemas sin autorización puede constituir un delito, p. ej.:
- **EE.UU.** — Computer Fraud and Abuse Act (CFAA).
- **UE** — Directiva 2013/40/UE sobre ataques a sistemas de información (y trasposiciones nacionales).
- **Perú** — Ley 30096 de Delitos Informáticos.
- **España** — art. 197 bis / 264 del Código Penal.

Consulta la legislación de tu jurisdicción y la del objetivo. La responsabilidad del uso es exclusivamente tuya.

## Buenas prácticas operativas

- Prefiere entornos de **staging**, no producción.
- Empieza con `--profile quick` y un `--rps` bajo para medir impacto antes de un `--profile full`.
- Para OAST contra targets remotos usa `--oast interactsh` (el colaborador debe ser alcanzable por el objetivo); `--oast local` solo sirve para localhost o si hospedas el colaborador en una IP accesible.
- Guarda la evidencia (reportes SARIF/HTML/JSON) de forma segura: contienen fragmentos de request/response que pueden incluir datos sensibles.

## Reportar vulnerabilidades en dastcore

Si encuentras un fallo de seguridad **en dastcore** (no en un objetivo escaneado), repórtalo de forma privada al mantenedor en lugar de abrir un issue público, e incluye pasos de reproducción.

## Datos y privacidad

`dastcore` no envía telemetría. Todo el tráfico va del proceso al objetivo declarado (y, si activas OAST, al colaborador que configures). El reporte HTML es autocontenido y escapa todo input capturado para que el propio reporte no sea vector de XSS.
