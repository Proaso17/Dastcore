# Desplegar dastcore como SaaS (Render, sin VPS)

Esta guía levanta el **control-plane** de dastcore en la nube (Render), con HTTPS y Postgres
gestionados, y explica cómo cada usuario ejecuta un **runner** en su propia red.

## El modelo de seguridad (léelo)

- El **control-plane** que despliegas aquí **solo encola trabajos y guarda resultados. NUNCA escanea.**
  Por eso es seguro exponerlo en internet: ningún tráfico intrusivo sale de tu servidor.
- El escaneo lo hace un **runner self-hosted** que **cada usuario ejecuta en su propia máquina/red**,
  y solo tras confirmar `--i-have-authorization`. El tráfico intrusivo se queda en su lado.
- Tres credenciales, todas por `Authorization: Bearer <token>`:
  - **admin token** — crea proyectos (lo tienes tú, en secreto).
  - **API key de proyecto** — encola escaneos y ve resultados (la UI la guarda en una cookie httpOnly).
  - **token de runner** — solo reclama trabajos y reporta resultados.

---

## 1. Desplegar el control-plane en Render

**Requisitos:** una cuenta de GitHub (con este repo subido) y una cuenta gratuita en Render.

1. En Render: **New → Blueprint** y elige este repositorio. Render lee [`render.yaml`](../render.yaml)
   y prepara el servicio web (desde `Dockerfile.cloud`) + una base de datos Postgres.
2. Pulsa **Apply**. Render construye la imagen, provisiona Postgres, inyecta las variables de entorno
   y despliega. Espera a que el servicio quede en **Live**.
3. Tu control-plane vive en `https://dastcore-control-plane.onrender.com` (con HTTPS ya resuelto).
4. Copia el **admin token**: en el servicio → pestaña **Environment** → `DASTCORE_ADMIN_TOKEN`.

> **Notas de plan (free):** el servicio web gratuito "duerme" tras ~15 min de inactividad (primer
> acceso lento) y el Postgres gratuito caduca a los ~90 días. Para producción, sube el servicio a
> **Starter** (siempre activo) y el Postgres a **basic-256mb** o superior. **Mantén 1 instancia.**

**Dominio propio (opcional):** servicio → **Settings → Custom Domains** → añade `app.tudominio.com`
y crea el CNAME que te indique. El HTTPS se emite solo.

---

## 2. Crear el primer proyecto y dar acceso a un usuario

Un **proyecto** aísla los escaneos y resultados de un usuario/cliente. Se crea con el admin token:

```bash
ADMIN=<tu-DASTCORE_ADMIN_TOKEN>
BASE=https://dastcore-control-plane.onrender.com

curl -sX POST "$BASE/api/projects" \
  -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"acme"}'
# -> {"id":"...","name":"acme","api_key":"dcpk_..."}
```

Entrega esa **`api_key`** al usuario. Con ella:

- entra en la **UI** en `$BASE/` (login con su api_key) para encolar escaneos y ver resultados, o
- usa la **API** directamente (`Authorization: Bearer <api_key>`).

---

## 3. El usuario ejecuta su runner (escanea en SU red)

El runner es lo único que toca los objetivos, y se ejecuta **en la máquina/red del usuario** (no en
Render). Usa la imagen completa publicada en GHCR (trae Chromium para escaneos headless).

**Un solo comando (Docker), con la API key del proyecto** (el runner se registra y obtiene su token):

```bash
docker run -d --name dastcore-runner --restart unless-stopped \
  ghcr.io/proaso17/dastcore \
  runner https://dastcore-control-plane.onrender.com \
    --project-key dcpk_... \
    --i-have-authorization \
    --name mi-portatil
```

- `--i-have-authorization` es obligatorio: confirma que el usuario tiene permiso sobre los objetivos.
- El runner sondea el control-plane, reclama trabajos, escanea localmente y sube los resultados.
- Alternativa sin registrar por API key: pasa `--token <token-de-runner>` (creado en la UI del
  proyecto → "Nuevo runner", o vía `POST /api/runners`).

---

## 4. Lanzar un escaneo

Desde la UI del proyecto (`$BASE/ui`) encola un objetivo, o por API:

```bash
KEY=<api_key-del-proyecto>
curl -sX POST "$BASE/api/jobs" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"target":"https://staging.midominio.com","profile":"full"}'
```

El runner del usuario lo toma, escanea en su red y los resultados aparecen en el control-plane
(UI y `GET /api/jobs/<id>`).

---

## 5. Checklist de producción

- [ ] Servicio web en **Starter** (sin "sueño") y Postgres en un plan **de pago** (el free caduca).
- [ ] **1 instancia** del control-plane (no escalar horizontalmente).
- [ ] `DASTCORE_ADMIN_TOKEN` tratado como secreto (rota si se filtra).
- [ ] Dominio propio + HTTPS (Render lo emite). La cookie de sesión ya es `Secure`+`HttpOnly`+`SameSite=Strict`.
- [ ] Cada usuario ejecuta su propio runner y solo escanea su **scope autorizado**.
- [ ] Copia de seguridad del Postgres (Render ofrece backups en planes de pago).

## Alternativas a Render

Mismo modelo, otro proveedor: **Railway** (Docker + plugin Postgres), **Fly.io** (`fly launch` +
`fly postgres`). En todos, despliega `Dockerfile.cloud` con `DASTCORE_DB=<postgres-dsn>` y
`DASTCORE_ADMIN_TOKEN=<secreto>`, y bind a `0.0.0.0:$PORT`. Para un despliegue self-hosted con Docker
Compose + Postgres, usa [`docker-compose.cloud.yml`](../docker-compose.cloud.yml) detrás de un proxy TLS.
