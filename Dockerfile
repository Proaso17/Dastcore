# dastcore — Dynamic Application Security Testing scanner
# Ships with the headless browser, OAST and web-dashboard extras so `--engine
# headless|both`, the Interactsh client, and `dastcore serve` all work out of the box.
FROM python:3.11-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers

WORKDIR /app

# Copy metadata first for better layer caching, then the package.
COPY pyproject.toml README.md ./
COPY dastcore ./dastcore

RUN pip install --upgrade pip \
    && pip install ".[headless,oast,web]" \
    # Install the Chromium the headless engine needs, plus its OS dependencies.
    && python -m playwright install --with-deps chromium

# Run as a non-root user; its home (~/.dastcore) is where `serve` keeps history.
RUN useradd --create-home --uid 10001 dast \
    && chown -R dast:dast /opt/pw-browsers
USER dast

# The web dashboard listens here. Inside a container bind to 0.0.0.0 so the port
# is reachable from the host:  docker run -p 8000:8000 dastcore serve --host 0.0.0.0
EXPOSE 8000

ENTRYPOINT ["dastcore"]
CMD ["--help"]
