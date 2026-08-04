# dastcore — Dynamic Application Security Testing scanner
# Ships with the headless browser and OAST extras so `--engine headless|both`
# and the Interactsh client work out of the box.
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
    && pip install ".[headless,oast]" \
    # Install the Chromium the headless engine needs, plus its OS dependencies.
    && python -m playwright install --with-deps chromium

# Run as a non-root user.
RUN useradd --create-home --uid 10001 dast \
    && chown -R dast:dast /opt/pw-browsers
USER dast

ENTRYPOINT ["dastcore"]
CMD ["--help"]
