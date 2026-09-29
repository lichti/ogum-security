# US-13.12 — multi-stage, non-root, trivy de release pinada (sem curl|sh do main),
# dependências pelo poetry.lock commitado, CMD de produção (sem --reload).

# ── Stage 1: dependências ────────────────────────────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Trivy CLI (client) — release pinada; o sidecar trivy-server é pinnado por
# digest no docker-compose.yml. Divergência client/sidecar menor é tolerada
# pelo protocolo --server; atualize os dois juntos.
ARG TRIVY_VERSION=0.74.0
RUN curl -sfLo /tmp/trivy.deb \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb" \
    && apt-get update && apt-get install -y --no-install-recommends /tmp/trivy.deb \
    && rm -f /tmp/trivy.deb && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.3 \
    && pip install --no-cache-dir "packaging==23.2" "setuptools>=68"

# poetry.lock commitado (US-13.10) — build reprodutível; --sync remove o que
# estiver fora do lock.
COPY pyproject.toml poetry.lock ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --sync

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# git: clone dos repositórios no scan de IaC; trivy: client do sidecar
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin appuser

COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

# Produção: sem --reload; workers/serviços definidos pelo docker-compose
# (worker/beat sobrecarregam o command com celery).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
