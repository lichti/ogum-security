FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Trivy CLI — talks to the trivy-server sidecar (docker-compose.yml) via `--server`
# on the vm/rootfs/image/sbom subcommand (not `trivy client`, which is image-only in
# current releases). The version tracks aquasec/trivy:latest used for the sidecar
# itself, matching its existing convention rather than pinning here.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.3

# Pin packaging to the version checkov requires (~=23.0) and pre-install setuptools.
# Without this, poetry downgrades packaging mid-install, causing alibabacloud-tea's
# build isolation step to fail with FileNotFoundError on packaging/tags.py.
RUN pip install --no-cache-dir "packaging==23.2" "setuptools>=68"

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
