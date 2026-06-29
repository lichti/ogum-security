FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

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
