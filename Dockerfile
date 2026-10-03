FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app

COPY requirements.txt requirements-optional.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-optional.txt

COPY app ./app
COPY scripts ./scripts
COPY eval ./eval
COPY tests/regression ./tests/regression

RUN useradd -m runner && chown -R runner /app
USER runner

# Cloud Run sets $PORT. SQLite lives in /tmp unless DATABASE_URL points at Postgres.
ENV DATABASE_URL=sqlite:////tmp/proofladder.db
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
