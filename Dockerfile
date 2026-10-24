# syntax=docker/dockerfile:1

FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AUTHLIB_INSECURE_TRANSPORT=0 \
    PYTHONPATH=/app \
    OIDC_DATA_DIR=/data \
    OIDC_STATIC_DIR=/app/static \
    OIDC_ISSUER=http://localhost:8000 \
    OIDC_FRONTEND_ORIGIN=http://localhost:8000 \
    OIDC_CONNECTOR=local

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY backend/app ./app
COPY --from=frontend /frontend/dist ./static

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app

# Fixed uid for a plain `docker run`. Compose overrides it with PUID:PGID so a
# bind-mounted ./data stays writable by the host user.
USER appuser
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

# The app reads X-Forwarded-* itself, from OIDC_TRUSTED_PROXIES only. Uvicorn's
# own handling would replace the proxy address before the app can check it.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
