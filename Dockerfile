# One image, three roles (app, trust, lab) selected by the compose command.
FROM node:22-bookworm-slim AS web
RUN corepack enable && corepack prepare pnpm@10.20.0 --activate
WORKDIR /build/web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM python:3.12-slim-bookworm
# yara-python ships its own libyara; fonts are needed for PDF reports.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates fonts-dejavu-core tini \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY cbb/ ./cbb/
COPY pyproject.toml ./
COPY rules/ ./rules/
COPY deploy/docker/ ./deploy/docker/
COPY --from=web /build/web/dist ./web/dist
RUN sed -i 's/[[:cntrl:]]$//' deploy/docker/*.sh && chmod 0755 deploy/docker/*.sh \
 && useradd --uid 10001 --create-home cbb \
 && mkdir -p /data && chown cbb:cbb /data
USER 10001:10001
ENV CBB_DATA=/data CBB_CONTAINER=true PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
EXPOSE 8765
ENTRYPOINT ["/usr/bin/tini", "--"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/health/ready',timeout=3)"
CMD ["python", "-m", "cbb.cli", "serve", "--host", "0.0.0.0"]
