#!/usr/bin/env bash
set -euo pipefail

# Production container deployment for EVIDIQ Bulwark MCP
CONTAINER_NAME="evidiq-bulwark"
IMAGE_NAME="evidiq-bulwark:latest"
ENV_FILE="/root/evidiq-bulwark.env"
HOST_PORT="3015"

echo "Deploying ${CONTAINER_NAME} on host port ${HOST_PORT}..."

if [ ! -f "${ENV_FILE}" ]; then
  echo "Error: Environment file ${ENV_FILE} not found!"
  exit 1
fi

docker stop "${CONTAINER_NAME}" 2>/dev/null || true
docker rm "${CONTAINER_NAME}" 2>/dev/null || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  --network coolify \
  --env-file "${ENV_FILE}" \
  -p "127.0.0.1:${HOST_PORT}:3000" \
  --label "traefik.enable=true" \
  --label "traefik.http.routers.bulwark.rule=Host(\`mcp.evidiq.dev\`) && PathPrefix(\`/bulwark\`)" \
  --label "traefik.http.routers.bulwark.tls=true" \
  --label "traefik.http.routers.bulwark.tls.certresolver=letsencrypt" \
  --label "traefik.http.routers.bulwark.middlewares=bulwark-strip" \
  --label "traefik.http.middlewares.bulwark-strip.stripprefix.prefixes=/bulwark" \
  --label "traefik.http.services.bulwark.loadbalancer.server.port=3000" \
  "${IMAGE_NAME}"

echo "Started ${CONTAINER_NAME}."
