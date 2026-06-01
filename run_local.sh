#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required"
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "docker compose is required"
  exit 1
fi

USAGE() {
  cat <<EOF
Usage: $(basename "$0") [start|stop|status|leak-detect]

  start        Build and start all containers (detached)
  stop         Stop and remove all containers
  status       Show container status
  leak-detect  Start with Netty paranoid leak detection enabled
EOF
}

case "${1:-start}" in
  start)
    echo "[psk-poc] starting"
    "${COMPOSE[@]}" -f "$ROOT_DIR/docker-compose.yml" up -d --build
    echo "[psk-poc] launcher: http://localhost:5000"
    ;;
  leak-detect)
    echo "[psk-poc] starting with Netty paranoid leak detection"
    EXTRA_JVM_OPTS="-Dio.netty.leakDetection.level=paranoid" \
      "${COMPOSE[@]}" -f "$ROOT_DIR/docker-compose.yml" up -d --build
    ;;
  stop)
    echo "[psk-poc] stopping"
    "${COMPOSE[@]}" -f "$ROOT_DIR/docker-compose.yml" down
    ;;
  status)
    "${COMPOSE[@]}" -f "$ROOT_DIR/docker-compose.yml" ps
    ;;
  *)
    USAGE
    exit 1
    ;;
esac
