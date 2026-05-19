#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-tummifix/gcli2api}"
VERSION="${1:-${VERSION:-$(date +%Y%m%d%H%M)}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Building ${IMAGE_NAME}:${VERSION}"
docker build \
    -t "${IMAGE_NAME}:${VERSION}" \
    -t "${IMAGE_NAME}:latest" \
    "${ROOT_DIR}"

echo "Pushing ${IMAGE_NAME}:${VERSION}"
docker push "${IMAGE_NAME}:${VERSION}"

echo "Pushing ${IMAGE_NAME}:latest"
docker push "${IMAGE_NAME}:latest"

echo "Published ${IMAGE_NAME}:${VERSION}"
