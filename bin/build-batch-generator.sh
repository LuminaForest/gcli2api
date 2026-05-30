#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-tummifix/gcli2api-batch-generator}"
VERSION="${1:-${VERSION:-$(date +%Y%m%d%H%M)}}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
BUILDER_NAME="${BUILDER_NAME:-gcli2api-batch-generator-builder}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.batch-generator}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE_PATH="${ROOT_DIR}/${DOCKERFILE}"

if [[ ! -f "${DOCKERFILE_PATH}" ]]; then
    echo "Dockerfile not found: ${DOCKERFILE_PATH}" >&2
    exit 1
fi

if [[ ",${PLATFORMS}," == *",linux/arm64,"* ]]; then
    echo "linux/arm64 is not supported for the batch generator image: patchright install chrome fails on Linux Arm64." >&2
    echo "Use PLATFORMS=linux/amd64, or update the runtime to use a supported browser on arm64." >&2
    exit 1
fi

if ! docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
    docker buildx create --name "${BUILDER_NAME}" --driver docker-container --use >/dev/null
else
    docker buildx use "${BUILDER_NAME}" >/dev/null
fi

docker buildx inspect --bootstrap >/dev/null

echo "Building and pushing ${IMAGE_NAME}:${VERSION} for ${PLATFORMS}"
docker buildx build \
    --platform "${PLATFORMS}" \
    -f "${DOCKERFILE_PATH}" \
    -t "${IMAGE_NAME}:${VERSION}" \
    -t "${IMAGE_NAME}:latet" \
    --push \
    "${ROOT_DIR}"

echo "Published ${IMAGE_NAME}:${VERSION}"
