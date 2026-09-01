#!/usr/bin/env bash
#
# Runs the integration tests (build tag: integration) against a local moto server that emulates
# STS + ECS. moto is used rather than LocalStack because LocalStack's community edition does not
# implement ECS. The moto image is pinned because `:latest` has had regressions in ECS run-task.
#
# Usage: test/integration/run.sh
# Requires: docker, go, curl.
set -euo pipefail

MOTO_IMAGE="${MOTO_IMAGE:-motoserver/moto:5.0.28}"
MOTO_PORT="${MOTO_PORT:-5055}"
# Unique per-run container name so two runs on the same host don't collide.
MOTO_NAME="${MOTO_NAME:-ecs-inventory-moto-it-$$}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cleanup() {
  docker rm -f "${MOTO_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Start fresh (remove any leftover container from an interrupted run).
cleanup
echo "Starting moto (${MOTO_IMAGE}) on port ${MOTO_PORT}..."
docker run -d --name "${MOTO_NAME}" -p "${MOTO_PORT}:5000" "${MOTO_IMAGE}" >/dev/null

echo "Waiting for moto to become ready..."
for _ in $(seq 1 30); do
  if curl -fs "http://localhost:${MOTO_PORT}/moto-api/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready:-0}" != "1" ]]; then
  echo "moto did not become ready in time" >&2
  docker logs "${MOTO_NAME}" >&2 || true
  exit 1
fi

# Route every AWS service (STS + ECS) to moto and pin a fixed dummy identity. We deliberately
# FORCE the dummy credentials and region (rather than falling back to the caller's) and clear the
# other credential sources so a developer's real AWS_PROFILE / SSO session / shared credentials file
# can't leak into the run — that would otherwise trigger real STS calls or hang on SSO resolution.
export AWS_ENDPOINT_URL="http://localhost:${MOTO_PORT}"
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_REGION="us-east-1"
unset AWS_PROFILE AWS_SESSION_TOKEN AWS_SHARED_CREDENTIALS_FILE
export AWS_EC2_METADATA_DISABLED=true

echo "Running integration tests (using $(go version))..."
cd "${REPO_ROOT}"
# -run 'TestIntegration' so the integration job exercises only the integration tests, not the whole
# unit suite (which the build tag would otherwise re-run in every package here).
go test -tags integration -count=1 -run 'TestIntegration' -v ./pkg/...
