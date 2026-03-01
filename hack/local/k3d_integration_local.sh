#!/usr/bin/env bash
set -euo pipefail

# Local helper for running the CI-like k3d integration flow on macOS.

CLUSTER_NAME="${CLUSTER_NAME:-rbact-local}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-rbac-therapist/operator:local}"
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.32.2-k3s1}"
K3D_INTEGRATION_TIMEOUT="${K3D_INTEGRATION_TIMEOUT:-20m}"
KEEP_CLUSTER="${KEEP_CLUSTER:-false}"

if ! command -v k3d >/dev/null 2>&1; then
  echo "error: k3d not found on PATH" >&2
  exit 1
fi
if ! command -v kubectl >/dev/null 2>&1; then
  echo "error: kubectl not found on PATH" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found on PATH" >&2
  exit 1
fi

cleanup() {
  if [[ "${KEEP_CLUSTER}" != "true" ]]; then
    k3d cluster delete "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Creating k3d cluster: ${CLUSTER_NAME}"
k3d cluster delete "${CLUSTER_NAME}" >/dev/null 2>&1 || true
k3d cluster create "${CLUSTER_NAME}" --agents 1 --image "${K3S_IMAGE}" --wait

kubectl config use-context "k3d-${CLUSTER_NAME}" >/dev/null

echo "Building operator image: ${OPERATOR_IMAGE}"
docker build -t "${OPERATOR_IMAGE}" .

echo "Importing operator image into k3d cluster"
k3d image import "${OPERATOR_IMAGE}" -c "${CLUSTER_NAME}"

echo "Running integration checks"
export OPERATOR_IMAGE
export K3D_INTEGRATION_TIMEOUT
bash hack/ci/k3d_integration.sh

echo "Integration flow completed successfully"
