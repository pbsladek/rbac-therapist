#!/usr/bin/env bash
set -euo pipefail

echo "Running Go-based integration runner (Kubernetes SDK)..."
go run ./cmd/ci-k3d-integration
