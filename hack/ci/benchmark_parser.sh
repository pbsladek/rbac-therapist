#!/usr/bin/env bash
set -euo pipefail

MAX_ABAC_NS_PER_OP="${MAX_ABAC_NS_PER_OP:-3000000000}"
MAX_INLINE_NS_PER_OP="${MAX_INLINE_NS_PER_OP:-250000000}"
EXPECTED_BENCH_NAME="${EXPECTED_BENCH_NAME:-}"
MAX_NS_PER_OP="${MAX_NS_PER_OP:-}"

tmpfile="$(mktemp)"
trap 'rm -f "${tmpfile}"' EXIT

echo "Running parser benchmarks..."
if [[ -n "${EXPECTED_BENCH_NAME}" ]]; then
  if [[ -z "${MAX_NS_PER_OP}" ]]; then
    echo "MAX_NS_PER_OP is required when EXPECTED_BENCH_NAME is set"
    exit 1
  fi

  go test ./internal/engine/parser -bench "^${EXPECTED_BENCH_NAME}$" -benchmem -run '^$' -count=1 | tee "${tmpfile}"
  ns_per_op="$(awk -v n="${EXPECTED_BENCH_NAME}" '$1 ~ ("^" n "-") {print $3; exit}' "${tmpfile}")"
  if [[ -z "${ns_per_op}" ]]; then
    echo "failed to parse benchmark output for ${EXPECTED_BENCH_NAME}"
    exit 1
  fi

  echo "Benchmark threshold:"
  echo "  ${EXPECTED_BENCH_NAME} ns/op: ${ns_per_op} (max ${MAX_NS_PER_OP})"
  if [[ "${ns_per_op}" -gt "${MAX_NS_PER_OP}" ]]; then
    echo "${EXPECTED_BENCH_NAME} regression: ${ns_per_op} > ${MAX_NS_PER_OP}"
    exit 1
  fi

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## Parser Benchmark"
      echo "- ${EXPECTED_BENCH_NAME}: \`${ns_per_op} ns/op\` (max \`${MAX_NS_PER_OP}\`)"
    } >> "${GITHUB_STEP_SUMMARY}"
  fi

  echo "Parser benchmark threshold passed."
  exit 0
fi

go test ./internal/engine/parser -bench BenchmarkParse -benchmem -run '^$' -count=1 | tee "${tmpfile}"

abac_ns_per_op="$(awk '$1 ~ /^BenchmarkParse_ABACLarge-/ {print $3; exit}' "${tmpfile}")"
inline_ns_per_op="$(awk '$1 ~ /^BenchmarkParse_ManyInlineSubjects-/ {print $3; exit}' "${tmpfile}")"

if [[ -z "${abac_ns_per_op}" || -z "${inline_ns_per_op}" ]]; then
  echo "failed to parse benchmark output"
  exit 1
fi

echo "Benchmark thresholds:"
echo "  BenchmarkParse_ABACLarge ns/op: ${abac_ns_per_op} (max ${MAX_ABAC_NS_PER_OP})"
echo "  BenchmarkParse_ManyInlineSubjects ns/op: ${inline_ns_per_op} (max ${MAX_INLINE_NS_PER_OP})"

if [[ "${abac_ns_per_op}" -gt "${MAX_ABAC_NS_PER_OP}" ]]; then
  echo "BenchmarkParse_ABACLarge regression: ${abac_ns_per_op} > ${MAX_ABAC_NS_PER_OP}"
  exit 1
fi

if [[ "${inline_ns_per_op}" -gt "${MAX_INLINE_NS_PER_OP}" ]]; then
  echo "BenchmarkParse_ManyInlineSubjects regression: ${inline_ns_per_op} > ${MAX_INLINE_NS_PER_OP}"
  exit 1
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Parser Benchmarks"
    echo "- BenchmarkParse_ABACLarge: \`${abac_ns_per_op} ns/op\` (max \`${MAX_ABAC_NS_PER_OP}\`)"
    echo "- BenchmarkParse_ManyInlineSubjects: \`${inline_ns_per_op} ns/op\` (max \`${MAX_INLINE_NS_PER_OP}\`)"
  } >> "${GITHUB_STEP_SUMMARY}"
fi

echo "Parser benchmark thresholds passed."
