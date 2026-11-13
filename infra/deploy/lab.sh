#!/usr/bin/env bash
# Execute on the private Linux measurement host from a clean checkout. No remote command interpolation.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
lab=(node src/services/lab/src/controller/cli.ts)
case "${1:-}" in
  setup)
    test "$(node --version)" = "v$(tr -d '\r\n' < .node-version)"
    npm ci --ignore-scripts --prefix src/services/gateway
    npm ci --ignore-scripts --prefix src/services/lab
    if [[ ! -e .runtime/secrets ]]; then node infra/scripts/provision-secrets.ts; fi
    "${lab[@]}" preflight
    ;;
  preflight) "${lab[@]}" preflight ;;
  network) node infra/scripts/check-network.mjs ;;
  demo|security|performance|performance-smoke)
    suite="$1"
    out="artifacts/${suite}-$(date -u +%Y%m%dT%H%M%SZ).json"
    "${lab[@]}" preflight
    "${lab[@]}" run --suite "$suite" --out "$out"
    "${lab[@]}" verify-report --file "$out"
    printf 'Report: %s\n' "$out"
    if [[ "$suite" != performance-smoke ]]; then "${lab[@]}" verify-report --file "$out" --require-pass; fi
    ;;
  verify) "${lab[@]}" verify-report --file "${2:?report path required}" --require-pass ;;
  summary) "${lab[@]}" summarize-benchmark --file "${2:?report path required}" ;;
  viewer) "${lab[@]}" serve-report --file "${2:?report path required}" --host 127.0.0.1 ;;
  fence) "${lab[@]}" fence ;;
  cleanup)
    # A failed/unknown inventory or fence stops this script before any Redis removal.
    "${lab[@]}" fence
    docker compose -f infra/compose.yaml down
    ;;
  *) printf 'Usage: bash infra/deploy/lab.sh setup|preflight|network|demo|security|performance|performance-smoke|verify FILE|summary FILE|viewer FILE|fence|cleanup\n' >&2; exit 2 ;;
esac
