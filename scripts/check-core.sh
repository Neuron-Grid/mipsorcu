#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

check_config() {
    local tracked config_paths
    tracked="$(git ls-files 'supabase/supabase')"
    if [[ -n "${tracked}" ]]; then
        echo 'NG: tracked nested Supabase project files found'
        printf '%s\n' "${tracked}"
        return 1
    fi
    config_paths="$(find "${REPO_ROOT}/supabase" -name config.toml -type f | sort)"
    if [[ "${config_paths}" != "${REPO_ROOT}/supabase/config.toml" ]]; then
        echo 'NG: expected exactly one Supabase config at supabase/config.toml'
        printf '%s\n' "${config_paths}"
        return 1
    fi
}

check_rust() {
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets --all-features -- -D warnings
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}" cargo test --locked
}

case "${1:-all}" in
    all) check_config; check_rust; supabase test db ;;
    rust) check_rust ;;
    db) check_config; supabase test db ;;
    *) echo 'Usage: bash scripts/check-core.sh [all|rust|db]' >&2; exit 2 ;;
esac
