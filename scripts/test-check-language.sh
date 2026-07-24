#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf '%s\n' 'repository language check tests failed' >&2
  exit 1
}

expect_success() {
  "$@" >/dev/null 2>&1 || fail
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    fail
  fi
}

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || fail
readonly script_directory
work_directory=$(mktemp -d "${TMPDIR:-/tmp}/openbox-language-check.XXXXXXXX") || fail
readonly work_directory
trap 'rm -rf -- "$work_directory"' EXIT

repository="$work_directory/repository"
mkdir -p -- "$repository/scripts" "$repository/notes with spaces" || fail
git -C "$repository" init -q >/dev/null 2>&1 || fail
cp -- "$script_directory/check-language.sh" "$repository/scripts/check-language.sh" || fail

boundary='Integration P''oC/showcase material belongs exclusively to the separate `OpenBox-AI/openbox-sandbox-p''oc` repository and is not a dependency.'
printf '%s\n' "$boundary" >"$repository/README.md"
printf '%s\n' 'Examples, demos, and showcases are legitimate terms.' \
  >"$repository/notes with spaces/allowed words.txt"
long_value='PrOoF'' of ''CoNcEpT'
printf '\000%s\000' "$long_value" >"$repository/notes with spaces/binary.dat"
git -C "$repository" add -A >/dev/null 2>&1 || fail
expect_success "$repository/scripts/check-language.sh"

short_value='P''oC'
printf '%s\n' "$short_value" >"$repository/notes with spaces/rejected.txt"
git -C "$repository" add -A >/dev/null 2>&1 || fail
expect_failure "$repository/scripts/check-language.sh"
git -C "$repository" rm -q -f -- "notes with spaces/rejected.txt" >/dev/null 2>&1 || fail

printf '%s\n' "$long_value" >"$repository/notes with spaces/rejected.txt"
git -C "$repository" add -A >/dev/null 2>&1 || fail
expect_failure "$repository/scripts/check-language.sh"
git -C "$repository" rm -q -f -- "notes with spaces/rejected.txt" >/dev/null 2>&1 || fail

compound_value='GrOuNd''-uP'
printf '%s\n' "$compound_value" >"$repository/notes with spaces/rejected.txt"
git -C "$repository" add -A >/dev/null 2>&1 || fail
expect_failure "$repository/scripts/check-language.sh"
git -C "$repository" rm -q -f -- "notes with spaces/rejected.txt" >/dev/null 2>&1 || fail

printf '%s\n' "$boundary extra" >"$repository/README.md"
expect_failure "$repository/scripts/check-language.sh"
printf '%s\n' "$boundary" >"$repository/README.md"
expect_success "$repository/scripts/check-language.sh"

mkdir -p -- "$work_directory/outside/scripts" || fail
cp -- "$script_directory/check-language.sh" "$work_directory/outside/scripts/check-language.sh" || fail
expect_failure "$work_directory/outside/scripts/check-language.sh"

printf '%s\n' 'repository language check tests passed'
