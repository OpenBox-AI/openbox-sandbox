#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf '%s\n' 'repository language check failed' >&2
  exit 1
}

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || fail
repository_root=$(git -C "$script_directory" rev-parse --show-toplevel 2>/dev/null) || fail
cd -- "$repository_root" || fail

short_term=$(printf '\160\157\143')
readonly short_term
readonly forbidden_pattern="(^|[^[:alnum:]_])${short_term}s?([^[:alnum:]_]|$)|proof[-_[:space:]]*of[-_[:space:]]*concepts?|ground[-_[:space:]]*up"
readonly allowed_boundary='Integration P''oC/showcase material belongs exclusively to the separate `OpenBox-AI/openbox-sandbox-p''oc` repository and is not a dependency.'

set +e
git grep -I -i -E "$forbidden_pattern" -- . ':(exclude)README.md' >/dev/null 2>&1
scan_status=$?
set -e
case $scan_status in
  0) fail ;;
  1) ;;
  *) fail ;;
esac

set +e
readme_matches=$(git grep -I -i -h -E "$forbidden_pattern" -- README.md 2>/dev/null)
readme_status=$?
set -e
[[ $readme_status -eq 0 ]] || fail
[[ $readme_matches == "$allowed_boundary" ]] || fail

printf '%s\n' 'repository language check passed'
