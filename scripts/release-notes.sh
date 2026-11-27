#!/usr/bin/env bash
# Preview GitHub release notes from commits since the previous tag.
set -euo pipefail
cd "$(dirname "$0")/.."

if prev="$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null)"; then
  range="${prev}..HEAD"
else
  range="HEAD"
  prev=""
fi

version="$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")"
echo "## pilfer ${version}"
echo

# The README's "## What's new in MAJOR.MINOR" section, for any version, so the
# release page lists the changes in prose above the commit subjects.
if [[ "${version}" =~ ^([0-9]+\.[0-9]+)\. ]]; then
  whats_new="$(awk -v h="## What's new in ${BASH_REMATCH[1]}" '
    $0 == h { on = 1; next }
    on && /^## / { exit }
    on { print }
  ' README.md)"
  if [[ -n "${whats_new//[[:space:]]/}" ]]; then
    echo "### What's new"
    printf '%s\n' "${whats_new}"
    echo
  fi
fi
echo "### Summary"
git log ${range} --pretty=format:'- %s (%h)' --no-merges
echo

# A new major (X.0.0) carries its upgrade notes in the README's
# "## Upgrading to X.0" section, so the README stays the single source. Print
# nothing extra when the section is missing.
if [[ "${version}" =~ ^([0-9]+)\.0\.0$ ]]; then
  awk -v h="## Upgrading to ${BASH_REMATCH[1]}.0" '
    $0 == h { on = 1; print "\n### Upgrading"; next }
    on && /^## / { exit }
    on { print }
  ' README.md
fi
# Do not emit a Full Changelog link here: softprops/action-gh-release with
# generate_release_notes: true appends one already (duplicate otherwise).
