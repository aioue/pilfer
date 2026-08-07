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
echo "### Summary"
git log ${range} --pretty=format:'- %s (%h)' --no-merges
echo
# Do not emit a Full Changelog link here: softprops/action-gh-release with
# generate_release_notes: true appends one already (duplicate otherwise).
