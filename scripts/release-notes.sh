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
# A breaking commit ("feat!:", "fix(x)!:") carries its upgrade notes in the
# body, and a subject alone never reaches the release page. Print the body
# under the bullet, indented, without trailers such as Co-Authored-By.
for sha in $(git log ${range} --pretty=format:'%H' --no-merges); do
  subject="$(git log -1 --pretty=format:'%s' "${sha}")"
  echo "- ${subject} ($(git log -1 --pretty=format:'%h' "${sha}"))"
  case "${subject}" in
    *'!:'*)
      git log -1 --pretty=format:'%b' "${sha}" \
        | grep -viE '^(Co-Authored-By|Signed-off-by):' \
        | awk '/^[[:space:]]*$/ { blank = blank "\n"; next } { printf "%s  %s\n", blank, $0; blank = "" }'
      ;;
  esac
done
# Do not emit a Full Changelog link here: softprops/action-gh-release with
# generate_release_notes: true appends one already (duplicate otherwise).
