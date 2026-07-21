#!/bin/sh
set -eu

VERSION=${1:-}
if ! printf '%s\n' "$VERSION" |
  grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'
then
  printf '%s\n' "Usage: scripts/build-release.sh vX.Y.Z[-prerelease]" >&2
  exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$ROOT/dist/release-$VERSION"
PREFIX="ginger-personal-agent-$VERSION"
ARCHIVE="$DIST/$PREFIX.tar.gz"

mkdir -p "$DIST"
git -C "$ROOT" diff --quiet --exit-code
git -C "$ROOT" diff --cached --quiet --exit-code
test -z "$(git -C "$ROOT" ls-files --others --exclude-standard)"
python3 "$ROOT/scripts/check-release-tree.py" --tracked-tree
git -C "$ROOT" archive --format=tar --prefix="$PREFIX/" HEAD | gzip -9 > "$ARCHIVE"
python3 "$ROOT/scripts/check-release-tree.py" --archive "$ARCHIVE"
(
  cd "$DIST"
  shasum -a 256 "$(basename "$ARCHIVE")" > SHA256SUMS
)
printf '%s\n' "$ARCHIVE"
