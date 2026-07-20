#!/bin/sh
set -eu

VERSION=${1:-}
REPOSITORY=${GINGER_AGENT_REPOSITORY:-ChristopherCC-Liu/ginger_wechat_portrait}

if ! printf '%s\n' "$REPOSITORY" |
  grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
then
  printf '%s\n' "error: invalid GitHub owner/repository" >&2
  exit 2
fi
case "/$REPOSITORY/" in
  */../*|*/./*)
    printf '%s\n' "error: invalid GitHub owner/repository" >&2
    exit 2
    ;;
esac

if ! printf '%s\n' "$VERSION" |
  grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'
then
  printf '%s\n' "Usage: scripts/install-release.sh vX.Y.Z[-prerelease]" >&2
  exit 2
fi

ARCHIVE="ginger-personal-agent-${VERSION}.tar.gz"
BASE_URL="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ginger-agent-release.XXXXXX")
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$TMP_ROOT/$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$TMP_ROOT/SHA256SUMS" "$BASE_URL/SHA256SUMS"

(
  cd "$TMP_ROOT"
  grep "  ${ARCHIVE}$" SHA256SUMS > ARCHIVE.SHA256SUM
  [ -s ARCHIVE.SHA256SUM ] || {
    printf '%s\n' "error: release checksum does not list $ARCHIVE" >&2
    exit 1
  }
  shasum -a 256 -c ARCHIVE.SHA256SUM
)

mkdir "$TMP_ROOT/source"
PREFIX="ginger-personal-agent-${VERSION}"
LC_ALL=C tar -tzf "$TMP_ROOT/$ARCHIVE" | while IFS= read -r member; do
  case "$member" in
    "$PREFIX"|"$PREFIX"/*) ;;
    *)
      printf '%s\n' "error: release archive contains an unexpected path" >&2
      exit 1
      ;;
  esac
  case "/$member/" in
    */../*|*/./*|*//*)
      printf '%s\n' "error: release archive contains an unsafe path" >&2
      exit 1
      ;;
  esac
done
LC_ALL=C tar -tvzf "$TMP_ROOT/$ARCHIVE" | while IFS= read -r entry; do
  case "$entry" in
    -*|d*) ;;
    *)
      printf '%s\n' "error: release archive contains a link or special file" >&2
      exit 1
      ;;
  esac
done
LC_ALL=C tar -xzf "$TMP_ROOT/$ARCHIVE" -C "$TMP_ROOT/source" --strip-components=1
exec "$TMP_ROOT/source/install-macos.sh"
