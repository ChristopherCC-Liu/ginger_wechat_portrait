#!/bin/sh
set -eu

APP_ROOT="${GINGER_AGENT_HOME:-$HOME/Library/Application Support/GingerAgent}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_SERVICE=0

usage() {
  printf '%s\n' "Usage: ./install-macos.sh [--python /path/to/python] [--install-service]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --python)
      [ "$#" -ge 2 ] || { usage >&2; exit 2; }
      PYTHON_BIN="$2"
      shift 2
      ;;
    --install-service)
      INSTALL_SERVICE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || {
  printf '%s\n' "error: Ginger Personal Agent service installation requires macOS" >&2
  exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ -f "$SCRIPT_DIR/pyproject.toml" ] || {
  printf '%s\n' "error: run this script from an intact release archive" >&2
  exit 1
}
[ -f "$SCRIPT_DIR/requirements.lock" ] || {
  printf '%s\n' "error: requirements.lock is missing from the release" >&2
  exit 1
}

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  printf '%s\n' "error: Python 3.10 or newer is required" >&2
  exit 1
}

umask 077
VENV_ROOT="$APP_ROOT/venvs"
for PRIVATE_PATH in "$APP_ROOT" "$APP_ROOT/bin" "$APP_ROOT/logs" "$APP_ROOT/state" "$VENV_ROOT"
do
  [ ! -L "$PRIVATE_PATH" ] || {
    printf '%s\n' "error: refusing symbolic-link install path: $PRIVATE_PATH" >&2
    exit 1
  }
done
mkdir -p \
  "$APP_ROOT" "$APP_ROOT/bin" "$APP_ROOT/logs" "$APP_ROOT/state" "$VENV_ROOT"
chmod 700 \
  "$APP_ROOT" "$APP_ROOT/bin" "$APP_ROOT/logs" "$APP_ROOT/state" "$VENV_ROOT"

VENV="$APP_ROOT/venv"
NEW_VENV="$VENV_ROOT/release-$(date -u +%Y%m%dT%H%M%SZ)-$$"
NEW_LINK="$APP_ROOT/.venv-link.$$"
PREVIOUS_LINK="$APP_ROOT/venv.previous"
SWAPPED=0
cleanup() {
  rm -f "$NEW_LINK"
  if [ "$SWAPPED" -eq 0 ]; then
    rm -rf "$NEW_VENV"
  fi
}
trap cleanup EXIT HUP INT TERM

"$PYTHON_BIN" -m venv "$NEW_VENV"
"$NEW_VENV/bin/python" -m pip install --disable-pip-version-check --require-hashes \
  -r "$SCRIPT_DIR/requirements.lock"
"$NEW_VENV/bin/python" -m pip install --disable-pip-version-check \
  --no-build-isolation --no-deps "$SCRIPT_DIR"
ENTRY_POINTS="
ginger-agent
ginger-shadow-replay
ginger-wechat-db-doctor
ginger-wechat-find-keys
ginger-wechat-decrypt
"
for COMMAND in $ENTRY_POINTS
do
  ENTRY="$NEW_VENV/bin/$COMMAND"
  [ -f "$ENTRY" ] && [ ! -L "$ENTRY" ] && [ -x "$ENTRY" ] || {
    printf '%s\n' "error: installed entry point is invalid: $COMMAND" >&2
    exit 1
  }
  "$ENTRY" --help >/dev/null
done

ln -s "$NEW_VENV" "$NEW_LINK"
if [ -L "$VENV" ]; then
  OLD_TARGET=$(readlink "$VENV")
  case "$OLD_TARGET" in
    "$VENV_ROOT"/*) ln -sfn "$OLD_TARGET" "$PREVIOUS_LINK" ;;
  esac
  mv -fh "$NEW_LINK" "$VENV"
elif [ -e "$VENV" ]; then
  LEGACY_VENV="$VENV_ROOT/legacy-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mv "$VENV" "$LEGACY_VENV"
  ln -sfn "$LEGACY_VENV" "$PREVIOUS_LINK"
  mv "$NEW_LINK" "$VENV"
else
  mv "$NEW_LINK" "$VENV"
fi
SWAPPED=1
trap - EXIT HUP INT TERM

for COMMAND in $ENTRY_POINTS
do
  ln -sfn "$VENV/bin/$COMMAND" "$APP_ROOT/bin/$COMMAND"
done
cp "$SCRIPT_DIR/scripts/install-release.sh" "$APP_ROOT/bin/install-release"
chmod 700 "$APP_ROOT/bin/install-release"

CONFIG="$APP_ROOT/config.toml"
[ ! -L "$CONFIG" ] || {
  printf '%s\n' "error: refusing symbolic-link config: $CONFIG" >&2
  exit 1
}
if [ ! -e "$CONFIG" ]; then
  cp "$SCRIPT_DIR/config.example.toml" "$CONFIG"
  chmod 600 "$CONFIG"
fi

printf '%s\n' "Installed Ginger Personal Agent into: $APP_ROOT"
printf '%s\n' "Configuration: $CONFIG"
printf '%s\n' "Command: $APP_ROOT/bin/ginger-agent"

if [ "$INSTALL_SERVICE" -eq 1 ]; then
  "$APP_ROOT/bin/ginger-agent" --config "$CONFIG" install-service
else
  printf '%s\n' "Service not loaded. Configure Keychain/database, run doctor, then install-service."
fi
