#!/usr/bin/env bash
set -euo pipefail

trap 'echo "Install failed on line ${LINENO}." >&2' ERR

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [--api-only|--full]

  --full      Install and verify the full local stack prerequisites. This is the default.
  --api-only  Set up the Python environment only. Docker is not required in this mode.
EOF
}

mode="--full"
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  case "$1" in
    --full|--api-only)
      mode="$1"
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
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${PYTHON:-python3}"
venv_dir="${VENV_DIR:-$repo_root/.venv}"

if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "Python 3 is required but '$python_bin' was not found on PATH." >&2
  echo "Install Python 3.10+ first, then rerun this script." >&2
  exit 1
fi

python_version="$("$python_bin" - <<'PY'
import sys
print(".".join(map(str, sys.version_info[:3])))
PY
)"
if ! "$python_bin" - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
then
  echo "Python 3.10 or newer is required. Found ${python_version}." >&2
  exit 1
fi

if [[ "$mode" == "--full" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for the full stack but was not found on PATH." >&2
    echo "Use --api-only if you only want the Python environment prepared." >&2
    exit 1
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 is required, but 'docker compose' is not available." >&2
    exit 1
  fi
fi

if [[ ! -d "$venv_dir" ]]; then
  "$python_bin" -m venv "$venv_dir"
fi

# shellcheck disable=SC1090
source "$venv_dir/bin/activate"

python -m ensurepip --upgrade >/dev/null 2>&1 || true

python -m pip install -r "$repo_root/requirements.txt"

if [[ -f "$repo_root/requirements-dev.txt" ]]; then
  python -m pip install -r "$repo_root/requirements-dev.txt"
fi

python -m compileall "$repo_root/mangopanel" "$repo_root/scripts" "$repo_root/tests" >/dev/null

echo "Python environment is ready in: $venv_dir"
echo "Python dependencies installed from requirements.txt"
if [[ "$mode" == "--full" ]]; then
  echo "Docker and Docker Compose are available."
fi
echo "Next: make dev-init"
