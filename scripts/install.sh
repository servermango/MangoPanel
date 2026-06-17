#!/usr/bin/env bash
set -euo pipefail

trap 'echo "Install failed on line ${LINENO}." >&2' ERR

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [--api-only|--full]

  --full      Install system prerequisites plus the Python environment. This is the default.
  --api-only  Install non-Docker prerequisites plus the Python environment.
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
repo_remote_url="${REPO_REMOTE_URL:-https://github.com/servermango/MangoPanel.git}"
venv_dir="${VENV_DIR:-$repo_root/.venv}"
target_user="${SUDO_USER:-$USER}"
needs_new_login=false

say() {
  printf '%s\n' "$*"
}

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_sudo() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

detect_os() {
  local uname_out
  uname_out="$(uname -s)"
  case "$uname_out" in
    Darwin)
      echo "macos"
      ;;
    Linux)
      if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}" in
          ubuntu|debian)
            echo "${ID}"
            ;;
          *)
            echo "linux"
            ;;
        esac
      else
        echo "linux"
      fi
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

ensure_homebrew() {
  if have_cmd brew; then
    return
  fi

  if ! xcode-select -p >/dev/null 2>&1; then
    xcode-select --install || true
    die "Xcode Command Line Tools are required before Homebrew can be installed. Finish that installer, then rerun scripts/install.sh."
  fi

  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi

  have_cmd brew || die "Homebrew installation completed, but 'brew' is still not on PATH."
}

ensure_brew_shellenv() {
  if ! have_cmd brew; then
    return
  fi

  local brew_bin
  brew_bin="$(command -v brew)"
  eval "$("$brew_bin" shellenv)"
}

install_macos_prereqs() {
  ensure_homebrew
  ensure_brew_shellenv

  brew update
  brew install python@3.13 git make lsof

  if [[ "$mode" == "--full" ]]; then
    brew install --cask docker
    if [[ -d /Applications/Docker.app || -d "$HOME/Applications/Docker.app" ]]; then
      open -a Docker || true
    fi
  fi
}

install_apt_basics() {
  run_sudo apt-get update
  run_sudo apt-get install -y ca-certificates curl git lsof make python3 python3-pip python3-venv tar
}

install_linux_docker() {
  local distro="${1}"
  local repo_url

  case "$distro" in
    ubuntu)
      repo_url="https://download.docker.com/linux/ubuntu"
      ;;
    debian)
      repo_url="https://download.docker.com/linux/debian"
      ;;
    *)
      die "Automatic Docker installation is only supported on Ubuntu and Debian in this installer."
      ;;
  esac

  run_sudo install -m 0755 -d /etc/apt/keyrings
  run_sudo curl -fsSL "${repo_url}/gpg" -o /etc/apt/keyrings/docker.asc
  run_sudo chmod a+r /etc/apt/keyrings/docker.asc

  local codename arch source_line
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}")"
  arch="$(dpkg --print-architecture)"
  [[ -n "$codename" ]] || die "Could not determine Linux codename from /etc/os-release."

  source_line="deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] ${repo_url} ${codename} stable"
  printf '%s\n' "$source_line" | run_sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

  run_sudo apt-get update
  run_sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  run_sudo systemctl enable --now docker

  if id -nG "$target_user" | tr ' ' '\n' | grep -qx docker; then
    return
  fi

  run_sudo usermod -aG docker "$target_user"
  needs_new_login=true
}

install_linux_prereqs() {
  local distro="${1}"
  case "$distro" in
    ubuntu|debian)
      install_apt_basics
      if [[ "$mode" == "--full" ]]; then
        install_linux_docker "$distro"
      fi
      ;;
    *)
      die "Unsupported Linux distribution for automatic bootstrap. Use Ubuntu or Debian, or install python3, git, make, curl, tar, lsof, and Docker manually."
      ;;
  esac
}

wait_for_docker() {
  local attempts=30

  if [[ "$mode" != "--full" ]]; then
    return
  fi

  if ! have_cmd docker; then
    die "Docker CLI is still unavailable after installation."
  fi

  while (( attempts > 0 )); do
    if docker info >/dev/null 2>&1; then
      return
    fi
    sleep 2
    attempts=$((attempts - 1))
  done

  die "Docker was installed but the daemon is not ready. Start Docker Desktop or the Docker service, then rerun scripts/install.sh."
}

prefetch_docker_images() {
  local images=(
    "python:3.11-slim"
    "debian:bookworm-slim"
    "litespeedtech/openlitespeed:latest"
    "lucaslorentz/caddy-docker-proxy:ci-alpine"
    "redis:7-alpine"
    "filebrowser/filebrowser:latest"
    "phpmyadmin:latest"
    "ghcr.io/docker-mailserver/docker-mailserver:latest"
    "djmaze/snappymail:latest@sha256:5e3d990438809a8a49f8ac5758db03e858e6e9fc0e369e1f9e474f7664079905"
    "mariadb:10.11"
    "postgres:16"
    "adminer:latest"
    "alpine:3.20"
    "atmoz/sftp:alpine"
  )

  local image
  for image in "${images[@]}"; do
    say "Pulling Docker image: $image"
    docker pull "$image"
  done
}

ensure_python() {
  local python_bin

  python_bin="${PYTHON:-python3}"
  have_cmd "$python_bin" || die "Python 3 is required but '$python_bin' was not found on PATH."

  local python_version
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
    die "Python 3.10 or newer is required. Found ${python_version}."
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
}

verify_tooling() {
  have_cmd git || die "git is still unavailable after installation."
  have_cmd make || die "make is still unavailable after installation."
  have_cmd curl || die "curl is still unavailable after installation."
  have_cmd tar || die "tar is still unavailable after installation."
  have_cmd lsof || die "lsof is still unavailable after installation."
}

ensure_git_repo() {
  if [[ -d "$repo_root/.git" ]]; then
    return
  fi

  say "Initializing git metadata for future updates."
  (
    cd "$repo_root"
    git init -b main
    git remote add origin "$repo_remote_url"
    git fetch --depth=1 origin main
    git reset --hard FETCH_HEAD
    git branch --set-upstream-to=origin/main main >/dev/null 2>&1 || true
  )
}

main() {
  local os_id
  os_id="$(detect_os)"

  case "$os_id" in
    macos)
      install_macos_prereqs
      ;;
    ubuntu|debian|linux)
      install_linux_prereqs "$os_id"
      ;;
    *)
      die "Unsupported operating system for automatic bootstrap."
      ;;
  esac

  ensure_brew_shellenv
  verify_tooling
  ensure_git_repo
  wait_for_docker
  if [[ "$mode" == "--full" ]]; then
    prefetch_docker_images
  fi
  ensure_python

  python -m compileall "$repo_root/mangopanel" "$repo_root/scripts" "$repo_root/tests" >/dev/null

  say "Python environment is ready in: $venv_dir"
  say "System prerequisites installed: git, make, curl, tar, lsof, python3"
  if [[ "$mode" == "--full" ]]; then
    say "Docker and Docker Compose are installed, reachable, and the project images are pre-pulled."
  fi
  if [[ "$needs_new_login" == true ]]; then
    say "You were added to the docker group. Open a new shell session before using Docker without sudo."
  fi
  say "Next: make dev-init"
}

main
