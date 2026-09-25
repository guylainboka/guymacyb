#!/usr/bin/env bash
#
# Guyma Cyb - Installation de la chaîne d'outils de sécurité Linux.
#
# Installe les binaires utilisés par le moteur de scan. Idempotent : peut être
# relancé sans effet de bord. Nécessite un accès sudo sur une distribution
# basée sur Debian/Ubuntu.
#
set -euo pipefail

APT_PACKAGES=(
  nmap
  whatweb
  sslscan
  dnsutils
  curl
  openssl
  ca-certificates
)

log() {
  printf '[guyma-cyb] %s\n' "$1"
}

die() {
  printf '[guyma-cyb] ERREUR: %s\n' "$1" >&2
  exit 1
}

require_apt() {
  command -v apt-get >/dev/null 2>&1 ||
    die "apt-get introuvable. Ce script cible les distributions Debian/Ubuntu."
}

sudo_cmd() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    command -v sudo >/dev/null 2>&1 || die "sudo requis pour installer les paquets."
    sudo "$@"
  fi
}

install_apt_packages() {
  local missing=()
  local pkg
  for pkg in "${APT_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done

  if [ ${#missing[@]} -eq 0 ]; then
    log "Tous les paquets apt sont déjà installés."
    return
  fi

  log "Installation des paquets manquants : ${missing[*]}"
  sudo_cmd apt-get update -qq
  DEBIAN_FRONTEND=noninteractive sudo_cmd apt-get install -y -qq "${missing[@]}"
}

verify() {
  local failed=0
  local tool
  for tool in nmap whatweb sslscan dig openssl curl; do
    if command -v "$tool" >/dev/null 2>&1; then
      log "OK   $tool -> $(command -v "$tool")"
    else
      log "FAIL $tool introuvable"
      failed=1
    fi
  done
  return "$failed"
}

main() {
  require_apt
  install_apt_packages
  log "Vérification de la chaîne d'outils..."
  if verify; then
    log "Chaîne d'outils de sécurité prête."
  else
    die "Certains outils n'ont pas pu être installés."
  fi
}

main "$@"
