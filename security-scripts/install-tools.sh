#!/usr/bin/env bash
#
# ============================================================
#  Guyma Cyb — Installation complète de la chaîne d'outils
#  réseau & sécurité Linux.
# ============================================================
#
#  Couvre la liste demandée :
#
#  1. Test & diagnostic réseau :
#     iproute2 (ip), ping, mtr, iperf3, netcat/socat, dig/host, ethtool, traceroute
#
#  2. Sécurité & audit réseau :
#     nmap, wireshark/tshark, tcpdump, suricata, snort, aircrack-ng,
#     nftables, openvas/greenbone, nikto, whatweb, sslscan, sqlmap,
#     gobuster, dirb, dnsrecon, masscan, nuclei, hydra, wpscan
#
#  Idempotent : peut être relancé sans effet de bord.
#  Nécessite sudo sur Debian/Ubuntu/Fedora/Arch.
#
#  Usage :
#     sudo ./install-tools.sh            # tout installer
#     ./install-tools.sh --check         # vérifier uniquement (sans sudo)
#     ./install-tools.sh --list          # lister les outils et leur statut
#
# ============================================================
set -euo pipefail

# ---------- Définition des paquets par catégorie ----------

NETWORK_TOOLS=(
  "iproute2"          # commande `ip` (interfaces, routes)
  "iputils-ping"      # ping
  "mtr-tiny"          # mtr (ping + traceroute continu)
  "iperf3"            # mesure de bande passante TCP/UDP/SCTP
  "netcat-openbsd"    # nc — couteau suisse réseau
  "socat"             # relais/reirection réseau avancé
  "dnsutils"          # dig, host, nslookup
  "ethtool"           # paramètres carte réseau (vitesse, duplex)
  "traceroute"        # traceroute ICMP/UDP
  "tcpdump"           # capture de paquets en CLI
  "wireless-tools"    # iwconfig (WiFi)
  "rfkill"            # blocage radio (WiFi/Bluetooth)
)

SECURITY_TOOLS=(
  "nmap"              # scanner de ports & services
  "nikto"             # scanner de vulnérabilités web
  "whatweb"           # empreinte technologies web
  "sslscan"           # audit suites cryptographiques TLS
  "sqlmap"            # tests d'injection SQL automatisés
  "gobuster"          # bruteforce de chemins/sous-domaines
  "dirb"              # bruteforce de chemins web
  "dnsrecon"          # reconnaissance DNS avancée
  "masscan"           # scanner de ports ultra-rapide
  "hydra"             # bruteforce d'authentification
  "wpscan"            # scanner WordPress
  "aircrack-ng"       # suite audit WiFi (ruby/gem)
  "nftables"          # pare-feu natif noyau Linux
  "tshark"            # Wireshark en CLI (dumpcap)
  "suricata"          # IDS/IPS réseau
  "snort"             # IDS/IPS réseau (legacy)
)

# OpenVAS/Greenbone : installation plus lourde (service + feed). Paquets :
OPENVAS_PACKAGES=(
  "gvm"               # Greenbone Vulnerability Management (Debian/Ubuntu)
)

# Outils via pip (si paquet système absent) :
PIP_TOOLS=(
  " nuclei"           # scanner de vulnérabilités basé sur templates (via go souvent)
)

# ---------- Helpers ----------

YELLOW=$'\033[33m'; GREEN=$'\033[32m'; RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

log()  { printf '%s[guyma-cyb]%s %s\n' "$BOLD" "$RESET" "$1"; }
ok()   { printf '%s[  OK  ]%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '%s[ WARN ]%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail() { printf '%s[ FAIL ]%s %s\n' "$RED" "$RESET" "$1" >&2; }
die()  { fail "$1"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

detect_pm() {
  if have apt-get; then echo "apt"
  elif have dnf; then echo "dnf"
  elif have yum; then echo "yum"
  elif have pacman; then echo "pacman"
  elif have zypper; then echo "zypper"
  else echo "none"; fi
}

sudo_cmd() {
  if [ "$(id -u)" -eq 0 ]; then "$@"
  elif have sudo; then sudo "$@"
  else die "sudo requis pour installer des paquets."
  fi
}

# Associe un nom de paquet Debian → nom équivalent sur d'autres distros
pkgname() {
  local p="$1"
  case "$(detect_pm)" in
    dnf|yum)
      case "$p" in
        iputils-ping)      echo "iputils" ;;
        mtr-tiny)          echo "mtr" ;;
        netcat-openbsd)    echo "nmap-ncat" ;;
        dnsutils)          echo "bind-utils" ;;
        iproute2)          echo "iproute" ;;
        tshark)            echo "wireshark-cli" ;;
        gvm)               echo "openvas-scanner" ;;
        *)                 echo "$p" ;;
      esac ;;
    pacman)
      case "$p" in
        iputils-ping)      echo "iputils" ;;
        mtr-tiny)          echo "mtr" ;;
        netcat-openbsd)    echo "gnu-netcat" ;;
        dnsutils)          echo "bind" ;;
        gvm)               echo "openvas" ;;
        *)                 echo "$p" ;;
      esac ;;
    zypper)
      case "$p" in
        iputils-ping)      echo "iputils" ;;
        mtr-tiny)          echo "mtr" ;;
        netcat-openbsd)    echo "gnu-netcat" ;;
        dnsutils)          echo "bind-utils" ;;
        gvm)               echo "openvas" ;;
        *)                 echo "$p" ;;
      esac ;;
    *) echo "$p" ;;
  esac
}

install_one() {
  local pkg="$1"
  local realpkg
  realpkg="$(pkgname "$pkg")"
  case "$(detect_pm)" in
    apt)
      if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive sudo_cmd apt-get install -y -qq "$pkg"
      fi ;;
    dnf) sudo_cmd dnf install -y -q "$realpkg" 2>/dev/null || true ;;
    yum) sudo_cmd yum install -y -q "$realpkg" 2>/dev/null || true ;;
    pacman) sudo_cmd pacman -S --noconfirm --needed "$realpkg" 2>/dev/null || true ;;
    zypper) sudo_cmd zypper -q install -y "$realpkg" 2>/dev/null || true ;;
    none) warn "Aucun gestionnaire de paquets reconnu — ne peut pas installer $pkg" ;;
  esac
}

# ---------- Commandes ----------

cmd_list() {
  cat <<EOF
${BOLD}Outils réseau & diagnostic${RESET}
  iproute2 (ip), iputils-ping (ping), mtr-tiny (mtr), iperf3,
  netcat-openbsd (nc), socat, dnsutils (dig/host), ethtool, traceroute,
  tcpdump, wireless-tools, rfkill

${BOLD}Outils sécurité & audit${RESET}
  nmap, nikto, whatweb, sslscan, sqlmap, gobuster, dirb, dnsrecon,
  masscan, hydra, wpscan, aircrack-ng, nftables, tshark (Wireshark CLI),
  suricata, snort

${BOLD}Scanner de vulnérabilités complet${RESET}
  OpenVAS / Greenbone (gvm)

EOF
}

cmd_check() {
  local all_tools=(ip ping mtr iperf3 nc socat dig host ethtool traceroute
                   tcpdump nmap nikto whatweb sslscan sqlmap gobuster dirb
                   dnsrecon masscan hydra wpscan aircrack-ng nft tshark
                   suricata snort gvm openvas)
  local missing=()
  local found=()
  for t in "${all_tools[@]}"; do
    if have "$t"; then
      found+=("$t")
    else
      missing+=("$t")
    fi
  done
  printf '%s=== Outils installés (%d) ===%s\n' "$GREEN" "${#found[@]}" "$RESET"
  for t in "${found[@]}"; do ok "$t -> $(command -v "$t")"; done
  printf '\n%s=== Outils manquants (%d) ===%s\n' "$YELLOW" "${#missing[@]}" "$RESET"
  for t in "${missing[@]}"; do warn "$t"; done
  if [ ${#missing[@]} -gt 0 ]; then
    printf '\nLancez : sudo %s install-tools.sh\n' "$0"
    return 1
  fi
  return 0
}

cmd_install() {
  local pm; pm="$(detect_pm)"
  [ "$pm" = "none" ] && die "Aucun gestionnaire de paquets reconnu (apt/dnf/yum/pacman/zypper)."

  log "Gestionnaire détecté : $pm"

  # Mise à jour index
  case "$pm" in
    apt)    sudo_cmd apt-get update -qq ;;
    dnf|yum) sudo_cmd "$pm" -q makecache 2>/dev/null || true ;;
    pacman) : ;;
    zypper) sudo_cmd zypper -q refresh 2>/dev/null || true ;;
  esac

  log "Installation des outils réseau..."
  for p in "${NETWORK_TOOLS[@]}"; do
    log "→ $p"; install_one "$p" || warn "échec install $p"
  done

  log "Installation des outils de sécurité..."
  for p in "${SECURITY_TOOLS[@]}"; do
    log "→ $p"; install_one "$p" || warn "échec install $p"
  done

  log "Installation d'OpenVAS/Greenbone (lourd — peut prendre plusieurs minutes)..."
  for p in "${OPENVAS_PACKAGES[@]}"; do
    log "→ $p"; install_one "$p" || warn "échec install $p (disponible sur Debian/Ubuntu principalement)"
  done

  # nuclei : souvent via Go ou binaire dédié
  if ! have nuclei; then
    log "Installation de nuclei (binaire GitHub)..."
    if have curl && have unzip; then
      local tmp; tmp="$(mktemp -d)"
      if curl -sSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip" -o "$tmp/nuclei.zip" 2>/dev/null && [ -s "$tmp/nuclei.zip" ]; then
        (cd "$tmp" && unzip -o -q nuclei.zip && sudo_cmd mv nuclei /usr/local/bin/ && sudo_cmd chmod +x /usr/local/bin/nuclei) || warn "échec nuclei"
        ok "nuclei installé"
      else
        warn "nuclei : téléchargement échoué (installez via : go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
      fi
      rm -rf "$tmp"
    fi
  fi

  log "Vérification finale..."
  cmd_check || warn "Certains outils restent manquants — voir ci-dessus."

  cat <<EOF

${GREEN}${BOLD}=== Installation terminée ===${RESET}

  OpenVAS/Greenbone nécessite une initialisation post-install :
    sudo gvm-setup          # (long : télécharge les feeds NVT)
    sudo gvm-start
    # Interface web : https://127.0.0.1:9392

  Suricata/Snort nécessitent des règles ( Emerging Threats / Talos ).

  Pour capturer en raw (tcpdump/tshark/suricata) sans sudo :
    sudo usermod -aG wireshark \$USER      # pour tshark
    (se déconnecter/reconnecter)

EOF
}

# ---------- Entrée ----------

case "${1:-install}" in
  install|"")   cmd_install ;;
  --check|check)cmd_check ;;
  --list|list)  cmd_list ;;
  -h|--help)
    echo "Usage: $0 [install|--check|--list]"
    echo "  install (défaut) : installe toute la chaîne d'outils (sudo requis)"
    echo "  --check          : affiche les outils installés/manquants (sans sudo)"
    echo "  --list           : liste les outils ciblés"
    ;;
  *) die "argument inconnu : $1 (essayer --help)" ;;
esac
