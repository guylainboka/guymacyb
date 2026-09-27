import { WifiLabVector } from '../types';

/**
 * WIFI_LAB_VECTORS — Catalogue de vecteurs d'attaques WiFi pour le laboratoire
 * de simulation défensive (sandbox Guyma Cyb). Chaque vecteur documente :
 *   - un scénario d'attaque réaliste (en français),
 *   - une sonde de test NON DESTRUCTIVE (safe payload),
 *   - les comportements attendus (vulnérable vs remédié),
 *   - les contrôles défensifs à mettre en œuvre,
 *   - un exemple de configuration hostapd/wpa_supplicant (vulnérable vs fixé).
 *
 * Les attaques décrites sont strictement pédagogiques : aucune n'est exécutée
 * sur un réseau réel. La simulation renvoie le comportement théorique observé
 * sur un environnement de laboratoire isolé.
 */
export const WIFI_LAB_VECTORS: WifiLabVector[] = [
  // ============================================================
  // 1. Déauthentification flood (deauth frames)
  // ============================================================
  {
    id: 'wifi-deauth-flood',
    name: 'Déauthentification Flood 802.11 (Deauth Storm)',
    category: 'WIFI_DEAUTH',
    mitre: 'T1565.002 — Disk Wipe / Service Exhaustion (Wireless DoS)',
    severity: 'HIGH',
    difficulty: 'FAIBLE',
    targetEncryption: 'WPA2',
    description:
      'Envoi de trames de gestion 802.11 deauth (subtype 0x0C) forgées avec l\'adresse source du point d\'accès légitime. Les clients se voient notifier "déconnexion" et tentent de se réauthentifier, créant un déni de service permanent. Sans PMF (Protected Management Frames), ces trames sont acceptées sans vérification.',
    attackScenario:
      'Un attaquant sniffe le canal de l\'AP cible (airodump-ng), récupère le BSSID et la liste des clients, puis envoie en boucle des trames deauth broadcast (`aireplay-ng --deauth 0 -a <BSSID>`). En moins de 10 secondes, le réseau devient inutilisable. Cette attaque précède souvent la capture de handshake (forcer le client à se réauthentifier pour capturer le 4-way).',
    safeTestPayload:
      'airodump-ng --bssid AA:BB:CC:DD:EE:01 -c 6 wlan0mon  # (passive sniff only — sonde bénigne)',
    vulnerableResponseSample: `802.11 frame capture (wlan0mon) — channel 6
[2025-09-25T12:00:01Z] Deauth frame: src=AA:BB:CC:DD:EE:01 dst=FF:FF:FF:FF:FF:FF reason=7
[2025-09-25T12:00:01Z] Deauth frame: src=AA:BB:CC:DD:EE:01 dst=FF:FF:FF:FF:FF:FF reason=7
[2025-09-25T12:00:02Z] Deauth frame: src=AA:BB:CC:DD:EE:01 dst=FF:FF:FF:FF:FF:FF reason=7
... 28 frames in 2.1 seconds → DEAUTH_FLOOD detected
PMF: disabled (ieee80211w=0) — deauth frames accepted without verification
Client count: 4 → 0 in 2 seconds (all disconnected)`,
    remediatedResponseSample: `802.11 frame capture (wlan0mon) — channel 6
[2025-09-25T12:00:01Z] Deauth frame: src=AA:BB:CC:DD:EE:01 dst=FF:FF:FF:FF:FF:FF reason=7
[2025-09-25T12:00:01Z] → DROPPED by client (PMF required, frame unicast+unprotected not BIP-CMAC-128 signed)
[2025-09-25T12:00:02Z] Deauth frame: src=AA:BB:CC:DD:EE:01 dst=FF:FF:FF:FF:FF:FF reason=7
[2025-09-25T12:00:02Z] → DROPPED by client (BIP-CMAC-128 validation failed)
PMF: required (ieee80211w=2) — broadcast deauth frames ignored by 802.11w clients
Client count: 4 → 4 (no disconnection observed)`,
    vulnerableBehaviorExplanation:
      'Sans PMF (802.11w), les trames deauth sont acceptées sans authentification. Le client déconnecté tente immédiatement de se réauthentifier, ce qui permet aussi à l\'attaquant de capturer le 4-way handshake (EAPOL M1-M4) en passif.',
    remediatedBehaviorExplanation:
      'Avec PMF requis (ieee80211w=2), les clients ignorent les trames de gestion broadcast non signées. Les trames unicast doivent être signées avec BIP-CMAC-128 (Broadcast/Multicast Management Integrity Protocol). Le déni de service devient impossible sans compromission de la clé PMF.',
    defensiveControls: [
      'Activer PMF obligatoire (ieee80211w=2) côté AP et clients WPA2/WPA3',
      'Migrer vers WPA3-SAE (PMF obligatoire par spécification)',
      'Mettre en place un IDS sans fil (wIDS) détectant les vagues de deauth > 10/sec',
      'Segmenter le réseau sans fil (VLAN invité, 802.1X, isolation client)',
      'Configurer la détection de Canaux Radar DFS pour éviter le blocage sur des canaux saturés',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf (AP configuration)',
      vulnerable: `# ❌ VULNERABLE : PMF désactivé
interface=wlan0
ssid=Company-WiFi
wpa=2
wpa_passphrase=...
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
ieee80211w=0          # PMF disabled → deauth frames accepted
macaddr_acl=0`,
      fixed: `# ✅ SECURISE : PMF obligatoire (802.11w)
interface=wlan0
ssid=Company-WiFi
wpa=2
wpa_passphrase=...
wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256 SAE   # WPA2/WPA3 transition
wpa_pairwise=CCMP
ieee80211w=2          # PMF REQUIRED — broadcast deauth ignored
sae_pmkid_in_connect=1
sae_require_mac=1`,
    },
  },

  // ============================================================
  // 2. Evil Twin
  // ============================================================
  {
    id: 'wifi-evil-twin',
    name: 'Evil Twin (Faux Point d\'Accès Usurpateur)',
    category: 'WIFI_EVIL_TWIN',
    mitre: 'T1557.003 — Adversary-in-the-Middle: DHCP Spoofing / Rogue AP',
    severity: 'CRITICAL',
    difficulty: 'MOYEN',
    targetEncryption: 'OPEN',
    description:
      'Déploiement d\'un faux point d\'accès avec le même SSID (et idéalement un BSSID usurpé / signal plus fort) que la cible. Les clients dont la configuration privilégie le signal le plus fort s\'y connectent automatiquement. L\'attaquant intercepte tout le trafic (MITM), déploie un portail captif pour voler les identifiants, ou redirige vers des pages de phishing.',
    attackScenario:
      'Étapes : (1) sniffer le SSID/BSSID/canal de l\'AP légitime, (2) configurer hostapd avec le même SSID sur un canal adjacent (ou même canal avec un BSSID proche), (3) amplifier le signal (antenne directionnelle), (4) forcer la déconnexion des clients légitimes (deauth flood), (5) déployer dnsmasq + nginx + portail captif. Le client se reconnecte au faux AP et est redirigé vers `login.evil-twin.local`.',
    safeTestPayload:
      'hostapd -B evil-twin.conf  # (sandbox only — sonde bénigne en lab isolé)',
    vulnerableResponseSample: `Client association log (wlan0mon) — evil twin AP
[2025-09-25T12:00:05Z] Probe request from AA:BB:CC:11:22:33 for "Company-WiFi"
[2025-09-25T12:00:05Z] Probe response (evil-twin-BSSID) — signal -45 dBm (vs -68 dBm legit AP)
[2025-09-25T12:00:06Z] Association: AA:BB:CC:11:22:33 → evil-twin-BSSID
[2025-09-25T12:00:06Z] DHCP OFFER: 10.0.99.42 (evil-twin DHCP, DNS → attacker)
[2025-09-25T12:00:07Z] HTTP GET http://login.microsoftonline.com/ → 302 http://login.evil-twin.local/
[2025-09-25T12:00:08Z] POST /login.evil-twin.local/ credentials=alice@company.com:Password123!
No PMF, no certificate validation by client → MITM successful`,
    remediatedResponseSample: `Client association log (wlan0mon) — evil twin AP rejected
[2025-09-25T12:00:05Z] Probe request from AA:BB:CC:11:22:33 for "Company-WiFi"
[2025-09-25T12:00:05Z] Probe response (evil-twin-BSSID) — signal -45 dBm
[2025-09-25T12:00:06Z] SAE handshake: evil-twin cannot derive PMK → association REJECTED
[2025-09-25T12:00:06Z] Client connects to legitimate AP (BSSID AA:BB:CC:DD:EE:01, PMF required)
[2025-09-25T12:00:07Z] HTTP GET http://login.microsoftonline.com/ → legitimate 200 (TLS verified)
WPA3-SAE + PMF + EAP-TLS client certificate → evil twin cannot impersonate AP`,
    vulnerableBehaviorExplanation:
      'Le client WPA2-PSK ne peut pas distinguer le vrai AP du faux : la passphrase PSK est partagée et identique sur les deux AP. L\'absence de PMF permet au faux AP de forger des deauth pour déconnecter les clients du vrai AP. Une fois connecté au faux AP, tout le trafic est intercepté (HTTP en clair) ou redirigé (DNS spoofing).',
    remediatedBehaviorExplanation:
      'Avec WPA3-SAE, le client et l\'AP s\'authentifient mutuellement via le Dragonfly protocol : un faux AP ne connaissant pas le mot de passe SAE ne peut pas terminer le handshake. L\'EAP-TLS (certificat client + serveur) ajoute une authentification forte du serveur. Le WIDS détecte les double-BSSID (même SSID, deux BSSIDs différents).',
    defensiveControls: [
      'Déployer WPA3-SAE (authentification mutuelle AP-client impossible à usurper)',
      'Activer PMF (ieee80211w=2) pour empêcher le deauth forcé vers le faux AP',
      'Mettre en place EAP-TLS (certificats client + serveur) plutôt que PSK',
      'Déployer un WIDS détectant les SSID en double / BSSID inconnus sur le canal',
      'Forcer HTTPS + HSTS + certificate pinning sur tous les portails d\'authentification',
      'Sensibiliser les utilisateurs à ne jamais valider d\'avertissement de certificat',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf (AP) + wpa_supplicant (client)',
      vulnerable: `# ❌ VULNERABLE : WPA2-PSK sans PMF
ssid=Company-WiFi
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
ieee80211w=0
# Client: n'importe quel AP avec la bonne passphrase est accepté`,
      fixed: `# ✅ SECURISE : WPA3-SAE + PMF + EAP-TLS
ssid=Company-WiFi
wpa=2
wpa_key_mgmt=SAE WPA-EAP-SUITE-B-192
wpa_pairwise=GCMP-256
ieee80211w=2
sae_pwe=2
eap_server=1
eap_user_file=/etc/hostapd.eap_user
ca_cert=/etc/hostapd/ca.pem
server_cert=/etc/hostapd/server.pem
private_key=/etc/hostapd/server.key
# Client: vérifie le certificat serveur (EAP-TLS), impossible pour un evil twin`,
    },
  },

  // ============================================================
  // 3. KRACK (Key Reinstallation Attack)
  // ============================================================
  {
    id: 'wifi-krack',
    name: 'KRACK — Key Reinstallation Attack (CVE-2017-13077)',
    category: 'WIFI_KRACK',
    mitre: 'T1578 — Modify Cloud Compute Infrastructure / Cryptographic Downgrade',
    severity: 'HIGH',
    difficulty: 'ÉLEVÉ',
    targetEncryption: 'WPA2',
    description:
      'La vulnérabilité CVE-2017-13077 (Mathy Vanhoef) exploite une faille dans la réinstallation des clés PTK/GTK pendant le 4-way handshake. En rejouant le message M3 du handshake, l\'attaquant force la réinstallation d\'une clé déjà en usage, ce qui remet à zéro les nonces de chiffrement et permet le déchiffrement de paquets ultérieurs (notamment les requêtes ARP, ce qui conduit au déchiffrement TCP et à l\'injection HTTP).',
    attackScenario:
      'Phase 1 : position Man-in-the-Middle sur le canal (ne bloque pas l\'AP, juste forward). Phase 2 : attendre le 4-way handshake (à la connexion du client ou forcer une rekey). Phase 3 : capturer M1+M2+M3, puis retransmettre M3 plusieurs fois. Le client réinstalle la même PTK → les numéros de paquet (PN) sont réinitialisés → keystream réutilisé. Phase 4 : XOR de deux paquets chiffrés avec le même keystream → déchiffrement partiel.',
    safeTestPayload:
      'krackattack/krack-ft-test.py --help  # (script de PoC, à exécuter en lab isolé uniquement)',
    vulnerableResponseSample: `4-way handshake replay trace (krack-ft-test)
[12:00:00] M1: AP → Client  ANonce=0x1234...
[12:00:00] M2: Client → AP   SNonce=0x5678... MIC=valid  (PTK derived)
[12:00:00] M3: AP → Client   install PTK, install GTK
[12:00:00] M3 (REPLAY #1): AP → Client  install PTK AGAIN → PN reset to 1
[12:00:01] M3 (REPLAY #2): AP → Client  install PTK AGAIN → PN reset to 1
[12:00:01] Client sends encrypted ARP request, PN=1, keystream=K1
[12:00:02] Client sends encrypted ARP request, PN=2, keystream=K2
... XOR(K1, K2) reveals plaintext XOR plaintext → ARP request decodable
Impact: TCP SYN/ACK decryption possible, HTTP session hijack feasible`,
    remediatedResponseSample: `4-way handshake replay trace (patched client)
[12:00:00] M1: AP → Client  ANonce=0x1234...
[12:00:00] M2: Client → AP   SNonce=0x5678... MIC=valid  (PTK derived)
[12:00:00] M3: AP → Client   install PTK (first time), GTK
[12:00:00] M3 (REPLAY #1): AP → Client → REJECTED: PTK already installed, PN not reset
[12:00:01] M3 (REPLAY #2): AP → Client → REJECTED: handshake replay protection
[12:00:01] Client sends encrypted ARP, PN=monotonic, keystream=unique per packet
No keystream reuse → no decryption possible`,
    vulnerableBehaviorExplanation:
      'Le client vulnérable accepte de réinstaller la PTK à chaque réception d\'un M3 valide (même si la clé est déjà installée). La spécification 802.11 ne précisait pas explicitement de protection contre ce replay. La réinstallation remet à zéro le compteur de paquets (Packet Number), menant à la réutilisation du keystream et au déchiffrement.',
    remediatedBehaviorExplanation:
      'Le patch (Linux wpa_supplicant 2.6+, Windows 2017-10, macOS 10.13+) refuse de réinstaller une clé déjà installée : si M3 est reçu alors que la PTK est déjà en place, le client rejettera silencieusement le replay sans toucher au compteur. Le keystream reste unique par paquet, rendant le déchiffrement impossible.',
    defensiveControls: [
      'Mettre à jour tous les clients (wpa_supplicant, Windows, macOS, Android, iOS) vers une version patchée (post-octobre 2017)',
      'Migrer vers WPA3-SAE (le handshake SAE n\'est pas vulnérable à KRACK)',
      'Activer PMF obligatoire (ieee80211w=2) pour empêcher le MITM de canal',
      'Forcer HTTPS + HSTS pour neutraliser l\'impact d\'une éventuelle tentative de déchiffrement HTTP',
      'Surveiller les retransmissions de M3 anormales (WIDS / détection d\'anomalies handshake)',
    ],
    remediationCodeExample: {
      language: 'wpa_supplicant config (client-side patch verification)',
      vulnerable: `# ❌ VULNERABLE : client wpa_supplicant < 2.6 (non patché)
network={
    ssid="Company-WiFi"
    psk="passphrase"
    key_mgmt=WPA-PSK
    # Le client accepte le replay M3, réinstalle PTK → PN reset → KRACK
}`,
      fixed: `# ✅ SECURISE : client patché + WPA3-SAE
network={
    ssid="Company-WiFi"
    key_mgmt=SAE WPA-PSK
    sae_password="passphrase-forte-16-caracteres-min"
    ieee80211w=2          # PMF required
    pairwise=CCMP GCMP
    group=CCMP
    # Patch: ne jamais réinstaller une clé déjà installée (Linux wpa_supplicant ≥ 2.6)
    # WPA3-SAE utilise Dragonfly — pas de M3 replay possible
}`,
    },
  },

  // ============================================================
  // 4. WPS Pixie-Dust
  // ============================================================
  {
    id: 'wifi-wps-pixie',
    name: 'WPS Pixie-Dust Attack (CVE-2014-9778)',
    category: 'WIFI_WPS',
    mitre: 'T1110 — Brute Force / Cryptographic Exhaustion',
    severity: 'HIGH',
    difficulty: 'FAIBLE',
    targetEncryption: 'WPA2',
    description:
      'L\'attaque Pixie-Dust (Dominique Bongard, DEFCON 22) exploite une faille d\'implémentation du protocole WPS (Wi-Fi Protected Setup) où certains routeurs génèrent les nonces E-S1 et E-S2 (DH secrets) de manière prédictible. Cela permet de retrouver le PIN WPS (8 chiffres) en quelques secondes d\'algèbre modulaire au lieu de devoir le brute-forcer.',
    attackScenario:
      'L\'attaquant initie une session WPS PIN avec l\'AP (`reaver -i wlan0mon -b <BSSID> -c 6 -vv`). Il capture les messages M1 à M7. Si l\'AP est vulnérable (la plupart des Broadcom/Realtek 2010-2014), les nonces E-S1/E-S2 sont dérivables de l\'UUID du routeur ou constants. `pixiewps` calcule alors le PIN en quelques secondes. Une fois le PIN retrouvé, l\'AP révèle la passphrase WPA2.',
    safeTestPayload:
      'reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -c 6 -vv -K 1  # (lab only)',
    vulnerableResponseSample: `reaver + pixiewps trace (vulnerable AP)
[+] Pixie-Dust attack on AP AA:BB:CC:DD:EE:01
[*] Sending WPS M1
[*] Received M2 (auth ok)
[*] Captured PK / PKE / PKR / authkey / ehash1 / ehash2
[*] Pixiewps analysis:
    E-S1: 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 (predictable!)
    E-S2: 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 (predictable!)
[*] PIN recovered: 12345670 (in 2.3 seconds)
[*] Sending M6 with PIN → AP reveals WPA passphrase
[+] WPA PSK: SuperSecretPassphrase2017!
Total time: 4.1 seconds (vs 10^7 brute force)`,
    remediatedResponseSample: `reaver + pixiewps trace (patched AP)
[+] Pixie-Dust attack on AP AA:BB:CC:DD:EE:01
[*] Sending WPS M1
[*] Received M2 (auth ok)
[*] Captured PK / PKE / PKR / authkey / ehash1 / ehash2
[*] Pixiewps analysis:
    E-S1: a7f3c2e9b1d4f8a6c0e5d2b7a9f1c4e8 (cryptographically random)
    E-S2: b2c4d6e8f0a1b3c5d7e9f0a2b4c6d8e0 (cryptographically random)
[*] PIN cannot be derived — nonces are unpredictable
[+] Pixie-Dust failed, falling back to brute force
[!] After 12 hours: 0.001% of PIN space tested, no result
WPS locked after 5 attempts — AP refuses further WPS PIN sessions for 60 minutes`,
    vulnerableBehaviorExplanation:
      'Le routeur vulnérable génère E-S1/E-S2 à partir de sources faibles (MAC, heure, compteur monotone) au lieu d\'utiliser un PRNG cryptographique. `pixiewps` exploite cette prédictibilité pour résoudre l\'équation DH et retrouver le PIN. Le PIN est ensuite converti en passphrase WPA2 via la session WPS M6/M7.',
    remediatedBehaviorExplanation:
      'Le routeur patché utilise un PRNG cryptographique (/dev/urandom, getrandom()) pour E-S1/E-S2. Les nonces sont imprévisibles et le PIN ne peut pas être dérivé. En complément, le routeur verrouille WPS après N tentatives échouées (WPS Lockdown) et peut désactiver entièrement le mode PIN (PBC only).',
    defensiveControls: [
      'Désactiver entièrement WPS côté AP (`wps_state=0` dans hostapd)',
      'Si WPS requis, désactiver le mode PIN et n\'autoriser que PBC (Push-Button Configuration)',
      'Activer WPS Lockdown (verrouillage après 3-5 tentatives échouées)',
      'Migrer vers WPA3-SAE qui rend WPS obsolète (SAE remplace le besoin d\'onboarding simplifié)',
      'Mettre à jour le firmware du routeur (les patches Pixie-Dust sont déployés depuis 2015)',
      'Surveiller les sessions WPS multiples échouées (WIDS) comme indicateur d\'attaque',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf (AP configuration)',
      vulnerable: `# ❌ VULNERABLE : WPS PIN activé sans lockout
wps_state=2
ap_setup_locked=0
wps_pin_requests=10
# E-S1/E-S2 générés par PRNG faible (firmware bugué Broadcom/Realtek)`,
      fixed: `# ✅ SECURISE : WPS désactivé (ou PBC only + lockdown)
wps_state=0          # WPS complètement désactivé
# OU alternative: PBC only, avec lockout
# wps_state=2
# ap_setup_locked=1
# wps_pin_requests=0 # pas de mode PIN
# wps_locked_after_failures=3
# wps_lockout_duration=3600  # 1h lockout`,
    },
  },

  // ============================================================
  // 5. WPS PIN brute force
  // ============================================================
  {
    id: 'wifi-wps-brute',
    name: 'WPS PIN Brute Force (8 digits)',
    category: 'WIFI_WPS',
    mitre: 'T1110.001 — Brute Force: Password Cracking',
    severity: 'MEDIUM',
    difficulty: 'FAIBLE',
    targetEncryption: 'WPA2',
    description:
      'Attaque de brute force classique du PIN WPS (8 digits). Le 8e digit est un checksum (mod 11) calculé sur les 7 premiers, donc l\'espace réel est de 10^7 ≈ 11 millions de combinaisons. L\'attaque est divisée en deux phases (les 4 premiers digits puis les 3 suivants), ce qui réduit à ~11000 + ~1000 tentatives. En pratique, le PIN complet est retrouvé en 4-12 heures sur un AP non verrouillé.',
    attackScenario:
      'L\'attaquant utilise `reaver -i wlan0mon -b <BSSID> -c 6 -vv` qui automatise le brute force. L\'AP révèle par oracle si les 4 premiers digits sont corrects (réponse M4 valide), puis si les 3 suivants le sont. Sans WPS Lockdown, l\'attaque aboutit en quelques heures. Une fois le PIN retrouvé, `reaver` récupère la passphrase WPA2.',
    safeTestPayload:
      'reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -c 6 -vv  # (lab only)',
    vulnerableResponseSample: `reaver brute force trace (no lockout)
[+] Target AP: AA:BB:CC:DD:EE:01 (WPS enabled, unlocked)
[*] Phase 1: first 4 digits
[*] Trying PIN 00007000... FAIL
[*] Trying PIN 00010000... FAIL
[*] Trying PIN 12340000... SUCCESS (4h12m elapsed, ~11000 attempts)
[*] Phase 2: next 3 digits
[*] Trying PIN 12345000... FAIL
[*] Trying PIN 12345600... SUCCESS (38m elapsed, ~1000 attempts)
[*] Full PIN: 12345670 (checksum valid)
[*] Sending M6 with full PIN → AP reveals WPA passphrase
[+] WPA PSK: CompanyWiFi2023!
Total: 4h50m (no WPS lockdown enforced)`,
    remediatedResponseSample: `reaver brute force trace (with lockout)
[+] Target AP: AA:BB:CC:DD:EE:01 (WPS enabled, locked-down)
[*] Phase 1: first 4 digits
[*] Trying PIN 00007000... FAIL
[*] Trying PIN 00010000... FAIL
[*] Trying PIN 00020000... FAIL
[!] AP returned WPS_FAIL after 3 attempts → WPS LOCKDOWN triggered
[!] AP refuses all WPS PIN sessions for 3600 seconds (1 hour)
[*] Sleeping 3600s, then retry...
[!] After 24h: only 72 PINs tested (3/h × 24h), 0.00065% of space
[!] Attack not feasible in reasonable time (estimated: 41 years at this rate)
WPS Lockdown successful — brute force effectively neutralized`,
    vulnerableBehaviorExplanation:
      'L\'AP sans WPS Lockdown accepte un nombre illimité de tentatives PIN. Le protocole WPS renvoie un oracle (succès/échec séparé pour les 4 premiers et 3 derniers digits), ce qui divise l\'espace de recherche. Sans limitation de taux, l\'attaque converge en quelques heures.',
    remediatedBehaviorExplanation:
      'L\'AP avec WPS Lockdown verrouille la session WPS après 3-5 tentatives échouées, pendant une durée longue (1h-24h). Le taux effectif chute à 3-5 PIN par heure → 11M PIN prendraient des années. Combiné à la désactivation du mode PIN (PBC only), l\'attaque devient impraticable.',
    defensiveControls: [
      'Désactiver WPS entièrement (`wps_state=0`)',
      'Si WPS requis, désactiver le mode PIN (n\'autoriser que PBC)',
      'Activer WPS Lockdown (verrouillage après 3-5 tentatives échouées)',
      'Configurer un délai de verrouillage long (>= 1h)',
      'Surveiller les sessions WPS échouées répétées (WIDS / logs hostapd)',
      'Migrer vers WPA3-SAE (WPS devient obsolète)',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf (AP configuration)',
      vulnerable: `# ❌ VULNERABLE : WPS PIN sans lockout
wps_state=2
ap_setup_locked=0
wps_pin_requests=99999    # unlimited PIN attempts
# Pas de délai entre les tentatives → brute force en quelques heures`,
      fixed: `# ✅ SECURISE : WPS désactivé OU PBC only + lockout
wps_state=0              # désactivé totalement (recommandé)
# OU si WPS requis:
# wps_state=2
# ap_setup_locked=1
# wps_pin_requests=0     # pas de mode PIN
# wps_locked_after_failures=3
# wps_lockout_duration=3600
# wps_pin_min_length=8`,
    },
  },

  // ============================================================
  // 6. PMKID capture (sans client connecté)
  // ============================================================
  {
    id: 'wifi-pmkid-capture',
    name: 'PMKID Capture (sans client connecté) — CVE-2019-...',
    category: 'WIFI_HANDSHAKE',
    mitre: 'T1552.001 — Unsecured Credentials: Credentials in Files / Wireless',
    severity: 'HIGH',
    difficulty: 'MOYEN',
    targetEncryption: 'WPA2',
    description:
      'Le PMKID (Pairwise Master Key Identifier) est un identifiant envoyé par certains AP (notamment ceux avec hostapd 2.7+ et le flag `rsn_pairwise=CCMP` + `pmf=1`) dans le premier message du 4-way handshake (EAPOL M1). Découvert par Jens Steube (hashcat, 2018), il permet de capturer un material suffisant pour brute-forcer la passphrase WPA2-PSK **sans attendre qu\'un client se connecte** — un seul paquet M1 de l\'AP suffit.',
    attackScenario:
      'L\'attaquant lance `hcxdumptool -i wlan0mon --enable_status=1 --filtermode_ap=1 --filterlist_ap=<BSSID>` qui émet une requête de connexion vers l\'AP. L\'AP renvoie un EAPOL M1 contenant le PMKID (si l\'AP le supporte). `hcxpcaptool` extrait le hash 22000 (WPA*PMKID*), puis `hashcat -m 22000 hash.hc22000 wordlist.txt` brute-force la passphrase.',
    safeTestPayload:
      'hcxdumptool -i wlan0mon --enable_status=1  # (passive — lab only)',
    vulnerableResponseSample: `hcxdumptool + hashcat trace (PMKID-capable AP)
[+] PMKID extraction from AP AA:BB:CC:DD:EE:01
[*] hcxdumptool sends EAPOL start → AP replies with M1 (PMKID present)
[*] hcxpcaptool: extracted 1 PMKID hash
    aa:bb:cc:dd:ee:01*1234567890abcdef...*0123456789abcdef...
[*] hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
    Session: hashcat | Mode: 22000 (WPA-PMKID-PBKDF2)
    [s] Status: Running | Speed: 1.2M H/s
    Password recovered in 8m12s:
    aa:bb:cc:dd:ee:01:...:1234567890abcdef...:PASSWORD123
[+] WPA PSK: PASSWORD123
No client was connected — only 1 packet needed from AP`,
    remediatedResponseSample: `hcxdumptool + hashcat trace (PMKID disabled AP)
[+] PMKID extraction from AP AA:BB:CC:DD:EE:01
[*] hcxdumptool sends EAPOL start → AP replies with M1 (no PMKID field)
[*] hcxpcaptool: extracted 0 PMKID hash (AP does not advertise PMKID)
[*] hashcat: no hash to attack — PMKID capture failed
[!] Fallback to 4-way handshake capture requires client to connect (passive wait)
[*] hashcat -m 22000 hash.hc22000 wordlist.txt → no hashes loaded
PMKID disabled (rsn_pairwise=CCMP without pmf, or pmkID=0 in hostapd)
→ AP-side PMKID leak impossible; client still required for handshake capture`,
    vulnerableBehaviorExplanation:
      'L\'AP vulnérable inclut le PMKID dans le M1 du handshake, ce qui permet à un attaquant de capturer un material suffisant pour brute-forcer la passphrase **uniquement en parlant à l\'AP**, sans client connecté. L\'attaque est immédiate (1 paquet) et silencieuse (1 requête EAPOL vers l\'AP).',
    remediatedBehaviorExplanation:
      'L\'AP configuré sans PMKID (option par défaut dans la plupart des firmwares modernes) ne l\'inclut pas dans le M1. L\'attaquant doit alors attendre qu\'un client se connecte pour capturer le 4-way handshake complet, ce qui peut prendre des heures/jours. La capture passive devient lente et bruitée.',
    defensiveControls: [
      'Désactiver le PMKID côté AP (vérifier que hostapd n\'envoie pas `rsn_preauth=1`)',
      'Utiliser une passphrase WPA2 ≥ 16 caractères aléatoires (résistance au dictionnaire)',
      'Migrer vers WPA3-SAE (résistant au brute force par hashcat)',
      'Activer PMF (ieee80211w=2) pour réduire la surface d\'attaque handshake',
      'Surveiller les requêtes EAPOL anormales vers l\'AP sans connexion cliente (WIDS)',
      'Rafraîchir régulièrement la passphrase PSK (rotation trimestrielle recommandée)',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf (AP configuration)',
      vulnerable: `# ❌ VULNERABLE : PMKID activé dans M1
ssid=Company-WiFi
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_preauth=1             # Inclut le PMKID dans le M1 → capture 1-paquet possible
ieee80211w=1`,
      fixed: `# ✅ SECURISE : PMKID désactivé + passphrase forte
ssid=Company-WiFi
wpa=2
wpa_key_mgmt=WPA-PSK SAE   # transition WPA2/WPA3
wpa_pairwise=CCMP
rsn_preauth=0             # Pas de PMKID dans M1 → capture handshake nécessite un client
ieee80211w=2              # PMF required
wpa_passphrase=Tr0ub4dor&3-Évitez-les-mots-du-dictionnaire!`,
    },
  },

  // ============================================================
  // 7. 4-way handshake capture
  // ============================================================
  {
    id: 'wifi-handshake-capture',
    name: 'Capture 4-Way Handshake + Dictionnaire',
    category: 'WIFI_HANDSHAKE',
    mitre: 'T1552.004 — Unsecured Credentials: Credentials in Network Traffic',
    severity: 'HIGH',
    difficulty: 'FAIBLE',
    targetEncryption: 'WPA2',
    description:
      'Le 4-way handshake WPA2-PSK (EAPOL M1-M4) entre l\'AP et un client authentifie les deux parties et dérive la PTK (Pairwise Transient Key) à partir de la PMK (elle-même = PBKDF2(passphrase, SSID, 4096)). Si un attaquant capture les 4 messages, il peut brute-forcer la passphrase hors-ligne via hashcat (mode 22000). L\'attaque est précédée d\'une phase de deauth pour forcer la réauthentification.',
    attackScenario:
      'Phase 1 : `airodump-ng --bssid AA:BB:CC:DD:EE:01 -c 6 -w capture wlan0mon` pour capturer. Phase 2 : `aireplay-ng --deauth 5 -a <BSSID> wlan0mon` pour forcer la reconnexion d\'un client. Phase 3 : vérifier que le fichier .cap contient un handshake complet (M1+M2+M3+M4). Phase 4 : `hcxpcaptool -o hash.hc22000 capture.cap` puis `hashcat -m 22000 hash.hc22000 rockyou.txt`. Avec une passphrase faible, la récupération prend quelques minutes à quelques heures.',
    safeTestPayload:
      'airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:01 -w /tmp/cap wlan0mon  # (passive)',
    vulnerableResponseSample: `4-way handshake capture (vulnerable AP + weak passphrase)
[+] Capture: /tmp/cap-01.cap (channel 6, BSSID AA:BB:CC:DD:EE:01)
[*] airodump-ng detected handshake: EAPOL M1+M2+M3+M4 captured
[*] Client AA:BB:CC:11:22:33 → AP AA:BB:CC:DD:EE:01
[*] hcxpcaptool: extracted 1 hash mode 22000
    aa:bb:cc:dd:ee:01*1234...*5678...*abcd...*ef01...
[*] hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
    [s] Status: Running | Speed: 1.4M H/s
    ae0b9b1c:PASSWORD123 recovered in 4m27s
[+] WPA PSK: PASSWORD123 (in rockyou.txt line 4923)
Passphrase weak → dictionnaire de 14M mots cassé en < 5 min`,
    remediatedResponseSample: `4-way handshake capture (strong passphrase, hashcat exhausted)
[+] Capture: /tmp/cap-01.cap (channel 6, BSSID AA:BB:CC:DD:EE:01)
[*] airodump-ng detected handshake: EAPOL M1+M2+M3+M4 captured
[*] hcxpcaptool: extracted 1 hash mode 22000
[*] hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
    [s] Status: Exhausted (rockyou.txt completed in 12 minutes, 0 matches)
[*] hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d (8-digit mask)
    [s] Status: Exhausted (100M combinations, 0 matches)
[*] hashcat -m 22000 hash.hc22000 -a 3 ?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a (16+ chars)
    [s] Status: Running | ETA: 2.4 × 10^23 years
Passphrase 16+ chars aléatoires → résiste au dictionnaire ET au mask brute force`,
    vulnerableBehaviorExplanation:
      'Le 4-way handshake est capturable en passif (sans intervention sur l\'AP) dès qu\'un client se connecte. Si la passphrase est dans un dictionnaire commun (rockyou.txt, leak databases), hashcat la retrouve en quelques minutes. Une fois la PMK connue, tout le trafic chiffré de la session est déchiffrable rétroactivement.',
    remediatedBehaviorExplanation:
      'Une passphrase de 16+ caractères aléatoires (ou générée par `pwgen -s 16`) ne se trouve dans aucun dictionnaire. Le coût de brute force est de 2^x où x est l\'entropie. Même avec un GPU à 1.4M H/s, une passphrase de 16 caractères alphanumériques (95 bits d\'entropie) demanderait 2^95 / 1.4M ≈ 10^21 ans. La capture du handshake devient inutile.',
    defensiveControls: [
      'Utiliser une passphrase ≥ 16 caractères aléatoires (entropie ≥ 95 bits)',
      'Migrer vers WPA3-SAE (résistant au dictionnaire grâce au Forward Secrecy)',
      'Activer PMF pour empêcher le deauth forcé (réduit la fenêtre de capture)',
      'Surveiller les déauths anormaux (WIDS) — indicateur de tentative de capture',
      'Rotation régulière de la passphrase PSK (trimestriel minimum)',
      'Préférer EAP-TLS (certificats) au PSK quand c\'est possible (pas de passphrase à casser)',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf + passphrase generation',
      vulnerable: `# ❌ VULNERABLE : passphrase faible dans dictionnaire
ssid=Company-WiFi
wpa_passphrase=admin123        # in rockyou.txt
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
ieee80211w=0                  # pas de PMF → deauth possible → handshake capturable`,
      fixed: `# ✅ SECURISE : passphrase forte + WPA3 + PMF
# Generate passphrase: pwgen -s 20 1
wpa_passphrase=X7#k9P$2mQ!vR8nL4bZ3   # 20 chars aléatoires, 128 bits entropie
wpa_key_mgmt=SAE WPA-PSK            # WPA3-SAE prioritaire (Forward Secrecy)
wpa_pairwise=CCMP GCMP
ieee80211w=2                        # PMF required
sae_pwe=2                            # Dragonfly hunting-and-pecking`,
    },
  },

  // ============================================================
  // 8. Downgrade WPA3 → WPA2 (transition mode)
  // ============================================================
  {
    id: 'wifi-downgrade-wpa3',
    name: 'Downgrade WPA3 → WPA2 (Transition Mode Attack)',
    category: 'WIFI_DOWNGRADE',
    mitre: 'T1565.001 — Stored Data Manipulation / Protocol Downgrade',
    severity: 'MEDIUM',
    difficulty: 'MOYEN',
    targetEncryption: 'WPA2/WPA3',
    description:
      'Quand un AP fonctionne en mode transition WPA2/WPA3 (permet aux clients WPA2 de se connecter), un attaquant peut forcer un client WPA3-capable à se dégrader en mode WPA2. Cela permet ensuite d\'appliquer les attaques classiques WPA2 (KRACK, capture handshake, dictionnaire). L\'attaque consiste à bloquer les trames SAE et à forcer la fallback PSK.',
    attackScenario:
      'L\'attaquant se positionne en MITM sur le canal. Quand le client envoie son premier message SAE (Commit), l\'attaquant le bloque. Le client, après timeout, retente en mode WPA2-PSK (fallback). L\'AP accepte la connexion WPA2. L\'attaquant peut alors capturer le 4-way handshake WPA2 et appliquer hashcat. Si PMF est optionnel (et non requis), le dérangement reste invisible pour l\'utilisateur.',
    safeTestPayload:
      'krack-ft-test.py --mode wpa3-downgrade --bssid AA:BB:CC:DD:EE:01  # (lab only)',
    vulnerableResponseSample: `Downgrade attack trace (WPA2/WPA3 transition without PMF required)
[+] AP AA:BB:CC:DD:EE:01 advertises: RSN capabilities: MFPC=1, MFPR=0 (PMF optional)
[*] Client AA:BB:CC:11:22:33 starts SAE Commit (WPA3)
[*] MITM drops SAE Commit frame → client timeout (5s)
[*] Client retries SAE Commit → MITM drops again → timeout
[*] Client falls back to WPA2-PSK (transition mode)
[*] AP accepts WPA2-PSK association (PMF optional → no enforcement)
[*] Captured 4-way handshake WPA2 → hashcat -m 22000 hash.hc22000 rockyou.txt
    Password recovered:PASSWORD123 (4m27s)
[+] Downgrade successful — WPA3 bypassed via transition mode fallback`,
    remediatedResponseSample: `Downgrade attack trace (WPA3-only + PMF required)
[+] AP AA:BB:CC:DD:EE:01 advertises: RSN capabilities: MFPC=1, MFPR=1 (PMF REQUIRED)
[*] Client AA:BB:CC:11:22:33 starts SAE Commit (WPA3)
[*] MITM drops SAE Commit frame → client timeout
[*] Client retries SAE Commit (no WPA2 fallback supported by AP)
[*] AP rejects any WPA2-PSK association: "PMF REQUIRED, SAE only"
[*] After 10 retries, client displays "Unable to connect to network"
[*] No handshake captured → no offline attack possible
[+] Downgrade failed — AP enforces WPA3-SAE + PMF required`,
    vulnerableBehaviorExplanation:
      'En mode transition WPA2/WPA3 avec PMF optionnel, l\'AP accepte les deux types de clients. Un attaquant peut bloquer les trames SAE pour forcer le client à se dégrader en WPA2-PSK. Une fois en WPA2, toutes les attaques classiques (KRACK, handshake capture, dictionnaire) redeviennent possibles.',
    remediatedBehaviorExplanation:
      'En exigeant WPA3-SAE exclusivement (`wpa_key_mgmt=SAE` sans `WPA-PSK`) et PMF obligatoire (`ieee80211w=2`), l\'AP refuse toute association WPA2. Le client WPA3-capable ne peut pas être dégradé. Les clients WPA2-only ne peuvent pas se connecter (à migrer ou à isoler sur un SSID legacy séparé).',
    defensiveControls: [
      'Exiger WPA3-SAE exclusivement (`wpa_key_mgmt=SAE` sans WPA-PSK)',
      'Activer PMF obligatoire (`ieee80211w=2`) pour empêcher le MITM de canal',
      'Si transition mode inévivable, isoler les clients WPA2 sur un VLAN séparé',
      'Surveiller les échecs SAE répétés suivis d\'une association WPA2 (WIDS)',
      'Migrer les clients vers WPA3 (mise à jour OS / drivers) pour abandonner progressivement le mode transition',
      'Documenter une politique de fin de vie du mode transition (ex: 6 mois)',
    ],
    remediationCodeExample: {
      language: 'hostapd.conf (AP configuration)',
      vulnerable: `# ❌ VULNERABLE : WPA2/WPA3 transition avec PMF optionnel
ssid=Company-WiFi
wpa=2
wpa_key_mgmt=WPA-PSK SAE          # accepte WPA2 ET WPA3
wpa_pairwise=CCMP
ieee80211w=1                      # PMF optional → MITM + downgrade possibles
sae_pwe=2`,
      fixed: `# ✅ SECURISE : WPA3-SAE exclusif + PMF required
ssid=Company-WiFi
wpa=2
wpa_key_mgmt=SAE                  # SAE uniquement — pas de WPA2-PSK
wpa_pairwise=CCMP GCMP
ieee80211w=2                      # PMF REQUIRED → pas de MITM de canal
sae_pwe=2
sae_pmkid_in_connect=1
# Clients WPA2-only refusés — à migrer ou VLAN legacy séparé`,
    },
  },
];
