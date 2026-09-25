import { CourseNotion } from '../types';

/**
 * COURSE_NOTIONS — Catalogue de notions de cybersécurité WiFi / réseau / crypto
 * pour la section "Cours & Notions" de Guyma Cyb. Chaque notion contient :
 *   - un résumé court (1-2 lignes) pour la liste,
 *   - un contenu markdown pédagogique (##, listes, **gras**),
 *   - 3-5 points clés à retenir,
 *   - des références (RFC, OWASP, Wi-Fi Alliance, CVE).
 *
 * Les notions sont triées par niveau (DÉBUTANT → AVANCÉ) et par catégorie.
 */
export const COURSE_NOTIONS: CourseNotion[] = [
  // ============================================================
  // WiFi — DÉBUTANT
  // ============================================================
  {
    id: 'wifi-wep',
    title: 'WEP — Wired Equivalent Privacy',
    category: 'wifi',
    level: 'DÉBUTANT',
    summary:
      'Premier protocole de chiffrement WiFi (1997). Utilise RC4 avec un IV de 24 bits. Cassable en minutes — à ne plus utiliser.',
    content: `## WEP (Wired Equivalent Privacy)

WEP est le premier protocole de sécurité WiFi, normalisé en 1997 dans la norme IEEE 802.11. Il a été conçu pour offrir une confidentialité équivalente à celle d'un réseau filaire.

### Mécanisme
- **Chiffrement** : RC4 (Rivest Cipher 4) en mode flux.
- **Clé** : 40 bits ou 104 bits, partagée entre tous les clients (PSK statique).
- **Vecteur d'Initialisation (IV)** : 24 bits, transmis en clair devant chaque paquet.

### Pourquoi c'est obsolète
- **IV de 24 bits** = seulement 16 777 216 combinaisons → collisions en quelques heures sur un réseau actif.
- **Attaque FMS** (Fluhrer, Mantin, Shamir, 2001) : exploite les IV faibles pour retrouver la clé.
- **Attaque PTW** (Tews, Weinmann, Pyshkin, 2007) : récupère la clé en **moins de 60 secondes** avec ~40 000 paquets.
- **ARP injection** : force l'AP à émettre plus de trafic chiffré pour accélérer la collecte.

### Statut
WEP est **désapprouvé depuis 2004** par le Wi-Fi Alliance et **interdit** dans la plupart des politiques de conformité (PCI-DSS, ANSSI).

**Ne l'utilisez jamais.** Si vous voyez un réseau WEP, signalez-le et migrez immédiatement.`,
    keyPoints: [
      'WEP utilise RC4 + un IV de 24 bits (espace trop petit → collisions).',
      'Attaque PTW casse la clé en moins de 60 secondes avec 40k paquets.',
      'Déprécié depuis 2004 — aucun usage légitime possible aujourd\'hui.',
      'PCI-DSS et l\'ANSSI interdisent formellement WEP.',
      'Toujours migrer vers WPA2 minimum, idéalement WPA3.',
    ],
    references: [
      'https://standards.ieee.org/ieee/802.11/1350/',
      'https://www.wi-fi.org/discover-wi-fi/security',
      'https://www.ssi.gouv.fr/uploads/2021/01/guide_hygiene_info.pdf',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2249',
    ],
  },
  {
    id: 'wifi-wpa',
    title: 'WPA — Wi-Fi Protected Access',
    category: 'wifi',
    level: 'DÉBUTANT',
    summary:
      'Correctif temporaire (2003) apporté au WEP. Introduit TKIP et le 4-way handshake. Aujourd\'hui vulnérable — à remplacer par WPA2.',
    content: `## WPA (Wi-Fi Protected Access)

WPA a été publié en 2003 par le Wi-Fi Alliance comme **solution intérimaire** en attendant la norme 802.11i (qui deviendra WPA2). Il s'agit essentiellement d'un WEP patché.

### Améliorations par rapport à WEP
- **TKIP** (Temporal Key Integrity Protocol) : change la clé de chiffrement à chaque paquet.
- **IV étendu** : 48 bits au lieu de 24 (collisions beaucoup plus rares).
- **MIC** (Message Integrity Code) : détecte les altérations (mais ne les empêche pas).
- **4-way handshake** : dérive une clé de session unique (PTK) à partir de la PMK.

### Vulnérabilités
- **Attaque Beck-Tews (2008)** : exploite TKIP pour injecter des paquets chiffrés arbitraires (ARP poisoning, déauthentication forgée).
- **Attaque Ohigashi-Morii (2009)** : étend Beck-Tews au TCP/UDP bidirectionnel.
- **Dictionnaire** : comme WPA-PSK dérive la PMK via PBKDF2(passphrase, SSID, 4096), une passphrase faible reste cassable via hashcat.

### Statut
WPA est **déprécié depuis 2012**. Le Wi-Fi Alliance ne le certifie plus depuis 2014. Migrer vers WPA2-AES-CCMP est obligatoire.`,
    keyPoints: [
      'WPA = WEP patché (2003) : TKIP + 4-way handshake + IV 48 bits.',
      'Attaque Beck-Tews (2008) permet l\'injection de paquets chiffrés TKIP.',
      'PBKDF2(passphrase, SSID, 4096) → dictionnaire possible si passphrase faible.',
      'Déprécié depuis 2012 — utiliser WPA2 minimum.',
      'TKIP doit être désactivé dans hostapd (`wpa_pairwise=CCMP`).',
    ],
    references: [
      'https://www.wi-fi.org/discover-wi-fi/security',
      'https://eprint.iacr.org/2008/403.pdf',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3865',
    ],
  },

  // ============================================================
  // WiFi — INTERMÉDIAIRE
  // ============================================================
  {
    id: 'wifi-wpa2',
    title: 'WPA2 — Wi-Fi Protected Access II',
    category: 'wifi',
    level: 'INTERMÉDIAIRE',
    summary:
      'Norme 802.11i (2004). Chiffrement AES-CCMP, 4-way handshake, PSK ou 802.1X/EAP. Référence actuelle mais vulnérable au dictionnaire si passphrase faible.',
    content: `## WPA2 (802.11i, 2004)

WPA2 implémente intégralement la norme IEEE 802.11i. Il remplace TKIP par **AES-CCMP** (Counter Mode with CBC-MAC Protocol) — un chiffrement par bloc authentifié, considéré comme sûr.

### Architecture
- **PMK** (Pairwise Master Key) : partagée entre client et AP. En mode PSK, c'est \`PBKDF2(passphrase, SSID, 4096, 256 bits)\`. En mode 802.1X, elle est négociée par le serveur RADIUS via EAP.
- **PTK** (Pairwise Transient Key) : dérivée du 4-way handshake via PRF-512(PMK, ANonce, SNonce, adresses). Spécifique à chaque session.
- **GTK** (Group Temporal Key) : partagée par tous les clients pour le broadcast/multicast, rotée régulièrement.
- **4-way handshake** : M1 (AP→client, ANonce) → M2 (client→AP, SNonce + MIC) → M3 (AP→client, GTK chiffré + MIC) → M4 (client→AP, ACK + MIC).

### Modes d'authentification
| Mode | Usage | Clé |
|------|-------|-----|
| **WPA2-PSK** | Grand public, petite entreprise | Passphrase partagée |
| **WPA2-Enterprise (802.1X)** | Entreprise, campus | Certificat / login + RADIUS |
| **WPA2-FT** | Roaming rapide (802.11r) | PMK-R1 dérivée du domaine |

### Vulnérabilités connues
- **KRACK** (CVE-2017-13077) : réinstallation de PTK dans le 4-way handshake. Patché en 2017.
- **PMKID leak** (2018, Jens Steube) : hashcat mode 22000 sur le PMKID du M1.
- **Dictionnaire PSK** : si passphrase faible, brute force offline possible.

### Recommandations
- Passphrase ≥ 16 caractères aléatoires (entropie ≥ 95 bits).
- Activer PMF (ieee80211w=2) si possible.
- Préférer 802.1X (EAP-TLS) en entreprise.`,
    keyPoints: [
      'WPA2 = AES-CCMP + 4-way handshake + PSK ou 802.1X.',
      'PMK = PBKDF2(passphrase, SSID, 4096, 256 bits) en mode PSK.',
      'PTK dérivée par session via ANonce + SNonce + PMK.',
      'Vulnérable à KRACK (patché) et au dictionnaire si passphrase faible.',
      'En entreprise : préférer WPA2-Enterprise (802.1X/EAP-TLS).',
    ],
    references: [
      'https://standards.ieee.org/ieee/802.11i/4/](https://standards.ieee.org',
      'https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-97.pdf',
      'https://www.krackattacks.com/',
      'https://hashcat.net/forum/thread-7717.html',
    ],
  },
  {
    id: 'wifi-pmf',
    title: 'PMF — Protected Management Frames (802.11w)',
    category: 'wifi',
    level: 'INTERMÉDIAIRE',
    summary:
      'Norme 802.11w (2009). Protège les trames de gestion (deauth, dissociation) par signature BIP-CMAC-128. Empêche les attaques deauth et facilite la détection d\'evil twin.',
    content: `## PMF (Protected Management Frames, 802.11w)

PMF protège les **trames de gestion 802.11** (beacons, probe, deauth, dissociation, action) contre la falsification. Sans PMF, n'importe qui peut forger une trame deauth avec l'adresse source de l'AP — c'est la base de toutes les attaques WiFi (deauth flood, capture handshake, evil twin).

### Mécanisme
- **BIP-CMAC-128** (Broadcast/Multicast Integrity Protocol) : signature HMAC-CMAC-128 des trames de gestion broadcast.
- **IGTK** (Integrity Group Temporal Key) : clé partagée dérivée du 4-way handshake, utilisée par BIP.
- **Unicast Management Frame Protection** : chiffrement AES-CCMP des trames de gestion unicast.

### Niveaux de protection
| Valeur \`ieee80211w\` | Sens |
|---------------------|------|
| **0** (disabled) | PMF désactivé — toutes les attaques deauth sont possibles |
| **1** (optional / capable) | PMF supporté mais non exigé — clients PMF=0 acceptés |
| **2** (required) | PMF obligatoire — les clients non-PMF sont refusés |

### Configuration hostapd
\`\`\`ini
wpa=2
wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256  # SHA256 requis pour PMF
wpa_pairwise=CCMP
ieee80211w=2                            # PMF REQUIRED
\`\`\`

### Impact
- **Bloque** : deauth flood, capture handshake forcée, evil twin (clients PMF refusent les faux AP).
- **Ne bloque pas** : déni de service sur couche physique (brouillage radio), écoute passive.

### Compatibilité
- Tous les clients modernes (Windows 10+, macOS 10.13+, Android 8+, iOS 11+) supportent PMF.
- En WPA3, PMF est **obligatoire** par spécification.`,
    keyPoints: [
      'PMF (802.11w) protège les trames de gestion par BIP-CMAC-128 + IGTK.',
      'ieee80211w=0 (désactivé), 1 (optionnel), 2 (obligatoire).',
      'Bloque les attaques deauth flood, capture forcée, evil twin.',
      'Obligatoire en WPA3 — fortement recommandé en WPA2.',
      'Ne protège pas contre le brouillage radio (couche physique).',
    ],
    references: [
      'https://standards.ieee.org/ieee/802.11w/4669/',
      'https://www.wi-fi.org/discover-wi-fi/security',
      'https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf',
    ],
  },

  // ============================================================
  // WiFi — AVANCÉ
  // ============================================================
  {
    id: 'wifi-wpa3',
    title: 'WPA3 — Wi-Fi Protected Access III',
    category: 'wifi',
    level: 'AVANCÉ',
    summary:
      'Norme 2018. Remplace PSK par SAE (Dragonfly) → résistance au dictionnaire offline. PMF obligatoire. Variantes : Personal, Enterprise, OWE.',
    content: `## WPA3 (2018)

WPA3 est une refonte majeure publiée par le Wi-Fi Alliance en juin 2018. Il remplace le mécanisme PSK vulnérable au dictionnaire par **SAE** (Simultaneous Authentication of Equals), basé sur le protocole Dragonfly.

### SAE (Simultaneous Authentication of Equals)
- **Authentification mutuelle** : le client ET l'AP s'authentifient l'un l'autre (impossible pour un evil twin sans connaître le mot de passe).
- **Forward Secrecy** : la capture du handshake ne permet pas le brute force offline — chaque tentative nécessite une interaction live avec l'AP (rate-limited).
- **Dragonfly protocol** : échange de commits basé sur un groupe ECC (P-256, Brainpool) ou MODP (FFC).
- Résiste au dictionnaire car le coût de chaque essai est volontairement élevé (itérations hunting-and-pecking).

### Variantes
| Variante | Usage | Authentification |
|----------|-------|------------------|
| **WPA3-Personal** | Grand public | SAE (mot de passe) |
| **WPA3-Enterprise** | Entreprise | 802.1X + EAP-TLS (clé 192 bits) |
| **OWE** (Opportunistic Wireless Encryption) | Réseaux ouverts | DH sans mot de passe → chiffre le trafic même sans auth |
| **WPA3-Enterprise 192-bit** | Gouvernement / santé | Suite B (AES-256, GCMP-256, EAP-TLS) |

### Améliorations par rapport à WPA2
1. **Résistance au dictionnaire offline** (SAE).
2. **PMF obligatoire** (ieee80211w=2 implicite).
3. **Forward Secrecy** (la compromission future du mot de passe ne déchiffre pas les captures passées).
4. **Confidentialité des adresses MAC** (MAC randomization par défaut sur iOS/Android).
5. **Taille minimale de mot de passe** (8 caractères imposés, mais 12+ recommandés).

### Mode transition WPA2/WPA3
Permet aux clients WPA2 de se connecter pendant la migration. **Risque** : si PMF est optionnel, un attaquant peut forcer le downgrade d'un client WPA3 vers WPA2. **Recommandation** : exiger PMF (ieee80211w=2) en mode transition.

### Configuration hostapd
\`\`\`ini
wpa=2
wpa_key_mgmt=SAE
sae_password="mot-de-passe-fort"
wpa_pairwise=CCMP GCMP
ieee80211w=2                  # obligatoire en WPA3
sae_pwe=2                     # méthode hunting-and-pecking
sae_groups=19 20 21           # curves ECC
\`\`\``,
    keyPoints: [
      'WPA3 remplace PSK par SAE (Dragonfly) → résistance au dictionnaire offline.',
      'SAE fournit Forward Secrecy — la capture handshake ne permet pas le brute force.',
      'PMF est obligatoire par spécification (ieee80211w=2 implicite).',
      'Variantes : Personal (SAE), Enterprise (EAP-TLS), OWE (chiffrement sans mot de passe).',
      'Le mode transition WPA2/WPA3 doit toujours exiger PMF pour éviter le downgrade.',
    ],
    references: [
      'https://www.wi-fi.org/discover-wi-fi/security',
      'https://datatracker.ietf.org/doc/draft-irtf-cfrg-dragonfly/',
      'https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9494',
    ],
  },
  {
    id: 'wifi-handshake',
    title: '4-Way Handshake WPA2/WPA3',
    category: 'wifi',
    level: 'AVANCÉ',
    summary:
      'Échange EAPOL M1-M4 qui dérive la PTK (clé de session) à partir de la PMK. Cible principale des attaques par capture + dictionnaire (hashcat mode 22000).',
    content: `## 4-Way Handshake (802.11i)

Le 4-way handshake est l'échange EAPOL entre l'AP (authenticator) et le client (supplicant) qui dérive la **PTK** (Pairwise Transient Key) à partir de la **PMK** (Pairwise Master Key). Il authentifie mutuellement les deux parties et garantit la fraîcheur des clés.

### Les 4 messages
| Msg | Sens | Contenu | But |
|-----|------|---------|-----|
| **M1** | AP → Client | ANonce (aléatoire AP) | L'AP envoie son nonce |
| **M2** | Client → AP | SNonce + MIC + RSN IE | Le client envoie son nonce + prouve qu'il connaît la PMK |
| **M3** | AP → Client | GTK chiffré + MIC + RSN IE | L'AP installe la PTK + envoie la GTK |
| **M4** | Client → AP | MIC | Le client confirme l'installation |

### Dérivation des clés
\`\`\`
PRF-512(PMK, "Pairwise key expansion",
        min(AA, SPA) || max(AA, SPA) ||
        min(ANonce, SNonce) || max(ANonce, SNonce))
\`\`\`
→ donne 512 bits de PTK, décomposée en :
- **KCK** (Key Confirmation Key, 128 bits) : pour les MIC.
- **KEK** (Key Encryption Key, 128 bits) : pour chiffrer la GTK dans M3.
- **TK** (Temporal Key, 128 bits) : pour le chiffrement des données unicast.
- **TMK** (optional, 128 bits) : pour TKIP.

### Attaque par dictionnaire
1. **Capturer M1-M4** (airodump-ng + deauth forcée).
2. **Vérifier le MIC** dans M2/M3/M4 — cela confirme la capture complète.
3. **Brute force** : pour chaque passphrase candidate, calculer \`PMK = PBKDF2(passphrase, SSID, 4096, 256)\`, puis PTK, puis MIC. Si MIC match → passphrase trouvée.
4. **hashcat** : \`hashcat -m 22000 hash.hc22000 wordlist.txt\` (1.4M H/s sur GPU RTX 3090).

### Défense
- **Passphrase ≥ 16 caractères aléatoires** (entropie ≥ 95 bits → 10^21 ans de brute force).
- **WPA3-SAE** : pas de dictionnaire offline possible (chaque tentative nécessite interaction live).
- **PMF** : empêche le deauth forcé qui permet la capture.
- **Désactiver PMKID** (rsn_preauth=0) pour éviter la capture 1-paquet.

### PMKID (shortcut)
Certains AP incluent dans M1 un PMKID = HMAC-SHA1-128(PMK, "PMK Name" | AA | SPA). Si présent, l'attaquant n'a besoin **que de M1** (pas de client connecté). Hashcat mode 22000 gère les deux formats.`,
    keyPoints: [
      'M1 (ANonce) → M2 (SNonce + MIC) → M3 (GTK + MIC) → M4 (ACK + MIC).',
      'PTK = PRF-512(PMK, ANonce || SNonce, adresses), décomposée en KCK/KEK/TK/TMK.',
      'PMK = PBKDF2(passphrase, SSID, 4096, 256 bits) — 4096 itérations ralentissent le brute force.',
      'Capture M1-M4 → hashcat mode 22000 (1.4M H/s sur GPU).',
      'Défense : passphrase ≥ 16 chars OU WPA3-SAE (pas de dictionnaire offline).',
    ],
    references: [
      'https://standards.ieee.org/ieee/802.11i/4/',
      'https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2',
      'https://w1.fi/cgit/hostap/tree/src/rsn_supp/wpa.c',
      'https://www.aircrack-ng.org/doku.php?id=cracking_wpa',
    ],
  },

  // ============================================================
  // Attack — INTERMÉDIAIRE / AVANCÉ
  // ============================================================
  {
    id: 'wifi-evil-twin',
    title: 'Evil Twin — Faux Point d\'Accès',
    category: 'attack',
    level: 'INTERMÉDIAIRE',
    summary:
      'Déploiement d\'un AP malveillant avec le même SSID que la cible pour MITM le trafic. Contourné par WPA3-SAE (authentification mutuelle) + EAP-TLS.',
    content: `## Evil Twin (Rogue AP)

L'attaque Evil Twin consiste à déployer un **faux point d'accès** avec le même SSID (et idéalement un BSSID proche) que l'AP légitime, mais avec un signal plus fort pour attirer les clients.

### Scénario typique
1. **Sniffer** le réseau cible : SSID, BSSID, canal, clients (airodump-ng).
2. **Déployer** le faux AP : hostapd avec même SSID, dnsmasq pour DHCP + DNS, nginx pour portail captif.
3. **Forcer** la déconnexion des clients légitimes (deauth flood).
4. **Capturer** les clients reconnectés au faux AP (signal plus fort).
5. **Intercepter** : HTTP en clair, DNS spoofing, portail captif pour phishing.

### Variantes
- **Captive portal phishing** : redirige vers \`login.evil-twin.local\` qui ressemble à Google/Microsoft.
- **SSL stripping** : downgrade HTTPS → HTTP (si HSTS absent).
- **Karma attack** : le faux AP répond à toutes les Probe Request avec le SSID demandé par le client (auto-connect).

### Détection (WIDS)
- **Double BSSID** pour un même SSID sur le même canal.
- **Vendor OUI inattendu** pour un SSID connu (ex: FreeWifi avec OUI Cisco).
- **Signal anormal** : variation > 10 dBm en peu de temps.
- **DHCP différentes** : deux plages d'IP sur le même SSID.

### Défense
| Contrôle | Efficacité |
|----------|------------|
| **WPA3-SAE** | Authentification mutuelle → evil twin ne peut pas finir le handshake |
| **EAP-TLS** | Certificat serveur vérifié par le client → faux AP rejeté |
| **PMF required** | Empêche le deauth forcé qui pousse les clients vers le faux AP |
| **HSTS + Certificate Pinning** | Neutralise le SSL stripping même si le client est sur le faux AP |
| **WIDS** | Détecte les double-SSID / BSSID inconnus / signal anormal |
| **VPN corporate** | Même sur un evil twin, le trafic est chiffré end-to-end |

### Outils
- \`hostapd\` (avec \`ssid=...\`), \`dnsmasq\`, \`nginx\` côté attaquant.
- \`airbase-ng\` (aircrack-ng) pour le mode karma.
- \`wifipumpkin3\` : framework tout-en-un.`,
    keyPoints: [
      'Evil twin = faux AP avec même SSID que la cible + signal plus fort.',
      'Précédé d\'un deauth flood pour forcer la reconnexion des clients.',
      'Permet MITM, phishing (captive portal), SSL stripping (si pas HSTS).',
      'Contourné par WPA3-SAE (auth mutuelle) + EAP-TLS (cert serveur).',
      'Détectable par WIDS (double BSSID, OUI inattendu, signal anormal).',
    ],
    references: [
      'https://attack.mitre.org/techniques/T1557/003/',
      'https://www.owasp.org/index.php/Man-in-the-middle_attack',
      'https://wifipumpkin3.github.io/',
      'https://www.sans.org/white-papers/34849/',
    ],
  },
  {
    id: 'wifi-deauth',
    title: 'Déauthentification 802.11',
    category: 'attack',
    level: 'DÉBUTANT',
    summary:
      'Trame de gestion subtype 0x0C qui notifie un client de sa déconnexion. Forgeable sans authentification si PMF désactivé → base de toutes les attaques WiFi.',
    content: `## Trame de déauthentification 802.11

La trame deauth (subtype 0x0C, frame type 0x00 = management) est un message de gestion 802.11 par lequel l'AP ou le client notifie l'autre partie d'une déconnexion immédiate.

### Structure
- **Frame Control** : type=0x00 (management), subtype=0x0C (deauth).
- **Duration** : durée virtuelle du médium.
- **Address 1** : destination (client ou broadcast FF:FF:FF:FF:FF:FF).
- **Address 2** : source (AP légitime — forgeable sans auth !).
- **Address 3** : BSSID.
- **Reason Code** : code de déconnexion (1 = unspecified, 7 = Class 3 frame, etc.).

### Pourquoi c'est critique
**Sans PMF**, cette trame n'est pas authentifiée. N'importe qui peut la forger avec l'adresse source de l'AP légitime :
- Tous les clients l'acceptent et se déconnectent immédiatement.
- Le client tente de se reconnecter → l'attaquant peut capturer le 4-way handshake.
- En broadcast (FF:FF:FF:FF:FF:FF), une seule trame déconnecte tous les clients.

### Outils
\`\`\`bash
# Déauth flood broadcast (déconnecte tous les clients)
aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:01 wlan0mon

# Déauth unicast vers un client spécifique
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:01 -c FF:EE:DD:CC:BB:AA wlan0mon

# Mdk3 (alternative)
mdk3 wlan0mon d -b blacklist.txt -c 6
\`\`\`

### Codes reason courants
| Code | Signification |
|------|---------------|
| 1 | Unspecified |
| 2 | Previous auth no longer valid |
| 4 | Disassociated due to inactivity |
| 7 | Class 3 frame from non-associated station |
| 8 | Class 3 frame (station leaving BSS) |

### Détection (IDS)
- **Total deauths ≥ 10 / sec** → DEAUTH_FLOOD.
- **Même client ciblé ≥ 3 fois** → CAPTURE_HANDSHAKE.
- **Plusieurs APs source différents (usurpés)** → EVIL_TWIN.

### Défense
- **PMF required (ieee80211w=2)** : les trames deauth broadcast sont ignorées, les unicast doivent être signées BIP-CMAC-128.
- **WPA3-SAE** : PMF obligatoire par spécification.
- **WIDS** : détecter les vagues de deauth anormales.`,
    keyPoints: [
      'Trame deauth = subtype 0x0C, non authentifiée sans PMF.',
      'Forgeable en broadcast → déconnecte tous les clients en une seule trame.',
      'Base de toutes les attaques WiFi (handshake capture, evil twin, DoS).',
      'Codes reason courants : 1 (unspecified), 7 (class 3 frame), 8 (leaving BSS).',
      'Défense : PMF required (ieee80211w=2) ou WPA3-SAE.',
    ],
    references: [
      'https://standards.ieee.org/ieee/802.11/1350/',
      'https://www.aircrack-ng.org/doku.php?id=deauthentication',
      'https://standards.ieee.org/ieee/802.11w/4669/',
    ],
  },
  {
    id: 'wifi-krack',
    title: 'KRACK — Key Reinstallation Attack',
    category: 'attack',
    level: 'AVANCÉ',
    summary:
      'Vulnérabilité CVE-2017-13077 (Vanhoef) : la réinstallation de la PTK lors d\'un replay M3 réinitialise le compteur de paquets → déchiffrement partiel du trafic.',
    content: `## KRACK (Key Reinstallation Attack)

KRACK est une famille de vulnérabilités découverte par **Mathy Vanhoef** en octobre 2017 (CVE-2017-13077 à 13082). Elle affecte le standard WPA2 lui-même (pas une implémentation spécifique) dans sa spécification du 4-way handshake et du groupe key handshake.

### Principe
La spécification 802.11i autorise la retransmission de M3 si M4 n'est pas reçu (fiable sur le medium radio). Mais elle ne précisait pas que **réinstaller une clé déjà installée ne devait pas réinitialiser le compteur de paquets (PN)**.

### Attaque
1. L'attaquant se positionne en **MITM de canal** (pas de blocage total — il forward les trames).
2. Il attend le 4-way handshake (connexion d'un client ou rekey GTK).
3. Il capture M1+M2+M3, puis **retransmet M3** plusieurs fois.
4. Le client vulnérable **réinstalle la PTK** à chaque réception de M3 → le **PN (Packet Number) est remis à 1**.
5. Les paquets chiffrés suivants utilisent le même keystream → XOR de deux paquets révèle le plaintext.

### Variantes (par type de handshake)
| CVE | Variante | Impact |
|-----|----------|--------|
| CVE-2017-13077 | 4-way handshake PTK reinstall | Déchiffrement TCP/ARP |
| CVE-2017-13078 | 4-way handshake GTK reinstall | Injection paquets broadcast |
| CVE-2017-13079 | Group key handshake | Injection broadcast |
| CVE-2017-13080 | Fast BSS Transition (802.11r) | Reinstall PTK sur roaming |
| CVE-2017-13081 | IBSS (ad-hoc) | Reinstall |
| CVE-2017-13082 | TWN (Tunneled Direct-Link Setup) | Reinstall |

### Limites
- L'attaquant **ne récupère pas la passphrase** directement.
- Il peut **déchiffrer des paquets** et **injecter du trafic** (notamment ARP → TCP).
- HTTPS reste protégé (TLS) sauf si SSL stripping réussit.
- L'attaque est **par client** (le patch OS corrige pour tous les AP).

### Patch
Tous les OS majeurs patchés en octobre-novembre 2017 :
- Linux wpa_supplicant ≥ 2.6
- Windows (Patch Tuesday octobre 2017)
- macOS 10.13.1
- Android (security patch novembre 2017)
- iOS 11.1

### Défense
- **Mettre à jour** tous les clients (post-2017).
- **WPA3-SAE** : SAE n'utilise pas le mécanisme de réinstallation → non vulnérable.
- **PMF required** : empêche le MITM de canal nécessaire à l'attaque.
- **HTTPS + HSTS** : même si l'attaque réussit, TLS protège les données applicatives.

### Vérifier si un client est patché
\`\`\`bash
# Sur le client Linux :
wpa_cli status | grep 'wpa_supplicant v'
# Version ≥ 2.6 → patché
\`\`\``,
    keyPoints: [
      'KRACK (CVE-2017-13077) exploite la réinstallation de PTK sur replay M3.',
      'Le PN (Packet Number) est réinitialisé → keystream réutilisé → déchiffrement.',
      'Attaque par MITM de canal (forward des trames, pas de blocage).',
      'Patché en 2017 sur tous les OS (Linux wpa_supplicant ≥ 2.6).',
      'WPA3-SAE non vulnérable (pas de réinstallation de clé).',
    ],
    references: [
      'https://www.krackattacks.com/',
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13077',
      'https://w1.fi/security/2017-1/wpa-packet-number-reuse-with-replayed-messages.txt',
      'https://papers.mathyvanhoef.com/ccs2017.pdf',
    ],
  },
  {
    id: 'wifi-wps',
    title: 'WPS — Wi-Fi Protected Setup',
    category: 'attack',
    level: 'INTERMÉDIAIRE',
    summary:
      'Mécanisme d\'onboarding simplifié (2007). Mode PIN brute-forçable en quelques heures (Pixie-Dust : secondes). À désactiver systématiquement.',
    content: `## WPS (Wi-Fi Protected Setup, 2007)

WPS a été conçu par le Wi-Fi Alliance pour simplifier l'ajout d'un nouvel appareil au réseau WiFi. Trois modes : **PIN** (8 digits), **PBC** (Push-Button), **NFC**.

### Mode PIN (le plus vulnérable)
- Le client saisit un PIN à 8 digits sur l'AP (ou l'inverse).
- L'AP valide séparément les **4 premiers digits** puis les **3 suivants** (le 8e est un checksum mod 11).
- Espace réel : 10^4 + 10^3 = **11 000 combinaisons** (et non 10^7).
- À 5 PIN/sec (limitation de l'AP) : ~30 minutes.

### Attaque Pixie-Dust (CVE-2014-9778)
Dominique Bongard (DEFCON 22, 2014) a découvert que certains chipsets (Broadcom, Realtek, Ralink) généraient les nonces E-S1 et E-S2 avec un **PRNG faible** (MAC, temps, compteur monotone). \`pixiewps\` résout alors l'équation DH en **2-4 secondes**.

\`\`\`bash
# Attaque Pixie-Dust (reaver)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -c 6 -K 1 -vv

# Si Pixie-Dust échoue, brute force classique
reaver -i wlan0mon -b AA:BB:CC:DD:EE:01 -c 6 -vv
\`\`\`

### Attaque brute force classique
Sans Pixie-Dust, l'attaque nécessite ~11000 tentatives à ~5 PIN/sec → ~30 minutes à 4 heures selon l'AP.

### Défense
| Mesure | Efficacité |
|--------|------------|
| **Désactiver WPS** (\`wps_state=0\`) | Totale — recommandé |
| **Désactiver PIN, garder PBC** | Bonne — le mode PBC n'est pas vulnérable |
| **WPS Lockdown** (3-5 échecs → 1h lockout) | Réduit le taux → 41 ans estimé |
| **WPA3-SAE** | Rend WPS obsolète (onboarding via SAE) |

### Configuration hostapd
\`\`\`ini
# Désactivé (recommandé)
wps_state=0

# OU PBC only + lockout
wps_state=2
ap_setup_locked=1
wps_pin_requests=0                    # pas de mode PIN
wps_locked_after_failures=3
wps_lockout_duration=3600
\`\`\`

### Vérification
\`\`\`bash
# Scanner un réseau pour WPS
wash -i wlan0mon -c 6 -C

# Lister les AP WPS vulnérables à Pixie-Dust
reaver -i wlan0mon -b <BSSID> -K 1 -vv
\`\`\``,
    keyPoints: [
      'WPS PIN = 8 digits dont 1 checksum → 11 000 combinaisons exploitables.',
      'Pixie-Dust (CVE-2014-9778) casse le PIN en 2-4 secondes sur chipsets vulnérables.',
      'Brute force classique : ~30 min à 4h selon l\'AP.',
      'Défense : désactiver WPS (wps_state=0) ou PBC only + WPS Lockdown.',
      'WPA3-SAE rend WPS obsolète.',
    ],
    references: [
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9778',
      'https://sviehb.files.wordpress.com/2011/12/viehboeff_wps.pdf',
      'https://github.com/t6x/reaver-wps-fork-t6x',
      'https://www.wi-fi.org/discover-wi-fi/wi-fi-protected-setup',
    ],
  },

  // ============================================================
  // Network — DÉBUTANT / INTERMÉDIAIRE
  // ============================================================
  {
    id: 'network-osi',
    title: 'Modèle OSI — 7 Couches',
    category: 'network',
    level: 'DÉBUTANT',
    summary:
      'Modèle théorique de communication réseau en 7 couches. WiFi opère en couche 2 (liaison). TCP/IP en couche 4 (transport) et 3 (réseau).',
    content: `## Modèle OSI (Open Systems Interconnection)

Le modèle OSI, normalisé par l'ISO en 1984, décrit les communications réseau en **7 couches**. Chaque couche offre des services à la couche supérieure et utilise ceux de la couche inférieure.

### Les 7 couches
| # | Couche | Rôle | Exemples |
|---|--------|------|----------|
| 7 | **Application** | Interface utilisateur | HTTP, DNS, SMTP, FTP |
| 6 | **Présentation** | Encodage, chiffrement | TLS, JPEG, ASCII |
| 5 | **Session** | Gestion des sessions | NetBIOS, RPC |
| 4 | **Transport** | Connexion bout en bout | TCP, UDP, QUIC |
| 3 | **Réseau** | Routage inter-réseaux | IP, ICMP, OSPF |
| 2 | **Liaison** | Trame sur le lien local | Ethernet, **WiFi (802.11)**, ARP |
| 1 | **Physique** | Signal électrique/ radio | Câble RJ45, onde radio, fibre |

### Encapsulation
\`\`\`
Application data
→ [TCP header] data        (couche 4 = segment)
→ [IP header][TCP] data    (couche 3 = paquet)
→ [Ethernet header][IP][TCP] data  (couche 2 = trame)
→ signal physique          (couche 1)
\`\`\`

### WiFi dans le modèle OSI
WiFi (**IEEE 802.11**) couvre les couches **1 et 2** :
- **Couche 1** (PHY) : modulation OFDM, canaux 2.4 GHz / 5 GHz / 6 GHz.
- **Couche 2** (MAC) : CSMA/CA, trames 802.11, adressage MAC, chiffrement WPA2/WPA3.

### Comparaison avec TCP/IP
Le modèle TCP/IP (4 couches) est plus pragmatique :
| TCP/IP | OSI |
|--------|-----|
| Application | 7 + 6 + 5 |
| Transport | 4 |
| Internet | 3 |
| Network access | 2 + 1 |

### Sécurité par couche
- **L2** : 802.1X, MAC filtering, WPA2/3.
- **L3** : IPsec, firewall, ACL.
- **L4** : TCP SYN cookies, port knocking.
- **L7** : TLS, WAF, validation applicative.

Une défense en profondeur protège chaque couche indépendamment.`,
    keyPoints: [
      'Modèle OSI = 7 couches (Physique → Application).',
      'WiFi opère en couches 1 (PHY) et 2 (MAC) — cf. IEEE 802.11.',
      'Encapsulation : chaque couche ajoute son header.',
      'TCP/IP simplifie en 4 couches (Application, Transport, Internet, Network access).',
      'Sécurité par couche : 802.1X (L2), IPsec (L3), TLS (L7) — défense en profondeur.',
    ],
    references: [
      'https://www.iso.org/standard/20269.html',
      'https://standards.ieee.org/ieee/802.11/1350/',
      'https://datatracker.ietf.org/doc/html/rfc1122',
    ],
  },
  {
    id: 'network-tcpip',
    title: 'Suite TCP/IP vs OSI',
    category: 'network',
    level: 'INTERMÉDIAIRE',
    summary:
      'Modèle pratique en 4 couches (Link, Internet, Transport, Application). Référence d\'Internet (RFC 1122). WiFi est dans la couche Link avec Ethernet.',
    content: `## Suite TCP/IP (RFC 1122)

Le modèle TCP/IP, antérieur à OSI, est le modèle réellement utilisé sur Internet. Il est défini dans le RFC 1122 (Host Requirements).

### 4 couches
| Couche | Protocoles | Fonction |
|--------|------------|----------|
| **Application** | HTTP, DNS, SMTP, SSH, TLS | API utilisateur |
| **Transport** | TCP, UDP, QUIC | Connexion bout en bout, fiabilité |
| **Internet** | IP (v4/v6), ICMP, IGMP | Routage inter-réseaux |
| **Link (Network access)** | Ethernet, **WiFi (802.11)**, PPP, ARP | Trame sur le lien local |

### Différences avec OSI
- OSI = modèle **théorique** (7 couches, dont Présentation et Session rarement utilisées).
- TCP/IP = modèle **pragmatique** (4 couches, fusionne les couches hautes).
- Les couches 5 et 6 d'OSI sont en pratique fusionnées dans la couche Application de TCP/IP (ex : TLS est géré par l'application, pas par une couche dédiée).

### TCP vs UDP vs QUIC
| Protocole | Fiabilité | Connexion | Usage typique |
|-----------|-----------|-----------|---------------|
| **TCP** | Oui (ACK, retransmission) | Connectée | HTTP, SSH, SMTP |
| **UDP** | Non | Sans connexion | DNS, VoIP, streaming |
| **QUIC** | Oui (sur UDP) | Connectée (HTTP/3) | Web moderne, HTTP/3 |

### Ports et sockets
- **Port** = adresse de service (16 bits, 0-65535).
- **Well-known** : 0-1023 (HTTP=80, HTTPS=443, SSH=22, DNS=53).
- **Registered** : 1024-49151.
- **Dynamic** : 49152-65535.
- **Socket** = (IP locale, port local, IP distante, port distant, protocole).

### Sécurité
- **L3 (IP)** : IPsec (ESP/AH), firewalls, ACL.
- **L4 (TCP/UDP)** : SYN cookies (Linux \`tcp_syncookies=1\`), port knocking.
- **L7 (Application)** : TLS, mTLS, WAF, validation stricte des entrées.
- **Défense en profondeur** : protéger chaque couche indépendamment (ex : WPA3 L2 + IPsec L3 + TLS L7).`,
    keyPoints: [
      'TCP/IP = 4 couches (Application, Transport, Internet, Link).',
      'WiFi et Ethernet sont dans la couche Link avec ARP.',
      'TCP = connecté + fiable ; UDP = sans connexion ; QUIC = HTTP/3 sur UDP.',
      'Ports well-known 0-1023 (HTTP=80, HTTPS=443, SSH=22, DNS=53).',
      'Défense en profondeur : IPsec L3 + SYN cookies L4 + TLS L7.',
    ],
    references: [
      'https://datatracker.ietf.org/doc/html/rfc1122',
      'https://datatracker.ietf.org/doc/html/rfc793',
      'https://datatracker.ietf.org/doc/html/rfc7600',
    ],
  },

  // ============================================================
  // Crypto — AVANCÉ
  // ============================================================
  {
    id: 'crypto-aes-ccmp',
    title: 'AES-CCMP — Chiffrement WPA2',
    category: 'crypto',
    level: 'AVANCÉ',
    summary:
      'AES en mode Counter + CBC-MAC (CCMP). Confidentialité + intégrité par bloc de 128 bits. Référence WPA2. Remplace TKIP.',
    content: `## AES-CCMP (Counter Mode with CBC-MAC Protocol)

AES-CCMP est le protocole de chiffrement obligatoire de WPA2 (802.11i, 2004). Il combine AES (Rijndael, FIPS 197) en mode **CTR** pour la confidentialité et **CBC-MAC** pour l'intégrité, dans une construction **AEAD** (Authenticated Encryption with Associated Data).

### Pourquoi pas RC4 ?
- RC4 (utilisé par WEP et WPA-TKIP) a des faiblesses cryptographiques connues (clés faibles, keystream biaisé).
- AES (Rijndael) a été sélectionné par NIST en 2001 après un concours public ouvert — analysé par la communauté cryptographique pendant 4 ans, considéré comme sûr.

### Construction AEAD
CCMP produit à la fois :
- **Ciphertext** (données chiffrées) via AES-CTR (Counter Mode).
- **MIC** (Message Integrity Code, 8 octets) via AES-CBC-MAC sur l'en-tête + les données.

Cela garantit simultanément **confidentialité** (lecture) et **intégrité** (altération détectable) avec une seule clé (TK, 128 bits, dérivée de la PTK).

### Format de la trame CCMP
\`\`\`
| Header  | Packet Number (PN, 6 bytes) | Encrypted payload | MIC (8 bytes) |
\`\`\`

- **PN** (Packet Number) : incrémenté à chaque paquet, jamais réutilisé (sinon KRACK).
- **Header** : non chiffré mais authentifié (CBW-MAC).
- **MIC** : 8 octets, vérifié par le récepteur.

### Comparaison avec TKIP
| Aspect | TKIP (WPA) | CCMP (WPA2) |
|--------|-----------|-------------|
| Algorithme | RC4 | AES |
| Taille clé | 128 bits | 128 bits |
| Taille bloc | RC4 = flux | 128 bits |
| Intégrité | MIC 64 bits faible | CBC-MAC 64 bits fort |
| Anti-replay | TSC 48 bits | PN 48 bits |
| Statut | Déprécié (2012) | Standard actuel |

### WPA3 — GCMP
WPA3 (2018) introduit **GCMP** (Galois/Counter Mode Protocol), plus rapide que CCMP grâce à l'utilisation de GHASH (parallélisable) au lieu de CBC-MAC. GCMP-256 (clé 256 bits) est requis pour **WPA3-Enterprise 192-bit** (Suite B).

### Configuration hostapd
\`\`\`ini
# WPA2-AES-CCMP (standard)
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP           # AES-CCMP uniquement (jamais TKIP)

# WPA3-GCMP (suite B 192-bit)
wpa=2
wpa_key_mgmt=WPA-EAP-SUITE-B-192
wpa_pairwise=GCMP-256
group=GCMP-256
ieee80211w=2
\`\`\`

### Tests de conformité
\`\`\`bash
# Vérifier que TKIP est désactivé sur l'AP
iw dev wlan0 scan | grep -A 20 "BSS.*<BSSID>" | grep -i "pairwise"

# Sniffer le cipher négocié sur une session existante
wpa_cli status | grep pairwise_cipher
\`\`\``,
    keyPoints: [
      'AES-CCMP = AES en mode CTR (confidentialité) + CBC-MAC (intégrité).',
      'Clé TK 128 bits dérivée de la PTK, PN 48 bits anti-replay.',
      'Remplace TKIP/RC4 — déprécié depuis 2012.',
      'WPA3 utilise GCMP (plus rapide, parallélisable) — GCMP-256 pour Suite B.',
      'Configuration : wpa_pairwise=CCMP (jamais TKIP).',
    ],
    references: [
      'https://csrc.nist.gov/publications/detail/fips/197/final',
        'https://standards.ieee.org/ieee/802.11i/4/',
      'https://datatracker.ietf.org/doc/html/rfc3610',
      'https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf',
    ],
  },

  // ============================================================
  // Defense — INTERMÉDIAIRE
  // ============================================================
  {
    id: 'defense-csma-ca',
    title: 'CSMA/CA — Évitement de Collisions WiFi',
    category: 'defense',
    level: 'INTERMÉDIAIRE',
    summary:
      'Mécanisme d\'accès au medium WiFi (802.11). Écoute + backoff aléatoire avant émission. Source de vulnérabilités DoS (brouillage, virtual carrier sense).',
    content: `## CSMA/CA (Carrier Sense Multiple Access with Collision Avoidance)

WiFi utilise **CSMA/CA** comme protocole d'accès au médium radio (couche MAC, 802.11). Contrairement à Ethernet (CSMA/CD — Collision Detection), la radio ne peut pas détecter une collision pendant l'émission (le signal émis couvre tout signal reçu).

### Mécanisme
1. **Carrier Sense** : écoute du canal (energy detect + virtual carrier sense via Network Allocation Vector NAV).
2. **IFS** (InterFrame Space) : attendre DIFS (DCF IFS) avant de tenter l'émission.
3. **Backoff aléatoire** : si le canal est occupé, attendre \`CW * slot_time\` (CW = Contention Window, entre CWmin et CWmax).
4. **RTS/CTS** (optionnel) : handshake pour réserver le canal (évite le problème des terminaux cachés).
5. **Émission** : envoi de la trame + attente de l'ACK du destinataire.
6. **Reprise** : si pas d'ACK, doubler CW (binary exponential backoff) jusqu'à CWmax.

### Paramètres 802.11 (2.4 GHz, OFDM)
| Paramètre | Valeur |
|-----------|--------|
| Slot time | 9 µs (OFDM) / 20 µs (HR-DSSS) |
| SIFS | 16 µs |
| DIFS | SIFS + 2×slot = 34 µs |
| CWmin | 15 |
| CWmax | 1023 |
| Max retries | 7 (data), 4 (RTS) |

### Attaques sur CSMA/CA
| Attaque | Principe |
|---------|----------|
| **Brouillage radio** (L1) | Émettre un signal continu → jamais d'IFS libre → DoS total |
| **NAV inflation** (L2) | Forger des trames avec Duration long → tous les clients attendent |
| **CTS flood** (L2) | Forger des CTS broadcast → tous les clients se taisent |
| **Replay ACK** (L2) | Forger des ACK pour des trames non reçues → retransmission du client |

### Détection
- **WIDS** : surveiller les pics de CSMA/CA inactif (énergie détectée mais pas de trames valides).
- **Spectrum analyzer** : détecter le brouillage (énergie continue hors modulation).
- **802.11ax BSS coloring** : permet à plusieurs BSS de coexister sur le même canal.

### Défense
- **Écoute passive impossible à bloquer** : c'est la nature du medium radio.
- **DFS** (Dynamic Frequency Selection, 5 GHz) : déplacer l'AP sur un autre canal si brouillage détecté.
- **PMF** : ne protège pas contre CSMA/CA mais empêche les attaques L2 sur les trames de gestion.
- **Wi-Fi 6E (6 GHz)** : plus de spectre, moins de collision, plus dur à brouiller.

### Limites fondamentales
- Le **brouillage radio** est **impossible à empêcher** par logiciel — c'est un problème physique.
- Le **déni de service L1/L2** est inhérent au medium partagé.
- La seule défense complète est **physique** (supervision radio, géofencing, atténuation directionnelle).`,
    keyPoints: [
      'CSMA/CA = écoute + backoff aléatoire (CW 15-1023) + ACK.',
      'WiFi ne peut pas détecter les collisions en émission → avoidance (pas detection).',
      'IFS : SIFS=16µs, DIFS=34µs, slot=9µs (OFDM 2.4 GHz).',
      'Attaques : brouillage radio, NAV inflation, CTS flood — DoS L1/L2 inhérent.',
      'DFS (5 GHz) et Wi-Fi 6E (6 GHz) réduisent la surface d\'attaque en changeant de canal.',
    ],
    references: [
      'https://standards.ieee.org/ieee/802.11/1350/',
      'https://www.sciencedirect.com/topics/computer-science/carrier-sense-multiple-access',
      'https://www.wi-fi.org/discover-wi-fi/wi-fi-6e',
    ],
  },
];
