# Audit des Simulations — Guyma Cyb

> **STATUT : RÉSOLU ✅ (Phases 1 → 3 terminées)**
>
> - **Phase 1** (commit `71821aa`) : les 9 derniers résidus corrigés — télémétrie
>   réelle (Footer, ScannerRecon, AnalyseWeb), IDs séquentiels, durées mesurées,
>   CVSS unifiés.
> - **Phase 2** (commit `570e084`) : le laboratoire et les tests actifs sont des
>   moteurs 100 % réels (vraies requêtes réseau, vrais verdicts, vraies preuves)
>   encadrés par le modèle d'attestation légale `authorization.ts`.
> - **Phase 3** : attestations étendues à TOUS les outils WiFi réels (monitor,
>   handshake, crack, WPS, MAC, Evil Twin), calculateur **CVSS v3.1 vectoriel
>   conforme FIRST** (`src/server/cvss31.ts`) — la sévérité est dérivée du score
>   calculé —, endpoint `/api/lab/history`, purge finale du vocabulaire
>   « simulation » et retrait du dossier `skills/` (artefacts de dev).
>
> Le reste de ce document est conservé comme **archive historique** de l'audit
> initial (inventaire daté, lu en lecture seule).

> Audit exhaustif en lecture seule effectué par l'agent `AUDIT-1` (Explore).
> Aucun code source n'a été modifié — ce document est un inventaire de toutes
> les simulations / données fictives / faux succès identifiés dans le logiciel.

---

## Résumé exécutif

**Total des simulations identifiées : 47** réparties sur **14 fichiers**
(8 fichiers frontend, 4 fichiers backend, 1 script shell, 1 fichier de données statiques).

### Répartition par catégorie

| Catégorie | Nombre | Sévérité |
|-----------|--------|----------|
| Données statiques hardcodées présentées comme résultats réels (mockSecurityData, KPI cards, badges) | 22 | Élevée |
| Faux succès (try/catch qui retourne un objet « réussi » ; setTimeout qui affiche « confirmé ») | 9 | Critique |
| `Math.random()` pour générer des données affichées à l'utilisateur (télémetrie, latence, IDs) | 6 | Élevée |
| Fallbacks silencieux / mock local en cas d'erreur backend | 3 | Moyenne |
| Données de seed injectées en base au premier lancement | 1 | Moyenne |
| Stub .exe retourné à la place d'un vrai installateur | 1 | Moyenne (documenté) |
| Faux délai / fausse latence / fausse durée | 3 | Faible |
| Commentaire de doc obsolète mentionnant un mode simulé supprimé | 1 | Faible |
| Fonction de simulation morte (jamais appelée) | 1 | Faible |

### Note importante sur le travail déjà fait

Les agents précédents (DEBUG-1, VITE-RUNTIME-FIX-1, AUTONOMOUS-INSTALL-1,
ICON-1+TERMINAL-VERIFY) ont **déjà** appliqué la doctrine « zéro simulation » sur
les chemins critiques suivants :
- `scanner.ts` → délègue à `coreScan` (Rust) ou `nodeRealScan` (fallback réel HTTP/TCP/DNS/TLS)
- `toolbridge.ts` → exécute réellement les scripts bash via WSL/Linux, retourne `{error}` honnête si un outil manque
- `runAutomatedReconSuite` → vraies sondes TCP `net.Socket`, vrai GET HTTP, vraie résolution DNS
- `App.tsx handleLaunchAnalysis` → catch affiche l'erreur réelle, plus de faux succès
- `ScannerReconView handleTestConnectivity` → plus de faux « HTTP 200 • Latence 18ms » en catch

**Les simulations qui restent sont concentrées dans :**
1. Le laboratoire d'attaques (securityLab.ts + 2 vues) — qui **simule** par conception (bac à sable défensif).
2. Les vues d'affichage des résultats (AnalyseWebView, ActiveTestsView, ReportRemediationView) — KPI hardcodés.
3. L'en-tête de l'application (Header.tsx) — fausse télémétrie CPU/RAM/Threads.
4. Les données d'initialisation (mockSecurityData.ts + db.ts seed) — fausses cibles/findings au démarrage.

---

## Détail par fichier

### A. Backend — `src/server/*.ts` + `server.ts`

| Fichier | Ligne(s) | Nature | Ce que ça prétend faire | Ce que ça fait réellement | Impact utilisateur | Recommandation |
|---------|----------|--------|--------------------------|----------------------------|--------------------|----------------|
| `src/server/securityLab.ts` | 26-156 (`executeLabSimulation`) | Faux succès + Math.random + données hardcodées | « Exécute une simulation sécurisée d'un vecteur d'attaque en bac à sable et qualifie une preuve non-destructive » | `setTimeout(50ms)` + `Math.random()*25` pour la latence ; détermine `httpStatus`, `wafIntercepted`, `observations` uniquement à partir de `targetMode === 'vulnerable'` ; insère un finding `confidence: 99, status: 'VALIDATED'` en SQLite — sans aucune requête réseau réelle | L'utilisateur croit qu'une « preuve non-destructive qualifiée à 99% » a été capturée ; le finding est persisté dans la même table SQLite que les findings réels → **indissociable** dans le Dashboard | **MARQUER « NON CONFIGURÉ »** : retourner `{ error: "Lab non configuré — vecteur théorique, aucune preuve réelle capturée" }` OU, si le lab est volontairement pédagogique, **persist dans une table `lab_findings` séparée** et afficher un badge « LAB » clair dans le Dashboard |
| `src/server/securityLab.ts` | 36, 62 | `Math.random()` pour données affichées | Génère `durationMs` (latence réseau réaliste) et un suffixe d'ID finding | `Date.now() - startTime + Math.floor(Math.random() * 25)` — la latence est inventée ; l'ID `LAB-FND-...-${Math.floor(Math.random()*900+100)}` ressemble à un ID réel | Les métadonnées de timing sont fausses | **SUPPRIMER** (utiliser le vrai `Date.now() - startTime` uniquement, et un UUID ou un compteur monotone pour l'ID) |
| `src/server/securityLab.ts` | 63, 199, 413-420, 557-564 | CVSS hardcodé selon la sévérité | Calcule un score CVSS | Mappe `CRITICAL→9.6/9.5/9.7`, `HIGH→8.2/8.0/8.3`, `MEDIUM→5.4/6.5/6.0` — valeurs arbitraires non dérivées d'un calcul CVSS | Les CVSS affichés sont inventés | **MARQUER « NON CONFIGURÉ »** : utiliser le vrai calculator CVSS v3.1 ou retourner `cvss: null` avec un flag `cvssEstimated: true` |
| `src/server/securityLab.ts` | 162-236 (`commitFullLabSuiteToReport`) | Faux succès de rapport complet | « Génère un rapport de sécurité exhaustif basé sur le laboratoire complet » | Insère en SQLite un scan factice `SCAN-LAB-...` avec `cvss_score: 8.8`, `risk_level: 'HIGH'`, `duration_ms: 1250`, `endpoints_count: LAB_ATTACK_VECTORS.length` — toutes valeurs hardcodées | L'utilisateur obtient un « rapport d'audit » qui ne correspond à aucun scan réel | **SUPPRIMER** l'insertion dans `scans`/`findings` ou **MARQUER « NON CONFIGURÉ »** avec un scan_type `LAB_SIMULATION` filtré du Dashboard |
| `src/server/securityLab.ts` | 370-512 (`executeWifiLabSimulation`) | Idem que `executeLabSimulation` mais pour WiFi | « Exécute une simulation sécurisée d'un vecteur d'attaque WiFi dans le bac à sable » | `setTimeout(60ms)` + `Math.random()*40` ; `apIntercepted`, `status` déterminés uniquement par `targetMode` ; finding persisté avec `confidence: 99, status: 'VALIDATED'`, `cwe: vector.mitre` (réutilise le champ cwe pour MITRE) | Idem que pour le lab web — preuve fictive persistée comme réelle | **MARQUER « NON CONFIGURÉ »** (même recommandation) |
| `src/server/securityLab.ts` | 518-603 (`commitFullWifiLabSuiteToReport`) | Faux succès de rapport WiFi complet | « Génère un rapport WiFi exhaustif » | Insère `SCAN-WIFI-LAB-...` avec `cvss: 9.0`, `risk: 'HIGH'`, `duration: 1850`, technologies `['802.11','WPA2','WPA3','PMF','SAE','hostapd-sandbox']` — toutes hardcodées | Rapport WiFi factice persisté | **SUPPRIMER** / **MARQUER « NON CONFIGURÉ »** |
| `src/server/db.ts` | 135-146 | Seed de données fictives au premier lancement | (Aucune prétention explicite — code d'init) | Insère 3 cibles fictives (`t-1` https://api.internal-cloud.io, `t-2` https://stage-auth.corporation.com, `t-3` https://payment-gateway.node12.org) avec timestamps `-2 hours`, `-1 day`, `-5 days` | L'utilisateur voit 3 « cibles historiques » au premier lancement, comme s'il avait déjà scanné ces domaines | **SUPPRIMER** le bloc `if (count === 0) { INSERT ... }` — démarrer avec une base vide est plus honnête |
| `src/server/packaging.ts` | 44-89 (`getOrCreateInstallerExeBuffer`) | Stub .exe retourné pour le téléchargement | « Télécharger l'installateur Windows GuymaCyb-Setup-v1.0.0.exe » | Retourne un buffer de 64 octets (en-tête MZ) + un manifest JSON — PAS un vrai exécutable. Commentaire de doc l'admet mais le frontend `DesktopPackagingModal` propose un bouton « Télécharger .exe » qui déclenche ce téléchargement | L'utilisateur télécharge un faux .exe de quelques Ko au lieu du vrai installateur de ~180 Mo | **MARQUER « NON CONFIGURÉ »** : le bouton de téléchargement doit afficher « Build non disponible sur cet environnement — exécutez `desktop\build-windows-exe.bat` sur Windows » au lieu de déclencher un téléchargement factice |
| `server.ts` | 262 | Fausse latence dans `/api/findings` | Retourne le `roundtripMs` réel de chaque finding | Hardcodé `roundtripMs: 25` pour tous les findings | Faible impact (champ secondaire) | **SUPPRIMER** — persister le vrai `roundtripMs` dans la table `findings` ou omettre ce champ |

### B. Frontend — `src/components/views/*.tsx` + `src/App.tsx`

| Fichier | Ligne(s) | Nature | Ce que ça prétend faire | Ce que ça fait réellement | Impact utilisateur | Recommandation |
|---------|----------|--------|--------------------------|----------------------------|--------------------|----------------|
| `src/App.tsx` | 53-57 | Initial state peuplé avec mock data | Charge `INITIAL_HISTORICAL_TARGETS`, `INITIAL_ENDPOINTS_TREE`, `INITIAL_FINDINGS`, `INITIAL_TEST_FAMILIES`, `INITIAL_TERMINAL_LOGS` au démarrage | Affiche 3 cibles, 11 endpoints, 7 findings, 9 familles de tests, 14 logs terminaux AVANT tout scan réel | L'utilisateur voit un tableau de bord « vivant » au premier lancement, comme si un audit avait déjà été effectué | **SUPPRIMER** — initialiser avec `[]` et afficher un état vide clair « Aucun scan effectué — lancez votre première analyse » |
| `src/App.tsx` | 167-209 (`handleStartAttackConfirmed`) | Faux succès de tests actifs | « Démarre une suite de tests actifs contrôlés contre la cible » | Aucun appel backend — `setTimeout(4500ms)` puis `setEngineStatus('Tests actifs complétés • 3 vulnérabilités confirmées')` ; ajoute 2 logs terminaux factices (« Dispatching contextual non-destructive probes to 42 API endpoints ») | L'utilisateur croit qu'une suite de tests actifs a confirmé 3 vulnérabilités alors que **rien ne s'est passé** | **SUPPRIMER** le setTimeout et le message de succès ; appeler une vraie API backend `/api/tests/active/run` qui n'existe pas encore — en attendant, **MARQUER « NON CONFIGURÉ »** avec un message « Tests actifs non implémentés » |
| `src/components/common/Header.tsx` | 26-27, 46-59, 271-280 | Math.random pour télémétrie affichée | Affiche « CPU X% • RAM YMB • Threads: 8 » dans l'en-tête (live engine telemetry) | `cpuUsage` aléatoire entre 8 et 26% (initial 12), `ramUsage` aléatoire entre 405 et 425 MB (initial 410), mis à jour toutes les 3s via `setInterval`. Le commentaire l'admet : « Dynamic light telemetry fluctuation to feel like a real native engine ». `Threads: 8` est hardcodé | L'utilisateur voit une fausse activité moteur dans l'en-tête permanent — donne l'illusion que le moteur « tourne » | **SUPPRIMER** le bloc setInterval + les states cpuUsage/ramUsage ; **REMPLACER PAR VRAI OUTIL** : appeler `/api/core/status` (qui retourne déjà `memoryMb: Math.round(process.memoryUsage().heapUsed/...)`) et afficher la vraie valeur. Supprimer le `Threads: 8` hardcodé (utiliser `os.cpus().length` déjà exposé par `/api/health`) |
| `src/components/views/ActiveTestsView.tsx` | 41-53 | Fausse barre de progression | « Progression de la suite de tests actifs » | `setInterval(() => setProgress(prev+1), 400)` — la barre avance mécaniquement de 1% toutes les 400ms jusqu'à 100%, sans aucun rapport avec un vrai test | L'utilisateur voit une barre de progression qui n'a aucun sens | **SUPPRIMER** (associé à la suppression de `handleStartAttackConfirmed` dans App.tsx) |
| `src/components/views/ActiveTestsView.tsx` | 84-86 | Métriques live hardcodées | « Workers: 4 threads • Rate: 42 req/s » | Valeurs statiques hardcodées dans le JSX | L'utilisateur croit que 4 workers tournent à 42 req/s | **SUPPRIMER** ou binder à de vraies métriques backend |
| `src/components/views/ActiveTestsView.tsx` | 142-168 | Breadcrumb de pipeline hardcodé | Affiche « 1. RECON (100%) • 2. DISCOVERY (137 pts) • 3. CLASSIFICATION (42 APIs) • 4. CHOIX DES TESTS • 5. TEST & VALIDATION • 6. RAPPORT » | Tous les chiffres (137 pts, 42 APIs) sont hardcodés dans le JSX, ne proviennent pas du backend | Pipeline fictif présenté comme réel | **SUPPRIMER** les compteurs hardcodés ou les dériver des vrais `endpointsTree` / `findings` passés en props |
| `src/components/views/ActiveTestsView.tsx` | 330 | Compteur hardcodé | « Voir les 21 preuves qualifiées dans l'Evidence Hub » | `21` est hardcodé | L'utilisateur s'attend à 21 preuves, peut en trouver un nombre différent | **REMPLACER** par `findings.length` (le compte réel) |
| `src/components/views/AnalyseWebView.tsx` | 53-61 | KPI bar hardcodée | « Terminé en 14.8s • Profondeur crawler: 4 • 137 URLs inspectées • IP: 192.0.2.42 • Origin: Nginx/1.24.0 (Ubuntu) » | Toutes ces valeurs sont hardcodées dans le JSX — ne proviennent pas du backend | L'utilisateur voit des statistiques de scan qui ne correspondent pas au scan réel | **SUPPRIMER** ou dériver de `endpointsTree.length` + des vraies métadonnées de scan |
| `src/components/views/AnalyseWebView.tsx` | 98, 104-112 | KPI « Endpoints Découverts » hardcodé | « 137 • +12 subpaths • GET 98 / POST 31 / PUT 8 » | `137`, `98`, `31`, `8` hardcodés | Métriques fictives | **REMPLACER** par `endpointsTree.length` et un vrai comptage par méthode HTTP |
| `src/components/views/AnalyseWebView.tsx` | 124-137 | KPI « Routes d'API Visibles » hardcodé | « 42 / 3 namespaces • /api/v1/auth OAUTH2 • /api/v1/users/{id} IDOR SUSP » | `42` hardcodé ; les routes affichées sont statiques | Fausse cartographie API | **REMPLACER** par un vrai calcul depuis `endpointsTree.filter(e => e.type==='api')` |
| `src/components/views/AnalyseWebView.tsx` | 148-166 | KPI « Technologies Détectées » hardcodé | « 9 Technologies • Nginx 1.24 • Express • PostgreSQL • React 18 » | `9` hardcodé ; liste statique de 4 techs | Empreinte technologique fictive | **REMPLACER** par les technologies renvoyées par le scan (champ `scanResult.technologies` déjà disponible côté App.tsx — à propager) |
| `src/components/views/AnalyseWebView.tsx` | 176-184 | KPI « Anomalies Détectées » hardcodé | « 21 Alertes actives • 3 HIGH Exploitable • 7 MED Durcissement • 11 LOW Info » | `21`, `3`, `7`, `11` hardcodés | Fausse matrice de sévérité | **REMPLACER** par `findings.length` et un vrai `findings.filter(f => f.severity==='HIGH').length` |
| `src/components/views/AnalyseWebView.tsx` | 199 | Compteur d'arborescence hardcodé | « 137 Découvertes » | `137` hardcodé | Incohérent avec le nombre réel d'endpoints affichés juste en dessous | **REMPLACER** par `endpointsTree.length` |
| `src/components/views/ScannerReconView.tsx` | 237-238 | Labels hardcodés dans le bouton ANALYSER | « 137 Endpoints • 9 Technologies » | Valeurs statiques affichées comme capacités de l'analyseur | L'utilisateur s'attend à découvrir 137 endpoints | **SUPPRIMER** ces labels ou les remplacer par une description qualitative (« cartographie passive ») |
| `src/components/views/ResultsEvidenceView.tsx` | 37-46 (`handleRetest`) | Faux succès de re-test | « Re-tester ce finding » → après 900ms affiche « Vérifié à [time] : Vulnérabilité toujours confirmée (Exploitable à 100%) » | `setTimeout(900ms)` + message hardcodé — aucun appel backend | L'utilisateur croit qu'une contre-vérification a été faite et confirme la vulnérabilité à 100% | **SUPPRIMER** le setTimeout et le message ; appeler une vraie API de re-test (qui n'existe pas encore) — en attendant **MARQUER « NON CONFIGURÉ »** |
| `src/components/views/ReportRemediationView.tsx` | 17-36 (`handleCopyJson`) | Données de rapport hardcodées | « Copier le rapport JSON » copie un objet avec `reportId: 'REP-20240524-EXM'`, `overallRisk: 'HIGH'`, `cvssBaseScore: 7.4`, `findingsSummary: {critical:0, high:3, medium:7, low:11}`, `auditSurface: {endpoints:137, apiRoutes:42, technologies:9, testedVectors:8}` | Toutes ces valeurs sont hardcodées dans le source — n'ont aucun lien avec le scan réel | L'utilisateur exporte un rapport SARIF/JSON avec des métriques fictives | **REMPLACER** par les vraies données dérivées de `findings` (passé en props via `targetConfig` uniquement — il faut propager `findings` à cette vue) |
| `src/components/views/ReportRemediationView.tsx` | 60, 134, 142-150, 158, 175, 180, 185, 190 | Métriques de rapport hardcodées dans l'UI | « ID: REP-20240524-EXM », CVSS gauge « 7.4 », « 3 Faiblesses Élevées / 7 Moyennes / 11 Faibles », « SHA-256: 8fa09...c1e92 », « 137 endpoints / 42 API / 9 tech / 8 vecteurs » | Toutes ces valeurs sont statiques dans le JSX | Le rapport affiché ne reflète pas l'audit réel | **REMPLACER** par de vraies valeurs (calculer depuis `findings`, générer un vrai hash SHA-256 du contenu) |
| `src/components/views/ReportRemediationView.tsx` | 257-406 | Sections de remédiation statiques | 3 onglets « 1. Fix BOLA/IDOR (Express) », « 2. Fix SQL Injection (PostgreSQL) », « 3. Hardening Headers (Nginx) » avec code Before/After | Contenu pédagogique statique — présente des correctifs génériques comme s'ils étaient les correctifs des findings de l'utilisateur | L'utilisateur croit que ces correctifs ciblent ses propres findings | **MARQUER « NON CONFIGURÉ »** : afficher en clair « Exemples de remédiation génériques — non liés à vos findings » OU binder sur les `remediationSteps` réelles de chaque `Finding` (champ déjà peuplé par le backend) |
| `src/components/views/SecurityLabView.tsx` | 75-104 | Fallback local mock en cas d'erreur API | « Lancer la Simulation » → si `/api/lab/simulate` échoue, génère `mockResult` avec `durationMs: 45`, observations hardcodées, et l'affiche comme si la simulation avait réussi | `catch { const mockResult = {...}; setSimulationHistory(...) ; showToast('Simulation exécutée en mode bac à sable local') }` | L'utilisateur voit un résultat de simulation alors que le backend était down — ne sait pas que ça a échoué | **SUPPRIMER** le bloc `mockResult` ; afficher `showToast('Échec de la simulation : API injoignable')` comme le fait déjà le WiFi lab |
| `src/components/common/Sidebar.tsx` | 36 | Badge hardcodé | « Analyse Web » porte un badge `137 URI` | Valeur statique dans le JSX | L'utilisateur voit 137 URI dans la sidebar sans aucun scan | **SUPPRIMER** le badge ou binder à `endpointsTree.length` |

### C. Données — `src/data/*.ts`

| Fichier | Ligne(s) | Nature | Ce que ça prétend faire | Ce que ça fait réellement | Impact utilisateur | Recommandation |
|---------|----------|--------|--------------------------|----------------------------|--------------------|----------------|
| `src/data/mockSecurityData.ts` | 3-31 (`INITIAL_HISTORICAL_TARGETS`) | 3 cibles fictives pré-remplies | Cibles historiques scannées | `api.internal-cloud.io` (HIGH, 8.4, "Aujourd'hui • 14:20", 18 findings), `stage-auth.corporation.com` (MED, 5.1, "Hier • 18:45", 9 findings), `payment-gateway.node12.org` (CLEAN, "12 Mai • 09:12") | Au premier lancement, l'utilisateur voit 3 cibles « déjà auditées » avec timestamps « Aujourd'hui • 14:20 » | **SUPPRIMER** (vide au démarrage) OU **MARQUER « Démo »** explicitement |
| `src/data/mockSecurityData.ts` | 33-168 (`INITIAL_ENDPOINTS_TREE`) | 11 endpoints fictifs pré-remplis | Arborescence découverte par scan | Endpoints `/login`, `/dashboard` (401), `/admin` (403, HIGH FINDING), `/api/user/{id}` (IDOR), `/api/products`, `/api/orders`, `/admin/metrics` (Prometheus exposé), `/api/v1/search?sort=` (SQLi injectable), `/backup.sql.gz` (archive backup publique) | Cartographie d'API réaliste affichée sans scan | **SUPPRIMER** (vide au démarrage) |
| `src/data/mockSecurityData.ts` | 170-417 (`INITIAL_FINDINGS`) | 7 findings fictifs pré-remplis avec preuves HTTP complètes | Findings validés | Findings SEC-2024-8841..8847 avec req/résponse HTTP complètes (Bearer tokens, SQL pg_sleep, métriques Prometheus, etc.) et `confidence: 94-100%` | L'utilisateur voit 7 findings « validés » au premier lancement | **SUPPRIMER** (vide au démarrage) |
| `src/data/mockSecurityData.ts` | 419-498 (`INITIAL_TEST_FAMILIES`) | 9 familles de tests fictives pré-remplies | Familles de tests actifs | `tf-auth` (PASS), `tf-bac` (FAIL, IDOR sur /api/user/42), `tf-injection` (TESTING), `tf-api` (FAIL, tenant isolation), `tf-rate` (WARNING, 250 req/2s), etc. — avec evidenceTrace complet | L'utilisateur voit une matrice de tests actifs déjà exécutés | **SUPPRIMER** (vide au démarrage) |
| `src/data/mockSecurityData.ts` | 500-515 (`INITIAL_TERMINAL_LOGS`) | 14 logs terminaux fictifs pré-remplis | Journal d'audit en direct | Logs horodatés `14:22:01` à `14:22:35` — « 137 endpoints found, 42 API routes categorized », « IDOR confirmed! », « Broken Tenant Isolation on /api/orders » | L'utilisateur voit un journal d'audit qui n'a jamais eu lieu | **SUPPRIMER** (vide au démarrage) |
| `src/data/labAttackVectors.ts` | 1-439 | Catalogue de 8 vecteurs d'attaque (OWASP) | Catalogue pédagogique du Cyber Lab | Dataset statique de vecteurs (SQLi, XSS, IDOR, SSRF, JWT, CORS, rate-limit, path traversal) avec `safeTestPayload`, `vulnerableResponseSample`, `remediationCodeExample` | Catalogue légitime — ces vecteurs alimentent le lab pédagogique | **GARDER** (légitime — contenu de cours / bac à sable) |
| `src/data/wifiLabVectors.ts` | 1-572 | Catalogue de ~10 vecteurs WiFi | Catalogue pédagogique du lab WiFi | Dataset statique (deauth flood, evil twin, KRACK, WPS, handshake, downgrade WPA3) avec MITRE, scenarios, code vuln/fix | Catalogue légitime | **GARDER** (légitime — contenu de cours / bac à sable) |
| `src/data/courseNotions.ts` | 1-871 | ~15 notions pédagogiques | Contenu de cours cybersécurité | Notions WiFi, réseau, cryptographie, attaques, défense — markdown, points clés, références | Contenu pédagogique légitime | **GARDER** (légitime — contenu de cours) |

### D. Scripts — `security-scripts/*.sh` et `*.py`

| Fichier | Ligne(s) | Nature | Ce que ça prétend faire | Ce que ça fait réellement | Impact utilisateur | Recommandation |
|---------|----------|--------|--------------------------|----------------------------|--------------------|----------------|
| `security-scripts/wifi-scan.sh` | 11-15 (commentaires), 329-400 (`builtin_networks()`), 454 | Commentaire obsolète + fonction morte | Commentaire ligne 11-15 prétend qu'il existe un mode « builtin-simulated » produisant « 6-8 realistic networks » | La fonction `builtin_networks()` (lignes 331-400) retourne 8 faux SSIDs français (FreeWifi_secure, Livebox-AB12, Bbox-A1B2C3, NETGEAR_5G, eduroam, Guest-WiFi, hidden, Cafe-des-Amis) MAIS n'est **jamais appelée** — le script retourne honnêtement `mode: "no-wireless-hardware"` avec un message d'erreur si pas de WiFi | Aucun impact fonctionnel (fonction morte) MAIS le commentaire induit en erreur les futurs développeurs | **SUPPRIMER** la fonction `builtin_networks()` et mettre à jour les commentaires lignes 11-15 pour refléter le comportement réel (« aucun matériel → erreur honnête, jamais de données simulées ») |
| `security-scripts/builtin_portscan.py` | 1-206 | (vérification) | « Pure-Python TCP connect scanner » | Vraie implémentation `socket.connect_ex()` sur 19 ports par défaut, ThreadPoolExecutor, map service/port réel | Réel — pas une simulation | **GARDER** |
| `security-scripts/builtin_fingerprint.py` | 1-145 | (vérification) | « Empreinte technologique web de secours » | Vrai `urllib.request.urlopen` + analyse des en-têtes Server/X-Powered-By + détection dans le HTML | Réel — pas une simulation | **GARDER** |
| `security-scripts/builtin_dirbrute.py` | 1-118 | (vérification) | « Découverte de chemins web de secours » | Vrai balayage HTTP GET sur une wordlist intégrée (40 chemins communs) | Réel — pas une simulation | **GARDER** |
| `security-scripts/cameradar-scan.sh` | 1-326 | (vérification) | « RTSP camera discovery + credential sweep » | Vrai scan TCP port 554 sur /24 + vrai DESCRIBE RTSP + vrai test de credentials par défaut (20 paires) | Réel — pas une simulation | **GARDER** |
| `security-scripts/hid-payloads.sh` | 1-266 | (vérification) | « Génération de payloads DuckyScript réels » | Génère de vrais payloads DuckyScript fonctionnels (reverse shell PowerShell, extraction clés WiFi netsh, etc.) | Réel — pas une simulation | **GARDER** |
| Tous les autres scripts `*.sh` (nmap, nikto, whatweb, dirbrute, dnsrecon, ssl-audit, ping, mtr, netcat, iperf3, wpa-audit, deauth-detect, wifi-handshake-capture, wifi-crack-handshake, wifi-wps-attack, wifi-mac-changer, wifi-monitor-mode, localnetwork-scan, terminal-exec, usb-arsenal, arsenal-hashcat, arsenal-searchsploit, geomac-locate, hid-payloads) | — | (vérification) | Exécutent de vrais binaires externes (nmap, nikto, hashcat, aircrack-ng…) et retournent `{error: ...}` honnête si l'outil manque | Réel — pas de simulation | Réel | **GARDER** |

### E. Desktop — `desktop/*.cjs` + `setup-wizard.html`

| Fichier | Ligne(s) | Nature | Ce que ça prétend faire | Ce que ça fait réellement | Impact utilisateur | Recommandation |
|---------|----------|--------|--------------------------|----------------------------|--------------------|----------------|
| `desktop/electron-main.cjs` | 1-772 | (vérification) | Shell Electron qui spawn le vrai backend Express + gère le wizard WSL | Aucune simulation — `spawn(process.execPath, [SERVER_BUNDLE])`, vraies commandes `wsl.exe -d Ubuntu -u root -- apt-get install`, vraie détection `wsl -l -v`, etc. | Réel — pas de simulation | **GARDER** |
| `desktop/setup-wizard.html` | 1-452 | (vérification) | Assistant de configuration WSL + outils | Vraies détections via IPC `setup:detect-all` → `detectWsl()` + `detectTools()` + `fs.existsSync(RUST_CORE)`. Commentaire ligne 146 « noyau Rust (optionnel — fallback Node disponible) » et ligne 431 « Fallback Node (réel) » — exacts | Réel — pas de simulation | **GARDER** |
| `desktop/main-preload.cjs`, `desktop/setup-preload.cjs`, `desktop/build-icon.cjs` | — | (vérification) | Preloads contextBridge + génération icône | Réel | Réel | **GARDER** |

---

## Priorités de correction — Top 10 critiques

| # | Fichier | Ligne(s) | Problème | Sévérité | Recommandation |
|---|---------|----------|----------|----------|----------------|
| 1 | `src/App.tsx` | 167-209 | `handleStartAttackConfirmed` = `setTimeout(4500)` + message « 3 vulnérabilités confirmées » sans aucun appel backend | **CRITIQUE** | **SUPPRIMER** le setTimeout et le message de succès ; appeler une vraie API backend `/api/tests/active/run` (à créer) — en attendant, **MARQUER « NON CONFIGURÉ »** |
| 2 | `src/components/common/Header.tsx` | 26-27, 46-59, 271-280 | Fausse télémétrie CPU/RAM/Threads via `Math.random()` affichée en permanence dans l'en-tête (commentaire explicite : « to feel like a real native engine ») | **CRITIQUE** | **SUPPRIMER** le `setInterval` random ; **REMPLACER PAR VRAI OUTIL** via `/api/core/status` (qui retourne déjà `memoryMb`) et `/api/health` (`threads: os.cpus().length`) |
| 3 | `src/data/mockSecurityData.ts` | 3-515 (5 exports) | 515 lignes de données fictives pré-chargées au démarrage : 3 cibles, 11 endpoints, 7 findings, 9 familles de tests, 14 logs terminaux horodatés `14:22:01-35` | **CRITIQUE** | **SUPPRIMER** les 5 exports et initialiser les states App.tsx à `[]` |
| 4 | `src/server/securityLab.ts` | 26-156, 162-236, 370-512, 518-603 | Le laboratoire d'attaques simule des preuves (« VULNERABLE confirmé à 99% ») et les persiste dans la table `findings` — indissociables des findings réels dans le Dashboard | **CRITIQUE** | **MARQUER « NON CONFIGURÉ »** : persister dans une table `lab_findings` séparée OU filtrer les findings par `scan_id LIKE 'SCAN-LAB-%'` / `SCAN-WIFI-LAB-%` dans le Dashboard |
| 5 | `src/components/views/AnalyseWebView.tsx` | 53-199 | 12 KPI hardcodés dans l'UI (« 137 URLs inspectées », « IP: 192.0.2.42 », « 9 Technologies », « 3 HIGH / 7 MED / 11 LOW », etc.) qui ne proviennent pas du backend | **ÉLEVÉE** | **REMPLACER** par de vraies valeurs dérivées de `endpointsTree` et `findings` (déjà disponibles en props au niveau App.tsx — à propager à AnalyseWebView) |
| 6 | `src/components/views/ReportRemediationView.tsx` | 17-36, 60-406 | Rapport d'audit entièrement factice : `REP-20240524-EXM`, CVSS `7.4`, `3H/7M/11L`, `137 endpoints`, `SHA-256: 8fa09...c1e92` — copié dans le presse-papier comme « rapport SARIF/JSON » | **ÉLEVÉE** | **REMPLACER** par les vraies valeurs dérivées de `findings` (propager `findings` en props à cette vue) |
| 7 | `src/components/views/ResultsEvidenceView.tsx` | 37-46 | Bouton « Re-tester ce finding » → `setTimeout(900ms)` + message « Vulnérabilité toujours confirmée (Exploitable à 100%) » — aucun appel backend | **ÉLEVÉE** | **SUPPRIMER** le setTimeout ; appeler une vraie API de re-test (à créer) — en attendant **MARQUER « NON CONFIGURÉ »** |
| 8 | `src/components/views/ActiveTestsView.tsx` | 41-53, 84-86, 142-168, 330 | Fausse barre de progression `setInterval`, « Workers: 4 threads • Rate: 42 req/s », breadcrumb « 137 pts / 42 APIs » et « 21 preuves qualifiées » — tous hardcodés | **ÉLEVÉE** | **SUPPRIMER** les métriques hardcodées ; dériver les compteurs de `findings.length` et `endpointsTree.length` |
| 9 | `src/server/db.ts` | 135-146 | Seed de 3 cibles fictives (`t-1`, `t-2`, `t-3`) au premier lancement — apparaissent dans `/api/targets` et le Dashboard comme cibles historiques | **MOYENNE** | **SUPPRIMER** le bloc `if (count === 0) { INSERT ... }` |
| 10 | `src/server/packaging.ts` | 44-89 | `getOrCreateInstallerExeBuffer` retourne un stub de 64 octets (en-tête MZ + JSON manifest) au lieu du vrai installateur de 180 Mo ; le frontend `DesktopPackagingModal` propose un bouton « Télécharger .exe » qui déclenche ce faux téléchargement | **MOYENNE** (documenté) | **MARQUER « NON CONFIGURÉ »** : remplacer le bouton de téléchargement par un message « Build non disponible sur cet environnement — exécutez `desktop\build-windows-exe.bat` sur Windows » |

---

## Notes méthodologiques

1. **Le dossier `skills/`** (~ 700 fichiers) a été **exclu** de l'audit : il contient des définitions de compétences externes (ClawHub Skills) sans rapport avec le code de Guyma Cyb.

2. **Le dossier `shadowscan-core/`** (noyau Rust) n'a pas été audité en détail — il n'a été identifié aucune simulation dans le fichier `src/main.rs` lors d'un grep rapide. À valider par un agent Rust séparé si nécessaire.

3. **Les fichiers de données pédagogiques** (`labAttackVectors.ts`, `wifiLabVectors.ts`, `courseNotions.ts`) sont **légitimes** : ils alimentent le Cyber Range / les cours et sont explicitement labellisés « bac à sable défensif » dans l'UI. Ils ne prétendent pas être des résultats de scan réels.

4. **Les scripts shell `security-scripts/*.sh` et Python `builtin_*.py`** sont **réels** : ils exécutent de vrais binaires (nmap, nikto, hashcat, aircrack-ng, iw, iwlist, python sockets) et retournent honnêtement `{error: ...}` quand l'outil ou le hardware manque. La seule exception est `wifi-scan.sh` qui contient une fonction `builtin_networks()` morte (jamais appelée) + un commentaire obsolète mentionnant un mode « builtin-simulated » supprimé.

5. **Le shell Electron** (`desktop/electron-main.cjs`, `setup-wizard.html`) est **réel** : vraies détections WSL, vraies commandes `wsl.exe -d Ubuntu -u root -- apt-get install`, vrai spawn du backend Express, etc.

6. **Le backend `toolbridge.ts`** est **réel** : exécute les scripts via `spawn(bash, [sp, ...args])` ou `spawn('wsl.exe', [...])` sur Windows, parse le JSON stdout, retourne `{error}` honnête si l'outil manque. Le fallback Node (`nodeRealScan`, `nodeRealRecon`, `nodeRealHeaders`) est une **vraie implémentation** (fetch HTTP, sockets TCP, tls.connect, dns.resolve) — pas une simulation.
