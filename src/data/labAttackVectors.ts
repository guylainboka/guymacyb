import { LabAttackVector } from '../types';

export const LAB_ATTACK_VECTORS: LabAttackVector[] = [
  {
    id: 'sqli-error',
    name: 'Injection SQL (SQLi)',
    category: 'INJECTION',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    severity: 'CRITICAL',
    difficulty: 'MOYEN',
    description:
      'Tentative de manipulation de requêtes SQL via des paramètres utilisateur non assainis. Permet le contournement d’authentification ou l’exfiltration de données.',
    safeTestPayload: "' OR '1'='1' -- (Sonde sécurisée non destructive)",
    vulnerableResponseSample: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "authenticated": true,
  "user": "admin",
  "role": "SUPERADMIN",
  "debug_query": "SELECT * FROM users WHERE email='' OR '1'='1' --' AND active=1",
  "db_driver": "sqlite3_native"
}`,
    remediatedResponseSample: `HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "status": "error",
  "code": "INVALID_INPUT_FORMAT",
  "message": "Caractères suspects neutralisés. Les requêtes utilisent des requêtes préparées (Prepared Statements).",
  "waf_flag": "SQL_INJECTION_PATTERN_DETECTED",
  "audit_event_id": "SEC-SQL-98214"
}`,
    vulnerableBehaviorExplanation:
      'La requête concatène directement l’entrée utilisateur dans la chaîne SQL sans échappement ni requêtes préparées. Le payload altère la logique booléenne et renvoie le premier compte administrateur.',
    remediatedBehaviorExplanation:
      'Le moteur utilise une requête préparée avec des marqueurs de substitution (?, $1). Le payload est traité comme une simple valeur de chaîne littérale inoffensive.',
    defensiveControls: [
      'Utilisation stricte de requêtes préparées (Prepared Statements) ou ORM',
      'Validation de schéma d’entrée (Zod / Joi / Pydantic)',
      'Principe du moindre privilège sur le compte de base de données',
      'Règles WAF de détection de motifs SQL syntaxiques',
    ],
    remediationCodeExample: {
      language: 'TypeScript / Node.js',
      vulnerable: `// ❌ VULNERABLE : Concaténation directe
const user = await db.query(
  \`SELECT * FROM accounts WHERE email = '\${req.body.email}'\`
);`,
      fixed: `// ✅ SECURISE : Requête paramétrée (Prepared Statement)
const user = await db.query(
  'SELECT * FROM accounts WHERE email = ? AND status = ?',
  [req.body.email, 'ACTIVE']
);`,
    },
  },
  {
    id: 'xss-reflected',
    name: 'Cross-Site Scripting Réfléchi (XSS)',
    category: 'INJECTION',
    owasp: 'A03:2021 - Injection',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    severity: 'HIGH',
    difficulty: 'FAIBLE',
    description:
      'Injection de code script malveillant dans la réponse HTTP suite à un manque d’échappement des données reçues via les paramètres d’URL ou formulaires.',
    safeTestPayload: '<script>console.warn("SHADOWSCAN_BENIGN_PROBE")</script>',
    vulnerableResponseSample: `HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<div class="search-banner">
  Résultats de recherche pour : <script>console.warn("SHADOWSCAN_BENIGN_PROBE")</script>
</div>
<!-- Aucun en-tête CSP configuré -->`,
    remediatedResponseSample: `HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123';
X-Content-Type-Options: nosniff

<div class="search-banner">
  Résultats de recherche pour : &lt;script&gt;console.warn(&quot;SHADOWSCAN_BENIGN_PROBE&quot;)&lt;/script&gt;
</div>`,
    vulnerableBehaviorExplanation:
      'Le paramètre q reflète directement le balisage HTML non échappé dans le DOM du navigateur. Le script s’exécute dans le contexte de sécurité de la session utilisateur.',
    remediatedBehaviorExplanation:
      'Les entités HTML sont encodées (&lt; &gt; &quot;) et la directive CSP bloque tout script inline non signé par un nonce cryptographique.',
    defensiveControls: [
      'Encodage contextuel strict des sorties (HTML, JavaScript, CSS)',
      'Déploiement d’un en-tête Content-Security-Policy (CSP) avec nonces',
      'Attributs HttpOnly et SameSite sur tous les cookies de session',
      'Nettoyage DOM via des bibliothèques certifiées (ex: DOMPurify)',
    ],
    remediationCodeExample: {
      language: 'TypeScript / Express',
      vulnerable: `// ❌ VULNERABLE : Injection directe dans le template
res.send(\`<p>Recherche : \${req.query.q}</p>\`);`,
      fixed: `// ✅ SECURISE : Encodage et CSP stricte
import sanitizeHtml from 'sanitize-html';
const cleanQuery = sanitizeHtml(req.query.q as string);
res.setHeader('Content-Security-Policy', "default-src 'self'");
res.send(\`<p>Recherche : \${cleanQuery}</p>\`);`,
    },
  },
  {
    id: 'ssrf-internal',
    name: 'Server-Side Request Forgery (SSRF)',
    category: 'SERVER_SIDE',
    owasp: 'A10:2021 - Server-Side Request Forgery',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
    severity: 'CRITICAL',
    difficulty: 'ÉLEVÉ',
    description:
      'L’application Web télécharge ou interroge une ressource distante en utilisant une URL fournie par l’utilisateur, permettant d’interroger le réseau interne ou les métadonnées cloud (AWS/GCP).',
    safeTestPayload: 'http://169.254.169.254/latest/meta-data/ (Sonde bénigne Cloud Metadata)',
    vulnerableResponseSample: `HTTP/1.1 200 OK
Content-Type: text/plain

ami-id
iam/security-credentials/production-role
local-hostname
local-ipv4: 10.0.4.15
instance-type: c5.xlarge`,
    remediatedResponseSample: `HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "status": "blocked",
  "reason": "SSRF_FILTER_RESTRICTION",
  "error": "L'adresse IP cible résolue (169.254.169.254) appartient à une plage réseau privée/interdite.",
  "defense": "DNS resolution validation & IP range denylist enforced"
}`,
    vulnerableBehaviorExplanation:
      'Le serveur accepte une URL arbitraire passée en paramètre et initie un appel HTTP sortant sans vérifier si l’adresse cible est une IP interne ou le service de métadonnées du cloud.',
    remediatedBehaviorExplanation:
      'Le validateur DNS résout l’adresse IP avant la requête et refuse les adresses RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) ainsi que 127.0.0.1 et 169.254.169.254.',
    defensiveControls: [
      'Liste blanche stricte des protocoles (uniquement HTTPS)',
      'Vérification IP après résolution DNS (anti-rebond DNS Rebinding)',
      'Désactivation du support des redirections HTTP automatiques',
      'Activation du mode IMDSv2 avec token obligatoire sur AWS / GCP',
    ],
    remediationCodeExample: {
      language: 'Node.js / TypeScript',
      vulnerable: `// ❌ VULNERABLE : Requête aveugle vers l'URL cliente
const response = await fetch(req.body.avatarUrl);`,
      fixed: `// ✅ SECURISE : Validation stricte d'IP et domaine
import ipaddr from 'ipaddr.js';
import dns from 'dns/promises';

const host = new URL(req.body.avatarUrl).hostname;
const { address } = await dns.lookup(host);
const addr = ipaddr.parse(address);
if (addr.range() !== 'unicast') {
  throw new Error('Adresse réseau interne non autorisée');
}`,
    },
  },
  {
    id: 'idor-bola',
    name: 'Accès Direct à un Objet (IDOR / BOLA)',
    category: 'ACCESS_CONTROL',
    owasp: 'A01:2021 - Broken Access Control',
    cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
    severity: 'HIGH',
    difficulty: 'FAIBLE',
    description:
      'L’utilisateur modifie l’identifiant numérique d’une ressource dans l’URL (ex: /api/invoices/1042) pour accéder aux données confidentielles d’un autre client sans contrôle de droits.',
    safeTestPayload: 'GET /api/client/records/1089 (avec jeton utilisateur standard #1002)',
    vulnerableResponseSample: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "record_id": 1089,
  "owner_account": "entreprise-partenaire-alpha",
  "client_ssn": "***-**-9812",
  "tax_balance_due": 45890.00,
  "private_documents": ["contrat_secret_2026.pdf"]
}`,
    remediatedResponseSample: `HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "status": "error",
  "code": "ACCESS_DENIED",
  "message": "Vous n'avez pas les autorisations nécessaires pour consulter la ressource #1089.",
  "security_audit": "Tentative de franchissement de cloisonnement locataire consignée."
}`,
    vulnerableBehaviorExplanation:
      'Le contrôleur backend récupère l’enregistrement directement avec WHERE id = :id sans vérifier si le compte connecté est le propriétaire ou possède le rôle requis.',
    remediatedBehaviorExplanation:
      'Le filtre d’autorisation applique le contrôle au niveau de la requête SQL (WHERE id = :id AND tenant_id = :current_user_tenant), garantissant un cloisonnement étanche.',
    defensiveControls: [
      'Contrôle d’autorisation basé sur les attributs (ABAC / RBAC) à chaque endpoint',
      'Utilisation d’UUID v4 non séquentiels plutôt que d’entiers auto-incrémentés',
      'Audit systématique de propriété de ressource au niveau de la couche service',
      'Tests d’intégration d’accès croisé automatisés en CI/CD',
    ],
    remediationCodeExample: {
      language: 'TypeScript / Express',
      vulnerable: `// ❌ VULNERABLE : Recherche par ID sans vérifier le propriétaire
const invoice = await db.invoices.findById(req.params.id);
res.json(invoice);`,
      fixed: `// ✅ SECURISE : Vérification systématique du tenant / propriétaire
const invoice = await db.invoices.findOne({
  id: req.params.id,
  tenantId: req.user.tenantId, // Contrôle d'accès strict
});
if (!invoice) return res.status(403).json({ error: 'Accès non autorisé' });
res.json(invoice);`,
    },
  },
  {
    id: 'jwt-alg-none',
    name: 'Falsification de Jeton JWT (Broken Auth)',
    category: 'AUTHENTICATION',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    cwe: 'CWE-287: Improper Authentication',
    severity: 'CRITICAL',
    difficulty: 'MOYEN',
    description:
      'Contournement de la validation cryptographique du jeton JWT par substitution de l’algorithme à "none" ou utilisation d’un secret de signature faible.',
    safeTestPayload: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9.',
    vulnerableResponseSample: `HTTP/1.1 200 OK
Content-Type: application/json

{
  "session": "active",
  "user": "admin",
  "privileged_access": true,
  "scope": ["users:read", "users:delete", "server:restart"],
  "warning": "Signature bypassed - accepted alg=none"
}`,
    remediatedResponseSample: `HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "status": "error",
  "code": "JWT_VERIFICATION_FAILED",
  "message": "L'algorithme du jeton ('none') n'est pas autorisé. Seul RS256/ES256 est accepté avec signature obligatoire."
}`,
    vulnerableBehaviorExplanation:
      'La bibliothèque de validation accepte le paramètre "alg" envoyé par le client sans forcer un algorithme prédéfini, validant ainsi un token sans signature.',
    remediatedBehaviorExplanation:
      'Le vérificateur force explicitement les algorithmes autorisés (ex: algorithms: ["RS256"]) et rejette immédiatement tout token non conforme ou sans signature.',
    defensiveControls: [
      'Spécification explicite des algorithmes de signature acceptés dans la méthode de vérification',
      'Clés asymétriques fortes (RSA 2048+ ou ECDSA P-256)',
      'Expiration courte des tokens (15 minutes) avec rotation de refresh token',
      'Révocation des tokens via liste de blocage ou version de session',
    ],
    remediationCodeExample: {
      language: 'TypeScript / JWT',
      vulnerable: `// ❌ VULNERABLE : Accepte n'importe quel algorithme dans le header
const payload = jwt.decode(token); // Ou jwt.verify sans forcer l'algo`,
      fixed: `// ✅ SECURISE : Forcer strictement l'algorithme asymétrique
const payload = jwt.verify(token, publicKey, {
  algorithms: ['RS256'], // Interdit explicitement 'none' ou 'HS256'
  issuer: 'https://auth.enterprise.com',
  audience: 'https://api.enterprise.com',
});`,
    },
  },
  {
    id: 'path-traversal',
    name: 'Traversée de Répertoire (Path Traversal)',
    category: 'SERVER_SIDE',
    owasp: 'A01:2021 - Broken Access Control',
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    severity: 'HIGH',
    difficulty: 'FAIBLE',
    description:
      'Exploitation des séquences de remontée de répertoires "../" pour lire des fichiers système ou des configurations sensibles en dehors du dossier prévu.',
    safeTestPayload: 'GET /api/download?file=../../../../etc/resolv.conf',
    vulnerableResponseSample: `HTTP/1.1 200 OK
Content-Type: text/plain

# Generated by NetworkManager
nameserver 1.1.1.1
nameserver 8.8.8.8
search localdomain`,
    remediatedResponseSample: `HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "status": "error",
  "code": "ILLEGAL_FILE_PATH",
  "message": "Le chemin demandé sort des limites du répertoire autorisé.",
  "resolved_path_violation": true
}`,
    vulnerableBehaviorExplanation:
      'Le chemin du fichier est concaténé directement à la racine du dossier sans résolution de chemin canonique, permettant à l’attaquant de remonter vers la racine du système.',
    remediatedBehaviorExplanation:
      'Le chemin est résolu avec path.resolve() et vérifié pour s’assurer qu’il commence obligatoirement par le préfixe du dossier de stockage autorisé.',
    defensiveControls: [
      'Résolution canonique du chemin et validation stricte du préfixe',
      'Stockage des fichiers sous des identifiants aléatoires (UUID) en base',
      'Exécution de l’application dans un conteneur en lecture seule (read-only filesystem)',
      'Utilisation d’une liste blanche stricte pour les noms de fichiers',
    ],
    remediationCodeExample: {
      language: 'TypeScript / Node.js',
      vulnerable: `// ❌ VULNERABLE : Concaténation naïve
const filePath = path.join(__dirname, 'public/docs', req.query.file as string);
res.sendFile(filePath);`,
      fixed: `// ✅ SECURISE : Vérification du chemin canonique
const safeBase = path.resolve(__dirname, 'public/docs');
const targetPath = path.resolve(safeBase, req.query.file as string);

if (!targetPath.startsWith(safeBase)) {
  return res.status(403).json({ error: 'Accès fichier interdit' });
}
res.sendFile(targetPath);`,
    },
  },
  {
    id: 'rate-limit-bypass',
    name: 'Absence de Limitation de Débit (Brute-Force / DoS)',
    category: 'AUTHENTICATION',
    owasp: 'A04:2021 - Insecure Design',
    cwe: 'CWE-307: Improper Restriction of Excessive Authentication Attempts',
    severity: 'MEDIUM',
    difficulty: 'FAIBLE',
    description:
      'Absence de quota ou de seuil sur les points de terminaison sensibles (/api/login, /api/reset-password), permettant les attaques par force brute et credential stuffing.',
    safeTestPayload: 'Envoi de 100 requêtes d’authentification consécutives en 200ms',
    vulnerableResponseSample: `HTTP/1.1 200 OK (sur les 100 requêtes consécutives)
X-RateLimit-Remaining: Indéfini (aucun en-tête)

{
  "status": "failure",
  "attempts_processed": 100,
  "ip_lockout": false,
  "elapsed_ms": 184
}`,
    remediatedResponseSample: `HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
Content-Type: application/json

{
  "status": "rate_limited",
  "message": "Trop de tentatives détectées. Votre adresse IP est temporairement suspendue pendant 60 secondes.",
  "protection": "Token Bucket Rate Limiting (Redis-backed)"
}`,
    vulnerableBehaviorExplanation:
      'Le serveur traite chaque tentative de connexion de manière synchrone sans limiter la cadence par IP ou par compte utilisateur ciblé.',
    remediatedBehaviorExplanation:
      'Un middleware de limitation de débit (ex: express-rate-limit couplé à Redis) bloque les requêtes excédant le quota (ex: max 5 requêtes par minute sur le login).',
    defensiveControls: [
      'Mise en place de rate limiting par IP et par identifiant de compte',
      'Implémentation de mécanismes CAPTCHA ou Proof-of-Work après 3 échecs',
      'Détection de credential stuffing avec réputation IP',
      'Verrouillage temporaire exponentiel des comptes ciblés',
    ],
    remediationCodeExample: {
      language: 'TypeScript / Express',
      vulnerable: `// ❌ VULNERABLE : Aucun limiteur de débit
app.post('/api/login', handleLogin);`,
      fixed: `// ✅ SECURISE : Limiteur de débit strict
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 tentatives maximum
  message: { error: 'Trop de tentatives, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.post('/api/login', authLimiter, handleLogin);`,
    },
  },
  {
    id: 'cors-misconfig',
    name: 'Mauvaise Configuration CORS (Data Leak)',
    category: 'CONFIG',
    owasp: 'A05:2021 - Security Misconfiguration',
    cwe: 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains',
    severity: 'MEDIUM',
    difficulty: 'FAIBLE',
    description:
      'Configuration trop permissive du partage de ressources entre origines multiples (CORS), permettant à des sites tiers non autorisés de lire des données privées de l’utilisateur authentifié.',
    safeTestPayload: 'GET /api/user/profile avec Origin: https://malicious-site-simulation.test',
    vulnerableResponseSample: `HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-site-simulation.test
Access-Control-Allow-Credentials: true
Vary: Origin

{
  "email": "victim@corporate.internal",
  "api_token": "live_sec_9934208a12",
  "internal_notes": "Données confidentielles accessibles"
}`,
    remediatedResponseSample: `HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.authorized-enterprise.com
Access-Control-Allow-Credentials: true
Vary: Origin

{
  "email": "victim@corporate.internal",
  "api_token": "live_sec_9934208a12"
}
<!-- L'origine frauduleuse est rejetée par la politique CORS stricte -->`,
    vulnerableBehaviorExplanation:
      'Le serveur reflète dynamiquement l’en-tête Origin reçu sans le valider par rapport à une liste blanche, tout en activant Allow-Credentials: true.',
    remediatedBehaviorExplanation:
      'Le serveur valide rigoureusement l’origine contre une liste blanche exacte et refuse de répondre avec des en-têtes CORS permissifs aux origines non autorisées.',
    defensiveControls: [
      'Liste blanche stricte des domaines autorisés (pas de regex permissive ni de réflexion aveugle)',
      'Ne jamais combiner Access-Control-Allow-Origin: * avec Allow-Credentials: true',
      'Validation des en-têtes Sec-Fetch-Site et Sec-Fetch-Mode',
    ],
    remediationCodeExample: {
      language: 'TypeScript / Express',
      vulnerable: `// ❌ VULNERABLE : Réflexion aveugle de l'origine
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});`,
      fixed: `// ✅ SECURISE : Liste blanche stricte des origines
import cors from 'cors';

const allowedOrigins = ['https://app.monentreprise.fr', 'https://admin.monentreprise.fr'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origine CORS non autorisée'));
    }
  },
  credentials: true,
}));`,
    },
  },
];
