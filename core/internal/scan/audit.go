package scan

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/guylainboka/guymacyb/core/internal/model"
)

// auditContext rassemble les observations d'une cible pour en dériver les
// découvertes de sécurité.
type auditContext struct {
	domain         string
	target         *url.URL
	isHTTPS        bool
	headers        map[string]string
	setCookies     []string
	statusCode     int
	statusText     string
	latencyMs      int64
	allowedMethods string
	traceEnabled   bool
}

// check décrit une règle d'audit déclarative portant sur un en-tête manquant.
type missingHeaderCheck struct {
	header           string
	requiresHTTPS    bool
	title            string
	severity         string
	cvss             float64
	category         string
	cwe              string
	description      string
	impact           string
	remediationTitle string
	remediationSteps []string
}

var missingHeaderChecks = []missingHeaderCheck{
	{
		header:           "content-security-policy",
		title:            "Absence de Content Security Policy (CSP)",
		severity:         "MEDIUM",
		cvss:             5.3,
		category:         "Headers Security",
		cwe:              "CWE-1021",
		description:      "Aucun en-tête Content-Security-Policy n'est renvoyé. Sans CSP, le navigateur exécute tout script injecté sans politique de confinement contre les attaques XSS.",
		impact:           "Exécution de JavaScript non autorisé, vol de jetons de session et détournement d'interface.",
		remediationTitle: "Déployer une Content Security Policy stricte",
		remediationSteps: []string{
			"Définir : Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
			"Proscrire les directives 'unsafe-inline' et 'unsafe-eval'.",
			"Déployer d'abord en Content-Security-Policy-Report-Only pour mesurer l'impact.",
		},
	},
	{
		header:           "strict-transport-security",
		requiresHTTPS:    true,
		title:            "En-tête HSTS manquant",
		severity:         "MEDIUM",
		cvss:             4.8,
		category:         "Transport Security",
		cwe:              "CWE-319",
		description:      "La cible sert du HTTPS mais n'envoie pas l'en-tête Strict-Transport-Security. Un attaquant en position réseau peut tenter un déclassement vers HTTP en clair (SSLStrip).",
		impact:           "Interception de trafic par attaque de l'intercepteur (MitM).",
		remediationTitle: "Activer HSTS",
		remediationSteps: []string{
			"Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			"Rediriger systématiquement HTTP vers HTTPS avant d'activer preload.",
		},
	},
	{
		header:           "x-content-type-options",
		title:            "Absence de protection contre le MIME sniffing",
		severity:         "LOW",
		cvss:             3.1,
		category:         "Headers Security",
		cwe:              "CWE-430",
		description:      "L'en-tête X-Content-Type-Options n'est pas défini. Certains navigateurs peuvent alors réinterpréter le type MIME d'une ressource et exécuter un contenu téléversé comme du script.",
		impact:           "Exécution de contenu téléversé interprété comme script actif.",
		remediationTitle: "Forcer le type MIME déclaré",
		remediationSteps: []string{
			"Ajouter : X-Content-Type-Options: nosniff",
		},
	},
	{
		header:           "referrer-policy",
		title:            "Politique de référent non définie",
		severity:         "LOW",
		cvss:             3.1,
		category:         "Information Disclosure",
		cwe:              "CWE-200",
		description:      "Sans en-tête Referrer-Policy, l'URL complète de la page courante — jetons inclus — peut être transmise aux domaines tiers lors de la navigation sortante.",
		impact:           "Fuite d'identifiants ou de jetons présents dans les URL vers des tiers.",
		remediationTitle: "Restreindre l'envoi du référent",
		remediationSteps: []string{
			"Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
		},
	},
	{
		header:           "permissions-policy",
		title:            "Permissions-Policy absent",
		severity:         "LOW",
		cvss:             2.6,
		category:         "Headers Security",
		cwe:              "CWE-693",
		description:      "Aucune politique de permissions n'est déclarée : les API sensibles du navigateur (caméra, micro, géolocalisation) restent accessibles aux iframes intégrées.",
		impact:           "Accès non maîtrisé aux périphériques de l'utilisateur par du contenu tiers embarqué.",
		remediationTitle: "Déclarer une Permissions-Policy restrictive",
		remediationSteps: []string{
			"Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()",
		},
	},
}

// run applique l'ensemble des règles d'audit et retourne les découvertes
// triées par criticité décroissante.
func (a auditContext) run() []model.Finding {
	findings := []model.Finding{}

	for _, check := range missingHeaderChecks {
		if check.requiresHTTPS && !a.isHTTPS {
			continue
		}
		if a.headers[check.header] != "" {
			continue
		}
		// frame-ancestors dans la CSP couvre le besoin anti-clickjacking.
		findings = append(findings, a.finding(check.header, model.Finding{
			Title:             check.title,
			Severity:          check.severity,
			CVSS:              check.cvss,
			Confidence:        100,
			Status:            "VALIDATED",
			AffectedComponent: "En-tête HTTP: " + check.header,
			Category:          check.category,
			CWE:               check.cwe,
			Description:       fmt.Sprintf("%s (cible : %s)", check.description, a.domain),
			Impact:            check.impact,
			RemediationTitle:  check.remediationTitle,
			RemediationSteps:  check.remediationSteps,
			Evidence: model.Evidence{
				Request:  a.requestTrace(http.MethodGet),
				Response: a.responseTrace(fmt.Sprintf("(%s absent)", check.header)),
			},
		}))
	}

	if f, ok := a.checkClickjacking(); ok {
		findings = append(findings, f)
	}
	if f, ok := a.checkBannerLeak(); ok {
		findings = append(findings, f)
	}
	if f, ok := a.checkTrace(); ok {
		findings = append(findings, f)
	}
	if f, ok := a.checkCORS(); ok {
		findings = append(findings, f)
	}
	if f, ok := a.checkPlaintextTransport(); ok {
		findings = append(findings, f)
	}
	findings = append(findings, a.checkCookies()...)

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].CVSS > findings[j].CVSS })
	for i := range findings {
		findings[i].SQLiteRow = i + 1
	}
	return findings
}

// finding complète une découverte avec les champs dérivés du contexte.
func (a auditContext) finding(check string, f model.Finding) model.Finding {
	sig := signature(a.domain, check)
	f.ID = "SEC-" + strings.ToUpper(check) + "-" + sig[:8]
	f.Signature = sig
	f.Evidence.AuthContext = "Inspection passive non authentifiée"
	f.Evidence.RoundtripMs = a.latencyMs
	f.Evidence.NonDestructiveProof = true
	return f
}

func (a auditContext) requestTrace(method string) string {
	return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s\nUser-Agent: %s",
		method, orSlash(a.target.Path), a.domain, userAgent)
}

func (a auditContext) responseTrace(note string) string {
	keys := make([]string, 0, len(a.headers))
	for key := range a.headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 8 {
		keys = keys[:8]
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %s\n", a.statusText)
	for _, key := range keys {
		fmt.Fprintf(&builder, "%s: %s\n", key, a.headers[key])
	}
	builder.WriteString(note)
	return builder.String()
}

func (a auditContext) checkClickjacking() (model.Finding, bool) {
	csp := a.headers["content-security-policy"]
	if a.headers["x-frame-options"] != "" || strings.Contains(csp, "frame-ancestors") {
		return model.Finding{}, false
	}
	return a.finding("clickjacking", model.Finding{
		Title:             "Absence de protection anti-clickjacking",
		Severity:          "MEDIUM",
		CVSS:              4.3,
		Confidence:        95,
		Status:            "VALIDATED",
		AffectedComponent: "En-tête HTTP: X-Frame-Options / CSP frame-ancestors",
		Category:          "UI Redressing",
		CWE:               "CWE-1021",
		Description:       fmt.Sprintf("L'application %s ne définit ni X-Frame-Options ni la directive CSP frame-ancestors. Elle peut être intégrée dans une iframe transparente sur un domaine malveillant.", a.domain),
		Impact:            "Détournement de clics forçant des actions non intentionnelles de l'utilisateur authentifié.",
		RemediationTitle:  "Interdire l'intégration en iframe",
		RemediationSteps: []string{
			"Ajouter : Content-Security-Policy: frame-ancestors 'none'",
			"Conserver X-Frame-Options: DENY pour les navigateurs anciens.",
		},
		Evidence: model.Evidence{
			Request:  a.requestTrace(http.MethodGet),
			Response: a.responseTrace("(X-Frame-Options et frame-ancestors absents)"),
		},
	}), true
}

func (a auditContext) checkBannerLeak() (model.Finding, bool) {
	server := a.headers["server"]
	powered := a.headers["x-powered-by"]
	if server == "" && powered == "" {
		return model.Finding{}, false
	}
	leaked := strings.Join(nonEmpty(server, powered), " / ")

	return a.finding("banner", model.Finding{
		Title:             "Divulgation de bannière serveur",
		Severity:          "LOW",
		CVSS:              3.1,
		Confidence:        100,
		Status:            "VALIDATED",
		AffectedComponent: "En-tête HTTP: Server / X-Powered-By",
		Category:          "Information Disclosure",
		CWE:               "CWE-200",
		Description:       fmt.Sprintf("La cible expose la signature logicielle %q, ce qui facilite le ciblage des vulnérabilités connues de cette version.", leaked),
		Impact:            "Reconnaissance automatisée facilitant la sélection d'exploits adaptés à la version exposée.",
		RemediationTitle:  "Masquer la bannière logicielle",
		RemediationSteps: []string{
			"Nginx : server_tokens off;",
			"Apache : ServerTokens Prod et ServerSignature Off",
			"Express : app.disable('x-powered-by')",
		},
		Evidence: model.Evidence{
			Request:  a.requestTrace(http.MethodGet),
			Response: fmt.Sprintf("HTTP/1.1 %s\nServer: %s\nX-Powered-By: %s", a.statusText, orNA(server), orNA(powered)),
		},
	}), true
}

func (a auditContext) checkTrace() (model.Finding, bool) {
	if !a.traceEnabled {
		return model.Finding{}, false
	}
	return a.finding("trace", model.Finding{
		Title:             "Méthode HTTP TRACE activée (Cross-Site Tracing)",
		Severity:          "HIGH",
		CVSS:              7.2,
		Confidence:        90,
		Status:            "VALIDATED",
		AffectedComponent: "Verbe HTTP TRACE",
		Category:          "HTTP Methods",
		CWE:               "CWE-693",
		Description:       "Le serveur annonce la méthode TRACE. Elle réfléchit la requête complète et permet de contourner la protection HttpOnly des cookies de session.",
		Impact:            "Contournement du drapeau HttpOnly et vol de cookies de session.",
		RemediationTitle:  "Désactiver le verbe TRACE",
		RemediationSteps: []string{
			"Nginx : if ($request_method = TRACE) { return 405; }",
			"Apache : TraceEnable Off",
		},
		Evidence: model.Evidence{
			Request:  a.requestTrace(http.MethodOptions),
			Response: fmt.Sprintf("HTTP/1.1 200 OK\nAllow: %s", a.allowedMethods),
		},
	}), true
}

func (a auditContext) checkCORS() (model.Finding, bool) {
	origin := a.headers["access-control-allow-origin"]
	credentials := strings.EqualFold(a.headers["access-control-allow-credentials"], "true")
	if origin != "*" {
		return model.Finding{}, false
	}

	severity, cvss := "MEDIUM", 5.3
	description := "La ressource autorise toute origine (Access-Control-Allow-Origin: *). Toute page tierce peut lire les réponses de cette API."
	if credentials {
		severity, cvss = "HIGH", 7.5
		description = "La ressource combine Access-Control-Allow-Origin: * et Access-Control-Allow-Credentials: true. Cette configuration expose les réponses authentifiées à n'importe quelle origine."
	}

	return a.finding("cors", model.Finding{
		Title:             "Politique CORS permissive",
		Severity:          severity,
		CVSS:              cvss,
		Confidence:        95,
		Status:            "VALIDATED",
		AffectedComponent: "En-tête HTTP: Access-Control-Allow-Origin",
		Category:          "Access Control",
		CWE:               "CWE-942",
		Description:       description,
		Impact:            "Lecture de données applicatives par un site tiers contrôlé par l'attaquant.",
		RemediationTitle:  "Restreindre les origines autorisées",
		RemediationSteps: []string{
			"Remplacer le joker par une liste blanche explicite d'origines de confiance.",
			"Ne jamais combiner Access-Control-Allow-Credentials: true avec une origine joker.",
		},
		Evidence: model.Evidence{
			Request:  a.requestTrace(http.MethodGet),
			Response: fmt.Sprintf("HTTP/1.1 %s\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", a.statusText, origin, orNA(a.headers["access-control-allow-credentials"])),
		},
	}), true
}

func (a auditContext) checkPlaintextTransport() (model.Finding, bool) {
	if a.isHTTPS {
		return model.Finding{}, false
	}
	return a.finding("plaintext", model.Finding{
		Title:             "Transport non chiffré (HTTP en clair)",
		Severity:          "HIGH",
		CVSS:              7.4,
		Confidence:        100,
		Status:            "VALIDATED",
		AffectedComponent: "Couche transport",
		Category:          "Transport Security",
		CWE:               "CWE-319",
		Description:       fmt.Sprintf("La cible %s est servie en HTTP sans chiffrement. Identifiants et cookies transitent en clair sur le réseau.", a.domain),
		Impact:            "Interception et modification du trafic par tout équipement intermédiaire.",
		RemediationTitle:  "Imposer HTTPS",
		RemediationSteps: []string{
			"Déployer un certificat TLS valide et rediriger HTTP vers HTTPS en 301.",
			"Activer ensuite HSTS pour verrouiller le schéma sécurisé.",
		},
		Evidence: model.Evidence{
			Request:  a.requestTrace(http.MethodGet),
			Response: fmt.Sprintf("HTTP/1.1 %s (transport en clair, aucune couche TLS négociée)", a.statusText),
		},
	}), true
}

// checkCookies signale les cookies de session dépourvus d'attributs de
// sécurité.
func (a auditContext) checkCookies() []model.Finding {
	weaknesses := map[string][]string{}

	for _, raw := range a.setCookies {
		parts := strings.Split(raw, ";")
		if len(parts) == 0 {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0])
		if name == "" {
			continue
		}

		lower := strings.ToLower(raw)
		missing := []string{}
		if a.isHTTPS && !strings.Contains(lower, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(lower, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !strings.Contains(lower, "samesite") {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			weaknesses[name] = missing
		}
	}

	if len(weaknesses) == 0 {
		return nil
	}

	names := make([]string, 0, len(weaknesses))
	for name := range weaknesses {
		names = append(names, name)
	}
	sort.Strings(names)

	details := make([]string, 0, len(names))
	for _, name := range names {
		details = append(details, fmt.Sprintf("%s (manque : %s)", name, strings.Join(weaknesses[name], ", ")))
	}

	return []model.Finding{a.finding("cookies", model.Finding{
		Title:             "Cookies dépourvus d'attributs de sécurité",
		Severity:          "MEDIUM",
		CVSS:              5.4,
		Confidence:        100,
		Status:            "VALIDATED",
		AffectedComponent: "En-tête HTTP: Set-Cookie",
		Category:          "Session Management",
		CWE:               "CWE-1004",
		Description:       fmt.Sprintf("%d cookie(s) sont émis sans les attributs de protection attendus : %s.", len(names), strings.Join(details, " ; ")),
		Impact:            "Vol de cookie via XSS ou canal non chiffré, et exposition aux attaques CSRF.",
		RemediationTitle:  "Durcir les attributs des cookies",
		RemediationSteps: []string{
			"Émettre les cookies de session avec Secure; HttpOnly; SameSite=Lax (ou Strict).",
			"Limiter la portée via les attributs Domain et Path.",
		},
		Evidence: model.Evidence{
			Request:  a.requestTrace(http.MethodGet),
			Response: "Set-Cookie: " + strings.Join(a.setCookies, "\nSet-Cookie: "),
		},
	})}
}

func nonEmpty(values ...string) []string {
	out := []string{}
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func orNA(value string) string {
	if value == "" {
		return "N/A"
	}
	return value
}

func orSlash(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
