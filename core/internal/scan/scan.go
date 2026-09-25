// Package scan implémente l'audit passif et semi-actif de la surface web
// d'une cible : en-têtes de sécurité, posture TLS, cartographie des routes et
// empreinte technologique.
package scan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/guylainboka/guymacyb/core/internal/model"
	"github.com/guylainboka/guymacyb/core/internal/toolchain"
)

const (
	userAgent      = "GuymaCyb-Security-Auditor/2.0 (+audit defensif non destructif)"
	maxBodyBytes   = 2 << 20 // 2 MiB : suffisant pour la cartographie, borne la mémoire.
	requestTimeout = 12 * time.Second
)

// Engine exécute les audits web. Le client HTTP est réutilisé entre les scans.
type Engine struct {
	client *http.Client
}

// NewEngine construit un moteur d'audit.
func NewEngine() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("trop de redirections")
				}
				return nil
			},
		},
	}
}

// Connectivity est le résultat d'un test de joignabilité de la cible.
type Connectivity struct {
	Success      bool   `json:"success"`
	StatusCode   int    `json:"statusCode,omitempty"`
	LatencyMs    int64  `json:"latencyMs"`
	ServerBanner string `json:"serverBanner,omitempty"`
	TLSVersion   string `json:"tlsVersion,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Normalize complète l'URL fournie par l'opérateur avec un schéma par défaut.
func Normalize(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("URL manquante")
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "https://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("URL invalide: %w", err)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("URL invalide: nom d'hôte absent")
	}
	return parsed, nil
}

// CheckConnectivity vérifie qu'une cible répond et relève sa bannière.
func (e *Engine) CheckConnectivity(ctx context.Context, raw string) Connectivity {
	start := time.Now()

	target, err := Normalize(raw)
	if err != nil {
		return Connectivity{LatencyMs: time.Since(start).Milliseconds(), Error: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
	if err != nil {
		return Connectivity{LatencyMs: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	req.Header.Set("User-Agent", userAgent)

	res, err := e.client.Do(req)
	if err != nil {
		return Connectivity{
			LatencyMs: time.Since(start).Milliseconds(),
			Error:     fmt.Sprintf("Impossible de joindre la cible: %v", err),
		}
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	banner := firstNonEmpty(res.Header.Get("Server"), res.Header.Get("X-Powered-By"), "Non divulgué")
	tlsVersion := "Non chiffré (HTTP brut)"
	if res.TLS != nil {
		tlsVersion = tlsVersionName(res.TLS.Version)
	}

	return Connectivity{
		Success:      true,
		StatusCode:   res.StatusCode,
		LatencyMs:    time.Since(start).Milliseconds(),
		ServerBanner: banner,
		TLSVersion:   tlsVersion,
	}
}

// Analyze réalise l'audit complet d'une cible.
func (e *Engine) Analyze(ctx context.Context, raw string) (*model.ScanResult, error) {
	started := time.Now()

	target, err := Normalize(raw)
	if err != nil {
		return nil, err
	}
	domain := target.Hostname()
	isHTTPS := target.Scheme == "https"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	reqStart := time.Now()
	res, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("échec de connexion vers %s: %w", target, err)
	}
	latency := time.Since(reqStart).Milliseconds()
	body, readErr := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	res.Body.Close()
	if readErr != nil {
		body = nil
	}
	bodyText := string(body)

	headers := flattenHeaders(res.Header)
	allowedMethods, traceEnabled := e.probeMethods(ctx, target)
	paths := e.discoverPaths(ctx, target, bodyText)
	technologies := e.detectTechnologies(ctx, target, headers, bodyText)
	tlsInfo := inspectTLS(ctx, target, headers)

	audit := auditContext{
		domain:         domain,
		target:         target,
		isHTTPS:        isHTTPS,
		headers:        headers,
		setCookies:     res.Header.Values("Set-Cookie"),
		statusCode:     res.StatusCode,
		statusText:     res.Status,
		latencyMs:      latency,
		allowedMethods: allowedMethods,
		traceEnabled:   traceEnabled,
	}
	findings := audit.run()

	endpoints := buildEndpoints(paths, res.StatusCode, res.Status, len(findings) > 0)

	maxCVSS := 0.0
	for _, f := range findings {
		if f.CVSS > maxCVSS {
			maxCVSS = f.CVSS
		}
	}

	apiCount := 0
	for _, ep := range endpoints {
		if ep.Type == "api" {
			apiCount++
		}
	}

	return &model.ScanResult{
		ScanID:       fmt.Sprintf("scan-%d", time.Now().UnixNano()/int64(time.Millisecond)),
		TargetURL:    target.String(),
		Domain:       domain,
		StatusCode:   res.StatusCode,
		StatusText:   res.Status,
		LatencyMs:    latency,
		Headers:      headers,
		TLS:          tlsInfo,
		Technologies: technologies,
		Endpoints:    endpoints,
		Findings:     findings,
		OverallRisk:  model.RiskFromCVSS(maxCVSS),
		CVSSScore:    round1(maxCVSS),
		Summary: model.ScanSummary{
			EndpointsCount:    len(endpoints),
			APIRoutesCount:    apiCount,
			TechnologiesCount: len(technologies),
			AnomaliesCount:    len(findings),
		},
		DurationMs: time.Since(started).Milliseconds(),
	}, nil
}

// probeMethods interroge les verbes HTTP autorisés via une requête OPTIONS.
func (e *Engine) probeMethods(ctx context.Context, target *url.URL) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, target.String(), nil)
	if err != nil {
		return "GET, HEAD", false
	}
	req.Header.Set("User-Agent", userAgent)

	res, err := e.client.Do(req)
	if err != nil {
		return "GET, HEAD", false
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	allow := res.Header.Get("Allow")
	if allow == "" {
		return "GET, HEAD", false
	}
	return allow, strings.Contains(strings.ToUpper(allow), "TRACE")
}

var (
	hrefPattern  = regexp.MustCompile(`(?i)href=["'](/[a-zA-Z0-9_\-./]*)["']`)
	srcPattern   = regexp.MustCompile(`(?i)src=["'](/[a-zA-Z0-9_\-./]*)["']`)
	apiPattern   = regexp.MustCompile(`["'](/api/[a-zA-Z0-9_\-./]+)["']`)
	disallowLine = regexp.MustCompile(`(?i)Disallow:\s*(/\S*)`)
)

// discoverPaths cartographie les routes à partir du HTML et de robots.txt.
func (e *Engine) discoverPaths(ctx context.Context, target *url.URL, bodyText string) []string {
	unique := map[string]struct{}{"/": {}}

	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || strings.HasPrefix(path, "//") || len(path) > 80 {
			return
		}
		unique[path] = struct{}{}
	}

	for _, pattern := range []*regexp.Regexp{hrefPattern, srcPattern, apiPattern} {
		for _, match := range pattern.FindAllStringSubmatch(bodyText, -1) {
			add(match[1])
		}
	}

	if robots := e.fetchText(ctx, target, "/robots.txt"); robots != "" {
		add("/robots.txt")
		for _, match := range disallowLine.FindAllStringSubmatch(robots, -1) {
			add(match[1])
		}
	}
	if sitemap := e.fetchText(ctx, target, "/sitemap.xml"); sitemap != "" {
		add("/sitemap.xml")
	}

	paths := make([]string, 0, len(unique))
	for path := range unique {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// fetchText récupère une ressource texte annexe ; l'absence n'est pas une erreur.
func (e *Engine) fetchText(ctx context.Context, target *url.URL, path string) string {
	ref, err := target.Parse(path)
	if err != nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.String(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)

	res, err := e.client.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return ""
	}
	content, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if err != nil {
		return ""
	}
	return string(content)
}

// detectTechnologies combine l'analyse des en-têtes et, si l'outil est
// disponible, l'empreinte produite par whatweb.
func (e *Engine) detectTechnologies(ctx context.Context, target *url.URL, headers map[string]string, bodyText string) []string {
	unique := map[string]struct{}{}
	add := func(tech string) {
		if tech = strings.TrimSpace(tech); tech != "" {
			unique[tech] = struct{}{}
		}
	}

	server := headers["server"]
	add(server)
	add(headers["x-powered-by"])
	add(headers["x-aspnet-version"])

	lowerBody := strings.ToLower(bodyText)
	markers := map[string]string{
		"wp-content":  "WordPress",
		"__next":      "Next.js",
		"__nuxt":      "Nuxt.js",
		"ng-version":  "Angular",
		"data-svelte": "Svelte",
	}
	for marker, tech := range markers {
		if strings.Contains(lowerBody, marker) {
			add(tech)
		}
	}
	lowerServer := strings.ToLower(server)
	for marker, tech := range map[string]string{
		"nginx":      "Nginx",
		"apache":     "Apache HTTPD",
		"cloudflare": "Cloudflare Edge CDN",
		"iis":        "Microsoft IIS",
		"caddy":      "Caddy",
	} {
		if strings.Contains(lowerServer, marker) {
			add(tech)
		}
	}
	if target.Scheme == "https" {
		add("TLS")
	}

	for _, tech := range whatwebTechnologies(ctx, target) {
		add(tech)
	}

	if len(unique) == 0 {
		add("HTTP/1.1 Standard Stack")
	}

	technologies := make([]string, 0, len(unique))
	for tech := range unique {
		technologies = append(technologies, tech)
	}
	sort.Strings(technologies)
	return technologies
}

var whatwebPlugin = regexp.MustCompile(`([A-Za-z0-9_\-]+)(?:\[[^\]]*\])?`)

// whatwebTechnologies exécute whatweb si présent et extrait les plugins
// détectés. L'absence de l'outil dégrade la détection sans la casser.
func whatwebTechnologies(ctx context.Context, target *url.URL) []string {
	if !toolchain.Available(toolchain.WhatWeb) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	out, err := toolchain.Run(ctx, toolchain.WhatWeb, "--color=never", "--no-errors", "-a", "1", target.String())
	if err != nil && out == "" {
		return nil
	}

	// Format : "http://cible [200 OK] Plugin1[detail], Plugin2, Country[FR]"
	idx := strings.Index(out, "]")
	if idx == -1 {
		return nil
	}
	ignored := map[string]bool{"Country": true, "IP": true, "RedirectLocation": true, "UncommonHeaders": true}

	technologies := []string{}
	for _, part := range strings.Split(out[idx+1:], ",") {
		match := whatwebPlugin.FindStringSubmatch(strings.TrimSpace(part))
		if match == nil {
			continue
		}
		name := match[1]
		if name == "" || ignored[name] {
			continue
		}
		technologies = append(technologies, name)
	}
	return technologies
}

// inspectTLS réalise une vraie poignée de main TLS pour qualifier le transport.
func inspectTLS(ctx context.Context, target *url.URL, headers map[string]string) model.TLSInfo {
	if target.Scheme != "https" {
		return model.TLSInfo{
			Protocol: "HTTP en clair",
			IsHTTPS:  false,
			Grade:    "F",
			Details:  "Trafic non chiffré, vulnérable à l'interception réseau.",
			Warnings: []string{"La cible n'utilise pas HTTPS."},
		}
	}

	port := target.Port()
	if port == "" {
		port = "443"
	}

	dialer := &tls.Dialer{Config: &tls.Config{ServerName: target.Hostname(), MinVersion: tls.VersionTLS10}}
	conn, err := dialer.DialContext(ctx, "tcp", target.Hostname()+":"+port)
	if err != nil {
		return model.TLSInfo{
			Protocol: "TLS",
			IsHTTPS:  true,
			Grade:    "Indéterminé",
			Details:  fmt.Sprintf("Poignée de main TLS impossible: %v", err),
		}
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	info := model.TLSInfo{
		Protocol:    tlsVersionName(state.Version),
		IsHTTPS:     true,
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Details:     "Chiffrement de transport actif.",
	}

	warnings := []string{}
	if state.Version < tls.VersionTLS12 {
		warnings = append(warnings, "Version TLS obsolète (< TLS 1.2).")
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Issuer = cert.Issuer.CommonName
		info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		remaining := time.Until(cert.NotAfter)
		switch {
		case remaining <= 0:
			warnings = append(warnings, "Certificat expiré.")
		case remaining < 21*24*time.Hour:
			warnings = append(warnings, fmt.Sprintf("Certificat expirant dans %d jours.", int(remaining.Hours()/24)))
		}
	}
	info.Warnings = warnings

	switch {
	case len(warnings) > 0:
		info.Grade = "C"
	case headers["strict-transport-security"] != "":
		info.Grade = "A+"
	default:
		info.Grade = "B"
	}
	return info
}

func buildEndpoints(paths []string, rootStatus int, rootStatusText string, hasFindings bool) []model.Endpoint {
	endpoints := make([]model.Endpoint, 0, len(paths))
	for i, path := range paths {
		lower := strings.ToLower(path)
		isAPI := strings.Contains(lower, "/api") || strings.HasSuffix(lower, ".json")
		isAuth := strings.Contains(lower, "login") || strings.Contains(lower, "auth") || strings.Contains(lower, "signin")
		isAdmin := strings.Contains(lower, "admin") || strings.Contains(lower, "dashboard") || strings.Contains(lower, "metrics")

		endpointType := "page"
		switch {
		case path == "/":
			endpointType = "root"
		case isAPI:
			endpointType = "api"
		case isAuth:
			endpointType = "auth"
		case isAdmin:
			endpointType = "admin"
		case strings.HasSuffix(path, "/"):
			endpointType = "folder"
		}

		endpoint := model.Endpoint{
			ID:         fmt.Sprintf("ep-%d", i),
			Path:       path,
			Method:     http.MethodGet,
			Status:     200,
			StatusText: "Découvert",
			Type:       endpointType,
		}
		if path == "/" {
			endpoint.Status = rootStatus
			endpoint.StatusText = rootStatusText
		}
		switch {
		case isAPI:
			endpoint.Note = "Route API"
		case isAdmin:
			endpoint.Note = "Zone restreinte"
		}
		if isAdmin {
			endpoint.HasFinding = true
			endpoint.FindingSeverity = "HIGH"
		} else if isAPI && hasFindings {
			endpoint.HasFinding = true
			endpoint.FindingSeverity = "MEDIUM"
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func flattenHeaders(header http.Header) map[string]string {
	flat := make(map[string]string, len(header))
	for key, values := range header {
		flat[strings.ToLower(key)] = strings.Join(values, ", ")
	}
	return flat
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1 (obsolète)"
	case tls.VersionTLS10:
		return "TLS 1.0 (obsolète)"
	default:
		return "TLS (version inconnue)"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func round1(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}

func signature(domain, check string) string {
	sum := sha256.Sum256([]byte(domain + ":" + check))
	return hex.EncodeToString(sum[:16])
}
