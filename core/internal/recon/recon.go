// Package recon orchestre la reconnaissance défensive d'une cible :
// résolution DNS, découverte de ports, audit TLS et relevé de bannière. Les
// outils externes sont utilisés quand ils sont disponibles ; sinon le moteur
// bascule sur une implémentation native Go afin que le résultat reste réel.
package recon

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guylainboka/guymacyb/core/internal/scan"
	"github.com/guylainboka/guymacyb/core/internal/toolchain"
)

// defaultPorts est la liste sondée lorsque nmap n'est pas disponible.
var defaultPorts = []int{21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200}

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 25: "smtp", 53: "domain", 80: "http", 110: "pop3",
	143: "imap", 443: "https", 445: "microsoft-ds", 3306: "mysql", 3389: "ms-wbt-server",
	5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
}

// PortResult décrit l'état d'un port TCP sur la cible.
type PortResult struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service"`
	Product string `json:"product,omitempty"`
}

// DNSRecords regroupe les enregistrements résolus pour la cible.
type DNSRecords struct {
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	CNAME       string   `json:"cname,omitempty"`
	MX          []string `json:"mx,omitempty"`
	NameServers []string `json:"nameServers,omitempty"`
	TXT         []string `json:"txt,omitempty"`
}

// Report est le rapport de reconnaissance renvoyé à l'interface.
type Report struct {
	Target                 string           `json:"target"`
	Domain                 string           `json:"domain"`
	PrimaryIP              string           `json:"primaryIp"`
	AllIPs                 []string         `json:"allIps"`
	DNS                    DNSRecords       `json:"dns"`
	ServerBanner           string           `json:"serverBanner"`
	PortAudit              []PortResult     `json:"portAudit"`
	MissingSecurityHeaders []string         `json:"missingSecurityHeaders"`
	TLS                    *TLSAudit        `json:"tls,omitempty"`
	Toolchain              []toolchain.Tool `json:"toolchain"`
	ReconLogs              []string         `json:"reconLogs"`
	CompletedAt            string           `json:"completedAt"`
	DurationMs             int64            `json:"durationMs"`
}

// TLSAudit résume la sortie de sslscan.
type TLSAudit struct {
	Tool              string   `json:"tool"`
	SupportedVersions []string `json:"supportedVersions,omitempty"`
	WeakCiphers       []string `json:"weakCiphers,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

// Engine exécute la suite de reconnaissance.
type Engine struct {
	scanner *scan.Engine
	client  *http.Client
}

// NewEngine construit un moteur de reconnaissance.
func NewEngine(scanner *scan.Engine) *Engine {
	return &Engine{
		scanner: scanner,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// logger accumule la trace d'exécution présentée à l'opérateur.
type logger struct {
	mu    sync.Mutex
	lines []string
}

func (l *logger) addf(tag, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf("[%s] %s", tag, fmt.Sprintf(format, args...)))
}

// Run exécute la reconnaissance complète sur la cible fournie.
func (e *Engine) Run(ctx context.Context, raw string) (*Report, error) {
	started := time.Now()

	target, err := scan.Normalize(raw)
	if err != nil {
		return nil, err
	}
	domain := target.Hostname()

	log := &logger{}
	log.addf("RECON_INIT", "Démarrage de la reconnaissance sur %s", domain)

	records := e.resolveDNS(ctx, domain, log)

	ports := e.scanPorts(ctx, domain, log)

	banner, missingHeaders := e.auditHTTP(ctx, target, log)

	tlsAudit := runSSLScan(ctx, target, log)

	report := &Report{
		Target:                 target.String(),
		Domain:                 domain,
		PrimaryIP:              firstOr(records.IPv4, firstOr(records.IPv6, "")),
		AllIPs:                 append(append([]string{}, records.IPv4...), records.IPv6...),
		DNS:                    records,
		ServerBanner:           banner,
		PortAudit:              ports,
		MissingSecurityHeaders: missingHeaders,
		TLS:                    tlsAudit,
		Toolchain:              toolchain.Inventory(),
		ReconLogs:              log.lines,
		CompletedAt:            time.Now().UTC().Format(time.RFC3339),
		DurationMs:             time.Since(started).Milliseconds(),
	}
	return report, nil
}

// resolveDNS interroge le résolveur système, puis enrichit avec dig lorsque
// l'outil est présent.
func (e *Engine) resolveDNS(ctx context.Context, domain string, log *logger) DNSRecords {
	records := DNSRecords{IPv4: []string{}, IPv6: []string{}}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		log.addf("DNS_FAIL", "Résolution impossible pour %s : %v", domain, err)
		return records
	}
	for _, addr := range addrs {
		if v4 := addr.IP.To4(); v4 != nil {
			records.IPv4 = append(records.IPv4, v4.String())
		} else {
			records.IPv6 = append(records.IPv6, addr.IP.String())
		}
	}
	sort.Strings(records.IPv4)
	sort.Strings(records.IPv6)
	log.addf("DNS_RESOLVE", "Adresses résolues : IPv4=%s IPv6=%s",
		joinOrNone(records.IPv4), joinOrNone(records.IPv6))

	if cname, err := net.DefaultResolver.LookupCNAME(ctx, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, domain) {
			records.CNAME = cname
			log.addf("DNS_CNAME", "Alias canonique : %s", cname)
		}
	}
	if mxs, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			records.MX = append(records.MX, strings.TrimSuffix(mx.Host, "."))
		}
		if len(records.MX) > 0 {
			log.addf("DNS_MX", "Serveurs de messagerie : %s", strings.Join(records.MX, ", "))
		}
	}
	if nss, err := net.DefaultResolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			records.NameServers = append(records.NameServers, strings.TrimSuffix(ns.Host, "."))
		}
		if len(records.NameServers) > 0 {
			log.addf("DNS_NS", "Serveurs de noms : %s", strings.Join(records.NameServers, ", "))
		}
	}
	if txts, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil {
		records.TXT = txts
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=spf1") {
				log.addf("DNS_SPF", "Politique SPF publiée : %s", txt)
			}
		}
	}

	return records
}

// scanPorts délègue à nmap si disponible, sinon effectue un balayage TCP
// connect natif.
func (e *Engine) scanPorts(ctx context.Context, host string, log *logger) []PortResult {
	if toolchain.Available(toolchain.Nmap) {
		results, err := nmapScan(ctx, host)
		if err == nil {
			log.addf("PORT_SCAN", "nmap : %d port(s) qualifiés", len(results))
			for _, result := range results {
				log.addf("PORT_PROBE", "Port %d/tcp (%s) : %s", result.Port, result.Service, result.Status)
			}
			return results
		}
		log.addf("PORT_WARN", "nmap indisponible pour ce scan (%v), bascule sur le sondage natif", err)
	} else {
		log.addf("PORT_INFO", "nmap absent du système, sondage TCP natif utilisé")
	}

	results := nativePortScan(ctx, host, defaultPorts)
	for _, result := range results {
		log.addf("PORT_PROBE", "Port %d/tcp (%s) : %s", result.Port, result.Service, result.Status)
	}
	return results
}

// auditHTTP relève la bannière et les en-têtes de durcissement manquants.
func (e *Engine) auditHTTP(ctx context.Context, target *url.URL, log *logger) (string, []string) {
	required := []struct{ header, label string }{
		{"content-security-policy", "Content-Security-Policy (CSP)"},
		{"strict-transport-security", "Strict-Transport-Security (HSTS)"},
		{"x-frame-options", "X-Frame-Options"},
		{"x-content-type-options", "X-Content-Type-Options"},
		{"referrer-policy", "Referrer-Policy"},
		{"permissions-policy", "Permissions-Policy"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
	if err != nil {
		log.addf("BANNER_FAIL", "Requête impossible : %v", err)
		return "Indisponible", nil
	}
	req.Header.Set("User-Agent", "GuymaCyb-Recon/2.0")

	res, err := e.client.Do(req)
	if err != nil {
		log.addf("BANNER_FAIL", "Relevé de bannière impossible : %v", err)
		return "Indisponible", nil
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	banner := res.Header.Get("Server")
	if banner == "" {
		banner = res.Header.Get("X-Powered-By")
	}
	if banner == "" {
		banner = "Non divulgué"
	}
	log.addf("BANNER_GRAB", "Empreinte serveur : %s", banner)

	missing := []string{}
	for _, item := range required {
		if res.Header.Get(item.header) == "" {
			missing = append(missing, item.label)
		}
	}
	log.addf("AUDIT_HEADERS", "%d en-tête(s) de durcissement manquant(s)", len(missing))

	return banner, missing
}

// --- nmap ---

type nmapRun struct {
	Hosts []struct {
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// nmapScan exécute un balayage TCP connect non privilégié et analyse la
// sortie XML.
func nmapScan(ctx context.Context, host string) ([]PortResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// -sT : connect scan (aucun privilège root requis)
	// -Pn : ne pas présumer que la cible répond au ping
	// -T4 : cadence soutenue mais non agressive
	out, err := toolchain.Run(ctx, toolchain.Nmap,
		"-sT", "-Pn", "-T4", "--top-ports", "50", "-oX", "-", host)
	if err != nil {
		return nil, err
	}

	var run nmapRun
	if err := xml.Unmarshal([]byte(out), &run); err != nil {
		return nil, fmt.Errorf("analyse de la sortie nmap: %w", err)
	}

	results := []PortResult{}
	for _, host := range run.Hosts {
		for _, port := range host.Ports.Ports {
			if port.Protocol != "tcp" {
				continue
			}
			service := port.Service.Name
			if service == "" {
				service = serviceFor(port.PortID)
			}
			product := strings.TrimSpace(port.Service.Product + " " + port.Service.Version)
			results = append(results, PortResult{
				Port:    port.PortID,
				Status:  strings.ToUpper(port.State.State),
				Service: service,
				Product: product,
			})
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, nil
}

// nativePortScan effectue un balayage TCP connect en Go pur, borné en
// parallélisme pour rester non intrusif.
func nativePortScan(ctx context.Context, host string, ports []int) []PortResult {
	const workers = 8
	const perPortTimeout = 2 * time.Second

	jobs := make(chan int)
	results := make([]PortResult, 0, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: perPortTimeout}
			for port := range jobs {
				status := "FILTERED"
				address := net.JoinHostPort(host, strconv.Itoa(port))
				conn, err := dialer.DialContext(ctx, "tcp", address)
				switch {
				case err == nil:
					status = "OPEN"
					conn.Close()
				case isRefused(err):
					status = "CLOSED"
				}
				mu.Lock()
				results = append(results, PortResult{Port: port, Status: status, Service: serviceFor(port)})
				mu.Unlock()
			}
		}()
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

func isRefused(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

func serviceFor(port int) string {
	if name, ok := serviceNames[port]; ok {
		return name
	}
	return "unknown"
}

// --- sslscan ---

var weakCipherMarkers = []string{"RC4", "DES", "NULL", "MD5", "EXPORT", "anon"}

// runSSLScan qualifie les suites TLS supportées lorsque sslscan est présent.
func runSSLScan(ctx context.Context, target *url.URL, log *logger) *TLSAudit {
	if target.Scheme != "https" {
		return nil
	}
	if !toolchain.Available(toolchain.SSLScan) {
		log.addf("TLS_INFO", "sslscan absent du système, audit TLS limité à la poignée de main native")
		return nil
	}

	port := target.Port()
	if port == "" {
		port = "443"
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	out, err := toolchain.Run(ctx, toolchain.SSLScan, "--no-colour", net.JoinHostPort(target.Hostname(), port))
	if err != nil && strings.TrimSpace(out) == "" {
		log.addf("TLS_WARN", "sslscan a échoué : %v", err)
		return nil
	}

	audit := parseSSLScan(out)
	log.addf("TLS_AUDIT", "sslscan : %d protocole(s) actif(s), %d suite(s) faible(s)",
		len(audit.SupportedVersions), len(audit.WeakCiphers))
	return audit
}

// parseSSLScan extrait les protocoles activés et les suites faibles de la
// sortie texte de sslscan.
func parseSSLScan(out string) *TLSAudit {
	audit := &TLSAudit{Tool: "sslscan"}
	seen := map[string]bool{}

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Lignes de protocole : "TLSv1.2   enabled"
		if strings.HasPrefix(fields[0], "TLSv") || strings.HasPrefix(fields[0], "SSLv") {
			if fields[1] != "enabled" {
				continue
			}
			audit.SupportedVersions = append(audit.SupportedVersions, fields[0])
			switch fields[0] {
			case "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1":
				audit.Notes = append(audit.Notes,
					fmt.Sprintf("Protocole obsolète encore activé : %s", fields[0]))
			}
			continue
		}

		// Lignes de suite : "Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256"
		if fields[0] != "Accepted" && fields[0] != "Preferred" {
			continue
		}
		for _, field := range fields[1:] {
			if !strings.Contains(field, "-") && !strings.HasPrefix(field, "TLS_") {
				continue
			}
			for _, marker := range weakCipherMarkers {
				if strings.Contains(field, marker) && !seen[field] {
					seen[field] = true
					audit.WeakCiphers = append(audit.WeakCiphers, field)
				}
			}
			break
		}
	}

	return audit
}

func firstOr(values []string, fallback string) string {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "aucune"
	}
	return strings.Join(values, ", ")
}
