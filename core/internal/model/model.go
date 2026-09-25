// Package model contient les structures de données partagées entre le moteur
// de scan, le stockage SQLite et l'API HTTP. Les tags JSON reproduisent le
// contrat attendu par l'interface React.
package model

// Evidence regroupe la preuve non-destructive associée à une découverte.
type Evidence struct {
	Request             string `json:"request"`
	Response            string `json:"response"`
	AuthContext         string `json:"authContext"`
	RoundtripMs         int64  `json:"roundtripMs"`
	NonDestructiveProof bool   `json:"nonDestructiveProof"`
}

// Finding décrit une vulnérabilité ou faiblesse identifiée sur une cible.
type Finding struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	CVSS              float64  `json:"cvss"`
	Confidence        int      `json:"confidence"`
	Status            string   `json:"status"`
	AffectedComponent string   `json:"affectedComponent"`
	Category          string   `json:"category"`
	CWE               string   `json:"cwe"`
	Description       string   `json:"description"`
	Evidence          Evidence `json:"evidence"`
	Impact            string   `json:"impact"`
	RemediationTitle  string   `json:"remediationTitle"`
	RemediationSteps  []string `json:"remediationSteps"`
	Signature         string   `json:"signature"`
	SQLiteRow         int      `json:"sqliteRow"`
}

// Endpoint représente une route découverte lors de la cartographie.
type Endpoint struct {
	ID              string `json:"id"`
	Path            string `json:"path"`
	Method          string `json:"method"`
	Status          int    `json:"status"`
	StatusText      string `json:"statusText"`
	Type            string `json:"type"`
	Note            string `json:"note,omitempty"`
	HasFinding      bool   `json:"hasFinding"`
	FindingSeverity string `json:"findingSeverity,omitempty"`
}

// TLSInfo décrit la posture de chiffrement du transport.
type TLSInfo struct {
	Protocol    string   `json:"protocol"`
	IsHTTPS     bool     `json:"isHttps"`
	Grade       string   `json:"grade"`
	Details     string   `json:"details"`
	CipherSuite string   `json:"cipherSuite,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	NotAfter    string   `json:"notAfter,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// ScanSummary agrège les compteurs affichés dans l'interface.
type ScanSummary struct {
	EndpointsCount    int `json:"endpointsCount"`
	APIRoutesCount    int `json:"apiRoutesCount"`
	TechnologiesCount int `json:"technologiesCount"`
	AnomaliesCount    int `json:"anomaliesCount"`
}

// ScanResult est le rapport complet d'un audit de surface web.
type ScanResult struct {
	ScanID       string            `json:"scanId"`
	TargetURL    string            `json:"targetUrl"`
	Domain       string            `json:"domain"`
	StatusCode   int               `json:"statusCode"`
	StatusText   string            `json:"statusText"`
	LatencyMs    int64             `json:"latencyMs"`
	Headers      map[string]string `json:"headers"`
	TLS          TLSInfo           `json:"tls"`
	Technologies []string          `json:"technologies"`
	Endpoints    []Endpoint        `json:"endpoints"`
	Findings     []Finding         `json:"findings"`
	OverallRisk  string            `json:"overallRisk"`
	CVSSScore    float64           `json:"cvssScore"`
	Summary      ScanSummary       `json:"summary"`
	DurationMs   int64             `json:"durationMs"`
}

// HistoricalTarget est une entrée de l'historique des cibles auditées.
type HistoricalTarget struct {
	ID           string  `json:"id"`
	URL          string  `json:"url"`
	Domain       string  `json:"domain"`
	Risk         string  `json:"risk"`
	Score        float64 `json:"score"`
	Timestamp    string  `json:"timestamp"`
	FindingCount int     `json:"findingCount"`
}

// RiskFromCVSS convertit un score CVSS en niveau de risque agrégé.
func RiskFromCVSS(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MED"
	case score > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}
