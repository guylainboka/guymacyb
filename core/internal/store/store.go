// Package store encapsule la persistance SQLite locale de Guyma Cyb. Le pilote
// utilisé est une implémentation Go pure : aucun cgo n'est requis, ce qui
// permet la compilation croisée vers Windows.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"

	"github.com/guylainboka/guymacyb/core/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS targets (
  id              TEXT PRIMARY KEY,
  url             TEXT NOT NULL,
  domain          TEXT NOT NULL,
  scope           TEXT NOT NULL,
  operator_id     TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  last_scanned_at TEXT NOT NULL,
  status          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id                TEXT PRIMARY KEY,
  target_id         TEXT NOT NULL,
  url               TEXT NOT NULL,
  scan_type         TEXT NOT NULL,
  cvss_score        REAL NOT NULL,
  risk_level        TEXT NOT NULL,
  duration_ms       INTEGER NOT NULL,
  endpoints_count   INTEGER NOT NULL,
  technologies_json TEXT,
  created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
  id          TEXT PRIMARY KEY,
  scan_id     TEXT NOT NULL,
  path        TEXT NOT NULL,
  method      TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  status_text TEXT NOT NULL,
  type        TEXT NOT NULL,
  note        TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id                     TEXT PRIMARY KEY,
  scan_id                TEXT NOT NULL,
  target_url             TEXT NOT NULL,
  title                  TEXT NOT NULL,
  severity               TEXT NOT NULL,
  cvss                   REAL NOT NULL,
  confidence             INTEGER NOT NULL,
  status                 TEXT NOT NULL,
  affected_component     TEXT NOT NULL,
  category               TEXT NOT NULL,
  cwe                    TEXT NOT NULL,
  description            TEXT NOT NULL,
  evidence_request       TEXT NOT NULL,
  evidence_response      TEXT NOT NULL,
  impact                 TEXT NOT NULL,
  remediation_title      TEXT NOT NULL,
  remediation_steps_json TEXT NOT NULL,
  signature              TEXT NOT NULL,
  created_at             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id            TEXT PRIMARY KEY,
  operator_id   TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  message       TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_target    ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan  ON endpoints(scan_id);
`

// Store est un accès concurrent-sûr à la base SQLite locale.
type Store struct {
	db   *sql.DB
	path string
	mu   sync.Mutex
}

// Open ouvre (ou crée) la base au chemin indiqué et applique le schéma.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ouverture de la base: %w", err)
	}
	// Le pilote pur Go ne supporte pas les écritures concurrentes sur une même
	// connexion ; une connexion unique évite les erreurs "database is locked".
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connexion à la base: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("application du schéma: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close ferme la base.
func (s *Store) Close() error { return s.db.Close() }

// Path retourne le chemin du fichier SQLite.
func (s *Store) Path() string { return s.path }

// Counts retourne le nombre de cibles, scans et découvertes enregistrés.
func (s *Store) Counts() (targets, scans, findings int, err error) {
	row := s.db.QueryRow(`
		SELECT (SELECT COUNT(*) FROM targets),
		       (SELECT COUNT(*) FROM scans),
		       (SELECT COUNT(*) FROM findings)`)
	err = row.Scan(&targets, &scans, &findings)
	return
}

// SaveScan persiste de manière atomique une cible, son scan, ses endpoints et
// ses découvertes.
func (s *Store) SaveScan(res *model.ScanResult, scope, operatorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("début de transaction: %w", err)
	}
	defer tx.Rollback()

	targetID := "target-" + res.Domain
	if _, err := tx.Exec(`
		INSERT INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), 'COMPLETED')
		ON CONFLICT(id) DO UPDATE SET
			url = excluded.url,
			scope = excluded.scope,
			operator_id = excluded.operator_id,
			last_scanned_at = datetime('now'),
			status = 'COMPLETED'`,
		targetID, res.TargetURL, res.Domain, scope, operatorID); err != nil {
		return fmt.Errorf("enregistrement de la cible: %w", err)
	}

	techJSON, err := json.Marshal(res.Technologies)
	if err != nil {
		return fmt.Errorf("sérialisation des technologies: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		res.ScanID, targetID, res.TargetURL, "PASSIVE_AND_SEMI_ACTIVE", res.CVSSScore,
		res.OverallRisk, res.DurationMs, len(res.Endpoints), string(techJSON)); err != nil {
		return fmt.Errorf("enregistrement du scan: %w", err)
	}

	for _, ep := range res.Endpoints {
		if _, err := tx.Exec(`
			INSERT OR REPLACE INTO endpoints (id, scan_id, path, method, status_code, status_text, type, note, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			res.ScanID+"-"+ep.ID, res.ScanID, ep.Path, ep.Method, ep.Status, ep.StatusText, ep.Type, ep.Note); err != nil {
			return fmt.Errorf("enregistrement de l'endpoint %s: %w", ep.Path, err)
		}
	}

	for _, f := range res.Findings {
		if err := insertFinding(tx, res.ScanID, res.TargetURL, f); err != nil {
			return err
		}
	}

	return tx.Commit()
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertFinding(e execer, scanID, targetURL string, f model.Finding) error {
	steps, err := json.Marshal(f.RemediationSteps)
	if err != nil {
		return fmt.Errorf("sérialisation de la remédiation: %w", err)
	}
	if _, err := e.Exec(`
		INSERT OR REPLACE INTO findings (
			id, scan_id, target_url, title, severity, cvss, confidence, status,
			affected_component, category, cwe, description, evidence_request,
			evidence_response, impact, remediation_title, remediation_steps_json,
			signature, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		f.ID, scanID, targetURL, f.Title, f.Severity, f.CVSS, f.Confidence, f.Status,
		f.AffectedComponent, f.Category, f.CWE, f.Description, f.Evidence.Request,
		f.Evidence.Response, f.Impact, f.RemediationTitle, string(steps), f.Signature); err != nil {
		return fmt.Errorf("enregistrement de la découverte %s: %w", f.ID, err)
	}
	return nil
}

// SaveFinding persiste une découverte isolée (laboratoire de simulation).
func (s *Store) SaveFinding(scanID, targetURL string, f model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return insertFinding(s.db, scanID, targetURL, f)
}

// SaveLabSuite enregistre une cible virtuelle de laboratoire, son scan et
// l'ensemble des découvertes associées.
func (s *Store) SaveLabSuite(scanID, targetURL, domain, operatorID string, cvss float64, findings []model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("début de transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		INSERT INTO targets (id, url, domain, scope, operator_id, created_at, last_scanned_at, status)
		VALUES (?, ?, ?, 'wildcard', ?, datetime('now'), datetime('now'), 'COMPLETED')
		ON CONFLICT(id) DO UPDATE SET last_scanned_at = datetime('now'), status = 'COMPLETED'`,
		"target-lab-sandbox", targetURL, domain, operatorID); err != nil {
		return fmt.Errorf("enregistrement de la cible de laboratoire: %w", err)
	}

	if _, err := tx.Exec(`
		INSERT INTO scans (id, target_id, url, scan_type, cvss_score, risk_level, duration_ms, endpoints_count, technologies_json, created_at)
		VALUES (?, 'target-lab-sandbox', ?, 'LAB_CYBER_RANGE_SUITE', ?, ?, 0, ?, '[]', datetime('now'))`,
		scanID, targetURL, cvss, model.RiskFromCVSS(cvss), len(findings)); err != nil {
		return fmt.Errorf("enregistrement du scan de laboratoire: %w", err)
	}

	for _, f := range findings {
		if err := insertFinding(tx, scanID, targetURL, f); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// AppendAuditLog journalise un évènement opérateur.
func (s *Store) AppendAuditLog(id, operatorID, eventType, message string, metadata any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta := []byte("{}")
	if metadata != nil {
		encoded, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("sérialisation des métadonnées: %w", err)
		}
		meta = encoded
	}
	if _, err := s.db.Exec(`
		INSERT OR REPLACE INTO audit_logs (id, operator_id, event_type, message, metadata_json, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`,
		id, operatorID, eventType, message, string(meta)); err != nil {
		return fmt.Errorf("journalisation de l'évènement: %w", err)
	}
	return nil
}

// ListTargets retourne l'historique des cibles avec leur risque agrégé.
func (s *Store) ListTargets() ([]model.HistoricalTarget, error) {
	rows, err := s.db.Query(`
		SELECT t.id,
		       t.url,
		       t.domain,
		       COALESCE(MAX(s.cvss_score), 0.0) AS score,
		       t.last_scanned_at,
		       (SELECT COUNT(*) FROM findings f
		          JOIN scans sc ON f.scan_id = sc.id
		         WHERE sc.target_id = t.id) AS finding_count
		FROM targets t
		LEFT JOIN scans s ON t.id = s.target_id
		GROUP BY t.id
		ORDER BY t.last_scanned_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("lecture des cibles: %w", err)
	}
	defer rows.Close()

	targets := []model.HistoricalTarget{}
	for rows.Next() {
		var t model.HistoricalTarget
		if err := rows.Scan(&t.ID, &t.URL, &t.Domain, &t.Score, &t.Timestamp, &t.FindingCount); err != nil {
			return nil, fmt.Errorf("lecture d'une cible: %w", err)
		}
		t.Risk = model.RiskFromCVSS(t.Score)
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// ListFindings retourne les découvertes les plus critiques, éventuellement
// filtrées par fragment d'URL.
func (s *Store) ListFindings(urlFilter string, limit int) ([]model.Finding, error) {
	query := `
		SELECT id, title, severity, cvss, confidence, status, affected_component,
		       category, cwe, description, evidence_request, evidence_response,
		       impact, remediation_title, remediation_steps_json, signature
		FROM findings`
	args := []any{}
	if urlFilter != "" {
		query += ` WHERE target_url LIKE ?`
		args = append(args, "%"+urlFilter+"%")
	}
	query += ` ORDER BY cvss DESC, created_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des découvertes: %w", err)
	}
	defer rows.Close()

	findings := []model.Finding{}
	for rows.Next() {
		var f model.Finding
		var stepsJSON string
		if err := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.CVSS, &f.Confidence, &f.Status,
			&f.AffectedComponent, &f.Category, &f.CWE, &f.Description, &f.Evidence.Request,
			&f.Evidence.Response, &f.Impact, &f.RemediationTitle, &stepsJSON, &f.Signature); err != nil {
			return nil, fmt.Errorf("lecture d'une découverte: %w", err)
		}
		if err := json.Unmarshal([]byte(stepsJSON), &f.RemediationSteps); err != nil {
			f.RemediationSteps = []string{}
		}
		f.Evidence.AuthContext = "Audit de sécurité enregistré"
		f.Evidence.NonDestructiveProof = true
		f.SQLiteRow = len(findings) + 1
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
