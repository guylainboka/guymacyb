// Package lab expose le catalogue pédagogique de vecteurs d'attaque utilisé par
// le laboratoire de simulation défensive. Le catalogue est embarqué dans le
// binaire : le backend est la source de vérité unique pour cette base de
// connaissances.
package lab

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed vectors.json
var vectorsJSON []byte

// CodeExample illustre la version vulnérable et la version corrigée d'un
// extrait de code pour un vecteur donné.
type CodeExample struct {
	Language   string `json:"language"`
	Vulnerable string `json:"vulnerable"`
	Fixed      string `json:"fixed"`
}

// Vector décrit un vecteur d'attaque du laboratoire avec ses contrôles
// défensifs et sa remédiation.
type Vector struct {
	ID                            string      `json:"id"`
	Name                          string      `json:"name"`
	Category                      string      `json:"category"`
	OWASP                         string      `json:"owasp"`
	CWE                           string      `json:"cwe"`
	Severity                      string      `json:"severity"`
	Difficulty                    string      `json:"difficulty"`
	Description                   string      `json:"description"`
	SafeTestPayload               string      `json:"safeTestPayload"`
	VulnerableResponseSample      string      `json:"vulnerableResponseSample"`
	RemediatedResponseSample      string      `json:"remediatedResponseSample"`
	VulnerableBehaviorExplanation string      `json:"vulnerableBehaviorExplanation"`
	RemediatedBehaviorExplanation string      `json:"remediatedBehaviorExplanation"`
	DefensiveControls             []string    `json:"defensiveControls"`
	RemediationCodeExample        CodeExample `json:"remediationCodeExample"`
}

// CVSS retourne le score CVSS conventionnel associé à la sévérité du vecteur.
func (v Vector) CVSS() float64 {
	switch v.Severity {
	case "CRITICAL":
		return 9.5
	case "HIGH":
		return 8.0
	case "MEDIUM":
		return 5.5
	case "LOW":
		return 3.1
	default:
		return 1.0
	}
}

var catalog []Vector

func init() {
	if err := json.Unmarshal(vectorsJSON, &catalog); err != nil {
		panic(fmt.Sprintf("lab: catalogue de vecteurs invalide: %v", err))
	}
	if len(catalog) == 0 {
		panic("lab: catalogue de vecteurs vide")
	}
}

// All retourne l'intégralité du catalogue.
func All() []Vector {
	out := make([]Vector, len(catalog))
	copy(out, catalog)
	return out
}

// ByID retourne le vecteur portant l'identifiant demandé.
func ByID(id string) (Vector, bool) {
	for _, v := range catalog {
		if v.ID == id {
			return v, true
		}
	}
	return Vector{}, false
}
