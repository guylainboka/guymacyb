// Package toolchain localise et exécute les outils de sécurité externes
// (nmap, sslscan, whatweb, dig). La découverte fonctionne sous Linux comme
// sous Windows : le PATH est inspecté en premier, puis les emplacements
// d'installation usuels de chaque plateforme.
package toolchain

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Noms canoniques des outils pilotés par le moteur.
const (
	Nmap    = "nmap"
	SSLScan = "sslscan"
	WhatWeb = "whatweb"
	Dig     = "dig"
	OpenSSL = "openssl"
)

// ErrToolUnavailable indique qu'un outil requis n'est pas installé.
type ErrToolUnavailable struct{ Tool string }

func (e *ErrToolUnavailable) Error() string {
	return fmt.Sprintf("outil %q introuvable sur ce système", e.Tool)
}

// Tool décrit la disponibilité d'un outil externe.
type Tool struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Purpose   string `json:"purpose"`
}

var purposes = map[string]string{
	Nmap:    "Découverte de ports et de services",
	SSLScan: "Audit des suites cryptographiques TLS",
	WhatWeb: "Empreinte des technologies web",
	Dig:     "Interrogation DNS détaillée",
	OpenSSL: "Inspection des certificats X.509",
}

// candidateDirs retourne les répertoires d'installation usuels à inspecter en
// complément du PATH.
func candidateDirs(name string) []string {
	if runtime.GOOS != "windows" {
		return []string{"/usr/bin", "/usr/local/bin", "/usr/sbin", "/opt/homebrew/bin", "/snap/bin"}
	}

	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	if programFilesX86 == "" {
		programFilesX86 = `C:\Program Files (x86)`
	}

	// Les outils embarqués avec l'application prennent le pas sur les
	// installations système afin de garantir un comportement reproductible.
	dirs := bundledDirs()
	for _, root := range []string{programFiles, programFilesX86} {
		switch name {
		case Nmap:
			dirs = append(dirs, filepath.Join(root, "Nmap"))
		case OpenSSL:
			dirs = append(dirs, filepath.Join(root, "OpenSSL-Win64", "bin"), filepath.Join(root, "Git", "usr", "bin"))
		case Dig:
			dirs = append(dirs, filepath.Join(root, "ISC BIND 9", "bin"))
		default:
			dirs = append(dirs, filepath.Join(root, name))
		}
	}
	return dirs
}

// bundledDirs retourne les répertoires d'outils livrés avec l'application.
// L'installateur Windows dépose les binaires multiplateformes dans
// "resources/tools" à côté de l'exécutable.
func bundledDirs() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	base := filepath.Dir(exe)
	return []string{
		filepath.Join(base, "tools"),
		filepath.Join(base, "resources", "tools"),
		filepath.Join(filepath.Dir(base), "resources", "tools"),
	}
}

func executableNames(name string) []string {
	if runtime.GOOS == "windows" {
		return []string{name + ".exe", name + ".bat", name}
	}
	return []string{name}
}

type lookupResult struct {
	path string
	ok   bool
}

var (
	lookupMu    sync.Mutex
	lookupCache = map[string]lookupResult{}
)

// Resolve retourne le chemin absolu de l'outil demandé. Le résultat est mis en
// cache : la découverte n'est effectuée qu'une fois par exécution.
func Resolve(name string) (string, error) {
	lookupMu.Lock()
	defer lookupMu.Unlock()

	if cached, ok := lookupCache[name]; ok {
		if !cached.ok {
			return "", &ErrToolUnavailable{Tool: name}
		}
		return cached.path, nil
	}

	path, found := discover(name)
	lookupCache[name] = lookupResult{path: path, ok: found}
	if !found {
		return "", &ErrToolUnavailable{Tool: name}
	}
	return path, nil
}

func discover(name string) (string, bool) {
	for _, candidate := range executableNames(name) {
		// Les répertoires embarqués sont prioritaires sur le PATH.
		for _, dir := range bundledDirs() {
			full := filepath.Join(dir, candidate)
			if isExecutable(full) {
				return full, true
			}
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, true
		}
	}
	for _, dir := range candidateDirs(name) {
		for _, candidate := range executableNames(name) {
			full := filepath.Join(dir, candidate)
			if isExecutable(full) {
				return full, true
			}
		}
	}
	return "", false
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}

// Available indique si l'outil est utilisable.
func Available(name string) bool {
	_, err := Resolve(name)
	return err == nil
}

// Run exécute l'outil avec les arguments fournis et retourne sa sortie
// standard. L'exécution est bornée par le contexte fourni.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	path, err := Resolve(name)
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return stdout.String(), fmt.Errorf("%s: délai dépassé: %w", name, ctx.Err())
		}
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return stdout.String(), fmt.Errorf("%s: %v: %s", name, err, truncate(detail, 300))
	}
	return stdout.String(), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func detectVersion(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	flag := "--version"
	if name == Dig {
		flag = "-v"
	}
	out, err := Run(ctx, name, flag)
	if err != nil && out == "" {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return truncate(line, 120)
		}
	}
	return ""
}

// Inventory retourne l'état de disponibilité de toute la chaîne d'outils,
// trié par nom pour un affichage stable.
func Inventory() []Tool {
	names := make([]string, 0, len(purposes))
	for name := range purposes {
		names = append(names, name)
	}
	sort.Strings(names)

	tools := make([]Tool, 0, len(names))
	for _, name := range names {
		tool := Tool{Name: name, Purpose: purposes[name]}
		if path, err := Resolve(name); err == nil {
			tool.Available = true
			tool.Path = path
			tool.Version = detectVersion(name)
		}
		tools = append(tools, tool)
	}
	return tools
}
