// shadowscan-core — pure-Rust security scanning core for the Guyma Cyb desktop app.
//
// Three subcommands:
//   shadowscan-core scan    --url <URL> --scope <strict|wildcard> --operator <ID>
//   shadowscan-core recon   --url <URL>
//   shadowscan-core headers --url <URL>
//
// Each subcommand prints exactly one JSON object to stdout (logs go to stderr).
// On hard failure, prints `{"error":"..."}` to stdout and exits non-zero.
//
// The `scan` output JSON shape is meant to be byte-compatible with the
// ScanResult interface from src/server/scanner.ts so the Express backend can
// pass it straight through to the React frontend.

// Field names use camelCase on purpose so the serialized JSON matches the
// TypeScript interface in src/server/scanner.ts exactly (the Express backend
// forwards our stdout to the React frontend without reshaping).
#![allow(non_snake_case)]
#![allow(unused_assignments)]

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use md5::{Digest, Md5};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use url::Url;

const USER_AGENT: &str = "ShadowScan-Security-Auditor/1.0 (+https://github.com/shadowscan/assessment)";
const ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

#[derive(Parser)]
#[command(
    name = "shadowscan-core",
    version = "1.0.0",
    about = "Pure-Rust security scanning core (scan / recon / headers)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full passive+semi-active scan of a URL. Output mirrors the ScanResult TS interface.
    Scan {
        #[arg(long)]
        url: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        operator: String,
    },
    /// DNS + TCP port + server banner reconnaissance.
    Recon {
        #[arg(long)]
        url: String,
    },
    /// HTTP security headers audit with letter grade.
    Headers {
        #[arg(long)]
        url: String,
    },
}

// ============================ shared helpers ============================

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// ISO 8601 timestamp (UTC, RFC 3339, trailing Z). Pure-Rust civil-from-days
/// algorithm so we don't pull chrono just for this.
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z / 146097 } else { (z - 146096) / 146097 };
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, min, sec
    )
}

/// Normalize URL: add `https://` if no scheme present. Returns (normalized, host).
fn normalize_url(raw: &str) -> Result<(String, String)> {
    let trimmed = raw.trim();
    let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    let parsed = Url::parse(&normalized)
        .map_err(|e| anyhow!("URL invalide {}: {}", normalized, e))?;
    let host = parsed.host_str().ok_or_else(|| anyhow!("URL sans hôte: {}", normalized))?.to_string();
    Ok((normalized, host))
}

fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn build_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(true) // passive scanning of self-signed targets
        .build()
        .map_err(|e| anyhow!("échec de construction du client HTTP: {}", e))
}

/// Collect response headers into a lowercased BTreeMap (last value wins, matching the TS impl).
fn collect_headers(resp: &reqwest::Response) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (k, v) in resp.headers() {
        if let Ok(val) = v.to_str() {
            map.insert(k.as_str().to_lowercase(), val.to_string());
        }
    }
    map
}

fn reason_phrase(code: u16) -> String {
    reqwest::StatusCode::from_u16(code)
        .map(|s| s.canonical_reason().unwrap_or("OK").to_string())
        .unwrap_or_else(|_| "OK".to_string())
}

// ============================ data shapes ============================

#[derive(Serialize)]
struct TlsInfo {
    protocol: String,
    isHttps: bool,
    grade: String,
    details: String,
}

#[derive(Serialize, Clone)]
struct Endpoint {
    id: String,
    path: String,
    method: String,
    status: u16,
    statusText: String,
    #[serde(rename = "type")]
    type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    hasFinding: Option<bool>,
    findingSeverity: Option<String>,
}

#[derive(Serialize)]
struct FindingEvidence {
    request: String,
    response: String,
    authContext: String,
    roundtripMs: u64,
    nonDestructiveProof: bool,
}

#[derive(Serialize)]
struct Finding {
    id: String,
    title: String,
    severity: String,
    cvss: f64,
    confidence: u32,
    status: String,
    affectedComponent: String,
    category: String,
    cwe: String,
    description: String,
    evidence: FindingEvidence,
    impact: String,
    remediationTitle: String,
    remediationSteps: Vec<String>,
    signature: String,
    sqliteRow: u32,
}

#[derive(Serialize)]
struct ScanSummary {
    endpointsCount: usize,
    apiRoutesCount: usize,
    technologiesCount: usize,
    anomaliesCount: usize,
}

#[derive(Serialize)]
struct ScanResult {
    scanId: String,
    targetUrl: String,
    domain: String,
    statusCode: u16,
    statusText: String,
    latencyMs: u64,
    headers: BTreeMap<String, String>,
    tls: TlsInfo,
    technologies: Vec<String>,
    endpoints: Vec<Endpoint>,
    findings: Vec<Finding>,
    overallRisk: String,
    cvssScore: f64,
    summary: ScanSummary,
}

#[derive(Serialize)]
struct PortAuditEntry {
    port: u16,
    status: String,
    service: String,
}

#[derive(Serialize)]
struct ReconResult {
    target: String,
    domain: String,
    primaryIp: String,
    allIps: Vec<String>,
    serverBanner: String,
    portAudit: Vec<PortAuditEntry>,
    missingSecurityHeaders: Vec<String>,
    reconLogs: Vec<String>,
    completedAt: String,
}

#[derive(Serialize)]
struct HeaderAuditEntry {
    header: String,
    present: bool,
    value: String,
    status: String,
    recommendation: String,
}

#[derive(Serialize)]
struct HeadersResult {
    url: String,
    domain: String,
    statusCode: u16,
    headers: BTreeMap<String, String>,
    securityHeadersAudit: Vec<HeaderAuditEntry>,
    grade: String,
    checkedAt: String,
}

// ============================ scan subcommand ============================

async fn run_scan(raw_url: &str, scope: &str, _operator: &str) -> Result<Value> {
    let (normalized, domain) = normalize_url(raw_url)?;
    let parsed = Url::parse(&normalized)?;
    let is_https = parsed.scheme() == "https";
    eprintln!("[SCAN] Cible: {} (domaine: {})", normalized, domain);

    let client = build_http_client(Duration::from_secs(8))?;

    // 1. GET the URL
    let req_start = SystemTime::now();
    let response = client
        .get(&normalized)
        .header("Accept", ACCEPT)
        .send()
        .await
        .map_err(|e| anyhow!("Échec de connexion vers {}: {}", normalized, e))?;
    let latency_ms = req_start
        .elapsed()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let status_code = response.status().as_u16();
    let status_text = reason_phrase(status_code);
    eprintln!("[SCAN] Statut: {} {}, latence: {} ms", status_code, status_text, latency_ms);

    let headers_map = collect_headers(&response);
    let body_text = response.text().await.unwrap_or_default();
    eprintln!("[SCAN] Body: {} octets, {} en-têtes", body_text.len(), headers_map.len());

    // 2. OPTIONS probe for Allow / TRACE
    let mut allowed_methods = String::from("GET, HEAD");
    let mut trace_enabled = false;
    if let Ok(opts_resp) = client
        .request(reqwest::Method::OPTIONS, &normalized)
        .send()
        .await
    {
        if let Some(allow) = opts_resp.headers().get("allow").and_then(|v| v.to_str().ok()) {
            allowed_methods = allow.to_string();
            if allow.to_uppercase().contains("TRACE") {
                trace_enabled = true;
            }
        }
    }

    // 3. Crawl body for paths
    let mut discovered: BTreeSet<String> = BTreeSet::new();
    discovered.insert("/".to_string());

    let href_re = Regex::new(r#"href=["'](\/[a-zA-Z0-9_\-\.\/]+)["']"#).unwrap();
    let src_re = Regex::new(r#"src=["'](\/[a-zA-Z0-9_\-\.\/]+)["']"#).unwrap();
    let api_re = Regex::new(r#"["'](\/api\/[a-zA-Z0-9_\-\.\/]+)["']"#).unwrap();

    for cap in href_re.captures_iter(&body_text) {
        let p = cap.get(1).unwrap().as_str();
        if !p.starts_with("//") && p.len() < 80 {
            discovered.insert(p.to_string());
        }
    }
    for cap in src_re.captures_iter(&body_text) {
        let p = cap.get(1).unwrap().as_str();
        if !p.starts_with("//") && p.len() < 80 {
            discovered.insert(p.to_string());
        }
    }
    for cap in api_re.captures_iter(&body_text) {
        let p = cap.get(1).unwrap().as_str();
        if p.len() < 80 {
            discovered.insert(p.to_string());
        }
    }

    // 4. robots.txt
    let robots_url = format!("{}/robots.txt", parsed.origin().ascii_serialization());
    if let Ok(robots_resp) = client.get(&robots_url).send().await {
        if robots_resp.status().as_u16() == 200 {
            discovered.insert("/robots.txt".to_string());
            if let Ok(robots_text) = robots_resp.text().await {
                let disallow_re = Regex::new(r"(?i)Disallow:\s*([^\s#]+)").unwrap();
                for cap in disallow_re.captures_iter(&robots_text) {
                    let p = cap.get(1).unwrap().as_str();
                    if p.starts_with('/') {
                        discovered.insert(p.trim().to_string());
                    }
                }
            }
        }
    }

    eprintln!("[SCAN] {} chemins découverts", discovered.len());

    // 5. Technology detection
    let mut detected_tech: BTreeSet<String> = BTreeSet::new();
    let server_val = headers_map.get("server").cloned().unwrap_or_default();
    if !server_val.is_empty() {
        detected_tech.insert(server_val.clone());
    }
    if let Some(xpb) = headers_map.get("x-powered-by") {
        detected_tech.insert(xpb.clone());
    }
    let body_lower = body_text.to_lowercase();
    if body_lower.contains("react") || body_lower.contains("__next") || body_lower.contains("root") {
        detected_tech.insert("React".to_string());
    }
    if body_lower.contains("vue") || body_lower.contains("__nuxt") {
        detected_tech.insert("Vue.js".to_string());
    }
    if body_lower.contains("wp-content") || body_lower.contains("wordpress") {
        detected_tech.insert("WordPress".to_string());
    }
    if server_val.to_lowercase().contains("nginx") {
        detected_tech.insert("Nginx Web Server".to_string());
    }
    if server_val.to_lowercase().contains("apache") {
        detected_tech.insert("Apache HTTPD".to_string());
    }
    if server_val.to_lowercase().contains("cloudflare") {
        detected_tech.insert("Cloudflare Edge CDN".to_string());
    }
    if is_https {
        detected_tech.insert("TLS 1.3 / OpenSSL".to_string());
    }
    if detected_tech.is_empty() {
        detected_tech.insert("HTTP/1.1 Standard Stack".to_string());
    }
    let technologies: Vec<String> = detected_tech.iter().cloned().collect();

    // 6. Security findings
    let timestamp = now_millis();
    let mut findings: Vec<Finding> = Vec::new();
    let mut cvss_base_total: f64 = 0.0;
    let header_preview: String = headers_map
        .iter()
        .take(7)
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    // (findings are pushed below; cvss_base_total is updated as we go)

    // Check A: missing CSP
    if !headers_map.contains_key("content-security-policy") {
        let tag = "CSP";
        findings.push(Finding {
            id: format!("SEC-{}-{}", timestamp, tag),
            title: "Absence de Content Security Policy (CSP)".to_string(),
            severity: "MEDIUM".to_string(),
            cvss: 5.3,
            confidence: 100,
            status: "VALIDATED".to_string(),
            affectedComponent: "En-tête HTTP: Content-Security-Policy".to_string(),
            category: "Headers Security".to_string(),
            cwe: "CWE-1021".to_string(),
            description: format!(
                "Aucun en-tête Content-Security-Policy n'a été renvoyé par {}. En l'absence de CSP, le navigateur exécutera tout script inline sans politique de confinement contre les injections XSS.",
                domain
            ),
            evidence: FindingEvidence {
                request: format!(
                    "GET / HTTP/1.1\nHost: {}\nUser-Agent: ShadowScan-Security-Auditor/1.0",
                    domain
                ),
                response: format!(
                    "HTTP/1.1 {} {}\n{}\n(Content-Security-Policy absent)",
                    status_code, status_text, header_preview
                ),
                authContext: "Inspection passive des en-têtes HTTP".to_string(),
                roundtripMs: latency_ms,
                nonDestructiveProof: true,
            },
            impact: "Augmentation du risque d’exécution de code JavaScript non autorisé, vol de tokens de session et détournement d’interface.".to_string(),
            remediationTitle: "Déploiement Header CSP Stricte".to_string(),
            remediationSteps: vec![
                "Définir l'en-tête HTTP : Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';".to_string(),
                "Éviter absolument les directives 'unsafe-inline' et 'unsafe-eval'.".to_string(),
            ],
            signature: md5_hex(&format!("{}-csp", domain)),
            sqliteRow: 1,
        });
        cvss_base_total = cvss_base_total.max(5.3);
    }

    // Check B: missing HSTS (HTTPS only)
    if is_https && !headers_map.contains_key("strict-transport-security") {
        let tag = "HSTS";
        findings.push(Finding {
            id: format!("SEC-{}-{}", timestamp, tag),
            title: "En-tête HSTS (HTTP Strict Transport Security) manquant".to_string(),
            severity: "MEDIUM".to_string(),
            cvss: 4.8,
            confidence: 100,
            status: "VALIDATED".to_string(),
            affectedComponent: "En-tête HTTP: Strict-Transport-Security".to_string(),
            category: "Transport Security".to_string(),
            cwe: "CWE-319".to_string(),
            description: format!(
                "La cible {} propose HTTPS mais n'envoie pas l'en-tête HSTS. Un attaquant sur le même réseau local (Wi-Fi public) peut tenter une attaque de déclassement SSLStrip vers HTTP non chiffré.",
                domain
            ),
            evidence: FindingEvidence {
                request: format!("GET / HTTP/1.1\nHost: {}", domain),
                response: format!(
                    "HTTP/1.1 {} {}\n(Strict-Transport-Security absent)",
                    status_code, status_text
                ),
                authContext: "Vérification TLS Transport Layer".to_string(),
                roundtripMs: latency_ms,
                nonDestructiveProof: true,
            },
            impact: "Attaque de type Man-in-the-Middle (MitM) et interception de trafic non chiffré.".to_string(),
            remediationTitle: "Activer la directive HSTS".to_string(),
            remediationSteps: vec![
                "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".to_string(),
            ],
            signature: md5_hex(&format!("{}-hsts", domain)),
            sqliteRow: 2,
        });
        cvss_base_total = cvss_base_total.max(4.8);
    }

    // Check C: missing X-Frame-Options AND no frame-ancestors in CSP
    let xfo_missing = !headers_map.contains_key("x-frame-options");
    let csp_no_frame_ancestors = headers_map
        .get("content-security-policy")
        .map(|v| !v.to_lowercase().contains("frame-ancestors"))
        .unwrap_or(true);
    if xfo_missing && csp_no_frame_ancestors {
        let tag = "XFO";
        findings.push(Finding {
            id: format!("SEC-{}-{}", timestamp, tag),
            title: "Absence de protection anti-Clickjacking (X-Frame-Options manquant)".to_string(),
            severity: "MEDIUM".to_string(),
            cvss: 4.3,
            confidence: 95,
            status: "VALIDATED".to_string(),
            affectedComponent: "En-tête HTTP: X-Frame-Options".to_string(),
            category: "UI Redressing".to_string(),
            cwe: "CWE-1021".to_string(),
            description: "L'application web ne définit ni X-Frame-Options ni frame-ancestors. Le site peut être intégré dans une balise <iframe> transparente sur un domaine tiers malveillant pour intercepter des clics utilisateur.".to_string(),
            evidence: FindingEvidence {
                request: format!("GET / HTTP/1.1\nHost: {}", domain),
                response: format!(
                    "HTTP/1.1 {} {}\n(X-Frame-Options absent)",
                    status_code, status_text
                ),
                authContext: "Inspection de réponse HTTP".to_string(),
                roundtripMs: latency_ms,
                nonDestructiveProof: true,
            },
            impact: "Détournement de clics (Clickjacking) forçant des actions non intentionnelles.".to_string(),
            remediationTitle: "Activer X-Frame-Options SAMEORIGIN".to_string(),
            remediationSteps: vec![
                "Ajouter l’en-tête HTTP : X-Frame-Options: SAMEORIGIN ou DENY".to_string(),
            ],
            signature: md5_hex(&format!("{}-xfo", domain)),
            sqliteRow: 3,
        });
        cvss_base_total = cvss_base_total.max(4.3);
    }

    // Check D: Server / X-Powered-By banner leak
    if headers_map.contains_key("server") || headers_map.contains_key("x-powered-by") {
        let leaked = [
            headers_map.get("server").cloned(),
            headers_map.get("x-powered-by").cloned(),
        ]
        .iter()
        .filter_map(|s| s.clone())
        .collect::<Vec<_>>()
        .join(" / ");
        let tag = "BANNER";
        findings.push(Finding {
            id: format!("SEC-{}-{}", timestamp, tag),
            title: "Divulgation de bannière serveur (Information Disclosure)".to_string(),
            severity: "LOW".to_string(),
            cvss: 3.1,
            confidence: 100,
            status: "VALIDATED".to_string(),
            affectedComponent: "Header HTTP: Server / X-Powered-By".to_string(),
            category: "Information Disclosure".to_string(),
            cwe: "CWE-200".to_string(),
            description: format!(
                "La cible expose la signature logicielle suivante : \"{}\". Cela facilite la reconnaissance d'un attaquant pour cibler les vulnérabilités connues de cette version logicielle.",
                leaked
            ),
            evidence: FindingEvidence {
                request: format!("GET / HTTP/1.1\nHost: {}", domain),
                response: format!(
                    "HTTP/1.1 {} {}\nServer: {}\nX-Powered-By: {}",
                    status_code,
                    status_text,
                    headers_map.get("server").cloned().unwrap_or_else(|| "N/A".to_string()),
                    headers_map.get("x-powered-by").cloned().unwrap_or_else(|| "N/A".to_string()),
                ),
                authContext: "Lecture des en-têtes HTTP".to_string(),
                roundtripMs: latency_ms,
                nonDestructiveProof: true,
            },
            impact: "Reconnaissance automatisée facilitant le ciblage d’exploits spécifiques.".to_string(),
            remediationTitle: "Désactiver la bannière logicielle".to_string(),
            remediationSteps: vec![
                "Nginx : ajouter \"server_tokens off;\" dans nginx.conf".to_string(),
                "Express.js : ajouter \"app.disable('x-powered-by');\"".to_string(),
            ],
            signature: md5_hex(&format!("{}-banner", domain)),
            sqliteRow: 4,
        });
        // LOW severity finding does not raise cvss_base_total above the existing floor
        // in scanner.ts (it doesn't update cvssBaseTotal). Mirror that exactly.
    }

    // Check E: TRACE method enabled
    if trace_enabled {
        let tag = "TRACE";
        findings.push(Finding {
            id: format!("SEC-{}-{}", timestamp, tag),
            title: "Méthode HTTP TRACE activée (Risque Cross-Site Tracing XST)".to_string(),
            severity: "HIGH".to_string(),
            cvss: 7.2,
            confidence: 90,
            status: "VALIDATED".to_string(),
            affectedComponent: "OPTIONS/TRACE /".to_string(),
            category: "HTTP Methods".to_string(),
            cwe: "CWE-693".to_string(),
            description: "La méthode HTTP TRACE est autorisée sur le serveur. Elle permet de réfléchir la requête HTTP complète et de contourner les protections HttpOnly des cookies de session.".to_string(),
            evidence: FindingEvidence {
                request: format!("OPTIONS / HTTP/1.1\nHost: {}", domain),
                response: format!("HTTP/1.1 200 OK\nAllow: {}", allowed_methods),
                authContext: "Sonde de méthodes HTTP".to_string(),
                roundtripMs: latency_ms,
                nonDestructiveProof: true,
            },
            impact: "Contournement du flag de sécurité HttpOnly sur les cookies de session.".to_string(),
            remediationTitle: "Désactiver le verbe HTTP TRACE".to_string(),
            remediationSteps: vec![
                "Nginx: if ($request_method = TRACE) { return 405; }".to_string(),
                "Apache: TraceEnable Off".to_string(),
            ],
            signature: md5_hex(&format!("{}-trace", domain)),
            sqliteRow: 5,
        });
        cvss_base_total = cvss_base_total.max(7.2);
    }

    // 7. Build endpoints list (preserve insertion order via BTreeSet then Vec — alphabetical OK)
    let endpoints_list: Vec<Endpoint> = discovered
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let is_api = p.contains("/api") || p.contains(".json");
            let is_auth = p.contains("login") || p.contains("auth") || p.contains("signin");
            let is_admin = p.contains("admin") || p.contains("dashboard") || p.contains("metrics");
            let type_ = if p == "/" {
                "root".to_string()
            } else if is_api {
                "api".to_string()
            } else if is_auth {
                "auth".to_string()
            } else if is_admin {
                "admin".to_string()
            } else {
                "page".to_string()
            };
            let note = if is_api {
                Some("Route API".to_string())
            } else if is_admin {
                Some("Zone restreinte".to_string())
            } else {
                None
            };
            let has_finding = is_admin || (is_api && !findings.is_empty());
            let finding_severity = if is_admin {
                Some("HIGH".to_string())
            } else {
                Some("MEDIUM".to_string())
            };
            let status = if p == "/" { status_code } else { 200 };
            let status_text_ep = if p == "/" {
                format!("{} {}", status_code, status_text)
            } else {
                "Découvert".to_string()
            };
            Endpoint {
                id: format!("ep-{}", idx),
                path: p.clone(),
                method: "GET".to_string(),
                status,
                statusText: status_text_ep,
                type_,
                note,
                hasFinding: Some(has_finding),
                findingSeverity: finding_severity,
            }
        })
        .collect();

    let api_count = endpoints_list.iter().filter(|e| e.type_ == "api").count();
    let anomalies_count = findings.len();
    let result_findings = findings; // move into the result
    let overall_risk = if cvss_base_total >= 7.0 {
        "HIGH"
    } else if cvss_base_total >= 4.0 {
        "MED"
    } else if cvss_base_total > 0.0 {
        "LOW"
    } else {
        "CLEAN"
    };
    let cvss_score = if cvss_base_total > 0.0 {
        (cvss_base_total * 10.0).round() / 10.0
    } else {
        3.1
    };

    let has_hsts = headers_map.contains_key("strict-transport-security");
    let result = ScanResult {
        scanId: format!("scan-{}", timestamp),
        targetUrl: normalized,
        domain: domain.clone(),
        statusCode: status_code,
        statusText: status_text.clone(),
        latencyMs: latency_ms,
        headers: headers_map,
        tls: TlsInfo {
            protocol: if is_https {
                "TLS 1.3 / 1.2".to_string()
            } else {
                "HTTP Clair (Non chiffré)".to_string()
            },
            isHttps: is_https,
            grade: if is_https {
                if has_hsts {
                    "Grade A+".to_string()
                } else {
                    "Grade B".to_string()
                }
            } else {
                "Grade F (Insecure)".to_string()
            },
            details: if is_https {
                "Chiffrement de transport actif".to_string()
            } else {
                "Trafic non chiffré vulnérable aux écoutes réseau".to_string()
            },
        },
        technologies,
        endpoints: endpoints_list.clone(),
        findings: result_findings,
        overallRisk: overall_risk.to_string(),
        cvssScore: cvss_score,
        summary: ScanSummary {
            endpointsCount: endpoints_list.len(),
            apiRoutesCount: api_count,
            technologiesCount: detected_tech.len(),
            anomaliesCount: anomalies_count,
        },
    };
    let _ = scope; // scope accepted but currently informational
    Ok(serde_json::to_value(&result)?)
}

// ============================ recon subcommand ============================

async fn run_recon(raw_url: &str) -> Result<Value> {
    let (normalized, domain) = normalize_url(raw_url)?;
    let mut logs: Vec<String> = Vec::new();
    eprintln!("[RECON] Cible: {} (domaine: {})", normalized, domain);
    logs.push(format!("[RECON] Initialisation de la reconnaissance sur {}", domain));

    // 1. DNS resolution
    logs.push(format!("[DNS] Résolution A/AAAA pour {}", domain));
    let mut all_ips: Vec<String> = Vec::new();
    let primary_ip;
    let resolver = match hickory_resolver::TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("[DNS] Erreur d'initialisation du résolveur: {}", e);
            logs.push(format!("[DNS] Erreur d'initialisation du résolveur: {}", e));
            None
        }
    };
    if let Some(resolver) = &resolver {
        match resolver.lookup_ip(&domain).await {
            Ok(lookup) => {
                for ip in lookup.iter() {
                    all_ips.push(ip.to_string());
                }
                if all_ips.is_empty() {
                    logs.push(format!("[DNS] Aucun enregistrement A/AAAA trouvé pour {}", domain));
                } else {
                    logs.push(format!("[DNS] Adresse IP principale: {}", all_ips[0]));
                }
            }
            Err(e) => {
                eprintln!("[DNS] Échec de résolution: {}", e);
                logs.push(format!("[DNS] Échec de résolution pour {}: {}", domain, e));
            }
        }
    }
    if all_ips.is_empty() {
        all_ips.push("93.184.216.34".to_string());
        logs.push("[DNS] Fallback: utilisation de 93.184.216.34".to_string());
    }
    primary_ip = all_ips[0].clone();

    // 2. TCP port scan (non-intrusive connect)
    let ports: &[(u16, &str)] = &[
        (80, "HTTP"),
        (443, "HTTPS"),
        (8080, "HTTP-Alt"),
        (8443, "HTTPS-Alt"),
    ];
    logs.push(format!(
        "[PORT] Audit des ports {}",
        ports.iter().map(|(p, _)| p.to_string()).collect::<Vec<_>>().join(", ")
    ));
    let mut port_audit: Vec<PortAuditEntry> = Vec::new();
    for (port, service) in ports {
        let host_for_connect: String = if parsed_host_allows_connect(&domain) {
            domain.clone()
        } else {
            primary_ip.clone()
        };
        let addr = format!("{}:{}", host_for_connect, port);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&addr),
        )
        .await;
        let (status_str, log_status) = match result {
            Ok(Ok(_stream)) => ("OPEN", "OUVERT"),
            Ok(Err(_e)) => ("CLOSED", "FERMÉ"),
            Err(_) => ("FILTERED", "FILTRÉ"),
        };
        logs.push(format!("[PORT] Port {} ({}): {}", port, service, log_status));
        port_audit.push(PortAuditEntry {
            port: *port,
            status: status_str.to_string(),
            service: service.to_string(),
        });
    }

    // 3. HEAD request for server banner
    logs.push("[HTTP] Sonde HEAD pour récupération de bannière serveur".to_string());
    let client = build_http_client(Duration::from_secs(6))?;
    let mut server_banner = String::from("Non divulgué");
    let mut headers_map: BTreeMap<String, String> = BTreeMap::new();
    let mut status_code: u16 = 0;
    match client.head(&normalized).send().await {
        Ok(resp) => {
            status_code = resp.status().as_u16();
            logs.push(format!("[HTTP] HEAD {} {}", normalized, status_code));
            headers_map = collect_headers(&resp);
            if let Some(s) = headers_map.get("server") {
                server_banner = s.clone();
                logs.push(format!("[HTTP] Bannière serveur détectée: {}", s));
            } else if let Some(s) = headers_map.get("x-powered-by") {
                server_banner = s.clone();
                logs.push(format!("[HTTP] Bannière x-powered-by détectée: {}", s));
            } else {
                logs.push("[HTTP] Aucune bannière serveur divulguée".to_string());
            }
        }
        Err(e) => {
            eprintln!("[HTTP] HEAD échoué: {}", e);
            logs.push(format!("[HTTP] Échec du sondage HEAD: {}", e));
            // Fallback: try GET (some servers reject HEAD)
            if let Ok(resp) = client.get(&normalized).send().await {
                status_code = resp.status().as_u16();
                logs.push(format!("[HTTP] GET fallback {} {}", normalized, status_code));
                headers_map = collect_headers(&resp);
                if let Some(s) = headers_map.get("server") {
                    server_banner = s.clone();
                    logs.push(format!("[HTTP] Bannière serveur (via GET): {}", s));
                }
            }
        }
    }

    // 4. Missing security headers check
    let required = ["content-security-policy", "strict-transport-security", "permissions-policy"];
    let mut missing: Vec<String> = Vec::new();
    for h in &required {
        if !headers_map.contains_key(*h) {
            missing.push(h.to_string());
        }
    }
    if missing.is_empty() {
        logs.push("[HEADERS] Tous les en-têtes de sécurité attendus sont présents".to_string());
    } else {
        logs.push(format!(
            "[HEADERS] En-têtes de sécurité manquants: {}",
            missing.join(", ")
        ));
    }

    let result = ReconResult {
        target: normalized,
        domain,
        primaryIp: primary_ip,
        allIps: all_ips,
        serverBanner: server_banner,
        portAudit: port_audit,
        missingSecurityHeaders: missing,
        reconLogs: logs,
        completedAt: iso8601_now(),
    };
    Ok(serde_json::to_value(&result)?)
}

fn parsed_host_allows_connect(_host: &str) -> bool {
    // Always use the hostname for connect; DNS resolution will give us an IP via
    // the OS resolver. For IPv6-only hosts the TcpStream connect still works.
    true
}

// ============================ headers subcommand ============================

async fn run_headers(raw_url: &str) -> Result<Value> {
    let (normalized, domain) = normalize_url(raw_url)?;
    eprintln!("[HEADERS] Cible: {} (domaine: {})", normalized, domain);
    let client = build_http_client(Duration::from_secs(8))?;

    // Prefer HEAD, fall back to GET (some servers refuse HEAD)
    let mut response = client.head(&normalized).send().await;
    if response.is_err() {
        response = client.get(&normalized).send().await;
    }
    let response = response?;
    let status_code = response.status().as_u16();
    let headers_map = collect_headers(&response);

    // Audit each header
    let audit_specs: [(&str, &str); 6] = [
        (
            "Content-Security-Policy",
            "Définir une CSP stricte: default-src 'self'; object-src 'none'",
        ),
        (
            "Strict-Transport-Security",
            "HSTS: max-age=31536000; includeSubDomains; preload",
        ),
        (
            "X-Frame-Options",
            "X-Frame-Options: SAMEORIGIN ou DENY (ou frame-ancestors dans la CSP)",
        ),
        (
            "X-Content-Type-Options",
            "X-Content-Type-Options: nosniff",
        ),
        (
            "Referrer-Policy",
            "Referrer-Policy: strict-origin-when-cross-origin ou no-referrer",
        ),
        (
            "Permissions-Policy",
            "Permissions-Policy: géocoder les API sensibles (camera=(), microphone=(), geolocation=())",
        ),
    ];

    let mut audit: Vec<HeaderAuditEntry> = Vec::new();
    let mut pass_count = 0u32;
    let mut weak_count = 0u32;
    for (header, recommendation) in audit_specs.iter() {
        let key = header.to_lowercase();
        let (present, value, status) = if let Some(v) = headers_map.get(&key) {
            // Weak-value heuristics
            let weak = match key.as_str() {
                "strict-transport-security" => {
                    // weak if max-age < 31536000
                    let ma = v
                        .to_lowercase()
                        .split(';')
                        .find_map(|part| {
                            let p = part.trim();
                            p.strip_prefix("max-age=")
                                .and_then(|n| n.trim().parse::<u64>().ok())
                        })
                        .unwrap_or(0);
                    ma < 31536000
                }
                "content-security-policy" => {
                    let lv = v.to_lowercase();
                    lv.contains("unsafe-inline") || lv.contains("unsafe-eval")
                }
                "x-frame-options" => {
                    let lv = v.to_lowercase();
                    lv.contains("allowall") || lv.contains("allow-from")
                }
                _ => false,
            };
            if weak {
                weak_count += 1;
                (true, v.clone(), "WEAK")
            } else {
                pass_count += 1;
                (true, v.clone(), "PASS")
            }
        } else {
            (false, String::new(), "MISSING")
        };
        audit.push(HeaderAuditEntry {
            header: header.to_string(),
            present,
            value,
            status: status.to_string(),
            recommendation: recommendation.to_string(),
        });
    }

    // Letter grade based on pass/weak/missing ratios
    let total = audit_specs.len() as u32;
    let score = pass_count as f64 + (weak_count as f64 * 0.5);
    let pct = score / total as f64;
    let grade = if pct >= 1.0 {
        "A+"
    } else if pct >= 0.85 {
        "A"
    } else if pct >= 0.70 {
        "B"
    } else if pct >= 0.55 {
        "C"
    } else if pct >= 0.40 {
        "D"
    } else if pct > 0.0 {
        "E"
    } else {
        "F"
    };

    let result = HeadersResult {
        url: normalized,
        domain,
        statusCode: status_code,
        headers: headers_map,
        securityHeadersAudit: audit,
        grade: grade.to_string(),
        checkedAt: iso8601_now(),
    };
    Ok(serde_json::to_value(&result)?)
}

// ============================ entrypoint ============================

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result: Result<Value> = match cli.cmd {
        Commands::Scan { url, scope, operator } => run_scan(&url, &scope, &operator).await,
        Commands::Recon { url } => run_recon(&url).await,
        Commands::Headers { url } => run_headers(&url).await,
    };
    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()));
            std::process::exit(0);
        }
        Err(e) => {
            let err = serde_json::json!({ "error": e.to_string() });
            println!("{}", serde_json::to_string(&err).unwrap_or_else(|_| "{\"error\":\"unknown\"}".to_string()));
            std::process::exit(1);
        }
    }
}
