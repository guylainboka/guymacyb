# shadowscan-core

Pure-Rust security scanning core for the **Guyma Cyb** desktop cybersecurity
application. Provides three JSON-emitting CLI subcommands that the Express
backend (Task D) spawns and parses.

## Why pure-Rust

The crate is **100% Rust** with no OpenSSL or system-TLS linkage. `reqwest` is
configured with `default-features = false` and the `rustls-tls` feature, so it
uses `rustls` + `aws-lc-rs` (which only needs a C compiler, not OpenSSL). This
keeps cross-compilation to Windows tractable.

## CLI

```
shadowscan-core scan    --url <URL> --scope <strict|wildcard> --operator <ID>
shadowscan-core recon   --url <URL>
shadowscan-core headers --url <URL>
```

* Each subcommand prints exactly **one JSON object** to stdout.
* Logs go to **stderr** (`eprintln!`), never to stdout.
* On hard failure, prints `{"error":"..."}` to stdout and exits non-zero.

### `scan`

Full passive + semi-active scan of a URL. The output JSON shape is
**byte-compatible** with the `ScanResult` TypeScript interface declared in
`src/server/scanner.ts`, so the Express backend can pass it straight through to
the React frontend without reshaping.

The scan:
1. Normalizes the URL (adds `https://` if missing).
2. `GET` with an 8 s timeout and the official ShadowScan user-agent.
3. Probes `OPTIONS` to read `Allow` and detect `TRACE`.
4. Crawls the HTML body for `href`, `src`, `/api/...` absolute-path links
   (length < 80), plus `/robots.txt` `Disallow:` lines.
5. Detects technologies from `Server`, `X-Powered-By` and HTML markers
   (react, vue, wordpress, nginx, apache, cloudflare, TLS).
6. Emits findings for missing CSP / HSTS / X-Frame-Options, banner leak, and
   `TRACE` enabled — with the **same French titles, CVSS scores, CWE codes,
   impact and remediation steps** as `src/server/scanner.ts`.
7. Computes `overallRisk`, `cvssScore`, and `summary` counts.

Signatures are `md5("<domain>-<tag>")` computed via the pure-Rust `md-5` crate.

### `recon`

* DNS resolution via `hickory-resolver` (pure Rust). Falls back to
  `93.184.216.34` if resolution fails.
* Non-intrusive TCP `connect()` to ports 80, 443, 8080, 8443 (3 s timeout) —
  `OPEN` / `FILTERED` / `CLOSED`.
* `HEAD` probe to grab the `Server` banner (falls back to `GET` if HEAD is
  refused).
* Reports missing security headers: `Content-Security-Policy`,
  `Strict-Transport-Security`, `Permissions-Policy`.
* `reconLogs` contains French log lines tagged `[DNS]`, `[PORT]`, `[HTTP]`,
  `[HEADERS]`.
* `completedAt` is an ISO 8601 UTC timestamp.

### `headers`

Audits 6 security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) with `PASS` / `WEAK` / `MISSING` status
and a letter grade from `A+` to `F`.

## Build (Linux)

```bash
. "$HOME/.cargo/env"   # if Rust is installed user-space
cd shadowscan-core
cargo build --release
./target/release/shadowscan-core scan --url https://example.com --scope wildcard --operator SEC-OPS-0982
```

## Cross-compile to Windows

> The Rust source here is pure-Rust (no OpenSSL), but the `aws-lc-rs` crypto
> provider used by `rustls` requires a C compiler. On a Linux build machine,
> cross-compiling to `x86_64-pc-windows-gnu` needs the **MinGW-w64** linker
> (`x86_64-w64-mingw32-gcc`) installed. The Guyma Cyb project does **not**
> ship a pre-built Windows `.exe` from this repo because the Linux dev box
> has no MinGW; instead, the Windows binary is built on a Windows host or in
> CI.

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# -> target/x86_64-pc-windows-gnu/release/shadowscan-core.exe
```

If `aws-lc-rs` becomes a blocker for Windows cross-compile, switch the
`reqwest` feature in `Cargo.toml` from `rustls-tls` to
`rustls-tls-webpki-roots-no-provider` and add an explicit pure-Rust crypto
provider such as `rustls-rustcrypto` (pure Rust, no C). The current
configuration favors build simplicity on Linux.

## Dependencies

| Crate             | Purpose                              | Pure-Rust? |
|-------------------|--------------------------------------|------------|
| tokio             | async runtime + TCP timeouts         | yes        |
| reqwest           | HTTP client (rustls backend)         | yes (TLS via aws-lc-rs needs C compiler, no OpenSSL) |
| serde / serde_json| JSON (de)serialization               | yes        |
| clap              | CLI argument parsing                 | yes        |
| hickory-resolver  | DNS resolution                       | yes        |
| anyhow            | error handling                       | yes        |
| url               | URL parsing                          | yes        |
| md-5              | MD5 signatures for findings          | yes        |
| regex             | HTML body crawl                      | yes        |
| hex               | hex encoding of MD5 digests          | yes        |

No native-tls, no OpenSSL, no system-TLS. The crate can be vendored and built
fully offline on a Linux host with `gcc` available.
