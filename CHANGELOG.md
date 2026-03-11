# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-03-11

### Added
- **Retry with backoff** — Automatic retries with linear backoff for transient errors (timeouts, HTTP 429/502/503/504, connection resets) during both discovery and metadata extraction phases. New flags: `--max-retries` (default: 2) and `--retry-delay` (default: 2s). Use `--max-retries 0` to disable.
- **Direct URL input** — New `-u`/`--urls` flag accepts a file with URLs (one per line), bypassing the discovery phase entirely. Useful when URLs come from external recon tools like gau, waymore, or katana.
- **Per-request timeouts** — Replaced global HTTP client timeout with per-request context timeouts. Discovery sources receive 3x the configured timeout to accommodate large API responses from sources like crt.sh and Wayback Machine.
- Visible `[retry]` log messages on stderr when retries occur.

### Changed
- Global `http.Client.Timeout` removed in favor of context-based timeouts, preventing premature termination of large response body reads.

## [1.0.0] - 2026-03-10

### Added
- Initial public release.
- Discovery from 12 sources: Wayback Machine, Common Crawl, AlienVault OTX, URLScan.io, Web Scraping, Sitemap, HackerTarget, crt.sh, ThreatMiner, RapidDNS, VirusTotal, Google Search.
- Metadata extraction for JPEG, TIFF, PNG, PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP, SVG, MP3, DOC, XLS, PPT, GIF, WebP.
- XMP metadata extraction from any file type.
- Finding categories: GPS, Users, Emails, Software, Printers, Serials, Paths, URLs, Hostnames.
- JSON output, file export, quiet mode, proxy support, rate limiting.
- TLS fingerprinting with uTLS (Chrome profile) and HTTP/2 support.
- API key configuration via `~/.exifray.conf`.
