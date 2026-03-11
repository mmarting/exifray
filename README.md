# Exifray

[![Go Version](https://img.shields.io/github/go-mod/go-version/mmarting/exifray)](https://go.dev/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Exifray is a Go tool that discovers publicly accessible files on a target domain, extracts their metadata on-the-fly (without saving files to disk), and surfaces interesting findings — usernames, emails, GPS coordinates, internal paths, software versions, printer names, serial numbers, and more.

**Current version: 1.1.0**

## Table of Contents

- [How It Works](#how-it-works)
- [Discovery Sources](#discovery-sources)
- [What It Detects](#what-it-detects)
- [Supported File Types](#supported-file-types)
- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Configuration](#configuration)
- [Author](#author)
- [Changelog](#changelog)
- [Contributors](#contributors)
- [License](#license)

## How It Works

1. **Discovery** — Queries multiple sources (passive archives, search engines, web scraping) to find file URLs associated with the target domain. Alternatively, accepts a file with URLs directly via `-u` to skip discovery entirely.
2. **Deduplication** — Merges results from all sources, removes duplicates, and filters by file extension.
3. **Metadata Extraction** — Downloads each file, extracts metadata in memory (EXIF, PDF info, OOXML/ODF properties, XMP, HTTP headers), and discards the file. Nothing is saved to disk. Transient errors (timeouts, 502/503) are retried automatically with linear backoff.
4. **Analysis** — Scans extracted metadata for interesting findings: usernames, email addresses, GPS coordinates, internal paths, software versions, printer models, serial numbers, and internal URLs.
5. **Output** — Presents deduplicated findings grouped by category, with optional JSON output and file export.

## Discovery Sources

| Source | Type | Description |
|---|---|---|
| Wayback Machine | Free | CDX API — historical URLs from web.archive.org |
| Common Crawl | Free | CC Index API — URLs from Common Crawl datasets |
| AlienVault OTX | Free | URL list for domain (optional API key raises rate limits) |
| URLScan.io | Free | Search API (optional API key raises rate limits) |
| Web Scraping | Free | Crawls target site, extracts file URLs from HTML tags |
| Sitemap | Free | Parses sitemap.xml and linked sitemaps |
| HackerTarget | Free | Host search API |
| crt.sh | Free | Certificate Transparency logs — discovers subdomains |
| ThreatMiner | Free | Threat intelligence API — URLs associated with domain |
| RapidDNS | Free | Subdomain discovery via rapiddns.io |
| VirusTotal | API | URL discovery via domain endpoint (requires API key) |
| Google Search | API | File-type dorking via Custom Search API (requires API key + CSE ID) |

## What It Detects

| Category | Description |
|---|---|
| GPS | Latitude/longitude from EXIF data, with Google Maps link |
| Users | Author names, usernames, last modified by, company names |
| Emails | Email addresses found in any metadata field |
| Software | Applications, camera models, PDF producers, office versions |
| Printers | Printer models and print drivers (LaserJet, Ricoh, etc.) |
| Serials | Camera serial numbers, lens serial numbers |
| Paths | Internal file paths (Windows, Linux, UNC) |
| URLs | Internal domain URLs (.local, .corp, SharePoint, Jira, etc.) |
| Hostnames | Private IPs and internal hostnames |

## Supported File Types

| Type | Extraction Method |
|---|---|
| JPEG, TIFF | EXIF tags (camera, GPS, software, author, serial numbers) |
| PNG | Text chunks (tEXt, iTXt, zTXt) |
| PDF | Info dictionary (Author, Creator, Producer, dates) |
| DOCX, XLSX, PPTX | OOXML — `docProps/core.xml` and `docProps/app.xml` |
| ODT, ODS, ODP | ODF — `meta.xml` |
| SVG | XML metadata, Dublin Core elements |
| MP3 | ID3 tags (artist, album, comment) |
| DOC, XLS, PPT | OLE compound documents |
| GIF, WebP, BMP | Basic metadata extraction |

XMP metadata is also extracted from any file type that embeds it.

## Installation

```sh
go install github.com/mmarting/exifray@latest
```

## Usage

```sh
exifray -h
```

## Options

| Flag | Long Flag | Description | Default |
|------|-----------|-------------|---------|
| `-d` | `--domain` | Target domain | **(required unless `-l`, `-u` or stdin)** |
| `-l` | `--list` | File with list of domains | — |
| `-u` | `--urls` | File with list of URLs (skip discovery) | — |
| `-w` | `--workers` | Number of concurrent workers | `20` |
| | `--timeout` | HTTP timeout in seconds | `15` |
| | `--max-retries` | Max retries on transient errors | `2` |
| | `--retry-delay` | Retry delay in seconds | `2` |
| `-v` | `--verbose` | Enable verbose output | `false` |
| `-q` | `--quiet` | Silent mode: findings only, one per line | `false` |
| | `--json` | Output results as JSON | `false` |
| `-o` | `--output` | Write results to file (JSON) | — |
| | `--proxy` | Proxy URL (`http://` or `socks5://`) | — |
| | `--rate-limit` | Max HTTP requests per second, 0=unlimited | `0` |
| `-e` | `--extensions` | Custom file extensions (comma-separated) | — |
| | `--show-urls` | Show source file URLs per finding | `false` |
| `-s` | `--sources` | Sources to use (comma-separated) | `all` |
| `-c` | `--config` | Config file path | `$HOME/.exifray.conf` |
| | `--version` | Print version and exit | — |
| `-h` | `--help` | Display help information | — |

## Examples

Scan a domain (free sources only, no API keys needed):

```sh
exifray -d example.com
```

JSON output to file:

```sh
exifray -d example.com --json -o results.json
```

Scan multiple domains from a file:

```sh
exifray -l domains.txt -w 50
```

Use specific sources only:

```sh
exifray -d example.com --sources wayback,scrape,sitemap
```

Custom file extensions:

```sh
exifray -d example.com -e pdf,docx,xlsx
```

Silent mode for automation — outputs findings one per line:

```sh
exifray -q -d example.com
```

Show source file URLs alongside findings:

```sh
exifray -d example.com --show-urls
```

Use a proxy:

```sh
exifray -d example.com --proxy socks5://127.0.0.1:9050
```

Rate-limit requests:

```sh
exifray -d example.com --rate-limit 5
```

Direct URL input (skip discovery, extract metadata only):

```sh
exifray --urls file_urls.txt --show-urls
```

Use URLs from other recon tools:

```sh
gau example.com | grep -E '\.(pdf|docx|xlsx)$' > urls.txt
exifray --urls urls.txt
```

Increase retries and timeout for slow sources:

```sh
exifray -d example.com --max-retries 3 --timeout 30
```

Disable retries (original behavior):

```sh
exifray -d example.com --max-retries 0
```

### Piping into exifray

Reads domains from stdin when piped, one per line:

```sh
subfinder -d example.com -silent | exifray
```

```sh
cat domains.txt | exifray --json
```

### Piping exifray output

```sh
# Extract only usernames
exifray -q -d target.com | grep "^\[Users\]" | cut -d' ' -f2-

# JSON + jq
exifray -d target.com --json | jq '.findings[] | select(.category == "GPS")'
```

## Configuration

On first run, exifray creates `$HOME/.exifray.conf` with this template:

```ini
# Exifray config file — API keys for optional sources
# Free sources (wayback, commoncrawl, otx, urlscan, scrape, sitemap,
# hackertarget, crtsh, threatminer, rapiddns) work without any keys.

# VirusTotal — URL discovery via domain endpoint (free: 500 lookups/day)
vt_api_key=""

# URLScan.io — search API (optional, raises rate limits)
urlscan_api_key=""

# AlienVault OTX — URL list (optional, raises rate limits)
otx_api_key=""

# Google Custom Search — file-type dorking (requires API key + Custom Search Engine ID)
# Get API key: https://console.cloud.google.com/apis/credentials
# Create CSE: https://programmablesearchengine.google.com/
google_api_key=""
google_cx=""
```

## Author

**Martin Martin**

- [Website](https://mmartin.me/)
- [LinkedIn](https://www.linkedin.com/in/martinmarting/)
- [GitHub](https://github.com/mmarting)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes between versions.

## Contributors

- [six2dez](https://github.com/six2dez) — Retry with backoff and direct URL input ([#1](https://github.com/mmarting/exifray/pull/1))

## License

Distributed under the [GPL v3 License](LICENSE.md).
