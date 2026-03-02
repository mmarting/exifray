package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	emailRegex   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	windowsPath  = regexp.MustCompile(`[A-Z]:\\[^\s"',;]{2,}\\[^\s"',;]+`)
	linuxPath    = regexp.MustCompile(`/(?:home|Users|tmp|var|etc|opt|srv|mnt)/[^\s"',;<>]+`)
	uncPath      = regexp.MustCompile(`\\\\[a-zA-Z0-9._\-]+\\[a-zA-Z0-9._\-\\]+`)
	privateIPv4  = regexp.MustCompile(`(?:^|[^0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)`)
	internalHost = regexp.MustCompile(`(?i)(?:^|[\s,;])([a-z0-9\-]+\.(?:internal|local|corp|intranet|lan|private|home)\b)`)
	internalURL  = regexp.MustCompile(`(?i)https?://[a-z0-9.\-]+\.(?:internal|local|corp|intranet|lan|private)[:/][^\s"'<>]*`)
	intranetURL  = regexp.MustCompile(`(?i)https?://(?:sharepoint|confluence|jira|wiki|gitlab|jenkins|bamboo|nexus|artifactory|sonar|grafana|kibana|nagios|zabbix)[.\-][^\s"'<>]+`)
	byteArray    = regexp.MustCompile(`^\[[\d,\s]+\]$`)
	pureYear     = regexp.MustCompile(`^\d{4}$`)
	trailingYear = regexp.MustCompile(`\s*\d{4}\s*$`)
	userAgentStr = regexp.MustCompile(`(?i)^mozilla/[\d.]`)
	canvaParams  = regexp.MustCompile(`(?i)\s*doc=\S*`)
	garbledUTF16 = regexp.MustCompile(`(?:000[a-zA-Z0-9]){3,}|(?:376377)`)

)

// softwareIndicators are substrings that identify a value as software rather than a person.
var softwareIndicators = []string{
	"adobe", "microsoft", "office", "word", "excel", "powerpoint",
	"acrobat", "photoshop", "gimp", "inkscape", "libreoffice",
	"openoffice", "illustrator", "indesign", "imageready",
	"canon", "nikon", "sony", "fuji", "olympus", "panasonic",
	"samsung", "apple", "google", "huawei", "xerox", "hp ",
	"windows", "macos", "linux", "ios", "android",
	"version", "ver.", "pdf library", "software", "dalim",
	"quarkxpress", "corel", "affinity", "sketch", "figma",
	"latex", "tex", "ghostscript", "cairo", "poppler",
	"canva", "renderer", "telerik", "ilovepdf",
	"pdfium", "capture one", "skia", "distiller",
	"convertapi", "print to pdf", "photoshelter",
	"dji", "hasselblad",
	"tcpdf", "jasperreports", "jasper", "pdfcreator",
	"wkhtmltopdf", "itext", "fpdf", "reportlab",
	"prince", "weasyprint", "puppeteer", "headless",
	"servlet", "tomcat",
}

// printerIndicators are substrings that identify a metadata value as a printer.
var printerIndicators = []string{
	"printer", "print driver", "print service",
	"laserjet", "deskjet", "officejet", "pagewide",
	"stylus", "workforce", "ecotank",
	"mfc-", "hl-", "dcp-",
	"imagerunner", "imagepress", "imageclass",
	"workcentre", "phaser", "versalink", "altalink",
	"bizhub", "accurio",
	"aficio", "mp c", "im c",
	"ecosys", "taskalfa",
	"clx-", "scx-", "xpress",
	"pixma", "maxify", "imageprograf",
	"pcl-6", "pcl6", "pcl 6", "postscript",
	"cups", "lpd://", "ipp://", "smb://",
}

// analyzeFindings scans all metadata results and identifies interesting findings.
func analyzeFindings(results []MetadataResult) []Finding {
	var findings []Finding

	for _, r := range results {
		if r.Error != "" || len(r.Fields) == 0 {
			continue
		}

		filePath := shortenURL(r.URL)

		findings = append(findings, detectGPS(r, filePath)...)
		findings = append(findings, detectUsers(r, filePath)...)
		findings = append(findings, detectEmails(r, filePath)...)
		findings = append(findings, detectSoftware(r, filePath)...)
		findings = append(findings, detectPrinters(r, filePath)...)
		findings = append(findings, detectSerials(r, filePath)...)
		findings = append(findings, detectPaths(r, filePath)...)
		findings = append(findings, detectURLs(r, filePath)...)
		findings = append(findings, detectHostnames(r, filePath)...)
	}

	return findings
}

func detectGPS(r MetadataResult, filePath string) []Finding {
	lat, hasLat := r.Fields["GPSLatitude"]
	lon, hasLon := r.Fields["GPSLongitude"]

	if !hasLat || !hasLon {
		return nil
	}

	if lat == "0.000000" && lon == "0.000000" {
		return nil
	}

	return []Finding{{
		Category: CategoryGPS,
		Severity: SeverityNotable,
		File:     filePath,
		Details:  map[string]string{"Latitude": lat, "Longitude": lon},
	}}
}

func detectUsers(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// Fields that typically contain person names
	userFields := []string{
		"Artist", "Author", "LastModifiedBy",
		"XPAuthor", "Company", "Manager",
		"Composer", "AlbumArtist",
		"AuthorPosition", "CaptionWriter",
	}

	for _, field := range userFields {
		val, ok := r.Fields[field]
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) < 3 || !isUsefulValue(val) || seen[strings.ToLower(val)] {
			continue
		}
		// If it looks like software, skip — it belongs in the software category
		if looksLikeSoftware(val) {
			continue
		}
		seen[strings.ToLower(val)] = true
		findings = append(findings, Finding{
			Category: CategoryUser,
			Severity: SeverityInteresting,
			File:     filePath,
			Details:  map[string]string{"Value": val, "Field": field},
		})
	}

	// Creator is ambiguous: person in OOXML/ODF, software in PDF.
	// Classify based on content.
	if val, ok := r.Fields["Creator"]; ok {
		val = strings.TrimSpace(val)
		if len(val) >= 3 && isUsefulValue(val) && !seen[strings.ToLower(val)] {
			if !looksLikeSoftware(val) {
				seen[strings.ToLower(val)] = true
				findings = append(findings, Finding{
					Category: CategoryUser,
					Severity: SeverityInteresting,
					File:     filePath,
					Details:  map[string]string{"Value": val, "Field": "Creator"},
				})
			}
		}
	}

	// Copyright — only if it looks like a person, not software/boilerplate
	if val, ok := r.Fields["Copyright"]; ok {
		val = strings.TrimSpace(val)
		// Strip common copyright symbols/text to get the actual name
		cleaned := strings.TrimLeft(val, "© ")
		cleaned = strings.TrimSpace(cleaned)
		cleaned = strings.TrimPrefix(cleaned, "Copyright ")
		cleaned = strings.TrimPrefix(cleaned, "copyright ")
		cleaned = strings.TrimSpace(cleaned)
		if isUsefulValue(cleaned) && !seen[strings.ToLower(cleaned)] && !looksLikeSoftware(cleaned) && len(cleaned) > 2 {
			seen[strings.ToLower(cleaned)] = true
			findings = append(findings, Finding{
				Category: CategoryUser,
				Severity: SeverityInteresting,
				File:     filePath,
				Details:  map[string]string{"Value": cleaned, "Field": "Copyright"},
			})
		}
	}

	return findings
}

func detectEmails(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, val := range r.Fields {
		matches := emailRegex.FindAllString(val, -1)
		for _, email := range matches {
			lower := strings.ToLower(email)
			if !seen[lower] {
				seen[lower] = true
				findings = append(findings, Finding{
					Category: CategoryEmail,
					Severity: SeverityInteresting,
					File:     filePath,
					Details:  map[string]string{"Value": email},
				})
			}
		}
	}

	return findings
}

func detectSoftware(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// Fields that are always software
	softwareFields := []string{
		"Software", "Producer", "Application",
		"AppVersion", "Generator", "EncoderSettings",
		"Model", "HostComputer", "LensModel",
		"HTTPServer", "HTTPPoweredBy", "HTTPGenerator", "HTTPAspNetVersion",
	}

	for _, field := range softwareFields {
		val, ok := r.Fields[field]
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if !isUsefulValue(val) {
			continue
		}
		// Skip if it's a printer — handled by detectPrinters
		if looksLikePrinter(val) {
			continue
		}
		// Skip user agent strings
		if userAgentStr.MatchString(val) {
			continue
		}
		// Normalize Canva entries — strip doc/user/brand/template params
		val = normalizeSoftware(val)
		key := strings.ToLower(val)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			Category: CategorySoftware,
			Severity: SeverityInfo,
			File:     filePath,
			Details:  map[string]string{"Value": val, "Field": field},
		})
	}

	// Creator — if it looks like software (which it usually is in PDFs)
	if val, ok := r.Fields["Creator"]; ok {
		val = strings.TrimSpace(val)
		if isUsefulValue(val) && looksLikeSoftware(val) && !looksLikePrinter(val) && !userAgentStr.MatchString(val) {
			val = normalizeSoftware(val)
			key := strings.ToLower(val)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Category: CategorySoftware,
					Severity: SeverityInfo,
					File:     filePath,
					Details:  map[string]string{"Value": val, "Field": "Creator"},
				})
			}
		}
	}

	// Copyright mentioning software
	if val, ok := r.Fields["Copyright"]; ok {
		val = strings.TrimSpace(val)
		if isUsefulValue(val) && looksLikeSoftware(val) && !looksLikePrinter(val) {
			val = normalizeSoftware(val)
			key := strings.ToLower(val)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Category: CategorySoftware,
					Severity: SeverityInfo,
					File:     filePath,
					Details:  map[string]string{"Value": val, "Field": "Copyright"},
				})
			}
		}
	}

	return findings
}

func looksLikeSoftware(val string) bool {
	lower := strings.ToLower(val)
	for _, ind := range softwareIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	// Contains version-like pattern: digit.digit
	for i := 0; i+2 < len(val); i++ {
		if val[i] >= '0' && val[i] <= '9' && val[i+1] == '.' && val[i+2] >= '0' && val[i+2] <= '9' {
			return true
		}
	}
	return false
}

func detectPrinters(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// Fields that may contain printer names
	printerFields := []string{
		"Producer", "Creator", "Software", "Application", "Generator",
	}

	for _, field := range printerFields {
		val, ok := r.Fields[field]
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if !looksLikePrinter(val) {
			continue
		}
		key := strings.ToLower(val)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			Category: CategoryPrinter,
			Severity: SeverityInteresting,
			File:     filePath,
			Details:  map[string]string{"Value": val, "Field": field},
		})
	}

	return findings
}

func looksLikePrinter(val string) bool {
	lower := strings.ToLower(val)
	for _, ind := range printerIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// normalizeSoftware cleans up noisy software values.
// E.g. "Canva (Renderer) doc=DAGliN user=UAF brand=BAF template=" → "Canva (Renderer)"
func normalizeSoftware(val string) string {
	// Strip Canva doc/user/brand/template params
	if idx := strings.Index(strings.ToLower(val), "doc="); idx > 0 {
		val = strings.TrimSpace(val[:idx])
	}
	if idx := strings.Index(strings.ToLower(val), "user="); idx > 0 {
		val = strings.TrimSpace(val[:idx])
	}
	return val
}

func detectSerials(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	serialFields := []string{
		"CameraSerialNumber", "BodySerialNumber",
		"LensSerialNumber", "InternalSerialNumber",
		"ImageUniqueID",
	}

	for _, field := range serialFields {
		val, ok := r.Fields[field]
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" || val == "0" {
			continue
		}
		key := strings.ToLower(val)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			Category: CategorySerial,
			Severity: SeverityInteresting,
			File:     filePath,
			Details:  map[string]string{"Value": val, "Field": field},
		})
	}

	return findings
}

func detectURLs(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, val := range r.Fields {
		// Internal domain URLs (*.internal, *.local, *.corp, etc.)
		for _, match := range internalURL.FindAllString(val, -1) {
			if !seen[match] {
				seen[match] = true
				findings = append(findings, Finding{
					Category: CategoryURL,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match},
				})
			}
		}
		// Known intranet service URLs (SharePoint, Confluence, Jira, etc.)
		for _, match := range intranetURL.FindAllString(val, -1) {
			if !seen[match] {
				seen[match] = true
				findings = append(findings, Finding{
					Category: CategoryURL,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match},
				})
			}
		}
	}

	return findings
}

func detectPaths(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// Direct path fields from extractors
	if val, ok := r.Fields["InternalPath"]; ok {
		val = strings.TrimSpace(val)
		if val != "" && !seen[val] {
			seen[val] = true
			findings = append(findings, Finding{
				Category: CategoryPath,
				Severity: SeverityNotable,
				File:     filePath,
				Details:  map[string]string{"Value": val},
			})
		}
	}

	for _, val := range r.Fields {
		for _, match := range windowsPath.FindAllString(val, -1) {
			if !seen[match] {
				seen[match] = true
				findings = append(findings, Finding{
					Category: CategoryPath,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match},
				})
			}
		}
		for _, match := range linuxPath.FindAllString(val, -1) {
			if !seen[match] {
				seen[match] = true
				findings = append(findings, Finding{
					Category: CategoryPath,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match},
				})
			}
		}
		for _, match := range uncPath.FindAllString(val, -1) {
			if !seen[match] {
				seen[match] = true
				findings = append(findings, Finding{
					Category: CategoryPath,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match},
				})
			}
		}
	}

	return findings
}

func detectHostnames(r MetadataResult, filePath string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, val := range r.Fields {
		for _, match := range privateIPv4.FindAllStringSubmatch(val, -1) {
			if len(match) > 1 && !seen[match[1]] {
				seen[match[1]] = true
				findings = append(findings, Finding{
					Category: CategoryHostname,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match[1]},
				})
			}
		}
		for _, match := range internalHost.FindAllStringSubmatch(val, -1) {
			if len(match) > 1 && !seen[match[1]] {
				seen[match[1]] = true
				findings = append(findings, Finding{
					Category: CategoryHostname,
					Severity: SeverityNotable,
					File:     filePath,
					Details:  map[string]string{"Value": match[1]},
				})
			}
		}
	}

	return findings
}

// isUsefulValue filters out empty, whitespace-only, and generic values.
func isUsefulValue(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}
	lower := strings.ToLower(val)
	skip := []string{
		"unknown", "none", "n/a", "null", "undefined", "default",
		"contributor", "author", "editor", "photographer",
		"creator", "owner", "untitled", "test", "writer",
	}
	for _, s := range skip {
		if lower == s {
			return false
		}
	}
	// Raw byte arrays like [67,0,105,0,...]
	if byteArray.MatchString(val) {
		return false
	}
	// Pure year (e.g. "2017")
	if pureYear.MatchString(val) {
		return false
	}
	// URLs are not person names
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "www.") {
		return false
	}
	// Garbled UTF-16 / binary data
	if garbledUTF16.MatchString(val) {
		return false
	}
	// All whitespace / control chars
	for _, c := range val {
		if c > ' ' {
			return true
		}
	}
	return false
}

func shortenURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	p := parsed.Path
	if p == "" {
		p = "/"
	}
	return fmt.Sprintf("%s%s", parsed.Host, p)
}
