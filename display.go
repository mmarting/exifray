package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	cyan    = color.New(color.FgCyan)
	green   = color.New(color.FgGreen)
	yellow  = color.New(color.FgYellow)
	red     = color.New(color.FgRed)
	white   = color.New(color.FgWhite)
	bold    = color.New(color.Bold)
	dim     = color.New(color.Faint)
)

const banner = `
               .__  _____
  ____ ___  __ |__|/ ____\___________  ___.__.
_/ __ \\  \/  / |  \   __\\_  __ \__  \<   |  |
\  ___/ >    <  |  ||  |   |  | \// __ \\___  |
 \___  >__/\_ \ |__||__|   |__|  (____  / ____|
     \/      \/                       \/\/
`

func printBanner() {
	fmt.Fprint(os.Stderr, banner)
	dim.Fprintf(os.Stderr, "  v%s — metadata discovery tool by Martín Martín (mmartin.me)\n\n", Version)
}

func printUsage() {
	printBanner()
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  exifray [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  -d, --domain string       Target domain\n")
	fmt.Fprintf(os.Stderr, "  -l, --list string         File with list of domains\n")
	fmt.Fprintf(os.Stderr, "  -w, --workers int         Concurrent workers (default 20)\n")
	fmt.Fprintf(os.Stderr, "      --timeout int         HTTP timeout in seconds (default 15)\n")
	fmt.Fprintf(os.Stderr, "  -v, --verbose             Verbose output\n")
	fmt.Fprintf(os.Stderr, "  -q, --quiet               Silent mode (findings only)\n")
	fmt.Fprintf(os.Stderr, "      --json                JSON output\n")
	fmt.Fprintf(os.Stderr, "  -o, --output string       Output file path\n")
	fmt.Fprintf(os.Stderr, "      --proxy string        HTTP/SOCKS5 proxy URL\n")
	fmt.Fprintf(os.Stderr, "      --rate-limit float    Max requests per second (0 = unlimited)\n")
	fmt.Fprintf(os.Stderr, "  -e, --extensions string   Custom file extensions (comma-separated)\n")
	fmt.Fprintf(os.Stderr, "      --show-urls           Show source file URLs per finding\n")
	fmt.Fprintf(os.Stderr, "  -s, --sources string      Sources to use (default \"all\")\n")
	fmt.Fprintf(os.Stderr, "  -c, --config string       Config file path (default ~/.exifray.conf)\n")
	fmt.Fprintf(os.Stderr, "      --version             Print version\n")
	fmt.Fprintf(os.Stderr, "  -h, --help                Show this help\n\n")
	fmt.Fprintf(os.Stderr, "Sources:\n")
	fmt.Fprintf(os.Stderr, "  wayback, commoncrawl, otx, urlscan, scrape, sitemap,\n")
	fmt.Fprintf(os.Stderr, "  hackertarget, virustotal, crtsh, threatminer, rapiddns, google\n\n")
	fmt.Fprintf(os.Stderr, "Config:\n")
	fmt.Fprintf(os.Stderr, "  API keys are stored in ~/.exifray.conf (created on first run).\n")
	fmt.Fprintf(os.Stderr, "  Supported keys: vt_api_key, urlscan_api_key, otx_api_key,\n")
	fmt.Fprintf(os.Stderr, "                  google_api_key, google_cx\n\n")
	fmt.Fprintf(os.Stderr, "Stdin:\n")
	fmt.Fprintf(os.Stderr, "  Reads domains from stdin when piped, one per line.\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  exifray -d example.com\n")
	fmt.Fprintf(os.Stderr, "  exifray -d example.com --json -o results.json\n")
	fmt.Fprintf(os.Stderr, "  exifray -l domains.txt -w 50 --sources wayback,scrape,sitemap\n")
	fmt.Fprintf(os.Stderr, "  subfinder -d example.com -silent | exifray\n")
	fmt.Fprintf(os.Stderr, "  cat domains.txt | exifray --json\n\n")
	fmt.Fprintf(os.Stderr, "Author:\n")
	fmt.Fprintf(os.Stderr, "  Name:               Martín Martín\n")
	fmt.Fprintf(os.Stderr, "  Website:            https://mmartin.me/\n")
	fmt.Fprintf(os.Stderr, "  LinkedIn:           https://www.linkedin.com/in/martinmarting/\n")
	fmt.Fprintf(os.Stderr, "  GitHub:             https://github.com/mmarting/exifray\n\n")
}

func printSection(title string) {
	fmt.Fprintf(os.Stderr, "\n")
	dim.Fprintf(os.Stderr, "── %s ", title)
	for i := 0; i < 55-len(title); i++ {
		dim.Fprint(os.Stderr, "─")
	}
	fmt.Fprintf(os.Stderr, "\n")
}

func sourcePrefix(index, total int) string {
	width := len(fmt.Sprintf("%d", total))
	return fmt.Sprintf("%*d/%d", width, index, total)
}

func printSourceResult(index, total int, label string, urlCount, fileCount int, skipped bool) {
	prefix := sourcePrefix(index, total)
	if skipped {
		dim.Fprintf(os.Stderr, "  [skip] %-35s\n", label)
		return
	}
	green.Fprintf(os.Stderr, "  [%s] ", prefix)
	fmt.Fprintf(os.Stderr, "%-35s ", label)
	cyan.Fprintf(os.Stderr, "%d URLs", urlCount)
	if fileCount != urlCount {
		dim.Fprintf(os.Stderr, " → %d files", fileCount)
	}
	fmt.Fprintln(os.Stderr)
}

func printSourceSkip(index, total int, label string, hint string) {
	prefix := sourcePrefix(index, total)
	dim.Fprintf(os.Stderr, "  [%s] %-35s %s\n", prefix, label, hint)
}

func printSourceError(index, total int, label string, err error) {
	prefix := sourcePrefix(index, total)
	yellow.Fprintf(os.Stderr, "  [%s] ", prefix)
	fmt.Fprintf(os.Stderr, "%-35s ", label)
	red.Fprintf(os.Stderr, "error: %v\n", err)
}

func printDedup(unique int) {
	green.Fprintf(os.Stderr, "  ✓ ")
	fmt.Fprintf(os.Stderr, "%d unique file URLs discovered (after dedup)\n", unique)
}

// categoryOrder defines the display order of finding categories.
var categoryOrder = []FindingCategory{
	CategoryGPS,
	CategoryUser,
	CategoryEmail,
	CategorySoftware,
	CategoryPrinter,
	CategorySerial,
	CategoryPath,
	CategoryURL,
	CategoryHostname,
}

// dedupFinding groups a finding by its display value for dedup purposes.
type dedupFinding struct {
	value string
	files []string
	first Finding
}

// printFindings prints all findings grouped by category, with deduplication.
func printFindings(findings []Finding, showURLs bool) {
	// Group by category
	groups := make(map[FindingCategory][]Finding)
	for _, f := range findings {
		groups[f.Category] = append(groups[f.Category], f)
	}

	for _, cat := range categoryOrder {
		items, ok := groups[cat]
		if !ok || len(items) == 0 {
			continue
		}
		fmt.Fprintln(os.Stderr)
		bold.Fprintf(os.Stderr, "  %s\n", string(cat))

		if cat == CategoryGPS {
			// GPS findings are unique per location — show each with Maps link
			for _, f := range items {
				lat, lon := f.Details["Latitude"], f.Details["Longitude"]
				green.Fprintf(os.Stderr, "    ✓ ")
				fmt.Fprintf(os.Stderr, "%s, %s\n", lat, lon)
				if showURLs {
					dim.Fprintf(os.Stderr, "      %s\n", f.File)
				}
				cyan.Fprintf(os.Stderr, "      https://maps.google.com/?q=%s,%s\n", lat, lon)
			}
			continue
		}

		// Deduplicate by value — group files under the same finding
		deduped := dedupByValue(items)
		for _, d := range deduped {
			green.Fprintf(os.Stderr, "    ✓ ")
			fmt.Fprintln(os.Stderr, d.value)
			if showURLs {
				if len(d.files) == 1 {
					dim.Fprintf(os.Stderr, "      %s\n", d.files[0])
				} else {
					dim.Fprintf(os.Stderr, "      %s\n", d.files[0])
					dim.Fprintf(os.Stderr, "      ... and %d more files\n", len(d.files)-1)
				}
			}
		}
	}
}

func dedupByValue(items []Finding) []dedupFinding {
	seen := make(map[string]int) // value -> index in result
	var result []dedupFinding

	for _, f := range items {
		val := f.Details["Value"]
		key := strings.ToLower(val)
		if idx, ok := seen[key]; ok {
			result[idx].files = append(result[idx].files, f.File)
		} else {
			seen[key] = len(result)
			result = append(result, dedupFinding{
				value: val,
				files: []string{f.File},
				first: f,
			})
		}
	}
	return result
}

func printQuietFinding(f Finding) {
	val := f.Details["Value"]
	if f.Category == CategoryGPS {
		lat, lon := f.Details["Latitude"], f.Details["Longitude"]
		fmt.Printf("[%s] %s, %s https://maps.google.com/?q=%s,%s\n", f.Category, lat, lon, lat, lon)
		return
	}
	fmt.Printf("[%s] %s\n", f.Category, val)
}

func printReachability(reachable, total, errCount int) {
	green.Fprintf(os.Stderr, "  ✓ ")
	fmt.Fprintf(os.Stderr, "%d reachable", reachable)
	if errCount > 0 {
		dim.Fprintf(os.Stderr, ", %d offline", errCount)
	}
	fmt.Fprintf(os.Stderr, " (out of %d file URLs)\n", total)
}

func printSummary(analyzed, total, findingsCount int, categoryCounts map[FindingCategory]int) {
	printSection("Summary")
	fmt.Fprintf(os.Stderr, "  Files analyzed:  %d/%d\n", analyzed, total)
	fmt.Fprintf(os.Stderr, "  Findings:        %d\n", findingsCount)
	if len(categoryCounts) > 0 {
		for _, cat := range categoryOrder {
			if c, ok := categoryCounts[cat]; ok && c > 0 {
				fmt.Fprintf(os.Stderr, "    %-15s%d\n", string(cat)+":", c)
			}
		}
	}
	fmt.Fprintln(os.Stderr)
}

func logVerbose(format string, args ...interface{}) {
	dim.Fprintf(os.Stderr, "  [debug] "+format+"\n", args...)
}
