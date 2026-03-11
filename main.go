package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mmarting/exifray/sources"
)

func main() {
	// Suppress Go's default logger (noisy HTTP/2 frame messages)
	log.SetOutput(io.Discard)
	// --- Flag parsing (unwaf pattern) ---
	domain := flag.String("domain", "", "Target domain")
	flag.StringVar(domain, "d", "", "Target domain")

	list := flag.String("list", "", "File with list of domains")
	flag.StringVar(list, "l", "", "File with list of domains")

	workers := flag.Int("workers", 20, "Concurrent workers")
	flag.IntVar(workers, "w", 20, "Concurrent workers")

	timeout := flag.Int("timeout", 15, "HTTP timeout (seconds)")

	verbose := flag.Bool("verbose", false, "Verbose output")
	flag.BoolVar(verbose, "v", false, "Verbose output")

	quiet := flag.Bool("quiet", false, "Silent mode (findings only)")
	flag.BoolVar(quiet, "q", false, "Silent mode")

	jsonOutput := flag.Bool("json", false, "JSON output")

	output := flag.String("output", "", "Output file path")
	flag.StringVar(output, "o", "", "Output file path")

	proxy := flag.String("proxy", "", "HTTP/SOCKS5 proxy URL")

	rateLimit := flag.Float64("rate-limit", 0, "Max requests per second (0 = unlimited)")

	version := flag.Bool("version", false, "Print version")

	extensions := flag.String("extensions", "", "Custom file extensions (comma-separated)")
	flag.StringVar(extensions, "e", "", "Custom file extensions")

	showURLs := flag.Bool("show-urls", false, "Show source file URLs per finding")

	sourcesFlag := flag.String("sources", "all", "Sources to use (comma-separated)")
	flag.StringVar(sourcesFlag, "s", "all", "Sources to use")

	maxRetries := flag.Int("max-retries", 2, "Max retries on timeout")
	retryDelay := flag.Int("retry-delay", 2, "Retry delay in seconds")

	urlsFile := flag.String("urls", "", "File with list of URLs (skip discovery)")
	flag.StringVar(urlsFile, "u", "", "File with list of URLs (skip discovery)")

	configPath := flag.String("config", filepath.Join(os.Getenv("HOME"), ".exifray.conf"), "Config file path")
	flag.StringVar(configPath, "c", filepath.Join(os.Getenv("HOME"), ".exifray.conf"), "Config file path")

	flag.Usage = printUsage
	flag.Parse()

	// --- Version ---
	if *version {
		fmt.Printf("exifray v%s\n", Version)
		os.Exit(0)
	}

	// --- Collect domains ---
	var domains []string
	if *domain != "" {
		if d := cleanDomain(*domain); d != "" {
			domains = append(domains, d)
		}
	}
	if *list != "" {
		f, err := os.Open(*list)
		if err != nil {
			red.Fprintf(os.Stderr, "Error: cannot open list file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				if d := cleanDomain(line); d != "" {
					domains = append(domains, d)
				}
			}
		}
		f.Close()
	}

	// Read from stdin if piped
	if stat, _ := os.Stdin.Stat(); stat != nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				if d := cleanDomain(line); d != "" {
					domains = append(domains, d)
				}
			}
		}
	}

	// Dedup domains
	domains = dedupDomains(domains)

	if len(domains) == 0 && *urlsFile == "" {
		printUsage()
		os.Exit(1)
	}

	// --- Load API config ---
	apiCfg, err := loadAPIConfig(*configPath)
	if err != nil {
		apiCfg = &APIConfig{}
	}

	// Pass API keys to sources package
	keys := make(map[string]string)
	if apiCfg.VTAPIKey != "" {
		keys["vt_api_key"] = apiCfg.VTAPIKey
	}
	if apiCfg.URLScanAPIKey != "" {
		keys["urlscan_api_key"] = apiCfg.URLScanAPIKey
	}
	if apiCfg.OTXAPIKey != "" {
		keys["otx_api_key"] = apiCfg.OTXAPIKey
	}
	if apiCfg.GoogleAPIKey != "" {
		keys["google_api_key"] = apiCfg.GoogleAPIKey
	}
	if apiCfg.GoogleCX != "" {
		keys["google_cx"] = apiCfg.GoogleCX
	}
	sources.SetAPIKeys(keys)

	// --- Config ---
	exts := DefaultExtensions
	if *extensions != "" {
		exts = parseExtensions(*extensions)
	}

	cfg := &Config{
		Domains:    domains,
		Workers:    *workers,
		Timeout:    time.Duration(*timeout) * time.Second,
		MaxRetries: *maxRetries,
		RetryDelay: time.Duration(*retryDelay) * time.Second,
		Verbose:    *verbose,
		Quiet:      *quiet,
		JSON:       *jsonOutput,
		Output:     *output,
		Proxy:      *proxy,
		RateLimit:  *rateLimit,
		Extensions: exts,
		Sources:    strings.Split(*sourcesFlag, ","),
		ShowURLs:   *showURLs,
		URLsFile:   *urlsFile,
	}

	// --- Context with signal handling ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		cancel()
	}()

	// --- Banner ---
	if !cfg.Quiet && !cfg.JSON {
		printBanner()
	}

	// --- HTTP client ---
	client := newHTTPClient(cfg)

	// --- Process ---
	if cfg.URLsFile != "" {
		urls := readURLsFromFile(cfg.URLsFile)
		if len(urls) == 0 {
			red.Fprintf(os.Stderr, "Error: no valid URLs found in %s\n", cfg.URLsFile)
			os.Exit(1)
		}
		processURLs(ctx, cfg, urls, client)
	} else {
		for _, d := range cfg.Domains {
			processDomain(ctx, cfg, d, client)
		}
	}
}

func processDomain(ctx context.Context, cfg *Config, domain string, client *http.Client) {
	// Filter sources
	sourceNames := cfg.Sources
	enabledSources := sources.FilterByName(sourceNames)
	allSources := sources.All()

	// --- Discovery ---
	if !cfg.Quiet && !cfg.JSON {
		printSection("Discovery")
	}

	var allURLs []string
	var sourceResults []SourceResult

	for i, src := range allSources {
		if ctx.Err() != nil {
			break
		}

		enabled := sources.IsEnabled(src.Name(), enabledSources)

		if !enabled {
			if !cfg.Quiet && !cfg.JSON {
				printSourceResult(i+1, len(allSources), src.Label(), 0, 0, true)
			}
			sourceResults = append(sourceResults, SourceResult{
				Name:  src.Name(),
				Label: src.Label(),
				Count: 0,
			})
			continue
		}

		if cfg.Verbose {
			logVerbose("querying %s...", src.Label())
		}

		var urls []string
		var err error
		retries := 0
		// Discovery sources get 3x timeout — APIs like crt.sh and Wayback
		// return large responses that need more time than file downloads.
		discoverTimeout := cfg.Timeout * 3
		for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
			dctx, dcancel := context.WithTimeout(ctx, discoverTimeout)
			urls, err = src.Discover(dctx, domain, client)
			dcancel()
			if err == nil {
				break
			}
			// Don't retry config errors or non-retryable errors
			if _, ok := err.(*sources.ErrNeedsConfig); ok || !isRetryableError(err.Error()) {
				break
			}
			if attempt < cfg.MaxRetries {
				retries++
				if !cfg.Quiet && !cfg.JSON {
					dim.Fprintf(os.Stderr, "  [retry] %s failed (%v), waiting %ds...\n", src.Name(), err, int(cfg.RetryDelay.Seconds())*retries)
				}
				time.Sleep(cfg.RetryDelay * time.Duration(attempt+1))
			}
		}
		_ = retries
		if err != nil {
			// Check if source just needs API configuration (not a real error)
			if needsCfg, ok := err.(*sources.ErrNeedsConfig); ok {
				if !cfg.Quiet && !cfg.JSON {
					printSourceSkip(i+1, len(allSources), src.Label(), needsCfg.Hint)
				}
			} else {
				if !cfg.Quiet && !cfg.JSON {
					printSourceError(i+1, len(allSources), src.Label(), err)
				}
				if cfg.Verbose {
					logVerbose("%s error: %v", src.Name(), err)
				}
			}
			sourceResults = append(sourceResults, SourceResult{
				Name:  src.Name(),
				Label: src.Label(),
				Count: 0,
				Err:   err,
			})
			continue
		}

		fileURLs := filterByExtension(urls, cfg.Extensions)
		if !cfg.Quiet && !cfg.JSON {
			printSourceResult(i+1, len(allSources), src.Label(), len(urls), len(fileURLs), false)
		}

		allURLs = append(allURLs, urls...)
		sourceResults = append(sourceResults, SourceResult{
			Name:  src.Name(),
			Label: src.Label(),
			Count: len(fileURLs),
		})
	}

	// --- Dedup & filter ---
	uniqueURLs := dedup(allURLs)
	filteredURLs := filterByExtension(uniqueURLs, cfg.Extensions)

	if !cfg.Quiet && !cfg.JSON {
		printDedup(len(filteredURLs))
	}

	if len(filteredURLs) == 0 {
		if !cfg.Quiet && !cfg.JSON {
			dim.Fprintln(os.Stderr, "  No files to analyze.")
		}
		outputResults(cfg, domain, sourceResults, filteredURLs, nil, nil)
		outputToFile(cfg, domain, sourceResults, filteredURLs, nil, nil)
		return
	}

	// --- Metadata extraction ---
	if !cfg.Quiet && !cfg.JSON {
		printSection("Metadata Extraction")
		fmt.Fprintf(os.Stderr, "  Processing %d file URLs...\n", len(filteredURLs))
	}

	var bar ProgressBar
	if !cfg.Quiet && !cfg.JSON {
		bar = newProgressBar(len(filteredURLs), "  ")
	} else {
		bar = newNoopBar()
	}

	results := extractAll(ctx, filteredURLs, client, cfg.Workers, cfg.Timeout, cfg.MaxRetries, cfg.RetryDelay, bar)
	bar.Finish()

	// Count reachable vs failed
	reachable := 0
	for _, r := range results {
		if r.Error == "" {
			reachable++
		}
	}
	offline := len(filteredURLs) - reachable

	if !cfg.Quiet && !cfg.JSON {
		printReachability(reachable, len(filteredURLs), offline)
	}

	// --- Analyze ---
	findings := analyzeFindings(results)

	// --- Output ---
	outputResults(cfg, domain, sourceResults, filteredURLs, results, findings)

	// --- File output ---
	if err := outputToFile(cfg, domain, sourceResults, filteredURLs, results, findings); err != nil {
		red.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

// extractAll runs metadata extraction concurrently using a worker pool.
func extractAll(ctx context.Context, urls []string, client *http.Client, workers int, timeout time.Duration, maxRetries int, retryDelay time.Duration, bar ProgressBar) []MetadataResult {
	results := make([]MetadataResult, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for i, u := range urls {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, fileURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			results[idx] = extractMetadata(fileURL, client, timeout, maxRetries, retryDelay)
			bar.Add(1)
		}(i, u)
	}

	wg.Wait()
	return results
}

// dedup removes duplicate URLs.
func dedup(urls []string) []string {
	seen := make(map[string]bool, len(urls))
	var unique []string
	for _, u := range urls {
		normalized := strings.TrimRight(u, "/")
		if !seen[normalized] {
			seen[normalized] = true
			unique = append(unique, u)
		}
	}
	return unique
}

// filterByExtension keeps only URLs with matching file extensions.
func filterByExtension(urls []string, exts []string) []string {
	extSet := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = strings.ToLower(e)
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		extSet[e] = true
	}

	var filtered []string
	for _, u := range urls {
		ext := strings.ToLower(filepath.Ext(urlPath(u)))
		if extSet[ext] {
			filtered = append(filtered, u)
		}
	}
	return filtered
}

// cleanDomain extracts a hostname from various input formats:
// example.com, http://example.com, https://example.com:8080/path?q=1,
// *.example.com, sub.example.com, HTTP://EXAMPLE.COM, etc.
func cleanDomain(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}

	// Lowercase for consistency
	d = strings.ToLower(d)

	// Strip protocol
	if strings.HasPrefix(d, "http://") || strings.HasPrefix(d, "https://") {
		// Remove everything up to ://
		d = d[strings.Index(d, "://")+3:]
	}

	// Strip userinfo (user:pass@host)
	if at := strings.Index(d, "@"); at != -1 {
		d = d[at+1:]
	}

	// Strip path, query, fragment
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(d, sep); idx != -1 {
			d = d[:idx]
		}
	}

	// Strip port
	if idx := strings.LastIndex(d, ":"); idx != -1 {
		d = d[:idx]
	}

	// Strip wildcard prefix
	d = strings.TrimPrefix(d, "*.")

	// Strip trailing dots
	d = strings.TrimRight(d, ".")

	return d
}


// dedupDomains removes duplicate domains preserving order.
func dedupDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	var unique []string
	for _, d := range domains {
		lower := strings.ToLower(d)
		if !seen[lower] {
			seen[lower] = true
			unique = append(unique, d)
		}
	}
	return unique
}

// readURLsFromFile reads URLs from a file, one per line.
func readURLsFromFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		red.Fprintf(os.Stderr, "Error: cannot open URLs file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return dedup(urls)
}

// processURLs handles direct URL input mode (skips discovery).
func processURLs(ctx context.Context, cfg *Config, urls []string, client *http.Client) {
	// Filter by extension
	filteredURLs := filterByExtension(urls, cfg.Extensions)
	if len(filteredURLs) == 0 {
		// If no extension filter matches, use all URLs as-is
		filteredURLs = urls
	}

	label := "direct-urls"
	if len(filteredURLs) > 0 {
		// Derive domain label from first URL for output
		parts := strings.SplitN(filteredURLs[0], "/", 4)
		if len(parts) >= 3 {
			label = strings.TrimPrefix(strings.TrimPrefix(parts[2], "www."), ":")
			// Strip port if present
			if idx := strings.LastIndex(label, ":"); idx != -1 {
				label = label[:idx]
			}
		}
	}

	if !cfg.Quiet && !cfg.JSON {
		printSection("Metadata Extraction")
		fmt.Fprintf(os.Stderr, "  Processing %d URLs (direct mode)...\n", len(filteredURLs))
	}

	var bar ProgressBar
	if !cfg.Quiet && !cfg.JSON {
		bar = newProgressBar(len(filteredURLs), "  ")
	} else {
		bar = newNoopBar()
	}

	results := extractAll(ctx, filteredURLs, client, cfg.Workers, cfg.Timeout, cfg.MaxRetries, cfg.RetryDelay, bar)
	bar.Finish()

	// Count reachable vs failed
	reachable := 0
	for _, r := range results {
		if r.Error == "" {
			reachable++
		}
	}
	offline := len(filteredURLs) - reachable

	if !cfg.Quiet && !cfg.JSON {
		printReachability(reachable, len(filteredURLs), offline)
	}

	findings := analyzeFindings(results)

	outputResults(cfg, label, nil, filteredURLs, results, findings)
	if err := outputToFile(cfg, label, nil, filteredURLs, results, findings); err != nil {
		red.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

// parseExtensions splits a comma-separated extension string.
func parseExtensions(s string) []string {
	parts := strings.Split(s, ",")
	var exts []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			if !strings.HasPrefix(p, ".") {
				p = "." + p
			}
			exts = append(exts, p)
		}
	}
	return exts
}
