package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// outputResults handles text or JSON output to stdout/file.
func outputResults(cfg *Config, domain string, sourceResults []SourceResult, uniqueURLs []string, metadata []MetadataResult, findings []Finding) {
	analyzed := 0
	for _, m := range metadata {
		if m.Error == "" {
			analyzed++
		}
	}

	if cfg.JSON {
		outputJSON(cfg, domain, sourceResults, uniqueURLs, metadata, findings, analyzed)
		return
	}

	// Deduplicate findings for display
	uniqueFindings := dedupFindingsGlobal(findings)

	if cfg.Quiet {
		outputQuiet(uniqueFindings)
		return
	}

	// Text output: findings + summary to stderr
	printSection("Findings")
	if len(uniqueFindings) == 0 {
		dim.Fprintln(os.Stderr, "  No interesting findings.")
	} else {
		printFindings(findings, cfg.ShowURLs)
	}

	categoryCounts := countCategories(uniqueFindings)
	printSummary(analyzed, len(uniqueURLs), len(uniqueFindings), categoryCounts)
}

func outputJSON(cfg *Config, domain string, sourceResults []SourceResult, uniqueURLs []string, metadata []MetadataResult, findings []Finding, analyzed int) {
	sourceCounts := make(map[string]int)
	for _, sr := range sourceResults {
		sourceCounts[sr.Name] = sr.Count
	}

	// Filter metadata to only include entries with data
	var metaWithData []MetadataResult
	for _, m := range metadata {
		if m.Error == "" && len(m.Fields) > 0 {
			metaWithData = append(metaWithData, m)
		}
	}
	if metaWithData == nil {
		metaWithData = []MetadataResult{}
	}
	if findings == nil {
		findings = []Finding{}
	}

	output := JSONOutput{
		Version:        Version,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Domain:         domain,
		URLsDiscovered: len(uniqueURLs),
		FilesAnalyzed:  analyzed,
		Findings:       findings,
		Metadata:       metaWithData,
		Sources:        sourceCounts,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}

func outputQuiet(findings []Finding) {
	for _, f := range findings {
		printQuietFinding(f)
	}
}

// dedupFindingsGlobal collapses findings by (category, value), keeping one per unique pair.
func dedupFindingsGlobal(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding
	for _, f := range findings {
		var key string
		if f.Category == CategoryGPS {
			key = string(f.Category) + "|" + f.Details["Latitude"] + "," + f.Details["Longitude"]
		} else {
			key = string(f.Category) + "|" + strings.ToLower(f.Details["Value"])
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}

// writeToFile writes content to the output file.
func writeToFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func countCategories(findings []Finding) map[FindingCategory]int {
	counts := make(map[FindingCategory]int)
	for _, f := range findings {
		counts[f.Category]++
	}
	return counts
}

// outputToFile handles writing to --output file if specified.
func outputToFile(cfg *Config, domain string, sourceResults []SourceResult, uniqueURLs []string, metadata []MetadataResult, findings []Finding) error {
	if cfg.Output == "" {
		return nil
	}

	analyzed := 0
	for _, m := range metadata {
		if m.Error == "" {
			analyzed++
		}
	}

	sourceCounts := make(map[string]int)
	for _, sr := range sourceResults {
		sourceCounts[sr.Name] = sr.Count
	}

	var metaWithData []MetadataResult
	for _, m := range metadata {
		if m.Error == "" && len(m.Fields) > 0 {
			metaWithData = append(metaWithData, m)
		}
	}
	if metaWithData == nil {
		metaWithData = []MetadataResult{}
	}
	if findings == nil {
		findings = []Finding{}
	}

	output := JSONOutput{
		Version:        Version,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Domain:         domain,
		URLsDiscovered: len(uniqueURLs),
		FilesAnalyzed:  analyzed,
		Findings:       findings,
		Metadata:       metaWithData,
		Sources:        sourceCounts,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := writeToFile(cfg.Output, data); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	dim.Fprintf(os.Stderr, "  Results written to %s\n", cfg.Output)
	return nil
}
