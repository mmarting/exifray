package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// APIConfig holds API keys loaded from the config file.
type APIConfig struct {
	VTAPIKey      string
	URLScanAPIKey string
	OTXAPIKey     string
	GoogleAPIKey  string
	GoogleCX      string
}

var apiKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-:]+$`)

const defaultConfigTemplate = `# Exifray config file — API keys for optional sources
# Free sources (wayback, commoncrawl, otx, scrape, sitemap, hackertarget, crtsh) work without any keys.

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
`

func loadAPIConfig(path string) (*APIConfig, error) {
	// Create default config if it doesn't exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := createDefaultConfig(path); err != nil {
			return &APIConfig{}, nil
		}
		return &APIConfig{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	config := &APIConfig{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		value = strings.Trim(value, `"`)

		if value == "" || !apiKeyRegex.MatchString(value) {
			continue
		}

		switch key {
		case "vt_api_key":
			config.VTAPIKey = value
		case "urlscan_api_key":
			config.URLScanAPIKey = value
		case "otx_api_key":
			config.OTXAPIKey = value
		case "google_api_key":
			config.GoogleAPIKey = value
		case "google_cx":
			config.GoogleCX = value
		}
	}

	return config, scanner.Err()
}

func createDefaultConfig(path string) error {
	if err := os.WriteFile(path, []byte(defaultConfigTemplate), 0600); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	return nil
}
