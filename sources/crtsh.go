package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() { Register(&CrtSh{}) }

// CrtSh discovers subdomains via crt.sh (Certificate Transparency logs)
// and then probes each for files. It returns URLs built from discovered subdomains.
type CrtSh struct{}

func (c *CrtSh) Name() string  { return "crtsh" }
func (c *CrtSh) Label() string { return "crt.sh (CT Logs)" }

func (c *CrtSh) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	var records []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}

	// Deduplicate subdomains
	seen := make(map[string]bool)
	var subdomains []string
	for _, r := range records {
		// name_value can contain multiple names separated by newlines
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			// Only include subdomains of the target domain
			if name == domain || strings.HasSuffix(name, "."+domain) {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	// Build base URLs for each subdomain — the scrape source can handle the actual crawl
	// We return the root URLs which can be checked for file links
	var urls []string
	for _, sub := range subdomains {
		urls = append(urls, fmt.Sprintf("https://%s/", sub))
	}

	return urls, nil
}
