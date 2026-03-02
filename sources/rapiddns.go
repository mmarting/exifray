package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

func init() { Register(&RapidDNS{}) }

// RapidDNS discovers subdomains via rapiddns.io (free, no key needed).
// Returns root URLs for discovered subdomains.
type RapidDNS struct{}

func (r *RapidDNS) Name() string  { return "rapiddns" }
func (r *RapidDNS) Label() string { return "RapidDNS" }

var subdomainRegex = regexp.MustCompile(`(?i)([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}`)

func (r *RapidDNS) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)

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

	content := string(body)

	// Extract subdomains from the HTML table
	seen := make(map[string]bool)
	var urls []string

	matches := subdomainRegex.FindAllString(content, -1)
	for _, match := range matches {
		match = strings.ToLower(match)
		if !strings.HasSuffix(match, "."+domain) && match != domain {
			continue
		}
		if seen[match] {
			continue
		}
		seen[match] = true
		urls = append(urls, fmt.Sprintf("https://%s/", match))
	}

	return urls, nil
}
