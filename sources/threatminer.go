package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func init() { Register(&ThreatMiner{}) }

// ThreatMiner discovers file URLs via the ThreatMiner API (free, no key needed).
// Uses report type 5 (URIs) which returns URLs associated with a domain.
type ThreatMiner struct{}

func (t *ThreatMiner) Name() string  { return "threatminer" }
func (t *ThreatMiner) Label() string { return "ThreatMiner" }

func (t *ThreatMiner) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiURL := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var result struct {
		StatusCode string   `json:"status_code"`
		Results    []string `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.StatusCode != "200" {
		return nil, nil
	}

	var urls []string
	for _, u := range result.Results {
		if u != "" {
			urls = append(urls, u)
		}
	}

	return urls, nil
}
