package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func init() { Register(&VirusTotal{}) }

// VirusTotal discovers file URLs via the VirusTotal API.
// Requires VT_API_KEY environment variable.
type VirusTotal struct{}

func (v *VirusTotal) Name() string  { return "virustotal" }
func (v *VirusTotal) Label() string { return "VirusTotal" }

func (v *VirusTotal) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiKey := GetAPIKey("vt_api_key")
	if apiKey == "" {
		return nil, &ErrNeedsConfig{Hint: "requires API key — see ~/.exifray.conf"}
	}

	var allURLs []string
	cursor := ""

	for i := 0; i < 10; i++ { // max 10 pages
		if ctx.Err() != nil {
			break
		}

		apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/urls?limit=40", domain)
		if cursor != "" {
			apiURL += "&cursor=" + cursor
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return allURLs, err
		}
		req.Header.Set("x-apikey", apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return allURLs, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return allURLs, fmt.Errorf("invalid API key (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode == 429 {
			return allURLs, fmt.Errorf("rate limited (HTTP 429)")
		}
		if resp.StatusCode != http.StatusOK {
			return allURLs, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		if err != nil {
			return allURLs, err
		}

		var result struct {
			Data []struct {
				Attributes struct {
					URL string `json:"url"`
				} `json:"attributes"`
			} `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
			Meta struct {
				Cursor string `json:"cursor"`
			} `json:"meta"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			return allURLs, err
		}

		for _, d := range result.Data {
			if d.Attributes.URL != "" {
				allURLs = append(allURLs, d.Attributes.URL)
			}
		}

		if result.Meta.Cursor == "" || len(result.Data) == 0 {
			break
		}
		cursor = result.Meta.Cursor
	}

	return allURLs, nil
}
