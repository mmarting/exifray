package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func init() { Register(&URLScan{}) }

// URLScan discovers file URLs via urlscan.io.
type URLScan struct{}

func (u *URLScan) Name() string  { return "urlscan" }
func (u *URLScan) Label() string { return "URLScan.io" }

func (u *URLScan) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiURL := fmt.Sprintf(
		"https://urlscan.io/api/v1/search/?q=domain:%s&size=1000",
		url.QueryEscape(domain),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")
	if apiKey := GetAPIKey("urlscan_api_key"); apiKey != "" {
		req.Header.Set("API-Key", apiKey)
	}

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

	var result struct {
		Results []struct {
			Page struct {
				URL string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var urls []string
	seen := make(map[string]bool)
	for _, r := range result.Results {
		u := r.Page.URL
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls, nil
}
