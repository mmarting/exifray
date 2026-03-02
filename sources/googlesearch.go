package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func init() { Register(&GoogleSearch{}) }

// GoogleSearch discovers file URLs via Google Custom Search API.
// Requires google_api_key and google_cx in ~/.exifray.conf.
type GoogleSearch struct{}

func (g *GoogleSearch) Name() string  { return "google" }
func (g *GoogleSearch) Label() string { return "Google Search" }

func (g *GoogleSearch) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	apiKey := GetAPIKey("google_api_key")
	cx := GetAPIKey("google_cx")
	if apiKey == "" || cx == "" {
		return nil, &ErrNeedsConfig{Hint: "requires API key — see ~/.exifray.conf"}
	}

	// File type queries to find documents
	fileTypes := []string{
		"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
	}

	var allURLs []string
	seen := make(map[string]bool)

	for _, ft := range fileTypes {
		if ctx.Err() != nil {
			break
		}

		query := fmt.Sprintf("site:%s filetype:%s", domain, ft)
		urls, err := g.search(ctx, client, apiKey, cx, query)
		if err != nil {
			continue
		}
		for _, u := range urls {
			if !seen[u] {
				seen[u] = true
				allURLs = append(allURLs, u)
			}
		}
	}

	return allURLs, nil
}

func (g *GoogleSearch) search(ctx context.Context, client *http.Client, apiKey, cx, query string) ([]string, error) {
	var allURLs []string

	// Paginate through results (max 100 results = 10 pages of 10)
	for start := 1; start <= 91; start += 10 {
		if ctx.Err() != nil {
			break
		}

		apiURL := fmt.Sprintf(
			"https://www.googleapis.com/customsearch/v1?key=%s&cx=%s&q=%s&start=%d&num=10",
			url.QueryEscape(apiKey), url.QueryEscape(cx), url.QueryEscape(query), start,
		)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return allURLs, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return allURLs, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			return allURLs, fmt.Errorf("rate limited")
		}
		if resp.StatusCode != http.StatusOK {
			return allURLs, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			return allURLs, err
		}

		var result struct {
			Items []struct {
				Link string `json:"link"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return allURLs, err
		}

		for _, item := range result.Items {
			if item.Link != "" {
				allURLs = append(allURLs, item.Link)
			}
		}

		// No more results
		if len(result.Items) < 10 {
			break
		}
	}

	return allURLs, nil
}
