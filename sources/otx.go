package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func init() { Register(&OTX{}) }

// OTX discovers file URLs via AlienVault OTX.
type OTX struct{}

func (o *OTX) Name() string  { return "otx" }
func (o *OTX) Label() string { return "AlienVault OTX" }

func (o *OTX) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	var allURLs []string
	page := 1

	for {
		apiURL := fmt.Sprintf(
			"https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=200&page=%d",
			domain, page,
		)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return allURLs, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")
		if apiKey := GetAPIKey("otx_api_key"); apiKey != "" {
			req.Header.Set("X-OTX-API-KEY", apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			return allURLs, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return allURLs, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		if err != nil {
			return allURLs, err
		}

		var result struct {
			URLList []struct {
				URL string `json:"url"`
			} `json:"url_list"`
			HasNext bool `json:"has_next"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return allURLs, err
		}

		for _, entry := range result.URLList {
			if entry.URL != "" {
				allURLs = append(allURLs, entry.URL)
			}
		}

		if !result.HasNext || len(result.URLList) == 0 {
			break
		}
		page++
		if page > 10 { // safety limit
			break
		}
	}

	return allURLs, nil
}
