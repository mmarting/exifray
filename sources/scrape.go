package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

func init() { Register(&Scrape{}) }

// Scrape discovers file URLs by crawling the target site's HTML.
type Scrape struct{}

func (s *Scrape) Name() string  { return "scrape" }
func (s *Scrape) Label() string { return "Web Scraping" }

func (s *Scrape) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	baseURL := fmt.Sprintf("https://%s", domain)
	urls, err := s.crawlPage(ctx, baseURL, domain, client)
	if err != nil {
		// Try HTTP if HTTPS fails
		baseURL = fmt.Sprintf("http://%s", domain)
		urls, err = s.crawlPage(ctx, baseURL, domain, client)
		if err != nil {
			return nil, err
		}
	}
	return urls, nil
}

func (s *Scrape) crawlPage(ctx context.Context, pageURL, domain string, client *http.Client) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, 5*1024*1024)
	return s.extractURLs(body, pageURL, domain)
}

func (s *Scrape) extractURLs(r io.Reader, baseURLStr, domain string) ([]string, error) {
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, err
	}

	tokenizer := html.NewTokenizer(r)
	seen := make(map[string]bool)
	var urls []string

	// Attributes that may contain URLs
	urlAttrs := map[string][]string{
		"a":      {"href"},
		"img":    {"src"},
		"link":   {"href"},
		"embed":  {"src"},
		"object": {"data"},
		"source": {"src"},
		"video":  {"src"},
		"audio":  {"src"},
	}

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		t := tokenizer.Token()
		tagName := strings.ToLower(t.Data)

		attrs, ok := urlAttrs[tagName]
		if !ok {
			continue
		}

		for _, attr := range attrs {
			for _, a := range t.Attr {
				if strings.ToLower(a.Key) != attr {
					continue
				}
				val := strings.TrimSpace(a.Val)
				if val == "" || strings.HasPrefix(val, "javascript:") || strings.HasPrefix(val, "mailto:") || val == "#" {
					continue
				}

				resolved := resolveURL(baseURL, val)
				if resolved != "" && !seen[resolved] {
					seen[resolved] = true
					urls = append(urls, resolved)
				}
			}
		}
	}

	return urls, nil
}

func resolveURL(base *url.URL, rawURL string) string {
	ref, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	// Strip fragment
	resolved.Fragment = ""
	return resolved.String()
}
