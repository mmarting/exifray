package sources

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func init() { Register(&Sitemap{}) }

// Sitemap discovers file URLs by parsing sitemap.xml files.
type Sitemap struct{}

func (s *Sitemap) Name() string  { return "sitemap" }
func (s *Sitemap) Label() string { return "Sitemap" }

func (s *Sitemap) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	seen := make(map[string]bool)
	var allURLs []string

	// Common sitemap locations
	paths := []string{
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/sitemaps.xml",
		"/sitemap1.xml",
		"/wp-sitemap.xml",
		"/sitemap/sitemap.xml",
	}

	// Also check robots.txt for Sitemap directives
	robotsSitemaps := s.parseSitemapsFromRobots(ctx, domain, client)
	for _, sm := range robotsSitemaps {
		paths = append(paths, sm)
	}

	for _, p := range paths {
		if ctx.Err() != nil {
			break
		}

		var sitemapURL string
		if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
			sitemapURL = p
		} else {
			sitemapURL = fmt.Sprintf("https://%s%s", domain, p)
		}

		if seen[sitemapURL] {
			continue
		}
		seen[sitemapURL] = true

		urls, nested := s.fetchSitemap(ctx, sitemapURL, client)
		allURLs = append(allURLs, urls...)

		// Follow nested sitemaps (one level deep)
		for _, nestedURL := range nested {
			if ctx.Err() != nil {
				break
			}
			if seen[nestedURL] {
				continue
			}
			seen[nestedURL] = true
			nestedURLs, _ := s.fetchSitemap(ctx, nestedURL, client)
			allURLs = append(allURLs, nestedURLs...)
		}
	}

	return allURLs, nil
}

type sitemapURLSet struct {
	URLs []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc string `xml:"loc"`
}

type sitemapIndex struct {
	Sitemaps []sitemapEntry `xml:"sitemap"`
}

type sitemapEntry struct {
	Loc string `xml:"loc"`
}

// fetchSitemap fetches and parses a sitemap, returning file URLs and nested sitemap URLs.
func (s *Sitemap) fetchSitemap(ctx context.Context, sitemapURL string, client *http.Client) (urls []string, nested []string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return
	}

	// Try as sitemap index first
	var idx sitemapIndex
	if err := xml.Unmarshal(data, &idx); err == nil && len(idx.Sitemaps) > 0 {
		for _, sm := range idx.Sitemaps {
			if sm.Loc != "" {
				nested = append(nested, sm.Loc)
			}
		}
		return
	}

	// Try as URL set
	var urlset sitemapURLSet
	if err := xml.Unmarshal(data, &urlset); err == nil {
		for _, u := range urlset.URLs {
			if u.Loc != "" {
				urls = append(urls, u.Loc)
			}
		}
		return
	}

	// Fallback: scan for <loc> tags manually
	content := string(data)
	for {
		idx := strings.Index(content, "<loc>")
		if idx == -1 {
			break
		}
		content = content[idx+5:]
		end := strings.Index(content, "</loc>")
		if end == -1 {
			break
		}
		loc := strings.TrimSpace(content[:end])
		if loc != "" {
			if strings.HasSuffix(loc, ".xml") || strings.HasSuffix(loc, ".xml.gz") {
				nested = append(nested, loc)
			} else {
				urls = append(urls, loc)
			}
		}
		content = content[end+6:]
	}

	return
}

func (s *Sitemap) parseSitemapsFromRobots(ctx context.Context, domain string, client *http.Client) []string {
	robotsURL := fmt.Sprintf("https://%s/robots.txt", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; exifray/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil
	}

	var sitemaps []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "sitemap:") {
			sm := strings.TrimSpace(line[8:])
			if sm != "" {
				sitemaps = append(sitemaps, sm)
			}
		}
	}
	return sitemaps
}
