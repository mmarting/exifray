package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

// browserTransport routes HTTPS through HTTP/2 (with Chrome TLS fingerprint)
// and falls back to HTTP/1.1 when h2 is unavailable. Plain HTTP uses h1.
type browserTransport struct {
	h2 *http2.Transport
	h1 *http.Transport
}

func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		resp, err := t.h2.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// h2 failed, fall back to h1
		return t.h1.RoundTrip(req)
	}
	return t.h1.RoundTrip(req)
}

// utlsDialTLS returns a dial function that performs a TLS handshake using
// uTLS with Chrome's fingerprint. When forceH1 is true, only http/1.1 is
// offered in ALPN (used for h1 fallback).
func utlsDialTLS(tcpDial func(ctx context.Context, network, addr string) (net.Conn, error), forceH1 bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		tcpConn, err := tcpDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		config := &utls.Config{
			ServerName: host,
		}
		if forceH1 {
			config.NextProtos = []string{"http/1.1"}
		}

		tlsConn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// newHTTPClient creates an http.Client with uTLS fingerprinting, optional proxy, and rate limiting.
func newHTTPClient(cfg *Config) *http.Client {
	dialer := &net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: 30 * time.Second,
	}

	tcpDial := dialer.DialContext
	var useHTTPProxy bool

	h1Transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err == nil {
			useHTTPProxy = true
			h1Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	h1Transport.DialContext = tcpDial
	h1Transport.DialTLSContext = utlsDialTLS(tcpDial, true) // h1-only ALPN for fallback

	var transport http.RoundTripper
	if useHTTPProxy {
		transport = h1Transport
	} else {
		h2DialTLS := utlsDialTLS(tcpDial, false)
		h2Transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return h2DialTLS(ctx, network, addr)
			},
		}
		transport = &browserTransport{h2: h2Transport, h1: h1Transport}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	if cfg.RateLimit > 0 {
		client.Transport = &rateLimitedTransport{
			base:    client.Transport,
			limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
		}
	}

	return client
}

type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter *rate.Limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}
