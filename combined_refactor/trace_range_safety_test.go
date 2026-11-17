package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const mockCloudflareRanges = `{"success":true,"result":{"ipv4_cidrs":["1.1.1.0/24"],"ipv6_cidrs":["2606:4700::/32"]}}`

func TestCloudflareRangeLoaderFallsBackToOfficialAPIOnHTTP503(t *testing.T) {
	var apiCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ips-v4":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/ips-v6":
			_, _ = w.Write([]byte("2606:4700::/32\n"))
		case "/api/ips":
			apiCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mockCloudflareRanges))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	prefixes, err := loadCloudflareExclusionPrefixesFrom(t.Context(), server.Client(), server.URL+"/ips-v4", server.URL+"/ips-v6", server.URL+"/api/ips")
	if err != nil {
		t.Fatalf("official API fallback failed: %v", err)
	}
	if !apiCalled.Load() || len(prefixes) != 2 {
		t.Fatalf("API called=%v, prefixes=%v; want successful official fallback with both families", apiCalled.Load(), prefixes)
	}
	if err := validateCloudflareExclusionPrefixes(prefixes); err != nil {
		t.Fatalf("fallback ranges did not pass complete-list validation: %v", err)
	}
}

func TestCloudflareRangeLoaderFallsBackWhenTextListIsMalformed(t *testing.T) {
	var apiCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ips-v4":
			_, _ = w.Write([]byte("not-a-cidr\n"))
		case "/ips-v6":
			_, _ = w.Write([]byte("2606:4700::/32\n"))
		case "/api/ips":
			apiCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mockCloudflareRanges))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	prefixes, err := loadCloudflareExclusionPrefixesFrom(t.Context(), server.Client(), server.URL+"/ips-v4", server.URL+"/ips-v6", server.URL+"/api/ips")
	if err != nil || !apiCalled.Load() || len(prefixes) != 2 {
		t.Fatalf("malformed text did not fall back safely: prefixes=%v API-called=%v err=%v", prefixes, apiCalled.Load(), err)
	}
}

func TestCloudflareRangeLoaderFailsClosedWhenSourcesAreUnavailableOrMalformed(t *testing.T) {
	cases := []struct {
		name      string
		apiStatus int
		apiBody   string
		wantError string
	}{
		{name: "both HTTP 503", apiStatus: http.StatusServiceUnavailable, apiBody: `{"success":false}`, wantError: "HTTP 503"},
		{name: "malformed API JSON", apiStatus: http.StatusOK, apiBody: `{not-json`, wantError: "JSON 格式无效"},
		{name: "missing IPv6 family", apiStatus: http.StatusOK, apiBody: `{"success":true,"result":{"ipv4_cidrs":["1.1.1.0/24"],"ipv6_cidrs":[]}}`, wantError: "IPv4 或 IPv6 清单为空"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/ips" {
					w.WriteHeader(tc.apiStatus)
					_, _ = w.Write([]byte(tc.apiBody))
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()

			prefixes, err := loadCloudflareExclusionPrefixesFrom(t.Context(), server.Client(), server.URL+"/ips-v4", server.URL+"/ips-v6", server.URL+"/api/ips")
			if err == nil || len(prefixes) != 0 {
				t.Fatalf("untrustworthy sources returned prefixes=%v err=%v; want no prefixes and fail closed", prefixes, err)
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error %q does not include diagnostic %q", err, tc.wantError)
			}
		})
	}
}

func TestTraceCheckPreflightRequiresCompleteTrustedRanges(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []netip.Prefix
		err      error
		wantCode int
	}{
		{name: "unavailable", err: fmt.Errorf("mock official sources unavailable"), wantCode: http.StatusServiceUnavailable},
		{name: "missing IPv6", prefixes: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}, wantCode: http.StatusServiceUnavailable},
		{name: "complete", prefixes: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("2606:4700::/32")}, wantCode: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/trace-check/preflight", strings.NewReader(`{}`))
			req.Host = "checker.example"
			req.Header.Set("Origin", "https://checker.example")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handleTraceCheckPreflightWithLoader(rec, req, func(context.Context) ([]netip.Prefix, error) {
				return tc.prefixes, tc.err
			})
			if rec.Code != tc.wantCode {
				t.Fatalf("preflight status=%d want=%d body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantCode == http.StatusOK && !strings.Contains(rec.Body.String(), `"ready":true`) {
				t.Fatalf("successful preflight omitted ready flag: %s", rec.Body.String())
			}
		})
	}
}

func TestFourConcurrentTraceChecksCanceledDuringRangeLoadNeverCallScanner(t *testing.T) {
	const workers = 4
	started := make(chan struct{}, workers)
	cancels := make([]context.CancelFunc, 0, workers)
	var scans atomic.Int32
	var group sync.WaitGroup
	responses := make([]*httptest.ResponseRecorder, workers)

	loader := func(ctx context.Context) ([]netip.Prefix, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	parseFixture := func(value string) (traceCandidate, error) {
		return traceCandidate{Address: netip.MustParseAddr("203.0.113.7"), Port: 443, Canonical: value}, nil
	}
	scanner := func(context.Context, traceCandidate, string) traceCheckResult {
		scans.Add(1)
		return traceCheckResult{OK: true}
	}

	for i := 0; i < workers; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/trace-check", strings.NewReader(`{"domain":"example.com","candidates":["203.0.113.7:443"]}`))
		req.Host = "checker.example"
		req.Header.Set("Origin", "https://checker.example")
		req.Header.Set("Content-Type", "application/json")
		responses[i] = httptest.NewRecorder()
		group.Add(1)
		go func(i int, req *http.Request) {
			defer group.Done()
			handleTraceCheckWithDeps(responses[i], req, loader, parseFixture, scanner)
		}(i, req)
	}

	for i := 0; i < workers; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			for _, cancel := range cancels {
				cancel()
			}
			t.Fatal("not all four requests reached the range-list loader")
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	group.Wait()

	for i, response := range responses {
		if response.Code != http.StatusServiceUnavailable {
			t.Errorf("worker %d status=%d want 503; body=%s", i, response.Code, response.Body.String())
		}
	}
	if got := scans.Load(); got != 0 {
		t.Fatalf("scanner called %d times after four concurrent range-load cancellations; want zero", got)
	}
}
