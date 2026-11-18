package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localOracleRequestForTest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:13335"
	req.RemoteAddr = "127.0.0.1:43123"
	req.Header.Set("Origin", localOracleOrigin)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestLocalOracleFlowUsesMockedAuthenticatedOracleEndpoints(t *testing.T) {
	oldURL := localOracleServiceURL
	localOracleSessions.Lock()
	oldSessions := localOracleSessions.items
	localOracleSessions.items = make(map[string]*localOracleSession)
	localOracleSessions.Unlock()
	t.Cleanup(func() {
		localOracleServiceURL = oldURL
		localOracleSessions.Lock()
		localOracleSessions.items = oldSessions
		localOracleSessions.Unlock()
	})

	const testPassword = "not-a-real-password"
	var sawStart atomic.Bool
	var sawStop atomic.Bool
	oracle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s", r.Method)
			}
			var payload localOracleLoginRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode mock login body: %v", err)
			}
			if payload.Username != "demo-user" || payload.Password != testPassword {
				t.Errorf("unexpected mock login credentials")
			}
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "mock-oracle-session", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/trace-countries":
			if _, err := r.Cookie(sessionCookieName); err != nil {
				t.Errorf("Oracle region request missing authenticated session: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"countries":{"HK":"Hong Kong","JP":"Japan"}}`))
		case "/api/trace-sweep/start":
			if _, err := r.Cookie(sessionCookieName); err != nil {
				t.Errorf("Oracle start missing authenticated session: %v", err)
			}
			var payload traceSweepRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode mock start body: %v", err)
			}
			if payload.Source != traceSweepSourceRegional || payload.Domain != "example.com" || payload.TotalLimit != 20 || payload.PerCountry != 5 || payload.Concurrency != 8 || len(payload.Countries) != 2 {
				t.Errorf("unexpected Oracle start payload: %+v", payload)
			}
			sawStart.Store(true)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"accepted"}`))
		case "/api/trace-sweep/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"running":false,"phase":"完成","domain":"example.com","total":2,"scanned":2,"success":2,"failed":0}`))
		case "/api/trace-sweep/results":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"candidate":"203.0.113.7:443","ok":true,"source_country":"JP"},{"candidate":"192.0.2.5:443","ok":true,"source_country":"HK"},{"candidate":"198.51.100.8:443","ok":false}]}`))
		case "/api/trace-sweep/stop":
			sawStop.Store(true)
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"no running task"}`))
		default:
			t.Errorf("unexpected mocked Oracle request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer oracle.Close()
	localOracleServiceURL = oracle.URL

	loginBody, _ := json.Marshal(localOracleLoginRequest{Username: "demo-user", Password: testPassword})
	loginRec := httptest.NewRecorder()
	handleLocalOracleLogin(loginRec, localOracleRequestForTest(http.MethodPost, localOracleLoginPath, string(loginBody)))
	if loginRec.Code != http.StatusCreated {
		t.Fatalf("login status = %d: %s", loginRec.Code, loginRec.Body.String())
	}
	if strings.Contains(loginRec.Body.String(), testPassword) {
		t.Fatal("login response unexpectedly exposed the submitted password")
	}
	var loginResponse struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResponse); err != nil || len(loginResponse.SessionID) != 64 {
		t.Fatalf("invalid local session response: %s (%v)", loginRec.Body.String(), err)
	}

	sessionBody, _ := json.Marshal(localOracleSessionRequest{SessionID: loginResponse.SessionID})
	countriesRec := httptest.NewRecorder()
	handleLocalOracleCountries(countriesRec, localOracleRequestForTest(http.MethodPost, localOracleCountriesPath, string(sessionBody)))
	if countriesRec.Code != http.StatusOK || !strings.Contains(countriesRec.Body.String(), `"JP":"Japan"`) {
		t.Fatalf("Oracle region catalog response = %d: %s", countriesRec.Code, countriesRec.Body.String())
	}

	startBody, _ := json.Marshal(localOracleStartRequest{
		SessionID: loginResponse.SessionID, Domain: "Example.COM.", Countries: []string{"jp", "HK"},
		PerCountry: 5, TotalLimit: 20, Concurrency: 8,
	})
	startRec := httptest.NewRecorder()
	handleLocalOracleStart(startRec, localOracleRequestForTest(http.MethodPost, localOracleStartPath, string(startBody)))
	if startRec.Code != http.StatusAccepted || !sawStart.Load() {
		t.Fatalf("Oracle start response = %d: %s", startRec.Code, startRec.Body.String())
	}

	statusRec := httptest.NewRecorder()
	handleLocalOracleStatus(statusRec, localOracleRequestForTest(http.MethodPost, localOracleStatusPath, string(sessionBody)))
	if statusRec.Code != http.StatusOK {
		t.Fatalf("Oracle status response = %d: %s", statusRec.Code, statusRec.Body.String())
	}
	var statusResponse struct {
		Phase      string             `json:"phase"`
		Candidates []traceCheckResult `json:"candidates"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResponse); err != nil {
		t.Fatalf("decode local status response: %v", err)
	}
	if statusResponse.Phase != "完成" || len(statusResponse.Candidates) != 2 || statusResponse.Candidates[0].Candidate != "203.0.113.7:443" {
		t.Fatalf("unexpected Oracle candidate handoff: %+v", statusResponse)
	}

	cancelRec := httptest.NewRecorder()
	handleLocalOracleCancel(cancelRec, localOracleRequestForTest(http.MethodPost, localOracleCancelPath, string(sessionBody)))
	if cancelRec.Code != http.StatusOK || !sawStop.Load() {
		t.Fatalf("Oracle cancellation response = %d: %s", cancelRec.Code, cancelRec.Body.String())
	}
	finishRec := httptest.NewRecorder()
	handleLocalOracleFinish(finishRec, localOracleRequestForTest(http.MethodPost, localOracleFinishPath, string(sessionBody)))
	if finishRec.Code != http.StatusOK {
		t.Fatalf("finish response = %d: %s", finishRec.Code, finishRec.Body.String())
	}
}

func TestLocalOracleEndpointsRequireExactAppOriginAndLoopback(t *testing.T) {
	cases := []struct {
		name       string
		origin     string
		host       string
		remoteAddr string
	}{
		{name: "missing origin", host: "127.0.0.1:13335", remoteAddr: "127.0.0.1:43123"},
		{name: "different origin", origin: "https://evil.example", host: "127.0.0.1:13335", remoteAddr: "127.0.0.1:43123"},
		{name: "host mismatch", origin: localOracleOrigin, host: "localhost:13335", remoteAddr: "127.0.0.1:43123"},
		{name: "non-loopback peer", origin: localOracleOrigin, host: "127.0.0.1:13335", remoteAddr: "198.51.100.4:43123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := localOracleRequestForTest(http.MethodPost, localOracleLoginPath, `{"username":"x","password":"y"}`)
			req.Header.Set("Origin", tc.origin)
			req.Host = tc.host
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()
			handleLocalOracleLogin(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("got status %d, want forbidden: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLocalTraceCheckFailsClosedWhenOfficialRangesUnavailable(t *testing.T) {
	var scanCalled atomic.Bool
	parseReservedFixture := func(value string) (traceCandidate, error) {
		if value != "203.0.113.7:443" {
			return traceCandidate{}, fmt.Errorf("unexpected fixture %q", value)
		}
		return traceCandidate{Address: netip.MustParseAddr("203.0.113.7"), Port: 443, Canonical: value}, nil
	}
	loader := func(_ context.Context) ([]netip.Prefix, error) {
		return nil, fmt.Errorf("mock range feeds unavailable")
	}
	scanner := func(_ context.Context, _ traceCandidate, _ string) traceCheckResult {
		scanCalled.Store(true)
		return traceCheckResult{OK: true}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check", strings.NewReader(`{"domain":"example.com","candidates":["203.0.113.7:443"]}`))
	req.Host = "checker.example"
	req.Header.Set("Origin", "https://checker.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheckWithDeps(rec, req, loader, parseReservedFixture, scanner)
	if rec.Code != http.StatusServiceUnavailable || scanCalled.Load() {
		t.Fatalf("got status %d, scan called %v; expected fail-closed 503 before any scan", rec.Code, scanCalled.Load())
	}
	if !strings.Contains(rec.Body.String(), "range feeds unavailable") {
		t.Fatalf("missing actionable range failure: %s", rec.Body.String())
	}
}

func TestLocalTraceCheckExcludesOfficialFixtureBeforeScanner(t *testing.T) {
	var scanCalled atomic.Bool
	parseReservedFixture := func(value string) (traceCandidate, error) {
		return traceCandidate{Address: netip.MustParseAddr("203.0.113.7"), Port: 443, Canonical: value}, nil
	}
	loader := func(_ context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, nil
	}
	scanner := func(_ context.Context, _ traceCandidate, _ string) traceCheckResult {
		scanCalled.Store(true)
		return traceCheckResult{OK: true}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check", strings.NewReader(`{"domain":"example.com","candidates":["203.0.113.7:443"]}`))
	req.Host = "checker.example"
	req.Header.Set("Origin", "https://checker.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheckWithDeps(rec, req, loader, parseReservedFixture, scanner)
	if rec.Code != http.StatusBadRequest || scanCalled.Load() {
		t.Fatalf("got status %d, scan called %v; expected exclusion before scanner", rec.Code, scanCalled.Load())
	}
	if !strings.Contains(rec.Body.String(), "Cloudflare 官方网段") {
		t.Fatalf("missing official-range refusal: %s", rec.Body.String())
	}
}

func TestLocalOraclePageExposesExplicitStartAndCandidateLimitControls(t *testing.T) {
	page, err := staticFiles.ReadFile("local_oracle_trace.html")
	if err != nil {
		t.Fatalf("read embedded local Oracle page: %v", err)
	}
	text := string(page)
	for _, required := range []string{"登录并读取 Oracle 地区", "开始 Oracle 初筛并本机复测", "本机最多复测候选", "取消", "/api/local/oracle/start", "/api/trace-check/preflight", "/api/trace-check", "LocalFlowCounters.create", "本机复测请求已发起", "请求中", "已收到复测结果", "未扫描", "状态未明", "官方网段清单"} {
		if !strings.Contains(text, required) {
			t.Errorf("local flow page missing %q", required)
		}
	}
}

func TestLocalOracleJSONDistinguishesOversizeFromInterruptedRead(t *testing.T) {
	oldURL := localOracleServiceURL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large":
			_, _ = w.Write([]byte(strings.Repeat("x", localOracleMaxReplyBody+1)))
		case "/truncated":
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("abc"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	localOracleServiceURL = server.URL
	t.Cleanup(func() { localOracleServiceURL = oldURL })

	_, err := doLocalOracleJSON(t.Context(), server.Client(), http.MethodGet, "/large", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "超过 32 MiB 安全上限") || !strings.Contains(err.Error(), "/large") {
		t.Fatalf("oversize response error = %v; want distinct 32 MiB limit error", err)
	}
	_, err = doLocalOracleJSON(t.Context(), server.Client(), http.MethodGet, "/truncated", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "响应中断") || !strings.Contains(err.Error(), "已接收 3 字节") || !strings.Contains(err.Error(), "/truncated") {
		t.Fatalf("truncated response error = %v; want actionable read-interruption detail", err)
	}
}

func TestLocalOracleJSONWithRetryRetriesOnlyIdempotentGETReadFailuresOnce(t *testing.T) {
	oldURL := localOracleServiceURL
	var getAttempts atomic.Int32
	var postAttempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get":
			if getAttempts.Add(1) == 1 {
				w.Header().Set("Content-Length", "10")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("abc"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/post":
			postAttempts.Add(1)
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("abc"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	localOracleServiceURL = server.URL
	t.Cleanup(func() { localOracleServiceURL = oldURL })

	var response struct {
		OK bool `json:"ok"`
	}
	status, err := doLocalOracleJSONWithRetry(t.Context(), server.Client(), http.MethodGet, "/get", nil, &response)
	if err != nil || status != http.StatusOK || !response.OK || getAttempts.Load() != 2 {
		t.Fatalf("GET status=%d response=%+v attempts=%d err=%v; want one retry and success", status, response, getAttempts.Load(), err)
	}
	_, err = doLocalOracleJSONWithRetry(t.Context(), server.Client(), http.MethodPost, "/post", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "响应中断") || postAttempts.Load() != 1 {
		t.Fatalf("POST attempts=%d err=%v; want one attempt and no retry", postAttempts.Load(), err)
	}
}

func TestLocalOracleJSONAcceptsExactly32MiB(t *testing.T) {
	oldURL := localOracleServiceURL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", localOracleMaxReplyBody)))
	}))
	defer server.Close()
	localOracleServiceURL = server.URL
	t.Cleanup(func() { localOracleServiceURL = oldURL })
	if _, err := doLocalOracleJSON(t.Context(), server.Client(), http.MethodGet, "/exact", nil, nil); err != nil {
		t.Fatalf("exactly 32 MiB response should fit the limit: %v", err)
	}
}

func TestLocalOracleJSONCapsUnknownLengthResponse(t *testing.T) {
	oldURL := localOracleServiceURL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("mock server does not support flushing")
			return
		}
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		chunk := []byte(strings.Repeat("x", 1<<20))
		for i := 0; i < 33; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer server.Close()
	localOracleServiceURL = server.URL
	t.Cleanup(func() { localOracleServiceURL = oldURL })
	_, err := doLocalOracleJSON(t.Context(), server.Client(), http.MethodGet, "/chunked", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "至少已读取 33554433 字节") || !strings.Contains(err.Error(), "超过 32 MiB 安全上限") {
		t.Fatalf("chunked response error = %v; want bounded 32 MiB error", err)
	}
}

func TestTraceCheckPreflightPrefersOracleExclusions(t *testing.T) {
	oldURL := localOracleServiceURL
	oracle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/trace-sweep/exclusions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":["1.1.1.0/24","2606:4700::/32"],"prefix_count":2}`))
	}))
	defer oracle.Close()
	localOracleServiceURL = oracle.URL
	const sessionToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	localOracleSessions.Lock()
	oldSessions := localOracleSessions.items
	localOracleSessions.items = map[string]*localOracleSession{
		sessionToken: {client: oracle.Client(), expiresAt: time.Now().Add(time.Hour)},
	}
	localOracleSessions.Unlock()
	t.Cleanup(func() {
		localOracleServiceURL = oldURL
		localOracleSessions.Lock()
		localOracleSessions.items = oldSessions
		localOracleSessions.Unlock()
	})

	var directCalled atomic.Bool
	directLoader := func(context.Context) ([]netip.Prefix, error) {
		directCalled.Store(true)
		return nil, fmt.Errorf("direct fetch must not run when Oracle answers")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check/preflight", strings.NewReader(`{"session_id":"`+sessionToken+`"}`))
	req.Host = "127.0.0.1:13335"
	req.Header.Set("Origin", localOracleOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheckPreflightWithOracle(rec, req, directLoader)
	if rec.Code != http.StatusOK || directCalled.Load() {
		t.Fatalf("preflight status=%d directCalled=%v body=%s; want Oracle prefixes without direct fetch", rec.Code, directCalled.Load(), rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"prefix_count":2`) {
		t.Fatalf("preflight body missing Oracle prefix count: %s", rec.Body.String())
	}
}

func TestTraceCheckPreflightFallsBackToDirectRangesWhenOracleFails(t *testing.T) {
	oldURL := localOracleServiceURL
	oracle := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer oracle.Close()
	localOracleServiceURL = oracle.URL
	const sessionToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	localOracleSessions.Lock()
	oldSessions := localOracleSessions.items
	localOracleSessions.items = map[string]*localOracleSession{
		sessionToken: {client: oracle.Client(), expiresAt: time.Now().Add(time.Hour)},
	}
	localOracleSessions.Unlock()
	t.Cleanup(func() {
		localOracleServiceURL = oldURL
		localOracleSessions.Lock()
		localOracleSessions.items = oldSessions
		localOracleSessions.Unlock()
	})

	directLoader := func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{
			netip.MustParsePrefix("1.1.1.0/24"),
			netip.MustParsePrefix("2606:4700::/32"),
		}, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check/preflight", strings.NewReader(`{"session_id":"`+sessionToken+`"}`))
	req.Host = "127.0.0.1:13335"
	req.Header.Set("Origin", localOracleOrigin)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheckPreflightWithOracle(rec, req, directLoader)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"prefix_count":2`) {
		t.Fatalf("preflight fallback status=%d body=%s; want direct ranges", rec.Code, rec.Body.String())
	}
}
