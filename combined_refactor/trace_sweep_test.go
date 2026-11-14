package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeTraceSweepSourceDefaultsToRegionalAndCanEnforceIt(t *testing.T) {
	oldRegionalOnly := traceRegionalOnly
	t.Cleanup(func() { traceRegionalOnly = oldRegionalOnly })
	traceRegionalOnly = false
	if got, err := normalizeTraceSweepSource(""); err != nil || got != traceSweepSourceRegional {
		t.Fatalf("empty source = %q, %v; want regional", got, err)
	}
	if got, err := normalizeTraceSweepSource(" FoFa "); err != nil || got != traceSweepSourceFOFA {
		t.Fatalf("FOFA source = %q, %v; want fofa", got, err)
	}
	traceRegionalOnly = true
	if got, err := normalizeTraceSweepSource("regional"); err != nil || got != traceSweepSourceRegional {
		t.Fatalf("regional-only source = %q, %v; want regional", got, err)
	}
	if _, err := normalizeTraceSweepSource("fofa"); err == nil {
		t.Fatal("regional-only deployment accepted FOFA")
	}
}

func TestNormalizeTraceCountries(t *testing.T) {
	got, err := normalizeTraceCountries([]string{" jp ", "HK", "JP", "sg", "tw"})
	if err != nil {
		t.Fatalf("normalize countries: %v", err)
	}
	want := []string{"JP", "HK", "SG", "TW"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	tooMany := make([]string, traceSweepMaxCountries+1)
	for i := range tooMany {
		tooMany[i] = "JP"
	}
	for _, input := range [][]string{{}, {"USA"}, {"J;"}, tooMany} {
		if _, err := normalizeTraceCountries(input); err == nil {
			t.Fatalf("expected invalid country input to fail: %#v", input)
		}
	}
}

func TestParseRegionalCandidateRecord(t *testing.T) {
	candidate, ok := parsePublicProxyIPRecord(proxyIPRecord{
		IP: "8.8.8.8", Port: 443, Country: " jp ", City: "Tokyo", Region: "Tokyo", ISP: "Example ISP", Score: 2, Risk: "low",
	})
	if !ok {
		t.Fatal("expected regional candidate record to parse")
	}
	if candidate.Address.Canonical != "8.8.8.8:443" || candidate.Country != "JP" || candidate.City != "Tokyo" || candidate.ISP != "Example ISP" || !strings.Contains(candidate.Source, "arbitrary Host unverified") {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
	for _, record := range []proxyIPRecord{
		{IP: "127.0.0.1", Port: 443, Country: "JP"},
		{IP: "8.8.8.8", Port: 0, Country: "JP"},
		{IP: "8.8.8.8", Port: 443, Country: "USA"},
	} {
		if _, ok := parsePublicProxyIPRecord(record); ok {
			t.Fatalf("expected invalid regional candidate record to be rejected: %+v", record)
		}
	}
}

func TestSelectRegionalCandidatesExcludesRangesAndAppliesFairCaps(t *testing.T) {
	records := []proxyIPRecord{
		{IP: "8.8.8.8", Port: 443, Country: "JP", City: "Tokyo"},
		{IP: "8.8.4.4", Port: 443, Country: "JP", City: "Tokyo"},
		{IP: "1.1.1.1", Port: 443, Country: "JP", City: "Tokyo"},
		{IP: "9.9.9.9", Port: 443, Country: "HK", City: "Hong Kong"},
		{IP: "149.112.112.112", Port: 443, Country: "HK", City: "Hong Kong"},
		{IP: "4.2.2.2", Port: 443, Country: "US", City: "Outside selection"},
		{IP: "8.8.8.8", Port: 443, Country: "JP", City: "Duplicate"},
	}
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}
	got, excluded := selectPublicProxyIPCandidates(records, []string{"JP", "HK"}, 2, 3, prefixes)
	if excluded != 1 {
		t.Fatalf("got %d excluded candidates, want 1", excluded)
	}
	want := []string{"8.8.8.8:443", "9.9.9.9:443", "8.8.4.4:443"}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Address.Canonical != want[i] {
			t.Fatalf("candidate %d = %s, want %s", i, got[i].Address.Canonical, want[i])
		}
	}
}

func TestFetchRegionalCandidateDatasetUsesInjectedHTTPClient(t *testing.T) {
	oldURL, oldClient := proxyIPDataURL, publicIPHTTPClient
	t.Cleanup(func() { proxyIPDataURL, publicIPHTTPClient = oldURL, oldClient })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected public source request: %s headers=%v", r.Method, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"updated_at":"2026-11-13T13:01:11Z","proxies":[{"ip":"8.8.8.8","port":443,"country":"JP","city":"Tokyo"}]}`))
	}))
	defer server.Close()
	proxyIPDataURL = server.URL
	publicIPHTTPClient = server.Client()
	dataset, err := fetchPublicProxyIPDataset(t.Context())
	if err != nil {
		t.Fatalf("fetch public source mock: %v", err)
	}
	if dataset.UpdatedAt != "2026-11-13T13:01:11Z" || len(dataset.Proxies) != 1 || dataset.Proxies[0].Country != "JP" {
		t.Fatalf("unexpected public dataset: %+v", dataset)
	}
}

func TestParseFOFACandidate(t *testing.T) {
	candidate, ok := parseFOFACandidate([]string{"203.0.113.10", "443", "JP", "Tokyo"})
	if ok {
		t.Fatalf("documentation-only address unexpectedly accepted: %+v", candidate)
	}
	candidate, ok = parseFOFACandidate([]string{"1.1.1.1", "443", "JP", "Tokyo"})
	if !ok {
		t.Fatal("expected public IPv4 candidate to parse")
	}
	if candidate.Address.Canonical != "1.1.1.1:443" || candidate.Country != "JP" || candidate.City != "Tokyo" {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
	candidate, ok = parseFOFACandidate([]string{"[2606:4700:4700::1111]", "8443", "HK", "Hong Kong"})
	if !ok || candidate.Address.Canonical != "[2606:4700:4700::1111]:8443" {
		t.Fatalf("unexpected public IPv6 candidate: %+v, ok=%v", candidate, ok)
	}
	for _, row := range [][]string{
		{"127.0.0.1", "443", "JP", "Tokyo"},
		{"example.com", "443", "JP", "Tokyo"},
		{"1.1.1.1", "70000", "JP", "Tokyo"},
		{"1.1.1.1", "443"},
	} {
		if _, ok := parseFOFACandidate(row); ok {
			t.Fatalf("expected invalid FOFA result to be discarded: %#v", row)
		}
	}
}

func TestTraceIPInPrefixesExcludesOnlyMatchingAddresses(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("2606:4700::/32")}
	for _, value := range []string{"1.1.1.1", "2606:4700::1111"} {
		if !traceIPInPrefixes(netip.MustParseAddr(value), prefixes) {
			t.Fatalf("expected official-range address %s to be excluded", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "2606:4701::1"} {
		if traceIPInPrefixes(netip.MustParseAddr(value), prefixes) {
			t.Fatalf("unexpected exclusion for address %s", value)
		}
	}
}

func TestQueryFOFAUsesServerKeyAndOnlyRequestedFields(t *testing.T) {
	oldBase, oldClient := fofaAPIBaseURL, fofaHTTPClient
	oldKey, hadKey := os.LookupEnv("FOFA_KEY")
	t.Cleanup(func() {
		fofaAPIBaseURL, fofaHTTPClient = oldBase, oldClient
		if hadKey {
			_ = os.Setenv("FOFA_KEY", oldKey)
		} else {
			_ = os.Unsetenv("FOFA_KEY")
		}
	})
	_ = os.Setenv("FOFA_KEY", "unit-test-key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/search/all" {
			t.Errorf("unexpected FOFA endpoint: %s", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "unit-test-key" {
			t.Errorf("FOFA key was not sent from server environment")
		}
		if r.URL.Query().Get("fields") != "ip,port,country,city" {
			t.Errorf("unexpected fields: %q", r.URL.Query().Get("fields"))
		}
		query, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("qbase64"))
		if err != nil || string(query) != `server="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country="JP" && port="443"` {
			t.Errorf("unexpected query: %q (err=%v)", query, err)
		}
		if r.URL.Query().Get("page") != "2" || r.URL.Query().Get("size") != "100" {
			t.Errorf("unexpected pagination: page=%s size=%s", r.URL.Query().Get("page"), r.URL.Query().Get("size"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   false,
			"results": [][]string{{"1.1.1.1", "443", "JP", "Tokyo"}},
		})
	}))
	defer server.Close()
	fofaAPIBaseURL = server.URL
	fofaHTTPClient = server.Client()

	response, err := queryFOFA(t.Context(), buildFOFAQuery("JP", 443), 2, 100)
	if err != nil {
		t.Fatalf("query FOFA mock: %v", err)
	}
	if len(response.Results) != 1 || response.Results[0][3] != "Tokyo" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestQueryFOFARequiresServerKey(t *testing.T) {
	oldKey, hadKey := os.LookupEnv("FOFA_KEY")
	t.Cleanup(func() {
		if hadKey {
			_ = os.Setenv("FOFA_KEY", oldKey)
		} else {
			_ = os.Unsetenv("FOFA_KEY")
		}
	})
	_ = os.Unsetenv("FOFA_KEY")
	_, err := queryFOFA(t.Context(), `country="JP" && port="443"`, 1, 100)
	if err == nil || !strings.Contains(err.Error(), "FOFA_KEY 未配置") {
		t.Fatalf("expected missing server key error, got %v", err)
	}
}

func TestTraceSweepStartRejectsCrossOrigin(t *testing.T) {
	body := `{"domain":"example.com","countries":["JP"],"port":443}`
	req := httptest.NewRequest(http.MethodPost, "/api/trace-sweep/start", strings.NewReader(body))
	req.Host = "checker.example"
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceSweepStart(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestTraceSweepStartRejectsFOFAInRegionOnlyMode(t *testing.T) {
	oldRegionalOnly := traceRegionalOnly
	traceRegionalOnly = true
	t.Cleanup(func() { traceRegionalOnly = oldRegionalOnly })
	body := `{"source":"fofa"}`
	req := httptest.NewRequest(http.MethodPost, "/api/trace-sweep/start", strings.NewReader(body))
	req.Host = "checker.example"
	req.Header.Set("Origin", "https://checker.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceSweepStart(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "仅允许使用公开区域名单") {
		t.Fatalf("region-only mode did not reject FOFA safely: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTraceSweepStatusRequiresExistingWebSession(t *testing.T) {
	oldUser, oldPassword := webUser, webPassword
	webUser, webPassword = "sweep-test-user", "sweep-test-password"
	defer func() { webUser, webPassword = oldUser, oldPassword }()

	req := httptest.NewRequest(http.MethodGet, "/api/trace-sweep/status", nil)
	rec := httptest.NewRecorder()
	requireAuth(handleTraceSweepStatus)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected JSON unauthorized response, got %q", rec.Header().Get("Content-Type"))
	}
}

func TestTracePageServesEmbeddedRegionSweepUI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/trace", nil)
	rec := httptest.NewRecorder()
	handleTracePage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}
	for _, text := range []string{"地区候选 IP 初筛", "公开区域名单与 Trace 初筛", "NiREvil/vless 地区清单", "严格校验", "供本地二次筛选"} {
		if !strings.Contains(rec.Body.String(), text) {
			t.Fatalf("embedded Trace page is missing %q", text)
		}
	}
	for _, text := range []string{"FOFA 原始条件筛选", "手动检测候选", "/api/trace-check"} {
		if strings.Contains(rec.Body.String(), text) {
			t.Fatalf("restricted Trace page unexpectedly exposes %q", text)
		}
	}
}

func TestTraceLocalAuthenticatedSmokeNoExternalIO(t *testing.T) {
	oldUser, oldPassword := webUser, webPassword
	webUser, webPassword = "local-smoke-user", "local-smoke-password"
	t.Cleanup(func() {
		webUser, webPassword = oldUser, oldPassword
	})
	oldTraceOnly, oldRegionalOnly := traceOnlyWeb, traceRegionalOnly
	traceOnlyWeb, traceRegionalOnly = true, true
	t.Cleanup(func() { traceOnlyWeb, traceRegionalOnly = oldTraceOnly, oldRegionalOnly })

	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"local-smoke-user","password":"local-smoke-password"}`))
	loginReq.Host = "checker.example"
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	handleLoginPost(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login returned %d, want %d", loginRec.Code, http.StatusOK)
	}
	var session *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
			break
		}
	}
	if session == nil {
		t.Fatal("login did not issue a session cookie")
	}
	if !session.Secure {
		t.Fatal("Trace-only login cookie must be Secure behind HTTPS ingress")
	}
	t.Cleanup(func() { deleteAuthSession(session.Value) })

	pageReq := httptest.NewRequest(http.MethodGet, "/trace", nil)
	pageReq.Host = "checker.example"
	pageReq.AddCookie(session)
	pageRec := httptest.NewRecorder()
	requireAuth(handleTracePage)(pageRec, pageReq)
	if pageRec.Code != http.StatusOK || !strings.Contains(pageRec.Body.String(), "公开区域名单与 Trace 初筛") || strings.Contains(pageRec.Body.String(), "手动检测候选") {
		t.Fatalf("authenticated Trace page failed: status=%d", pageRec.Code)
	}

	countriesReq := httptest.NewRequest(http.MethodGet, "/api/trace-countries", nil)
	countriesReq.Host = "checker.example"
	countriesReq.AddCookie(session)
	countriesRec := httptest.NewRecorder()
	requireAuth(handleTraceCountryList)(countriesRec, countriesReq)
	var catalog struct {
		Countries map[string]string `json:"countries"`
	}
	if countriesRec.Code != http.StatusOK || json.Unmarshal(countriesRec.Body.Bytes(), &catalog) != nil || len(catalog.Countries) != 249 || catalog.Countries["JP"] == "" {
		t.Fatalf("authenticated country catalog failed: status=%d, countries=%d", countriesRec.Code, len(catalog.Countries))
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/trace-sweep/status", nil)
	statusReq.Host = "checker.example"
	statusReq.AddCookie(session)
	statusRec := httptest.NewRecorder()
	requireAuth(handleTraceSweepStatus)(statusRec, statusReq)
	if statusRec.Code != http.StatusOK || !strings.Contains(statusRec.Body.String(), `"phase":"idle"`) {
		t.Fatalf("idle task status failed: status=%d body=%s", statusRec.Code, statusRec.Body.String())
	}

	stopReq := httptest.NewRequest(http.MethodPost, "/api/trace-sweep/stop", nil)
	stopReq.Host = "checker.example"
	stopReq.Header.Set("Origin", "https://checker.example")
	stopReq.AddCookie(session)
	stopRec := httptest.NewRecorder()
	requireAuth(handleTraceSweepStop)(stopRec, stopReq)
	if stopRec.Code != http.StatusConflict {
		t.Fatalf("stop without an active job should be a safe conflict, got %d", stopRec.Code)
	}

	txtReq := httptest.NewRequest(http.MethodGet, "/api/trace-sweep/export?format=txt", nil)
	txtReq.Host = "checker.example"
	txtReq.AddCookie(session)
	txtRec := httptest.NewRecorder()
	requireAuth(handleTraceSweepExport)(txtRec, txtReq)
	if txtRec.Code != http.StatusOK || !strings.Contains(txtRec.Header().Get("Content-Disposition"), "trace-candidates.txt") || txtRec.Body.Len() != 0 {
		t.Fatalf("empty TXT export failed: status=%d headers=%v body=%q", txtRec.Code, txtRec.Header(), txtRec.Body.String())
	}

	csvReq := httptest.NewRequest(http.MethodGet, "/api/trace-sweep/export?format=csv", nil)
	csvReq.Host = "checker.example"
	csvReq.AddCookie(session)
	csvRec := httptest.NewRecorder()
	requireAuth(handleTraceSweepExport)(csvRec, csvReq)
	if csvRec.Code != http.StatusOK || !strings.Contains(csvRec.Body.String(), "candidate,source,source_country") {
		t.Fatalf("empty CSV export failed: status=%d body=%q", csvRec.Code, csvRec.Body.String())
	}
}
