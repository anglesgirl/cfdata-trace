package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTraceCandidate(t *testing.T) {
	ipv4, err := parseTraceCandidate("1.1.1.1:443")
	if err != nil {
		t.Fatalf("parse public IPv4: %v", err)
	}
	if ipv4.Canonical != "1.1.1.1:443" || ipv4.Port != 443 {
		t.Fatalf("unexpected normalized IPv4 candidate: %+v", ipv4)
	}

	ipv6, err := parseTraceCandidate("[2606:4700:4700::1111]:8443")
	if err != nil {
		t.Fatalf("parse public IPv6: %v", err)
	}
	if ipv6.Canonical != "[2606:4700:4700::1111]:8443" || ipv6.Port != 8443 {
		t.Fatalf("unexpected normalized IPv6 candidate: %+v", ipv6)
	}
}

func TestParseTraceCandidateRejectsUnsafeInputs(t *testing.T) {
	values := []string{
		"127.0.0.1:443", "10.1.2.3:443", "192.168.1.1:443", "169.254.169.254:80",
		"192.0.2.1:443", "224.0.0.1:443", "240.0.0.1:443", "[::1]:443",
		"[fc00::1]:443", "[fe80::1]:443", "[2001:db8::1]:443", "example.com:443",
		"1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:1-65535", "1.1.1.1/24:443",
		"1.1.1.1:443,8.8.8.8:443", "[::ffff:1.1.1.1]:443", "[fe80::1%eth0]:443",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			if _, err := parseTraceCandidate(value); err == nil {
				t.Fatalf("expected rejection for %q", value)
			}
		})
	}
}

func TestValidateTraceDomain(t *testing.T) {
	got, err := validateTraceDomain("  ANI.GAMER.TW. ")
	if err != nil {
		t.Fatalf("validate domain: %v", err)
	}
	if got != "ani.gamer.tw" {
		t.Fatalf("got %q, want normalized lowercase domain", got)
	}
	for _, value := range []string{
		"", "127.0.0.1", "localhost", "a.local", "a.example", "https://example.com",
		"example.com:443", "example.com/path", "a_b.example.com", "-bad.example.com",
		"example.com?x=1", "xn--.example.com",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := validateTraceDomain(value); err == nil {
				t.Fatalf("expected rejection for %q", value)
			}
		})
	}
}

func TestParseTraceFields(t *testing.T) {
	fields := parseTraceFields([]byte("h=ani.gamer.com.tw\nip=203.0.113.1\nloc=JP\ncolo=NRT\ninvalid\n<script>=x\n"))
	if fields["loc"] != "JP" || fields["colo"] != "NRT" || fields["h"] != "ani.gamer.com.tw" {
		t.Fatalf("unexpected trace fields: %#v", fields)
	}
	if _, exists := fields["<script>"]; exists {
		t.Fatalf("invalid trace key was accepted: %#v", fields)
	}
}

func TestTraceAPIRejectsCrossOriginBeforeAnyProbe(t *testing.T) {
	body := `{"domain":"example.com","candidates":["1.1.1.1:443"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check", strings.NewReader(body))
	req.Host = "checker.example"
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheck(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestTraceAPIRejectsPrivateAddressBeforeProbe(t *testing.T) {
	body := `{"domain":"example.com","candidates":["127.0.0.1:443"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check", strings.NewReader(body))
	req.Host = "checker.example"
	req.Header.Set("Origin", "https://checker.example")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheck(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode API error: %v", err)
	}
	if !strings.Contains(response["error"], "非公网地址") {
		t.Fatalf("unexpected API error: %q", response["error"])
	}
}

func TestTraceAPIRejectsOversizedRequest(t *testing.T) {
	body := `{"domain":"example.com","candidates":["` + strings.Repeat("a", traceMaxRequestBytes) + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/trace-check", strings.NewReader(body))
	req.Host = "checker.example"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleTraceCheck(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestTraceAPIMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/trace-check", nil)
	rec := httptest.NewRecorder()
	handleTraceCheck(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("unexpected Allow header: %q", rec.Header().Get("Allow"))
	}
}

func TestTraceAPIRequiresExistingWebSession(t *testing.T) {
	oldUser, oldPassword := webUser, webPassword
	webUser, webPassword = "trace-test-user", "trace-test-password"
	defer func() { webUser, webPassword = oldUser, oldPassword }()

	req := httptest.NewRequest(http.MethodPost, "/api/trace-check", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	requireAuth(handleTraceCheck)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("expected JSON error, got content type %q", rec.Header().Get("Content-Type"))
	}
}
