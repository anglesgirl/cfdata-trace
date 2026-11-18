package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tracePath              = "/cdn-cgi/trace"
	traceMaxCandidates     = 10
	traceMaxConcurrency    = 64
	traceMaxRequestBytes   = 8192
	traceMaxResponseBytes  = 8192
	traceMaxResponseHeader = 16 * 1024
	traceConnectTimeout    = 5 * time.Second
	traceRequestTimeout    = 8 * time.Second
)

var (
	traceSlots    = make(chan struct{}, traceMaxConcurrency)
	traceDomainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	traceSpecial  = mustTracePrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
	)
)

type traceCheckRequest struct {
	Domain     string   `json:"domain"`
	Candidates []string `json:"candidates"`
}

type traceCheckResponse struct {
	Domain  string             `json:"domain"`
	Path    string             `json:"path"`
	Results []traceCheckResult `json:"results"`
}

type traceCheckResult struct {
	Candidate     string            `json:"candidate"`
	Source        string            `json:"source,omitempty"`
	SourceCountry string            `json:"source_country,omitempty"`
	SourceCity    string            `json:"source_city,omitempty"`
	SourceRegion  string            `json:"source_region,omitempty"`
	SourceISP     string            `json:"source_isp,omitempty"`
	SourceRisk    string            `json:"source_risk,omitempty"`
	SourceScore   int               `json:"source_score,omitempty"`
	OK            bool              `json:"ok"`
	HTTPStatus    int               `json:"http_status,omitempty"`
	TLSVersion    string            `json:"tls_version,omitempty"`
	Trace         map[string]string `json:"trace,omitempty"`
	ElapsedMS     int64             `json:"elapsed_ms"`
	Error         string            `json:"error,omitempty"`
}

type traceCandidate struct {
	Address   netip.Addr
	Port      uint16
	Canonical string
}

func mustTracePrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func parseTraceCandidate(value string) (traceCandidate, error) {
	text := strings.TrimSpace(value)
	if text == "" || strings.ContainsAny(text, "\r\n\t ,") {
		return traceCandidate{}, errors.New("每行必须是单个 IP:端口")
	}
	host, portText, err := net.SplitHostPort(text)
	if err != nil {
		return traceCandidate{}, errors.New("请明确填写 IP:端口；IPv6 使用 [地址]:端口 格式")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return traceCandidate{}, errors.New("候选地址必须是 IP 字面量，不能输入域名或带区域标记的 IPv6")
	}
	if address.Is4In6() {
		return traceCandidate{}, errors.New("不接受 IPv4-mapped IPv6 地址，请直接填写 IPv4")
	}
	if !isTracePublicIP(address) {
		return traceCandidate{}, errors.New("已拒绝非公网地址、组播或保留地址（包括私网、回环和链路本地地址）")
	}
	if portText == "" || len(portText) > 5 {
		return traceCandidate{}, errors.New("端口必须是 1–65535 的单个端口号")
	}
	for _, ch := range portText {
		if ch < '0' || ch > '9' {
			return traceCandidate{}, errors.New("端口必须是 1–65535 的单个端口号")
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return traceCandidate{}, errors.New("端口必须是 1–65535 的单个端口号")
	}
	canonical := net.JoinHostPort(address.String(), strconv.FormatUint(port, 10))
	return traceCandidate{Address: address, Port: uint16(port), Canonical: canonical}, nil
}

func isTracePublicIP(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range traceSpecial {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validateTraceDomain(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, ":/@\\?#%\r\n\t ") {
		return "", errors.New("目标必须是完整域名，不要填写协议、端口、路径或查询参数")
	}
	if net.ParseIP(host) != nil || !traceDomainRE.MatchString(host) {
		return "", errors.New("目标域名格式无效；请填写 ASCII 公网域名")
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".home.arpa"} {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return "", errors.New("目标必须是公网域名")
		}
	}
	return host, nil
}

func parseTraceFields(body []byte) map[string]string {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 256), traceMaxResponseBytes)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok || len(key) == 0 || len(key) > 40 {
			continue
		}
		valid := true
		for _, ch := range key {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_') {
				valid = false
				break
			}
		}
		if valid {
			if len(value) > 500 {
				value = value[:500]
			}
			fields[key] = value
		}
	}
	return fields
}

func runTraceCheck(ctx context.Context, candidate traceCandidate, domain string) traceCheckResult {
	started := time.Now()
	result := traceCheckResult{Candidate: candidate.Canonical}
	select {
	case traceSlots <- struct{}{}:
		defer func() { <-traceSlots }()
	case <-ctx.Done():
		result.Error = "请求已取消"
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	case <-time.After(150 * time.Millisecond):
		result.Error = "检测并发已满，请稍后重试"
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, traceRequestTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: traceConnectTimeout}
	address := net.JoinHostPort(candidate.Address.String(), strconv.Itoa(int(candidate.Port)))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Error = traceErrorText(err)
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	_ = conn.SetDeadline(time.Now().Add(traceRequestTimeout))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		result.Error = traceErrorText(err)
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	request := "GET " + tracePath + " HTTP/1.1\r\nHost: " + domain + "\r\nAccept: text/plain\r\nUser-Agent: CFData-WEB-Trace/1.0\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, request); err != nil {
		result.Error = traceErrorText(err)
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	responseReader := bufio.NewReader(io.LimitReader(tlsConn, traceMaxResponseHeader+traceMaxResponseBytes))
	response, err := http.ReadResponse(responseReader, &http.Request{Method: http.MethodGet})
	if err != nil {
		result.Error = traceErrorText(err)
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, traceMaxResponseBytes+1))
	if err != nil {
		result.Error = traceErrorText(err)
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	if len(body) > traceMaxResponseBytes {
		result.Error = "trace 响应超过 8 KiB 限制"
		result.ElapsedMS = time.Since(started).Milliseconds()
		return result
	}
	fields := parseTraceFields(body)
	result.Trace = fields
	result.ElapsedMS = time.Since(started).Milliseconds()
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", response.StatusCode)
		return result
	}
	for _, key := range []string{"h", "ip", "loc", "colo"} {
		if strings.TrimSpace(fields[key]) == "" {
			result.Error = "响应不是完整的 Cloudflare trace（缺少 h/ip/loc/colo）"
			return result
		}
	}
	if strings.ToLower(strings.TrimSuffix(fields["h"], ".")) != domain {
		result.Error = "trace 返回的主机名与目标域名不一致"
		return result
	}
	result.OK = true
	result.TLSVersion = tlsVersionName(tlsConn.ConnectionState().Version)
	return result
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

func traceErrorText(err error) string {
	text := strings.TrimSpace(err.Error())
	if text == "" {
		text = "检测失败"
	}
	if len(text) > 240 {
		text = text[:240]
	}
	return text
}

func setTraceSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
}

func handleTracePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/trace" {
		http.NotFound(w, r)
		return
	}
	page, err := staticFiles.ReadFile("trace.html")
	if err != nil {
		http.Error(w, "无法加载 Trace 页面", http.StatusInternalServerError)
		return
	}
	setTraceSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}

func writeTraceJSON(w http.ResponseWriter, status int, value any) {
	setTraceSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func validateTraceOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func handleTraceCheckPreflight(w http.ResponseWriter, r *http.Request) {
	handleTraceCheckPreflightWithOracle(w, r, cachedCloudflareExclusionPrefixes)
}

// handleTraceCheckPreflightWithOracle 优先走 Oracle 服务端下好的官方网段清单
// （本机到 Oracle 的会话是通的），Oracle 不可用时回落到本机直连 cloudflare.com。
func handleTraceCheckPreflightWithOracle(w http.ResponseWriter, r *http.Request, directLoader func(context.Context) ([]netip.Prefix, error)) {
	sessionID := ""
	if r.Body != nil {
		var payload struct {
			SessionID string `json:"session_id"`
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
		if err == nil {
			_ = json.Unmarshal(body, &payload)
			sessionID = strings.TrimSpace(payload.SessionID)
		}
	}
	loader := func(ctx context.Context) ([]netip.Prefix, error) {
		if sessionID != "" {
			if prefixes, err := loadCloudflareExclusionPrefixesViaOracle(ctx, sessionID); err == nil {
				return prefixes, nil
			}
		}
		return directLoader(ctx)
	}
	handleTraceCheckPreflightWithLoader(w, r, loader)
}

func handleTraceCheckPreflightWithLoader(w http.ResponseWriter, r *http.Request, loadPrefixes func(context.Context) ([]netip.Prefix, error)) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTraceJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if r.URL.Path != "/api/trace-check/preflight" {
		writeTraceJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !validateTraceOrigin(r) {
		writeTraceJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request denied"})
		return
	}
	if contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); contentType != "application/json" {
		writeTraceJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	prefixes, err := loadPrefixes(r.Context())
	if err != nil {
		writeTraceJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	if err := validateCloudflareExclusionPrefixes(prefixes); err != nil {
		writeTraceJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeTraceJSON(w, http.StatusOK, map[string]any{"ready": true, "prefix_count": len(prefixes), "ipv4": true, "ipv6": true})
}

func handleTraceCheck(w http.ResponseWriter, r *http.Request) {
	handleTraceCheckWithDeps(w, r, cachedCloudflareExclusionPrefixes, parseTraceCandidate, runTraceCheck)
}

func handleTraceCheckWithDeps(
	w http.ResponseWriter,
	r *http.Request,
	loadPrefixes func(context.Context) ([]netip.Prefix, error),
	parseCandidate func(string) (traceCandidate, error),
	scan func(context.Context, traceCandidate, string) traceCheckResult,
) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTraceJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if r.URL.Path != "/api/trace-check" {
		writeTraceJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !validateTraceOrigin(r) {
		writeTraceJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request denied"})
		return
	}
	if contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); contentType != "application/json" {
		writeTraceJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, traceMaxRequestBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeTraceJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return
		}
		writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": "无法读取请求"})
		return
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var payload traceCheckRequest
	if err := decoder.Decode(&payload); err != nil {
		writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON 格式无效"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON 请求只能包含一个对象"})
		return
	}
	domain, err := validateTraceDomain(payload.Domain)
	if err != nil {
		writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(payload.Candidates) == 0 {
		writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": "至少输入一个候选 IP:端口"})
		return
	}
	if len(payload.Candidates) > traceMaxCandidates {
		writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("单批最多 %d 个候选", traceMaxCandidates)})
		return
	}
	candidates := make([]traceCandidate, 0, len(payload.Candidates))
	seen := make(map[string]struct{}, len(payload.Candidates))
	for _, raw := range payload.Candidates {
		candidate, err := parseCandidate(raw)
		if err != nil {
			writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if _, exists := seen[candidate.Canonical]; exists {
			continue
		}
		seen[candidate.Canonical] = struct{}{}
		candidates = append(candidates, candidate)
	}
	prefixes, err := loadPrefixes(r.Context())
	if err != nil {
		writeTraceJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	for _, candidate := range candidates {
		if traceIPInPrefixes(candidate.Address, prefixes) {
			writeTraceJSON(w, http.StatusBadRequest, map[string]string{"error": "候选位于 Cloudflare 官方网段；已在本机扫描前拒绝"})
			return
		}
	}
	results := make([]traceCheckResult, len(candidates))
	var group sync.WaitGroup
	for i, candidate := range candidates {
		group.Add(1)
		go func(i int, candidate traceCandidate) {
			defer group.Done()
			results[i] = scan(r.Context(), candidate, domain)
		}(i, candidate)
	}
	group.Wait()
	writeTraceJSON(w, http.StatusOK, traceCheckResponse{Domain: domain, Path: tracePath, Results: results})
}
