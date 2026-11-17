package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	localOracleOrigin        = "http://127.0.0.1:13335"
	localOracleLoginPath     = "/api/local/oracle/login"
	localOracleCountriesPath = "/api/local/oracle/countries"
	localOracleStartPath     = "/api/local/oracle/start"
	localOracleStatusPath    = "/api/local/oracle/status"
	localOracleCancelPath    = "/api/local/oracle/cancel"
	localOracleFinishPath    = "/api/local/oracle/finish"
	localOracleMaxBody       = 32 << 10
	localOracleMaxReplyBody  = 8 << 20
	localOracleSessionTTL    = 45 * time.Minute
	localOracleMaxSessions   = 4
)

var localOracleServiceURL = "https://cfdata-trace.anglesya.win"

type localOracleLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type localOracleSessionRequest struct {
	SessionID string `json:"session_id"`
}

type localOracleStartRequest struct {
	SessionID   string   `json:"session_id"`
	Domain      string   `json:"domain"`
	Countries   []string `json:"countries"`
	PerCountry  int      `json:"per_country"`
	TotalLimit  int      `json:"total_limit"`
	Concurrency int      `json:"concurrency"`
}

type localOracleSession struct {
	client    *http.Client
	domain    string
	expiresAt time.Time
}

var localOracleSessions = struct {
	sync.Mutex
	items map[string]*localOracleSession
}{items: make(map[string]*localOracleSession)}

func localOracleOriginAllowed(r *http.Request) bool {
	if r.Header.Get("Origin") != localOracleOrigin || r.Host != "127.0.0.1:13335" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func localOracleRequest(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.URL.Path != path {
		writeTraceJSONError(w, http.StatusNotFound, "not found")
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return false
	}
	if !localOracleOriginAllowed(r) {
		writeTraceJSONError(w, http.StatusForbidden, "仅允许 Android app 本机页面发起此请求；请从 CFData app 内打开")
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" {
		writeTraceJSONError(w, http.StatusUnsupportedMediaType, "Content-Type 必须是 application/json")
		return false
	}
	return true
}

func decodeLocalOracleJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, localOracleMaxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, "请求 JSON 无效或超过大小限制")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeTraceJSONError(w, http.StatusBadRequest, "JSON 请求只能包含一个对象")
		return false
	}
	return true
}

func newLocalOracleHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("无法建立仅保存在内存中的 Oracle 登录会话")
	}
	client := *managementHTTPClient(15 * time.Second)
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client, nil
}

func doLocalOracleJSON(ctx context.Context, client *http.Client, method, path string, payload any, target any) (int, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return 0, fmt.Errorf("无法编码 Oracle 请求")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(localOracleServiceURL, "/")+path, body)
	if err != nil {
		return 0, fmt.Errorf("无法创建 Oracle HTTPS 请求")
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("连接 Oracle HTTPS 接口失败：%s", safeTraceError(err.Error()))
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, localOracleMaxReplyBody+1))
	if err != nil || len(data) > localOracleMaxReplyBody {
		return response.StatusCode, fmt.Errorf("Oracle 返回数据无法读取或超过 8 MiB 限制")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, fmt.Errorf("Oracle 接口返回 HTTP %d；请检查账号权限、Oracle 任务状态或网络连接", response.StatusCode)
	}
	if target != nil {
		if err := json.Unmarshal(data, target); err != nil {
			return response.StatusCode, fmt.Errorf("Oracle 返回的 JSON 格式无效")
		}
	}
	return response.StatusCode, nil
}

func createLocalOracleSession(client *http.Client) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", fmt.Errorf("无法创建本机 Oracle 会话")
	}
	now := time.Now()
	localOracleSessions.Lock()
	for id, session := range localOracleSessions.items {
		if now.After(session.expiresAt) {
			delete(localOracleSessions.items, id)
		}
	}
	if len(localOracleSessions.items) >= localOracleMaxSessions {
		localOracleSessions.Unlock()
		return "", fmt.Errorf("本机 Oracle 会话已满，请等待旧任务过期后重试")
	}
	localOracleSessions.items[token] = &localOracleSession{client: client, expiresAt: now.Add(localOracleSessionTTL)}
	localOracleSessions.Unlock()
	return token, nil
}

func getLocalOracleSession(token string) (*localOracleSession, bool) {
	token = strings.TrimSpace(token)
	if len(token) != 64 {
		return nil, false
	}
	now := time.Now()
	localOracleSessions.Lock()
	defer localOracleSessions.Unlock()
	session, ok := localOracleSessions.items[token]
	if !ok || now.After(session.expiresAt) {
		delete(localOracleSessions.items, token)
		return nil, false
	}
	return session, true
}

func deleteLocalOracleSession(token string) {
	localOracleSessions.Lock()
	if session, ok := localOracleSessions.items[token]; ok {
		session.client.CloseIdleConnections()
		delete(localOracleSessions.items, token)
	}
	localOracleSessions.Unlock()
}

func validateLocalOracleSelection(req *localOracleStartRequest) error {
	req.Domain = strings.TrimSpace(req.Domain)
	domain, err := validateTraceDomain(req.Domain)
	if err != nil {
		return err
	}
	req.Domain = domain
	req.Countries, err = normalizeTraceCountries(req.Countries)
	if err != nil {
		return err
	}
	if len(req.Countries) == 0 {
		return fmt.Errorf("至少选择一个国家/地区代码")
	}
	if req.PerCountry == 0 {
		req.PerCountry = traceSweepDefaultPerCountry
	}
	if req.PerCountry < 1 || req.PerCountry > traceSweepMaxPerCountry {
		return fmt.Errorf("每地区候选数必须在 1–%d 之间", traceSweepMaxPerCountry)
	}
	if req.TotalLimit == 0 {
		req.TotalLimit = traceSweepDefaultTotalLimit
	}
	if req.TotalLimit < 1 || req.TotalLimit > traceSweepMaxTotalLimit {
		return fmt.Errorf("Oracle 候选总数必须在 1–%d 之间", traceSweepMaxTotalLimit)
	}
	if req.Concurrency == 0 {
		req.Concurrency = traceSweepDefaultConcurrency
	}
	if req.Concurrency < 1 || req.Concurrency > traceSweepMaxConcurrency {
		return fmt.Errorf("Oracle 并发数必须在 1–%d 之间", traceSweepMaxConcurrency)
	}
	return nil
}

func handleLocalOraclePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/oracle-local" {
		w.Header().Set("Allow", http.MethodGet)
		http.NotFound(w, r)
		return
	}
	page, err := staticFiles.ReadFile("local_oracle_trace.html")
	if err != nil {
		http.Error(w, "无法加载 Oracle 本机复测页面", http.StatusInternalServerError)
		return
	}
	setTraceSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}

func handleLocalFlowCountersJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/local-flow-counters.js" {
		w.Header().Set("Allow", http.MethodGet)
		http.NotFound(w, r)
		return
	}
	script, err := staticFiles.ReadFile("local_flow_counters.js")
	if err != nil {
		http.Error(w, "无法加载本机复测计数器", http.StatusInternalServerError)
		return
	}
	setTraceSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(script)
}

func handleLocalOracleLogin(w http.ResponseWriter, r *http.Request) {
	if !localOracleRequest(w, r, localOracleLoginPath) {
		return
	}
	var payload localOracleLoginRequest
	if !decodeLocalOracleJSON(w, r, &payload) {
		return
	}
	payload.Username = strings.TrimSpace(payload.Username)
	if payload.Username == "" || len(payload.Username) > 256 || payload.Password == "" || len(payload.Password) > 1024 {
		writeTraceJSONError(w, http.StatusBadRequest, "请输入有效 Oracle 网页账号和密码")
		return
	}
	client, err := newLocalOracleHTTPClient()
	if err != nil {
		writeTraceJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	loginBody := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: payload.Username, Password: payload.Password}
	payload.Password = ""
	var loginResult map[string]string
	status, err := doLocalOracleJSON(r.Context(), client, http.MethodPost, "/auth/login", loginBody, &loginResult)
	loginBody.Password = ""
	if err != nil {
		message := err.Error()
		if status == http.StatusUnauthorized || status == http.StatusFound {
			message = "Oracle 登录失败（账号或密码不正确，或账号无访问权限）"
		}
		writeTraceJSONError(w, http.StatusBadGateway, message)
		return
	}
	if loginResult["status"] != "ok" {
		writeTraceJSONError(w, http.StatusBadGateway, "Oracle 登录响应未确认成功；请检查账号或服务状态")
		return
	}
	sessionID, err := createLocalOracleSession(client)
	if err != nil {
		writeTraceJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeTraceJSON(w, http.StatusCreated, map[string]any{
		"status": "connected", "session_id": sessionID,
		"expires_in_seconds": int(localOracleSessionTTL.Seconds()),
	})
}

func handleLocalOracleCountries(w http.ResponseWriter, r *http.Request) {
	if !localOracleRequest(w, r, localOracleCountriesPath) {
		return
	}
	var payload localOracleSessionRequest
	if !decodeLocalOracleJSON(w, r, &payload) {
		return
	}
	session, ok := getLocalOracleSession(payload.SessionID)
	if !ok {
		writeTraceJSONError(w, http.StatusGone, "Oracle 登录会话已失效；请重新连接账号")
		return
	}
	var response struct {
		Countries map[string]string `json:"countries"`
	}
	requestContext, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, err := doLocalOracleJSON(requestContext, session.client, http.MethodGet, "/api/trace-countries", nil, &response); err != nil {
		writeTraceJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if len(response.Countries) == 0 || len(response.Countries) > traceSweepMaxCountries {
		writeTraceJSONError(w, http.StatusBadGateway, "Oracle 地区目录为空或超过允许的 249 个选项；没有开始扫描")
		return
	}
	for code, name := range response.Countries {
		if !traceCountryCodeRE.MatchString(code) || strings.TrimSpace(name) == "" {
			writeTraceJSONError(w, http.StatusBadGateway, "Oracle 地区目录含无效项目；没有开始扫描")
			return
		}
	}
	writeTraceJSON(w, http.StatusOK, response)
}

func handleLocalOracleStart(w http.ResponseWriter, r *http.Request) {
	if !localOracleRequest(w, r, localOracleStartPath) {
		return
	}
	var payload localOracleStartRequest
	if !decodeLocalOracleJSON(w, r, &payload) {
		return
	}
	if err := validateLocalOracleSelection(&payload); err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	session, ok := getLocalOracleSession(payload.SessionID)
	if !ok {
		writeTraceJSONError(w, http.StatusGone, "Oracle 登录会话已失效；请重新连接账号")
		return
	}
	localOracleSessions.Lock()
	if session.domain != "" {
		localOracleSessions.Unlock()
		writeTraceJSONError(w, http.StatusConflict, "此 Oracle 会话已经启动筛选；请结束当前流程后再开始")
		return
	}
	localOracleSessions.Unlock()
	startPayload := traceSweepRequest{
		Source: traceSweepSourceRegional, Domain: payload.Domain, Countries: payload.Countries,
		Port: 443, PerCountry: payload.PerCountry, TotalLimit: payload.TotalLimit, Concurrency: payload.Concurrency,
	}
	requestContext, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	status, err := doLocalOracleJSON(requestContext, session.client, http.MethodPost, "/api/trace-sweep/start", startPayload, nil)
	if err != nil {
		message := err.Error()
		if status == http.StatusConflict {
			message = "Oracle 已有筛选任务运行中；请先在 Oracle 页面结束该任务，再重试"
		}
		writeTraceJSONError(w, http.StatusBadGateway, message)
		return
	}
	if status != http.StatusAccepted {
		writeTraceJSONError(w, http.StatusBadGateway, fmt.Sprintf("Oracle 未接受筛选任务（HTTP %d）", status))
		return
	}
	if r.Context().Err() != nil {
		stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = doLocalOracleJSON(stopContext, session.client, http.MethodPost, "/api/trace-sweep/stop", nil, nil)
		stopCancel()
		return
	}
	localOracleSessions.Lock()
	if current, exists := localOracleSessions.items[payload.SessionID]; exists && current == session {
		session.domain = payload.Domain
	} else {
		localOracleSessions.Unlock()
		stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = doLocalOracleJSON(stopContext, session.client, http.MethodPost, "/api/trace-sweep/stop", nil, nil)
		stopCancel()
		writeTraceJSONError(w, http.StatusGone, "本机 Oracle 会话已失效；已尝试停止远端任务")
		return
	}
	localOracleSessions.Unlock()
	writeTraceJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted", "domain": payload.Domain,
		"expires_in_seconds": int(localOracleSessionTTL.Seconds()),
	})
}

func handleLocalOracleStatus(w http.ResponseWriter, r *http.Request) {
	if !localOracleRequest(w, r, localOracleStatusPath) {
		return
	}
	var payload localOracleSessionRequest
	if !decodeLocalOracleJSON(w, r, &payload) {
		return
	}
	session, ok := getLocalOracleSession(payload.SessionID)
	if !ok {
		writeTraceJSONError(w, http.StatusGone, "Oracle 登录会话已失效；请重新启动这一轮筛选")
		return
	}
	if session.domain == "" {
		writeTraceJSONError(w, http.StatusConflict, "请先选择 Oracle 地区并启动筛选")
		return
	}
	var status traceSweepSnapshot
	requestContext, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, err := doLocalOracleJSON(requestContext, session.client, http.MethodGet, "/api/trace-sweep/status", nil, &status); err != nil {
		writeTraceJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if status.Domain != "" && status.Domain != session.domain {
		writeTraceJSONError(w, http.StatusConflict, "Oracle 当前任务域名与本轮不一致；为避免错测，已停止本机复测")
		return
	}
	response := map[string]any{
		"running": status.Running, "phase": status.Phase, "message": status.Message,
		"scanned": status.Scanned, "total": status.Total, "success": status.Success,
		"error": status.Error, "domain": status.Domain,
	}
	if status.Running {
		writeTraceJSON(w, http.StatusOK, response)
		return
	}
	if status.Phase != "完成" {
		if status.Phase == "失败" && status.Error != "" {
			response["error"] = status.Error
		}
		writeTraceJSON(w, http.StatusOK, response)
		return
	}
	var resultPayload struct {
		Results []traceCheckResult `json:"results"`
	}
	if _, err := doLocalOracleJSON(requestContext, session.client, http.MethodGet, "/api/trace-sweep/results", nil, &resultPayload); err != nil {
		writeTraceJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if len(resultPayload.Results) > traceSweepMaxTotalLimit {
		writeTraceJSONError(w, http.StatusBadGateway, "Oracle 返回候选数超过本机允许的 2,000 条上限；未启动本机复测")
		return
	}
	candidates := make([]traceCheckResult, 0, len(resultPayload.Results))
	for _, result := range resultPayload.Results {
		if result.OK {
			candidates = append(candidates, result)
		}
	}
	response["candidates"] = candidates
	response["candidate_count"] = len(candidates)
	writeTraceJSON(w, http.StatusOK, response)
}

func handleLocalOracleCancel(w http.ResponseWriter, r *http.Request) {
	if !localOracleRequest(w, r, localOracleCancelPath) {
		return
	}
	var payload localOracleSessionRequest
	if !decodeLocalOracleJSON(w, r, &payload) {
		return
	}
	session, ok := getLocalOracleSession(payload.SessionID)
	if !ok {
		writeTraceJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	requestContext, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	status, err := doLocalOracleJSON(requestContext, session.client, http.MethodPost, "/api/trace-sweep/stop", nil, nil)
	if err != nil && status != http.StatusConflict {
		writeTraceJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeTraceJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func handleLocalOracleFinish(w http.ResponseWriter, r *http.Request) {
	if !localOracleRequest(w, r, localOracleFinishPath) {
		return
	}
	var payload localOracleSessionRequest
	if !decodeLocalOracleJSON(w, r, &payload) {
		return
	}
	deleteLocalOracleSession(payload.SessionID)
	writeTraceJSON(w, http.StatusOK, map[string]string{"status": "finished"})
}
