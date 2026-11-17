package main

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	traceSweepSourceFOFA         = "fofa"
	traceSweepSourceRegional     = "regional"
	traceSweepDefaultPerCountry  = 10
	traceSweepMaxPerCountry      = 200
	traceSweepDefaultTotalLimit  = 500
	traceSweepMaxTotalLimit      = 2000
	traceSweepMaxCountries       = 249
	traceSweepDefaultConcurrency = 8
	traceSweepMaxConcurrency     = 16
	traceSweepMaxRequestBytes    = 8192
	traceSweepQueryRateDelay     = 1 * time.Second
	traceSweepFOFATimeout        = 20 * time.Second
	traceSweepFOFAMaxBody        = 4 << 20
	traceSweepPublicMaxBody      = 8 << 20
	traceSweepPublicTimeout      = 25 * time.Second
	traceSweepCFRangeTimeout     = 10 * time.Second
	traceSweepCFRangeMaxBody     = 16 << 10
	traceSweepCFRangeAPIURL      = "https://api.cloudflare.com/client/v4/ips"
)

var (
	traceCountryCodeRE   = regexp.MustCompile(`^[A-Z]{2}$`)
	fofaAPIBaseURL       = "https://fofa.info"
	fofaHTTPClient       = &http.Client{Timeout: traceSweepFOFATimeout}
	proxyIPDataURL       = "https://gh.anglesya.win/NiREvil/vless/raw/main/sub/ProxyIP-for-zizifn.json"
	traceRegionalOnly    bool
	publicIPHTTPClient   *http.Client
	traceCountryDataOnce sync.Once
	traceCountryData     map[string]string
	traceCountryDataErr  error
	traceCFRangeCache    = struct {
		sync.Mutex
		prefixes  []netip.Prefix
		expiresAt time.Time
	}{}
)

type traceSweepRequest struct {
	Source      string   `json:"source"`
	Domain      string   `json:"domain"`
	Countries   []string `json:"countries"`
	Port        int      `json:"port"`
	PerCountry  int      `json:"per_country"`
	TotalLimit  int      `json:"total_limit"`
	Concurrency int      `json:"concurrency"`
}

type traceSweepSnapshot struct {
	Running         bool      `json:"running"`
	Phase           string    `json:"phase"`
	Message         string    `json:"message"`
	Source          string    `json:"source,omitempty"`
	Domain          string    `json:"domain,omitempty"`
	Countries       []string  `json:"countries,omitempty"`
	Port            int       `json:"port,omitempty"`
	PerCountry      int       `json:"per_country,omitempty"`
	TotalLimit      int       `json:"total_limit,omitempty"`
	Concurrency     int       `json:"concurrency,omitempty"`
	QueriesDone     int       `json:"queries_done"`
	QueriesTotal    int       `json:"queries_total"`
	SourceFetched   int       `json:"source_fetched"`
	SourceRegions   int       `json:"source_regions"`
	CFExcluded      int       `json:"cloudflare_excluded"`
	SourceUpdatedAt string    `json:"source_updated_at,omitempty"`
	Total           int       `json:"total"`
	Scanned         int       `json:"scanned"`
	Success         int       `json:"success"`
	Failed          int       `json:"failed"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
	Error           string    `json:"error,omitempty"`
}

type traceSweepCandidate struct {
	Address traceCandidate
	Source  string
	Country string
	City    string
	Region  string
	ISP     string
	Risk    string
	Score   int
}

type fofaSearchResponse struct {
	Error   bool       `json:"error"`
	Errmsg  string     `json:"errmsg"`
	Results [][]string `json:"results"`
}

type proxyIPDataset struct {
	UpdatedAt string          `json:"updated_at"`
	Proxies   []proxyIPRecord `json:"proxies"`
}

type proxyIPRecord struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	ISP     string `json:"isp"`
	Country string `json:"country"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Score   int    `json:"score"`
	Risk    string `json:"risk"`
}

var traceSweepState = struct {
	sync.RWMutex
	status  traceSweepSnapshot
	results []traceCheckResult
	session *appSession
	cancel  context.CancelFunc
}{status: traceSweepSnapshot{Phase: "idle", Message: "尚未开始"}}

func traceCountryCatalog() (map[string]string, error) {
	traceCountryDataOnce.Do(func() {
		data, err := staticFiles.ReadFile("trace_countries.json")
		if err != nil {
			traceCountryDataErr = fmt.Errorf("无法加载 ISO 国家/地区代码清单")
			return
		}
		var names map[string]string
		if err := json.Unmarshal(data, &names); err != nil || len(names) != traceSweepMaxCountries {
			traceCountryDataErr = fmt.Errorf("ISO 国家/地区代码清单格式无效")
			return
		}
		for code, name := range names {
			if !traceCountryCodeRE.MatchString(code) || strings.TrimSpace(name) == "" {
				traceCountryDataErr = fmt.Errorf("ISO 国家/地区代码清单含无效项目")
				return
			}
		}
		traceCountryData = names
	})
	if traceCountryDataErr != nil {
		return nil, traceCountryDataErr
	}
	return traceCountryData, nil
}

func handleTraceCountryList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	names, err := traceCountryCatalog()
	if err != nil {
		writeTraceJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeTraceJSON(w, http.StatusOK, map[string]map[string]string{"countries": names})
}

func normalizeTraceSweepSource(value string) (string, error) {
	source := strings.ToLower(strings.TrimSpace(value))
	if source == "" {
		source = traceSweepSourceRegional
	}
	if source != traceSweepSourceRegional && source != traceSweepSourceFOFA {
		return "", fmt.Errorf("候选来源仅支持 regional 或 fofa")
	}
	if traceRegionalOnly && source != traceSweepSourceRegional {
		return "", fmt.Errorf("此独立服务仅允许使用公开区域名单作为候选来源")
	}
	return source, nil
}

func handleTraceSweepStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !validTraceOrigin(r) {
		writeTraceJSONError(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeTraceJSONError(w, http.StatusUnsupportedMediaType, "Content-Type 必须是 application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, traceSweepMaxRequestBytes)
	var req traceSweepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, "请求 JSON 无效或过大")
		return
	}
	source, err := normalizeTraceSweepSource(req.Source)
	if err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	domain, err := validateTraceDomain(req.Domain)
	if err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	countries, err := normalizeTraceCountries(req.Countries)
	if err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Port < 1 || req.Port > 65535 {
		writeTraceJSONError(w, http.StatusBadRequest, "端口必须在 1–65535 之间")
		return
	}
	req.PerCountry, err = normalizeTraceSweepPerCountry(req.PerCountry)
	if err != nil {
		writeTraceJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.TotalLimit == 0 {
		req.TotalLimit = traceSweepDefaultTotalLimit
	}
	if req.TotalLimit < 1 || req.TotalLimit > traceSweepMaxTotalLimit {
		writeTraceJSONError(w, http.StatusBadRequest, fmt.Sprintf("整批候选上限必须在 1–%d 之间", traceSweepMaxTotalLimit))
		return
	}
	if req.Concurrency == 0 {
		req.Concurrency = traceSweepDefaultConcurrency
	}
	if req.Concurrency < 1 || req.Concurrency > traceSweepMaxConcurrency {
		writeTraceJSONError(w, http.StatusBadRequest, fmt.Sprintf("Trace 并发数必须在 1–%d 之间", traceSweepMaxConcurrency))
		return
	}
	if source == traceSweepSourceFOFA && strings.TrimSpace(os.Getenv("FOFA_KEY")) == "" {
		writeTraceJSONError(w, http.StatusServiceUnavailable, "服务器尚未配置 FOFA_KEY；请由部署者在服务器环境变量中设置 FOFA API Key")
		return
	}

	traceSweepState.Lock()
	if traceSweepState.status.Running {
		traceSweepState.Unlock()
		writeTraceJSONError(w, http.StatusConflict, "已有地区候选初筛任务正在运行")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &appSession{}
	params := map[string]interface{}{
		"source": source, "domain": domain, "countries": countries, "port": req.Port,
		"per_country": req.PerCountry, "total_limit": req.TotalLimit, "concurrency": req.Concurrency,
	}
	if !session.beginTask(cancel, "地区 Trace 候选初筛", "trace-sweep", params) {
		cancel()
		traceSweepState.Unlock()
		writeTraceJSONError(w, http.StatusConflict, "CFData-WEB 当前已有任务运行，请结束后再开始地区初筛")
		return
	}
	queriesTotal := 1
	if source == traceSweepSourceFOFA {
		queriesTotal = len(countries)
	}
	traceSweepState.status = traceSweepSnapshot{
		Running: true, Phase: "准备", Message: fmt.Sprintf("准备从 %s 来源读取候选，最多检测 %d 条", source, req.TotalLimit), Source: source,
		Domain: domain, Countries: countries, Port: req.Port,
		PerCountry: req.PerCountry, TotalLimit: req.TotalLimit, Concurrency: req.Concurrency,
		QueriesTotal: queriesTotal,
		StartedAt:    time.Now(),
	}
	traceSweepState.results = nil
	traceSweepState.session = session
	traceSweepState.cancel = cancel
	traceSweepState.Unlock()

	safeGo("trace-sweep", session, func() {
		var runErr error
		defer func() {
			if recovered := recover(); recovered != nil {
				runErr = fmt.Errorf("后台任务异常: %v", recovered)
			}
			wasCanceled := ctx.Err() != nil
			session.endTask()
			traceSweepState.Lock()
			traceSweepState.status.Running = false
			traceSweepState.status.FinishedAt = time.Now()
			if wasCanceled {
				traceSweepState.status.Phase = "已停止"
				traceSweepState.status.Message = "任务已停止，保留已完成结果"
			} else if runErr != nil {
				traceSweepState.status.Phase = "失败"
				traceSweepState.status.Message = "任务未能完成"
				traceSweepState.status.Error = runErr.Error()
			} else {
				traceSweepState.status.Phase = "完成"
				traceSweepState.status.Message = fmt.Sprintf("完成：%d 个候选中 %d 个返回有效 Trace", traceSweepState.status.Total, traceSweepState.status.Success)
			}
			traceSweepState.session = nil
			traceSweepState.cancel = nil
			traceSweepState.Unlock()
			cancel()
		}()
		runErr = runTraceSweep(ctx, source, domain, countries, req.Port, req.PerCountry, req.TotalLimit, req.Concurrency)
	})

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func handleTraceSweepStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	traceSweepState.RLock()
	status := traceSweepState.status
	status.Countries = append([]string(nil), status.Countries...)
	traceSweepState.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

func handleTraceSweepResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	traceSweepState.RLock()
	results := append([]traceCheckResult(nil), traceSweepState.results...)
	traceSweepState.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

func handleTraceSweepStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !validTraceOrigin(r) {
		writeTraceJSONError(w, http.StatusForbidden, "请求来源校验失败")
		return
	}
	traceSweepState.RLock()
	cancel := traceSweepState.cancel
	running := traceSweepState.status.Running
	traceSweepState.RUnlock()
	if !running || cancel == nil {
		writeTraceJSONError(w, http.StatusConflict, "当前没有运行中的地区初筛任务")
		return
	}
	cancel()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopping"})
}

func handleTraceSweepExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeTraceJSONError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	traceSweepState.RLock()
	results := append([]traceCheckResult(nil), traceSweepState.results...)
	traceSweepState.RUnlock()
	sort.Slice(results, func(i, j int) bool {
		if results[i].SourceCountry != results[j].SourceCountry {
			return results[i].SourceCountry < results[j].SourceCountry
		}
		return results[i].Candidate < results[j].Candidate
	})
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch format {
	case "", "txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="trace-candidates.txt"`)
		for _, result := range results {
			_, _ = fmt.Fprintln(w, result.Candidate)
		}
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="trace-candidates.csv"`)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"candidate", "source", "source_country", "source_city", "source_region", "source_isp", "source_risk", "loc", "colo", "trace_ip", "tls_version", "http_status", "elapsed_ms"})
		for _, result := range results {
			_ = writer.Write([]string{
				result.Candidate, result.Source, result.SourceCountry, result.SourceCity, result.SourceRegion, result.SourceISP, result.SourceRisk,
				result.Trace["loc"], result.Trace["colo"], result.Trace["ip"],
				result.TLSVersion, strconv.Itoa(result.HTTPStatus), strconv.FormatInt(result.ElapsedMS, 10),
			})
		}
		writer.Flush()
	default:
		writeTraceJSONError(w, http.StatusBadRequest, "format 仅支持 txt 或 csv")
	}
}

func runTraceSweep(ctx context.Context, source, domain string, countries []string, port, perCountry, totalLimit, concurrency int) error {
	updateTraceSweep(func(status *traceSweepSnapshot) {
		status.Phase = "加载排除清单"
		status.Message = "正在读取 Cloudflare 官方网段清单（仅用于排除，不作为候选）"
	})
	cloudflarePrefixes, err := loadCloudflareExclusionPrefixes(ctx)
	if err != nil {
		return err
	}
	var candidates []traceSweepCandidate
	fetched, excluded := 0, 0
	if source == traceSweepSourceRegional {
		updateTraceSweep(func(status *traceSweepSnapshot) {
			status.Phase = "读取可选地区清单"
			status.Message = "正在读取 NiREvil/VLESS 地区清单（仅下载；上游验证不保证兼容任意 Host 或严格 TLS）"
		})
		dataset, err := fetchPublicProxyIPDataset(ctx)
		if err != nil {
			return err
		}
		candidates, excluded = selectPublicProxyIPCandidates(dataset.Proxies, countries, perCountry, totalLimit, cloudflarePrefixes)
		fetched = len(dataset.Proxies)
		updateTraceSweep(func(status *traceSweepSnapshot) {
			status.QueriesDone = 1
			status.QueriesTotal = 1
			status.SourceFetched = fetched
			status.SourceRegions = countProxyIPCountries(dataset.Proxies)
			status.CFExcluded = excluded
			status.Total = len(candidates)
			status.SourceUpdatedAt = dataset.UpdatedAt
		})
	} else {
		allCandidates := make([]traceSweepCandidate, 0, len(countries)*perCountry)
		for index, country := range countries {
			if ctx.Err() != nil {
				return nil
			}
			if index > 0 {
				if err := waitTraceSweepRateLimit(ctx); err != nil {
					return nil
				}
			}
			updateTraceSweep(func(status *traceSweepSnapshot) {
				status.Phase = "FOFA 查询"
				status.Message = fmt.Sprintf("FOFA 查询地区 %s（%d/%d）", country, index+1, len(countries))
			})
			countryCandidates, count, countryExcluded, err := fetchFOFACandidates(ctx, country, port, perCountry, cloudflarePrefixes)
			if err != nil {
				return err
			}
			fetched += count
			excluded += countryExcluded
			allCandidates = append(allCandidates, countryCandidates...)
			updateTraceSweep(func(status *traceSweepSnapshot) {
				status.QueriesDone = index + 1
				status.SourceFetched = fetched
				status.CFExcluded = excluded
			})
		}
		candidates = applyTraceCandidateCaps(allCandidates, countries, perCountry, totalLimit)
	}
	if ctx.Err() != nil {
		return nil
	}
	updateTraceSweep(func(status *traceSweepSnapshot) {
		status.Phase = "Trace 检测"
		status.Total = len(candidates)
		status.Message = fmt.Sprintf("来源返回 %d 条记录；按地区上限与整批上限筛出 %d 个 IP:端口", fetched, len(candidates))
	})
	if len(candidates) == 0 {
		return nil
	}
	workers := concurrency
	if workers > len(candidates) {
		workers = len(candidates)
	}
	var next int64
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				index := int(atomic.AddInt64(&next, 1) - 1)
				if index >= len(candidates) {
					return
				}
				candidate := candidates[index]
				result := runTraceCheck(ctx, candidate.Address, domain)
				if ctx.Err() != nil {
					return
				}
				result.Source = candidate.Source
				result.SourceCountry = candidate.Country
				result.SourceCity = candidate.City
				result.SourceRegion = candidate.Region
				result.SourceISP = candidate.ISP
				result.SourceRisk = candidate.Risk
				result.SourceScore = candidate.Score
				traceSweepState.Lock()
				traceSweepState.status.Scanned++
				if result.OK {
					traceSweepState.status.Success++
					traceSweepState.results = append(traceSweepState.results, result)
				} else {
					traceSweepState.status.Failed++
				}
				traceSweepState.status.Message = fmt.Sprintf("已检测 %d/%d；有效 %d", traceSweepState.status.Scanned, traceSweepState.status.Total, traceSweepState.status.Success)
				traceSweepState.Unlock()
			}
		}()
	}
	wg.Wait()
	return nil
}

func fetchPublicProxyIPDataset(ctx context.Context) (proxyIPDataset, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyIPDataURL, nil)
	if err != nil {
		return proxyIPDataset{}, fmt.Errorf("无法创建 NiREvil/VLESS 地区候选清单请求")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CFData-WEB-Trace/1.0")
	client := publicIPHTTPClient
	if client == nil {
		client = managementHTTPClient(traceSweepPublicTimeout)
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return proxyIPDataset{}, ctx.Err()
		}
		return proxyIPDataset{}, fmt.Errorf("读取 NiREvil/VLESS 地区候选清单失败：%s", safeTraceError(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proxyIPDataset{}, fmt.Errorf("NiREvil/VLESS 地区候选清单返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, traceSweepPublicMaxBody+1))
	if err != nil || len(body) > traceSweepPublicMaxBody {
		return proxyIPDataset{}, fmt.Errorf("NiREvil/VLESS 地区候选清单读取失败或超过大小限制")
	}
	var dataset proxyIPDataset
	if err := json.Unmarshal(body, &dataset); err != nil || len(dataset.Proxies) == 0 || len(dataset.Proxies) > 100000 {
		return proxyIPDataset{}, fmt.Errorf("NiREvil/VLESS 地区候选清单格式无效或记录数超限")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(dataset.UpdatedAt)); err != nil {
		return proxyIPDataset{}, fmt.Errorf("NiREvil/VLESS 地区候选清单缺少有效更新时间")
	}
	return dataset, nil
}

func countProxyIPCountries(records []proxyIPRecord) int {
	countries := make(map[string]struct{})
	for _, record := range records {
		country := strings.ToUpper(strings.TrimSpace(record.Country))
		if traceCountryCodeRE.MatchString(country) {
			countries[country] = struct{}{}
		}
	}
	return len(countries)
}

func selectPublicProxyIPCandidates(records []proxyIPRecord, countries []string, perCountry, totalLimit int, excludedPrefixes []netip.Prefix) ([]traceSweepCandidate, int) {
	selected := make(map[string]struct{}, len(countries))
	for _, country := range countries {
		selected[country] = struct{}{}
	}
	groups := make(map[string][]traceSweepCandidate, len(countries))
	seen := make(map[string]struct{}, len(records))
	excluded := 0
	for _, record := range records {
		country := strings.ToUpper(strings.TrimSpace(record.Country))
		if _, ok := selected[country]; !ok {
			continue
		}
		candidate, ok := parsePublicProxyIPRecord(record)
		if !ok {
			continue
		}
		if traceIPInPrefixes(candidate.Address.Address, excludedPrefixes) {
			excluded++
			continue
		}
		if _, exists := seen[candidate.Address.Canonical]; exists {
			continue
		}
		seen[candidate.Address.Canonical] = struct{}{}
		groups[country] = append(groups[country], candidate)
	}
	return applyTraceCandidateCaps(groupsToSlice(groups, countries), countries, perCountry, totalLimit), excluded
}

func parsePublicProxyIPRecord(record proxyIPRecord) (traceSweepCandidate, bool) {
	country := strings.ToUpper(strings.TrimSpace(record.Country))
	if !traceCountryCodeRE.MatchString(country) || record.Port < 1 || record.Port > 65535 {
		return traceSweepCandidate{}, false
	}
	address := net.JoinHostPort(strings.TrimSpace(record.IP), strconv.Itoa(record.Port))
	parsed, err := parseTraceCandidate(address)
	if err != nil {
		return traceSweepCandidate{}, false
	}
	return traceSweepCandidate{
		Address: parsed, Source: "NiREvil/vless regional (arbitrary Host unverified)", Country: country,
		City: strings.TrimSpace(record.City), Region: strings.TrimSpace(record.Region),
		ISP: strings.TrimSpace(record.ISP), Risk: strings.TrimSpace(record.Risk), Score: record.Score,
	}, true
}

func groupsToSlice(groups map[string][]traceSweepCandidate, countries []string) []traceSweepCandidate {
	all := make([]traceSweepCandidate, 0)
	for _, country := range countries {
		all = append(all, groups[country]...)
	}
	return all
}

func applyTraceCandidateCaps(candidates []traceSweepCandidate, countries []string, perCountry, totalLimit int) []traceSweepCandidate {
	groups := make(map[string][]traceSweepCandidate, len(countries))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, exists := seen[candidate.Address.Canonical]; exists {
			continue
		}
		seen[candidate.Address.Canonical] = struct{}{}
		if len(groups[candidate.Country]) < perCountry {
			groups[candidate.Country] = append(groups[candidate.Country], candidate)
		}
	}
	result := make([]traceSweepCandidate, 0, minInt(totalLimit, len(candidates)))
	for round := 0; len(result) < totalLimit; round++ {
		added := false
		for _, country := range countries {
			if round < len(groups[country]) {
				result = append(result, groups[country][round])
				added = true
				if len(result) == totalLimit {
					break
				}
			}
		}
		if !added {
			break
		}
	}
	return result
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func waitTraceSweepRateLimit(ctx context.Context) error {
	timer := time.NewTimer(traceSweepQueryRateDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func fetchFOFACandidates(ctx context.Context, country string, port, limit int, excludedPrefixes []netip.Prefix) ([]traceSweepCandidate, int, int, error) {
	query := buildFOFAQuery(country, port)
	response, err := queryFOFA(ctx, query, 1, limit)
	if err != nil {
		return nil, 0, 0, err
	}
	candidates := make([]traceSweepCandidate, 0, len(response.Results))
	seen := make(map[string]struct{}, len(response.Results))
	excluded := 0
	for _, row := range response.Results {
		candidate, ok := parseFOFACandidate(row)
		if !ok {
			continue
		}
		if traceIPInPrefixes(candidate.Address.Address, excludedPrefixes) {
			excluded++
			continue
		}
		if _, exists := seen[candidate.Address.Canonical]; exists {
			continue
		}
		seen[candidate.Address.Canonical] = struct{}{}
		candidate.Source = "FOFA"
		candidates = append(candidates, candidate)
	}
	return candidates, len(response.Results), excluded, nil
}

func buildFOFAQuery(country string, port int) string {
	return fmt.Sprintf(`server="cloudflare" && header="Forbidden" && asn!="13335" && asn!="209242" && country="%s" && port="%d"`, country, port)
}

func loadCloudflareExclusionPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	return loadCloudflareExclusionPrefixesFrom(ctx, cloudflareRangeHTTPClient(),
		"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6", traceSweepCFRangeAPIURL)
}

// cloudflareRangeHTTPClient reuses the app's DNS-aware, TLS-verifying management transport.
func cloudflareRangeHTTPClient() *http.Client {
	return managementHTTPClient(traceSweepCFRangeTimeout)
}

func loadCloudflareExclusionPrefixesFrom(ctx context.Context, client *http.Client, ipv4URL, ipv6URL, apiURL string) ([]netip.Prefix, error) {
	textPrefixes, textErr := loadCloudflareTextRanges(ctx, client, ipv4URL, ipv6URL)
	if textErr == nil {
		return textPrefixes, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	apiPrefixes, apiErr := loadCloudflareAPIRanges(ctx, client, apiURL)
	if apiErr == nil {
		return apiPrefixes, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, fmt.Errorf("无法确认 Cloudflare 官方 IPv4/IPv6 排除清单；文本端点失败：%v；官方 API 备用源失败：%v。为避免误测官方段，本次停止", textErr, apiErr)
}

func loadCloudflareTextRanges(ctx context.Context, client *http.Client, ipv4URL, ipv6URL string) ([]netip.Prefix, error) {
	ipv4Body, err := fetchCloudflareRangeBody(ctx, client, ipv4URL)
	if err != nil {
		return nil, fmt.Errorf("IPv4 文本清单：%w", err)
	}
	ipv6Body, err := fetchCloudflareRangeBody(ctx, client, ipv6URL)
	if err != nil {
		return nil, fmt.Errorf("IPv6 文本清单：%w", err)
	}
	prefixes, err := parseCloudflareRangeLists(strings.Fields(string(ipv4Body)), strings.Fields(string(ipv6Body)))
	if err != nil {
		return nil, fmt.Errorf("文本清单校验失败：%w", err)
	}
	return prefixes, nil
}

func loadCloudflareAPIRanges(ctx context.Context, client *http.Client, endpoint string) ([]netip.Prefix, error) {
	body, err := fetchCloudflareRangeBody(ctx, client, endpoint)
	if err != nil {
		return nil, err
	}
	var response struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4CIDRs []string `json:"ipv4_cidrs"`
			IPv6CIDRs []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("官方 API JSON 格式无效：%w", err)
	}
	if !response.Success {
		return nil, fmt.Errorf("官方 API 未返回 success=true")
	}
	prefixes, err := parseCloudflareRangeLists(response.Result.IPv4CIDRs, response.Result.IPv6CIDRs)
	if err != nil {
		return nil, fmt.Errorf("官方 API 网段校验失败：%w", err)
	}
	return prefixes, nil
}

func fetchCloudflareRangeBody(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("无法创建请求：%w", err)
	}
	req.Header.Set("Accept", "text/plain, application/json")
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("请求失败：%w", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, traceSweepCFRangeMaxBody+1))
	if readErr != nil {
		return nil, fmt.Errorf("读取响应失败：%w", readErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if len(body) > traceSweepCFRangeMaxBody {
		return nil, fmt.Errorf("响应超过 %d 字节限制", traceSweepCFRangeMaxBody)
	}
	return body, nil
}

func parseCloudflareRangeLists(ipv4, ipv6 []string) ([]netip.Prefix, error) {
	if len(ipv4) == 0 || len(ipv6) == 0 {
		return nil, fmt.Errorf("IPv4 或 IPv6 清单为空")
	}
	prefixes := make([]netip.Prefix, 0, len(ipv4)+len(ipv6))
	for _, group := range []struct {
		name   string
		values []string
		isIPv4 bool
	}{{"IPv4", ipv4, true}, {"IPv6", ipv6, false}} {
		for _, value := range group.values {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("%s 清单含无效 CIDR %q", group.name, value)
			}
			prefix = prefix.Masked()
			if prefix.Addr().Is4() != group.isIPv4 || !isTracePublicIP(prefix.Addr()) {
				return nil, fmt.Errorf("%s 清单地址族或地址范围异常：%s", group.name, prefix)
			}
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, nil
}

func validateCloudflareExclusionPrefixes(prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return fmt.Errorf("Cloudflare 官方网段清单为空")
	}
	hasIPv4, hasIPv6 := false, false
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !isTracePublicIP(prefix.Addr()) {
			return fmt.Errorf("Cloudflare 官方网段清单含无效或非公网范围")
		}
		if prefix.Addr().Is4() {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	if !hasIPv4 || !hasIPv6 {
		return fmt.Errorf("Cloudflare 官方 IPv4/IPv6 网段清单不完整")
	}
	return nil
}

func cachedCloudflareExclusionPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	traceCFRangeCache.Lock()
	defer traceCFRangeCache.Unlock()
	if len(traceCFRangeCache.prefixes) > 0 && time.Now().Before(traceCFRangeCache.expiresAt) {
		if err := validateCloudflareExclusionPrefixes(traceCFRangeCache.prefixes); err == nil {
			return append([]netip.Prefix(nil), traceCFRangeCache.prefixes...), nil
		}
		traceCFRangeCache.prefixes = nil
		traceCFRangeCache.expiresAt = time.Time{}
	}
	prefixes, err := loadCloudflareExclusionPrefixes(ctx)
	if err == nil {
		err = validateCloudflareExclusionPrefixes(prefixes)
	}
	if err != nil {
		traceCFRangeCache.prefixes = nil
		traceCFRangeCache.expiresAt = time.Time{}
		return nil, fmt.Errorf("无法确认 Cloudflare 官方网段；为避免扫描官方地址，本机检测已停止：%w", err)
	}
	traceCFRangeCache.prefixes = append([]netip.Prefix(nil), prefixes...)
	traceCFRangeCache.expiresAt = time.Now().Add(30 * time.Minute)
	return append([]netip.Prefix(nil), prefixes...), nil
}

func traceIPInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func queryFOFA(ctx context.Context, query string, page, size int) (fofaSearchResponse, error) {
	key := strings.TrimSpace(os.Getenv("FOFA_KEY"))
	if key == "" {
		return fofaSearchResponse{}, fmt.Errorf("FOFA_KEY 未配置")
	}
	values := url.Values{}
	values.Set("key", key)
	values.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	values.Set("page", strconv.Itoa(page))
	values.Set("size", strconv.Itoa(size))
	values.Set("fields", "ip,port,country,city")
	endpoint := strings.TrimRight(fofaAPIBaseURL, "/") + "/api/v1/search/all?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fofaSearchResponse{}, fmt.Errorf("创建 FOFA 请求失败")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := fofaHTTPClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return fofaSearchResponse{}, ctx.Err()
		}
		return fofaSearchResponse{}, fmt.Errorf("连接 FOFA API 失败：%s", safeTraceError(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, traceSweepFOFAMaxBody))
		return fofaSearchResponse{}, fmt.Errorf("FOFA API 返回 HTTP %d；请检查 API Key、账户权限和查询额度", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, traceSweepFOFAMaxBody+1))
	if err != nil {
		return fofaSearchResponse{}, fmt.Errorf("读取 FOFA API 响应失败")
	}
	if len(body) > traceSweepFOFAMaxBody {
		return fofaSearchResponse{}, fmt.Errorf("FOFA API 响应超出大小限制")
	}
	var response fofaSearchResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fofaSearchResponse{}, fmt.Errorf("无法解析 FOFA API 响应")
	}
	if response.Error {
		return fofaSearchResponse{}, fmt.Errorf("FOFA 查询被拒绝；请检查 API Key、账户权限、F 点额度和查询条件")
	}
	return response, nil
}

func parseFOFACandidate(row []string) (traceSweepCandidate, bool) {
	if len(row) < 4 {
		return traceSweepCandidate{}, false
	}
	ip := strings.TrimSpace(row[0])
	portText := strings.TrimSpace(row[1])
	country := strings.ToUpper(strings.TrimSpace(row[2]))
	city := strings.TrimSpace(row[3])
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return traceSweepCandidate{}, false
	}
	host := strings.Trim(ip, "[]")
	address := net.JoinHostPort(host, strconv.Itoa(port))
	parsed, err := parseTraceCandidate(address)
	if err != nil {
		return traceSweepCandidate{}, false
	}
	return traceSweepCandidate{Address: parsed, Source: "FOFA", Country: country, City: city}, true
}

func normalizeTraceSweepPerCountry(value int) (int, error) {
	if value == 0 {
		return traceSweepDefaultPerCountry, nil
	}
	if value < 1 || value > traceSweepMaxPerCountry {
		return 0, fmt.Errorf("每地区结果上限必须在 1–%d 之间", traceSweepMaxPerCountry)
	}
	return value, nil
}

func normalizeTraceCountries(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > traceSweepMaxCountries {
		return nil, fmt.Errorf("国家/地区数量必须为 1–%d 个 ISO 两字母代码", traceSweepMaxCountries)
	}
	catalog, err := traceCountryCatalog()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(values))
	countries := make([]string, 0, len(values))
	for _, value := range values {
		country := strings.ToUpper(strings.TrimSpace(value))
		if !traceCountryCodeRE.MatchString(country) {
			return nil, fmt.Errorf("无效国家/地区代码：%q（请使用 ISO 两字母代码，例如 JP、HK、SG、TW）", value)
		}
		if _, supported := catalog[country]; !supported {
			return nil, fmt.Errorf("未收录的国家/地区代码：%q；请从 ISO 国家/地区列表中选择", country)
		}
		if _, exists := seen[country]; exists {
			continue
		}
		seen[country] = struct{}{}
		countries = append(countries, country)
	}
	if len(countries) == 0 {
		return nil, fmt.Errorf("请至少选择一个国家/地区代码")
	}
	return countries, nil
}

func updateTraceSweep(update func(*traceSweepSnapshot)) {
	traceSweepState.Lock()
	update(&traceSweepState.status)
	traceSweepState.Unlock()
}

func validTraceOrigin(r *http.Request) bool {
	return validateTraceOrigin(r)
}

func writeTraceJSONError(w http.ResponseWriter, status int, message string) {
	writeTraceJSON(w, status, map[string]string{"error": message})
}

func safeTraceError(value string) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\r", " ")
	if strings.Contains(value, "fofa.info") {
		return "网络请求失败"
	}
	if len(value) > 160 {
		value = value[:160] + "…"
	}
	return value
}
