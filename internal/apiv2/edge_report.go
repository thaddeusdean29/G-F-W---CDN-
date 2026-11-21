package apiv2

import (
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"cdn/internal/config"
	"cdn/internal/secure"
)

// ---------------------------------------------------------------------------
// 边缘主动上报：cdnedge 每 reportInterval 把统计快照 POST 到 /api/v2/edge/report，
// 主控只在内存里保留每个节点最近一份，安全/统计页直接读快照，不再回连边缘拉取。
// 快照按节点 ID 存；读取时只按本代理自己的节点 ID 取，再按本代理域名过滤，租户之间互不可见。
// ---------------------------------------------------------------------------

// 上报字段名，与 internal/edgeapi/report.go BuildReport 的键一一对应。
const (
	reportStatus       = "status"
	reportOverview     = "overview"
	reportDomainStats  = "domain_stats"
	reportCache        = "cache"
	reportCCStats      = "cc_stats"
	reportCCIPs        = "cc_ips"
	reportXDPStats     = "xdp_stats"
	reportXDPBlocklist = "xdp_blocklist"
	reportWAFBans      = "waf_bans"
	reportWAFStats     = "waf_stats"
	reportGeoStats     = "geo_stats"
)

const (
	// reportMaxBody 是解压后的上报体上限；边缘侧已对 IP 列表截断，正常远小于此。
	reportMaxBody = 16 << 20
	// reportStaleAfter 超过这么久没收到上报就当作节点数据过期（边缘每 10 秒报一次）。
	reportStaleAfter = 60 * time.Second
	// reportForgetAfter 之后从内存里清掉（节点已删除/长期离线）。
	reportForgetAfter = 30 * time.Minute
)

var (
	errReportMissing = errors.New("节点尚未上报数据（请确认 cdnedge 已升级并以 --master 启动）")
	errReportStale   = errors.New("节点上报超时")
)

type nodeReport struct {
	at     time.Time
	fields map[string]json.RawMessage
}

type reportStore struct {
	mu        sync.RWMutex
	m         map[string]*nodeReport
	lastPrune time.Time
}

// reports 是进程内唯一的快照存储。v2 路由和 v1 回落用的是不同的 EdgeHandler 实例，
// 所以放在包级而不是挂在 handler 上。
var reports = &reportStore{m: map[string]*nodeReport{}}

func (s *reportStore) put(nodeID string, fields map[string]json.RawMessage, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[nodeID] = &nodeReport{at: now, fields: fields}
	if now.Sub(s.lastPrune) > time.Minute {
		for id, r := range s.m {
			if now.Sub(r.at) > reportForgetAfter {
				delete(s.m, id)
			}
		}
		s.lastPrune = now
	}
}

func (s *reportStore) get(nodeID, key string, now time.Time) (json.RawMessage, error) {
	s.mu.RLock()
	r := s.m[nodeID]
	s.mu.RUnlock()
	if r == nil {
		return nil, errReportMissing
	}
	if now.Sub(r.at) > reportStaleAfter {
		return nil, errReportStale
	}
	raw, ok := r.fields[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("节点未上报该项数据")
	}
	return raw, nil
}

func (s *reportStore) forget(nodeID string) {
	s.mu.Lock()
	delete(s.m, nodeID)
	s.mu.Unlock()
}

// reportedAt 返回最近一次上报的时间；没上报过就是零值。
// 区域表的下发要拿它和"主控最后一次成功交表的时间"比新旧，见 geoNodeTableFingerprint。
func (s *reportStore) reportedAt(nodeID string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r := s.m[nodeID]; r != nil {
		return r.at
	}
	return time.Time{}
}

// reportField 从各节点最近一次上报里取出 key 对应的数据，按节点原顺序返回。
// 形状与以前回连拉取的结果一致，调用方无需关心数据来源。
func reportField[T any](nodes []*config.Node, key string) []nodeResult[T] {
	now := time.Now()
	out := make([]nodeResult[T], len(nodes))
	for i, n := range nodes {
		out[i].Node = n
		raw, err := reports.get(n.ID, key, now)
		if err != nil {
			out[i].Err = err
			continue
		}
		if err := json.Unmarshal(raw, &out[i].Data); err != nil {
			out[i].Err = errors.New("上报数据格式错误: " + err.Error())
		}
	}
	return out
}

type edgeReportRequest struct {
	NodeID string                     `json:"node_id"`
	Token  string                     `json:"token"`
	Report map[string]json.RawMessage `json:"report"`
}

// ServeReport 处理 POST /api/v2/edge/report。鉴权与心跳相同：node_id + 节点 token（常量时间比较）。
// 请求体可以 gzip 压缩（Content-Encoding: gzip），解压后限制在 reportMaxBody 以内。
func (h *EdgeHandler) ServeReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(io.LimitReader(r.Body, reportMaxBody))
		if err != nil {
			WriteError(w, NewApiError("invalid_json", "请求体 gzip 格式错误"))
			return
		}
		defer zr.Close()
		body = zr
	}
	var req edgeReportRequest
	if err := json.NewDecoder(io.LimitReader(body, reportMaxBody)).Decode(&req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.NodeID == "" || req.Token == "" {
		WriteError(w, NewApiError("forbidden", "节点 token 无效"))
		return
	}
	n, err := h.nodes.GetByID(r.Context(), req.NodeID)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	plain, err := secure.Decrypt(n.TokenEnc)
	if err != nil {
		WriteError(w, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), plain) != 1 {
		WriteError(w, NewApiError("forbidden", "节点 token 无效"))
		return
	}
	reports.put(n.ID, req.Report, time.Now())

	// 上报本身也算一次心跳。
	var st map[string]any
	if raw := req.Report[reportStatus]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &st)
	}
	if err := h.nodes.TouchHeartbeat(r.Context(), n.ID, mapEdgeStatus(st)); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
