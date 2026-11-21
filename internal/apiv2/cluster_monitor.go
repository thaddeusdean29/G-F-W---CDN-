package apiv2

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"cdn/internal/cloudflare"
	"cdn/internal/config"
)

// ---------------------------------------------------------------------------
// 集群监控（v2）：每 clusterMonitorInterval 检查一次开了防护的集群，连续
// failoverFailStreak 次不达标就自动切换，与 v1 healthcheck 的节奏一致。
//
// 按集群判断，不按单个节点：只打一台时其余节点照常服务，不该把整个集群切走。
// 可用率 = 可用节点 / 全部节点，低于 failover_threshold 记一次不达标。不可用节点有两种：
//   - 带宽打满：设置了单节点带宽上限 bw_limit_mbps 时，max(入, 出) 达到上限 bw_danger_percent%
//     的节点。XDP 丢包省的是 CPU，省不了线路带宽；这种节点心跳/探活往往还通，在线率看不出来，
//     但 DNS 仍会把一部分用户分给它。
//   - 离线：心跳超时（只在开了自动故障转移时计入）。
// 单节点：带宽连续 nodePauseStreak 次打满的节点，先把它的 A 记录从集群子域名下摘掉（用户不再被
// 解析到它），恢复后自动加回。集群里至少要留一台在线、未打满、未摘除的节点才会摘——全部打满时
// 交给下面的整集群切换，不能把解析摘空。
//
// 有带宽打满的节点参与触发时切高防 CNAME（域名自己的优先，未填用集群默认）——备用集群
// 多半扛不住同一波流量；纯离线触发与手动触发同规则：配置了目标集群就切过去，否则切高防。
//
// 自动切出去的（auto_failover_active）在连续达标 RecoverOKStreak 次、再稳定 RecoverHold 后
// 自动切回，且只切回被故障转移切走的域名（用户单独手动切到高防的域名不动）。手动触发的
// 故障转移不自动切回。
//
// 数据隔离：集群跨租户列出，但每个集群的节点、域名、Cloudflare 凭证都只按它自己的
// tenant_id 读取，绝不回落到 config.json 的全局 CF。
// ---------------------------------------------------------------------------

const clusterMonitorInterval = 30 * time.Second

const (
	// 连续 failoverFailStreak 次检查不达标才切走：一次网络抖动不该让全站换线路。
	failoverFailStreak = 3
	// 回切：连续 recoverOKStreak 次达标后开始计时，此后持续达标满 recoverHold 才切回。
	// 黑洞解除时攻击往往还在，立刻切回会被再打一轮、再断一次。期间任何一次不达标都重新计。
	recoverOKStreak = 3
	recoverHold     = time.Hour
)

// 单节点摘除：连续 nodePauseStreak 次打满才摘；连续 nodeResumeOKStreak 次正常后再稳定
// nodeResumeHold 才加回（比整集群回切的 1 小时短：只动一台，代价小）。
const (
	nodePauseStreak    = 3
	nodeResumeOKStreak = 3
	nodeResumeHold     = 10 * time.Minute
)

// nodeDNSState 是单个节点的连续打满 / 连续正常计数（只在内存里）。
type nodeDNSState struct {
	bad, ok int
	okSince time.Time
}

// observe 记录一轮结果，返回是否应当摘除 / 是否已可以加回。
func (st *nodeDNSState) observe(saturated bool, now time.Time) (pause, resume bool) {
	if saturated {
		st.ok, st.okSince = 0, time.Time{}
		st.bad++
		return st.bad >= nodePauseStreak, false
	}
	st.bad = 0
	st.ok++
	if st.ok == nodeResumeOKStreak {
		st.okSince = now
	}
	return false, st.ok >= nodeResumeOKStreak && now.Sub(st.okSince) >= nodeResumeHold
}

type clusterMonitorState struct {
	failStreak  int
	okStreak    int
	stableSince time.Time

	at        time.Time
	hasBW     bool
	peakMbps  float64
	peakNode  string
	saturated int    // 最近一次检查时带宽打满的节点数
	paused    int    // 最近一次检查后被摘除解析的节点数
	reason    string // 最近一次不达标/切换的原因，达标后清空
}

type clusterMonitor struct {
	mu     sync.Mutex
	states map[string]*clusterMonitorState
	nodes  map[string]*nodeDNSState
}

// monitor 是进程内唯一的监控状态（只在内存里；主控重启后计数从零开始，只会让切换更晚）。
var monitor = &clusterMonitor{states: map[string]*clusterMonitorState{}, nodes: map[string]*nodeDNSState{}}

func (m *clusterMonitor) node(id string) *nodeDNSState {
	st := m.nodes[id]
	if st == nil {
		st = &nodeDNSState{}
		m.nodes[id] = st
	}
	return st
}

func (m *clusterMonitor) state(id string) *clusterMonitorState {
	st := m.states[id]
	if st == nil {
		st = &clusterMonitorState{}
		m.states[id] = st
	}
	return st
}

// observe 的规则：连续失败 N 次切走；
// 连续达标 N 次后开始计时，持续达标满 RecoverHold 才允许切回。
func (st *clusterMonitorState) observe(healthy bool, now time.Time) (failover, recover bool) {
	if !healthy {
		st.okStreak = 0
		st.stableSince = time.Time{}
		st.failStreak++
		return st.failStreak >= failoverFailStreak, false
	}
	st.failStreak = 0
	st.okStreak++
	if st.okStreak == recoverOKStreak {
		st.stableSince = now
	}
	return false, st.okStreak >= recoverOKStreak && now.Sub(st.stableSince) >= recoverHold
}

// reset 在用户手动触发/取消故障转移后调用：清零计数，攻击仍在的话要重新连续超限才会再自动切走，
// 避免「手动切回后下一轮立刻又被切走」。
func (m *clusterMonitor) reset(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.state(id)
	st.failStreak, st.okStreak, st.stableSince, st.reason = 0, 0, time.Time{}, ""
}

func (m *clusterMonitor) fillHealth(id string, h *clusterHealth) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.states[id]
	if st == nil || st.at.IsZero() {
		return
	}
	h.FailStreak = st.failStreak
	h.LastReason = st.reason
	at := st.at.UTC().Format(rfc3339Milli)
	h.MonitoredAt = &at
	if st.hasBW {
		v := st.peakMbps
		h.BWPeakMbps = &v
		h.BWPeakNode = st.peakNode
		h.BWSaturated = st.saturated
	}
	h.DNSPaused = st.paused
}

// edgeNetStatus 是上报 status.system 里与带宽相关的字段（internal/edgeapi/stats.go SystemStats），单位字节/秒。
type edgeNetStatus struct {
	System *struct {
		NetRxBps uint64 `json:"net_rx_bps"`
		NetTxBps uint64 `json:"net_tx_bps"`
	} `json:"system"`
}

type clusterMonitorRunner struct {
	db         *sql.DB
	clusters   *ClusterRepo
	nodes      *NodeRepo
	domainRepo *DomainRepo
}

func startClusterMonitor(db *sql.DB, clusters *ClusterRepo, nodes *NodeRepo, domains *DomainRepo) {
	r := &clusterMonitorRunner{db: db, clusters: clusters, nodes: nodes, domainRepo: domains}
	go func() {
		t := time.NewTicker(clusterMonitorInterval)
		defer t.Stop()
		for range t.C {
			r.checkAll()
		}
	}()
}

func (r *clusterMonitorRunner) checkAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	list, err := r.clusters.ListMonitored(ctx)
	cancel()
	if err != nil {
		log.Printf("[ClusterMonitor] list clusters: %v", err)
		return
	}
	for _, c := range list {
		func() {
			defer func() {
				if p := recover(); p != nil {
					log.Printf("[ClusterMonitor] cluster %s panic: %v", c.ID, p)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			r.check(ctx, c)
		}()
	}
}

// bwSample 是单个节点最近一次上报的带宽（Mbps，取入/出较大者）。
type bwSample struct {
	node string
	mbps float64
}

// clusterBandwidthSamples 取集群内各节点最近一次上报的带宽；上报缺失或过期的节点跳过（它是否离线
// 由在线率判断）。byID 是同一份数据按节点 ID 索引，供单节点摘除使用。
func clusterBandwidthSamples(nodes []*config.Node) (samples []bwSample, byID map[string]float64) {
	byID = map[string]float64{}
	for _, res := range reportField[edgeNetStatus](nodes, reportStatus) {
		if res.Err != nil || res.Data.System == nil {
			continue
		}
		bps := res.Data.System.NetRxBps
		if res.Data.System.NetTxBps > bps {
			bps = res.Data.System.NetTxBps
		}
		mbps := float64(bps) * 8 / 1e6
		samples = append(samples, bwSample{node: nodeLabel(res.Node), mbps: mbps})
		byID[res.Node.ID] = mbps
	}
	return samples, byID
}

// bwVerdict 是一轮检查的结论：reason 为空表示达标；byBandwidth 表示有带宽打满的节点参与了触发。
type bwVerdict struct {
	reason      string
	byBandwidth bool
	peak        bwSample
	saturated   int
}

// evaluate 按集群可用率判断这一轮是否达标。online/total 来自心跳；samples 是各节点带宽；
// pausedIdle 是已摘除解析、带宽已回落但还没加回的节点数——它们暂时不接用户，也算不可用。
func evaluate(c *Cluster, online, total int, samples []bwSample, pausedIdle int) bwVerdict {
	var v bwVerdict
	var satNames []string
	danger := float64(c.BWLimitMbps) * float64(c.BWDangerPercent) / 100
	for _, s := range samples {
		if s.mbps > v.peak.mbps || v.peak.node == "" {
			v.peak = s
		}
		if c.BWLimitMbps > 0 && s.mbps >= danger {
			v.saturated++
			satNames = append(satNames, s.node)
		}
	}
	if total <= 0 || (!c.IsAutoFailover && c.BWLimitMbps <= 0) {
		return v
	}
	// 关了自动故障转移时只看带宽，离线节点不计入（不改变用户对在线率切换的选择）。
	offline := 0
	if c.IsAutoFailover && online < total {
		offline = total - online
	}
	available := total - offline - v.saturated - pausedIdle
	if available < 0 {
		available = 0
	}
	rate := float64(available) / float64(total) * 100
	if rate >= float64(c.FailoverThreshold) {
		return v
	}
	parts := []string{}
	if v.saturated > 0 {
		parts = append(parts, fmt.Sprintf("%d 台带宽打满（≥ %d Mbps 的 %d%%：%s）",
			v.saturated, c.BWLimitMbps, c.BWDangerPercent, strings.Join(satNames, "、")))
	}
	if offline > 0 {
		parts = append(parts, fmt.Sprintf("%d 台离线", offline))
	}
	if pausedIdle > 0 {
		parts = append(parts, fmt.Sprintf("%d 台已摘除解析待恢复", pausedIdle))
	}
	v.reason = fmt.Sprintf("可用节点 %d/%d（%.0f%%），低于阈值 %d%%：%s",
		available, total, rate, c.FailoverThreshold, strings.Join(parts, "，"))
	v.byBandwidth = v.saturated > 0
	return v
}

func (r *clusterMonitorRunner) check(ctx context.Context, c *Cluster) {
	all, err := tenantEdgeNodes(ctx, r.nodes, c.TenantID)
	if err != nil {
		log.Printf("[ClusterMonitor] cluster %s nodes: %v", c.Name, err)
		return
	}
	var nodes []*config.Node
	for _, n := range all {
		if n.ClusterID == c.ID {
			nodes = append(nodes, n)
		}
	}
	counts, err := r.clusters.NodeCounts(ctx, c.TenantID)
	if err != nil {
		log.Printf("[ClusterMonitor] cluster %s node counts: %v", c.Name, err)
		return
	}
	nc := counts[c.ID]
	if nc.Total == 0 {
		return
	}

	samples, bwByID := clusterBandwidthSamples(nodes)
	now := time.Now()
	paused, pausedIdle := r.balanceNodeDNS(ctx, c, bwByID, now)
	v := evaluate(c, nc.Online, nc.Total, samples, pausedIdle)
	reason, byBW, peak := v.reason, v.byBandwidth, v.peak

	monitor.mu.Lock()
	st := monitor.state(c.ID)
	failover, recover := st.observe(reason == "", now)
	st.at, st.hasBW, st.peakMbps, st.peakNode, st.saturated = now, peak.node != "", peak.mbps, peak.node, v.saturated
	st.paused = paused
	st.reason = reason
	if reason != "" {
		st.reason = fmt.Sprintf("%s（连续 %d/%d 次）", reason, st.failStreak, failoverFailStreak)
	}
	monitor.mu.Unlock()

	inFailover := c.Status == "failover_complete" || c.Status == "failover_in_progress"
	switch {
	case failover && !inFailover:
		r.autoTrigger(ctx, c, reason, byBW)
	case recover && c.AutoFailoverActive:
		r.autoRecover(ctx, c)
	}
}

// clusterNodeRows 取集群下的全部节点行（带 ip / cf_record_id / dns_paused_at，config.Node 没有这些）。
func (r *clusterMonitorRunner) clusterNodeRows(ctx context.Context, c *Cluster) ([]*Node, error) {
	var out []*Node
	for page := 1; ; page++ {
		rows, total, err := r.nodes.List(ctx, c.TenantID, c.ID, nil, "added_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(rows) == 0 || page*maxPageSize >= total {
			return out, nil
		}
	}
}

// pauseCandidate 是单节点摘除判断的输入（不碰 CF / DB，便于单测）。
type pauseCandidate struct {
	id        string
	online    bool
	paused    bool
	known     bool // 本轮有带宽上报
	saturated bool
}

// planNodeDNS 更新各节点计数并决定本轮要摘除 / 加回哪些节点。至少保留一台在线、未打满、
// 未摘除的节点继续解析；没有这样的节点就一台都不摘（交给整集群切换）。limitOff 时全部加回。
func planNodeDNS(m *clusterMonitor, cands []pauseCandidate, limitOff bool, now time.Time) (pause, resume, kept []string) {
	serving := 0
	for _, c := range cands {
		if c.online && !c.paused && !c.saturated {
			serving++
		}
	}
	for _, c := range cands {
		if limitOff {
			delete(m.nodes, c.id)
			if c.paused {
				resume = append(resume, c.id)
			}
			continue
		}
		if !c.known {
			continue // 没有上报（离线 / 过期）：不更新计数，保持现状
		}
		wantPause, canResume := m.node(c.id).observe(c.saturated, now)
		switch {
		case c.paused && canResume:
			resume = append(resume, c.id)
		case !c.paused && wantPause && serving >= 1:
			pause = append(pause, c.id)
		case !c.paused && wantPause:
			kept = append(kept, c.id)
		}
	}
	return pause, resume, kept
}

// balanceNodeDNS 把带宽持续打满的节点从集群子域名摘掉，恢复后加回。返回处理后仍处于摘除状态的
// 节点数，以及其中带宽已回落（在线、不再打满）只是还在等待加回的节点数。
// CF 只用本代理自己的凭证；没配就不做，集群监控的其他判断照常。
func (r *clusterMonitorRunner) balanceNodeDNS(ctx context.Context, c *Cluster, bwByID map[string]float64, now time.Time) (paused, pausedIdle int) {
	rows, err := r.clusterNodeRows(ctx, c)
	if err != nil {
		log.Printf("[ClusterMonitor] cluster %s list nodes: %v", c.Name, err)
		return 0, 0
	}
	danger := float64(c.BWLimitMbps) * float64(c.BWDangerPercent) / 100
	byID := map[string]*Node{}
	var cands []pauseCandidate
	pausedNow := 0
	for _, n := range rows {
		if !n.Enabled || !n.IP.Valid || n.IP.String == "" {
			continue
		}
		byID[n.ID] = n
		mbps, known := bwByID[n.ID]
		cands = append(cands, pauseCandidate{
			id:        n.ID,
			online:    n.LastHeartbeatAt.Valid && now.Sub(n.LastHeartbeatAt.Time) < nodeOnlineThreshold,
			paused:    n.DNSPausedAt.Valid,
			known:     known,
			saturated: c.BWLimitMbps > 0 && known && mbps >= danger,
		})
		if n.DNSPausedAt.Valid {
			pausedNow++
		}
	}

	monitor.mu.Lock()
	pause, resume, kept := planNodeDNS(monitor, cands, c.BWLimitMbps <= 0, now)
	monitor.mu.Unlock()
	// 状态以本轮实际执行结果为准（CF 失败的不算），最后统一统计。
	idle := func() int {
		n := 0
		for _, cd := range cands {
			if cd.paused && cd.online && !cd.saturated {
				n++
			}
		}
		return n
	}
	if len(kept) > 0 {
		log.Printf("[ClusterMonitor] cluster %s: %d 台节点带宽持续打满，但集群没有其他可用节点，保留解析（交给整集群切换）", c.Name, len(kept))
	}
	if len(pause) == 0 && len(resume) == 0 {
		return pausedNow, idle()
	}

	cf, err := tenantCF(ctx, r.db, c.TenantID)
	if err != nil || !cf.Enabled() {
		log.Printf("[ClusterMonitor] cluster %s: 需要调整节点解析，但本代理未配置 Cloudflare (err=%v)", c.Name, err)
		return pausedNow, idle()
	}
	for _, id := range pause {
		n := byID[id]
		if n.CFRecordID != "" {
			if err := cf.DeleteRecord(n.CFRecordID); err != nil && !cloudflare.IsNotFound(err) {
				log.Printf("[ClusterMonitor] cluster %s: 摘除节点 %s 的解析失败: %v", c.Name, nodeName(n), err)
				continue
			}
		}
		if err := r.nodes.PauseDNS(ctx, c.TenantID, n.ID); err != nil {
			log.Printf("[ClusterMonitor] cluster %s: 记录节点 %s 摘除状态失败: %v", c.Name, nodeName(n), err)
			continue
		}
		pausedNow++
		markPaused(cands, id, true)
		log.Printf("[ClusterMonitor] cluster %s (tenant %s): 节点 %s (%s) 带宽连续 %d 次 >= %d%%，已暂时从 %s 摘除解析",
			c.Name, c.TenantID, nodeName(n), n.IP.String, nodePauseStreak, c.BWDangerPercent, cf.ClusterSubdomain(c.Name))
	}
	for _, id := range resume {
		n := byID[id]
		recordID, err := cf.EnsureARecord(c.Name, n.IP.String)
		if err != nil {
			// 记录没建成就保持摘除状态，下一轮重试（不能标记恢复却没有解析）。
			log.Printf("[ClusterMonitor] cluster %s: 恢复节点 %s 的解析失败，下一轮重试: %v", c.Name, nodeName(n), err)
			continue
		}
		if err := r.nodes.ResumeDNS(ctx, c.TenantID, n.ID, recordID); err != nil {
			log.Printf("[ClusterMonitor] cluster %s: 记录节点 %s 恢复状态失败: %v", c.Name, nodeName(n), err)
			continue
		}
		pausedNow--
		markPaused(cands, id, false)
		log.Printf("[ClusterMonitor] cluster %s (tenant %s): 节点 %s (%s) 带宽已恢复，重新加入 %s 解析",
			c.Name, c.TenantID, nodeName(n), n.IP.String, cf.ClusterSubdomain(c.Name))
	}
	return pausedNow, idle()
}

func markPaused(cands []pauseCandidate, id string, paused bool) {
	for i := range cands {
		if cands[i].id == id {
			cands[i].paused = paused
		}
	}
}

func nodeName(n *Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

// effectiveDefenseCNAME 域名自己填了高防 CNAME 就用它，否则用集群默认值。
func effectiveDefenseCNAME(d *Domain, c *Cluster) string {
	if d.DefenseCNAME != "" {
		return d.DefenseCNAME
	}
	if c != nil {
		return c.DefenseCNAME
	}
	return ""
}

func (r *clusterMonitorRunner) setReason(id, reason string) {
	monitor.mu.Lock()
	monitor.state(id).reason = reason
	monitor.mu.Unlock()
}

func (r *clusterMonitorRunner) tenantCF(ctx context.Context, c *Cluster) (*cloudflare.Client, bool) {
	cf, err := tenantCF(ctx, r.db, c.TenantID)
	if err != nil || !cf.Enabled() {
		r.setReason(c.ID, "需要自动切换，但本代理未配置 Cloudflare，无法切换")
		log.Printf("[ClusterMonitor] cluster %s: cloudflare not configured for tenant %s (err=%v)", c.Name, c.TenantID, err)
		return nil, false
	}
	return cf, true
}

func (r *clusterMonitorRunner) clusterDomains(ctx context.Context, c *Cluster) ([]*Domain, error) {
	h := &clustersHandler{domainRepo: r.domainRepo}
	return h.clusterDomains(ctx, c.TenantID, c.ID)
}

// autoTrigger 把集群下的域名切走。带宽触发一律切高防 CNAME；在线率触发与手动触发同规则
// （配置了目标集群就切过去，否则切高防）。已被用户单独切到高防的域名不动；没有任何可用高防
// CNAME 的域名跳过并记录原因——自动防护宁可部分切换也不要整体放弃。
func (r *clusterMonitorRunner) autoTrigger(ctx context.Context, c *Cluster, reason string, byBandwidth bool) {
	cf, ok := r.tenantCF(ctx, c)
	if !ok {
		return
	}
	clusterSubdomain := cf.ClusterSubdomain(c.Name)
	backupSubdomain := ""
	if !byBandwidth && c.FailoverTargetID.Valid && c.FailoverTargetID.String != "" {
		if target, err := r.clusters.Get(ctx, c.TenantID, c.FailoverTargetID.String); err == nil {
			backupSubdomain = cf.ClusterSubdomain(target.Name)
		} else {
			log.Printf("[ClusterMonitor] cluster %s: failover target missing, fall back to defense cname: %v", c.Name, err)
		}
	}
	domains, err := r.clusterDomains(ctx, c)
	if err != nil {
		log.Printf("[ClusterMonitor] cluster %s domains: %v", c.Name, err)
		return
	}

	switched, skipped, failed := 0, []string{}, []string{}
	for _, d := range domains {
		if d.OnDefense {
			continue
		}
		target, onDefense := backupSubdomain, false
		if target == "" {
			target, onDefense = effectiveDefenseCNAME(d, c), true
		}
		if target == "" {
			skipped = append(skipped, d.Domain)
			continue
		}
		if err := switchOneDomain(ctx, cf, r.domainRepo, c.TenantID, d, clusterSubdomain, target, onDefense, true); err != nil {
			failed = append(failed, d.Domain+": "+err.Error())
			continue
		}
		switched++
	}
	if switched == 0 {
		msg := fmt.Sprintf("%s；自动切换未成功（未配置高防 CNAME: %v，失败: %v）", reason, skipped, failed)
		r.setReason(c.ID, msg)
		log.Printf("[ClusterMonitor] cluster %s: %s", c.Name, msg)
		return
	}
	if err := r.clusters.UpdateFailoverState(ctx, c.TenantID, c.ID, "failover_complete", c.FailoverTargetID, true); err != nil {
		log.Printf("[ClusterMonitor] cluster %s: save failover state: %v", c.Name, err)
	}
	dest := "高防 CNAME"
	if backupSubdomain != "" {
		dest = "备用集群 " + backupSubdomain
	}
	msg := fmt.Sprintf("已自动切到%s：%s", dest, reason)
	if len(skipped) > 0 {
		msg += fmt.Sprintf("；未配置高防 CNAME 未切换: %v", skipped)
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("；切换失败: %v", failed)
	}
	r.setReason(c.ID, msg)
	log.Printf("[ClusterMonitor] cluster %s (tenant %s): %s（%d 个域名）", c.Name, c.TenantID, msg, switched)
}

// autoRecover 只把被故障转移切走的域名（defense_by_failover）切回集群。
func (r *clusterMonitorRunner) autoRecover(ctx context.Context, c *Cluster) {
	cf, ok := r.tenantCF(ctx, c)
	if !ok {
		return
	}
	clusterSubdomain := cf.ClusterSubdomain(c.Name)
	domains, err := r.clusterDomains(ctx, c)
	if err != nil {
		log.Printf("[ClusterMonitor] cluster %s domains: %v", c.Name, err)
		return
	}
	var failed []string
	for _, d := range domains {
		if !d.DefenseByFailover {
			continue
		}
		if err := switchOneDomain(ctx, cf, r.domainRepo, c.TenantID, d, clusterSubdomain, clusterSubdomain, false, false); err != nil {
			failed = append(failed, d.Domain+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		// 有域名没切回来就保持故障转移状态，下一轮继续尝试。
		msg := fmt.Sprintf("自动切回失败，下一轮重试: %v", failed)
		r.setReason(c.ID, msg)
		log.Printf("[ClusterMonitor] cluster %s: %s", c.Name, msg)
		return
	}
	if err := r.clusters.UpdateFailoverState(ctx, c.TenantID, c.ID, "active", c.FailoverTargetID, false); err != nil {
		log.Printf("[ClusterMonitor] cluster %s: save recover state: %v", c.Name, err)
		return
	}
	r.setReason(c.ID, "")
	log.Printf("[ClusterMonitor] cluster %s (tenant %s): 已稳定 %v，自动切回集群", c.Name, c.TenantID, recoverHold)
}
