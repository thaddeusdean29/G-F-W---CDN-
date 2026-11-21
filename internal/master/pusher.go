package master

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"cdn/internal/config"
	"cdn/internal/stats"
	"cdn/internal/waf"
)

// Pusher 向所有启用的边缘节点推送配置变更。
// 每个节点使用独立的 HTTP client，基于证书指纹做钉扎校验。
// 单个节点失败只记录日志，不阻塞主流程。
type Pusher struct {
	nodes *config.NodeStore
	mu    sync.RWMutex
	// clients 按节点 ID 缓存，连带记住建它时用的指纹：指纹一改，缓存条目自动失效。
	// 光靠调用方在改完指纹后记得 InvalidateClient 是不够的 —— 漏一处，运维照报错提示
	// 填了新指纹重试，撞上的还是旧 pin，那句提示就成了假承诺。
	clients map[string]cachedClient
}

type cachedClient struct {
	fingerprint string
	client      *http.Client
}

func NewPusher(nodes *config.NodeStore) *Pusher {
	return &Pusher{
		nodes:   nodes,
		clients: make(map[string]cachedClient),
	}
}

// GetNodeStore 返回 NodeStore（用于域名创建时查询节点）
func (p *Pusher) GetNodeStore() (*config.NodeStore, bool) {
	if p.nodes == nil {
		return nil, false
	}
	return p.nodes, true
}

// pinnedTLSConfig 构造控制面出站连接的 TLS 配置。
//
// InsecureSkipVerify=true 不等于"不校验"：它把校验权整条接管给 VerifyConnection。边缘
// 节点用的是自签证书，标准信任链（CA + 域名 + 有效期）在这里本来就走不通，而控制面真正
// 要锁死的属性是"这张证书是不是登记过的那一张"。所以这个函数只在指纹非空时调用 ——
// 少了 VerifyConnection 的 InsecureSkipVerify 等于把 CC/XDP 阈值、封禁名单和域名私钥
// 交给路径上的任何人改写。
func pinnedTLSConfig(fingerprint string) *tls.Config {
	want := normalizeFingerprint(fingerprint)
	return &tls.Config{
		InsecureSkipVerify:       true,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites:             controlPlaneCipherSuites,
		PreferServerCipherSuites: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("边缘节点未出示证书（certificate not presented）")
			}
			got := certFingerprint(cs.PeerCertificates[0])
			if got != want {
				return fmt.Errorf("证书指纹不匹配：得到 %s，期望 %s（边缘重装过就会换证书；在面板该节点的「证书指纹」里更新后重试）", got, want)
			}
			return nil
		},
	}
}

// controlPlaneCipherSuites 与原来的钉扎客户端保持一致：只留 AEAD 套件，
// 控制面不需要（也不该有）CBC / 流密码这类可被降级的选项。
var controlPlaneCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// pinningRequiredError 说明拒绝原因和恢复路径。这里不能只是"记一条日志然后照发"：
// 没有指纹就没有钉扎，而主控下发的东西里包含域名私钥和整套防御阈值 —— 中间人一旦能
// 改写，面板上显示的"防御已生效"就只是主控自己的一厢情愿。
func pinningRequiredError(n *config.Node) error {
	return fmt.Errorf("节点 %s (%s) 未登记证书指纹，推送已拒绝。恢复：在边缘节点执行 "+
		"`journalctl -u cdnedge | grep 'Certificate fingerprint'` 取 SHA-256 指纹，在面板该节点的「证书指纹」里填入并保存；"+
		"由主控一键部署、或以 --master 启动的 cdnedge 会在注册时自动上报指纹，无需手填",
		n.Name, n.Address)
}

// clientFor 返回节点对应的 HTTP client。没有证书指纹的节点直接拒掉（见 pinningRequiredError）。
// 使用写锁一次完成检查+写入，消除 TOCTOU。
func (p *Pusher) clientFor(n *config.Node) (*http.Client, error) {
	if n.CertFingerprint == "" {
		return nil, pinningRequiredError(n)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[n.ID]; ok && c.fingerprint == n.CertFingerprint {
		return c.client, nil
	}
	tr := &http.Transport{
		TLSClientConfig:       pinnedTLSConfig(n.CertFingerprint),
		DisableKeepAlives:     false,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		ResponseHeaderTimeout: 15 * time.Second, // 防止服务端不响应导致永久挂起
		TLSHandshakeTimeout:   10 * time.Second, // TLS 握手超时
	}
	// 启用 HTTP/2
	if err := http2.ConfigureTransport(tr); err != nil {
		log.Printf("[Pusher] Failed to configure HTTP/2 for node %s: %v", n.ID, err)
	} else {
		log.Printf("[Pusher] HTTP/2 enabled for node %s (%s)", n.ID, n.Address)
	}
	c := &http.Client{Timeout: 15 * time.Second, Transport: tr} // 增加超时到 15 秒
	p.clients[n.ID] = cachedClient{fingerprint: n.CertFingerprint, client: c}
	return c, nil
}

// do 是控制面出站的唯一闸口：先过钉扎检查，再发请求。新增调用点只要走 p.do / p.post，
// 就没法"忘了做指纹校验"地把配置发出去。
func (p *Pusher) do(n *config.Node, req *http.Request) (*http.Response, error) {
	client, err := p.clientFor(n)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// InvalidateClient 节点信息变更后清除缓存的 client（如指纹更新）。
func (p *Pusher) InvalidateClient(nodeID string) {
	p.mu.Lock()
	delete(p.clients, nodeID)
	p.mu.Unlock()
}

// InvalidateAllClients 清除所有客户端缓存（用于强制重新创建所有连接）
func (p *Pusher) InvalidateAllClients() {
	p.mu.Lock()
	p.clients = make(map[string]cachedClient)
	p.mu.Unlock()
	log.Printf("[Pusher] 已清除所有客户端缓存")
}

// longTimeoutClientFor 返回一个具有更长超时时间的客户端（用于耗时操作，如 XDP 安装）。
// 不缓存：这类调用几分钟一次，缓存反而会让节点换指纹后继续复用旧连接。
//
// 只设 client.Timeout，不设 ResponseHeaderTimeout —— install-xdp 会在握手后长时间占用
// 同一个请求，15 秒的响应头超时会让它每次都失败。
func (p *Pusher) longTimeoutClientFor(n *config.Node, timeout time.Duration) (*http.Client, error) {
	if n.CertFingerprint == "" {
		return nil, pinningRequiredError(n)
	}
	tr := &http.Transport{
		TLSClientConfig:     pinnedTLSConfig(n.CertFingerprint),
		DisableKeepAlives:   false,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}
	// 启用 HTTP/2
	if err := http2.ConfigureTransport(tr); err != nil {
		log.Printf("Failed to configure HTTP/2: %v", err)
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

func (p *Pusher) PushDomain(d *config.Domain) {
	// 如果是手动 SSL 模式，读取证书内容一起推送
	payload := buildDomainPayload(d)
	for _, n := range p.targetNodes(d.ClusterID) {
		go func(n *config.Node) {
			if err := p.post(n, "/edge/domains", payload); err != nil {
				log.Printf("push domain %s to node %s (%s) failed: %v", d.Domain, n.Name, n.Address, err)
			}
		}(n)
	}
}

func (p *Pusher) DeleteDomain(domainID, clusterID string) {
	for _, n := range p.targetNodes(clusterID) {
		go func(n *config.Node) {
			req, err := http.NewRequest(http.MethodDelete, n.Address+"/edge/domains/"+domainID, nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+n.Token)
			resp, err := p.do(n, req)
			if err != nil {
				log.Printf("delete domain %s on node %s failed: %v", domainID, n.Name, err)
				return
			}
			resp.Body.Close()
		}(n)
	}
}

// SyncAll 将所有域名配置全量推送到指定集群（或全部节点），使用替换模式。
// 边缘节点收到完整域名列表后，会删除本地存在但不在列表中的域名。
// 用于新加节点后的配置同步，或配置丢失后的恢复。
// clusterID 为空时推送到所有启用的节点，否则只推送到指定集群。
// 返回 (推送的域名数, 推送到的节点数)。
func (p *Pusher) SyncAll(domains []*config.Domain, clusterID string) (int, int) {
	nodes := p.targetNodes(clusterID)
	if len(nodes) == 0 {
		return 0, 0
	}

	// 按集群分组域名
	clusterDomains := make(map[string][]*DomainPushPayload)
	// 空字符串键用于无集群的域名
	for _, d := range domains {
		// 如果指定了 clusterID，只包含该集群的域名
		if clusterID != "" && d.ClusterID != clusterID {
			continue
		}
		key := d.ClusterID
		payload := buildDomainPayload(d)
		clusterDomains[key] = append(clusterDomains[key], payload)
	}

	// 向每个节点推送其对应集群的完整域名列表
	totalPushed := 0
	for _, n := range nodes {
		nodeCluster := n.ClusterID
		// 节点应该收到：本集群的域名 + 无集群域名（如果 clusterID 为空）
		var domainsForNode []*DomainPushPayload
		if clusterID == "" {
			// 全局同步：发送该节点集群的域名 + 无集群域名
			domainsForNode = append(domainsForNode, clusterDomains[nodeCluster]...)
			domainsForNode = append(domainsForNode, clusterDomains[""]...)
		} else {
			// 集群同步：只发送该集群的域名
			domainsForNode = clusterDomains[nodeCluster]
		}

		go func(n *config.Node, domains []*DomainPushPayload) {
			payload := map[string]any{"domains": domains}
			if err := p.post(n, "/edge/domains/replace-all", payload); err != nil {
				log.Printf("sync-all to node %s (%s) failed: %v", n.Name, n.Address, err)
			} else {
				log.Printf("sync-all to node %s: sent %d domains", n.Name, len(domains))
			}
		}(n, domainsForNode)
	}

	// 计算实际推送的域名数（去重）
	allDomains := make(map[string]bool)
	for _, list := range clusterDomains {
		for _, d := range list {
			allDomains[d.ID] = true
		}
	}
	totalPushed = len(allDomains)

	return totalPushed, len(nodes)
}

// SyncNode 以替换模式把某个节点应得的域名推给它：本集群的域名 + 无集群的域名
// （与 PushDomain 的目标选择一致：无集群域名会推到所有节点）。
// 与 SyncAll 不同，它只碰这一个节点 —— 新节点接入时没必要对全网做一次 replace-all。
// 返回推送的域名数。
func (p *Pusher) SyncNode(n *config.Node, domains []*config.Domain) (int, error) {
	list := make([]*DomainPushPayload, 0, len(domains))
	for _, d := range domains {
		if d.ClusterID == "" || d.ClusterID == n.ClusterID {
			list = append(list, buildDomainPayload(d))
		}
	}
	if err := p.post(n, "/edge/domains/replace-all", map[string]any{"domains": list}); err != nil {
		return 0, err
	}
	return len(list), nil
}

// SyncNodePayloads 与 SyncNode 相同，但接收已构建好的 payload（v2 证书存在数据库里，
// 不在主控磁盘上，由调用方解密后填好 CertPEM/KeyPEM）。
func (p *Pusher) SyncNodePayloads(n *config.Node, payloads []*DomainPushPayload) (int, error) {
	list := make([]*DomainPushPayload, 0, len(payloads))
	for _, d := range payloads {
		if d.ClusterID == "" || d.ClusterID == n.ClusterID {
			list = append(list, d)
		}
	}
	if err := p.post(n, "/edge/domains/replace-all", map[string]any{"domains": list}); err != nil {
		return 0, err
	}
	return len(list), nil
}

// PostToNode 向单个节点 POST 一份配置，供新节点接入时逐项下发（CC / XDP / 封禁阶梯）。
func (p *Pusher) PostToNode(n *config.Node, path string, body any) error {
	return p.post(n, path, body)
}

func (p *Pusher) BlockIP(ip string) {
	p.broadcastXDP("", "/edge/xdp/block", map[string]string{"ip": ip})
}

func (p *Pusher) UnblockIP(ip string) {
	p.broadcastXDP("", "/edge/xdp/unblock", map[string]string{"ip": ip})
}

// PushXDPBanConfig 向所有启用的边缘节点下发 XDP 封禁阶梯。
//
// 返回每个节点的结果而不是像 BlockIP 那样发完就忘：改阶梯是配置操作，用户需要知道
// 「哪些节点没接住」。某个节点没跑 AutoBlocker（没指定网卡、XDP 加载失败）会返回 409，
// 静默忽略的话用户会以为全网都改好了，而那个节点仍在用旧阶梯封人。
func (p *Pusher) PushXDPBanConfig(ladder, offenderTTL string) map[string]string {
	payload := map[string]string{"ladder": ladder, "offender_ttl": offenderTTL}
	nodes := p.nodes.ListEnabled()
	results := make(map[string]string, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			msg := "ok"
			if err := p.post(n, "/edge/xdp/ban-config", payload); err != nil {
				msg = err.Error()
				log.Printf("push XDP ban config to node %s (%s) failed: %v", n.Name, n.Address, err)
			}
			mu.Lock()
			results[n.Name] = msg
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return results
}

// GetXDPConfig 从指定边缘节点读取 XDP 配置
func (p *Pusher) GetXDPConfig(nodeID string) (map[string]any, error) {
	node, err := p.nodes.Get(nodeID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, node.Address+"/edge/xdp/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+node.Token)
	resp, err := p.do(node, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var cfg map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// PushXDPConfig 向所有边缘节点推送 XDP 配置
func (p *Pusher) PushXDPConfig(cfg any) map[string]string {
	nodes := p.nodes.ListEnabled()
	results := make(map[string]string, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			msg := "ok"
			if err := p.post(n, "/edge/xdp/config", cfg); err != nil {
				msg = err.Error()
				log.Printf("push XDP config to node %s (%s) failed: %v", n.Name, n.Address, err)
			}
			mu.Lock()
			results[n.Name] = msg
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return results
}

func (p *Pusher) BlockIPInCluster(ip, clusterID string) {
	p.broadcastXDP(clusterID, "/edge/xdp/block", map[string]string{"ip": ip})
}

func (p *Pusher) UnblockIPInCluster(ip, clusterID string) {
	p.broadcastXDP(clusterID, "/edge/xdp/unblock", map[string]string{"ip": ip})
}

// PushCCConfig 向所有启用的边缘节点推送 CC 防御基础阈值配置（每秒/每分钟请求数、
// 突发容忍、封禁时长、白名单）。按域名的强检测策略随 Domain 对象走 PushDomain，不经过此处。
// 返回每个节点的推送结果，格式与 PushXDPConfig 一致。
func (p *Pusher) PushCCConfig(enabled bool, rps, rpm, burst int, blockDuration int64) map[string]string {
	cfg := waf.CCConfig{
		Enabled:           enabled,
		RequestsPerSecond: rps,
		RequestsPerMinute: rpm,
		BurstSize:         burst,
		BlockDuration:     time.Duration(blockDuration),
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make(map[string]string)
	)

	for _, n := range p.nodes.ListEnabled() {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			msg := "ok"
			if err := p.post(n, "/edge/cc/config", cfg); err != nil {
				msg = err.Error()
				log.Printf("push CC config to node %s (%s) failed: %v", n.Name, n.Address, err)
			}
			mu.Lock()
			results[n.Name] = msg
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return results
}

// RotateTicketKey 向所有边缘节点推送新的 SSL 会话票据密钥。
// key 是 base64 编码的 32 字节 AES-256 密钥。
func (p *Pusher) RotateTicketKey(key []byte) {
	payload := map[string]string{"ticket_key": base64.StdEncoding.EncodeToString(key)}
	for _, n := range p.nodes.ListEnabled() {
		go func(n *config.Node) {
			if err := p.post(n, "/edge/rotate-ticket-key", payload); err != nil {
				log.Printf("rotate ticket key on node %s (%s) failed: %v", n.Name, n.Address, err)
			}
		}(n)
	}
}

func (p *Pusher) broadcastXDP(clusterID, path string, body any) {
	for _, n := range p.targetNodes(clusterID) {
		go func(n *config.Node) {
			if err := p.post(n, path, body); err != nil {
				log.Printf("xdp push to node %s (%s)%s failed: %v", n.Name, n.Address, path, err)
			}
		}(n)
	}
}

func (p *Pusher) GetStatus(n *config.Node) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/status", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)

	// 钉扎检查单独走：未登记指纹时直接把恢复路径返回给调用方，不能套进下面的"连接类"
	// 错误分类里（那会把它说成一次网络故障，运维就会去查防火墙，而真正缺的是指纹）。
	client, err := p.clientFor(n)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// 提供更详细的错误信息，帮助诊断问题
		if strings.Contains(err.Error(), "timeout") {
			return nil, fmt.Errorf("connection timeout - check if firewall allows connections to %s: %w", n.Address, err)
		}
		if strings.Contains(err.Error(), "connection refused") {
			return nil, fmt.Errorf("connection refused - node service may not be running on %s: %w", n.Address, err)
		}
		if strings.Contains(err.Error(), "no such host") {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", n.Address, err)
		}
		if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "证书") {
			// 钉扎失败最常见的原因是边缘重装后换了自签证书：这需要在面板更新指纹，
			// 不是重启 cdnedge 就能"重新生成一张对得上的"证书。
			return nil, fmt.Errorf("TLS 证书校验未通过 - 若边缘节点重装过，请在面板更新证书指纹后重试: %w", err)
		}
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed - token mismatch between master and edge node")
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("edge node returned HTTP %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// InstallXdp 在边缘节点上一键安装 XDP
func (p *Pusher) InstallXdp(n *config.Node) (map[string]any, error) {
	// 安装 XDP 可能需要几分钟（下载依赖、编译），使用更长的超时时间
	client, err := p.longTimeoutClientFor(n, 10*time.Minute)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, n.Address+"/edge/install-xdp", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		if msg, ok := result["error"].(string); ok {
			// 如果有 details 字段，也返回它
			if details, ok := result["details"].(string); ok && details != "" {
				return result, fmt.Errorf("%s: %s", msg, details)
			}
			return result, fmt.Errorf("%s", msg)
		}
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	return result, nil
}

// GetInstallXdpStatus 查询边缘节点的 XDP 安装状态
func (p *Pusher) GetInstallXdpStatus(n *config.Node) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/install-xdp/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetDomainStats 从边缘节点拉取当日域名流量和访问 IP 统计。
func (p *Pusher) GetDomainStats(n *config.Node) ([]map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/stats", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetStatsOverview 从边缘节点拉取当日全站大盘数据（24 小时分桶 + Top 域名/IP + 今日总计）。
func (p *Pusher) GetStatsOverview(n *config.Node) (*stats.Overview, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/stats/overview", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result stats.Overview
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBannedIPs 从边缘节点拉取当前所有有效封禁 IP（CC + WAF 共用封禁集合）。
func (p *Pusher) GetBannedIPs(n *config.Node) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/waf/banned", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.IPs, nil
}

// BanSnapshot 是一个节点当前的封禁集合。Expiry 已换算到**主控本地时钟**
// （节点 exp - 节点 now + 主控 now），不受节点间时钟偏差影响。
// Legacy=true 表示节点是旧版、没有上报到期时刻，Expiry 为空。
type BanSnapshot struct {
	IPs    []string
	Expiry map[string]time.Time
	Legacy bool
}

// GetBanSnapshot 拉取节点封禁集合及每条的到期时刻。
func (p *Pusher) GetBanSnapshot(n *config.Node) (*BanSnapshot, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/waf/banned", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result struct {
		IPs  []string         `json:"ips"`
		Bans map[string]int64 `json:"bans"`
		Now  int64            `json:"now"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return parseBanSnapshot(result.IPs, result.Bans, result.Now, time.Now()), nil
}

// parseBanSnapshot 把节点上报的 unix 到期时刻换算到主控时钟。单独拆出便于测试。
func parseBanSnapshot(ips []string, bans map[string]int64, edgeNow int64, masterNow time.Time) *BanSnapshot {
	snap := &BanSnapshot{IPs: ips}
	if bans == nil || edgeNow <= 0 {
		snap.Legacy = true
		return snap
	}
	snap.Expiry = make(map[string]time.Time, len(bans))
	for ip, exp := range bans {
		remaining := time.Duration(exp-edgeNow) * time.Second
		if remaining <= 0 {
			continue
		}
		snap.Expiry[ip] = masterNow.Add(remaining)
	}
	// 以 bans 为准重建 IP 列表：已到期的条目不应再进入并集。
	snap.IPs = make([]string, 0, len(snap.Expiry))
	for ip := range snap.Expiry {
		snap.IPs = append(snap.IPs, ip)
	}
	return snap
}

// GetCCStats 从边缘节点拉取 CC 防御统计（追踪/活跃/违规/封禁 IP 数）。
func (p *Pusher) GetCCStats(n *config.Node) (waf.CCStats, error) {
	var stats waf.CCStats
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/cc/stats", nil)
	if err != nil {
		return stats, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return stats, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return stats, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return stats, err
	}
	return stats, nil
}

// GetCCTrackedIPs 从边缘节点拉取当前被追踪的 IP 明细列表。
func (p *Pusher) GetCCTrackedIPs(n *config.Node) ([]waf.IPStatus, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/cc/ips", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result struct {
		IPs []waf.IPStatus `json:"ips"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.IPs, nil
}

// GetCacheStats 从边缘节点拉取边缘磁盘缓存的已用字节与文件数。
func (p *Pusher) GetCacheStats(n *config.Node) (bytes int64, files int64, err error) {
	req, e := http.NewRequest(http.MethodGet, n.Address+"/edge/cache/stats", nil)
	if e != nil {
		return 0, 0, e
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, e := p.do(n, req)
	if e != nil {
		return 0, 0, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result struct {
		Bytes int64 `json:"bytes"`
		Files int64 `json:"files"`
	}
	if e := json.NewDecoder(resp.Body).Decode(&result); e != nil {
		return 0, 0, e
	}
	return result.Bytes, result.Files, nil
}

// GetXDPBlocklist 从边缘节点拉取 XDP 当前封禁的 IP 列表。
// 返回 []any 以支持两种格式：旧版返回 []string，新版返回 []map[string]any（带 remaining_time）。
func (p *Pusher) GetXDPBlocklist(n *config.Node) ([]any, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/xdp/blocklist", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result []any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetXDPBanConfig 从单个边缘节点读取当前生效的封禁阶梯，供面板回显。
//
// 只读一个节点（调用方取第一个应答成功的）而不是聚合所有节点：阶梯是全网统一下发的，
// 正常情况下所有节点一致。真要不一致（某节点下发时离线），面板显示其中一个总比显示
// 一个合并出来的假象要好 —— 后者会让用户以为全网都是那个值。
func (p *Pusher) GetXDPBanConfig(n *config.Node) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/xdp/ban-config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetXDPStats 从边缘节点拉取 XDP 统计数据（通过/放行/丢包数）。
func (p *Pusher) GetXDPStats(n *config.Node) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, n.Address+"/edge/xdp/stats", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// PostBan 向单个边缘节点下发一条软件层 WAF 封禁（POST /edge/waf/block）。
// body 形如 {"ip": "1.2.3.4", "minutes": 0}，minutes<=0 时边缘按默认 24 小时封禁。
func (p *Pusher) PostBan(n *config.Node, body any) error {
	return p.post(n, "/edge/waf/block", body)
}

// BroadcastBanIP 向所有启用的边缘节点下发一条封禁（软件层 WAF 封禁，非 XDP）。
// minutes<=0 表示「不封禁/禁用」，边缘节点会跳过该封禁请求（不能兜底成默认值，否则把
// 「关闭」悄悄变成「封禁N小时」，导致 CC 的 5 分钟本地封禁扩散成全网永久封禁）。
func (p *Pusher) BroadcastBanIP(ip string, minutes int) {
	body := map[string]any{"ip": ip, "minutes": minutes}
	for _, n := range p.nodes.ListEnabled() {
		go func(n *config.Node) {
			if err := p.post(n, "/edge/waf/block", body); err != nil {
				log.Printf("broadcast ban %s to node %s (%s) failed: %v", ip, n.Name, n.Address, err)
			}
		}(n)
	}
}

// BroadcastUnbanIP 向所有启用的边缘节点解除某个 IP 的封禁（WAF 封禁表 + CC 追踪状态）。
// 面板上解封一个 IP 时调用，确保全网一致解封，而不是只在某一个节点生效。
func (p *Pusher) BroadcastUnbanIP(ip string) {
	body := map[string]string{"ip": ip}
	for _, n := range p.nodes.ListEnabled() {
		go func(n *config.Node) {
			if err := p.post(n, "/edge/waf/unblock", body); err != nil {
				log.Printf("broadcast unban(waf) %s to node %s (%s) failed: %v", ip, n.Name, n.Address, err)
			}
			// 同时清掉该节点 CC 追踪器里的封禁/违规状态，避免下一秒又被本地计数重新封禁。
			if err := p.post(n, "/edge/cc/unblock", body); err != nil {
				log.Printf("broadcast unban(cc) %s to node %s (%s) failed: %v", ip, n.Name, n.Address, err)
			}
		}(n)
	}
}

// BroadcastDomainAttackState 向所有启用的边缘节点广播域名攻击态变更（实现 waf.AttackStateBroadcaster 接口）。
// 当某个域名在主控进程内进入第二层开盾态或第三层攻击态时，通知其他节点同步进入，确保全网统一响应。
// 到期时刻由 waf 侧算好后带在消息里，这里只补发起方身份（主控自己）。
func (p *Pusher) BroadcastDomainAttackState(msg waf.AttackStateMessage) {
	msg.NodeID = "master"
	for _, n := range p.nodes.ListEnabled() {
		go func(n *config.Node, m waf.AttackStateMessage) {
			if err := p.post(n, "/edge/cc/attack-state", m); err != nil {
				log.Printf("broadcast domain %s attack state to node %s (%s) failed: %v", m.Domain, n.Name, n.Address, err)
			}
		}(n, msg)
	}
}

// 区域封禁的下发不走这里：旧路径把 GeoIPManager 导出的 IP 范围 base64 塞进
// /edge/geo/sync，而边缘只打一行日志就回 ok，面板上的"已下发"是假的。
// 现在由主控把国家编译成带指纹的前缀表，见 internal/apiv2/geo_admin.go 的 buildGeoPlan/geoPushNode
// 与边缘的 /edge/geo/table。

// PurgeCluster 并发向 clusterID 下全部启用节点的 /edge/cache/purge 发起清缓存请求，
// 收集每个节点的结果（node.Name -> "ok" 或错误信息），模式与 PushXDPBanConfig 一致：
// 清缓存是用户主动触发的操作，需要如实反馈哪些节点没清成功，不能静默丢失。
func (p *Pusher) PurgeCluster(clusterID, domain string) map[string]string {
	payload := map[string]string{"domain": domain}
	nodes := p.targetNodes(clusterID)
	results := make(map[string]string, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			msg := "ok"
			if err := p.post(n, "/edge/cache/purge", payload); err != nil {
				msg = err.Error()
				log.Printf("purge cache for domain %s on node %s (%s) failed: %v", domain, n.Name, n.Address, err)
			}
			mu.Lock()
			results[n.Name] = msg
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return results
}

// PushDomainToCluster 并发向 clusterID 下全部启用节点推送单个域名配置（upsert 语义，
// POST /edge/domains，与 PushDomain 的目标节点选择一致），收集每个节点的结果。
// 与 PushDomain 不同的是这里等待所有 goroutine 完成并返回结果——resync 场景需要知道
// 集群里哪些节点没接住新配置，PushDomain 那种 fire-and-forget 不满足这个需求。
func (p *Pusher) PushDomainToCluster(d *config.Domain, clusterID string) map[string]string {
	payload := buildDomainPayload(d)
	nodes := p.targetNodes(clusterID)
	results := make(map[string]string, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			msg := "ok"
			if err := p.post(n, "/edge/domains", payload); err != nil {
				msg = err.Error()
				log.Printf("push domain %s to node %s (%s) failed: %v", d.Domain, n.Name, n.Address, err)
			}
			mu.Lock()
			results[n.Name] = msg
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return results
}

func (p *Pusher) post(n *config.Node, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, n.Address+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.Token)

	// 请求级别超时：避免被攻击节点拖垮整个推送流程
	// 10 秒已足够边缘节点处理配置更新，超过说明节点有问题
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := p.do(n, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	return nil
}

// PostToNodeResp 向节点 POST 一份体积较大的配置，并把响应的状态码与响应体带回来。
//
// 与 PostToNode 的差别就是带回来的这两样：规则包被边缘整包拒收时，原因写在响应体里
// （"active 包不可用: 规则 x 的正则编译失败（不支持前后向断言）"）。只回一句
// "edge returned 400" 的话，管理员只能对着自己刚写的那份 JSON 猜哪一条坏了。
// 超时由调用方给：p.post 里那个 10 秒是按小配置写的，几 MB 的包在慢链路上不够用。
func (p *Pusher) PostToNodeResp(n *config.Node, path string, body any, timeout time.Duration) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, n.Address+path, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.Token)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req = req.WithContext(ctx)

	client, err := p.longTimeoutClientFor(n, timeout)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	// 截断读：正常响应是一小段 JSON。真读出几十 MB 说明对端不正常，别跟着涨内存。
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, payload, nil
}

func (p *Pusher) targetNodes(clusterID string) []*config.Node {
	all := p.nodes.ListEnabled()
	if clusterID == "" {
		return all
	}
	var out []*config.Node
	for _, n := range all {
		if n.ClusterID == clusterID {
			out = append(out, n)
		}
	}
	return out
}

// DomainPushPayload 是推送到边缘节点的完整域名配置，包含证书内容。
type DomainPushPayload struct {
	config.Domain
	CertPEM string `json:"cert_pem,omitempty"` // 证书 PEM 内容
	KeyPEM  string `json:"key_pem,omitempty"`  // 私钥 PEM 内容
}

// buildDomainPayload 构建推送 payload，手动 SSL 模式时读取证书内容一起推送。
// cert 和 key 必须同时读取成功才填充，任一失败则不发送（边缘节点不会写入不完整的证书对）。
func buildDomainPayload(d *config.Domain) *DomainPushPayload {
	payload := &DomainPushPayload{Domain: *d}
	if d.SSL.Enabled && d.SSL.Mode == "manual" && d.SSL.CertFile != "" && d.SSL.KeyFile != "" {
		cert, certErr := os.ReadFile(d.SSL.CertFile)
		key, keyErr := os.ReadFile(d.SSL.KeyFile)
		if certErr != nil {
			log.Printf("push domain %s: read cert file failed: %v", d.Domain, certErr)
		} else if keyErr != nil {
			log.Printf("push domain %s: read key file failed: %v", d.Domain, keyErr)
		} else {
			payload.CertPEM = string(cert)
			payload.KeyPEM = string(key)
		}
	}
	return payload
}

// certFingerprint 计算证书的 SHA-256 指纹（小写十六进制，冒号分隔）。
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":")
}

// normalizeFingerprint 统一格式为冒号分隔小写，兼容以下输入：
// - "AA:BB:CC:..." （openssl -fingerprint 输出）
// - "aabbcc..."    （64字符无冒号 hex）
// - "AA BB CC ..."  （空格分隔）
func normalizeFingerprint(fp string) string {
	// 去掉所有空格和冒号，得到纯 hex 字符串
	clean := strings.ToLower(strings.NewReplacer(" ", "", ":", "").Replace(fp))
	if len(clean) != 64 {
		return clean // 格式不对，原样返回，TLS 验证时会不匹配并给出错误
	}
	// 重新插入冒号，变成 certFingerprint 的输出格式
	parts := make([]string, 32)
	for i := 0; i < 32; i++ {
		parts[i] = clean[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

// GetJSON 向单个节点发 GET 并把 JSON 响应解到 out，供 v2 多租户接口按代理自己的节点逐个拉取
// （v2 节点不在 p.nodes 里，不能用按 nodeID 查找的旧方法）。>=400 视为错误。
func (p *Pusher) GetJSON(n *config.Node, path string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.Address+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+n.Token)
	resp, err := p.do(n, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("edge returned %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}
