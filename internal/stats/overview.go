package stats

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HourBucket 是当日某个小时（0-23）的聚合桶。
type HourBucket struct {
	Hour     int    `json:"hour"`     // 0-23（本地时间）
	Requests uint64 `json:"requests"` // 该小时请求数
	Bytes    uint64 `json:"bytes"`    // 该小时出站字节（body_bytes_sent）
	Blocked  uint64 `json:"blocked"`  // 该小时被拦截的请求数（status >= 400）
}

// TopItem 是 Top 排行里的一条（域名或客户端 IP）。
type TopItem struct {
	Key      string `json:"key"`      // 域名或 IP
	Requests uint64 `json:"requests"` // 请求数
	Bytes    uint64 `json:"bytes"`    // 出站字节
}

// Overview 是单个边缘节点当日全站聚合结果。
// 小时桶固定 24 个（hour 0-23），Top 列表已按请求数降序截断。
type Overview struct {
	TotalRequests uint64        `json:"total_requests"`
	TotalBytes    uint64        `json:"total_bytes"`
	TotalBlocked  uint64        `json:"total_blocked"`
	UniqueIPs     int           `json:"unique_ips"`
	Hourly        []*HourBucket `json:"hourly"`      // 长度 24
	TopDomains    []*TopItem    `json:"top_domains"` // 最多 overviewTopN
	TopIPs        []*TopItem    `json:"top_ips"`     // 最多 overviewTopN
	// DomainIPs 是逐域名的热门来源 IP，主控按代理名下的域名筛选后展示。
	// 与 TopIPs 的区别只有一个：TopIPs 是全站合并后的排行，看不出某个 IP 打的是哪个域名。
	DomainIPs   []*DomainTopIPs `json:"domain_ips,omitempty"`
	CollectedAt string          `json:"collected_at"`
}

// DomainTopIPs 是单个域名的热门来源 IP 排行。
type DomainTopIPs struct {
	Domain string    `json:"domain"`
	Items  []*TopItem `json:"items"`
}

// overviewTopN 是 Top 域名 / Top 客户端 IP 的截断长度。
// 参考图取 Top 100；边缘侧就截到 100，主控汇总多节点后再截一次到 100。
const overviewTopN = 100

// domainTopIPN 是单个域名的热门来源 IP 截断长度。取 20 而不是 100 是因为每个域名都带一份、
// 全部塞在同一条 60 秒一次的上报体里（上报体走 gzip，见 cmd/cdnedge/main.go 的 postMaster）。
// 注意这里只截每个域名的 IP 条数，不截域名个数：域名清单由主控按代理名下的域名过滤，
// 一旦按流量排序截断，小代理的域名会整列空掉，那是静默降级而不是省流量。
const domainTopIPN = 20

// domainPartial 是单个域名扫描后的局部聚合，合并前用。
type domainPartial struct {
	hourly [24]HourBucket
	ips    map[string]struct{}
	reqs   uint64
	bytes  uint64
	ipReqs map[string]uint64
	ipByts map[string]uint64
	domain string
}

// CollectOverview 扫描所有域名的当日 access log，产出全站大盘数据：
// 24 小时分桶（请求/流量/拦截）、Top 域名、Top 客户端 IP、独立访客数。
// 与 Collect 独立：Collect 只输出每域名当日总数，本函数按小时分桶并做 Top 排行。
func (c *Collector) CollectOverview(domains []string) *Overview {
	ov := &Overview{
		Hourly:      make([]*HourBucket, 24),
		TopDomains:  []*TopItem{},
		TopIPs:      []*TopItem{},
		CollectedAt: time.Now().Format(time.RFC3339),
	}
	for i := 0; i < 24; i++ {
		ov.Hourly[i] = &HourBucket{Hour: i}
	}
	if _, err := os.Stat(c.logDir); os.IsNotExist(err) {
		log.Printf("[stats] log directory %s does not exist", c.logDir)
		return ov
	}

	now := time.Now()
	today := now.Format("02/Jan/2006")
	yesterday := now.AddDate(0, 0, -1).Format("02/Jan/2006")

	// 每个域名并发扫描，各自产出局部聚合，最后合并。
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		partials []*domainPartial
	)
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			p := c.scanDomainOverview(d, today, yesterday)
			if p == nil {
				return
			}
			mu.Lock()
			partials = append(partials, p)
			mu.Unlock()
		}(domain)
	}
	wg.Wait()

	// 合并所有域名的局部聚合。
	globalIPs := make(map[string]struct{})
	ipReqs := make(map[string]uint64)
	ipByts := make(map[string]uint64)
	domainItems := make([]*TopItem, 0, len(partials))
	for _, p := range partials {
		for i := 0; i < 24; i++ {
			ov.Hourly[i].Requests += p.hourly[i].Requests
			ov.Hourly[i].Bytes += p.hourly[i].Bytes
			ov.Hourly[i].Blocked += p.hourly[i].Blocked
			ov.TotalRequests += p.hourly[i].Requests
			ov.TotalBytes += p.hourly[i].Bytes
			ov.TotalBlocked += p.hourly[i].Blocked
		}
		for ip := range p.ips {
			globalIPs[ip] = struct{}{}
		}
		for ip, n := range p.ipReqs {
			ipReqs[ip] += n
		}
		for ip, n := range p.ipByts {
			ipByts[ip] += n
		}
		domainItems = append(domainItems, &TopItem{Key: p.domain, Requests: p.reqs, Bytes: p.bytes})
		if len(p.ipReqs) > 0 {
			ov.DomainIPs = append(ov.DomainIPs, &DomainTopIPs{
				Domain: p.domain,
				Items:  topIPItems(p.ipReqs, p.ipByts, domainTopIPN),
			})
		}
	}
	ov.UniqueIPs = len(globalIPs)

	sortTop(domainItems)
	ov.TopDomains = truncateTop(domainItems, overviewTopN)
	ov.TopIPs = topIPItems(ipReqs, ipByts, overviewTopN)

	return ov
}

// topIPItems 把 (ip→请求数, ip→字节数) 两份表合成按请求数降序、请求数相同按字节降序的
// TopItem 列表并截断。全站那份和逐域名那份共用，免得同一个 IP 在两张表里排出两个名次。
func topIPItems(reqs, byts map[string]uint64, n int) []*TopItem {
	items := make([]*TopItem, 0, len(reqs))
	for ip, count := range reqs {
		items = append(items, &TopItem{Key: ip, Requests: count, Bytes: byts[ip]})
	}
	sortTop(items)
	return truncateTop(items, n)
}

// scanDomainOverview 扫描单个域名当日日志，返回局部聚合；无日志文件返回 nil。
func (c *Collector) scanDomainOverview(domain, today, yesterday string) *domainPartial {
	logPath := filepath.Join(c.logDir, domain+".access.log")
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	p := &domainPartial{
		ips:    make(map[string]struct{}),
		ipReqs: make(map[string]uint64),
		ipByts: make(map[string]uint64),
		domain: domain,
	}

	const maxLines = 200000 // 大盘扫描上限比单域名统计更宽，覆盖高流量站点全天日志
	lineCount := 0

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lineCount++
		if lineCount > maxLines {
			log.Printf("[stats] overview domain %s: stopped after %d lines", domain, maxLines)
			break
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		if !strings.Contains(line, today) && !strings.Contains(line, yesterday) {
			continue
		}
		if !strings.Contains(line, today) {
			if extractLogDate(line) != today {
				continue
			}
		}
		ip, bytes, status, hour, ok := parseOverviewLine(line)
		if !ok || hour < 0 || hour > 23 {
			continue
		}
		p.hourly[hour].Requests++
		p.hourly[hour].Bytes += bytes
		if status >= 400 {
			p.hourly[hour].Blocked++
		}
		p.ips[ip] = struct{}{}
		p.reqs++
		p.bytes += bytes
		p.ipReqs[ip]++
		p.ipByts[ip] += bytes
	}
	return p
}

// parseOverviewLine 解析一行 combined/main 格式日志，返回 (ip, bytes, status, hour, ok)。
// 结构：$remote_addr - $remote_user [dd/Mon/yyyy:HH:MM:SS +ZZZZ] "$request" $status $body_bytes ...
// IP 取第一段；hour 从方括号时间提取；status/bytes 从 "request" 引号对之后定位，
// 避免 $remote_user 含空格导致按列切分错位。
func parseOverviewLine(line string) (ip string, bytes uint64, status int, hour int, ok bool) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return "", 0, 0, -1, false
	}
	ip = line[:sp]
	hour = extractLogHour(line)
	st, by, ok2 := extractStatusBytes(line)
	if !ok2 {
		return "", 0, 0, -1, false
	}
	return ip, by, st, hour, true
}

// extractLogHour 从 "[dd/Mon/yyyy:HH:MM:SS +ZZZZ]" 提取小时 HH，失败返回 -1。
func extractLogHour(line string) int {
	start := strings.IndexByte(line, '[')
	end := strings.IndexByte(line, ']')
	if start == -1 || end == -1 || end <= start {
		return -1
	}
	seg := line[start+1 : end]
	c1 := strings.IndexByte(seg, ':')
	if c1 < 0 || c1+3 > len(seg) {
		return -1
	}
	h, err := strconv.Atoi(seg[c1+1 : c1+3])
	if err != nil {
		return -1
	}
	return h
}

// extractStatusBytes 定位 "$request" 引号对之后的 status 与 body_bytes。
func extractStatusBytes(line string) (status int, bytes uint64, ok bool) {
	q1 := strings.IndexByte(line, '"')
	if q1 < 0 {
		return 0, 0, false
	}
	q2 := strings.IndexByte(line[q1+1:], '"')
	if q2 < 0 {
		return 0, 0, false
	}
	rest := strings.TrimSpace(line[q1+1+q2+1:])
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return 0, 0, false
	}
	st, err1 := strconv.Atoi(fields[0])
	by, err2 := strconv.ParseUint(fields[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return st, by, true
}

// sortTop 按请求数降序（相等按字节降序）原地排序。
func sortTop(items []*TopItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Requests != items[j].Requests {
			return items[i].Requests > items[j].Requests
		}
		return items[i].Bytes > items[j].Bytes
	})
}

// truncateTop 截断到 n 条（已排序），保证非 nil。
func truncateTop(items []*TopItem, n int) []*TopItem {
	if items == nil {
		return []*TopItem{}
	}
	if len(items) > n {
		items = items[:n]
	}
	return items
}
