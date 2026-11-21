package stats

import (
"bufio"
"log"
"os"
"path/filepath"
"strings"
"sync"
"time"
)

type DomainStats struct {
Domain      string    `json:"domain"`
TodayBytes  uint64    `json:"today_bytes"`
TodayMB     float64   `json:"today_mb"`
UniqueIPs   int       `json:"unique_ips"`
Requests    uint64    `json:"requests"`
Blocked     uint64    `json:"blocked"` // 当日 status >= 400 的请求数（与 Overview.TotalBlocked 同口径）
CollectedAt string    `json:"collected_at"`
}

type Collector struct {
logDir string
}

func NewCollector(logDir string) *Collector {
return &Collector{logDir: logDir}
}
// CollectAll 并发解析所有域名的当日统计。
// 对于没有日志文件的域名返回 nil，CollectAll 会跳过。
func (c *Collector) CollectAll(domains []string) []*DomainStats {
if _, err := os.Stat(c.logDir); os.IsNotExist(err) {
log.Printf("[stats] log directory %s does not exist", c.logDir)
return nil
}

var (
wg      sync.WaitGroup
mu      sync.Mutex
results []*DomainStats
)
for _, domain := range domains {
wg.Add(1)
go func(d string) {
defer wg.Done()
s, err := c.Collect(d)
if err == nil && s != nil {
mu.Lock()
results = append(results, s)
mu.Unlock()
}
}(domain)
}
wg.Wait()
return results
}
// Collect 解析单个域名的 access log，统计当日数据。
// Tengine access log 格式 (main)：
//   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent ...
//
// 日期匹配策略：
// 1. 使用当前时间计算今天的日期字符串（如 "13/Jul/2026"）
// 2. 快速过滤：检查日志行是否包含今天的日期
// 3. 容差过滤：同时检查 +1 天，防止边缘/主控节点时区差异
// 4. 二次验证：对容差匹配的日志行，通过 extractLogDate 验证日期
func (c *Collector) Collect(domain string) (*DomainStats, error) {
logPath := filepath.Join(c.logDir, domain+".access.log")
f, err := os.Open(logPath)
if err != nil {
if os.IsNotExist(err) {
// 日志文件不存在，返回 nil 让调用方跳过（不是错误）
return nil, nil
}
return nil, err
}
defer f.Close()

now := time.Now()
today := now.Format("02/Jan/2006")
yesterday := now.AddDate(0, 0, -1).Format("02/Jan/2006")

ips := make(map[string]struct{})
var totalBytes uint64
var requests uint64
var blocked uint64

// 限制最多处理 50000 行，避免大文件导致 CPU 爆满
const maxLines = 50000
lineCount := 0

scanner := bufio.NewScanner(f)
buf := make([]byte, 64*1024)
scanner.Buffer(buf, 1024*1024)

for scanner.Scan() {
lineCount++
if lineCount > maxLines {
log.Printf("[stats] domain %s: stopped after %d lines (limit reached)", domain, maxLines)
break
}

line := scanner.Text()
if line == "" {
continue
}
// 快速日期过滤（容差 +1 天，处理时区差异）
if !strings.Contains(line, today) && !strings.Contains(line, yesterday) {
continue
}
// 容差匹配的日志行，二次验证日期
if !strings.Contains(line, today) {
lineDate := extractLogDate(line)
if lineDate != today {
continue
}
}
ip, bytes, status, ok := parseAccessLogLine(line)
if !ok {
continue
}
ips[ip] = struct{}{}
totalBytes += bytes
requests++
if status >= 400 {
blocked++
}
}

mb := float64(totalBytes) / 1024 / 1024

return &DomainStats{
Domain:      domain,
TodayBytes:  totalBytes,
TodayMB:     math2decimal(mb, 2),
UniqueIPs:   len(ips),
Requests:    requests,
Blocked:     blocked,
CollectedAt: time.Now().Format(time.RFC3339),
}, nil
}
// extractLogDate 从日志行中提取日期字符串（格式 "02/Jan/2006"）。
// 用于时区容差匹配后的二次验证。
func extractLogDate(line string) string {
start := strings.Index(line, "[")
end := strings.Index(line, "]")
if start == -1 || end == -1 || end <= start {
return ""
}
dateWithTime := line[start+1 : end]
colonIdx := strings.Index(dateWithTime, ":")
if colonIdx > 0 && colonIdx < 12 {
return dateWithTime[:colonIdx]
}
return ""
}

// parseAccessLogLine 解析一行 access log，返回 (clientIP, bodyBytes, status, ok)。
//
// 不能按空格切分后取固定列号：
//   - per-domain 日志（templates/site.conf.tmpl 的 access_log 未指定格式名）用的是
//     Tengine 内置 combined，而非 configs/tengine.conf 里定义的 main。两种格式下
//     $body_bytes_sent 的列号不同：原实现取 fields[8]，在 combined 下拿到的其实是
//     $status —— 于是"当日流量"统计的是状态码之和（一次 200 响应记成 200 字节），
//     面板上的 MB 数与真实出站流量毫无关系。原本那句 len(fields) < 9 也从未生效，
//     combined 实测 12 列。
//   - $remote_user 允许含空格，一旦出现，后续所有列号整体错位。
//
// 改为与 parseOverviewLine 共用 extractStatusBytes：从 "$request" 引号对之后定位
// status 与 body_bytes，让两个统计口径由同一套解析保证一致。
func parseAccessLogLine(line string) (string, uint64, int, bool) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return "", 0, 0, false
	}
	status, bytes, ok := extractStatusBytes(line)
	if !ok {
		return "", 0, 0, false
	}
	return line[:sp], bytes, status, true
}

func math2decimal(f float64, places int) float64 {
pow := 1.0
for i := 0; i < places; i++ {
pow *= 10
}
return float64(int(f*pow+0.5)) / pow
}
