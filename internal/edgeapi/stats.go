package edgeapi

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemStats 节点系统资源快照。
type SystemStats struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemTotal    uint64  `json:"mem_total_mb"`
	MemUsed     uint64  `json:"mem_used_mb"`
	MemPercent  float64 `json:"mem_percent"`
	NetRxBps    uint64  `json:"net_rx_bps"`
	NetTxBps    uint64  `json:"net_tx_bps"`
	TrafficRxMB uint64  `json:"traffic_rx_mb"`
	TrafficTxMB uint64  `json:"traffic_tx_mb"`
	Connections int     `json:"connections"` // 当前 ESTABLISHED TCP 连接数
	Uptime      string  `json:"uptime"`
	CollectedAt string  `json:"collected_at"`
}

type cpuSnapshot struct {
	total float64
	idle  float64
	taken time.Time
}

type netSnapshot struct {
	rx    uint64
	tx    uint64
	taken time.Time
}

// statsMu 保护所有包级采样变量，防止并发调用产生数据竞争。
var (
	statsMu     sync.Mutex
	lastCPU     cpuSnapshot
	lastNet     netSnapshot
	cachedIface string // 主网卡名缓存，避免每次重新读 /proc/net/route
)

// CollectStats 采集当前节点的系统资源指标（并发安全）。
func CollectStats(iface string) (*SystemStats, error) {
	s := &SystemStats{CollectedAt: time.Now().Format(time.RFC3339)}

	statsMu.Lock()
	defer statsMu.Unlock()

	// 主网卡名只检测一次
	if iface == "" {
		if cachedIface == "" {
			cachedIface = detectMainIface()
		}
		iface = cachedIface
	}

	if cpu, err := cpuPercentLocked(); err == nil {
		s.CPUPercent = cpu
	}

	if total, used, err := memStats(); err == nil {
		s.MemTotal = total
		s.MemUsed = used
		if total > 0 {
			s.MemPercent = float64(used) / float64(total) * 100
		}
	}

	if rx, tx, rxBps, txBps, err := netStatsLocked(iface); err == nil {
		s.TrafficRxMB = rx / 1024 / 1024
		s.TrafficTxMB = tx / 1024 / 1024
		s.NetRxBps = rxBps
		s.NetTxBps = txBps
	}

	if uptime, err := sysUptime(); err == nil {
		s.Uptime = uptime
	}

	s.Connections = countEstablishedConns()

	return s, nil
}

// countEstablishedConns 统计当前 ESTABLISHED 状态的 TCP 连接数（IPv4 + IPv6）。
// 直接解析 /proc/net/tcp{,6}，不依赖 nginx stub_status，适用于任意监听进程。
func countEstablishedConns() int {
	const establishedState = "01" // /proc/net/tcp 状态字段：01 = ESTABLISHED
	total := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // 跳过表头
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			if fields[3] == establishedState {
				total++
			}
		}
		f.Close()
	}
	return total
}

// cpuPercentLocked 必须在 statsMu 持锁时调用。
func cpuPercentLocked() (float64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, fmt.Errorf("unexpected /proc/stat format")
	}

	var vals [7]float64
	for i := 0; i < 7; i++ {
		v, _ := strconv.ParseFloat(fields[i+1], 64)
		vals[i] = v
	}
	idle := vals[3] + vals[4]
	total := 0.0
	for _, v := range vals {
		total += v
	}

	now := cpuSnapshot{total: total, idle: idle, taken: time.Now()}
	var percent float64
	if lastCPU.total > 0 {
		dTotal := now.total - lastCPU.total
		dIdle := now.idle - lastCPU.idle
		if dTotal > 0 {
			percent = (1 - dIdle/dTotal) * 100
		}
	}
	lastCPU = now
	return percent, nil
}

func memStats() (total, used uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var memFree, buffers, cached, sReclaimable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemFree:":
			memFree = v
		case "Buffers:":
			buffers = v
		case "Cached:":
			cached = v
		case "SReclaimable:":
			sReclaimable = v
		}
	}
	available := memFree + buffers + cached + sReclaimable
	if total > available {
		used = total - available
	}
	return total / 1024, used / 1024, nil
}

// netStatsLocked 必须在 statsMu 持锁时调用。
func netStatsLocked(iface string) (rx, tx, rxBps, txBps uint64, err error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, iface+":") {
			continue
		}
		line = strings.TrimPrefix(line, iface+":")
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		rx, _ = strconv.ParseUint(fields[0], 10, 64)
		tx, _ = strconv.ParseUint(fields[8], 10, 64)

		now := netSnapshot{rx: rx, tx: tx, taken: time.Now()}
		if !lastNet.taken.IsZero() {
			dt := now.taken.Sub(lastNet.taken).Seconds()
			if dt > 0 && rx >= lastNet.rx && tx >= lastNet.tx {
				rxBps = uint64(float64(rx-lastNet.rx) / dt)
				txBps = uint64(float64(tx-lastNet.tx) / dt)
			}
		}
		lastNet = now
		return rx, tx, rxBps, txBps, nil
	}
	return 0, 0, 0, 0, fmt.Errorf("interface %s not found", iface)
}

func sysUptime() (string, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty /proc/uptime")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", err
	}
	d := time.Duration(secs) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dd %dh %dm", days, hours, mins), nil
}

func detectMainIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "eth0"
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 1 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return "eth0"
}
