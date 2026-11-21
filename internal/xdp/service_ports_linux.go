//go:build linux

package xdp

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// listenStateHex 是 /proc/net/tcp 里 TCP_LISTEN 的状态码（十六进制第 4 列）。
const listenStateHex = "0A"

// listeningTCPPorts 枚举本机所有处于 LISTEN 状态的 TCP 端口。
//
// 为什么用它而不是让用户手填端口：port_guard 的本意是丢掉"本机根本没人监听"的端口
// 上的包（扫描、无状态洪水、反射包落点）。凡是有进程在听的端口都是这台机器真实提供的
// 服务，放行它们才是正确语义。更要紧的是安全兜底——SSH 常被改到非标端口，靠硬编码 22
// 会把管理员锁在门外（XDP 在驱动层丢包，iptables 都救不回来，只能走 VPS 控制台 VNC）。
//
// 读取失败时返回 nil，调用方会退回到 80/443/22 的静态兜底列表。
func listeningTCPPorts() []uint16 {
	seen := make(map[uint16]bool)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		for _, p := range parseProcNetTCP(path) {
			seen[p] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ports := make([]uint16, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	return ports
}

func parseProcNetTCP(path string) []uint16 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ports []uint16
	sc := bufio.NewScanner(f)
	sc.Scan() // 跳过表头
	for sc.Scan() {
		// 列布局：sl local_address rem_address st ...
		// local_address 形如 "0100007F:1F90"（十六进制 IP:PORT）。
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || !strings.EqualFold(fields[3], listenStateHex) {
			continue
		}
		colon := strings.LastIndex(fields[1], ":")
		if colon < 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[1][colon+1:], 16, 32)
		if err != nil || n == 0 || n > 65535 {
			continue
		}
		ports = append(ports, uint16(n))
	}
	return ports
}
