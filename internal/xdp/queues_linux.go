//go:build linux

package xdp

import (
	"os"
	"path/filepath"
)

// rxQueues 返回网卡的收包队列数（/sys/class/net/<iface>/queues/rx-*）。
//
// 这个数决定 cpu_syn_limit 怎么分：队列多于核时多个队列共用一个 per-CPU 计数器，
// 队列少于核时用不到的核不会计数。读不到（虚拟网卡不导 queues、目录不存在）返回 0，
// 调用方按 1 个 CPU 处理，等于把全部预算压在一个计数器上——宁可放行量偏小，
// 不要因为猜不到队列数就把额度放大若干倍。
func rxQueues(iface string) int {
	if iface == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", iface, "queues"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if len(name) > 3 && name[:3] == "rx-" {
			n++
		}
	}
	return n
}
