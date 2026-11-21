//go:build !linux

package xdp

import "time"

// SetBroadcastHook 在非 Linux 平台上是空操作。
func (a *AutoBlocker) SetBroadcastHook(hook func(ip string, duration time.Duration)) {
	// no-op on non-Linux platforms
}
