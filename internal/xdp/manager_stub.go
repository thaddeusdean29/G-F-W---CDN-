//go:build !linux

package xdp

import (
	"fmt"
	"net"
	"time"

	"cdn/internal/geo"
)

// Manager stub implementation for non-Linux platforms
type Manager struct{}

// XDPConfig stub。字段与 JSON 标签必须与 linux 版一致：面板在 Windows 上开发/测试时
// 读写的 xdp 配置文件与线上是同一格式。
type XDPConfig struct {
	SYNLimit          uint32 `json:"syn_limit"`
	PPSLimit          uint32 `json:"pps_limit"`
	UDPLimit          uint32 `json:"udp_limit"`
	ConnLimit         uint32 `json:"conn_limit"`
	Enabled           uint32 `json:"enabled"`
	ICMPLimit         uint32 `json:"icmp_limit"`
	UDPDNSLimit       uint32 `json:"udp_dns_limit"`
	TCPRstLimit       uint32 `json:"tcp_rst_limit"`
	FragmentDrop      uint32 `json:"fragment_drop"`
	InvalidFlagsDrop  uint32 `json:"invalid_flags_drop"`
	AckLimit          uint32 `json:"ack_limit"`
	FinLimit          uint32 `json:"fin_limit"`
	PortGuard         uint32 `json:"port_guard"`
	BogonDrop         uint32 `json:"bogon_drop"`
	PshAckGuard       uint32 `json:"psh_ack_guard"`
	CPUSYNLimit       uint32 `json:"cpu_syn_limit"`
	OrphanTCPDrop     uint32 `json:"orphan_tcp_drop"`
	ServiceOrphanDrop uint32 `json:"service_orphan_drop"`
}

// Stats stub
type Stats struct {
	Passed       uint64
	Blocked      uint64
	BlockedSyn   uint64
	BlockedPps   uint64
	BlockedConn  uint64
	BlockedUdp   uint64
	BlockedMatch uint64
}

// NewManager returns a stub manager on non-Linux platforms
func NewManager(iface, objPath string) *Manager {
	return &Manager{}
}

// Load does nothing on non-Linux platforms
func (m *Manager) Load() error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// Close does nothing on non-Linux platforms
func (m *Manager) Close() {}

// Mode returns "" on non-Linux platforms (never attached)
func (m *Manager) Mode() string { return "" }

// Iface returns "" on non-Linux platforms
func (m *Manager) Iface() string { return "" }

// DefaultObjPath returns empty path on non-Linux platforms
func DefaultObjPath() string {
	return ""
}

// Loaded always returns false on non-Linux platforms
func (m *Manager) Loaded() bool {
	return false
}

// ConfigError always returns "" on non-Linux platforms（没有 XDP，也就没有写失败的配置）
func (m *Manager) ConfigError() string {
	return ""
}

// rxQueues returns 0 on non-Linux platforms（没有 /sys）
func rxQueues(string) int {
	return 0
}

// BlockIP does nothing on non-Linux platforms
func (m *Manager) BlockIP(ip net.IP) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// UnblockIP does nothing on non-Linux platforms
func (m *Manager) UnblockIP(ip net.IP) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// GetStats returns empty stats on non-Linux platforms
func (m *Manager) GetStats() (*Stats, error) {
	return &Stats{}, nil
}

// SetSYNLimit does nothing on non-Linux platforms
func (m *Manager) SetSYNLimit(limit uint32) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// SetPPSLimit does nothing on non-Linux platforms
func (m *Manager) SetPPSLimit(limit uint32) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// SetConnLimit does nothing on non-Linux platforms
func (m *Manager) SetConnLimit(limit uint32) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// SetUDPLimit does nothing on non-Linux platforms
func (m *Manager) SetUDPLimit(limit uint32) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// AutoBlocker stub for non-Linux platforms
type AutoBlocker struct{}

// AutoBlockerConfig stub
type AutoBlockerConfig struct {
	Interval  interface{}
	Duration  interface{}
	SYNLimit  uint64
	PPSLimit  uint64
	ConnLimit uint64
	UDPLimit  uint64
	AckLimit  uint64
	StatePath string
	// 与 linux 版保持同名同类型：cmd/cdnedge 在 Windows 上也要能编译通过，
	// 否则「本地 go build 通过、交叉编译才发现字段名写错」这类问题会拖到部署前。
	BanLadder     []time.Duration
	OffenderTTL   time.Duration
	RSTLimit      uint64
	FINLimit      uint64
	ICMPLimit     uint64
	DNSLimit      uint64
	BroadcastHook func(ip string, duration time.Duration)
}

// IsBlocked always returns false on non-Linux platforms
func (ab *AutoBlocker) IsBlocked(ip string) bool { return false }

// SetExternalBanCheck does nothing on non-Linux platforms
func (ab *AutoBlocker) SetExternalBanCheck(fn func(ip string) bool) {}

// NewAutoBlocker returns stub blocker
func NewAutoBlocker(mgr *Manager, cfg AutoBlockerConfig) *AutoBlocker {
	return &AutoBlocker{}
}

// Start does nothing on non-Linux platforms
func (ab *AutoBlocker) Start() {}

// Stop does nothing on non-Linux platforms
func (ab *AutoBlocker) Stop() {}

// GetBlockedIPs returns empty list on non-Linux platforms
func (ab *AutoBlocker) GetBlockedIPs() []interface{} {
	return nil
}

// Forget does nothing on non-Linux platforms
func (ab *AutoBlocker) Forget(ip string) {}

// SetBanConfig does nothing on non-Linux platforms
func (ab *AutoBlocker) SetBanConfig(ladder []time.Duration, ttl time.Duration) {}

// BanConfig returns the built-in defaults on non-Linux platforms.
// 返回默认值而不是空值：面板在 Windows 上开发时能看到真实的阶梯形状，
// 而不是一个空列表让人以为「阶梯没配」。
func (ab *AutoBlocker) BanConfig() ([]time.Duration, time.Duration) {
	return DefaultBanLadder, DefaultOffenderTTL
}

// BlockedIP stub
type BlockedIP struct {
	IP            string
	RemainingTime interface{}
}

// ExtendedStats stub for non-Linux platforms
type ExtendedStats struct {
	Passed           uint64
	DroppedBlocklist uint64
	DroppedSynFlood  uint64
	DroppedPPS       uint64
	DroppedConnLimit uint64
	DroppedUDPFlood  uint64
}

// GetExtendedStats returns empty stats on non-Linux platforms
func (m *Manager) GetExtendedStats() (*ExtendedStats, error) {
	return &ExtendedStats{}, nil
}

// ListBlocked returns empty list on non-Linux platforms
func (m *Manager) ListBlocked() ([]net.IP, error) {
	return nil, nil
}

// AddToWhitelist does nothing on non-Linux platforms
func (m *Manager) AddToWhitelist(ip net.IP) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// RemoveFromWhitelist does nothing on non-Linux platforms
func (m *Manager) RemoveFromWhitelist(ip net.IP) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// ListWhitelisted returns empty list on non-Linux platforms
func (m *Manager) ListWhitelisted() ([]net.IP, error) {
	return nil, nil
}

// SetConfig does nothing on non-Linux platforms
func (m *Manager) SetConfig(cfg XDPConfig) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// GetConfig returns empty config on non-Linux platforms
func (m *Manager) GetConfig() (*XDPConfig, error) {
	return &XDPConfig{}, nil
}

// InitDefaults does nothing on non-Linux platforms
func (m *Manager) InitDefaults(extraPorts ...uint16) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// DefaultServicePorts mirrors the Linux implementation so callers compile everywhere.
// There is no /proc on non-Linux platforms, so no LISTEN-port discovery here.
func DefaultServicePorts(extra ...uint16) []uint16 {
	return append([]uint16{80, 443, 22}, extra...)
}

// SetServicePorts does nothing on non-Linux platforms
func (m *Manager) SetServicePorts(ports []uint16) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// ListServicePorts returns empty list on non-Linux platforms
func (m *Manager) ListServicePorts() ([]uint16, error) {
	return nil, nil
}

// ApplyGeo does nothing on non-Linux platforms.
// 返回错误而不是 nil：面板在 Windows 上跑时，区域规则的四层下发必须如实显示"没装上"，
// 而不是"下发成功"——后者会让管理员以为网卡上正在丢包。
func (m *Manager) ApplyGeo(in geo.L4Install) error {
	return fmt.Errorf("XDP is only supported on Linux")
}

// GeoState reports "never armed" on non-Linux platforms（Loaded() 恒为 false，读数照这个形状给）
func (m *Manager) GeoState() geo.L4State {
	return geo.L4State{
		NotInstall: true,
		Error:      "XDP 没加载：四层不会丢任何包",
	}
}
