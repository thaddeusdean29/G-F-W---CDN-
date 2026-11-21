package edgeapi

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"cdn/internal/waf"
	"cdn/internal/xdp"
)

// SetConfigStatePaths 设置 CC / XDP 阈值存档路径，并立即从 CC 存档恢复配置。
// 在启动 HTTP 服务前调用：先恢复再对外服务，第一批请求就按面板配置的阈值判定。
// XDP 的恢复要等 XDP 加载并 InitDefaults 之后，由调用方另行调用 RestoreXDPConfig。
func (h *Handler) SetConfigStatePaths(ccPath, xdpPath string) {
	h.ccStatePath = ccPath
	h.xdpStatePath = xdpPath
	h.restoreCCConfig()
}

func (h *Handler) restoreCCConfig() {
	if h.ccStatePath == "" || h.ccDefense == nil {
		return
	}
	data, err := os.ReadFile(h.ccStatePath)
	if os.IsNotExist(err) {
		return // 从没下发过，用内置默认值
	}
	if err != nil {
		log.Printf("CC config restore: read %s: %v", h.ccStatePath, err)
		return
	}
	var cfg waf.CCConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("CC config restore: parse %s: %v (keeping defaults)", h.ccStatePath, err)
		return
	}
	// 与 updateCCConfig 同样的校验：坏存档不能把 CC 退化成全放或全封。
	if cfg.RequestsPerSecond <= 0 || cfg.RequestsPerMinute <= 0 || cfg.BlockDuration <= 0 {
		log.Printf("CC config restore: %s has non-positive thresholds, keeping defaults", h.ccStatePath)
		return
	}
	h.ccDefense.UpdateConfig(cfg)
	log.Printf("CC defense config restored from %s: enabled=%v, rps=%d, rpm=%d, burst=%d, block=%s",
		h.ccStatePath, cfg.Enabled, cfg.RequestsPerSecond, cfg.RequestsPerMinute, cfg.BurstSize, cfg.BlockDuration)
}

// RestoreXDPConfig 用存档覆盖 InitDefaults 写入的默认阈值。XDP 未加载或没有存档时什么都不做。
// 存档应用失败（例如 port_guard 开着但本次启动服务端口白名单没装上）时保留默认值，
// 不会留下半套配置 —— SetConfig 是整条 map 值一次写入。
func (h *Handler) RestoreXDPConfig() {
	if h.xdpStatePath == "" || h.xdpMgr == nil || !h.xdpMgr.Loaded() {
		return
	}
	data, err := os.ReadFile(h.xdpStatePath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("XDP config restore: read %s: %v", h.xdpStatePath, err)
		return
	}
	var cfg xdp.XDPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("XDP config restore: parse %s: %v (keeping defaults)", h.xdpStatePath, err)
		return
	}
	if err := h.xdpMgr.SetConfig(cfg); err != nil {
		log.Printf("XDP config restore: apply failed: %v (keeping defaults)", err)
		return
	}
	log.Printf("XDP config restored from %s", h.xdpStatePath)
}

func (h *Handler) saveCCState(cfg waf.CCConfig) error {
	return writeStateAtomic(h.ccStatePath, cfg)
}

func (h *Handler) saveXDPState(cfg xdp.XDPConfig) error {
	return writeStateAtomic(h.xdpStatePath, cfg)
}

// writeStateAtomic .tmp + rename 原子写入；path 为空时不落盘。
func writeStateAtomic(path string, v any) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
