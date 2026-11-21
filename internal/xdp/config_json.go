package xdp

import "encoding/json"

// UnmarshalJSON 让 JSON 里**缺失**的 orphan_tcp_drop / service_orphan_drop 按默认开启处理。
//
// 这两个字段是后加的：主控存档 /etc/cdnpanel/xdp_config.json、边缘存档
// /var/lib/cdnedge/xdp_config.json、旧版面板下发的配置里都没有它。按 Go 的零值解码
// 会把它读成 0，升级后的节点一恢复存档就把新防护悄悄关掉。
// 显式写了 0 的仍然是 0（用户确实关掉了），只有「没这个键」才取默认值。
func (c *XDPConfig) UnmarshalJSON(b []byte) error {
	type plain XDPConfig
	p := plain{OrphanTCPDrop: 1, ServiceOrphanDrop: 1}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*c = XDPConfig(p)
	return nil
}
