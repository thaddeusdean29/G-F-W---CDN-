package xdp

// Status 是 L4 防护的真实生效状态，随心跳/上报给主控。
//
// 「程序挂在网卡上」不等于「防护在生效」：xdp_config 写失败（.o 与二进制字段对不上、
// value_size 不匹配）时程序照样挂着，但 C 侧读到的一整套阈值都是初始值；面板把
// enabled 关掉也是同样情形。以前主控只看 attached，这类节点在面板上显示
// 「已加载 · 原生」，实际 L4 完全裸奔——这是最坏的一种假象，它会让运维以为洪水已经被挡在
// 内核外面，从而不去看 Tengine 的 CPU。
type Status struct {
	// Attached：XDP 程序已加载并挂到网卡（native 或 generic）。
	Attached bool `json:"attached"`
	// Enabled：内核 xdp_config 里 enabled 标志位的实际值，不是面板上想设的值。
	Enabled bool `json:"enabled"`
	// Armed：真正在生效。判据见 xdpArmed。
	Armed bool `json:"armed"`
	// Mode：native / generic，未挂载为空。
	Mode string `json:"mode,omitempty"`
	// Iface：挂载（或将要挂载）的网卡名。
	Iface string `json:"iface,omitempty"`
	// ConfigError：最近一次写 xdp_config 失败的原因；成功时为空。
	// 不报错的 armed 才有意义：面板要能照着这句话去修，而不是只看到「未生效」。
	ConfigError string `json:"config_error,omitempty"`
	// CPUSYNLimit：内核里的每 CPU 新连接总量上限（0 = 不限）。
	CPUSYNLimit uint32 `json:"cpu_syn_limit,omitempty"`
	// RXQueues：该网卡的收包队列数，用于把 CPUSYNLimit 还原成全局放行量。
	RXQueues int `json:"rx_queues,omitempty"`
}

// Status 汇总 L4 防护状态。非 Linux 平台上 Loaded() 恒为 false，因此各字段自然退化。
func (m *Manager) Status() Status {
	st := Status{
		Attached:    m.Loaded(),
		Mode:        m.Mode(),
		Iface:       m.Iface(),
		ConfigError: m.ConfigError(),
	}
	if st.Attached {
		// 读 map 里的真实值而不是内存里的副本：面板改过参数、存档恢复过、InitDefaults
		// 跑过，走的都是写 map 这条路，只有 map 才是 XDP 实际执行的那一套。
		if cfg, err := m.GetConfig(); err == nil {
			st.Enabled = cfg.Enabled != 0
			st.CPUSYNLimit = cfg.CPUSYNLimit
		}
		st.RXQueues = rxQueues(st.Iface)
	}
	st.Armed = xdpArmed(st.Attached, st.Enabled, st.ConfigError)
	return st
}

// xdpArmed 是「L4 防护确实在拦包」的判据：程序挂着 + 内核 enabled=1 + 最近一次写参数成功。
//
// 三项缺一就是裸奔：没挂载时没有任何包经过 XDP；enabled=0 时程序在但直接放行；
// 写参数失败时 C 侧用的是上一次（或全零）的配置，面板显示的阈值与实际执行的不一致。
func xdpArmed(attached, enabled bool, configError string) bool {
	return attached && enabled && configError == ""
}
