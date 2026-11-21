package xdp

// 跨平台共用的默认阈值。放在无构建标签的文件里，让 cmd/cdnedge 之类的调用方
// 在 Windows/Mac 上编译时也能引用（非 Linux 时 Manager 只是 stub，但常量仍应可见）。
const (
	DefaultSYNLimit = 100 // 单 IP 100 SYN/s（正常浏览器建连约 20-40 SYN/s，留 2-3 倍余量）
	// DefaultPPSLimit 为 per-IP 总包速率。TCP 只统计发往服务端口的包（含数据包和 ACK），
	// 所以它必须高于 DefaultAckLimit：满速下载的用户光 ACK 就有 3000-4000/s，上传时
	// 数据包约 700 pps/MB/s。以前是 2000 —— 那时 C 里根本没读这个字段，一旦真正生效，
	// 2000 会把任何下载速度超过 ~5MB/s 的用户掐断。20000 只拦真正的单源洪水。
	DefaultPPSLimit  = 20000
	DefaultUDPLimit  = 0  // 0 = disabled（UDP 全站禁；开启也能兜底）
	// DefaultConnLimit 不是真正的半开连接数：每个 SYN +1、每 60 秒减半，握手完成不减。
	// 以稳定速率 r（个/分钟）建连时，计数在减半前收敛到 ≈ 2r，所以**持续超过每分钟
	// limit/2 个新连接**才开始丢 SYN。
	//
	// 以前是 30（每分钟 15 个就撞线）：一个 CGNAT / 公司 / 校园网出口后面几十个真人、或者
	// 一次 CC 压测，都会在 L4 直接被 conn_flood 封掉，L7 的 CC 人机验证根本没机会出场 ——
	// 那是误伤，不是防护。真人走 HTTP/2 每人每分钟约 10~30 个新连接，一个几百人的 NAT
	// 出口就是每分钟几千个。单 IP 的高频建连本来就归 L7 CC 管（它能区分真人和脚本），
	// 秒级 SYN 洪水归 DefaultSYNLimit，这里只兜「长时间持续中速建连」的连接耗尽型洪水。
	//
	// 3000 ≈ 单 IP 持续每分钟 1500 个（约 25/s）新连接才开始丢；AutoBlocker 封禁阈值取它的
	// 2 倍（见 cmd/cdnedge），约持续 50/s 才封。注意超限后被丢的 SYN 重传也计数，
	// 一旦撞线整个出口的新连接都会被丢到速率回落为止，所以宁可偏高。
	DefaultConnLimit = 3000
	// DefaultTCPRstLimit 为 per-IP RST 速率上限（只统计发往服务端口的 RST）。ptcp 这类
	// "分片脉冲 SYN+RST" 攻击正是靠大量 RST 打满连接表/耗 CPU。正常客户端极少发 RST
	// （只在异常断开时），100/s 对真人是天文数字，对攻击是有效闸门。
	DefaultTCPRstLimit = 100
	// DefaultFinLimit 为 per-IP FIN 速率上限（只统计发往服务端口的 FIN）。
	// 真人每条连接结束时一个 FIN，与 SYN 同量级，取同样的 100/s。
	DefaultFinLimit = 100
	// DefaultAckLimit 为 per-IP 纯 ACK 上限。CDN 的主业务是传输文件：用户以 10MB/s 下载时，
	// 按每两个 MSS 回一个 ACK 估算，正常 ACK 速率约 3000-4000/s。
	// 设置为 8000 可以给满速下载用户留足余量（2 倍安全边际），同时仍能拦截真正的 ACK 洪水攻击。
	// 低于 5000 的阈值可能误伤正常下载，表现为下载卡死/504 超时。
	DefaultAckLimit = 8000 // ACK 洪水阈值（正常下载约 3000-4000 ACK/s，8000 留足余量）
	// DefaultICMPLimit 挡 ping flood，不影响正常 ping 诊断。ICMP 差错报文（PMTUD 用的
	// "需要分片"/"包过大" 等）在 C 里按 10 倍放宽。
	DefaultICMPLimit = 20

	// DefaultSynTotalBudget 是每个节点每秒放行的「新连接 SYN」总量上限（所有 CPU 合计），
	// 落到 cpu_syn_limit 上。它专挡「每包换一个伪造源」的 SYN 洪水：这种流量每个源只来
	// 一两个包，per-IP 阈值永远碰不到，速率表反而被它挤满，唯一有效的闸门是总量。
	//
	// 20000 不是拍的，是内核连接表反推出来的（改任何一个数都要重新走一遍这笔账）：
	//   洪水被放行 r 个/秒，其中没完成握手的每个 SYN 在 conntrack 里占一个条目、活
	//   syn_sent 超时那么久（安装脚本下调到 30 秒，发行版默认 120 秒会让占用翻 4 倍），
	//   所以半开条目 ≈ r × 30。nf_conntrack_max = 1048576 → r 的上限约 3.5 万/秒。
	//   取 20000 留掉一半余量给真人的 established 条目。conntrack 一旦写满，内核对
	//   **所有**新连接直接 DROP，真人也进不来，比洪水本身更致命。
	// 20000/秒比一台 4~8 核 VPS 的真实新建连接峰值高一个量级（并发上限本来由
	// Tengine worker_connections 4096 × worker 数决定），又比最小的 SYN 洪水（几十万 pps）
	// 低一个量级，所以正常节点撞不到它、攻击一定撞得到。
	// 大节点要放行更多：面板上调 cpu_syn_limit，同时按上面的式子同步抬 nf_conntrack_max。
	DefaultSynTotalBudget = 20000
)

// CPUSYNLimitFor 把节点的总新连接预算换算成 cpu_syn_limit（单个 CPU 每秒放行的 SYN 数）。
//
// C 侧的计数器是 PERCPU_ARRAY：每个 CPU 一份，全局单计数器在千万级 pps 下自己就是瓶颈。
// 真正会执行 XDP 的 CPU 数 = min(网卡收包队列数, 逻辑核数)——队列多于核时多个队列共用一个
// 计数器，核多于队列时多出来的核根本收不到包。按这个数来分，全局放行量才等于预算，
// 而不是预算的整数倍（按核数分会把额度放大到 budget/r × r，队列少时形同关闭）。
//
// rxQueues 读不到（0/负数）时按 1 个 CPU 算：宁可放行量等于预算，不要放大。
func CPUSYNLimitFor(rxQueues, cpus int) uint32 {
	d := rxQueues
	if d < 1 {
		d = 1
	}
	if cpus > 0 && d > cpus {
		d = cpus
	}
	return uint32((DefaultSynTotalBudget + d - 1) / d)
}
