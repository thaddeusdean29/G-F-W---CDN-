package apiv2

// 本文件把 docs/API-v2.md §2.2 Cluster 的 API 契约字段（role / failover）
// 与 clusters 表的列（is_primary / is_backup / is_auto_failover / failover_threshold /
// failover_target_id）互相转换。写成不依赖 DB 的纯函数，方便单测覆盖全部枚举组合。

// roleToFlags 把 API 的 role 枚举翻译成两个数据库列。非法枚举值返回 error，
// 调用方应将其映射为 400 validation_failed。
func roleToFlags(role string) (isPrimary, isBackup bool, err error) {
	switch role {
	case "primary":
		return true, false, nil
	case "backup":
		return false, true, nil
	case "normal":
		return false, false, nil
	default:
		return false, false, NewApiError("validation_failed", "role 必须是 primary/backup/normal 之一")
	}
}

// flagsToRole 是 roleToFlags 的反向映射，用于把 DB 行渲染成 API 响应。
// is_primary/is_backup 理论上不会同时为 true（应用层通过 roleToFlags 保证互斥），
// 若数据库里出现了这种脏数据，这里优先按 primary 处理而不是 panic。
func flagsToRole(isPrimary, isBackup bool) string {
	switch {
	case isPrimary:
		return "primary"
	case isBackup:
		return "backup"
	default:
		return "normal"
	}
}

// clusterFailover 是 docs/API-v2.md §2.2 里的 failover 子对象。
type clusterFailover struct {
	Auto            bool    `json:"auto"`
	Threshold       int     `json:"threshold"`
	TargetClusterID *string `json:"target_cluster_id"`
}

// clusterBandwidth 是带宽防护设置：单个节点带宽上限（Mbps，0 = 关闭）与危险值百分比。
// 达到危险值的节点计为不可用，与离线节点一起按集群可用率（failover.threshold）判断是否切换。
type clusterBandwidth struct {
	LimitMbps     int `json:"limit_mbps"`
	DangerPercent int `json:"danger_percent"`
}

const defaultBWDangerPercent = 90

// clusterHealth 是 §2.2 里的只读 health 子对象。bw_* / fail_streak / last_reason 来自
// cluster_monitor.go 最近一次检查（只在内存里，主控重启后要等下一轮检查才有）。
type clusterHealth struct {
	Status       string   `json:"status"`
	OnlineNodes  int      `json:"online_nodes"`
	TotalNodes   int      `json:"total_nodes"`
	CheckedAt    *string  `json:"checked_at"`
	AutoSwitched bool     `json:"auto_switched"`
	BWPeakMbps   *float64 `json:"bw_peak_mbps,omitempty"`
	BWPeakNode   string   `json:"bw_peak_node,omitempty"`
	BWSaturated  int      `json:"bw_saturated_nodes"`
	DNSPaused    int      `json:"dns_paused_nodes"`
	FailStreak   int      `json:"fail_streak"`
	LastReason   string   `json:"last_reason,omitempty"`
	MonitoredAt  *string  `json:"monitored_at,omitempty"`
}
