package apiv2

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Cluster 是 clusters 表一行的 Go 映射，字段名与列名对应，不做 API 层的 role/failover 包装
// （那层映射在 clusters.go 里做，保持这个结构体和 SQL 之间的对应关系简单直观）。
type Cluster struct {
	ID                string
	TenantID          string
	Name              string
	Description       string
	IsPrimary         bool
	IsBackup          bool
	IsAutoFailover    bool
	FailoverThreshold int
	FailoverTargetID  sql.NullString
	DefenseCNAME      string
	Status            string
	OnlineNodes       int
	TotalNodes        int
	LastCheckTime     sql.NullTime
	Version           int
	CreatedAt         time.Time
	// 带宽防护：BWLimitMbps 是单个节点的带宽上限（0 = 关闭），max(入,出) 达到上限 BWDangerPercent%
	// 的节点计为不可用；集群可用率低于 FailoverThreshold 连续 3 次自动切高防 CNAME（cluster_monitor.go）。
	BWLimitMbps     int
	BWDangerPercent int
	// AutoFailoverActive 表示当前的故障转移是监控协程自动触发的；只有这种才会自动切回，
	// 用户手动触发的保持到用户手动取消。
	AutoFailoverActive bool
}

type ClusterRepo struct {
	db *sql.DB
}

func NewClusterRepo(db *sql.DB) *ClusterRepo {
	return &ClusterRepo{db: db}
}

var clusterIndexCodes = map[string]string{
	"clusters_name_uq": "conflict",
}

const clusterColumns = `id, tenant_id, name, description, is_primary, is_backup, is_auto_failover,
	failover_threshold, failover_target_id, defense_cname, status, online_nodes, total_nodes,
	last_check_time, version, created_at, bw_limit_mbps, bw_danger_percent, auto_failover_active`

func scanCluster(row *sql.Row) (*Cluster, error) {
	var c Cluster
	err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Description, &c.IsPrimary, &c.IsBackup, &c.IsAutoFailover,
		&c.FailoverThreshold, &c.FailoverTargetID, &c.DefenseCNAME, &c.Status, &c.OnlineNodes, &c.TotalNodes,
		&c.LastCheckTime, &c.Version, &c.CreatedAt, &c.BWLimitMbps, &c.BWDangerPercent, &c.AutoFailoverActive)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Create 插入一个新集群。ID/CreatedAt/Version 由数据库默认值生成，调用方传入的同名字段会被忽略；
// 插入后立即用生成的 ID 回查一次，把这些默认值带回给调用方。
//
// 配额检查（checkPlanQuota）和 INSERT 必须在同一个事务里，理由见 nodes_repo.go Create 的注释
// 和 quota.go。
func (r *ClusterRepo) Create(ctx context.Context, c *Cluster) (*Cluster, error) {
	id := uuid.New().String()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := checkPlanQuota(ctx, tx, c.TenantID, "clusters"); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO clusters (id, tenant_id, name, description, is_primary, is_backup, is_auto_failover,
			failover_threshold, failover_target_id, defense_cname, bw_limit_mbps, bw_danger_percent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, c.TenantID, c.Name, c.Description, c.IsPrimary, c.IsBackup, c.IsAutoFailover,
		c.FailoverThreshold, c.FailoverTargetID, c.DefenseCNAME, c.BWLimitMbps, c.BWDangerPercent); err != nil {
		if ae := ClassifyMySQLError(err, clusterIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.Get(ctx, c.TenantID, id)
}

// Get 按租户查询单个集群；不存在或不属于该租户统一返回 sql.ErrNoRows，调用方（handler 层）
// 据此映射成 404 not_found，不区分"不存在"和"属于别的租户"。
func (r *ClusterRepo) Get(ctx context.Context, tenantID, id string) (*Cluster, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+clusterColumns+` FROM clusters WHERE tenant_id = ? AND id = ?`, tenantID, id)
	return scanCluster(row)
}

// List 返回该租户的集群分页列表和总数。orderBy 是已经过白名单校验的 SQL 片段
// （见 resource.go 的 parseSort），调用方负责保证它不是用户输入直接拼接的结果。
func (r *ClusterRepo) List(ctx context.Context, tenantID, orderBy string, page, pageSize int) ([]*Cluster, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clusters WHERE tenant_id = ?`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+clusterColumns+` FROM clusters WHERE tenant_id = ? ORDER BY `+orderBy+` LIMIT ? OFFSET ?`,
		tenantID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Cluster
	for rows.Next() {
		var c Cluster
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Description, &c.IsPrimary, &c.IsBackup, &c.IsAutoFailover,
			&c.FailoverThreshold, &c.FailoverTargetID, &c.DefenseCNAME, &c.Status, &c.OnlineNodes, &c.TotalNodes,
			&c.LastCheckTime, &c.Version, &c.CreatedAt, &c.BWLimitMbps, &c.BWDangerPercent, &c.AutoFailoverActive); err != nil {
			return nil, 0, err
		}
		out = append(out, &c)
	}
	return out, total, rows.Err()
}

// ErrVersionConflict 表示 If-Match 携带的 version 与当前值不一致。
var ErrVersionConflict = errors.New("apiv2: version conflict")

// Update 用乐观锁更新可写字段。expectedVersion<=0 表示调用方未提供 If-Match，不做版本校验。
//
// 故意不接受 status/online_nodes/total_nodes/last_check_time：这几个是健康检查协程独占写入的
// 遥测字段，PATCH 请求体里不会出现它们（handler 层的只读字段名单已经拦掉），这里的 SQL 也不接受
// 调用方覆盖，双重保险——参考 v1 internal/config/cluster.go 的 Update 教训：一旦允许整体覆盖，
// 遥测字段会被请求里的旧值/零值打回去。
func (r *ClusterRepo) Update(ctx context.Context, tenantID, id string, expectedVersion int, c *Cluster) (*Cluster, error) {
	var (
		res sql.Result
		err error
	)
	if expectedVersion > 0 {
		res, err = r.db.ExecContext(ctx, `
			UPDATE clusters SET description = ?, is_primary = ?, is_backup = ?, is_auto_failover = ?,
				failover_threshold = ?, failover_target_id = ?, defense_cname = ?, bw_limit_mbps = ?, bw_danger_percent = ?,
				version = version + 1
			WHERE tenant_id = ? AND id = ? AND version = ?`,
			c.Description, c.IsPrimary, c.IsBackup, c.IsAutoFailover, c.FailoverThreshold, c.FailoverTargetID, c.DefenseCNAME,
			c.BWLimitMbps, c.BWDangerPercent, tenantID, id, expectedVersion)
	} else {
		res, err = r.db.ExecContext(ctx, `
			UPDATE clusters SET description = ?, is_primary = ?, is_backup = ?, is_auto_failover = ?,
				failover_threshold = ?, failover_target_id = ?, defense_cname = ?, bw_limit_mbps = ?, bw_danger_percent = ?,
				version = version + 1
			WHERE tenant_id = ? AND id = ?`,
			c.Description, c.IsPrimary, c.IsBackup, c.IsAutoFailover, c.FailoverThreshold, c.FailoverTargetID, c.DefenseCNAME,
			c.BWLimitMbps, c.BWDangerPercent, tenantID, id)
	}
	if err != nil {
		if ae := ClassifyMySQLError(err, clusterIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		// 区分 404（不存在/不属于该租户）和 409（存在但 version 不匹配）。
		if _, err := r.Get(ctx, tenantID, id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			return nil, err
		}
		return nil, ErrVersionConflict
	}
	return r.Get(ctx, tenantID, id)
}

// Delete 删除集群。集群下仍有节点或域名时，外键 RESTRICT 会让这条语句失败（1451），
// 调用方（handler）在此之前应先查引用计数以便在 409 响应里带上 details.{nodes,domains}。
func (r *ClusterRepo) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM clusters WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		if ae := ClassifyMySQLError(err, nil); ae != nil {
			return ae
		}
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateFailoverState 写入 status/failover_target_id/auto_failover_active，供 failover trigger/cancel
// 与 cluster_monitor.go 的自动切换在完成域名批量切换后落库集群当前的故障转移状态。不做乐观锁校验，
// 理由与 Update() 故意排除 status 等遥测字段相同——这里同样是系统流程独占写入，不经过用户 PATCH 路径。
// failover_target_id 是用户配置的切换目标，调用方应原样传回 c.FailoverTargetID，不要借这里清空它。
func (r *ClusterRepo) UpdateFailoverState(ctx context.Context, tenantID, id, status string, failoverTargetID sql.NullString, auto bool) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE clusters SET status = ?, failover_target_id = ?, auto_failover_active = ? WHERE tenant_id = ? AND id = ?`,
		status, failoverTargetID, auto, tenantID, id)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListMonitored 跨租户列出需要监控协程检查的集群：开了在线率自动故障转移、设置了带宽上限，
// 或者正处于自动触发的故障转移中（需要判断能否自动切回）。只供 cluster_monitor.go 使用，
// 结果里的每个集群都带着自己的 TenantID，后续读节点/域名/CF 凭证都按它隔离。
func (r *ClusterRepo) ListMonitored(ctx context.Context) ([]*Cluster, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+clusterColumns+` FROM clusters
		WHERE is_auto_failover = TRUE OR bw_limit_mbps > 0 OR auto_failover_active = TRUE
			OR EXISTS (SELECT 1 FROM nodes WHERE nodes.tenant_id = clusters.tenant_id
				AND nodes.cluster_id = clusters.id AND nodes.dns_paused_at IS NOT NULL)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cluster
	for rows.Next() {
		var c Cluster
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Description, &c.IsPrimary, &c.IsBackup, &c.IsAutoFailover,
			&c.FailoverThreshold, &c.FailoverTargetID, &c.DefenseCNAME, &c.Status, &c.OnlineNodes, &c.TotalNodes,
			&c.LastCheckTime, &c.Version, &c.CreatedAt, &c.BWLimitMbps, &c.BWDangerPercent, &c.AutoFailoverActive); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// CountReferences 返回该集群下的节点数与域名数，用于删除前的 409 in_use 响应体
// 或直接依赖 Delete 触发的外键错误——这里显式查询是为了能在错误信息里带上具体数字。
func (r *ClusterRepo) CountReferences(ctx context.Context, tenantID, id string) (nodes, domains int, err error) {
	if err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE tenant_id = ? AND cluster_id = ?`, tenantID, id).Scan(&nodes); err != nil {
		return 0, 0, err
	}
	if err = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE tenant_id = ? AND cluster_id = ?`, tenantID, id).Scan(&domains); err != nil {
		return 0, 0, err
	}
	return nodes, domains, nil
}

// nodeCount 是某个集群当前的节点总数与在线数（按心跳现算）。
type nodeCount struct{ Total, Online int }

// NodeCounts 按集群汇总该租户的节点总数和在线数。clusters.online_nodes/total_nodes 两列没有协程
// 维护，直接读会恒为 0/0，所以列表和详情都用这里现算的值覆盖。
func (r *ClusterRepo) NodeCounts(ctx context.Context, tenantID string) (map[string]nodeCount, error) {
	cutoff := time.Now().UTC().Add(-nodeOnlineThreshold)
	rows, err := r.db.QueryContext(ctx, `
		SELECT cluster_id, COUNT(*), COALESCE(SUM(enabled AND last_heartbeat_at > ?), 0)
		FROM nodes WHERE tenant_id = ? AND cluster_id IS NOT NULL GROUP BY cluster_id`, cutoff, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]nodeCount{}
	for rows.Next() {
		var id string
		var nc nodeCount
		if err := rows.Scan(&id, &nc.Total, &nc.Online); err != nil {
			return nil, err
		}
		out[id] = nc
	}
	return out, rows.Err()
}

// applyNodeCount 把现算的节点数写进 c，并据此推出健康状态。故障转移中/已完成的状态由
// failover 流程独占，不覆盖。
func applyNodeCount(c *Cluster, nc nodeCount) {
	c.OnlineNodes, c.TotalNodes = nc.Online, nc.Total
	switch c.Status {
	case "failover_in_progress", "failover_complete":
		return
	}
	switch {
	case nc.Total == 0 || nc.Online == nc.Total:
		c.Status = "active"
	case nc.Online == 0:
		c.Status = "failed"
	default:
		c.Status = "degraded"
	}
}
