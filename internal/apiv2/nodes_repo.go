package apiv2

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Node 是 nodes 表一行的 Go 映射。ClusterID/IP 允许 NULL（未分配集群 / 未填公网 IP），
// 用 sql.NullString 而不是空字符串表达，这样 Update 时能区分"不改"和"清空"。
type Node struct {
	ID              string
	TenantID        string
	ClusterID       sql.NullString
	Name            string
	Address         string
	TokenEnc        []byte // Update 时为 nil 表示不修改 token；Create/List/Get 总是非空
	IP              sql.NullString
	CertFingerprint string
	CFRecordID      string
	Enabled         bool
	LastHeartbeatAt sql.NullTime
	LastStatus      []byte
	Version         int
	AddedAt         time.Time
	// DNSPausedAt 非空表示带宽打满被监控暂时从集群 DNS 摘除（cluster_monitor.go），恢复后自动加回。
	DNSPausedAt sql.NullTime
}

type NodeRepo struct {
	db *sql.DB
}

func NewNodeRepo(db *sql.DB) *NodeRepo {
	return &NodeRepo{db: db}
}

var nodeIndexCodes = map[string]string{
	"nodes_ip_uq": "conflict",
}

const nodeColumns = `id, tenant_id, cluster_id, name, address, token_enc, ip, cert_fingerprint, cf_record_id,
	enabled, last_heartbeat_at, last_status, version, added_at, dns_paused_at`

func scanNode(row *sql.Row) (*Node, error) {
	var n Node
	err := row.Scan(&n.ID, &n.TenantID, &n.ClusterID, &n.Name, &n.Address, &n.TokenEnc, &n.IP, &n.CertFingerprint,
		&n.CFRecordID, &n.Enabled, &n.LastHeartbeatAt, &n.LastStatus, &n.Version, &n.AddedAt, &n.DNSPausedAt)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// Create 插入一个手动添加的节点（已安装好、只是把它接入面板）。ID 由应用层生成——
// UUID 主键一律由应用层生成（MySQL 5.7 不支持 DEFAULT (UUID())）；nodes.id 还要容纳边缘自动注册上报的 ID。
//
// 配额检查（checkPlanQuota）和 INSERT 必须在同一个事务里：先锁租户行、数当前节点数，
// 锁一直持有到 INSERT 完成再 COMMIT，否则两个请求并发进来都会读到"未插入前"的计数，
// 都以为没超限，实际一起插入后就超了（这也是原来触发器方案的语义，见 quota.go 注释）。
func (r *NodeRepo) Create(ctx context.Context, n *Node) (*Node, error) {
	return r.CreateWithID(ctx, uuid.New().String(), n)
}

// CreateWithID 与 Create 相同，只是 ID 由调用方给定：边缘自动注册用边缘上报并落盘的 node_id，
// 这样边缘重启后凭同一个 ID 找回这条记录，而不是每次重启多出一个节点。
func (r *NodeRepo) CreateWithID(ctx context.Context, id string, n *Node) (*Node, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := checkPlanQuota(ctx, tx, n.TenantID, "nodes"); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO nodes (id, tenant_id, cluster_id, name, address, token_enc, ip, cert_fingerprint, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, n.TenantID, n.ClusterID, n.Name, n.Address, n.TokenEnc, n.IP, n.CertFingerprint, n.Enabled); err != nil {
		if ae := ClassifyMySQLError(err, nodeIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.Get(ctx, n.TenantID, id)
}

// ReplaceOpts 控制 CreateReplacingIP 遇到同 IP 旧节点时怎么处理。
type ReplaceOpts struct {
	// AllowCrossTenant：旧节点属于别的租户时也允许顶掉。只有调用方已经证明控制这台机器
	// （SSH 登录成功、或注册请求确实从这个 IP 发出）时才能打开，否则任何人伪造上报 IP 就能抢节点。
	AllowCrossTenant bool
	// KeepName：同租户重装时沿用旧节点名称（边缘自动注册的名称是自动生成的 edge-xxxx，
	// 用户在面板上改过的名字不应因重装丢失）；SSH 部署用用户这次填的名称，不沿用。
	KeepName bool
}

// CreateReplacingIP 用于「重新安装」：机器上的边缘被卸载重装后 node_id 变了（uninstall.sh 会删
// /etc/cdnpanel/edge.node_id）或者重新走了一遍 SSH 部署，IP 却还是同一个。nodes_ip_uq 是全局唯一，
// 直接 INSERT 会 409；这里等价于「先删掉旧节点再装」：同一事务里删旧行、查配额、插新行。
//
// 同租户重装时沿用旧节点的集群（新记录没指定集群时）、启用状态和（可选）名称，重装对域名下发透明。
// 返回被替换掉的旧节点（没有则为 nil），调用方据此丢掉旧节点的 TLS client 缓存并记日志。
func (r *NodeRepo) CreateReplacingIP(ctx context.Context, id string, n *Node, opts ReplaceOpts) (*Node, *Node, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	// 先锁本租户行，再锁旧节点行，与 checkPlanQuota 的加锁顺序一致，避免同租户并发注册互相死锁。
	var tid string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM tenants WHERE id = ? FOR UPDATE`, n.TenantID).Scan(&tid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, NewApiError("tenant_inactive", "租户已停用或到期")
		}
		return nil, nil, err
	}

	var old *Node
	if n.IP.Valid && n.IP.String != "" {
		row := tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE ip = ? FOR UPDATE`, n.IP.String)
		o, err := scanNode(row)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return nil, nil, err
		case o.ID == id:
			// 同一个 ID 已经存在不属于「重装」，交给调用方的更新路径；这里照常插入会触发主键冲突。
		default:
			old = o
		}
	}
	if old != nil {
		if old.TenantID != n.TenantID && !opts.AllowCrossTenant {
			// 旧节点属于别的租户，而调用方没有证明自己控制这台机器。
			return nil, nil, NewApiError("conflict", "该 IP 已被其他租户的节点占用")
		}
		if old.TenantID == n.TenantID {
			if !n.ClusterID.Valid {
				n.ClusterID = old.ClusterID
			}
			n.Enabled = old.Enabled
			if opts.KeepName {
				n.Name = old.Name
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, old.ID); err != nil {
			return nil, nil, err
		}
	}

	// 删掉旧行之后再数配额：同租户重装是一换一，不应因为「旧的还在」被判超限。
	if err := checkPlanQuota(ctx, tx, n.TenantID, "nodes"); err != nil {
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO nodes (id, tenant_id, cluster_id, name, address, token_enc, ip, cert_fingerprint, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, n.TenantID, n.ClusterID, n.Name, n.Address, n.TokenEnc, n.IP, n.CertFingerprint, n.Enabled); err != nil {
		if ae := ClassifyMySQLError(err, nodeIndexCodes); ae != nil {
			return nil, nil, ae
		}
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	created, err := r.Get(ctx, n.TenantID, id)
	return created, old, err
}

// Get 按租户查询单个节点；不存在或不属于该租户统一返回 sql.ErrNoRows。
func (r *NodeRepo) Get(ctx context.Context, tenantID, id string) (*Node, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE tenant_id = ? AND id = ?`, tenantID, id)
	return scanNode(row)
}

// nodeOnlineThreshold 心跳超过这个时长没更新就判定离线。边缘心跳间隔 3 秒
// （cmd/cdnedge/main.go keepHeartbeat），这里留 5 倍余量容忍网络抖动。
const nodeOnlineThreshold = 15 * time.Second

// List 返回该租户的节点分页列表和总数。clusterID 非空时按集群过滤；
// onlineFilter 非 nil 时按最近心跳时间过滤在线/离线。
func (r *NodeRepo) List(ctx context.Context, tenantID, clusterID string, onlineFilter *bool, orderBy string, page, pageSize int) ([]*Node, int, error) {
	where := "tenant_id = ?"
	args := []any{tenantID}
	if clusterID != "" {
		where += " AND cluster_id = ?"
		args = append(args, clusterID)
	}
	if onlineFilter != nil {
		cutoff := time.Now().UTC().Add(-nodeOnlineThreshold)
		if *onlineFilter {
			where += " AND last_heartbeat_at > ?"
		} else {
			where += " AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= ?)"
		}
		args = append(args, cutoff)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE `+where+` ORDER BY `+orderBy+` LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.TenantID, &n.ClusterID, &n.Name, &n.Address, &n.TokenEnc, &n.IP, &n.CertFingerprint,
			&n.CFRecordID, &n.Enabled, &n.LastHeartbeatAt, &n.LastStatus, &n.Version, &n.AddedAt, &n.DNSPausedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, &n)
	}
	return out, total, rows.Err()
}

// Update 用乐观锁更新可写字段。n.TokenEnc == nil 表示本次不修改 token
// （PATCH 请求体里没出现 token 字段）；非 nil 表示替换为新加密值。
// 不接受 last_heartbeat_at/last_status/cf_record_id：这些是边缘心跳和 CF 同步独占写入的字段。
func (r *NodeRepo) Update(ctx context.Context, tenantID, id string, expectedVersion int, n *Node) (*Node, error) {
	cols := []string{"cluster_id = ?", "name = ?", "address = ?", "ip = ?", "cert_fingerprint = ?", "enabled = ?"}
	args := []any{n.ClusterID, n.Name, n.Address, n.IP, n.CertFingerprint, n.Enabled}
	if n.TokenEnc != nil {
		cols = append(cols, "token_enc = ?")
		args = append(args, n.TokenEnc)
	}
	query := `UPDATE nodes SET ` + strings.Join(cols, ", ") + `, version = version + 1 WHERE tenant_id = ? AND id = ?`
	args = append(args, tenantID, id)
	if expectedVersion > 0 {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		if ae := ClassifyMySQLError(err, nodeIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		if _, err := r.Get(ctx, tenantID, id); err != nil {
			return nil, err
		}
		return nil, ErrVersionConflict
	}
	return r.Get(ctx, tenantID, id)
}

// Delete 删除节点。没有其他表以外键引用 nodes，因此不需要像 clusters 那样先查引用计数；
// 通知边缘清空站点配置属于 Stage 3 的异步副作用，这里只管落库。
func (r *NodeRepo) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM nodes WHERE tenant_id = ? AND id = ?`, tenantID, id)
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

// GetByID 不带租户条件按 ID 查节点，只供边缘心跳/注册这类没有会话、靠节点 token 或注册密钥
// 鉴权的内部路径使用；面板接口一律用带 tenantID 的 Get。
func (r *NodeRepo) GetByID(ctx context.Context, id string) (*Node, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id)
	return scanNode(row)
}

// ApplyEdgeReport 用边缘注册上报的内容刷新已有节点：只改边缘自己说了算的地址 / token / 证书指纹 / IP，
// 名称、启用状态以面板为准；集群只在面板上还没分配时才采纳上报值（COALESCE），
// 避免边缘启动参数和面板上的手动调整来回打架（与 v1 internal/api/edge_register.go 语义一致）。
//
// 指纹用 COALESCE(NULLIF(?, ''), cert_fingerprint)：边缘偶尔会在证书还没生成的那一拍
// 注册（首次启动竞态），上报空串不能把面板上已经登记好的指纹抹掉 —— 主控现在对无指纹
// 的节点一律拒绝推送，抹掉就等于把一台在跑的节点变成不可管理，而且要等它下次注册才能好。
func (r *NodeRepo) ApplyEdgeReport(ctx context.Context, tenantID, id, address string, tokenEnc []byte, certFP string, ip, clusterID sql.NullString) (*Node, error) {
	_, err := r.db.ExecContext(ctx, `
		UPDATE nodes SET address = ?, token_enc = ?,
			cert_fingerprint = COALESCE(NULLIF(?, ''), cert_fingerprint), ip = ?,
			cluster_id = COALESCE(cluster_id, ?), version = version + 1
		WHERE tenant_id = ? AND id = ?`,
		address, tokenEnc, certFP, ip, clusterID, tenantID, id)
	if err != nil {
		if ae := ClassifyMySQLError(err, nodeIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}
	return r.Get(ctx, tenantID, id)
}

// TouchHeartbeat 记录一次心跳（或主控探测成功）。不递增 version：心跳每 3 秒一次，
// 递增的话面板上任何带 If-Match 的编辑都会因版本号被心跳顶掉而 409。
func (r *NodeRepo) TouchHeartbeat(ctx context.Context, id string, status []byte) error {
	var st any
	if len(status) > 0 {
		st = status
	}
	_, err := r.db.ExecContext(ctx, `UPDATE nodes SET last_heartbeat_at = ?, last_status = ? WHERE id = ?`,
		time.Now().UTC(), st, id)
	return err
}

// ListStale 返回所有租户中启用、且 cutoff 之后没有心跳的节点，供主控探测器补测在线状态。
func (r *NodeRepo) ListStale(ctx context.Context, cutoff time.Time, limit int) ([]*Node, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes
		WHERE enabled = TRUE AND (last_heartbeat_at IS NULL OR last_heartbeat_at < ?)
		ORDER BY last_heartbeat_at LIMIT ?`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.TenantID, &n.ClusterID, &n.Name, &n.Address, &n.TokenEnc, &n.IP, &n.CertFingerprint,
			&n.CFRecordID, &n.Enabled, &n.LastHeartbeatAt, &n.LastStatus, &n.Version, &n.AddedAt, &n.DNSPausedAt); err != nil {
			return nil, err
		}
		out = append(out, &n)
	}
	return out, rows.Err()
}
