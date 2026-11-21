package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Job 是 jobs 表一行的 Go 映射。TenantID 允许 NULL 表示平台任务（管理员发起，不属于任何租户）；
// apiv2 目前只有租户路由挂了 jobs 资源，所以这里创建/查询到的 Job.TenantID 总是有值,
// NULL 的分支是为将来管理员接口留的余地,不是死代码。
type Job struct {
	ID            string
	TenantID      sql.NullString
	Type          string
	Status        string
	Progress      int
	Message       string
	Warning       string
	Result        json.RawMessage
	NodeID        sql.NullString
	Params        json.RawMessage
	OwnerInstance sql.NullString
	LeaseUntil    sql.NullTime
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type JobRepo struct {
	db *sql.DB
}

func NewJobRepo(db *sql.DB) *JobRepo {
	return &JobRepo{db: db}
}

const jobColumns = `id, tenant_id, type, status, progress, message, warning, result, node_id, params,
	owner_instance, lease_until, created_at, updated_at`

func scanJob(row *sql.Row) (*Job, error) {
	var j Job
	var result sql.NullString
	err := row.Scan(&j.ID, &j.TenantID, &j.Type, &j.Status, &j.Progress, &j.Message, &j.Warning, &result,
		&j.NodeID, &j.Params, &j.OwnerInstance, &j.LeaseUntil, &j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if result.Valid {
		j.Result = json.RawMessage(result.String)
	}
	return &j, nil
}

// Create 插入一条 pending 状态的 job，status/progress/message/warning 用表默认值
// （pending/0/''/''）。nodeID 为空字符串表示与具体节点无关（如 domain.resync/domain.purge）；
// params 为 nil 时落成 JSON 对象空值而不是 SQL NULL，与列的 NOT NULL 约束一致。
func (r *JobRepo) Create(ctx context.Context, tenantID, jobType, nodeID string, params json.RawMessage) (*Job, error) {
	id := uuid.New().String()
	if params == nil {
		params = json.RawMessage("{}")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO jobs (id, tenant_id, type, node_id, params)
		VALUES (?, ?, ?, ?, ?)`,
		id, sql.NullString{String: tenantID, Valid: tenantID != ""}, jobType,
		sql.NullString{String: nodeID, Valid: nodeID != ""}, params)
	if err != nil {
		return nil, err
	}
	return r.Get(ctx, tenantID, id)
}

// Get 按租户查询单个 job；不存在或不属于该租户统一返回 sql.ErrNoRows。
func (r *JobRepo) Get(ctx context.Context, tenantID, id string) (*Job, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE tenant_id = ? AND id = ?`, tenantID, id)
	return scanJob(row)
}

// List 返回该租户最近的任务（按创建时间倒序），jobType/status 均可选过滤。
// docs/API-v2.md §3.10 没有要求自定义排序，所以不像其它资源那样接受 sort 参数。
func (r *JobRepo) List(ctx context.Context, tenantID, jobType, status string, page, pageSize int) ([]*Job, int, error) {
	where := "tenant_id = ?"
	args := []any{tenantID}
	if jobType != "" {
		where += " AND type = ?"
		args = append(args, jobType)
	}
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE `+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		var j Job
		var result sql.NullString
		if err := rows.Scan(&j.ID, &j.TenantID, &j.Type, &j.Status, &j.Progress, &j.Message, &j.Warning, &result,
			&j.NodeID, &j.Params, &j.OwnerInstance, &j.LeaseUntil, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, 0, err
		}
		if result.Valid {
			j.Result = json.RawMessage(result.String)
		}
		out = append(out, &j)
	}
	return out, total, rows.Err()
}

// UpdateProgress 把 job 标记为 running 并汇报进度。不做乐观锁：job 从创建到结束只由
// 发起它的那一次异步调用（一个 goroutine）独占写入，不存在并发更新同一 job 的场景，
// 不需要像 nodes/clusters/domains 那样的 version 字段。
func (r *JobRepo) UpdateProgress(ctx context.Context, id string, progress int, message string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE jobs SET status = 'running', progress = ?, message = ? WHERE id = ?`, progress, message, id)
	return err
}

// MarkDone 把 job 标记为 done，写入最终 result（可为空,存 SQL NULL）和可选的 warning。
func (r *JobRepo) MarkDone(ctx context.Context, id string, result json.RawMessage, warning string) error {
	var resultArg any
	if len(result) > 0 {
		resultArg = result
	}
	_, err := r.db.ExecContext(ctx, `UPDATE jobs SET status = 'done', progress = 100, result = ?, warning = ? WHERE id = ?`, resultArg, warning, id)
	return err
}

// MarkFailed 把 job 标记为 failed，message 是失败原因（如 SSH 连接失败、配额释放失败等）。
func (r *JobRepo) MarkFailed(ctx context.Context, id, message string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE jobs SET status = 'failed', message = ? WHERE id = ?`, message, id)
	return err
}
