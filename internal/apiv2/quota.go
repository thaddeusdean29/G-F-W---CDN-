package apiv2

import (
	"context"
	"database/sql"
	"time"
)

// checkPlanQuota 取代原来的 check_plan_quota 存储过程 + 触发器（migrations/0001_init.sql
// 已经不再建它们）：开启 binlog 又没有 SUPER 权限的服务器（云数据库、宝塔/aaPanel 默认账号
// 很常见）建 PROCEDURE/TRIGGER 会报 1419，每换一台服务器都要单独放权限，不可移植；
// 配额检查挪到应用层就不再依赖数据库对象。
//
// 语义与原存储过程完全一致：先 SELECT ... FOR UPDATE 锁租户行（校验 active/未过期），
// 再 SELECT COUNT(*) ... FOR UPDATE 数当前资源数，两次查询和随后的 INSERT 必须在同一个
// 事务 tx 里、不能提前 Commit，否则锁提前释放，多个 cdnpanel 实例并发创建时又会超限。
// resource 只能是 "nodes"/"domains"/"clusters"，其余值直接 panic——调用方写死传入，不是用户输入。
func checkPlanQuota(ctx context.Context, tx *sql.Tx, tenantID, resource string) error {
	var (
		status    string
		expiresAt sql.NullTime
		planID    int
	)
	err := tx.QueryRowContext(ctx, `SELECT status, expires_at, plan_id FROM tenants WHERE id = ? FOR UPDATE`, tenantID).
		Scan(&status, &expiresAt, &planID)
	if err != nil {
		if err == sql.ErrNoRows {
			return NewApiError("tenant_inactive", "租户已停用或到期")
		}
		return err
	}
	if status != "active" || (expiresAt.Valid && expiresAt.Time.Before(time.Now().UTC())) {
		return NewApiError("tenant_inactive", "租户已停用或到期")
	}

	var limitCol, table string
	switch resource {
	case "nodes":
		limitCol, table = "max_nodes", "nodes"
	case "domains":
		limitCol, table = "max_domains", "domains"
	case "clusters":
		limitCol, table = "max_clusters", "clusters"
	default:
		panic("apiv2: unknown quota resource " + resource)
	}

	var limit int
	if err := tx.QueryRowContext(ctx, `SELECT `+limitCol+` FROM plans WHERE id = ?`, planID).Scan(&limit); err != nil {
		return err
	}

	var count int
	// 用 FOR UPDATE 而不是 FOR SHARE：FOR SHARE 是 MySQL 8 专有语法，MariaDB 直接报 1064，
	// 所有创建接口都会 500。上面已经 FOR UPDATE 锁住租户行，同租户的创建本来就串行，这里换成排他锁不增加实际争用。
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id = ? FOR UPDATE`, tenantID).Scan(&count); err != nil {
		return err
	}

	if count >= limit {
		return NewApiError("quota_exceeded", "已达套餐上限").WithDetails(map[string]any{"resource": resource})
	}
	return nil
}
