package setup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
)

// defaultTenantName 是首次安装时自动建的租户名，管理员账号同时作为它的 owner。
const defaultTenantName = "默认租户"

// EnsureAccounts 把 config.json 里的管理员账号补进数据库。
//
// 安装向导以前只把 bcrypt 哈希写进 config.json，而 /api/v2 的两套登录
// （admin_users、tenant_users）都只查库，于是装完库里一个账号都没有，谁都登不进去。
// 这里在向导提交后和每次启动时各跑一次：
//   - admin_users 为空 → 插入平台管理员（username = cfg.AdminUser）
//   - tenants 与 tenant_users 都为空 → 建一个默认租户（最高套餐），管理员作为 owner，
//     登录名（email 列）同样用 cfg.AdminUser，控制台 /console/ 用它 + 同一个密码登录
//
// 只在表为空时写入，库里已有账号就一律不动，不会覆盖之后在库里改过的密码。
// passHash 必须是 bcrypt 哈希（config.HashPassword 的产物），两套登录都用 bcrypt 校验。
func EnsureAccounts(ctx context.Context, db *sql.DB, username, passHash string) error {
	if username == "" || passHash == "" {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&n); err != nil {
		return fmt.Errorf("count admin_users: %w", err)
	}
	if n == 0 {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO admin_users (id, username, password_hash, status) VALUES (?, ?, ?, 'active')`,
			uuid.New().String(), username, passHash); err != nil {
			return fmt.Errorf("insert admin_users: %w", err)
		}
		log.Printf("bootstrap: created platform admin %q", username)
	}

	var tenants, users int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&tenants); err != nil {
		return fmt.Errorf("count tenants: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_users`).Scan(&users); err != nil {
		return fmt.Errorf("count tenant_users: %w", err)
	}
	if tenants == 0 && users == 0 {
		var planID int
		err := tx.QueryRowContext(ctx, `SELECT id FROM plans ORDER BY max_nodes DESC, id DESC LIMIT 1`).Scan(&planID)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("plans 表为空，无法创建默认租户（migration 是否完整执行？）")
		}
		if err != nil {
			return fmt.Errorf("select plan: %w", err)
		}
		tenantID := uuid.New().String()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tenants (id, name, plan_id, status) VALUES (?, ?, ?, 'active')`,
			tenantID, defaultTenantName, planID); err != nil {
			return fmt.Errorf("insert tenants: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tenant_users (id, tenant_id, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'owner', 'active')`,
			uuid.New().String(), tenantID, username, passHash); err != nil {
			return fmt.Errorf("insert tenant_users: %w", err)
		}
		log.Printf("bootstrap: created default tenant with owner %q", username)
	}

	return tx.Commit()
}
