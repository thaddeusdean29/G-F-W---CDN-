package setup

import (
	"context"
	"database/sql"
	"fmt"
)

// ResetResult 是一次密码重置的结果：各更新了几个账号，没匹配到时附上现有登录名供参考。
type ResetResult struct {
	Admins       int
	TenantUsers  int
	AdminNames   []string
	TenantEmails []string
}

// ResetPassword 在服务器本机（命令行 --reset-password）重置密码：平台管理员 admin_users.username
// 和代理登录账号 tenant_users.email 里与 login 相同的都改成 passHash（bcrypt），并让这些账号
// 已登录的会话全部失效、清空登录失败计数（输错太多次被临时锁住时也能马上登录）。
// 只能由能读 config.json、能连数据库的人执行，不经过任何网络接口。
func ResetPassword(ctx context.Context, db *sql.DB, login, passHash string) (*ResetResult, error) {
	if login == "" || passHash == "" {
		return nil, fmt.Errorf("login and password hash are required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	res := &ResetResult{}
	r, err := tx.ExecContext(ctx, `UPDATE admin_users SET password_hash = ?, status = 'active' WHERE username = ?`, passHash, login)
	if err != nil {
		return nil, fmt.Errorf("update admin_users: %w", err)
	}
	n, _ := r.RowsAffected()
	res.Admins = int(n)

	r, err = tx.ExecContext(ctx, `UPDATE tenant_users SET password_hash = ? WHERE email = ?`, passHash, login)
	if err != nil {
		return nil, fmt.Errorf("update tenant_users: %w", err)
	}
	n, _ = r.RowsAffected()
	res.TenantUsers = int(n)

	if res.Admins == 0 && res.TenantUsers == 0 {
		// 没有这个登录名：列出现有的，方便确认要改哪个（只列名字，不涉及密码）。
		if res.AdminNames, err = listStrings(ctx, tx, `SELECT username FROM admin_users ORDER BY created_at`); err != nil {
			return nil, err
		}
		if res.TenantEmails, err = listStrings(ctx, tx, `SELECT email FROM tenant_users ORDER BY created_at LIMIT 50`); err != nil {
			return nil, err
		}
		return res, nil
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE admin_user_id IN (SELECT id FROM admin_users WHERE username = ?)
		OR tenant_user_id IN (SELECT id FROM tenant_users WHERE email = ?)`, login, login); err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_attempts`); err != nil {
		return nil, fmt.Errorf("clear login attempts: %w", err)
	}
	return res, tx.Commit()
}

func listStrings(ctx context.Context, tx *sql.Tx, q string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
