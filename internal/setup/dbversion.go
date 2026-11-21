package setup

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var versionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

// checkServerVersion 拒绝装不上 migrations/0001_init.sql 的数据库：JSON 列要 MySQL 5.7.8+，
// MariaDB 按 10.3+（10.2 已停止维护，JSON 支持也不完整）。解析不出版本号时不拦，交给建表报错。
func checkServerVersion(version string) error {
	m := versionRe.FindStringSubmatch(version)
	if m == nil {
		return nil
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	v := major*10000 + minor*100 + patch
	if strings.Contains(strings.ToLower(version), "mariadb") {
		if v < 100300 {
			return fmt.Errorf("数据库版本 %s 过低，需要 MariaDB 10.3 或以上", version)
		}
		return nil
	}
	if v < 50708 {
		return fmt.Errorf("数据库版本 %s 过低，需要 MySQL 5.7.8 或以上（推荐 8.0）", version)
	}
	return nil
}

func serverVersion(ctx context.Context, db *sql.DB) (string, error) {
	var v string
	err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&v)
	return v, err
}

// tableCollation 返回新建表要用的排序规则：跟 tenants 表保持一致（老库可能是 utf8mb4_0900_ai_ci），
// 查不到时用 5.7/8.x/MariaDB 都有的 utf8mb4_unicode_520_ci。结果会拼进 DDL，只接受安全字符。
var collationRe = regexp.MustCompile(`^utf8mb4_[a-z0-9_]+$`)

func tableCollation(ctx context.Context, db *sql.DB) string {
	var c sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT TABLE_COLLATION FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants'`).Scan(&c); err == nil && collationRe.MatchString(c.String) {
		return c.String
	}
	return "utf8mb4_unicode_520_ci"
}
