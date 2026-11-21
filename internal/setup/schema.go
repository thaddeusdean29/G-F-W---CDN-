package setup

import (
	"context"
	"database/sql"
	"fmt"
)

// EnsureSchema 在启动时补齐 0001 之后新增的表/列。RunMigration 不是幂等的，
// 这里每一步都先查 information_schema 或用 IF NOT EXISTS，重复执行无副作用。
//   - tenant_cf_credentials.base_domain：每个代理自己的 Cloudflare 根域名（与 token/zone 一起按代理隔离）
//   - tenant_settings：每个代理自己的 CC / XDP 防御配置（JSON），新节点接入时按它补发
//   - platform_settings：平台级系统设置（平台名称等品牌信息），管理员修改
//   - platform_assets：平台级小文件（网站图标），管理员上传
//   - clusters.bw_limit_mbps / bw_danger_percent / auto_failover_active：带宽防护与自动切换状态
//   - nodes.dns_paused_at：带宽打满的节点被暂时从集群 DNS 摘除的时刻
//   - domains.static_public：静态赛道免凭证直连开关（纯多媒体/静态资产域名）
//   - acme_accounts：每个代理自己的 ACME 账号（私钥加密落库，与 Cloudflare token 同样隔离）
//   - waf_rule_packages：平台级的 WAF 托管规则包（密文），管理员维护、激活后下发全网
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	// 新表与 0001 建的表用同一排序规则（老库 0900_ai_ci，5.7 上装的是 unicode_520_ci），
	// 否则 JOIN/比较字符串列会报 Illegal mix of collations。
	coll := tableCollation(ctx, db)
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenant_cf_credentials' AND COLUMN_NAME = 'base_domain'`).Scan(&n)
	if err != nil {
		return fmt.Errorf("check tenant_cf_credentials.base_domain: %w", err)
	}
	if n == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE tenant_cf_credentials
			ADD COLUMN base_domain VARCHAR(253) NOT NULL DEFAULT '' AFTER zone_id`); err != nil {
			return fmt.Errorf("add tenant_cf_credentials.base_domain: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS tenant_settings (
		tenant_id  CHAR(36) CHARACTER SET ascii NOT NULL,
		name       VARCHAR(64) NOT NULL,
		value      JSON NOT NULL,
		updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
		PRIMARY KEY (tenant_id, name),
		FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=`+coll); err != nil {
		return fmt.Errorf("create tenant_settings: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_settings (
		name       VARCHAR(64) NOT NULL PRIMARY KEY,
		value      JSON NOT NULL,
		updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=`+coll); err != nil {
		return fmt.Errorf("create platform_settings: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_assets (
		name       VARCHAR(64) NOT NULL PRIMARY KEY,
		mime       VARCHAR(64) NOT NULL,
		sha256     CHAR(64) CHARACTER SET ascii NOT NULL,
		data       MEDIUMBLOB NOT NULL,
		updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=`+coll); err != nil {
		return fmt.Errorf("create platform_assets: %w", err)
	}
	// 每个代理各一把 ACME 账号私钥：与 tenant_cf_credentials 同样的隔离和加密方式，
	// 只按 api_token_set / 签发结果对外，私钥任何接口都不回显。
	// directory 记下建号时用的 CA 目录：切到/切回测试环境时账号 URL 会失效，靠它判出来重注册。
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS acme_accounts (
		tenant_id   CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
		key_enc     VARBINARY(1024) NOT NULL,
		thumbprint  VARCHAR(64) CHARACTER SET ascii NOT NULL DEFAULT '',
		account_url VARCHAR(512) NOT NULL DEFAULT '',
		directory   VARCHAR(512) NOT NULL DEFAULT '',
		updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
		FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=`+coll); err != nil {
		return fmt.Errorf("create acme_accounts: %w", err)
	}
	// WAF 托管规则包（平台级，只有管理员能维护）：payload 存的是密文，与内置 rules.enc
	// 同一种格式（secure.Encrypt 的产物），边缘拿到也是密文自己解密编译。规则文本本身
	// 就是"这台产品是自研的"指纹，明文进库等于把指纹交给任何能读到备份的人。
	// enabled 至多一行为真（激活在同一事务里先清后设）；activated_at 用来找"上一版"，
	// 灰度分流与回滚都要一个旧档可指。
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS waf_rule_packages (
		id           CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
		version      VARCHAR(32) CHARACTER SET ascii NOT NULL,
		notes        VARCHAR(500) NOT NULL DEFAULT '',
		payload      MEDIUMBLOB NOT NULL,
		rule_count   INT NOT NULL DEFAULT 0,
		set_count    INT NOT NULL DEFAULT 0,
		enabled      BOOLEAN NOT NULL DEFAULT FALSE,
		activated_at DATETIME(6) NULL,
		created_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
		updated_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
		UNIQUE KEY waf_rule_packages_version_uq (version),
		KEY waf_rule_packages_enabled_idx (enabled, activated_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=`+coll); err != nil {
		return fmt.Errorf("create waf_rule_packages: %w", err)
	}
	for _, col := range []struct{ name, ddl string }{
		{"bw_limit_mbps", `ALTER TABLE clusters ADD COLUMN bw_limit_mbps INT NOT NULL DEFAULT 0`},
		{"bw_danger_percent", `ALTER TABLE clusters ADD COLUMN bw_danger_percent INT NOT NULL DEFAULT 90`},
		{"auto_failover_active", `ALTER TABLE clusters ADD COLUMN auto_failover_active BOOLEAN NOT NULL DEFAULT FALSE`},
	} {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'clusters' AND COLUMN_NAME = ?`, col.name).Scan(&n); err != nil {
			return fmt.Errorf("check clusters.%s: %w", col.name, err)
		}
		if n == 0 {
			if _, err := db.ExecContext(ctx, col.ddl); err != nil {
				return fmt.Errorf("add clusters.%s: %w", col.name, err)
			}
		}
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'nodes' AND COLUMN_NAME = 'dns_paused_at'`).Scan(&n); err != nil {
		return fmt.Errorf("check nodes.dns_paused_at: %w", err)
	}
	if n == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE nodes ADD COLUMN dns_paused_at DATETIME(6) NULL`); err != nil {
			return fmt.Errorf("add nodes.dns_paused_at: %w", err)
		}
	}
	// domains.static_public：按域名的「静态赛道免凭证直连」开关。默认 FALSE 就是升级前的
	// 行为（静态块挂 auth_request），所以这条 ALTER 不需要回填、也不改变任何存量域名的配置。
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'domains' AND COLUMN_NAME = 'static_public'`).Scan(&n); err != nil {
		return fmt.Errorf("check domains.static_public: %w", err)
	}
	if n == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE domains ADD COLUMN static_public BOOLEAN NOT NULL DEFAULT FALSE AFTER enabled`); err != nil {
			return fmt.Errorf("add domains.static_public: %w", err)
		}
	}
	// domains.geo_policy：按域名的区域规则（internal/geo.Policy 的 JSON 本体）。
	// MySQL/MariaDB 都不给 JSON 列写 DEFAULT，所以只能"先可空、再回填"两步：
	// 只加列不回填的话，存量行是 NULL，读接口扫进 json.RawMessage 会当场报错，
	// 于是升级到这一版之后域名列表整体打不开——比区域规则没生效严重得多。
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'domains' AND COLUMN_NAME = 'geo_policy'`).Scan(&n); err != nil {
		return fmt.Errorf("check domains.geo_policy: %w", err)
	}
	if n == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE domains ADD COLUMN geo_policy JSON NULL AFTER cc_policy`); err != nil {
			return fmt.Errorf("add domains.geo_policy: %w", err)
		}
	}
	// 回填每次启动都跑：它只碰 NULL/空串，正常库里影响 0 行，所以不需要和加列绑在一起。
	// 加列与回填之间如果进程被打断（升级脚本超时），下一次启动仍然会补上，
	// 不会留下"列有了但存量行是 NULL"这个能把域名列表打挂的状态。
	if _, err := db.ExecContext(ctx, `UPDATE domains SET geo_policy = '{}' WHERE geo_policy IS NULL OR geo_policy = ''`); err != nil {
		return fmt.Errorf("backfill domains.geo_policy: %w", err)
	}
	return nil
}
