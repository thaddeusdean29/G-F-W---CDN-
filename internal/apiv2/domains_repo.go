package apiv2

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Domain 是 domains 表一行的 Go 映射。upstreams/cache_rules/ssl_config/cc_policy/geo_policy/gateway_profile/tags
// 都是 JSON 列，这里用 json.RawMessage 原样存取，不在 repo 层做业务结构体反序列化——
// 校验和默认值填充交给 handler 层（domains.go），repo 只管把字节存进去、读出来。
type Domain struct {
	ID           string
	TenantID     string
	ClusterID    sql.NullString
	Domain       string
	OriginScheme string
	Upstreams    json.RawMessage
	CacheRules   json.RawMessage
	SSLConfig    json.RawMessage
	CCPolicy     json.RawMessage
	// GeoPolicy 是按域名的区域规则 JSON 本体（internal/geo.Policy）。和 cc_policy 一样
	// 在 repo 层只搬字节：校验、平台范围限制、默认值填充都在 handler 层做，
	// 这样"库里存的"与"下发给节点的"是同一串。
	GeoPolicy             json.RawMessage
	GatewayProfile        json.RawMessage
	Tags                  json.RawMessage
	Enabled               bool
	DefenseCNAME          string
	VerifyToken           string
	VerifiedAt            sql.NullTime
	CNAMERecord           string
	CNAMERecordID         string
	MainSubdomainRecordID string
	EdgeRecordIDs         json.RawMessage
	CloudflareProxyID     string
	OnDefense             bool
	DefenseByFailover     bool
	// StaticPublic 是租户可写的按域名开关（静态赛道免凭证直连），与 Enabled 一样走
	// 普通列而不是塞进某个 JSON 列：JSON 列整体覆盖会让"只改一个开关"的 PATCH 抹掉
	// 其他字段，列级别才能让 Update 的 SET 清单和 handler 的 fields 判定一一对应。
	StaticPublic  bool
	FailStreak    int
	RecoverStreak int
	RecoverSince  sql.NullTime
	CFMessage     string
	Version       int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type DomainRepo struct {
	db *sql.DB
}

func NewDomainRepo(db *sql.DB) *DomainRepo {
	return &DomainRepo{db: db}
}

// domainIndexCodes 把 domains 表的唯一索引名映射到业务错误码（docs/API-v2.md §0.6）。
// domains_verified_uq 命中说明域名已被别的租户验证占用，必须映射成 domain_taken 而不是
// 泛化的 conflict——前端要据此展示"该域名已被占用"而不是"数据冲突请重试"。
var domainIndexCodes = map[string]string{
	"domains_verified_uq":      "domain_taken",
	"domains_tenant_domain_uq": "conflict",
	"domains_cname_uq":         "conflict",
}

const domainColumns = `id, tenant_id, cluster_id, domain, origin_scheme, upstreams, cache_rules, ssl_config,
	cc_policy, geo_policy, gateway_profile, tags, enabled, static_public, defense_cname, verify_token, verified_at,
	cname_record, cname_record_id, main_subdomain_record_id, edge_record_ids, cloudflare_proxy_id,
	on_defense, defense_by_failover, fail_streak, recover_streak, recover_since, cf_message,
	version, created_at, updated_at`

// rowScanner 让 *sql.Row 与 *sql.Rows 共用同一份字段扫描清单。
// 列只有 domainColumns 一份、扫描却写两处时，加一列会有一种最坏的失效形态：
// 只改了一处，另一处把后面的值整体错位扫进相邻字段——不报错，只是数据悄悄串位。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanDomain(s rowScanner) (*Domain, error) {
	var d Domain
	err := s.Scan(&d.ID, &d.TenantID, &d.ClusterID, &d.Domain, &d.OriginScheme, &d.Upstreams, &d.CacheRules,
		&d.SSLConfig, &d.CCPolicy, &d.GeoPolicy, &d.GatewayProfile, &d.Tags, &d.Enabled, &d.StaticPublic, &d.DefenseCNAME, &d.VerifyToken, &d.VerifiedAt,
		&d.CNAMERecord, &d.CNAMERecordID, &d.MainSubdomainRecordID, &d.EdgeRecordIDs, &d.CloudflareProxyID,
		&d.OnDefense, &d.DefenseByFailover, &d.FailStreak, &d.RecoverStreak, &d.RecoverSince, &d.CFMessage,
		&d.Version, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func scanDomainRow(row *sql.Row) (*Domain, error) {
	return scanDomain(row)
}

// generateVerifyToken 生成 32 位 hex 的所有权验证 token（docs/API-v2.md §2.1 verify_token 注释：
// 应用层生成，租户在自己 DNS 加一条 TXT _cdn-verify.<domain> = 这个值）。
func generateVerifyToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create 插入一个新域名。verify_token 由这里生成（不接受调用方传入），
// gateway_profile/edge_record_ids 显式写空值（MySQL 5.7 的 JSON 列不能有默认值），
// cname_record 等 CF 同步专用字段走字符串列默认值。
//
// 配额检查（checkPlanQuota）和 INSERT 必须在同一个事务里，理由见 nodes_repo.go Create 的注释
// 和 quota.go。
func (r *DomainRepo) Create(ctx context.Context, d *Domain) (*Domain, error) {
	id := uuid.New().String()
	token, err := generateVerifyToken()
	if err != nil {
		return nil, err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := checkPlanQuota(ctx, tx, d.TenantID, "domains"); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO domains (id, tenant_id, cluster_id, domain, origin_scheme, upstreams, cache_rules,
			ssl_config, cc_policy, geo_policy, gateway_profile, tags, edge_record_ids, enabled, static_public, defense_cname, verify_token)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, '[]', ?, ?, ?, ?)`,
		id, d.TenantID, d.ClusterID, d.Domain, d.OriginScheme, d.Upstreams, d.CacheRules,
		d.SSLConfig, d.CCPolicy, d.GeoPolicy, d.Tags, d.Enabled, d.StaticPublic, d.DefenseCNAME, token); err != nil {
		if ae := ClassifyMySQLError(err, domainIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r.Get(ctx, d.TenantID, id)
}

// Get 按租户查询单个域名；不存在或不属于该租户统一返回 sql.ErrNoRows。
func (r *DomainRepo) Get(ctx context.Context, tenantID, id string) (*Domain, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+domainColumns+` FROM domains WHERE tenant_id = ? AND id = ?`, tenantID, id)
	return scanDomainRow(row)
}

// List 返回该租户的域名分页列表和总数。clusterID/tag/enabledFilter/q 均可选过滤；
// tag 用 JSON_CONTAINS 在 tags 数组列里做包含匹配，q 对 domain 做前后模糊匹配。
func (r *DomainRepo) List(ctx context.Context, tenantID, clusterID, tag string, enabledFilter *bool, q, orderBy string, page, pageSize int) ([]*Domain, int, error) {
	where := "tenant_id = ?"
	args := []any{tenantID}
	if clusterID != "" {
		where += " AND cluster_id = ?"
		args = append(args, clusterID)
	}
	if tag != "" {
		where += " AND JSON_CONTAINS(tags, JSON_QUOTE(?))"
		args = append(args, tag)
	}
	if enabledFilter != nil {
		where += " AND enabled = ?"
		args = append(args, *enabledFilter)
	}
	if q != "" {
		where += " AND domain LIKE ?"
		args = append(args, "%"+q+"%")
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, args...), pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT `+domainColumns+` FROM domains WHERE `+where+` ORDER BY `+orderBy+` LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// Update 用乐观锁更新可写字段（docs/API-v2.md §2.1：cluster_id/origin_scheme/upstreams/cache_rules/
// ssl/enabled/static_public/tags/defense_cname/cc_policy/geo_policy）。domain 本身创建后不可改；verify_token/verified_at/
// cname_record 系列/on_defense/defense_by_failover/fail_streak/recover_streak/recover_since/cf_message
// 都是系统或健康检查协程独占写入的字段，故意不接受调用方覆盖。
func (r *DomainRepo) Update(ctx context.Context, tenantID, id string, expectedVersion int, d *Domain) (*Domain, error) {
	query := `UPDATE domains SET cluster_id = ?, origin_scheme = ?, upstreams = ?, cache_rules = ?,
		ssl_config = ?, cc_policy = ?, geo_policy = ?, tags = ?, enabled = ?, static_public = ?, defense_cname = ?, version = version + 1
		WHERE tenant_id = ? AND id = ?`
	args := []any{d.ClusterID, d.OriginScheme, d.Upstreams, d.CacheRules, d.SSLConfig, d.CCPolicy, d.GeoPolicy, d.Tags, d.Enabled, d.StaticPublic, d.DefenseCNAME, tenantID, id}
	if expectedVersion > 0 {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		if ae := ClassifyMySQLError(err, domainIndexCodes); ae != nil {
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

// MarkVerified 把域名标记为已验证。WHERE 里带 verified_at IS NULL 是为了幂等：
// 已验证过的域名再次调用不会报错也不会重复触发唯一索引冲突检测，直接回查当前状态即可
// （调用方 verify() 在此之前已经检查过 d.VerifiedAt.Valid 并短路跳过 DNS 查询,这里的
// IS NULL 条件是双重保险,不依赖调用方一定按顺序调用）。
// verified_at 一旦写入,domains_verified_uq 生成列唯一索引开始生效——如果域名此时已被
// 别的租户验证占用,这里的 UPDATE 会触发 1062,ClassifyMySQLError 翻译成 409 domain_taken。
func (r *DomainRepo) MarkVerified(ctx context.Context, tenantID, id string) (*Domain, error) {
	_, err := r.db.ExecContext(ctx, `UPDATE domains SET verified_at = CURRENT_TIMESTAMP(6) WHERE tenant_id = ? AND id = ? AND verified_at IS NULL`, tenantID, id)
	if err != nil {
		if ae := ClassifyMySQLError(err, domainIndexCodes); ae != nil {
			return nil, ae
		}
		return nil, err
	}
	return r.Get(ctx, tenantID, id)
}

// UpdateCFState 写入 CF 同步产生的记录信息（resync 成功后落库）。不做乐观锁校验：
// 这几列是 resync/purge 后台 goroutine 独占写入的，不经过用户 PATCH 路径，
// 与 Update() 故意排除它们的原因相同（见 Update 注释）。
func (r *DomainRepo) UpdateCFState(ctx context.Context, tenantID, id, cnameRecord, cnameRecordID, mainSubdomainRecordID, cfMessage string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE domains SET cname_record = ?, cname_record_id = ?, main_subdomain_record_id = ?, cf_message = ?
		WHERE tenant_id = ? AND id = ?`,
		cnameRecord, cnameRecordID, mainSubdomainRecordID, cfMessage, tenantID, id)
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

// SetDefenseFlags 写入 on_defense/defense_by_failover 两列，供 switch-to-defense/
// switch-to-cluster/failover trigger-cancel 在完成 CF 记录切换后落库当前指向状态。
func (r *DomainRepo) SetDefenseFlags(ctx context.Context, tenantID, id string, onDefense, byFailover bool) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE domains SET on_defense = ?, defense_by_failover = ? WHERE tenant_id = ? AND id = ?`,
		onDefense, byFailover, tenantID, id)
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

// Delete 删除域名。certificates/usage_daily 对 domains 的外键都是 ON DELETE CASCADE，
// 不需要像 clusters 那样先查引用计数。CF 记录与边缘配置清理是异步副作用（docs §3.1），
// 属于 Stage 2b Job 机制范围,这里先只做落库。
func (r *DomainRepo) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM domains WHERE tenant_id = ? AND id = ?`, tenantID, id)
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
