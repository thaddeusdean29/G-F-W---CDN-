package apiv2

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"cdn/internal/cloudflare"
)

// 节点灰云 A 记录：集群子域名 <cluster.name>.<代理 base_domain> 下每个节点一条 A 记录（不走 CF 代理），
// 指向节点 IP；用户域名 CNAME → 切换记录 → 集群子域名，最终解析到这些节点。
// nodes.cf_record_id 记的是面板替这个节点建的那一条，只删自己建的，不碰同名的其它记录。
// 只用代理自己保存的 CF 凭据（tenantCF），没配或停用就跳过——绝不退回全局 config.json 的 CF。

const nodeDNSTimeout = 30 * time.Second

// SetCFRecordID 只改 cf_record_id，不递增 version：这是 CF 同步的副作用，
// 不应让用户手里的 If-Match 版本号失效。
func (r *NodeRepo) SetCFRecordID(ctx context.Context, tenantID, id, recordID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE nodes SET cf_record_id = ? WHERE tenant_id = ? AND id = ?`, recordID, tenantID, id)
	return err
}

// clusterExists 校验集群属于该租户。部署要在 SSH 安装之前调用，免得装完才因外键失败。
func clusterExists(ctx context.Context, db *sql.DB, tenantID, clusterID string) error {
	if db == nil || clusterID == "" {
		return nil
	}
	var id string
	err := db.QueryRowContext(ctx, `SELECT id FROM clusters WHERE tenant_id = ? AND id = ?`, tenantID, clusterID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return NewApiError("validation_failed", "集群不存在").
			WithDetails(map[string]any{"fields": map[string]string{"cluster_id": "不存在"}})
	}
	return err
}

// nodeDNSWanted 判断节点当前应不应该有 A 记录。被带宽监控暂时摘除的节点不要（由监控负责加回）。
func nodeDNSWanted(n *Node) bool {
	return n != nil && n.Enabled && n.ClusterID.Valid && n.ClusterID.String != "" && n.IP.Valid && n.IP.String != "" &&
		!n.DNSPausedAt.Valid
}

// PauseDNS 标记节点已从集群 DNS 摘除，并清掉 cf_record_id（调用方已删除该记录）。不递增 version。
func (r *NodeRepo) PauseDNS(ctx context.Context, tenantID, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE nodes SET dns_paused_at = ?, cf_record_id = '' WHERE tenant_id = ? AND id = ?`,
		time.Now().UTC(), tenantID, id)
	return err
}

// ResumeDNS 清除摘除标记并写入重新建好的 A 记录 ID（没建记录时传空）。不递增 version。
func (r *NodeRepo) ResumeDNS(ctx context.Context, tenantID, id, recordID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE nodes SET dns_paused_at = NULL, cf_record_id = ? WHERE tenant_id = ? AND id = ?`,
		recordID, tenantID, id)
	return err
}

// syncNodeDNS 让节点的 A 记录与当前状态一致：先删掉旧记录（oldRecordID，集群/IP 变了或节点停用时），
// 再按需新建（同名同 IP 的记录已存在就接管），最后把记录 ID 写回 nodes.cf_record_id。
// CF 出错只记日志：DNS 是副作用，不能让节点保存/注册失败。调用方应在 goroutine 里调用。
func syncNodeDNS(db *sql.DB, repo *NodeRepo, n *Node, oldRecordID string) {
	if db == nil || repo == nil || n == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeDNSTimeout)
	defer cancel()

	cf, err := tenantCF(ctx, db, n.TenantID)
	if err != nil {
		log.Printf("[apiv2 NodeDNS] load CF for tenant %s: %v", n.TenantID, err)
		return
	}
	if !cf.Enabled() {
		if nodeDNSWanted(n) {
			log.Printf("[apiv2 NodeDNS] tenant %s has no Cloudflare credentials, skip A record for node %s", n.TenantID, n.ID)
		}
		return
	}

	if oldRecordID != "" {
		if err := cf.DeleteRecord(oldRecordID); err != nil && !cloudflare.IsNotFound(err) {
			log.Printf("[apiv2 NodeDNS] delete old A record %s of node %s: %v", oldRecordID, n.ID, err)
		}
	}

	recordID := ""
	if nodeDNSWanted(n) {
		var name string
		err := db.QueryRowContext(ctx, `SELECT name FROM clusters WHERE tenant_id = ? AND id = ?`, n.TenantID, n.ClusterID.String).Scan(&name)
		if err != nil {
			log.Printf("[apiv2 NodeDNS] load cluster %s of node %s: %v", n.ClusterID.String, n.ID, err)
		} else if id, err := cf.EnsureARecord(name, n.IP.String); err != nil {
			log.Printf("[apiv2 NodeDNS] create A record %s → %s for node %s: %v", cf.ClusterSubdomain(name), n.IP.String, n.ID, err)
		} else {
			recordID = id
			log.Printf("[apiv2 NodeDNS] A record %s → %s ready for node %s", cf.ClusterSubdomain(name), n.IP.String, n.ID)
		}
	}
	if recordID == oldRecordID && oldRecordID == n.CFRecordID {
		return
	}
	if err := repo.SetCFRecordID(ctx, n.TenantID, n.ID, recordID); err != nil {
		log.Printf("[apiv2 NodeDNS] save cf_record_id for node %s: %v", n.ID, err)
	}
}

// deleteNodeDNS 删除已删节点自己的 A 记录。
func deleteNodeDNS(db *sql.DB, tenantID, nodeID, recordID string) {
	if db == nil || recordID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeDNSTimeout)
	defer cancel()
	cf, err := tenantCF(ctx, db, tenantID)
	if err != nil || !cf.Enabled() {
		log.Printf("[apiv2 NodeDNS] node %s deleted but CF unavailable, A record %s left in place (err=%v)", nodeID, recordID, err)
		return
	}
	if err := cf.DeleteRecord(recordID); err != nil && !cloudflare.IsNotFound(err) {
		log.Printf("[apiv2 NodeDNS] delete A record %s of node %s: %v", recordID, nodeID, err)
	}
}

// syncReplacedNodeDNS 处理「同 IP 重装」：新节点的记录照常建；旧节点的记录若与新记录同名同 IP，
// EnsureARecord 会直接接管它，不必删；否则（换了集群、旧节点属于别的代理）用旧节点所属代理的凭据删掉。
func syncReplacedNodeDNS(db *sql.DB, repo *NodeRepo, created, replaced *Node) {
	if replaced != nil && replaced.CFRecordID != "" {
		sameRecord := replaced.TenantID == created.TenantID && replaced.ClusterID == created.ClusterID &&
			replaced.IP == created.IP && nodeDNSWanted(created)
		if !sameRecord {
			deleteNodeDNS(db, replaced.TenantID, replaced.ID, replaced.CFRecordID)
		}
	}
	syncNodeDNS(db, repo, created, "")
}

// backfillTenantNodeDNS 给该代理所有应有却还没有 A 记录的节点补建（CF 凭据刚保存、旧版本建的节点等）。
func backfillTenantNodeDNS(db *sql.DB, tenantID string) {
	if db == nil {
		return
	}
	repo := NewNodeRepo(db)
	ctx, cancel := context.WithTimeout(context.Background(), nodeDNSTimeout)
	rows, err := db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes
		WHERE tenant_id = ? AND enabled AND cluster_id IS NOT NULL AND ip IS NOT NULL AND ip <> '' AND cf_record_id = ''
			AND dns_paused_at IS NULL`, tenantID)
	if err != nil {
		cancel()
		log.Printf("[apiv2 NodeDNS] list nodes to backfill for tenant %s: %v", tenantID, err)
		return
	}
	var pending []*Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.TenantID, &n.ClusterID, &n.Name, &n.Address, &n.TokenEnc, &n.IP, &n.CertFingerprint,
			&n.CFRecordID, &n.Enabled, &n.LastHeartbeatAt, &n.LastStatus, &n.Version, &n.AddedAt, &n.DNSPausedAt); err == nil {
			pending = append(pending, &n)
		}
	}
	rows.Close()
	cancel()
	for _, n := range pending {
		syncNodeDNS(db, repo, n, "")
	}
}

// backfillAllNodeDNS 启动时对所有配了 CF 的代理跑一遍补建，覆盖升级前就装好的节点。
func backfillAllNodeDNS(db *sql.DB) {
	if db == nil {
		return
	}
	time.Sleep(10 * time.Second) // 等启动完成，不和迁移 / 首批心跳抢连接
	ctx, cancel := context.WithTimeout(context.Background(), nodeDNSTimeout)
	rows, err := db.QueryContext(ctx, `SELECT tenant_id FROM tenant_cf_credentials WHERE enabled`)
	if err != nil {
		cancel()
		log.Printf("[apiv2 NodeDNS] list tenants for backfill: %v", err)
		return
	}
	var tenants []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			tenants = append(tenants, id)
		}
	}
	rows.Close()
	cancel()
	for _, id := range tenants {
		backfillTenantNodeDNS(db, id)
	}
}
