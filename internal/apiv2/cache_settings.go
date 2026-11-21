package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"cdn/internal/config"
	"cdn/internal/master"
)

// 代理级默认缓存规则：域名的 cache_rules 为空（新建域名默认如此）时下发这一套。
// 存在 tenant_settings 的 cache_config 里，按代理隔离；代理从未保存过就用平台默认
// （defaultCacheRules）。保存后把本代理全部域名重新下发到本代理的节点，规则立即生效。
const settingCacheConfig = "cache_config"

type cacheSetting struct {
	Rules []domainCacheRule `json:"rules"`
}

// usesDefaultCache 判断域名是否沿用默认规则（没有自己的缓存规则）。
func usesDefaultCache(d *Domain) bool {
	s := strings.TrimSpace(string(d.CacheRules))
	return s == "" || s == "null" || s == "[]"
}

func platformCacheSetting() cacheSetting {
	var out cacheSetting
	for _, r := range defaultCacheRules() {
		out.Rules = append(out.Rules, domainCacheRule{Extensions: r.Extensions, TTL: r.TTL, Enabled: r.Enabled})
	}
	return out
}

func (c cacheSetting) configRules() []config.CacheRule {
	out := make([]config.CacheRule, 0, len(c.Rules))
	for _, r := range c.Rules {
		out = append(out, config.CacheRule{Extensions: append([]string(nil), r.Extensions...), TTL: r.TTL, Enabled: r.Enabled})
	}
	return out
}

// tenantCacheRules 返回本代理的默认缓存规则；没保存过就是平台默认。保存为空列表表示
// 「默认不缓存」，原样返回空（不再回落到平台默认）。
func tenantCacheRules(ctx context.Context, db *sql.DB, tenantID string) ([]config.CacheRule, error) {
	cs := platformCacheSetting()
	if db == nil {
		return cs.configRules(), nil
	}
	var saved cacheSetting
	ok, err := loadTenantSetting(ctx, db, tenantID, settingCacheConfig, &saved)
	if err != nil {
		return nil, err
	}
	if ok {
		cs = saved
	}
	return cs.configRules(), nil
}

// tenantDomainPayloads 取出该代理的全部域名并转成下发 payload（证书一并带上），
// 供节点补发配置与保存缓存设置后的重新下发共用。
func tenantDomainPayloads(ctx context.Context, db *sql.DB, repo *DomainRepo, tenantID string) ([]*master.DomainPushPayload, error) {
	var out []*master.DomainPushPayload
	for page := 1; ; page++ {
		rows, total, err := repo.List(ctx, tenantID, "", "", nil, "", "created_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		for _, d := range rows {
			p, err := domainPushPayload(ctx, db, d)
			if err != nil {
				return nil, fmt.Errorf("domain %s: %w", d.Domain, err)
			}
			out = append(out, p)
		}
		if len(rows) == 0 || page*maxPageSize >= total {
			return out, nil
		}
	}
}

func (h *securityHandler) getCacheConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	cs := platformCacheSetting()
	saved, err := loadTenantSetting(r.Context(), h.db, tenantID, settingCacheConfig, &cs)
	if err != nil {
		WriteError(w, err)
		return
	}
	if cs.Rules == nil {
		cs.Rules = []domainCacheRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cs, "saved": saved, "platform_default": platformCacheSetting()})
}

func (h *securityHandler) putCacheConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, fields, err := decodeKnownFields(r, []string{"rules"})
	if err != nil {
		WriteError(w, err)
		return
	}
	rulesRaw, ok := fields["rules"]
	if !ok {
		WriteError(w, NewApiError("validation_failed", "rules 为必填字段"))
		return
	}
	_ = raw
	norm, err := validateCacheRules(rulesRaw)
	if err != nil {
		WriteError(w, err)
		return
	}
	var cs cacheSetting
	if err := json.Unmarshal(norm, &cs.Rules); err != nil {
		WriteError(w, NewApiError("validation_failed", "rules 格式不正确"))
		return
	}
	if cs.Rules == nil {
		cs.Rules = []domainCacheRule{}
	}
	for i := range cs.Rules {
		cs.Rules[i].TTL = strings.TrimSpace(cs.Rules[i].TTL)
		for j, ext := range cs.Rules[i].Extensions {
			cs.Rules[i].Extensions[j] = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
		}
	}
	if err := saveTenantSetting(r.Context(), h.db, tenantID, settingCacheConfig, cs); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cs, "push": h.repushDomains(r.Context(), tenantID)})
}

// repushDomains 把本代理全部域名整体下发到本代理的每个节点（replace-all，各节点只收自己集群的）。
// 没有域名时不下发：空的 replace-all 会把节点上的站点全部删掉。
func (h *securityHandler) repushDomains(ctx context.Context, tenantID string) map[string]string {
	payloads, err := tenantDomainPayloads(ctx, h.db, h.domainRepo, tenantID)
	if err != nil {
		return map[string]string{"_": "读取域名失败: " + err.Error()}
	}
	if len(payloads) == 0 {
		return map[string]string{"_": "skipped: no domains"}
	}
	nodes, err := tenantEdgeNodes(ctx, h.nodeRepo, tenantID)
	if err != nil {
		return map[string]string{"_": "读取节点失败: " + err.Error()}
	}
	return fanoutNodes(nodes, func(n *config.Node) error {
		cnt, err := h.pusher.SyncNodePayloads(n, payloads)
		if err == nil {
			log.Printf("[apiv2 Cache] tenant %s: re-pushed %d domains to node %s", tenantID, cnt, nodeLabel(n))
		}
		return err
	})
}
