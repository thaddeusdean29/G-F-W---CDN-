package edgeapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"cdn/internal/waf"
)

// 本文件是托管规则在边缘的三个入口：
//   - POST /edge/waf/config 面板下发的策略补丁（开关/模式/级别/规则集/单条覆盖/包版本/灰度）
//   - POST /edge/waf/rules  管理员维护的规则包（密文），编译校验通过后原子换表
//   - GET  /edge/waf/stats  本节点的实际装载与命中读数
//
// 两个写入口都落盘：cdnedge 重启（含升级）后必须回到面板上看到的那份状态，
// 否则"下发成功"只维持到下一次重启为止。

// wafPackageFile 是 /var/lib/cdnedge/waf_package.json 的结构。
// 存的是密文（secure.Encrypt 的产物）base64：规则文本本身就是"这台产品是自研的"指纹，
// 明文躺在节点上等于把指纹交给拿到一台机器的人。
type wafPackageFile struct {
	Active   string `json:"active"`
	Previous string `json:"previous,omitempty"`
	SavedAt  string `json:"saved_at"`
}

// SetWAFStatePaths 记录两份存档路径并立即恢复。必须在对外服务之前调用。
func (h *Handler) SetWAFStatePaths(statePath, packagePath string) {
	h.wafStatePath = statePath
	h.wafPackagePath = packagePath
	h.restoreWAFConfig()
	h.restoreWAFPackage()
}

func (h *Handler) restoreWAFConfig() {
	if h.wafStatePath == "" || h.wafEngine == nil {
		return
	}
	data, err := os.ReadFile(h.wafStatePath)
	if os.IsNotExist(err) {
		return // 面板从没下发过：用 DefaultPolicy（开启 + 拦截 + 中级别），与升级前行为一致
	}
	if err != nil {
		log.Printf("WAF config restore: read %s: %v", h.wafStatePath, err)
		return
	}
	var pol waf.Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		log.Printf("WAF config restore: parse %s: %v (keeping defaults)", h.wafStatePath, err)
		return
	}
	pol.Normalize()
	h.wafEngine.SetPolicy(pol)
	log.Printf("WAF 策略已从 %s 恢复：enabled=%v mode=%s level=%s 固定包=%q 灰度=%d%%",
		h.wafStatePath, pol.Enabled, pol.Mode, pol.Level, pol.RulesVersion, pol.GrayPercent)
}

// restoreWAFPackage 恢复上次下发的规则包。任一份编译失败都只丢掉那一份并记日志，
// 出厂包（go:embed）始终作为 active 兜底 —— 但读数里 active 会退回内置版本，
// 面板的版本列能看出这台节点没吃到管理员维护的包。
func (h *Handler) restoreWAFPackage() {
	if h.wafPackagePath == "" || h.wafEngine == nil {
		return
	}
	data, err := os.ReadFile(h.wafPackagePath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("WAF package restore: read %s: %v", h.wafPackagePath, err)
		return
	}
	var f wafPackageFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("WAF package restore: parse %s: %v (keeping built-in package)", h.wafPackagePath, err)
		return
	}
	var active, previous *waf.Compiled
	if active, err = decodeWAFPackage(f.Active); err != nil {
		log.Printf("WAF package restore: active 不可用: %v (keeping built-in package)", err)
		return
	}
	if f.Previous != "" {
		if previous, err = decodeWAFPackage(f.Previous); err != nil {
			// previous 坏掉不影响 active 生效；但灰度/回滚档位会退化成"只有 active"，
			// 必须说出来，不能让面板以为还能切。
			log.Printf("WAF package restore: previous 不可用: %v (只恢复 active)", err)
		}
	}
	h.wafEngine.SetPackages(active, previous)
	log.Printf("WAF 规则包已从 %s 恢复：active=%s previous=%s",
		h.wafPackagePath, active.Version(), versionOrEmpty(previous))
}

func decodeWAFPackage(b64 string) (*waf.Compiled, error) {
	if b64 == "" {
		return nil, errors.New("包内容为空")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return waf.CompilePackageEncrypted(raw)
}

func versionOrEmpty(c *waf.Compiled) string {
	if c == nil {
		return ""
	}
	return c.Version()
}

// wafRulesPush 是主控下发的规则包。两个字段都是 base64(secure.Encrypt(rules.json))。
// Previous 传空串表示"保持节点现有 previous"（灰度与回滚的旧档不会因为只更新 active 而消失）。
type wafRulesPush struct {
	Active   string `json:"active"`
	Previous string `json:"previous,omitempty"`
}

func (h *Handler) pushWAFRules(w http.ResponseWriter, r *http.Request) {
	if h.wafEngine == nil {
		http.Error(w, "WAF engine not initialized", http.StatusInternalServerError)
		return
	}
	var in wafRulesPush
	// 16MB：主控侧单包明文限 2MB，active+previous 两份 base64 之后约 5.4MB，
	// 再留一倍余量。上限的意义是别让一次误传把节点内存打爆，不是抠字节。
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&in); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	active, err := decodeWAFPackage(in.Active)
	if err != nil {
		// 拒绝整包而不是接受半套：半套规则会让面板以为新包已生效。
		http.Error(w, "active 包不可用: "+err.Error(), http.StatusBadRequest)
		return
	}
	var previous *waf.Compiled
	if in.Previous != "" {
		if previous, err = decodeWAFPackage(in.Previous); err != nil {
			http.Error(w, "previous 包不可用: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	h.wafEngine.SetPackages(active, previous)

	if err := h.saveWAFPackageState(in); err != nil {
		// 换表已经生效，落盘失败只影响"重启后回到这一份"，必须报出来而不是返回 ok。
		log.Printf("WAF package persist failed: %v", err)
		jsonResp(w, http.StatusOK, map[string]any{
			"status":           "applied-not-persisted",
			"persist_error":    err.Error(),
			"active_version":   active.Version(),
			"previous_version": versionOrEmpty(previous),
		})
		return
	}
	log.Printf("WAF 规则包已热更新：active=%s previous=%s", active.Version(), versionOrEmpty(previous))
	jsonResp(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"active_version":   active.Version(),
		"previous_version": versionOrEmpty(previous),
	})
}

func (h *Handler) saveWAFPackageState(in wafRulesPush) error {
	if h.wafPackagePath == "" {
		return nil
	}
	// 上一次存档里的 previous 要继承下来：只更新 active 的下发不带 previous，
	// 直接覆盖会让旧档消失，灰度比例与"回滚到上一版"就同时失效。
	if data, err := os.ReadFile(h.wafPackagePath); err == nil {
		var old wafPackageFile
		if json.Unmarshal(data, &old) == nil && in.Previous == "" {
			in.Previous = old.Previous
		}
	}
	f := wafPackageFile{Active: in.Active, Previous: in.Previous, SavedAt: time.Now().UTC().Format(time.RFC3339)}
	return writeStateAtomic(h.wafPackagePath, f)
}

// updateWAFConfig 接收面板下发的策略补丁。逐字段 patch（指针），缺失字段保持原值 ——
// 与 updateCCConfig 同一个理由：漏一个 enabled 就静默关掉整段防护是不可接受的。
func (h *Handler) updateWAFConfig(w http.ResponseWriter, r *http.Request) {
	if h.wafEngine == nil {
		http.Error(w, "WAF engine not initialized", http.StatusInternalServerError)
		return
	}
	var patch waf.PolicyPatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&patch); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	pol := h.wafEngine.UpdatePolicy(patch)
	if err := writeStateAtomic(h.wafStatePath, pol); err != nil {
		log.Printf("WAF config persist failed: %v", err)
		jsonResp(w, http.StatusOK, map[string]any{
			"policy": pol, "effective": h.wafEngine.Effective(),
			"status": "applied-not-persisted", "persist_error": err.Error(),
		})
		return
	}
	jsonResp(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"policy":    pol,
		"effective": h.wafEngine.Effective(),
		"packages":  h.wafEngine.Packages(),
	})
}

// wafStatsView 是本节点 WAF 的对外读数，同时用于 GET /edge/waf/stats 与周期上报。
type wafStatsView struct {
	Policy    waf.Policy          `json:"policy"`
	Packages  waf.PackageReadings `json:"packages"`
	Effective []string            `json:"effective"`
	Hits      []waf.HitRow        `json:"hits"`
	Observe   uint64              `json:"observe_total"`
	Blocked   uint64              `json:"blocked_total"`
	Catalog   waf.RulePackage     `json:"catalog,omitempty"`
	At        string              `json:"at"`
}

// wafStatsData 取读数。withCatalog=false 时不拷规则目录：目录是包内容（几百条
// id/名称/描述/作用域），主控库里本来就有，没必要让每台节点每 10 秒回传一份。
func (h *Handler) wafStatsData(withCatalog bool) wafStatsView {
	v := wafStatsView{Effective: []string{}, Hits: []waf.HitRow{}}
	if h.wafEngine == nil {
		return v
	}
	v.Policy = h.wafEngine.GetPolicy()
	v.Packages = h.wafEngine.Packages()
	v.Effective = h.wafEngine.Effective()
	v.Hits, v.Observe, v.Blocked = h.wafEngine.Hits()
	if withCatalog {
		v.Catalog = h.wafEngine.Catalog()
		if v.Catalog.Rules == nil {
			v.Catalog.Rules = []waf.ManagedRule{}
		}
		if v.Catalog.Sets == nil {
			v.Catalog.Sets = []waf.RuleSet{}
		}
	}
	v.At = time.Now().UTC().Format(time.RFC3339)
	return v
}

func (h *Handler) wafStats(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, h.wafStatsData(true))
}

// wafReportData 是周期上报里的 WAF 段。
//
// hits 全量保留：主控不回连边缘取数，边缘不上报面板就永远看不到 —— 少带一条
// 就等于"这条规则没命中过"，那是假结论。
func (h *Handler) wafReportData() wafStatsView {
	return h.wafStatsData(false)
}
