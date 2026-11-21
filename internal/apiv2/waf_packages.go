package apiv2

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"cdn/internal/config"
	"cdn/internal/master"
	"cdn/internal/secure"
	"cdn/internal/waf"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// WAF 托管规则包（平台级，只有管理员能维护）。
//
// 库里的 payload 是密文（secure.Encrypt 的产物），与内置 rules.enc 同一种格式：
// 规则文本本身就是"这台产品是自研的"的指纹，明文进库等于把指纹交给任何拿到备份的人。
// 下发给边缘的也是密文，边缘自己解密编译 —— 主控只管搬运密文，从不看明文规则长什么样。
//
// 「至多一个 enabled」靠激活事务保证（先全表清掉，再置这一行为真），不靠索引：
// MySQL/MariaDB 都没有部分索引，而 UNIQUE 也管不了多行 FALSE。
// ---------------------------------------------------------------------------

const (
	// wafPackageMaxPlain 是单个规则包明文上限。包结构本身有 256 条规则 × 32 条正则的
	// 硬上限（waf.CompilePackage），2MB 是"正常维护的包"与"往上灌垃圾"的分界。
	wafPackageMaxPlain = 2 << 20
	// wafPushTimeout 是整包下发的超时。master.post 里那个 10 秒是按 CC/XDP 那种几百字节的
	// 配置写的，几 MB 的包在跨机房慢链路上真的传不完。
	wafPushTimeout = 90 * time.Second
)

// wafPkgPair 是当前该下发的那两份包。previous 是灰度分流的旧档，也是"整代理锁定旧包"
// 的唯一可选值来源 —— 没有它就只能全量切，出问题只能整包换回去。
type wafPkgPair struct {
	Active       *waf.Compiled
	ActiveCipher []byte
	// ActiveFromDB=false 表示库里没有启用的行，活动包仍是出厂那一份。
	ActiveFromDB bool

	Previous       *waf.Compiled
	PreviousCipher []byte
	// BuiltinVersion 恒有值：面板要能认出"这台节点跑的是出厂包"这件事。
	BuiltinVersion string
}

// pushBody 拼出边缘 POST /edge/waf/rules 的请求体。没有旧档就整个不带 previous 字段：
// 边缘的语义是"缺省=保持节点现有旧档"，显式传空串反而是同一个意思，少一个字段少一种误解。
func (p *wafPkgPair) pushBody() map[string]any {
	body := map[string]any{"active": base64.StdEncoding.EncodeToString(p.ActiveCipher)}
	if len(p.PreviousCipher) > 0 {
		body["previous"] = base64.StdEncoding.EncodeToString(p.PreviousCipher)
	}
	return body
}

// versions 返回策略里 rules_version 允许出现的值（空串=跟随活动包）。
func (p *wafPkgPair) versions() []string {
	out := []string{""}
	add := func(v string) {
		if v == "" {
			return
		}
		for _, e := range out {
			if e == v {
				return
			}
		}
		out = append(out, v)
	}
	if p.Active != nil {
		add(p.Active.Version())
	}
	if p.Previous != nil {
		add(p.Previous.Version())
	}
	add(p.BuiltinVersion)
	return out
}

// wafPkgCache 缓存已编译的包：正则有几百条量级，每次渲染配置页都重新编译没必要。
// 键取"启用行与旧档行的 id+updated_at"，改包、换启用、删行都会自然改掉它 ——
// 在写路径上记得清缓存这种约定，漏一处就是面板从此看不到新包。
type wafPkgCache struct {
	mu   sync.Mutex
	key  string
	pair *wafPkgPair
}

var wafPackages wafPkgCache

func (c *wafPkgCache) get(ctx context.Context, db *sql.DB) (*wafPkgPair, error) {
	key, err := wafPkgKey(ctx, db)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pair != nil && c.key == key {
		return c.pair, nil
	}
	pair, err := buildWafPkgPair(ctx, db)
	if err != nil {
		// 建不出新的也不清旧的：坏包只该让引用它的那一次请求报错，
		// 清掉缓存会让所有读接口跟着一起失败。
		return nil, err
	}
	c.key, c.pair = key, pair
	return pair, nil
}

// wafPkgKey 只查元数据，不碰 payload。
func wafPkgKey(ctx context.Context, db *sql.DB) (string, error) {
	var b strings.Builder
	for _, q := range []string{
		`SELECT CONCAT('a', IFNULL(GROUP_CONCAT(CONCAT(id, ':', UNIX_TIMESTAMP(updated_at))
			ORDER BY activated_at DESC SEPARATOR '|'), '')) FROM waf_rule_packages WHERE enabled`,
		`SELECT CONCAT('p', IFNULL(GROUP_CONCAT(CONCAT(id, ':', UNIX_TIMESTAMP(updated_at))
			ORDER BY activated_at DESC SEPARATOR '|'), ''))
			FROM waf_rule_packages WHERE NOT enabled AND activated_at IS NOT NULL`,
	} {
		var s string
		if err := db.QueryRowContext(ctx, q).Scan(&s); err != nil {
			return "", err
		}
		b.WriteString(s)
	}
	return b.String(), nil
}

// latestActivatedRow 取最近一次激活的行。enabled=true 拿当前活动包，false 拿旧档。
// 没有符合的行返回全零值（不是 error）：库里一行都没有是升级完的初始状态。
func latestActivatedRow(ctx context.Context, db *sql.DB, enabled bool) (id string, cipher []byte, err error) {
	cond := "enabled"
	if !enabled {
		cond = "NOT enabled AND activated_at IS NOT NULL"
	}
	err = db.QueryRowContext(ctx,
		`SELECT id, payload FROM waf_rule_packages WHERE `+cond+
			` ORDER BY activated_at DESC LIMIT 1`).Scan(&id, &cipher)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	return id, cipher, nil
}

func compileWafPackage(cipher []byte, which string) (*waf.Compiled, error) {
	c, err := waf.CompilePackageEncrypted(cipher)
	if err != nil {
		// 能走到这里说明库里的行是绕过接口写进去的（正常路径在上传时就编译过一遍）。
		return nil, NewApiError("internal_error", which+"规则包不可用: "+err.Error())
	}
	return c, nil
}

func buildWafPkgPair(ctx context.Context, db *sql.DB) (*wafPkgPair, error) {
	pair := &wafPkgPair{BuiltinVersion: waf.BuiltinCatalog().Version}
	_, cipher, err := latestActivatedRow(ctx, db, true)
	if err != nil {
		return nil, err
	}
	if cipher != nil {
		pair.ActiveFromDB = true
		pair.ActiveCipher = cipher
	} else {
		pair.ActiveCipher = waf.BuiltinEncrypted()
	}
	if pair.Active, err = compileWafPackage(pair.ActiveCipher, "启用的"); err != nil {
		return nil, err
	}
	_, pcipher, err := latestActivatedRow(ctx, db, false)
	if err != nil {
		return nil, err
	}
	switch {
	case pcipher != nil:
		if pair.Previous, err = compileWafPackage(pcipher, "旧档"); err != nil {
			return nil, err
		}
		pair.PreviousCipher = pcipher
	case pair.ActiveFromDB:
		// 只激活过一次：旧档回落出厂包。灰度于是变成"新包 vs 出厂包"，这正是
		// "先切 10% 域名试试"想要的对照，也保证"取消启用"永远有个地方可回。
		pair.PreviousCipher = waf.BuiltinEncrypted()
		if pair.Previous, err = compileWafPackage(pair.PreviousCipher, "出厂"); err != nil {
			return nil, err
		}
	}
	return pair, nil
}

// wafPackageRow 是列表里的一行（不含 payload）。
type wafPackageRow struct {
	ID          string  `json:"id"`
	Version     string  `json:"version"`
	Notes       string  `json:"notes"`
	RuleCount   int     `json:"rule_count"`
	SetCount    int     `json:"set_count"`
	Enabled     bool    `json:"enabled"`
	SizeBytes   int     `json:"size_bytes"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	ActivatedAt *string `json:"activated_at"`
}

// ── 管理员接口 ──────────────────────────────────────────────────────────────

type adminWafHandler struct {
	db     *sql.DB
	pusher *master.Pusher
	nodes  *NodeRepo
}

func (h *adminWafHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v2/admin/waf/packages":
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	case "/api/v2/admin/waf/packages/push":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.pushCurrent(w, r)
		return
	case "/api/v2/admin/waf/nodes":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.nodePackages(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/admin/waf/packages/")
	id, action, hasAction := strings.Cut(rest, "/")
	if id == "" || id == "push" {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if !hasAction {
		switch r.Method {
		case http.MethodGet:
			h.getOne(w, r, id)
		case http.MethodPatch:
			h.patch(w, r, id)
		case http.MethodDelete:
			h.delete(w, r, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if action != "activate" || r.Method != http.MethodPost {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	h.activate(w, r, id)
}

func (h *adminWafHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, version, notes, rule_count, set_count, enabled, LENGTH(payload),
			created_at, updated_at, activated_at
			FROM waf_rule_packages ORDER BY activated_at DESC, updated_at DESC, version DESC`)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer rows.Close()
	items := []wafPackageRow{}
	for rows.Next() {
		var (
			row              wafPackageRow
			created, updated time.Time
			activated        sql.NullTime
		)
		if err := rows.Scan(&row.ID, &row.Version, &row.Notes, &row.RuleCount, &row.SetCount,
			&row.Enabled, &row.SizeBytes, &created, &updated, &activated); err != nil {
			WriteError(w, err)
			return
		}
		row.CreatedAt = created.UTC().Format(rfc3339Milli)
		row.UpdatedAt = updated.UTC().Format(rfc3339Milli)
		row.ActivatedAt = formatNullTime(activated)
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, err)
		return
	}
	builtin := waf.BuiltinCatalog()
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"builtin": map[string]any{
			"version": builtin.Version, "rule_count": len(builtin.Rules), "set_count": len(builtin.Sets),
		},
		// active 是"现在下发出去的那一份"：库里没有启用行时就是出厂包。
		// 面板顶部那行状态必须报这个，而不是报列表第一行。
		"active": h.activeReading(r),
	})
}

// activeReading 给出当前生效包的读数。坏包不让整个状态栏空掉：报出厂档那一份，
// 并把原因写在 error 里，管理员才知道要去修哪一行。
func (h *adminWafHandler) activeReading(r *http.Request) map[string]any {
	pair, err := wafPackages.get(r.Context(), h.db)
	if err != nil {
		return map[string]any{"version": waf.BuiltinCatalog().Version, "from_db": false, "error": err.Error()}
	}
	out := map[string]any{
		"version":    pair.Active.Version(),
		"from_db":    pair.ActiveFromDB,
		"rule_count": len(pair.Active.RuleIDs()),
	}
	if pair.Previous != nil {
		out["previous_version"] = pair.Previous.Version()
	}
	return out
}

func (h *adminWafHandler) getOne(w http.ResponseWriter, r *http.Request, id string) {
	var (
		row          wafPackageRow
		cipher       []byte
		created, upd time.Time
		activated    sql.NullTime
	)
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, version, notes, rule_count, set_count, enabled, LENGTH(payload), payload,
			created_at, updated_at, activated_at
			FROM waf_rule_packages WHERE id = ?`, id).
		Scan(&row.ID, &row.Version, &row.Notes, &row.RuleCount, &row.SetCount, &row.Enabled,
			&row.SizeBytes, &cipher, &created, &upd, &activated)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	row.CreatedAt = created.UTC().Format(rfc3339Milli)
	row.UpdatedAt = upd.UTC().Format(rfc3339Milli)
	row.ActivatedAt = formatNullTime(activated)
	// 明文只回给平台管理员（这条路由挂在 RequireAdminSession 上）：维护规则的人要的就是
	// 能改回来再传上去的那份文本。对客接口一律不给，理由见 waf.Compiled.Package 不导出正则。
	plain, err := secure.Decrypt(cipher)
	if err != nil {
		WriteError(w, NewApiError("internal_error", "规则包解密失败（主控密钥与入库时不一致？）"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"package": row, "rules": json.RawMessage(plain)})
}

// readWafBody 读规则包上传体。不能用 readBody：它按 1MiB 限，那是给域名/节点这种
// 几百字节资源体写的，规则包明文允许到 2MiB。
func readWafBody(r *http.Request, known []string) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, wafPackageMaxPlain+1))
	if err != nil {
		return nil, NewApiError("invalid_json", "请求体读取失败")
	}
	if len(raw) > wafPackageMaxPlain {
		return nil, NewApiError("validation_failed", fmt.Sprintf("请求体超过 %d 字节上限", wafPackageMaxPlain))
	}
	if len(raw) == 0 {
		return nil, NewApiError("invalid_json", "请求体不能为空")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, NewApiError("invalid_json", "请求体必须是 JSON 对象")
	}
	if bad := UnknownFields(raw, known); len(bad) > 0 {
		return nil, unknownFieldError(bad)
	}
	return json.RawMessage(raw), nil
}

// parseWafPackage 校验并规范化规则包本体，返回包对象与可直接入库的密文。
// 编译不过就整包拒绝：半套规则比旧规则危险，面板会以为新包已经生效。
func parseWafPackage(pkgRaw json.RawMessage) (*waf.RulePackage, []byte, error) {
	if len(pkgRaw) == 0 || string(pkgRaw) == "null" {
		return nil, nil, fieldError("package", "必须带 package 字段（规则包 JSON 本体）")
	}
	if _, err := waf.CompilePackage(pkgRaw); err != nil {
		return nil, nil, fieldError("package", err.Error())
	}
	// 存规范化后的 JSON，而不是管理员贴来的原始字节：同一份内容两次上传（一次 CRLF、
	// 一次缩进不同）如果落成不同密文，边缘就会把同一版包当成两个包，灰度与回滚同时乱掉。
	//
	// 注意这里必须从 RulePackage 重新序列化，不能用 Compiled.Package()：那个是"目录视图"，
	// 按设计不含正则本体（见其注释），拿它入库等于传上去一个编译不了的包。
	var pkg waf.RulePackage
	if err := json.Unmarshal(pkgRaw, &pkg); err != nil {
		return nil, nil, fieldError("package", "规则包不是合法 JSON: "+err.Error())
	}
	canonical, err := json.Marshal(pkg)
	if err != nil {
		return nil, nil, err
	}
	cipher, err := secure.Encrypt(canonical)
	if err != nil {
		return nil, nil, err
	}
	return &pkg, cipher, nil
}

func (h *adminWafHandler) create(w http.ResponseWriter, r *http.Request) {
	raw, err := readWafBody(r, []string{"notes", "package", "activate"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var in struct {
		Notes    string          `json:"notes"`
		Package  json.RawMessage `json:"package"`
		Activate bool            `json:"activate"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		WriteError(w, err)
		return
	}
	pkg, cipher, err := parseWafPackage(in.Package)
	if err != nil {
		WriteError(w, err)
		return
	}
	in.Notes = strings.TrimSpace(in.Notes)
	if len(in.Notes) > 500 {
		WriteError(w, fieldError("notes", "最长 500 字节"))
		return
	}
	id := uuid.NewString()
	_, err = h.db.ExecContext(r.Context(),
		`INSERT INTO waf_rule_packages (id, version, notes, payload, rule_count, set_count)
			VALUES (?, ?, ?, ?, ?, ?)`, id, pkg.Version, in.Notes, cipher, len(pkg.Rules), len(pkg.Sets))
	if ae := classifyOr(err, map[string]string{"waf_rule_packages_version_uq": "conflict"}); ae != nil {
		if apiErr, ok := ae.(*ApiError); ok && apiErr.Code == "conflict" {
			apiErr.Message = "已经有同版本的包了（" + pkg.Version + "）。改版本号再传，或直接启用已有那一行。"
		}
		WriteError(w, ae)
		return
	}
	res := map[string]any{"id": id, "version": pkg.Version, "rule_count": len(pkg.Rules), "set_count": len(pkg.Sets)}
	if in.Activate {
		push, err := h.activateAndPush(r.Context(), id)
		if err != nil {
			WriteError(w, err)
			return
		}
		res["enabled"] = true
		res["push"] = push
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *adminWafHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	raw, err := readWafBody(r, []string{"notes", "package"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var cur struct {
		Version string
		Enabled bool
	}
	if err := h.db.QueryRowContext(r.Context(),
		`SELECT version, enabled FROM waf_rule_packages WHERE id = ?`, id).Scan(&cur.Version, &cur.Enabled); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	var in struct {
		Notes   *string         `json:"notes"`
		Package json.RawMessage `json:"package"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		WriteError(w, err)
		return
	}
	if in.Notes == nil && len(in.Package) == 0 {
		WriteError(w, NewApiError("validation_failed", "至少要改 notes 或 package"))
		return
	}
	if in.Notes != nil {
		notes := strings.TrimSpace(*in.Notes)
		if len(notes) > 500 {
			WriteError(w, fieldError("notes", "最长 500 字节"))
			return
		}
		if _, err := h.db.ExecContext(r.Context(),
			`UPDATE waf_rule_packages SET notes = ? WHERE id = ?`, notes, id); err != nil {
			WriteError(w, err)
			return
		}
	}
	if len(in.Package) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "version": cur.Version})
		return
	}
	pkg, cipher, err := parseWafPackage(in.Package)
	if err != nil {
		WriteError(w, err)
		return
	}
	if _, err := h.db.ExecContext(r.Context(),
		`UPDATE waf_rule_packages SET version = ?, payload = ?, rule_count = ?, set_count = ? WHERE id = ?`,
		pkg.Version, cipher, len(pkg.Rules), len(pkg.Sets), id); err != nil {
		WriteError(w, classifyOr(err, map[string]string{"waf_rule_packages_version_uq": "conflict"}))
		return
	}
	res := map[string]any{"id": id, "version": pkg.Version, "rule_count": len(pkg.Rules), "set_count": len(pkg.Sets)}
	// 改的正是启用中那一份：必须重推全网，否则节点还在跑旧内容而面板显示新内容 ——
	// 那种不一致比不下发更糟，因为它让"已经生效"这句话变成假的。
	if cur.Enabled {
		push, err := h.pushPairs(r.Context())
		if err != nil {
			WriteError(w, err)
			return
		}
		res["push"] = push
		res["repushed"] = true
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *adminWafHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	var enabled bool
	if err := h.db.QueryRowContext(r.Context(),
		`SELECT enabled FROM waf_rule_packages WHERE id = ?`, id).Scan(&enabled); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if enabled {
		// 删掉正在用的那一份等于让全网回到出厂包 —— 那是"启用另一份"的动作，
		// 不该是删除的副作用。
		WriteError(w, NewApiError("in_use", "这一份正在启用中。先启用别的包，再删除它。"))
		return
	}
	if _, err := h.db.ExecContext(r.Context(), `DELETE FROM waf_rule_packages WHERE id = ?`, id); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (h *adminWafHandler) activate(w http.ResponseWriter, r *http.Request, id string) {
	push, err := h.activateAndPush(r.Context(), id)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "push": push})
}

// activateAndPush 换启用行并下发。三步在一个事务里：清掉旧启用行、置新行、记激活时刻。
// 中途失败必须整体回滚，否则会留下两行 enabled（下发时取哪一份就变成运气）。
func (h *adminWafHandler) activateAndPush(ctx context.Context, id string) (map[string]any, error) {
	var version string
	if err := h.db.QueryRowContext(ctx,
		`SELECT version FROM waf_rule_packages WHERE id = ?`, id).Scan(&version); err != nil {
		return nil, notFoundOr(err)
	}
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE waf_rule_packages SET enabled = FALSE WHERE enabled`); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE waf_rule_packages SET enabled = TRUE, activated_at = NOW(6) WHERE id = ?`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return h.pushPairs(ctx)
}

// pushPairs 把"现在应该生效的那两份包"推给全部启用节点。
func (h *adminWafHandler) pushPairs(ctx context.Context) (map[string]any, error) {
	if h.pusher == nil {
		return nil, NewApiError("unavailable", "主控未启用节点推送，规则包没能下发")
	}
	pair, err := wafPackages.get(ctx, h.db)
	if err != nil {
		return nil, err
	}
	nodes, err := allEnabledNodes(ctx, h.db, h.nodes)
	if err != nil {
		return nil, err
	}
	return pushWafPackages(h.pusher, nodes, pair), nil
}

// pushCurrent 是 POST /api/v2/admin/waf/packages/push：不改变启用行，只把当前该生效的
// 那份重推一遍。节点当时不在线、后来装好了，用的就是这个入口。
func (h *adminWafHandler) pushCurrent(w http.ResponseWriter, r *http.Request) {
	res, err := h.pushPairs(r.Context())
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// pushWafPackages 并发下发，按节点保留边缘给的原因（整包被拒时原因在响应体里）。
//
// 逐节点结果必须回给前端："启用了"不等于"全网都在用"。某个节点没接住意味着它还在跑旧包，
// 而攻击流量不会因为它没更新就绕开它。
func pushWafPackages(p *master.Pusher, nodes []*config.Node, pair *wafPkgPair) map[string]any {
	body := pair.pushBody()
	per := make(map[string]map[string]any, len(nodes))
	var (
		mu sync.Mutex
		wg sync.WaitGroup
		ok int
	)
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			status, respBody, err := p.PostToNodeResp(n, "/edge/waf/rules", body, wafPushTimeout)
			item := map[string]any{}
			switch {
			case err != nil:
				item["status"] = "failed"
				item["error"] = err.Error()
				log.Printf("[WAF] 下发规则包到 %s (%s) 失败: %v", nodeLabel(n), n.Address, err)
			case status >= 400:
				msg := strings.TrimSpace(string(respBody))
				if msg == "" {
					msg = fmt.Sprintf("边缘返回 %d", status)
				}
				item["status"] = "rejected"
				item["error"] = msg
				log.Printf("[WAF] 节点 %s 拒收规则包 (%d): %s", nodeLabel(n), status, msg)
			default:
				// 边缘可能回 applied-not-persisted（换表成功、落盘失败）：原样透传，
				// 不能压成 ok —— 那种节点一重启就回到上一份包。
				var edge map[string]any
				if json.Unmarshal(respBody, &edge) == nil {
					for k, v := range edge {
						item[k] = v
					}
				}
				if s, _ := item["status"].(string); s == "" || s == "ok" {
					item["status"] = "ok"
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}
			mu.Lock()
			per[nodeLabel(n)] = item
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	out := map[string]any{
		"nodes": len(nodes), "ok": ok, "per_node": per,
		"active_version": pair.Active.Version(),
	}
	if pair.Previous != nil {
		out["previous_version"] = pair.Previous.Version()
	}
	return out
}

// pushWafPairToNode 向单个节点补发当前包对（新节点接入、onboard 补发用）。
// 走 PostToNodeResp：包是 MB 级，p.post 里那个 10 秒是按小配置写的；而且边缘拒收时
// 原因在响应体里，只回 "edge returned 400" 等于把最有用的那句话扔掉了。
func pushWafPairToNode(p *master.Pusher, n *config.Node, pair *wafPkgPair) error {
	status, body, err := p.PostToNodeResp(n, "/edge/waf/rules", pair.pushBody(), wafPushTimeout)
	if err != nil {
		return err
	}
	if status >= 400 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = fmt.Sprintf("边缘返回 %d", status)
		}
		return errors.New(msg)
	}
	return nil
}

// nodePackages 报每台节点当前实际装载的包版本（数据来自节点上报，主控不回连节点）。
// 这是"新包真的全网生效了吗"唯一的证据来源。
func (h *adminWafHandler) nodePackages(w http.ResponseWriter, r *http.Request) {
	nodes, err := allEnabledNodes(r.Context(), h.db, h.nodes)
	if err != nil {
		WriteError(w, err)
		return
	}
	type reading struct {
		Node        string `json:"node"`
		IP          string `json:"ip"`
		Active      string `json:"active_version"`
		Previous    string `json:"previous_version"`
		Builtin     string `json:"builtin_version"`
		Reported    string `json:"reported_at,omitempty"`
		MatchesPlan *bool  `json:"matches_active,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	want := ""
	if pair, err := wafPackages.get(r.Context(), h.db); err == nil {
		want = pair.Active.Version()
	} else {
		log.Printf("[WAF] 读取启用规则包失败: %v", err)
	}
	rs := reportField[wafNodeStats](nodes, reportWAFStats)
	items := make([]reading, 0, len(rs))
	for _, x := range rs {
		it := reading{Node: nodeLabel(x.Node), IP: x.Node.IP}
		if x.Err != nil {
			it.Error = x.Err.Error()
		} else {
			it.Active = x.Data.Packages.Active
			it.Previous = x.Data.Packages.Previous
			it.Builtin = x.Data.Packages.Builtin
			it.Reported = x.Data.At
			if want != "" {
				m := it.Active == want
				it.MatchesPlan = &m
			}
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"expected_version": want, "items": items, "total": len(items)})
}
