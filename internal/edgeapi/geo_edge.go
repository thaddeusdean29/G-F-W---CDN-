package edgeapi

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"cdn/internal/geo"
)

// 本文件是区域规则（按国家封禁/只放行）在边缘的一侧：
//   - POST /edge/geo/table   主控下发的编译前缀表（gzip+base64，指纹寻址）；空载荷表示撤表
//   - POST /edge/geo/config  平台总闸 + 整节点策略 + 例外清单
//   - GET  /edge/geo/stats   本节点实际装载与判定读数（同一份内容进周期上报）
//   - 请求路径上的判定：wafProxy.check 第二步之后、托管规则之前
//
// 两份配置都落盘：cdnedge 一重启（含升级）就回到"没配过区域规则"的话，面板上下发的
// 封禁只维持到下一次重启为止，而这恰好是最没人会去核对的时候。
//
// 边缘不打开国家级地理库：它只吃主控算好的那张表。库在节点上自己查一遍，
// 就意味着"面板显示的那张表"和"网卡上生效的那张表"是两条代码路径算出来的。

// geoTablePushLimit 是前缀表下发体的上限。全库所有国家约 4MB 原始 / 1.5MB gz，
// base64 之后约 2MB；上限给到 32MB 是为了"选满国家也不会被拒"，
// 同时拦住一次误传把节点内存打爆。
const geoTablePushLimit = 32 << 20

// geoObserveLogWindow 是观察模式同一个国家的日志限速窗口。
const geoObserveLogWindow = 30 * time.Second

// SetGeoStatePaths 记录两份存档路径并立即恢复。必须在对外服务之前调用。
func (h *Handler) SetGeoStatePaths(configPath, tablePath string) {
	h.geoConfigPath = configPath
	h.geoTablePath = tablePath
	h.restoreGeo()
}

func (h *Handler) restoreGeo() {
	if h.geoGuard == nil {
		return
	}
	// 恢复完把四层喂一遍。用 defer 是因为下面有几条"表没恢复成"的提前 return——
	// 那正是最需要四层跟着实况走的时候：内存里的表没装上，网卡上的 trie 也该是空的。
	// 漏掉这一步的话，节点每次重启四层都是裸的，直到主控下一次下发才补上，
	// 而面板上那条规则从头到尾都显示着"已生效"。
	defer h.applyGeoL4("启动恢复")
	if h.geoConfigPath != "" {
		data, err := os.ReadFile(h.geoConfigPath)
		switch {
		case os.IsNotExist(err):
			// 从没下发过：保持"未配置"，判定路径直接跳过，行为与升级前一致。
		case err != nil:
			log.Printf("GEO config restore: read %s: %v", h.geoConfigPath, err)
		default:
			var cfg geo.ConfigPayload
			if err := json.Unmarshal(data, &cfg); err != nil {
				log.Printf("GEO config restore: parse %s: %v (按未配置运行)", h.geoConfigPath, err)
			} else if err := h.geoGuard.SetConfig(cfg); err != nil {
				log.Printf("GEO config restore: %v (按未配置运行)", err)
			} else {
				log.Printf("GEO 策略已从 %s 恢复：总闸=%v 节点规则=%v mode=%s action=%s 例外=%d 条",
					h.geoConfigPath, cfg.ScopeEnabled, cfg.Node.Enabled, cfg.Node.Mode, cfg.Node.Action,
					len(cfg.Node.Exceptions))
			}
		}
	}
	if h.geoTablePath != "" {
		data, err := os.ReadFile(h.geoTablePath)
		switch {
		case os.IsNotExist(err):
		case err != nil:
			log.Printf("GEO table restore: read %s: %v", h.geoTablePath, err)
		default:
			var p geo.TablePayload
			if err := json.Unmarshal(data, &p); err != nil {
				log.Printf("GEO table restore: parse %s: %v (未装载表)", h.geoTablePath, err)
				return
			}
			tbl, err := h.geoGuard.SetTablePayload(p)
			if err != nil {
				// 恢复不出表而策略却是开着的，判定就会全部记成"没有表"：
				// 这行日志是这件事唯一的现场证据。
				log.Printf("GEO table restore: %v (策略仍启用，来源一律按未知放行)", err)
				return
			}
			log.Printf("GEO 前缀表已从 %s 恢复：指纹=%s %d 条 %v 国家",
				h.geoTablePath, tbl.Fingerprint, tbl.Total(), tbl.Countries)
		}
	}
}

// geoStatsData 是本节点的区域判定读数，用于 GET /edge/geo/stats 和周期上报（同一个形状）。
func (h *Handler) geoStatsData() geo.Readings {
	if h.geoGuard == nil {
		return geo.Readings{At: time.Now().UTC().Format(time.RFC3339), Countries: []geo.CountryCount{}}
	}
	return h.geoGuard.Stats()
}

func (h *Handler) geoStats(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, h.geoStatsData())
}

// pushGeoTable 装载或撤下主控编译好的前缀表。
//
// 换表成功的判据是"解出来的指纹等于下发的指纹"（在 Guard 里核对），
// 不是"我收到了"：一张少了几万条的表看起来完全正常工作，只在恰好有人来自被丢掉那段地址时才现形。
func (h *Handler) pushGeoTable(w http.ResponseWriter, r *http.Request) {
	if h.geoGuard == nil {
		http.Error(w, "geo guard not initialized", http.StatusInternalServerError)
		return
	}
	var in geo.TablePayload
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, geoTablePushLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 空载荷 = 撤表：当前没有任何启用的区域规则时主控不发这张表，
	// 但不发不等于已经撤下来——不撤，节点会一直带着几十万条一条也不会执行的前缀跑。
	if in.Fingerprint == "" && in.GzipB64 == "" {
		h.geoGuard.ClearTable()
		// 撤表必须一路撤到网卡：内存里的表撤了而 trie 还留着，节点会继续丢一个
		// 已经取消封禁的国家的包，而面板上那条规则已经不存在了。
		h.applyGeoL4("主控撤表")
		if err := h.clearGeoTableState(); err != nil {
			log.Printf("GEO table clear: 已撤下但存档没清掉 %s: %v（重启会重新装载旧表）", h.geoTablePath, err)
			jsonResp(w, http.StatusOK, geo.EdgeTableResult{
				Status: "cleared-not-persisted", AppliedButNotStored: true,
				Error: "存档未清除，重启后会回到旧表: " + err.Error(),
			})
			return
		}
		log.Printf("GEO 前缀表已撤下（当前没有启用的区域规则）")
		jsonResp(w, http.StatusOK, geo.EdgeTableResult{Status: "cleared"})
		return
	}
	tbl, err := h.geoGuard.SetTablePayload(in)
	if err != nil {
		// 拒收整张表并继续用旧的：半张表会让面板以为"这个国家封了一半"。
		log.Printf("GEO table push rejected: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := geo.EdgeTableResult{Status: "ok", Fingerprint: tbl.Fingerprint, Total: tbl.Total()}
	// 表刚装载就同步把四层喂一遍：50 万条前缀写进 trie 是秒级的事，而下发体的超时按
	// MB 级载荷给到了 90 秒，够。换成后台协程的话，这个回执就成了谎——主控看到 ok 时
	// 网卡上还是上一轮的树。
	h.applyGeoL4("换表")
	if err := writeStateAtomic(h.geoTablePath, in); err != nil {
		// 表已经生效，只是重启后回不到这一份——必须单独说，不能让"下发成功"盖住它。
		res.Status = "applied-not-persisted"
		res.AppliedButNotStored = true
		res.Error = "换表成功但落盘失败，重启后回到旧表: " + err.Error()
		log.Printf("GEO table persist failed: %v", err)
	}
	if res.Status == "ok" {
		log.Printf("GEO 前缀表已装载：指纹=%s %d 条 %v 国家（主控编译于 %s）",
			tbl.Fingerprint, tbl.Total(), tbl.Countries, in.Built)
	}
	jsonResp(w, http.StatusOK, res)
}

func (h *Handler) clearGeoTableState() error {
	if h.geoTablePath == "" {
		return nil
	}
	if err := os.Remove(h.geoTablePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// putGeoConfig 接收平台总闸 + 整节点策略 + 例外清单。
//
// 边缘只拒一件事：例外清单编译不过。例外少认一条就是把一个本该放行的地址放到被封的位置上，
// 而主控 IP 一旦落在那里，这台节点会从集群里消失且不报错。
// 策略语义本身（observe/block、deny/allow）不在这儿二次裁决：能执行什么是主控按
// L4Enabled 算过的，边缘在这里改判就会出现"面板存了一份节点其实不认的配置"。
func (h *Handler) putGeoConfig(w http.ResponseWriter, r *http.Request) {
	if h.geoGuard == nil {
		http.Error(w, "geo guard not initialized", http.StatusInternalServerError)
		return
	}
	var in geo.ConfigPayload
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.geoGuard.SetConfig(in); err != nil {
		log.Printf("GEO config rejected: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	eff := h.geoGuard.Config()
	// 策略一变，四层该装的内容就跟着变（关掉、改观察、改 allow、换国家清单都在这儿）。
	// 放在落盘之前：落盘失败只影响"重启后回不回得到这一份"，不影响这一份当场生效。
	h.applyGeoL4("策略更新")
	if err := writeStateAtomic(h.geoConfigPath, eff); err != nil {
		log.Printf("GEO config persist failed: %v", err)
		jsonResp(w, http.StatusOK, map[string]any{
			"status":        "applied-not-persisted",
			"persist_error": err.Error(),
			"config":        eff,
		})
		return
	}
	log.Printf("GEO 节点策略已更新：总闸=%v 节点规则=%v mode=%s action=%s 国家=%v 四层意愿=%v",
		eff.ScopeEnabled, eff.Node.Enabled, eff.Node.Mode, eff.Node.Action, eff.Node.Countries, eff.L4Enabled)
	jsonResp(w, http.StatusOK, map[string]any{"status": "ok", "config": eff})
}

// ── 请求路径上的判定 ──────────────────────────────────────────────────────

// geoDecisionFor 取这个 host 该按哪条域名规则判，然后连同整节点策略一起算。
//
// 域名规则从 store 里读（和 CC 的按域名强检测同一个来源、同样的取法），不在边缘另存一份：
// 存了就要回答"两份什么时候同步"，而那正是本项目最忌讳的那类问题。
func (wp *wafProxy) geoDecisionFor(host, clientIP string) geo.Result {
	// 总闸关着时不去查域名表：这一笔只要记进 Off 就够了。
	// 直接 return 的话面板上"因为平台没开而没执行"那个数字永远是 0，
	// 看上去就像这条链路上根本没有流量经过。
	if !wp.geoGuard.ScopeEnabled() {
		return wp.geoGuard.Check(geo.Policy{}, nil)
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		// 拿不到客户端地址就不判：判定不了的请求按"未知"放行，
		// 而不是按最严的那条拦——封禁国家里合法的 IPv6 写法不该因为解析没配上就被拒。
		return geo.Result{Why: geo.WhyUnknown}
	}
	var dom geo.Policy
	if wp.geoDomains != nil && host != "" {
		if d, err := wp.geoDomains.GetByDomain(host); err == nil {
			dom = d.GeoPolicy.WithDefaults()
		}
	}
	return wp.geoGuard.Check(dom, ip)
}

// geoEnforce 在判定之后负责拦与记。返回 true 表示请求已经应答完，调用方必须直接 return。
//
// 它不受面板「启用 WAF 防护」开关控制，理由和封禁表一样：代理关掉 WAF 的意思是
// "我不想跑签名规则"，不是"把区域封禁也关掉"。
func (wp *wafProxy) geoEnforce(w http.ResponseWriter, host, clientIP, rawURI string) bool {
	if wp.geoGuard == nil || !wp.geoGuard.Configured() {
		return false
	}
	res := wp.geoDecisionFor(host, clientIP)
	if res.Why != geo.WhyHit {
		return false
	}
	if !res.Blocked {
		// 观察模式：命中已经在 Guard 里记账，这里只留一行限速的证据。
		// 不打这行的话"只记账不拦"在节点日志上完全不可见，开拦之前没有素材可看。
		if wp.geoGuard.LogOnce(res.Country, geoObserveLogWindow) {
			log.Printf("GEO OBSERVE country=%s ip=%s host=%s uri=%s (观察模式，未拦截)",
				res.Country, clientIP, host, rawURI)
		}
		return false
	}
	log.Printf("GEO BLOCK country=%s ip=%s host=%s uri=%s", res.Country, clientIP, host, rawURI)
	http.Error(w, "Forbidden", http.StatusForbidden)
	return true
}
