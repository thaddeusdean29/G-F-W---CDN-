package edgeapi

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cdn/internal/config"
	"cdn/internal/geo"
	"cdn/internal/stats"
	"cdn/internal/tengine"
	"cdn/internal/waf"
	"cdn/internal/xdp"
)

// Handler 是边缘节点接收主控推送的 HTTP 服务。
type Handler struct {
	token      string
	store      *config.Store
	generator  *tengine.Generator
	controller *tengine.Controller
	xdpMgr     *xdp.Manager
	// ab 是 XDP 自动封禁器。启动时 XDP 没挂上（.o 还没编译）的节点，面板「安装 XDP」热加载
	// 成功后才会创建它，所以必须能在运行中替换 —— 读取一律走 h.blocker()。
	ab atomic.Pointer[xdp.AutoBlocker]
	// abFactory 由 cmd/cdnedge 注入，按启动时同一套阈值新建 AutoBlocker（未 Start）。
	// 为 nil 时热安装只挂 XDP、不启用自动封禁。
	abFactory      func() *xdp.AutoBlocker
	wafEngine      *waf.Engine
	ccDefense      *waf.CCDefense
	verifyThrottle *waf.VerifyThrottle // /__cc/verify 应用层失败限速：同 IP 反复拿不到 cookie 即封

	// agentPort 是本 agent 的对外监听端口，用于 XDP 服务端口白名单。
	// 面板触发的 XDP 安装会调用 InitDefaults 开启 port_guard；不把这个端口放行，
	// 主控就再也连不上该节点。0 表示未知，此时只放行 80/443/22。
	agentPort uint16

	// XDP 安装状态跟踪
	xdpInstallMu     sync.Mutex
	xdpInstallStatus *InstallStatus

	// 面板下发的 CC / XDP 阈值存档路径。为空表示不落盘（测试）。
	// CC 配置原本只在内存里，cdnedge 一重启（含升级）就回到内置默认值，
	// XDP 阈值则被 InitDefaults 覆盖回默认值 —— 面板上显示的和节点实际执行的不一致。
	ccStatePath  string
	xdpStatePath string
	// challengeKeyPath 是 CC 挑战签名密钥的存档（主控下发的部署级密钥）。
	challengeKeyPath string

	// WAF 托管规则的两份存档：策略（面板下发）与规则包（管理员在面板维护后下发）。
	// 理由与 CC 一样 —— cdnedge 一重启就回到内置默认值的话，面板显示的和节点实跑的就不一致；
	// 规则包更严重：重启回出厂包，管理员刚下发的版本全网静默失效。
	wafStatePath   string
	wafPackagePath string

	// 区域规则（按国家封禁/只放行）的两份存档：主控下发的配置（平台总闸 + 整节点策略 +
	// 例外清单）与编译好的前缀表。不落盘的话 cdnedge 一升级就回到"没配过区域规则"，
	// 而面板上那条规则还显示着在拦——这正是本项目最忌讳的失效形态。
	geoConfigPath string
	geoTablePath  string
	// geoGuard 是本节点的区域判定运行时：当前装的是哪张表、策略是什么、每种判决各多少次。
	geoGuard *geo.Guard

	// slow 缓存上报里较重的部分（日志解析、缓存目录遍历），见 report.go。
	slow slowReport
}

// SetAgentPort 记录 agent 对外端口，供 XDP 端口白名单使用。在启动 HTTP 服务前调用。
func (h *Handler) SetAgentPort(port uint16) {
	h.agentPort = port
}

type InstallStatus struct {
	Status   string    `json:"status"`   // idle, running, success, failed
	Progress string    `json:"progress"` // 当前进度描述
	Error    string    `json:"error,omitempty"`
	Details  string    `json:"details,omitempty"`
	StartAt  time.Time `json:"start_at,omitempty"`
}

func NewHandler(
	token string,
	store *config.Store,
	generator *tengine.Generator,
	controller *tengine.Controller,
	xdpMgr *xdp.Manager,
	autoBlocker *xdp.AutoBlocker,
) *Handler {
	wafEng := waf.NewEngine()
	// 先建 h：下面的 L4 hook 要通过 h.blocker() 读当前的 AutoBlocker，而不是闭包捕获
	// 构造参数 —— 热安装 XDP 后才创建的 AutoBlocker 否则永远是 nil。
	h := &Handler{
		token:            token,
		store:            store,
		generator:        generator,
		controller:       controller,
		xdpMgr:           xdpMgr,
		wafEngine:        wafEng,
		geoGuard:         geo.NewGuard(),
		xdpInstallStatus: &InstallStatus{Status: "idle"},
	}
	// 区域判定的四层读数：面板上"网卡正在按国家丢包"那个勾，只有节点自己看得见。
	// 必须在对外服务之前注入（Guard 里那个字段不加锁）。
	h.geoGuard.SetL4Reader(h.geoL4Reader)
	// 把 L7 封禁同步下沉到 L4：WAF/CC 判定为攻击 IP 后，除了写入本进程封禁表，
	// 同时推入 XDP blocklist。下一波包在 XDP 层直接 DROP，不再进入 Tengine/内核栈，
	// 免得单波 L4 洪水打穿。xdpMgr 未加载时 (Loaded()==false) 静默跳过，不影响 L7。
	if xdpMgr != nil {
		wafEng.SetL4BlockHook(func(ip string, _ time.Duration) {
			if !xdpMgr.Loaded() {
				return
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return
			}
			_ = xdpMgr.BlockIP(parsed)
		})
		// 解封必须同时摘掉 L4，否则 XDP blocklist 里的残留会让「已解封」的 IP
		// 继续在网卡层被 DROP，且从 L7 侧再也清不掉。
		wafEng.SetL4UnblockHook(func(ip string) {
			// AutoBlocker 的记账要先清：它不依赖 XDP 是否 Loaded，而残留的记账会被
			// 落盘并在下次启动时重新封禁（见 AutoBlocker.Forget）。
			if ab := h.blocker(); ab != nil {
				ab.Forget(ip)
			}
			if !xdpMgr.Loaded() {
				return
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return
			}
			_ = xdpMgr.UnblockIP(parsed)
		})
		// L7 封禁自然到期时摘掉 L4。XDP blocklist 不存过期时刻，没有这一步，WAF/CC
		// 下沉的封禁和从其他节点同步来的封禁都会在 XDP 里永久生效。
		// AutoBlocker 自己仍在封的（它有独立的到期与阶梯）不摘，由它自己到期时处理。
		wafEng.SetL4ExpireHook(func(ip string) {
			if ab := h.blocker(); ab != nil && ab.IsBlocked(ip) {
				return
			}
			if !xdpMgr.Loaded() {
				return
			}
			if parsed := net.ParseIP(ip); parsed != nil {
				_ = xdpMgr.UnblockIP(parsed)
			}
		})
	}

	// 启用登录端点暴力破解防护（边缘节点）
	wafEng.EnableLoginBruteforceProtection(waf.LoginBruteforceConfig{
		LoginPaths: []string{
			"/api/login",      // API 登录端点
			"/api/auth/login", // 备用认证路径
		},
		SoftThreshold:  3,                // 3 次失败后记录（应用层可显示 CAPTCHA）
		HardThreshold:  5,                // 5 次失败后封禁 IP
		BanDuration:    30 * time.Minute, // 封禁 30 分钟
		WindowDuration: 10 * time.Minute, // 10 分钟时间窗口
	})

	// 启用 HTTP/2 Rapid Reset 攻击检测
	wafEng.EnableHTTP2RapidResetDetection(waf.RapidResetConfig{
		Enabled:      true,
		RSTThreshold: 100,     // 100 次 RST_STREAM/秒
		WindowSize:   1,       // 1 秒窗口
		BanDuration:  10 * 60, // 封禁 10 分钟
	})

	h.ccDefense = waf.NewCCDefense(wafEng, store)
	h.verifyThrottle = waf.NewVerifyThrottle()
	if autoBlocker != nil {
		h.adoptAutoBlocker(autoBlocker)
	}
	return h
}

// blocker 返回当前的 XDP AutoBlocker，未启用时为 nil。
func (h *Handler) blocker() *xdp.AutoBlocker {
	return h.ab.Load()
}

// SetAutoBlockerFactory 注入 AutoBlocker 构造函数，供热安装 XDP 成功后启用自动封禁。
// 在启动 HTTP 服务前调用。
func (h *Handler) SetAutoBlockerFactory(f func() *xdp.AutoBlocker) {
	h.abFactory = f
}

// adoptAutoBlocker 接管一个 AutoBlocker：接上 L7 外部封禁检查。
// AutoBlocker 到期时，如果 L7 还有更长的封禁（主控下发/WAF 判定），不能把它从 XDP 摘掉。
func (h *Handler) adoptAutoBlocker(ab *xdp.AutoBlocker) {
	if h.wafEngine != nil {
		ab.SetExternalBanCheck(h.wafEngine.IsBanned)
	}
	h.ab.Store(ab)
}

// startAutoBlockerAfterInstall 在热安装 XDP 成功后启用自动封禁。没有这一步，面板上
// 补装的 XDP 只会按静态阈值丢包，攻击源永远不会被整 IP 封掉，封禁阶梯下发也会 409。
func (h *Handler) startAutoBlockerAfterInstall() {
	if h.blocker() != nil || h.abFactory == nil {
		return
	}
	ab := h.abFactory()
	if ab == nil {
		return
	}
	h.adoptAutoBlocker(ab)
	ab.Start()
	h.SetupXDPBroadcast()
	log.Println("[XDP Install] auto-blocker started")
}

// Stop 停止 Handler 的后台任务（CC 防御 cleanup 协程）。
func (h *Handler) Stop() {
	if h.ccDefense != nil {
		h.ccDefense.Stop()
	}
	// AutoBlocker 归 Handler 管（可能是热安装时才建的），退出前落盘封禁状态。
	if ab := h.ab.Swap(nil); ab != nil {
		ab.Stop()
	}
}

// authOK 校验主控请求携带的 Bearer token。
//
// 比较必须走常数时间：Authorization 头完全远程可控，而 `!=` 的字符串比较在第一个不同
// 字节就返回，攻击者能用响应时间差逐字节还原出机密（时序侧信道）。这把 token 是
// 主控→边缘的唯一凭据，拿到就等于能向所有节点下发配置、封禁名单和域名私钥。
func (h *Handler) authOK(auth string) bool {
	// 空 token 一律拒绝。生产用 --token-file 启动不会有空值，但手动 `--token ""` 起
	// 来调试过的人会把这台边缘变成完全无鉴权的配置下发端点。
	if h.token == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := []byte(strings.TrimPrefix(auth, prefix))
	return subtle.ConstantTimeCompare(got, []byte(h.token)) == 1
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /edge/waf/check 和 /edge/waf/challenge 均由 Tengine 内部调用（127.0.0.1），
	// 限制只接受本机请求，防止外部探测 WAF 规则或伪造挑战凭证签发请求。
	if r.URL.Path == "/edge/waf/check" || r.URL.Path == "/edge/waf/challenge" || r.URL.Path == "/edge/waf/verify" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host != "127.0.0.1" && host != "::1" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/edge/waf/check":
			h.wafCheck(w, r)
		case "/edge/waf/challenge":
			h.wafChallenge(w, r)
		default:
			h.wafVerify(w, r)
		}
		return
	}

	// HTTP/2 Rapid Reset 端点（Tengine 内部调用）
	if strings.HasPrefix(r.URL.Path, "/edge/http2/") {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host != "127.0.0.1" && host != "::1" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h.serveHTTP2RapidResetAPI(w, r)
		return
	}

	// 其余端点均需 Bearer token 认证
	if !h.authOK(r.Header.Get("Authorization")) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch {
	case r.URL.Path == "/edge/status" && r.Method == http.MethodGet:
		h.status(w, r)

	case r.URL.Path == "/edge/install-xdp" && r.Method == http.MethodPost:
		h.installXdp(w, r)

	case r.URL.Path == "/edge/install-xdp/status" && r.Method == http.MethodGet:
		h.installXdpStatus(w, r)

	case r.URL.Path == "/edge/domains" && r.Method == http.MethodPost:
		h.syncDomain(w, r)

	case r.URL.Path == "/edge/domains/replace-all" && r.Method == http.MethodPost:
		h.replaceAllDomains(w, r)

	case strings.HasPrefix(r.URL.Path, "/edge/domains/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/edge/domains/")
		h.deleteDomain(w, r, id)

	case r.URL.Path == "/edge/xdp/block" && r.Method == http.MethodPost:
		h.xdpBlock(w, r)

	case r.URL.Path == "/edge/xdp/unblock" && r.Method == http.MethodPost:
		h.xdpUnblock(w, r)

	case r.URL.Path == "/edge/xdp/blocklist" && r.Method == http.MethodGet:
		h.xdpBlocklist(w, r)

	// 主控聚合 XDP 统计时拉取本节点计数（Pusher.GetXDPStats）。
	// 缺这条路由会让主控侧的请求落到默认分支返回 404，聚合结果恒为空。
	case r.URL.Path == "/edge/xdp/stats" && r.Method == http.MethodGet:
		h.xdpStats(w, r)

	// 封禁阶梯配置（面板下发 / 回显）。走主控推送而不是只有启动 flag，
	// 是因为调阶梯是运维在观察攻击后的反应动作，要求改 systemd unit 再重启
	// 意味着调一次参数就要断一次防护。
	case r.URL.Path == "/edge/xdp/ban-config" && r.Method == http.MethodGet:
		h.xdpGetBanConfig(w, r)

	case r.URL.Path == "/edge/xdp/ban-config" && r.Method == http.MethodPost:
		h.xdpSetBanConfig(w, r)

	// WAF 检测端点（供 Tengine auth_request 调用，不需要 Bearer token）
	case r.URL.Path == "/edge/waf/check" && r.Method == http.MethodGet:
		h.wafCheck(w, r)

	case r.URL.Path == "/edge/waf/block" && r.Method == http.MethodPost:
		h.wafBlockIP(w, r)

	case r.URL.Path == "/edge/waf/unblock" && r.Method == http.MethodPost:
		h.wafUnblockIP(w, r)

	// 返回本节点当前所有有效封禁 IP（CC 限速封禁 + WAF 规则封禁共用同一个 waf.Engine，
	// 因此这里一次性返回完整封禁集合）。主控据此做全网并集 + 补齐分发，实现封禁 IP 全网同步。
	case r.URL.Path == "/edge/waf/banned" && r.Method == http.MethodGet:
		h.wafBannedIPs(w, r)

	// 托管规则：面板下发策略（开关/模式/级别/规则集/单条覆盖/包版本与灰度）。
	case r.URL.Path == "/edge/waf/config" && r.Method == http.MethodPost:
		h.updateWAFConfig(w, r)

	// 本节点 WAF 读数：策略、包装载情况、生效规则、命中计数。
	// 面板靠它回答"我改的配置在这台节点上到底算什么"，也是下发失败的可见入口。
	case r.URL.Path == "/edge/waf/stats" && r.Method == http.MethodGet:
		h.wafStats(w, r)

	// 规则包热更新：主控把管理员维护的包（密文）推过来，边缘编译校验通过后原子换表。
	case r.URL.Path == "/edge/waf/rules" && r.Method == http.MethodPost:
		h.pushWAFRules(w, r)

	// 返回本节点边缘磁盘缓存的已用字节与文件数（缓存只存在于边缘节点，主控仅采集展示）。
	case r.URL.Path == "/edge/cache/stats" && r.Method == http.MethodGet:
		h.cacheStats(w, r)

	// 主控触发清缓存（域名 purge）：本机回环 curl 命中 site.conf.tmpl 里的
	// /purge location（限制 127.0.0.1），实际清除动作由 ngx_cache_purge 模块完成。
	case r.URL.Path == "/edge/cache/purge" && r.Method == http.MethodPost:
		h.purgeCache(w, r)

	case r.URL.Path == "/edge/cc/config" && r.Method == http.MethodGet:
		h.getCCConfig(w, r)

	case r.URL.Path == "/edge/cc/config" && r.Method == http.MethodPost:
		h.updateCCConfig(w, r)

	case r.URL.Path == "/edge/cc/stats" && r.Method == http.MethodGet:
		h.getCCStats(w, r)

	case r.URL.Path == "/edge/cc/ips" && r.Method == http.MethodGet:
		h.getCCTrackedIPs(w, r)

	case r.URL.Path == "/edge/cc/unblock" && r.Method == http.MethodPost:
		h.unblockCCIP(w, r)

	case r.URL.Path == "/edge/cc/attack-state" && r.Method == http.MethodPost:
		h.applyAttackState(w, r)

	case r.URL.Path == "/edge/stats" && r.Method == http.MethodGet:
		h.domainStats(w, r)

	case r.URL.Path == "/edge/stats/overview" && r.Method == http.MethodGet:
		h.statsOverview(w, r)

	case r.URL.Path == "/edge/cc/challenge-key" && r.Method == http.MethodPost:
		h.setChallengeKey(w, r)

	case r.URL.Path == "/edge/cc/challenge-key" && r.Method == http.MethodGet:
		h.getChallengeKeyID(w, r)

	case r.URL.Path == "/edge/rotate-ticket-key" && r.Method == http.MethodPost:
		h.rotateTicketKey(w, r)

	// 区域规则：主控下发编译好的前缀表、平台总闸+整节点策略，读数走 GET。
	// 旧的 /edge/geo/sync 桩只打一行日志就返回 ok，面板会以为封禁已生效 —— 已删除。
	case r.URL.Path == "/edge/geo/table" && r.Method == http.MethodPost:
		h.pushGeoTable(w, r)

	case r.URL.Path == "/edge/geo/config" && r.Method == http.MethodPost:
		h.putGeoConfig(w, r)

	case r.URL.Path == "/edge/geo/stats" && r.Method == http.MethodGet:
		h.geoStats(w, r)

	case r.URL.Path == "/edge/xdp/config" && r.Method == http.MethodGet:
		h.getXDPConfig(w, r)

	case r.URL.Path == "/edge/xdp/config" && r.Method == http.MethodPost:
		h.setXDPConfig(w, r)

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, h.BuildStatus())
}

func (h *Handler) installXdp(w http.ResponseWriter, r *http.Request) {
	h.xdpInstallMu.Lock()

	// 检查是否已经加载
	if h.xdpMgr.Loaded() {
		h.xdpInstallMu.Unlock()
		jsonResp(w, http.StatusOK, map[string]string{
			"status":  "already_loaded",
			"message": "XDP 已加载",
		})
		return
	}

	// 检查是否正在安装
	if h.xdpInstallStatus.Status == "running" {
		h.xdpInstallMu.Unlock()
		jsonResp(w, http.StatusOK, h.xdpInstallStatus)
		return
	}

	// 开始异步安装
	h.xdpInstallStatus = &InstallStatus{
		Status:   "running",
		Progress: "开始安装...",
		StartAt:  time.Now(),
	}
	h.xdpInstallMu.Unlock()

	// 在后台执行安装
	go h.doInstallXdp()

	jsonResp(w, http.StatusAccepted, map[string]string{
		"status":  "running",
		"message": "XDP 安装已启动，请轮询 /edge/install-xdp/status 查看进度",
	})
}

func (h *Handler) installXdpStatus(w http.ResponseWriter, r *http.Request) {
	h.xdpInstallMu.Lock()
	status := *h.xdpInstallStatus
	h.xdpInstallMu.Unlock()
	jsonResp(w, http.StatusOK, status)
}

func (h *Handler) updateInstallProgress(progress string) {
	h.xdpInstallMu.Lock()
	h.xdpInstallStatus.Progress = progress
	h.xdpInstallMu.Unlock()
	log.Printf("[XDP Install] %s", progress)
}

// machineArch 返回 `uname -m` 的结果，用于拼出 /usr/include/<arch>-linux-gnu。
// 走 uname 而不是 runtime.GOARCH，是因为需要的正是 Debian multiarch 目录名
// （x86_64 / aarch64），而 GOARCH 给的是 amd64 / arm64，拼出来的路径不存在。
// 取不到时回落到 x86_64：调用方对该 -I 失败有备用参数兜底。
func machineArch() string {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "x86_64"
	}
	return strings.TrimSpace(string(out))
}

func (h *Handler) doInstallXdp() {
	defer func() {
		if r := recover(); r != nil {
			h.xdpInstallMu.Lock()
			h.xdpInstallStatus.Status = "failed"
			h.xdpInstallStatus.Error = fmt.Sprintf("panic: %v", r)
			h.xdpInstallMu.Unlock()
		}
	}()

	log.Println("Starting XDP installation...")
	h.updateInstallProgress("获取内核版本...")

	// 1. 检查内核版本
	kernelCmd := exec.Command("uname", "-r")
	kernelOut, err := kernelCmd.Output()
	if err != nil {
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "获取内核版本失败: " + err.Error()
		h.xdpInstallMu.Unlock()
		return
	}
	kernelVersion := strings.TrimSpace(string(kernelOut))
	log.Printf("Kernel version: %s", kernelVersion)

	// 2. 安装编译工具和头文件
	h.updateInstallProgress("安装编译工具和头文件（约 1-3 分钟）...")
	installCmd := exec.Command("bash", "-c", fmt.Sprintf(`
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq 2>&1 | tail -5
		apt-get install -y -qq \
			clang \
			llvm \
			libbpf-dev \
			linux-libc-dev \
			libc6-dev \
			linux-headers-%s \
			linux-headers-generic \
			build-essential \
			pkg-config 2>&1 | tail -20
	`, kernelVersion))
	installCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := installCmd.CombinedOutput(); err != nil {
		log.Printf("Install tools failed: %v\n%s", err, out)
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "安装编译工具失败"
		h.xdpInstallStatus.Details = string(out)
		h.xdpInstallMu.Unlock()
		return
	}
	log.Println("Build tools installed successfully")

	// 3. 检查必要的头文件
	//
	// 只检查 UAPI / libbpf / libc 这三处头文件。这里刻意不再要求 /usr/src/linux-headers-*
	// 里的内核内部头文件存在：cdn_xdp.c 只 include <linux/bpf.h> 与 <bpf/*.h>，
	// 编译根本不需要内核源码树（见下方 compileArgs 的注释）。把内核头文件列为硬性
	// 前提会让内核版本与 apt 里 linux-headers 包不匹配的机器（自定义内核、云厂商
	// 内核、刚升级还没重启）直接卡在这一步，而它们其实完全编得出来。
	//
	// asm/types.h 单列一条：<linux/bpf.h> → <linux/types.h> → <asm/types.h> 这条
	// include 链一定会走到它，缺了就是 fatal error: 'asm/types.h' file not found。
	// 它由 libc6-dev 铺在 multiarch 目录下，两个候选位置命中任一即可。
	h.updateInstallProgress("检查头文件...")
	arch := machineArch()
	headerPaths := []string{
		"/usr/include/linux/bpf.h",
		"/usr/include/bpf/bpf_helpers.h",
	}
	missingHeaders := []string{}
	for _, path := range headerPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			missingHeaders = append(missingHeaders, path)
		}
	}
	asmCandidates := []string{
		"/usr/include/" + arch + "-linux-gnu/asm/types.h",
		"/usr/include/asm/types.h",
	}
	asmFound := false
	for _, path := range asmCandidates {
		if _, err := os.Stat(path); err == nil {
			asmFound = true
			break
		}
	}
	if !asmFound {
		missingHeaders = append(missingHeaders,
			"asm/types.h (tried "+strings.Join(asmCandidates, ", ")+"; install libc6-dev)")
	}
	if len(missingHeaders) > 0 {
		log.Printf("Missing headers: %v", missingHeaders)
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "缺少必要的头文件"
		h.xdpInstallStatus.Details = "Missing: " + strings.Join(missingHeaders, ", ")
		h.xdpInstallMu.Unlock()
		return
	}

	// 4. 编译 XDP 程序
	h.updateInstallProgress("编译 XDP 程序...")
	xdpObj := xdp.DefaultObjPath()

	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(xdpObj), 0755); err != nil {
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "创建输出目录失败: " + err.Error()
		h.xdpInstallMu.Unlock()
		return
	}

	// 将嵌入的源代码写入临时文件
	tmpSource := "/tmp/cdn_xdp_temp.c"
	if err := os.WriteFile(tmpSource, []byte(xdpSourceCode), 0644); err != nil {
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "写入临时源文件失败: " + err.Error()
		h.xdpInstallMu.Unlock()
		return
	}
	defer os.Remove(tmpSource)

	// 先删掉可能存在的旧 .o。否则本次三轮全部失败时，上一次安装留下的陈旧文件会让
	// 后面的 os.Stat 校验通过，把失败当成成功，接着 Load() 加载的是过期程序。
	if err := os.Remove(xdpObj); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: failed to remove stale %s: %v", xdpObj, err)
	}

	// 三轮递进的编译参数，必须与 install.sh 和 internal/deploy/ssh.go 保持一致——三条
	// 路径编的是同一份源码，参数不一致就会出现"一键部署装得上、面板按钮装不上"这种
	// 只在某条路径复现的故障。
	//
	// 两条不能碰的红线：
	//
	// 1）不要把 /usr/src/linux-headers-* 加进 -I，也不要定义 __KERNEL__。cdn_xdp.c 只
	//    include <linux/bpf.h> 与 <bpf/*.h> 这类 UAPI/libbpf 头文件，编译不需要内核源码
	//    树。一旦内核内部头文件路径进了 -I，<linux/bpf.h> 会被解析成内核内部那份，它一路
	//    include 到 asm/arch_hweight.h、asm/cmpxchg.h 等含 x86 内联汇编的头文件；clang
	//    此时 target 是 bpf，不认识 "=a"/"+q" 这些 x86 寄存器约束，于是刷出成百上千个
	//    "invalid output constraint" 并以 exit 139 崩掉前端。
	//
	// 2）-I/usr/include/<arch>-linux-gnu 不是可选装饰：<linux/bpf.h> → <linux/types.h>
	//    → <asm/types.h>，而 asm/ 就铺在这个 multiarch 目录下。去掉它必然
	//    fatal error: 'asm/types.h' file not found。所以"去掉 -I"那一轮只对 asm/ 直接
	//    位于 /usr/include 下的少数镜像有意义，绝不能把它的报错当成真正的失败原因。
	attempts := []struct {
		name string
		args []string
	}{
		{
			name: "arch include",
			args: []string{
				"-O2", "-g", "-target", "bpf",
				"-D__TARGET_ARCH_x86",
				"-I/usr/include/" + arch + "-linux-gnu",
				"-c", tmpSource, "-o", xdpObj,
			},
		},
		{
			// 有些镜像把 asm/ 软链到 /usr/include/asm，显式补一条 -I/usr/include 兜底。
			name: "arch include + /usr/include",
			args: []string{
				"-O2", "-g", "-target", "bpf",
				"-D__TARGET_ARCH_x86",
				"-I/usr/include/" + arch + "-linux-gnu",
				"-I/usr/include",
				"-c", tmpSource, "-o", xdpObj,
			},
		},
		{
			name: "minimal",
			args: []string{
				"-O2", "-g", "-target", "bpf",
				"-c", tmpSource, "-o", xdpObj,
			},
		},
	}

	compiled := false
	var failLog strings.Builder
	for _, a := range attempts {
		out, err := exec.Command("clang", a.args...).CombinedOutput()
		if err == nil {
			log.Printf("XDP compiled successfully (%s args)", a.name)
			compiled = true
			break
		}
		log.Printf("Compile XDP failed (%s): %v\nCommand: clang %s\nOutput:\n%s",
			a.name, err, strings.Join(a.args, " "), out)
		// 每一轮的参数与输出都进 Details。不去猜哪一轮的报错"更接近真因"——减配轮的
		// 报错往往是减配本身造成的（例如去掉 -I 后必然找不到 asm/types.h），只上报它
		// 会把真正的失败原因藏起来。全部给出来，由人判断。
		fmt.Fprintf(&failLog, "=== attempt: %s ===\nclang %s\n%s\n",
			a.name, strings.Join(a.args, " "), out)
	}

	if !compiled {
		// 清掉失败轮次可能留下的半成品 .o，避免它被下一次安装的 Stat 校验当成有效产物。
		if err := os.Remove(xdpObj); err != nil && !os.IsNotExist(err) {
			log.Printf("warning: failed to remove partial %s: %v", xdpObj, err)
		}
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "编译 XDP 程序失败"
		h.xdpInstallStatus.Details = failLog.String()
		h.xdpInstallMu.Unlock()
		return
	}
	log.Printf("XDP compiled successfully to %s", xdpObj)

	// 5. 验证编译结果
	if stat, err := os.Stat(xdpObj); err != nil {
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "XDP 程序未生成: " + err.Error()
		h.xdpInstallMu.Unlock()
		return
	} else {
		log.Printf("XDP object file size: %d bytes", stat.Size())
	}

	// 6. 加载 XDP 程序
	h.updateInstallProgress("加载 XDP 程序到网卡...")
	if err := h.xdpMgr.Load(); err != nil {
		h.xdpInstallMu.Lock()
		h.xdpInstallStatus.Status = "failed"
		h.xdpInstallStatus.Error = "加载 XDP 失败"
		h.xdpInstallStatus.Details = err.Error()
		h.xdpInstallMu.Unlock()
		return
	}

	// 7. 初始化默认配置
	h.updateInstallProgress("初始化配置...")
	if err := h.xdpMgr.InitDefaults(h.agentPort); err != nil {
		log.Printf("XDP init defaults failed: %v", err)
		// 不返回错误，继续
	}
	// 之前面板下发过阈值的话，装完用存档覆盖默认值。
	h.RestoreXDPConfig()
	h.startAutoBlockerAfterInstall()
	// 区域封禁补一遍：XDP 是刚挂上的，四棵 trie 还是空的，而整节点策略可能早就下发过了。
	// 漏这一步就会出现"面板上装了 XDP、区域规则显示已生效、网卡一条包都没丢"，
	// 要等到下一次换表或改策略才对上。
	h.updateInstallProgress("应用区域封禁到网卡...")
	h.applyGeoL4("XDP 热安装")

	log.Println("XDP installation completed successfully")
	h.xdpInstallMu.Lock()
	h.xdpInstallStatus.Status = "success"
	h.xdpInstallStatus.Progress = "安装完成"
	h.xdpInstallMu.Unlock()
}

func (h *Handler) syncDomain(w http.ResponseWriter, r *http.Request) {
	// 接收包含可选证书内容的推送 payload
	var payload struct {
		config.Domain
		CertPEM string `json:"cert_pem,omitempty"`
		KeyPEM  string `json:"key_pem,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("edge: syncDomain decode error: %v", err)
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	d := payload.Domain

	log.Printf("edge: syncing domain %s (ID: %s, CacheRules: %d)", d.Domain, d.ID, len(d.CacheRules))

	// 如果推送包含证书内容，先保存到磁盘
	if payload.CertPEM != "" && payload.KeyPEM != "" && d.SSL.CertFile != "" && d.SSL.KeyFile != "" {
		const sslBase = "/etc/ssl/cdnpanel/"
		// 防路径穿越：证书路径必须在 /etc/ssl/cdnpanel/ 下
		certClean := filepath.Clean(d.SSL.CertFile)
		keyClean := filepath.Clean(d.SSL.KeyFile)
		if !strings.HasPrefix(certClean, sslBase) || !strings.HasPrefix(keyClean, sslBase) {
			log.Printf("edge: invalid cert path for domain %s: cert=%s, key=%s", d.Domain, certClean, keyClean)
			http.Error(w, "invalid cert path: must be under /etc/ssl/cdnpanel/", http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(certClean), 0700); err != nil {
			log.Printf("edge: mkdir cert dir failed for domain %s: %v", d.Domain, err)
			http.Error(w, "mkdir cert dir: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 原子写入证书文件：.tmp + rename，避免 reload 期间读到半截证书。
		certTmp := certClean + ".tmp"
		if err := os.WriteFile(certTmp, []byte(payload.CertPEM), 0644); err != nil {
			log.Printf("edge: write cert failed for domain %s: %v", d.Domain, err)
			http.Error(w, "write cert: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(certTmp, certClean); err != nil {
			log.Printf("edge: rename cert failed for domain %s: %v", d.Domain, err)
			http.Error(w, "rename cert: "+err.Error(), http.StatusInternalServerError)
			return
		}
		keyTmp := keyClean + ".tmp"
		if err := os.WriteFile(keyTmp, []byte(payload.KeyPEM), 0600); err != nil {
			log.Printf("edge: write key failed for domain %s: %v", d.Domain, err)
			http.Error(w, "write key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(keyTmp, keyClean); err != nil {
			log.Printf("edge: rename key failed for domain %s: %v", d.Domain, err)
			http.Error(w, "rename key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("edge: saved SSL cert for %s", d.Domain)
	}

	// 改动前先记下站点配置原样：新配置过不了 tengine -t 时恢复，坏配置不能留在 sites-enabled，
	// 否则下次重启 Tengine（systemd ExecStartPre 先跑 -t）整台节点所有站点一起起不来。
	snapNames := []string{d.Domain}
	if oldByID, err := h.store.Get(d.ID); err == nil && oldByID.Domain != d.Domain {
		snapNames = append(snapNames, oldByID.Domain)
	}
	snap := h.generator.Snapshot(snapNames...)

	// 更新或新建域名配置
	// 先检查是否有相同域名（不同 ID）的旧配置，如果有则删除
	if oldByName, err := h.store.GetByDomain(d.Domain); err == nil && oldByName.ID != d.ID {
		log.Printf("edge: removing old config for domain %s (old ID: %s, new ID: %s)", d.Domain, oldByName.ID, d.ID)
		// 删除旧配置的 Tengine 配置文件
		h.generator.RemoveConfig(oldByName)
		// 从 store 中删除旧记录
		h.store.Delete(oldByName.ID)
	}

	// 然后按 ID 更新或创建
	existing, err := h.store.Get(d.ID)
	if err == nil {
		d.CreatedAt = existing.CreatedAt
		if err := h.store.Update(&d); err != nil {
			log.Printf("edge: store update failed for domain %s: %v", d.Domain, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("edge: updated domain %s in store", d.Domain)
	} else {
		if err := h.store.Create(&d); err != nil {
			log.Printf("edge: store create failed for domain %s: %v", d.Domain, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("edge: created domain %s in store", d.Domain)
	}

	if err := h.generator.WriteConfig(&d); err != nil {
		log.Printf("edge: WriteConfig failed for domain %s: %v", d.Domain, err)
		http.Error(w, "write config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("edge: wrote Tengine config for %s", d.Domain)

	testOutput, err := h.controller.TestAndReload()
	if err != nil {
		log.Printf("edge: Tengine reload failed for domain %s: %v, test output: %s", d.Domain, err, testOutput)
		h.rollbackSiteConfigs(snap, d.Domain)
		http.Error(w, "tengine reload failed: "+err.Error()+", output: "+testOutput, http.StatusInternalServerError)
		return
	}
	log.Printf("edge: Tengine reloaded successfully for domain %s", d.Domain)
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

// rollbackSiteConfigs 新站点配置过不了 tengine -t 时把文件恢复原样，并再测一次确认恢复后的配置可用。
// 域名记录（store）保留新值：主控会把下发失败报给面板，修好原因后重新同步即可。
func (h *Handler) rollbackSiteConfigs(snap *tengine.ConfigSnapshot, what string) {
	if err := snap.Restore(); err != nil {
		log.Printf("edge: restore site configs after failed test (%s): %v", what, err)
		return
	}
	if out, err := h.controller.Test(); err != nil {
		// 恢复后仍不通过：问题不在这次的站点配置（比如主配置缺 zone、模块缺失），原样记日志。
		log.Printf("edge: site configs restored (%s) but tengine -t still fails: %v, output: %s", what, err, out)
		return
	}
	log.Printf("edge: rejected site configs rolled back (%s); running Tengine untouched and next restart is safe", what)
}

// replaceAllDomains 接收完整的域名列表，删除本地不在列表中的域名，然后创建/更新列表中的域名。
func (h *Handler) replaceAllDomains(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Domains []struct {
			config.Domain
			CertPEM string `json:"cert_pem,omitempty"`
			KeyPEM  string `json:"key_pem,omitempty"`
		} `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 构建接收到的域名 ID 集合
	receivedIDs := make(map[string]bool)
	for _, d := range payload.Domains {
		receivedIDs[d.ID] = true
	}

	// 改动前记下所有会被动到的站点配置（失败时整批恢复，理由同 syncDomain）。
	existing := h.store.List()
	snapNames := make([]string, 0, len(existing)+len(payload.Domains))
	for _, old := range existing {
		snapNames = append(snapNames, old.Domain)
	}
	for _, it := range payload.Domains {
		snapNames = append(snapNames, it.Domain.Domain)
	}
	snap := h.generator.Snapshot(snapNames...)

	// 删除本地存在但不在接收列表中的域名
	deletedCount := 0
	for _, old := range existing {
		if !receivedIDs[old.ID] {
			log.Printf("edge: removing domain %s (ID: %s) not in master list", old.Domain, old.ID)
			_ = h.generator.RemoveConfig(old)
			_ = h.store.Delete(old.ID)
			deletedCount++
		}
	}

	// 创建或更新接收到的每个域名
	updatedCount := 0
	createdCount := 0
	for _, item := range payload.Domains {
		d := item.Domain

		// 如果推送包含证书内容，先保存到磁盘
		if item.CertPEM != "" && item.KeyPEM != "" && d.SSL.CertFile != "" && d.SSL.KeyFile != "" {
			const sslBase = "/etc/ssl/cdnpanel/"
			certClean := filepath.Clean(d.SSL.CertFile)
			keyClean := filepath.Clean(d.SSL.KeyFile)
			if !strings.HasPrefix(certClean, sslBase) || !strings.HasPrefix(keyClean, sslBase) {
				log.Printf("edge: invalid cert path for %s: must be under /etc/ssl/cdnpanel/", d.Domain)
				continue
			}
			if err := os.MkdirAll(filepath.Dir(certClean), 0700); err != nil {
				log.Printf("edge: mkdir cert dir for %s failed: %v", d.Domain, err)
				continue
			}
			// 原子写入证书文件：.tmp + rename，避免 reload 期间读到半截证书。
			certTmp := certClean + ".tmp"
			if err := os.WriteFile(certTmp, []byte(item.CertPEM), 0644); err != nil {
				log.Printf("edge: write cert for %s failed: %v", d.Domain, err)
				continue
			}
			if err := os.Rename(certTmp, certClean); err != nil {
				log.Printf("edge: rename cert for %s failed: %v", d.Domain, err)
				continue
			}
			keyTmp := keyClean + ".tmp"
			if err := os.WriteFile(keyTmp, []byte(item.KeyPEM), 0600); err != nil {
				log.Printf("edge: write key for %s failed: %v", d.Domain, err)
				continue
			}
			if err := os.Rename(keyTmp, keyClean); err != nil {
				log.Printf("edge: rename key for %s failed: %v", d.Domain, err)
				continue
			}
		}

		// 按 ID 更新或创建
		existing, err := h.store.Get(d.ID)
		if err == nil {
			d.CreatedAt = existing.CreatedAt
			if err := h.store.Update(&d); err != nil {
				log.Printf("edge: update domain %s failed: %v", d.Domain, err)
				continue
			}
			updatedCount++
		} else {
			if err := h.store.Create(&d); err != nil {
				log.Printf("edge: create domain %s failed: %v", d.Domain, err)
				continue
			}
			createdCount++
		}

		if err := h.generator.WriteConfig(&d); err != nil {
			log.Printf("edge: write config for %s failed: %v", d.Domain, err)
		}
	}

	// 重载 Tengine
	if out, err := h.controller.TestAndReload(); err != nil {
		log.Printf("edge reload failed after replace-all: %v, test output: %s", err, out)
		h.rollbackSiteConfigs(snap, "replace-all")
		http.Error(w, "tengine reload failed: "+err.Error()+", output: "+out, http.StatusInternalServerError)
		return
	}

	log.Printf("edge: replace-all completed: deleted=%d, created=%d, updated=%d", deletedCount, createdCount, updatedCount)
	jsonResp(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"deleted": deletedCount,
		"created": createdCount,
		"updated": updatedCount,
	})
}

func (h *Handler) deleteDomain(w http.ResponseWriter, r *http.Request, id string) {
	d, err := h.store.Get(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = h.generator.RemoveConfig(d)
	if err := h.store.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := h.controller.TestAndReload(); err != nil {
		log.Printf("edge reload failed after delete domain %s: %v", id, err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) xdpBlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	ip := net.ParseIP(body.IP)
	if ip == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	if h.xdpMgr.Loaded() {
		if err := h.xdpMgr.BlockIP(ip); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	jsonResp(w, http.StatusOK, map[string]string{"blocked": body.IP})
}

func (h *Handler) xdpUnblock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	ip := net.ParseIP(body.IP)
	if ip == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	if h.xdpMgr.Loaded() {
		if err := h.xdpMgr.UnblockIP(ip); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// 同时清掉 AutoBlocker 的记账，否则这条封禁会留在存档里，节点下次启动时
	// 被 restoreState 重新塞回 blocklist —— 表现为「解封后重启又被封」。
	if ab := h.blocker(); ab != nil {
		ab.Forget(body.IP)
	}
	jsonResp(w, http.StatusOK, map[string]string{"unblocked": body.IP})
}

// xdpStats 返回本节点的 XDP 计数器，供主控 /api/xdp/stats 跨节点求和。
// XDP 未加载时返回全 0 而非错误：主控把 map 里的每个字段累加，少一个节点的 0
// 和拿不到响应是等价的，但返回 200 能让「节点在线但没装 XDP」和「节点失联」
// 在主控日志里区分开。
func (h *Handler) xdpStats(w http.ResponseWriter, r *http.Request) {
	if !h.xdpMgr.Loaded() {
		jsonResp(w, http.StatusOK, map[string]uint64{})
		return
	}
	s, err := h.xdpMgr.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, http.StatusOK, s)
}

// xdpGetBanConfig 回显本节点当前生效的封禁阶梯，供面板展示。
//
// 阶梯以「5m,30m,2h」这样的字符串返回而不是纳秒数组：面板要把它填回输入框，
// 而 time.Duration 编成 JSON 是 3600000000000 这样的整数，前端还得反向格式化一遍。
func (h *Handler) xdpGetBanConfig(w http.ResponseWriter, r *http.Request) {
	ab := h.blocker()
	if ab == nil {
		// 没有 AutoBlocker（未指定网卡 / XDP 加载失败）时返回内置默认值并标明未生效，
		// 而不是 500 —— 面板的 XDP 页要能正常渲染并告诉用户「阶梯没在跑」。
		jsonResp(w, http.StatusOK, map[string]any{
			"active":       false,
			"ladder":       xdp.FormatBanLadder(xdp.DefaultBanLadder),
			"offender_ttl": xdp.DefaultOffenderTTL.String(),
		})
		return
	}
	ladder, ttl := ab.BanConfig()
	jsonResp(w, http.StatusOK, map[string]any{
		"active":       true,
		"ladder":       xdp.FormatBanLadder(ladder),
		"offender_ttl": ttl.String(),
		"preview":      xdp.LadderPreview(ladder),
	})
}

// xdpSetBanConfig 接收面板下发的封禁阶梯。
func (h *Handler) xdpSetBanConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ladder      string `json:"ladder"`
		OffenderTTL string `json:"offender_ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 先把两项都解析校验完再落任何一项，避免「阶梯生效了但 TTL 报错」这种半套配置 ——
	// 那会留下一个 ladder 和 ttl 不匹配的状态（比如末档 24h 配窗口 1h），而这种组合
	// 正好让封顶档失效，且从面板上看不出问题。
	ladder, err := xdp.ParseBanLadder(body.Ladder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var ttl time.Duration
	if body.OffenderTTL != "" {
		ttl, err = time.ParseDuration(body.OffenderTTL)
		if err != nil {
			http.Error(w, "invalid offender_ttl: "+err.Error(), http.StatusBadRequest)
			return
		}
		if ttl <= 0 {
			http.Error(w, "offender_ttl must be positive", http.StatusBadRequest)
			return
		}
	}
	// 末档 >= 窗口时封顶档形同虚设：被关满末档的 IP 解封时记账刚好过期，下次再来
	// 直接回首档 —— 越是打到封顶的攻击者越容易清零档位。拒绝而不是接受后静默失效。
	if err := xdp.ValidateBanConfig(ladder, ttl); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ab := h.blocker()
	if ab == nil {
		// 配置本身合法，但本节点没在跑 AutoBlocker。返回 409 而不是 200：
		// 主控广播后会记下哪些节点没接住，否则用户会以为全网都改好了。
		http.Error(w, "XDP auto-blocker not running on this node", http.StatusConflict)
		return
	}
	ab.SetBanConfig(ladder, ttl)

	applied, appliedTTL := ab.BanConfig()
	log.Printf("[XDP] ban config updated: ladder=%v offender_ttl=%v",
		xdp.LadderPreview(applied), appliedTTL)
	jsonResp(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"ladder":       xdp.FormatBanLadder(applied),
		"offender_ttl": appliedTTL.String(),
	})
}

func (h *Handler) xdpBlocklist(w http.ResponseWriter, r *http.Request) {
	// 如果有 AutoBlocker，返回它的封禁列表（包含剩余时间）
	if ab := h.blocker(); ab != nil {
		entries := ab.GetBlockedIPs()
		jsonResp(w, http.StatusOK, entries)
		return
	}

	// 回退：读取 eBPF map（但没有剩余时间信息）
	if !h.xdpMgr.Loaded() {
		jsonResp(w, http.StatusOK, []string{})
		return
	}
	ips, err := h.xdpMgr.ListBlocked()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	jsonResp(w, http.StatusOK, strs)
}

func jsonResp(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// ── WAF 处理方法 ────────────────────────────────────────────────

// wafCheck 供 Tengine auth_request 内部调用，200=放行，403=拦截，495=需要 JS 挑战。
func (h *Handler) wafCheck(w http.ResponseWriter, r *http.Request) {
	// panic 必须 fail-closed。net/http 自带的 recover 会直接断开连接，Tengine 看到的是
	// 502（upstream prematurely closed）；而模板里 /edge-waf-check 把 502 视为「cdnedge
	// 没在跑」并放行（避免 cdnedge 重启/升级期间整站 500）。不在这里兜住的话，任何能触发
	// panic 的请求都会变成绕过 WAF/CC 的钥匙。
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("WAF check panic (fail-closed 403): %v uri=%s", rec, r.Header.Get("X-Waf-URI"))
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}()
	wafHandler := &wafProxy{engine: h.wafEngine, ccDefense: h.ccDefense, geoGuard: h.geoGuard, geoDomains: h.store}
	wafHandler.check(w, r)
}

// challengeBindingFP 计算挑战凭证/票据绑定用的客户端指纹。
//
// 绑定必须在"内容请求（导航 GET）/ 挑战页（GET）/ 验证提交（POST fetch）"三种请求形态下
// 完全一致，否则签发与校验对不上会导致所有模式验证恒 403。这三种请求的 method、header 集合、
// 顺序、sec-fetch-* 各不相同，因此不能用 JA4H（其设计目的正是刻画请求形态，跨请求必然不同）。
// 改用请求形态无关的 User-Agent 派生指纹（见 waf.ChallengeBindingFP）：三条路径都转发了
// X-Waf-UA，UA 在同一浏览器的三种请求里保持一致，又能"换浏览器即失效"防复用穿透。
// UA 缺失时返回空串（退化为仅绑 IP）。第三层 CC 指纹统计仍走独立的 X-Ja4h 路径，不受影响。
func (h *Handler) challengeBindingFP(r *http.Request) string {
	return waf.ChallengeBindingFP(r.Header.Get("X-Waf-UA"))
}

// challengeModeForHost 读取指定域名配置的验证模式；未配置或读取失败时返回无感 JS 模式。
func (h *Handler) challengeModeForHost(host string) string {
	if host == "" || h.store == nil {
		return waf.ChallengeModeJS
	}
	d, err := h.store.GetByDomain(host)
	if err != nil || d == nil {
		return waf.ChallengeModeJS
	}
	if d.CCPolicy.ChallengeMode == "" {
		return waf.ChallengeModeJS
	}
	return d.CCPolicy.ChallengeMode
}

// gatewayProfileForHost 读取该域名的白标签皮肤，供等待页按厂商家族自适应渲染。
// 取不到域名配置时返回零值皮肤：渲染层据此回落到 gateway 家族 + 默认 verify 路径，
// 页面照常可验证，不会因为一条域名记录缺失而 500。
func (h *Handler) gatewayProfileForHost(host string) config.GatewayProfile {
	if host == "" || h.store == nil {
		return config.GatewayProfile{VerifyUrl: config.DefaultVerifyPath}
	}
	d, err := h.store.GetByDomain(host)
	if err != nil || d == nil {
		return config.GatewayProfile{VerifyUrl: config.DefaultVerifyPath}
	}
	d.GatewayProfile.Normalize()
	return d.GatewayProfile
}

// challengeBindScopeForHost 读取指定域名配置的凭证地址绑定粒度。
//
// 这个值必须在三条路径上取自同一处配置：签票据（wafChallenge）、签 Cookie 与校验票据
// （wafVerify）、校验 Cookie（CC 层的 waf.CCDefense.Check）。任一处取到不同的 scope，
// 绑定串就不一致，凭证校验恒失败 → 无限挑战循环。CC 层从 domainStore 读同一个
// CCPolicy.ChallengeBindScope，与这里同源。
//
// 未配置时返回空串，bindingAddr 按默认档（绑完整 IP）处理，行为与升级前完全一致。
func (h *Handler) challengeBindScopeForHost(host string) string {
	if host == "" || h.store == nil {
		return ""
	}
	d, err := h.store.GetByDomain(host)
	if err != nil || d == nil {
		return ""
	}
	return d.CCPolicy.ChallengeBindScope
}

// wafChallenge 供 Tengine error_page 401 指向的真实 proxy_pass location 调用（非 auth_request 子请求）。
//   - 无感 JS 模式（默认）：直接签发挑战 Cookie 并返回自动跳转页，行为与升级前一致。
//   - 可见验证模式（shield/slider/text）：不签发 Cookie，改为下发一次性票据 + 交互页；
//     用户完成交互后由 /__cc/verify 领取 Cookie。凭证与票据均绑定 ip+JA4H 指纹防复用穿透。
func (h *Handler) wafChallenge(w http.ResponseWriter, r *http.Request) {
	// 必须与 CC 限速侧（waf.clientIP）用同一套归一化，否则 IPv6 客户端的票据/Cookie
	// 绑定串与校验串不同，验证恒失败 → 无限挑战循环。
	clientIP := waf.NormalizeClientIP(r.Header.Get("X-Waf-Client-IP"))
	if clientIP == "" {
		clientIP = waf.NormalizeClientIP(r.RemoteAddr)
	}
	redirectURL := r.Header.Get("X-Waf-URI")
	if redirectURL == "" {
		redirectURL = "/"
	}

	host := r.Header.Get("X-Waf-Host")
	if host == "" {
		host = r.Host
	}
	mode := h.challengeModeForHost(host)
	bindFP := h.challengeBindingFP(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if mode == "" {
		mode = waf.ChallengeModeJS
	}

	// 所有模式统一走"票据 + 环境采集 + /__cc/verify 领 Cookie"流程：
	//   - 服务端不再随挑战页预发 Cookie，Cookie 只在环境评分通过后由 verify 下发；
	//   - 无感 JS 模式同样采集浏览器环境并评分，headless/自动化框架即使执行 JS 也会被挡下；
	//   - text 模式额外生成算术题并把答案写进票据。
	var question, answer string
	if mode == waf.ChallengeModeText {
		question, answer = waf.NewArithChallenge()
	}
	ticket := waf.IssueChallengeTicket(mode, host, clientIP, bindFP, answer, h.challengeBindScopeForHost(host))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(waf.ChallengePageHTMLForSkin(h.gatewayProfileForHost(host), mode, redirectURL, ticket, question)))
}

// wafVerify 处理可见验证模式下用户完成交互后的验证提交（公开 location /__cc/verify → 此端点）。
// 校验票据（签名/绑定 ip+指纹/有效期/最小交互耗时，text 模式还校验答案），通过则签发挑战 Cookie 返回 200。
func (h *Handler) wafVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 与 wafChallenge 用同一套归一化：票据在那边按归一化后的 IP 签发，这里必须用同一个
	// 串才能校验通过（否则 IPv6 客户端永远过不了验证）。
	clientIP := waf.NormalizeClientIP(r.Header.Get("X-Waf-Client-IP"))
	if clientIP == "" {
		clientIP = waf.NormalizeClientIP(r.RemoteAddr)
	}
	host := r.Header.Get("X-Waf-Host")
	if host == "" {
		host = r.Host
	}
	mode := h.challengeModeForHost(host)
	if mode == "" {
		mode = waf.ChallengeModeJS
	}
	bindFP := h.challengeBindingFP(r)
	// 票据校验与随后签发的 Cookie 必须用同一个 scope，且与 CC 层校验 Cookie 时读到的
	// 一致（三者同源于该域名的 CCPolicy.ChallengeBindScope）。
	bindScope := h.challengeBindScopeForHost(host)

	var body struct {
		Ticket string `json:"ticket"`
		Answer string `json:"answer"`
		Env    string `json:"env"` // 浏览器采集的环境信号（base64(JSON)），所有模式统一上报
	}
	// 限制请求体大小：env 字段是攻击者可控的 base64 字符串，不设上限可被塞入几十 MB
	// 来耗边缘内存/CPU。真实环境采集的 JSON base64 后远小于 64KB。
	const maxVerifyBody = 64 << 10
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxVerifyBody)).Decode(&body); err != nil || body.Ticket == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// verifyFail 记录一次"拿不到正确 cookie"的验证失败：正常用户过一次挑战即成功，
	// 反复失败（票据无效/交互太快/答案错）极大概率是脚本在爆破。达阈值即封禁该 IP。
	verifyFail := func(msg, reason string) {
		if h.verifyThrottle != nil && h.verifyThrottle.RecordFailure(clientIP) {
			h.wafBlockShieldSuspect(clientIP, "verify brute-force: "+reason)
		}
		http.Error(w, msg, http.StatusForbidden)
	}

	answer, issuedAt, ok := waf.VerifyChallengeTicket(body.Ticket, mode, host, clientIP, bindFP, bindScope)
	if !ok {
		verifyFail("invalid or expired ticket", "invalid ticket")
		return
	}
	// 最小交互耗时：挡住不经过真实交互、拿到票据即秒提交的脚本。
	if time.Since(issuedAt) < waf.MinDwellForMode(mode) {
		verifyFail("verification too fast", "too fast")
		return
	}
	// 文字/算术模式校验答案。
	if mode == waf.ChallengeModeText && strings.TrimSpace(body.Answer) != answer {
		verifyFail("wrong answer", "wrong answer")
		return
	}

	// 环境评分（所有模式统一执行，即便无 XDP 也生效——封禁走 waf.Engine 内存表）：
	// 前端 env 字段带的是浏览器采到的环境 JSON（base64）。headless/自动化框架即便通过了
	// 滑块/答案/JS 挑战，也会在环境信号组合上露馅。
	envWeak := false
	env, ok := waf.DecodeShieldEnv(body.Env)
	if !ok {
		// env 缺失/损坏的宽限策略：多站点 + 多浏览器内核环境下，老旧内核、隐私模式、
		// 缓存的旧挑战页都可能导致采集失败，一刀切封禁会误伤真实用户。
		//   - shield 模式以环境检测为唯一目的（无其它交互兜底），env 缺失即视为脚本，封禁；
		//   - js/slider/text 已有 JS 执行 / 滑块 / 答案作为主验证，env 缺失时不封禁，
		//     但只发降权凭证（见 waf.ChallengeTierWeak）：过去的"放行"是整条链上最便宜的
		//     绕过——不带 env 字段提交即可领 30 分钟 verified_rps 宽松配额，等于把
		//     "要不要出示浏览器证据"交给攻击者自己决定。
		if mode == waf.ChallengeModeShield {
			h.wafBlockShieldSuspect(clientIP, "shield env missing or malformed")
			http.Error(w, "environment check failed", http.StatusForbidden)
			return
		}
		envWeak = true
	} else if score := waf.ScoreShieldEnv(env, r.Header.Get("User-Agent")); score.Suspect {
		// env 成功上报但评分可疑（死信号或多弱信号叠加）→ 高置信度机器人，所有模式一律封禁。
		// 这不是浏览器内核差异能造成的：真实浏览器上报的 screen/canvas/tz 等一定齐全干净。
		h.wafBlockShieldSuspect(clientIP, mode+" score="+strings.Join(score.Reasons, ","))
		http.Error(w, "environment check failed", http.StatusForbidden)
		return
	}

	// 验证通过：清除该 IP 的失败计数，避免此前偶发失败残留累计误封后续正常请求。
	if h.verifyThrottle != nil {
		h.verifyThrottle.RecordSuccess(clientIP)
	}
	// HTTPS 站点给 Cookie 加 Secure，避免验证凭证在明文 HTTP 上被嗅探重放；
	// 纯 HTTP 站点必须不加，否则浏览器不回传 Cookie 会导致反复要求验证。
	secure := strings.EqualFold(r.Header.Get("X-Waf-Scheme"), "https")
	tier, tierLabel := waf.ChallengeTierFull, "full"
	if envWeak {
		tier, tierLabel = waf.ChallengeTierWeak, "weak"
	}
	http.SetCookie(w, waf.IssueChallengeCookieTier(host, clientIP, bindFP, secure, bindScope, tier))
	if envWeak {
		// 降权必须留痕：环境采集若在真实用户身上大面积失败（隐私模式、老内核、采集脚本被
		// 站点自身的 CSP 拦掉），这条日志是唯一能看出规模的地方；不打日志就只能靠猜。
		log.Printf("edge: challenge credential downgraded: ip=%s host=%s mode=%s env_bytes=%d", clientIP, host, mode, len(body.Env))
	}
	w.WriteHeader(http.StatusOK)
	// tier 只进响应体、不参与页面逻辑（挑战页只看 response.ok），给排障用：
	// "为什么每 5 分钟就要重新验证一次"的答案就在这里，而不是要靠翻节点日志。
	_, _ = w.Write([]byte(`{"status":"ok","tier":"` + tierLabel + `"}`))
}

// wafBlockShieldSuspect 处理 3 秒盾评分不通过的可疑 IP：交给 waf.Engine.BlockIP。
// 它内部已挂 L4 hook，会把该 IP 一并写入 XDP blocklist，让后续 SYN 直接在网卡驱动层 DROP。
func (h *Handler) wafBlockShieldSuspect(ip, reason string) {
	if h == nil || h.wafEngine == nil || ip == "" {
		return
	}
	// 3 秒盾拦下的是"通过表面挑战但环境异常"的机器人；封禁 30 分钟足够劝退当前攻击波，
	// 又不会因为误伤留下持久黑名单。真实攻击持续时 AutoBlocker/CC 累积会覆盖到更长。
	h.wafEngine.BlockIP(ip, 30*time.Minute)
	log.Printf("[shield] block %s reason=%s", ip, reason)
}

func (h *Handler) wafBlockIP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP      string `json:"ip"`
		Minutes int    `json:"minutes"`
		// Seconds 是主控全网同步下发的精确剩余时长，优先于 Minutes。同步语义：
		// 只在比本地现有封禁更晚到期时写入，不缩短、不按完整时长重新计时。
		// Minutes 同时保留，供旧版边缘兼容（旧版忽略未知字段）。
		Seconds int `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	// 验证必须是合法 IPv4/IPv6 地址
	if net.ParseIP(body.IP) == nil {
		http.Error(w, "invalid IP address: "+body.IP, http.StatusBadRequest)
		return
	}
	if body.Seconds > 0 {
		until := time.Now().Add(time.Duration(body.Seconds) * time.Second)
		adopted := h.wafEngine.BlockIPUntil(body.IP, until)
		jsonResp(w, http.StatusOK, map[string]any{"blocked": body.IP, "seconds": body.Seconds, "adopted": adopted})
		return
	}
	if body.Minutes < 0 {
		http.Error(w, "minutes must be >= 0", http.StatusBadRequest)
		return
	}
	// minutes:0 表示「不封禁/禁用」，直接忽略（不能兜底成默认值，否则把「关闭」悄悄变成「封禁N小时」）
	if body.Minutes == 0 {
		jsonResp(w, http.StatusOK, map[string]string{"status": "skipped", "reason": "minutes is 0"})
		return
	}
	dur := time.Duration(body.Minutes) * time.Minute
	h.wafEngine.BlockIP(body.IP, dur)
	log.Printf("WAF: blocked IP %s for %v", body.IP, dur)
	jsonResp(w, http.StatusOK, map[string]string{"blocked": body.IP, "duration": dur.String()})
}

func (h *Handler) wafUnblockIP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	h.wafEngine.UnblockIP(body.IP)
	jsonResp(w, http.StatusOK, map[string]string{"unblocked": body.IP})
}

// wafBannedIPs 返回本节点当前所有有效封禁 IP。CC 限速封禁和 WAF 规则封禁共用
// 同一个 waf.Engine（见 NewHandler），因此 GetBannedIPs 返回的是完整封禁集合。
//
// bans 给出每条封禁的到期时刻（unix 秒），now 是本节点当前时刻：主控用 exp-now 得到
// 剩余时长再换算到自己的时钟，不受节点间时钟偏差影响。以前只给 IP 列表，主控只能
// 按完整时长重新封，封禁在主控与节点之间来回续命、永不到期。
func (h *Handler) wafBannedIPs(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, h.wafBansData())
}

// cacheStats 扫描本节点的边缘磁盘缓存目录，返回已用字节数与文件数。
// 缓存文件只存在于边缘节点（主控只是配置主机），主控通过此端点采集后仅用于展示。
func (h *Handler) cacheStats(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, cacheUsage())
}

// purgeCache 清除本节点上某个域名的边缘磁盘缓存。实际清除由 Tengine 的 ngx_cache_purge
// 模块完成，key 是 "$scheme$host/*"（site.conf.tmpl 里的 `location ~ ^/purge(/.*)?$`，
// 通配符前缀匹配该域名下全部路径，不影响同节点其他域名的缓存条目）。
//
// proxy_cache_key 用 $scheme 区分 http/https 两套缓存，各自要单独 purge 一次：
//   - http 那份：本机回环 + Host 头指定域名即可命中对应 server 块。
//   - https 那份：TLS 的虚拟主机分发靠 SNI，Host 头不够，需要 --resolve 把域名解析到
//     127.0.0.1 并用域名本身作为请求 URL（走 SNI），-k 跳过证书校验（回环请求，证书是否
//     匹配域名不重要）。
//
// curl 只看状态码，不解析 purge 返回的 HTML 内容：ngx_cache_purge 命中删除返回 200，
// 缓存本就不存在返回 404，两者都算"清理完成"；两次请求都失败才算这次 purge 失败
// （站点可能只启用了 http 或只启用了 https，单边 404/连接失败是正常情况）。
func (h *Handler) purgeCache(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		http.Error(w, "bad request: domain is required", http.StatusBadRequest)
		return
	}

	httpCode, httpErr := purgeCurl("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Host: "+req.Domain, "http://127.0.0.1/purge/")
	httpsCode, httpsErr := purgeCurl("curl", "-sS", "-k", "-o", "/dev/null", "-w", "%{http_code}",
		"--resolve", req.Domain+":443:127.0.0.1", "https://"+req.Domain+"/purge/")

	httpOK := httpErr == nil && (httpCode == "200" || httpCode == "404")
	httpsOK := httpsErr == nil && (httpsCode == "200" || httpsCode == "404")
	if !httpOK && !httpsOK {
		log.Printf("edge: purge cache for domain %s failed: http(code=%s err=%v) https(code=%s err=%v)",
			req.Domain, httpCode, httpErr, httpsCode, httpsErr)
		jsonResp(w, http.StatusBadGateway, map[string]any{"error": "purge failed on both http and https"})
		return
	}
	jsonResp(w, http.StatusOK, map[string]any{"status": "ok", "http": purgeStatus(httpOK, httpCode, httpErr), "https": purgeStatus(httpsOK, httpsCode, httpsErr)})
}

func purgeCurl(name string, args ...string) (code string, err error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func purgeStatus(ok bool, code string, err error) string {
	if ok {
		return code
	}
	if err != nil {
		return "failed: " + err.Error()
	}
	return "failed: unexpected status " + code
}

// wafProxy 把 Tengine 通过 auth_request 传来的请求头还原成原始请求并做 WAF 检测。
type wafProxy struct {
	engine    *waf.Engine
	ccDefense *waf.CCDefense
	// geoGuard 是区域规则运行时；geoDomains 用来取这个 host 自己配的那条域名规则。
	// 判定发生在内置段（封禁表/UA）之后、托管规则之前，不受面板 WAF 开关控制。
	geoGuard   *geo.Guard
	geoDomains *config.Store
}

func (wp *wafProxy) check(w http.ResponseWriter, r *http.Request) {
	rawURI := r.Header.Get("X-Waf-URI")
	method := firstNonEmpty(r.Header.Get("X-Waf-Method"), "GET")

	// URI 为空时失败拦截（fail-closed），防止绕过
	if rawURI == "" {
		log.Printf("WAF: missing X-Waf-URI, blocking request (fail-closed)")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	realReq, err := http.NewRequest(method, rawURI, nil)
	if err != nil {
		log.Printf("WAF: invalid X-Waf-URI %q, blocking request (fail-closed): %v", rawURI, err)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	realReq.Header = http.Header{
		"User-Agent":   {r.Header.Get("X-Waf-UA")},
		"Referer":      {r.Header.Get("X-Waf-Referer")},
		"Content-Type": {r.Header.Get("X-Waf-Content-Type")},
		"X-Real-IP":    {r.Header.Get("X-Waf-Client-IP")},
		"Cookie":       {r.Header.Get("X-Waf-Cookie")},
	}
	// 第三层 JA4H 指纹：X-Waf-Raw-Headers-B64 由 site.conf.tmpl 里的
	// access_by_lua_block 转发（原始顺序的请求头文本，base64 编码）。缺失时
	// （lua-nginx-module 未启用或旧版模板）ComputeJA4H 返回空串，指纹检测按
	// "不可用"处理，不影响第一、二层照常生效。
	if rawHeadersB64 := r.Header.Get("X-Waf-Raw-Headers-B64"); rawHeadersB64 != "" {
		if ja4h := waf.ComputeJA4H(method, "11", rawHeadersB64, r.Header.Get("X-Waf-Cookie")); ja4h != "" {
			realReq.Header.Set("X-Ja4h", ja4h)
		}
	}
	// http.NewRequest 不会自动填充 Host 字段（客户端请求场景下该字段默认留空），
	// 域名级强检测需要按 Host 区分，这里显式补上。
	//
	// 必须优先用 X-Waf-Host（$host），不能只依赖 URL.Host。挑战 Cookie 的绑定串含 host，
	// 而签发端（wafChallenge/wafVerify）读的正是 X-Waf-Host；校验端若从 X-Waf-URI
	// （$scheme://$host$request_uri）反解 URL.Host，两边就是两条不同的取值路径。它们在
	// 正常请求下恰好相等（$host 已是小写且不含端口），但只要 $request_uri 不是以 "/"
	// 开头的 origin-form —— 例如客户端发 absolute-form 请求行
	// "GET http://other/x HTTP/1.1"，$request_uri 原样保留整个绝对 URI，拼出来的
	// "https://example.comhttp://other/x" 会被解析成 Host="example.comhttp" ——
	// 两端绑定串就不一致，VerifyChallengeCookie 恒失败，表现为真人反复收到验证页却
	// 永远进不去（无限挑战循环）；同时 domainAttackLevel 按这个畸形 host 查不到域名，
	// 该域名配置的 CC 策略会整体静默失效。统一读 $host 即可两头同源。
	realReq.Host = firstNonEmpty(r.Header.Get("X-Waf-Host"), realReq.URL.Host)
	clientIP := waf.NormalizeClientIP(r.Header.Get("X-Waf-Client-IP"))
	if clientIP == "" {
		// X-Waf-Client-IP 缺失时使用 RemoteAddr（Tengine 内部调用，值为 127.0.0.1）
		clientIP = waf.NormalizeClientIP(r.RemoteAddr)
	}
	// X-Real-IP 是 waf.clientIP 实际读取的头，必须填归一化后的值（上面构造 Header 时
	// 塞的是原始头）。IPv6 地址直接拼 ":0" 会得到 "2001:db8::1:0" 这种畸形 RemoteAddr，
	// 因此改用 net.JoinHostPort 正确加方括号。
	realReq.Header.Set("X-Real-IP", clientIP)
	realReq.RemoteAddr = net.JoinHostPort(clientIP, "0")

	// ===== 第一步：CC 防御检查（频率限制 + 按域名强检测） =====
	if wp.ccDefense != nil {
		ccResult := wp.ccDefense.Check(realReq)
		if ccResult.Action == waf.Challenge {
			// 日志里带全绑定三元组 host|ip|fp 与 Cookie 到达状态：反复收到验证页时，
			// 只有这几项能直接指出是哪一环对不上——cookie=absent 说明凭证根本没回到
			// 边缘（Secure/Path/转发问题），cookie=mismatch 说明凭证到了但绑定变了，
			// 此时比对同一浏览器相邻两条日志的 ip/fp/host 即可看出是哪个分量在动
			// （双栈客户端在 IPv4/IPv6 间切换导致 ip 变化是最常见的一种）。
			log.Printf("CC DEFENSE CHALLENGE rule=%s ip=%s host=%s fp=%s cookie=%s uri=%s msg=%s",
				ccResult.Rule, clientIP, realReq.Host,
				waf.ChallengeBindingFP(realReq.Header.Get("User-Agent")),
				waf.ChallengeCookieState(realReq.Header.Get("Cookie")),
				rawURI, ccResult.Message)
			// nginx 的 auth_request 模块只原生识别子请求的 2xx/401/403 状态码，
			// 其他任何状态码都会被 nginx 自身转换成主请求的 500，子请求响应体
			// 也一律被丢弃（无法借此把 Set-Cookie/HTML 传给客户端）。这里必须
			// 用 401（而不是任意自定义码），由 Tengine 模板里的 error_page 401
			// 转发到真实 proxy_pass 的挑战页 location，才能正常把响应体和
			// Set-Cookie 发给客户端。
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if ccResult.Action == waf.Block {
			log.Printf("CC DEFENSE BLOCK rule=%s ip=%s uri=%s msg=%s",
				ccResult.Rule,
				clientIP,
				rawURI,
				ccResult.Message,
			)
			// auth_request 只会原生转发 401/403（其余码会变成 500），
			// 因此这里必须用 403 而不是 429，才能被 Tengine 直接转发给客户端。
			http.Error(w, "Too Many Requests", http.StatusForbidden)
			return
		}
	}

	// ===== 第二步：内置段（IP 封禁表 / ACME 路径限速 / UA 校验）=====
	// 这一段不受面板「启用 WAF 防护」开关控制：封禁表是全节点共享的一份，
	// 代理把开关关掉的意思是"我不想跑签名规则"，不该顺手清掉已经生效的封禁。
	if res := wp.engine.CheckBase(realReq); res.Action == waf.Block {
		log.Printf("WAF BLOCK rule=%s ip=%s uri=%s msg=%s",
			res.Rule,
			clientIP,
			rawURI,
			res.Message,
		)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// ===== 第三步：区域规则（按国家封禁 / 只放行）=====
	// 排在内置段之后、托管规则之前，且不受面板「启用 WAF 防护」开关控制：
	// 区域规则的归属由平台总闸和域名配置决定，代理关掉 WAF 是想停掉签名规则，
	// 不是想把已封禁国家的流量放进来。放在托管规则之前还有一个理由：
	// 它只要一次二分就能得出"这个来源不受欢迎"，不该再去跑几十条正则。
	if wp.geoEnforce(w, realReq.Host, clientIP, rawURI) {
		return
	}

	// ===== 第四步：托管规则段（受开关/模式/级别/规则集/单条覆盖/包版本与灰度控制）=====
	verdict := wp.engine.InspectManaged(realReq)
	if verdict.Hit && !verdict.Observe {
		log.Printf("WAF BLOCK rule=%s ip=%s host=%s pkg=%s uri=%s msg=%s",
			verdict.Rule,
			clientIP,
			realReq.Host,
			verdict.Package,
			rawURI,
			verdict.Message,
		)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if verdict.Hit {
		// 观察模式：命中已在引擎里记账，这里只留一行证据后照常放行 200。
		// 不打这行的话，"只记账不拦"在节点日志上就完全不可见，灰度验证没素材可看。
		log.Printf("WAF OBSERVE rule=%s ip=%s host=%s pkg=%s uri=%s msg=%s",
			verdict.Rule,
			clientIP,
			realReq.Host,
			verdict.Package,
			rawURI,
			verdict.Message,
		)
	}

	// ===== 第五步：上传校验（文件名 / 大小 / 魔术字节）=====
	if res := wp.engine.CheckUpload(realReq); res.Action == waf.Block {
		log.Printf("WAF BLOCK rule=%s ip=%s uri=%s msg=%s",
			res.Rule,
			clientIP,
			rawURI,
			res.Message,
		)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func firstNonEmpty(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}

// domainStats 解析本节点所有域名的当日 access log，返回流量和访问 IP 统计。
func (h *Handler) domainStats(w http.ResponseWriter, r *http.Request) {
	collector := stats.NewCollector("/var/log/tengine")
	domains := h.store.List()
	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Domain
	}
	result := collector.CollectAll(names)
	jsonResp(w, http.StatusOK, result)
}

// statsOverview 解析本节点所有域名当日 access log，返回全站大盘数据
// （24 小时分桶 + Top 域名 + Top 客户端 IP + 今日总计）。
func (h *Handler) statsOverview(w http.ResponseWriter, r *http.Request) {
	collector := stats.NewCollector("/var/log/tengine")
	domains := h.store.List()
	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Domain
	}
	jsonResp(w, http.StatusOK, collector.CollectOverview(names))
}

// rotateTicketKey 接收主控推送的 SSL 会话票据密钥并追加到本地文件。
func (h *Handler) rotateTicketKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TicketKey string `json:"ticket_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TicketKey == "" {
		http.Error(w, "ticket_key required", http.StatusBadRequest)
		return
	}

	key, err := base64.StdEncoding.DecodeString(body.TicketKey)
	if err != nil {
		http.Error(w, "invalid base64 ticket_key", http.StatusBadRequest)
		return
	}

	// 追加到票据密钥文件
	ticketPath := "/etc/ssl/cdnpanel/ticket.key"
	if err := os.MkdirAll(filepath.Dir(ticketPath), 0755); err != nil {
		http.Error(w, "mkdir failed", http.StatusInternalServerError)
		return
	}

	f, err := os.OpenFile(ticketPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		http.Error(w, "open ticket file failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.Write(key); err != nil {
		http.Error(w, "write ticket key failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 触发 Tengine 平滑重载
	h.controller.Reload()

	log.Printf("rotated SSL ticket key on edge node")
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

// getXDPConfig 读取当前 XDP 配置
func (h *Handler) getXDPConfig(w http.ResponseWriter, r *http.Request) {
	if !h.xdpMgr.Loaded() {
		http.Error(w, "XDP not loaded", http.StatusServiceUnavailable)
		return
	}
	cfg, err := h.xdpMgr.GetConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, http.StatusOK, cfg)
}

// setXDPConfig 应用 XDP 配置
func (h *Handler) setXDPConfig(w http.ResponseWriter, r *http.Request) {
	if !h.xdpMgr.Loaded() {
		http.Error(w, "XDP not loaded", http.StatusServiceUnavailable)
		return
	}
	var cfg xdp.XDPConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "invalid config format", http.StatusBadRequest)
		return
	}
	if err := h.xdpMgr.SetConfig(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 只存 SetConfig 接受了的配置：被拒的（如 port_guard 在空白名单上开启）不能进存档，
	// 否则每次启动恢复都会失败一次。
	if err := h.saveXDPState(cfg); err != nil {
		log.Printf("XDP config persist failed: %v", err)
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── CC 防御处理函数 ──────────────────────────────────────────────

// getCCConfig 获取CC防御配置
func (h *Handler) getCCConfig(w http.ResponseWriter, r *http.Request) {
	if h.ccDefense == nil {
		http.Error(w, "CC defense not initialized", http.StatusInternalServerError)
		return
	}
	config := h.ccDefense.GetConfig()
	jsonResp(w, http.StatusOK, config)
}

// updateCCConfig 更新CC防御配置
func (h *Handler) updateCCConfig(w http.ResponseWriter, r *http.Request) {
	if h.ccDefense == nil {
		http.Error(w, "CC defense not initialized", http.StatusInternalServerError)
		return
	}

	// 用指针字段接收，才能区分"字段未出现在 payload 里"和"显式设为 0/false"。
	// 直接 Decode 到 waf.CCConfig 会让任何缺失字段静默变成零值：漏 enabled 就等于
	// 整个 CC 防御被关闭（Check 第一行即 return Allow），漏 block_duration 会让
	// blockedUntil == 封禁时刻，下一个请求立刻判过期解封 —— 表现就是"限速命中了但从不封禁"。
	var patch struct {
		Enabled           *bool          `json:"enabled"`
		RequestsPerSecond *int           `json:"requests_per_second"`
		RequestsPerMinute *int           `json:"requests_per_minute"`
		BurstSize         *int           `json:"burst_size"`
		BlockDuration     *time.Duration `json:"block_duration"`
		WhitelistIPs      *[]string      `json:"whitelist_ips"`
		PathWhitelist     *[]string      `json:"path_whitelist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	config := h.ccDefense.GetConfig()
	if patch.Enabled != nil {
		config.Enabled = *patch.Enabled
	}
	if patch.RequestsPerSecond != nil {
		config.RequestsPerSecond = *patch.RequestsPerSecond
	}
	if patch.RequestsPerMinute != nil {
		config.RequestsPerMinute = *patch.RequestsPerMinute
	}
	if patch.BurstSize != nil {
		config.BurstSize = *patch.BurstSize
	}
	if patch.BlockDuration != nil {
		config.BlockDuration = *patch.BlockDuration
	}
	if patch.WhitelistIPs != nil {
		config.WhitelistIPs = *patch.WhitelistIPs
	}
	if patch.PathWhitelist != nil {
		config.PathWhitelist = *patch.PathWhitelist
	}

	// 兜底：阈值/封禁时长为非正数时限速逻辑会退化成"全放"或"全封"，两种都不是用户想要的。
	// 拒绝这类配置而不是静默接受，避免压测时看到"CC 好像没生效"却查不出原因。
	if config.RequestsPerSecond <= 0 || config.RequestsPerMinute <= 0 || config.BlockDuration <= 0 {
		http.Error(w, "requests_per_second, requests_per_minute and block_duration must all be > 0", http.StatusBadRequest)
		return
	}

	h.ccDefense.UpdateConfig(config)
	log.Printf("CC defense config updated: enabled=%v, rps=%d, rpm=%d, burst=%d, block=%s",
		config.Enabled, config.RequestsPerSecond, config.RequestsPerMinute,
		config.BurstSize, config.BlockDuration)
	if err := h.saveCCState(config); err != nil {
		// 不回滚：配置已在内存生效，只是重启后会回到默认值（主控重新注册时会再补发一次）。
		log.Printf("CC defense config persist failed: %v", err)
	}

	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

// getCCStats 获取CC防御统计信息
func (h *Handler) getCCStats(w http.ResponseWriter, r *http.Request) {
	if h.ccDefense == nil {
		http.Error(w, "CC defense not initialized", http.StatusInternalServerError)
		return
	}
	stats := h.ccDefense.GetStats()
	jsonResp(w, http.StatusOK, stats)
}

// getCCTrackedIPs 获取被追踪的IP列表
func (h *Handler) getCCTrackedIPs(w http.ResponseWriter, r *http.Request) {
	if h.ccDefense == nil {
		http.Error(w, "CC defense not initialized", http.StatusInternalServerError)
		return
	}
	ips := h.ccDefense.GetTrackedIPs()
	jsonResp(w, http.StatusOK, map[string]interface{}{
		"ips": ips,
	})
}

// unblockCCIP 解除CC防御封禁的IP
func (h *Handler) unblockCCIP(w http.ResponseWriter, r *http.Request) {
	if h.ccDefense == nil {
		http.Error(w, "CC defense not initialized", http.StatusInternalServerError)
		return
	}

	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}

	// 验证IP格式
	if net.ParseIP(body.IP) == nil {
		http.Error(w, "invalid IP address: "+body.IP, http.StatusBadRequest)
		return
	}

	h.ccDefense.UnblockIP(body.IP)
	log.Printf("CC defense: unblocked IP %s", body.IP)
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok", "unblocked": body.IP})
}

// applyAttackState 接收并应用来自其他节点的域名攻击态广播消息。
func (h *Handler) applyAttackState(w http.ResponseWriter, r *http.Request) {
	if h.ccDefense == nil {
		http.Error(w, "CC defense not initialized", http.StatusInternalServerError)
		return
	}

	var msg waf.AttackStateMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if msg.Domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	h.ccDefense.ApplyAttackState(msg)
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok", "domain": msg.Domain})
}
