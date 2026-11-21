package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"cdn/internal/config"
	"cdn/internal/edgeapi"
	"cdn/internal/ssl"
	"cdn/internal/tengine"
	"cdn/internal/xdp"
)

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:9090", "edge agent listen address")
	token := flag.String("token", "", "shared secret token (use --token-file instead in production)")
	tokenFile := flag.String("token-file", "", "path to file containing the shared secret token")
	masterURL := flag.String("master", "", "master panel URL for auto-registration (e.g. https://master:7072)")
	masterCert := flag.String("master-cert", "", "master TLS certificate path for verification")
	xdpIface := flag.String("xdp-iface", "", "network interface to attach XDP")
	xdpObj := flag.String("xdp-obj", xdp.DefaultObjPath(), "path to compiled cdn_xdp.o")
	cfgPath := flag.String("config", "/etc/cdnpanel/config.json", "config file path")
	certDir := flag.String("cert-dir", "/etc/cdnpanel/edge-tls", "directory to store edge TLS cert/key")
	xdpStatePath := flag.String("xdp-state", "/var/lib/cdnedge/xdp_blocked.json", "path to persist XDP auto-block state across restarts")
	// 这两个 flag 只是**初始值**：面板下发的阶梯会写进 --xdp-state 存档并在重启后
	// 覆盖它们（否则节点一重启就悄悄回到 flag 值，面板显示的和实际封人的不一致）。
	// 要让 flag 重新生效，得先在面板上下发一次，或清掉存档里的 ladder 字段。
	// 面板下发的 CC / XDP 阈值存档。不落盘的话 cdnedge 一重启（含升级）就回到内置默认值。
	ccStatePath := flag.String("cc-state", "/var/lib/cdnedge/cc_config.json", "path to persist panel-pushed CC defense config across restarts")
	xdpCfgStatePath := flag.String("xdp-config-state", "/var/lib/cdnedge/xdp_config.json", "path to persist panel-pushed XDP thresholds across restarts")
	// CC 挑战凭证签名密钥：主控下发的部署级随机密钥。以前用内置在二进制里的静态密钥，
	// 拿到二进制即可伪造 __cc_chk 绕过人机验证。
	ccChallengeKeyPath := flag.String("cc-challenge-key", "/var/lib/cdnedge/cc_challenge.key", "path to persist the deployment CC challenge signing key pushed by the master")
	// WAF 托管规则的两份存档：面板下发的策略 + 管理员维护后下发的规则包（密文）。
	// 规则包尤其必须落盘：不落的话 cdnedge 一升级就退回出厂包，管理员刚下发的版本全网静默失效。
	wafStatePath := flag.String("waf-config-state", "/var/lib/cdnedge/waf_config.json", "path to persist panel-pushed WAF policy (mode/level/rule toggles/gray) across restarts")
	wafPackageStatePath := flag.String("waf-package-state", "/var/lib/cdnedge/waf_package.json", "path to persist panel-pushed WAF rule packages (encrypted) across restarts")
	// 区域规则的两份存档：主控下发的配置（平台总闸 + 整节点策略 + 例外清单）与编译好的前缀表。
	// 表尤其必须落盘：不落的话 cdnedge 一升级就要等下一次下发才有表，而在那之前所有来源都判成
	// "未知"并放行——面板上那条"已封禁某国"正好在升级后这段时间里是假的。
	geoConfigStatePath := flag.String("geo-config-state", "/var/lib/cdnedge/geo_config.json", "path to persist panel-pushed geo policy (scope switch, node policy, exceptions) across restarts")
	geoTableStatePath := flag.String("geo-table-state", "/var/lib/cdnedge/geo_table.json", "path to persist the panel-compiled geo prefix table across restarts")
	xdpBanLadder := flag.String("xdp-ban-ladder", "", "initial comma-separated escalating ban durations for repeat offenders (e.g. 1h,6h,24h); empty uses built-in default; panel-pushed values take precedence after restart")
	xdpOffenderTTL := flag.Duration("xdp-offender-ttl", 0, "initial forgetting window for repeat-offense counts (0 uses built-in default 48h); must exceed the last ladder tier")
	// 自动注册相关（仅 --master 非空时使用）
	clusterID := flag.String("cluster", "", "cluster ID to join when auto-registering (only applied if the node has no cluster on the panel yet)")
	registerSecretFile := flag.String("register-secret-file", "/etc/cdnpanel/edge_register.secret", "file containing the master's edge registration secret (copy of master /etc/cdnpanel/edge_register.secret)")
	nodeIDFile := flag.String("node-id-file", "/etc/cdnpanel/edge.node_id", "file persisting this node's registration ID across restarts")
	flag.Parse()

	// 阶梯解析失败直接 Fatal，不退回默认值。写错一个档位（比如 "5min"）时如果静默
	// 用默认阶梯，运维会以为自己配的时长生效了，而偏差只在真的封到那一档时才暴露。
	banLadder, err := xdp.ParseBanLadder(*xdpBanLadder)
	if err != nil {
		log.Fatalf("--xdp-ban-ladder: %v", err)
	}
	// 末档 >= 遗忘窗口时封顶档形同虚设（被关满末档的 IP 解封时计数刚好过期，下次回首档）。
	// 这个矛盾不会报任何错，只表现为「封顶档好像没用」，所以在启动时就拦住。
	if err := xdp.ValidateBanConfig(banLadder, *xdpOffenderTTL); err != nil {
		log.Fatalf("--xdp-ban-ladder / --xdp-offender-ttl: %v", err)
	}

	// 优先从文件读取 token，避免进程参数列表暴露
	resolvedToken := *token
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("read token file %s: %v", *tokenFile, err)
		}
		resolvedToken = strings.TrimSpace(string(data))
	}
	if resolvedToken == "" {
		log.Fatal("--token or --token-file is required")
	}

	cfg := config.DefaultPanelConfig()
	if data, err := os.ReadFile(*cfgPath); err == nil {
		_ = json.Unmarshal(data, cfg)
	}

	store, err := config.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}

	// 提取对外监听端口（去掉 IP 前缀）。对外端口只跑 HTTPS（带 token 认证）。
	_, edgePortOnly, _ := net.SplitHostPort(*listenAddr)
	if edgePortOnly == "" {
		edgePortOnly = "9090"
	}
	// 本地明文 WAF 端口：Tengine 的 auth_request 子请求（/edge/waf/check、
	// /edge/waf/challenge）从本机 127.0.0.1 发起。若让它们走对外 HTTPS 端口，
	// 明文 HTTP 打 TLS 端口会握手失败，auth_request 拿到非 2xx/401/403 → nginx
	// 把主请求转成 500。因此额外起一个只绑 127.0.0.1 的明文 HTTP 监听器专供子请求，
	// 端口取对外端口 +1（回环专用，无需开防火墙）。
	wafPort := localWafPort(edgePortOnly)
	// generator 渲染模板里 auth_request 的 proxy_pass 目标端口，用本地明文 WAF 端口。
	generator, err := tengine.NewGeneratorWithBinary(cfg.SitesAvailable, cfg.SitesEnabled, wafPort, cfg.TengineCmd)
	if err != nil {
		log.Fatalf("init generator: %v", err)
	}

	controller := tengine.NewController(cfg.TengineCmd, cfg.TenginePid, cfg.TengineConf)
	_ = ssl.NewManager(cfg.SSLBasePath, cfg.AutocertEmail)

	// 自动配置 Tengine nginx.conf：确保 include sites-enabled 目录
	if err := ensureTengineInclude(cfg.TengineConf, cfg.SitesEnabled); err != nil {
		log.Printf("Warning: failed to configure Tengine include: %v", err)
	}
	// 站点配置里的 proxy_cache / proxy_cache_purge 都引用 edge_cache；主配置缺这个 zone 时
	// tengine -t 失败，Tengine 重启后起不来。手工改过或老版本装的主配置在这里补上。
	if added, err := ensureEdgeCacheZone(cfg.TengineConf, cfg.SitesEnabled, edgeCacheDir); err != nil {
		log.Printf("Warning: check edge_cache zone in %s: %v", cfg.TengineConf, err)
	} else if added {
		if out, err := controller.TestAndReload(); err != nil {
			log.Printf("Warning: added edge_cache zone but tengine test/reload failed: %v, output: %s", err, out)
		} else {
			log.Printf("✓ Tengine reloaded with edge_cache zone")
		}
	}

	// 站点模板 location / 里的 $connection_upgrade（WebSocket 状态机）同样依赖主配置：
	// 缺了这个 map，tengine -t 报 unknown variable，本节点所有域名的新配置都推不下去。
	if added, err := ensureUpgradeMap(cfg.TengineConf, cfg.SitesEnabled); err != nil {
		log.Printf("Warning: check $connection_upgrade map in %s: %v", cfg.TengineConf, err)
	} else if added {
		if out, err := controller.TestAndReload(); err != nil {
			log.Printf("Warning: added $connection_upgrade map but tengine test/reload failed: %v, output: %s", err, out)
		} else {
			log.Printf("✓ Tengine reloaded with $connection_upgrade map")
		}
	}

	// 自动检测网卡（如果未指定）
	detectedIface := *xdpIface
	if detectedIface == "" {
		detectedIface = autoDetectInterface()
		if detectedIface != "" {
			log.Printf("Auto-detected network interface: %s", detectedIface)
		}
	}

	xdpMgr := xdp.NewManager(detectedIface, *xdpObj)
	// newAutoBlocker 按同一套阈值构造 AutoBlocker（未 Start）。启动时挂上 XDP 直接用它；
	// 启动时没挂上（.o 还没编译）的节点，面板「安装 XDP」热加载成功后 handler 也用它补建，
	// 否则热装的 XDP 只按静态阈值丢包，攻击源永远不会被整 IP 封禁。
	newAutoBlocker := func() *xdp.AutoBlocker {
		return xdp.NewAutoBlocker(xdpMgr, xdp.AutoBlockerConfig{
			Interval: 5 * time.Second, // 扫描间隔从 10s 降到 5s,更快响应新攻击 IP
			Duration: 5 * time.Minute,
			SYNLimit: xdp.DefaultSYNLimit,
			PPSLimit: xdp.DefaultPPSLimit,
			// 封禁阈值取丢包阈值的 2 倍：刚过 conn_limit 时 XDP 只丢多出来的 SYN（客户端会
			// 重传），真人撞线后自然回落；只有持续远超阈值的源才值得整 IP 封掉 ——
			// 封禁会连同 NAT 后面的所有真人一起关掉至少 1 小时（见 DefaultBanLadder）。
			ConnLimit: xdp.DefaultConnLimit * 2,
			AckLimit:  xdp.DefaultAckLimit,
			// RST/FIN 与 XDP 丢包阈值一致：XDP 侧只统计发往服务端口的 RST/FIN，
			// 回源连接的 RST/FIN 不进这两张表，不会把源站封掉。
			RSTLimit: xdp.DefaultTCPRstLimit,
			FINLimit: xdp.DefaultFinLimit,
			// ICMP 封禁阈值取丢包阈值的 10 倍：XDP 对差错报文本来就放宽 10 倍，
			// 封禁比丢包重得多，不能因为一台路由器回了一串 "需要分片" 就把它整个封掉。
			ICMPLimit: xdp.DefaultICMPLimit * 10,
			// DNS 不自动封禁：udp_dns_rate 同时统计源端口 53 的包 —— 那是本机解析器的
			// 应答，封掉等于把节点自己的 DNS 解析掐断。
			DNSLimit: 0,
			// 落盘封禁状态：eBPF blocklist 随 XDP 卸载消失，不持久化的话
			// 进程重启（含版本升级）会把所有攻击 IP 一次性放行。
			StatePath: *xdpStatePath,
			// 累犯递增阶梯：同一 IP 反复被封则时长逐级拉长。传 nil 时
			// NewAutoBlocker 用 DefaultBanLadder（5m→30m→2h→12h→24h 封顶）。
			// 上面的 Duration 只在阶梯为空时才起作用。
			BanLadder:   banLadder,
			OffenderTTL: *xdpOffenderTTL,
		})
	}
	var autoBlocker *xdp.AutoBlocker
	if detectedIface != "" {
		// 检查 XDP 程序文件是否存在
		if _, err := os.Stat(*xdpObj); os.IsNotExist(err) {
			log.Printf("XDP program not found at %s - compile it first with: clang -O2 -target bpf -c internal/xdp/cdn_xdp.c -o %s", *xdpObj, *xdpObj)
		} else if err := xdpMgr.Load(); err != nil {
			log.Printf("XDP load failed (non-fatal): %v - XDP features will be unavailable", err)
		} else {
			log.Printf("✓ XDP attached to %s", detectedIface)
			// 初始化默认配置。额外放行 agent 自己的对外端口，否则 port_guard 一开
			// 主控就连不上这个节点了。
			if err := xdpMgr.InitDefaults(parsePortForGuard(edgePortOnly)); err != nil {
				log.Printf("XDP init defaults failed: %v", err)
			}

			// 启动自动封禁:定期扫描 XDP per-IP 速率 map,把超阈值的源 IP 塞进 blocklist。
			// 这样 L4 洪水源在下一波 SYN 到达时就在 XDP 层被 DROP,不再进入内核栈/Tengine。
			autoBlocker = newAutoBlocker()
			autoBlocker.Start()
		}
	} else {
		log.Printf("No suitable network interface found for XDP - XDP features will be unavailable")
	}

	// TLS：加载或生成自签名证书
	tlsCert, fingerprint, err := ensureCert(*certDir, *listenAddr)
	if err != nil {
		log.Fatalf("TLS cert setup: %v", err)
	}

	handler := edgeapi.NewHandler(resolvedToken, store, generator, controller, xdpMgr, autoBlocker)
	handler.SetAutoBlockerFactory(newAutoBlocker)
	handler.SetAgentPort(parsePortForGuard(edgePortOnly))
	// 先恢复存档再对外服务：CC 立即恢复；XDP 已在上面 InitDefaults 过，这里用存档覆盖默认值。
	handler.SetConfigStatePaths(*ccStatePath, *xdpCfgStatePath)
	handler.RestoreXDPConfig()
	handler.LoadChallengeKey(*ccChallengeKeyPath)
	// WAF 同理：先恢复策略与规则包再对外服务，重启后第一批请求就按面板下发的判定，
	// 不会先放行一段再切过去。
	handler.SetWAFStatePaths(*wafStatePath, *wafPackageStatePath)
	// 区域规则同理：先恢复策略与前缀表再对外服务。恢复顺序是先配置后表，
	// 因为读表时要按当前配置判断"有启用的规则但没表"该报什么原因。
	handler.SetGeoStatePaths(*geoConfigStatePath, *geoTableStatePath)

	// 注入跨节点攻击态广播器（边缘节点无主控，不需要广播；主控侧会注入）
	// 边缘节点只接收广播，不发起广播，因此这里不设置 broadcaster

	// 注入 XDP AutoBlocker 的广播 hook：让 XDP 自动封禁同步到 WAF 封禁表，
	// 并触发 WAF 的 l4BlockHook（如果边缘节点向主控注册了的话），实现跨节点封禁同步
	handler.SetupXDPBroadcast()

	srv := &http.Server{
		Addr:    *listenAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 本地明文 HTTP 监听器：只绑 127.0.0.1:wafPort，专供 Tengine 的 auth_request
	// 子请求（/edge/waf/check、/edge/waf/challenge）。handler 已限制这两个路径只接受
	// 127.0.0.1/::1，其余需 token 的端点即使被本地进程命中也会因缺 Bearer 而 401，
	// 因此本地明文监听不构成对外暴露面。
	localSrv := &http.Server{
		Addr:         "127.0.0.1:" + wafPort,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		log.Printf("cdnedge local WAF endpoint listening on 127.0.0.1:%s (plain HTTP, for Tengine auth_request)", wafPort)
		if err := localSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("local waf listen: %v", err)
		}
	}()

	go func() {
		log.Printf("cdnedge agent listening on %s (TLS)", *listenAddr)
		log.Printf("Certificate fingerprint (SHA-256): %s", fingerprint)
		if *masterURL != "" {
			log.Printf("Auto-registering with master: %s", *masterURL)
			go startAutoRegister(autoRegisterOpts{
				masterURL:          *masterURL,
				masterCert:         *masterCert,
				listenAddr:         *listenAddr,
				tokenFile:          *tokenFile,
				token:              resolvedToken,
				wafPort:            wafPort,
				clusterID:          *clusterID,
				registerSecretFile: *registerSecretFile,
				nodeIDFile:         *nodeIDFile,
				certFingerprint:    fingerprint,
				handler:            handler,
			})
		} else {
			log.Printf("Add this node in cdnpanel with the above fingerprint and token")
		}
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down cdnedge...")
	// handler.Stop 会停掉 AutoBlocker 并落盘封禁（含热安装后才建的那个），再卸载 XDP。
	handler.Stop()
	xdpMgr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = localSrv.Shutdown(ctx)
	log.Println("cdnedge stopped")
}

// localWafPort 返回本地明文 WAF 监听端口：对外端口 +1；若对外端口是 65535 则回退 -1，
// 保证落在合法范围内。这个端口只绑 127.0.0.1，不对外，无需与对外端口协商。
func localWafPort(edgePort string) string {
	n, err := strconv.Atoi(edgePort)
	if err != nil || n < 1 || n > 65535 {
		return "19090"
	}
	if n < 65535 {
		return strconv.Itoa(n + 1)
	}
	return strconv.Itoa(n - 1)
}

// parsePortForGuard 把监听端口字符串转成 uint16，供 XDP 服务端口白名单使用。
// 解析失败返回 0，SetServicePorts 会忽略 0 值——宁可少放行一个端口（面板暂时连不上，
// 可以改配置重启修好），也不能把垃圾值写进白名单。
func parsePortForGuard(port string) uint16 {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return uint16(n)
}

type autoRegisterOpts struct {
	masterURL, masterCert, listenAddr, tokenFile, token, wafPort string
	clusterID, registerSecretFile, nodeIDFile                    string
	certFingerprint                                              string
	handler                                                      *edgeapi.Handler
}

// loadOrCreateNodeID 读取落盘的节点 ID，没有则生成并写入。以前每次启动都 uuid.New()，
// 主控把每次重启都当成新节点：面板上重复节点越积越多，旧记录永远离线。
func loadOrCreateNodeID(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	id := uuid.New().String()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(id+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return id, nil
}

// startAutoRegister 主动向主控注册当前边缘节点。
// 通过 HTTPS POST /api/edge/register 发送节点信息，主控会返回注册凭证。
func startAutoRegister(o autoRegisterOpts) {
	masterURL, masterCert, listenAddr, tokenFile, wafPort := o.masterURL, o.masterCert, o.listenAddr, o.tokenFile, o.wafPort

	// main 已经按 --token-file / --token 解析好了 token，直接用；不再重读文件
	// （用 --token 启动时 tokenFile 为空，重读必然失败）。
	nodeToken := o.token
	if nodeToken == "" {
		log.Printf("auto-register: empty token")
		return
	}

	// 注册密钥与节点 ID 放在最前面检查：缺了就不必再等服务起来、再重试 50 次。
	// SSH 一键部署的节点由主控建好记录并写入 node_id 文件，不需要注册密钥，
	// 直接进入心跳 + 上报（节点状态与统计全部由边缘主动推送，主控不回连拉取）。
	var registerSecret string
	if secretData, err := os.ReadFile(o.registerSecretFile); err == nil {
		registerSecret = strings.TrimSpace(string(secretData))
	}
	if registerSecret == "" {
		nodeID := readNodeID(o.nodeIDFile)
		if nodeID == "" {
			log.Printf("auto-register: no register secret at %s and no node id at %s (copy master's /etc/cdnpanel/edge_register.secret here); reporting disabled", o.registerSecretFile, o.nodeIDFile)
			return
		}
		client, err := masterClient(masterCert, tokenFile)
		if err != nil {
			log.Printf("auto-register: %v", err)
			return
		}
		log.Printf("auto-register: no register secret, using pre-provisioned node_id=%s; starting heartbeat/report", nodeID)
		startPushLoops(masterURL, nodeToken, nodeID, o.handler, client)
		return
	}
	nodeID, err := loadOrCreateNodeID(o.nodeIDFile)
	if err != nil {
		// 不退回随机 ID：那样每次重启都会在面板上多出一个重复节点。
		log.Printf("auto-register: load/create node id %s failed: %v; auto-registration disabled", o.nodeIDFile, err)
		return
	}
	// 等待边缘服务启动（证书生成需要时间）。健康检查走本地明文 WAF 端口，
	// 对外端口只跑 HTTPS，用明文 HTTP GET 打它会握手失败。
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		if resp, err := http.Get("http://127.0.0.1:" + wafPort + "/edge/status"); err == nil {
			resp.Body.Close()
			break
		}
	}

	// 证书指纹直接取启动时 ensureCert 算好的那一份。以前这里按写死的
	// /etc/cdnpanel/edge-tls 再读一遍文件，用 --cert-dir 换过目录的节点会读到空，
	// 注册上去的 cert_fingerprint 为空 → 主控拒绝向它推送任何配置（无指纹节点），
	// 表现是"面板显示已下发、这台节点其实从没收到"。
	certFingerprint := o.certFingerprint

	client, err := masterClient(masterCert, tokenFile)
	if err != nil {
		log.Printf("auto-register: %v", err)
		return
	}

	// 获取本机 IP 列表
	var localIPs []string
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			localIPs = append(localIPs, ipNet.IP.String())
		}
	}

	// 重试注册（指数退避）
	backoff := 2 * time.Second
	for attempt := 0; attempt < 50; attempt++ {
		regURL := masterURL + "/api/edge/register"

		payload := map[string]string{
			"node_id":          nodeID,
			"token":            nodeToken,
			"listen":           listenAddr,
			"local_ips":        strings.Join(localIPs, ","),
			"cert_fingerprint": certFingerprint,
			"cluster_id":       o.clusterID,
			"register_secret":  registerSecret,
		}
		body, _ := json.Marshal(payload)

		req, _ := http.NewRequest("POST", regURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("auto-register: master unreachable at %s, retrying in %v...", regURL, backoff)
			time.Sleep(backoff)
			backoff = minDuration(backoff*2, 30*time.Second)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result struct {
				Status string `json:"status"`
			}
			json.Unmarshal(respBody, &result)
			if result.Status == "ok" {
				log.Printf("auto-register: successfully registered with master (node_id=%s, cluster=%q)", nodeID, o.clusterID)
				startPushLoops(masterURL, nodeToken, nodeID, o.handler, client)
				return
			}
		}
		// 400/403（密钥错、集群不存在、node_id 不合法）重试也不会变好，直接停下并把原因打出来。
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden {
			log.Printf("auto-register: master rejected registration (%d): %s; fix the config and restart cdnedge", resp.StatusCode, strings.TrimSpace(string(respBody)))
			// 注册密钥轮换后，已注册节点重启会被拒；节点记录和 token 仍有效，照常心跳/上报。
			startPushLoops(masterURL, nodeToken, nodeID, o.handler, client)
			return
		}

		log.Printf("auto-register: master returned %d, retrying...", resp.StatusCode)
		time.Sleep(backoff)
		backoff = minDuration(backoff*2, 30*time.Second)
	}
	log.Printf("auto-register: failed after 50 attempts")
}

// readNodeID 读取主控（SSH 部署）或上次注册落盘的节点 ID；不存在或为空返回 ""。
func readNodeID(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// masterClient 构造连主控用的 HTTPS 客户端：优先 --master-cert，其次 token 目录下的
// master-cert.pem，都没有时跳过证书校验（兼容模式；鉴权仍靠节点 token）。
func masterClient(masterCert, tokenFile string) (*http.Client, error) {
	var rootCAPool *x509.CertPool
	if masterCert != "" {
		certData, err := os.ReadFile(masterCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read master cert: %w", err)
		}
		rootCAPool = x509.NewCertPool()
		if !rootCAPool.AppendCertsFromPEM(certData) {
			return nil, fmt.Errorf("failed to parse master cert")
		}
	} else if tokenFile != "" {
		certPath := filepath.Join(filepath.Dir(tokenFile), "master-cert.pem")
		if certData, err := os.ReadFile(certPath); err == nil {
			rootCAPool = x509.NewCertPool()
			rootCAPool.AppendCertsFromPEM(certData)
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if rootCAPool != nil {
		tlsConfig.RootCAs = rootCAPool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

const (
	heartbeatInterval = 3 * time.Second
	reportInterval    = 10 * time.Second
)

// startPushLoops 启动心跳与统计上报。两者都是边缘 → 主控的主动推送，主控不再回连节点拉状态。
func startPushLoops(masterURL, token, nodeID string, h *edgeapi.Handler, client *http.Client) {
	go keepHeartbeat(masterURL, token, nodeID, h, client)
	go keepReporting(masterURL, token, nodeID, h, client)
}

// keepHeartbeat 定期向主控发送心跳，保持节点在线状态。
// 状态在进程内直接生成（以前从本地 WAF 端口 GET /edge/status，那个接口要 Bearer，
// 不带 token 永远 401，心跳里的状态一直是空的）。
func keepHeartbeat(masterURL, token, nodeID string, h *edgeapi.Handler, client *http.Client) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for ; ; <-ticker.C {
		payload := map[string]any{
			"node_id": nodeID,
			"token":   token,
			"status":  h.BuildStatus(),
		}
		body, _ := json.Marshal(payload)
		if err := postMaster(client, masterURL+"/api/edge/heartbeat", body, false); err != nil {
			log.Printf("heartbeat: %v", err)
		}
	}
}

// keepReporting 定期把完整统计快照（流量/缓存/CC/XDP/WAF 封禁）推给主控。
// 主控只读这份快照，不再对 /edge/stats、/edge/cc/*、/edge/xdp/* 等接口发起请求。
func keepReporting(masterURL, token, nodeID string, h *edgeapi.Handler, client *http.Client) {
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	failing := false
	for ; ; <-ticker.C {
		payload := map[string]any{
			"node_id": nodeID,
			"token":   token,
			"report":  h.BuildReport(),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("report: marshal: %v", err)
			continue
		}
		if err := postMaster(client, masterURL+"/api/edge/report", body, true); err != nil {
			if !failing {
				log.Printf("report: %v (will keep retrying every %v)", err, reportInterval)
			}
			failing = true
			continue
		}
		if failing {
			log.Printf("report: master reachable again")
		}
		failing = false
	}
}

// postMaster POST JSON 到主控；gz 为 true 时 gzip 压缩请求体（统计快照里 IP 列表可能较大）。
func postMaster(client *http.Client, url string, body []byte, gz bool) error {
	var rd io.Reader = bytes.NewReader(body)
	if gz {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		rd = &buf
	}
	req, err := http.NewRequest(http.MethodPost, url, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// ensureCert 加载已有证书，不存在则自动生成自签名证书。
// 返回 tls.Certificate 和 SHA-256 指纹。
func ensureCert(dir, listenAddr string) (tls.Certificate, string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, "", err
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	// 如果已存在则直接加载
	if _, err := os.Stat(certFile); err == nil {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err == nil {
			fp, err := fingerprintFromTLSCert(cert)
			if err == nil {
				return cert, fp, nil
			}
		}
	}

	// 生成 ECDSA P-256 密钥对
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate key: %w", err)
	}

	// 解析 IP（用于 SAN）
	host, _, _ := net.SplitHostPort(listenAddr)
	var ipAddrs []net.IP
	if host != "0.0.0.0" && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		}
	}
	// 获取本机所有 IP 加入 SAN
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					ipAddrs = append(ipAddrs, ipNet.IP)
				}
			}
		}
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cdnedge"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 年
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create cert: %w", err)
	}

	// 写入 PEM 文件
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	if err := os.WriteFile(certFile+".tmp", certPEM, 0644); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.Rename(certFile+".tmp", certFile); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyFile+".tmp", keyPEM, 0600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.Rename(keyFile+".tmp", keyFile); err != nil {
		return tls.Certificate{}, "", err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	fp, err := fingerprintFromTLSCert(cert)
	return cert, fp, err
}

func fingerprintFromTLSCert(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("empty certificate")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":"), nil
}

// autoDetectInterface 自动检测合适的网卡用于 XDP
func autoDetectInterface() string {
	// 优先取默认路由所在网卡：攻击流量和业务流量都从这里进来。按枚举顺序取「第一个 UP 且有
	// IPv4」的网卡会在装了 docker / 多网卡的机器上挑到 docker0、内网卡，XDP 挂上了却一个攻击包
	// 都看不到，表现为面板显示已加载、机器照样被打崩。与 internal/deploy/ssh.go DetectMainIface 一致。
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		if name := defaultRouteIface(string(data)); name != "" {
			if _, err := net.InterfaceByName(name); err == nil {
				return name
			}
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Failed to list network interfaces: %v", err)
		return ""
	}

	// 优先选择非 loopback、up 状态、有 IPv4 地址的网卡
	for _, iface := range ifaces {
		// 跳过 loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// 必须是 up 状态
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// 检查是否有 IPv4 地址
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return iface.Name
			}
		}
	}

	return ""
}

// defaultRouteIface 从 /proc/net/route 的内容里找出 IPv4 默认路由（Destination 与 Mask 均为 0）
// 的网卡；有多条时取 Metric 最小的。找不到返回空串。
func defaultRouteIface(routeTable string) string {
	best, bestMetric := "", -1
	for i, line := range strings.Split(routeTable, "\n") {
		if i == 0 {
			continue // 表头
		}
		f := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = f[0], metric
		}
	}
	return best
}

// edgeCacheDir 是 edge_cache 的磁盘目录，与 configs/tengine.conf、install.sh、SSH 部署保持一致。
const edgeCacheDir = "/var/cache/tengine/edge"

// edgeCacheZoneDirective 与 configs/tengine.conf 里的定义一致。
const edgeCacheZoneDirective = "    proxy_cache_path " + edgeCacheDir + " levels=1:2 keys_zone=edge_cache:100m max_size=10g inactive=7d use_temp_path=off;"

// upgradeMapBlock 补的是站点模板 location / 里 $connection_upgrade 的来源。它必须待在 http 块
// 且全节点只能有一份：map 是 http 上下文指令（写进 server 块 -t 就报 directive is not allowed），
// 而站点配置是 sites-enabled/*.conf 逐域名 include 的，模板里写 map 等于每个域名一份，从第 2 个
// 域名起报 duplicate "map" directive → 整节点配置停更。
// 无 Upgrade 头那一支映射成 keep-alive 而不是网上常见的 close：close 会让每个非 WS 请求都
// 对源站声明关连接，直接废掉 upstream 块的 keepalive 64 连接池。
const upgradeMapBlock = "    # WebSocket 升级状态机：站点配置的 location / 用 $connection_upgrade 做头联动，缺它就是\n" +
	"    # unknown variable、tengine -t 失败（cdnedge 启动时自动补上；install.sh 生成的新节点自带）。\n" +
	"    # 只能全节点定义一份：map 属于 http 上下文，逐域名 include 的片段里重复定义会直接报错。\n" +
	"    map $http_upgrade $connection_upgrade {\n" +
	"        default upgrade;\n" +
	"        ''      keep-alive;\n" +
	"    }"

// httpInsertionPoint 找出往 http 块顶部补指令的位置：优先 include sites-enabled 那一行之前，
// 找不到就退到最后一个 }（即 http 块结束）之前。返回 -1 表示这份主配置没法定位。
func httpInsertionPoint(lines []string, sitesEnabled string) int {
	includeDir := sitesEnabled + "/*.conf"
	for i, line := range lines {
		code := line
		if j := strings.Index(code, "#"); j >= 0 {
			code = code[:j]
		}
		if strings.Contains(code, "include") && strings.Contains(code, includeDir) {
			return i
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "}" {
			return i
		}
	}
	return -1
}

// ensureUpgradeMap 老节点（或手工改过主配置的节点）没有 $connection_upgrade 时补上。
// 备份 + 临时文件 rename 写入，与 ensureEdgeCacheZone 同一套路；返回是否改了文件。
func ensureUpgradeMap(nginxConf, sitesEnabled string) (bool, error) {
	data, err := os.ReadFile(nginxConf)
	if err != nil {
		return false, err
	}
	content := string(data)
	if hasActiveDirective(content, "$connection_upgrade") {
		return false, nil
	}

	lines := strings.Split(content, "\n")
	insertIdx := httpInsertionPoint(lines, sitesEnabled)
	if insertIdx == -1 {
		return false, fmt.Errorf("cannot find where to add $connection_upgrade map")
	}

	// upgradeMapBlock 自带注释，这里不再另起说明行。
	newLines := append(append(append([]string{}, lines[:insertIdx]...), upgradeMapBlock), lines[insertIdx:]...)
	if err := os.WriteFile(nginxConf+".bak", data, 0644); err != nil {
		return false, fmt.Errorf("backup %s: %w", nginxConf, err)
	}
	tmp := nginxConf + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, nginxConf); err != nil {
		return false, err
	}
	log.Printf("✓ Added missing $connection_upgrade map to %s (backup: %s.bak)", nginxConf, nginxConf)
	return true, nil
}

// hasActiveDirective 判断配置里是否有未被注释的、包含 needle 的行。
func hasActiveDirective(content, needle string) bool {
	for _, line := range strings.Split(content, "\n") {
		code := line
		if i := strings.Index(code, "#"); i >= 0 {
			code = code[:i]
		}
		if strings.Contains(code, needle) {
			return true
		}
	}
	return false
}

// ensureEdgeCacheZone 主配置没有 keys_zone=edge_cache 时，在 http 块里 include sites-enabled 那一行
// 之前补上（找不到就放在最后一个 } 之前），并建好缓存目录。返回是否改了文件。
// 改之前留 .bak 备份；写入用临时文件 + rename，不会留下半截配置。
func ensureEdgeCacheZone(nginxConf, sitesEnabled, cacheDir string) (bool, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", cacheDir, err)
	}
	// 缓存由 worker 进程（www-data）写入；用户不存在时忽略，按 Tengine 实际 user 处理。
	_ = exec.Command("chown", "-R", "www-data:www-data", filepath.Dir(cacheDir)).Run()

	data, err := os.ReadFile(nginxConf)
	if err != nil {
		return false, err
	}
	content := string(data)
	if hasActiveDirective(content, "keys_zone=edge_cache") {
		return false, nil
	}

	lines := strings.Split(content, "\n")
	insertIdx := httpInsertionPoint(lines, sitesEnabled)
	if insertIdx == -1 {
		return false, fmt.Errorf("cannot find where to add edge_cache zone")
	}

	block := []string{"    # edge_cache：站点配置的 proxy_cache / proxy_cache_purge 依赖它（cdnedge 启动时自动补上）", edgeCacheZoneDirective}
	newLines := append(append(append([]string{}, lines[:insertIdx]...), block...), lines[insertIdx:]...)
	if err := os.WriteFile(nginxConf+".bak", data, 0644); err != nil {
		return false, fmt.Errorf("backup %s: %w", nginxConf, err)
	}
	tmp := nginxConf + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, nginxConf); err != nil {
		return false, err
	}
	log.Printf("✓ Added missing edge_cache zone to %s (backup: %s.bak)", nginxConf, nginxConf)
	return true, nil
}

// ensureTengineInclude 确保 Tengine nginx.conf 包含 sites-enabled 目录
func ensureTengineInclude(nginxConf, sitesEnabled string) error {
	// 读取 nginx.conf
	data, err := os.ReadFile(nginxConf)
	if err != nil {
		return fmt.Errorf("read nginx.conf: %w", err)
	}

	content := string(data)
	includeDir := sitesEnabled + "/*.conf"

	// 检查是否已经包含 include 指令
	if strings.Contains(content, includeDir) {
		log.Printf("Tengine nginx.conf already includes %s", includeDir)
		return nil
	}

	// 在 http 块的最后一个 } 之前添加 include 指令
	// 找到最后一个 } （应该是 http 块的结束）
	lines := strings.Split(content, "\n")
	insertIdx := -1
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "}" {
			insertIdx = i
			break
		}
	}

	if insertIdx == -1 {
		return fmt.Errorf("cannot find closing brace in nginx.conf")
	}

	// 在找到的 } 之前插入 include 指令
	includeLine := fmt.Sprintf("    include %s;", includeDir)
	newLines := append(lines[:insertIdx], includeLine)
	newLines = append(newLines, lines[insertIdx:]...)
	newContent := strings.Join(newLines, "\n")

	// 备份原文件
	backupPath := nginxConf + ".bak"
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("backup nginx.conf: %w", err)
	}

	// 写入新配置
	if err := os.WriteFile(nginxConf, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("write nginx.conf: %w", err)
	}

	log.Printf("✓ Added 'include %s;' to Tengine nginx.conf", includeDir)
	return nil
}
