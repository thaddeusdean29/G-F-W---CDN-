package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"cdn/internal/apiv2"
	"cdn/internal/cloudflare"
	"cdn/internal/config"
	"cdn/internal/geo"
	"cdn/internal/geoip"
	"cdn/internal/master"
	"cdn/internal/setup"
	"cdn/internal/xdp"
	"cdn/web"
)

// panelPort 从 "host:port" 里取出端口；解析失败返回 0。
func panelPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

func main() {
	cfgPath := flag.String("config", "/etc/cdnpanel/config.json", "panel config file path")
	initAdmin := flag.String("init-admin", "", "set admin password and exit")
	listenAddr := flag.String("listen", "", "panel listen address (used with --init-admin)")
	resetPassword := flag.String("reset-password", "", "reset a login's password in the database and exit (8-72 chars)")
	resetUser := flag.String("user", "", "login name for --reset-password (platform admin username or agent login email); default: admin_user in config.json")
	xdpIface := flag.String("xdp-iface", "", "network interface to attach XDP (e.g. eth0)")
	xdpObj := flag.String("xdp-obj", xdp.DefaultObjPath(), "path to compiled cdn_xdp.o")
	flag.Parse()

	cfg := config.DefaultPanelConfig()
	if data, err := os.ReadFile(*cfgPath); err == nil {
		if err := json.Unmarshal(data, cfg); err != nil {
			log.Fatalf("parse config %s: %v", *cfgPath, err)
		}
	}

	if *initAdmin != "" {
		if *listenAddr != "" {
			cfg.ListenAddr = *listenAddr
		}
		if err := setAdminPassword(cfg, *cfgPath, *initAdmin); err != nil {
			log.Fatalf("set admin password: %v", err)
		}
		fmt.Println("Admin password set successfully.")
		return
	}

	if *resetPassword != "" {
		if err := runResetPassword(cfg, *cfgPath, *resetUser, *resetPassword); err != nil {
			fmt.Fprintln(os.Stderr, "重置密码失败:", err)
			os.Exit(1)
		}
		return
	}

	// 面板全部数据都在 MySQL 里（旧的 JSON 文件版面板已移除），没配数据库就先跑安装向导。
	// 只设过管理员密码（install.sh --init-admin）而没配数据库的，同样要走向导。
	if cfg.AdminPassHash == "" || cfg.DBName == "" {
		runSetupWizard(cfg, *cfgPath)
		return
	}

	// 配了 DB 但连不上时直接 Fatal：面板离开数据库什么都做不了，静默启动只会让人误以为正常。
	db, err := sql.Open("mysql", cfg.MySQLDSN())
	if err != nil {
		log.Fatalf("open mysql: %v", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(90 * time.Second)
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	pingErr := db.PingContext(pingCtx)
	cancel()
	if pingErr != nil {
		log.Fatalf("ping mysql %s:%s/%s: %v", cfg.DBHost, cfg.DBPort, cfg.DBName, pingErr)
	}
	defer db.Close()
	log.Printf("connected to MySQL at %s:%s/%s", cfg.DBHost, cfg.DBPort, cfg.DBName)

	// 旧版安装向导只把管理员写进 config.json，库里没有账号就登不上。表为空时从 config.json 补齐；
	// 已有账号则不动。0001 之后新增的表/列由 EnsureSchema 幂等补齐。
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := setup.EnsureAccounts(bootCtx, db, cfg.AdminUser, cfg.AdminPassHash); err != nil {
		log.Printf("bootstrap accounts failed (non-fatal): %v", err)
	}
	if err := setup.EnsureSchema(bootCtx, db); err != nil {
		log.Printf("ensure schema failed (non-fatal): %v", err)
	}
	bootCancel()

	// 主控本机的 XDP（可选，需要 root + 支持 XDP 的网卡驱动），只保护面板所在服务器。
	xdpMgr := xdp.NewManager(*xdpIface, *xdpObj)
	if *xdpIface != "" {
		if err := xdpMgr.Load(); err != nil {
			log.Printf("XDP load failed (non-fatal): %v", err)
		} else {
			log.Printf("XDP attached to interface %s", *xdpIface)
			defer xdpMgr.Close()
			// 必须写默认配置：xdp_config 是 ARRAY map，加载后全零 = enabled:0，程序对每个包直接 PASS。
			// 面板端口加入服务端口白名单，否则 port_guard 会把面板自己锁在门外。
			var extra []uint16
			if p := panelPort(cfg.ListenAddr); p != 0 {
				extra = append(extra, p)
			}
			if err := xdpMgr.InitDefaults(extra...); err != nil {
				log.Printf("XDP init defaults failed (non-fatal): %v", err)
			}
		}
	}

	// 节点都在数据库里，Pusher 不需要旧的 nodes.json（只用按节点直连的方法）。
	pusher := master.NewPusher(nil)
	// 代理接口只用各代理自己保存的 Cloudflare 凭证；这里的全局 client 仅为满足 NewRouter 签名。
	cf := cloudflare.NewClient(cfg.CFApiToken, cfg.CFZoneID, cfg.CFBaseDomain)

	// IP 归属地库（DB-IP City Lite）。找不到也照常起服务，流量页会显式写明缺哪个文件、
	// 在哪些目录找过——归属地是加分项，不该因为它不开板。
	locator := geoip.Open(geoip.DefaultDirs(cfg.GeoIPDir))
	for _, p := range locator.Loaded {
		log.Printf("geoip loaded: %s", p)
	}
	for _, m := range locator.Missing {
		log.Printf("geoip: %s", m)
	}
	// 国家级库（DB-IP Country Lite）：区域封禁的前缀表由它编译，找的是同一批目录。
	// 缺库也照常起服务，但性质和归属地不同：那时任何区域规则都编不出表，
	// 所以主控在"保存启用中的规则"那一层就直接拒绝，并把缺的文件名报给页面。
	country := geo.Open(geoip.DefaultDirs(cfg.GeoIPDir)...)
	for _, p := range country.Loaded {
		log.Printf("geo country db loaded: %s", p)
	}
	for _, m := range country.Missing {
		log.Printf("geo country db: %s", m)
	}

	httpSrv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      logging(newPanelMux(db, pusher, cf, locator, country, cfg.ACMEDirectory)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("cdnpanel listening on %s", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("cdnpanel stopped")
}

// newPanelMux 组装面板的全部路由：
//   - /api/v2/*：面板接口（多代理，MySQL）
//   - /api/edge/{register,heartbeat,report}：已部署的 cdnedge 写死调用这三个路径，
//     直接交给 v2 的边缘处理器（与 /api/v2/edge/* 是同一套逻辑）
//   - /console/：编译进二进制的 Vue 控制台
//   - /：公开首页（产品能力、价格、联系方式，管理员在后台编辑；关闭后跳转控制台）
func newPanelMux(db *sql.DB, pusher *master.Pusher, cf *cloudflare.Client, locator *geoip.Locator, country *geo.DB, acmeDir string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v2/", apiv2.NewRouter(db, pusher, cf, locator, country, acmeDir))

	edge := apiv2.NewEdgeHandler(db, pusher)
	mux.HandleFunc("/api/edge/register", edge.ServeRegister)
	mux.HandleFunc("/api/edge/heartbeat", edge.ServeHeartbeat)
	mux.HandleFunc("/api/edge/report", edge.ServeReport)

	mux.Handle("/console/", web.ConsoleHandler())
	home := apiv2.HomepageHandler(db)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			home.ServeHTTP(w, r)
		case "/index.html":
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

// runSetupWizard 在面板未完成安装时提供安装向导（数据库 + 管理员）；提交成功后原地重启进程。
func runSetupWizard(cfg *config.PanelConfig, cfgPath string) {
	done := make(chan struct{})
	wizard := setup.New(cfg, cfgPath, done)
	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: wizard}
	go func() {
		log.Printf("cdnpanel not configured yet, serving setup wizard on %s", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-done:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = httpSrv.Shutdown(ctx)
		cancel()
		exe, err := os.Executable()
		if err != nil {
			log.Fatalf("re-exec failed (%v); run: systemctl restart cdnpanel", err)
		}
		if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
			log.Fatalf("re-exec failed (%v); run: systemctl restart cdnpanel", err)
		}
	case <-quit:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = httpSrv.Shutdown(ctx)
		cancel()
	}
}

// logging 记录每个请求的方法、路径和响应状态码（不记录查询串与请求体，避免把 token 写进日志）。
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d", r.Method, r.URL.Path, rw.status)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// runResetPassword 在服务器上直接改数据库里的登录密码（忘记密码时用）。平台管理员和代理登录账号
// 里登录名相同的都会改；改完让这些账号已登录的会话失效，并清空登录失败计数。
func runResetPassword(cfg *config.PanelConfig, cfgPath, login, password string) error {
	if n := len(password); n < 8 || n > 72 {
		return fmt.Errorf("密码长度必须是 8-72 位（当前 %d 位）", n)
	}
	if login == "" {
		login = cfg.AdminUser
	}
	if login == "" {
		return fmt.Errorf("请用 --user 指定要改密码的登录名")
	}
	if cfg.DBName == "" {
		return fmt.Errorf("%s 里没有数据库配置：面板还没完成安装向导，直接访问面板完成安装即可设置密码", cfgPath)
	}
	db, err := sql.Open("mysql", cfg.MySQLDSN())
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("连接数据库 %s:%s/%s 失败: %w", cfg.DBHost, cfg.DBPort, cfg.DBName, err)
	}
	hash, err := config.HashPassword(password)
	if err != nil {
		return err
	}
	res, err := setup.ResetPassword(ctx, db, login, hash)
	if err != nil {
		return err
	}
	if res.Admins == 0 && res.TenantUsers == 0 {
		msg := fmt.Sprintf("没有登录名为 %q 的账号。", login)
		if len(res.AdminNames) > 0 {
			msg += "\n  平台管理员: " + strings.Join(res.AdminNames, ", ")
		}
		if len(res.TenantEmails) > 0 {
			msg += "\n  代理账号: " + strings.Join(res.TenantEmails, ", ")
		}
		return fmt.Errorf("%s\n用 --user <登录名> 指定要改的账号", msg)
	}
	// config.json 里的管理员哈希只在库里没有账号时用来补建账号；同步一下，免得两边不一致。
	if login == cfg.AdminUser {
		cfg.AdminPassHash = hash
		if err := config.SaveConfig(cfg, cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "注意：数据库里的密码已改好，但更新", cfgPath, "失败:", err)
		}
	}
	if res.Admins > 0 {
		fmt.Printf("已重置平台管理员 %q 的密码，在 /console/admin/login 登录。\n", login)
	}
	if res.TenantUsers > 0 {
		fmt.Printf("已重置代理账号 %q 的密码，在 /console/login 登录。\n", login)
	}
	fmt.Println("该账号原来的登录状态已全部失效，登录失败锁定也已清除。")
	return nil
}

func setAdminPassword(cfg *config.PanelConfig, cfgPath, password string) error {
	hash, err := config.HashPassword(password)
	if err != nil {
		return err
	}
	cfg.AdminPassHash = hash
	return config.SaveConfig(cfg, cfgPath)
}
