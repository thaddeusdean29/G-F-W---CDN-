package setup

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"cdn/internal/config"
	"cdn/internal/secure"
	"cdn/migrations"
)

// setup.html 是开发态维护用的明文源文件，不再被直接嵌入。
// 编译期由 cmd/sealresource 生成 setup.html.enc，运行时解密后使用。

//go:embed setup.html.enc
var setupHTMLEnc []byte

var setupHTML = secure.MustDecrypt(setupHTMLEnc)

// Handler 是安装向导的 HTTP handler。仅在 cfg.AdminPassHash == "" 时使用，
// 提交成功后关闭 Done 通知调用方重启进程。
type Handler struct {
	mux     *http.ServeMux
	cfg     *config.PanelConfig
	cfgPath string
	done    chan struct{}
}

// New 创建安装向导 handler。cfgPath 是 config.json 的落盘路径，done 在安装完成后被关闭。
func New(cfg *config.PanelConfig, cfgPath string, done chan struct{}) *Handler {
	h := &Handler{cfg: cfg, cfgPath: cfgPath, done: done}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/api/setup/test-db", h.handleTestDB)
	mux.HandleFunc("/api/setup/submit", h.handleSubmit)
	h.mux = mux
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(setupHTML)
}

type dbFields struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
}

func (f dbFields) dsn() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=UTC&time_zone=%%27%%2B00%%3A00%%27&charset=utf8mb4&clientFoundRows=true",
		f.User, f.Password, f.Host, f.Port, f.DBName)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) handleTestDB(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var f dbFields
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}

	if err := pingDB(f); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func pingDB(f dbFields) error {
	db, err := sql.Open("mysql", f.dsn())
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	return checkDBVersion(ctx, db)
}

// checkDBVersion 连得上之后再看版本，版本太低在测试连接这一步就说清楚，而不是建表到一半报语法错。
func checkDBVersion(ctx context.Context, db *sql.DB) error {
	v, err := serverVersion(ctx, db)
	if err != nil {
		return err
	}
	return checkServerVersion(v)
}

type submitRequest struct {
	dbFields
	PanelPort     string `json:"panel_port"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
}

func (h *Handler) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req submitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式错误"})
		return
	}
	if req.AdminUser == "" {
		req.AdminUser = "admin"
	}
	if len(req.AdminPassword) < 8 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "管理员密码至少需要 8 位"})
		return
	}

	// 端口只改 host:port 里的 port，保留 ListenAddr 原有的监听地址（如 0.0.0.0）。
	listenAddr := h.cfg.ListenAddr
	if req.PanelPort != "" {
		if _, err := strconv.ParseUint(req.PanelPort, 10, 16); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "端口必须是 1-65535 的数字"})
			return
		}
		host, _, err := net.SplitHostPort(listenAddr)
		if err != nil {
			host = "0.0.0.0"
		}
		listenAddr = net.JoinHostPort(host, req.PanelPort)
	}

	db, err := sql.Open("mysql", req.dbFields.dsn())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := db.PingContext(ctx); err != nil {
		cancel()
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "数据库连接失败: " + err.Error()})
		return
	}
	if err := checkDBVersion(ctx, db); err != nil {
		cancel()
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cancel()

	if err := RunMigration(db, migrations.InitSQL); err != nil {
		if IsTableExistsError(err) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "数据库已安装，请更换新的数据库"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "初始化数据库失败: " + err.Error()})
		return
	}

	hash, err := config.HashPassword(req.AdminPassword)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	// 账号必须进库：/api/v2 的登录只查 admin_users / tenant_users。这里失败不中断安装——
	// 表已经建好，中断的话重试会撞上「数据库已安装」；启动时 main 还会再补一次。
	bctx, bcancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := EnsureAccounts(bctx, db, req.AdminUser, hash); err != nil {
		log.Printf("setup wizard: write admin account to db failed (will retry on startup): %v", err)
	}
	bcancel()

	h.cfg.ListenAddr = listenAddr
	h.cfg.DBHost = req.Host
	h.cfg.DBPort = req.Port
	h.cfg.DBUser = req.User
	h.cfg.DBPassword = req.Password
	h.cfg.DBName = req.DBName
	h.cfg.AdminUser = req.AdminUser
	h.cfg.AdminPassHash = hash

	if err := config.SaveConfig(h.cfg, h.cfgPath); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "写入配置失败: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	log.Println("setup wizard: installation complete, requesting restart")
	close(h.done)
}
