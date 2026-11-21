package deploy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`)
)

// validateEdgePort 确保端口是 1-65535 的纯数字字符串。
func validateEdgePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q: must be a number between 1 and 65535", port)
	}
	return nil
}

// validateIface 确保网卡名只含合法字符，杜绝换行注入。
func validateIface(iface string) error {
	if iface == "" {
		return nil
	}
	if !validIfaceRe.MatchString(iface) {
		return fmt.Errorf("invalid interface name %q: only alphanumeric, hyphen, dot, underscore allowed", iface)
	}
	return nil
}

type SSHClient struct {
	client      *ssh.Client
	stopKeepalive chan struct{}
}

// Connect 建立 SSH 连接（密码或私钥二选一，privateKey 非空时优先使用），并启动应用层
// keepalive 防止长时间编译期间被 NAT/sshd 断开。
func Connect(host, port, user, password, privateKey string) (*SSHClient, error) {
	var auth []ssh.AuthMethod
	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		auth = []ssh.AuthMethod{ssh.Password(password)}
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	addr := host + ":" + port
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	client := &SSHClient{
		client:        c,
		stopKeepalive: make(chan struct{}),
	}
	// 每 30 秒发送一次 keepalive，防止 sshd 空闲超时断开（编译约 5-15 分钟）
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					return
				}
			case <-client.stopKeepalive:
				return
			}
		}
	}()
	return client, nil
}

func (c *SSHClient) Close() {
	close(c.stopKeepalive)
	c.client.Close()
}

// Run 执行远程命令，返回合并输出。
func (c *SSHClient) Run(cmd string) (string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// Upload 将内容通过 stdin pipe 写入远程文件，避免 scp 依赖。
// remotePath 必须是受控的静态路径（不接受用户输入）。
func (c *SSHClient) Upload(remotePath string, data []byte, mode string) error {
	sess, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("cat > %s && chmod %s %s", remotePath, mode, remotePath)
	sess.Stdout = io.Discard
	sess.Stderr = io.Discard

	if err := sess.Start(cmd); err != nil {
		return err
	}
	if _, err := io.Copy(stdin, bytes.NewReader(data)); err != nil {
		return err
	}
	stdin.Close()
	return sess.Wait()
}

// UploadFile 上传本地文件到远程路径。
func (c *SSHClient) UploadFile(localPath, remotePath, mode string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file %s: %w", localPath, err)
	}
	return c.Upload(remotePath, data, mode)
}

// DetectMainIface 在远程节点上自动检测第一块 UP 状态的非 lo 网卡。
func DetectMainIface(c *SSHClient) (string, error) {
	// 方法1：从默认路由找网卡（最准确）
	out, err := c.Run("ip route show default 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}' | head -1")
	if err == nil {
		iface := strings.TrimSpace(out)
		if iface != "" && iface != "lo" && validIfaceRe.MatchString(iface) {
			return iface, nil
		}
	}

	// 方法2：找第一块 UP 状态的非 lo 网卡
	out, err = c.Run("ip link show | awk -F': ' '/^[0-9]+:/{iface=$2} /UP,LOWER_UP/{if(iface!=\"lo\" && iface!=\"\") {print iface; exit}}'")
	if err == nil {
		iface := strings.TrimSpace(out)
		if idx := strings.Index(iface, "@"); idx != -1 {
			iface = iface[:idx]
		}
		if iface != "" && iface != "lo" && validIfaceRe.MatchString(iface) {
			return iface, nil
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

// aptWaitLock 是一段在执行 apt-get 前先等待 dpkg/apt 锁释放的 shell 前缀。
//
// 云服务器开机后 unattended-upgrades / apt-daily.timer 常在后台跑 apt，此时 dpkg 前端锁
// (/var/lib/dpkg/lock-frontend) 被占用，直接跑 apt-get 会立刻报 "Could not get lock" 退出，
// 导致部署失败。这里最多等 300 秒让后台任务完成；同时给 apt-get 传 DPkg::Lock::Timeout，
// 新版 apt(>=1.9.11) 会自己重试等锁（老版本忽略该选项，靠前面的轮询兜底）。
const aptWaitLock = `_apt_wait(){ ` +
	`i=0; ` +
	`while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do ` +
	`  i=$((i+1)); if [ "$i" -gt 150 ]; then echo "timeout waiting for apt lock" >&2; break; fi; ` +
	`  sleep 2; ` +
	`done; }; _apt_wait; `

// aptGet 给一条 apt-get 子命令加上等锁前缀与锁超时选项，返回可交给 c.Run 的完整命令串。
// args 例如 `update -qq` 或 `install -y -qq clang llvm`。
func aptGet(args string) string {
	return "export DEBIAN_FRONTEND=noninteractive && " + aptWaitLock +
		"apt-get -o DPkg::Lock::Timeout=300 " + args
}

// ProgressCallback 部署进度回调函数
type ProgressCallback func(step, message string)

// DeployEdge 在远程节点上完整部署 cdnedge + Tengine。
// edgeBinary:  本地 cdnedge 二进制路径
// xdpSource:   cdn_xdp.c 源码内容（可为空，为空则跳过 XDP）
// tengineCfg:  tengine.conf 文件内容（直接上传，无需远程编译）
// edgePort:    边缘节点监听端口（1-65535）
// xdpIface:    XDP 网卡名（可为空）
// progress:    进度回调（可为 nil）
// DeployResult 是一次部署的产出。
type DeployResult struct {
	Token string
	// XDPWarning 非空表示 XDP（L4 防护）没有启用，内容是原因。XDP 失败不阻塞部署，
	// 但以前只写进主控日志，面板上显示「部署成功」，节点实际上没有任何 L4 防护。
	XDPWarning string
	// XDPCompiled 表示 .o 已编出并写进了 systemd 启动参数。编出来不等于挂上了
	// （驱动不支持、内核太旧都会在 cdnedge 启动时 Load 失败），调用方应再查一次节点状态。
	XDPCompiled bool
}

// MasterLink 让部署出来的 cdnedge 带 --master 启动，并预先写好主控分配的节点 ID：
// 节点启动后直接用 node_id + token 向主控心跳、上报统计（主控不回连节点拉取）。
// 为 nil 时保持旧行为（不带 --master，由主控回连）。
type MasterLink struct {
	NodeID    string
	MasterURL string
}

var (
	nodeIDRe    = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)
	masterURLRe = regexp.MustCompile(`^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/\-]*)?$`)
)

// validate 两个值都会进 systemd 的 ExecStart 行和远端文件，必须挡住空格、引号、换行等注入字符。
func (m *MasterLink) validate() error {
	if !nodeIDRe.MatchString(m.NodeID) {
		return fmt.Errorf("invalid node id")
	}
	if !masterURLRe.MatchString(m.MasterURL) {
		return fmt.Errorf("invalid master url %q (need http(s)://host[:port])", m.MasterURL)
	}
	return nil
}

// 返回生成的 Token 与 XDP 状态。
func DeployEdge(c *SSHClient, edgeBinary string, xdpSource []byte, tengineCfg []byte, edgePort, xdpIface string, link *MasterLink, progress ProgressCallback) (*DeployResult, error) {
	if link != nil {
		if err := link.validate(); err != nil {
			return nil, err
		}
	}
	var xdpWarn string
	var xdpCompiled bool
	token, err := deployEdge(c, edgeBinary, xdpSource, tengineCfg, edgePort, xdpIface, link, progress, &xdpWarn, &xdpCompiled)
	if err != nil {
		return nil, err
	}
	return &DeployResult{Token: token, XDPWarning: xdpWarn, XDPCompiled: xdpCompiled}, nil
}

// sysctlHardening 与 install.sh 第 10 步写入的内容保持一致（两条安装路径互不共用代码，
// 改一处必须同步另一处）。internal/deploy 里有一个测试逐行比对这两份内容，不一致就红。
//
// rp_filter 用 2（宽松）而不是 1（严格）：严格模式要求回包必须从「到源地址的路由」那张网卡
// 进来，多网卡/策略路由的云主机上回源流量可能从另一张网卡回来，会被内核静默丢弃 ——
// 表现和 XDP 丢回源包一样是全站 504。宽松模式仍能丢掉路由表里根本不可达的伪造源。
// 不含任何 UDP 相关规则：UDP 由安全组统一禁止。
const sysctlHardening = `net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 60
`

// cdnedgeUnitTemplate 与 install.sh 第 11 步 edge 分支写入的 unit 一致（hardening_parity_test.go
// 逐条比对，唯一允许不同的是 ExecStart 那行——两边的启动参数本来就是拼出来的）。
//
// 为什么盯这一组：cdnedge 停着的每一秒 CC/WAF 都不在线（Tengine 对 WAF 子请求的 502 放行），
// 而 systemd 默认限速是 10 秒内 5 次，崩溃循环几次后服务会永久停在 failed 状态，
// 面板只显示「离线」，没人去救。Restart=always + StartLimitIntervalSec=0 断掉这条路。
// MemoryHigh/MemoryMax 只兜内存泄漏、不兜设计容量：internal/waf 各表硬上限合计约 400MB，
// 加 2 倍 GC 余量后 RSS 天花板约 800MB，压到设计容量以内换来的是攻击高峰期被 OOM 杀掉。
const cdnedgeUnitTemplate = "[Unit]\n" +
	"Description=CDN Edge Agent Service\n" +
	"After=network.target\n" +
	"StartLimitIntervalSec=0\n\n" +
	"[Service]\n" +
	"Type=simple\n" +
	"User=root\n" +
	"ExecStart=%s\n" +
	"Restart=always\n" +
	"RestartSec=2s\n" +
	"LimitNOFILE=65536\n" +
	"MemoryHigh=1G\n" +
	"MemoryMax=2G\n\n" +
	"[Install]\n" +
	"WantedBy=multi-user.target\n"

// xdpBuildLogHint 附在 XDP 告警后面，指明去哪看完整的 clang 输出。
const xdpBuildLogHint = "，完整编译输出见节点 /tmp/cdn_xdp_build.log"

// tailLines 取输出的最后 n 行，用于把 clang 报错塞进进度消息而不撑爆面板。
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func deployEdge(c *SSHClient, edgeBinary string, xdpSource []byte, tengineCfg []byte, edgePort, xdpIface string, link *MasterLink, progress ProgressCallback, xdpWarn *string, xdpCompiled *bool) (string, error) {
	// 辅助函数：报告进度
	report := func(step, msg string) {
		if progress != nil {
			progress(step, msg)
		}
		log.Printf("[Deploy] %s: %s", step, msg)
	}

	// 输入验证
	if err := validateEdgePort(edgePort); err != nil {
		return "", err
	}
	if err := validateIface(xdpIface); err != nil {
		return "", err
	}

	// 1. 安装系统依赖
	// 核心依赖（Tengine 编译必需）：失败则终止部署。
	// update 与 install 各自等 dpkg 锁——避免撞上云机开机后台的 unattended-upgrades。
	report("step_1", "更新 apt 缓存...")
	if out, err := c.Run(aptGet("update -qq")); err != nil {
		return "", fmt.Errorf("apt update: %s: %w", out, err)
	}

	report("step_1", "安装系统依赖（build-essential, libpcre3-dev, libssl-dev, wget...）...")
	if out, err := c.Run(aptGet("install -y -qq build-essential libpcre3-dev zlib1g-dev libssl-dev wget git")); err != nil {
		return "", fmt.Errorf("install deps: %s: %w", out, err)
	}

	// XDP eBPF 依赖（可选）
	report("step_2", "安装 XDP/eBPF 依赖（clang, llvm, libbpf-dev）...")
	xdpDepsCmd := aptGet("install -y -qq clang llvm libbpf-dev linux-headers-\"$(uname -r)\"")
	// 依赖装失败不直接判死：部分包（例如某个 linux-headers 版本源里没有）缺了也可能编得过，
	// 以下面的实际编译结果为准；但要把原因记下来，编译真失败时一起报给面板。
	xdpDepsErr := ""
	if out, err := c.Run(xdpDepsCmd); err != nil {
		xdpDepsErr = tailLines(out, 3)
		log.Printf("xdp deps install on remote node failed (non-fatal, XDP may be skipped): %s: %v", out, err)
		report("step_2", "⚠ XDP 依赖安装失败，稍后编译可能失败: "+xdpDepsErr)
	}

	// 2. 安装 Tengine
	report("step_3", "检查 Tengine 状态...")
	needBuild := false
	if tengineCheck, _ := c.Run("test -f /usr/local/tengine/sbin/nginx && echo ok"); strings.TrimSpace(tengineCheck) != "ok" {
		needBuild = true
		report("step_3", "Tengine 未安装，需要编译安装")
	} else if luaCheck, _ := c.Run("/usr/local/tengine/sbin/nginx -V 2>&1 | grep -c lua-nginx-module"); strings.TrimSpace(luaCheck) == "0" {
		needBuild = true
		report("step_3", "Tengine 缺少 lua-nginx-module，需要重新编译")
		c.Run("systemctl stop tengine 2>/dev/null; /usr/local/tengine/sbin/nginx -s stop 2>/dev/null; pkill -f '[/]usr/local/tengine/sbin/' 2>/dev/null; rm -f /usr/local/tengine/sbin/nginx /usr/local/tengine/sbin/tengine 2>/dev/null; true")
	} else {
		report("step_3", "Tengine 已安装，跳过编译")
	}
	if needBuild {
		report("step_3", "开始编译 Tengine（需要 5-15 分钟，请耐心等待）...")
		if err := installTengine(c); err != nil {
			return "", fmt.Errorf("install tengine: %w", err)
		}
		report("step_3", "Tengine 编译安装完成")
	}

	// 2b. 确保 resty.core / lrucache 就位
	report("step_4", "安装 Lua 运行时依赖（resty.core, lrucache）...")
	if err := ensureRestyCore(c); err != nil {
		return "", fmt.Errorf("ensure resty.core: %w", err)
	}

	// 3. 创建必要目录
	report("step_5", "创建配置目录...")
	dirs := []string{
		"/etc/cdnpanel/domains",
		"/etc/cdnpanel/edge-tls",
		"/etc/tengine/sites-available",
		"/etc/tengine/sites-enabled",
		"/var/cache/tengine",
		"/var/log/tengine",
		"/var/www/acme/.well-known/acme-challenge",
		"/etc/ssl/cdnpanel",
	}
	if _, err := c.Run("mkdir -p " + strings.Join(dirs, " ")); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	// 4. 预生成 tengine.conf / 站点模板依赖的静态文件，否则 tengine -t 直接失败、443 不监听：
	//   - default_server 兜底自签证书：tengine.conf 的全局 default_server 引用它
	//   - ticket.key：站点模板无条件引用 ssl_session_ticket_key /etc/ssl/cdnpanel/ticket.key，
	//     平时只在主控轮换推送时才写入，首次部署缺此文件会 open() failed。
	//     这里先生成 48 字节随机密钥兜底，主控之后的轮换推送会覆盖它。
	// 缓存目录也要预建并授权给 www-data，供 proxy_cache_path edge_cache 使用。
	prepCmd := `set -e
mkdir -p /etc/ssl/cdnpanel/default /var/cache/tengine/edge
chown -R www-data:www-data /var/cache/tengine 2>/dev/null || true
if [ ! -f /etc/ssl/cdnpanel/default/cert.pem ]; then
    # ECDSA P-256：扫 IP 的握手洪水都落在 default_server 上，RSA 签名开销是它的数倍
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /etc/ssl/cdnpanel/default/key.pem \
        -out /etc/ssl/cdnpanel/default/cert.pem \
        -days 3650 -subj "/CN=default" >/dev/null 2>&1
    chmod 600 /etc/ssl/cdnpanel/default/key.pem
    chmod 644 /etc/ssl/cdnpanel/default/cert.pem
fi
if [ ! -f /etc/ssl/cdnpanel/ticket.key ]; then
    openssl rand 48 > /etc/ssl/cdnpanel/ticket.key
    chmod 600 /etc/ssl/cdnpanel/ticket.key
fi`
	report("step_6", "生成 SSL 相关资源（默认证书、票据密钥）...")
	if out, err := c.Run(prepCmd); err != nil {
		return "", fmt.Errorf("prepare tengine ssl assets: %s: %w", out, err)
	}

	// 上传 tengine.conf
	report("step_7", "上传 Tengine 主配置文件...")
	if err := c.Upload("/etc/tengine/tengine.conf", tengineCfg, "644"); err != nil {
		return "", fmt.Errorf("upload tengine.conf: %w", err)
	}
	// 复制 mime.types
	if _, err := c.Run("cp /usr/local/tengine/conf/mime.types /etc/tengine/mime.types 2>/dev/null || true"); err != nil {
		return "", fmt.Errorf("copy mime.types: %w", err)
	}

	// 5. 停用原版 nginx（释放 80/443）
	report("step_8", "停用系统自带 nginx/openresty（释放 80/443 端口）...")
	c.Run("systemctl stop nginx openresty 2>/dev/null; systemctl disable nginx openresty 2>/dev/null; true")

	// 6. 上传 cdnedge 二进制
	report("step_9", "上传 cdnedge 边缘节点程序...")
	c.Run("systemctl stop cdnedge 2>/dev/null; true")
	if err := c.UploadFile(edgeBinary, "/usr/local/bin/cdnedge.new", "755"); err != nil {
		return "", fmt.Errorf("upload cdnedge: %w", err)
	}
	if out, err := c.Run("mv -f /usr/local/bin/cdnedge.new /usr/local/bin/cdnedge && chmod 755 /usr/local/bin/cdnedge"); err != nil {
		return "", fmt.Errorf("install cdnedge binary: %s: %w", out, err)
	}

	// 7. 上传 cdn_xdp.c 源码并在远程节点本机现场编译（可选，失败不影响其余部署）
	xdpReady := false
	switch {
	case len(xdpSource) == 0:
		*xdpWarn = "主控未内嵌 XDP 源码，已跳过 XDP"
		report("step_10", "⚠ "+*xdpWarn)
	case xdpIface == "":
		*xdpWarn = "未检测到可挂载 XDP 的网卡（可在部署表单里手动填写网卡名），已跳过 XDP"
		report("step_10", "⚠ "+*xdpWarn)
	}
	if len(xdpSource) > 0 && xdpIface != "" {
		report("step_10", "上传并编译 XDP 程序...")
		if err := c.Upload("/usr/local/bin/cdn_xdp.c", xdpSource, "644"); err != nil {
			return "", fmt.Errorf("upload xdp source: %w", err)
		}
		// 三轮递进参数，与 install.sh 和 internal/edgeapi/handler.go 的 doInstallXdp 一致。
		// 每轮的参数与 clang 输出都进 /tmp/cdn_xdp_build.log 并回显，失败时能直接看到原因：
		// 以前只有一层 `||` 兜底且输出被 err 分支吞掉，源码里一个多余的
		// #include <linux/icmp.h>（拉到 32 位 glibc 的 gnu/stubs-32.h）让两轮全挂，
		// 但日志里只有一行 non-fatal，问题被藏了很久。
		//
		// 开头先 rm -f 掉旧的 .o：否则上一次部署留下的陈旧文件会让下面的 test -f 判定
		// 通过，把 xdpReady 误标成 true。
		compileCmd := `rm -f /usr/local/bin/cdn_xdp.o
XDP_LOG=/tmp/cdn_xdp_build.log
: > "$XDP_LOG"
ARCH="$(uname -m)"
xdp_try() {
    label="$1"; shift
    { echo "=== attempt: $label ==="; echo "clang $*"; } >> "$XDP_LOG"
    clang "$@" -c /usr/local/bin/cdn_xdp.c -o /usr/local/bin/cdn_xdp.o >>"$XDP_LOG" 2>&1
}
xdp_try "arch include" -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/"$ARCH"-linux-gnu \
  || xdp_try "arch include + /usr/include" -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/"$ARCH"-linux-gnu -I/usr/include \
  || xdp_try "minimal" -O2 -g -target bpf
rc=$?
if [ $rc -ne 0 ]; then
    rm -f /usr/local/bin/cdn_xdp.o
    cat "$XDP_LOG"
fi
exit $rc`
		if out, err := c.Run(compileCmd); err != nil {
			// 非致命：XDP 编译失败不阻塞其余部署，边缘节点仍能正常提供服务。
			// 但必须报给面板：以前只进主控日志，面板显示「部署成功」，节点实际没有 L4 防护。
			log.Printf("xdp compile on remote node failed (non-fatal), all 3 attempts failed: %v\nclang output:\n%s", err, out)
			*xdpWarn = "XDP 编译失败（三轮参数均失败），节点未启用 L4 防护" + xdpBuildLogHint
			if xdpDepsErr != "" {
				*xdpWarn += "；依赖安装也失败过: " + xdpDepsErr
			}
			if tail := tailLines(out, 5); tail != "" {
				*xdpWarn += "\nclang 输出末尾:\n" + tail
			}
			report("step_10", "⚠ "+*xdpWarn)
		} else if check, _ := c.Run("test -f /usr/local/bin/cdn_xdp.o && echo ok"); strings.TrimSpace(check) == "ok" {
			xdpReady = true
			report("step_10", "XDP 程序编译成功，将挂载到网卡 "+xdpIface)
		} else {
			*xdpWarn = "XDP 编译命令返回成功但未生成 cdn_xdp.o，节点未启用 L4 防护" + xdpBuildLogHint
			report("step_10", "⚠ "+*xdpWarn)
		}
	}

	// 7b. 内核网络加固（非致命）。以前只有 install.sh 做了这一步，面板 SSH 一键部署的节点
	// 用的是发行版默认值：somaxconn=4096、syn_backlog=512、conntrack 约 26 万 ——
	// XDP 放行的合法新连接一多就把内核队列打满，Tengine 的 backlog=65535 也被 somaxconn 截断。
	report("step_10b", "配置内核网络加固参数（sysctl）...")
	if err := c.Upload("/etc/sysctl.d/99-cdn-hardening.conf", []byte(sysctlHardening), "644"); err != nil {
		report("step_10b", "⚠ 写入 sysctl 配置失败（不影响部署）: "+err.Error())
	} else {
		// 逐条生效、失败不中断：容器/精简内核里某些键（如 nf_conntrack_max 未加载模块时）
		// 不存在，sysctl -p 遇到第一个未知键就会整体返回非零。
		out, _ := c.Run(`mkdir -p /etc/modprobe.d
echo 'options nf_conntrack hashsize=262144' > /etc/modprobe.d/nf_conntrack.conf
[ -w /sys/module/nf_conntrack/parameters/hashsize ] && echo 262144 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null
sysctl -e -p /etc/sysctl.d/99-cdn-hardening.conf 2>&1 | grep -i 'error\|denied' | head -3
true`)
		if s := strings.TrimSpace(out); s != "" {
			report("step_10b", "⚠ 部分 sysctl 参数未生效: "+s)
		} else {
			report("step_10b", "内核网络参数已生效")
		}
	}

	// 8. 在远程节点生成 Token
	report("step_11", "生成节点 Token...")
	tokenOut, err := c.Run("openssl rand -hex 32")
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := strings.TrimSpace(tokenOut)
	if len(token) != 64 || !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(token) {
		return "", fmt.Errorf("unexpected token format from remote openssl")
	}
	if err := c.Upload("/etc/cdnpanel/edge.token", []byte(token+"\n"), "600"); err != nil {
		return "", fmt.Errorf("write token: %w", err)
	}
	if link != nil {
		if err := c.Upload("/etc/cdnpanel/edge.node_id", []byte(link.NodeID+"\n"), "600"); err != nil {
			return "", fmt.Errorf("write node id: %w", err)
		}
	}

	// 9. 写入 config.json
	report("step_12", "写入边缘节点配置文件...")
	configJSON := `{
  "tengine_cmd":     "/usr/local/tengine/sbin/tengine",
  "tengine_pid":     "/var/run/tengine.pid",
  "tengine_conf":    "/etc/tengine/tengine.conf",
  "sites_available": "/etc/tengine/sites-available",
  "sites_enabled":   "/etc/tengine/sites-enabled",
  "cache_base_path": "/var/cache/tengine",
  "ssl_base_path":   "/etc/ssl/cdnpanel",
  "data_dir":        "/etc/cdnpanel/domains"
}`
	if err := c.Upload("/etc/cdnpanel/config.json", []byte(configJSON), "600"); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	// 10. 生成并启动 cdnedge systemd 服务
	report("step_13", "创建 cdnedge systemd 服务...")
	execStart := fmt.Sprintf(
		"/usr/local/bin/cdnedge --listen 0.0.0.0:%s --token-file /etc/cdnpanel/edge.token --config /etc/cdnpanel/config.json",
		edgePort,
	)
	if link != nil {
		execStart += " --master " + link.MasterURL
	}
	if xdpReady {
		execStart += " --xdp-iface " + xdpIface + " --xdp-obj /usr/local/bin/cdn_xdp.o"
		*xdpCompiled = true
	}
	// unit 内容与 install.sh 的 edge 分支同一份形状，理由写在 cdnedgeUnitTemplate 上。
	serviceContent := fmt.Sprintf(cdnedgeUnitTemplate, execStart)
	if err := c.Upload("/etc/systemd/system/cdnedge.service", []byte(serviceContent), "644"); err != nil {
		return "", fmt.Errorf("write service file: %w", err)
	}
	report("step_13", "启动 cdnedge 服务...")
	for _, cmd := range []string{
		"systemctl daemon-reload",
		"systemctl enable cdnedge",
		"systemctl restart cdnedge",
	} {
		if out, err := c.Run(cmd); err != nil {
			return "", fmt.Errorf("systemctl (%s): %s: %w", cmd, out, err)
		}
	}

	// 11. 启动 Tengine
	report("step_14", "测试 Tengine 配置...")
	const tengineTest = "/usr/local/tengine/sbin/tengine -t -c /etc/tengine/tengine.conf"
	if out, err := c.Run(tengineTest); err != nil {
		// 重装老节点时 sites-enabled 里还留着旧版 cdnedge 按旧模板渲染的站点 conf（旧模板写过
		// 当前 Tengine 不认的指令/参数），它们会让 tengine -t 失败、整台节点起不来。站点 conf
		// 是生成物：部署成功后主控 Onboard 会用新模板重新下发全部域名。所以这里把旧 conf 挪到
		// sites-stale（可回滚，不删除）后重测；若仍失败，说明是 tengine.conf 本身的问题，照常报错。
		report("step_14", "Tengine 配置测试失败，停用旧版站点配置后重试（部署完成后由主控重新下发）...")
		c.Run("mkdir -p /etc/tengine/sites-stale && for f in /etc/tengine/sites-enabled/*.conf; do [ -e \"$f\" ] || [ -L \"$f\" ] || continue; mv -f \"$f\" /etc/tengine/sites-stale/; done; true")
		if out2, err2 := c.Run(tengineTest); err2 != nil {
			return "", fmt.Errorf("tengine config test failed: %s: %w", out2, err2)
		}
		log.Printf("deploy: stale site configs moved to /etc/tengine/sites-stale, first test output: %s", out)
	}
	report("step_14", "启动 Tengine 服务...")
	if err := startTengine(c, report); err != nil {
		return "", err
	}

	// 12. 等待 TLS 证书生成（最多 10 秒）
	report("step_15", "等待边缘节点 TLS 证书生成...")
	for i := 0; i < 10; i++ {
		if out, _ := c.Run("test -f /etc/cdnpanel/edge-tls/cert.pem && echo ok"); strings.TrimSpace(out) == "ok" {
			break
		}
		time.Sleep(time.Second)
	}
	report("step_16", fmt.Sprintf(
		"部署完成！请务必把 %s 限源到主控 IP：ufw allow from <主控IP> to any port %s proto tcp && ufw deny %s/tcp"+
			"（云主机改在安全组里配，授权对象不要写 0.0.0.0/0）。这是主控下发 CC/XDP 阈值、封禁名单和域名私钥的"+
			"唯一通道，裸放在外网等于把整台节点交给中间人。验证：从别的机器 curl -m 5 https://<节点IP>:%s/edge/status，"+
			"应当超时或被拒绝；拿到 401 说明端口还对外可达。", edgePort, edgePort, edgePort, edgePort))

	return token, nil
}

// startTengine 让节点上的 Tengine 以新配置运行，重复部署也不会 bind() 失败。
//
// 以前这里是 `pkill -f 'tengine: master'` 再直接启动，但 Tengine 的进程标题是
// "nginx: master process ..."，那个模式永远匹配不到：重装老节点时旧实例一直占着 80/443，
// 新实例报 "bind() to 0.0.0.0:80 failed (98: Address already in use)"。
//
//  1. 旧实例还活着（pid 文件指向 /usr/local/tengine 下的进程）→ 直接 reload，连接不断。
//  2. 否则清掉残留实例（systemd 单元、-s stop、按二进制路径 pkill），等端口释放。
//  3. 80/443 仍被占用 → 一定是别的程序（宝塔 nginx、apache、caddy…），不替用户杀，
//     把占用者报出来。
func startTengine(c *SSHClient, report func(step, msg string)) error {
	const (
		bin  = "/usr/local/tengine/sbin/tengine"
		conf = "/etc/tengine/tengine.conf"
	)
	running := `p=$(cat /var/run/tengine.pid 2>/dev/null); [ -n "$p" ] && readlink /proc/$p/exe 2>/dev/null | grep -q '^/usr/local/tengine/' && echo running`
	if out, _ := c.Run(running); strings.TrimSpace(out) == "running" {
		report("step_14", "Tengine 已在运行，平滑重载配置...")
		if out, err := c.Run(bin + " -c " + conf + " -s reload"); err == nil {
			return nil
		} else {
			log.Printf("deploy: tengine reload failed, falling back to restart: %s: %v", out, err)
		}
	}

	// pkill 模式写成 [/]usr/...：否则执行这条命令的 shell 自己的命令行也匹配，会被一起杀掉，
	// 后半截命令不执行。
	c.Run("systemctl stop tengine 2>/dev/null; " + bin + " -c " + conf + " -s stop 2>/dev/null; " +
		"sleep 1; pkill -f '[/]usr/local/tengine/sbin/tengine' 2>/dev/null; true")

	portsBusy := `ss -ltn 'sport = :80 or sport = :443' 2>/dev/null | awk 'NR>1' | grep -q . && echo busy`
	for i := 0; i < 10; i++ {
		if out, _ := c.Run(portsBusy); strings.TrimSpace(out) != "busy" {
			break
		}
		if i == 9 {
			owners, _ := c.Run(`ss -ltnp 'sport = :80 or sport = :443' 2>/dev/null | awk 'NR>1{print $4, $NF}'`)
			return fmt.Errorf("80/443 端口被其他程序占用，Tengine 无法监听。占用者：\n%s\n"+
				"如果是宝塔的 Nginx/Apache，请在宝塔「软件商店」里停止并关闭开机自启（或 systemctl stop nginx httpd），"+
				"边缘节点的 80/443 必须交给 Tengine；处理后重新部署", strings.TrimSpace(owners))
		}
		time.Sleep(500 * time.Millisecond)
	}

	if out, err := c.Run(bin + " -c " + conf); err != nil {
		return fmt.Errorf("tengine start failed: %s: %w", out, err)
	}
	return nil
}

// ensureRestyCore 幂等地确保 lua-resty-core + lua-resty-lrucache 装进 LuaJIT 默认搜索路径
// /usr/local/share/lua/5.1。已存在（resty/core.lua 就位）则直接跳过，避免每次部署都联网拉源码。
// 版本与 installTengine 保持一致（OpenResty 1.25.3.1 官方配对）。
// 缺它 tengine 启动时报 "failed to load the 'resty.core' module" 直接失败。
func ensureRestyCore(c *SSHClient) error {
	const (
		restyCoreVer = "0.1.28"
		lruCacheVer  = "0.13"
	)
	if out, _ := c.Run("test -f /usr/local/share/lua/5.1/resty/core.lua && echo ok"); strings.TrimSpace(out) == "ok" {
		return nil
	}
	script := `set -e
export DEBIAN_FRONTEND=noninteractive
_apt_wait(){ i=0; while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do i=$((i+1)); [ "$i" -gt 150 ] && break; sleep 2; done; }
command -v wget >/dev/null 2>&1 || { _apt_wait; apt-get -o DPkg::Lock::Timeout=300 install -y -qq wget; }
cd /tmp
rm -rf lua-resty-core.tar.gz lua-resty-core-` + restyCoreVer + ` \
  lua-resty-lrucache.tar.gz lua-resty-lrucache-` + lruCacheVer + `
wget -q "https://github.com/openresty/lua-resty-core/archive/refs/tags/v` + restyCoreVer + `.tar.gz" -O lua-resty-core.tar.gz
tar -xzf lua-resty-core.tar.gz
wget -q "https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v` + lruCacheVer + `.tar.gz" -O lua-resty-lrucache.tar.gz
tar -xzf lua-resty-lrucache.tar.gz
( cd "lua-resty-core-` + restyCoreVer + `" && make install LUA_LIB_DIR=/usr/local/share/lua/5.1 )
( cd "lua-resty-lrucache-` + lruCacheVer + `" && make install LUA_LIB_DIR=/usr/local/share/lua/5.1 )
rm -rf lua-resty-core.tar.gz lua-resty-core-` + restyCoreVer + ` \
  lua-resty-lrucache.tar.gz lua-resty-lrucache-` + lruCacheVer + `
test -f /usr/local/share/lua/5.1/resty/core.lua
`
	out, err := c.Run(script)
	if err != nil {
		return fmt.Errorf("install lua-resty-core/lrucache: %s: %w", out, err)
	}
	return nil
}

// installTengine 在远程节点编译安装 Tengine 3.1.0（原生支持 OpenSSL 3.x），
// 并带上 lua 全家桶，使站点模板的 access_by_lua_block（第三层 JA4H 指纹检测）可用。
// 版本用 OpenResty 1.25.3.1 bundle 的官方配对（权威，避免版本猜测）：
//
//	LuaJIT2 fork 2.1-20220411 + NDK 0.3.1（必须排在 lua-nginx-module 前）
//	+ lua-nginx-module 0.10.26 + lua-resty-core 0.1.28 + lua-resty-lrucache 0.13
//
// 关键：lua-nginx-module >= 0.10.16 强制依赖 resty.core（纯 lua 库），缺它启动时
// lua VM 初始化直接失败（"failed to load the 'resty.core' module"）。resty-core 又
// 依赖 lrucache。两个纯 lua 库必须装进 LuaJIT 的默认搜索路径 /usr/local/share/lua/5.1，
// 否则 tengine 起不来。
//
// lua 依赖需联网从 github.com 拉源码；若边缘节点访问 GitHub 受限则编译失败，
// 由上层 DeployEdge 返回错误（不静默降级，避免拿到不带 lua 的二进制）。
func installTengine(c *SSHClient) error {
	const (
		ver          = "3.1.0"
		luajitVer    = "2.1-20220411"
		ndkVer       = "0.3.1"
		luaNgxVer    = "0.10.26"
		restyCoreVer = "0.1.28"
		lruCacheVer  = "0.13"
	)
	script := `set -e
export DEBIAN_FRONTEND=noninteractive
LOG=/tmp/tengine_install.log
exec > >(tee -a "$LOG") 2>&1
echo "=== Tengine ` + ver + ` installation started at $(date) ==="
echo "Memory: $(free -h | grep Mem)"
cd /tmp
rm -rf "tengine-` + ver + `" "tengine-` + ver + `.tar.gz" \
  headers-more.tar.gz headers-more-nginx-module-0.36 \
  ngx_cache_purge.tar.gz ngx_cache_purge-2.3 \
  luajit2.tar.gz luajit2-` + luajitVer + ` \
  ndk.tar.gz ngx_devel_kit-` + ndkVer + ` \
  lua-nginx-module.tar.gz lua-nginx-module-` + luaNgxVer + ` \
  lua-resty-core.tar.gz lua-resty-core-` + restyCoreVer + ` \
  lua-resty-lrucache.tar.gz lua-resty-lrucache-` + lruCacheVer + `

echo "[1/8] Downloading Tengine..."
wget "https://github.com/alibaba/tengine/archive/refs/tags/` + ver + `.tar.gz" -O "tengine-` + ver + `.tar.gz" || { echo "ERROR: Failed to download Tengine"; exit 1; }
tar -xzf "tengine-` + ver + `.tar.gz" || { echo "ERROR: Failed to extract Tengine"; exit 1; }

echo "[2/8] Downloading modules..."
wget "https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v0.36.tar.gz" -O headers-more.tar.gz || { echo "ERROR: Failed to download headers-more"; exit 1; }
tar -xzf headers-more.tar.gz
wget "https://github.com/FRiCKLE/ngx_cache_purge/archive/refs/tags/2.3.tar.gz" -O ngx_cache_purge.tar.gz || { echo "ERROR: Failed to download ngx_cache_purge"; exit 1; }
tar -xzf ngx_cache_purge.tar.gz

echo "[3/8] Downloading LuaJIT2..."
wget "https://github.com/openresty/luajit2/archive/refs/tags/v` + luajitVer + `.tar.gz" -O luajit2.tar.gz || { echo "ERROR: Failed to download LuaJIT2"; exit 1; }
tar -xzf luajit2.tar.gz

echo "[4/8] Compiling LuaJIT2..."
( cd "luajit2-` + luajitVer + `" && make CCDEBUG=-g CFLAGS=-fPIC -j"$(nproc)" && make install PREFIX=/usr/local ) || { echo "ERROR: LuaJIT2 compilation failed"; exit 1; }
echo "/usr/local/lib" > /etc/ld.so.conf.d/luajit.conf
ldconfig || true
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
echo "LuaJIT installed: $(ls -la /usr/local/lib/libluajit* 2>/dev/null || echo 'WARNING: libluajit not found')"

echo "[5/8] Downloading Lua modules..."
wget "https://github.com/vision5/ngx_devel_kit/archive/refs/tags/v` + ndkVer + `.tar.gz" -O ndk.tar.gz || { echo "ERROR: Failed to download NDK"; exit 1; }
tar -xzf ndk.tar.gz
wget "https://github.com/openresty/lua-nginx-module/archive/refs/tags/v` + luaNgxVer + `.tar.gz" -O lua-nginx-module.tar.gz || { echo "ERROR: Failed to download lua-nginx-module"; exit 1; }
tar -xzf lua-nginx-module.tar.gz
wget "https://github.com/openresty/lua-resty-core/archive/refs/tags/v` + restyCoreVer + `.tar.gz" -O lua-resty-core.tar.gz || { echo "ERROR: Failed to download lua-resty-core"; exit 1; }
tar -xzf lua-resty-core.tar.gz
wget "https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v` + lruCacheVer + `.tar.gz" -O lua-resty-lrucache.tar.gz || { echo "ERROR: Failed to download lua-resty-lrucache"; exit 1; }
tar -xzf lua-resty-lrucache.tar.gz

echo "[6/8] Installing Lua libraries..."
( cd "lua-resty-core-` + restyCoreVer + `" && make install LUA_LIB_DIR=/usr/local/share/lua/5.1 ) || { echo "ERROR: lua-resty-core installation failed"; exit 1; }
( cd "lua-resty-lrucache-` + lruCacheVer + `" && make install LUA_LIB_DIR=/usr/local/share/lua/5.1 ) || { echo "ERROR: lua-resty-lrucache installation failed"; exit 1; }

echo "[7/8] Configuring Tengine..."
cd "tengine-` + ver + `"
./configure \
  --prefix=/usr/local/tengine \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_gzip_static_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --add-module=modules/ngx_http_upstream_check_module \
  --add-module=modules/ngx_http_concat_module \
  --add-module=/tmp/headers-more-nginx-module-0.36 \
  --add-module=/tmp/ngx_cache_purge-2.3 \
  --add-module=/tmp/ngx_devel_kit-` + ndkVer + ` \
  --add-module=/tmp/lua-nginx-module-` + luaNgxVer + ` \
  --with-http_gunzip_module \
  --with-pcre \
  --with-stream \
  --with-stream_ssl_module || { echo "ERROR: Tengine configure failed"; exit 1; }

echo "[8/8] Compiling Tengine (this may take 5-15 minutes)..."
TOTAL_MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)
if [ "$TOTAL_MEM_MB" -lt 3072 ]; then
  echo "Low memory detected ($TOTAL_MEM_MB MB), using single thread compilation"
  MAKE_JOBS=1
else
  MAKE_JOBS=$(nproc)
  echo "Using $MAKE_JOBS parallel jobs"
fi
make -j"$MAKE_JOBS" || { echo "ERROR: Tengine compilation failed"; exit 1; }

echo "Installing Tengine..."
make install || { echo "ERROR: Tengine installation failed"; exit 1; }

echo "Creating symlinks..."
ln -sf /usr/local/tengine/sbin/nginx /usr/local/tengine/sbin/tengine
ln -sf /usr/local/tengine/sbin/tengine /usr/local/sbin/tengine

echo "Verifying installation..."
if [ ! -f /usr/local/tengine/sbin/nginx ]; then
  echo "ERROR: Tengine binary not found after installation"
  exit 1
fi

/usr/local/tengine/sbin/nginx -V 2>&1 | grep -q "lua-nginx-module" || { echo "ERROR: lua-nginx-module not found in compiled binary"; exit 1; }

echo "Cleaning up..."
cd /tmp && rm -rf "tengine-` + ver + `" "tengine-` + ver + `.tar.gz" \
  headers-more.tar.gz headers-more-nginx-module-0.36 \
  ngx_cache_purge.tar.gz ngx_cache_purge-2.3 \
  luajit2.tar.gz luajit2-` + luajitVer + ` \
  ndk.tar.gz ngx_devel_kit-` + ndkVer + ` \
  lua-nginx-module.tar.gz lua-nginx-module-` + luaNgxVer + ` \
  lua-resty-core.tar.gz lua-resty-core-` + restyCoreVer + ` \
  lua-resty-lrucache.tar.gz lua-resty-lrucache-` + lruCacheVer + `

echo "=== Tengine installation completed successfully at $(date) ==="
echo "Installation log saved to: /tmp/tengine_install.log"
`
	out, err := c.Run(script)
	if err != nil {
		return fmt.Errorf("tengine build failed: %w\n\nOutput:\n%s\n\nPlease check /tmp/tengine_install.log on the remote server for detailed error messages", err, out)
	}
	return nil
}
