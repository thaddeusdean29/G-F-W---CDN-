#!/bin/bash

# CDN Panel + Tengine 一键安装脚本
# 支持 Debian/Ubuntu
# 健壮性改进：不会因为单个步骤失败而停止，关键步骤必须成功

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[ "$(id -u)" -ne 0 ] && error "请用 root 或 sudo 运行此脚本"

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILED_STEPS=()
SUCCESS_STEPS=()

[ -f "$SCRIPT_DIR/go.mod" ] || error "go.mod not found in $SCRIPT_DIR"

# 配置参数
PANEL_VERSION="${PANEL_VERSION:-1.0.0}"
ADMIN_PASS="${ADMIN_PASS:-123456}"
PANEL_PORT="${PANEL_PORT:-8080}"
EDGE_PORT="${EDGE_PORT:-9090}"
EDGE_TOKEN="${EDGE_TOKEN:-}"
MODE="${MODE:-master}"
XDP_IFACE="${XDP_IFACE:-}"
SKIP_TENGINE="${SKIP_TENGINE:-0}"
GO_MIN_VERSION="1.21"
GO_INSTALL_VERSION="1.21.13"
# 前端编译用（见 4.5 步）。vite 6 的 engines 是 ^18 || ^20 || >=22，取 20 LTS。
# 发行版仓库里的 nodejs 常常是 12/16，装上也编不动，所以与 Go 一样走官方 tarball。
NODE_INSTALL_VERSION="20.18.1"
NODE_MIN_MAJOR="18"
TENGINE_VERSION="3.1.0"
TENGINE_URL="https://github.com/alibaba/tengine/archive/refs/tags/${TENGINE_VERSION}.tar.gz"
# Lua 全家桶版本（用 OpenResty 1.25.3.1 bundle 的官方配对，权威，避免版本猜测）。
# 关键：lua-nginx-module >= 0.10.16 强制依赖 resty.core（纯 lua 库），缺它启动时
# lua VM 初始化直接失败（"failed to load the 'resty.core' module"）；resty-core 又
# 依赖 lrucache。两个纯 lua 库必须装进 LuaJIT 默认路径 /usr/local/share/lua/5.1。
LUAJIT_VERSION="2.1-20220411"   # OpenResty LuaJIT2 fork
NDK_VERSION="0.3.1"             # ngx_devel_kit（GitHub tag v0.3.1）
LUA_NGX_VERSION="0.10.26"       # lua-nginx-module
RESTY_CORE_VERSION="0.1.28"     # lua-resty-core（lua-nginx-module 强制运行时依赖）
LRUCACHE_VERSION="0.13"         # lua-resty-lrucache（resty-core 依赖）
MASTER_URL="${MASTER_URL:-}"
# 自动注册：CLUSTER_ID 为要加入的集群 ID（面板「集群」页可见）；REGISTER_SECRET 为主控
# /etc/cdnpanel/edge_register.secret 的内容，没有它主控会拒绝注册（403）。
CLUSTER_ID="${CLUSTER_ID:-}"
REGISTER_SECRET="${REGISTER_SECRET:-}"
HOST_IP=""

# 步骤记录函数
step_start() { info "▶ $1"; }
step_success() { info "✓ $1"; SUCCESS_STEPS+=("$1"); }
step_fail() { warn "✗ $1"; FAILED_STEPS+=("$1"); }

# ═══════════════════════════════════════════════════════════════════════════
# 0. 内存检测和 Swap 优化
# ═══════════════════════════════════════════════════════════════════════════
step_start "检测系统资源 - 系统开源：@AnJintalk_bot"
TOTAL_MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)
SWAP_MB=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)

info "系统内存: ${TOTAL_MEM_MB}MB"
info "Swap 空间: ${SWAP_MB}MB"

# 如果内存小于 3GB 且 Swap 小于 2GB，建议创建 Swap
if [ "$TOTAL_MEM_MB" -lt 3072 ] && [ "$SWAP_MB" -lt 2048 ] && [ "$SKIP_TENGINE" != "1" ]; then
    warn "检测到低内存环境（< 3GB），建议创建 Swap 空间以确保 Tengine 编译成功"
    echo ""
    echo "Tengine 编译需要较多内存，在低内存环境下可能失败。"
    echo "创建 Swap 交换空间可以解决此问题（安装后可以保留或删除）。"
    echo ""
    echo "选项："
    echo "  1) 自动创建 2GB Swap（推荐，安全可靠）"
    echo "  2) 跳过 Swap 创建（可能导致编译失败）"
    echo ""
    read -p "请选择 [1/2，默认1]: " SWAP_CHOICE
    SWAP_CHOICE="${SWAP_CHOICE:-1}"

    if [ "$SWAP_CHOICE" = "1" ]; then
        if [ -f /swapfile ]; then
            warn "检测到 /swapfile 已存在"
            EXISTING_SWAP_MB=$(du -m /swapfile 2>/dev/null | awk '{print $1}')
            if [ -n "$EXISTING_SWAP_MB" ] && [ "$EXISTING_SWAP_MB" -ge 1024 ]; then
                info "已有 Swap 文件大小: ${EXISTING_SWAP_MB}MB，跳过创建"
            else
                warn "现有 Swap 文件太小，将重新创建"
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile

                info "创建 2GB Swap 文件（约需1-2分钟）..."
                dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress 2>&1 | grep -v records || true
                chmod 600 /swapfile
                mkswap /swapfile >/dev/null 2>&1
                swapon /swapfile

                if ! grep -q '/swapfile' /etc/fstab 2>/dev/null; then
                    echo '/swapfile none swap sw 0 0' >> /etc/fstab
                    info "Swap 已添加到 /etc/fstab（重启后自动启用）"
                fi
            fi
        else
            info "创建 2GB Swap 文件（约需1-2分钟）..."
            dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress 2>&1 | grep -v records || true
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null 2>&1
            swapon /swapfile

            if ! grep -q '/swapfile' /etc/fstab 2>/dev/null; then
                echo '/swapfile none swap sw 0 0' >> /etc/fstab
                info "Swap 已添加到 /etc/fstab（重启后自动启用）"
            fi
        fi

        SWAP_MB=$(awk '/SwapTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
        info "✓ Swap 配置完成，当前总计: ${SWAP_MB}MB"
        step_success "Swap 空间创建"
    else
        warn "已跳过 Swap 创建，如果编译失败请重新运行安装脚本并选择创建 Swap"
    fi
fi
step_success "系统资源检测"

# ═══════════════════════════════════════════════════════════════════════════
# 1. 网络检测
# ═══════════════════════════════════════════════════════════════════════════
step_start "检测网络接口"
HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
[ -z "$HOST_IP" ] && HOST_IP=$(hostname -I | awk '{print $1}')
[ -z "$HOST_IP" ] && HOST_IP="127.0.0.1"

if [ -z "$XDP_IFACE" ]; then
    XDP_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
fi
[ -z "$XDP_IFACE" ] && XDP_IFACE="eth0"

info "IP: ${HOST_IP}, 网卡: ${XDP_IFACE}"
step_success "网络检测"

# ═══════════════════════════════════════════════════════════════════════════
# 2. Go 环境
# ═══════════════════════════════════════════════════════════════════════════
step_start "检查 Go 环境"
if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    GO_MAJOR=$(echo "$CURRENT_GO" | cut -d. -f1)
    GO_MINOR=$(echo "$CURRENT_GO" | cut -d. -f2)
    if [ "$GO_MAJOR" -gt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 21 ]; }; then
        info "Go ${CURRENT_GO} ✓"
        step_success "Go 环境就位"
    else
        error "Go 版本过低（${CURRENT_GO}），需要 >= 1.21"
    fi
else
    info "安装 Go ${GO_INSTALL_VERSION}..."
    cd /tmp
    GO_TARBALL="go${GO_INSTALL_VERSION}.linux-amd64.tar.gz"
    rm -f "$GO_TARBALL"

    GO_MIRRORS=(
        "https://go.dev/dl/${GO_TARBALL}"
        "https://golang.google.cn/dl/${GO_TARBALL}"
        "https://mirrors.aliyun.com/golang/${GO_TARBALL}"
    )

    GO_DOWNLOADED=0
    for url in "${GO_MIRRORS[@]}"; do
        info "尝试下载：${url}"
        if wget -q --tries=3 --timeout=30 "$url" -O "$GO_TARBALL" && [ -s "$GO_TARBALL" ] && file "$GO_TARBALL" | grep -q gzip; then
            GO_DOWNLOADED=1
            break
        fi
        warn "下载失败或文件损坏：${url}"
        rm -f "$GO_TARBALL"
    done

    [ "$GO_DOWNLOADED" -eq 1 ] || error "Go 下载失败（已尝试 ${#GO_MIRRORS[@]} 个源，请检查服务器出网/DNS）"

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TARBALL"
    rm -f "$GO_TARBALL"
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    step_success "Go 安装完成"
fi
export PATH=$PATH:/usr/local/go/bin

# ═══════════════════════════════════════════════════════════════════════════
# 3. 系统依赖
# ═══════════════════════════════════════════════════════════════════════════
step_start "安装系统依赖"
if command -v apt-get &>/dev/null; then
    apt-get update -qq 2>/dev/null || true
    # libc6-dev / linux-libc-dev 显式列出：XDP 编译走 <linux/bpf.h> → <linux/types.h>
    # → <asm/types.h>，asm/ 由它们铺在 /usr/include/<arch>-linux-gnu 下。build-essential
    # 通常会间接拉进来，但显式声明可避免精简镜像里缺 asm/types.h 导致 XDP 编译失败。
    apt-get install -y -qq curl wget build-essential libpcre3-dev zlib1g-dev libssl-dev certbot \
        clang llvm libbpf-dev libc6-dev linux-libc-dev linux-headers-"$(uname -r)" iproute2 openssl \
        libbrotli-dev libbrotli1 >/dev/null 2>&1
    step_success "系统依赖（apt-get）"
elif command -v yum &>/dev/null; then
    yum install -y -q curl wget gcc gcc-c++ make pcre-devel zlib-devel openssl-devel certbot \
        clang llvm libbpf-devel kernel-devel iproute brotli-devel >/dev/null 2>&1 || true
    step_success "系统依赖（yum）"
else
    step_fail "包管理器检测（只支持 apt-get/yum）"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4. 编译 XDP + Go 应用
# ═══════════════════════════════════════════════════════════════════════════
step_start "编译 XDP eBPF 程序"
mkdir -p /usr/local/bin
# XDP 源码只有一份（internal/xdp/cdn_xdp.c，同时被 go:embed 与本脚本的 clang 使用）：
# 历史上这里还往 internal/edgeapi 同步一份 .embed.c.txt 副本，那个副本已经没人读了，
# 留着只会让人以为面板装 XDP 用的是另一份源码。
# 编译 XDP。三轮递进参数与 internal/edgeapi/handler.go 的 doInstallXdp 保持一致，
# 保证"install.sh"、"面板一键部署"、"面板安装 XDP 按钮"三条路径行为相同。
#
# 注意：这里**不能**把编译错误丢进 /dev/null。历史上三轮都写 `2>/dev/null`，源码里一个
# 多余的 `#include <linux/icmp.h>`（会拉到 32 位 glibc 的 gnu/stubs-32.h）让所有轮次
# 全部失败，但脚本只在末尾列一行"XDP 编译失败"，没人看得到真正原因，于是"XDP 已启用"
# 的假象维持了很久。失败时必须把 clang 的原始输出打出来。
XDP_LOG="/tmp/cdn_xdp_build.log"
: > "$XDP_LOG"
XDP_ARCH="$(uname -m)"
xdp_compiled=0
xdp_try() {
    local label="$1"; shift
    {
        echo "=== attempt: $label ==="
        echo "clang $*"
    } >> "$XDP_LOG"
    if clang "$@" -c "$SCRIPT_DIR/internal/xdp/cdn_xdp.c" \
        -o /usr/local/bin/cdn_xdp.o >>"$XDP_LOG" 2>&1; then
        step_success "XDP 编译成功（$label）"
        xdp_compiled=1
        return 0
    fi
    echo "" >> "$XDP_LOG"
    return 1
}

xdp_try "标准参数" -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/"$XDP_ARCH"-linux-gnu \
  || xdp_try "追加 /usr/include" -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/"$XDP_ARCH"-linux-gnu -I/usr/include \
  || xdp_try "最小参数" -O2 -g -target bpf

if [ "$xdp_compiled" -ne 1 ]; then
    # 删掉可能残留的半成品 .o，避免后续 `[ -f cdn_xdp.o ]` 判断误报"XDP 已启用"。
    rm -f /usr/local/bin/cdn_xdp.o
    step_fail "XDP 编译失败，跳过 XDP 防护（详见 $XDP_LOG）"
    warn "XDP 编译失败，clang 输出如下（三轮参数全部失败）："
    sed 's/^/    /' "$XDP_LOG" >&2
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4.5 前端控制台（Vue -> web/console_dist，go:embed 进 cdnpanel）
# ═══════════════════════════════════════════════════════════════════════════
# 必须在「编译 Go 应用」之前：web/web.go 是 go:embed all:console_dist，缺产物时
# go build 报的是 pattern all:console_dist: no matching files found，客户看不懂那句。
#
# 判据是「有没有真产物」而不是「目录在不在」：web/web.go 的注释提到仓库里可能只留一个
# 占位提示页，占位页同样能让 go:embed 编过，但装完打开 /console/ 是个空壳。真产物要
# 两条同时成立——index.html 按 /console/ base 引用了 assets，且 assets 目录非空。
web_dist_ready() {
    [ -f "$SCRIPT_DIR/web/console_dist/index.html" ] || return 1
    grep -q '/console/assets/' "$SCRIPT_DIR/web/console_dist/index.html" || return 1
    [ -n "$(find "$SCRIPT_DIR/web/console_dist/assets" -type f -print -quit 2>/dev/null)" ] || return 1
    return 0
}

# vite 6 的 engines 是 ^18 || ^20 || >=22。发行版仓库的 nodejs 常是 12/16，
# 「装了 node」不等于「能编」，所以版本也要一起判。
node_ok() {
    command -v node &>/dev/null || return 1
    command -v npm &>/dev/null || return 1
    local major
    major="$(node -v | sed 's/^v//' | cut -d. -f1)"
    [ "${major:-0}" -ge "$NODE_MIN_MAJOR" ]
}

step_start "构建前端控制台"
if web_dist_ready; then
    step_success "前端产物已就位，跳过构建（要强制重编：删掉 web/console_dist 后重跑）"
elif [ ! -f "$SCRIPT_DIR/vue/package.json" ]; then
    # 二进制分发包不带 vue 源码，产物必须已经在包里。
    step_fail "前端控制台缺失"
    error "包里没有 vue/ 源码，也没有可用的 web/console_dist，cdnpanel 编不出来。
       请在构建机上跑 ./build.sh（会自动编译前端）出包，再拿产物安装。"
else
    # 源码包安装：现场编前端。客户机一般没有 Node，这里沿用上面 Go 那一步的同一套路——
    # 官方 tarball + 国内镜像兜底，解到 /usr/local，不引第三方软件源。
    if ! node_ok; then
        info "安装 Node ${NODE_INSTALL_VERSION}（前端编译需要，>= ${NODE_MIN_MAJOR}）..."
        cd /tmp
        NODE_TARBALL="node-v${NODE_INSTALL_VERSION}-linux-x64.tar.gz"
        rm -f "$NODE_TARBALL"
        NODE_MIRRORS=(
            "https://nodejs.org/dist/v${NODE_INSTALL_VERSION}/${NODE_TARBALL}"
            "https://mirrors.aliyun.com/nodejs-release/v${NODE_INSTALL_VERSION}/${NODE_TARBALL}"
            "https://mirrors.tuna.tsinghua.edu.cn/nodejs-release/v${NODE_INSTALL_VERSION}/${NODE_TARBALL}"
        )
        NODE_DOWNLOADED=0
        for url in "${NODE_MIRRORS[@]}"; do
            info "尝试下载：${url}"
            if wget -q --tries=3 --timeout=60 "$url" -O "$NODE_TARBALL" && [ -s "$NODE_TARBALL" ] && file "$NODE_TARBALL" | grep -q gzip; then
                NODE_DOWNLOADED=1
                break
            fi
            warn "下载失败或文件损坏：${url}"
            rm -f "$NODE_TARBALL"
        done
        if [ "$NODE_DOWNLOADED" -ne 1 ]; then
            step_fail "Node 下载失败"
            error "Node 下载失败（已尝试 ${#NODE_MIRRORS[@]} 个源，请检查服务器出网/DNS）。
       也可自行装好 Node >= ${NODE_MIN_MAJOR} 与 npm 后重跑本脚本。"
        fi
        # 解到带版本号的目录再软链，不 rm -rf 任何既有 node：换版本/装失败都能回退。
        tar -C /usr/local -xzf "$NODE_TARBALL"
        rm -f "$NODE_TARBALL"
        ln -sfn "/usr/local/node-v${NODE_INSTALL_VERSION}-linux-x64" /usr/local/node
        export PATH=/usr/local/node/bin:$PATH
        grep -q '/usr/local/node/bin' /etc/profile 2>/dev/null || echo 'export PATH=/usr/local/node/bin:$PATH' >> /etc/profile
        cd "$SCRIPT_DIR"
        step_success "Node 安装完成"
    fi
    if ! node_ok; then
        step_fail "Node/npm 不可用"
        error "前端编译需要 Node >= ${NODE_MIN_MAJOR} 与 npm，自动安装没成功（当前 node：$(node -v 2>/dev/null || echo 无)）。
       手动装好后重跑本脚本；或在构建机上跑 ./build.sh 出带前端产物的包再安装。"
    fi
    info "Node $(node -v) / npm $(npm -v)"

    # vite 的 emptyOutDir 会清空 console_dist，先备份旧产物才可回滚。
    # 备份目录是 console_dist 的兄弟目录，不会被 emptyOutDir 清掉。
    if [ -f "$SCRIPT_DIR/web/console_dist/index.html" ]; then
        WEB_BAK="$SCRIPT_DIR/web/_backup-console_dist-$(date +%Y%m%d-%H%M)"
        mkdir -p "$WEB_BAK"
        cp -a "$SCRIPT_DIR/web/console_dist/." "$WEB_BAK/"
        info "旧前端产物已备份到 $WEB_BAK"
    fi

    # npm 输出留档不吞掉：XDP 那一步的历史教训就是三轮错误全进 /dev/null，
    # 末尾只留一行「编译失败」，真正原因没人看得到，假象维持了很久。
    WEB_LOG="/tmp/cdn_web_build.log"
    : > "$WEB_LOG"
    if (
        cd "$SCRIPT_DIR/vue"
        # 有 lock 文件用 ci：按 lock 精确装，产物可复现。
        if [ -f package-lock.json ]; then
            npm ci --no-audit --no-fund
        else
            npm install --no-audit --no-fund
        fi
        # NODE_ENV 显式钉 production：vite.config.ts 的 base 由它决定，
        # 环境里带个 development 就会产出 base=/ 的包，挂到 /console/ 下资源全 404。
        NODE_ENV=production npm run build
    ) >>"$WEB_LOG" 2>&1; then
        if web_dist_ready; then
            step_success "前端控制台构建成功（$(find "$SCRIPT_DIR/web/console_dist/assets" -type f | wc -l | tr -d '[:space:]') 个资源文件）"
        else
            step_fail "前端产物举证失败"
            sed 's/^/    /' "$WEB_LOG" >&2
            error "npm run build 报成功，但 web/console_dist 不是可用产物（index.html 未按 /console/ base 引用 assets，或 assets 为空）。详见 $WEB_LOG"
        fi
    else
        step_fail "前端控制台构建失败"
        sed 's/^/    /' "$WEB_LOG" >&2
        error "前端构建失败，cdnpanel 的 go:embed 拿不到 console_dist。详见 $WEB_LOG
       手动复现：cd $SCRIPT_DIR/vue && npm ci && NODE_ENV=production npm run build"
    fi
fi

step_start "编译 Go 应用"
cd "$SCRIPT_DIR"
go mod tidy >/dev/null 2>&1 || true
go mod download >/dev/null 2>&1 || true

# garble 默认关闭，要开就显式 GARBLE=1 bash install.sh。与 build.sh 同一套判断，原因不是
# "混淆没生效"，而是混淆把程序本身打坏了：2026-11-14 用 v0.12.1 `-literals -tiny` 出的包，
# 面板首页每请求必 500，日志是
#   template: layout:7:9: executing "head" at <.PageTitle>: can't evaluate field PageTitle
#   in type bmiwf8V3.hXyVqMmqM
# ——那就是被改名的 homeView。模板数据全靠 struct 字段渲染（对客首页、文档页、
# internal/tengine/generator.go 的站点配置），而字段名只出现在密封的 .tmpl 文本里，
# garble 看不见这种用法，照改字段名，反射取值全线失败。代价不是某个页面，是全站。
# 这里比构建机更要紧：装的是客户自己手里的边缘节点，首页 500 之外还会整节点配置停更。
# 旧代码是 `go install mvdan.cc/garble@latest` + 无条件优先 garble，等于默认把这套打坏的
# 配置发给每一台新装机器；@latest 还会随上游漂到与本机 Go 不配对的版本。两条都撤掉。
GARBLE_VERSION="v0.12.1"

GOBIN_DIR="$(go env GOBIN)"
[ -n "$GOBIN_DIR" ] || GOBIN_DIR="$(go env GOPATH)/bin"

garble_ok() {
    local bin="$1"
    [ -n "$bin" ] && [ -x "$bin" ] || return 1
    "$bin" version 2>/dev/null | head -1 | grep -qF "garble ${GARBLE_VERSION}"
}

BUILD_CMD="go build"
GARBLE_BIN=""
if [ "${GARBLE:-0}" = "1" ]; then
    for cand in "$GOBIN_DIR/garble" "$GOBIN_DIR/garble.exe" "$(command -v garble 2>/dev/null)"; do
        if garble_ok "$cand"; then GARBLE_BIN="$cand"; break; fi
    done
    if [ -z "$GARBLE_BIN" ]; then
        info "安装 garble ${GARBLE_VERSION}（与本机 Go 配对的版本）..."
        go install "mvdan.cc/garble@${GARBLE_VERSION}" >/dev/null 2>&1 || true
        for cand in "$GOBIN_DIR/garble" "$GOBIN_DIR/garble.exe" "$(command -v garble 2>/dev/null)"; do
            if garble_ok "$cand"; then GARBLE_BIN="$cand"; break; fi
        done
    fi
    if [ -z "$GARBLE_BIN" ]; then
        # 版本与 Go 严格配对：v0.12.1 的 go.mod 写 go 1.21，本脚本装的正是 1.21.13。
        # 禁止回退成 @latest，也禁止静默改用普通 go build 冒充混淆产物。
        error "GARBLE=1 但拿不到 garble ${GARBLE_VERSION}。若本机 Go 已不是 1.21，把脚本里的
       GARBLE_VERSION 一起升到配对版本；不要改回 @latest。"
    fi
    BUILD_CMD="$GARBLE_BIN -literals -tiny build"
    warn "已启用 garble ${GARBLE_VERSION}：装完必须真打开一次面板首页并生成一次站点配置，"
    warn "字段名被改名会表现为 template: ... can't evaluate field ...（历史上全站 500）"
else
    info "未启用 garble（默认）：二进制里可 grep 到包路径与内置总密钥"
    warn "  ⇒ 拿到该二进制的人可解站点模板/WAF 规则密文，以及库里的租户 TLS 私钥、Cloudflare token、节点 token"
    warn "  要混淆就 GARBLE=1 bash install.sh，但必须先按上面的警告真验一次首页与站点配置生成"
fi

# 构建号注入，与 build.sh 同格式同取法。包路径从 go.mod 现取，别硬编码 cdn/：
# 换模块名时 -X 会静默注不进去，产物照样能跑却带着默认值 dev，面板节点列表只说
# "版本未知"，永远看不出哪台边缘没升级。
BUILD_ID="cdn-$(date +%Y%m%d-%H%M)"
MODULE_PATH="$(grep -m1 '^module ' "$SCRIPT_DIR/go.mod" | awk '{print $2}')"
[ -n "$MODULE_PATH" ] || error "go.mod 里读不到 module 行，无法注入构建号"
LDFLAGS="-s -w -X ${MODULE_PATH}/internal/version.Build=${BUILD_ID}"
info "构建标识 ${BUILD_ID}"

# 构建号举证放在编译之前，判的是注入目标本身，不是产物里有没有那串字符。
# 2026-11-20 实测（Go 1.21，-s -w）：包路径写对 → 运行期 version.Build 就是构建号，
# grep 命中 3；包路径写错（wrongmod）→ 运行期仍是 "dev"，grep 照样命中 2；完全不传
# -X → "dev"，grep 0。链接器会把 -X 的「值」当字符串留在产物里，哪怕目标符号根本
# 不存在，所以 grep 命中数当门禁是假的：注错了也报通过。-s -w 剥掉符号表，
# go tool nm 只会说 no symbols；两个 main 都没有 --version，产物又是给 Linux 的，
# 构建机上跑不了。能静态判准的只有注入目标：包路径与变量声明。
VER_PKG="$(cd "$SCRIPT_DIR" && go list -f '{{.ImportPath}}' ./internal/version 2>/dev/null)"
[ "$VER_PKG" = "${MODULE_PATH}/internal/version" ] || error "构建号注入目标对不上：go.mod 的 module 是 ${MODULE_PATH}，
       但 go list 报 internal/version 的导入路径是「${VER_PKG:-取不到}」。-X 会静默注不进去，
       这台节点的版本永远是 dev（面板显示"版本未知"），先修好再装。"
grep -Eq '^[[:space:]]*var Build[[:space:]]*(=[[:space:]]*"|string([[:space:]]|$))' "$SCRIPT_DIR"/internal/version/*.go \
    || error "internal/version 里没有可被 -X 覆盖的 var Build 声明（必须是包级、字符串、常量初始化）。
       变量改名或改成函数返回值后 -X 同样静默失效，节点版本会一直是 dev。
       只认单行 var 声明；若改成 var (...) 块，这条会拦下来，届时同步改判据。"
info "构建号注入目标已核实：${VER_PKG}.Build"
if [ -n "$GARBLE_BIN" ]; then
    # garble 在链接期改包名，上面查的是源码路径，查不出改名后的落点。
    warn "混淆产物无法静态判定 -X 是否落地：装完请在面板节点列表确认版本列不是"未知""
fi

# 编译输出留档不吞掉。原来两条命令都带 2>/dev/null，失败时末尾只剩一行
# "CDN程序编译是必要的，无法继续"，真正的报错没人看得到——XDP 那步历史上就是三轮错误
# 全进 /dev/null，假象维持了很久。做法与前端那步一致。
GO_LOG="/tmp/cdn_go_build.log"
: > "$GO_LOG"

build_app() {
    local pkg="$1" out="$2"
    echo "==== ${pkg} -> ${out} ====" >>"$GO_LOG"
    $BUILD_CMD -ldflags="$LDFLAGS" -o "$out" "./${pkg}" >>"$GO_LOG" 2>&1
}

if build_app cmd/cdnpanel /usr/local/bin/cdnpanel && build_app cmd/cdnedge /usr/local/bin/cdnedge; then
    chmod +x /usr/local/bin/cdnpanel /usr/local/bin/cdnedge
    step_success "CDN程序编译成功（${BUILD_ID}）"
else
    step_fail "CDN程序编译失败 - 有可能你的代码不完整或GO环境不正确。必要时可以联系：@AnJintalk_bot"
    sed 's/^/    /' "$GO_LOG" >&2
    error "CDN程序编译是必要的，无法继续。详见 $GO_LOG
       手动复现：cd $SCRIPT_DIR && $BUILD_CMD -ldflags='$LDFLAGS' -o /usr/local/bin/cdnpanel ./cmd/cdnpanel"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. 创建目录结构
# ═══════════════════════════════════════════════════════════════════════════
step_start "创建目录结构"
mkdir -p /etc/tengine/sites-available /etc/tengine/sites-enabled 2>/dev/null || true
mkdir -p /var/cache/tengine /var/log/tengine 2>/dev/null || true
mkdir -p /etc/cdnpanel/domains /etc/ssl/cdnpanel 2>/dev/null || true
mkdir -p /var/www/acme/.well-known/acme-challenge 2>/dev/null || true
chown -R www-data:www-data /var/cache/tengine /var/log/tengine /var/www/acme 2>/dev/null || true
step_success "目录创建完成"

# ═══════════════════════════════════════════════════════════════════════════
# 5.1 安装城市级 IP 归属地库（DB-IP City Lite mmdb）
# ═══════════════════════════════════════════════════════════════════════════
# 这两份喂面板流量页「热门来源 IP」的归属地列（要城市）。缺库不影响安装，面板会在页面上
# 写明缺哪个文件、在哪些目录找过；补上文件后重启 cdnpanel 即可，不必重新编译。
# 区域封禁用的是下面 5.2 那两份国家级库，与 city 库不是一回事。
#
# 这里原先还有一段下载 geoip.csv（GeoLite2-country CSV）的逻辑，已删除：没有任何代码读它，
# 区域封禁改由主控扫国家级 mmdb 编前缀表下发（见 docs/GEO_BLOCKING.md），节点上不查库。
# 那份 CSV 随包再分发还与 GeoLite2 的再分发条款冲突。旧脚本备份在
# _v1_backup/root/install.sh.before-geoip-csv-removal-20261119，
# CSV 本体与 download_geoip_csv.sh / setup_geoip.sh 也已移进 _v1_backup/。
step_start "安装城市级 IP 归属地库"
CITY_GEO_OK=0
for f in dbip-city-ipv4.mmdb dbip-city-ipv6.mmdb; do
    DEST="/etc/cdnpanel/$f"
    if [ -s "$DEST" ]; then
        info "$f 已存在，跳过（要换新版本请手工替换后重启 cdnpanel）"
        CITY_GEO_OK=1
        continue
    fi
    if [ -s "$SCRIPT_DIR/data/$f" ]; then
        cp "$SCRIPT_DIR/data/$f" "$DEST"
        chmod 644 "$DEST"
        info "使用内置 $f（$(du -h "$DEST" | cut -f1)）"
        CITY_GEO_OK=1
        continue
    fi
    URL="https://github.com/sapics/ip-location-db/releases/download/latest/$f"
    info "内置库不存在，尝试在线下载：$URL"
    if wget -q --tries=2 --timeout=120 "$URL" -O "$DEST" && [ -s "$DEST" ]; then
        chmod 644 "$DEST"
        info "$f 下载完成（$(du -h "$DEST" | cut -f1)）"
        CITY_GEO_OK=1
    else
        rm -f "$DEST"
        warn "$f 下载失败（非致命）：流量页的归属地列会提示库未就位"
    fi
done
if [ "$CITY_GEO_OK" -eq 1 ]; then
    # CC BY 4.0：许可正文随库交付；控制台展示归属地的那一页已按许可署名回链 db-ip.com。
    if [ -s "$SCRIPT_DIR/data/DBIP-LICENSE" ]; then
        cp "$SCRIPT_DIR/data/DBIP-LICENSE" /etc/cdnpanel/DBIP-LICENSE
        chmod 644 /etc/cdnpanel/DBIP-LICENSE
    fi
    step_success "城市级 IP 归属地库就位"
else
    step_fail "城市级 IP 归属地库未就位（非致命）"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5.2 安装国家级地理库（DB-IP Country Lite mmdb，区域封禁的前缀表由它编译）
# ═══════════════════════════════════════════════════════════════════════════
# 和 5.1 那两份 city 库不是一回事：city 库只给流量页显示归属地，country 库是区域封禁
# 唯一的判决依据——面板扫它编出「国家 → 前缀」表再下发，节点上并不查库。
# 缺它不影响其它功能，但区域封禁会在保存那一步就被拒（管理员页直接写「地理库未就位」），
# 所以这一步要单独报出来，不能让人以为开关拨了就在拦。
step_start "安装国家级地理库（区域封禁）"
COUNTRY_GEO_OK=0
for f in dbip-country-ipv4.mmdb dbip-country-ipv6.mmdb; do
    DEST="/etc/cdnpanel/$f"
    if [ -s "$DEST" ]; then
        info "$f 已存在，跳过（要换新版本请手工替换后重启 cdnpanel）"
        COUNTRY_GEO_OK=1
        continue
    fi
    if [ -s "$SCRIPT_DIR/data/$f" ]; then
        cp "$SCRIPT_DIR/data/$f" "$DEST"
        chmod 644 "$DEST"
        info "使用内置 $f（$(du -h "$DEST" | cut -f1)）"
        COUNTRY_GEO_OK=1
        continue
    fi
    URL="https://github.com/sapics/ip-location-db/releases/download/latest/$f"
    info "内置库不存在，尝试在线下载：$URL"
    if wget -q --tries=2 --timeout=120 "$URL" -O "$DEST" && [ -s "$DEST" ]; then
        chmod 644 "$DEST"
        info "$f 下载完成（$(du -h "$DEST" | cut -f1)）"
        COUNTRY_GEO_OK=1
    else
        rm -f "$DEST"
        warn "$f 下载失败：区域封禁开不了（保存时报「国家级地理库未就位」），其余功能不受影响"
    fi
done
if [ "$COUNTRY_GEO_OK" -eq 1 ]; then
    step_success "国家级地理库就位（区域封禁可用）"
else
    step_fail "国家级地理库未就位：区域封禁开不了，补上 /etc/cdnpanel/dbip-country-*.mmdb 后重启 cdnpanel"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 6. 初始化管理员密码（必须）
# ═══════════════════════════════════════════════════════════════════════════
step_start "初始化管理员密码"
if /usr/local/bin/cdnpanel \
    --init-admin "$ADMIN_PASS" \
    --listen "0.0.0.0:${PANEL_PORT}" \
    --config /etc/cdnpanel/config.json >/dev/null 2>&1; then
    step_success "管理员密码初始化完成"
else
    step_fail "密码初始化失败，手动创建配置"
    # 创建最小配置
    cat > /etc/cdnpanel/config.json << 'EOF'
{
  "listen_addr": "0.0.0.0:8080",
  "tengine_cmd": "/usr/local/tengine/sbin/tengine",
  "tengine_pid": "/var/run/tengine.pid",
  "tengine_conf": "/etc/tengine/tengine.conf",
  "sites_available": "/etc/tengine/sites-available",
  "sites_enabled": "/etc/tengine/sites-enabled",
  "cache_base_path": "/var/cache/tengine",
  "ssl_base_path": "/etc/ssl/cdnpanel",
  "data_dir": "/etc/cdnpanel/domains"
}
EOF
    chmod 600 /etc/cdnpanel/config.json
fi

# ═══════════════════════════════════════════════════════════════════════════
# 7. Tengine 安装（可选，失败时继续）
# ═══════════════════════════════════════════════════════════════════════════
if [ "$SKIP_TENGINE" != "1" ]; then
    step_start "安装 Tengine（可选，失败时继续）"
    mkdir -p /var/log/cdnpanel
    TENGINE_BUILD_LOG="/var/log/cdnpanel/tengine_build.log"
    : > "$TENGINE_BUILD_LOG"
    # 判断是否需要（重新）编译 Tengine：
    #   - 二进制不存在 → 必须编译
    #   - FORCE_TENGINE=1 → 强制重编译
    #   - 已存在但当前二进制不带 lua-nginx-module（旧版本，站点模板的 access_by_lua_block
    #     会导致 tengine -t 失败、443 不监听）→ 强制重编译，拿到带 lua 的新二进制
    NEED_BUILD_TENGINE=0
    if [ ! -f /usr/local/tengine/sbin/tengine ]; then
        NEED_BUILD_TENGINE=1
    elif [ "$FORCE_TENGINE" = "1" ]; then
        NEED_BUILD_TENGINE=1
        info "FORCE_TENGINE=1，强制重新编译 Tengine"
    elif ! /usr/local/tengine/sbin/tengine -V 2>&1 | grep -q "lua-nginx-module"; then
        NEED_BUILD_TENGINE=1
        warn "检测到已有 Tengine 不含 lua-nginx-module（旧版本），强制重新编译以支持 JA4H 指纹检测"
        # 停掉旧实例并删除旧二进制，确保重装干净
        systemctl stop tengine 2>/dev/null || true
        /usr/local/tengine/sbin/tengine -s stop 2>/dev/null || true
        pkill -f /usr/local/tengine/sbin/tengine 2>/dev/null || true
        rm -f /usr/local/tengine/sbin/tengine /usr/local/tengine/sbin/nginx 2>/dev/null || true
    fi
    if [ "$NEED_BUILD_TENGINE" = "1" ]; then
        (
            cd /tmp
            rm -f "tengine-${TENGINE_VERSION}".tar.gz
            if wget -q "${TENGINE_URL}" -O "tengine-${TENGINE_VERSION}.tar.gz" >>"$TENGINE_BUILD_LOG" 2>&1; then
                if file "tengine-${TENGINE_VERSION}.tar.gz" | grep -q gzip; then
                    tar -xzf "tengine-${TENGINE_VERSION}.tar.gz" >>"$TENGINE_BUILD_LOG" 2>&1 || true

                    # 可选模块
                    wget -q "https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v0.36.tar.gz" \
                        -O headers-more.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf headers-more.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true

                    wget -q "https://github.com/FRiCKLE/ngx_cache_purge/archive/refs/tags/2.3.tar.gz" \
                        -O ngx_cache_purge.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf ngx_cache_purge.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true

                    # ── Lua 三件套（版本严格配对，来自官方 tengine-ingress build.sh）──
                    # 1) OpenResty LuaJIT2 fork：系统自带 LuaJIT 未必兼容，必须单独编译。
                    echo "===== 下载编译 LuaJIT2 (${LUAJIT_VERSION}) =====" >>"$TENGINE_BUILD_LOG"
                    wget -q "https://github.com/openresty/luajit2/archive/refs/tags/v${LUAJIT_VERSION}.tar.gz" \
                        -O luajit2.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf luajit2.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    if [ -d "luajit2-${LUAJIT_VERSION}" ]; then
                        ( cd "luajit2-${LUAJIT_VERSION}" \
                            && make CCDEBUG=-g CFLAGS=-fPIC -j"$(nproc)" >>"$TENGINE_BUILD_LOG" 2>&1 \
                            && make install PREFIX=/usr/local >>"$TENGINE_BUILD_LOG" 2>&1 ) || \
                            echo "LuaJIT2 编译失败" >>"$TENGINE_BUILD_LOG"
                        # 确保运行时能找到 libluajit-5.1.so（tengine 启动动态链接需要）
                        echo "/usr/local/lib" > /etc/ld.so.conf.d/luajit.conf
                        ldconfig >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    fi
                    # 2) ngx_devel_kit（NDK，lua-nginx-module 前置依赖）
                    wget -q "https://github.com/vision5/ngx_devel_kit/archive/refs/tags/v${NDK_VERSION}.tar.gz" \
                        -O ndk.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf ndk.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    # 3) lua-nginx-module
                    wget -q "https://github.com/openresty/lua-nginx-module/archive/refs/tags/v${LUA_NGX_VERSION}.tar.gz" \
                        -O lua-nginx-module.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf lua-nginx-module.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    # 4) lua-resty-core + lua-resty-lrucache（纯 lua 运行时依赖，装进 LuaJIT
                    #    默认搜索路径 /usr/local/share/lua/5.1，否则 lua-nginx-module >= 0.10.16
                    #    启动时会报 "failed to load the 'resty.core' module" 直接起不来）
                    echo "===== 安装 lua-resty-core (${RESTY_CORE_VERSION}) + lua-resty-lrucache (${LRUCACHE_VERSION}) =====" >>"$TENGINE_BUILD_LOG"
                    wget -q "https://github.com/openresty/lua-resty-core/archive/refs/tags/v${RESTY_CORE_VERSION}.tar.gz" \
                        -O lua-resty-core.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf lua-resty-core.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    wget -q "https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v${LRUCACHE_VERSION}.tar.gz" \
                        -O lua-resty-lrucache.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    tar -xzf lua-resty-lrucache.tar.gz >>"$TENGINE_BUILD_LOG" 2>&1 || true
                    ( cd "lua-resty-core-${RESTY_CORE_VERSION}" \
                        && make install LUA_LIB_DIR=/usr/local/share/lua/5.1 >>"$TENGINE_BUILD_LOG" 2>&1 ) || \
                        echo "lua-resty-core 安装失败" >>"$TENGINE_BUILD_LOG"
                    ( cd "lua-resty-lrucache-${LRUCACHE_VERSION}" \
                        && make install LUA_LIB_DIR=/usr/local/share/lua/5.1 >>"$TENGINE_BUILD_LOG" 2>&1 ) || \
                        echo "lua-resty-lrucache 安装失败" >>"$TENGINE_BUILD_LOG"

                    if [ -d "tengine-${TENGINE_VERSION}" ]; then
                        cd "tengine-${TENGINE_VERSION}"

                        # 配置参数
                        CONFIGURE_OPTS=(
                            "--prefix=/usr/local/tengine"
                            "--with-http_ssl_module"
                            "--with-http_v2_module"
                            "--with-http_gzip_static_module"
                            "--with-http_stub_status_module"
                            "--with-http_realip_module"
                            "--add-module=modules/ngx_http_upstream_check_module"
                            "--add-module=modules/ngx_http_concat_module"
                            "--add-module=/tmp/headers-more-nginx-module-0.36"
                            "--add-module=/tmp/ngx_cache_purge-2.3"
                            "--with-http_gunzip_module"
                            "--with-pcre"
                            "--with-stream"
                            "--with-stream_ssl_module"
                        )

                        # ── Lua 模块（站点模板 access_by_lua_block / JA4H 指纹检测依赖）──
                        # Tengine 3.1.0 不内置 lua，需 OpenResty LuaJIT2 fork + ngx_devel_kit
                        # + lua-nginx-module 三件套，版本严格配对（官方 tengine-ingress build.sh）。
                        # 上面已下载解压到 /tmp/luajit2-* /tmp/ngx_devel_kit-* /tmp/lua-nginx-module-*
                        # 并把 LuaJIT 装到 /usr/local。此处校验是否就绪：全就绪才启用，否则跳过，
                        # 保证 lua 编译失败时配置里不出现 access_by_lua_block、443 仍能监听。
                        if [ -f /usr/local/lib/libluajit-5.1.so ] \
                            && [ -d /tmp/ngx_devel_kit-${NDK_VERSION} ] \
                            && [ -d /tmp/lua-nginx-module-${LUA_NGX_VERSION} ]; then
                            export LUAJIT_LIB=/usr/local/lib
                            export LUAJIT_INC=/usr/local/include/luajit-2.1
                            # NDK 必须排在 lua-nginx-module 之前
                            CONFIGURE_OPTS+=("--add-module=/tmp/ngx_devel_kit-${NDK_VERSION}")
                            CONFIGURE_OPTS+=("--add-module=/tmp/lua-nginx-module-${LUA_NGX_VERSION}")
                            LUA_ENABLED=1
                            echo "Lua 三件套就绪，启用 access_by_lua（JA4H 指纹检测可用）" >>"$TENGINE_BUILD_LOG"
                        else
                            LUA_ENABLED=0
                            echo "警告：Lua 依赖未就绪，跳过 lua 模块；JA4H 指纹检测将退化为 IP+速率" >>"$TENGINE_BUILD_LOG"
                        fi

                        echo "===== configure =====" >>"$TENGINE_BUILD_LOG"
                        ./configure "${CONFIGURE_OPTS[@]}" >>"$TENGINE_BUILD_LOG" 2>&1 && \
                        echo "===== make =====" >>"$TENGINE_BUILD_LOG" && \
                        # 低内存环境优化：根据可用内存调整并行编译任务数
                        # 每个编译任务约需 200-300MB 内存，2GB 内存建议单线程编译
                        TOTAL_MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)
                        if [ "$TOTAL_MEM_MB" -lt 3072 ]; then
                            info "检测到可用内存 ${TOTAL_MEM_MB}MB，使用单线程编译（避免内存不足）"
                            MAKE_JOBS=1
                        else
                            MAKE_JOBS=$(nproc)
                        fi
                        make -j"$MAKE_JOBS" >>"$TENGINE_BUILD_LOG" 2>&1 && \
                        echo "===== make install =====" >>"$TENGINE_BUILD_LOG" && \
                        make install >>"$TENGINE_BUILD_LOG" 2>&1 && {
                            ln -sf /usr/local/tengine/sbin/nginx /usr/local/tengine/sbin/tengine 2>/dev/null || true
                            ln -sf /usr/local/tengine/sbin/tengine /usr/local/sbin/tengine 2>/dev/null || true
                            exit 0
                        }
                    else
                        echo "解压后未找到 tengine-${TENGINE_VERSION} 目录" >>"$TENGINE_BUILD_LOG"
                    fi
                else
                    echo "下载的文件不是 gzip 格式，可能下载失败" >>"$TENGINE_BUILD_LOG"
                fi
            else
                echo "下载 Tengine 源码失败：${TENGINE_URL}" >>"$TENGINE_BUILD_LOG"
            fi
            exit 1
        ) && step_success "Tengine 安装完成" || step_fail "Tengine 安装失败（可选，详细日志见 $TENGINE_BUILD_LOG）"
    else
        step_success "Tengine 已存在且含 lua-nginx-module，跳过编译"
    fi
else
    step_start "跳过 Tengine 安装（已指定 SKIP_TENGINE=1）"
    info "注意：主控节点未安装 Tengine"
    info "  - 域名配置文件仍会在本地生成（用于推送到边缘节点）"
    info "  - 边缘节点部署时会自动安装 Tengine"
    info "  - 如需在主控节点使用 Tengine，请运行：sudo ./install_tengine.sh"
    step_success "跳过 Tengine"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 8. 停用其他 Web 服务
# ═══════════════════════════════════════════════════════════════════════════
step_start "停用其他 Web 服务"
for svc in nginx openresty apache2; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    fi
done
step_success "Web 服务处理完成"

# ═══════════════════════════════════════════════════════════════════════════
# 9. Tengine 配置和最小化配置（无论 Tengine 是否存在都创建配置）
# ═══════════════════════════════════════════════════════════════════════════
step_start "部署 Tengine 配置"

# 总是创建最小化 Tengine 配置，确保 cdnpanel 能运行。
# 配置本体是密封资源，脚本里不留明文（开源副本同样只带密文）。第 3 步已装 Go、
# 第 8 步已编译过应用，这里的 go run 复用同一份已热的模块缓存，不需要再联网。
(
    cd "$SCRIPT_DIR"
    go run ./cmd/sealresource -d \
        -in configs/tengine_install.conf.enc \
        -out /etc/tengine/tengine.conf
) || error "解出 Tengine 主配置失败 —— /etc/tengine/tengine.conf 没写成，default_server 与 edge_cache zone 都会缺，443 起不来。
   手动复现：cd $SCRIPT_DIR && go run ./cmd/sealresource -d -in configs/tengine_install.conf.enc -out /etc/tengine/tengine.conf"

# 预创建缓存目录并授权
mkdir -p /var/cache/tengine/edge
chown -R www-data:www-data /var/cache/tengine 2>/dev/null || true

# 为 default_server 生成自签证书（IP 直连 / 未知 SNI 兜底用）
# 用 ECDSA P-256 而非 RSA 2048：扫 IP 的握手洪水全落在这个 default_server 上，
# RSA 签名的 CPU 开销是 ECDSA 的数倍，2 核机器很快被握手打满。与 internal/deploy/ssh.go 一致。
mkdir -p /etc/ssl/cdnpanel/default
if [ ! -f /etc/ssl/cdnpanel/default/cert.pem ]; then
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /etc/ssl/cdnpanel/default/key.pem \
        -out /etc/ssl/cdnpanel/default/cert.pem \
        -days 3650 -subj "/CN=default" >/dev/null 2>&1
    chmod 600 /etc/ssl/cdnpanel/default/key.pem
    chmod 644 /etc/ssl/cdnpanel/default/cert.pem
fi

# 预生成 SSL 会话票据密钥：站点模板无条件引用 /etc/ssl/cdnpanel/ticket.key，
# 而它平时只在主控推送轮换时才写入。首次安装若缺此文件，ssl_session_ticket_key
# 会让 tengine -t 报 open() failed、443 无法监听。这里先生成一份 48 字节随机密钥兜底，
# 主控之后的轮换推送会覆盖它。
if [ ! -f /etc/ssl/cdnpanel/ticket.key ]; then
    openssl rand 48 > /etc/ssl/cdnpanel/ticket.key 2>/dev/null
    chmod 600 /etc/ssl/cdnpanel/ticket.key
fi

chmod 644 /etc/tengine/tengine.conf

# 上面 heredoc 生成的 /etc/tengine/tengine.conf 已是完整正确的配置
# （含全局 default_server、自签兜底证书、edge_cache 缓存 zone），
# 不要再用仓库里陈旧的 tengine.conf 覆盖它——那份缺 default_server 和
# edge_cache zone，会导致每个站点的 proxy_cache edge_cache 校验失败、443 无法监听。
if [ -f /usr/local/tengine/sbin/tengine ]; then
    # 仅复制 mime.types，配置本体保持 heredoc 生成的版本
    cp /usr/local/tengine/conf/mime.types /etc/tengine/mime.types 2>/dev/null || true
    info "Tengine 已检测到"
else
    warn "Tengine 未安装，使用最小配置（cdnpanel 仍能正常运行）"
fi

# 移除 brotli 指令（如果存在）
if grep -qi "brotli" /etc/tengine/tengine.conf; then
    sed -i '/brotli/d' /etc/tengine/tengine.conf
fi

step_success "Tengine 配置完成"

# ═══════════════════════════════════════════════════════════════════════════
# 创建示例站点配置文件（包含所有 P1 安全修复）
# ═══════════════════════════════════════════════════════════════════════════
# 注意：此文件仅供参考，实际站点配置由 cdnpanel 运行时动态生成。
# 本体同样是密封资源，脚本里不留明文。它是参考件而非运行必需件，解不出来记失败但继续装。
(
    cd "$SCRIPT_DIR"
    go run ./cmd/sealresource -d \
        -in configs/example_site.conf.enc \
        -out /etc/tengine/sites-available/example.conf.sample
) || {
    step_fail "示例站点配置解出失败"
    warn "手动复现：cd $SCRIPT_DIR && go run ./cmd/sealresource -d -in configs/example_site.conf.enc -out /etc/tengine/sites-available/example.conf.sample"
}

if [ -f /etc/tengine/sites-available/example.conf.sample ]; then
    chmod 644 /etc/tengine/sites-available/example.conf.sample
    info "示例站点配置已创建: /etc/tengine/sites-available/example.conf.sample"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 10. 系统硬化
# ═══════════════════════════════════════════════════════════════════════════
step_start "配置网络防护"
cat > /etc/sysctl.d/99-cdn-hardening.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
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
# rp_filter=2（宽松）：严格模式在多网卡/策略路由的云主机上会丢掉从另一张网卡回来的回源包 → 全站 504。
# 与 internal/deploy/ssh.go 的 sysctlHardening 保持一致。
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# conntrack 表容量：默认约 26w，被 SYN 洪水灌满后内核会 DROP 所有新连接（含正常用户）。抬到百万级 + 桶数同步扩，压制单波洪水打死 conntrack 的场景。
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576
# 半开 SYN 在 conntrack 里只留 60 秒（发行版默认 120）：连接表占用 = 放行速率 × 存活时长，
# 压一半时长等于把 XDP 的新连接预算翻倍。60 秒仍覆盖真人 SYN 重传的完整退避序列
# （1/2/4/8/16/32 秒，第 6 次重传在第 63 秒）——再短就会把弱网真人挤出去。
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 60
EOF
# nf_conntrack_buckets 是模块参数，不走 sysctl，走 modprobe.d
mkdir -p /etc/modprobe.d 2>/dev/null
cat > /etc/modprobe.d/nf_conntrack.conf << 'EOF'
options nf_conntrack hashsize=262144
EOF
# 立即生效（模块已加载时改 /sys；未加载时下次 modprobe 生效）
[ -w /sys/module/nf_conntrack/parameters/hashsize ] && echo 262144 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-cdn-hardening.conf >/dev/null 2>&1

if command -v iptables &>/dev/null; then
    # 清掉旧的全局 -m limit 规则（老版本安装留下的，会因为全局令牌桶被打空而把所有正常 SYN 也 DROP 掉，等于自我 DoS）
    iptables -D INPUT -p tcp --syn -m limit --limit 60/s --limit-burst 100 -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --syn -j DROP 2>/dev/null || true
    # 也清一遍新规则，防止 reinstall 时叠加（旧的不限端口的两条同样要清掉，它们会把 SSH 算进去）
    iptables -D INPUT -p tcp --syn -m connlimit --connlimit-above 60 --connlimit-mask 32 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_perip --hashlimit-above 30/sec --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-htable-expire 60000 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --syn -m connlimit --connlimit-above 4096 --connlimit-mask 32 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_perip --hashlimit-above 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-htable-expire 60000 -j DROP 2>/dev/null || true

    # ══ 主机层每 IP SYN 闸门：只在 XDP 没生效时才起作用 ══
    # 阈值刻意比 internal/xdp/defaults.go 宽一倍，让 L4 永远是先撞到的那道门：XDP 在驱动层
    # 就把超量 SYN 丢了，netfilter 根本看不到这些包；只有 cdn_xdp.o 没装、编译失败或
    # 面板上 armed=false 的节点，才轮到主机层兜底。
    # 反过来，如果这里比 XDP 严（以前是 30/s、并发 60），面板显示的 syn_limit=100 就是假的：
    # 真人撞线的是内核，XDP 从头到尾没判过。并发 60 尤其致命——一个公司/CGNAT 出口后面
    # 几十个真人，keepalive 期间的并发早就过 60，表现是「一部分用户间歇性打不开」，
    # 而 L4 面板上一切正常，最难定位的就是它。
    #
    #   并发 4096 = Tengine 单个 worker 的 worker_connections：一个源 IP 独占的量
    #     不允许超过「一台机器一档能扛的量」，再高就是连接耗尽型攻击，与速率无关。
    #   速率 200/s、burst 400 = DefaultSYNLimit(100) 的 2 倍。
    #
    # 只管 80/443：connlimit 数的是该源 IP 的**全部**连接、不分端口，不加限定就会把 SSH
    # 和 agent 端口一起算进去，管理员可能被锁在门外（XDP 那道门至少还能靠 port_guard 白名单
    # 放行 LISTEN 端口，iptables 这道是硬丢）。
    iptables -A INPUT -p tcp --syn -m multiport --dports 80,443 -m connlimit --connlimit-above 4096 --connlimit-mask 32 -j DROP 2>/dev/null
    iptables -A INPUT -p tcp --syn -m multiport --dports 80,443 -m hashlimit --hashlimit-name syn_perip --hashlimit-above 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-htable-expire 60000 -j DROP 2>/dev/null

    # ══ 主机层 UDP 全禁（第三重保障）══
    # 上游安全组和上游防火墙已经禁止入站 UDP；这里在主机 iptables 再加一道，
    # 万一上游放行了（安全组误改 / 供应商变更 / 从内网测试环境接入等）也不会漏。
    # 出站 UDP 保留：DNS 解析、NTP、edge→panel/upstream 里若有 UDP 流量都不受影响。
    # 例外 1：lo 回环放行，本机进程之间 UDP 通信（比如 systemd-resolved）不能挡。
    # 例外 2：conntrack 已建立/相关的 UDP 响应放行——虽然入站 UDP 全禁，但如果本机
    # 主动发出 UDP（DNS 请求）需要接收响应，靠 state ESTABLISHED,RELATED 放通。
    iptables -D INPUT -i lo -p udp -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p udp -j DROP 2>/dev/null || true
    iptables -A INPUT -i lo -p udp -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -A INPUT -p udp -j DROP 2>/dev/null

    mkdir -p /etc/iptables 2>/dev/null
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# ip6tables 也顺手同步一份（有些云上 IPv6 默认放行 UDP，别留后门）
if command -v ip6tables &>/dev/null; then
    ip6tables -D INPUT -i lo -p udp -j ACCEPT 2>/dev/null || true
    ip6tables -D INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    ip6tables -D INPUT -p udp -j DROP 2>/dev/null || true
    ip6tables -A INPUT -i lo -p udp -j ACCEPT 2>/dev/null
    ip6tables -A INPUT -p udp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    ip6tables -A INPUT -p udp -j DROP 2>/dev/null
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
fi
step_success "网络防护配置完成"

# ═══════════════════════════════════════════════════════════════════════════
# 11. systemd 服务
# ═══════════════════════════════════════════════════════════════════════════
step_start "创建 systemd 服务"

if [ "$MODE" = "edge" ]; then
    if [ -z "$EDGE_TOKEN" ]; then
        EDGE_TOKEN=$(openssl rand -hex 32)
    fi
    printf '%s\n' "$EDGE_TOKEN" > /etc/cdnpanel/edge.token
    chmod 600 /etc/cdnpanel/edge.token

    EXEC="/usr/local/bin/cdnedge --listen 0.0.0.0:${EDGE_PORT} --token-file /etc/cdnpanel/edge.token --config /etc/cdnpanel/config.json"
    [ -n "$XDP_IFACE" ] && [ -f /usr/local/bin/cdn_xdp.o ] && EXEC="${EXEC} --xdp-iface ${XDP_IFACE} --xdp-obj /usr/local/bin/cdn_xdp.o"
    # 注意 flag 名是 --master（以前这里写成 --master-url，cdnedge 不认识会直接退出，服务起不来）
    if [ -n "$MASTER_URL" ]; then
        EXEC="${EXEC} --master ${MASTER_URL}"
        if [ -n "$REGISTER_SECRET" ]; then
            printf '%s\n' "$REGISTER_SECRET" > /etc/cdnpanel/edge_register.secret
            chmod 600 /etc/cdnpanel/edge_register.secret
        elif [ ! -s /etc/cdnpanel/edge_register.secret ]; then
            warn "未提供 REGISTER_SECRET，自动注册会被主控拒绝；请把主控 /etc/cdnpanel/edge_register.secret 复制到本机同路径后重启 cdnedge"
        fi
        if [ -n "$CLUSTER_ID" ]; then
            # 值会拼进 systemd ExecStart，只允许 ID 字符，防止注入额外参数
            case "$CLUSTER_ID" in
                *[!A-Za-z0-9-]*) error "CLUSTER_ID 含非法字符: $CLUSTER_ID" ;;
            esac
            EXEC="${EXEC} --cluster ${CLUSTER_ID}"
        fi
    fi

    cat > /etc/systemd/system/cdnedge.service << EOSVC
[Unit]
Description=CDN Edge Agent Service
After=network.target
# cdnedge 停着的每一秒 CC/WAF 都不在线（Tengine 对 502 放行）：永不放弃重启。
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=${EXEC}
Restart=always
RestartSec=2s
LimitNOFILE=65536
# 内存闸门只兜「泄漏」，不兜「设计容量」——容量由 internal/waf 各表的硬上限决定，
# 单节点最坏占用一本账（按每个条目的 map 键 + 结构体 + map 开销约 300B 估）：
#   CC 按 IP 追踪器 50 万        ≈ 150MB
#   CC 指纹追踪器 20 万          ≈  50MB
#   CC 域名追踪器 5 万           ≈  20MB
#   缓存绕过 IP 追踪器 10 万     ≈  15MB，路径条目另有全局预算 50 万 ≈ 150MB
#   WAF 封禁表 10 万             ≈   8MB
# 合计约 400MB，Go 堆再留约 2 倍 GC 余量 → RSS 天花板约 800MB。
# 所以 MemoryHigh=1G 只是「比设计值更晚的回收压力」，MemoryMax=2G 只在真失控时才杀。
# 不能压得更小：cdnedge 被 OOM 杀掉的那几十秒里 Tengine 对 WAF 子请求的 502 是放行的，
# 等于 CC/WAF 全体下线——拿「防护消失」换内存是亏的。小内存节点该按容量挑机器，
# 不是靠调小这里。两条安装路径的数值必须一致（见 internal/deploy 的比对测试）。
MemoryHigh=1G
MemoryMax=2G

[Install]
WantedBy=multi-user.target
EOSVC
else
    EXEC="/usr/local/bin/cdnpanel --config /etc/cdnpanel/config.json"
    [ -n "$XDP_IFACE" ] && [ -f /usr/local/bin/cdn_xdp.o ] && EXEC="${EXEC} --xdp-iface ${XDP_IFACE} --xdp-obj /usr/local/bin/cdn_xdp.o"

    cat > /etc/systemd/system/cdnpanel.service << EOSVC
[Unit]
Description=CDN Panel Management Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=${EXEC}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOSVC
fi

systemctl daemon-reload
systemctl enable cdnpanel cdnedge 2>/dev/null || true
step_success "systemd 服务创建完成"

# ═══════════════════════════════════════════════════════════════════════════
# 12. 启动服务
# ═══════════════════════════════════════════════════════════════════════════
step_start "启动服务"
if [ "$MODE" = "master" ]; then
    systemctl start cdnpanel 2>/dev/null
    sleep 2
    if systemctl is-active --quiet cdnpanel 2>/dev/null; then
        step_success "cdnpanel 启动成功"
    else
        step_fail "cdnpanel 启动失败"
    fi
else
    systemctl start cdnedge 2>/dev/null
    sleep 2
    if systemctl is-active --quiet cdnedge 2>/dev/null; then
        step_success "cdnedge 启动成功"
    else
        step_fail "cdnedge 启动失败"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 13. Tengine 启动（可选，失败时继续）
# ═══════════════════════════════════════════════════════════════════════════
if [ -f /usr/local/tengine/sbin/tengine ]; then
    step_start "写入 tengine.service"
    cat > /etc/systemd/system/tengine.service << 'EOFTS'
[Unit]
Description=Tengine HTTP and reverse proxy server
After=network.target

[Service]
Type=forking
PIDFile=/var/run/tengine.pid
ExecStartPre=/usr/local/tengine/sbin/tengine -t -c /etc/tengine/tengine.conf
ExecStart=/usr/local/tengine/sbin/tengine -c /etc/tengine/tengine.conf
ExecReload=/usr/local/tengine/sbin/tengine -c /etc/tengine/tengine.conf -s reload
ExecStop=/usr/local/tengine/sbin/tengine -c /etc/tengine/tengine.conf -s stop
# worker_connections 4096 需要每个 worker 至少 4096 个 fd，默认 ulimit 1024 会触发
# "worker_connections exceed open file resource limit: 1024" 警告并被截断到 1024。
LimitNOFILE=65536
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOFTS
    systemctl daemon-reload
    step_success "tengine.service 已写入"

    step_start "启动 Tengine"
    # 先停可能已存在的老实例（无论怎么启动的）
    if [ -f /var/run/tengine.pid ] && kill -0 "$(cat /var/run/tengine.pid)" 2>/dev/null; then
        /usr/local/tengine/sbin/tengine -c /etc/tengine/tengine.conf -s stop 2>/dev/null || true
        sleep 1
    fi
    pkill -f "/usr/local/tengine/sbin/tengine" 2>/dev/null || true
    sleep 1

    if /usr/local/tengine/sbin/tengine -t -c /etc/tengine/tengine.conf >/dev/null 2>&1; then
        systemctl enable tengine >/dev/null 2>&1 || true
        if systemctl start tengine 2>/dev/null; then
            sleep 1
            if systemctl is-active --quiet tengine 2>/dev/null; then
                step_success "Tengine 启动成功"
            else
                step_fail "Tengine 启动失败（非致命，cdnpanel 仍能运行）"
            fi
        else
            step_fail "Tengine 启动失败（非致命，cdnpanel 仍能运行）"
        fi
    else
        step_fail "Tengine 配置验证失败（非致命，cdnpanel 仍能运行）"
    fi
else
    info "跳过 Tengine 启动（未安装），cdnpanel 仍能正常运行"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 完成报告
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
if [ "$MODE" = "master" ]; then
    echo -e "${GREEN}║ CDN主控安装完成 - 程序开源方：@AnJintalk_bot ║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║ 面板地址：http://${HOST_IP}:${PANEL_PORT}/console/${NC}"
    echo -e "${GREEN}║ 首次访问会进入安装向导（配置 MySQL）${NC}"
    echo -e "${GREEN}║ 管理账号：admin${NC}"
    echo -e "${GREEN}║ 初始密码：${ADMIN_PASS}${NC}"
    echo -e "${GREEN}║ 配置文件：/etc/cdnpanel/config.json${NC}"
    echo -e "${GREEN}║ 服务日志：journalctl -u cdnpanel -f${NC}"
else
    echo -e "${GREEN}║ 程序针对GFW/省墙/三网屏蔽做深度优化,必要时可联系：@AnJintalk_bot ║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║ Agent 地址：https://${HOST_IP}:${EDGE_PORT}${NC}"
    echo -e "${GREEN}║ Token 文件：/etc/cdnpanel/edge.token${NC}"
fi

# XDP 状态如实汇报。以前这里只判断 .o 是否存在就打印"已启用"，编译失败时既不提示、
# 也和末尾的失败清单对不上，用户会以为 XDP 在工作。
if [ -f /usr/local/bin/cdn_xdp.o ]; then
    echo -e "${GREEN}║ XDP 防护：已编译（${XDP_IFACE}）${NC}"
else
    echo -e "${YELLOW}║ XDP 防护：未启用（编译失败，见 ${XDP_LOG}）${NC}"
fi

# 控制面端口限源：这一版脚本不替用户写防火墙规则，只把要求说清楚。
# 原因是限源必须填"主控的 IP"，猜错一次就把这台节点锁成主控够不着的僵尸（它既不能
# 自我修复，也收不到任何后续配置），而云安全组在主机上根本看不见、无法探测。
# 宁可让运维自己执行一条明确的命令，也不要在安装脚本里埋一条能把节点打死的规则。
if [ "$MODE" = "edge" ]; then
    echo -e "${YELLOW}║${NC}"
    echo -e "${YELLOW}║ 必须手工完成：把 ${EDGE_PORT} 限源到主控 IP（这是主控下发 CC/XDP 阈值、封禁名单${NC}"
    echo -e "${YELLOW}║ 和域名私钥的唯一通道，只有 TLS+token 两层保护，裸放等于把整台节点交给中间人）：${NC}"
    echo -e "${YELLOW}║   ufw allow from <主控IP> to any port ${EDGE_PORT} proto tcp${NC}"
    echo -e "${YELLOW}║   ufw deny  ${EDGE_PORT}/tcp        # 云主机改在安全组里配，授权对象不要写 0.0.0.0/0${NC}"
    echo -e "${YELLOW}║ 验证：在别的机器上执行 curl -m 5 https://<本机IP>:${EDGE_PORT}/edge/status${NC}"
    echo -e "${YELLOW}║   期望连接超时/被拒绝；拿到 401 说明端口仍对外可达，只是被 token 挡住${NC}"
fi

if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}║${NC}"
    echo -e "${YELLOW}║ 以下步骤失败（非致命）：${NC}"
    for step in "${FAILED_STEPS[@]}"; do
        echo -e "${YELLOW}║   - ${step}${NC}"
    done
fi

echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""

# Swap 保留建议
if [ "$TOTAL_MEM_MB" -lt 3072 ] && [ "$SWAP_MB" -ge 2048 ]; then
    info "低内存环境建议："
    echo "  - 建议保留 Swap 空间以确保系统稳定运行"
    echo "  - 如需删除 Swap："
    echo "      sudo swapoff /swapfile"
    echo "      sudo rm /swapfile"
    echo "      # 并从 /etc/fstab 中删除 swap 行"
    echo ""
fi

# 验证关键步骤是否成功
[ -f /usr/local/bin/cdnpanel ] && [ -f /etc/cdnpanel/config.json ] && [ -f /etc/systemd/system/cdnpanel.service ] && \
    info "✓ 安装完成，可以访问面板了 - 程序开源方：@AnJintalk_bot" || \
    error "关键步骤失败，无法继续"
