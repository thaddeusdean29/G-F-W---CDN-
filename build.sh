#!/bin/bash

# 独立打包脚本：把 cdnpanel / cdnedge 编译为 Linux 二进制，输出到 2jz 目录
# 目录结构与 cmd/ 子目录一一对应：
#   cmd/cdnpanel -> 2jz/cmd/cdnpanel/cdnpanel
#   cmd/cdnedge  -> 2jz/cmd/cdnedge/cdnedge
# 与 install.sh 不同：install.sh 是客户机上跑的安装脚本，本脚本是构建机上用的
# 打包脚本，只负责产出二进制，不做任何安装/部署动作。

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/2jz"

# 构建标识：面板判断「节点上的边缘是不是最新版」的唯一依据，两个二进制必须在同一次构建里
# 拿到同一个值，否则出包自带版本不一致。格式被 internal/apiv2 里的正则写死了
# （cdn-[0-9]{8}-[0-9]{4}），改格式要一起改。
BUILD_ID="cdn-$(date +%Y%m%d-%H%M)"

[ -f "$SCRIPT_DIR/go.mod" ] || error "go.mod not found in $SCRIPT_DIR"

command -v go &>/dev/null || error "未找到 go，请先安装 Go >= 1.21"
CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
GO_MAJOR=$(echo "$CURRENT_GO" | cut -d. -f1)
GO_MINOR=$(echo "$CURRENT_GO" | cut -d. -f2)
if ! { [ "$GO_MAJOR" -gt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -ge 21 ]; }; }; then
    error "Go 版本过低（${CURRENT_GO}），需要 >= 1.21"
fi
info "Go ${CURRENT_GO} ✓"

cd "$SCRIPT_DIR"

# XDP 源码不再往 edgeapi 同步副本：internal/edgeapi/xdp_embed.go 直接引用
# internal/xdp 里 go:embed 的真源码，只有一份，面板安装与本地 go build 必然一致。

# 重新密封全部密封资源。运行时解密的是 go:embed 进去的 .enc，不是明文源文件：
# 改完明文不密封，改动静默不生效（面板推下去的仍是旧的 error_page / location / TLS
# 参数、旧皮肤、旧规则、旧首页），而构建全程零报错。模板那边历史上真踩过。
# 明文数据源只存在于构建仓库，分发出去的开源副本只有密文，所以是「有明文才密封」。
# 失败不静默兜底：宁可构建中断，也不能产出一个带着过期资源的包。
#
# 清单里每行是「明文:密文」。新增密封资源时在这里加一行，并确认对应 .go 的 go:embed
# 已指向 .enc —— 只改一边就是上面那种静默故障。
# 末两份不是 go:embed，是 install.sh 部署时用 sealresource -d 现解现写的安装期资源
# （Tengine 主配置、示例站点配置），它们原先是脚本里的明文 heredoc。
# 不在清单里的两份明文是有意保留的：internal/xdp/cdn_xdp.c 被 install.sh 的 clang、
# compile_xdp_docker.sh、diagnose_xdp.sh 直读磁盘，密封即打坏 XDP 编译；
# web/console_dist 是 vite 产物且按文件服务 SPA，前端代码本来就在浏览器里明文可下载。
SEALED_RESOURCES="
templates/site.conf.tmpl:templates/site.conf.tmpl.enc
internal/config/gateway_profiles.json:internal/config/gateway_profiles.enc
internal/waf/rules.json:internal/waf/rules.enc
internal/apiv2/site_layout.tmpl:internal/apiv2/site_layout.tmpl.enc
internal/apiv2/homepage.tmpl:internal/apiv2/homepage.tmpl.enc
internal/setup/setup.html:internal/setup/setup.html.enc
configs/tengine.conf:configs/tengine.conf.enc
migrations/0001_init.sql:migrations/0001_init.sql.enc
configs/tengine_install.conf:configs/tengine_install.conf.enc
configs/example_site.conf:configs/example_site.conf.enc
"
sealed_count=0
for pair in $SEALED_RESOURCES; do
    src="${pair%%:*}"
    dst="${pair##*:}"
    [ -f "$SCRIPT_DIR/$src" ] || continue
    if go run ./cmd/sealresource -in "$src" -out "$dst" >/dev/null 2>&1; then
        info "已重新密封 ${dst}"
        sealed_count=$((sealed_count + 1))
    else
        warn "密封 ${src} 失败——带着过期资源出包是静默故障，直接中断构建。"
        warn "手动复现：go run ./cmd/sealresource -in ${src} -out ${dst}"
        exit 1
    fi
done
if [ "$sealed_count" = 0 ]; then
    info "没有明文数据源（开源副本形态）：沿用随包密文，跳过密封"
fi

# 密封一致性门禁：rules.enc 解出来的字节必须与 rules.json 完全一致。上面刚密封过，
# 正常必然一致；这道门抓的是「密封命令报成功但写错了目标」这类静默故障。
# 工具是现成的 cmd/wafselfcheck -seal-check，此前两份脚本都没调用它。
# 必须放在 export GOOS=linux 之前：go run 要跑的是本机可执行文件。
if [ -f "$SCRIPT_DIR/internal/waf/rules.json" ]; then
    if go run ./cmd/wafselfcheck -seal-check; then
        info "✓ WAF 规则包密封一致性举证通过"
    else
        error "rules.enc 与 rules.json 不一致，不能出包。
       手动复现：go run ./cmd/wafselfcheck -seal-check"
    fi
fi

# 前端控制台。web/web.go 是 go:embed all:console_dist，整套 Vue 产物在编译期就打进
# cdnpanel，所以必须先有真产物再 go build，客户机也因此不需要 Node。
#
# 无条件重建，不做「缺了才编」：2026-11-20 实测仓库里那份 console_dist 停在 11-15，
# 而 vue/src 已改到 11-19，产物里 grep「区域封禁 / geo_policy / waf_packages」全 0 命中
# （对照串 domains 有命中，证明不是 grep 失效）。过期产物照样编过、照样出包，只是控制台
# 少两批页面，全程零报错——「缺了才编」正好会把这份过期前端一直打进包。
#
# NODE_ENV 必须显式钉 production：vite.config.ts 的 base 是
# NODE_ENV==='production' ? '/console/' : '/'，而 vite 只在调用方没设 NODE_ENV 时才自己
# 填 production。环境里带个 development 就会产出 base=/ 的包，挂到 /console/ 下资源全 404。
if [ -f "$SCRIPT_DIR/vue/package.json" ]; then
    command -v node &>/dev/null || error "未找到 node —— 前端产物是 go:embed 进 cdnpanel 的，缺产物 go build 必挂。请先装 Node >= 18（vite 6 要求 ^18 || ^20 || >=22）"
    command -v npm &>/dev/null || error "未找到 npm（随 Node 一起装）"
    info "Node $(node -v) / npm $(npm -v)"

    # vite 的 emptyOutDir 会清空 console_dist。这个工作区不是 git 仓库，没备份就不可回滚。
    # 备份目录是 console_dist 的兄弟目录，不会被 emptyOutDir 清掉。
    if [ -f "$SCRIPT_DIR/web/console_dist/index.html" ]; then
        web_bak="$SCRIPT_DIR/web/_backup-console_dist-$(date +%Y%m%d-%H%M)"
        mkdir -p "$web_bak"
        cp -a "$SCRIPT_DIR/web/console_dist/." "$web_bak/"
        info "旧前端产物已备份到 $web_bak"
    fi

    info "构建前端控制台（vue -> web/console_dist）"
    (
        cd "$SCRIPT_DIR/vue"
        # 有 lock 文件就用 ci：按 lock 精确装，产物可复现。install 会重新解析 ^ 范围，
        # 同一份源码不同时间可能编出不同的前端。
        if [ -f package-lock.json ]; then
            npm ci --no-audit --no-fund
        else
            npm install --no-audit --no-fund
        fi
        NODE_ENV=production npm run build
    ) || error "前端构建失败 —— 带着缺失/过期的 console_dist 出包是静默故障，直接中断。
       手动复现：cd vue && npm ci && NODE_ENV=production npm run build"

    # 产物举证：目录存在不算数，占位提示页也算存在。两条同时成立才算真控制台——
    # index.html 按 /console/ base 引用了 assets，且 assets 目录非空。
    if [ ! -f "$SCRIPT_DIR/web/console_dist/index.html" ] \
       || ! grep -q '/console/assets/' "$SCRIPT_DIR/web/console_dist/index.html"; then
        error "前端产物举证失败：web/console_dist/index.html 没有按 /console/ base 引用 assets。
       base 由 NODE_ENV 决定，base=/ 的产物挂到 /console/ 下会全部资源 404。"
    fi
    asset_count="$(find "$SCRIPT_DIR/web/console_dist/assets" -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
    if [ "${asset_count:-0}" = "0" ]; then
        error "前端产物举证失败：web/console_dist/assets 为空，嵌进二进制的会是个白页。"
    fi
    info "✓ 前端产物举证通过：index.html 按 /console/ base 引用，assets ${asset_count} 个文件"
else
    warn "没有 vue/package.json，跳过前端构建 —— 沿用现有 web/console_dist，可能是过期产物"
fi

# garble 默认关闭，要开就显式给 GARBLE=1。原因不是"混淆没生效"，而是混淆把程序本身打坏了：
# 2026-11-14 在 cdntest 上用 v0.12.1 `-literals -tiny` 出的包，面板首页每请求必 500，日志是
#   template: layout:7:9: executing "head" at <.PageTitle>: can't evaluate field PageTitle
#   in type bmiwf8V3.hXyVqMmqM
# ——bmiwf8V3.hXyVqMmqM 就是被改名的 homeView。我们的模板数据全部靠 struct 字段渲染
# （对客首页、文档页、以及 internal/tengine/generator.go 的站点配置），而字段名只出现在
# go:embed 的 .tmpl 文本里，garble 看不见这种用法，于是照改字段名，反射取值全线失败。
# 也就是说开 garble 的代价不是某个页面，是全站。修不好之前别默认开。
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
        # 版本与 Go 严格配对：v0.12.1 的 go.mod 写 go 1.21，v0.16/0.17 要 go1.26.2，
        # v0.18 要 go1.27。禁止回退成 @latest，也禁止静默改用普通 go build 冒充混淆产物。
        error "GARBLE=1 但拿不到 garble ${GARBLE_VERSION}。若本机 Go 已不是 1.21，把脚本里的
       GARBLE_VERSION 一起升到配对版本；不要改回 @latest。"
    fi
    BUILD_CMD="$GARBLE_BIN -literals -tiny build"
    warn "已启用 garble ${GARBLE_VERSION}：出包后必须真打开首页和一次站点配置生成，"
    warn "字段名被改名会表现为 template: ... can't evaluate field ...（历史上全站 500）"
else
    info "未启用 garble（默认）：内置密钥与包路径在二进制里可 grep，代价见 verify_artifact 的输出"
fi

export GOOS=linux
export GOARCH=amd64
# CGO_ENABLED=0：仓库里 0 个文件 import "C"，但 CGO_ENABLED=1 仍会把 runtime/cgo 拉进
# 依赖图（go list -deps 实测命中），交叉编译时就得要一台有 gcc 的机器——构建机没有就
# 直接 cgo: C compiler "gcc" not found 中断。关 cgo 后纯 Go 链接，产物也不依赖任何 C 库，
# 与 dist/README 对客户的承诺一致。
export CGO_ENABLED=0

# 出包后对产物举证。Go 的类型元数据里带完整包路径，-s -w 剥不掉，只有 garble 会改名，
# 所以 "模块路径/internal/" 的命中数就是混淆是否生效的直接证据。阈值设 0 的前提是逐个
# 核过的：仓库里剩 2 个明文 go:embed 目标（internal/xdp/cdn_xdp.c，以及 console_dist 的
# index.html 与全部 assets）都不含这个串，所以混淆成功时必然为 0。其余 10 份资源已密封成
# .enc（见上面 SEALED_RESOURCES 清单，末两份只由 install.sh 现解现写、不进二进制），
# 密文是高熵字节，更不会命中。将来若某个明文 embed
# 真要带包路径，改这里并留一句理由，别把阈值调大了事。
MODULE_PATH="$(grep -m1 '^module ' "$SCRIPT_DIR/go.mod" | awk '{print $2}')"

# -X 必须是「包路径.变量名=值」，包路径拿 MODULE_PATH 拼，别硬编码 cdn/：换模块名时
# 静默注不进去，产出的两个二进制就都带着 dev，面板只会说版本未知（不会谎报最新，但白装了）。
LDFLAGS="-s -w -X ${MODULE_PATH}/internal/version.Build=${BUILD_ID}"
info "构建标识 ${BUILD_ID}"

# 这条举证只在 GARBLE=1 时有意义：默认不混淆，产物里必然带着包路径和明文密钥，
# 拿它当出包门禁等于把默认路径堵死。所以未混淆时改成把代价说清楚，不许静默。
#
# 代价的真实分量：internal/secure 里那把 AES-256 常量密钥不只保护 site.conf.tmpl.enc
# 和 rules.enc，数据库里托管的租户 TLS 私钥、Cloudflare API token、节点注册/上报
# token 也都用它加解密。未混淆的二进制装到客户自己手里的边缘节点上，等于把跨租户的
# 主密钥一起发出去了。前 8 字节从源码现取，脚本里不落密钥本身。
KEY_PREFIX_HEX="$(sed -n '/resourceKey = \[32\]byte{/,/^}/p' "$SCRIPT_DIR/internal/secure/secure.go" \
    | grep -o '0x[0-9a-fA-F]\{2\}' | sed 's/0x//' | head -8 | tr -d '\n')"

key_plaintext_hits() {
    local bin="$1" esc pat
    esc="$(printf '%s' "$KEY_PREFIX_HEX" | sed 's/../\\x&/g')"
    # 只含 [0-9a-f]，能安全当格式串让 printf 展开成原始字节；grep 用 LC_ALL=C
    # 按字节匹配，否则非 UTF-8 序列在中文/英文 locale 下会漏匹配。
    pat="$(printf "$esc")"
    LC_ALL=C grep -aoc "$pat" "$bin" 2>/dev/null | tr -d '[:space:]'
}

# 提醒：以下全是字节级举证，只能证明"产物里有什么"，证明不了"程序能跑"。
# 2026-11-14 的教训就是举证、go vet、反射脚检全绿，首页却每请求必 500。
# 无论开不开 garble，交付前都要真打开一次首页并生成一次站点配置。
verify_artifact() {
    local bin="$1" hits khits
    hits="$(grep -ao "${MODULE_PATH}/internal/" "$bin" 2>/dev/null | wc -l | tr -d '[:space:]')"
    if [ -n "$GARBLE_BIN" ]; then
        if [ "${hits:-1}" != "0" ]; then
            error "混淆举证失败：$(basename "$bin") 里仍能 grep 到 ${MODULE_PATH}/internal/ ${hits} 次。
               garble 装了却没真正跑成（版本与 Go 不配对、构建被跳过都会走到这里），不能出包。"
        fi
        info "混淆举证通过：$(basename "$bin") 里 ${MODULE_PATH}/internal/ 命中 0"
        return 0
    fi
    khits="$(key_plaintext_hits "$bin")"
    warn "未混淆产物 $(basename "$bin")：包路径命中 ${hits} 处，内置密钥明文可 grep=${khits}（1 就是一条命令能捞出来）"
    warn "  ⇒ 拿到该二进制的人可解站点模板/WAF 规则密文，以及库里的租户 TLS 私钥、Cloudflare token、节点 token"
}

# 构建号举证：判注入目标本身，且在编译之前判。别拿"产物里 grep 得到构建号"当门禁——
# 2026-11-20 实测（Go 1.21，-s -w）：包路径写对 → 运行期 version.Build 就是构建号、grep 3 次；
# 包路径写错（wrongmod）→ 运行期仍是 dev、grep 照样 2 次；不传 -X → dev、grep 0 次。
# 链接器把 -X 的「值」当字符串留在产物里，目标符号不存在也留，所以那条判据注错了也报通过。
# -s -w 剥了符号表，go tool nm 只说 no symbols；产物是 GOOS=linux，构建机上跑不了，
# 两个 main 也都没有 --version。能静态判准的只有包路径与变量声明这两件事。
# 注错的后果不是崩，是这台边缘永远报 dev：面板只说"版本未知"，节点列表看不出谁没升级。
verify_ldflags_target() {
    local ver_pkg
    ver_pkg="$(cd "$SCRIPT_DIR" && go list -f '{{.ImportPath}}' ./internal/version 2>/dev/null)"
    if [ "$ver_pkg" != "${MODULE_PATH}/internal/version" ]; then
        error "构建号注入目标对不上：go.mod 的 module 是 ${MODULE_PATH}，但 go list 报
       internal/version 的导入路径是「${ver_pkg:-取不到}」。-X 会静默注不进去，不能出包。"
    fi
    if ! grep -Eq '^[[:space:]]*var Build[[:space:]]*(=[[:space:]]*"|string([[:space:]]|$))' "$SCRIPT_DIR"/internal/version/*.go; then
        error "internal/version 里没有可被 -X 覆盖的 var Build 声明（须包级、字符串、常量初始化）。
       改名或改成函数返回值后 -X 同样静默失效，不能出包。
       只认单行 var 声明；若改成 var (...) 块，这条会拦下来，届时同步改判据。"
    fi
    info "构建号注入目标已核实：${ver_pkg}.Build"
    if [ -n "$GARBLE_BIN" ]; then
        # garble 在链接期改包名，上面查的是源码路径，查不出改名后的落点。
        warn "混淆产物无法静态判定 -X 是否落地：装完请在面板节点列表确认版本列不是"未知""
    fi
}

build_target() {
    local pkg="$1" name="$2"
    local out_dir="$OUT_DIR/cmd/${name}"
    mkdir -p "$out_dir"
    info "编译 ${name} -> ${out_dir}/${name}"
    if $BUILD_CMD -ldflags="$LDFLAGS" -o "${out_dir}/${name}" "./${pkg}"; then
        info "✓ ${name} 编译成功"
        verify_artifact "${out_dir}/${name}"
    else
        error "✗ ${name} 编译失败"
    fi
}

verify_ldflags_target
build_target "cmd/cdnpanel" "cdnpanel"
build_target "cmd/cdnedge" "cdnedge"

# 二进制分发不带 Go 源码，但 XDP eBPF 防护是非 Go 静态资源，随安装脚本在目标
# 服务器上现场编译/使用，需要每次同步到 2jz。
info "同步 XDP 源码到 ${OUT_DIR}"
mkdir -p "$OUT_DIR/internal/xdp"
cp "$SCRIPT_DIR/internal/xdp/cdn_xdp.c" "$OUT_DIR/internal/xdp/cdn_xdp.c"

# 安装脚本必须一并分发到 2jz，否则目标机器拿不到最新的安装逻辑（lua 编译、
# 强制重装、全局 default_server、ticket.key 预生成等修复都在这些脚本里）。
info "同步安装脚本到 ${OUT_DIR}"
for f in install.sh install_tengine.sh uninstall.sh reinstall.sh update.sh; do
    [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" "$OUT_DIR/$f"
done

# IP 归属地库（流量页的来源 IP 归属地列）。这是可选数据，不在 Go 源码里也不内嵌进二进制：
# 面板按 geoip.DefaultDirs 的顺序找 config.json 的 geoip_dir → 二进制同目录 → 同目录 data/ →
# /etc/cdnpanel → 相对 data/。找不到时页面会显式提示缺哪个文件，不会静默留空列。
info "同步 IP 归属地库到 ${OUT_DIR}/data"
geo_ok=0
for f in dbip-city-ipv4.mmdb dbip-city-ipv6.mmdb; do
    if [ -s "$SCRIPT_DIR/data/$f" ]; then
        mkdir -p "$OUT_DIR/data"
        cp "$SCRIPT_DIR/data/$f" "$OUT_DIR/data/$f"
        info "✓ $f（$(du -h "$OUT_DIR/data/$f" | cut -f1)）"
        geo_ok=1
    else
        warn "缺少 data/$f —— 流量页的来源 IP 归属地列会提示库未就位"
        warn "  取库：curl -L -o data/$f https://github.com/sapics/ip-location-db/releases/download/latest/$f"
        warn "  （DB-IP City Lite，CC BY 4.0，页面已按许可署名回链；详见 docs/IP-归属地库.md）"
        warn "  下完放进面板二进制的同目录、同目录 data/ 或 /etc/cdnpanel 任一处即可，不必重新编译"
    fi
done
[ "$geo_ok" = 1 ] || warn "  两个库都没就位：本次产物不含归属地数据（面板其余功能不受影响）"

# 国家级地理库（DB-IP Country Lite）：区域封禁的前缀表只从这两份库编译，节点上不查库。
# 少了它们，装完机打开区域封禁总闸就会被保存那一层拒掉，所以缺库要在出包时就喊出来，
# 而不是等客户在面板上看到一句"地理库未就位"再回来问。
country_ok=0
for f in dbip-country-ipv4.mmdb dbip-country-ipv6.mmdb; do
    if [ -s "$SCRIPT_DIR/data/$f" ]; then
        mkdir -p "$OUT_DIR/data"
        cp "$SCRIPT_DIR/data/$f" "$OUT_DIR/data/$f"
        info "✓ $f（$(du -h "$OUT_DIR/data/$f" | cut -f1)）"
        country_ok=1
    else
        warn "缺少 data/$f —— 区域封禁编译不出前缀表，总闸一开就会被保存拒掉"
        warn "  取库：curl -L -o data/$f https://github.com/sapics/ip-location-db/releases/download/latest/$f"
        warn "  （DB-IP Country Lite，CC BY 4.0，与上面的 city 库同一来源同一许可）"
        warn "  下完放进面板二进制的同目录、同目录 data/ 或 /etc/cdnpanel 任一处，重启 cdnpanel 即可"
    fi
done
[ "$country_ok" = 1 ] || warn "  国家级库未就位：本次产物的区域封禁只能报「地理库未就位」，装不上任何前缀表"
# CC BY 4.0 的许可正文随库一起交付，客户侧要核对署名义务时不用再去网上找。
if [ -s "$SCRIPT_DIR/data/DBIP-LICENSE" ]; then
    mkdir -p "$OUT_DIR/data"
    cp "$SCRIPT_DIR/data/DBIP-LICENSE" "$OUT_DIR/data/DBIP-LICENSE"
fi

# 注意：不再拷贝仓库根的 tengine.conf。那份旧配置缺全局 default_server 和
# edge_cache 缓存 zone，会导致站点的 proxy_cache edge_cache 校验失败、443 不监听。
# 正确的 tengine.conf 由 install.sh 用 heredoc 现场生成。

# dist/ 是对客的生产部署包（扁平布局：cdnpanel + cdnedge + config.json + start.sh/stop.sh + README.md，
# 见 dist/README.md）。这里只同步二进制和归属地库，绝不写 config.json / start.sh / stop.sh / README.md：
# 那几个是手维护的，config.json 里还可能已经是客户填过的真实配置，覆盖等于把线上配置冲掉。
# 旧二进制按本目录既有惯例先备份成 dist/backup-<时间戳>/，这个工作区不是 git 仓库，没有备份就不可回滚。
DIST_DIR="$SCRIPT_DIR/dist"
if [ -d "$DIST_DIR" ]; then
    if [ -f "$DIST_DIR/cdnpanel" ] || [ -f "$DIST_DIR/cdnedge" ]; then
        dist_bak="$DIST_DIR/backup-$(date +%Y%m%d-%H%M)"
        mkdir -p "$dist_bak"
        for f in cdnpanel cdnedge; do
            if [ -f "$DIST_DIR/$f" ]; then
                cp -p "$DIST_DIR/$f" "$dist_bak/$f"
            fi
        done
        info "dist/ 旧二进制已备份到 $dist_bak"
    fi
    for f in cdnpanel cdnedge; do
        cp "$OUT_DIR/cmd/$f/$f" "$DIST_DIR/$f"
        chmod +x "$DIST_DIR/$f" 2>/dev/null || true
        info "→ dist/$f（$(du -h "$DIST_DIR/$f" | cut -f1)）"
    done
    # 归属地库放 dist/data/：面板的 geoip.DefaultDirs 会找"二进制同目录/data"，
    # 所以整目录传到服务器就能用，不需要改 config.json 的 geoip_dir。
    if [ -d "$OUT_DIR/data" ]; then
        mkdir -p "$DIST_DIR/data"
        for f in dbip-city-ipv4.mmdb dbip-city-ipv6.mmdb dbip-country-ipv4.mmdb dbip-country-ipv6.mmdb DBIP-LICENSE; do
            if [ -f "$OUT_DIR/data/$f" ]; then
                cp "$OUT_DIR/data/$f" "$DIST_DIR/data/$f"
            fi
        done
        info "→ dist/data/（归属地库、区域封禁国家级库与 CC BY 许可正文）"
    fi
else
    warn "没有 $DIST_DIR 目录，跳过对客包同步（产物只在 $OUT_DIR）"
fi

info "打包完成：构建标识 ${BUILD_ID}，构建产物 ${OUT_DIR}，对客部署包 ${DIST_DIR}"
