#!/bin/bash

# CDN Panel + Edge 升级脚本
# 用于更新已安装的 CDN 系统（主控和边缘节点）

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[ "$(id -u)" -ne 0 ] && error "请用 root 或 sudo 运行此脚本"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/go.mod" ] || error "go.mod not found in $SCRIPT_DIR"

# 检测当前安装的模式
MODE=""
if systemctl is-enabled cdnpanel >/dev/null 2>&1; then
    MODE="master"
    info "检测到主控节点"
elif systemctl is-enabled cdnedge >/dev/null 2>&1; then
    MODE="edge"
    info "检测到边缘节点"
else
    error "未检测到已安装的 CDN 系统"
fi

# 检测 XDP 配置
XDP_ENABLED=0
if [ "$MODE" = "edge" ]; then
    if systemctl cat cdnedge 2>/dev/null | grep -q "xdp-iface"; then
        XDP_ENABLED=1
        info "检测到 XDP 已启用"
    fi
fi

cd "$SCRIPT_DIR" || error "无法进入源码目录"

# ═══════════════════════════════════════════════════════════════════════════
# 1. 备份当前版本
# ═══════════════════════════════════════════════════════════════════════════
info "备份当前版本..."
BACKUP_DIR="/tmp/cdn_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ "$MODE" = "master" ]; then
    [ -f /usr/local/bin/cdnpanel ] && cp /usr/local/bin/cdnpanel "$BACKUP_DIR/"
    [ -f /etc/cdnpanel/config.json ] && cp /etc/cdnpanel/config.json "$BACKUP_DIR/"
    info "备份保存至: $BACKUP_DIR"
else
    [ -f /usr/local/bin/cdnedge ] && cp /usr/local/bin/cdnedge "$BACKUP_DIR/"
    [ -f /usr/local/bin/cdn_xdp.o ] && cp /usr/local/bin/cdn_xdp.o "$BACKUP_DIR/"
    [ -f /etc/cdnpanel/edge.token ] && cp /etc/cdnpanel/edge.token "$BACKUP_DIR/"
    [ -f /etc/cdnpanel/config.json ] && cp /etc/cdnpanel/config.json "$BACKUP_DIR/"
    info "备份保存至: $BACKUP_DIR"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 2. 编译新版本
# ═══════════════════════════════════════════════════════════════════════════
info "编译新版本..."

if [ "$MODE" = "master" ]; then
    info "编译主控程序..."
    if ! go build -o cdnpanel ./cmd/cdnpanel; then
        error "cdnpanel 编译失败"
    fi
    step_success "cdnpanel 编译成功"

    info "编译边缘节点程序（用于推送到边缘节点）..."
    if ! go build -o cdnedge ./cmd/cdnedge; then
        warn "cdnedge 编译失败（非致命错误）"
    else
        step_success "cdnedge 编译成功"
    fi
else
    info "编译边缘节点程序..."
    if ! go build -o cdnedge ./cmd/cdnedge; then
        error "cdnedge 编译失败"
    fi
    step_success "cdnedge 编译成功"
fi

# 编译 XDP 程序（如果需要）
if [ "$MODE" = "edge" ] && [ "$XDP_ENABLED" = "1" ]; then
    info "编译优化后的 XDP 程序..."

    # 检查 clang 是否安装
    if ! command -v clang >/dev/null 2>&1; then
        warn "clang 未安装，尝试安装..."
        apt-get update -qq
        apt-get install -y clang libbpf-dev linux-headers-$(uname -r) || warn "clang 安装失败，跳过 XDP 编译"
    fi

    if command -v clang >/dev/null 2>&1; then
        if clang -O2 -target bpf -c internal/xdp/cdn_xdp.c -o cdn_xdp.o 2>/dev/null; then
            step_success "XDP 程序编译成功（已优化）"
        else
            warn "XDP 编译失败，将使用旧版本"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. 停止服务
# ═══════════════════════════════════════════════════════════════════════════
info "停止服务..."

if [ "$MODE" = "master" ]; then
    systemctl stop cdnpanel || warn "停止 cdnpanel 失败"
else
    systemctl stop cdnedge || warn "停止 cdnedge 失败"

    # 卸载 XDP（如果启用）
    if [ "$XDP_ENABLED" = "1" ]; then
        info "卸载旧的 XDP 程序..."
        XDP_IFACE=$(systemctl cat cdnedge 2>/dev/null | grep -oP '(?<=--xdp-iface )[^ ]+' || echo "eth0")
        ip link set dev "$XDP_IFACE" xdp off 2>/dev/null || warn "卸载 XDP 失败"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4. 替换二进制文件
# ═══════════════════════════════════════════════════════════════════════════
info "更新程序文件..."

if [ "$MODE" = "master" ]; then
    cp cdnpanel /usr/local/bin/cdnpanel
    chmod +x /usr/local/bin/cdnpanel
    step_success "cdnpanel 已更新"

    # 如果编译了 cdnedge，也保存一份用于后续推送
    if [ -f cdnedge ]; then
        cp cdnedge /tmp/cdnedge_latest
        info "cdnedge 已保存至 /tmp/cdnedge_latest（可用于推送到边缘节点）"
    fi
else
    cp cdnedge /usr/local/bin/cdnedge
    chmod +x /usr/local/bin/cdnedge
    step_success "cdnedge 已更新"

    # 更新 XDP 程序（如果存在）
    if [ -f cdn_xdp.o ]; then
        cp cdn_xdp.o /usr/local/bin/cdn_xdp.o
        step_success "XDP 程序已更新"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. 启动服务
# ═══════════════════════════════════════════════════════════════════════════
info "启动服务..."

systemctl daemon-reload

if [ "$MODE" = "master" ]; then
    if ! systemctl start cdnpanel; then
        error "cdnpanel 启动失败，请检查日志: journalctl -u cdnpanel -n 50"
    fi

    sleep 2

    if systemctl is-active cdnpanel >/dev/null 2>&1; then
        step_success "cdnpanel 已启动"
    else
        error "cdnpanel 启动失败"
    fi
else
    if ! systemctl start cdnedge; then
        error "cdnedge 启动失败，请检查日志: journalctl -u cdnedge -n 50"
    fi

    sleep 2

    if systemctl is-active cdnedge >/dev/null 2>&1; then
        step_success "cdnedge 已启动"
    else
        error "cdnedge 启动失败"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 6. 验证服务状态
# ═══════════════════════════════════════════════════════════════════════════
info "验证服务状态..."

sleep 3

if [ "$MODE" = "master" ]; then
    systemctl status cdnpanel --no-pager -l | head -15
else
    systemctl status cdnedge --no-pager -l | head -15

    # 检查 CPU 占用
    sleep 2
    CPU_USAGE=$(top -bn1 | grep cdnedge | awk '{print $9}' | head -1)
    if [ -n "$CPU_USAGE" ]; then
        info "当前 CPU 占用: ${CPU_USAGE}%"

        CPU_INT=$(echo "$CPU_USAGE" | cut -d. -f1)
        if [ "$CPU_INT" -gt 50 ]; then
            warn "CPU 占用较高，如果持续高占用请检查日志"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 完成
# ═══════════════════════════════════════════════════════════════════════════
echo ""
info "================================================================"
info "升级完成！"
info "================================================================"

if [ "$MODE" = "master" ]; then
    echo ""
    info "主控节点更新内容："
    info "  1. 修复访问日志解析导致的 CPU 爆满（限制最多读取 50000 行）"
    info "  2. 新增节点时自动同步所有域名配置"
    info "  3. 优化域名删除和同步逻辑"
    echo ""
    info "下一步："
    info "  - 访问控制面板检查功能是否正常"
    info "  - 更新边缘节点: 将此脚本复制到边缘节点并执行"

    if [ -f /tmp/cdnedge_latest ]; then
        echo ""
        info "边缘节点更新方法："
        echo "  scp /tmp/cdnedge_latest root@边缘节点IP:/tmp/"
        echo "  scp $SCRIPT_DIR/cdn_xdp.o root@边缘节点IP:/tmp/"
        echo "  ssh root@边缘节点IP"
        echo "  cd /www/wwwroot/cdn && bash update.sh"
    fi
else
    echo ""
    info "边缘节点更新内容："
    info "  1. 修复 XDP 程序被攻击后 CPU 爆满（优化速率检查逻辑）"
    info "  2. 修复域名同步和删除问题"
    echo ""
    info "下一步："
    info "  - 监控 CPU 占用: top -bn1 | grep cdnedge"
    info "  - 查看日志: journalctl -u cdnedge -f"
    info "  - 在主控面板点击"同步站点"确保配置一致"
fi

echo ""
info "备份位置: $BACKUP_DIR"
info "如遇问题，可用备份恢复: cp $BACKUP_DIR/* /usr/local/bin/"
echo ""
