#!/bin/bash

# CDN Panel 完整卸载并重新安装脚本
# 保留所有数据：配置、域名、节点、用户、SSL证书等

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
elif systemctl is-enabled cdnpanel-edge >/dev/null 2>&1 || systemctl is-enabled cdnedge >/dev/null 2>&1; then
    MODE="edge"
    info "检测到边缘节点"
else
    error "未检测到已安装的 CDN 系统"
fi

echo ""
warn "==================================================================="
warn "           CDN Panel 完整卸载并重新安装"
warn "==================================================================="
warn "此操作将："
warn "  1. 停止并删除所有服务"
warn "  2. 删除所有程序文件（二进制、XDP对象等）"
warn "  3. 保留所有数据（/etc/cdnpanel/ 目录）"
warn "  4. 重新编译并安装最新版本"
warn ""
warn "数据将被保留："
warn "  - 域名配置"
warn "  - 节点配置"
warn "  - 用户账号"
warn "  - SSL证书"
warn "  - 系统配置"
warn "  - Tengine配置"
warn "==================================================================="
echo ""

read -p "确认继续？[y/N]: " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    info "操作已取消"
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════
# 1. 备份数据目录
# ═══════════════════════════════════════════════════════════════════════════
info "备份数据目录..."
BACKUP_DIR="/tmp/cdnpanel_data_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -d /etc/cdnpanel ]; then
    cp -r /etc/cdnpanel "$BACKUP_DIR/"
    info "数据已备份至: $BACKUP_DIR"
fi

# 记录当前 XDP 配置
if [ "$MODE" = "edge" ]; then
    XDP_ENABLED=0
    XDP_IFACE=""

    if systemctl cat cdnedge 2>/dev/null | grep -q "xdp-iface"; then
        XDP_ENABLED=1
        XDP_IFACE=$(systemctl cat cdnedge 2>/dev/null | grep -oP '(?<=--xdp-iface )[^ ]+' || echo "eth0")
        info "记录到 XDP 配置: 接口=$XDP_IFACE"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 2. 停止所有服务
# ═══════════════════════════════════════════════════════════════════════════
info "停止所有服务..."

if [ "$MODE" = "master" ]; then
    systemctl stop cdnpanel 2>/dev/null || true
    systemctl disable cdnpanel 2>/dev/null || true
else
    systemctl stop cdnedge 2>/dev/null || true
    systemctl stop cdnpanel-edge 2>/dev/null || true
    systemctl disable cdnedge 2>/dev/null || true
    systemctl disable cdnpanel-edge 2>/dev/null || true

    # 卸载 XDP
    if [ "$XDP_ENABLED" = "1" ] && [ -n "$XDP_IFACE" ]; then
        info "卸载 XDP 程序..."
        ip link set dev "$XDP_IFACE" xdp off 2>/dev/null || true
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. 删除服务文件
# ═══════════════════════════════════════════════════════════════════════════
info "删除服务文件..."

rm -f /etc/systemd/system/cdnpanel.service
rm -f /etc/systemd/system/cdnedge.service
rm -f /etc/systemd/system/cdnpanel-edge.service
systemctl daemon-reload

# ═══════════════════════════════════════════════════════════════════════════
# 4. 删除程序文件
# ═══════════════════════════════════════════════════════════════════════════
info "删除程序文件..."

rm -f /usr/local/bin/cdnpanel
rm -f /usr/local/bin/cdnedge
rm -f /usr/local/bin/cdnpanel-edge
rm -f /usr/local/bin/cdn_xdp.o

# 保留 Tengine（如果存在）
if [ -f /usr/local/tengine/sbin/tengine ]; then
    info "保留 Tengine（如需卸载请手动删除 /usr/local/tengine）"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. 等待确认数据安全
# ═══════════════════════════════════════════════════════════════════════════
echo ""
info "卸载完成！"
info "数据目录 /etc/cdnpanel/ 已保留"
info "备份位置: $BACKUP_DIR"
echo ""
info "现在将重新安装最新版本..."
sleep 2

# ═══════════════════════════════════════════════════════════════════════════
# 6. 重新安装
# ═══════════════════════════════════════════════════════════════════════════
cd "$SCRIPT_DIR" || error "无法进入源码目录"

if [ "$MODE" = "master" ]; then
    info "以主控模式重新安装..."

    # 设置环境变量跳过初始化（保留现有数据）
    export SKIP_INIT=1
    export MODE=master

    # 运行安装脚本
    if [ -f install.sh ]; then
        bash install.sh
    else
        error "install.sh 未找到"
    fi
else
    info "以边缘节点模式重新安装..."

    # 读取保存的配置
    if [ -f /etc/cdnpanel/edge.token ]; then
        EDGE_TOKEN=$(cat /etc/cdnpanel/edge.token)
    fi

    if [ -f /etc/cdnpanel/config.json ]; then
        MASTER_URL=$(grep -oP '(?<="master_url": ")[^"]+' /etc/cdnpanel/config.json 2>/dev/null || echo "")
    fi

    # 设置环境变量
    export SKIP_INIT=1
    export MODE=edge
    export EDGE_TOKEN="$EDGE_TOKEN"
    export MASTER_URL="$MASTER_URL"

    if [ "$XDP_ENABLED" = "1" ]; then
        export XDP_IFACE="$XDP_IFACE"
    fi

    # 运行安装脚本
    if [ -f install.sh ]; then
        bash install.sh
    else
        error "install.sh 未找到"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 7. 验证安装
# ═══════════════════════════════════════════════════════════════════════════
echo ""
info "验证安装..."
sleep 3

if [ "$MODE" = "master" ]; then
    if systemctl is-active cdnpanel >/dev/null 2>&1; then
        info "✓ cdnpanel 服务已启动"
        systemctl status cdnpanel --no-pager -l | head -15
    else
        error "cdnpanel 启动失败，请检查日志: journalctl -u cdnpanel -n 50"
    fi
else
    if systemctl is-active cdnedge >/dev/null 2>&1; then
        info "✓ cdnedge 服务已启动"
        systemctl status cdnedge --no-pager -l | head -15
    else
        error "cdnedge 启动失败，请检查日志: journalctl -u cdnedge -n 50"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 完成
# ═══════════════════════════════════════════════════════════════════════════
echo ""
info "================================================================"
info "重新安装完成！"
info "================================================================"
echo ""
info "所有数据已保留："
info "  - 配置目录: /etc/cdnpanel/"
info "  - 备份位置: $BACKUP_DIR"
echo ""

if [ "$MODE" = "master" ]; then
    info "主控节点访问地址:"
    info "  http://$(hostname -I | awk '{print $1}'):8080"
    info "  或 http://localhost:8080"
    echo ""
    info "默认账号密码:"
    info "  admin / 123456（如果是新安装）"
else
    info "边缘节点已启动"
    info "请在主控面板确认节点状态"
fi

echo ""
info "如遇问题:"
info "  - 查看日志: journalctl -u cdnpanel -f （或 cdnedge）"
info "  - 恢复备份: cp -r $BACKUP_DIR/cdnpanel/* /etc/cdnpanel/"
echo ""
