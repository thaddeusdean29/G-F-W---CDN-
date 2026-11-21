#!/bin/bash
# CDN Panel 完全卸载脚本
# 与 install.sh 对称：install.sh 里创建/写入的东西，这里都能清理干净

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[ "$(id -u)" -ne 0 ] && { error "需要 root 权限运行"; exit 1; }

echo -e "${YELLOW}=====================================${NC}"
echo -e "${YELLOW}  CDN Panel 卸载程序${NC}"
echo -e "${YELLOW}=====================================${NC}"
echo ""
echo -e "${RED}警告：此操作将删除以下内容：${NC}"
echo "  - cdnpanel / cdnedge 服务与二进制"
echo "  - 配置文件 /etc/cdnpanel/"
echo "  - Tengine 配置 /etc/tengine/"
echo "  - 缓存 /var/cache/tengine/"
echo "  - ACME 挑战目录 /var/www/acme/"
echo "  - SSL 证书目录 /etc/ssl/cdnpanel/"
echo "  - iptables SYN 限速规则和 /etc/iptables/rules.v4"
echo "  - 系统硬化配置 /etc/sysctl.d/99-cdn-hardening.conf"
echo "  - XDP eBPF 对象文件"
echo "  - 可选：Tengine 程序 / Go 环境 / Swap 文件 / 日志 / 数据"
echo ""
read -p "确认继续？(yes/no): " confirm
[ "$confirm" != "yes" ] && { info "已取消"; exit 0; }

# ─────────────────────────────────────────────────────────
# 1. 停止并禁用 systemd 服务
# ─────────────────────────────────────────────────────────
info "停止 systemd 服务..."
systemctl stop cdnpanel cdnedge 2>/dev/null || true
systemctl disable cdnpanel cdnedge 2>/dev/null || true
rm -f /etc/systemd/system/cdnpanel.service
rm -f /etc/systemd/system/cdnedge.service
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true

# ─────────────────────────────────────────────────────────
# 1.5 强制杀掉所有 cdnpanel / cdnedge 进程
# systemd 只能管它自己拉起的进程；如果是手动 nohup / go run / 从源码目录跑的实例
# 必须按进程名和监听端口再兜底杀一次，否则面板"卸载后仍然能访问"
# ─────────────────────────────────────────────────────────
info "强制清理残留进程..."
pkill -TERM -f 'cdnpanel' 2>/dev/null || true
pkill -TERM -f 'cdnedge'  2>/dev/null || true
sleep 1
pkill -KILL -f 'cdnpanel' 2>/dev/null || true
pkill -KILL -f 'cdnedge'  2>/dev/null || true

# 按占用端口兜底：面板默认 8080，边缘默认 9090
for port in 8080 9090; do
    if command -v ss &>/dev/null; then
        PIDS=$(ss -ltnp "sport = :$port" 2>/dev/null | awk -F 'pid=' 'NR>1{split($2,a,","); print a[1]}' | sort -u)
    elif command -v lsof &>/dev/null; then
        PIDS=$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null)
    else
        PIDS=""
    fi
    for pid in $PIDS; do
        # 只杀名字对得上的，避免误杀其他占了 8080 的服务
        pname=$(ps -p "$pid" -o comm= 2>/dev/null)
        case "$pname" in
            cdnpanel|cdnedge|cdn|main)
                warn "端口 $port 仍被 $pname (pid=$pid) 占用，强制结束"
                kill -KILL "$pid" 2>/dev/null || true
                ;;
        esac
    done
done

# 常见 crontab 里可能有自启行（保险起见列出，不自动改）
if crontab -l 2>/dev/null | grep -qE 'cdnpanel|cdnedge'; then
    warn "检测到 crontab 中含 cdnpanel/cdnedge 相关条目，请手动检查：crontab -e"
fi

# ─────────────────────────────────────────────────────────
# 2. 删除二进制文件（含常见非标准位置）
# ─────────────────────────────────────────────────────────
info "删除二进制文件..."
rm -f /usr/local/bin/cdnpanel
rm -f /usr/local/bin/cdnedge
rm -f /usr/local/bin/cdn_xdp.o
rm -f /usr/local/bin/cdn_xdp.c
# 兜底：曾经手动放到 /usr/bin 或从源码目录里直接生成的二进制
rm -f /usr/bin/cdnpanel /usr/bin/cdnedge 2>/dev/null || true
# 源码目录常见位置扫描并提示（不自动删源码目录）
for candidate in /www/wwwroot/cdn /root/cdn /opt/cdn /home/*/cdn; do
    [ -d "$candidate" ] || continue
    for bin in cdnpanel cdnedge; do
        if [ -x "$candidate/$bin" ]; then
            warn "发现源码目录二进制：$candidate/$bin （已删除）"
            rm -f "$candidate/$bin"
        fi
    done
done

# ─────────────────────────────────────────────────────────
# 3. 卸载 XDP（先卸载再删对象，顺序重要）
# ─────────────────────────────────────────────────────────
info "卸载 XDP..."
for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}'); do
    ip link set dev "$iface" xdp off 2>/dev/null || true
    ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
done

# ─────────────────────────────────────────────────────────
# 4. 停止 Tengine 进程
# ─────────────────────────────────────────────────────────
info "停止 Tengine 进程..."
if [ -f /var/run/tengine.pid ]; then
    kill "$(cat /var/run/tengine.pid)" 2>/dev/null || true
    sleep 1
    kill -9 "$(cat /var/run/tengine.pid)" 2>/dev/null || true
fi
pkill -f 'tengine: master' 2>/dev/null || true
pkill -f 'tengine: worker' 2>/dev/null || true
rm -f /var/run/tengine.pid

# ─────────────────────────────────────────────────────────
# 5. 删除 iptables 规则（install.sh 添加的 SYN 限速）
# ─────────────────────────────────────────────────────────
if command -v iptables &>/dev/null; then
    info "清理 iptables 规则..."
    # 反复删直到删完（install.sh 里可能反复运行过，规则重复）
    while iptables -C INPUT -p tcp --syn -m limit --limit 60/s --limit-burst 100 -j ACCEPT 2>/dev/null; do
        iptables -D INPUT -p tcp --syn -m limit --limit 60/s --limit-burst 100 -j ACCEPT 2>/dev/null || break
    done
    while iptables -C INPUT -p tcp --syn -j DROP 2>/dev/null; do
        iptables -D INPUT -p tcp --syn -j DROP 2>/dev/null || break
    done
    rm -f /etc/iptables/rules.v4
    # 目录为空则删
    [ -d /etc/iptables ] && rmdir /etc/iptables 2>/dev/null || true
fi

# ─────────────────────────────────────────────────────────
# 6. 删除系统硬化 sysctl 配置
# ─────────────────────────────────────────────────────────
info "移除系统硬化配置..."
rm -f /etc/sysctl.d/99-cdn-hardening.conf
sysctl --system >/dev/null 2>&1 || true

# ─────────────────────────────────────────────────────────
# 7. 询问是否删除 Tengine 程序
# ─────────────────────────────────────────────────────────
read -p "是否删除 Tengine 程序？(yes/no，建议保留): " del_tengine
if [ "$del_tengine" = "yes" ]; then
    info "删除 Tengine 程序..."
    rm -rf /usr/local/tengine
    rm -f /usr/local/sbin/tengine
else
    info "保留 Tengine 程序"
fi

# ─────────────────────────────────────────────────────────
# 8. 询问是否删除配置和数据
# ─────────────────────────────────────────────────────────
read -p "是否删除配置和域名数据？(yes/no，建议首次卸载选 yes): " del_data
if [ "$del_data" = "yes" ]; then
    info "删除配置和数据..."
    rm -rf /etc/cdnpanel
    rm -rf /etc/tengine
    rm -rf /var/cache/tengine
    rm -rf /var/www/acme
    rm -rf /etc/ssl/cdnpanel
    # XDP 自动封禁的跨重启存档（cdnedge --xdp-state）
    rm -rf /var/lib/cdnedge
else
    info "保留配置和数据"
    warn "保留的目录（如需手动删除）："
    [ -d /etc/cdnpanel ]     && warn "  - /etc/cdnpanel/"
    [ -d /etc/tengine ]      && warn "  - /etc/tengine/"
    [ -d /var/cache/tengine ] && warn "  - /var/cache/tengine/"
    [ -d /var/www/acme ]     && warn "  - /var/www/acme/"
    [ -d /etc/ssl/cdnpanel ] && warn "  - /etc/ssl/cdnpanel/"
    [ -d /var/lib/cdnedge ]  && warn "  - /var/lib/cdnedge/"
fi

# ─────────────────────────────────────────────────────────
# 9. 询问是否删除日志
# ─────────────────────────────────────────────────────────
read -p "是否删除日志文件？(yes/no): " del_logs
if [ "$del_logs" = "yes" ]; then
    info "删除日志..."
    rm -rf /var/log/tengine
    rm -rf /var/log/cdnpanel
else
    info "保留日志"
fi

# ─────────────────────────────────────────────────────────
# 10. 询问是否删除 Go 环境（install.sh 会装 Go 到 /usr/local/go）
# ─────────────────────────────────────────────────────────
if [ -d /usr/local/go ] && [ -x /usr/local/go/bin/go ]; then
    read -p "是否删除 Go 环境（/usr/local/go）？(yes/no，如系统其他项目也用请选 no): " del_go
    if [ "$del_go" = "yes" ]; then
        info "删除 Go 环境..."
        rm -rf /usr/local/go
        # 清理 install.sh 追加到 /etc/profile 的 PATH
        if [ -f /etc/profile ] && grep -q 'export PATH=$PATH:/usr/local/go/bin' /etc/profile; then
            sed -i '\|export PATH=\$PATH:/usr/local/go/bin|d' /etc/profile
        fi
        # 顺带清理 garble：install.sh 现在默认不装它，只有显式 GARBLE=1 才装，
        # 所以这里删到的是历史版本留下的、或用户自己开过混淆装上的那份。
        rm -f /root/go/bin/garble
    else
        info "保留 Go 环境"
    fi
fi

# ─────────────────────────────────────────────────────────
# 11. 询问是否删除 Swap 文件（install.sh 低内存环境会创建 /swapfile）
# ─────────────────────────────────────────────────────────
if [ -f /swapfile ] && grep -q '^/swapfile' /etc/fstab 2>/dev/null; then
    read -p "是否删除安装脚本创建的 /swapfile？(yes/no，低内存服务器建议保留): " del_swap
    if [ "$del_swap" = "yes" ]; then
        info "关闭并删除 Swap 文件..."
        swapoff /swapfile 2>/dev/null || true
        rm -f /swapfile
        # 从 fstab 中移除
        sed -i '\|^/swapfile[[:space:]]|d' /etc/fstab
    else
        info "保留 Swap 文件"
    fi
fi

# ─────────────────────────────────────────────────────────
# 完成
# ─────────────────────────────────────────────────────────
info ""
info "${GREEN}✓ 卸载完成${NC}"
info ""

# 剩余目录列举（凡还存在的都提示）
REMAINING=()
[ -d /etc/cdnpanel ]     && REMAINING+=("/etc/cdnpanel/")
[ -d /etc/tengine ]      && REMAINING+=("/etc/tengine/")
[ -d /var/cache/tengine ] && REMAINING+=("/var/cache/tengine/")
[ -d /var/www/acme ]     && REMAINING+=("/var/www/acme/")
[ -d /etc/ssl/cdnpanel ] && REMAINING+=("/etc/ssl/cdnpanel/")
[ -d /usr/local/tengine ] && REMAINING+=("/usr/local/tengine/")
[ -d /usr/local/go ]     && REMAINING+=("/usr/local/go/")
[ -d /var/log/tengine ]  && REMAINING+=("/var/log/tengine/")
[ -d /var/log/cdnpanel ] && REMAINING+=("/var/log/cdnpanel/")
[ -f /swapfile ]         && REMAINING+=("/swapfile")

if [ ${#REMAINING[@]} -gt 0 ]; then
    info "以下内容按你的选择被保留（如需彻底清理请手动删除）："
    for p in "${REMAINING[@]}"; do
        info "  - $p"
    done
    info ""
fi

info "现在可以运行 install.sh 重新安装"
