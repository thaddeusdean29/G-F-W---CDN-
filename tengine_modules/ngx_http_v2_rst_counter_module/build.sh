#!/bin/bash
#
# Tengine 编译脚本 - 包含 HTTP/2 RST Counter 模块
# 用于检测 HTTP/2 Rapid Reset 攻击 (CVE-2023-44487)
#

set -e

# 配置变量
TENGINE_VERSION=${TENGINE_VERSION:-"3.1.0"}
TENGINE_DIR="/usr/local/src/tengine-${TENGINE_VERSION}"
INSTALL_PREFIX="/usr/local/tengine"
MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================="
echo "Tengine HTTP/2 RST Counter 模块编译脚本"
echo "========================================="
echo ""
echo "Tengine 版本: ${TENGINE_VERSION}"
echo "安装路径: ${INSTALL_PREFIX}"
echo "模块路径: ${MODULE_DIR}"
echo ""

# 检查是否有 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "错误: 需要 root 权限运行此脚本"
    echo "请使用: sudo $0"
    exit 1
fi

# 检查 Tengine 源码目录
if [ ! -d "$TENGINE_DIR" ]; then
    echo "错误: Tengine 源码目录不存在: $TENGINE_DIR"
    echo ""
    echo "请先下载 Tengine 源码:"
    echo "  wget https://tengine.taobao.org/download/tengine-${TENGINE_VERSION}.tar.gz"
    echo "  tar -zxf tengine-${TENGINE_VERSION}.tar.gz -C /usr/local/src/"
    exit 1
fi

# 检查依赖
echo "检查编译依赖..."
MISSING_DEPS=""

if ! command -v gcc &> /dev/null; then
    MISSING_DEPS="$MISSING_DEPS gcc"
fi

if ! command -v make &> /dev/null; then
    MISSING_DEPS="$MISSING_DEPS make"
fi

if [ ! -f /usr/include/pcre.h ] && [ ! -f /usr/local/include/pcre.h ]; then
    MISSING_DEPS="$MISSING_DEPS libpcre3-dev"
fi

if [ ! -f /usr/include/zlib.h ] && [ ! -f /usr/local/include/zlib.h ]; then
    MISSING_DEPS="$MISSING_DEPS zlib1g-dev"
fi

if [ ! -f /usr/include/openssl/ssl.h ] && [ ! -f /usr/local/include/openssl/ssl.h ]; then
    MISSING_DEPS="$MISSING_DEPS libssl-dev"
fi

if [ -n "$MISSING_DEPS" ]; then
    echo "错误: 缺少以下依赖:$MISSING_DEPS"
    echo ""
    echo "Ubuntu/Debian 安装命令:"
    echo "  apt-get update"
    echo "  apt-get install -y build-essential libpcre3-dev zlib1g-dev libssl-dev"
    echo ""
    echo "CentOS/RHEL 安装命令:"
    echo "  yum groupinstall -y 'Development Tools'"
    echo "  yum install -y pcre-devel zlib-devel openssl-devel"
    exit 1
fi

echo "依赖检查通过 ✓"
echo ""

# 进入 Tengine 源码目录
cd "$TENGINE_DIR"

echo "配置 Tengine..."
./configure \
    --prefix="$INSTALL_PREFIX" \
    --add-module="${MODULE_DIR}" \
    --with-http_v2_module \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --with-threads \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_realip_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-file-aio \
    --http-client-body-temp-path=/var/cache/tengine/client_temp \
    --http-proxy-temp-path=/var/cache/tengine/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/tengine/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/tengine/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/tengine/scgi_temp \
    --user=www-data \
    --group=www-data

if [ $? -ne 0 ]; then
    echo ""
    echo "错误: Tengine 配置失败"
    exit 1
fi

echo ""
echo "配置成功 ✓"
echo ""

# 编译
echo "编译 Tengine (这可能需要几分钟)..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo ""
    echo "错误: Tengine 编译失败"
    exit 1
fi

echo ""
echo "编译成功 ✓"
echo ""

# 备份旧版本
if [ -f "${INSTALL_PREFIX}/sbin/tengine" ]; then
    echo "备份旧版本..."
    BACKUP_DIR="${INSTALL_PREFIX}_backup_$(date +%Y%m%d_%H%M%S)"
    cp -a "$INSTALL_PREFIX" "$BACKUP_DIR"
    echo "旧版本已备份到: $BACKUP_DIR"
    echo ""
fi

# 安装
echo "安装 Tengine..."
make install

if [ $? -ne 0 ]; then
    echo ""
    echo "错误: Tengine 安装失败"
    exit 1
fi

echo ""
echo "安装成功 ✓"
echo ""

# 创建缓存目录
echo "创建缓存目录..."
mkdir -p /var/cache/tengine/client_temp
mkdir -p /var/cache/tengine/proxy_temp
mkdir -p /var/cache/tengine/fastcgi_temp
mkdir -p /var/cache/tengine/uwsgi_temp
mkdir -p /var/cache/tengine/scgi_temp
chown -R www-data:www-data /var/cache/tengine

echo "缓存目录创建完成 ✓"
echo ""

# 验证模块
echo "验证模块安装..."
if "${INSTALL_PREFIX}/sbin/tengine" -V 2>&1 | grep -q "ngx_http_v2_rst_counter_module"; then
    echo "HTTP/2 RST Counter 模块已成功编译 ✓"
else
    echo "警告: 未在编译信息中找到模块，但这可能是正常的"
fi

echo ""
echo "========================================="
echo "编译安装完成！"
echo "========================================="
echo ""
echo "下一步:"
echo ""
echo "1. 配置 Tengine (编辑 ${INSTALL_PREFIX}/conf/nginx.conf):"
echo "   http {"
echo "       http2_rst_counter_zone zone=rst_zone:10m;"
echo "   }"
echo ""
echo "   server {"
echo "       listen 443 ssl http2;"
echo "       http2_rst_counter on;"
echo "   }"
echo ""
echo "2. 测试配置:"
echo "   ${INSTALL_PREFIX}/sbin/tengine -t"
echo ""
echo "3. 启动/重载 Tengine:"
echo "   ${INSTALL_PREFIX}/sbin/tengine        # 首次启动"
echo "   ${INSTALL_PREFIX}/sbin/tengine -s reload  # 重载配置"
echo ""
echo "4. 查看详细使用说明:"
echo "   cat ${MODULE_DIR}/README.md"
echo ""
echo "注意: 要让 RST_STREAM 检测真正工作，还需要修改 Tengine 源码"
echo "      详见 README.md 中的\"源码修改指南\"部分"
echo ""
