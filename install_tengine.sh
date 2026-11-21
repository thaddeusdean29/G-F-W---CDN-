#!/bin/bash
# 手动安装 Tengine 3.1.0

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[ "$(id -u)" -ne 0 ] && error "需要 root 权限"

# 检查是否已安装：已存在且带 lua-nginx-module 才跳过；旧版本（不带 lua）强制重装，
# 否则站点模板的 access_by_lua_block 会让 tengine -t 失败、443 无法监听。
# 也支持 FORCE_TENGINE=1 手动强制重编译。
if [ -f /usr/local/tengine/sbin/nginx ]; then
    if [ "$FORCE_TENGINE" != "1" ] && /usr/local/tengine/sbin/nginx -V 2>&1 | grep -q "lua-nginx-module"; then
        info "Tengine 已存在且含 lua-nginx-module，跳过安装"
        exit 0
    fi
    info "检测到旧 Tengine（不含 lua 或指定 FORCE_TENGINE=1），停止并重新编译..."
    systemctl stop tengine 2>/dev/null || true
    /usr/local/tengine/sbin/nginx -s stop 2>/dev/null || true
    pkill -f /usr/local/tengine/sbin/nginx 2>/dev/null || true
    rm -f /usr/local/tengine/sbin/nginx /usr/local/tengine/sbin/tengine 2>/dev/null || true
fi

info "安装编译依赖..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential libpcre3-dev zlib1g-dev libssl-dev wget tar

TENGINE_VERSION="3.1.0"
info "下载 Tengine ${TENGINE_VERSION}..."
cd /tmp
rm -rf tengine-${TENGINE_VERSION}*
wget -q https://github.com/alibaba/tengine/archive/refs/tags/${TENGINE_VERSION}.tar.gz -O tengine.tar.gz || \
    error "下载失败，请检查网络"

info "解压源码..."
tar -xzf tengine.tar.gz

info "下载扩展模块..."
wget -q https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v0.36.tar.gz -O headers-more.tar.gz
tar -xzf headers-more.tar.gz

wget -q https://github.com/FRiCKLE/ngx_cache_purge/archive/refs/tags/2.3.tar.gz -O ngx_cache_purge.tar.gz
tar -xzf ngx_cache_purge.tar.gz

# lua-nginx-module（OpenResty 生态标准组件，用于第三层 JA4H 指纹检测：在 auth_request
# 子请求里用 ngx.req.raw_header() 拿到未被 nginx 打乱顺序的原始请求头）依赖 LuaJIT2。
# 版本用 OpenResty 1.25.3.1 bundle 的官方配对（权威，避免版本猜测）。
# 关键：lua-nginx-module >= 0.10.16 强制依赖 resty.core（纯 lua 库），缺它启动时
# lua VM 初始化直接失败（"failed to load the 'resty.core' module"）；resty-core 又依赖
# lrucache。两个纯 lua 库必须装进 LuaJIT 默认路径 /usr/local/share/lua/5.1。
LUAJIT_VERSION="2.1-20220411"
LUA_NGINX_MODULE_VERSION="0.10.26"
NDK_VERSION="0.3.1"   # ngx_devel_kit：lua-nginx-module 的强制前置依赖，缺它 configure 直接失败
RESTY_CORE_VERSION="0.1.28"
LRUCACHE_VERSION="0.13"
info "下载并编译 LuaJIT2 ${LUAJIT_VERSION}..."
wget -q https://github.com/openresty/luajit2/archive/refs/tags/v${LUAJIT_VERSION}.tar.gz -O luajit2.tar.gz
tar -xzf luajit2.tar.gz
# 与 install.sh 保持一致：装到 /usr/local，并写 ld.so.conf 让运行时能找到 libluajit-5.1.so，
# CFLAGS=-fPIC 保证能静态链接进 tengine。
(cd luajit2-${LUAJIT_VERSION} && make CCDEBUG=-g CFLAGS=-fPIC -j"$(nproc)" && make install PREFIX=/usr/local)
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
echo "/usr/local/lib" > /etc/ld.so.conf.d/luajit.conf
ldconfig || true

info "下载 ngx_devel_kit ${NDK_VERSION}（lua-nginx-module 前置依赖）..."
wget -q https://github.com/vision5/ngx_devel_kit/archive/refs/tags/v${NDK_VERSION}.tar.gz -O ndk.tar.gz
tar -xzf ndk.tar.gz

info "下载 lua-nginx-module ${LUA_NGINX_MODULE_VERSION}..."
wget -q https://github.com/openresty/lua-nginx-module/archive/refs/tags/v${LUA_NGINX_MODULE_VERSION}.tar.gz -O lua-nginx-module.tar.gz
tar -xzf lua-nginx-module.tar.gz

info "下载并安装 lua-resty-core ${RESTY_CORE_VERSION} + lua-resty-lrucache ${LRUCACHE_VERSION}（纯 lua，装进 LuaJIT 默认路径）..."
wget -q https://github.com/openresty/lua-resty-core/archive/refs/tags/v${RESTY_CORE_VERSION}.tar.gz -O lua-resty-core.tar.gz
tar -xzf lua-resty-core.tar.gz
wget -q https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v${LRUCACHE_VERSION}.tar.gz -O lua-resty-lrucache.tar.gz
tar -xzf lua-resty-lrucache.tar.gz
(cd lua-resty-core-${RESTY_CORE_VERSION} && make install LUA_LIB_DIR=/usr/local/share/lua/5.1)
(cd lua-resty-lrucache-${LRUCACHE_VERSION} && make install LUA_LIB_DIR=/usr/local/share/lua/5.1)

cd tengine-${TENGINE_VERSION}

info "配置编译参数..."
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
  --add-module=/tmp/ngx_devel_kit-${NDK_VERSION} \
  --add-module=/tmp/lua-nginx-module-${LUA_NGINX_MODULE_VERSION} \
  --with-http_gunzip_module \
  --with-pcre \
  --with-stream \
  --with-stream_ssl_module

info "开始编译（这将需要 5-15 分钟，取决于系统性能）..."
# 低内存环境优化：根据可用内存调整并行编译任务数
TOTAL_MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)
if [ "$TOTAL_MEM_MB" -lt 3072 ]; then
    info "检测到可用内存 ${TOTAL_MEM_MB}MB，使用单线程编译（避免内存不足）"
    MAKE_JOBS=1
else
    MAKE_JOBS=$(nproc)
    info "使用 $MAKE_JOBS 线程并行编译"
fi
make -j"$MAKE_JOBS"

info "安装 Tengine..."
make install

info "创建软链接..."
ln -sf /usr/local/tengine/sbin/nginx /usr/local/tengine/sbin/tengine
ln -sf /usr/local/tengine/sbin/tengine /usr/local/sbin/tengine

info "清理临时文件..."
cd /tmp
rm -rf tengine-${TENGINE_VERSION}* headers-more* ngx_cache_purge* luajit2* lua-nginx-module* ndk* ngx_devel_kit* lua-resty-core* lua-resty-lrucache*

info "验证安装..."
/usr/local/tengine/sbin/tengine -v

echo ""
info "${GREEN}✓ Tengine 安装成功！${NC}"
info "版本：$(/usr/local/tengine/sbin/tengine -v 2>&1)"
info "路径：/usr/local/tengine/sbin/tengine"
