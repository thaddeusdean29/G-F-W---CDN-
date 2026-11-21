#!/bin/bash
#
# 应用 Tengine HTTP/2 RST_STREAM 钩子补丁
# 此脚本会修改 Tengine 源码以支持 RST_STREAM 事件捕获
#

set -e

TENGINE_VERSION=${TENGINE_VERSION:-"3.1.0"}
TENGINE_DIR="/usr/local/src/tengine-${TENGINE_VERSION}"
PATCH_FILE="$(cd "$(dirname "$0")" && pwd)/tengine_http_v2_rst_hook.patch"

echo "========================================="
echo "Tengine HTTP/2 RST Hook 补丁应用脚本"
echo "========================================="
echo ""

# 检查 Tengine 源码目录
if [ ! -d "$TENGINE_DIR" ]; then
    echo "错误: Tengine 源码目录不存在: $TENGINE_DIR"
    echo ""
    echo "请设置 TENGINE_VERSION 环境变量指向正确的版本"
    echo "例如: TENGINE_VERSION=3.1.0 $0"
    exit 1
fi

# 检查补丁文件
if [ ! -f "$PATCH_FILE" ]; then
    echo "错误: 补丁文件不存在: $PATCH_FILE"
    exit 1
fi

echo "Tengine 源码目录: $TENGINE_DIR"
echo "补丁文件: $PATCH_FILE"
echo ""

# 检查文件是否已修改
TARGET_FILE="${TENGINE_DIR}/src/http/v2/ngx_http_v2.c"
if [ ! -f "$TARGET_FILE" ]; then
    echo "错误: 目标文件不存在: $TARGET_FILE"
    exit 1
fi

if grep -q "ngx_http_v2_rst_handler" "$TARGET_FILE"; then
    echo "检测到文件已经包含 RST handler 调用"
    echo "补丁可能已经应用过，跳过..."
    echo ""
    echo "如需重新应用，请先恢复原始文件:"
    echo "  cd $TENGINE_DIR"
    echo "  git checkout src/http/v2/ngx_http_v2.c"
    echo "  # 或者重新解压 Tengine 源码包"
    exit 0
fi

# 备份原文件
echo "备份原文件..."
cp "$TARGET_FILE" "${TARGET_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo "备份完成 ✓"
echo ""

# 应用补丁
echo "应用补丁..."
cd "$TENGINE_DIR"

if patch -p1 < "$PATCH_FILE"; then
    echo ""
    echo "补丁应用成功 ✓"
    echo ""
    echo "========================================="
    echo "下一步: 重新编译 Tengine"
    echo "========================================="
    echo ""
    echo "执行以下命令:"
    echo "  cd $TENGINE_DIR"
    echo "  make clean"
    echo "  ./configure [你的配置参数]"
    echo "  make -j\$(nproc)"
    echo "  sudo make install"
    echo ""
    echo "或使用提供的编译脚本:"
    echo "  sudo bash build.sh"
    echo ""
else
    echo ""
    echo "错误: 补丁应用失败"
    echo ""
    echo "可能的原因:"
    echo "1. Tengine 版本不匹配（补丁针对 Tengine 3.1.0）"
    echo "2. 源文件已被修改"
    echo ""
    echo "手动修改方法:"
    echo "编辑 ${TARGET_FILE}"
    echo ""
    echo "在文件开头添加:"
    echo "  extern ngx_int_t ngx_http_v2_rst_handler(ngx_http_request_t *r);"
    echo ""
    echo "在 ngx_http_v2_state_rst_stream() 函数中，"
    echo "在 ngx_http_v2_finalize_connection() 调用之后添加:"
    echo "  if (stream->request) {"
    echo "      (void) ngx_http_v2_rst_handler(stream->request);"
    echo "  }"
    echo ""

    # 恢复备份
    if [ -f "${TARGET_FILE}.backup."* ]; then
        latest_backup=$(ls -t "${TARGET_FILE}.backup."* | head -1)
        cp "$latest_backup" "$TARGET_FILE"
        echo "已恢复原文件"
    fi

    exit 1
fi
