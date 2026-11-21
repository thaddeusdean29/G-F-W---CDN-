package edgeapi

import "cdn/internal/xdp"

// xdpSourceCode 是面板"安装 XDP"时在边缘节点本地 clang 编译的 eBPF 源码。
//
// 直接引用 internal/xdp 里 go:embed 的真源码，不再维护副本。历史上这里先后嵌入过
// 精简分叉版（缺 ack_rate map → 加载报 "missing map ack_rate"）和一份需要 build.sh
// 手动同步的副本 cdn_xdp.embed.c.txt —— 本地直接 go build 时副本不会同步，面板装出
// 的 .o 缺新 map，LoadAndAssign 失败。现在只有一份源码，SSH 一键部署（deploy.go 用
// xdp.Source）与面板安装编出的 .o 永远一致。
var xdpSourceCode = xdp.Source
