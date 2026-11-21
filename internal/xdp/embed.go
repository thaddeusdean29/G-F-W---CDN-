package xdp

import _ "embed"

// Source 是 cdn_xdp.c 的原始源码，供远程部署时上传到边缘节点现场编译。
// eBPF 字节码依赖目标机器的内核头文件，不能在别的机器上编译后直接搬运。
//
//go:embed cdn_xdp.c
var Source []byte
