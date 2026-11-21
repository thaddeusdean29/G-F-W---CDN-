package templates

import _ "embed"

// site.conf.tmpl 是开发态维护用的明文模板源文件，不再被直接嵌入。
// 编译期通过 cmd/sealresource 加密生成 site.conf.tmpl.enc，运行时由
// internal/tengine.Generator 解密后使用。

//go:embed site.conf.tmpl.enc
var SiteConfEnc []byte
