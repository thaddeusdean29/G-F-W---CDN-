package configs

import (
	_ "embed"

	"cdn/internal/secure"
)

// tengine.conf 是开发态维护用的明文源文件，不再被直接嵌入。
// 编译期由 cmd/sealresource 生成 tengine.conf.enc，运行时解密后使用。

//go:embed tengine.conf.enc
var tengineConfEnc []byte

var TengineConf = secure.MustDecrypt(tengineConfEnc)
