package migrations

import (
	_ "embed"

	"cdn/internal/secure"
)

// 0001_init.sql 是开发态维护用的明文源文件，不再被直接嵌入。
// 编译期由 cmd/sealresource 生成 0001_init.sql.enc，运行时解密后使用。

//go:embed 0001_init.sql.enc
var initSQLEnc []byte

var InitSQL = string(secure.MustDecrypt(initSQLEnc))
