package waf

import _ "embed"

//go:embed rules.enc
var rulesEnc []byte

// BuiltinPlaintext 返回内置包解密后的原始 JSON。
// 只给构建期自检工具（cmd/wafselfcheck -seal-check）用来比对密封有没有过期；
// 产品二进制不会调用它。
func BuiltinPlaintext() []byte {
	data, err := decryptRules(rulesEnc)
	if err != nil {
		panic("waf: 内置规则包解密失败: " + err.Error())
	}
	return data
}

// BuiltinEncrypted 返回内置包的密文本体（未解密）。
//
// 主控需要它，是因为规则包对边缘来说只有两种来源：管理员在面板维护的那份，和出厂这份。
// 下发"上一版/回滚档"时如果库里只有一行，旧档就得回落到出厂包，而边缘存的是密文、
// 校验的是密文能不能编译 —— 传明文反而要多一条格式约定。
func BuiltinEncrypted() []byte { return rulesEnc }

// BuiltinCatalog 返回内置包的目录（不含正则本体），供主控在库里没有启用包时渲染配置界面。
func BuiltinCatalog() RulePackage { return builtinPackage().Package() }
