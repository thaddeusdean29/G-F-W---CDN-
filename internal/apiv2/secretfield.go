package apiv2

import "encoding/json"

// SecretFields 按 docs/API-v2.md §0.5 的约定构造 {"<name>_set": bool, "<name>_hint": "…末4位"}，
// 供 handler 合并进响应体。plaintext 为空表示该字段未设置。
func SecretFields(name string, plaintext string) map[string]any {
	out := map[string]any{name + "_set": plaintext != ""}
	if plaintext != "" {
		out[name+"_hint"] = secretHint(plaintext)
	}
	return out
}

func secretHint(plaintext string) string {
	if len(plaintext) <= 4 {
		return plaintext
	}
	return plaintext[len(plaintext)-4:]
}

// SecretWriteIntent 是敏感字段三态写入语义（docs/API-v2.md §0.5）的解析结果。
type SecretWriteIntent int

const (
	SecretUnset   SecretWriteIntent = iota // 字段不出现：不修改
	SecretClear                            // 字段为 null：清除
	SecretReplace                          // 非空字符串：替换
)

// ParseSecretField 从请求体顶层字段中解析出写入意图：
// 字段不出现 = 不修改；传 null = 清除（clearAllowed=false 时报错，必填字段不允许清除）；
// 传非空字符串 = 替换。
func ParseSecretField(rawFields map[string]json.RawMessage, name string, clearAllowed bool) (SecretWriteIntent, string, error) {
	raw, ok := rawFields[name]
	if !ok {
		return SecretUnset, "", nil
	}
	if string(raw) == "null" {
		if !clearAllowed {
			return SecretUnset, "", NewApiError("validation_failed", name+" 为必填字段，不能清除")
		}
		return SecretClear, "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return SecretUnset, "", NewApiError("validation_failed", name+" 必须是字符串")
	}
	if s == "" {
		return SecretUnset, "", NewApiError("validation_failed", name+" 不能为空字符串")
	}
	return SecretReplace, s, nil
}
