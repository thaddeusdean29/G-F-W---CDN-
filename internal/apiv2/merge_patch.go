package apiv2

import "encoding/json"

// ApplyMergePatch 实现 RFC 7396 JSON Merge Patch：对象逐字段合并，
// 其余类型（包括数组）整体替换，patch 中的字段值为 null 表示删除该字段。
// target 为空（未初始化的资源）时视为空对象。
func ApplyMergePatch(target, patch json.RawMessage) (json.RawMessage, error) {
	var patchVal any
	if err := json.Unmarshal(patch, &patchVal); err != nil {
		return nil, err
	}
	patchMap, ok := patchVal.(map[string]any)
	if !ok {
		// patch 本身不是 JSON 对象：按 RFC 7396，结果就是 patch 本身。
		return patch, nil
	}

	var targetVal any
	if len(target) > 0 {
		if err := json.Unmarshal(target, &targetVal); err != nil {
			return nil, err
		}
	}
	targetMap, _ := targetVal.(map[string]any)

	merged := mergeObject(targetMap, patchMap)
	return json.Marshal(merged)
}

func mergeObject(target, patch map[string]any) map[string]any {
	if target == nil {
		target = map[string]any{}
	}
	for k, v := range patch {
		if v == nil {
			delete(target, k)
			continue
		}
		if vMap, ok := v.(map[string]any); ok {
			tMap, _ := target[k].(map[string]any)
			target[k] = mergeObject(tMap, vMap)
			continue
		}
		target[k] = v
	}
	return target
}

// DisallowedFields 返回 patch 顶层出现的、在 readonly 列表里的字段名，
// 用于 handler 在合并前拦截并返回 400 readonly_field。
func DisallowedFields(patch json.RawMessage, readonly []string) []string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(patch, &m); err != nil {
		return nil
	}
	var bad []string
	for _, f := range readonly {
		if _, ok := m[f]; ok {
			bad = append(bad, f)
		}
	}
	return bad
}

// UnknownFields 返回 body 顶层出现的、不在 known 里的字段名，
// 用于 handler 按 docs/API-v2.md §0.3 返回 400 unknown_field（未知字段不再静默忽略）。
func UnknownFields(body json.RawMessage, known []string) []string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	knownSet := make(map[string]bool, len(known))
	for _, f := range known {
		knownSet[f] = true
	}
	var bad []string
	for f := range m {
		if !knownSet[f] {
			bad = append(bad, f)
		}
	}
	return bad
}
