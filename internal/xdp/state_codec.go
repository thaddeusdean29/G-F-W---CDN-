//go:build linux

package xdp

import (
	"encoding/json"
	"fmt"
)

// stateVersion 是存档格式版本。v1 是最初的裸 map（`{"1.2.3.4": "2026-09-20T12:00:00Z"}`），
// 没有版本号字段；v2 起是带 version/bans/offenders 三个键的对象。
// v3 格式与 v2 相同，区别只在 IPv4 地址的字节序：v1/v2 记下的 IPv4 全是倒序的
// （见 ipv4Key），读入时由 decodeState 倒回来。
const stateVersion = 3

// stateFile 是 v2 存档的结构。
//
// 为什么要改格式：累犯档位必须跨重启保留，否则攻击者只要打到节点重启（或等一次版本
// 升级）就能把自己的档位清零，递增机制形同虚设。而 v1 的裸 map 没有任何地方放这个信息。
type stateFile struct {
	Version int `json:"version"`
	// Bans 是 IP → 封禁过期时刻（RFC3339）。存绝对过期时刻而非起始时刻，
	// 这样改了阶梯配置也不会影响已生效封禁的剩余时长。
	Bans map[string]string `json:"bans"`
	// Offenders 是 IP → 累犯记账。条目可以比 Bans 多：封禁到期后档位仍保留到
	// offenderTTL，这正是挡住"长间隔轮询"所必需的。
	Offenders map[string]*offenderRecord `json:"offenders"`

	// Ladder / OffenderTTL 是面板下发的封禁阶梯，以 "1h0m0s,6h0m0s,24h0m0s" 和
	// "48h0m0s" 的形式存字符串。空表示"从未从面板改过，用启动参数/内置默认值"。
	//
	// 为什么存在边缘节点自己的存档里，而不是只靠主控推送：主控在节点注册时**不重放**
	// 任何配置（CC 配置也一样）。只存在主控侧的话，边缘节点一旦重启就悄悄回到启动
	// flag 的值 —— 面板上显示的是新阶梯，实际在封人的是旧阶梯，而这种不一致没有任何
	// 迹象。存进这份本来就要原子写的存档，节点自己就能恢复，不依赖主控是否在线。
	//
	// 这两个字段是**增量添加**的，没有跟着升 version：老二进制读到会忽略未知键，
	// 新二进制读到老存档则是空字符串走默认路径，两个方向都不会出错。
	Ladder      string `json:"ladder,omitempty"`
	OffenderTTL string `json:"offender_ttl,omitempty"`
}

// decodeState 解析存档，同时兼容 v1 的裸 map 格式。
//
// 必须兼容而不是「格式不对就丢掉重来」：升级时节点上已经有一份 v1 存档（作者的节点上
// 是 141 条封禁），当成解析失败丢掉等于在升级那一刻把所有生效封禁放行 —— 攻击方只要
// 卡在版本升级的时间点就能清空封禁，而这正是引入持久化要堵的漏洞。
//
// v1 存档没有累犯信息，恢复后所有 IP 从首档开始，这是可接受的一次性降级。
//
// 返回整个 stateFile 而不是拆开的 bans/offenders：存档里现在还带面板下发的阶梯配置，
// 每加一项都改签名会让调用方和测试跟着抖。返回的结构里 Bans/Offenders 保证非 nil，
// 调用方可以直接写入。
func decodeState(data []byte) (*stateFile, error) {
	// 先试 v2。用 json.Unmarshal 到结构体时，v1 的裸 map 会因为值类型不匹配
	// （string vs 嵌套对象）而报错，所以两种格式不会互相误判。
	var st stateFile
	if e := json.Unmarshal(data, &st); e == nil && st.Version > 0 {
		if st.Version > stateVersion {
			// 比本进程更新的格式：拒绝而不是按已知字段部分解析。部分解析会静默丢掉
			// 新版本写入的信息，然后在下次落盘时把丢掉的部分永久抹掉（降级回滚场景）。
			return nil, fmt.Errorf("state file version %d is newer than supported %d", st.Version, stateVersion)
		}
		if st.Bans == nil {
			st.Bans = map[string]string{}
		}
		if st.Offenders == nil {
			st.Offenders = map[string]*offenderRecord{}
		}
		if st.Version < 3 {
			st.Bans, st.Offenders = fixLegacyV4Order(st.Bans, st.Offenders)
		}
		return &st, nil
	}

	// 回退到 v1：裸 `{"ip": "RFC3339"}`。
	var legacy map[string]string
	if e := json.Unmarshal(data, &legacy); e != nil {
		return nil, e
	}
	bans, offenders := fixLegacyV4Order(legacy, nil)
	return &stateFile{
		Version:   1,
		Bans:      bans,
		Offenders: offenders,
	}, nil
}
