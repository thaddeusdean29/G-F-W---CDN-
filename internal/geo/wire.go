package geo

// 主控与边缘之间的三份线上协议。放在这里是因为两边都要用同一个结构体：
// 分成两份定义就会重演"面板显示的和节点实际跑的不是同一件事"那种失效——
// 字段名对不上时 JSON 只会安静地解出零值，谁都不报错。

// TablePayload 是下发的前缀表本体。
//
// 表用 gzip + base64 搬运：CN+US+RU 实测 3.82MB 原始 / 0.98MB gz（相邻同国家的段地址连续，
// 压缩率很好）。Fingerprint 是"面板算出来的那张表"的身份，节点装载后原样回传，
// 控制面比字节而不是比"我发过了"。
type TablePayload struct {
	Fingerprint string   `json:"fingerprint"`
	Countries   []string `json:"countries"`
	Total       int      `json:"total"`
	GzipB64     string   `json:"table_gz"`
	// Built 是主控编译完成的时刻，只用于面板显示"这张表是几点算的"。
	Built string `json:"built"`
}

// ConfigPayload 是节点级（四层 + 平台总闸）配置。
// 域名级的策略跟着域名配置走，不在这个包里。
type ConfigPayload struct {
	// ScopeEnabled 是平台总闸。关掉时边缘判定直接跳过，但仍然照常记账与上报：
	// "因为平台没开所以没拦"必须是能看见的状态，不是静默。
	ScopeEnabled bool   `json:"scope_enabled"`
	Node         Policy `json:"node"`
	// L4Enabled 由主控按"这张表能不能装进四层"算出来：XDP 没挂、库没就位、
	// 或者策略是国家只放行（四层做不到）时为 false，节点必须把原因上报而不是什么都不显示。
	L4Enabled bool `json:"l4_enabled"`
}

// EdgeTableResult 是节点装载表之后的回执。
type EdgeTableResult struct {
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
	Total       int    `json:"total"`
	// AppliedButNotStored 换表成功、落盘失败：节点重启就回到旧表，必须单独说。
	AppliedButNotStored bool   `json:"applied_not_persisted"`
	Error               string `json:"error,omitempty"`
}

// Readings 是节点上报的区域判决读数（每 10 秒一次，控制面只读缓存不回连节点）。
type Readings struct {
	At           string         `json:"at"`
	ScopeEnabled bool           `json:"scope_enabled"`
	Table        TableState     `json:"table"`
	Node         Policy         `json:"node"`
	L4           L4State        `json:"l4"`
	Counters     Counters       `json:"counters"`
	Countries    []CountryCount `json:"countries"`
}

// TableState 报的是"这张网卡上现在装的到底是哪张表"。
type TableState struct {
	Loaded      bool     `json:"loaded"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Countries   []string `json:"countries,omitempty"`
	Total       int      `json:"total"`
	// MissingDB 节点自己没找到国家级地理库（只有面板需要库；节点只吃下发的表）。
	// 留这个字段是因为旧版本节点会走"自己查库"那条路，读数要能区分。
	Error string `json:"error,omitempty"`
}

// L4State 是四层丢包的真实落地情况。Armed=false 时所有"已封禁"的显示都必须是灰的：
// XDP 没挂上网卡，四层一条包都不会丢。
type L4State struct {
	Armed     bool   `json:"armed"`
	Want      bool   `json:"want"`
	Mode      string `json:"mode,omitempty"`
	EntriesV4 int    `json:"entries_v4"`
	EntriesV6 int    `json:"entries_v6"`
	Dropped   uint64 `json:"dropped"`
	Program   string `json:"program,omitempty"`
	Error     string `json:"error,omitempty"`
	// Fingerprint 是**trie 里现在这份表**的身份，来自装载时那份下发体。
	// 有它才能回答"面板显示的这张表和网卡上丢包用的那张表是不是同一张"；
	// 光比"我下发成功过"回答不了，因为节点重启后从存档恢复的是另一份。
	Fingerprint string `json:"fingerprint,omitempty"`
	NotInstall  bool   `json:"not_install,omitempty"`
	// Applied 是这台节点最后一次动过四棵 trie 的时刻（装成功、清空、装失败都算）。
	// 只有 Fingerprint 没有时刻，面板就无法区分"表刚换上去"和"三小时前换上去后一直没动"——
	// 后者配合一个 0 丢包数才是真问题，前者不是。
	Applied string `json:"applied,omitempty"`
}

// Counters 按判决来由分类累计。每个 Why 都必须单独有数：
// 把"归属未知"并进"放行"会让库里没覆盖到的那部分流量在任何数字里彻底消失，
// 而那正是"我只封了 A 国，为什么 B 国访客也进不来"这类工单唯一能自证的地方。
type Counters struct {
	Observe   uint64 `json:"observe"`   // 命中名单，但因为是观察模式没拦
	Blocked   uint64 `json:"blocked"`   // 命中名单且真的拦下（七层 403 / 四层丢包）
	Pass      uint64 `json:"pass"`      // 名单判定应当放行
	Unknown   uint64 `json:"unknown"`   // 表里查不到归属（私网、保留段、库未覆盖）
	Exception uint64 `json:"exception"` // 命中例外清单
	Off       uint64 `json:"off"`       // 规则没启用或平台总闸关着
	NoTable   uint64 `json:"no_table"`  // 一张表都没装上，全部按未知处理
}

// CountryCount 是单个国家的命中读数。观察模式下 Blocked 恒 0，
// 面板要显示的是"如果开拦会拦下多少次"，那正是 Observe。
type CountryCount struct {
	Country string `json:"country"`
	Observe uint64 `json:"observe"`
	Blocked uint64 `json:"blocked"`
	Pass    uint64 `json:"pass"`
}
