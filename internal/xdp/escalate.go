// 无构建标签：默认值常量和 ParseBanLadder 要在 Windows/Mac 上也能引用
// （cmd/cdnedge 解析 flag 时用），与 defaults.go 同理。
// 挂在 AutoBlocker 上的方法在 escalate_linux.go 里，那边才需要 linux。
package xdp

import (
	"fmt"
	"time"
)

// DefaultBanLadder 是累犯递增的封禁时长阶梯。
//
// 为什么不用单一固定时长：要挡住「24 小时持续轮询」这种攻击，固定时长就得设成 24 小时，
// 而所有 per-IP 阈值都是**按源 IP 聚合**的（conn_limit / syn_limit）。办公网、
// 学校、运营商 CGNAT 大出口后面几十个用户共用一个 IP 时会累加撞线，于是一次误封就是
// 关一天 —— 而封禁现在是落盘的，重启不再自动清空，误封代价从「等 5 分钟」变成「关一天」。
//
// 阶梯把两个需求分开：真实攻击者反复被封，第二三轮就进了「小时级以上」档位，轮询的
// 收益迅速归零；被误伤的真人几乎不会在观察窗口内触发第二次，只吃首档。
//
// 首档取 1 小时而非 5 分钟：实测节点上的封禁绝大多数是真实攻击源反复来打，5 分钟对
// 它们几乎没有成本。代价明确写在这里 —— **误判一个 NAT 共用出口时，它后面的所有真人
// 会被一起关掉 1 小时**。这是刻意选择的取舍，不是疏漏；如果开始收到「某公司/校园网
// 访问不了」的反馈，第一件该调的就是这个值（`--xdp-ban-ladder`）。
//
// 阶梯是「第 N 次被封用第 N 档」，超出长度后一直用最后一档（封顶，不无限增长）。
var DefaultBanLadder = []time.Duration{
	1 * time.Hour,
	6 * time.Hour,
	24 * time.Hour,
}

// DefaultOffenderTTL 是累犯计数的遗忘窗口：一个 IP 在这段时间内没有再次被封，
// 计数归零、下次从首档重新开始。
//
// **必须明显大于末档时长**，否则封顶档形同虚设：末档 24 小时而窗口也是 24 小时的话，
// 一个被关满 24 小时的 IP 在解封那一刻记账刚好过期，下次再来直接回首档 —— 越是打到
// 封顶的攻击者越容易把档位清零，正好反了。48 小时给封顶档留出 24 小时的记忆余量。
//
// 另一头的代价：这个窗口同时决定「误封的真人要多久才能回到首档」。取 48 小时而不是
// 一周，是因为窗口越长，一个偶然撞线的办公网出口 IP 越容易在几次零星误判后爬到
// 24 小时档，表现为「这个公司的人越来越容易被长时间封」，且极难归因。48 小时意味着
// 隔天再来仍算累犯，但隔个周末就回首档。
const DefaultOffenderTTL = 48 * time.Hour

// maxOffenders 是累犯记账的条数上限。
//
// 必须有上限：伪造源虽然已经在 XDP 层被 bogon_drop 挡掉，但真实攻击仍可以用大量
// 不同的真实 IP（僵尸网络）轮换，每个都留下一条记账。没有上限时这张表会随攻击规模
// 无界增长，并且整份落盘 —— 内存放大加写盘放大同时发生在节点负载最高的时刻。
//
// 超限时按「最久未见」淘汰：被淘汰的 IP 只是回到首档，不影响正在生效的封禁
// （封禁过期时刻存在 blockedIPs 里，与这张表独立）。
const maxOffenders = 65536

// offenderRecord 是单个 IP 的累犯记账。
type offenderRecord struct {
	// Count 是该 IP 累计被封的次数（含本次），决定用阶梯的第几档。
	Count int `json:"count"`
	// LastSeen 是最近一次被封的时刻，用于 TTL 遗忘和超限淘汰。
	LastSeen time.Time `json:"last_seen"`
}

// ladderDuration 按累犯次数取对应档位，超出阶梯长度则返回最后一档（封顶）。
// 纯函数，便于单测覆盖边界（count<=0、超长、空阶梯）。
func ladderDuration(ladder []time.Duration, count int, fallback time.Duration) time.Duration {
	if len(ladder) == 0 {
		return fallback
	}
	idx := count - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(ladder) {
		idx = len(ladder) - 1
	}
	return ladder[idx]
}

// ParseBanLadder 把「5m,30m,2h,12h,24h」这样的逗号分隔列表解析成阶梯。
//
// 空字符串返回 nil，调用方应视为「用 DefaultBanLadder」。任何一项解析失败或
// 非正数都返回错误而不是跳过它 —— 静默忽略一个写错的档位会让实际阶梯与运维
// 以为配置的阶梯不一致，而这种偏差只会在真的封到那一档时才暴露出来。
func ParseBanLadder(s string) ([]time.Duration, error) {
	if s == "" {
		return nil, nil
	}
	parts := splitComma(s)
	out := make([]time.Duration, 0, len(parts))
	for _, p := range parts {
		d, err := time.ParseDuration(p)
		if err != nil {
			return nil, &BanLadderError{Item: p, Err: err}
		}
		if d <= 0 {
			return nil, &BanLadderError{Item: p, Err: errNonPositive}
		}
		out = append(out, d)
	}
	return out, nil
}

// FormatBanLadder 把阶梯编回「1h0m0s,6h0m0s,24h0m0s」这样的逗号列表，
// 供面板回显到输入框。与 ParseBanLadder 互逆。
func FormatBanLadder(ladder []time.Duration) string {
	out := ""
	for i, d := range ladder {
		if i > 0 {
			out += ","
		}
		out += d.String()
	}
	return out
}

// ValidateBanConfig 检查阶梯与遗忘窗口的组合是否自相矛盾。
//
// 唯一但关键的一条：**末档必须严格小于遗忘窗口**。相等或更大时，一个被关满末档的 IP
// 在解封那一刻记账刚好过期，下次再来直接回首档 —— 越是打到封顶的攻击者越容易把档位
// 清零，与阶梯的目的完全相反。这个矛盾不会报任何错，只表现为「封顶档好像没用」，
// 所以必须在配置入口拦住而不是接受后静默失效。
//
// 空阶梯或 ttl<=0 表示「该项不变」（见 SetBanConfig），无从校验组合，直接放过。
func ValidateBanConfig(ladder []time.Duration, ttl time.Duration) error {
	if len(ladder) == 0 || ttl <= 0 {
		return nil
	}
	if last := ladder[len(ladder)-1]; last >= ttl {
		return &BanConfigError{Last: last, TTL: ttl}
	}
	return nil
}

// BanConfigError 报告阶梯末档与遗忘窗口冲突，消息里带上具体数值便于直接改。
type BanConfigError struct {
	Last time.Duration
	TTL  time.Duration
}

func (e *BanConfigError) Error() string {
	return "ban ladder last tier " + e.Last.String() +
		" must be shorter than offender TTL " + e.TTL.String() +
		" (otherwise an IP that serves the full last tier is forgotten the moment it is released, and drops back to tier 1)"
}

// BanLadderError 指出阶梯配置里具体是哪一项有问题，便于运维直接定位。
type BanLadderError struct {
	Item string
	Err  error
}

func (e *BanLadderError) Error() string {
	return "invalid ban ladder entry " + e.Item + ": " + e.Err.Error()
}

func (e *BanLadderError) Unwrap() error { return e.Err }

type constError string

func (e constError) Error() string { return string(e) }

const errNonPositive = constError("duration must be positive")

// splitComma 按逗号切分并去掉每项两端空白，跳过空项（允许「5m, 30m」这种写法）。
func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			item := trimSpace(s[start:i])
			if item != "" {
				out = append(out, item)
			}
			start = i + 1
		}
	}
	return out
}

// LadderPreview 按阶梯返回「第 N 次被封 → 时长」的可读预览，供面板展示与日志打印。
// 超出阶梯长度的次数一律是最后一档（封顶），因此只需要展示到阶梯长度。
func LadderPreview(ladder []time.Duration) []string {
	if len(ladder) == 0 {
		return nil
	}
	out := make([]string, 0, len(ladder))
	for i, d := range ladder {
		label := fmt.Sprintf("#%d: %v", i+1, d)
		if i == len(ladder)-1 {
			label += " (封顶)"
		}
		out = append(out, label)
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
