// This file is compiled separately by clang for BPF, not by Go's cgo
// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
// 刻意不 include <linux/icmp.h>：它会经 linux/if.h → sys/socket.h → features.h →
// gnu/stubs.h 拉到 <gnu/stubs-32.h>，那是 32 位 glibc 的头文件（gcc-multilib 才有），
// 在只装了 64 位工具链的机器上直接 fatal error。ICMP 只需要读首字节的 type，
// 下面自己按偏移读，不引用任何 icmphdr 结构。同理 VLAN 头也自己定义（linux/if_vlan.h
// 是内核内部头文件，UAPI 里没有 struct vlan_hdr）。

// IPPROTO constants for BPF context
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17
#define IPPROTO_ICMP   1
#define IPPROTO_ICMPV6 58

// IPv6 扩展头协议号
#define IPV6_EXT_HOPOPTS  0
#define IPV6_EXT_ROUTING  43
#define IPV6_EXT_FRAGMENT 44
#define IPV6_EXT_DSTOPTS  60
// 最多跳过的扩展头个数。BPF 验证器不接受无界循环；正常流量几乎不带扩展头，
// 超过这个层数的包本身就可疑，按「无法解析」处理（只做通用 PPS 限速）。
#define IPV6_EXT_MAX 4

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

struct vlan_hdr_ {
    __be16 tci;
    __be16 encap_proto;
};

// IPv6 逐跳/路由/目的选项头的公共前缀（长度字段以 8 字节为单位，不含首个 8 字节）。
struct ipv6_opt_hdr_ {
    __u8 nexthdr;
    __u8 hdrlen;
};

// IPv6 分片头，固定 8 字节。
struct ipv6_frag_hdr_ {
    __u8   nexthdr;
    __u8   reserved;
    __be16 frag_off; // 高 13 位是偏移（8 字节单位），最低位是 M 标志
    __be32 identification;
};

// IPv6 地址作为 map 键：128 位定长结构，避免直接用 struct in6_addr（其内部是
// union，BTF 里的布局对用户态 Go 侧不够直观）。
struct ipv6_key {
    __u8 addr[16];
};

// 速率条目。count/window_start 是 1 秒滑窗的工作字段，每秒重置；
// total 是单调累计包数，**不随窗口重置**。
//
// 为什么需要 total：用户态 AutoBlocker 每 10 秒扫一次 map，若只能读到 count，
// 读到的就只是"扫描那一瞬间所在的那 1 秒窗口"的计数，10 秒里其余 9 秒的攻击数据
// 在扫描前就被窗口重置清零了。更糟的是 count 在超过阈值后 rate_check 直接 return
// 不再自增，等于封顶在 limit+1，永远到不了 AutoBlocker 那个更高的封禁阈值
// —— 自动封禁因此从未触发。有了 total，用户态可用两次扫描的增量除以间隔算真实 pps。
struct rate_entry {
    __u64 count;
    __u64 window_start;
    __u64 total;
};

// ============================================================
// CDN Edge WAF - Enhanced XDP Layer (L3/L4) Protection
// Target: Drop attacks at NIC driver level before hitting CPU
// ============================================================
//
// 贯穿全文件的约束：XDP 挂在 ingress，边缘节点**回源时是客户端**，源站发回来的
// SYN-ACK / 数据 / ACK / FIN / RST 全是入站包，源地址是源站 IP、目的端口是本机临时
// 端口，且源站从不给边缘发 SYN。任何按「源 IP 计数」且不区分目的端口的规则，都会把
// 整个回源流量记在源站 IP 这一个键上 → DROP 源站的包 → 全站 504 而源站毫无异常。
// port_guard、ack_limit、psh_ack_guard 都因此出过事故。所以下面所有 per-IP 的 TCP
// 限速都只统计 is_service_port() 为真的包 —— 别人连我的服务，而不是我连别人。
//
// 发往非服务端口的 TCP 包唯一的检查是 orphan_tcp_drop：查内核 socket 表，本机没有
// 对应连接就丢。回源连接在 connect() 时就已进入内核连接表（SYN_SENT），源站回包
// 一定查得到，所以这条规则不会重蹈上面几次的覆辙。
//
// 服务端口上的 service_orphan_drop 同理只查 socket 表、不按源 IP 计数；它命中的是
// 「只有监听 socket、没有连接」的非 SYN 包，回源流量的目的端口不是服务端口，碰不到它。

// ------------------------
// Configuration (user-space updatable via ARRAY map)
// ------------------------
struct xdp_config {
    __u32 syn_limit;         // SYN rate limit per IP (packets/sec)
    // pps_limit：per-IP 总包速率（packets/sec，0=disabled）。TCP 只统计发往本机服务端口
    // 的包（排除回源返回包），非 TCP 全部统计。此前这个字段在 C 里从未被读取。
    __u32 pps_limit;
    __u32 udp_limit;         // UDP rate limit (packets/sec, 0=disabled)
    __u32 conn_limit;        // Max half-open TCP connections per IP
    __u32 enabled;           // Master switch (1=enabled, 0=disabled)
    // icmp_limit：per-IP ICMP 速率（0=disabled）。差错报文（v4 的 3/11/12，v6 的 1-4）
    // 放宽到 10 倍：PMTUD 依赖 "需要分片"/"包过大" 报文，丢了会让大包连接卡死。
    // 不完全豁免，因为 BlackNurse 攻击用的恰恰是 type 3 code 3。
    __u32 icmp_limit;
    __u32 udp_dns_limit;     // DNS amplification protection (0=disabled)
    __u32 tcp_rst_limit;     // TCP RST flood per IP (0=disabled)，只统计发往服务端口的 RST
    // fragment_drop=1：丢弃 **TCP** 分片。TCP 自己按 MSS 分段，合法 TCP 分片几乎不存在，
    // 而分片是经典的绕过手段。非 TCP 分片（大 ping、EDNS 大包 DNS 响应）不丢，只走 PPS 限速。
    __u32 fragment_drop;
    __u32 invalid_flags_drop;// Drop TCP packets with invalid flags (1=drop, 0=allow)
    __u32 ack_limit;         // bare-ACK flood per IP (0=disabled)，只统计发往服务端口的纯 ACK
    // port_guard=1：入站新连接（纯 SYN）的 dst port 必须命中 service_ports，否则 DROP。
    // 只管纯 SYN——既有连接的后续包一律不按端口过滤，否则会丢掉回源连接的返回包。
    // 字段顺序必须与 Go 侧 xdpConfigRaw 严格一致（同为连续 __u32，无填充）。
    __u32 port_guard;
    // bogon_drop=1：丢弃源地址不可能合法的包（见 is_bogon_v4）。
    __u32 bogon_drop;
    // psh_ack_guard=1：丢弃不属于已知连接的 PSH-ACK（只看服务端口），默认关。
    __u32 psh_ack_guard;
    // fin_limit：FIN flood per IP（0=disabled），只统计发往服务端口的 FIN。
    __u32 fin_limit;
    // cpu_syn_limit：**每个 CPU** 每秒放行的新连接 SYN 总数上限（0=disabled）。
    // 这是给「每包换一个源地址」的洪水准备的：per-IP 阈值对它无效（每个源只来一两个包），
    // 速率表也会被挤满。超出部分直接丢，保护内核 SYN 队列和 CPU。
    // 按 CPU 计数而不是全局一个计数器：全局计数器是所有核争抢的同一条缓存行，千万级
    // pps 下它本身就成了瓶颈。实际全局上限 ≈ cpu_syn_limit × 收包队列数。
    __u32 cpu_syn_limit;
    // orphan_tcp_drop=1：发往**非服务端口**、且本机内核里没有对应 socket 的 TCP 包直接丢
    // （纯 SYN 除外，那归 port_guard 管）。针对 TCP 反射：攻击者冒用本机 IP 向大量真实
    // Web 服务器发 SYN，它们的 SYN-ACK/ACK 打到本机随机高位端口，内核对每个包回一个 RST，
    // 上行带宽被 RST 吃满。这些包源 IP 是真实服务器、每个源量都不大，per-IP 限速和封禁都
    // 无从下手，只能按「本机有没有这条连接」判断。
    // 查不到 socket 的合法包只有一种：别的 netns（Docker 容器经 MASQUERADE 出网）的回包。
    // 边缘节点不应跑这类业务；若必须跑，关掉此项。
    __u32 orphan_tcp_drop;
    // service_orphan_drop=1：发往**服务端口**、不是纯 SYN 的 TCP 包（ACK / PSH-ACK / RST /
    // FIN / SYN-ACK），如果内核里只查到监听 socket、没有属于它的连接，就丢。
    // 针对随机源 ACK 类洪水：每包换一个源，per-IP 表碰不到阈值；而内核对每个这样的 ACK
    // 回一个 RST，效果与 TCP 反射相同，上行被 RST 吃满。
    // syncookies 例外：SYN 洪水期间内核不建半连接，真人握手的第三个 ACK 同样只查得到
    // 监听 socket。所以带 ACK、不带 RST/FIN/SYN 的包先用 bpf_tcp_check_syncookie 验 cookie，
    // 验过才放行（见 service_orphan_check）。
    __u32 service_orphan_drop;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} xdp_config SEC(".maps");

// ------------------------
// BPF Maps
// ------------------------
//
// 键一律是**原始网络序字节**（IPv4 即 ip->saddr 的 4 字节内存）。用户态必须用 [4]byte
// 读写，不能用 uint32：cilium/ebpf 按主机字节序（x86 小端）序列化 uint32，字节会反。
//
// 容量：封禁表 262144；SYN/ACK/PPS/半开连接这四张决定自动封禁的主力表 131072，
// 其余 65536。LRU hash 在加载时预分配全部条目，每张 13 万条约 10MB，不宜全部放大。
// 速率表被轮换源地址挤满的问题主要靠用户态 rateDiffer 的「新键按下界速率判定」解决。

// IP blocklist (manual + auto)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, __u8);
} blocklist SEC(".maps");

// IP whitelist (bypass all checks)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} whitelist SEC(".maps");

// SYN rate limiter per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_entry);
} syn_rate SEC(".maps");

// PPS rate limiter per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_entry);
} pps_rate SEC(".maps");

// TCP half-open connection counter per IP
//
// decay_start 是衰减窗口起点，与 last_update（最后收包时间）分开记录：
// 衰减必须按"距上次衰减多久"算，若复用 last_update，持续攻击会让它每包刷新，
// 衰减条件永不满足、计数只增不减（详见 conn_check 注释）。
// 字段顺序/尺寸必须与 Go 侧 readConnRateMap 的偏移解析一致。
struct conn_entry {
    __u32 count;
    __u32 _pad;        // 显式填充，避免 count 与 __u64 之间出现隐式空洞
    __u64 last_update;
    __u64 decay_start;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct conn_entry);
} conn_rate SEC(".maps");

// UDP rate limiter per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_entry);
} udp_rate SEC(".maps");

// ICMP rate limiter per IP (ping flood protection)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_entry);
} icmp_rate SEC(".maps");

// UDP DNS rate limiter per IP (DNS amplification protection)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_entry);
} udp_dns_rate SEC(".maps");

// TCP RST rate limiter per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_entry);
} tcp_rst_rate SEC(".maps");

// TCP FIN flood rate limiter per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_entry);
} tcp_fin_rate SEC(".maps");

// TCP bare-ACK flood rate limiter per IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_entry);
} ack_rate SEC(".maps");

// 每 CPU 的新连接 SYN 计数（cpu_syn_limit）。PERCPU：XDP 在一个 CPU 上不会被抢占，
// 普通读写即可，无需原子操作。
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_entry);
} cpu_syn_rate SEC(".maps");

// 服务端口白名单：key = 目的端口（主机字节序 __u16 提升为 __u32），value = 1。
// 由用户态在加载时写入（80/443/22 + agent 端口 + 本机所有 LISTEN 端口）。
// 用于 port_guard，以及区分「发往本机服务的包」和「回源返回包」（is_service_port）。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} service_ports SEC(".maps");

// ------------------------
// IPv6 Maps
// ------------------------
// IPv4 的键是 __u32，装不下 128 位地址，因此 IPv6 需要一整套平行的 map。

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct ipv6_key);
    __type(value, __u8);
} blocklist6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct ipv6_key);
    __type(value, __u8);
} whitelist6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} syn_rate6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} ack_rate6 SEC(".maps");

// IPv6 per-IP 总包速率（pps_limit）。以前 UDP/ICMPv6 也共用这张表，导致 pps 语义混乱；
// 现在 UDP、ICMPv6 各有独立的表，这张只做 pps。
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} pps_rate6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} udp_rate6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} icmp_rate6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} tcp_rst_rate6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_key);
    __type(value, struct rate_entry);
} tcp_fin_rate6 SEC(".maps");

// ------------------------
// 区域封禁（按国家）LPM trie
// ------------------------
//
// 键的前 4 字节是前缀长度（内核 lpm_trie 按主机字节序的 __u32 读它），后面紧跟地址的
// **原始网络序字节**——和 blocklist 同一条规矩：用户态必须逐字节写地址，不能写成 uint32
// （cilium/ebpf 按小端序列化 uint32，字节会反，于是一张表里全是看不见的错地址）。
//
// 为什么是两棵而不是查一次：例外清单必须永远赢，而 LPM 的"最长前缀优先"只在前缀互相
// 包含时成立——例外写 10.0.0.0/8、封禁写整段公网 /0 时，先查封禁树就会把例外吃掉。
// 七层 Decide 的顺序是"例外先于名单"，这里必须一模一样，否则同一份例外清单在两层给出
// 相反答案，而面板上只会显示一个"命中区域规则"。
//
// 只做 deny：四层看不到 HTTP host，也分不清"表里没这个地址"到底是未知还是不该拦，
// 所以 allow（只放行某些国家）一律留在七层。装进这两棵树的前缀只来自整节点策略里
// mode=block + action=deny 的那些国家，域名级规则不进四层。
struct geo_key4 {
    __u32 prefixlen;
    __u32 addr; // ip->saddr 原样拷贝，4 个字节就是网络序
};

struct geo_key6 {
    __u32 prefixlen;
    __u8  addr[16];
};

// 容量：单个大国（CN/US）实测 4~8 万条前缀，选满一个国家约 50 万条。BPF_F_NO_PREALLOC
// 是 LPM_TRIE 的硬性要求（不带它内核直接 EINVAL），好处是按实际条目分配内存，
// 不像 LRU hash 那样加载时就预分配全部槽位。装不下的情况由用户态在写入前按
// MaxEntries() 拒收并报告，绝不写半棵树——半棵树在面板上就是"这个国家封了一半"。
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 524288);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct geo_key4);
    __type(value, __u8);
} geo_block4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 262144);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct geo_key6);
    __type(value, __u8);
} geo_block6 SEC(".maps");

// 例外表：条数是"几十"这个量级，给到 4096 已经宽得多。
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct geo_key4);
    __type(value, __u8);
} geo_exc4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct geo_key6);
    __type(value, __u8);
} geo_exc6 SEC(".maps");

// XDP statistics counter。字段一律追加在末尾：Go 侧 GetStats 按 map 的真实 value_size
// 分配缓冲区，旧 .o 缺的尾部计数读成 0，不会因为差一个字段就让面板整页 XDP 读数空掉。
// 计数项复用还是新开一项，标准是"面板能不能单独解释这个数"：速率类复用 dropped_pps，
// 而区域丢包必须能自证四层真的在按表丢包，所以单独一项。
struct stats {
    __u64 passed;
    __u64 dropped_blocklist;
    __u64 dropped_syn_flood;
    __u64 dropped_pps;
    __u64 dropped_conn_limit;
    __u64 dropped_udp_flood;
    __u64 dropped_icmp_flood;
    __u64 dropped_dns_amp;
    __u64 dropped_tcp_rst;
    __u64 dropped_invalid_flags;
    __u64 dropped_fragment;
    __u64 dropped_invalid_packet;
    __u64 dropped_ack_flood;
    __u64 dropped_bogon;
    __u64 dropped_psh_ack_guard;
    __u64 dropped_fin_flood;
    __u64 dropped_orphan_tcp;
    __u64 dropped_service_orphan;
    // dropped_geo：命中区域封禁 trie 丢掉的包数（v4+v6 合一个计数）。四层没有 host 概念，
    // 分不出"哪条域名规则放行的这个国家"，所以只记总量；逐国家的量由七层那套计数负责。
    __u64 dropped_geo;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} xdp_stats SEC(".maps");

// ------------------------
// Helper Functions
// ------------------------

static __always_inline
struct stats* get_stats(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&xdp_stats, &key);
}

// rate_check 维护 1 秒固定窗口的 per-IP 限速，并同时累加不随窗口重置的 total。
// total 必须在"超限提前 return"之前累加：用户态靠 total 的增量算真实 pps，
// 若超限后不再累加，total 会和 count 一样封顶，自动封禁又会失效。
static __always_inline
int rate_check(__u32 src_ip, void *rate_map, __u64 limit) {
    if (limit == 0)
        return 0; // 0 = disabled

    __u64 now = bpf_ktime_get_ns();
    __u64 window = 1000000000ULL; // 1 second in nanoseconds

    struct rate_entry *entry = bpf_map_lookup_elem(rate_map, &src_ip);

    if (entry) {
        entry->total++;
        if (now - entry->window_start < window) {
            entry->count++;
            if (entry->count > limit)
                return 1; // Rate exceeded
            return 0;
        }
        entry->count = 1;
        entry->window_start = now;
        return 0;
    }

    struct rate_entry init = { .count = 1, .window_start = now, .total = 1 };
    bpf_map_update_elem(rate_map, &src_ip, &init, BPF_ANY);
    return 0;
}

// rate_check6 是 rate_check 的 IPv6 版本。BPF 里没有泛型，键类型不同就得单独一份。
static __always_inline
int rate_check6(struct ipv6_key *src, void *rate_map, __u64 limit) {
    if (limit == 0)
        return 0; // 0 = disabled

    __u64 now = bpf_ktime_get_ns();
    __u64 window = 1000000000ULL;

    struct rate_entry *entry = bpf_map_lookup_elem(rate_map, src);

    if (entry) {
        entry->total++;
        if (now - entry->window_start < window) {
            entry->count++;
            if (entry->count > limit)
                return 1;
            return 0;
        }
        entry->count = 1;
        entry->window_start = now;
        return 0;
    }

    struct rate_entry init = { .count = 1, .window_start = now, .total = 1 };
    bpf_map_update_elem(rate_map, src, &init, BPF_ANY);
    return 0;
}

// cpu_syn_exceeded：本 CPU 本秒放行的新连接 SYN 是否已超过 cpu_syn_limit。
static __always_inline
int cpu_syn_exceeded(__u64 limit) {
    if (limit == 0)
        return 0;
    __u32 k = 0;
    struct rate_entry *e = bpf_map_lookup_elem(&cpu_syn_rate, &k);
    if (!e)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    if (now - e->window_start >= 1000000000ULL) {
        e->window_start = now;
        e->count = 0;
    }
    e->total++;
    e->count++;
    return e->count > limit;
}

// is_service_port：目的端口是否是本机对外服务的端口（主机字节序）。
//
// 这是区分「别人连我」与「我回源时对方回给我的包」的唯一可靠依据：回源连接的本地端口
// 是内核分配的临时端口（默认 32768-60999），永远不在服务端口表里。
// < 1024 的端口无条件视为服务端口：临时端口不可能落在这里，这样即使 service_ports
// 没写成功（port_guard 因此关闭），80/443 上的限速仍然生效。
static __always_inline
int is_service_port(__u16 dport_host) {
    if (dport_host < 1024)
        return 1;
    __u32 k = dport_host;
    return bpf_map_lookup_elem(&service_ports, &k) != NULL;
}

// BPF_F_CURRENT_NETNS 在 UAPI 里是 enum 成员，没法 #ifndef 兜底，自己定义一个同值常量。
#define CDN_CURRENT_NETNS ((__u64)-1)

// tcp_has_socket4/6：本机当前 netns 里是否存在与这个入站包匹配的 TCP socket
// （已建立 / SYN_SENT / TIME_WAIT / 半连接 / 监听，skc 版本全都算）。
// 元组按「包的视角」填：saddr/sport 是对端，daddr/dport 是本机，与内核收包时查表一致。
// 回源连接 connect() 时就进了 ehash（SYN_SENT），源站的 SYN-ACK 和后续回包都能查到。
// 需要内核 5.2+（XDP 里的 skc_lookup 助手）。
static __always_inline
int tcp_has_socket4(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr *tcp) {
    struct bpf_sock_tuple t = {};
    t.ipv4.saddr = ip->saddr;
    t.ipv4.daddr = ip->daddr;
    t.ipv4.sport = tcp->source;
    t.ipv4.dport = tcp->dest;
    struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &t, sizeof(t.ipv4), CDN_CURRENT_NETNS, 0);
    if (!sk)
        return 0;
    bpf_sk_release(sk);
    return 1;
}

static __always_inline
int tcp_has_socket6(struct xdp_md *ctx, struct ipv6hdr *ip6, struct tcphdr *tcp) {
    struct bpf_sock_tuple t = {};
    __builtin_memcpy(t.ipv6.saddr, &ip6->saddr, 16);
    __builtin_memcpy(t.ipv6.daddr, &ip6->daddr, 16);
    t.ipv6.sport = tcp->source;
    t.ipv6.dport = tcp->dest;
    struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &t, sizeof(t.ipv6), CDN_CURRENT_NETNS, 0);
    if (!sk)
        return 0;
    bpf_sk_release(sk);
    return 1;
}

// service_orphan_verdict：服务端口上非纯 SYN 的 TCP 包（ACK / PSH-ACK / RST / FIN / SYN-ACK）
// 是否属于本机某条连接。sk 为 skc_lookup 的结果（可为 NULL），函数负责 release。返回 1 = 丢。
//
//   查不到 socket       → 端口上根本没监听，内核也只会回 RST，丢。
//   非 LISTEN 状态      → 已建立 / 半连接(NEW_SYN_RECV) / TIME_WAIT 等真实连接，放行。
//   只命中 LISTEN       → 没有属于它的连接。唯一的合法情形是 syncookie 握手的第三个包
//                          （内核在 SYN 队列溢出时不建半连接）：带 ACK、不带 SYN/RST/FIN，
//                          可能带数据。这类包交给 bpf_tcp_check_syncookie，返回 0 才放行。
//                          RST/FIN/SYN-ACK/其余 ACK 一律丢 —— 否则内核逐包回 RST 占满上行。
//
// check_syncookie 传固定头长（sizeof）而不是 ihl*4 / doff*4：内核只读固定头里的地址、端口、
// 序号，常量长度也让 verifier 不必证明变长范围。内核在最近没发过 cookie、或
// net.ipv4.tcp_syncookies=0 时返回非 0 —— 那两种情况下本来就不存在 cookie 握手，丢是对的。
// 需要内核 5.3+（XDP 里的 tcp_check_syncookie）。
static __always_inline
int service_orphan_verdict(struct bpf_sock *sk, void *iph, __u32 iph_len, struct tcphdr *tcp) {
    if (!sk)
        return 1;
    if (sk->state != BPF_TCP_LISTEN) {
        bpf_sk_release(sk);
        return 0;
    }
    int drop = 1;
    if (tcp->ack && !tcp->syn && !tcp->rst && !tcp->fin &&
        bpf_tcp_check_syncookie(sk, iph, iph_len, tcp, sizeof(*tcp)) == 0)
        drop = 0;
    bpf_sk_release(sk);
    return drop;
}

static __always_inline
int service_orphan_drop4(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr *tcp) {
    struct bpf_sock_tuple t = {};
    t.ipv4.saddr = ip->saddr;
    t.ipv4.daddr = ip->daddr;
    t.ipv4.sport = tcp->source;
    t.ipv4.dport = tcp->dest;
    struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &t, sizeof(t.ipv4), CDN_CURRENT_NETNS, 0);
    return service_orphan_verdict(sk, ip, sizeof(*ip), tcp);
}

static __always_inline
int service_orphan_drop6(struct xdp_md *ctx, struct ipv6hdr *ip6, struct tcphdr *tcp) {
    struct bpf_sock_tuple t = {};
    __builtin_memcpy(t.ipv6.saddr, &ip6->saddr, 16);
    __builtin_memcpy(t.ipv6.daddr, &ip6->daddr, 16);
    t.ipv6.sport = tcp->source;
    t.ipv6.dport = tcp->dest;
    struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &t, sizeof(t.ipv6), CDN_CURRENT_NETNS, 0);
    return service_orphan_verdict(sk, ip6, sizeof(*ip6), tcp);
}

// conn_check 统计单 IP 的新建连接数（每个 SYN +1，每 60 秒减半），超过 conn_limit 则 DROP。
// 注意它不是真正的半开连接数：握手完成不会减，实际约等于每 IP 每分钟 conn_limit~2×conn_limit 个新连接。
//
// 衰减必须按"距上次衰减多久"算，不能按"距上次收包多久"算：持续攻击下每个 SYN 都会
// 刷新 last_update，"60 秒没收包才衰减"的条件永远不满足，count 只增不减。
// 用独立的 decay_start 记录窗口起点，每 60 秒必定减半一次。
static __always_inline
int conn_check(__u32 limit, struct conn_entry *entry) {
    __u64 now = bpf_ktime_get_ns();
    __u64 decay_window = 60000000000ULL; // 60s

    if (!entry)
        return 0;

    if (entry->decay_start == 0)
        entry->decay_start = now;

    // 可能跨过多个衰减窗口。每次最多减半 6 次（verifier 要求循环有界）；空闲更久的
    // 条目剩余的衰减在下一个包到来时继续，count 是 __u32，衰减不完全也只是暂时偏高。
    if (now - entry->decay_start >= decay_window) {
        __u64 elapsed = now - entry->decay_start;
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (elapsed < decay_window)
                break;
            entry->count >>= 1;
            elapsed -= decay_window;
        }
        entry->decay_start = now - elapsed;
    }

    entry->count++;
    entry->last_update = now;
    if (limit > 0 && entry->count > limit)
        return 1;
    return 0;
}

// is_bare_ack 判断这是否为一个**不携带数据**的纯 ACK 包。
// payload_len = L3 负载长度 - TCP 头。取不到长度（截断包）时保守返回 0。
static __always_inline
int is_bare_ack(void *data_end, struct tcphdr *tcp, __u32 l3_payload_len) {
    if ((void *)(tcp + 1) > data_end)
        return 0;
    __u32 doff = (__u32)tcp->doff * 4;
    if (doff < 20 || doff > l3_payload_len)
        return 0;
    return (l3_payload_len - doff) == 0;
}

// is_bogon_v4 判断源地址是否**不可能**属于一台真实的互联网主机。
//
// 只收录两段，且刻意收得很窄：
//   127.0.0.0/8  环回。
//   224.0.0.0/3  组播 + Class E + 广播。
// 以下看着像 bogon 但**不能丢**：169.254/16（云元数据服务返回包）、0/8（DHCP）、
// 100.64/10（CGNAT，后面是真实用户）、RFC1918（内网回源/前置 LB）。
static __always_inline
int is_bogon_v4(__u32 saddr_be) {
    __u8 first = (__u8)(bpf_ntohl(saddr_be) >> 24);
    if (first == 127)
        return 1;
    if (first >= 224)
        return 1;
    return 0;
}

// Check if TCP flags are invalid (common attack patterns)
static __always_inline
int has_invalid_tcp_flags(struct tcphdr *tcp) {
    if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst && !tcp->psh && !tcp->urg)
        return 1; // NULL scan
    if (tcp->fin && tcp->psh && tcp->urg)
        return 1; // XMAS scan
    if (tcp->syn && tcp->fin)
        return 1;
    if (tcp->syn && tcp->rst)
        return 1;
    if (tcp->fin && !tcp->ack)
        return 1;
    return 0;
}

// ------------------------
// XDP Program
// ------------------------
SEC("xdp")
int cdn_xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;

    struct stats *s = get_stats();
    if (!s) return XDP_PASS;

    struct xdp_config *cfg = bpf_map_lookup_elem(&xdp_config, &zero);
    if (!cfg || !cfg->enabled)
        goto pass;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass;

    // 剥掉最多两层 VLAN 标签（802.1Q / QinQ）。以前直接看 eth->h_proto，带 VLAN 的网卡
    // （部分云厂商、托管机房的 trunk 口）上所有流量的 h_proto 都是 0x8100，整个 XDP 形同虚设。
    __u16 h_proto = eth->h_proto;
    void *l3 = (void *)(eth + 1);
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr_ *vh = l3;
            if ((void *)(vh + 1) > data_end)
                goto pass;
            h_proto = vh->encap_proto;
            l3 = (void *)(vh + 1);
        }
    }

    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            goto pass;

        struct ipv6_key src6 = {};
        __builtin_memcpy(src6.addr, &ip6->saddr, 16);

        // 0. 白名单快路径
        if (bpf_map_lookup_elem(&whitelist6, &src6))
            goto pass;

        // 0.5 伪造源地址：只丢组播源 ff00::/8。刻意不丢 fe80::/10（NDP/RA 的源地址）。
        if (cfg->bogon_drop && src6.addr[0] == 0xff) {
            __sync_fetch_and_add(&s->dropped_bogon, 1);
            return XDP_DROP;
        }

        // 1. 封禁表快路径
        if (bpf_map_lookup_elem(&blocklist6, &src6)) {
            __sync_fetch_and_add(&s->dropped_blocklist, 1);
            return XDP_DROP;
        }

        // 1.5 区域封禁。位置在人工封禁之后、扩展头解析之前：判定只看 L3 源地址，
        //     所以分片包、带扩展头的包、认不出上层协议的包一样覆盖到，攻击者加一个
        //     空目的选项头并不能绕过它。
        //     例外先判且命中即跳过区域丢包（与七层 Decide 同序），速率限制照常继续。
        {
            struct geo_key6 gk = { .prefixlen = 128 };
            __builtin_memcpy(gk.addr, src6.addr, 16);
            if (!bpf_map_lookup_elem(&geo_exc6, &gk) &&
                bpf_map_lookup_elem(&geo_block6, &gk)) {
                __sync_fetch_and_add(&s->dropped_geo, 1);
                return XDP_DROP;
            }
        }

        // 2. 跳过扩展头，找到真正的上层协议。
        //
        // 以前只看 ip6->nexthdr：攻击者给每个包加一个 8 字节的空目的选项头，nexthdr 就变成
        // 60，SYN/ACK/UDP/ICMP 的限速全部被跳过 —— IPv6 上的限速等于一个参数就能绕过。
        __u8 nexthdr = ip6->nexthdr;
        void *l4 = (void *)(ip6 + 1);
        int frag = 0, frag_later = 0;
        // 扩展头总长，用于从 payload_len 推出上层负载长度（纯 ACK 判断）。
        // 单独累加成标量，而不是事后用 l4 - (ip6+1) 求：两个包指针相减在未开放
        // allow_ptr_leaks 的内核上会被验证器拒绝（"pointer -= pointer prohibited"）。
        __u32 ext_len = 0;
        #pragma unroll
        for (int i = 0; i < IPV6_EXT_MAX; i++) {
            if (nexthdr == IPV6_EXT_HOPOPTS || nexthdr == IPV6_EXT_ROUTING ||
                nexthdr == IPV6_EXT_DSTOPTS) {
                struct ipv6_opt_hdr_ *oh = l4;
                if ((void *)(oh + 1) > data_end)
                    goto v6_other;
                __u32 hl = ((__u32)oh->hdrlen + 1) * 8;
                nexthdr = oh->nexthdr;
                l4 = l4 + hl;
                ext_len += hl;
            } else if (nexthdr == IPV6_EXT_FRAGMENT) {
                struct ipv6_frag_hdr_ *fh = l4;
                if ((void *)(fh + 1) > data_end)
                    goto v6_other;
                frag = 1;
                if (bpf_ntohs(fh->frag_off) & 0xFFF8)
                    frag_later = 1;
                nexthdr = fh->nexthdr;
                l4 = (void *)(fh + 1);
                ext_len += sizeof(*fh);
            }
        }
        // 扩展头层数超过上限：无法定位上层协议，只做 PPS 限速。
        if (nexthdr == IPV6_EXT_HOPOPTS || nexthdr == IPV6_EXT_ROUTING ||
            nexthdr == IPV6_EXT_DSTOPTS || nexthdr == IPV6_EXT_FRAGMENT)
            goto v6_other;

        if (frag && nexthdr == IPPROTO_TCP && cfg->fragment_drop) {
            __sync_fetch_and_add(&s->dropped_fragment, 1);
            return XDP_DROP;
        }
        // 非首片不含上层协议头，l4 指向的是载荷数据，不能按 TCP/UDP 头解析。
        if (frag_later)
            goto v6_other;

        if (nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                goto v6_other;

            __u16 dport6 = bpf_ntohs(tcp->dest);

            // 服务端口白名单，只对纯 SYN 生效（理由见 IPv4 分支）。
            if (cfg->port_guard && tcp->syn && !tcp->ack) {
                __u32 dk6 = dport6;
                if (!bpf_map_lookup_elem(&service_ports, &dk6)) {
                    __sync_fetch_and_add(&s->dropped_invalid_packet, 1);
                    return XDP_DROP;
                }
            }

            if (cfg->invalid_flags_drop && has_invalid_tcp_flags(tcp)) {
                __sync_fetch_and_add(&s->dropped_invalid_flags, 1);
                return XDP_DROP;
            }

            // 以下 per-IP 限速只统计发往本机服务端口的包（见文件头的回源说明）。
            // 非服务端口只做无主连接检查（理由见 IPv4 分支）。
            if (!is_service_port(dport6)) {
                if (cfg->orphan_tcp_drop && !(tcp->syn && !tcp->ack) &&
                    !tcp_has_socket6(ctx, ip6, tcp)) {
                    __sync_fetch_and_add(&s->dropped_orphan_tcp, 1);
                    return XDP_DROP;
                }
                goto pass;
            }

            // 服务端口上的无主包（随机源 ACK/RST/FIN 洪水），理由见 IPv4 分支。
            if (cfg->service_orphan_drop && !(tcp->syn && !tcp->ack) &&
                service_orphan_drop6(ctx, ip6, tcp)) {
                __sync_fetch_and_add(&s->dropped_service_orphan, 1);
                return XDP_DROP;
            }

            if (rate_check6(&src6, &pps_rate6, cfg->pps_limit)) {
                __sync_fetch_and_add(&s->dropped_pps, 1);
                return XDP_DROP;
            }

            if (tcp->syn && !tcp->ack) {
                if (rate_check6(&src6, &syn_rate6, cfg->syn_limit)) {
                    __sync_fetch_and_add(&s->dropped_syn_flood, 1);
                    return XDP_DROP;
                }
                if (cpu_syn_exceeded(cfg->cpu_syn_limit)) {
                    __sync_fetch_and_add(&s->dropped_syn_flood, 1);
                    return XDP_DROP;
                }
            }

            if (tcp->rst && rate_check6(&src6, &tcp_rst_rate6, cfg->tcp_rst_limit)) {
                __sync_fetch_and_add(&s->dropped_tcp_rst, 1);
                return XDP_DROP;
            }

            if (tcp->fin && rate_check6(&src6, &tcp_fin_rate6, cfg->fin_limit)) {
                __sync_fetch_and_add(&s->dropped_fin_flood, 1);
                return XDP_DROP;
            }

            // ACK flood（只算纯 ACK）。上层负载长度 = payload_len - 扩展头总长。
            if (tcp->ack && !tcp->syn && !tcp->fin && !tcp->rst && cfg->ack_limit > 0) {
                __u32 pl6 = bpf_ntohs(ip6->payload_len);
                if (pl6 >= ext_len && is_bare_ack(data_end, tcp, pl6 - ext_len)) {
                    if (rate_check6(&src6, &ack_rate6, cfg->ack_limit)) {
                        __sync_fetch_and_add(&s->dropped_ack_flood, 1);
                        return XDP_DROP;
                    }
                }
            }

            goto pass;
        }

        if (nexthdr == IPPROTO_UDP) {
            if (rate_check6(&src6, &udp_rate6, cfg->udp_limit)) {
                __sync_fetch_and_add(&s->dropped_udp_flood, 1);
                return XDP_DROP;
            }
            goto v6_other;
        }

        if (nexthdr == IPPROTO_ICMPV6) {
            __u8 *icmp6_type = l4;
            if ((void *)(icmp6_type + 1) > data_end)
                goto v6_other;
            __u8 t6 = *icmp6_type;
            // NDP（133-137）且 hop limit = 255：RFC 4861 要求 NDP 包 hop limit 必须是 255，
            // 经过任何路由器都会减 1，所以这保证了来自同一链路的邻居。不限速：丢了 NDP
            // 节点的 IPv6 直接断网，而能发这种包的只有同网段主机。
            if (t6 >= 133 && t6 <= 137 && ip6->hop_limit == 255)
                goto pass;
            __u64 lim6 = cfg->icmp_limit;
            // 差错报文（1-4，含 2 = Packet Too Big）：IPv6 路由器不分片，PMTUD 完全依赖
            // Packet Too Big，丢了大包连接直接卡死。放宽 10 倍但不豁免。
            if (t6 >= 1 && t6 <= 4)
                lim6 = lim6 * 10;
            if (rate_check6(&src6, &icmp_rate6, lim6)) {
                __sync_fetch_and_add(&s->dropped_icmp_flood, 1);
                return XDP_DROP;
            }
            goto v6_other;
        }

v6_other:
        // 非 TCP / 无法解析的 IPv6 包：统一过 per-IP PPS 限速。
        if (rate_check6(&src6, &pps_rate6, cfg->pps_limit)) {
            __sync_fetch_and_add(&s->dropped_pps, 1);
            return XDP_DROP;
        }
        goto pass;
    }

    // Only process IPv4 packets beyond this point
    if (h_proto != bpf_htons(ETH_P_IP))
        goto pass;

    struct iphdr *ip = l3;
    if ((void *)(ip + 1) > data_end)
        goto pass;

    if (ip->version != 4 || ip->ihl < 5)
        goto pass;

    __u32 src_ip = ip->saddr;

    // 0. Whitelist check (fast path - bypass all checks)
    if (bpf_map_lookup_elem(&whitelist, &src_ip))
        goto pass;

    // 0.5 伪造源地址：放在**所有速率统计和封禁表之前**，否则它们会挤满 LRU 速率表、
    // 把真实攻击源的计数挤出去。放在白名单之后，保留人工覆盖的余地。
    if (cfg->bogon_drop && is_bogon_v4(src_ip)) {
        __sync_fetch_and_add(&s->dropped_bogon, 1);
        return XDP_DROP;
    }

    // 1. Blocklist check (fast path)
    if (bpf_map_lookup_elem(&blocklist, &src_ip)) {
        __sync_fetch_and_add(&s->dropped_blocklist, 1);
        return XDP_DROP;
    }

    // 1.5 区域封禁（LPM 最长前缀匹配）。与 IPv6 分支同序同理由：人工封禁优先，例外先判，
    //     分片包也照样覆盖。代价是每个 IPv4 包多两次 trie 查找——两棵树都空着的时候，
    //     一次查找就是根节点无子树，成本可以忽略，所以没配区域规则的节点不必再加开关位。
    {
        struct geo_key4 gk = {
            .prefixlen = 32,
            .addr = src_ip, // 网络序字节直接进键，不做任何主机序转换
        };
        if (!bpf_map_lookup_elem(&geo_exc4, &gk) &&
            bpf_map_lookup_elem(&geo_block4, &gk)) {
            __sync_fetch_and_add(&s->dropped_geo, 1);
            return XDP_DROP;
        }
    }

    __u8 protocol = ip->protocol;

    // 2. 分片。只丢 TCP 分片（见 xdp_config.fragment_drop）。以前一律丢：路径 MTU 较小时
    //    的大 ping、EDNS 大包 DNS 响应都会被丢，且这些场景排查起来毫无头绪。
    //    非首片（offset > 0）不含上层协议头，不能按 TCP/UDP/ICMP 头解析，只走 PPS。
    {
        __u16 frag_off = bpf_ntohs(ip->frag_off);
        if ((frag_off & 0x2000) || (frag_off & 0x1FFF)) {
            if (protocol == IPPROTO_TCP && cfg->fragment_drop) {
                __sync_fetch_and_add(&s->dropped_fragment, 1);
                return XDP_DROP;
            }
            if (frag_off & 0x1FFF)
                goto v4_other;
        }
    }

    // 3. Protocol-specific protection
    switch (protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end)
                goto v4_other;

            __u16 dport = bpf_ntohs(tcp->dest);

            // 服务端口白名单：只对「入站新连接」= 纯 SYN 包生效。
            // 绝不能对所有入站包生效：源站回给边缘的 SYN-ACK 和后续数据包，目的端口是
            // 边缘发起连接时用的临时端口，永远不在 service_ports 里 —— 一律按 dport 过滤
            // 会让回源 100% 失败，站点全站 504 而源站侧完全正常。
            if (cfg->port_guard && tcp->syn && !tcp->ack) {
                __u32 dk = dport;
                if (!bpf_map_lookup_elem(&service_ports, &dk)) {
                    __sync_fetch_and_add(&s->dropped_invalid_packet, 1);
                    return XDP_DROP;
                }
            }

            if (cfg->invalid_flags_drop && has_invalid_tcp_flags(tcp)) {
                __sync_fetch_and_add(&s->dropped_invalid_flags, 1);
                return XDP_DROP;
            }

            // 以下所有 per-IP 限速只统计发往本机服务端口的包。
            //
            // 以前 RST/FIN 限速对所有 TCP 包生效：源站在高负载下批量关闭/重置回源连接时，
            // 源站 IP 的 RST/FIN 很容易超过 100/s，被丢的 RST/FIN 让边缘的回源连接挂到
            // 超时。纯 ACK 同理：大文件上传时源站回的纯 ACK 全记在源站 IP 上。
            //
            // 非服务端口唯一的检查：无主连接（TCP 反射）。实测攻击形态是大量真实 Web 服务器
            // 从 80/443/8443 发来纯 ACK / SYN-ACK，目的端口是本机随机高位端口，内核对每个
            // 回一个 RST，入站多少出站就多少，100M 上行先被打满。本机没有对应 socket 的包
            // 在这里丢掉，内核就不会回 RST。纯 SYN 不在此列（新连接归 port_guard 管）。
            if (!is_service_port(dport)) {
                if (cfg->orphan_tcp_drop && !(tcp->syn && !tcp->ack) &&
                    !tcp_has_socket4(ctx, ip, tcp)) {
                    __sync_fetch_and_add(&s->dropped_orphan_tcp, 1);
                    return XDP_DROP;
                }
                goto pass;
            }

            // 服务端口上的无主包：随机源 ACK / PSH-ACK / RST / FIN 洪水每包换一个源，per-IP
            // 限速碰不到阈值，内核却对每个包回 RST。放在 per-IP 限速之前，免得这些一次性
            // 源地址把速率表里真实攻击源的条目挤掉。纯 SYN 不在此列（新连接走 SYN 限速）。
            if (cfg->service_orphan_drop && !(tcp->syn && !tcp->ack) &&
                service_orphan_drop4(ctx, ip, tcp)) {
                __sync_fetch_and_add(&s->dropped_service_orphan, 1);
                return XDP_DROP;
            }

            if (rate_check(src_ip, &pps_rate, cfg->pps_limit)) {
                __sync_fetch_and_add(&s->dropped_pps, 1);
                return XDP_DROP;
            }

            // SYN flood protection
            if (tcp->syn && !tcp->ack) {
                if (rate_check(src_ip, &syn_rate, cfg->syn_limit)) {
                    __sync_fetch_and_add(&s->dropped_syn_flood, 1);
                    return XDP_DROP;
                }

                // Connection limit check
                struct conn_entry *conn = bpf_map_lookup_elem(&conn_rate, &src_ip);
                if (conn) {
                    if (conn_check(cfg->conn_limit, conn)) {
                        __sync_fetch_and_add(&s->dropped_conn_limit, 1);
                        return XDP_DROP;
                    }
                } else {
                    __u64 now = bpf_ktime_get_ns();
                    struct conn_entry new_conn = {
                        .count = 1,
                        ._pad = 0,
                        .last_update = now,
                        .decay_start = now,
                    };
                    bpf_map_update_elem(&conn_rate, &src_ip, &new_conn, BPF_ANY);
                }

                // 最后一道：每 CPU 新连接总量。放在 per-IP 检查之后，已经被 per-IP 规则
                // 丢掉的包不占这份额度。
                if (cpu_syn_exceeded(cfg->cpu_syn_limit)) {
                    __sync_fetch_and_add(&s->dropped_syn_flood, 1);
                    return XDP_DROP;
                }
            }

            if (tcp->rst && rate_check(src_ip, &tcp_rst_rate, cfg->tcp_rst_limit)) {
                __sync_fetch_and_add(&s->dropped_tcp_rst, 1);
                return XDP_DROP;
            }

            if (tcp->fin && rate_check(src_ip, &tcp_fin_rate, cfg->fin_limit)) {
                __sync_fetch_and_add(&s->dropped_fin_flood, 1);
                return XDP_DROP;
            }

            // ACK flood protection: 只对**不携带数据**的纯 ACK 计数（见 is_bare_ack）。
            if (tcp->ack && !tcp->syn && !tcp->fin && !tcp->rst && cfg->ack_limit > 0) {
                __u32 ip_hdr_len = ip->ihl * 4;
                __u32 tot_len = bpf_ntohs(ip->tot_len);
                if (tot_len >= ip_hdr_len &&
                    is_bare_ack(data_end, tcp, tot_len - ip_hdr_len)) {
                    if (rate_check(src_ip, &ack_rate, cfg->ack_limit)) {
                        __sync_fetch_and_add(&s->dropped_ack_flood, 1);
                        return XDP_DROP;
                    }
                }
            }

            // PSH-ACK guard（已限定服务端口）：只看 conn_rate 里「有没有条目」、不看 count ——
            // conn_check 每 60 秒把 count 减半，长连接几分钟后 count 就归零。
            if (cfg->psh_ack_guard && tcp->psh && tcp->ack && !tcp->syn) {
                if (!bpf_map_lookup_elem(&conn_rate, &src_ip)) {
                    __sync_fetch_and_add(&s->dropped_psh_ack_guard, 1);
                    return XDP_DROP;
                }
            }

            goto pass;
        }

        case IPPROTO_UDP: {
            struct udphdr *udp = (void *)ip + (ip->ihl * 4);
            if ((void *)(udp + 1) > data_end)
                goto v4_other;

            __u16 udport = bpf_ntohs(udp->dest);
            __u16 usport = bpf_ntohs(udp->source);

            // DNS amplification protection (port 53)
            if ((udport == 53 || usport == 53) &&
                rate_check(src_ip, &udp_dns_rate, cfg->udp_dns_limit)) {
                __sync_fetch_and_add(&s->dropped_dns_amp, 1);
                return XDP_DROP;
            }

            if (rate_check(src_ip, &udp_rate, cfg->udp_limit)) {
                __sync_fetch_and_add(&s->dropped_udp_flood, 1);
                return XDP_DROP;
            }

            goto v4_other;
        }

        case IPPROTO_ICMP: {
            __u8 *icmp_type = (void *)ip + (ip->ihl * 4);
            if ((void *)(icmp_type + 1) > data_end)
                goto v4_other;
            __u64 lim = cfg->icmp_limit;
            // 差错报文（3 目的不可达 —— 含 PMTUD 的 "需要分片"、11 超时、12 参数问题）
            // 放宽 10 倍：丢了 "需要分片" 会让走小 MTU 路径（PPPoE、隧道）的大包连接卡死。
            __u8 t = *icmp_type;
            if (t == 3 || t == 11 || t == 12)
                lim = lim * 10;
            if (rate_check(src_ip, &icmp_rate, lim)) {
                __sync_fetch_and_add(&s->dropped_icmp_flood, 1);
                return XDP_DROP;
            }
            goto v4_other;
        }

        default:
            goto v4_other;
    }

v4_other:
    // 非 TCP（以及 TCP 分片之外无法解析的包）：统一过 per-IP PPS 限速。
    if (rate_check(src_ip, &pps_rate, cfg->pps_limit)) {
        __sync_fetch_and_add(&s->dropped_pps, 1);
        return XDP_DROP;
    }

pass:
    __sync_fetch_and_add(&s->passed, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
