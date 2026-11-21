package apiv2

// 节点版本可见性：面板能不能说清「这个节点上跑的 cdnedge，和我现在能下发的 cdnedge 是不是同一份」。
//
// 判据只用构建标识（build.sh 用 -X 注入 internal/version.Build，格式 cdn-YYYYMMDD-HHMM），
// 不用语义版本号：这个仓库没有发布流程，版本号只能靠人记得改，而人忘记改的时候面板会谎报
// 「一致」——比显示「未知」危险得多。
//
// 关键取舍：面板不报自己的 version.Build，而是去读同目录那个 cdnedge 文件里真正嵌进去的标识。
// 因为点「重装最新版」下发的就是那个文件；如果只比面板自己的构建号，「面板是新的、cdnedge 没
// 传上去或传坏了」会判成一致，而这正是节点列表最需要暴露的那类事故。文件里读不到就一律「未知」，
// 绝不替一个没核实的事实说好话。

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// buildIDPattern 与 build.sh 里 BUILD_ID 的格式是一对，改一边必须改另一边。
var buildIDPattern = regexp.MustCompile(`cdn-[0-9]{8}-[0-9]{4}`)

const (
	// 版本判定取值，前端按值渲染标签，不再自己复制一份判据（两份定义迟早分叉）。
	versionStateMatch    = "match"    // 节点上的边缘 == 面板准备下发的这份
	versionStateOutdated = "outdated" // 不等：节点跑的是旧构建（或面板换过 cdnedge 后没重装）
	versionStateUnknown  = "unknown"  // 有一边说不清，不猜

	edgeScanChunk = 512 * 1024
	// 滑动拼接时留给下一块的重叠字节数，必须大于最长匹配（"cdn-" + 8 + "-" + 4 = 17 字节），
	// 否则标识正好跨在两块交界处会被漏判 —— 这种漏判随二进制布局出现，看着像偶发故障。
	edgeScanOverlap = 32
	// 拿不到确定答案（文件不在/读失败）后的重试间隔：不缓存失败结论太久，否则把 cdnedge
	// 传上去后要等很久面板才认。
	edgeScanRetryAfter = 60 * time.Second
)

// packageVersionCache 缓存「同目录 cdnedge 的构建标识」。有效结论按 (路径, mtime, 大小) 复用，
// 所以正常轮询每 60 秒只会多一次 os.Stat，不会反复扫 9 MB 文件。
type packageVersionCache struct {
	mu       sync.Mutex
	path     string
	modTime  time.Time
	size     int64
	id       string
	definite bool      // 上次扫到了确定结论（包括"文件在、里面没有标识"）
	nextTry  time.Time // definite=false 时，在此之前不再重试
}

var pkgVersion packageVersionCache

// edgePackageVersion 返回面板同目录 cdnedge 里嵌的构建标识；说不清就返回空串。
func edgePackageVersion() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	path := filepath.Join(filepath.Dir(exe), "cdnedge")

	c := &pkgVersion
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.path != path {
		// 只能逐字段清，不能 *c = packageVersionCache{path: path}：那会把当前正持有的 mu
		// 一起清零，defer 里的 Unlock 变成"解锁未上锁的互斥量"，直接 panic 掉整个面板进程。
		// （11-14 本机真心跳台架第一次跑就撞上了，栈顶就是 edgePackageVersion。）
		c.path, c.id, c.definite = path, "", false
		c.nextTry, c.modTime, c.size = time.Time{}, time.Time{}, 0
	}
	st, err := os.Stat(path)
	if err == nil && c.definite && st.ModTime().Equal(c.modTime) && st.Size() == c.size {
		return c.id
	}
	if !c.definite && time.Now().Before(c.nextTry) {
		return c.id
	}

	id, scanned, serr := readEdgeBuildID(path)
	if serr != nil {
		// id 必须一起清掉：cdnedge 被移走之后这次扫描是失败的，若留着上一次读到的标识，
		// TTL 内的后续请求会走进下面 "return c.id"，拿一个已经不存在的文件的旧标识去判"一致"。
		c.id = ""
		c.definite = false
		if os.IsNotExist(serr) {
			// 文件不在不设冷却：把新版 cdnedge 传上去之后下一个请求就该认出它来，
			// 这里只多一次 open 失败，不是 9 MB 的重扫。
			c.nextTry = time.Time{}
		} else {
			// 读得动但扫失败（权限、IO 错误）才需要限速，别每次轮询都去撞一遍磁盘。
			c.nextTry = time.Now().Add(edgeScanRetryAfter)
			log.Printf("[apiv2 nodes] 扫描 %s 的构建标识失败：%v（节点版本列显示未知）", path, serr)
		}
		return ""
	}
	c.id, c.definite, c.modTime, c.size = id, true, scanned.modTime, scanned.size
	if id == "" {
		log.Printf("[apiv2 nodes] %s 里没有 cdn-YYYYMMDD-HHMM 构建标识：这份 cdnedge 不是 build.sh 出的包，"+
			"节点版本列会显示未知", path)
	}
	return id
}

type scannedFile struct {
	modTime time.Time
	size    int64
}

// readEdgeBuildID 分块流式扫，不把整个二进制读进内存：cdnedge 约 9 MB，节点列表是轮询接口，
// 一次请求凭空多分配 9 MB 会让面板自己的内存曲线难看。
func readEdgeBuildID(path string) (id string, info scannedFile, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", scannedFile{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", scannedFile{}, err
	}
	info = scannedFile{modTime: fi.ModTime(), size: fi.Size()}

	buf := make([]byte, 0, edgeScanChunk+edgeScanOverlap)
	tmp := make([]byte, edgeScanChunk)
	for {
		n, rerr := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if m := buildIDPattern.Find(buf); m != nil {
				return string(m), info, nil
			}
			if len(buf) > edgeScanOverlap {
				buf = append(buf[:0], buf[len(buf)-edgeScanOverlap:]...)
			}
		}
		if rerr == io.EOF {
			return "", info, nil
		}
		if rerr != nil {
			return "", info, rerr
		}
	}
}

// resolveVersionState 把「节点上报的版本」和「面板能下发的版本」算成一个结论。
// 任何一侧说不清都是 unknown —— 宁可让运维去核实，也不给一个没依据的「已是最新」。
// "dev" 是本地 go build、没走 build.sh 的默认值，它俩相等也只说明是同一份开发构建，
// 对客环境里出现就按未知报出来，别标成「一致」让人以为交付包已就位。
func resolveVersionState(nodeVersion, packageVersion string) string {
	if nodeVersion == "" || packageVersion == "" || nodeVersion == "dev" || packageVersion == "dev" {
		return versionStateUnknown
	}
	if nodeVersion == packageVersion {
		return versionStateMatch
	}
	return versionStateOutdated
}
