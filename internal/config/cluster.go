package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Cluster struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	IsPrimary           bool      `json:"is_primary"`          // 是否为主集群
	IsBackup            bool      `json:"is_backup"`           // 是否为备用集群
	IsAutoFailover      bool      `json:"is_auto_failover"`    // 是否启用自动故障转移
	FailoverThreshold   int       `json:"failover_threshold"`  // 触发阈值(0-100)，默认50，表示节点在线率低于此值时切换
	FailoverTargetID    string    `json:"failover_target_id"`  // 故障转移目标集群ID（备用集群的ID）
	FailoverSourceID    string    `json:"failover_source_id"`  // 原主集群ID（从哪个集群切换）
	DefenseCNAME        string    `json:"defense_cname"`       // 高防 CDN 默认 CNAME：域名没单独配置时，故障转移/手动切高防指向它
	Status              string    `json:"status"`              // active | degraded | failed | failover_in_progress | failover_complete
	OnlineNodes         int       `json:"online_nodes"`        // 当前在线节点数
	TotalNodes          int       `json:"total_nodes"`         // 总节点数
	LastCheckTime       time.Time `json:"last_check_time"`     // 最后检查时间
	CreatedAt           time.Time `json:"created_at"`
}

// ClusterStore 集群存储
type ClusterStore struct {
	mu       sync.RWMutex
	path     string
	clusters map[string]*Cluster
}

// NewClusterStore 创建集群存储
func NewClusterStore(path string) (*ClusterStore, error) {
	s := &ClusterStore{path: path, clusters: make(map[string]*Cluster)}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// load 从文件加载
func (s *ClusterStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []*Cluster
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	for _, c := range list {
		s.clusters[c.ID] = c
	}
	return nil
}

// save 保存到文件
func (s *ClusterStore) save() error {
	list := make([]*Cluster, 0, len(s.clusters))
	for _, c := range s.clusters {
		list = append(list, c)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// cloneCluster 返回 Cluster 的副本。Cluster 目前全是值类型字段（string/bool/int/time.Time），
// 浅拷贝即完整拷贝；将来若加入 slice/map 字段，必须在这里单独深拷贝。
func cloneCluster(c *Cluster) *Cluster {
	cp := *c
	return &cp
}

// List 列出所有集群（副本）。
//
// 返回副本而非内部指针：调用方（面板 API handler）拿到后会直接改字段，若共享指针，
// 这些改动会在不持写锁的情况下直接落到 store 内部，与健康检查协程的 UpdateHealthStatus
// 形成数据竞争，也让"改了但没调 Update"的代码看起来正常工作（隐式生效）。
func (s *ClusterStore) List() []*Cluster {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Cluster, 0, len(s.clusters))
	for _, c := range s.clusters {
		out = append(out, cloneCluster(c))
	}
	return out
}

// Get 获取单个集群（副本，理由同 List）。
func (s *ClusterStore) Get(id string) (*Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clusters[id]
	if !ok {
		return nil, fmt.Errorf("cluster %s not found", id)
	}
	return cloneCluster(c), nil
}

// Create 创建集群
func (s *ClusterStore) Create(c *Cluster) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.ID = uuid.New().String()
	c.CreatedAt = time.Now()
	if c.FailoverThreshold == 0 {
		c.FailoverThreshold = 50 // 默认50%
	}
	if c.Status == "" {
		c.Status = "active"
	}
	// 存副本：调用方（clustersHandler.create）在 Create 返回后还会把 c 序列化进响应，
	// 若存的是同一个指针，之后任何对 c 的改动都会不加锁地渗进 store。
	s.clusters[c.ID] = cloneCluster(c)
	return s.save()
}

// Update 写回集群配置。
//
// 健康遥测字段（OnlineNodes/TotalNodes/LastCheckTime）由 UpdateHealthStatus 独占，这里
// 一律保留 store 内的现值，不接受调用方传入：Get/List 现在返回副本，调用方手里的副本从
// 读到写之间可能已被健康检查刷新过，直接整体覆盖会把刚采集到的在线数/检查时间回退成旧值
// （clustersHandler.update 更极端——它用 JSON 新建 Cluster，这三个字段是零值，会把遥测清零，
// 面板上表现为集群在线数突然变 0、最后检查时间变成 0001-01-01）。
//
// ID/CreatedAt 同理属于身份字段，不允许被改写。
//
// Status 不能一律保留（failoverHandler.trigger/cancel 就是要改它），但空串一定不是
// 调用方的本意：Status 是枚举，没有"空"这个合法取值，Create 也会兜底成 active。
// 面板的集群编辑表单 PUT 的是一个不含 status 的完整 Cluster JSON
// （clustersHandler.update 用它新建 Cluster），照抄就会把状态清成空串，面板上
// 表现为集群状态列突然空白，直到下一次健康检查把它写回来。
func (s *ClusterStore) Update(c *Cluster) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.clusters[c.ID]
	if !ok {
		return fmt.Errorf("cluster %s not found", c.ID)
	}
	merged := cloneCluster(c)
	merged.ID = cur.ID
	merged.CreatedAt = cur.CreatedAt
	merged.OnlineNodes = cur.OnlineNodes
	merged.TotalNodes = cur.TotalNodes
	merged.LastCheckTime = cur.LastCheckTime
	if merged.Status == "" {
		merged.Status = cur.Status
	}
	// 同理：阈值 0 不是合法配置，它会让 UpdateHealthStatus 里的"在线率 < 阈值"永不成立，
	// 自动故障转移静默失效。Create 会把 0 兜底成 50，Update 这里保留现值。
	if merged.FailoverThreshold == 0 {
		merged.FailoverThreshold = cur.FailoverThreshold
	}
	s.clusters[c.ID] = merged
	return s.save()
}

// Delete 删除集群
func (s *ClusterStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clusters[id]; !ok {
		return fmt.Errorf("cluster %s not found", id)
	}
	delete(s.clusters, id)
	return s.save()
}

// UpdateHealthStatus 更新集群健康状态
func (s *ClusterStore) UpdateHealthStatus(clusterID string, onlineNodes, totalNodes int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.clusters[clusterID]
	if !ok {
		return
	}

	c.OnlineNodes = onlineNodes
	c.TotalNodes = totalNodes
	c.LastCheckTime = time.Now()

	if totalNodes == 0 {
		c.Status = "active"
		return
	}

	ratio := float64(onlineNodes) / float64(totalNodes) * 100

	switch {
	case ratio >= 90:
		c.Status = "active"
	case ratio >= float64(c.FailoverThreshold):
		c.Status = "degraded"
	default:
		c.Status = "failed"
	}
}

// GetBackupCluster 获取指定主集群的备用集群（自动故障转移开关在主集群上，此处只按关联关系查找）
func (s *ClusterStore) GetBackupCluster(primaryID string) (*Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.clusters {
		if c.FailoverSourceID == primaryID && c.IsBackup {
			return cloneCluster(c), nil
		}
	}
	return nil, fmt.Errorf("no backup cluster for %s", primaryID)
}

// GetActivePrimaryClusters 获取所有活跃的主集群
func (s *ClusterStore) GetActivePrimaryClusters() []*Cluster {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*Cluster
	for _, c := range s.clusters {
		if c.IsPrimary && c.Status != "failed" {
			out = append(out, cloneCluster(c))
		}
	}
	return out
}

// GetAllClustersByFailoverGroup 获取故障转移组中的所有集群
func (s *ClusterStore) GetAllClustersByFailoverGroup(primaryID string) []*Cluster {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*Cluster
	for _, c := range s.clusters {
		if c.ID == primaryID || c.FailoverSourceID == primaryID {
			out = append(out, cloneCluster(c))
		}
	}
	return out
}
// EffectiveDefenseCNAME 返回该域名切到高防时应指向的 CNAME：域名自己配置的优先，否则用集群默认值。
// 返回空串表示没配置高防，不能切。
func EffectiveDefenseCNAME(d *Domain, c *Cluster) string {
	if d != nil && d.DefenseCNAME != "" {
		return d.DefenseCNAME
	}
	if c != nil {
		return c.DefenseCNAME
	}
	return ""
}
