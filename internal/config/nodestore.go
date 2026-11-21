package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Node struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`    // "https://1.2.3.4:9090"
	IP             string    `json:"ip"`
	Token          string    `json:"token"`
	CertFingerprint string   `json:"cert_fingerprint,omitempty"` // SHA-256 指纹，用于证书钉扎
	ClusterID      string    `json:"cluster_id"`
	CFRecordID     string    `json:"cf_record_id,omitempty"`
	Enabled        bool      `json:"enabled"`
	AddedAt        time.Time `json:"added_at"`
}

type NodeStore struct {
	mu      sync.RWMutex
	path    string
	nodes   map[string]*Node
}

func NewNodeStore(path string) (*NodeStore, error) {
	s := &NodeStore{path: path, nodes: make(map[string]*Node)}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *NodeStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []*Node
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	for _, n := range list {
		s.nodes[n.ID] = n
	}
	return nil
}

func (s *NodeStore) save() error {
	list := make([]*Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		list = append(list, n)
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

func (s *NodeStore) List() []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out
}

func (s *NodeStore) ListEnabled() []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Node
	for _, n := range s.nodes {
		if n.Enabled {
			out = append(out, n)
		}
	}
	return out
}

func (s *NodeStore) Get(id string) (*Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, fmt.Errorf("node %s not found", id)
	}
	return n, nil
}

func (s *NodeStore) Create(n *Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n.ID = uuid.New().String()
	n.AddedAt = time.Now()
	s.nodes[n.ID] = n
	return s.save()
}

// CreateWithID 以调用方给定的 ID 创建节点，供自动注册使用：边缘节点把自己的 node_id
// 落盘，重启后凭它找回同一条记录。Create 会重新生成 ID，用它的话边缘上报的 ID 永远
// 对不上，每次重启都多一个重复节点，心跳也一直 not_found。
func (s *NodeStore) CreateWithID(n *Node) error {
	if n.ID == "" {
		return fmt.Errorf("node id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nodes[n.ID]; ok {
		return fmt.Errorf("node %s already exists", n.ID)
	}
	if n.AddedAt.IsZero() {
		n.AddedAt = time.Now()
	}
	s.nodes[n.ID] = n
	return s.save()
}

func (s *NodeStore) Update(n *Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nodes[n.ID]; !ok {
		return fmt.Errorf("node %s not found", n.ID)
	}
	s.nodes[n.ID] = n
	return s.save()
}

func (s *NodeStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.nodes[id]; !ok {
		return fmt.Errorf("node %s not found", id)
	}
	delete(s.nodes, id)
	return s.save()
}

// ListByCluster 获取指定集群的所有节点
func (s *NodeStore) ListByCluster(clusterID string) []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Node
	for _, n := range s.nodes {
		if n.ClusterID == clusterID {
			out = append(out, n)
		}
	}
	return out
}
