package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Store struct {
	mu      sync.RWMutex
	dataDir string
	cache   map[string]*Domain
}

func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{dataDir: dataDir, cache: make(map[string]*Domain)}
	if err := s.loadAll(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadAll() error {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return fmt.Errorf("read data dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		d, err := s.readFile(filepath.Join(s.dataDir, e.Name()))
		if err != nil {
			return err
		}
		s.cache[d.ID] = d
	}
	return nil
}

func (s *Store) readFile(path string) (*Domain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read domain file %s: %w", path, err)
	}
	var d Domain
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse domain file %s: %w", path, err)
	}
	return &d, nil
}

func (s *Store) writeFile(d *Domain) error {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, d.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write tmp file: %w", err)
	}
	return os.Rename(tmp, path) // atomic on Linux
}

func (s *Store) List() []*Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Domain, 0, len(s.cache))
	for _, d := range s.cache {
		out = append(out, cloneDomain(d))
	}
	return out
}

func (s *Store) Get(id string) (*Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.cache[id]
	if !ok {
		return nil, fmt.Errorf("domain %s not found", id)
	}
	return cloneDomain(d), nil
}

func (s *Store) GetByDomain(domain string) (*Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.cache {
		if d.Domain == domain {
			return cloneDomain(d), nil
		}
	}
	return nil, fmt.Errorf("domain %s not found", domain)
}

// cloneDomain 返回 Domain 的深拷贝，切片字段单独分配，避免调用方修改影响缓存。
func cloneDomain(d *Domain) *Domain {
	cp := *d
	if d.Upstreams != nil {
		cp.Upstreams = make([]Upstream, len(d.Upstreams))
		copy(cp.Upstreams, d.Upstreams)
	}
	if d.CacheRules != nil {
		cp.CacheRules = make([]CacheRule, len(d.CacheRules))
		for i, r := range d.CacheRules {
			cr := r
			if r.Extensions != nil {
				cr.Extensions = make([]string, len(r.Extensions))
				copy(cr.Extensions, r.Extensions)
			}
			cp.CacheRules[i] = cr
		}
	}
	return &cp
}

func (s *Store) Create(d *Domain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d.ID = uuid.New().String()
	d.CreatedAt = time.Now()
	d.UpdatedAt = time.Now()
	if err := s.writeFile(d); err != nil {
		return err
	}
	s.cache[d.ID] = cloneDomain(d)
	return nil
}

func (s *Store) Update(d *Domain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[d.ID]; !ok {
		return fmt.Errorf("domain %s not found", d.ID)
	}
	d.UpdatedAt = time.Now()
	if err := s.writeFile(d); err != nil {
		return err
	}
	s.cache[d.ID] = cloneDomain(d)
	return nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[id]; !ok {
		return fmt.Errorf("domain %s not found", id)
	}
	path := filepath.Join(s.dataDir, id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(s.cache, id)
	return nil
}
