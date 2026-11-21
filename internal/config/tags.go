package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type TagStore struct {
	path string
	mu   sync.RWMutex
}

func NewTagStore(dataDir string) *TagStore {
	return &TagStore{
		path: filepath.Join(dataDir, "tags.json"),
	}
}

func (s *TagStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return []string{}
	}

	var tags []string
	if err := json.Unmarshal(data, &tags); err != nil {
		return []string{}
	}
	return tags
}

func (s *TagStore) Add(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tags := s.unsafeList()
	for _, t := range tags {
		if t == tag {
			return nil // 已存在，不重复添加
		}
	}
	tags = append(tags, tag)
	return s.unsaveSave(tags)
}

func (s *TagStore) Delete(tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tags := s.unsafeList()
	newTags := []string{}
	for _, t := range tags {
		if t != tag {
			newTags = append(newTags, t)
		}
	}
	return s.unsaveSave(newTags)
}

func (s *TagStore) unsafeList() []string {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return []string{}
	}
	var tags []string
	if err := json.Unmarshal(data, &tags); err != nil {
		return []string{}
	}
	return tags
}

func (s *TagStore) unsaveSave(tags []string) error {
	data, err := json.MarshalIndent(tags, "", "  ")
	if err != nil {
		return err
	}
	// 原子写入：先写 .tmp 再 rename，避免崩溃时损坏标签文件。
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
