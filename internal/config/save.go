package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SaveConfig 原子写入面板配置：临时文件 + rename，0600 权限。
// --init-admin 和安装向导都用这个函数落盘，行为保持一致。
func SaveConfig(cfg *PanelConfig, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
