package ssl

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Manager struct {
	basePath string
	email    string
}

func NewManager(basePath, email string) *Manager {
	return &Manager{basePath: basePath, email: email}
}

// certDir validates the domain and returns its certificate directory path.
// Rejects any domain containing path separators or ".." traversal sequences.
func (m *Manager) certDir(domain string) (string, error) {
	if strings.Contains(domain, "/") || strings.Contains(domain, "\\") || strings.Contains(domain, "..") {
		return "", fmt.Errorf("invalid domain name: %q", domain)
	}
	dir := filepath.Join(m.basePath, domain)
	// Ensure the resolved path stays inside basePath
	base := filepath.Clean(m.basePath) + string(filepath.Separator)
	if !strings.HasPrefix(dir+string(filepath.Separator), base) {
		return "", fmt.Errorf("domain %q escapes base path", domain)
	}
	return dir, nil
}

func (m *Manager) CertFile(domain string) string {
	dir, err := m.certDir(domain)
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "cert.pem")
}

func (m *Manager) KeyFile(domain string) string {
	dir, err := m.certDir(domain)
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "key.pem")
}

// IssueCertbot runs certbot to obtain a Let's Encrypt certificate.
func (m *Manager) IssueCertbot(domain string) error {
	dir, err := m.certDir(domain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	cmd := exec.Command("certbot", "certonly", "--webroot",
		"-w", "/var/www/acme",
		"--non-interactive", "--agree-tos",
		"--email", m.email,
		"-d", domain,
		"--cert-path", m.CertFile(domain),
		"--key-path", m.KeyFile(domain),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certbot: %s: %w", string(out), err)
	}
	return nil
}

// SaveManual saves manually supplied PEM content to disk after validating the key pair.
func (m *Manager) SaveManual(domain, certPEM, keyPEM string) error {
	dir, err := m.certDir(domain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("invalid cert/key pair: %w", err)
	}
	// 原子写入证书和私钥：先写 .tmp 再 rename，避免 kill -9 时留下半截文件导致
	// Tengine reload 读到损坏的证书后拒绝启动（整个站点下线）。
	certPath := filepath.Join(dir, "cert.pem")
	certTmp := certPath + ".tmp"
	if err := os.WriteFile(certTmp, []byte(certPEM), 0644); err != nil {
		return err
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		return err
	}

	keyPath := filepath.Join(dir, "key.pem")
	keyTmp := keyPath + ".tmp"
	if err := os.WriteFile(keyTmp, []byte(keyPEM), 0600); err != nil {
		return err
	}
	return os.Rename(keyTmp, keyPath)
}

// SaveManualFiles saves uploaded cert and key from io.Reader streams.
func (m *Manager) SaveManualFiles(domain string, certReader, keyReader io.Reader) error {
	certPEM, err := io.ReadAll(certReader)
	if err != nil {
		return err
	}
	keyPEM, err := io.ReadAll(keyReader)
	if err != nil {
		return err
	}
	return m.SaveManual(domain, string(certPEM), string(keyPEM))
}

// Remove deletes certificate files for a domain.
func (m *Manager) Remove(domain string) error {
	dir, err := m.certDir(domain)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
