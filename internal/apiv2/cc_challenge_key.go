package apiv2

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cdn/internal/config"
	"cdn/internal/master"
)

// ccChallengeSecretFile 是本部署的 CC 挑战凭证签名密钥（hex，32 字节随机数）。主控首次启动
// 自动生成，下发给所有边缘节点，使同一部署的节点互认挑战 Cookie；只拿到二进制的人算不出它。
const ccChallengeSecretFile = "/etc/cdnpanel/cc_challenge.secret"

// ccChallengeKeyResyncInterval 定期重推：覆盖「主控启动时节点不在线」「边缘重装后存档丢失
// （节点先用本机随机密钥顶着）」等情况。推送幂等，密钥不变时边缘什么都不做。
const ccChallengeKeyResyncInterval = 10 * time.Minute

// loadOrCreateCCSecret 读取密钥，不存在则生成并以 0600 原子落盘。
func loadOrCreateCCSecret(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			return s, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(secret+"\n"), 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return secret, nil
}

// startCCChallengeKeySync 确保密钥存在，启动后推一次，之后每 ccChallengeKeyResyncInterval 重推
// 给所有代理的已启用节点。节点新接入时 onboardNode 也会单独补发一次。
func startCCChallengeKeySync(db *sql.DB, pusher *master.Pusher) {
	if db == nil || pusher == nil {
		return
	}
	secret, err := loadOrCreateCCSecret(ccChallengeSecretFile)
	if err != nil {
		log.Printf("[CCKey] load/create %s failed, CC challenge cookies won't be shared across nodes: %v", ccChallengeSecretFile, err)
		return
	}
	payload := map[string]string{"secret": secret}
	repo := NewNodeRepo(db)
	push := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		nodes, err := allEnabledNodes(ctx, db, repo)
		if err != nil {
			log.Printf("[CCKey] list nodes: %v", err)
			return
		}
		var wg sync.WaitGroup
		for _, n := range nodes {
			wg.Add(1)
			go func(n *config.Node) {
				defer wg.Done()
				if err := pusher.PostToNode(n, "/edge/cc/challenge-key", payload); err != nil {
					log.Printf("[CCKey] push challenge key to node %s (%s) failed: %v", nodeLabel(n), n.Address, err)
				}
			}(n)
		}
		wg.Wait()
	}
	go func() {
		time.Sleep(15 * time.Second) // 等边缘重新注册 / 首批心跳，不和启动迁移抢连接
		push()
		t := time.NewTicker(ccChallengeKeyResyncInterval)
		defer t.Stop()
		for range t.C {
			push()
		}
	}()
}

// allEnabledNodes 跨代理列出全部已启用节点（只供部署级任务使用，比如上面的密钥同步）。
func allEnabledNodes(ctx context.Context, db *sql.DB, repo *NodeRepo) ([]*config.Node, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM nodes WHERE enabled`)
	if err != nil {
		return nil, err
	}
	var tenants []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			tenants = append(tenants, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []*config.Node
	for _, t := range tenants {
		nodes, err := tenantEdgeNodes(ctx, repo, t)
		if err != nil {
			return nil, err
		}
		out = append(out, nodes...)
	}
	return out, nil
}
