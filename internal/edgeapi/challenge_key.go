package edgeapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"cdn/internal/waf"
)

// LoadChallengeKey 设置 CC 挑战签名密钥的存档路径并加载。
//
// 存档存在：直接用（主控下发过的部署级密钥，重启后各节点仍互认）。
// 存档不存在：生成一把本机随机密钥并落盘。此时本节点签发的凭证其它节点不认，
// 用户换节点要重新验证一次，但绝不会退回任何可预测的密钥；主控下发后自动统一。
// 在启动 HTTP 服务前调用。
func (h *Handler) LoadChallengeKey(path string) {
	h.challengeKeyPath = path
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err == nil {
		secret, perr := waf.ParseChallengeSecret(string(data))
		if perr == nil {
			if serr := waf.SetChallengeSecret(secret); serr == nil {
				log.Printf("CC challenge key loaded from %s (key_id=%s)", path, waf.ChallengeKeyID())
				return
			}
		}
		log.Printf("CC challenge key: %s is corrupt (%v), generating a new local key", path, perr)
	} else if !os.IsNotExist(err) {
		// 读不了（权限等）时不覆盖文件，只用进程内随机密钥，等主控下发。
		log.Printf("CC challenge key: read %s: %v (using per-process random key until master pushes one)", path, err)
		return
	}

	buf := make([]byte, waf.MinChallengeSecretLen)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("CC challenge key: generate: %v (using per-process random key)", err)
		return
	}
	if err := writeSecretAtomic(path, hex.EncodeToString(buf)); err != nil {
		log.Printf("CC challenge key: persist %s: %v", path, err)
	}
	_ = waf.SetChallengeSecret(buf)
	log.Printf("CC challenge key: no deployment key yet, using local key_id=%s (cookies are node-local until the master pushes its key)", waf.ChallengeKeyID())
}

// setChallengeKey 接收主控下发的部署级密钥：POST /edge/cc/challenge-key {"secret":"<hex>"}。
// 先落盘再生效：落盘失败直接报错，避免「内存里换了、重启又变回旧钥」的不一致。
func (h *Handler) setChallengeKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	secret, err := waf.ParseChallengeSecret(body.Secret)
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.challengeKeyPath != "" {
		if err := writeSecretAtomic(h.challengeKeyPath, hex.EncodeToString(secret)); err != nil {
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "persist: " + err.Error()})
			return
		}
	}
	prev := waf.ChallengeKeyID()
	if err := waf.SetChallengeSecret(secret); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if id := waf.ChallengeKeyID(); id != prev {
		log.Printf("CC challenge key updated by master: key_id %s -> %s", prev, id)
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok", "key_id": waf.ChallengeKeyID()})
}

// getChallengeKeyID 只返回密钥指纹，绝不返回密钥本身。
func (h *Handler) getChallengeKeyID(w http.ResponseWriter, _ *http.Request) {
	jsonResp(w, http.StatusOK, map[string]string{"key_id": waf.ChallengeKeyID()})
}

func writeSecretAtomic(path, secret string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(secret+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
