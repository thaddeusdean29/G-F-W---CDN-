package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

type Client struct {
	apiToken   string
	zoneID     string
	BaseDomain string // e.g. "example.com"
	http       *http.Client
	apiBase    string // 测试时替换为 httptest 地址
}

func NewClient(apiToken, zoneID, baseDomain string) *Client {
	return &Client{
		apiToken:   apiToken,
		zoneID:     zoneID,
		BaseDomain: baseDomain,
		http:       &http.Client{Timeout: 15 * time.Second},
		apiBase:    apiBase,
	}
}

// Enabled 返回是否已配置 Cloudflare 凭据。
func (c *Client) Enabled() bool {
	return c.apiToken != "" && c.zoneID != "" && c.BaseDomain != ""
}

// InZone 判断 name 是否属于当前 zone（BaseDomain 本身或其子域名）。
// 不在 zone 里的用户域名无法由面板代建记录，只能由用户在自己的 DNS 服务商处添加 CNAME。
func (c *Client) InZone(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	base := strings.ToLower(c.BaseDomain)
	return base != "" && (name == base || strings.HasSuffix(name, "."+base))
}

type dnsRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIError 是 Cloudflare 返回 success=false 时的错误，保留 HTTP 状态码供调用方判断「不存在」。
type APIError struct {
	Status  int
	Code    int
	Message string
}

func (e *APIError) Error() string {
	if e.Code == 0 && e.Message == "" {
		return fmt.Sprintf("cloudflare request failed (HTTP %d)", e.Status)
	}
	return fmt.Sprintf("cloudflare error %d: %s", e.Code, e.Message)
}

func isNotFound(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Status == http.StatusNotFound
}

// ClusterSubdomain 返回集群对应的完整域名，如 "cn1.example.com"。
func (c *Client) ClusterSubdomain(clusterName string) string {
	return clusterName + "." + c.BaseDomain
}

// RandomSubdomain 生成一个随机的 6 字符子域名，如 "a1b2c3.example.com"。
func (c *Client) RandomSubdomain() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b) + "." + c.BaseDomain
}

// CreateARecord 为集群子域名创建 A 记录，返回记录 ID。
func (c *Client) CreateARecord(clusterName, ip string) (string, error) {
	return c.createRecord(dnsRecord{
		Type:    "A",
		Name:    c.ClusterSubdomain(clusterName),
		Content: ip,
		TTL:     1,
		Proxied: false,
	})
}

// CreateCNAMERecord 创建灰云 CNAME 记录 name→target，返回记录 ID。
func (c *Client) CreateCNAMERecord(name, target string) (string, error) {
	return c.createRecord(dnsRecord{Type: "CNAME", Name: name, Content: target, TTL: 60})
}

// DeleteRecord 删除指定 ID 的 DNS 记录。
func (c *Client) DeleteRecord(recordID string) error {
	_, err := c.do("DELETE", "/zones/"+c.zoneID+"/dns_records/"+recordID, nil)
	return err
}

// ListARecords 列出集群子域名下所有 A 记录。
func (c *Client) ListARecords(clusterName string) ([]dnsRecord, error) {
	return c.listRecords("A", c.ClusterSubdomain(clusterName))
}

func (c *Client) listRecords(typ, name string) ([]dnsRecord, error) {
	q := url.Values{}
	if typ != "" {
		q.Set("type", typ)
	}
	q.Set("name", name)
	resp, err := c.do("GET", "/zones/"+c.zoneID+"/dns_records?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var records []dnsRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return nil, fmt.Errorf("parse records: %w", err)
	}
	return records, nil
}

func (c *Client) createRecord(rec dnsRecord) (string, error) {
	body, _ := json.Marshal(rec)
	resp, err := c.do("POST", "/zones/"+c.zoneID+"/dns_records", body)
	if err != nil {
		return "", err
	}
	var result dnsRecord
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return result.ID, nil
}

// isNameConflict 判断新建失败是否因为同名记录已存在（81053：同名 A/AAAA/CNAME 已存在；81057/81058：相同记录已存在）。
func isNameConflict(err error) bool {
	e, ok := err.(*APIError)
	return ok && (e.Code == 81053 || e.Code == 81057 || e.Code == 81058)
}

// createOrAdopt 新建记录；若同名记录已存在（面板存的 ID 过期、记录在 CF 后台被手动删过重建过等），
// 接管那条记录并整体覆盖，返回它的 ID。同名的其它 A/AAAA/CNAME 会被删掉——CNAME 不能与它们共存，
// 这些名字都是面板独占管理的。
func (c *Client) createOrAdopt(rec dnsRecord) (string, error) {
	id, err := c.createRecord(rec)
	if err == nil || !isNameConflict(err) {
		return id, err
	}
	existing, lerr := c.listRecords("", rec.Name)
	if lerr != nil {
		return "", fmt.Errorf("%w；查询同名记录失败: %v", err, lerr)
	}
	adopt := ""
	for _, r := range existing {
		if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
			continue
		}
		if adopt == "" {
			adopt = r.ID
			continue
		}
		_ = c.DeleteRecord(r.ID)
	}
	if adopt == "" {
		return "", err
	}
	body, _ := json.Marshal(rec)
	if _, perr := c.do("PUT", "/zones/"+c.zoneID+"/dns_records/"+adopt, body); perr != nil {
		return "", fmt.Errorf("%w；接管同名记录也失败: %v", err, perr)
	}
	return adopt, nil
}

// upsertRecord 按记录 ID 整体覆盖记录；recordID 为空时新建。返回最终记录 ID（可能与输入不同）。
func (c *Client) upsertRecord(recordID string, rec dnsRecord) (string, error) {
	if recordID == "" {
		return c.createOrAdopt(rec)
	}
	return c.overwriteRecord(recordID, rec)
}

// overwriteRecord 用 PUT 整体覆盖一条记录（type 也一起改：切换记录会在不同类型/橙云状态之间切）。
// 只 PATCH content/proxied 而不带 type 时，类型变化会直接被拒；
// PUT 若仍被拒（记录已被手动删掉等），退化为删除后重建（同名记录还在就接管它），返回最终记录 ID（可能与输入不同）。
func (c *Client) overwriteRecord(recordID string, rec dnsRecord) (string, error) {
	body, _ := json.Marshal(rec)
	_, putErr := c.do("PUT", "/zones/"+c.zoneID+"/dns_records/"+recordID, body)
	if putErr == nil {
		return recordID, nil
	}
	_ = c.DeleteRecord(recordID)
	id, err := c.createOrAdopt(rec)
	if err != nil {
		return "", fmt.Errorf("覆盖记录失败: %v；重建也失败: %w", putErr, err)
	}
	return id, nil
}

func (c *Client) do(method, path string, body []byte) (*cfResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	base := c.apiBase
	if base == "" {
		base = apiBase
	}
	req, err := http.NewRequest(method, base+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare request: %w", err)
	}
	defer res.Body.Close()

	var cfResp cfResponse
	if err := json.NewDecoder(res.Body).Decode(&cfResp); err != nil {
		if res.StatusCode >= 400 {
			return nil, &APIError{Status: res.StatusCode}
		}
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !cfResp.Success {
		e := &APIError{Status: res.StatusCode}
		if len(cfResp.Errors) > 0 {
			e.Code, e.Message = cfResp.Errors[0].Code, cfResp.Errors[0].Message
		}
		return nil, e
	}
	return &cfResp, nil
}

// VerifyZone 用当前凭据读取 zone 信息，返回 zone 名称。用于保存凭据前的连通性测试：
// token 无权限、zone_id 不存在都会在这里报错；调用方再检查 BaseDomain 是否属于该 zone。
func (c *Client) VerifyZone() (string, error) {
	resp, err := c.do(http.MethodGet, "/zones/"+url.PathEscape(c.zoneID), nil)
	if err != nil {
		return "", err
	}
	var z struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(resp.Result, &z); err != nil {
		return "", fmt.Errorf("decode zone: %w", err)
	}
	return z.Name, nil
}

// EnsureARecord 确保集群子域名下有一条指向 ip 的灰云 A 记录，返回记录 ID。
// 同一子域名下每个节点各一条 A 记录，所以不能像 createOrAdopt 那样删掉同名的其它记录；
// 只在「相同记录已存在」（面板丢了记录 ID、重装后重新注册等）时接管内容相同的那条。
func (c *Client) EnsureARecord(clusterName, ip string) (string, error) {
	id, err := c.CreateARecord(clusterName, ip)
	if err == nil || !isNameConflict(err) {
		return id, err
	}
	existing, lerr := c.ListARecords(clusterName)
	if lerr != nil {
		return "", fmt.Errorf("%w；查询同名记录失败: %v", err, lerr)
	}
	for _, r := range existing {
		if r.Content == ip {
			if r.Proxied {
				body, _ := json.Marshal(dnsRecord{Type: "A", Name: r.Name, Content: ip, TTL: 1, Proxied: false})
				if _, perr := c.do("PUT", "/zones/"+c.zoneID+"/dns_records/"+r.ID, body); perr != nil {
					return "", fmt.Errorf("接管已有记录失败: %w", perr)
				}
			}
			return r.ID, nil
		}
	}
	return "", err
}

// IsNotFound 判断错误是否为记录不存在（已在 CF 后台被手动删掉等），删除时可当成功处理。
func IsNotFound(err error) bool { return isNotFound(err) }
