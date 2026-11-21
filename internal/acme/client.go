// Package acme 实现 ACME v2（RFC 8555）的「建号 → 下单 → dns-01 校验 → 签发」流程，只用标准库。
//
// 为什么不用 golang.org/x/crypto/acme：go.mod 里那份 v0.17.0 的 Authorize 仍然 POST 旧语义的
// resource:"new-authz"，而 Let's Encrypt 早已把该端点从 directory 里下线，CreateCert 直接返回
// errPreRFC；autocert 的 order 流程（createOrder/finalizeOrder/AuthzURLs）全是未导出的，而且
// autocert 没有 DNS-01 钩子。面板只需要 dns-01 一种挑战，手写的面积就是「一个账号 + 一次下单」，
// 比依赖一个跟不上 CA 现实的库小。
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProductionDirectory 是 Let's Encrypt 正式环境的 directory URL。
const ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

const (
	// 单次 HTTP 请求超时：下单、取证书都是小请求，卡住就该报错而不是把作业挂着。
	httpPerRequestTimeout = 30 * time.Second
	// 一次请求最多重试一次，专治 badNonce（nonce 是一次性消耗品，被别处用掉就换一个）。
	maxNonceRetry = 1
	// 轮询 CA 状态时，响应没有 Retry-After 就用它。
	defaultPollInterval = 3 * time.Second
	// 等订单进入终态的上限。CA 签发通常几秒。
	orderWaitTimeout = 3 * time.Minute
	// nonce 池上限：CA 每个响应都塞一个新 nonce，攒多了没地方用，留着只会过期。
	maxNoncePool = 16
	// 响应体上限：证书链几十 KB，problem document 几百字节。4 MB 是兜底，防止对端跑飞。
	maxResponseBytes = 4 << 20
)

// Directory 是 CA directory 文档里我们关心的端点。
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

// Error 是 CA 返回的 problem document（application/problem+json）。Type 是 urn，Detail 是人话；
// 两个都留在错误串里，作业失败时前端不用猜。Status 保留 HTTP 码，429（限流）要能和 400 分开。
type Error struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"-"`
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("acme %s (HTTP %d)", e.Type, e.Status)
	}
	return fmt.Sprintf("acme %s: %s", e.Type, e.Detail)
}

// IsBadNonce 判断是否为 RFC 8555 的 badNonce：换个 nonce 重试即可，不是配置错误。
func IsBadNonce(err error) bool {
	var ae *Error
	return errors.As(err, &ae) && strings.HasSuffix(ae.Type, ":badNonce")
}

// Client 代表一个 ACME 账号（持一把 ECDSA P-256 私钥）。
//
// 单个 Client 只能串行使用：nonce 一次性消耗，并发共用会让请求互相把对方的 nonce 用掉，
// 表现是成片 badNonce。所以每次签发新建一个 Client，用完丢弃。
type Client struct {
	key     *ecdsa.PrivateKey
	dir     Directory
	http    *http.Client
	accURL  string
	contact []string

	mu     sync.Mutex
	nonces []string
}

// NewClient 拉取 directory 并绑定账号私钥。directoryURL 为空时用 Let's Encrypt 正式环境。
func NewClient(ctx context.Context, directoryURL string, key *ecdsa.PrivateKey) (*Client, error) {
	if key == nil {
		return nil, errors.New("acme: 缺少账号私钥")
	}
	if directoryURL == "" {
		directoryURL = ProductionDirectory
	}
	c := &Client{key: key, http: &http.Client{Timeout: httpPerRequestTimeout}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme: 连接 CA 失败: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("acme: 读取 directory: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("acme: 读取 directory 得到 HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	// directory 响应里就带一个可用 nonce，省掉一次 newNonce 往返。
	if n := res.Header.Get("Replay-Nonce"); n != "" {
		c.nonces = append(c.nonces, n)
	}
	var dir Directory
	if err := json.Unmarshal(body, &dir); err != nil {
		return nil, fmt.Errorf("acme: directory 不是合法 JSON: %w", err)
	}
	if dir.NewNonce == "" || dir.NewAccount == "" || dir.NewOrder == "" {
		return nil, errors.New("acme: directory 缺少 newNonce/newAccount/newOrder 端点")
	}
	c.dir = dir
	return c, nil
}

// SetAccountURL 复用已存在的账号 URL（调用方从库里读出来喂给它），避免每次重新注册。
// 换 directory（正式 ↔ 测试）时调用方必须丢掉旧 URL，否则会拿着别家 CA 的账号 URL 去请求。
func (c *Client) SetAccountURL(url string) { c.accURL = url }

// AccountURL 返回当前账号 URL，EnsureAccount 之后才有值。
func (c *Client) AccountURL() string { return c.accURL }

// SetContact 设置注册时提交的联系邮箱（形如 "mailto:x@y"，可为空）。只在第一次建号时提交，
// 账号已存在时 CA 会忽略它。面板不靠邮件通知到期（界面显示剩余天数），默认为空。
func (c *Client) SetContact(contact ...string) { c.contact = contact }

// NewAccountKey 生成一把新的账号私钥（P-256）。每个代理各存一把，加密落库。
func NewAccountKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ParseAccountKey / FormatAccountKey 是账号私钥的存取名（PKCS#8 DER）。
func ParseAccountKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("acme: 解析账号私钥: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("acme: 账号私钥不是 ECDSA 密钥")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("acme: 账号私钥不是 P-256 曲线")
	}
	return key, nil
}

func FormatAccountKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("acme: 导出账号私钥: %w", err)
	}
	return der, nil
}

// EnsureAccount 注册账号，或按已存 URL 取回账号。
//
// 存的 URL 失效（换 CA 目录、账号被删）时重新注册一次，而不是让作业卡在废 URL 上。
// 重注册是幂等的：同一把私钥在同一家 CA 只会对应一个账号。
func (c *Client) EnsureAccount(ctx context.Context) error {
	if c.accURL != "" {
		if _, err := c.post(ctx, c.accURL, nil); err == nil {
			return nil
		} else if !isAccountGone(err) {
			return err
		} else {
			c.accURL = ""
		}
	}
	body := map[string]any{"termsOfServiceAgreed": true}
	if len(c.contact) > 0 {
		// 不带 contact 时整个字段必须缺省：CA 对 "contact": null 按 malformed 处理。
		body["contact"] = c.contact
	}
	res, err := c.post(ctx, c.dir.NewAccount, body)
	if err != nil {
		return err
	}
	if res.Location == "" {
		return errors.New("acme: 注册账号后 CA 没返回 Location")
	}
	c.accURL = res.Location
	return nil
}

func isAccountGone(err error) bool {
	var ae *Error
	if !errors.As(err, &ae) {
		return false
	}
	return strings.HasSuffix(ae.Type, ":accountDoesNotExist") || ae.Status == http.StatusNotFound
}

// Order 是一次下单。
type Order struct {
	url       string
	authzURLs []string
	finalize  string
	certURL   string
	notAfter  string
	cause     *Error
	retry     time.Duration

	// Status 是最近一次刷新读到的订单状态（pending / ready / processing / valid / invalid）。
	Status string
	// IDNS 是下单时的域名列表，Finalize 用它生成 CSR（证书 SAN 就是这批名字）。
	IDNS []string
}

// URL 返回订单 URL，只用于日志与错误信息。
func (o *Order) URL() string { return o.url }

// NotAfter 是 CA 在订单文档里声明的证书到期时间（RFC 3339），可能为空；
// 真到期时间以签回来的证书为准。
func (o *Order) NotAfter() string { return o.notAfter }

// OrderDomains 下单，全部域名进同一张证书（SAN）。
func (c *Client) OrderDomains(ctx context.Context, domains []string) (*Order, error) {
	if len(domains) == 0 {
		return nil, errors.New("acme: 下单至少需要一个域名")
	}
	ids := make([]map[string]string, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	res, err := c.post(ctx, c.dir.NewOrder, map[string]any{"identifiers": ids})
	if err != nil {
		return nil, err
	}
	if res.Location == "" {
		return nil, errors.New("acme: 下单后 CA 没返回 Location")
	}
	o := &Order{url: res.Location, IDNS: domains}
	if err := c.refreshOrder(ctx, o); err != nil {
		return nil, err
	}
	return o, nil
}

// Authz 是订单里一条授权（一个域名一条）。
type Authz struct {
	URL    string
	Domain string
	Status string
}

// AuthzPending 返回还需要处理的授权，Valid 返回 CA 已经认过的。
//
// 同域名近期验过时 Let's Encrypt 会复用授权并直接给 valid——这些不该再放一遍 TXT、
// 再发一次挑战（白改 DNS，还多消耗一次校验机会）。ok=false 表示订单已 invalid，
// 调用方必须重新下单：CA 不接受对 invalid 订单再 finalize。
func (c *Client) AuthzPending(ctx context.Context, o *Order) (pending, valid []Authz, ok bool, err error) {
	if err := c.refreshOrder(ctx, o); err != nil {
		return nil, nil, false, err
	}
	if o.Status == "invalid" {
		return nil, nil, false, nil
	}
	for _, u := range o.authzURLs {
		a, _, err := c.fetchAuthz(ctx, u)
		if err != nil {
			return nil, nil, false, err
		}
		item := Authz{URL: u, Domain: a.Identifier.Value, Status: a.Status}
		if a.Status == "valid" {
			valid = append(valid, item)
		} else {
			pending = append(pending, item)
		}
	}
	return pending, valid, true, nil
}

type challengeDoc struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

type authzDoc struct {
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Status     string         `json:"status"`
	Error      *Error         `json:"error"`
	Challenges []challengeDoc `json:"challenges"`
}

func (a *authzDoc) dns() (*challengeDoc, error) {
	for i := range a.Challenges {
		if a.Challenges[i].Type == "dns-01" {
			if a.Challenges[i].Token == "" {
				return nil, fmt.Errorf("acme: %s 的 dns-01 挑战没有 token", a.Identifier.Value)
			}
			return &a.Challenges[i], nil
		}
	}
	return nil, fmt.Errorf("acme: %s 的授权不提供 dns-01 挑战", a.Identifier.Value)
}

// DNS01Record 返回为通过 authz 校验必须放到 DNS 上的那条 TXT。
// 名字固定为 _acme-challenge.<domain>，值是 key authorization 的 base64url(SHA-256)（RFC 8555 §8.4）。
func (c *Client) DNS01Record(ctx context.Context, authzURL string) (domain string, name string, value string, err error) {
	a, _, err := c.fetchAuthz(ctx, authzURL)
	if err != nil {
		return "", "", "", err
	}
	ch, err := a.dns()
	if err != nil {
		return "", "", "", err
	}
	tp, err := AccountThumbprint(c.key)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256([]byte(ch.Token + "." + tp))
	return a.Identifier.Value, "_acme-challenge." + a.Identifier.Value, b64(sum[:]), nil
}

// Accept 告诉 CA「TXT 放好了，开始校验」。CA 立刻去查 DNS，结论要稍后才落到授权文档，
// 所以这里只提交不等待，等待交给 WaitAuthz。
func (c *Client) Accept(ctx context.Context, authzURL string) error {
	a, _, err := c.fetchAuthz(ctx, authzURL)
	if err != nil {
		return err
	}
	ch, err := a.dns()
	if err != nil {
		return err
	}
	// RFC 8555 §7.5.1：挑战响应必须带一个空 key，否则 CA 按 GET 处理。
	_, err = c.post(ctx, ch.URL, map[string]any{"": map[string]any{}})
	return err
}

// WaitAuthz 轮询授权直到 valid 或 invalid，或超时（timeout 传 0 用默认 3 分钟）。
func (c *Client) WaitAuthz(ctx context.Context, authzURL string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = orderWaitTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		a, retry, err := c.fetchAuthz(ctx, authzURL)
		if err != nil {
			return err
		}
		switch a.Status {
		case "valid":
			return nil
		case "invalid":
			if a.Error != nil {
				return fmt.Errorf("acme: CA 拒绝校验 %s: %w", a.Identifier.Value, a.Error)
			}
			return fmt.Errorf("acme: CA 拒绝校验 %s（未给出原因）", a.Identifier.Value)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acme: 等待 %s 校验超时（当前状态 %s）", a.Identifier.Value, a.Status)
		}
		if err := sleepCtx(ctx, pollDelay(retry)); err != nil {
			return err
		}
	}
}

// Finalize 生成 CSR、提交给 CA，等订单 valid 后取回证书。
// 证书私钥每次新生成（P-256），不复用账号密钥，也不复用上一张证书的私钥。
func (c *Client) Finalize(ctx context.Context, o *Order) (certPEM, keyPEM string, err error) {
	if o.finalize == "" {
		return "", "", errors.New("acme: 订单没有给出 finalize 端点")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("acme: 生成证书私钥: %w", err)
	}
	csrDER, err := makeCSR(key, o.IDNS)
	if err != nil {
		return "", "", err
	}
	if _, err := c.post(ctx, o.finalize, map[string]any{"csr": b64(csrDER)}); err != nil {
		return "", "", err
	}
	if err := c.waitOrder(ctx, o); err != nil {
		return "", "", err
	}
	if o.Status != "valid" {
		return "", "", fmt.Errorf("acme: 订单结束时状态为 %s（期望 valid）", o.Status)
	}
	if o.certURL == "" {
		return "", "", errors.New("acme: 订单已 valid 但没给出证书 URL")
	}
	certPEM, err = c.fetchCert(ctx, o.certURL)
	if err != nil {
		return "", "", err
	}
	k, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("acme: 导出证书私钥: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k}))
	return certPEM, keyPEM, nil
}

func (c *Client) waitOrder(ctx context.Context, o *Order) error {
	deadline := time.Now().Add(orderWaitTimeout)
	for {
		if err := c.refreshOrder(ctx, o); err != nil {
			return err
		}
		if o.Status == "valid" || o.Status == "invalid" {
			if o.cause != nil {
				return fmt.Errorf("acme: 订单失败: %w", o.cause)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acme: 等待订单完成超时（当前状态 %s）", o.Status)
		}
		if err := sleepCtx(ctx, pollDelay(o.retry)); err != nil {
			return err
		}
	}
}

func (c *Client) refreshOrder(ctx context.Context, o *Order) error {
	res, err := c.post(ctx, o.url, nil)
	if err != nil {
		return err
	}
	var raw struct {
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Certificate    string   `json:"certificate"`
		NotAfter       string   `json:"notAfter"`
		Status         string   `json:"status"`
		Error          *Error   `json:"error"`
	}
	if err := json.Unmarshal(res.Body, &raw); err != nil {
		return fmt.Errorf("acme: 解析订单文档: %w", err)
	}
	if len(raw.Authorizations) > 0 {
		o.authzURLs = raw.Authorizations
	}
	if raw.Finalize != "" {
		o.finalize = raw.Finalize
	}
	if raw.Certificate != "" {
		o.certURL = raw.Certificate
	}
	if raw.NotAfter != "" {
		o.notAfter = raw.NotAfter
	}
	o.Status = raw.Status
	o.cause = raw.Error
	o.retry = res.RetryAfter
	return nil
}

func (c *Client) fetchAuthz(ctx context.Context, url string) (*authzDoc, time.Duration, error) {
	res, err := c.post(ctx, url, nil)
	if err != nil {
		return nil, 0, err
	}
	var a authzDoc
	if err := json.Unmarshal(res.Body, &a); err != nil {
		return nil, 0, fmt.Errorf("acme: 解析授权文档: %w", err)
	}
	return &a, res.RetryAfter, nil
}

// fetchCert 取证书链。CA 返回的是「叶子 + 中间证书」的 PEM 链，边缘要整链，原样收下。
func (c *Client) fetchCert(ctx context.Context, url string) (string, error) {
	res, err := c.post(ctx, url, nil)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(res.Body))
	if !strings.HasPrefix(s, "-----BEGIN CERTIFICATE-----") {
		return "", errors.New("acme: CA 返回的不是 PEM 证书链")
	}
	return s + "\n", nil
}

func makeCSR(key *ecdsa.PrivateKey, domains []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domains[0]},
		DNSNames:           domains,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("acme: 生成 CSR: %w", err)
	}
	return der, nil
}

// response 是一次签名请求的结果，字段取自状态行与响应头。
type response struct {
	Body       []byte
	Location   string
	RetryAfter time.Duration
	Status     int
}

// post 发一个带 JWS 签名的请求；payload 为 nil 时是 POST-as-GET（RFC 8555 §7.2）。
// badNonce 自动重试一次：nonce 被并发/重启用掉是 CA 明确预期的情况，不值得让作业失败。
// 成功与否都从响应头把新 nonce 收进池子，调用方不用管 nonce 生命周期。
func (c *Client) post(ctx context.Context, url string, payload any) (*response, error) {
	var lastErr error
	for attempt := 0; attempt <= maxNonceRetry; attempt++ {
		nonce, err := c.takeNonce(ctx)
		if err != nil {
			return nil, err
		}
		res, err := c.postOnce(ctx, url, payload, nonce)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !IsBadNonce(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) postOnce(ctx context.Context, url string, payload any, nonce string) (*response, error) {
	var payloadB64 string
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadB64 = b64(raw)
	}
	body, err := c.sign(url, nonce, payloadB64)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme: 请求 CA 失败: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("acme: 读取 CA 响应: %w", err)
	}
	out := &response{Body: raw, Location: res.Header.Get("Location"), Status: res.StatusCode}
	if n := res.Header.Get("Replay-Nonce"); n != "" {
		c.pushNonce(n)
	}
	if ra := res.Header.Get("Retry-After"); ra != "" {
		if secs, cerr := strconv.Atoi(strings.TrimSpace(ra)); cerr == nil && secs > 0 {
			out.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	if res.StatusCode >= 400 {
		return out, problemError(res.StatusCode, raw)
	}
	return out, nil
}

// problemError 把非 2xx 响应翻成 *Error。能解析出 problem document 就保留 urn，
// 解析不出来（网关 HTML、空响应）就用原文片段当 Detail，别让作业日志只剩一个状态码。
func problemError(status int, raw []byte) error {
	ae := &Error{Status: status}
	if err := json.Unmarshal(raw, ae); err == nil && ae.Type != "" {
		return ae
	}
	ae.Type = ""
	msg := strings.TrimSpace(string(raw))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	ae.Detail = msg
	return ae
}

// sign 拼出 <b64(protected)>.<b64(payload)>、用账号私钥做 ES256 签名，返回完整 JWS JSON。
//
// 签名必须是定长的 r||s（各 32 字节），不是 ASN.1 DER：塞 ecdsa.SignASN1 的结果 CA 会
// 直接报签名校验失败。账号还不存在时用 jwk 头自证公钥，之后一律用 kid（账号 URL）。
func (c *Client) sign(url, nonce, payloadB64 string) (string, error) {
	var protected map[string]any
	if c.accURL == "" {
		jwk, err := c.jwk()
		if err != nil {
			return "", err
		}
		protected = map[string]any{"alg": "ES256", "jwk": jwk, "nonce": nonce, "url": url}
	} else {
		protected = map[string]any{"alg": "ES256", "kid": c.accURL, "nonce": nonce, "url": url}
	}
	pb, err := json.Marshal(protected)
	if err != nil {
		return "", err
	}
	signingInput := b64(pb) + "." + payloadB64
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, sum[:])
	if err != nil {
		return "", fmt.Errorf("acme: 签名失败: %w", err)
	}
	sig, err := encodeES256(r, s, c.key.Curve.Params().BitSize/8)
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(signingInput, ".", 2)
	out, err := json.Marshal(map[string]string{
		"protected": parts[0],
		"payload":   parts[1],
		"signature": b64(sig),
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func encodeES256(r, s *big.Int, size int) ([]byte, error) {
	sig := make([]byte, 2*size)
	rb, sb := r.Bytes(), s.Bytes()
	if len(rb) > size || len(sb) > size {
		return nil, errors.New("acme: 签名长度异常（r/s 超出曲线宽度）")
	}
	copy(sig[size-len(rb):], rb)
	copy(sig[2*size-len(sb):], sb)
	return sig, nil
}

// Thumbprint 返回账号公钥的 JWK SHA-256 指纹（RFC 7638），dns-01 的 TXT 值由它派生。
func (c *Client) Thumbprint() (string, error) { return AccountThumbprint(c.key) }

// AccountThumbprint 是 RFC 7638 的 JWK SHA-256 指纹：成员按字典序（crv/kty/x/y）、无空白的
// JSON，对其字节做 SHA-256。顺序或字符差一点，CA 就认不出我们放的 TXT。
// 单独导出是因为落库时也要算一遍（那时还没有 Client）。
func AccountThumbprint(key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", errors.New("acme: 缺少账号私钥")
	}
	if key.Curve != elliptic.P256() {
		return "", errors.New("acme: 账号密钥必须是 P-256（ES256）")
	}
	size := key.Curve.Params().BitSize / 8
	canonical := `{"crv":"P-256","kty":"EC","x":"` + b64(coordBytes(key.PublicKey.X, size)) +
		`","y":"` + b64(coordBytes(key.PublicKey.Y, size)) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:]), nil
}

// jwk 只支持 P-256。
func (c *Client) jwk() (map[string]string, error) {
	if c.key.Curve != elliptic.P256() {
		return nil, errors.New("acme: 账号密钥必须是 P-256（ES256）")
	}
	size := c.key.Curve.Params().BitSize / 8
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(coordBytes(c.key.PublicKey.X, size)),
		"y":   b64(coordBytes(c.key.PublicKey.Y, size)),
	}, nil
}

// coordBytes 把曲线坐标定宽左补齐成大端字节。big.Int 会吃掉前导零，而 JWK 要求固定 32 字节。
func coordBytes(v *big.Int, size int) []byte {
	out := make([]byte, size)
	b := v.Bytes()
	if len(b) > size {
		return out
	}
	copy(out[size-len(b):], b)
	return out
}

func (c *Client) pushNonce(n string) {
	if n == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.nonces) >= maxNoncePool {
		return
	}
	for _, existing := range c.nonces {
		if existing == n {
			return
		}
	}
	c.nonces = append(c.nonces, n)
}

// takeNonce 优先消耗池里的 nonce；池空了就去 newNonce 端点取（HEAD 即可，RFC 8555 这么规定）。
func (c *Client) takeNonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if n := len(c.nonces); n > 0 {
		nonce := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		c.mu.Unlock()
		return nonce, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("acme: 取 nonce 失败: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<10))
	nonce := res.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("acme: newNonce 响应没有 Replay-Nonce 头")
	}
	return nonce, nil
}

func pollDelay(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return defaultPollInterval
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
