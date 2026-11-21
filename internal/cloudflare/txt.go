package cloudflare

import (
	"fmt"
	"strings"
)

// SetAPIBase 把请求指向另一个 Cloudflare API 地址。只有本地自证（假 CF）会调它，
// 生产路径永远不传。client.go 里 apiBase 字段本来就写着"测试时替换为 httptest 地址"，
// 但没有注入口——那句注释一直是空头支票。
func (c *Client) SetAPIBase(base string) {
	c.apiBase = strings.TrimSuffix(strings.TrimSpace(base), "/")
}

// TXT 记录用于 ACME dns-01 校验（_acme-challenge.<域名>）。这里不套用 createOrAdopt：
// 那个函数会删掉同名的其它 A/AAAA/CNAME，而 TXT 天然可以和任何记录同名共存，
// 也能在同一个名字下有多条——那是别人的记录，碰不得。
//
// 同一个名字上只留我们这一条：先删掉面板上次留下的旧 TXT 再建新的。CA 对同名多条 TXT
// 的处理并不统一，留一条过期值在里面对校验只有坏处。

// SetTXTRecord 在 name 上放一条值为 content 的 TXT，覆盖面板此前留在同名下的 TXT，返回新记录 ID。
func (c *Client) SetTXTRecord(name, content string) (string, error) {
	if err := c.DeleteTXTRecords(name); err != nil {
		return "", fmt.Errorf("清理旧 TXT 记录失败: %w", err)
	}
	return c.createRecord(dnsRecord{Type: "TXT", Name: name, Content: content, TTL: 1})
}

// DeleteTXTRecords 删掉 name 下的全部 TXT 记录。名字下没有记录时正常返回（校验完就该清干净，
// 但记录已被手动删掉不该让签发失败）。不动其它类型的同名记录。
func (c *Client) DeleteTXTRecords(name string) error {
	records, err := c.listRecords("TXT", name)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	for _, r := range records {
		if r.ID == "" {
			continue
		}
		if err := c.DeleteRecord(r.ID); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}
