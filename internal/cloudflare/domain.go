package cloudflare

import (
	"fmt"

	"cdn/internal/config"
)

// 单个域名在 Cloudflare 上的布局（每个域名独享切换点，切高防/切回互不影响）：
//
//	用户域名 ──CNAME──▶ 切换记录 S（d.CNAMERecord，如 test.gqcdnwaf.click）   // 用户只需加这一次
//	S ──灰云 CNAME──▶ 集群子域名（如 hktest.gqcdnwaf.click，下挂全部边缘节点 A 记录） // 平时
//	S ──灰云 CNAME──▶ 高防 CDN 给的 CNAME（d.DefenseCNAME 或集群默认值）            // 被攻击时
//
// 全部记录都是灰云，本 zone 不再有任何指向源站的记录。以前的橙云方案有死结：
// 用户域名托管在另一个 CF 账号时，请求落到本账号的橙云记录上必报 1014；要避开 1014
// 只能让专用记录灰云直指源站，源站 IP 就直接暴露在公网 DNS 里。
// 用户域名在本 zone 内时，由面板代建用户域名那条 CNAME。

// SwitchTarget 返回切换记录 S 当前应指向的目标。defenseCNAME 为该域名生效的高防 CNAME。
func SwitchTarget(d *config.Domain, clusterSubdomain, defenseCNAME string) string {
	if d.OnDefense && defenseCNAME != "" {
		return defenseCNAME
	}
	return clusterSubdomain
}

// SyncDomain 把该域名的 CF 记录调整到位（缺什么建什么），并更新 d 上的记录 ID。
// clusterSubdomain 是平时 S 的目标；d.OnDefense 时 S 指向 defenseCNAME。
func (c *Client) SyncDomain(d *config.Domain, clusterSubdomain, defenseCNAME string) error {
	if clusterSubdomain == "" {
		return fmt.Errorf("域名未关联集群")
	}
	if d.OnDefense && defenseCNAME == "" {
		return fmt.Errorf("未配置高防 CNAME，无法切到高防")
	}
	// 分配切换记录 S。旧数据迁移：以前 CNAMERecord 存的是集群子域名本身（CNAMERecordID 是
	// 用户域名那条 CNAME、MainSubdomainRecordID 为空），这种要换成独享的 S。
	// 已分配的 S 绝不能随便换：用户已经在自己的 DNS 里 CNAME 到它了。
	legacy := d.MainSubdomainRecordID == "" && d.CNAMERecordID != ""
	if d.CNAMERecord == "" || !c.InZone(d.CNAMERecord) || d.CNAMERecord == clusterSubdomain || legacy {
		d.CNAMERecord = c.RandomSubdomain()
		d.MainSubdomainRecordID = ""
	}
	if legacy && !c.InZone(d.Domain) {
		// 旧逻辑对 zone 外的用户域名也在本 zone 建了一条记录（名字会被补成 xxx.<zone>），是垃圾记录
		_ = c.DeleteRecord(d.CNAMERecordID)
		d.CNAMERecordID = ""
	}
	d.CFMessage = ""

	// 1. 切换记录 S：始终灰云，只换目标
	id, err := c.upsertRecord(d.MainSubdomainRecordID, dnsRecord{
		Type: "CNAME", Name: d.CNAMERecord, Content: SwitchTarget(d, clusterSubdomain, defenseCNAME), TTL: 60,
	})
	if err != nil {
		return fmt.Errorf("写入切换记录 %s 失败: %w", d.CNAMERecord, err)
	}
	d.MainSubdomainRecordID = id

	// 2. 用户域名在本 zone 内：代建用户域名 CNAME → S（灰云，与 zone 外用户的链路一致）
	if c.InZone(d.Domain) {
		uid, err := c.upsertRecord(d.CNAMERecordID, dnsRecord{Type: "CNAME", Name: d.Domain, Content: d.CNAMERecord, TTL: 60})
		if err != nil {
			return fmt.Errorf("写入用户域名 CNAME 失败: %w", err)
		}
		d.CNAMERecordID = uid
	} else {
		d.CNAMERecordID = ""
	}
	return nil
}

// PointSwitchTo 把切换记录 S 改指向指定目标（集群子域名 / 备用集群子域名 / 高防 CNAME）。
func (c *Client) PointSwitchTo(d *config.Domain, clusterSubdomain string) error {
	if d.MainSubdomainRecordID == "" || d.CNAMERecord == "" {
		return fmt.Errorf("域名尚未分配切换记录")
	}
	id, err := c.overwriteRecord(d.MainSubdomainRecordID, dnsRecord{
		Type: "CNAME", Name: d.CNAMERecord, Content: clusterSubdomain, TTL: 60,
	})
	if err != nil {
		return err
	}
	d.MainSubdomainRecordID = id
	return nil
}

// RemoveDomain 删除该域名在 CF 上的全部记录（尽力而为，返回第一个错误）。
// CloudflareProxyID 是旧版专用橙云记录，新版不再创建，但老域名删除时顺手清掉。
func (c *Client) RemoveDomain(d *config.Domain) error {
	var first error
	for _, id := range []string{d.CNAMERecordID, d.MainSubdomainRecordID, d.CloudflareProxyID} {
		if id == "" {
			continue
		}
		if err := c.DeleteRecord(id); err != nil && !isNotFound(err) && first == nil {
			first = err
		}
	}
	return first
}
