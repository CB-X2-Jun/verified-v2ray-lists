# Verified V2Ray Lists
提供定时检查并更新的 人工入库 V2Ray 节点列表。

## 特点
- 人工入库，不搞爬虫，保证质量
- 历史记录保留，成功率一目了然
- 提供特殊warning

## 目前支持协议
- VLESS
- VMESS

## 已解决的问题
- 使用WARP给GitHub action套上IPv6以检测IPv6节点

## TODO

### 最高优先级
- 解决Shadowsocks（传输协议为tcp）的配置与检测
- 解决Shadowsocks（传输协议为ws，带有v2ray-plugin）的配置与检测
- 解决hy2的配置与检测
- 支持trojan

### 第二优先级
- 支持TUIC
- 支持Anytls

### 最低优先级
- 支持WireGuard

### 暂无计划考虑
- 支持HY
- 支持SSR

## 友情链接
- 四大传统协议代理（HTTP HTTPS SOCKS4 SOCKS5）：[CB-X2-Jun/proxy-lists](https://github.com/CB-X2-Jun/proxy-lists)
- 特别地，不支持SSL的HTTP代理：[CB-X2-Jun/test-t](https://github.com/CB-X2-Jun/test-t)
