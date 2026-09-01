# 08 · 案例：Web 攻击流量研判

把前 7 章套到真实 Web 攻击上。每种攻击给：**流量特征 → 查什么 → 怎么定性 → 缓解**。

## 8.1 目录/路径爆破

**特征**：同 IP 对大量不同路径发 GET，大多 404；UA 常为工具名或空。
**查**：
```bash
# Web 日志：某 IP 的 404 频率
awk '$1=="10.0.0.5" && $9==404 {print $7}' access.log | sort | uniq -c | sort -rn | head
# Zeek http：uri 计数
zeek-cut id.orig_h uri < logs/http.log | grep "10.0.0.5" | sort | uniq -c | sort -rn | head
```
**定性**：高频 404 + 常见路径(`/admin`,`/wp-admin`,`/.env`) → 踩点/爆破。**多为真**（意图明确），严重度 Medium-High。
**缓解**：路径混淆、WAF 限速、关键路径加鉴权。

## 8.2 SQL 注入

**特征**：uri/body 含 `union`/`select`/`sleep`/`'`/`--`；响应 500（报错）或 200 却带异常内容；时间盲注看 `duration` 异常长。
**查**：
```bash
tshark -r web.pcap -Y 'http.request.uri matches "(?i)(union|select|sleep|benchmark|0x|or 1=1)"' \
  -T fields -e frame.time -e ip.src -e http.request.uri -e http.response.code
```
**定性（闭环判据，回扣第 01 章铁律）**：
- 仅请求含 payload → **待查**（疑似探测）
- + 响应 500 且含数据库报错指纹 → 偏高置信
- + 后续 `UNION` 后开始拖表名/数据 → **真（High）**
**缓解**：参数化查询、关详细报错、WAF 规则、最小权限账号。

## 8.3 XSS

**特征**：参数含 `<script>`/`onerror=`/`svg onload`；反射型看该参数**原样回显**在响应 HTML。
**查**：在响应体搜注入串是否未编码出现。
**定性**：回显未过滤 → **真（Medium）**；仅发出未回显 → 待查。
**缓解**：输出编码、CSP、`HttpOnly`+输入校验。

## 8.4 SSRF

**特征**：参数含内网 IP（`10.`/`192.168.`/`169.254.169.254`）、云元数据地址、非常见域名。
**查**：
```bash
tshark -r web.pcap -Y 'http.request.uri matches "(169\.254\.169\.254|metadata|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"'
```
**定性**：请求打向元数据/内网且响应带回内网内容（如 IAM 临时凭证）→ **真（High）**。
**缓解**：禁用服务端对外请求、URL 白名单、云元数据加 IMDSv2（带鉴权）。

## 8.5 上传 / Webshell 落地

**特征**：POST 大 body 到上传接口；文件名 `.php/.jsp/.asp/.phtml`；落地后该文件被访问返回 200。
**查**：看 `http.request` 的 content-type/文件名 + 后续 `GET /uploads/shell.php 200`。
**定性**：上传成功且可访问 → **真（High/Critical）**，几乎等于拿到机子。
**缓解**：上传类型白名单、存非执行目录、改随机名、病毒扫描。

## 8.6 综合实战（脱敏样本，给 AI 研判）

```
INT_10_0_0_5  GET /item?id=1'  > 500 (sql syntax error)
INT_10_0_0_5  GET /item?id=1+UNION+SELECT+password+FROM+users--  > 200, body含"admin:xxxx"
INT_10_0_0_5  POST /upload img.php (image/png but content has <?php)  > 200
INT_10_0_0_5  GET /upload/img.php?c=whoami  > 200, body含"www-data"
```
AI 应给出：三步串成“注入→拖库→传马→命令执行”，定性 **True/Critical**，建议立刻隔离 + 排查落马 + 改参数化。
注意：AI 能串链，但**隔离动作必须人确认**（第 05 章铁律）。

## 8.7 本章 checklist

- [ ] 能说清 5 类 Web 攻击各自流量特征
- [ ] 会用 tshark/zeek-cut 抽出对应证据
- [ ] 知道 SQLi 的“闭环判据”（请求+响应+后续）
- [ ] 记得：AI 串链后，处置仍要人拍板

下一章：09 · 案例：内网横向与提权流量研判。
