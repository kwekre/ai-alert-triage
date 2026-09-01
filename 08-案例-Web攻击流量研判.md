# 08 · 实战：Web 攻击流量研判（从一条告警到一次入侵）

前面 7 章是"方法"。这一章开始"练"——而且能**真的跑起来**。

我们用仓库自带的脱敏数据集 `dataset/sample_alerts.jsonl`（28 条真实结构、零真实凭据的告警）当靶子。所有命令你本地都能复现。

---

## 8.0 先别急着看单条告警：让聚类替你排个队

凌晨 2 点你接班，SIEM 里堆了 2000 条 Web 告警。逐条看？不。先聚类降噪：

```powershell
$env:PYTHONIOENCODING="utf-8"
python scripts/triage_cluster.py --top 12
```

输出（节选）：

```
#  src             count suspicion techniques
1  INT_10_0_0_5    17    44        RDP爆破,SMB横向,SQL注入,SSRF,WebShell落地,XSS,命令注入,开放重定向,路径遍历
2  INT_10_0_0_7    5     11        C2信标,DNS隧道
3  INT_10_0_1_9    1     4         敏感信息泄露
4  EXT_9_9_9_9     1     4         CORS错误
5  EXT_2_2_2_2     1     4         钓鱼邮件
6  INT_10_0_0_8    3     3         良性资产
```

> 一眼就明白：先打 **INT_10_0_0_5**——单台机器 17 条告警、9 种手法并行，这不是"误报噪音"，这是**一条完整的 Web 攻击链**。第 9 章会讲它的内网横向，本章先盯 Web 这一段。

---

## 8.1 顺着时间线还原：2:13 发生了什么

把 INT_10_0_0_5 的 HTTP 告警按时间排序（直接看 `sample_alerts.jsonl` 里 02:13 那几条）：

```
02:13:00  GET /item?id=1'                       -> 500  "You have an error in your SQL syntax"
02:13:01  GET /item?id=1+UNION+SELECT+password+FROM+users--  -> 200  "admin:5f4dcc3b5aa765d61d8327deb882cf99"
02:14:00  GET /search?q=<script>alert(1)</script>  -> 200  "<p>q=<script>alert(1)</script></p>"
02:15:00  GET /fetch?url=http://169.254.169.254/latest/meta-data/  -> 200  "ami-id: mock-instance"
02:16:00  GET /p?name=test;echo PRBCMD7Z9        -> 200  "result=PRBCMD7Z9"
02:17:00  GET /file?name=../../../../etc/passwd  -> 200  "root:x:0:0:root:/root:/bin/bash"
02:18:00  GET /go?next=https://evil.example.com/ -> 302  Location: https://evil.example.com/
```

**这就是一条教科书式的攻击链**：报错探注入 → UNION 拖出 admin 密码哈希 → 顺手测 XSS → 打云元数据(SSRF) → 命令注入 → 读 `/etc/passwd` → 找开放重定向当跳板。

### 用 tshark 抽 SQLi 证据（真实命令）

假设你手上有 `web.pcap`，抽注入请求：

```bash
tshark -r web.pcap -Y 'http.request.uri matches "(?i)(union|select|sleep|benchmark|0x|or 1=1|'"'"')"' \
  -T fields -e frame.time -e ip.src -e http.request.uri -e http.response.code
```

输出里 `?id=1'` 后面跟 500、再跟 `UNION SELECT` 跟 200 带 `admin:5f4...`，就闭环了。

### 三种 SQLi，判定口径不一样（回扣第 01 章）

| 类型 | 证据 | 定性 |
|------|------|------|
| 报错型 | 响应 500 + 数据库报错指纹 | **真 / High**（已确认可注入） |
| 联合/堆叠 | 后续 `UNION` 拖出数据 | **真 / High→Critical**（已读到库） |
| 布尔/时间盲注 | `id=1 AND 1=1` vs `1=2` 响应不同；或 `SLEEP(5)` 耗时 5s | **真 / High**（无回显也能注） |

数据集里还有两条盲注样本（`04:00:00` 布尔、`05:00:00` 时间），正是 probekit 第 4 章去噪层要抓的那种。

---

## 8.2 让 AI 串链——然后看它翻车

把 8.1 的 7 行贴给模型，让它出研判：

> **AI 草稿**：综合 7 条，判定 **True / Critical**：攻击者通过 SQLi 注入→拖库（admin 密码哈希 `5f4dcc3b...`）→XSS→SSRF 打元数据→命令注入→读 passwd→开放重定向。建议立即隔离 INT_10_0_0_5、排查落马、全站改参数化。

看起来很对。**但翻车点来了** 👇

> 🔴 **翻车现场 #1（误报升级）**：AI 把 `5f4dcc3b5aa765d61d8327deb882cf99` 当成了"admin 的真实密码"，建议"立刻重置 admin 密码"。其实那是 `md5("password")`——靶场用的弱口令示意值，**不是真实凭证**。AI 没区分"靶场示例哈希"和"生产明文"。**人的动作**：先确认这是测试/靶场流量（来源 IP 段、资产归属），再决定要不要惊动全员。

> 🔴 **翻车现场 #2（漏了闭环判据）**：AI 给 SSRF 打了 High，但没说明"响应里出现了 `ami-id: mock-instance` 才坐实打到云元数据"。没有这行响应证据，SSRF 只是"请求可疑"。**人的动作**：判定永远要 `请求 + 响应 + 后续动作` 三段齐全（第 01 章铁律）。

> 🔴 **翻车现场 #3（越权建议）**：AI 直接写"立即隔离 + 改参数化"。隔离是**处置动作，不是研判结论**——必须由人拍板并走变更流程（第 05 章）。**正确产物**：AI 给 `疑似/证据/建议`，人给 `定性 + 处置工单`。

**所以本章要你记住的不是"AI 很牛"，而是：AI 串链能力是真的不错，但它在"值不值得惊动业务""这是不是靶场""该不该自动处置"这三件事上会翻车——这正是人的价值。**

---

## 8.3 红队视角：他怎么躲过这套检测？

光会蓝队不够，知道红队怎么绕，检测才写得对：

- **SQLi 绕 WAF**：用 `/*!50000 union*/`、`CASE WHEN`、`宽字节`、分块编码，让 `union|select` 正则抓不到（对应 probekit 的 WAF 绕过表）。
- **盲注代替回显**：不拖数据，改用布尔/时间盲注——你的 tshark 正则抓不到 `union`，得看 `duration` 和 1=1/1=2 差异（这就是为什么数据集特意留了盲注样本）。
- **SSRF 打 IMDSv2**：现代云要求带 token 才返回元数据，老 `169.254.169.254` 探测会失效——检测要同时看"探测行为"和"是否真的拿到凭证"。
- **开放重定向当钓鱼跳板**：`/go?next=` 常被当成低危忽略，但它是钓鱼邮件里的"可信域名跳转器"。

> 🔧 **可练**：把 `sample_alerts.jsonl` 里这几行喂给 `scripts/golden_eval.py`，看内置规则研判器对 SQLi/XSS/SSRF/命令注入/路径遍历/开放重定向分别给什么 verdict——它就是第 14 章"用黄金集评测研判器"的最小雏形。

---

## 8.4 处置与缓解（这一条才进工单）

- **定性**：True / Critical（注入已读到库、且伴随命令执行与文件读取）。
- **IOC**：源 `INT_10_0_0_5`；参数 `id`/`q`/`url`/`name`/`next`；指纹 `5f4dcc3b...`(示例哈希)、`PRBCMD7Z9`、`mock-instance`。
- **ATT&CK**：T1190 Exploit Public-Facing App（SQLi/XSS/SSRF/遍历）、T1059.003 命令注入。
- **处置**：①隔离 INT_10_0_0_5（人确认）②查是否落马/拿凭证 ③相关接口改参数化 + 关详细报错 + WAF ④云元数据启用 IMDSv2。
- **缓解（长期）**：参数化查询、输出编码+CSP、`HttpOnly`、URL 白名单、上传类型白名单+非执行目录。

---

## 8.5 本章 checklist

- [ ] 跑过 `triage_cluster.py`，知道"先聚类再钻取"
- [ ] 能区分报错型 / 联合 / 盲注三类 SQLi 的判定口径
- [ ] 能说出 ≥2 个"AI 在 Web 研判里会翻车"的点
- [ ] 记得：AI 给建议，隔离/改代码这类动作必须人拍板

下一章：09 · 实战：内网横向与提权（回到 INT_10_0_0_5 的 445/3389 那段）。
