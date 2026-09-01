#!/usr/bin/env python3
"""告警聚类降噪（第 07 章）：把海量脱敏告警按来源 IP 聚成"事件"，
按可疑度排序，输出 Top-K 供人工优先研判。纯离线、无依赖。

用法：
    python scripts/triage_cluster.py                # 默认 Top-10
    python scripts/triage_cluster.py --top 5        # 只看前 5
    python scripts/triage_cluster.py --top 20 --json out.jsonl

输入：dataset/sample_alerts.jsonl （每行一条脱敏告警）
"""
import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "..", "dataset", "sample_alerts.jsonl")

# 非恶意的"技术标签"，用于计算可疑度时不计入
BENIGN = {"良性资产", "待研判"}


def tag(a):
    """根据脱敏告警字段推断攻击技术标签（启发式，可替换为你的 SIEM 规则）。"""
    module = a.get("module", "")
    uri = a.get("uri", "") or ""
    snippet = a.get("resp_snippet", "") or ""
    note = a.get("note", "") or ""
    status = a.get("status", 0)
    location = a.get("location", "") or ""
    dport = a.get("dport", 0)
    query = a.get("query", "") or ""
    rheaders = a.get("resp_headers") or {}

    if module == "dns" and len(query) > 40:
        return "DNS隧道"
    if "beacon" in note.lower():
        return "C2信标"
    if dport == 445:
        return "SMB横向"
    if dport == 3389:
        return "RDP爆破"
    if module == "mail":
        return "钓鱼邮件"
    if module == "http":
        if "webshell" in note.lower() or "shell.php" in snippet:
            return "WebShell落地"
        if "<script>" in uri:
            return "XSS"
        if "169.254" in uri:
            return "SSRF"
        if "PRBCMD" in uri:
            return "命令注入"
        if "../" in uri or "..%2f" in uri:
            return "路径遍历"
        if location and "evil.example.com" in location:
            return "开放重定向"
        if "UNION" in uri or ("'" in uri and status == 500):
            return "SQL注入"
        if "RSA PRIVATE KEY" in snippet:
            return "敏感信息泄露"
        if rheaders.get("Access-Control-Allow-Origin"):
            return "CORS错误"
        if uri in ("/assets/app.js", "/favicon.ico", "/api/health"):
            return "良性资产"
        return "待研判"
    return "待研判"


def cluster(alerts):
    groups = {}
    for a in alerts:
        src = a.get("src", a.get("source", {}).get("ip", "UNKNOWN"))
        g = groups.setdefault(src, {"src": src, "count": 0,
                                    "tech": set(), "samples": []})
        g["count"] += 1
        g["tech"].add(tag(a))
        g["samples"].append(a)
    for g in groups.values():
        mal = [t for t in g["tech"] if t not in BENIGN]
        # 可疑度 = 告警数 + 不同恶意技术数*3（多手法并行 = 更可疑）
        g["suspicion"] = g["count"] + len(mal) * 3
        g["mal_tech"] = mal
    return sorted(groups.values(), key=lambda x: x["suspicion"], reverse=True)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--json", dest="json_out", default="")
    args = ap.parse_args()

    alerts = []
    with open(SAMPLE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))

    clusters = cluster(alerts)
    top = clusters[: args.top]

    print(f"== triage_cluster : {len(alerts)} alerts -> {len(clusters)} clusters, Top-{args.top} ==")
    print(f"{'#':<3}{'src':<16}{'count':<6}{'suspicion':<10}techniques")
    for i, g in enumerate(top, 1):
        tech = ",".join(sorted(g["tech"]))
        print(f"{i:<3}{g['src']:<16}{g['count']:<6}{g['suspicion']:<10}{tech}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            for g in top:
                g2 = {k: (sorted(v) if isinstance(v, set) else v)
                      for k, v in g.items()}
                f.write(json.dumps(g2, ensure_ascii=False) + "\n")
        print(f"[written] {args.json_out}")


if __name__ == "__main__":
    main()
