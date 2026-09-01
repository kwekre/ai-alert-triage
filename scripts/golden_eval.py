#!/usr/bin/env python3
"""黄金集评测：检验一个"研判器(judge)"的质量（第 14 章指标）。

默认用内置的「规则研判器」离线运行，不需要任何 API/网络；
若设置环境变量 OPENAI_BASE_URL（指向本地 Ollama / vLLM / 兼容端点），
则改用 LLM 研判器，演示如何评测真实模型。

用法：
    python scripts/golden_eval.py                # 规则研判器，全离线
    OPENAI_BASE_URL=http://localhost:11434/v1 \
    OPENAI_MODEL=qwen2.5:32b python scripts/golden_eval.py   # LLM 研判器

输出：逐条 verdict 对比 + 精确率/召回（正类 = true）。
"""
import json
import os
import sys
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "dataset", "golden_set.json")


# ---------------- 默认：规则研判器（离线、可复现） ----------------
def rule_judge(alert):
    """极简启发式研判，仅用于演示评测 harness。真实环境用 LLM 或 SIEM 规则。"""
    module = alert.get("module", "")
    uri = alert.get("uri", "") or ""
    snippet = alert.get("resp_snippet", "") or ""
    note = alert.get("note", "") or ""
    status = alert.get("status", 0)
    location = alert.get("location", "") or ""
    mail_auth = alert.get("mail_auth", "") or ""
    mail_mac = alert.get("mail_mac", "") or ""
    query = alert.get("query", "") or ""
    dport = alert.get("dport", 0)

    if module == "mail" and "fail" in mail_auth and "IEX" in mail_mac:
        return _ver("true", "Phishing", [alert.get("mail_from", "")])
    if module == "dns" and len(query) > 40:
        return _ver("true", "DNSTunnel", [query.split(".")[-3] + ".test"])
    if "beacon" in note.lower():
        return _ver("true", "C2Beacon", [alert.get("dst", "")])
    if dport == 445 and "30 hosts" in note:
        return _ver("true", "LateralSMB", [alert.get("src", "")])
    if module == "http":
        if "webshell" in note.lower():
            return _ver("true", "UploadWebshell", ["shell.php"])
        if "<script>" in uri and "<script>" in snippet:
            return _ver("true", "XSS", ["<script>"])
        if "169.254" in uri:
            return _ver("true", "SSRF", ["169.254.169.254"])
        if "PRBCMD" in uri:
            return _ver("true", "CommandInjection", ["PRBCMD"])
        if "../" in uri and "root:x" in snippet:
            return _ver("true", "PathTraversal", ["../../etc/passwd"])
        if location and "evil.example.com" in location:
            return _ver("true", "OpenRedirect", ["evil.example.com"])
        u = uri.replace("+", " ").replace("%20", " ")
        if ("UNION" in u and "SELECT" in u) or ("'" in uri and status == 500):
            return _ver("true", "SQLi", ["sql-injection"])
        if "RSA PRIVATE KEY" in snippet:
            return _ver("true", "InfoLeak", ["private-key"])
        if uri in ("/assets/app.js", "/favicon.ico", "/api/health") \
                or "repeated successful login" in note:
            return _ver("false", "Benign", [])
        return _ver("needs_more_data", "Unknown", [])
    return _ver("needs_more_data", "Unknown", [])


def _ver(verdict, technique, ioc):
    return {"verdict": verdict, "technique": technique, "ioc": ioc, "confidence": 0.9}


# ---------------- 可选：LLM 研判器 ----------------
def llm_judge(alert):
    """调用 OpenAI 兼容端点。需 OPENAI_BASE_URL + OPENAI_MODEL；OPENAI_API_KEY 任意。"""
    base = os.environ.get("OPENAI_BASE_URL")
    model = os.environ.get("OPENAI_MODEL", "local-model")
    if not base:
        return None
    prompt = (
        "你是 SOC 研判助手。给定一条脱敏告警(JSON)，只输出 JSON："
        '{"verdict":"true|false|needs_more_data","technique":"...","ioc":[...]}.'
        "证据不足时 verdict 必须为 needs_more_data，不得编造。\n"
        f"{json.dumps(alert, ensure_ascii=False)}"
    )
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}],
               "temperature": 0}
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Bearer " + os.environ.get("OPENAI_API_KEY", "x"))
    try:
        with urllib.request.urlopen(req, data=json.dumps(payload).encode(),
                                     timeout=60) as r:
            data = json.loads(r.read().decode())
        content = data["choices"][0]["message"]["content"]
        return json.loads(_extract_json(content))
    except Exception as e:  # noqa
        return _ver("needs_more_data", "JudgeError", [])


def _extract_json(s):
    i = s.find("{")
    j = s.rfind("}")
    return s[i:j + 1] if i >= 0 and j > i else s


# ---------------- 评测 ----------------
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa
        pass
    judge = llm_judge if os.environ.get("OPENAI_BASE_URL") else rule_judge
    mode = "LLM" if os.environ.get("OPENAI_BASE_URL") else "RULE(offline)"
    with open(GOLDEN, encoding="utf-8") as f:
        cases = json.load(f)

    tp = fp = fn = match = 0
    print(f"== golden_eval ({mode}) : {len(cases)} samples ==")
    print(f"{'id':<5}{'expected':<16}{'judge':<16}{'technique':<18}{'ok'}")
    for c in cases:
        out = judge(c["alert"])
        exp = c["expected"]["verdict"]
        got = out["verdict"]
        ok = (exp == got)
        match += 1 if ok else 0
        if exp == "true" and got == "true":
            tp += 1
        elif exp != "true" and got == "true":
            fp += 1
        elif exp == "true" and got != "true":
            fn += 1
        print(f"{c['id']:<5}{exp:<16}{got:<16}{out['technique']:<18}{'Y' if ok else 'N'}")

    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    print("-" * 60)
    print(f"match_rate = {match}/{len(cases)} = {match / len(cases):.2f}")
    print(f"precision(true) = {prec:.2f}   recall(true) = {rec:.2f}")
    print("(提升精确率/召回的方法：换更大模型、加 RAG、加 few-shot —— 见第 13/14 章)")


if __name__ == "__main__":
    main()
