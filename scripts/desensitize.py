#!/usr/bin/env python3
"""日志脱敏（第 06 章）：喂给 AI 前先去掉真实值，保留研判所需的"模式"。

脱敏规则：私有/公网 IP -> INT_/EXT_ 占位（保留每 IP 唯一性，便于聚类）；
邮箱 -> <redacted>@example.com；凭证 -> <redacted>；云/API Key -> <KEY>；
UUID/哈希/JWT -> 占位符；非 example.com 的域名 -> suspect.test。

默认读 stdin，写 stdout；也可用 -i 输入文件、-o 输出文件。
支持 JSON 行（递归脱敏所有字符串）与纯文本。

用法：
    python scripts/desensitize.py -i raw.log -o clean.log
    cat raw.log | python scripts/desensitize.py
"""
import argparse
import json
import re
import sys

MASK = 90  # 异或掩码，把真实网段打乱成不可还原的占位


def _mask_ip(ip):
    parts = [int(x) for x in ip.split(".")]
    tag = "INT" if (parts[0] == 10 or (parts[0] == 192 and parts[1] == 168)
                    or (172 <= parts[0] <= 172 and 16 <= parts[1] <= 31)
                    or (parts[0] == 127)) else "EXT"
    m = [(p ^ MASK) % 256 for p in parts]
    return f"{tag}_{m[0]}_{m[1]}_{m[2]}_{m[3]}"


_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_HOST_RE = re.compile(r"(https?://|@)([A-Za-z0-9.-]+)")
_CRED_RE = re.compile(r'(?i)(pwd|pass|password|token|secret|api[_-]?key|authorization)["\']?\s*[=:]\s*["\']?([^\s"\'&<>`]+)')
_AWS_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_GCP_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_OPENAI_RE = re.compile(r"\bsk-[0-9A-Za-z]{20,}\b")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def mask_text(s):
    s = _IP_RE.sub(lambda m: _mask_ip(m.group(0)), s)
    s = _AWS_RE.sub("<AWS_KEY>", s)
    s = _GCP_RE.sub("<GCP_KEY>", s)
    s = _OPENAI_RE.sub("<OPENAI_KEY>", s)
    s = _JWT_RE.sub("<JWT>", s)
    s = _UUID_RE.sub("<UUID>", s)
    s = _HEX32_RE.sub("<H32>", s)
    s = _CRED_RE.sub(lambda m: f"{m.group(1)}=<redacted>", s)
    s = _EMAIL_RE.sub("<redacted>@example.com", s)
    # 非 example.com 的域名主机 -> suspect.test（保留协议/路径结构）
    s = _URL_HOST_RE.sub(lambda m: f"{m.group(1)}suspect.test"
                         if m.group(2) != "example.com" else m.group(0), s)
    return s


def mask_obj(o):
    if isinstance(o, str):
        return mask_text(o)
    if isinstance(o, dict):
        return {k: mask_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [mask_obj(v) for v in o]
    return o


def process_line(line):
    line = line.rstrip("\n")
    try:
        obj = json.loads(line)
        return json.dumps(mask_obj(obj), ensure_ascii=False)
    except Exception:
        return mask_text(line)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--in", dest="inp", default="")
    ap.add_argument("-o", "--out", dest="out", default="")
    args = ap.parse_args()

    inp = open(args.inp, encoding="utf-8") if args.inp else sys.stdin
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        for line in inp:
            out.write(process_line(line) + "\n")
    finally:
        if args.inp:
            inp.close()
        if args.out:
            out.close()


if __name__ == "__main__":
    main()
