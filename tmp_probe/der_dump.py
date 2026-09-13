# -*- coding: utf-8 -*-
"""递归打印 OCSP 响应 DER 结构，定位 RevokedInfo 编码。"""
import sys

data = open(r"C:\Users\28299\Desktop\modpkica4JAVA\tmp_probe\resp.der", "rb").read()

def rdlen(b, i):
    l = b[i]
    i += 1
    if l & 0x80:
        n = l & 0x7f
        l = int.from_bytes(b[i:i+n], "big")
        i += n
    return l, i

def fmt_tag(t):
    cls = (t >> 6) & 3
    cn = t & 0x1f
    if cn == 0x1f:
        return "TAG%d" % t
    if cls == 2:  # context-specific
        return "[%d]%s" % (cn, "EXPL" if (t & 0x20) else "IMPL")
    names = {0x02:"INTEGER",0x04:"OCTET",0x05:"NULL",0x06:"OID",0x0c:"UTF8",0x13:"PRINTSTR",0x16:"IA5STR",0x17:"UTCTIME",0x18:"GEN-TIME",0x30:"SEQ",0x31:"SET"}
    return names.get(t, "TAG%02x" % t)

def walk(b, off, depth, limit=60):
    if depth > limit:
        return
    i = off
    while i < len(b):
        if depth == 0 and i > 0:
            return
        t = b[i]; i += 1
        l, i = rdlen(b, i)
        end = i + l
        if end > len(b):
            print("  " * depth, "TRUNC at", i)
            return
        content = b[i:end]
        if t in (0x30, 0x31) or (0xa0 <= t <= 0xaf) or (t == 0x04 and len(content) > 4 and content[0] == 0x30):
            print("  " * depth, "%02x L=%d" % (t, l), fmt_tag(t))
            walk(content, 0, depth + 1, limit)
        else:
                if t == 0x06:
                    print("  " * depth, "%02x L=%d" % (t, l), fmt_tag(t), content.hex())
                elif t == 0x18 or t == 0x17:
                    print("  " * depth, "%02x L=%d" % (t, l), fmt_tag(t), content.decode("ascii", "replace"))
                elif t in (0x02, 0x0a, 0x03, 0x05, 0x01):
                    print("  " * depth, "%02x L=%d" % (t, l), fmt_tag(t), content.hex())
                else:
                    print("  " * depth, "%02x L=%d" % (t, l), fmt_tag(t), content[:40].hex())
        i = end

walk(data, 0, 0)
