# -*- coding: utf-8 -*-
"""
sm2lib.py —— 纯 Python 实现 SM3 哈希 与 SM2 椭圆曲线验签
依据：GB/T 32905-2016《信息安全技术 SM3密码杂凑算法》
      GB/T 32918-2016《信息安全技术 SM2椭圆曲线公钥密码算法》
仅用于技术验证，不追求性能。
"""

# ---------------- SM3（GB/T 32905-2016） ----------------
_SM3_IV = 0x7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E


def _rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def sm3(data: bytes) -> bytes:
    """SM3 哈希，返回 32 字节摘要。"""
    # 消息填充
    l = len(data) * 8
    msg = bytearray(data)
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += l.to_bytes(8, 'big')

    V = [_SM3_IV >> (32 * (7 - i)) & 0xFFFFFFFF for i in range(8)]

    for off in range(0, len(msg), 64):
        B = msg[off:off + 64]
        W = [int.from_bytes(B[i * 4:i * 4 + 4], 'big') for i in range(16)]
        for j in range(16, 68):
            W.append(_p1(W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15))
                     ^ _rotl(W[j - 13], 7) ^ W[j - 6])
        W1 = [W[j] ^ W[j + 4] for j in range(64)]

        A, B_, C, D, E, F, G, H = V
        for j in range(64):
            T = 0x79CC4519 if j < 16 else 0x7A879D8A
            SS1 = _rotl((_rotl(A, 12) + E + _rotl(T, j)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ _rotl(A, 12)
            if j < 16:
                FF = A ^ B_ ^ C
                GG = E ^ F ^ G
            else:
                FF = (A & B_) | (A & C) | (B_ & C)
                GG = (E & F) | ((~E & 0xFFFFFFFF) & G)
            TT1 = (FF + D + SS2 + W1[j]) & 0xFFFFFFFF
            TT2 = (GG + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = _rotl(B_, 9)
            B_ = A
            A = TT1
            H = G
            G = _rotl(F, 19)
            F = E
            E = _p0(TT2)
        V = [V[i] ^ [A, B_, C, D, E, F, G, H][i] for i in range(8)]

    return b''.join(x.to_bytes(4, 'big') for x in V)


# ---------------- SM2 曲线参数（GB/T 32918-2016 第 5 部分 附录 A） ----------------
_P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
_A = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)
_B = int('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)
_N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
_GX = int('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)
_GY = int('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)

# 默认用户 ID（GB/T 32918 建议 "1234567812345678"）
_DEFAULT_ID = b'1234567812345678'


def _inv(x, p=_P):
    return pow(x % p, -1, p)


def _add(p1, p2):
    """椭圆曲线点加（仿射坐标）。None 表示无穷远点。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = ((3 * x1 * x1 + _A) * _inv(2 * y1)) % _P
    else:
        lam = ((y2 - y1) * _inv(x2 - x1)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _mul(k, p):
    """标量乘 k*P。"""
    k %= _N
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def sm2_za(pub: tuple, uid: bytes = _DEFAULT_ID) -> bytes:
    """计算 ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)。"""
    entl = (len(uid) * 8).to_bytes(2, 'big')
    parts = [entl, uid]
    for v in (_A, _B, _GX, _GY, pub[0], pub[1]):
        parts.append(v.to_bytes(32, 'big'))
    return sm3(b''.join(parts))


def sm2_verify(pub: tuple, msg: bytes, r: int, s: int,
               with_za: bool = True, uid: bytes = _DEFAULT_ID) -> tuple:
    """
    SM2 验签（明文模式）。
    pub: (x, y) 公钥点（整数）
    msg: 待验签消息原文
    r, s: 签名分量
    with_za: True 时 e = SM3(ZA || M)（标准 GB/T 32918 模式）；
             False 时 e = SM3(M)（部分实现的简化模式）
    返回 (ok, detail)
    """
    if not (1 <= r <= _N - 1):
        return False, "r 越界"
    if not (1 <= s <= _N - 1):
        return False, "s 越界"
    t = (r + s) % _N
    if t == 0:
        return False, "t = (r+s) mod n = 0"
    P = (pub[0] % _P, pub[1] % _P)
    # 公钥合法性检查
    if (P[1] * P[1] - (P[0] * P[0] * P[0] + _A * P[0] + _B)) % _P != 0:
        return False, "公钥不在曲线上"
    if with_za:
        e = _bytes_to_int(sm3(sm2_za(P, uid) + msg))
    else:
        e = _bytes_to_int(sm3(msg))
    pt = _add(_mul(s, (_GX, _GY)), _mul(t, P))
    if pt is None:
        return False, "sG + tP = O（无穷远点）"
    R = (e + pt[0]) % _N
    return R == r, f"R={R:x} r={r:x}"


if __name__ == '__main__':
    # 自检：SM3("abc") 标准测试向量
    import binascii
    d = sm3(b'abc')
    print('SM3(abc) =', d.hex())
    assert d.hex() == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0', 'SM3 自检失败'
    print('SM3 自检通过')
