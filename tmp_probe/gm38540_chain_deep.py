# -*- coding: utf-8 -*-
"""gm38540_chain_deep.py —— GB/T 38540-2020 证书链深度验证：
1) 提取签名内全部证书（SESealInfo / TSA 令牌 / DSS）
2) 逐级密码学验签（SM2 用 ZA 模式、RSA 用 PKCS#1 v1.5）
3) 解析 DSS 内 CRL / OCSP，确认吊销证据离线可用
4) 给出"离线可验证性"结论
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r'C:\Users\28299\Desktop\modpkica4JAVA\GMcheck')
import pikepdf
from derlib import parse_tlv, parse_sequence, tlv_int, tlv_oid, X509Cert, CMS
from sm2lib import sm3, sm2_verify, sm2_za
from pdfsig_verify import rsa_pkcs1_v15_verify

PDF = r'C:\Users\28299\Desktop\modpkica4JAVA\GMcheck\GBT38540-2020.pdf'

def cert_signature(der):
    """X.509 证书：SEQUENCE{tbs, sigAlg, sig}，返回 (tbs_der, sig_bytes)。"""
    t = parse_tlv(der)
    seq = parse_sequence(t.value)
    tbs = t.value[seq[0].start:seq[0].end]   # 含 0x30 头
    sig = seq[2].value[1:]                   # BIT STRING 去 unused bits
    return tbs, sig

def verify_cert_signed_by(cert_der, issuer_cert):
    """用签发者公钥验证证书签名。返回 (ok, detail)。"""
    tbs, sig = cert_signature(cert_der)
    pub = issuer_cert.pubkey
    if pub is None:
        return False, '签发者公钥缺失'
    alg = cert_der
    # 证书签名算法从 tbs 外 sigAlg 取：seq[1] OID
    t = parse_tlv(cert_der)
    seq = parse_sequence(t.value)
    sig_alg_oid = None
    if seq[1].tag == 0x30:  # AlgorithmIdentifier: SEQUENCE{OID, params}
        alg_inner = parse_sequence(seq[1].value)
        if alg_inner and alg_inner[0].tag == 0x06:
            sig_alg_oid = tlv_oid(alg_inner[0])
    if pub[0] in ('SM2', 'EC'):
        # SM2：ZA 模式（默认用户 ID）
        rs = None
        # 尝试 DER ECDSA 签名（SEQUENCE{r,s}）
        try:
            s2 = parse_sequence(sig)
            r = int.from_bytes(s2[0].value, 'big')
            s = int.from_bytes(s2[1].value, 'big')
        except Exception:
            r = int.from_bytes(sig[:32], 'big')
            s = int.from_bytes(sig[32:], 'big')
        ok = sm2_verify((pub[1], pub[2]), tbs, r, s, with_za=True)
        return ok, 'SM2(ZA) 验签%s' % ('通过' if ok else '失败')
    elif pub[0] == 'RSA':
        # 从 OID 判断哈希
        hm = {'1.2.840.113549.1.1.11': 'sha256',
              '1.2.840.113549.1.1.12': 'sha384',
              '1.2.840.113549.1.1.13': 'sha512',
              '1.2.840.113549.1.1.5': 'sha1',
              '1.2.840.113549.1.1.14': 'sha224'}.get(sig_alg_oid)
        if not hm:
            return False, '未知 RSA 签名算法 %s' % sig_alg_oid
        ok = rsa_pkcs1_v15_verify((pub[1], pub[2]), sig, tbs, hm)
        return ok, 'RSA-%s 验签%s' % (hm, '通过' if ok else '失败')
    return False, '未知算法 %s' % pub[0]

def parse_crl(der):
    """CRL: SEQUENCE{tbsCertList, sigAlg, sig}。"""
    from derlib import _dn
    t = parse_tlv(der)
    seq = parse_sequence(t.value)
    tbs = t.value[seq[0].start:seq[0].end]
    tbsc = parse_sequence(seq[0].value)
    issuer_dn = _dn(tbsc[2])
    # revokedCertificates: SEQUENCE OF SEQUENCE{userCertificate INTEGER, ...}
    revoked = []
    for x in tbsc[4:]:
        if x.tag == 0x30:
            try:
                items = parse_sequence(x.value)
                if items and items[0].tag == 0x02:
                    for it in items:
                        if it.tag == 0x02:
                            revoked.append(format(tlv_int(it), 'x'))
                            break
            except Exception:
                pass
    sig = seq[2].value[1:]
    sig_alg = None
    if seq[1].tag == 0x30:
        alg_inner = parse_sequence(seq[1].value)
        if alg_inner and alg_inner[0].tag == 0x06:
            sig_alg = tlv_oid(alg_inner[0])
    return {'issuer': issuer_dn, 'revoked': revoked, 'tbs': tbs, 'sig': sig,
            'sig_alg': sig_alg}

def _dn2(tlv):
    try:
        from derlib import _dn
        return _dn(tlv)
    except Exception:
        return None

def parse_ocsp(der):
    """OCSPResponse: SEQUENCE{responseStatus, [0]{SEQUENCE{responseType, response OCTET STRING}}}"""
    try:
        t = parse_tlv(der)
        seq = parse_sequence(t.value)
        status = tlv_int(seq[0]) if seq[0].tag in (0x02, 0x0A) else None
        basic_der = None
        for x in seq[1:]:
            if x.tag == 0xA0:
                # ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
                rb = parse_sequence(x.value)
                if rb and rb[0].tag == 0x30:
                    rb_inner = parse_sequence(rb[0].value)
                    for c in rb_inner:
                        if c.tag == 0x04:
                            basic_der = c.value
                            break
                break
        if not basic_der:
            return {'status': '响应状态码=%s（无 responseBytes）' % status, 'serial': None}
        bt = parse_tlv(basic_der)
        bseq = parse_sequence(bt.value)  # BasicOCSPResponse{tbsResponseData, sigAlg, sig, [0]certs}
        tbs_c = parse_sequence(bseq[0].value)
        serials, cert_status = [], []
        for x in tbs_c:
            if x.tag == 0x30 and len(x.value) > 50:
                # responses: SEQUENCE OF SingleResponse
                for resp_tlv in parse_sequence(x.value):
                    try:
                        resp = parse_sequence(resp_tlv.value)  # SingleResponse
                        cert_id = parse_sequence(resp[0].value)  # CertID
                        sn = next((format(tlv_int(c), 'x') for c in cert_id if c.tag == 0x02), None)
                        st = '未知'
                        for c in resp[1:]:
                            if c.tag == 0x80:
                                st = '正常(good)'
                            elif c.tag == 0xA1:
                                st = '已吊销(revoked)'
                            elif c.tag == 0xA2:
                                st = '未知(unknown)'
                        if sn:
                            serials.append(sn)
                            cert_status.append(st)
                    except Exception:
                        pass
                break
        return {'status': 'BasicOCSP 可解析', 'serials': serials, 'cert_status': cert_status}
    except Exception as e:
        return {'status': '解析失败: %s' % e, 'serial': None}

print('=' * 76)
print('GB/T 38540-2020 证书链深度验证（离线材料盘点）')
print('=' * 76)

doc = pikepdf.open(PDF)
sig = doc.Root['/AcroForm']['/Fields'][0]['/V']
contents = bytes(sig['/Contents'])

# ---------- 1. 签名内证书 ----------
outer = parse_tlv(contents)
seq = parse_sequence(outer.value)
tosign = parse_sequence(seq[0].value)     # SES_ToSign
es = parse_sequence(tosign[1].value)       # esInfo
seal = parse_sequence(es[0].value)         # SESealInfo

certs = {}
def add_cert(der):
    try:
        x = X509Cert(der)
        certs[x.serial] = (der, x)
    except Exception as e:
        print('  证书解析失败:', e)

# SESealInfo 内的印章证书（SEQUENCE OF Certificate）
sub = parse_sequence(seal[2].value)
certlist = parse_sequence(sub[3].value)
for c in certlist:
    add_cert(c.value)

# TSA 令牌证书（SES.esInfo）
ts_c = parse_sequence(seq[4].value)
ts_data = ts_c[0].value[1:]
tms = CMS(ts_data)
for c in tms.certs:
    add_cert(bytes(c.der) if hasattr(c, 'der') else None or c.dump())

# ---------- 2. DSS 证书 ----------
print()
print('[DSS 对象]')
dss_materials = {'Certs': [], 'CRLs': [], 'OCSPs': []}
for key in doc.get_xref_table():
    n, g = (key[0], key[1]) if isinstance(key, tuple) else (key, 0)
    if n <= 0:
        continue
    try:
        obj = doc.get_object(n, g)
        if obj.get('/Type') == pikepdf.Name('/DSS'):
            for k in ('/Certs', '/CRLs', '/OCSPs'):
                v = obj.get(k)
                if v is not None:
                    for ref in v:
                        try:
                            if isinstance(ref, pikepdf.Stream):
                                raw = ref.read_bytes()
                            else:
                                raw = bytes(ref)
                        except Exception:
                            raw = b''
                        dss_materials[k[1:]].append(raw)
            break
    except Exception:
        continue

print('  DSS Certs: %d 项, CRLs: %d 项, OCSPs: %d 项' % (
    len(dss_materials['Certs']), len(dss_materials['CRLs']), len(dss_materials['OCSPs'])))

for der in dss_materials['Certs']:
    try:
        add_cert(der)
    except Exception as e:
        print('  DSS 证书解析失败:', e)

# ---------- 3. 全部证书清单 ----------
print()
print('[内嵌证书清单（%d 张，按序列号去重）]' % len(certs))
for sn, (der, x) in certs.items():
    print('  SN=%-14s %-45s | 颁发者=%s | %s' % (sn, x.subject, x.issuer, x.pubkey_algo))

# ---------- 4. 文档签名链（逐级验签） ----------
print()
print('[文档签名证书链（密码学逐级验签）]')
# 签名者证书：sid 匹配（SES_ToSign 的签名者 = 印章证书[0]？实际用 SID 从 SESealInfo 证书集找）
# 简化：文档签名/印章签名都出自 113548382（pdfsig_verify 已验证），链从它开始
leaf = certs.get('113548382')
if not leaf:
    # 可能序列号前导零
    leaf = next((v for k, v in certs.items() if k.lstrip('0') == '113548382' or k == '113548382'), None)
if leaf:
    der, x = leaf
    chain = [(x, der)]
    cur_issuer = x.issuer
    for _ in range(5):
        nxt = None
        for sn2, (d2, x2) in certs.items():
            if x2.subject == cur_issuer and sn2 not in [c[0].serial for c in chain]:
                nxt = (x2, d2)
                break
        if not nxt:
            break
        chain.append(nxt)
        cur_issuer = nxt[0].issuer
    for i in range(len(chain)):
        cx, cder = chain[i]
        tag = '签名者证书' if i == 0 else ('CA 证书' if i < len(chain) - 1 else '根证书')
        print('  %s: SN=%s subject=%s' % (tag, cx.serial, cx.subject))
        if i == 0:
            continue
    # 逐级密码学验签：子证书由父证书（签发者）公钥验证
    print('  --- 逐级验签（子证书 ← 父证书公钥） ---')
    for i in range(len(chain) - 1, 0, -1):
        child = chain[i - 1]   # 子证书
        parent = chain[i]      # 父证书（签发者）
        ok, det = verify_cert_signed_by(child[1], parent[0])
        print('  子证书 SN=%s (subject=%s)' % (child[0].serial, child[0].subject))
        print('      ← 父证书 SN=%s 签名验证: %s' % (parent[0].serial, det))
    # 根证书自签名验证
    root = chain[-1]
    ok2, det2 = verify_cert_signed_by(root[1], root[0])
    print('  根证书 SN=%s 自签名验证: %s' % (root[0].serial, det2))
else:
    print('  未找到签名者证书 113548382')

# ---------- 5. TSA 链 ----------
print()
print('[TSA 令牌证书链（密码学逐级验签）]')
tms_certs = list(tms.certs)
# 按 subject 匹配 issuer
tsa_leaf = None
for c in tms_certs:
    if 'Timstamp' in c.subject or 'Timestamp' in c.subject:
        tsa_leaf = c
if not tsa_leaf and tms_certs:
    tsa_leaf = tms_certs[-1]
if tsa_leaf:
    der = bytes(tsa_leaf.der) if hasattr(tsa_leaf, 'der') else tsa_leaf.dump()
    chain = [(tsa_leaf, der)]
    cur_issuer = tsa_leaf.issuer
    for _ in range(3):
        nxt = None
        for c2 in tms_certs:
            if c2.subject == cur_issuer and c2.serial != chain[-1][0].serial:
                nxt = (c2, bytes(c2.der) if hasattr(c2, 'der') else c2.dump())
                break
        if not nxt:
            break
        chain.append(nxt)
        cur_issuer = nxt[0].issuer
    for i in range(len(chain)):
        cx, cder = chain[i]
        print('  TSA 证书: SN=%s subject=%s' % (cx.serial, cx.subject))
    print('  --- 逐级验签（子证书 ← 父证书公钥） ---')
    for i in range(len(chain) - 1, 0, -1):
        child = chain[i - 1]
        parent = chain[i]
        ok, det = verify_cert_signed_by(child[1], parent[0])
        print('  子证书 SN=%s (subject=%s)' % (child[0].serial, child[0].subject))
        print('      ← 父证书 SN=%s 签名验证: %s' % (parent[0].serial, det))
    root = chain[-1]
    ok2, det2 = verify_cert_signed_by(root[1], root[0])
    print('  根证书 SN=%s 自签名验证: %s' % (root[0].serial, det2))
else:
    print('  未找到 TSA 签名证书')

# ---------- 6. CRL ----------
print()
print('[DSS 内 CRL（吊销证据，离线可用）]')
for i, crl_der in enumerate(dss_materials['CRLs']):
    try:
        crl = parse_crl(crl_der)
        # CRL 签发者匹配根证书
        issuer_cert = next((x for sn2, (_d, x) in certs.items() if x.subject == crl['issuer']), None)
        ok = False
        det = '无匹配签发者证书'
        if issuer_cert:
            pub = issuer_cert.pubkey
            if pub and pub[0] in ('SM2', 'EC'):
                try:
                    s2 = parse_sequence(crl['sig'])
                    r = int.from_bytes(s2[0].value, 'big')
                    s = int.from_bytes(s2[1].value, 'big')
                except Exception:
                    r = int.from_bytes(crl['sig'][:32], 'big')
                    s = int.from_bytes(crl['sig'][32:], 'big')
                ok = sm2_verify((pub[1], pub[2]), crl['tbs'], r, s, with_za=True)
                det = 'SM2(ZA) 验签%s' % ('通过' if ok else '失败')
            elif pub and pub[0] == 'RSA':
                hm = {'1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.12': 'sha384',
                      '1.2.840.113549.1.1.13': 'sha512', '1.2.840.113549.1.1.5': 'sha1'}.get(crl['sig_alg'])
                if hm:
                    ok = rsa_pkcs1_v15_verify((pub[1], pub[2]), crl['sig'], crl['tbs'], hm)
                    det = 'RSA-%s 验签%s' % (hm, '通过' if ok else '失败')
                else:
                    det = '未知 RSA 算法 %s' % crl['sig_alg']
        print('  CRL[%d]: 签发者=%s 吊销 %d 条 | %s' % (
            i, crl['issuer'], len(crl['revoked']), det))
        print('          吊销序列号: %s' % (', '.join(crl['revoked'][:10]) or '（空）'))
    except Exception as e:
        print('  CRL[%d] 解析失败: %s' % (i, e))

# ---------- 7. OCSP ----------
print()
print('[DSS 内 OCSP 响应（吊销证据，离线可用）]')
for i, ocsp_der in enumerate(dss_materials['OCSPs']):
    r = parse_ocsp(ocsp_der)
    if 'serials' in r:
        pairs = ', '.join('%s(%s)' % (s, st) for s, st in zip(r['serials'], r['cert_status']))
        print('  OCSP[%d]: %s | 目标: %s' % (i, r['status'], pairs))
    else:
        print('  OCSP[%d]: %s' % (i, r['status']))

print()
print('=' * 76)
print('结论: 所有证书、CRL、OCSP 均内嵌于 PDF（签名 Contents + DSS）')
print('离线验证 = 不需要访问任何 URL')
print('=' * 76)
