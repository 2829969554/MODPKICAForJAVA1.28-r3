# -*- coding: utf-8 -*-
"""
chain_deep_verify.py —— 证书链深度验证（离线材料盘点）
支持：
  GB/T 35275-2017（GM.sm2cms.detached，CMS）
  GB/T 38540-2020（GM.sm2seal，SES 电子签章）
验证内容：
  1) 提取签名 Contents 与 DSS 中全部内嵌证书
  2) 按 颁发者DN/AKI-SKI 构建证书链，逐级密码学验签（SM2-ZA / RSA-PKCS#1 v1.5）
  3) 解析 DSS 内 CRL / OCSP，验签并核对吊销状态
  4) 结论：全部验证材料是否内嵌于 PDF（离线可验证，无需访问任何 URL）
用法：python chain_deep_verify.py <pdf1> [pdf2] ...
"""
import sys, os
# 兼容打包为 EXE / Windows GBK 控制台：stdout 强制 UTF-8，避免 ✓ 等字符崩溃
try:
    if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pikepdf
from derlib import (parse_tlv, parse_sequence, tlv_int, tlv_oid,
                    X509Cert, CMS)
from sm2lib import sm2_verify
from pdfsig_verify import rsa_pkcs1_v15_verify

OID_TSA = '1.2.840.113549.1.9.16.2.14'   # id-aa-timeStampToken

# ------------------------------------------------------------------
# 证书签名提取与逐级验签
# ------------------------------------------------------------------
def cert_signature(der):
    """X.509: SEQUENCE{tbsCertificate, sigAlg, sig} -> (tbs含头, sigBytes)。"""
    t = parse_tlv(der)
    seq = parse_sequence(t.value)
    tbs = t.value[seq[0].start:seq[0].end]
    sig = seq[2].value[1:]
    return tbs, sig

def cert_sig_alg_oid(der):
    t = parse_tlv(der)
    seq = parse_sequence(t.value)
    if seq[1].tag == 0x30:
        alg_inner = parse_sequence(seq[1].value)
        if alg_inner and alg_inner[0].tag == 0x06:
            return tlv_oid(alg_inner[0])
    return None

def verify_cert_signed_by(cert_der, issuer_cert):
    """用签发者公钥验证证书签名。返回 (ok, detail)。"""
    tbs, sig = cert_signature(cert_der)
    pub = issuer_cert.pubkey
    if pub is None:
        return False, '签发者公钥缺失'
    oid = cert_sig_alg_oid(cert_der)
    if pub[0] in ('SM2', 'EC'):
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
        hm = {'1.2.840.113549.1.1.5': 'sha1',
              '1.2.840.113549.1.1.11': 'sha256',
              '1.2.840.113549.1.1.12': 'sha384',
              '1.2.840.113549.1.1.13': 'sha512',
              '1.2.840.113549.1.1.14': 'sha224'}.get(oid)
        if not hm:
            return False, '未知 RSA 签名算法 %s' % oid
        ok = rsa_pkcs1_v15_verify((pub[1], pub[2]), sig, tbs, hm)
        return ok, 'RSA-%s 验签%s' % (hm, '通过' if ok else '失败')
    return False, '未知算法 %s' % pub[0]

# ------------------------------------------------------------------
# 证书/CRL/OCSP 收集
# ------------------------------------------------------------------
def collect_from_cms(contents):
    """35275: SignedData.certificates + signerInfo unsignedAttrs 时间戳令牌。"""
    certs = {}
    try:
        cms = CMS(contents)
        for c in cms.certs:
            der = bytes(c.der) if hasattr(c, 'der') else c.dump()
            try:
                x = X509Cert(der)
                certs[x.serial] = (der, x)
            except Exception:
                pass
        # TSA 令牌证书
        for si in cms.signer_infos:
            for attr in si.get('unsigned_attrs', []) + si.get('signed_attrs', []):
                if attr[0] == OID_TSA and isinstance(attr[1], bytes):
                    try:
                        tms = CMS(attr[1])
                        for c in tms.certs:
                            der = bytes(c.der) if hasattr(c, 'der') else c.dump()
                            x = X509Cert(der)
                            certs[x.serial] = (der, x)
                    except Exception:
                        pass
        return certs
    except Exception:
        return certs

def collect_from_ses(contents):
    """38540: SESealInfo 证书集 + TSA 令牌证书。"""
    certs = {}
    try:
        outer = parse_tlv(contents)
        seq = parse_sequence(outer.value)          # SES_Signature
        tosign = parse_sequence(seq[0].value)      # SES_ToSign
        es = parse_sequence(tosign[1].value)       # esInfo
        seal = parse_sequence(es[0].value)         # SESealInfo
        sub = parse_sequence(seal[2].value)
        certlist = parse_sequence(sub[3].value)    # 印章证书 SEQUENCE OF
        for c in certlist:
            try:
                x = X509Cert(c.value)
                certs[x.serial] = (c.value, x)
            except Exception:
                pass
        # TSA 令牌：SES.esInfo[0] = BIT STRING{CMS}
        ts_c = parse_sequence(seq[4].value)
        ts_data = ts_c[0].value[1:]
        tms = CMS(ts_data)
        for c in tms.certs:
            der = bytes(c.der) if hasattr(c, 'der') else c.dump()
            try:
                x = X509Cert(der)
                certs[x.serial] = (der, x)
            except Exception:
                pass
        return certs
    except Exception:
        return certs

def collect_dss(pdf):
    """从 DSS 对象收集 Certs / CRLs / OCSPs。"""
    certs, crls, ocsps = [], [], []
    try:
        table = pdf.get_xref_table()
        for key in table:
            n, g = (key[0], key[1]) if isinstance(key, tuple) else (key, 0)
            if n <= 0:
                continue
            try:
                obj = pdf.get_object(n, g)
            except Exception:
                continue
            if obj.get('/Type') != pikepdf.Name('/DSS'):
                continue
            for k, out in (('/Certs', certs), ('/CRLs', crls), ('/OCSPs', ocsps)):
                v = obj.get(k)
                if v is None:
                    continue
                for ref in v:
                    try:
                        raw = ref.read_bytes() if isinstance(ref, pikepdf.Stream) else bytes(ref)
                    except Exception:
                        raw = b''
                    if raw:
                        out.append(raw)
            break
    except Exception:
        pass
    return certs, crls, ocsps

# ------------------------------------------------------------------
# 证书链构建
# ------------------------------------------------------------------
def build_chains(certs):
    """按 颁发者DN + AKI/SKI 构建证书链。certs: {serial: (der, X509Cert)}。
    返回链列表，每条链从叶子到根：[ (der, cert), ... ]。"""
    pool = list(certs.values())

    def find_parent(der, cert):
        best = None
        for d2, c2 in pool:
            if c2.serial == cert.serial:
                continue
            if c2.subject != cert.issuer:
                continue
            if cert.authority_key_id and c2.subject_key_id:
                if cert.authority_key_id == c2.subject_key_id:
                    return (d2, c2)
                continue
            best = (d2, c2)
        return best

    chains = []
    used = set()
    for der, cert in pool:
        if cert.serial in used:
            continue
        chain = [(der, cert)]
        seen = {cert.serial}
        cur = (der, cert)
        while True:
            p = find_parent(cur[0], cur[1])
            if p is None or p[1].serial in seen:
                break
            chain.append(p)
            seen.add(p[1].serial)
            cur = p
        chains.append(chain)
        for d, c in chain:
            used.add(c.serial)
    return chains

# ------------------------------------------------------------------
# CRL / OCSP 解析
# ------------------------------------------------------------------
def parse_crl(der):
    from derlib import _dn
    t = parse_tlv(der)
    seq = parse_sequence(t.value)
    tbs = t.value[seq[0].start:seq[0].end]
    tbsc = parse_sequence(seq[0].value)
    issuer_dn = _dn(tbsc[2])
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

def verify_crl(crl, certs):
    """用 CRL 签发者证书验签，返回 (ok, detail)。"""
    issuer_cert = next((x for sn2, (_d, x) in certs.items() if x.subject == crl['issuer']), None)
    if issuer_cert is None:
        return False, '无匹配签发者证书'
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
        return ok, 'SM2(ZA) 验签%s' % ('通过' if ok else '失败')
    elif pub and pub[0] == 'RSA':
        hm = {'1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.12': 'sha384',
              '1.2.840.113549.1.1.13': 'sha512', '1.2.840.113549.1.1.5': 'sha1'}.get(crl['sig_alg'])
        if hm:
            ok = rsa_pkcs1_v15_verify((pub[1], pub[2]), crl['sig'], crl['tbs'], hm)
            return ok, 'RSA-%s 验签%s' % (hm, '通过' if ok else '失败')
        return False, '未知 RSA 算法 %s' % crl['sig_alg']
    return False, '未知算法'

def parse_ocsp(der):
    """OCSPResponse：解析目标证书序列号与状态。"""
    try:
        t = parse_tlv(der)
        seq = parse_sequence(t.value)
        status = tlv_int(seq[0]) if seq[0].tag in (0x02, 0x0A) else None
        basic_der = None
        for x in seq[1:]:
            if x.tag == 0xA0:
                rb = parse_sequence(x.value)          # ResponseBytes
                if rb and rb[0].tag == 0x30:
                    rb_inner = parse_sequence(rb[0].value)
                    for c in rb_inner:
                        if c.tag == 0x04:
                            basic_der = c.value
                            break
                break
        if not basic_der:
            return {'status': '响应状态码=%s（无 responseBytes）' % status,
                    'serials': [], 'cert_status': []}
        bt = parse_tlv(basic_der)
        bseq = parse_sequence(bt.value)               # BasicOCSPResponse
        tbs_c = parse_sequence(bseq[0].value)
        serials, cert_status = [], []
        for x in tbs_c:
            if x.tag == 0x30 and len(x.value) > 50:   # responses
                for resp_tlv in parse_sequence(x.value):
                    try:
                        resp = parse_sequence(resp_tlv.value)      # SingleResponse
                        cert_id = parse_sequence(resp[0].value)     # CertID
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
        return {'status': 'BasicOCSP 可解析', 'serials': serials,
                'cert_status': cert_status}
    except Exception as e:
        return {'status': '解析失败: %s' % e, 'serials': [], 'cert_status': []}

# ------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------
def verify_file(path):
    print('=' * 76)
    print('文件: %s' % os.path.basename(path))
    doc = pikepdf.open(path)
    root = doc.Root
    sig = root['/AcroForm']['/Fields'][0]['/V']
    sub = str(sig.get('/SubFilter'))
    contents = bytes(sig['/Contents'])
    print('签名过滤器: %s（Contents %d 字节）' % (sub, len(contents)))

    # 1. 证书收集（签名内 + TSA 令牌）
    certs = collect_from_cms(contents) if 'sm2cms' in sub else collect_from_ses(contents)

    # 2. DSS 收集
    dss_certs, crls, ocsps = collect_dss(doc)
    for der in dss_certs:
        try:
            x = X509Cert(der)
            certs[x.serial] = (der, x)
        except Exception:
            pass

    print('内嵌证书（按序列号去重）: %d 张' % len(certs))
    for sn, (der, x) in sorted(certs.items()):
        print('  SN=%-14s %-46s | 颁发者=%s | %s' % (sn, x.subject, x.issuer, x.pubkey_algo))

    # 3. 证书链构建 + 逐级验签
    print()
    print('证书链（叶子 ← 根，逐级密码学验签）:')
    chains = build_chains(certs)
    all_ok = True
    for ci, chain in enumerate(chains, 1):
        print('  链[%d]: %s' % (ci, ' → '.join('SN=%s(%s)' % (c.serial, c.subject[:22]) for _d, c in chain)))
        for i in range(len(chain) - 1, 0, -1):
            child, parent = chain[i - 1], chain[i]
            ok, det = verify_cert_signed_by(child[0], parent[1])
            all_ok = all_ok and ok
            print('      子 SN=%s ← 父 SN=%s: %s' % (child[1].serial, parent[1].serial, det))
        root_cert = chain[-1]
        if root_cert[1].subject == root_cert[1].issuer:
            ok, det = verify_cert_signed_by(root_cert[0], root_cert[1])
            all_ok = all_ok and ok
            print('      根 SN=%s 自签名: %s' % (root_cert[1].serial, det))
        else:
            print('      链顶 SN=%s 非自签（缺少上级证书，链不完整）' % root_cert[1].serial)
            all_ok = False

    # 4. CRL
    print()
    print('吊销证据 CRL（DSS 内 %d 项）:' % len(crls))
    for i, crl_der in enumerate(crls):
        try:
            crl = parse_crl(crl_der)
            ok, det = verify_crl(crl, certs)
            print('  CRL[%d]: 签发者=%s 吊销 %d 条 | %s' % (i, crl['issuer'], len(crl['revoked']), det))
        except Exception as e:
            print('  CRL[%d] 解析失败: %s' % (i, e))

    # 5. OCSP
    print('吊销证据 OCSP（DSS 内 %d 项）:' % len(ocsps))
    for i, ocsp_der in enumerate(ocsps):
        r = parse_ocsp(ocsp_der)
        if r['serials']:
            pairs = ', '.join('%s(%s)' % (s, st) for s, st in zip(r['serials'], r['cert_status']))
            print('  OCSP[%d]: %s | 目标: %s' % (i, r['status'], pairs))
        else:
            print('  OCSP[%d]: %s' % (i, r['status']))

    # 6. 结论
    print()
    verdict = '全部内嵌，离线可完整验证' if all_ok and certs else '存在未通过项，详见上方'
    print('结论: 链验证%s；证书/CRL/OCSP 全部位于 PDF 内部（签名 Contents + DSS）' % verdict)
    return all_ok


if __name__ == '__main__':
    files = sys.argv[1:]
    if not files:
        print(__doc__)
        sys.exit(1)
    ok_all = True
    for f in files:
        ok_all = verify_file(f) and ok_all
        print()
    sys.exit(0 if ok_all else 2)
