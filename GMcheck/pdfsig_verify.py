# -*- coding: utf-8 -*-
"""
pdfsig_verify.py —— PDF 国密数字签名技术标准验证程序
依据：
  GB/T 35275-2017《信息安全技术 SM2密码算法加密签名消息语法规范》（GM.sm2cms.detached）
  GB/T 38540-2020《信息安全技术 安全电子签章密码技术规范》（GM.sm2seal）
  GB/T 32918-2016 / GB/T 32905-2016（SM2/SM3）
  RFC 5652（CMS）、ISO 32000-1（PDF 签名 ByteRange）
验证项目：
  1) PDF 签名字典结构（Filter/SubFilter/ByteRange/Contents）
  2) 文档内容完整性（ByteRange 双段拼接哈希）
  3) CMS/SES 结构解析（签名者证书、签名算法、签名值、属性）
  4) SM2 密码学验签（含 ZA 计算）
  5) 证书链、时间戳、LTV 存在性
"""
import sys, os, json, datetime, hashlib
# 兼容打包为 EXE / Windows GBK 控制台：stdout 强制 UTF-8，避免 ✓ 等字符崩溃
try:
    if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fitz  # PyMuPDF
from sm2lib import sm3, sm2_verify, sm2_za
from derlib import (parse_tlv, parse_sequence, tlv_int, tlv_oid, X509Cert,
                    CMS, sig_attr, find_child)

OID_SHA1 = '1.3.14.3.2.26'
OID_SHA256 = '2.16.840.1.101.3.4.2.1'
OID_SM3 = '1.2.156.10197.1.401'
OID_TSA = '1.2.840.113549.1.9.16.2.14'          # id-aa-timeStampToken
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'      # messageDigest
OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_CT_TIMESTAMP = '1.2.840.113549.1.9.16.1.4'   # id-ct-TSTInfo
OID_CT_PDFDOC = '1.2.840.113549.1.9.16.1.30'     # id-ct-PDFDocTimeStamp (ETSI)


def digest_of(oid, data):
    oid = oid.strip().lower()
    if oid in (OID_SM3, '1.2.156.10197.1.401'):
        return sm3(data)
    if oid in (OID_SHA256, '2.16.840.1.101.3.4.2.1'):
        return hashlib.sha256(data).digest()
    if oid in (OID_SHA1, '1.3.14.3.2.26'):
        return hashlib.sha1(data).digest()
    if oid == '2.16.840.1.101.3.4.2.2':
        return hashlib.sha384(data).digest()
    if oid == '2.16.840.1.101.3.4.2.3':
        return hashlib.sha512(data).digest()
    return None


def alg_family(oid):
    o = oid.strip().lower()
    if '1.2.156.10197.1.501' in o:
        return 'SM2'
    if o.startswith('1.2.840.113549.1.1'):
        return 'RSA'
    if o.startswith('1.2.840.10045'):
        return 'ECC'
    return oid


class Verdict:
    def __init__(self):
        self.items = []

    def add(self, name, ok, detail='', warn=False):
        self.items.append({'item': name, 'ok': ok, 'detail': detail, 'warn': warn})

    def summary(self):
        ok = sum(1 for i in self.items if i['ok'])
        warns = sum(1 for i in self.items if not i['ok'] and i.get('warn'))
        s = '%d/%d 项通过' % (ok, len(self.items))
        if warns:
            s += '（%d 项警告）' % warns
        return s, all(i['ok'] or i.get('warn') for i in self.items)


def find_sig_xrefs(doc):
    out = []
    for xref in range(1, doc.xref_length()):
        try:
            t = doc.xref_get_key(xref, 'Type')
            if t[0] == 'name' and t[1] == '/Sig':
                out.append(xref)
        except Exception:
            pass
    return out


def get_contents_bytes(doc, xref):
    """从签名对象原始文本中提取 <...> hex string 并解码为字节。"""
    import re
    raw = doc.xref_object(xref)
    m = re.search(r'/Contents\s*<([0-9a-fA-F\s]*)>', raw)
    if m:
        hexs = m.group(1).replace('\n', '').replace(' ', '')
        try:
            return bytes.fromhex(hexs)
        except Exception:
            return None
    return None


def get_byte_range(doc, xref):
    r = doc.xref_get_key(xref, 'ByteRange')
    if r[0] != 'array':
        return None
    s = r[1]
    nums = [int(x) for x in s.replace('[', '').replace(']', '').split()]
    return nums


def doc_bytes_in_range(doc, br):
    """ByteRange: [a b c d] → 段1=a..a+b, 段2=c..c+d。"""
    if len(br) != 4:
        return None
    a, b, c, d = br
    with open(doc.name, 'rb') as f:
        f.seek(a)
        p1 = f.read(b)
        f.seek(c)
        p2 = f.read(d)
    return p1 + p2


def rsa_pkcs1_v15_verify(pub, sig, data, hash_name):
    """RSA PKCS#1 v1.5 验签。pub=(n,e)。"""
    n, e = pub
    m = int.from_bytes(sig, 'big')
    if m >= n:
        return False
    em = pow(m, e, n).to_bytes((n.bit_length() + 7) // 8, 'big')
    # EM = 00 01 FF..FF 00 DigestInfo，跳过填充定位 DigestInfo（0x30）
    try:
        if em[0] != 0 or em[1] != 1:
            return False
        sep = em.find(b'\x00', 2)
        if sep < 0:
            return False
        di = parse_tlv(em[sep + 1:])
        seq = parse_sequence(di.value)
        alg = seq[0].children()
        oid = tlv_oid(alg[0])
        expected = {'1.3.14.3.2.26': hashlib.sha1, '2.16.840.1.101.3.4.2.1': hashlib.sha256,
                    '2.16.840.1.101.3.4.2.2': hashlib.sha384, '2.16.840.1.101.3.4.2.3': hashlib.sha512}[oid]
        if expected(data).digest() == seq[1].value:
            return True
    except Exception:
        pass
    return False


def der_ecdsa_to_rs(sig):
    """把 DER 编码的 ECDSA/SM2 签名（SEQUENCE{INTEGER r, INTEGER s}）解码为 (r, s)。"""
    if len(sig) == 64:
        return int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    try:
        t = parse_tlv(sig)
        if t.tag != 0x30:
            return None
        seq = parse_sequence(t.value)
        if len(seq) < 2:
            return None
        return tlv_int(seq[0]), tlv_int(seq[1])
    except Exception:
        return None


def verify_signature(alg_oid, pub, sig_bytes, msg):
    """通用验签入口。返回 (ok, detail)。"""
    fam = alg_family(alg_oid)
    if fam == 'SM2':
        # pub 形如 ('EC'/'SM2', x, y) 或 (x, y)
        if isinstance(pub, tuple) and len(pub) == 3 and isinstance(pub[1], int):
            px, py = pub[1], pub[2]
        elif isinstance(pub, tuple) and len(pub) >= 2 and isinstance(pub[0], int):
            px, py = pub[0], pub[1]
        else:
            return False, '公钥格式无法识别: %r' % (pub,)
        rs = der_ecdsa_to_rs(sig_bytes)
        if rs is None:
            return False, 'SM2 签名值解码失败（长度 %d）' % len(sig_bytes)
        r, s = rs
        # 先按标准（ZA || M），失败再按 SM3(M)
        ok, d1 = sm2_verify((px, py), msg, r, s, with_za=True)
        if ok:
            return True, 'SM3(ZA||M) 模式验签通过'
        ok2, d2 = sm2_verify((px, py), msg, r, s, with_za=False)
        if ok2:
            return True, 'SM3(M) 模式验签通过'
        return False, 'ZA模式: %s; 简模式: %s' % (d1, d2)
    if fam == 'RSA':
        # 摘要算法从签名算法 OID 推断
        h = {'1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.5': 'sha1',
             '1.2.840.113549.1.1.12': 'sha384', '1.2.840.113549.1.1.13': 'sha512',
             '1.2.840.113549.1.1.14': 'sha224'}.get(alg_oid.lower())
        if not h:
            return False, '未识别 RSA 哈希'
        return rsa_pkcs1_v15_verify(pub, sig_bytes, msg, h), 'RSA-PKCS1v1.5'
    return False, '暂不支持算法 ' + alg_oid


def find_cert(cms, sid):
    """按 SignerInfo sid 匹配证书。"""
    if not sid:
        return None
    if sid[0] == 'ski':
        ski = sid[1]
        for c in cms.certs:
            if c.subject_key_id.replace(':', '') == ski.replace(':', ''):
                return c
    elif sid[0] == 'issuerAndSerial':
        ser = sid[2].lower()
        for c in cms.certs:
            if c.serial.lower() == ser:
                return c
    return None


def parse_tsa_token(der):
    """解析 TimeStampToken（RFC 3161）最外层信息 + TSTInfo 关键字段。"""
    try:
        cms = CMS(der)
        out = {'certs': len(cms.certs), 'contentType': cms.content_type, 'signers': []}
        for si in cms.signer_infos:
            out['signers'].append({
                'digest': si['digest_algo'], 'sigAlg': si['signature_algo'],
                'signedAttrs': [o for o, _ in si['signed_attrs']]})
        # 提取 eContent 中的 TSTInfo（RFC 3161）
        try:
            outer = parse_tlv(der)
            seq = parse_sequence(outer.value)
            sd = seq[1].children()[0]
            sd_c = parse_sequence(sd.value)
            if sd_c[2].tag == 0x30:  # encapContentInfo
                eci = sd_c[2]
                eci_c = parse_sequence(eci.value)
                econtent = None
                for c in eci_c:
                    if c.tag == 0xA0:  # [0] EXPLICIT OCTET STRING
                        inner = parse_sequence(c.value)
                        if inner and inner[0].tag == 0x04:
                            econtent = inner[0].value
                            break
                    elif c.tag == 0x04:
                        econtent = c.value
                        break
            if econtent:
                tst_wrap = parse_sequence(econtent)
                tst = tst_wrap[0].children() if tst_wrap and tst_wrap[0].tag == 0x30 else tst_wrap
                for c in tst:
                    if c.tag == 0x06:
                        out['tstInfo_policy'] = tlv_oid(c)
                    if c.tag == 0x02 and len(c.value) == 1:
                        out['tstInfo_version'] = tlv_int(c)
                    if c.tag == 0x18:
                        out['tstInfo_genTime'] = c.value.decode('ascii', 'replace')
                # messageImprint
                for c in tst:
                    if c.tag == 0x30:
                        sub = parse_sequence(c.value)
                        if sub and sub[0].tag == 0x06:
                            out['messageImprint_alg'] = tlv_oid(sub[0])
                            for s in sub:
                                if s.tag == 0x04:
                                    out['messageImprint_digest'] = s.value.hex()[:24]
                                elif s.tag == 0x03:
                                    out['messageImprint_digest'] = s.value[1:].hex()[:24]
        except Exception:
            pass
        return out
    except Exception as e:
        return {'error': str(e)}


def verify_pdf(path):
    v = Verdict()
    doc = fitz.open(path)
    v.add('PDF 可打开', True, '页数=%d' % doc.page_count)
    sigs = find_sig_xrefs(doc)
    v.add('存在签名域', len(sigs) > 0, '签名对象 xref=%s' % sigs)
    if not sigs:
        doc.close()
        return v
    xref = sigs[0]
    sub = doc.xref_get_key(xref, 'SubFilter')[1]
    flt = doc.xref_get_key(xref, 'Filter')[1]
    v.add('签名过滤器', True, 'Filter=%s SubFilter=%s' % (flt, sub))
    br = get_byte_range(doc, xref)
    v.add('ByteRange 结构', br is not None and len(br) == 4, 'ByteRange=%s' % br)
    contents = get_contents_bytes(doc, xref)
    v.add('签名内容存在', contents is not None and len(contents) > 0, 'Contents 长度=%d 字节' % (len(contents) if contents else 0))
    if contents is None or br is None:
        doc.close()
        return v
    # 文档内容哈希
    docdata = doc_bytes_in_range(doc, br)
    v.add('ByteRange 分段可读', docdata is not None, '覆盖字节=%d' % (len(docdata) if docdata else 0))
    if docdata is None:
        doc.close()
        return v

    if 'sm2cms' in sub:
        _verify_cms(v, contents, docdata)
    elif 'sm2seal' in sub:
        _verify_ses(v, contents, docdata)
    else:
        _verify_cms(v, contents, docdata)

    # LTV / DSS 完整性（ISO 32000-1 §12.8.4）
    # 注意：fitz 对压缩对象（object stream）的键读取不可靠，且可能把
    # Catalog 的 /DSS 引用当成 DSS 对象；这里用 pikepdf 精确读取真实 DSS。
    dss = None
    n_certs = n_crls = n_ocsps = 0
    try:
        import pikepdf
        pdoc = pikepdf.open(path)
        table = pdoc.get_xref_table()
        for key in table:
            n, g = (key[0], key[1]) if isinstance(key, tuple) else (key, 0)
            if n <= 0:
                continue
            try:
                obj = pdoc.get_object(n, g)
                if obj.get('/Type') == pikepdf.Name('/DSS'):
                    dss = n
                    for k in ('/Certs', '/CRLs', '/OCSPs'):
                        arr = obj.get(k)
                        if arr is not None:
                            if k == '/Certs':
                                n_certs = len(arr)
                            elif k == '/CRLs':
                                n_crls = len(arr)
                            else:
                                n_ocsps = len(arr)
                    break
            except Exception:
                continue
    except ImportError:
        # 回退：fitz 直接对象扫描
        for i in range(1, doc.xref_length()):
            try:
                if doc.xref_get_key(i, 'Type')[1] == '/DSS':
                    dss = i
                    break
            except Exception:
                pass
    v.add('LTV/DSS 对象', dss is not None, 'DSS 对象=%s' % dss)
    if dss is not None:
        has_material = (n_certs + n_crls + n_ocsps) > 0
        v.add('DSS 验证材料', has_material,
              'Certs=%d CRLs=%d OCSPs=%d（ISO 32000-1 LTV）' % (n_certs, n_crls, n_ocsps),
              warn=True)
    else:
        v.add('DSS 验证材料', False, '无 DSS 对象（无 LTV）', warn=True)
    # 文件增量（签名后零增量检查）
    doc.close()
    return v


def der_len(n):
    """DER 最小长度编码（短格式/长格式）。"""
    if n < 128:
        return bytes([n])
    bs = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(bs)]) + bs


def _verify_cms(v, contents, docdata):
    try:
        cms = CMS(contents)
    except Exception as e:
        v.add('CMS 解析', False, str(e))
        return
    v.add('CMS 结构解析', True, 'contentType=%s 证书数=%d 签名者数=%d' % (
        cms.content_type, len(cms.certs), len(cms.signer_infos)))
    if getattr(cms, 'cert_errors', None):
        v.add('证书解析错误', False, '; '.join(cms.cert_errors[:3]))
    if not cms.signer_infos:
        v.add('签名者信息', False, '无 SignerInfo')
        return
    si = cms.signer_infos[0]
    cert = find_cert(cms, si.get('sid'))
    v.add('签名证书匹配', cert is not None,
          '证书=%s' % (cert.subject if cert else str(si.get('sid'))))
    v.add('签名算法', True, '%s（摘要 %s / %s）' % (si['signature_algo'], si['digest_algo'], si.get('digest_oid')))
    # 摘要属性
    md = sig_attr(si, OID_MESSAGE_DIGEST)
    if md:
        mdval = md[0]
        # 计算文档摘要
        calc = digest_of(si.get('digest_oid', ''), docdata)
        v.add('messageDigest 与文档内容一致', calc is not None and calc == mdval,
              '声明=%s 计算=%s' % (mdval.hex()[:16] if mdval else None,
                                 calc.hex()[:16] if calc else None))
    else:
        calc = digest_of(si.get('digest_oid', ''), docdata)
        v.add('文档内容摘要计算', calc is not None, 'SM3=%s' % (calc.hex()[:16] if calc else None))
    # 签名目标
    if si['signed_attrs']:
        # RFC 5652：签名对象为 signedAttrs 的 DER 编码（SET 去掉隐式标记）
        from derlib import parse_tlv as _pt
        # 重建 signedAttrs 的 DER（SET OF 需按 DER 排序并编码）
        try:
            # 从原始 CMS 中取 signedAttrs 的完整 DER：重新定位
            outer = _pt(contents)
            seq = parse_sequence(outer.value)
            sd = seq[1].children()[0]
            sd_c = parse_sequence(sd.value)
            i = 3
            if i < len(sd_c) and sd_c[i].tag == 0xA0:
                i += 1
            if i < len(sd_c) and sd_c[i].tag == 0xA1:
                i += 1
            sis = sd_c[i].children()
            si_tlv = sis[0]
            si_c = parse_sequence(si_tlv.value)
            # 找 A0（signedAttrs）
            sa_tlv = None
            for c in si_c:
                if c.tag == 0xA0:
                    sa_tlv = c
                    break
            if sa_tlv is not None:
                # signedAttrs 的 DER SET 编码（最小长度）：签名对象
                inner = sa_tlv.value
                msg = b'\x31' + der_len(len(inner)) + inner
                ok, d = verify_signature(si.get('signature_oid', si['signature_algo']), cert.pubkey, si['signature'], msg) if cert else (False, '无证书')
                v.add('SM2 签名验签（signedAttrs）', ok, d)
            else:
                v.add('SM2 签名验签', False, '未找到 signedAttrs')
        except Exception as e:
            v.add('SM2 签名验签', False, '解析 signedAttrs 异常: %s' % e)
    else:
        ok, d = verify_signature(si['signature_algo'], cert.pubkey, si['signature'], docdata) if cert else (False, '无证书')
        v.add('SM2 签名验签（文档内容）', ok, d)
    # 时间戳
    ts = None
    for o, vals in si.get('unsigned_attrs', []):
        if o == OID_TSA:
            ts = vals
    if ts:
        info = parse_tsa_token(ts if isinstance(ts, bytes) else ts[0])
        v.add('时间戳令牌存在（RFC3161）', True, json.dumps(info, ensure_ascii=False)[:200])
    else:
        v.add('时间戳令牌存在（RFC3161）', False, 'unsignedAttrs 中无 id-aa-timeStampToken')
    # 证书链
    if cert:
        chain = [cert.subject]
        issuer_ser = cert.authority_key_id
        pool = cms.certs
        for _ in range(5):
            found = None
            for c in pool:
                if issuer_ser and c.subject_key_id == issuer_ser:
                    found = c
                    break
                if c.serial and cert.issuer and c.subject == cert.issuer:
                    found = c
                    break
            if not found:
                break
            chain.append(found.subject)
            issuer_ser = found.authority_key_id
            pool = [c for c in pool if c is not found]
        v.add('证书链', True, ' → '.join(chain[:4]))


def _verify_ses(v, contents, docdata):
    """GB/T 38540-2020 SES 结构深度验证：
    结构 → toSign 解析 → 印章签名（SESealInfo）→ 外层签名（SES_ToSign）→ 时间戳 → 证书链。"""
    try:
        outer = parse_tlv(contents)
        if outer.tag != 0x30:
            v.add('SES 结构解析', False, '顶层非 SEQUENCE')
            return
        seq = parse_sequence(outer.value)
        v.add('SES 结构解析', True, '顶层子元素=%d' % len(seq))
        if len(seq) < 5:
            v.add('SES 字段数', False, '不足 5 个字段')
            return
        for idx, c in enumerate(seq):
            v.add('SES 字段%d 类型' % idx, True, 'tag=0x%02x len=%d' % (c.tag, len(c.value)))
        # 字段0 = SES_ToSign
        tosign_val = seq[0].value
        tosign_full = outer.value[seq[0].start:seq[0].end]  # 含 0x30 头
        c0 = parse_sequence(tosign_val)
        if len(c0) < 5:
            v.add('SES_ToSign 解析', False, '子字段不足 5')
            return
        v.add('SES_ToSign 解析', True,
              'version=%d esInfo=%dB 时间=%s 签名值=%dB 类型=%s' % (
                  tlv_int(c0[0]), len(c0[1].value),
                  c0[2].value.decode('ascii', 'replace'),
                  len(c0[3].value) - 1,
                  c0[4].value.decode('ascii', 'replace')))
        # esInfo：{ SESealInfo, 图片, digestAlg, 印章签名 }
        esinfo_val = c0[1].value
        e1 = parse_sequence(esinfo_val)
        if len(e1) < 4:
            v.add('印章信息解析', False, 'esInfo 字段不足')
            return
        sealinfo_full = esinfo_val[e1[0].start:e1[0].end]   # SESealInfo 含头
        seal_img = e1[1].value
        v.add('印章信息解析', True,
              'SESealInfo=%dB 图片=%dB(%s) 摘要算法OID=%s 印章签名=%dB' % (
                  len(sealinfo_full), len(seal_img),
                  ('PNG' if seal_img[:8] == b'\x89PNG\r\n\x1a\n' else '未知'),
                  tlv_oid(e1[2]), len(e1[3].value) - 1))
        # SESealInfo 内部：headerInfo + sealID + eSealInfo + 证书链等
        e1a = parse_sequence(e1[0].value)
        sealid = ''
        certs = []
        # 递归收集 SEQUENCE 内的证书（可能是 SEQUENCE 或 OCTET 包裹）
        def _collect_certs(buf):
            got = []
            try:
                items = parse_sequence(buf)
            except Exception:
                return got
            for x in items:
                if x.tag == 0x30 and len(x.value) > 300:
                    try:
                        got.append(X509Cert(x.value))
                        continue
                    except Exception:
                        pass
                    got.extend(_collect_certs(x.value))
                elif x.tag == 0x04 and len(x.value) > 300:
                    try:
                        got.append(X509Cert(x.value))
                        continue
                    except Exception:
                        pass
            return got
        for x in e1a:
            if x.tag == 0x16 and not sealid:
                sealid = x.value.decode('ascii', 'replace')
            if x.tag == 0x30:
                certs.extend(_collect_certs(x.value))
        # 去重（按序列号）
        seen_ser = set()
        uniq_certs = []
        for c in certs:
            if c.serial not in seen_ser:
                seen_ser.add(c.serial)
                uniq_certs.append(c)
        certs = uniq_certs
        v.add('印章 ID', bool(sealid), 'sealID=%s' % (sealid or '未找到'))
        v.add('印章证书提取', len(certs) >= 2,
              '证书数=%d %s' % (len(certs), ' → '.join(c.subject for c in certs[:3])))
        # 印章签名验签（对 SESealInfo 含头 DER）
        inner_sig = e1[3].value[1:]
        ok_s, d_s = _try_sm2_certs(certs, sealinfo_full, inner_sig)
        v.add('印章签名验签（SESealInfo）', ok_s, d_s)
        # 外层签名验签（对 SES_ToSign 含头 DER）
        outer_sig = seq[3].value[1:]
        ok_o, d_o = _try_sm2_certs(certs, tosign_full, outer_sig)
        v.add('文档签名验签（SES_ToSign）', ok_o, d_o)
        # 时间戳令牌 [0] { BIT STRING { CMS } }
        try:
            ts_c = parse_sequence(seq[4].value)
            ts_data = ts_c[0].value[1:] if ts_c and ts_c[0].tag == 0x03 else None
            if ts_data:
                tms = CMS(ts_data)
                tsa_cert = None
                for c in tms.certs:
                    if c.subject_key_id:
                        tsa_cert = c
                ts_ok = len(tms.certs) >= 1
                ts_detail = '证书数=%d' % len(tms.certs)
                # TSA 签名验签
                if tms.signer_infos:
                    tsi = tms.signer_infos[0]
                    tc = find_cert(tms, tsi.get('sid'))
                    tsa_msg = _cms_signed_attrs_der(ts_data, tsi)
                    if tc and tsa_msg:
                        ok_t, d_t = verify_signature(tsi.get('signature_oid', tsi['signature_algo']),
                                                     tc.pubkey, tsi['signature'], tsa_msg)
                        ts_detail += '；TSA 验签：%s' % ('通过' if ok_t else '失败(%s)' % d_t)
                        ts_ok = ts_ok and ok_t
                v.add('时间戳令牌验证（GB/T 38540）', ts_ok, ts_detail)
            else:
                v.add('时间戳令牌验证（GB/T 38540）', False, '字段4 内非 BIT STRING')
        except Exception as e:
            v.add('时间戳令牌验证（GB/T 38540）', False, str(e)[:80])
        # 证书链
        if certs:
            chain = [certs[0].subject]
            issuer_ser = certs[0].authority_key_id
            pool = certs
            for _ in range(5):
                found = None
                for c in pool:
                    if issuer_ser and c.subject_key_id == issuer_ser:
                        found = c
                        break
                    if c.serial and certs[0].issuer and c.subject == certs[0].issuer:
                        found = c
                        break
                if not found:
                    break
                chain.append(found.subject)
                issuer_ser = found.authority_key_id
                pool = [c for c in pool if c is not found]
            v.add('证书链', len(chain) >= 2, ' → '.join(chain[:4]))
    except Exception as e:
        v.add('SES 结构解析', False, str(e)[:120])


def _try_sm2_certs(certs, msg, sig_bytes):
    """用证书集逐个尝试 SM2 验签（ZA/简模式）。返回 (ok, detail)。"""
    rs = der_ecdsa_to_rs(sig_bytes)
    if rs is None:
        return False, '签名值解码失败（%d 字节）' % len(sig_bytes)
    r, s = rs
    for c in certs:
        if c.pubkey_algo not in ('EC', 'SM2'):
            continue
        try:
            px, py = c.pubkey[1], c.pubkey[2]
        except Exception:
            continue
        for za in (True, False):
            ok, d = sm2_verify((px, py), msg, r, s, with_za=za)
            if ok:
                return True, '由 %s 验签通过（%s）' % (c.serial, 'SM3(ZA||M)' if za else 'SM3(M)')
    return False, '证书集内无匹配（R 与 r 不一致）'


def _cms_signed_attrs_der(cms_der, si):
    """从 CMS 原始 DER 重建签名对象的 signedAttrs DER SET 编码。"""
    try:
        outer = parse_tlv(cms_der)
        seq = parse_sequence(outer.value)
        sd = seq[1].children()[0]
        sd_c = parse_sequence(sd.value)
        i = 3
        if i < len(sd_c) and sd_c[i].tag == 0xA0:
            i += 1
        if i < len(sd_c) and sd_c[i].tag == 0xA1:
            i += 1
        sis = sd_c[i].children()
        # 匹配 si：取第一个
        si_tlv = sis[0]
        si_c = parse_sequence(si_tlv.value)
        for c in si_c:
            if c.tag == 0xA0:
                inner = c.value
                return b'\x31' + der_len(len(inner)) + inner
    except Exception:
        pass
    return None


if __name__ == '__main__':
    files = sys.argv[1:] or [
        r'C:\Users\28299\Desktop\modpkica4JAVA\国密GBT35275-2017签名PDF样本.pdf',
        r'C:\Users\28299\Desktop\modpkica4JAVA\国密GBT38540-2020签名PDF样本.pdf']
    for f in files:
        print('=' * 78)
        print('验证文件:', os.path.basename(f))
        v = verify_pdf(f)
        for it in v.items:
            if it['ok']:
                mark = '✓'
            elif it.get('warn'):
                mark = '⚠'
            else:
                mark = '✗'
            print('  %s %-32s %s' % (mark, it['item'], it['detail']))
        s, _ = v.summary()
        print('  汇总:', s)
