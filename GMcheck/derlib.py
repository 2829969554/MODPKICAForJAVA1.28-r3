# -*- coding: utf-8 -*-
"""
derlib.py —— 纯 Python DER（ASN.1）解析：TLV、OID、X.509 证书、CMS SignedData
依据：ITU-T X.690（BER/DER 编码）、RFC 5280（X.509）、RFC 5652（CMS）
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------------- TLV 解析 ----------------
class TLV:
    __slots__ = ('tag', 'cls', 'constructed', 'value', 'start', 'end', 'header_len')

    def __init__(self, tag, cls, constructed, value, start, end, header_len):
        self.tag = tag
        self.cls = cls          # 0 universal, 1 application, 2 context, 3 private
        self.constructed = constructed
        self.value = value      # 值内容（不含 tag/len）
        self.start = start      # 整个 TLV 起始
        self.end = end          # 结束（不含）
        self.header_len = header_len

    def children(self):
        """解析子元素（构造类型）。"""
        if not self.constructed:
            raise ValueError('TLV 0x%02x 不是构造类型' % self.tag)
        return parse_sequence(self.value)

    def __repr__(self):
        return '<TLV tag=%02x len=%d>' % (self.tag, len(self.value))


def parse_tlv(data, off=0):
    if off >= len(data):
        raise ValueError('数据越界')
    first = data[off]
    cls = (first >> 6) & 3
    constructed = bool(first & 0x20)
    tag = first  # 完整首字节（含 class/constructed 位），如 0x30 SEQUENCE、0xA0 [0]、0x80 [0] primitive
    if (first & 0x1F) == 0x1F:  # 多字节 tag（少见，简化处理）
        tag = 0
        while off < len(data):
            off += 1
            tag = (tag << 7) | (data[off] & 0x7F)
            if not data[off] & 0x80:
                break
    off += 1
    if off >= len(data):
        raise ValueError('缺少长度')
    lb = data[off]
    off += 1
    if lb & 0x80:
        n = lb & 0x7F
        if n > 8:
            raise ValueError('长度字段过长')
        length = int.from_bytes(data[off:off + n], 'big')
        off += n
    else:
        length = lb
    if off + length > len(data):
        raise ValueError('值越界: need %d have %d' % (length, len(data) - off))
    return TLV(tag, cls, constructed, data[off:off + length], off - 2 - (0 if lb < 0x80 else (lb & 0x7F)), off + length, off)


def parse_sequence(data):
    out = []
    off = 0
    while off < len(data):
        t = parse_tlv(data, off)
        out.append(t)
        off = t.end
    return out


def tlv_int(t):
    """INTEGER 值 → int（处理符号位）。"""
    v = t.value
    if not v:
        return 0
    if v[0] & 0x80:  # 负数：取补码
        return int.from_bytes(v, 'big') - (1 << (len(v) * 8))
    return int.from_bytes(v, 'big')


def tlv_oid(t):
    """OID 值 → 点分字符串。"""
    v = t.value
    parts = []
    first = v[0]
    parts.append(str(first // 40))
    parts.append(str(first % 40))
    num = 0
    for b in v[1:]:
        num = (num << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(num))
            num = 0
    return '.'.join(parts)


def tlv_utc(t):
    """UTCTime / GeneralizedTime → 字符串。"""
    try:
        return t.value.decode('ascii')
    except Exception:
        return t.value.hex()


def find_child(children, tag):
    for c in children:
        if c.tag == tag and c.cls == 0:
            return c
    return None


# ---------------- X.509 证书解析（RFC 5280） ----------------
class X509Cert:
    def __init__(self, der):
        self.der = der
        self.serial = ''
        self.subject = ''
        self.issuer = ''
        self.not_before = ''
        self.not_after = ''
        self.pubkey_algo = ''
        self.pubkey = None          # (algo, params)
        self.sig_algo = ''
        self.sig_value = b''
        self.eku = []               # 增强型密钥用法 OID 列表
        self.basic_constraints = None  # (is_ca, pathlen)
        self.subject_key_id = b''
        self.authority_key_id = b''
        self.cert_policy_oids = []  # 证书策略 OID
        self.parse()

    def parse(self):
        tbs_fields, sigs = _normalize_cert(self.der)
        # sigAlg / sigValue
        if sigs:
            self.sig_algo = _algo_name(_oid_of(sigs[0].children()[0]))
            if len(sigs) > 1:
                self.sig_value = sigs[1].value
        tbs_c = tbs_fields
        i = 0
        # 版本（可选）
        if tbs_c[0].tag == 0xA0:
            ver = tlv_int(tbs_c[0].children()[0]) + 1
            i = 1
        else:
            ver = 1
        self.version = ver
        self.serial = format(tlv_int(tbs_c[i]), 'x')
        i += 1
        self.sig_algo_tbs = _algo_name(_oid_of(tbs_c[i]))
        i += 1
        self.issuer = _dn(tbs_c[i])
        i += 1
        validity = tbs_c[i].children()
        i += 1
        self.not_before = tlv_utc(validity[0])
        self.not_after = tlv_utc(validity[1])
        self.subject = _dn(tbs_c[i])
        i += 1
        # SPKI
        spki = tbs_c[i]
        i += 1
        spki_c = parse_sequence(spki.value)
        self.pubkey_oid = _oid_of(spki_c[0].children()[0]) if spki_c[0].constructed else _oid_of(spki_c[0])
        self.pubkey_algo = _algo_name(self.pubkey_oid)
        bitstr = spki_c[1].value
        if bitstr:
            unused = bitstr[0]
            self.pubkey_bits = bitstr[1:]
        else:
            self.pubkey_bits = b''
        # 公钥解析
        if self.pubkey_algo.startswith('RSA'):
            rs = parse_sequence(self.pubkey_bits)
            if rs and rs[0].tag == 0x30:
                rs = rs[0].children()
            self.pubkey = ('RSA', tlv_int(rs[0]), tlv_int(rs[1]))
        elif self.pubkey_algo.startswith('EC'):
            # EC 点（未压缩 04 || X || Y）
            raw = self.pubkey_bits
            if raw and raw[0] == 4:
                ln = (len(raw) - 1) // 2
                self.pubkey = ('EC', int.from_bytes(raw[1:1 + ln], 'big'),
                               int.from_bytes(raw[1 + ln:], 'big'))
            else:
                self.pubkey = ('EC', None, None)
        elif self.pubkey_algo.startswith('SM2'):
            raw = self.pubkey_bits
            if raw and raw[0] == 4:
                ln = (len(raw) - 1) // 2
                self.pubkey = ('SM2', int.from_bytes(raw[1:1 + ln], 'big'),
                               int.from_bytes(raw[1 + ln:], 'big'))
            else:
                self.pubkey = ('SM2', None, None)
        else:
            self.pubkey = (self.pubkey_algo, None, None)
        # 扩展
        if i < len(tbs_c) and tbs_c[i].tag == 0xA3:
            exts = tbs_c[i].children()[0].children()
            for e in exts:
                ec = e.children()
                oid = _oid_of(ec[0])
                # 跳过 critical BOOLEAN，取 ExtnValue OCTET STRING
                val = b''
                for ecx in ec[1:]:
                    if ecx.tag == 0x04:
                        val = ecx.value
                        break
                if oid == '2.5.29.37':  # EKU
                    ekus = parse_sequence(val)
                    if ekus and ekus[0].tag == 0x30:
                        ekus = ekus[0].children()
                    for sub in ekus:
                        self.eku.append(tlv_oid(sub))
                elif oid == '2.5.29.19':  # BasicConstraints
                    if val:
                        bc = parse_sequence(val)
                        if bc and bc[0].tag == 0x30:
                            bc = bc[0].children()
                        ca = bool(tlv_int(bc[0])) if bc and bc[0].tag == 0x02 else False
                        pl = None
                        if len(bc) > 1 and bc[1].tag == 0x02:
                            pl = tlv_int(bc[1])
                        self.basic_constraints = (ca, pl)
                elif oid == '2.5.29.14':  # SKI（ExtnValue = OCTET STRING { keyid }）
                    ski = parse_tlv(val)
                    if ski.tag == 0x04:
                        self.subject_key_id = ski.value.hex()
                    else:
                        self.subject_key_id = val.hex()
                elif oid == '2.5.29.35':  # AKI
                    if val:
                        aki = parse_sequence(val)
                        if aki and aki[0].tag == 0x30:
                            aki = aki[0].children()
                        for sub in aki:
                            if sub.tag == 0x80:
                                self.authority_key_id = sub.value.hex()
                elif oid == '2.5.29.32':  # CertificatePolicies
                    try:
                        pols = parse_sequence(val)
                        if pols and pols[0].tag == 0x30:
                            pols = pols[0].children()
                        for pol in pols:
                            pc = parse_sequence(pol.value)
                            self.cert_policy_oids.append(tlv_oid(pc[0]))
                    except Exception:
                        pass

    def key_len(self):
        if self.pubkey and self.pubkey[0] == 'RSA':
            return self.pubkey[1].bit_length()
        if self.pubkey and self.pubkey[0] in ('EC', 'SM2'):
            return len(self.pubkey_bits) * 4 if self.pubkey_bits else 0
        return 0


def _normalize_cert(der):
    """把多种证书编码归一化为 (tbs字段TLV列表, [sigAlg, sigVal])。

    支持：
      A) 标准 X.509 证书 DER：SEQUENCE { TBS_SEQUENCE, sigAlg, sigVal }
      B) 证书 SEQUENCE 的 value：TBS字段展开 + sigAlg + sigVal（以 0x30 开头）
      C) 证书 SEQUENCE 的 value 变体：SEQUENCE(TBS展开) + sigAlg + sigVal
      D) 裸流：TBS字段展开 + sigAlg + sigVal（以 version [0] 开头）
    """
    if der[0] == 0x30:
        outer = parse_tlv(der)
        rest = der[outer.end:]
        seq = parse_sequence(outer.value)
        if seq and seq[0].tag == 0xA0:
            # outer.value = TBS 字段展开（version 开头）
            tbs_fields = seq
            sigs = parse_sequence(rest) if rest else []
        elif len(seq) >= 3 and seq[0].tag == 0x30:
            # 标准证书
            tbs_fields = parse_sequence(seq[0].value)
            sigs = seq[1:3]
        elif len(seq) == 1 and seq[0].tag == 0x30:
            # SEQUENCE(TBS展开) + 后续 sigAlg/sigVal
            tbs_fields = parse_sequence(seq[0].value)
            sigs = parse_sequence(rest) if rest else []
        else:
            raise ValueError('无法识别的证书结构(0x30)')
    else:
        # 裸 TBS 展开 + sigAlg + sigVal（version [0] 开头）
        all_t = parse_sequence(der)
        if len(all_t) >= 2 and all_t[-1].tag == 0x03 and all_t[-2].tag == 0x30:
            tbs_fields = all_t[:-2]
            sigs = all_t[-2:]
        else:
            raise ValueError('无法识别的证书结构(裸流)')
    return tbs_fields, sigs


def _oid_of(t):
    return tlv_oid(t)


_ALGO_OIDS = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.11': 'SHA256-RSA',
    '1.2.840.113549.1.1.12': 'SHA384-RSA',
    '1.2.840.113549.1.1.13': 'SHA512-RSA',
    '1.2.840.113549.1.1.5': 'SHA1-RSA',
    '1.2.840.113549.1.1.14': 'SHA224-RSA',
    '1.2.840.10045.2.1': 'EC',
    '1.2.840.10045.4.3.2': 'SHA256-ECDSA',
    '1.2.840.10045.4.3.3': 'SHA384-ECDSA',
    '1.2.840.10045.4.3.4': 'SHA512-ECDSA',
    '1.2.840.10045.4.1': 'SHA1-ECDSA',
    '1.2.840.10045.4.3.1': 'SHA224-ECDSA',
    '1.2.156.10197.1.501': 'SM3-SM2',
    '1.2.156.10197.1.301': 'SM2',
    '1.2.156.10197.1.401': 'SM3',
    '1.2.156.10197.1.102': 'SM4-CBC',
    '1.3.14.3.2.26': 'SHA1',
    '2.16.840.1.101.3.4.2.1': 'SHA256',
    '2.16.840.1.101.3.4.2.2': 'SHA384',
    '2.16.840.1.101.3.4.2.3': 'SHA512',
    '2.16.840.1.101.3.4.2.4': 'SHA224',
    '1.2.840.113549.2.5': 'MD5',
    '1.3.14.3.2.2': 'MD4',
}


def _algo_name(oid):
    return _ALGO_OIDS.get(oid, oid)


def _dn(t):
    """解析 Name → 'CN=xxx, O=yyy'。"""
    parts = []
    for rdn in t.children():
        for atv in rdn.children():
            a = atv.children()
            oid = tlv_oid(a[0])
            val = a[1]
            if val.tag == 0x0C:  # UTF8String
                s = val.value.decode('utf-8', 'replace')
            elif val.tag == 0x13:  # PrintableString
                s = val.value.decode('ascii', 'replace')
            elif val.tag == 0x14:  # TeletexString
                s = val.value.decode('latin1', 'replace')
            elif val.tag == 0x16:  # IA5String
                s = val.value.decode('ascii', 'replace')
            elif val.tag == 0x1E:  # BMPString
                s = val.value.decode('utf-16-be', 'replace')
            else:
                s = val.value.hex()
            parts.append(_ATTR_NAME(oid) + '=' + s)
    return ', '.join(parts)


_ATTRS = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
    '2.5.4.4': 'SN', '1.2.840.113549.1.9.1': 'emailAddress',
}


def _ATTR_NAME(oid):
    return _ATTRS.get(oid, oid)


# ---------------- CMS SignedData 解析（RFC 5652） ----------------
class CMS:
    """解析 PKCS#7 / CMS SignedData（第一层）。"""

    def __init__(self, der):
        self.der = der
        self.content_type = ''
        self.certs = []            # [X509Cert]
        self.signer_infos = []     # [dict]
        self.parse()

    def parse(self):
        outer = parse_tlv(self.der)
        if outer.tag != 0x30:
            raise ValueError('不是 SEQUENCE（非 CMS）')
        seq = outer.children()
        # ContentInfo: contentType + [0] EXPLICIT content
        self.content_type = tlv_oid(seq[0])
        if self.content_type != '1.2.840.113549.1.7.2':
            raise ValueError('不是 SignedData: ' + self.content_type)
        sd = seq[1].children()[0]
        sd_c = parse_sequence(sd.value)
        self.version = tlv_int(sd_c[0])
        digestAlgs = sd_c[1].children() if sd_c[1].constructed else []
        self.digest_algs = [_algo_name(_oid_of(a.children()[0])) for a in digestAlgs]
        encap = sd_c[2]
        if encap.tag == 0x04 and encap.value:
            self.encap_content = encap.value
        else:
            self.encap_content = None
        # 证书
        i = 3
        if i < len(sd_c) and sd_c[i].tag == 0xA0:
            for cert_t in sd_c[i].children():
                try:
                    self.certs.append(X509Cert(cert_t.value))
                except Exception as e:
                    self.cert_errors = getattr(self, 'cert_errors', [])
                    self.cert_errors.append(str(e))
            i += 1
        # CRL（跳过）
        if i < len(sd_c) and sd_c[i].tag == 0xA1:
            i += 1
        # SignerInfos
        if i < len(sd_c):
            sis = sd_c[i].children()
            for si in sis:
                self.signer_infos.append(_parse_signer_info(si))


def _parse_signer_info(si):
    c = si.children()
    d = {}
    d['version'] = tlv_int(c[0])
    sid = c[1]
    if sid.tag == 0x80:  # subjectKeyIdentifier
        d['sid'] = ('ski', sid.value.hex())
    elif sid.tag == 0x30:  # issuerAndSerialNumber
        sc = sid.children()
        d['sid'] = ('issuerAndSerial', _dn(sc[0]), format(tlv_int(sc[1]), 'x'))
    d['digest_oid'] = _oid_of(c[2].children()[0])
    d['digest_algo'] = _algo_name(d['digest_oid'])
    i = 3
    signed_attrs = None
    if i < len(c) and c[i].tag == 0xA0:
        signed_attrs = c[i].children()
        i += 1
    d['signature_oid'] = _oid_of(c[i].children()[0])
    d['signature_algo'] = _algo_name(d['signature_oid'])
    i += 1
    d['signature'] = c[i].value
    i += 1
    unsigned_attrs = None
    if i < len(c) and c[i].tag == 0xA1:
        unsigned_attrs = c[i].children()
        i += 1
    d['unsigned_attrs'] = []
    if unsigned_attrs:
        for a in unsigned_attrs:
            ac = a.children()
            d['unsigned_attrs'].append((tlv_oid(ac[0]), ac[1].value))
    # 解析 signedAttrs
    d['signed_attrs'] = []
    if signed_attrs:
        for a in signed_attrs:
            ac = a.children()
            oid = tlv_oid(ac[0])
            vals = [x.value for x in ac[1].children()] if ac[1].constructed else [ac[1].value]
            d['signed_attrs'].append((oid, vals))
    return d


def sig_attr(si, oid):
    for o, vals in si['signed_attrs']:
        if o == oid:
            return vals
    return None


if __name__ == '__main__':
    print('derlib OK')
