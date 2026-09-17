#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
国密 PDF 数字签名技术验证工具（原型）

参考标准与技术规范：
- GB/T 38540-2020 信息安全技术 安全电子签章密码技术规范
- GM/T 0031 系列 安全电子签章密码技术规范
- GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范
- GB/T 32918 系列 SM2椭圆曲线公钥密码算法
- GB/T 32905 SM3密码杂凑算法
- ISO 32000 / PDF 数字签名结构
- GM/T 0112-2021 PDF格式文档密码应用技术要求
- GM/T 0047-2024 安全电子签章密码检测规范

注意：
本工具是技术验证原型，用于从数据结构、算法、摘要、签名值等角度
检查国密 PDF 签名是否符合相关标准要求，不等同于商用密码检测机构
出具的合规检测报告。
"""

import sys
import json
import hashlib
from pathlib import Path

# 兼容打包为 EXE / Windows GBK 控制台：stdout 强制 UTF-8，避免 ✓ 等字符崩溃
try:
    if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

import pikepdf
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend

# CMS / PKCS#7 解析
from asn1crypto import cms, core


class GM_PDF_Verifier:
    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF 文件不存在: {pdf_path}")

        self.results = []
        self.pdf = None
        self.signature_dicts = []
        self.skipped = False  # 非 CMS 格式（如 SES 电子签章）时置 True

    # --------------------------
    # 1. 打开 PDF
    # --------------------------
    def open_pdf(self):
        try:
            self.pdf = pikepdf.open(str(self.pdf_path))
            self.add_result("PDF_OPEN", True, "PDF 文件可正常打开")
        except Exception as e:
            self.add_result("PDF_OPEN", False, f"PDF 打开失败: {e}")
            raise

    # --------------------------
    # 2. 查找签名字典
    # --------------------------
    def find_signature_dicts(self):
        try:
            root = self.pdf.Root

            # AcroForm -> SigFlags / Fields
            acroform = root.get("/AcroForm")
            if acroform is None:
                self.add_result("ACROFORM_EXIST", False, "未找到 AcroForm，可能无交互式签名字段")
                return

            fields = acroform.get("/Fields")
            if fields is None:
                self.add_result("FIELDS_EXIST", False, "未找到 Fields 数组")
                return

            found = 0
            for field in fields:
                field_obj = field
                if field_obj.get("/FT") == "/Sig":
                    # AcroForm 签名字段的 /V 才是真正的签名字典
                    # （/ByteRange、/Contents、/Filter、/SubFilter 都在 /V 上）
                    sig_dict = field_obj.get("/V")
                    if sig_dict is None:
                        sig_dict = field_obj
                    self.signature_dicts.append(sig_dict)
                    found += 1

            if found > 0:
                self.add_result("SIG_DICT_FOUND", True, f"找到 {found} 个签名字典")
            else:
                self.add_result("SIG_DICT_FOUND", False, "未找到 /FT=/Sig 签名字典")

        except Exception as e:
            self.add_result("SIG_DICT_FIND", False, f"查找签名字典失败: {e}")

    # --------------------------
    # 3. 验证 ByteRange
    # --------------------------
    def verify_byterange(self, sig_dict):
        byte_range = sig_dict.get("/ByteRange")
        if byte_range is None:
            self.add_result("BYTERANGE_EXIST", False, "签名字典缺少 ByteRange")
            return None, None

        try:
            br_list = [int(x) for x in byte_range]
        except Exception as e:
            self.add_result("BYTERANGE_PARSE", False, f"ByteRange 解析失败: {e}")
            return None, None

        if len(br_list) != 4:
            self.add_result("BYTERANGE_LENGTH", False, f"ByteRange 长度应为 4，实际为 {len(br_list)}")
            return None, None

        offset1, length1, offset2, length2 = br_list

        if offset1 < 0 or length1 < 0 or offset2 < 0 or length2 < 0:
            self.add_result("BYTERANGE_NEGATIVE", False, "ByteRange 包含负数")
            return None, None

        pdf_bytes = self.pdf_path.read_bytes()
        file_len = len(pdf_bytes)

        end1 = offset1 + length1
        end2 = offset2 + length2

        if end1 > file_len or end2 > file_len:
            self.add_result("BYTERANGE_OVERFLOW", False, "ByteRange 超出文件长度")
            return None, None

        self.add_result("BYTERANGE_VALID", True, "ByteRange 结构合法")
        return pdf_bytes, br_list

    # --------------------------
    # 4. 提取 Contents 签名值
    # --------------------------
    def extract_contents(self, sig_dict):
        contents = sig_dict.get("/Contents")
        if contents is None:
            self.add_result("CONTENTS_EXIST", False, "签名字典缺少 Contents")
            return None

        try:
            sig_bytes = bytes(contents)
        except Exception as e:
            self.add_result("CONTENTS_EXTRACT", False, f"Contents 提取失败: {e}")
            return None

        if len(sig_bytes) == 0:
            self.add_result("CONTENTS_EMPTY", False, "Contents 为空")
            return None

        self.add_result("CONTENTS_EXIST", True, f"Contents 长度: {len(sig_bytes)} 字节")
        return sig_bytes

    # --------------------------
    # 5. 解析 CMS / PKCS#7
    # --------------------------
    def parse_cms(self, sig_bytes: bytes):
        try:
            content_info = cms.ContentInfo.load(sig_bytes)
            # 必须为 SignedData（1.2.840.113549.1.7.2），
            # 否则（如 GB/T 38540 SES 电子签章）按非 CMS 处理
            if content_info['content_type'].dotted != '1.2.840.113549.1.7.2':
                return None
            self.add_result("CMS_PARSE", True, "CMS/PKCS#7 结构可解析（SignedData）")
            return content_info
        except Exception as e:
            self.add_result("CMS_PARSE", False, f"CMS 解析失败: {e}")
            return None

    # --------------------------
    # 6. 检查是否国密签名
    # --------------------------
    def check_gm_algorithm(self, content_info: cms.ContentInfo):
        try:
            signed_data = content_info["content"]

            if signed_data.native["version"] is not None:
                self.add_result("CMS_SIGNED_DATA_VERSION", True, "SignedData 版本存在")

            digest_algos = signed_data["digest_algorithms"]
            signer_infos = signed_data["signer_infos"]

            digest_algo_list = []
            signature_algo_list = []

            for da in digest_algos:
                digest_algo_list.append(da['algorithm'].dotted)

            for si in signer_infos:
                digest_algo = si["digest_algorithm"]
                signature_algo = si["signature_algorithm"]

                digest_algo_list.append(digest_algo['algorithm'].dotted)
                signature_algo_list.append(signature_algo['algorithm'].dotted)

            oids = digest_algo_list + signature_algo_list

            # 国密 OID：
            #   SM2 曲线 1.2.156.10197.1.301；SM2 公钥 1.2.156.10197.1.302
            #   SM3 摘要 1.2.156.10197.1.401；SM3-SM2 签名 1.2.156.10197.1.501
            has_sm2 = any(o in ("1.2.156.10197.1.301", "1.2.156.10197.1.302",
                                "1.2.156.10197.1.501") for o in oids)
            has_sm3 = any(o == "1.2.156.10197.1.401" for o in oids)

            if has_sm2:
                self.add_result("ALGO_SM2", True, "检测到 SM2 相关算法标识")
            else:
                self.add_result("ALGO_SM2", False, "未检测到 SM2 算法标识")

            if has_sm3:
                self.add_result("ALGO_SM3", True, "检测到 SM3 相关算法标识")
            else:
                self.add_result("ALGO_SM3", False, "未检测到 SM3 算法标识")

            return has_sm2, has_sm3

        except Exception as e:
            self.add_result("GM_ALGO_CHECK", False, f"国密算法检查失败: {e}")
            return False, False

    # --------------------------
    # 7. 重算摘要
    # --------------------------
    def recompute_digest(self, pdf_bytes: bytes, br_list: list):
        try:
            offset1, length1, offset2, length2 = br_list

            part1 = pdf_bytes[offset1: offset1 + length1]
            part2 = pdf_bytes[offset2: offset2 + length2]

            data = part1 + part2

            sm3_digest = hashlib.new("sm3", data).digest()

            self.add_result("DIGEST_RECOMPUTE", True, "摘要重算完成")
            return sm3_digest

        except Exception as e:
            self.add_result("DIGEST_RECOMPUTE", False, f"摘要重算失败: {e}")
            return None

    # --------------------------
    # 8. 提取签名值
    # --------------------------
    def extract_signature_value(self, content_info: cms.ContentInfo):
        try:
            signed_data = content_info["content"]
            signer_infos = signed_data["signer_infos"]

            if len(signer_infos) == 0:
                self.add_result("SIGNER_INFO_EXIST", False, "未找到 SignerInfo")
                return None

            si = signer_infos[0]
            signature_value = si["signature"].native

            self.add_result("SIGNATURE_VALUE_EXIST", True, "签名值存在")
            return signature_value

        except Exception as e:
            self.add_result("SIGNATURE_EXTRACT", False, f"签名值提取失败: {e}")
            return None

    # --------------------------
    # 9. 提取证书公钥（SM2 曲线证书 cryptography 不支持，改用 derlib）
    #    按 SignerInfo sid（颁发者+序列号）匹配签名者证书
    # --------------------------
    def extract_signer_cert(self, content_info: cms.ContentInfo):
        try:
            signed_data = content_info["content"]
            certificates = signed_data["certificates"]

            if certificates is None or len(certificates) == 0:
                self.add_result("CERT_EXIST", False, "未找到签名证书")
                return None

            si = signed_data["signer_infos"][0]
            sid = si["sid"]
            sid_native = sid.native
            want_serial = None
            want_ski = None
            if isinstance(sid_native, dict) and "serial_number" in sid_native:
                want_serial = format(sid_native["serial_number"], 'x')
            elif isinstance(sid_native, dict) and "subject_key_identifier" in sid_native:
                want_ski = sid_native["subject_key_identifier"]

            from derlib import X509Cert

            matched = None
            for c in certificates:
                cert_der = c.chosen.dump()
                cert = X509Cert(cert_der)
                if want_serial is not None and cert.serial == want_serial:
                    matched = cert
                    break
                if want_ski is not None and cert.subject_key_id \
                        and want_ski.hex() == cert.subject_key_id:
                    matched = cert
                    break

            if matched is None:
                self.add_result("CERT_EXIST", False,
                                f"证书集中未找到 sid 匹配的签名者证书（SN={want_serial or want_ski}）")
                return None

            pub = matched.pubkey  # ('SM2'/'EC', x, y) 或 ('RSA', n, e)
            if pub is None or pub[1] is None:
                self.add_result("CERT_PUBLIC_KEY", False, "证书公钥解析失败")
                return None

            self.add_result("CERT_PUBLIC_KEY", True,
                            f"签名证书公钥提取成功（{matched.pubkey_algo}，SN={matched.serial}）")
            return pub

        except Exception as e:
            self.add_result("CERT_EXTRACT", False, f"证书提取失败: {e}")
            return None

    # --------------------------
    # 10. SM2 验签（GB/T 32918.2-2016，含 ZA 的标准模式）
    # --------------------------
    def verify_sm2_signature(self, sig_bytes: bytes, content_info,
                             public_key, signature_value: bytes):
        try:
            # public_key 来自 derlib：('SM2'/'EC', x, y)
            if public_key[0] not in ('SM2', 'EC') or public_key[1] is None:
                self.add_result("SM2_VERIFY", False, "公钥不是 SM2/EC 椭圆曲线公钥")
                return

            # RFC 5652: CMS 签名对象 = signedAttrs 的 DER SET 编码。
            # 直接用原始 CMS 字节重建（已验证与签名时一致），
            # 不要用 asn1crypto 的 dump()（带 [0] IMPLICIT 头，编码不符）。
            from pdfsig_verify import _cms_signed_attrs_der

            signed_attrs_der = _cms_signed_attrs_der(sig_bytes, None)
            if signed_attrs_der is None:
                self.add_result("SM2_VERIFY", False, "signedAttrs DER 重建失败")
                return

            # 签名值 r||s（GB/T 35275 样本中为 DER SEQUENCE 编码）
            try:
                r, s = decode_dss_signature(signature_value)
            except Exception:
                if len(signature_value) >= 64:
                    r = int.from_bytes(signature_value[:32], byteorder="big")
                    s = int.from_bytes(signature_value[32:64], byteorder="big")
                else:
                    self.add_result("SM2_VERIFY", False, "签名值长度异常")
                    return

            # 使用同目录 sm2lib.py：e = SM3(ZA || M)，标准验签
            from sm2lib import sm2_verify

            ok, detail = sm2_verify((public_key[1], public_key[2]),
                                    signed_attrs_der, r, s, with_za=True)

            if ok:
                self.add_result("SM2_VERIFY", True, "SM2 验签通过（SM3(ZA||signedAttrs)，GB/T 32918.2）")
            else:
                self.add_result("SM2_VERIFY", False, f"SM2 验签失败: {detail}")

        except Exception as e:
            self.add_result("SM2_VERIFY", False, f"SM2 验签失败: {e}")

    # --------------------------
    # 11. 综合判定
    # --------------------------
    def summary(self):
        checks = [r["check"] for r in self.results]
        passed = sum(1 for r in self.results if r["passed"])
        failed = sum(1 for r in self.results if not r["passed"] and not r.get("warn"))
        warns = sum(1 for r in self.results if not r["passed"] and r.get("warn"))

        critical_checks = [
            "PDF_OPEN",
            "SIG_DICT_FOUND",
            "BYTERANGE_VALID",
            "CONTENTS_EXIST",
            "CMS_PARSE",
            "ALGO_SM2",
            "ALGO_SM3",
            "DIGEST_RECOMPUTE",
            "SM2_VERIFY"
        ]

        critical_failed = [
            r["check"] for r in self.results
            if not r["passed"] and not r.get("warn") and r["check"] in critical_checks
        ]

        result = {
            "file": str(self.pdf_path),
            "total_checks": len(self.results),
            "passed": passed,
            "failed": failed,
            "warns": warns,
            "critical_failed": [] if self.skipped else critical_failed,
            "skipped": self.skipped,
            "details": self.results
        }

        return result

    # --------------------------
    # 工具方法
    # --------------------------
    def add_result(self, check: str, passed: bool, message: str, warn: bool = False):
        self.results.append({
            "check": check,
            "passed": passed,
            "message": message,
            "warn": warn
        })

    # --------------------------
    # 主验证流程
    # --------------------------
    # --------------------------
    # 11. LTV / DSS 完整性（ISO 32000-1 §12.8.4）
    # --------------------------
    def check_dss(self):
        try:
            table = self.pdf.get_xref_table()
            dss = None
            for key in table:
                if isinstance(key, tuple):  # pikepdf 键为 (objnum, gen)
                    n, g = key
                else:
                    n, g = key, 0
                if n <= 0:
                    continue
                try:
                    obj = self.pdf.get_object(n, g)
                    if obj.get('/Type') == pikepdf.Name('/DSS'):
                        dss = n
                        break
                except Exception:
                    continue

            if dss is None:
                self.add_result("LTV_DSS_OBJECT", False, "未找到 DSS 对象（无 LTV）", warn=True)
                self.add_result("DSS_MATERIAL", False, "无 DSS 对象", warn=True)
                return

            n_certs = n_crls = n_ocsps = 0
            try:
                certs = self.pdf.get_object(dss, 0).get('/Certs')
                if certs is not None:
                    n_certs = len(certs)
            except Exception:
                pass
            try:
                crls = self.pdf.get_object(dss, 0).get('/CRLs')
                if crls is not None:
                    n_crls = len(crls)
            except Exception:
                pass
            try:
                ocsps = self.pdf.get_object(dss, 0).get('/OCSPs')
                if ocsps is not None:
                    n_ocsps = len(ocsps)
            except Exception:
                pass

            self.add_result("LTV_DSS_OBJECT", True, f"DSS 对象存在（xref={dss}）")
            self.add_result("DSS_MATERIAL", (n_certs + n_crls + n_ocsps) > 0,
                            f"Certs={n_certs} CRLs={n_crls} OCSPs={n_ocsps}（ISO 32000-1 LTV）",
                            warn=True)
        except Exception as e:
            self.add_result("LTV_DSS_OBJECT", False, f"DSS 检查失败: {e}", warn=True)

    def verify(self):
        self.open_pdf()
        self.find_signature_dicts()

        if not self.signature_dicts:
            return self.summary()

        for idx, sig_dict in enumerate(self.signature_dicts):
            prefix = f"SIG_{idx}"

            pdf_bytes, br_list = self.verify_byterange(sig_dict)
            if pdf_bytes is None or br_list is None:
                continue

            sig_bytes = self.extract_contents(sig_dict)
            if sig_bytes is None:
                continue

            content_info = self.parse_cms(sig_bytes)
            if content_info is None:
                # 非 CMS 结构：可能是 GB/T 38540 SES 电子签章，
                # 本工具（CMS 型）不支持，标记跳过，转交 pdfsig_verify.py
                self.skipped = True
                self.add_result("GM_FORMAT_HINT", True,
                                "Contents 不是 CMS SignedData（可能为 /GM.sm2seal SES 电子签章），"
                                "本工具跳过，请使用 pdfsig_verify.py 验证该文件")
                continue

            has_sm2, has_sm3 = self.check_gm_algorithm(content_info)

            sm3_digest = self.recompute_digest(pdf_bytes, br_list)
            if sm3_digest is None:
                continue

            signature_value = self.extract_signature_value(content_info)
            if signature_value is None:
                continue

            public_key = self.extract_signer_cert(content_info)
            if public_key is None:
                continue

            if has_sm2 and has_sm3:
                self.verify_sm2_signature(sig_bytes, content_info,
                                          public_key, signature_value)

        self.check_dss()
        return self.summary()


def print_report(report: dict):
    print(json.dumps(report, ensure_ascii=False, indent=2))

    print("\n===== 综合判定 =====")
    print(f"文件: {report['file']}")
    if report.get("skipped"):
        print("判定: 跳过（非 CMS 签名格式，如 SES 电子签章）")
        print("说明: 该文件的结构检查已完成；密码学验签请使用 pdfsig_verify.py")
        return
    print(f"检查项总数: {report['total_checks']}")
    print(f"通过: {report['passed']}")
    print(f"失败: {report['failed']}")
    if report.get("warns"):
        print(f"警告: {report['warns']}")

    if report["critical_failed"]:
        print("\n关键失败项:")
        for item in report["critical_failed"]:
            print(f"- {item}")
    else:
        print("\n关键检查项全部通过。")


def main():
    if len(sys.argv) < 2:
        print("用法: python verify_gm_pdf.py <pdf文件路径>")
        sys.exit(1)

    pdf_path = sys.argv[1]
    verifier = GM_PDF_Verifier(pdf_path)
    report = verifier.verify()
    print_report(report)


if __name__ == "__main__":
    main()
