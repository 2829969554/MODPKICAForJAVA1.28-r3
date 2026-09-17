# -*- coding: utf-8 -*-
"""生成《国密PDF签名技术验证报告.pdf》—— 与 GMcheck/国密PDF签名技术验证报告.md 同源"""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, Preformatted, HRFlowable)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "国密PDF签名技术验证报告.pdf")
FONT = r"C:\Windows\Fonts\simhei.ttf"
MONO = r"C:\Windows\Fonts\simhei.ttf"

pdfmetrics.registerFont(TTFont("SimHei", FONT))
pdfmetrics.registerFont(TTFont("Code", MONO))

H1 = ParagraphStyle("h1", fontName="SimHei", fontSize=16, leading=24, spaceAfter=8,
                    textColor=colors.HexColor("#0B3D91"), alignment=TA_CENTER)
H2 = ParagraphStyle("h2", fontName="SimHei", fontSize=13, leading=20, spaceBefore=12,
                    spaceAfter=5, textColor=colors.HexColor("#0B3D91"))
H3 = ParagraphStyle("h3", fontName="SimHei", fontSize=11, leading=16, spaceBefore=8,
                    spaceAfter=3, textColor=colors.HexColor("#1F4E79"))
BODY = ParagraphStyle("body", fontName="SimHei", fontSize=9, leading=13.5, spaceAfter=3)
BODY2 = ParagraphStyle("body2", fontName="SimHei", fontSize=8.5, leading=12.5, spaceAfter=2)
CODE = ParagraphStyle("code", fontName="Code", fontSize=7, leading=10,
                      leftIndent=6, backColor=colors.HexColor("#F2F4F8"),
                      borderPadding=4, borderColor=colors.HexColor("#CCCCCC"),
                      borderWidth=0.5, spaceAfter=4)
SUB = ParagraphStyle("sub", fontName="SimHei", fontSize=10, leading=15,
                     textColor=colors.HexColor("#555555"), alignment=TA_CENTER)
CELL = ParagraphStyle("cell", fontName="SimHei", fontSize=7.5, leading=10.5)
CELLB = ParagraphStyle("cellb", fontName="SimHei", fontSize=7.5, leading=10.5,
                       textColor=colors.white)

def P(txt, st=BODY):
    return Paragraph(txt, st)

def code(txt):
    return Preformatted(txt, CODE)

def table(headers, rows, widths=None):
    data = [[Paragraph(h, CELLB) for h in headers]]
    for r in rows:
        data.append([Paragraph(str(c), CELL) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B3D91")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F4F8")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t

story = []

# ================= 封面 =================
story.append(Spacer(1, 40 * mm))
story.append(Paragraph("国密 PDF 数字签名", H1))
story.append(Paragraph("技术标准验证报告", ParagraphStyle("t1", parent=H1, fontSize=22, leading=30)))
story.append(Spacer(1, 8 * mm))
story.append(Paragraph("GB/T 35275-2017（CMS 分离签名） · GB/T 38540-2020（SES 电子签章）", SUB))
story.append(Spacer(1, 6 * mm))
story.append(Paragraph("验证对象：GBT35275-2017.pdf / GBT38540-2020.pdf", SUB))
story.append(Paragraph("验证日期：2026-09-17（含证书链深度验证）", SUB))
story.append(Spacer(1, 24 * mm))
story.append(HRFlowable(width="70%", thickness=1, color=colors.HexColor("#0B3D91")))
story.append(Spacer(1, 8 * mm))
story.append(Paragraph("结论：两份样本均符合对应国家标准，全部验证项通过", ParagraphStyle(
    "sub2", parent=SUB, fontSize=12, textColor=colors.HexColor("#0B3D91"))))
story.append(Paragraph("证书链、CRL、OCSP 全部内嵌于 PDF，离线可完整验证", SUB))
story.append(PageBreak())

# ================= 摘要 =================
story.append(Paragraph("一、结论摘要", H2))
story.append(table(["样本", "签名格式", "签名证书", "摘要一致性", "密码学验签", "时间戳", "证书链", "LTV/DSS", "判定"], [
    ["35275-2017", "/GM.sm2cms.detached", "113548382 SM2", "✓", "✓ SM3(ZA‖M)", "✓ RFC3161", "✓ 终端→CA→根", "✓ DSS=92", "符合"],
    ["38540-2020", "/GM.sm2seal", "113548382 SM2", "✓", "✓ 双签名", "✓ 字段4", "✓ 终端→CA→根", "✓ DSS=92", "符合"],
], widths=[22 * mm, 34 * mm, 26 * mm, 18 * mm, 24 * mm, 20 * mm, 24 * mm, 18 * mm, 14 * mm]))
story.append(Spacer(1, 2))
story.append(P("汇总计数：35275 样本 pdfsig_verify <b>15/15</b>、verify_gm_pdf <b>14/14</b>；"
               "38540 样本 pdfsig_verify <b>22/22</b>；两样本证书链深度验证全部通过。"))

# ================= 依据标准 =================
story.append(Paragraph("二、依据标准（引用）", H2))
story.append(table(["标准/规范", "名称", "在本验证中的作用"], [
    ["GB/T 35275-2017", "SM2密码算法加密签名消息语法规范", "CMS 分离签名与 /GM.sm2cms.detached 语义"],
    ["GB/T 38540-2020", "安全电子签章密码技术规范", "电子印章 SES（SES_Signature/SESeal）结构与 /GM.sm2seal 语义"],
    ["GB/T 32918.2-2016", "SM2椭圆曲线公钥密码算法 第2部分：数字签名算法", "SM2 验签、ZA 计算、素域曲线参数"],
    ["GB/T 32905-2016", "SM3密码杂凑算法", "消息摘要与 ZA 计算底层"],
    ["RFC 5652", "Cryptographic Message Syntax (CMS)", "SignedData/SignerInfo/signedAttrs 的 DER 编码规则"],
    ["ISO 32000-1:2008", "PDF 文档管理", "数字签名 §12.8、ByteRange、DSS（§12.8.4，LTV）"],
    ["RFC 3161", "Time-Stamp Protocol", "时间戳令牌结构与 TSTInfo 语义"],
    ["RFC 6960", "OCSP 协议", "响应结构（responseStatus=ENUMERATED）、CertID/吊销状态语义"],
], widths=[38 * mm, 62 * mm, 80 * mm]))

# ================= 逐项验证 =================
story.append(PageBreak())
story.append(Paragraph("三、逐项验证结果", H2))

story.append(Paragraph("3.1 GB/T 35275-2017 样本（/GM.sm2cms.detached）", H3))
rows352 = [
    ["1", "PDF 可打开", "页数=1"],
    ["2", "存在签名域", "签名对象 xref=[75]"],
    ["3", "签名过滤器", "Filter=/Adobe.SM2 SubFilter=/GM.sm2cms.detached"],
    ["4", "ByteRange 结构", "[0, 54275, 198619, 30870]（4 段标准结构）"],
    ["5", "签名内容存在", "Contents 长度=72171 字节（DER 二进制）"],
    ["6", "ByteRange 分段可读", "覆盖字节=85145"],
    ["7", "CMS 结构解析", "contentType=1.2.840.113549.1.7.2，证书数=3，签名者数=1"],
    ["8", "签名证书匹配", "C=CN, O=ChinaITboys, OU=Person, CN=2829969554@qq.com"],
    ["9", "签名算法", "SM3-SM2（1.2.156.10197.1.501），摘要 SM3（1.2.156.10197.1.401）"],
    ["10", "messageDigest 一致性", "声明=99f29c0b…，计算=99f29c0b…（ByteRange 双段 SM3）"],
    ["11", "SM2 签名验签(signedAttrs)", "SET 最小长度 DER 编码，e=SM3(ZA‖M)，验签通过"],
    ["12", "时间戳令牌（RFC3161）", "证书数=2；TSA SM3-SM2；policy=1.3.6.1.4.1.4146.1.95；genTime=20260916141445Z"],
    ["13", "证书链", "终端 → CN=SM2CA → CN=ROOTCA"],
    ["14", "LTV/DSS 对象", "DSS 对象=92（pikepdf 按 Type=/DSS 精确定位）"],
    ["15", "DSS 验证材料", "Certs=3、CRLs=2、OCSPs=3"],
]
story.append(table(["#", "验证项", "证据"], rows352, widths=[10 * mm, 48 * mm, 122 * mm]))
story.append(P("汇总：15/15 项通过（verify_gm_pdf 结构检查另计 14/14 项通过）。"))

story.append(Paragraph("3.2 GB/T 38540-2020 样本（/GM.sm2seal）", H3))
rows385 = [
    ["1", "PDF 可打开", "页数=1"],
    ["2", "存在签名域", "签名对象 xref=[75]"],
    ["3", "签名过滤器", "Filter=/Adobe.SM2 SubFilter=/GM.sm2seal"],
    ["4", "ByteRange 结构", "[0, 54267, 198611, 30868]"],
    ["5", "签名内容存在", "Contents 长度=72171 字节"],
    ["6", "ByteRange 分段可读", "覆盖字节=85135"],
    ["7", "SES 结构解析", "顶层子元素=5（SES_Signature 标准五字段）"],
    ["8-12", "SES 字段类型", "toSign=0x30/20143B；印章图像=0x04/1677B；摘要算法=0x06/8B；签名值=0x03/71B；时间戳=0xA0/2278B"],
    ["13", "SES_ToSign 解析", "version=4；esInfo=20070B；时间=20260916144120Z；签名值=32B；类型=PDF-SM2-SEAL"],
    ["14", "印章信息解析", "SESealInfo=18305B；图片=1677B(PNG)；摘要算法OID=1.2.156.10197.1.501；印章签名=71B"],
    ["15", "印章 ID", "caa36f4f-0db5-445e-b255-67eaa0acd83c"],
    ["16", "印章证书提取", "证书数=3：终端 → CN=SM2CA → CN=ROOTCA"],
    ["17", "印章签名验签(SESealInfo)", "证书113548382 对 SESealInfo 完整 DER 验签通过，e=SM3(ZA‖M)"],
    ["18", "文档签名验签(SES_ToSign)", "证书113548382 对 SES_ToSign 完整 DER 验签通过，e=SM3(ZA‖M)"],
    ["19", "时间戳令牌验证", "证书数=2；TSA 含时间戳(1.3.6.1.5.5.7.3.8) EKU；TSA 令牌 SM2 验签通过"],
    ["20", "证书链", "终端 → CN=SM2CA → CN=ROOTCA"],
    ["21", "LTV/DSS 对象", "DSS 对象=92（pikepdf 按 Type=/DSS 精确定位）"],
    ["22", "DSS 验证材料", "Certs=3、CRLs=2、OCSPs=3"],
]
story.append(table(["#", "验证项", "证据"], rows385, widths=[10 * mm, 48 * mm, 122 * mm]))
story.append(P("汇总：22/22 项通过。"))

# ================= 深度链验证 =================
story.append(PageBreak())
story.append(Paragraph("3.3 证书链深度验证（离线材料盘点，两样本同批）", H3))
story.append(P("针对\"签名结构是否真的包含证书链、离线能否验证\"，对签名 Contents 与 DSS 对象做全量提取与逐级密码学验签。"))
story.append(table(["序列号", "证书", "算法", "嵌入位置"], [
    ["113548382", "签名者 C=CN, O=ChinaITboys, OU=Person, CN=2829969554@qq.com", "SM2(EC256)", "签名 Contents"],
    ["1cdd33203a2ce", "CA 证书 CN=SM2CA", "SM2(EC256)", "签名 Contents"],
    ["13fbe86586d3f90", "根证书 C=CN, O=My Org, CN=ROOTCA", "RSA 2048", "签名 Contents"],
    ["11355e5c4", "TSA 签名证书 CN=SM2ROOTCA By Timstamp SM3", "SM2(EC256)", "时间戳令牌"],
    ["13fbe865870f9b4", "TSA 根证书 C=CN, O=My Org, CN=SM2ROOTCA", "SM2(EC256)", "时间戳令牌"],
], widths=[26 * mm, 72 * mm, 24 * mm, 28 * mm]))
story.append(Spacer(1, 2))
story.append(Paragraph("文档签名链（子证书 ← 父证书公钥，逐级验签）", H3))
story.append(code(
    "签名者 113548382  ←  SM2CA 1cdd33203a2ce    SM2(ZA) 验签通过\n"
    "SM2CA 1cdd33203a2ce ← ROOTCA 13fbe86586d3f90  RSA-sha256 验签通过\n"
    "ROOTCA 13fbe86586d3f90 自签名（信任锚）          RSA-sha256 验签通过"))
story.append(Paragraph("TSA 时间戳链（逐级验签）", H3))
story.append(code(
    "TSA 签名证书 11355e5c4 ← SM2ROOTCA 13fbe865870f9b4  SM2(ZA) 验签通过\n"
    "SM2ROOTCA 13fbe865870f9b4 自签名（信任锚）           SM2(ZA) 验签通过"))
story.append(Paragraph("吊销证据（DSS 对象内，全部离线可核验）", H3))
story.append(table(["材料", "数量", "内容"], [
    ["CRL", "2", "CRL[0] 签发者=SM2CA（SM2(ZA) 验签通过，吊销 0 条）；CRL[1] 签发者=ROOTCA（RSA-sha256 验签通过，吊销 0 条）"],
    ["OCSP", "3", "OCSP[0]→113548382、OCSP[1]→1cdd33203a2ce、OCSP[2]→13fbe86586d3f90，状态全部正常(good)"],
], widths=[20 * mm, 16 * mm, 144 * mm]))
story.append(Spacer(1, 2))
story.append(P("<b>结论：</b>证书链、CRL、OCSP 全部内嵌于 PDF（签名 Contents + DSS），"
               "离线即可完成每一级的密码学验签与吊销状态核对，不依赖任何外部 URL。"))

# ================= 验证方法与程序 =================
story.append(PageBreak())
story.append(Paragraph("四、验证方法与程序", H2))
story.append(Paragraph("4.1 技术路线", H3))
story.append(P("A 线 —— 纯标准库自实现（不信任任何现成验签实现）："))
story.append(P("① SM3（sm2lib.py）：按 GB/T 32905-2016 实现，标准测试向量自检通过。", BODY2))
story.append(P("② SM2 验签（sm2lib.py）：按 GB/T 32918.2-2016 —— Fp 曲线参数、点加/倍点/标量乘、"
               "ZA=SM3(ENTL‖ID‖a‖b‖xG‖yG‖xA‖yA)（默认 ID 1234567812345678）、R=(e·G+r·Q) 判等。", BODY2))
story.append(P("③ RSA 验签（pdfsig_verify.py）：PKCS#1 v1.5 —— 验 00 01 填充头、定位 00 分隔符、解析 DigestInfo 比对。", BODY2))
story.append(P("④ DER 解析（derlib.py）：X.690 TLV；X.509 证书（序列号/DN/公钥/SKI/AKI/EKU/策略/基本约束）、CMS SignedData/SignerInfo。", BODY2))
story.append(P("⑤ 签名域提取（pdfsig_verify.py + PyMuPDF）：ByteRange 双段拼接 SM3 与 messageDigest 比对。", BODY2))
story.append(P("⑥ 签名对象重建：CMS=signedAttrs 的 SET 最小长度 DER；SES=印章对 SESealInfo、文档对 SES_ToSign 完整 SEQUENCE DER；均 e=SM3(ZA‖M)。", BODY2))
story.append(P("⑦ 时间戳令牌（RFC 3161）：TimeStampToken→CMS→TSTInfo→TSA 证书匹配→SM2 验签。", BODY2))
story.append(P("B 线 —— 第三方库交叉验证：⑧ verify_gm_pdf.py（pikepdf/cryptography/asn1crypto）做结构深度检查，SM2 验签回落 A 线；"
               "⑨ DSS 定位用 pikepdf 按 Type=/DSS 精确扫描（避免 PyMuPDF 误把 Catalog 的 /DSS 引用当 DSS 对象），数组元素为流对象直接取 DER。", BODY2))
story.append(Paragraph("4.2 程序清单（位于 GMcheck\\）", H3))
story.append(table(["文件", "作用"], [
    ["pdfsig_verify.py", "主验证：全项检查、时间戳令牌、SES 深度验签、RSA PKCS#1 v1.5、DSS 材料检查"],
    ["verify_gm_pdf.py", "pikepdf/cryptography/asn1crypto 交叉验证（CMS 深度检查，SES 走跳过分支）"],
    ["chain_deep_verify.py", "证书链深度验证：全量提取、AKI/SKI+DN 构链、逐级验签、CRL/OCSP 核验、离线结论"],
    ["derlib.py", "DER TLV、X.509、CMS、SES 辅助解析"],
    ["sm2lib.py", "SM3、SM2 曲线、ZA、sm2_verify"],
    ["check.cmd", "一键三步验证（结构→全项→深度链），英文输出规避 Win11 GBK 中文乱码"],
], widths=[52 * mm, 128 * mm]))
story.append(Paragraph("4.3 运行方式", H3))
story.append(code(
    "check.cmd\n"
    ":: 等价手工步骤：\n"
    "python verify_gm_pdf.py GBT35275-2017.pdf\n"
    "python verify_gm_pdf.py GBT38540-2020.pdf\n"
    "python pdfsig_verify.py \"GBT35275-2017.pdf\" \"GBT38540-2020.pdf\"\n"
    "python chain_deep_verify.py \"GBT35275-2017.pdf\" \"GBT38540-2020.pdf\""))

# ================= 关键事实 =================
story.append(PageBreak())
story.append(Paragraph("五、关键验证事实与实现要点", H2))
story.append(P("1. 签名对象编码：35275 的 CMS 签名对象为 signedAttrs 集合的 DER 编码——首字节 0x31（SET）+ DER 最小长度"
               "（22558 字节用 0x82 两字节长格式），直接决定摘要一致性。", BODY2))
story.append(P("2. ZA 参与：两样本均采用含 ZA 的摘要模式（e=SM3(ZA‖M)），符合 GB/T 32918.2-2016；无 ZA 简模式验签失败，反向证明符合标准。", BODY2))
story.append(P("3. SES 双签名：38540 含印章签名（SESealInfo）与文档签名（SES_ToSign）两层，均验签通过。", BODY2))
story.append(P("4. 时间戳：两样本均嵌入 SM3-SM2 时间戳令牌，policy=1.3.6.1.4.1.4146.1.95；TSA 令牌验签通过，TSA 链（TSA→SM2ROOTCA）独立验签通过。", BODY2))
story.append(P("5. 证书链：文档链 113548382 → 1cdd33203a2ce → 13fbe86586d3f90，与 AKI/SKI 一致，逐级验签全部通过（含根自签 RSA）。", BODY2))
story.append(P("6. 吊销证据离线可用：DSS(xref=92) 内含 Certs=3、CRLs=2、OCSPs=3；CRL 由 SM2CA 与 ROOTCA 分别签发并验签通过；OCSP 对链上全部证书返回正常(good)。", BODY2))
story.append(P("7. 材料全部内嵌：验证不访问任何外部 URL，仅凭 PDF 即可完成证书链验证与吊销状态核对，满足 LTV 离线可用性。", BODY2))

# ================= 局限性 =================
story.append(Paragraph("六、局限性与说明", H2))
story.append(P("1. 验证聚焦签名密码学正确性 + 结构符合性 + 链与吊销证据完整性，未对字体嵌入、元数据、页面内容做文档一致性检查（不属于签名标准范畴）。", BODY2))
story.append(P("2. genTime 为 UTC（20260916141445Z），PDF M 条目为本地时区（D:20260916221444+08'00'），相差 8 小时属同一时刻的时区表示，符合规范。", BODY2))
story.append(P("3. 所有结论基于对样本二进制内容的独立解析与重算，未借助商业验签工具；如需权威交叉验证可选用符合 GB/T 标准实现的 SDK。", BODY2))
story.append(P("4. verify_gm_pdf.py 对 38540（SES）按设计走\"结构检查 + 提示专用验证\"分支，密码学验证由 pdfsig_verify 与 chain_deep_verify 覆盖。", BODY2))

story.append(Spacer(1, 6))
story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#0B3D91")))
story.append(Paragraph("MODPKICA 国密 PDF 签名验证工具链（纯 Python，GMcheck\\ 三步验证）· 完", SUB))

doc = SimpleDocTemplate(OUT, pagesize=A4,
                        leftMargin=16 * mm, rightMargin=16 * mm,
                        topMargin=15 * mm, bottomMargin=15 * mm,
                        title="国密PDF签名技术验证报告",
                        author="MODPKICA")

def footer(canvas, doc_):
    canvas.saveState()
    canvas.setFont("SimHei", 8)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(16 * mm, 8 * mm, "MODPKICA 国密 PDF 签名技术验证报告")
    canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, "第 %d 页" % doc_.page)
    canvas.restoreState()

doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("PDF OK:", OUT)
