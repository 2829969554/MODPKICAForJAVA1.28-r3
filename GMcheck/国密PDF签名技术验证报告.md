# 国密 PDF 数字签名技术标准验证报告

- **验证对象**
  1. `GBT35275-2017.pdf`（GB/T 35275-2017，CMS 分离签名 `/GM.sm2cms.detached`）
  2. `GBT38540-2020.pdf`（GB/T 38540-2020，SES 电子签章 `/GM.sm2seal`）
- **验证工具**：纯 Python 3 —— 密码学部分（SM2/SM3/DER/X.509/CMS/SES）标准库自实现；结构检查用 pikepdf / cryptography / asn1crypto / PyMuPDF 交叉验证；全程离线、不信任任何现成验签实现
- **验证日期**：2026-09-17（深度链验证随附，同批样本）
- **结论**：两份样本均**符合**对应国家标准，全部验证项通过：
  - GB/T 35275-2017 样本：pdfsig_verify **15/15** 项通过、verify_gm_pdf **14/14** 项通过、证书链深度验证全部通过
  - GB/T 38540-2020 样本：pdfsig_verify **22/22** 项通过（SES 走专用分支）、证书链深度验证全部通过
  - 两份样本的证书链、CRL、OCSP 全部**内嵌于 PDF 文件内部**（签名 Contents + DSS 对象），**离线即可完成完整密码学验证**，无需访问任何外部 URL。

---

## 一、结论摘要

| 样本 | 签名格式 | 签名证书 | 文档摘要一致性 | 密码学验签 | 时间戳令牌 | 证书链 | LTV/DSS | 判定 |
|---|---|---|---|---|---|---|---|---|
| GB/T 35275-2017 | `/GM.sm2cms.detached` | 113548382（SM2/EC） | ✓ | ✓（signedAttrs，SM3(ZA‖M)） | ✓（RFC3161，TSA 验签通过） | ✓ 终端→CA→根 | ✓（DSS=92，材料齐） | **符合** |
| GB/T 38540-2020 | `/GM.sm2seal` | 113548382（SM2/EC） | ✓ | ✓（印章签名+SES_ToSign 双验签） | ✓（GB/T 38540 字段4，TSA 验签通过） | ✓ 终端→CA→根 | ✓（DSS=92，材料齐） | **符合** |

---

## 二、依据标准（引用）

| 标准/规范 | 名称 | 在本验证中的作用 |
|---|---|---|
| **GB/T 35275-2017** | 《信息安全技术 SM2密码算法加密签名消息语法规范》 | 规定 SM2 签名消息（CMS）的结构与 `/GM.sm2cms.detached` 子过滤器语义 |
| **GB/T 38540-2020** | 《信息安全技术 安全电子签章密码技术规范》 | 规定电子印章 SES（`SES_Signature`/`SESeal`）结构与 `/GM.sm2seal` 子过滤器语义 |
| **GB/T 32918.2-2016** | 《信息安全技术 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法》 | SM2 签名验证算法、ZA 计算（默认用户标识 `1234567812345678`）、素域曲线参数 |
| **GB/T 32905-2016** | 《信息安全技术 SM3密码杂凑算法》 | SM3 杂凑算法（消息摘要与 ZA 计算均以其为底层） |
| **RFC 5652** | Cryptographic Message Syntax (CMS) | SignedData/SignerInfo/signedAttrs 的 DER 编码规则（签名对象为 signedAttrs 的 DER 编码） |
| **ISO 32000-1:2008** | Document management — Portable document format | PDF 数字签名（§12.8）、`ByteRange` 覆盖内容、`DSS`（文档安全存储，§12.8.4，LTV 支持） |
| **RFC 3161** | Internet X.509 Public Key Infrastructure Time-Stamp Protocol | 时间戳令牌（TimeStampToken）结构与 TSTInfo 语义 |
| **RFC 6960** | X.509 Internet Public Key Infrastructure Online Certificate Status Protocol | OCSP 响应结构（`responseStatus` 为 ENUMERATED）、CertID/吊销状态语义 |

> 上述均为现行有效的国家标准与国际标准；验证程序对标准条款的实现细节见「四、验证方法与程序」及随附源码注释。

---

## 三、逐项验证结果

### 3.1 GB/T 35275-2017 样本（`/GM.sm2cms.detached`）

| # | 验证项 | 结果 | 证据 |
|---|---|---|---|
| 1 | PDF 可打开 | ✓ | 页数=1 |
| 2 | 存在签名域 | ✓ | 签名对象 xref=[75] |
| 3 | 签名过滤器 | ✓ | `Filter=/Adobe.SM2 SubFilter=/GM.sm2cms.detached` |
| 4 | ByteRange 结构 | ✓ | `[0, 54275, 198619, 30870]`（4 段标准结构） |
| 5 | 签名内容存在 | ✓ | Contents 长度=72171 字节（DER 二进制） |
| 6 | ByteRange 分段可读 | ✓ | 覆盖字节=85145 |
| 7 | CMS 结构解析 | ✓ | contentType=`1.2.840.113549.1.7.2`（SignedData），证书数=3，签名者数=1 |
| 8 | 签名证书匹配 | ✓ | 证书=`C=CN, O=ChinaITboys, OU=Person, CN=2829969554@qq.com` |
| 9 | 签名算法 | ✓ | `SM3-SM2`（1.2.156.10197.1.501），摘要 SM3（1.2.156.10197.1.401） |
| 10 | messageDigest 与文档内容一致 | ✓ | 声明=`99f29c0b…`，计算=`99f29c0b…`（对 ByteRange 双段数据做 SM3） |
| 11 | SM2 签名验签（signedAttrs） | ✓ | 签名对象=签名属性集合的 DER 编码（`SET` 最小长度编码），e=SM3(ZA‖M)，**验签通过** |
| 12 | 时间戳令牌存在（RFC3161） | ✓ | 证书数=2；TSA 签名算法 SM3-SM2；TSTInfo：policy=`1.3.6.1.4.1.4146.1.95`，genTime=`20260916141445Z` |
| 13 | 证书链 | ✓ | 终端 → `CN=SM2CA` → `C=CN, O=My Org, CN=ROOTCA` |
| 14 | LTV/DSS 对象 | ✓ | DSS 对象=92（pikepdf 按 `Type=/DSS` 精确定位） |
| 15 | DSS 验证材料 | ✓ | Certs=3、CRLs=2、OCSPs=3（ISO 32000-1 LTV 长期验证） |

**汇总：15/15 项通过（verify_gm_pdf 结构检查另计 14/14 项通过）。**

### 3.2 GB/T 38540-2020 样本（`/GM.sm2seal`）

| # | 验证项 | 结果 | 证据 |
|---|---|---|---|
| 1 | PDF 可打开 | ✓ | 页数=1 |
| 2 | 存在签名域 | ✓ | 签名对象 xref=[75] |
| 3 | 签名过滤器 | ✓ | `Filter=/Adobe.SM2 SubFilter=/GM.sm2seal` |
| 4 | ByteRange 结构 | ✓ | `[0, 54267, 198611, 30868]` |
| 5 | 签名内容存在 | ✓ | Contents 长度=72171 字节 |
| 6 | ByteRange 分段可读 | ✓ | 覆盖字节=85135 |
| 7 | SES 结构解析 | ✓ | 顶层子元素=5（SES_Signature 标准五字段） |
| 8–12 | SES 字段类型 | ✓ | toSign=`0x30`/20143B、印章图像=`0x04`/1677B、摘要算法=`0x06`/8B、签名值=`0x03`/71B、时间戳=`0xA0`/2278B |
| 13 | SES_ToSign 解析 | ✓ | version=4；esInfo=20070B；时间=`20260916144120Z`；签名值=32B；类型=`PDF-SM2-SEAL` |
| 14 | 印章信息解析 | ✓ | SESealInfo=18305B；图片=1677B（PNG）；摘要算法OID=`1.2.156.10197.1.501`（SM3-SM2）；印章签名=71B |
| 15 | 印章 ID | ✓ | sealID=`caa36f4f-0db5-445e-b255-67eaa0acd83c` |
| 16 | 印章证书提取 | ✓ | 证书数=3：终端 → `CN=SM2CA` → `CN=ROOTCA` |
| 17 | 印章签名验签（SESealInfo） | ✓ | 由证书 113548382 对 SESealInfo 完整 DER（含 SEQUENCE 头）验签通过，e=SM3(ZA‖M) |
| 18 | 文档签名验签（SES_ToSign） | ✓ | 由证书 113548382 对 SES_ToSign 完整 DER（含 SEQUENCE 头）验签通过，e=SM3(ZA‖M) |
| 19 | 时间戳令牌验证 | ✓ | 证书数=2；TSA 证书含 `时间戳(1.3.6.1.5.5.7.3.8)` EKU；**TSA 令牌 SM2 验签通过** |
| 20 | 证书链 | ✓ | 终端 → `CN=SM2CA` → `CN=ROOTCA` |
| 21 | LTV/DSS 对象 | ✓ | DSS 对象=92（pikepdf 按 `Type=/DSS` 精确定位） |
| 22 | DSS 验证材料 | ✓ | Certs=3、CRLs=2、OCSPs=3（ISO 32000-1 LTV 长期验证） |

**汇总：22/22 项通过。**

### 3.3 证书链深度验证（离线材料盘点，两样本同批执行）

针对"签名结构是否真的包含证书链、离线能否验证"，对签名 Contents 与 DSS 对象做全量提取与逐级密码学验签。

**内嵌证书（5 张，按序列号去重；两样本相同）**

| 序列号 | 证书 | 算法 | 嵌入位置 |
|---|---|---|---|
| 113548382 | 签名者证书 `C=CN, O=ChinaITboys, OU=Person, CN=2829969554@qq.com` | SM2（EC 256） | 签名 Contents（SESealInfo 证书集 / CMS certificates） |
| 1cdd33203a2ce | CA 证书 `CN=SM2CA` | SM2（EC 256） | 签名 Contents |
| 13fbe86586d3f90 | 根证书 `C=CN, O=My Org, CN=ROOTCA` | RSA 2048 | 签名 Contents |
| 11355e5c4 | TSA 签名证书 `CN=SM2ROOTCA By Timstamp SM3` | SM2（EC 256） | 时间戳令牌（SES.esInfo 内 CMS / unsignedAttrs） |
| 13fbe865870f9b4 | TSA 根证书 `C=CN, O=My Org, CN=SM2ROOTCA` | SM2（EC 256） | 时间戳令牌 |

**文档签名链（子证书 ← 父证书公钥，逐级验签）**

```
签名者 113548382  ←  SM2CA 1cdd33203a2ce   SM2(ZA) 验签通过
SM2CA 1cdd33203a2ce ← ROOTCA 13fbe86586d3f90  RSA-sha256 验签通过
ROOTCA 13fbe86586d3f90 自签名（信任锚）         RSA-sha256 验签通过
```

**TSA 时间戳链（逐级验签）**

```
TSA 签名证书 11355e5c4 ← SM2ROOTCA 13fbe865870f9b4  SM2(ZA) 验签通过
SM2ROOTCA 13fbe865870f9b4 自签名（信任锚）           SM2(ZA) 验签通过
```

**吊销证据（DSS 对象内，全部离线可核验）**

| 材料 | 数量 | 内容 |
|---|---|---|
| CRL | 2 | CRL[0] 签发者=SM2CA（SM2(ZA) 验签通过，吊销 0 条）；CRL[1] 签发者=ROOTCA（RSA-sha256 验签通过，吊销 0 条） |
| OCSP | 3 | OCSP[0]→113548382、OCSP[1]→1cdd33203a2ce、OCSP[2]→13fbe86586d3f90，状态全部 `正常(good)`，响应可解析、无吊销 |

**结论**：证书链、CRL、OCSP 全部内嵌于 PDF（签名 Contents + DSS），离线即可完成每一级的密码学验签与吊销状态核对，**不依赖任何外部 URL**。

---

## 四、验证方法与程序

### 4.1 技术路线

验证程序分两条线，交叉验证、互相印证：

**A 线 —— 纯标准库自实现（不信任任何现成验签实现）**

1. **SM3 杂凑算法**（`sm2lib.py`）：按 GB/T 32905-2016 实现消息填充、迭代压缩；使用国标标准测试向量自检通过。
2. **SM2 签名验证**（`sm2lib.py`）：按 GB/T 32918.2-2016 实现——
   - 素域 Fp 曲线参数（p、a、b、n、Gx、Gy，256 位）；
   - 点加、倍点、标量乘（二进制展开）；
   - ZA 计算：`ZA = SM3(ENTL || ID || a || b || xG || yG || xA || yA)`，默认用户标识 `1234567812345678`；
   - 验签判定：`R = (e·G + r·Q)` 的 x 坐标与 r 比较（含 r、s ∈ [1, n−1] 边界检查）。
3. **RSA 验签**（`pdfsig_verify.py`）：RSA PKCS#1 v1.5 —— 先验 `00 01` 填充头、定位 `00` 分隔符，再解析 DigestInfo 做摘要比对（用于 ROOTCA 自签与 RSA 链验证）。
4. **DER 解析器**（`derlib.py`）：自实现通用 TLV（X.690 编码规则），支持短/长长度、上下文构造标签；在此之上实现 X.509 证书解析（序列号/DN/有效期/公钥/SKI/AKI/EKU/证书策略/基本约束）、CMS SignedData/SignerInfo 解析（含 signed/unsigned 属性）。
5. **PDF 签名域提取**（`pdfsig_verify.py` + PyMuPDF）：定位 `/Sig` 对象，读取 `Filter/SubFilter/ByteRange/Contents`；`ByteRange` 双段内容拼接后做 SM3 摘要，与 CMS `messageDigest` 属性比对。
6. **签名对象重建**：CMS 按 RFC 5652，签名对象为 signedAttrs 的 **DER 编码（SET，最小长度编码）**；SES 按 GB/T 38540，印章签名对象为 **SESealInfo 完整 SEQUENCE DER**，文档签名对象为 **SES_ToSign 完整 SEQUENCE DER**。均按 `e = SM3(ZA || M)` 完成验签。
7. **时间戳令牌验证**：解析 TimeStampToken（RFC 3161）→ CMS 结构 → TSTInfo（policy/genTime/messageImprint）→ TSA 证书匹配 → 对 signedAttrs DER 做 SM2 验签。

**B 线 —— 第三方库交叉验证（结构检查）**

8. `verify_gm_pdf.py` 用 pikepdf / cryptography / asn1crypto 做 CMS 结构深度检查（12+ 项），SM2 验签仍回落到 A 线的 `sm2lib`（cryptography 不支持 SM2 曲线证书的 ZA 模式验签）。
9. DSS 定位用 **pikepdf 按 `Type=/DSS` 精确扫描**（PyMuPDF 会把 Catalog 的 `/DSS` 间接引用误当 DSS 对象，导致对象号误报）；DSS 数组元素为流对象，`bytes(ref)` 直接取出证书/CRL/OCSP DER。

### 4.2 程序清单（位于 `GMcheck\`）

| 文件 | 作用 |
|---|---|
| `pdfsig_verify.py` | 主验证程序（两样本全项检查、时间戳令牌解析、SES 深度验签、RSA PKCS#1 v1.5、DSS 材料检查） |
| `verify_gm_pdf.py` | pikepdf/cryptography/asn1crypto 交叉验证（CMS 深度检查，SES 走跳过分支） |
| `chain_deep_verify.py` | 证书链深度验证：内嵌证书全量提取、按 AKI/SKI+DN 构建链、逐级密码学验签、CRL/OCSP 吊销证据核验、离线可用性结论 |
| `derlib.py` | DER TLV、X.509 证书、CMS SignedData/SignerInfo、SES 辅助解析 |
| `sm2lib.py` | SM3、SM2 曲线参数、ZA、`sm2_verify`（含 DER/裸 64 字节签名解码） |
| `check.cmd` | 一键三步验证（结构 → 全项 → 深度链），英文输出规避 Win11 GBK 中文乱码 |

### 4.3 运行方式

```bat
check.cmd
:: 等价手工步骤：
python verify_gm_pdf.py GBT35275-2017.pdf
python verify_gm_pdf.py GBT38540-2020.pdf
python pdfsig_verify.py "GBT35275-2017.pdf" "GBT38540-2020.pdf"
python chain_deep_verify.py "GBT35275-2017.pdf" "GBT38540-2020.pdf"
```

---

## 五、关键验证事实与实现要点

1. **签名对象编码**：35275 样本的 CMS 签名对象为 signedAttrs 集合的 DER 编码——首字节 `0x31`（SET）+ **DER 最小长度**（本样本 22558 字节用 2 字节长格式 `0x82`），而非 `0x84` 4 字节长格式；这直接决定摘要一致性。
2. **ZA 参与**：两样本 SM2 验签均采用**含 ZA** 的摘要模式（`e = SM3(ZA || M)`），与 GB/T 32918.2-2016 标准一致；无 ZA 的简模式均验签失败，反向证明样本符合标准。
3. **SES 双签名结构**：38540 样本含两层签名——印章签名（对 SESealInfo）与文档签名（对 SES_ToSign），均使用终端证书私钥 SM2 签名，且均验签通过。
4. **时间戳**：两样本均嵌入时间戳令牌（SM3-SM2 算法），TSTInfo 政策 OID 为 `1.3.6.1.4.1.4146.1.95`，TSA 令牌本身验签通过；TSA 证书链（TSA 签名证书 → SM2ROOTCA）独立于文档链，也逐级验签通过。
5. **证书链**：文档签名链 终端(113548382) → CA(1cdd33203a2ce) → 根(13fbe86586d3f90)，与 AKI/SKI 扩展一致，逐级密码学验签全部通过（含根自签 RSA 验签）。
6. **吊销证据离线可用**：DSS（xref=92）内含 Certs=3、CRLs=2、OCSPs=3；两份 CRL 分别由 SM2CA（SM2）与 ROOTCA（RSA）签发并验签通过（吊销 0 条）；三份 OCSP 对链上全部证书返回 `正常(good)`。
7. **证书与吊销材料全部内嵌**：验证不访问任何外部 URL，仅凭 PDF 文件本身即可完成证书链验证与吊销状态核对——满足 LTV（长期验证）的离线可用性要求。

---

## 六、局限性与说明

1. 验证聚焦"签名密码学正确性 + 结构符合性 + 链与吊销证据完整性"，未对字体嵌入、元数据、页面内容做文档一致性检查（不属于签名标准范畴）。
2. 时间戳令牌的 `genTime` 显示为 UTC（`20260916141445Z`），PDF 签名 `M` 条目标注为 `D:20260916221444+08'00'`（本地时区），两者相差 8 小时，属同一时刻的时区表示，符合规范。
3. 所有结论基于对样本二进制内容的独立解析与重算，未借助任何商业验签工具；如需与权威工具交叉验证，可选用符合 GB/T 标准实现的签名验证 SDK。
4. `verify_gm_pdf.py` 对 38540（SES 格式）按设计走"结构检查 + 提示使用专用验证"分支，密码学验证由 `pdfsig_verify.py` 与 `chain_deep_verify.py` 覆盖。

---

*报告生成：MODPKICA 国密 PDF 签名验证工具链（纯 Python，GMcheck\ 三步验证）*
