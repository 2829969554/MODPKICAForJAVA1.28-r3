# MODPKICAForJAVA126 逐文件、逐方法源码级深度审计报告

**审计对象：** MODPKICAForJAVA126-master.zip  
**审计时间：** 2026-09-26  
**项目定位：** 实验型 PKI  
**源码文件：** 23 个 Java 文件  
**主要源码规模：** 约 2.3 万行  
**依赖：** BouncyCastle 1.85、PDFBox 3.0.4

---

# 一、审计结论先行

本次不是 README 审计，而是直接读取当前 ZIP 中的 Java 源码，并进行：

- 全部 Java 文件扫描
- 方法清单分析
- 核心方法源码检查
- 编译验证
- 实际 Root CA 运行
- 实际 PQC Root 运行
- X.509 JSON 往返测试
- 117 张当前仓库证书批量往返测试
- 吊销 CA 后继续签发终端证书测试

最终结论：

> **MODPKICAForJAVA126 已经形成一个功能范围很大的实验型 PKI 系统，但目前仍存在若干真正的源码级缺陷。**

尤其确认了以下几个以前无法通过 README 确定的问题：

1. **WebAdmin 在非回环绑定时确实没有认证/授权。**
2. **MAIN 主服务默认绑定所有网卡，而不是只绑定 localhost。**
3. **`/ct/add` 是未认证 CT 签名服务。**
4. **证书验证不是完整 PKIX Path Validation。**
5. **OCSP 响应者证书没有做授权验证。**
6. **吊销的 CA 仍然可以继续签发终端证书。**
7. **renew/rekey 会保留原证书 serial，属于严重的证书生命周期设计问题。**
8. **X.509 JSON 转换并非普遍“无损”。117 张实际证书中 13 张出现 DER 字节级不一致。**
9. **ML-DSA 已经能签发证书，但当前 JSON rekey/renew 生命周期并不支持 ML-DSA。**
10. **CT Log 私钥直接以 Base64(PKCS#8) 保存，没有加密保护。**
11. **CERTS.txt 重写失败会被静默吞掉，可能造成内存/磁盘状态不一致。**
12. **PDF/CMS 的证书链验证同样不是 PKIX 验证，而且存在“自签证书直接被当作链顶”的逻辑。**

因此：

> **当前版本作为“实验型 PKI”是成立的；作为生产级 CA/签名平台则还有明显的安全和 PKI 语义问题。**

---

# 二、实际编译验证

源码实际编译：

```text
javac
+
BC185/*
+
lib/*
```

结果：

```text
JAVAC = 0
```

仅存在 deprecated API、unchecked / unsafe operations 提示，没有编译错误。

---

# 三、实际运行验证

## 3.1 Root CA

实际执行 `MakeRoot` 成功产生：

- ROOT/*.crt
- ROOT/*.key
- WebPublic/CRT/*.crt
- WebPublic/CRL/*.crl
- WebPublic/CRL/*.der.crl
- CERTS.txt

说明 Root CA → 证书 → CERTS → CRL 的实际运行流程存在。

---

# 四、实际 PQC 验证

使用实际源码创建 ML-DSA-65 Root CA，成功产生 Root Certificate、CRL、CERTS.txt。

因此：

> **PQC Root CA 不是 README 假功能。**

但继续进行 PQC Certificate → X509JsonConverter → rekey 时实际失败：

```text
Unsupported key algorithm for rekey:
2.16.840.1.101.3.4.3.18
```

对应 ML-DSA-65。

源码位置：

```text
X509JsonConverter.java:1287-1340
```

`generateKeyPair()` 没有 ML-DSA-44/65/87 OID 分支。

---

# 五、X.509 JSON 无损转换：发现实际缺陷

仓库中实际存在 117 张 `.crt`。

使用同一个 JVM 批量执行：

```text
PEM
 ↓
X509JsonConverter.certToJson()
 ↓
jsonToCertPem()
 ↓
DER byte comparison
```

结果：

```text
成功：104
失败：13
总数：117
```

即：

- 成功率：88.89%
- DER 字节级失败率：11.11%

---

# 六、X.509 JSON 失败原因已经定位

失败样本的 DER 差异明确出现在 KeyUsage BIT STRING。

例如：

```text
原始：
03 55 1d 0f 04 04 03 02 00 a8

重建：
03 55 1d 0f 04 04 03 02 03 a8
```

对应：

```text
OID 2.5.29.15
KeyUsage
```

BIT STRING 的 `unusedBits` 发生变化。

源码：

```text
X509JsonConverter.java:585-597
```

解析时只保存：

- digitalSignature
- nonRepudiation
- keyEncipherment
- ...

没有保存原始 BIT STRING 的 `unusedBits`。

重建：

```text
X509JsonConverter.java:1539-1556
```

直接重新构造 `new KeyUsage(value)`。

因此：

> **它保存了“KeyUsage 的语义”，但没有保存“KeyUsage 的原始 ASN.1 BIT STRING 编码”。**

这与“字节级无损”不是同一件事。

---

# 七、其他潜在 BIT STRING 无损问题

需要继续关注：

- issuerUniqueId
- subjectUniqueId
- NetscapeCertType

目前部分路径只保存 bytes 或逻辑位集合，重建时可能统一按照默认 unusedBits 重新编码。

因此准确结论应该是：

> **X509JsonConverter 对部分证书能够做到 DER 字节级无损，但尚不能宣称对任意 X.509 证书普遍无损。**

---

# 八、PKI-001：MAIN 默认绑定所有网络接口

`MAIN.java:81`

实际：

```java
HttpServer.create(
    new InetSocketAddress(Integer.parseInt(port)), 0
);
```

没有指定 `127.0.0.1`。

因此不是只监听 localhost，而是典型的 `0.0.0.0:80`。

随后公开注册：

- `/OCSP`
- `/ocsp`
- `/timestamp`
- `/timestamp/sha1`
- `/rfc3161`
- `/ct/add`
- `/`

源码：

```text
MAIN.java:81-90
```

结论：

> **MAIN 与 WebAdmin 的安全边界不同。**

WebAdmin 默认 `127.0.0.1`，MAIN 默认所有网卡。

---

# 九、PKI-002：`/ct/add` 是未认证 CT 签名接口

`MAIN.java:579-635`

任何能够访问 MAIN 端口的客户端都可以 POST `/ct/add`。

服务器会：

1. 解析 precertificate
2. 解析 issuer
3. 删除 poison
4. 计算 issuer_key_hash
5. 使用 CT Log 私钥
6. 生成 SCT
7. 返回 SCTList

没有：

- 认证
- 授权
- 签名者身份验证
- issuer 与 precert 关系验证
- precertificate 签名验证
- poison 存在性验证

因此：

> **它实际上是一个 CT Log 签名 Oracle。**

对于实验型本地 CT Log 可以理解，但不能称为完整 RFC 6962 CT Log 服务。

---

# 十、PKI-003：CT Log 私钥明文保存

`CtLog.LogKey` 保存：

```text
Base64(PKCS#8 PrivateKey)
```

源码：

```text
CtLog.java:287-315
```

没有：

- 加密
- 密码保护
- Keystore
- HSM
- PKCS#11
- DPAPI

Base64 不是加密。

因此：

> `PKI/CA/modpkica_ct_list.json` 泄露后可以直接恢复 CT Log 私钥。

**严重程度：高。**

---

# 十一、PKI-004：CertVerify 不是完整 PKIX Path Validation

`CertVerify.run()` 主要执行：

```text
证书
 ↓
AIA caIssuers
 ↓
HTTP 下载 issuer
 ↓
issuer public key
 ↓
cert.verify()
```

源码：

- `CertVerify.java:197-206`
- `CertVerify.java:675-690`

验证的是当前证书签名是否能够被某个上级证书公钥验证。

但没有形成完整的：

- PKIX CertPath
- TrustAnchor
- BasicConstraints
- KeyUsage
- PathLenConstraint
- NameConstraints
- CertificatePolicies
- EKU
- 有效期
- CRL
- OCSP

统一验证结果。

---

# 十二、PKI-005：printChain() 不是逐级验签

`CertVerify.printChain()` 主要是：

```text
当前证书
 ↓
读取 AIA
 ↓
再读取 AIA
 ↓
Root
```

用于显示链，而不是完成完整验证。

没有在递归过程中逐级执行：

```text
child.verify(parent.getPublicKey())
```

并检查：

- parent BasicConstraints CA=true
- parent KeyUsage keyCertSign
- validity
- path constraints

因此：

> **显示出一条 Root → CA → Leaf 路径不等于这条 PKIX 链验证成功。**

---

# 十三、PKI-006：TrustAnchor 只比较 SPKI

`CertVerify.isInTrustAnchor()`：

```text
root.getPublicKey().getEncoded()
==
cert.getPublicKey().getEncoded()
```

源码：

```text
CertVerify.java:736-800
```

它不是比较完整根证书或根证书指纹，而是比较 SubjectPublicKeyInfo。

因此理论上：

```text
证书 A：公钥 K
证书 B：公钥 K
但 Subject / Issuer / Validity / Extensions 不同
```

B 也可能被视为同一 TrustAnchor。

这是信任锚模型不严谨的问题。

---

# 十四、PKI-007：OCSP 响应者授权没有完整验证

`CertVerify.checkOcsp()`：

```text
BasicOCSPResp
 ↓
取 embedded certificate
 ↓
获取 public key
 ↓
验证 OCSP signature
```

源码：

```text
CertVerify.java:924-930
```

但没有完整验证：

- responder certificate → issuer
- OCSPSigning EKU
- 有效期
- responder certificate chain

因此：

> **密码学签名能够验证，不等于 OCSP responder 具备合法授权。**

---

# 十五、PKI-008：CRL 验证相对完整

`checkCrl()` 实际执行：

- CRL issuer 与 issuer Subject 比较
- CRL signature verify
- thisUpdate
- nextUpdate
- serial lookup

源码：

```text
CertVerify.java:837-889
```

因此本项不应再误报为“没有 CRL 验证”。

---

# 十六、PKI-009：吊销 CA 后仍可以继续签发

实际运行验证：

```text
Root
 ↓
Intermediate CA
 ↓
吊销 Intermediate CA
 ↓
MakeCert
 ↓
使用已经吊销的 Intermediate CA
 ↓
成功签发 End Entity
```

原因：

`MakeCert.resolveIssuer()`：

```text
MakeCert.java:385-394
```

主要检查 CA 文件是否存在，没有检查：

- issuer status
- issuer validity
- issuer BasicConstraints
- issuer KeyUsage

因此：

> **“文件存在”被当成“允许作为 CA 继续签发”。**

这是实际 PKI 生命周期缺陷。

---

# 十七、PKI-010：终端证书可以请求 keyCertSign

`MakeCert.java:245-254`

普通 End Entity：

```text
isCa = false
```

但 KeyUsage 来自用户参数。

因此理论上可能产生：

```text
BasicConstraints CA=false
+
KeyUsage keyCertSign
```

的矛盾 profile。

签发器应该阻止：

```text
CA=false && keyCertSign
```

---

# 十八、PKI-011：Intermediate CA 没有 PathLenConstraint

CA 创建使用：

```text
new BasicConstraints(true)
```

没有明确 pathLen 限制。

因此理论上可以：

```text
Root
 ↓
CA
 ↓
CA
 ↓
CA
 ↓
...
```

实验型 PKI 可以作为设计选择，但如果追求完整 CA profile 管理，应增加 PathLenConstraint。

---

# 十九、PKI-012：Renew 保留原 serial

`renewJsonToPemByIssuer()`：

```text
X509JsonConverter.java:1087-1100
```

主要修改：

- notBefore
- notAfter

没有生成新的 serialNumber。

因此：

```text
旧证书：Serial=A
续签证书：Serial=A
```

同一 issuer 下多个证书实例共用 serial。

这是证书生命周期设计问题。

---

# 二十、PKI-013：Rekey 同样保留原 serial

`rekeyAction()`：

```text
WebAdmin.java:980-1044
```

流程：

```text
读取旧证书
 ↓
生成新 KeyPair
 ↓
替换 publicKey
 ↓
重新签名
 ↓
使用原 serial
 ↓
覆盖原证书
```

结果：

```text
旧 PublicKey=K1, Serial=A
新 PublicKey=K2, Serial=A
```

会影响：

- CRL
- OCSP
- 审计日志
- 历史签名
- LTV
- 证书归档

---

# 二十一、PKI-014：PQC 生命周期不完整

v1.26 已支持：

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

创建、签发、CRL 等基本能力实际存在。

但是 JSON rekey 实际失败，原因是：

`X509JsonConverter.generateKeyPair()` 没有 ML-DSA OID 分支。

`sigAlgOidToJcaName()` 也没有完整覆盖 ML-DSA signature OID。

因此：

> **v1.26 是“PQC 签发支持”，但不是完整 PQC 证书生命周期支持。**

---

# 二十二、PKI-015：CERTS.txt 不是事务数据库

`CertsDB` 采用：

```text
文本文件
+
内存 ArrayList
```

`rewriteAll()`：

```text
CertsDB.java:236-247
```

异常被：

```java
catch (IOException ignored) {
}
```

吞掉。

可能造成：

```text
内存状态：R
磁盘状态：V
```

重启后重新加载可能恢复成 V。

这是实际状态一致性问题。

---

# 二十三、PKI-016：CERTS.txt 没有统一事务/锁机制

WebAdmin 有 `WRITE_LOCK`，可以保证同一 WebAdmin 进程内部分写操作串行。

但：

- MakeCert
- MakeRoot
- Auto
- MAIN
- WebAdmin

都可能访问 CERTS.txt。

多个 JVM / 外部程序之间没有统一文件锁。

实验型环境可以接受，生产 CA 不可以。

---

# 二十四、PKI-017：CertsDB 全局按 serial 查找

代码同时存在：

- `findBySerial()`
- `findByIssuerAndSerial()`

部分业务使用 `findBySerial()`。

X.509 serial 的唯一性语义是 issuer 范围内，而不是全局。

由于项目 serial 为 128-bit 随机值，实际碰撞概率极低，所以这是架构严谨性问题。

---

# 二十五、PKI-018：WebAdmin 非回环绑定时没有认证

WebAdmin 默认：

```text
127.0.0.1
```

但如果：

```text
-Dmodpkica.admin.bind=0.0.0.0
```

管理接口仍没有认证/授权。

高权限 API 包括：

- `/api/init`
- `/api/makeroot`
- `/api/signcert`
- `/api/revoke`
- `/api/restore`
- `/api/rekey`
- `/api/renew`
- `/api/sign/exe`
- `/api/sign/pdf`
- `/api/my/import`
- `/api/my/delete`
- `/api/ctlog/delete`

这是高危问题。

---

# 二十六、PKI-019：WebAdmin 签名 API 未强制检查证书状态

`signAction()` 读取证书后直接进入签名流程，没有把：

- status == V
- notBefore
- notAfter

作为统一后端安全边界。

因此直接调用 API 时，已吊销或过期证书存在继续签名的可能。

> **UI 限制不等于后端安全限制。**

---

# 二十七、PKI-020：multipart 没有限制请求体大小

`WebAdmin.readMultipart()`：

```text
WebAdmin.java:2616-2697
```

直接把 RequestBody 全部读取进内存。

MAIN 的 `readAll()` 也有类似问题。

暴露到网络后，巨型请求可能导致内存 DoS。

---

# 二十八、PKI-021：SignTool.verifyChain() 不是 PKIX

`SignTool.verifyChain()`：

```text
SignTool.java:1078-1115
```

主要做证书签名关系检查。

没有完整检查：

- Issuer/Subject
- BasicConstraints
- KeyUsage
- PathLen
- Validity
- TrustAnchor
- EKU
- NameConstraints
- Policy

自签证书可能直接作为链顶。

---

# 二十九、PKI-022：PDF CAdES-T 时间戳主路径没有真正验证 TSA 签名

`verifyPdf()` 对 `id-aa-timeStampToken` 主要检查 token 与签名值的绑定关系。

没有在该主路径中完成完整：

```text
TimeStampToken
 ↓
TSA signature verify
 ↓
TSA certificate chain
 ↓
timeStamping EKU
 ↓
TrustAnchor
```

需要与独立 DocTimeStamp 验证路径区分。

---

# 三十、PKI-023：DocTimeStamp 做了 token 验签，但没有完整 TSA Trust Chain

`verifyDocTimeStamp()` 确实验证：

- messageImprint
- TSA certificate signature

但 TSA 证书直接来自 token，没有进一步建立完整可信链并检查 `timeStamping` EKU。

因此：

> **密码学验签 ≠ TSA 身份可信。**

---

# 三十一、PKI-024：PQC Authenticode/PDF 不是完整标准闭环

SignTool 对 PQC digest/signature OID 的处理存在实验性兼容路径。

目前不能把：

```text
PQC certificate
+
Authenticode/PDF
```

直接等同于完整的 Windows/标准 PAdES PQC 生态兼容。

更适合定位为实验性能力。

---

# 三十二、PKI-025：SM2 实现整体值得肯定

`Sm2Util` 使用：

- SM2Signer
- ParametersWithID
- 默认 UID
- ZA
- SM3

实现路径完整。

特别是使用 `ParametersWithID`，而不是简单把 SM2 当作 ECDSA，是正确方向。

---

# 三十三、PKI-026：OCSP CertID 匹配做得较认真

当前 OCSP 客户端比较：

- hashAlgorithm
- issuerNameHash
- issuerKeyHash
- serial

不是只看 serial。

源码：

```text
CertVerify.java:945-955
```

这是当前实现比较扎实的一块。

---

# 三十四、PKI-027：MAIN OCSP 对 issuer hash 做了二次验证

`MAIN.handleOcsp()`：

```text
MAIN.java:206-223
```

会把请求中的：

- issuerNameHash
- issuerKeyHash

与真实 issuer certificate 重算值比较。

这可以防止部分 issuer 混淆。

---

# 三十五、PKI-028：证书查看器两个版本确实存在

## CERTS.txt 证书查看器

实际进行：

- CRL
- OCSP
- 吊销状态

检查。

## Java cacerts / 根证书查看器

独立读取 Java certificate store。

主要检查：

- 有效期
- 自身签名

不调用项目 CERTS.txt 吊销状态。

因此该设计不是之前报告中的缺陷。

---

# 三十六、PKI-029：X509JsonConverter 的结构处理具有较高技术含量

实际处理：

- DN
- 多值 RDN
- AlgorithmIdentifier
- UTCTime
- GeneralizedTime
- SPKI
- SKI
- AKI
- SAN
- KeyUsage
- EKU
- BasicConstraints
- CRLDP
- CertificatePolicies
- AIA
- NameConstraints
- PolicyConstraints
- PolicyMappings
- SCT
- 未知 Extension rawHex

但：

> 已知结构如果只保留语义字段，没有同时保留原始 DER，就不能保证真正无损。

---

# 三十七、PKI-030：Admin.captureStdout 存在线程安全问题

`Admin.java:224-235`

使用：

```java
System.setOut(...)
```

而 WebAdmin 是多线程 executor。

并发请求可能互相污染 stdout 捕获结果。

建议改成：

```text
业务方法返回 String / Result 对象
```

而不是依赖 JVM 全局 `System.out`。

---

# 三十八、PKI-031：MakeRoot 的 baseDir 没有完整贯穿 CRL 流程

`MakeRoot.run(baseDir, args)` 使用了 baseDir，但最后：

```text
RootGetCrl.run()
```

没有把 baseDir 继续传进去。

源码：

```text
MakeRoot.java:235-236
```

如果调用者使用独立 baseDir，Root 生成与 CRL 生成可能操作不同目录。

---

# 三十九、逐文件审计结果

## Admin.java

主要方法均已检查：

- main
- printHelp
- cmdInit
- cmdMakeRoot
- cmdSignCert
- cmdRevoke
- cmdInitOcsp
- cmdInitTimestamp
- cmdVerifyCert
- captureStdout
- doList
- doRestore
- doSignCrl
- doInitOcsp
- doInitTimestamp
- doVerifyCert

主要问题：

- `captureStdout()` 线程安全
- baseDir 上下文不完全贯穿

---

## AppEnv.java

`getExeNames()` 为工具方法。

未发现明显 PKI 缺陷。

---

## AppPaths.java

`baseDir()` 功能简单。

环境变量可以改变 PKI 工作目录，实验环境可接受。

---

## Auto.java

主要负责：

- init
- revoke
- restore
- addCert

功能属于实验型自动化辅助。

---

## Bc.java

BC Provider 初始化正确。

---

## CertUtil.java

主要负责：

- RSA
- ECC
- SM2
- PQC
- ContentSigner
- SKI
- Policies

总体质量较高。

---

## CertVerify.java

属于核心安全模块。

主要问题：

- 非完整 PKIX
- AIA 过度依赖
- TrustAnchor 只比较 SPKI
- OCSP responder 授权不足
- CRL/OCSP 没有统一进入最终信任结论

---

## CertsDB.java

主要问题：

- 文件数据库无事务
- rewriteAll 吞异常
- serial 查询模型
- 跨进程没有锁

---

## Config.java

配置读取简单可靠。

---

## CrlUtil.java

CRL 编码与 revoked cert 处理正常。

---

## CtLog.java

优点：

- SCT TLS 编码
- poison 处理
- issuer_key_hash
- 多算法签名

问题：

- CT 私钥明文 Base64
- `/ct/add` 未认证
- precert/issuer 关系验证不足
- JSON 状态不是事务模型

---

## MAIN.java

实际提供：

- OCSP
- CRL/CRT
- RFC3161
- timestamp
- CT

主要问题：

- 默认全网卡监听
- body 无严格上限

---

## MLog.java

日志正常，但缺少轮转和保留策略。

---

## MakeCert.java

核心签发模块。

主要问题：

- 不检查 issuer 是否吊销
- 不检查 issuer KeyUsage
- 不检查 issuer BasicConstraints
- 不检查 issuer validity
- CA=false + keyCertSign
- SAN IP 处理依赖 DNS resolution
- 旧算法路径限制不足

---

## MakeRoot.java

优点：

- Root CA
- RSA/ECC/SM2/PQC
- AIA
- CRLDP
- Policy
- SKI/AKI

主要问题：

- PathLenConstraint
- baseDir 与 RootGetCrl 调用上下文

---

## OcspUtil.java

OCSP ASN.1 构造完整。

需要避免未知 hash OID 静默降级为 SHA-1。

---

## PemIO.java

PEM/key/cert 读写正常。

私钥最终明文存储仍是系统级问题。

---

## RootGetCrl.java

CRL 生成正常。

与 CERTS.txt 状态高度耦合。

---

## SignTool.java

包含：

- Authenticode
- CMS
- PDF
- PAdES
- CAdES-T
- DSS
- LTV
- DocTimeStamp
- 国密电子签章

技术复杂度很高。

主要问题：

- verifyChain 非 PKIX
- CAdES-T token 主路径验签不足
- TSA trust chain 不完整
- PQC 与标准生态并非完整闭环

---

## Sm2Util.java

SM2/SM3 实现质量较高。

---

## TimestampUtil.java

RFC3161 请求/响应处理实际存在。

TSA 信任链应与证书验证体系进一步整合。

---

# 四十、WebAdmin.java 总体审计

WebAdmin 同时包含：

- HTTP backend
- API
- JSON
- 文件处理
- 证书管理
- 签名
- 验证
- CT
- HTML/JavaScript
- Certificate Viewer

已确认关键管理流程均有真实后端：

- `/api/init`
- `/api/makeroot`
- `/api/signcert`
- `/api/revoke`
- `/api/restore`
- `/api/rekey`
- `/api/renew`

查看器接口：

- `/api/certs`
- `/api/certs/cacerts`
- `/api/certjson`
- `/api/certchainjson`
- `/api/verify`

CT：

- `/api/ctlog/*`

MyCert：

- `/api/my/import`
- `/api/my/delete`

因此：

> **WebAdmin 不是只有界面而缺少后端。**

最大安全问题仍然是：

> **没有认证授权。**

---

# 四十一、最终问题等级

## P0 / 立即整改

### P0-01
MAIN 默认全网卡监听。

### P0-02
WebAdmin 非回环绑定无认证。

### P0-03
`/ct/add` 未认证并可直接使用 CT Log 私钥签 SCT。

---

## P1 / 高优先级

1. CertVerify 非完整 PKIX。
2. OCSP responder 授权验证不足。
3. 吊销 CA 仍可签发新证书。
4. Renew 保留 serial。
5. Rekey 保留 serial。
6. X509JsonConverter 不是普遍无损。
7. CT Log 私钥明文保存。
8. CERTS.txt rewrite 失败吞异常。
9. 签名 API 未强制检查证书状态/有效期。
10. PDF/CMS 证书链不是 PKIX。

---

## P2 / 中优先级

1. Intermediate CA 无 PathLenConstraint。
2. CA=false 可以带 keyCertSign。
3. HTTP body 没有限制。
4. CertsDB 全局 serial 模型。
5. Admin.captureStdout 使用全局 System.out。
6. MakeRoot / RootGetCrl baseDir 不完全贯穿。
7. 未知 OCSP hash 默认 SHA-1。
8. 日志没有轮转。

---

# 四十二、已经确认“不是问题”的部分

本次源码级审计专门排除了若干此前容易误报的问题：

### CERTS.txt 证书查看器

确实进行 CRL/OCSP 吊销检查。

### Java cacerts 查看器

确实独立查看 Java certificate store，不调用项目 CERTS.txt 吊销状态。

### CRL

确实根据 issuer 分组生成，不是简单生成一个空文件。

### OCSP

不是只根据 serial 返回结果，实际进行了 issuer hash 校验。

### CT

不是随机生成 SCT，而是真实构造 CT 签名输入。

### X509JsonConverter

不是普通字段导出器，而是真正进行 ASN.1/DER 重建。

---

# 四十三、最终技术定位

综合全部源码：

```text
                 MODPKICAForJAVA126
                         |
          +--------------+--------------+
          |              |              |
        X.509          PKI状态       WebAdmin
          |              |              |
    +-----+-----+    +---+---+     +----+----+
    |     |     |    |   |   |     |    |    |
   RSA   ECC   SM2  CRL OCSP TSA   Viewer CT Sign
    |           |
    +-----+-----+
          |
        PQC/ML-DSA
```

已经明显超过普通：

> “证书生成器”

而属于：

> **实验型 PKI 综合平台。**

---

# 四十四、最终整改主线

建议后续优先处理：

1. MAIN 监听地址
2. WebAdmin 认证授权
3. CertVerify PKIX
4. OCSP responder authorization
5. issuer CA 状态检查
6. renew/rekey 使用新 serial
7. X509Json BIT STRING 无损处理
8. CT private key 加密
9. CERTS.txt 原子写入
10. PQC 生命周期

特别需要强调：

> **本次审计中的“117 张证书中 13 张 JSON 往返失败”和“吊销 CA 后仍能继续签发证书”属于实际运行/数据测试确认的问题，不是根据旧注释或 README 推测。**

---

# 四十五、审计结论

如果按照“实验型 PKI”定位：

**MODPKICAForJAVA126 已经具备较完整的实验型 PKI 功能体系。**

但如果目标进一步提升到：

- 企业 CA
- 生产级 PKI
- 合规 CA
- 可信签名服务
- 标准 PKIX 验证器

则必须优先整改：

```text
信任链验证
+
证书生命周期
+
私钥保护
+
管理面认证授权
+
状态持久化
+
X.509 严格无损转换
+
PQC 完整生命周期
```

当前最核心的技术差距并不是“有没有功能”，而是：

> **已有大量 PKI 功能，但部分模块仍采用“实验型实现逻辑”，尚未统一升级为严格的 PKI 信任模型。**
