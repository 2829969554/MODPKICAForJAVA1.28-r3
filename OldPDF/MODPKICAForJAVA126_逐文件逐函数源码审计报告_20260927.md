# MODPKICAForJAVA126 源码级逐文件 / 逐函数复审报告

**审计对象：** `MODPKICAForJAVA126-master.zip`
**审计日期：** 2026-09-27
**审计口径：** 只依据当前 ZIP 中实际源码、实际编译结果、当前 PKI 数据和当前测试代码；**完全忽略 README.md、OldPDF 下全部 PDF、历史 PDF/审计文档内容**。
**项目定位：** 实验型 PKI

## 1. 本次复审方法

本次不沿用上一份报告的缺陷清单，而是从当前 ZIP 重新开始。审查分为：

- Java `src/modpkica/*.java`：23 个文件，21,281 行；逐文件建立函数清单，并对函数实现、调用关系、异常路径、文件 I/O、证书/密钥/ASN.1 构造、网络入口逐项复核。
- Python `GMcheck/*.py`：7 个源码文件，3,180 行；逐函数复核，并执行 `py_compile`。
- `debug_test/ModpkicaUnitTest.java`：重新编译并执行。
- 忽略 README、PDF、PNG/JPG、历史审计文档、PyInstaller build 产物和已编译 `.class/.exe`，这些不作为源码缺陷依据。

## 2. 当前实际验证结果

| 检查 | 结果 |
|---|---:|
| 完整 Java 源码编译（BC 1.85 + PDFBox 3.0.4） | PASS |
| `-Xlint:all` | 28 warnings，无编译错误 |
| `ModpkicaUnitTest` | **166 passed / 0 failed** |
| 当前测试覆盖的真实 PKI 证书 | 57 张 DER byte-exact |
| ML-DSA-44/65/87 | 全部 roundtrip PASS |
| RSA-PSS | PASS |
| X.509 JSON 结构化/无损转换矩阵 | PASS |
| Python GMcheck 源码编译 | PASS |

因此，上一版报告中已经被当前代码修复的问题，本次不重复作为当前缺陷。

## 3. 当前确认的真实问题

### P1-01：MakeCert 允许使用“文件存在但未登记”的外部 CA 作为 issuer

**定位：** `MakeCert.resolveIssuer()`、`MakeCert.checkIssuerUsable()`，约 421-457 行。

当前 `resolveIssuer()` 只判断：

```text
PKI/CA/<issuerId>.crt
PKI/ROOT/<issuerId>.crt
```

文件是否存在；`checkIssuerUsable()` 虽然检查 validity、BasicConstraints、keyCertSign、CERTS.txt 的 R 状态，但没有强制要求 CERTS.txt 中存在该 issuer，也没有强制 `type == R/C`。

因此命令行用户可以在 CA/ROOT 放入一个满足 CA 条件的证书和私钥，但不在本项目证书台账登记，然后将它作为 issuer。

**影响：** 文件系统身份与 PKI 台账身份脱钩；吊销状态、issuer 类型和审计记录都可能失去约束。

**建议：** `checkIssuerUsable()` 必须要求 `entry != null && (entry.type == R || entry.type == C)`，并验证台账 serial、实际证书 serial、实际 subject/SPKI 与 issuer 文件一致。

### P1-02：CertVerify 的“信任状态”没有把证书有效期纳入最终信任判定

**定位：** `CertVerify.run(Path)` 约 118-215 行；`printChain()` 约 727-770 行。

当前主流程只在状态显示部分检查：

```java
if (now.before(cert.getNotBefore())) ...
```

没有对应的 `now.after(cert.getNotAfter())` 信任判定。更重要的是 `printChain()` 逐级验签时也没有检查当前证书和父证书 validity。

所以一个已经过期、但签名链仍然密码学有效且根位于实验信任锚中的证书，可能得到“链/信任”层面的成功信息。

**建议：** 将 `checkValidity(validationTime)` 纳入每一级 path validation；过期/未生效应直接使最终 trust=false，而不是只作为展示信息。

### P1-03：CertVerify 的 issuer 选择仍主要依赖“能验签”，没有强制 issuer DN / AKI 一致

**定位：** `fetchIssuer()`、`printChain()`、`findLocalIssuer()`。

`findLocalIssuer()` 会优先用 Issuer DN 筛选本地候选，这是好的；但 AIA 获取到的证书在 `printChain()` 中最终主要通过：

```text
verifySignature(child, parent.publicKey)
parent.BasicConstraints >= 0
```

来决定上级。没有强制：

- child.issuer == parent.subject；
- AKI == parent SKI（如果两者存在）；
- parent KeyUsage 包含 keyCertSign（如果 KeyUsage 存在）；
- pathLenConstraint；
- parent validity。

这不是完整 PKIX path validation。

### P1-04：SignTool.verifyChain() 存在更明显的“自签即链顶”问题

**定位：** `SignTool.verifyChain()` 约 1078-1120 行。

函数第一步直接尝试：

```java
cur.verify(cur.getPublicKey());
```

成功就直接返回 `true`，打印“自签根”。这意味着一个自签名的签名者证书，即使不是项目 Trust Anchor，也可能使代码签名链得到 `chainOk=true`。

此外，它从 CMS 证书集合中寻找 issuer 时也是“哪个公钥能验签就选哪个”，没有严格 DN/AKI/CA/pathLen/validity/trust-anchor 约束。

**建议：** SignTool 不应自己维护一套简化链验证；应复用统一 PKIX validator，或者至少增加明确 TrustAnchor 和全部路径约束。

### P1-05：OCSP delegated responder 验证仍缺“由 issuer 授权”这一步

**定位：** `CertVerify.ocspResponderKey()` 约 1129-1160 行。

当前已经正确增加：
- responder certificate validity 检查；
- `id-kp-OCSPSigning` EKU 检查。

但是之后直接：

```java
return respCert.getPublicKey();
```

没有验证 responder certificate 的签名是否由 issuer CA 验证通过，也没有验证 responder 与 issuer 的授权关系。

因此“响应由一个有效期内且带 OCSPSigning EKU 的证书签名”与“该证书确实被该 issuer 授权为 delegated responder”仍不是同一个结论。

### P1-06：签发 child certificate 时没有强制 child validity 不超过 issuer validity

**定位：** `MakeCert.checkIssuerUsable()` 与 `parseValidity()`；最终 `buildCertBuilder()`。

当前检查了 issuer 当前时刻有效，但没有在签发前强制：

```text
child.notBefore >= issuer.notBefore
child.notAfter  <= issuer.notAfter
```

所以理论上仍可以签出有效期超出 issuer 的下级证书。

### P1-07：实验型 PKI 的“证书链验签”与“PKIX 信任验证”仍未统一

这是上述 P1 的架构汇总问题，而不是另一个重复缺陷：当前至少存在 CertVerify、SignTool、GMcheck 三套不同程度的链逻辑。

CertVerify：有实验 TrustAnchor，但约束不完整；SignTool：自签即可结束；GMcheck：主要做 DN/AKI/SKI 链拼接 + 密码学验签。

建议最终建立一个统一 validator，三个 UI/工具都调用它。

## 4. P2 问题

### P2-01：CertsDB / Auto 的 CERTS.txt 重写不是原子事务

`CertsDB.rewriteAll()` 使用 `TRUNCATE_EXISTING` 后整文件写入；`Auto.revokeCert()` / `restoreCert()` 也整文件覆盖。进程在写入过程中异常退出可能得到半文件。

建议：`.tmp → flush/fsync → atomic move`，并保留 `.bak`。

### P2-02：CERTS.txt 的并发保护只覆盖 WebAdmin，不覆盖多个 JVM/CLI

WebAdmin 使用 `WRITE_LOCK`，这是当前已有的修复；但 `CertsDB` 本身没有 `FileChannel.lock()`。CLI、多 JVM、脚本并行执行时仍可能竞争。

### P2-03：WebAdmin JSON 请求体没有和 multipart 一样的明确大小上限

`runAction()` 调用 `readAll(ex.getRequestBody())`，没有长度上限；multipart 已经有 512MB 限制。恶意 chunked POST 可以持续占用 worker 内存。

建议管理 API JSON 限制在例如 1-4MB。

### P2-04：multipart 仍然一次性缓冲，512MB 对管理面仍偏大

当前已有 512MB 上限，说明上一轮已经修复了“无限读请求体”。但它仍是一次性内存缓冲；8 个 worker 在极端情况下会形成较大的内存压力。

### P2-05：Admin.captureStdout() 通过 System.setOut 做全局替换

WebAdmin 的写 API 有 `WRITE_LOCK`，但 `/api/verify/cert` 等读取/验证动作并不在这个锁里；多个请求同时 captureStdout 时会互相影响。

建议改成返回值/日志缓冲，不修改全局 stdout。

### P2-06：MakeRoot / MakeCert 序列号检查存在 TOCTOU

`existingSerials()` 读取台账后再随机生成 serial，然后后续写入。单 JVM WebAdmin 已通过 WRITE_LOCK 大幅降低风险，但独立进程并发仍存在极低概率的检查-写入竞争。

### P2-07：MakeCert.parseValidity() 输入校验偏宽松

`SimpleDateFormat` 默认 lenient；无效日期可能被自动修正。短字符串解析失败也可能静默回退 1 年。实验工具可接受，但管理 UI 更适合严格拒绝非法时间。

### P2-08：MakeCert 的 DN 输入用 Map 合并同名属性

`buildSubject()` 先把 DN 放进 `Map<String,String>`，同一个 key 重复出现时后者覆盖前者，因此无法通过普通 MakeCert DN 参数表达真正的多值同 OID RDN。X509JsonConverter 自身已经能够保留多值 RDN，所以这是签发入口能力缺口。

### P2-09：MakeCert 的 CA 模式可以生成“BasicConstraints=CA，但 KeyUsage 没有 keyCertSign”的自相矛盾证书

当前 `isCa` 与 `keyUsage` 参数相对独立。可以产生 CA=true 但 KU 不含 keyCertSign 的证书；随后本项目自己的 issuer 检查又会拒绝它继续签发。建议在签发阶段直接拒绝这种组合。

### P2-10：CtLog 本地私钥仍明文 Base64(PKCS#8) 存储

**定位：** `CtLog.LogKey.privateKey`、`saveKeys()`、`generateKey()`。

这不是“算法错误”，而是密钥保护问题。实验型 CT Log 可以接受，但必须明确它是实验密钥存储，不应作为生产 HSM 替代。

### P2-11：CT 请求日志无限增长

`ctlogs.txt` 追加写入，没有轮转/大小上限。长期运行会无限增长。

### P2-12：CT 公网 log_list 解析使用正则而不是 JSON parser

`CtLog.loadPublicList()` / `loadCtLogKeys()` 都以正则和对象片段定位字段；对当前 Google log_list v3 常见格式可工作，但不是通用 JSON 解析。格式发生变化时容易静默漏数据。

### P2-13：RootGetCrl 的 num.txt 更新不是原子写

`nextCrlNumber()` 使用整文件 `Files.write()`；断电/进程崩溃可能破坏 CRL 序号文件。

### P2-14：CERTS.txt 解析错误被静默丢弃
`CertsDB.load()` 对坏行直接 `catch (Exception ignore)`；I/O 失败也直接 return。对于实验台账，这会让“文件损坏”表现成“证书不存在”。建议至少记录警告并暴露加载状态。

## 5. 已确认“不是当前缺陷”的项目

- MakeCert 当前已经检查 issuer 有效期、BasicConstraints、keyCertSign 和 CERTS.txt 吊销状态；旧版“吊销 CA 仍能签发”不能再算当前缺陷。
- WebAdmin 当前签名 API 已检查签名证书有效期和 CERTS.txt 吊销状态。
- MAIN 当前请求体已有 8MB 上限；上一份报告若将 OCSP/CT 请求描述为无限内存读取，应删除该结论。
- multipart 当前已有 512MB 上限；因此不是“完全没有上传限制”。
- CRL 验证当前已经增加 issuer DN、CRL signature、thisUpdate、nextUpdate 检查。
- OCSP 当前已经增加 issuerNameHash/issuerKeyHash 对应性检查。
- X509JsonConverter 当前 166 个测试全部通过，真实 PKI 证书 57 张测试样本 DER byte-exact。
- ML-DSA-44/65/87、RSA-PSS、SHA3、DSA、Ed25519、SM2 等当前回归测试均通过。

## 6. Java 逐文件 / 逐函数审计清单

下面清单列出本次实际扫描到的全部 Java 文件及函数。没有列入 P1/P2 的函数，本次未发现足以形成当前缺陷的确定性问题；不是“没有阅读”。

### `src/modpkica/Admin.java` — 414 行，21 个函数/方法
**结论：** 功能入口通过；captureStdout 的并发问题归入 P2-05。

函数清单：

`main()`（L42）; `printHelp()`（L114）; `cmdInit()`（L135）; `cmdMakeRoot()`（L147）; `cmdSignCert()`（L160）; `cmdRevoke()`（L189）; `cmdInitOcsp()`（L201）; `cmdInitTimestamp()`（L208）; `cmdVerifyCert()`（L214）; `captureStdout()`（L225）; `doInit()`（L243）; `doMakeRoot()`（L258）; `doMakeRoot()`（L264）; `doList()`（L275）; `doRevoke()`（L305）; `doRestore()`（L319）; `doSignCrl()`（L329）; `doInitOcsp()`（L340）; `doInitTimestamp()`（L364）; `makeTsa()`（L400）; `doVerifyCert()`（L411）

### `src/modpkica/AppEnv.java` — 46 行，1 个函数/方法
**结论：** 通过。

函数清单：

`getExeNames()`（L35）

### `src/modpkica/AppPaths.java` — 51 行，1 个函数/方法
**结论：** 通过；支持显式 MODPKICA_BASE。

函数清单：

`baseDir()`（L22）

### `src/modpkica/Auto.java` — 203 行，8 个函数/方法
**结论：** 存在 P2-01；init/revoke/restore 属于明确的破坏性/重写操作。

函数清单：

`main()`（L40）; `nowMinus3Days()`（L65）; `runInit()`（L70）; `revoke()`（L75）; `restore()`（L80）; `initEnv()`（L85）; `revokeCert()`（L128）; `restoreCert()`（L161）

### `src/modpkica/Bc.java` — 26 行，1 个函数/方法
**结论：** 通过。

函数清单：

`init()`（L20）

### `src/modpkica/CertUtil.java` — 634 行，16 个函数/方法
**结论：** 核心密码学/证书构造本次未发现确定性缺陷；测试覆盖较强。

函数清单：

`generateRsaKeyPair()`（L101）; `generateEccKeyPair()`（L110）; `generateSm2KeyPair()`（L133）; `generateDsaKeyPair()`（L141）; `generateEd25519KeyPair()`（L156）; `generatePqcKeyPair()`（L166）; `normalizePqcSpec()`（L174）; `getSignatureAlgOid()`（L201）; `normalizeHash()`（L323）; `readJcaPrivateKey()`（L368）; `createContentSigner()`（L383）; `getAlgorithmIdentifier()`（L447）; `getOutputStream()`（L452）; `getSignature()`（L457）; `getSubjectKeyIdentifier()`（L479）; `buildCpsPolicy()`（L610）

### `src/modpkica/CertVerify.java` — 1758 行，55 个函数/方法
**结论：** 存在上述 P1-02、P1-03、P1-05；CRL/OCSP 对应性相关新增修复已复核。

函数清单：

`main()`（L75）; `run()`（L94）; `parseCert()`（L113）; `run()`（L118）; `sigAlgDisplay()`（L229）; `getHashType()`（L237）; `getHashType()`（L245）; `describePublicKey()`（L265）; `printExtKeyUsage()`（L284）; `ekuName()`（L295）; `printSan()`（L353）; `printAiaAndCrl()`（L371）; `printPolicies()`（L406）; `policyName()`（L421）; `printExtensions()`（L444）; `printSctList()`（L499）; `sigName()`（L601）; `verifySignature()`（L639）; `fetchIssuerSilent()`（L677）; `fetchIssuer()`（L694）; `printChain()`（L727）; `findLocalIssuer()`（L771）; `findLocalIssuerInCacerts()`（L813）; `isInTrustAnchor()`（L855）; `inJavaCacerts()`（L889）; `isSelfSigned()`（L924）; `subjectKeyIdHex()`（L930）; `aiaCaIssuers()`（L939）; `checkCrl()`（L961）; `checkOcsp()`（L1014）; `crlUrls()`（L1186）; `ocspUrls()`（L1209）; `printHashes()`（L1231）; `rfcSha1()`（L1253）; `copyRightAligned()`（L1278）; `httpGet()`（L1300）; `readAll()`（L1321）; `unwrapOctets()`（L1336）; `subjectKeyIdValue()`（L1347）; `authorityKeyIdValue()`（L1356）; `chunks()`（L1368）; `indexOf()`（L1382）; `hex()`（L1398）; `sha256()`（L1406）; `bitsToString()`（L1410）; `parseSctListData()`（L1446）; `tbsWithoutSctExt()`（L1563）; `verifySctSignature()`（L1594）; `tlsHashName()`（L1630）; `ecdsaRawToDer()`（L1646）; `loadCtLogKeys()`（L1663）; `writeU16()`（L1714）; `writeU24()`（L1719）; `writeU64()`（L1725）; `pssHashName()`（L1734）

### `src/modpkica/CertsDB.java` — 273 行，13 个函数/方法
**结论：** 存在 P2-01、P2-02、P2-14。

函数清单：

`load()`（L68）; `reload()`（L107）; `findBySerial()`（L120）; `findByIssuerAndSerial()`（L139）; `findIssuerIdBySerial()`（L158）; `addEntry()`（L171）; `revokeCert()`（L193）; `getAllRootAndCA()`（L207）; `getAllRevoked()`（L220）; `getAll()`（L231）; `rewriteAll()`（L236）; `formatLine()`（L252）; `stripCrLf()`（L261）

### `src/modpkica/Config.java` — 181 行，10 个函数/方法
**结论：** 通过；主要是简单配置解析器。

函数清单：

`load()`（L57）; `getCpsWithCid()`（L129）; `stripCrLf()`（L139）; `getCrlUrl()`（L154）; `getCrtUrl()`（L158）; `getOcspUrl()`（L162）; `getCps()`（L166）; `getCpsNonice()`（L170）; `getWebPort()`（L174）; `getRaw()`（L178）

### `src/modpkica/CrlUtil.java` — 132 行，1 个函数/方法
**结论：** 通过；CRLNumber、AKI、revocation reason 当前测试通过。

函数清单：

`derToPem()`（L124）

### `src/modpkica/CtLog.java` — 770 行，29 个函数/方法
**结论：** 存在 P2-10、P2-11、P2-12。

函数清单：

`keysJsonPath()`（L70）; `logsTxtPath()`（L75）; `publicListPath()`（L80）; `loadPublicList()`（L99）; `publicListTimestamp()`（L173）; `fetchPublicList()`（L188）; `loadKeys()`（L240）; `grab()`（L280）; `saveKeys()`（L287）; `esc()`（L318）; `generateKey()`（L330）; `deleteKey()`（L373）; `setState()`（L389）; `pickLogKeys()`（L420）; `isSm2Precert()`（L440）; `buildSctInput()`（L502）; `signInput()`（L516）; `buildSerializedSct()`（L532）; `appendRequestLog()`（L615）; `readLogs()`（L629）; `parsePemCerts()`（L652）; `pemCert()`（L680）; `tbsWithoutPoison()`（L692）; `extHex()`（L727）; `sha256()`（L741）; `toHex()`（L746）; `writeU16()`（L754）; `writeU24()`（L759）; `writeU64()`（L765）

### `src/modpkica/MAIN.java` — 853 行，24 个函数/方法
**结论：** MAIN 请求体已有 8MB 限制；OCSP issuer hash 校验已复核。仍受 P1-05（验证端 delegated responder 授权）和 P2-02/P2-10 等外围问题影响。

函数清单：

`main()`（L63）; `handleOcsp()`（L125）; `isKnownHash()`（L266）; `ocspHashName()`（L279）; `handleFile()`（L314）; `handleTimestampSha1()`（L371）; `handleTimestampSha256()`（L375）; `handleAuthenticode()`（L385）; `head()`（L452）; `jcaHashName()`（L465）; `extractAuthenticodeContent()`（L494）; `handleRfc3161()`（L515）; `handleCtAdd()`（L642）; `pickTSACert()`（L732）; `fileExists()`（L756）; `findExisting()`（L761）; `readAll()`（L774）; `sendBytes()`（L790）; `sendText()`（L801）; `writeFile()`（L810）; `sha1Hex()`（L820）; `toHex()`（L826）; `lastIndexOf()`（L835）; `log()`（L849）

### `src/modpkica/MLog.java` — 103 行，4 个函数/方法
**结论：** 通过；日志写入同步化且换行已转义。

函数清单：

`append()`（L43）; `append()`（L55）; `appendErr()`（L67）; `sanitize()`（L97）

### `src/modpkica/MakeCert.java` — 1138 行，33 个函数/方法
**结论：** 存在上述 P1-01、P1-06、P2-07、P2-08、P2-09；其余函数本次未发现确定性缺陷。

函数清单：

`setQuiet()`（L131）; `out()`（L139）; `main()`（L150）; `run()`（L161）; `run()`（L170）; `resolveIssuer()`（L423）; `checkIssuerUsable()`（L436）; `defaultBit()`（L459）; `parseBit()`（L469）; `generateKeyPair()`（L513）; `buildSubject()`（L564）; `dnOrder()`（L592）; `addDnField()`（L613）; `isStandardDnKey()`（L637）; `copySubject()`（L647）; `oidOf()`（L669）; `addIfPresent()`（L689）; `extractCn()`（L695）; `parseValidity()`（L706）; `buildSerial()`（L727）; `goKeyUsageToBc()`（L769）; `parseKeyUsage()`（L783）; `builtinEku()`（L811）; `extOid()`（L829）; `isValidOid()`（L839）; `addCrlDistributionPoints()`（L884）; `addSan()`（L900）; `removeCertsLine()`（L1076）; `concat()`（L1100）; `slice()`（L1107）; `longTo8Bytes()`（L1113）; `contains()`（L1122）; `hexToBytes()`（L1131）

### `src/modpkica/MakeRoot.java` — 569 行，11 个函数/方法
**结论：** 核心流程通过；存在 P2-06 的序列号 TOCTOU，BasicConstraints 无 pathLen 是明确设计选择。

函数清单：

`buildSerial()`（L70）; `main()`（L107）; `run()`（L118）; `parseKeyBits()`（L250）; `buildSubject()`（L303）; `dnOrder()`（L333）; `addDnField()`（L354）; `isStandardDnKey()`（L378）; `addIfPresent()`（L388）; `addCrlDistributionPoints()`（L417）; `getDnField()`（L447）

### `src/modpkica/OcspUtil.java` — 374 行，3 个函数/方法
**结论：** 通过；请求/响应 ASN.1 与 issuer hash 计算当前测试/源码复核正常。

函数清单：

`parseRequest()`（L101）; `hashDigestName()`（L339）; `unauthorizedResponse()`（L371）

### `src/modpkica/PemIO.java` — 318 行，11 个函数/方法
**结论：** 通过；RSA/EC/SM2/PQC 私钥读取路径已复核。

函数清单：

`readCert()`（L68）; `readPrivateKey()`（L90）; `readPrivateKeyAsSigner()`（L134）; `writeCert()`（L146）; `writePrivateKey()`（L160）; `detectKeyType()`（L213）; `isPqcOid()`（L256）; `isPqcAlgName()`（L274）; `lookupCurveBitLength()`（L287）; `readPemObject()`（L299）; `writePemObject()`（L307）

### `src/modpkica/RootGetCrl.java` — 318 行，7 个函数/方法
**结论：** 存在 P2-13；CRL issuer 隔离和 CRLNumber 单调递增逻辑已复核。

函数清单：

`main()`（L43）; `run()`（L48）; `run()`（L53）; `revokedCount()`（L126）; `parseModTime()`（L194）; `certHashFromSigAlg()`（L199）; `pssHashFromSigParams()`（L294）

### `src/modpkica/SignTool.java` — 2804 行，54 个函数/方法
**结论：** 存在上述 P1-04；签名内容摘要、CMS/PDF/时间戳主流程本次未发现确定性缺陷。

函数清单：

`isCodeSignCert()`（L187）; `isDocSignCert()`（L201）; `ekusOf()`（L211）; `keyBits()`（L224）; `loadCertBySerial()`（L241）; `loadKeyBySerial()`（L250）; `loadChain()`（L287）; `certFilePath()`（L313）; `digestName()`（L336）; `digestJca()`（L341）; `digestOid()`（L346）; `sigAlgOid()`（L351）; `jcaSigAlg()`（L362）; `digestJcaFromOid()`（L373）; `jcaSigFromOid()`（L393）; `buildSpcIndirectData()`（L514）; `extractFirstSignerInfo()`（L743）; `serialOf()`（L784）; `requestTimestamp()`（L796）; `stripSequenceHeader()`（L914）; `verifyExe()`（L938）; `signPdfTimestampOnly()`（L1171）; `addDocTimeStamp()`（L1183）; `extractTsaChain()`（L1231）; `serialHex()`（L1267）; `buildAdobeSignature()`（L1317）; `sign()`（L1474）; `sm2Sign()`（L1745）; `getContentType()`（L1784）; `write()`（L1789）; `getContent()`（L1794）; `applyLtvPdf()`（L1846）; `collectLtvData()`（L1885）; `installDss()`（L1940）; `newLtvStream()`（L1997）; `fetchIssuerCrl()`（L2034）; `configValue()`（L2065）; `configValue()`（L2069）; `httpPost()`（L2089）; `httpGet()`（L2120）; `isDer()`（L2145）; `toDerCrl()`（L2155）; `verifyPdf()`（L2177）; `verifyDocTimeStamp()`（L2361）; `shortDn()`（L2711）; `printable()`（L2718）; `asn1ObjectTotalLength()`（L2723）; `readU16()`（L2737）; `readU32()`（L2741）; `writeU32()`（L2746）; `writeU32()`（L2753）; `writeU16()`（L2760）; `readAllBytes()`（L2765）; `boundToSignature()`（L2776）

### `src/modpkica/Sm2Util.java` — 242 行，11 个函数/方法
**结论：** 通过；SM3/ZA/SM2 sign/verify 实现已复核。

函数清单：

`getSm2UidBytes()`（L70）; `sm3()`（L81）; `computeZa()`（L96）; `addFieldElement()`（L121）; `sm2Sign()`（L133）; `sm2Verify()`（L156）; `generateSm2JcaKeyPair()`（L186）; `toEcPublicParams()`（L195）; `toEcPrivateParams()`（L209）; `hex()`（L221）; `main()`（L232）

### `src/modpkica/TimestampUtil.java` — 264 行，5 个函数/方法
**结论：** 通过；RFC3161 构造主流程本次未发现确定性缺陷。

函数清单：

`parseRfc3161Request()`（L78）; `getAlgorithmIdentifier()`（L169）; `getOutputStream()`（L174）; `getDigest()`（L179）; `isEcc()`（L260）

### `src/modpkica/WebAdmin.java` — 7579 行，97 个函数/方法
**结论：** 存在 P2-03、P2-04、P2-05；默认绑定 127.0.0.1 的设计已复核。非回环绑定无认证属于已知条件风险。

函数清单：

`main()`（L128）; `ensureSuportConfig()`（L141）; `readConfigAdminPort()`（L181）; `probeMain()`（L212）; `probeMainIfStale()`（L231）; `canConnect()`（L241）; `port()`（L251）; `start()`（L260）; `route()`（L301）; `handleApi()`（L336）; `dispatchApi()`（L351）; `runAction()`（L565）; `hashOidOf()`（L610）; `jcaHashOf()`（L638）; `hashLabel()`（L665）; `hexOf()`（L670）; `postMain()`（L682）; `debugOcsp()`（L723）; `debugTsa()`（L875）; `ocspStatusName()`（L984）; `tsStatusName()`（L996）; `rekeyAction()`（L1017）; `renewAction()`（L1089）; `parseLocalDateTime()`（L1157）; `signAndVerify()`（L1214）; `certSerialOf()`（L1310）; `relPath()`（L1316）; `statusJson()`（L1327）; `certsJson()`（L1345）; `myRecordPath()`（L1376）; `myListJson()`（L1381）; `myHasSerial()`（L1411）; `verifyTarget()`（L1435）; `mySerialOf()`（L1446）; `myAlgoOf()`（L1455）; `myTypeOf()`（L1477）; `fmtMyTime()`（L1486）; `myKeyMatches()`（L1495）; `toJcaPrivateKey()`（L1538）; `myImportAction()`（L1560）; `myImportBytes()`（L1589）; `importKeyStore()`（L1720）; `persistMyCert()`（L1759）; `myAppendRecord()`（L1791）; `myDelete()`（L1807）; `myRemoveRecord()`（L1829）; `cacertsJson()`（L1851）; `fmtCacertsTime()`（L1866）; `certSerialHex()`（L1908）; `certAlgoDesc()`（L1917）; `findCacertsCertBySerial()`（L1937）; `issuersJson()`（L1953）; `logsJson()`（L1976）; `configJson()`（L2006）; `saveConfig()`（L2065）; `entryMillis()`（L2156）; `chainJson()`（L2182）; `buildChainNode()`（L2234）; `findCertFile()`（L2280）; `scanSerialInDir()`（L2304）; `hashFromCert()`（L2322）; `keyBits()`（L2400）; `certKind()`（L2424）; `policyOidSet()`（L2458）; `certJson()`（L2483）; `certChainJson()`（L2516）; `certDownload()`（L2559）; `certExport()`（L2643）; `qp()`（L2711）; `findIssuerByDn()`（L2788）; `findKeyFile()`（L2839）; `p7bBytes()`（L2859）; `pemToDer()`（L2928）; `readConfigWebPort()`（L2965）; `countLogLines()`（L2987）; `tailFile()`（L3019）; `normalizeTail()`（L3066）; `readAll()`（L3078）; `readMultipart()`（L3093）; `indexOfBytes()`（L3191）; `signAction()`（L3205）; `verifyAction()`（L3341）; `verifyCertFileAction()`（L3364）; `signCertsJson()`（L3397）; `jsonEscape()`（L3483）; `ctlogListJson()`（L3513）; `ctlogLogsJson()`（L3524）; `ctlogPublicJson()`（L3529）; `ctlogPublicFetch()`（L3549）; `ctlogGen()`（L3554）; `ctlogDelete()`（L3562）; `ctlogSetState()`（L3570）; `sendJson()`（L3580）; `appendJsonValue()`（L3598）; `sendText()`（L3634）; `parseJsonObject()`（L3651）; `str()`（L3729）

### `src/modpkica/X509JsonConverter.java` — 2233 行，97 个函数/方法
**结论：** 本次重点复核；当前无确定性 roundtrip 缺陷。注意 tbsRaw 是有意设计的终极保真 fallback。

函数清单：

`main()`（L56）; `isHelpArg()`（L166）; `printUsage()`（L170）; `pemToDer()`（L243）; `derToPem()`（L251）; `toHexEven()`（L260）; `certToJson()`（L384）; `algIdToJson()`（L439）; `tryStructuredParams()`（L466）; `buildParamsFromStruct()`（L491）; `dnToJson()`（L510）; `encodingName()`（L529）; `validityToJson()`（L542）; `timeToJson()`（L549）; `spkiToJson()`（L572）; `extensionToJson()`（L579）; `isKnownExtension()`（L609）; `parseExtensionValue()`（L624）; `parseSKI()`（L655）; `parseAKI()`（L661）; `parseGeneralNamesExt()`（L675）; `gnToJson()`（L684）; `parseKeyUsage()`（L705）; `parseEKU()`（L726）; `parseBasicConstraints()`（L741）; `parseCRLDP()`（L750）; `parseCertPolicies()`（L780）; `parseUserNotice()`（L811）; `displayTextTypeName()`（L833）; `parseAIA()`（L841）; `parseNameConstraints()`（L857）; `parseSubtrees()`（L865）; `parsePolicyConstraints()`（L877）; `parsePolicyMappings()`（L887）; `parseSubjectDirAttrs()`（L902）; `isStringEncoding()`（L931）; `parsePrivKeyUsagePeriod()`（L937）; `parseIssuingDP()`（L947）; `parseNetscapeCertType()`（L970）; `parseSCTList()`（L999）; `parseSCT()`（L1015）; `readUint16()`（L1050）; `writeUint16()`（L1054）; `jsonToCertPem()`（L1062）; `buildTBSCertificate()`（L1092）; `rekeyJsonToPem()`（L1155）; `rekeyJsonToPem()`（L1168）; `updateValidityTime()`（L1249）; `generateKeyPairFromJson()`（L1305）; `keyTypeFromJson()`（L1320）; `curveOidFromParams()`（L1341）; `doRekey()`（L1358）; `hexToKeyPair()`（L1399）; `keyAlgOidToJcaName()`（L1415）; `generateKeyPair()`（L1429）; `sigAlgOidToJcaName()`（L1494）; `buildAlgId()`（L1536）; `buildDN()`（L1558）; `buildStringValue()`（L1585）; `buildTime()`（L1600）; `buildSPKI()`（L1615）; `buildExtensions()`（L1621）; `buildExtensionValue()`（L1634）; `buildSKI()`（L1664）; `buildAKI()`（L1668）; `buildGeneralNames()`（L1682）; `buildGN()`（L1689）; `buildKeyUsage()`（L1716）; `decodeKeyUsageBits()`（L1758）; `buildEKU()`（L1768）; `buildBasicConstraints()`（L1776）; `buildCRLDP()`（L1783）; `buildCertPolicies()`（L1815）; `buildUserNotice()`（L1848）; `displayTextTypeId()`（L1875）; `buildAIA()`（L1883）; `buildNameConstraints()`（L1895）; `buildSubtrees()`（L1903）; `buildPolicyConstraints()`（L1915）; `buildPolicyMappings()`（L1923）; `buildSubjectDirAttrs()`（L1935）; `buildPrivKeyUsagePeriod()`（L1959）; `buildIssuingDP()`（L1972）; `boolVal()`（L1996）; `reasonFlagsToJson()`（L2009）; `reasonNamesToMask()`（L2019）; `buildNetscapeCertType()`（L2027）; `buildSCTList()`（L2041）; `buildSCTRaw()`（L2056）; `toJson()`（L2079）; `writeJson()`（L2087）; `jsonQuote()`（L2123）; `value()`（L2150）; `object()`（L2161）; `array()`（L2177）; `string()`（L2190）; `number()`（L2218）

## 7. Python GMcheck 逐文件 / 逐函数审计清单

### `GMcheck/chain_deep_verify.py` — 410 行，12 个函数
**结论：** 主要实现离线证书链逐级验签、CRL/OCSP 解析；它是“材料链验签器”，没有实现完整 PKIX validity/pathLen/policy/trust-anchor 语义，不能把其结果等同于完整 PKIX。

函数清单：

`cert_signature()`（L35）; `cert_sig_alg_oid()`（L43）; `verify_cert_signed_by()`（L52）; `collect_from_cms()`（L84）; `collect_from_ses()`（L112）; `collect_dss()`（L144）; `build_chains()`（L178）; `find_parent()`（L183）; `parse_crl()`（L220）; `verify_crl()`（L248）; `parse_ocsp()`（L273）; `verify_file()`（L326）

### `GMcheck/derlib.py` — 469 行，21 个函数
**结论：** DER/X.509/CMS 解析核心；本次未发现确定性编码解析错误。

函数清单：

`__init__()`（L13）; `children()`（L22）; `__repr__()`（L28）; `parse_tlv()`（L32）; `parse_sequence()`（L64）; `tlv_int()`（L74）; `tlv_oid()`（L84）; `tlv_utc()`（L100）; `find_child()`（L108）; `__init__()`（L117）; `parse()`（L135）; `key_len()`（L253）; `_normalize_cert()`（L261）; `_oid_of()`（L299）; `_algo_name()`（L330）; `_dn()`（L334）; `_ATTR_NAME()`（L365）; `__init__()`（L373）; `parse()`（L380）; `_parse_signer_info()`（L419）; `sig_attr()`（L461）

### `GMcheck/gen_pdf.py` — 629 行，5 个函数
**结论：** 报告/PDF 生成辅助代码，不作为 PKI 信任核心；本次未发现确定性问题。

函数清单：

`P()`（L43）; `code()`（L47）; `table()`（L51）; `cls()`（L161）; `footer()`（L619）

### `GMcheck/gen_report_pdf.py` — 252 行，4 个函数
**结论：** 报告/PDF 生成辅助代码，不作为 PKI 信任核心；本次未发现确定性问题。

函数清单：

`P()`（L39）; `code()`（L42）; `table()`（L45）; `footer()`（L243）

### `GMcheck/pdfsig_verify.py` — 678 行，21 个函数
**结论：** PDF/CMS/SES/时间戳解析验证；本次未发现确定性问题。其链验证仍应与统一 PKIX 模型区分。

函数清单：

`digest_of()`（L41）; `alg_family()`（L56）; `__init__()`（L68）; `add()`（L71）; `summary()`（L74）; `find_sig_xrefs()`（L83）; `get_contents_bytes()`（L95）; `get_byte_range()`（L109）; `doc_bytes_in_range()`（L118）; `rsa_pkcs1_v15_verify()`（L131）; `der_ecdsa_to_rs()`（L158）; `verify_signature()`（L174）; `find_cert()`（L208）; `parse_tsa_token()`（L225）; `verify_pdf()`（L281）; `der_len()`（L366）; `_verify_cms()`（L374）; `_verify_ses()`（L474）; `_collect_certs()`（L520）; `_try_sm2_certs()`（L616）; `_cms_signed_attrs_der()`（L636）

### `GMcheck/sm2lib.py` — 171 行，10 个函数
**结论：** SM3/SM2 核心实现；含公钥曲线点检查，源码结构完整。

函数清单：

`_rotl()`（L13）; `_p0()`（L18）; `_p1()`（L22）; `sm3()`（L26）; `_inv()`（L84）; `_add()`（L88）; `_mul()`（L107）; `_bytes_to_int()`（L119）; `sm2_za()`（L123）; `sm2_verify()`（L132）

### `GMcheck/verify_gm_pdf.py` — 571 行，17 个函数
**结论：** 国密 PDF 结构、SM2、DSS 等验证；本次未发现确定性问题。

函数清单：

`__init__()`（L49）; `open_pdf()`（L62）; `find_signature_dicts()`（L73）; `verify_byterange()`（L111）; `extract_contents()`（L149）; `parse_cms()`（L171）; `check_gm_algorithm()`（L187）; `recompute_digest()`（L238）; `extract_signature_value()`（L259）; `extract_signer_cert()`（L282）; `verify_sm2_signature()`（L336）; `summary()`（L382）; `add_result()`（L421）; `check_dss()`（L435）; `verify()`（L486）; `print_report()`（L536）; `main()`（L559）

## 8. 当前代码质量与测试判断

当前 126 版本与旧版相比，最重要的变化不是“功能更多”，而是很多上一轮指出的问题已经真正进入代码修复：

1. issuer 吊销/有效期/CA 属性检查已经存在；
2. WebAdmin 签名证书状态检查已经存在；
3. MAIN OCSP 请求体有 8MB 上限；
4. OCSP issuer hash 对应性已经实现；
5. CRL 签名和时间窗口已经验证；
6. X509JsonConverter 的无损机制已经达到当前测试要求；
7. RSA-PSS / PQC / SHA3 / SM2 / DSA / Ed25519 的回归测试已经覆盖。

因此，本次没有把旧报告中的这些内容继续算成缺陷。

## 9. 建议下一次整改顺序

第一优先级：

```text
统一 PKIX Validator
    ├─ validity
    ├─ issuer DN / AKI / SKI
    ├─ BasicConstraints
    ├─ KeyUsage
    ├─ pathLenConstraint
    ├─ TrustAnchor
    └─ revocation
             ↓
CertVerify / SignTool / GMcheck 全部复用
```

第二优先级：

```text
MakeCert issuer 台账绑定
child validity <= issuer validity
OCSP delegated responder 授权链
```

第三优先级：

```text
CERTS.txt atomic transaction
FileChannel.lock
WebAdmin JSON body limit
captureStdout 去全局 System.out
CT key protection / log rotation
```

## 10. 最终结论

当前源码不能再沿用上一份报告的旧缺陷清单。重新从 ZIP 实际代码审查后，真正需要关注的是上述 7 个 P1 和 14 个 P2，其中若只从“实验型 PKI 是否能工作”角度看，很多 P2 并不阻止项目正常运行；P1 主要集中在“验证器是否真正表达 PKIX 信任语义”和“issuer/responder 身份是否与台账/授权关系绑定”。

当前测试结果 **166/166 PASS**，说明大量此前修复确实已经落地。尤其 X.509 JSON、PQC、RSA-PSS、CRL、OCSP issuer hash、WebAdmin 状态检查等，不应再按旧版本问题报告。

**本报告没有引用 README.md、任何 PDF、OldPDF 历史审计报告或历史说明作为缺陷依据。**