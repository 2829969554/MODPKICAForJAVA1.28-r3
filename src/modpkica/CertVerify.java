package modpkica;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * CERTVERIFY —— 证书验证工具（对应 Go 版 cmd/certverify）。
 *
 * <p>用法：{@code CERTVERIFY 证书文件或序列号}。参数不含点号时自动从
 * PKI/WebPublic/CRT/序列号.crt 读取；否则按给定路径读取。
 *
 * <p>功能：
 * <ul>
 *   <li>解析并打印证书关键信息（版本、序列号、签名算法、颁发者/使用者、有效期、公钥、
 *       SKI/AKI、EKU、SAN、AIA、CRL 分发点、密钥用法、基本约束、证书策略、扩展、签名）；</li>
 *   <li>签名验证：根证书自验；非根证书从 AIA 的 caIssuers URL 拉取颁发者证书后验证；
 *       打印证书链与信任状态；</li>
 *   <li>吊销状态：CRL（从 CRL 分发点拉取）+ OCSP（构造请求并 POST 到 OCSP URL）；</li>
 *   <li>打印密钥/证书的各种哈希（RFC-SHA1、Pin-SHA256、SHA1、SHA256、签名哈希）；</li>
 *   <li>SCT / CT 透明度扩展展示（含 MODPKICA 3 组 SCT 的签名验证）。</li>
 * </ul>
 */
public final class CertVerify {

    private CertVerify() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println(" 验证证书签名、证书状态、证书有效性\n 例如 CERTVERIFY cert.crt");
            return;
        }
        String filename = args[0];
        if (!filename.contains(".")) {
            // 无扩展名：按序列号从 WebPublic/CRT 读取（文件名统一小写，容忍用户输入大写）
            filename = AppPaths.baseDir() + "/PKI/WebPublic/CRT/" + filename.toLowerCase() + ".crt";
        }
        Path p = Paths.get(filename);
        if (!Files.exists(p)) {
            System.out.println("文件 " + filename + " 不存在");
            return;
        }
        run(p);
    }

    /** 供 ADMIN verifyCERT / WebAdmin /api/verify 内部调用。 */
    public static void run(String filename) throws Exception {
        if (filename == null || filename.isEmpty()) {
            System.out.println("目标为空，请输入证书文件路径或序列号");
            return;
        }
        if (!filename.contains(".")) {
            // 无扩展名：按序列号从 WebPublic/CRT 读取（文件名统一小写，容忍用户输入大写）
            String serial = filename.toLowerCase();
            filename = AppPaths.baseDir() + "/PKI/WebPublic/CRT/" + serial + ".crt";
        }
        Path p = Paths.get(filename);
        if (!Files.exists(p)) {
            System.out.println("文件 " + filename + " 不存在（如输入的是序列号，请确认 WebPublic/CRT/序列号.crt 存在）");
            return;
        }
        run(p);
    }

    /** 解析证书字节：自动识别 PEM / DER。 */
    private static X509Certificate parseCert(byte[] data) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(data));
    }

    private static void run(Path p) throws Exception {
        Bc.init();
        byte[] certPem = Files.readAllBytes(p);
        X509Certificate cert = parseCert(certPem);

        // ---- 基本信息 ----
        System.out.println("        版本： " + (cert.getVersion()));
        String serialHex = cert.getSerialNumber().toString(16);
        if (serialHex.length() % 2 != 0) {
            serialHex = "0" + serialHex;
        }
        System.out.println("      序列号： " + serialHex);
        String[] ht = getHashType(cert.getSigAlgName());
        System.out.println("    签名算法： " + sigAlgDisplay(cert.getSigAlgName()) + " (" + cert.getSigAlgOID() + ")");
        System.out.println("签名哈希算法： " + ht[0] + "\n");
        System.out.println("颁发者： " + cert.getIssuerX500Principal());
        System.out.println("有效期从： " + cert.getNotBefore());
        System.out.println("有效期到： " + cert.getNotAfter() + "\n");
        System.out.println("使用者： " + cert.getSubjectX500Principal());

        // ---- 公钥 ----
        PublicKey pub = cert.getPublicKey();
        String keyInfo = describePublicKey(pub);
        System.out.println("    公钥： " + keyInfo);

        // ---- SKI/AKI（纯净值，剥离 ASN.1 包装，对齐 Go 版显示） ----
        byte[] ski = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        byte[] aki = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        System.out.println("授权密钥标识符  ： " + (aki == null ? "" : hex(authorityKeyIdValue(aki))));
        System.out.println("使用者密钥标识符： " + (ski == null ? "" : hex(subjectKeyIdValue(ski))) + "\n");

        // ---- EKU ----
        printExtKeyUsage(cert);

        // ---- SAN ----
        printSan(cert);

        // ---- AIA / CRL ----
        printAiaAndCrl(cert);

        // ---- KeyUsage / BasicConstraints ----
        System.out.println("密钥用法： " + cert.getKeyUsage() != null
                ? bitsToString(cert.getKeyUsage()) : "无");
        if (cert.getBasicConstraints() >= 0) {
            System.out.println("基本约束(关键)：\n              Subject Type="
                    + (cert.getBasicConstraints() > 0 ? "CA" : "End Entity")
                    + "  Path Length Constraint = " + cert.getBasicConstraints());
        }

        // ---- 证书策略 ----
        printPolicies(cert);

        // ---- 扩展（未知 OID 原样打印） ----
        printExtensions(cert);

        System.out.println("\n\n");
        System.out.println("证书签名：\n        " + hex(cert.getSignature()) + "\n");

        // ---- 签名验证与证书链 ----
        boolean isRoot = cert.getSubjectX500Principal().getName()
                .equals(cert.getIssuerX500Principal().getName());
        boolean signOk;
        if (isRoot) {
            System.out.println("证书类别： 根证书\n");
            signOk = verifySignature(cert, cert.getPublicKey());
            if (signOk) {
                System.out.println("验证签名： 成功（根证书自验证通过）");
            } else {
                System.out.println("验证签名： 失败");
            }
            System.out.println("信任状态： 可信 (此证书已通过信任锚[Root根证书]的验证)\n");
        } else {
            System.out.println("证书类别： 非根证书\n");
            System.out.println("证书链： ");
            X509Certificate issuer = fetchIssuer(cert);
            if (issuer == null) {
                System.out.println("验证签名： 无法验证签名 |无法找到上级证书链~ ");
            } else {
                signOk = verifySignature(cert, issuer.getPublicKey());
                System.out.println("验证签名： " + (signOk ? "通过、签名有效" : "失败")
                        + " 颁发者=" + issuer.getSubjectX500Principal());
            }
        }

        // ---- 吊销状态 ----
        System.out.print("证书状态：");
        Date now = new Date();
        if (now.before(cert.getNotBefore())) {
            System.out.println("该证书尚未生效。");
        } else {
            checkCrl(cert);
            checkOcsp(cert);
        }

        // ---- 各种哈希 ----
        printHashes(cert, pub);
    }

    // ============================================================
    // 信息打印
    // ============================================================

    /** JCA 签名算法名转 Go 风格显示（SHA256WITHRSA → SHA256-RSA、SHA256WITHECDSA → SHA256-ECDSA）。 */
    private static String sigAlgDisplay(String jcaName) {
        String s = jcaName == null ? "" : jcaName.replace("WITHRSA", "-RSA")
                .replace("WITHECDSA", "-ECDSA")
                .replace("WITH", "-")
                .replace("_", "");
        return s.isEmpty() ? (jcaName == null ? "" : jcaName) : s;
    }

    private static String[] getHashType(String sigAlgName) {
        String upper = sigAlgName == null ? "" : sigAlgName.toUpperCase();
        if (upper.contains("SM2") || upper.contains("SM3")) {
            return new String[]{"SM3", "SM2"};
        }
        if (upper.contains("SHA512")) {
            return new String[]{"SHA512", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        if (upper.contains("SHA384")) {
            return new String[]{"SHA384", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        if (upper.contains("SHA256")) {
            return new String[]{"SHA256", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        if (upper.contains("SHA1")) {
            return new String[]{"SHA1", upper.contains("ECDSA") ? "ECC" : "RSA"};
        }
        return new String[]{"", ""};
    }

    private static String describePublicKey(PublicKey pub) {
        String alg = pub.getAlgorithm();
        if ("RSA".equalsIgnoreCase(alg)) {
            java.security.interfaces.RSAPublicKey rsa =
                    (java.security.interfaces.RSAPublicKey) pub;
            return "RSA " + rsa.getModulus().bitLength();
        }
        if ("EC".equalsIgnoreCase(alg) || "SM2".equalsIgnoreCase(alg)) {
            java.security.interfaces.ECPublicKey ec =
                    (java.security.interfaces.ECPublicKey) pub;
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            if (bits == 256 && alg.startsWith("SM") || alg.equals("SM2")) {
                return "SM2 256";
            }
            return "ECC " + bits;
        }
        return alg;
    }

    private static void printExtKeyUsage(X509Certificate cert) throws Exception {
        System.out.println("增强型密钥用法：\n");
        List<String> oids = cert.getExtendedKeyUsage();
        if (oids == null) {
            return;
        }
        for (String oid : oids) {
            System.out.println("              " + ekuName(oid) + " (" + oid + ")");
        }
    }

    private static String ekuName(String oid) {
        switch (oid) {
            // ---- 标准 EKU（1.3.6.1.5.5.7.3.*） ----
            case "1.3.6.1.5.5.7.3.1": return "服务器身份验证";
            case "1.3.6.1.5.5.7.3.2": return "客户端身份验证";
            case "1.3.6.1.5.5.7.3.3": return "代码签名";
            case "1.3.6.1.5.5.7.3.4": return "安全电子邮件";
            case "1.3.6.1.5.5.7.3.5": return "IP 安全终端系统";
            case "1.3.6.1.5.5.7.3.6": return "IP 安全隧道终止";
            case "1.3.6.1.5.5.7.3.7": return "IP 安全用户";
            case "1.3.6.1.5.5.7.3.8": return "时间戳";
            case "1.3.6.1.5.5.7.3.9": return "OCSP 签名";
            case "1.3.6.1.4.1.311.10.3.3": return "微软服务器GatedCrypto";
            case "2.16.840.1.113730.4.1": return "Netscape服务器GatedCrypto";
            // ---- Windows / 微软扩展 EKU ----
            case "1.3.6.1.4.1.311.2.1.22": return "Windows 商业代码签名";
            case "1.3.6.1.4.1.311.10.3.5": return "Windows 硬件驱动程序验证";
            case "1.3.6.1.4.1.311.10.3.6": return "Windows 系统组件验证";
            case "1.3.6.1.4.1.311.10.3.7": return "OEM Windows 系统组件验证";
            case "1.3.6.1.4.1.311.10.3.8": return "内嵌 Windows 系统组件验证";
            case "1.3.6.1.4.1.311.61.1.1": return "内核模式代码签名";
            case "1.3.6.1.4.1.311.64.1.1": return "域名系统(DNS)服务器信任";
            case "1.3.6.1.4.1.311.47.1.1": return "系统健康身份认证";
            case "1.3.6.1.4.1.311.10.3.19": return "已吊销列表签名者";
            case "1.3.6.1.5.2.3.5": return "KDC 身份认证";
            case "1.3.6.1.4.1.311.10.3.13": return "生存时间签名";
            case "1.3.6.1.4.1.311.21.5": return "私钥存档";
            case "2.5.29.32.0": return "所有颁发策略";
            case "1.3.6.1.4.1.311.10.121": return "所有颁发应用程序策略";
            case "1.3.6.1.4.1.311.10.3.10": return "合格部署";
            case "1.3.6.1.4.1.311.10.3.11": return "密钥恢复";
            case "1.3.6.1.4.1.311.10.3.12": return "文档签名";
            case "1.3.6.1.4.1.311.10.3.2": return "Microsoft 时间戳";
            case "1.3.6.1.4.1.311.10.3.4": return "加密文件系统";
            case "1.3.6.1.4.1.311.21.6": return "密钥恢复代理";
            case "1.3.6.1.4.1.311.21.19": return "目录服务电子邮件复制";
            case "1.3.6.1.5.5.8.2.2": return "IP 安全 IKE 中级";
            case "1.3.6.1.4.1.311.10.3.4.1": return "文件恢复";
            case "1.3.6.1.4.1.311.10.3.9": return "根列表签名者";
            case "1.3.6.1.4.1.311.10.5.1": return "数字权利";
            case "1.3.6.1.4.1.311.10.6.1": return "密钥数据包许可证";
            case "1.3.6.1.4.1.311.10.6.2": return "许可证服务器验证";
            case "1.3.6.1.4.1.311.20.1": return "CTL 用法";
            case "1.3.6.1.4.1.311.20.2.1": return "证书申请代理";
            case "1.3.6.1.4.1.311.20.2.2": return "智能卡登录";
            case "1.3.6.1.4.1.311.21.30": return "智能卡已验证";
            case "1.3.6.1.4.1.311.21.31": return "智能卡证书已验证";
            case "1.3.6.1.4.1.311.21.32": return "智能卡信任使用";
            // ---- Apple ----
            case "1.2.840.113635.100.4.1": return "Apple CodeSign 代码签名";
            case "1.2.840.113635.100.4.1.1": return "Apple Development CodeSign 开发者代码签名";
            case "1.2.840.113635.100.4.1.4": return "Apple Resource Signing 资源签名";
            case "1.2.840.113635.100.4.2": return "Apple Ichat Signing Ichat签名";
            case "2.5.29.37.0": return "任何目的";
            default: return oid;
        }
    }

    private static void printSan(X509Certificate cert) throws Exception {
        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        if (sans == null || sans.isEmpty()) {
            return;
        }
        System.out.println("\n使用者可选名称：");
        for (List<?> san : sans) {
            int type = ((Number) san.get(0)).intValue();
            String value = String.valueOf(san.get(1));
            switch (type) {
                case 2: System.out.println("              DNS = " + value); break;
                case 1: System.out.println("              Email = " + value); break;
                case 7: System.out.println("              IP = " + value); break;
                default: System.out.println("              type" + type + " = " + value); break;
            }
        }
    }

    private static void printAiaAndCrl(X509Certificate cert) throws Exception {
        System.out.println("授权信息访问：");
        byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia != null) {
            org.bouncycastle.asn1.x509.AuthorityInformationAccess a =
                    org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
                            ASN1Primitive.fromByteArray(unwrapOctets(aia)));
            for (org.bouncycastle.asn1.x509.AccessDescription ad : a.getAccessDescriptions()) {
                String name = ad.getAccessMethod().equals(
                        org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp)
                        ? "OCSP   URL" : "颁发者 URL";
                System.out.println("              " + name + "="
                        + ad.getAccessLocation().getName().toString());
            }
        }
        System.out.println("证书吊销列表：");
        byte[] crlExt = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlExt != null) {
            org.bouncycastle.asn1.x509.CRLDistPoint cdp =
                    org.bouncycastle.asn1.x509.CRLDistPoint.getInstance(
                            ASN1Primitive.fromByteArray(unwrapOctets(crlExt)));
            for (org.bouncycastle.asn1.x509.DistributionPoint dp : cdp.getDistributionPoints()) {
                if (dp.getDistributionPoint() == null) {
                    continue;
                }
                org.bouncycastle.asn1.x509.GeneralNames gns =
                        org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                                dp.getDistributionPoint().getName());
                for (org.bouncycastle.asn1.x509.GeneralName gn : gns.getNames()) {
                    System.out.println("              CRL分发点 = " + gn.getName().toString());
                }
            }
        }
    }

    private static void printPolicies(X509Certificate cert) throws Exception {
        System.out.println("证书策略：");
        byte[] ext = cert.getExtensionValue(Extension.certificatePolicies.getId());
        if (ext == null) {
            return;
        }
        org.bouncycastle.asn1.x509.CertificatePolicies policies =
                org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(ext)));
        for (org.bouncycastle.asn1.x509.PolicyInformation pi : policies.getPolicyInformation()) {
            String oid = pi.getPolicyIdentifier().getId();
            System.out.println("              " + policyName(oid) + " OID = " + oid);
        }
    }

    private static String policyName(String oid) {
        switch (oid) {
            case "2.23.140.1.3": return "Extended Validation(扩展验证，代码签名)";
            case "2.23.140.1.4.1": return "Code Signing(代码签名)";
            case "2.23.140.1.4.2": return "TSA 证书(时间戳)";
            case "2.23.140.1.1": return "Extended Validation(扩展验证，SSL)";
            case "2.23.140.1.2.2": return "Organization Validation(组织验证)";
            case "2.23.140.1.2.1": return "Domain Validation(域名验证)";
            case "2.23.140.1.2.3": return "Individuals Validation(个人验证)";
            case "2.5.29.32.0": return "所有颁发策略";
            case "1.3.6.1.4.1.311.10.12.1": return "所有应用程序策略";
            case "1.3.6.1.5.5.7.2.1": return "证书实践声明指针(Practices Statement)";
            case "1.3.6.1.5.5.7.2.2": return "用户通告(User Notice)";
            default:
                // 对齐 Go 版：1.3.6.1.4.1 私用前缀的未知名 → 证书颁发策略(Statement Identifier)
                if (oid.startsWith("1.3.6.1.4.1.")) {
                    return "证书颁发策略(Statement Identifier)";
                }
                return "";
        }
    }

    /** 打印扩展（含 CT SCT 列表与 CT Log 公钥）。 */
    private static void printExtensions(X509Certificate cert) throws Exception {
        Set<String> critical = cert.getCriticalExtensionOIDs();
        for (String oid : cert.getNonCriticalExtensionOIDs() == null
                ? java.util.Collections.<String>emptySet()
                : cert.getNonCriticalExtensionOIDs()) {
            printOneExtension(cert, oid, false, critical != null && critical.contains(oid));
        }
        if (critical != null) {
            for (String oid : critical) {
                printOneExtension(cert, oid, true, true);
            }
        }
    }

    private static void printOneExtension(X509Certificate cert, String oid,
                                          boolean printed, boolean isCritical) throws Exception {
        byte[] value = unwrapOctets(cert.getExtensionValue(oid));
        if (oid.startsWith("1.3.6.1.4.1.11129.2.4.")) {
            // CT 扩展：单独展示
            if (oid.equals("1.3.6.1.4.1.11129.2.4.5")) {
                System.out.println("公钥列表:");
                byte[][] cs = chunks(value);
                for (byte[] c : cs) {
                    if (c.length == 0) {
                        continue;
                    }
                    System.out.println("         公钥标识符: " + hex(sha256(c)));
                    System.out.println("           签名公钥: " + hex(c));
                    System.out.println("");
                }
            } else if (oid.equals("1.3.6.1.4.1.11129.2.4.2")) {
                System.out.println("SCT列表:");
                printSctList(value);
            }
            return;
        }
        // 对齐 Go 版 ShowPkixExtension：X.509 标准扩展（2. 开头）与 AIA 已在上方结构化展示，
        // 不再重复打印原始 hex
        if (oid.startsWith("2.") || oid.equals("1.3.6.1.5.5.7.1.1")) {
            return;
        }
        if (printed) {
            return;
        }
        System.out.println((isCritical ? "(关键) " : "") + oid + ":\n        " + hex(value) + "\n");
    }

    /**
     * 解析并打印 SCT 列表（RFC 6962 TLS 编码）。
     *
     * <p>结构（与权威解析工具 X509JsonConverter.parseSCTList/parseSCT 一致）：
     * SCTList = uint16 totalLen + [uint16 sctLen + SerializedSCT]*；
     * SerializedSCT = version(1) + log_id(32) + timestamp(8) +
     * extensions(uint16+data) + hash_alg(1) + sig_alg(1) + signature(uint16+data)。
     */
    private static void printSctList(byte[] value) {
        // 扩展值是双重 OCTET STRING（BC addExtension 会再包一层；权威工具
        // X509JsonConverter 用 ext.getParsedValue() 解内层）。循环解开 0x04 外壳（最多 2 层）
        byte[] tls = value;
        for (int i = 0; i < 2 && tls != null && tls.length > 0 && (tls[0] & 0xff) == 0x04; i++) {
            byte[] inner = unwrapOctets(tls);
            if (inner == tls) {
                break;
            }
            tls = inner;
        }
        if (tls == null || tls.length < 2) {
            System.out.println(hex(value));
            return;
        }
        int totalLen = ((tls[0] & 0xff) << 8) | (tls[1] & 0xff);
        int pos = 2;
        int end = Math.min(pos + totalLen, tls.length);
        int no = 1;
        boolean parsedAny = false;
        while (pos + 2 <= end) {
            int sctLen = ((tls[pos] & 0xff) << 8) | (tls[pos + 1] & 0xff);
            pos += 2;
            if (sctLen < 47 || pos + sctLen > end) {
                break; // 结构异常，退出循环
            }
            int s = pos;
            int version = tls[s] & 0xff;
            byte[] logId = java.util.Arrays.copyOfRange(tls, s + 1, s + 33);
            long timestamp = 0;
            for (int i = 0; i < 8; i++) {
                timestamp = (timestamp << 8) | (tls[s + 33 + i] & 0xff);
            }
            int p = s + 41; // extensions 字段
            int extLen = ((tls[p] & 0xff) << 8) | (tls[p + 1] & 0xff);
            p += 2;
            byte[] extensions = extLen > 0
                    ? java.util.Arrays.copyOfRange(tls, p, p + extLen) : new byte[0];
            p += extLen;
            if (p + 4 > s + sctLen) {
                break;
            }
            int hash = tls[p++] & 0xff;
            int sigType = tls[p++] & 0xff;
            int sigLen = ((tls[p] & 0xff) << 8) | (tls[p + 1] & 0xff);
            p += 2;
            if (p + sigLen > s + sctLen) {
                break;
            }
            byte[] signature = java.util.Arrays.copyOfRange(tls, p, p + sigLen);
            System.out.println("      第 " + no + " 条 SCT:");
            System.out.println("        日志版本:  V" + (version + 1));
            System.out.println("      日志标识符:  " + hex(logId));
            System.out.println("          时间戳:  " + new Date(timestamp));
            if (extLen > 0) {
                System.out.println("        扩展数据:  " + hex(extensions));
            }
            System.out.println("        签名类型:  " + sigName(hash, sigType));
            System.out.println("            签名:  " + hex(signature));
            System.out.println("");
            pos = s + sctLen;
            parsedAny = true;
            no++;
        }
        if (!parsedAny) {
            // 一条都未解析出来（格式异常）：退回打印原始 hex
            System.out.println(hex(value));
        }
    }

    private static String sigName(int hash, int type) {
        String h = hash == 4 ? "SHA256" : "HASH" + hash;
        String t = type == 3 ? "ECDSA" : "TYPE" + type;
        return t + "-" + h;
    }

    // ============================================================
    // 签名验证 / 证书链
    // ============================================================

    /** 用给定公钥验证证书签名。 */
    private static boolean verifySignature(X509Certificate cert, PublicKey pub) {
        try {
            String sigAlg = cert.getSigAlgName();
            if (sigAlg == null) {
                return false;
            }
            // SM2 签名：用 BC 的 SM2 验签（e = SM3(ZA||TBS)）
            if (sigAlg.toUpperCase().contains("SM2")
                    || cert.getSigAlgOID().equals(Sm2Util.OID_SM3_WITH_SM2)) {
                org.bouncycastle.crypto.params.ECPublicKeyParameters ep =
                        Sm2Util.toEcPublicParams(pub);
                byte[] tbs = cert.getTBSCertificate();
                org.bouncycastle.crypto.signers.SM2Signer signer = new org.bouncycastle.crypto.signers.SM2Signer();
                org.bouncycastle.crypto.params.ParametersWithID pid = new org.bouncycastle.crypto.params.ParametersWithID(
                        ep, Sm2Util.getSm2UidBytes());
                signer.init(false, pid);
                signer.update(tbs, 0, tbs.length);
                byte[] sig = cert.getSignature();
                return signer.verifySignature(sig);
            }
            Signature s = Signature.getInstance(sigAlg, "BC");
            s.initVerify(pub);
            s.update(cert.getTBSCertificate());
            return s.verify(cert.getSignature());
        } catch (Exception e) {
            return false;
        }
    }

    /** 从 AIA caIssuers URL 拉取颁发者证书（打印完整证书链 CA→…→Root，返回直接颁发者用于验签）。 */
    private static X509Certificate fetchIssuer(X509Certificate cert) {
        try {
            List<String> urls = aiaCaIssuers(cert);
            if (urls.isEmpty()) {
                System.out.println("验证签名： 无法验证签名 |无法找到上级证书链~ ");
                return null;
            }
            byte[] data = httpGet(urls.get(0), 10000);
            if (data == null) {
                System.out.println("验证签名： 失败 |请求失败无法找到上级证书链~ ");
                return null;
            }
            X509Certificate issuer = parseCert(data);
            // 递归打印证书链（CA → … → Root）与信任状态（对齐 Go 版 GetSubPublicKey）
            printChain(issuer);
            return issuer;
        } catch (Exception e) {
            System.out.println("验证签名： 失败 |解析CA证书失败~ ");
            return null;
        }
    }

    /** 递归打印证书链：中间证书 CA --> SKI，根证书 Root --> SKI，并输出信任状态。 */
    private static void printChain(X509Certificate issuer) {
        String ski = subjectKeyIdHex(issuer);
        if (isSelfSigned(issuer)) {
            System.out.println("       Root --> " + ski);
            System.out.println("信任状态： 可信 (此证书已通过信任锚[Root根证书]的验证)\n");
            return;
        }
        System.out.println("       CA   --> " + ski);
        try {
            List<String> urls = aiaCaIssuers(issuer);
            if (urls.isEmpty()) {
                System.out.println("       CA   -->????????????????????");
                System.out.println("信任状态： 不可信 (由于无法找到上级证书链 或 证书链验证失败，所以它不受信任。)\n");
                return;
            }
            byte[] data = httpGet(urls.get(0), 10000);
            if (data == null) {
                System.out.println("       CA   -->????????????????????");
                System.out.println("信任状态： 不可信 (由于无法找到上级证书链 或 证书链验证失败，所以它不受信任。)\n");
                return;
            }
            printChain(parseCert(data));
        } catch (Exception e) {
            System.out.println("       CA   -->????????????????????");
            System.out.println("信任状态： 不可信 (由于无法找到上级证书链 或 证书链验证失败，所以它不受信任。)\n");
        }
    }

    /** 判断证书是否为自签名（Subject == Issuer）。 */
    private static boolean isSelfSigned(X509Certificate c) {
        return c.getSubjectX500Principal().getName()
                .equals(c.getIssuerX500Principal().getName());
    }

    /** 证书 SKI 纯净 hex（剥离双层 OCTET STRING 包装）。 */
    private static String subjectKeyIdHex(X509Certificate c) {
        try {
            byte[] v = c.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            return v == null ? "" : hex(subjectKeyIdValue(v));
        } catch (Exception e) {
            return "";
        }
    }

    private static List<String> aiaCaIssuers(X509Certificate cert) throws Exception {
        java.util.List<String> out = new java.util.ArrayList<>();
        byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia == null) {
            return out;
        }
        org.bouncycastle.asn1.x509.AuthorityInformationAccess a =
                org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(aia)));
        for (org.bouncycastle.asn1.x509.AccessDescription ad : a.getAccessDescriptions()) {
            if (ad.getAccessMethod().equals(
                    org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers)) {
                out.add(ad.getAccessLocation().getName().toString());
            }
        }
        return out;
    }

    // ============================================================
    // 吊销状态检查
    // ============================================================

    private static void checkCrl(X509Certificate cert) {
        try {
            List<String> urls = crlUrls(cert);
            if (urls.isEmpty()) {
                System.out.println("CRL无法检查吊销状态 | None~ ");
                return;
            }
            byte[] data = httpGet(urls.get(0), 10000);
            if (data == null) {
                System.out.println("CRL无法检查吊销状态 | 下载失败~ ");
                return;
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509CRL crl;
            try {
                crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(data));
            } catch (CRLException e) {
                // 尝试 PEM 解码
                crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(data));
            }
            X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
            if (entry != null) {
                System.out.println("          此证书已被颁发机构吊销。（CRL） 吊销时间："
                        + entry.getRevocationDate());
            } else {
                System.out.println("证书正常。（CRL）");
            }
        } catch (Exception e) {
            System.out.println("CRL无法检查吊销状态 | 解析失败~ ");
        }
    }

    private static void checkOcsp(X509Certificate cert) {
        try {
            List<String> urls = ocspUrls(cert);
            if (urls.isEmpty()) {
                System.out.println("        OCSP无法检查吊销状态:None~ ");
                return;
            }
            // 构造 OCSP 请求（CertID 用 SHA1，issuer 信息从证书自身取）
            byte[] req = buildOcspRequest(cert);
            HttpURLConnection conn = (HttpURLConnection) new URL(urls.get(0)).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/ocsp-request");
            conn.setRequestProperty("Accept", "application/ocsp-response");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(req);
            }
            byte[] resp = readAll(conn.getInputStream());
            OcspUtil.OcspRequest parsed = OcspUtil.parseRequest(req);
            // 用 BC 解析 OCSP 响应状态
            org.bouncycastle.cert.ocsp.OCSPResp ocspResp =
                    new org.bouncycastle.cert.ocsp.OCSPResp(resp);
            org.bouncycastle.cert.ocsp.BasicOCSPResp basic =
                    (org.bouncycastle.cert.ocsp.BasicOCSPResp) ocspResp.getResponseObject();
            org.bouncycastle.cert.ocsp.SingleResp single =
                    basic.getResponses()[0];
            Object st = single.getCertStatus();
            if (st == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                System.out.println("          证书正常。（OCSP）");
            } else if (st instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
                org.bouncycastle.cert.ocsp.RevokedStatus rs =
                        (org.bouncycastle.cert.ocsp.RevokedStatus) st;
                System.out.println("          此证书已被颁发机构吊销。（OCSP）吊销时间："
                        + rs.getRevocationTime() + " 原因:" + rs.getRevocationReason());
            } else {
                System.out.println("          证书未知。（OCSP）");
            }
        } catch (Exception e) {
            System.out.println("          OCSP无法检查吊销状态 | 上报失败~ ");
        }
    }

    /** 构造 SHA1 CertID 的 OCSP 请求。 */
    private static byte[] buildOcspRequest(X509Certificate cert) throws Exception {
        org.bouncycastle.cert.ocsp.CertificateID cid =
                new org.bouncycastle.cert.ocsp.CertificateID(
                        new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                                .setProvider("BC").build()
                                .get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.14.3.2.26"))),
                        new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert),
                        cert.getSerialNumber());
        org.bouncycastle.cert.ocsp.OCSPReqBuilder builder =
                new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
        builder.addRequest(cid);
        return builder.build().getEncoded();
    }

    private static List<String> crlUrls(X509Certificate cert) throws Exception {
        java.util.List<String> out = new java.util.ArrayList<>();
        byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (ext == null) {
            return out;
        }
        org.bouncycastle.asn1.x509.CRLDistPoint cdp =
                org.bouncycastle.asn1.x509.CRLDistPoint.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(ext)));
        for (org.bouncycastle.asn1.x509.DistributionPoint dp : cdp.getDistributionPoints()) {
            if (dp.getDistributionPoint() != null
                    && dp.getDistributionPoint().getName() != null) {
                org.bouncycastle.asn1.x509.GeneralNames gns =
                        org.bouncycastle.asn1.x509.GeneralNames.getInstance(
                                dp.getDistributionPoint().getName());
                for (org.bouncycastle.asn1.x509.GeneralName gn : gns.getNames()) {
                    out.add(gn.getName().toString());
                }
            }
        }
        return out;
    }

    private static List<String> ocspUrls(X509Certificate cert) throws Exception {
        java.util.List<String> out = new java.util.ArrayList<>();
        byte[] aia = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aia == null) {
            return out;
        }
        org.bouncycastle.asn1.x509.AuthorityInformationAccess a =
                org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(
                        ASN1Primitive.fromByteArray(unwrapOctets(aia)));
        for (org.bouncycastle.asn1.x509.AccessDescription ad : a.getAccessDescriptions()) {
            if (ad.getAccessMethod().equals(
                    org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp)) {
                out.add(ad.getAccessLocation().getName().toString());
            }
        }
        return out;
    }

    // ============================================================
    // 哈希打印
    // ============================================================

    private static void printHashes(X509Certificate cert, PublicKey pub) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        byte[] spki = pub.getEncoded();
        byte[] spkiSha1 = sha1.digest(spki);
        byte[] spkiSha256 = sha256.digest(spki);
        System.out.println("");
        System.out.println("密钥 Id 哈希(SHA1)          ： " + hex(spkiSha1));
        System.out.println("密钥 Id 哈希(RFC-SHA1)      ： " + hex(rfcSha1(pub)));
        System.out.println("密钥 Id 哈希(Pin-SHA256)    ： "
                + Base64.getEncoder().encodeToString(spkiSha256));
        System.out.println("密钥 Id 哈希(Pin-SHA256-Hex)： " + hex(spkiSha256));
        System.out.println("\n");

        byte[] raw = cert.getEncoded();
        System.out.println("证书哈希(SHA1)              ： " + hex(sha1.digest(raw)));
        System.out.println("证书哈希(SHA256)            ： " + hex(sha256.digest(raw)));
        System.out.println("签名哈希                    ： " + hex(sha256.digest(cert.getTBSCertificate())));
    }

    /** RFC5280 方法1 的密钥标识（RSA：PKCS#1 位串；ECC/SM2：未压缩点）。 */
    private static byte[] rfcSha1(PublicKey pub) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        if (pub instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsa =
                    (java.security.interfaces.RSAPublicKey) pub;
            org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1 =
                    new org.bouncycastle.asn1.pkcs.RSAPublicKey(rsa.getModulus(), rsa.getPublicExponent());
            return md.digest(pkcs1.getEncoded());
        }
        if (pub instanceof java.security.interfaces.ECPublicKey) {
            java.security.interfaces.ECPublicKey ec =
                    (java.security.interfaces.ECPublicKey) pub;
            // 未压缩点：04 || X || Y（固定长度，X/Y 按曲线字节数填充）
            int size = (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            byte[] x = ec.getW().getAffineX().toByteArray();
            byte[] y = ec.getW().getAffineY().toByteArray();
            byte[] xy = new byte[1 + 2 * size];
            xy[0] = 0x04;
            copyRightAligned(x, xy, 1, size);
            copyRightAligned(y, xy, 1 + size, size);
            return md.digest(xy);
        }
        return md.digest(pub.getEncoded());
    }

    private static void copyRightAligned(byte[] src, byte[] dst, int offset, int size) {
        int srcLen = src.length;
        int shift = 0;
        if (srcLen > size) {
            // 去掉可能的前导 00
            int s = 0;
            while (s < srcLen - 1 && src[s] == 0) {
                s++;
            }
            System.arraycopy(src, s, dst, offset, srcLen - s);
        } else {
            System.arraycopy(src, 0, dst, offset + size - srcLen, srcLen);
        }
    }

    // ============================================================
    // HTTP / 工具
    // ============================================================

    private static byte[] httpGet(String url, int timeoutMs) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            int code = conn.getResponseCode();
            if (code != 200) {
                return null;
            }
            return readAll(conn.getInputStream());
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** 去掉扩展值的 OCTET STRING 外层。 */
    private static byte[] unwrapOctets(byte[] extValue) {
        try {
            ASN1OctetString os = ASN1OctetString.getInstance(
                    ASN1Primitive.fromByteArray(extValue));
            return os.getOctets();
        } catch (Exception e) {
            return extValue;
        }
    }

    /** SKI 扩展值 → 纯净字节：extValue(04..) → SubjectKeyIdentifier(04 14 ..) → 20 字节。 */
    private static byte[] subjectKeyIdValue(byte[] extValue) {
        try {
            return unwrapOctets(unwrapOctets(extValue));
        } catch (Exception e) {
            return unwrapOctets(extValue);
        }
    }

    /** AKI 扩展值 → keyIdentifier 纯净字节：用 BC 解析 AuthorityKeyIdentifier 结构。 */
    private static byte[] authorityKeyIdValue(byte[] extValue) {
        try {
            org.bouncycastle.asn1.x509.AuthorityKeyIdentifier aki =
                    org.bouncycastle.asn1.x509.AuthorityKeyIdentifier.getInstance(
                            ASN1Primitive.fromByteArray(unwrapOctets(extValue)));
            byte[] kid = aki.getKeyIdentifier();
            return kid != null ? kid : new byte[0];
        } catch (Exception e) {
            return unwrapOctets(extValue);
        }
    }

    private static byte[][] chunks(byte[] data) {
        java.util.List<byte[]> list = new java.util.ArrayList<>();
        int start = 0;
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == 0 && data[i + 1] == 0) {
                list.add(java.util.Arrays.copyOfRange(data, start, i));
                start = i + 2;
                i++;
            }
        }
        list.add(java.util.Arrays.copyOfRange(data, start, data.length));
        return list.toArray(new byte[0][]);
    }

    private static int indexOf(byte[] data, byte[] needle) {
        for (int i = 0; i <= data.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static String bitsToString(boolean[] bits) {
        StringBuilder sb = new StringBuilder();
        String[] names = {"digitalSignature", "nonRepudiation", "keyEncipherment",
                "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                "encipherOnly", "decipherOnly"};
        for (int i = 0; i < bits.length && i < names.length; i++) {
            if (bits[i]) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(names[i]);
            }
        }
        return sb.toString();
    }
}
