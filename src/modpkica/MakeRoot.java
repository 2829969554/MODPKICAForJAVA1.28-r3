package modpkica;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;

/**
 * MakeRoot —— 生成根证书（对应 Go 版 cmd/makeroot）。
 *
 * <p>用法：{@code java -cp ... modpkica.MakeRoot "CN=xxx,O=yyy,..." &lt;密钥位数&gt; &lt;哈希&gt; &lt;算法&gt;}
 *
 * <ul>
 *   <li>DN 参数：逗号分隔的 {@code key=value}，支持 SERIALNUMBER/CN/O/OU/C/L/S/STREET/PostalCode，
 *       {@code %} 会替换为空格（与 Go 版一致）；</li>
 *   <li>密钥位数：RSA 1024~8192，ECC 224/256/384/521，SM2 固定 256；</li>
 *   <li>哈希：sha1 / sha256 / sha384 / sha512（RSA/ECC）；SM2 固定 SM3；</li>
 *   <li>算法：RSA / ECC / SM2。</li>
 * </ul>
 *
 * <p>输出（与 Go 版完全一致）：
 * <pre>
 *   PKI/ROOT/序列号.crt + 序列号.key（多根模型，不生成 root.crt/root.key）
 *   PKI/ROOT/序列号.crt + 序列号.key
 *   PKI/CERT/序列号.crt
 *   PKI/KEY/序列号.key
 *   PKI/WebPublic/CRT/序列号.crt
 * </pre>
 * 并向 CERTS.txt 追加一行根证书记录（类型 R，颁发者=自身）。
 */
public final class MakeRoot {

    /** 根证书序列号基准：90000000000000000 + 当前 Unix 秒（与 Go 版一致） */
    private static final BigInteger SERIAL_BASE = BigInteger.valueOf(90000000000000000L);

    /** 证书生效时间（Go 版固定值） */
    private static final String NOT_BEFORE = "2001-07-19 15:30:00";
    /** 证书过期时间（Go 版固定值） */
    private static final String NOT_AFTER = "2099-07-19 15:30:00";

    private MakeRoot() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("用法: MakeRoot \"DN(逗号分隔key=value)\" 密钥位数 哈希 算法");
            System.out.println("示例: MakeRoot \"CN=Test Root CA,O=My Org,C=CN\" 2048 sha256 RSA");
            return;
        }
        run(AppPaths.baseDir(), args);
    }

    /** 供 ADMIN 内部调用：指定工作目录签发根证书。 */
    public static void run(String baseDir, String[] args) throws Exception {
        // Go 版 os.Args 含程序名，Java 不含：args[0]=DN args[1]=bit args[2]=hash args[3]=alg
        String dn = args[0];
        String hash = args[2];
        String keyType = args[3].toUpperCase(Locale.ROOT);

        // 密钥位数归一化（与 Go 版一致）
        int bit = parseKeyBits(args[1], keyType);

        Config cfg = new Config(baseDir);

        // ---- 1. 生成密钥对 ----
        KeyPair kp;
        switch (keyType) {
            case "RSA":
                kp = CertUtil.generateRsaKeyPair(bit);
                break;
            case "ECC":
                kp = CertUtil.generateEccKeyPair(bit);
                break;
            case "SM2":
                kp = CertUtil.generateSm2KeyPair();
                break;
            default:
                System.out.println("不支持的算法: " + keyType);
                return;
        }

        // ---- 2. 序列号 / 有效期 ----
        BigInteger serial = SERIAL_BASE.add(BigInteger.valueOf(System.currentTimeMillis() / 1000L));
        Date notBefore = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(NOT_BEFORE);
        Date notAfter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(NOT_AFTER);

        // ---- 3. 构建根证书 ----
        X500Name subject = buildSubject(dn);
        ContentSigner signer = CertUtil.createContentSigner(kp.getPrivate(), keyType, hash);
        JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic());

        // KeyUsage: digitalSignature(Go 1) | contentCommitment(Go 2) | keyCertSign(Go 32) | cRLSign(Go 64)
        // BC 位定义与 Go 不同，必须用 BC 常量：128|64|4|2
        cb.addExtension(Extension.keyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                        | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        // BasicConstraints: 根 CA，无 pathLen 限制（对齐 Go 版，允许下级再签中间 CA）
        cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // SKI = SHA1(subjectPublicKey)；自签根 AKI = SKI
        byte[] ski = CertUtil.getSubjectKeyIdentifier(kp.getPublic());
        cb.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(ski));
        cb.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(ski));

        // ---- 4. AIA（OCSP + caIssuers）与 CRL 分发点（{CID} 替换为序列号） ----
        String serialHex = serial.toString(16);
        String ocspUrl = cfg.getOcspUrl();
        String crtUrl = cfg.getCrtUrl().replace("{CID}", serialHex);
        String crlUrl = cfg.getCrlUrl().replace("{CID}", serialHex);
        addAuthorityInfoAccess(cb, ocspUrl, crtUrl);
        addCrlDistributionPoints(cb, crlUrl);

        // ---- 5. CPS 证书策略扩展（2.5.29.32，结构对齐 Go 版 internal/cps） ----
        String cpsUrl = cfg.getCps();
        String cpsText = cfg.getCpsNonice();
        if (cpsUrl == null || cpsUrl.isEmpty() || "null".equalsIgnoreCase(cpsUrl)) {
            cpsUrl = "https://gitee.com/wxgshuju/modpkica";
        }
        if (cpsText == null || cpsText.isEmpty() || "null".equalsIgnoreCase(cpsText)) {
            cpsText = "我是受信任证书颁发机构签发的可信根证书。\nThis is a Trusted Root Certificate Authority.";
        }
        // CONFIG 中字面 \n 转真实换行（配置页以单行 \n 存储，证书内需真实换行）
        cpsText = cpsText.replace("\\n", "\n");
        cb.addExtension(new ASN1ObjectIdentifier("2.5.29.32"), false,
                buildCpsPolicies(cpsUrl, cpsText));

        // ---- 6. 生成并写出 ----
        X509CertificateHolder holder = cb.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(holder);

        String rootDir = baseDir + "/PKI/ROOT/";
        String webDir = baseDir + "/PKI/WebPublic/CRT/";

        // R 类型目录规则：ROOT/序列号.crt|.key + WebPublic/CRT/序列号.crt（不写 CERT/KEY）
        PemIO.writeCert(rootDir + serialHex + ".crt", cert);
        PemIO.writeCert(webDir + serialHex + ".crt", cert);
        PemIO.writePrivateKey(rootDir + serialHex + ".key", kp.getPrivate(), keyType);

        // ---- 7. 追加 CERTS.txt 记录（时间=当前-3天，与 Go 版 auto newcert 一致） ----
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = new CertsDB.CertEntry();
        e.serial = serialHex;
        e.type = 'R';
        e.status = 'V';
        e.reason = 0;
        e.time = LocalDateTime.now().minusDays(3);
        e.issuerId = serialHex; // 根证书颁发者=自身
        e.algo = keyType;
        db.addEntry(e);

        System.out.println("根证书生成成功 序列号=" + serialHex + " 算法=" + keyType
                + " 位长=" + bit + " 哈希=" + hash);

        // ---- 8. 生成该根的 CRL（对齐 Go 版：MAKEROOT 完成后调用 rootGETcrl） ----
        RootGetCrl.run();
    }

    /**
     * 解析并归一化密钥位数（规则与 Go 版完全一致）。
     */
    private static int parseKeyBits(String arg, String keyType) {
        int bit;
        try {
            bit = Integer.parseInt(arg.trim());
        } catch (NumberFormatException ex) {
            bit = 0;
        }
        if ("RSA".equals(keyType)) {
            if (bit < 1024) {
                bit = 2048; // 缺省
            }
            if (bit < 1024) {
                bit = 1024;
            }
            return bit;
        }
        if ("ECC".equals(keyType)) {
            if (bit <= 0) {
                return 256;
            }
            if (bit <= 256) {
                return 256;
            }
            if (bit <= 384) {
                return 384;
            }
            return 521;
        }
        return 256; // SM2 固定 256
    }

    /**
     * 解析 DN 字符串为 X500Name（RDN 顺序对齐 Go 版 pkix.Name：C,O,OU,L,S,STREET,PostalCode,SERIALNUMBER,CN）。
     */
    private static X500Name buildSubject(String dn) {
        X500NameBuilder builder = new X500NameBuilder();
        String[] parts = dn.split(",");
        // 记录值，最后按 Go 版顺序统一添加
        java.util.Map<String, String> fields = new java.util.LinkedHashMap<>();
        for (String part : parts) {
            String p = part.trim();
            int idx = p.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = p.substring(0, idx).trim();
            String value = p.substring(idx + 1).trim().replace("%", " ");
            if (value.isEmpty()) {
                continue;
            }
            fields.put(key, value);
        }
        addIfPresent(builder, BCStyle.C, fields.get("C"));
        addIfPresent(builder, BCStyle.O, fields.get("O"));
        addIfPresent(builder, BCStyle.OU, fields.get("OU"));
        addIfPresent(builder, BCStyle.L, fields.get("L"));
        addIfPresent(builder, BCStyle.ST, fields.get("S"));
        addIfPresent(builder, BCStyle.STREET, fields.get("STREET"));
        addIfPresent(builder, BCStyle.POSTAL_CODE, fields.get("PostalCode"));
        addIfPresent(builder, BCStyle.SERIALNUMBER, fields.get("SERIALNUMBER"));
        addIfPresent(builder, BCStyle.CN, fields.get("CN"));
        // 非标准字段：key 直接写 OID（如 2.5.4.42=张三、1.2.3.4.5=自定义），按输入顺序追加
        for (java.util.Map.Entry<String, String> e : fields.entrySet()) {
            String k = e.getKey();
            if (isStandardDnKey(k)) {
                continue;
            }
            try {
                addIfPresent(builder, new ASN1ObjectIdentifier(k), e.getValue());
            } catch (Exception ignored) {
                // 既不是标准字段也不是合法 OID：忽略该 RDN
            }
        }
        return builder.build();
    }

    /** 标准 DN 短名（Go 版 pkix.Name 支持的固定字段）。 */
    private static boolean isStandardDnKey(String key) {
        switch (key) {
            case "C": case "O": case "OU": case "L": case "S":
            case "STREET": case "PostalCode": case "SERIALNUMBER": case "CN":
                return true;
            default:
                return false;
        }
    }

    private static void addIfPresent(X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.isEmpty()) {
            builder.addRDN(oid, value);
        }
    }

    /**
     * 添加 AuthorityInfoAccess 扩展（OCSP + caIssuers）。
     */
    private static void addAuthorityInfoAccess(JcaX509v3CertificateBuilder cb,
                                               String ocspUrl, String caIssuerUrl) throws Exception {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (ocspUrl != null && !ocspUrl.isEmpty()) {
            vec.add(new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }
        if (caIssuerUrl != null && !caIssuerUrl.isEmpty()) {
            vec.add(new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier, caIssuerUrl)));
        }
        if (vec.size() > 0) {
            cb.addExtension(Extension.authorityInfoAccess, false,
                    AuthorityInformationAccess.getInstance(new DERSequence(vec)));
        }
    }

    /**
     * 添加 CRL 分发点扩展（含 .crl 与 .der.crl 两个 URL，对齐 Go 版）。
     */
    private static void addCrlDistributionPoints(JcaX509v3CertificateBuilder cb, String crlUrl)
            throws Exception {
        if (crlUrl == null || crlUrl.isEmpty()) {
            return;
        }
        String url1 = crlUrl;
        String url2 = crlUrl.replace(".crl", ".der.crl");
        GeneralName gn1 = new GeneralName(GeneralName.uniformResourceIdentifier, url1);
        GeneralName gn2 = new GeneralName(GeneralName.uniformResourceIdentifier, url2);
        DistributionPoint dp1 = new DistributionPoint(
                new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(gn1)), null, null);
        DistributionPoint dp2 = new DistributionPoint(
                new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(gn2)), null, null);
        cb.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{dp1, dp2}));
    }

    /**
     * 构建 CPS 证书策略扩展值（OID 2.5.29.32）。
     *
     * <p>结构与 Go 版 internal/cps/cps.go GenerateCPSbyte 一致：
     * <pre>
     *   SEQUENCE {
     *     SEQUENCE { 1.3.6.1.4.1.4146.1.95,
     *       SEQUENCE { 1.3.6.1.5.5.7.2.1, IA5String(cpsUrl) },
     *       SEQUENCE { 1.3.6.1.5.5.7.2.2, SEQUENCE { UTF8String(文本) } }
     *     },
     *     SEQUENCE { 2.5.29.32.0 },
     *     SEQUENCE { 1.3.6.1.4.1.311.10.12.1 },
     *     SEQUENCE { 2.23.140.1.1 },
     *     SEQUENCE { 2.23.140.1.3 }
     *   }
     * </pre>
     * 注意：explicitText 是 DisplayText CHOICE，直接放 UTF8String；
     * 不能用 [0] EXPLICIT 包裹，否则权威解析工具 UserNotice.getInstance 报 DLTaggedObject。
     */
    private static org.bouncycastle.asn1.ASN1Primitive buildCpsPolicies(String cpsUrl, String cpsText)
            throws Exception {
        // UserNotice ::= SEQUENCE { explicitText UTF8String }
        ASN1EncodableVector userNoticeVec = new ASN1EncodableVector();
        userNoticeVec.add(new DERUTF8String(cpsText));
        DERSequence userNotice = new DERSequence(userNoticeVec);

        // 第一个 PolicyInformation：策略 OID + CPS URI + UserNotice
        ASN1EncodableVector qualifiers = new ASN1EncodableVector();
        ASN1EncodableVector cpsQualifier = new ASN1EncodableVector();
        cpsQualifier.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.1"));
        cpsQualifier.add(new DERIA5String(cpsUrl));
        qualifiers.add(new DERSequence(cpsQualifier));

        ASN1EncodableVector unQualifier = new ASN1EncodableVector();
        unQualifier.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2"));
        unQualifier.add(userNotice);
        qualifiers.add(new DERSequence(unQualifier));

        ASN1EncodableVector firstPolicy = new ASN1EncodableVector();
        firstPolicy.add(new ASN1ObjectIdentifier("1.3.6.1.4.1.4146.1.95"));
        firstPolicy.add(new DERSequence(qualifiers));

        ASN1EncodableVector policies = new ASN1EncodableVector();
        policies.add(new DERSequence(firstPolicy));
        // 其余纯 OID 策略项
        String[] extraOids = {"2.5.29.32.0", "1.3.6.1.4.1.311.10.12.1", "2.23.140.1.1", "2.23.140.1.3"};
        for (String oid : extraOids) {
            ASN1EncodableVector p = new ASN1EncodableVector();
            p.add(new ASN1ObjectIdentifier(oid));
            policies.add(new DERSequence(p));
        }
        return new DERSequence(policies);
    }
}
