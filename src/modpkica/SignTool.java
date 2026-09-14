package modpkica;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Hex;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * SignTool —— 签名专区（微软代码签名 + PDF 文档签名）。
 *
 * <p><b>1) 微软代码签名（Windows Authenticode）</b>：
 * 对齐 signtool 标准结构，手动构造 ASN.1（不经 BC CMS 生成器，避免 OCTET STRING 包装 /
 * signingTime / SpcIndirectData 标签不合规）：
 * <ul>
 *   <li>encapContentInfo.contentType = 1.3.6.1.4.1.311.2.1.4 (spcIndirectDataContext)</li>
 *   <li>eContent = [0] EXPLICIT SpcIndirectDataContent（直接 SEQUENCE，无 OCTET STRING 包装）</li>
 *   <li>SpcPeImageData.file = [0] EXPLICIT → [2] EXPLICIT → SpcString(空 80 00)（对齐 signtool 标准）</li>
 *   <li>SpcAttributeTypeAndOptionalValue.value = 直接 SEQUENCE（微软实测，无 [0] 包装）</li>
 *   <li>DigestInfo = AlgorithmIdentifier(摘要OID, NULL) + 文件哈希（parameters 必须带 NULL）</li>
 *   <li>signedAttrs = { contentType, messageDigest }，messageDigest = hash(SpcIndirectData 内容字节)</li>
 *   <li>签名算法：SM2 → SM3withSM2；RSA → SHA256withRSA；ECC → SHA256withECDSA</li>
 *   <li>certificates = 链按根在前顺序（[根 … 叶子]）</li>
 *   <li>RFC3161 时间戳：messageImprint = SHA-256(签名值)，请求本机 MAIN /rfc3161，
 *       以 SPC_RFC3161_TS (1.3.6.1.4.1.311.3.3.1) 作为 unsignedAttr 嵌入；失败降级不影响签名</li>
 * </ul>
 *
 * <p><b>2) PDF 文档签名</b>：标准 PKCS#7 detached（adbe.pkcs7.detached），PDFBox 3.0.4 外部签名
 * 两段式；可选可见签章（png/jpg/bmp/gif 图片作为印章外观）。
 */
public final class SignTool {

    static {
        Bc.init();
    }

    private SignTool() {
    }

    // ============================ OID 常量 ============================

    /** spcIndirectDataContext：Authenticode 的 encapContentInfo.contentType */
    public static final String OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
    /** SpcPeImageData */
    public static final String OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15";
    /** Authenticode 时间戳属性（RFC3161 timestamp） */
    public static final String OID_SPC_RFC3161_TS = "1.3.6.1.4.1.311.3.3.1";

    /** 最近一次 EXE 签名的时间戳状态（供上层展示日志）。 */
    public static volatile String lastTsInfo = "未请求";

    /** 代码签名相关 EKU（用于证书筛选） */
    public static final String EKU_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";      // 代码签名
    public static final String EKU_KERNEL_MODE = "1.3.6.1.4.1.311.61.1.1";   // 内核模式代码签名
    public static final String EKU_DRIVER_VERIFY = "1.3.6.1.4.1.311.10.3.5"; // Windows 硬件驱动程序验证
    public static final String EKU_SYS_COMPONENT = "1.3.6.1.4.1.311.10.3.6"; // Windows 系统组件验证
    public static final String EKU_OEM_SYS = "1.3.6.1.4.1.311.10.3.7";       // OEM 系统组件
    public static final String EKU_EMBED_SYS = "1.3.6.1.4.1.311.10.3.8";     // 内嵌系统组件
    public static final String EKU_DOC_MICROSOFT = "1.3.6.1.4.1.311.10.3.12";// 微软文档签名
    public static final String EKU_DOC_GENERIC = "1.3.6.1.5.5.7.3.36";       // 通用文档签名

    /** 判定证书是否可用于代码签名（EKU 含标准或微软代码签名 OID）。 */
    public static boolean isCodeSignCert(X509Certificate cert) {
        Set<String> ekus = ekusOf(cert);
        if (ekus == null || ekus.isEmpty()) {
            return false;
        }
        return ekus.contains(EKU_CODE_SIGNING)
                || ekus.contains(EKU_KERNEL_MODE)
                || ekus.contains(EKU_DRIVER_VERIFY)
                || ekus.contains(EKU_SYS_COMPONENT)
                || ekus.contains(EKU_OEM_SYS)
                || ekus.contains(EKU_EMBED_SYS);
    }

    /** 判定证书是否可用于 PDF 文档签名（EKU 含微软文档签名或通用文档签名 OID 即可）。 */
    public static boolean isDocSignCert(X509Certificate cert) {
        Set<String> ekus = ekusOf(cert);
        if (ekus == null || ekus.isEmpty()) {
            return false;
        }
        return ekus.contains(EKU_DOC_MICROSOFT)
                || ekus.contains(EKU_DOC_GENERIC);
    }

    /** 读取证书 EKU OID 集合（无 EKU 扩展返回空集合）。 */
    public static Set<String> ekusOf(X509Certificate cert) {
        try {
            List<String> ext = cert.getExtendedKeyUsage();
            if (ext == null) {
                return Collections.emptySet();
            }
            return new HashSet<>(ext);
        } catch (Exception e) {
            return Collections.emptySet();
        }
    }

    /** 证书密钥位数（RSA modulus bit 数；ECC/SM2 曲线位宽）。 */
    public static int keyBits(X509Certificate cert) {
        try {
            java.security.PublicKey pk = cert.getPublicKey();
            if (pk instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength();
            }
            if (pk instanceof java.security.interfaces.ECPublicKey) {
                return ((java.security.interfaces.ECPublicKey) pk).getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    // ============================ 证书 / 密钥 / 链加载 ============================

    /** 按序列号从 CERTS.txt 台账定位并加载证书（R→ROOT、C→CA、E→CERT，兜底 WebPublic/CRT）。 */
    public static X509Certificate loadCertBySerial(String baseDir, String serial) throws Exception {
        String p = certFilePath(baseDir, serial);
        if (p == null) {
            throw new IllegalArgumentException("未找到证书 " + serial + "（CERTS.txt 无记录或文件缺失）");
        }
        return PemIO.readCert(p);
    }

    /** 按序列号加载私钥（R→ROOT、C→CA、E→KEY）。 */
    public static PrivateKey loadKeyBySerial(String baseDir, String serial) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = db.findBySerial(serial);
        String dir;
        if (e == null) {
            dir = null;
        } else if (e.type == 'R') {
            dir = "ROOT";
        } else if (e.type == 'C') {
            dir = "CA";
        } else {
            dir = "KEY";
        }
        String p = null;
        if (dir != null) {
            Path path = Paths.get(baseDir, "PKI", dir, serial + ".key");
            if (Files.exists(path)) {
                p = path.toString();
            }
        }
        if (p == null) {
            for (String d : new String[]{"KEY", "ROOT", "CA"}) {
                Path path = Paths.get(baseDir, "PKI", d, serial + ".key");
                if (Files.exists(path)) {
                    p = path.toString();
                    break;
                }
            }
        }
        if (p == null) {
            throw new IllegalArgumentException("未找到私钥 " + serial + ".key");
        }
        return CertUtil.readJcaPrivateKey(p);
    }

    /** 按序列号加载完整证书链（签名证书 + 按 CERTS.txt 颁发者关系逐级上级，直到自签根）。 */
    public static List<X509Certificate> loadChain(String baseDir, String serial) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        List<X509Certificate> chain = new ArrayList<>();
        String cur = serial;
        Set<String> seen = new HashSet<>();
        int guard = 0;
        while (cur != null && guard++ < 32 && seen.add(cur)) {
            String p = certFilePath(baseDir, cur);
            if (p == null) {
                break;
            }
            chain.add(PemIO.readCert(p));
            CertsDB.CertEntry e = db.findBySerial(cur);
            if (e == null) {
                break;
            }
            String issuer = e.issuerId;
            if (issuer == null || issuer.isEmpty() || issuer.equalsIgnoreCase(cur)) {
                break;
            }
            cur = issuer;
        }
        return chain;
    }

    private static String certFilePath(String baseDir, String serial) {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry e = db.findBySerial(serial);
        if (e != null) {
            String dir = e.type == 'R' ? "ROOT" : (e.type == 'C' ? "CA" : "CERT");
            Path p = Paths.get(baseDir, "PKI", dir, serial + ".crt");
            if (Files.exists(p)) {
                return p.toString();
            }
        }
        for (String d : new String[]{"ROOT", "CA", "CERT", "WebPublic/CRT"}) {
            Path p = Paths.get(baseDir, "PKI", d, serial + ".crt");
            if (Files.exists(p)) {
                return p.toString();
            }
        }
        return null;
    }

    // ============================ 摘要 / 签名算法推导 ============================

    /** 密钥类型 → 摘要名（"SHA256" / "SM3"）。 */
    public static String digestName(String keyType) {
        return "SM2".equalsIgnoreCase(keyType) ? "SM3" : "SHA256";
    }

    /** 密钥类型 → JCA 摘要算法名。 */
    public static String digestJca(String keyType) {
        return "SM2".equalsIgnoreCase(keyType) ? "SM3" : "SHA-256";
    }

    /** 密钥类型 → 摘要算法 OID。 */
    public static String digestOid(String keyType) {
        return "SM2".equalsIgnoreCase(keyType) ? Sm2Util.OID_SM3 : "2.16.840.1.101.3.4.2.1";
    }

    /** 密钥类型 → 签名算法 OID（Authenticode SignerInfo.signatureAlgorithm）。 */
    public static String sigAlgOid(String keyType) {
        if ("SM2".equalsIgnoreCase(keyType)) {
            return "1.2.156.10197.1.501";          // SM3withSM2
        }
        if ("ECC".equalsIgnoreCase(keyType)) {
            return "1.2.840.10045.4.3.2";          // ecdsa-with-SHA256
        }
        return "1.2.840.113549.1.1.1";             // rsaEncryption
    }

    /** 密钥类型 → JCA 签名算法名。 */
    public static String jcaSigAlg(String keyType) {
        if ("SM2".equalsIgnoreCase(keyType)) {
            return "SM3withSM2";
        }
        if ("ECC".equalsIgnoreCase(keyType)) {
            return "SHA256withECDSA";
        }
        return "SHA256withRSA";
    }

    /** 摘要算法 OID → JCA 名（验证时从 CMS 读取）。 */
    private static String digestJcaFromOid(String oid) {
        if (oid == null) {
            return "SHA-256";
        }
        switch (oid) {
            case "1.3.14.3.2.26":
                return "SHA-1";
            case "2.16.840.1.101.3.4.2.2":
                return "SHA-384";
            case "2.16.840.1.101.3.4.2.3":
                return "SHA-512";
            case Sm2Util.OID_SM3:
                return "SM3";
            case "2.16.840.1.101.3.4.2.1":
            default:
                return "SHA-256";
        }
    }

    /** 签名算法 OID → JCA 名（验证时使用）。 */
    private static String jcaSigFromOid(String oid) {
        if (oid == null) {
            return "SHA256withRSA";
        }
        switch (oid) {
            case "1.2.156.10197.1.501":
                return "SM3withSM2";
            case "1.2.840.10045.4.3.2":
            case "1.2.840.10045.4.3.1":
                return "SHA256withECDSA";
            case "1.2.840.113549.1.1.1":
            case "1.2.840.113549.1.1.11":
            case "1.2.840.113549.1.1.13":
            default:
                return "SHA256withRSA";
        }
    }

    // ============================ EXE Authenticode 签名 ============================

    /**
     * 对 PE 文件（exe/dll/sys）做 Windows Authenticode 代码签名。
     * 结构对齐 signtool 标准：手动 ASN.1（直接 SEQUENCE eContent、signedAttrs={contentType,messageDigest}、
     * DigestInfo 带 NULL、SpcPeImageData 空 SpcLink），并自动请求本机 MAIN /rfc3161 时间戳嵌入。
     *
     * @param file     原始 PE 字节
     * @param keyType  RSA / ECC / SM2
     * @param cert     签名证书
     * @param key      签名私钥
     * @param chain    证书链（含签名证书，顺序任意，写入时自动根在前）
     * @param baseDir  PKI 基目录（读 CONFIG.txt 的 WEBPORT 定位本机 TSA）
     * @return 已签名 PE 字节
     */
    public static byte[] signExe(byte[] file, String keyType,
                                 X509Certificate cert, PrivateKey key,
                                 List<X509Certificate> chain, String baseDir) throws Exception {
        if (file.length < 0x40 || file[0] != 'M' || file[1] != 'Z') {
            throw new IllegalArgumentException("不是有效 PE 文件（缺 MZ 头）");
        }
        long eLfanew = readU32(file, 0x3C);
        int magic = readU16(file, (int) eLfanew + 24);
        if (magic != 0x10B && magic != 0x20B) {
            throw new IllegalArgumentException("无法识别的 PE 魔术字: 0x" + Integer.toHexString(magic));
        }
        boolean is64 = magic == 0x20B;
        int dataDirStart = is64 ? 112 : 96;
        long checksumOff = eLfanew + 24 + 64;                              // OptionalHeader.Checksum
        long secDirOff = eLfanew + 24 + dataDirStart + 4 * 8;              // DataDirectory[4] Certificate Table

        // 证书表起始 = 原文件长度 8 字节对齐
        long certTableOffset = (file.length + 7) & ~7L;

        // 先把 Security Directory 8 字节写入 header（占位 size=0）
        byte[] exe = Arrays.copyOf(file, file.length);
        writeU32(exe, (int) secDirOff, (int) certTableOffset);
        writeU32(exe, (int) secDirOff + 4, 0);

        // 计算 Authenticode 文件哈希
        MessageDigest md = MessageDigest.getInstance(digestJca(keyType));
        authenticodeDigest(md, exe, checksumOff, secDirOff, certTableOffset, 0);
        byte[] fileHash = md.digest();

        // 构建 SpcIndirectDataContent（对齐 signtool 标准结构）
        byte[] spcIndirectData = buildSpcIndirectData(fileHash, digestOid(keyType));

        // 手写 CMS SignedData（对齐 signtool，eContent 直接 SEQUENCE）
        byte[] signedData = buildExeCms(spcIndirectData, keyType, cert, key, chain, baseDir);

        // WIN_CERTIFICATE 表：头 8 字节 + CMS，8 字节对齐
        long certHeaderLen = 8;
        long certTableSize = ((certHeaderLen + signedData.length + 7) & ~7L);
        writeU32(exe, (int) secDirOff + 4, (int) certTableSize);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(exe);
        for (long i = file.length; i < certTableOffset; i++) {
            out.write(0);
        }
        writeU32(out, (int) certTableSize);  // dwLength（含头、对齐后总长）
        writeU16(out, 0x0200);               // wRevision = WIN_CERT_REVISION_2_0
        writeU16(out, 0x0002);               // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        out.write(signedData);
        while ((out.size() & 7) != 0) {
            out.write(0);
        }
        return out.toByteArray();
    }

    /** Authenticode 哈希：跳过 checksum(4B)、Security Directory entry(8B)、证书表区域。 */
    private static void authenticodeDigest(MessageDigest md, byte[] file,
                                           long checksumOff, long secDirOff,
                                           long certTableOff, long certTableSize) {
        md.update(file, 0, (int) checksumOff);
        md.update(file, (int) checksumOff + 4, (int) (secDirOff - checksumOff - 4));
        md.update(file, (int) secDirOff + 8, (int) (certTableOff - secDirOff - 8));
        long tableEnd = certTableOff + certTableSize;
        if (tableEnd < file.length) {
            md.update(file, (int) tableEnd, file.length - (int) tableEnd);
        }
    }

    /**
     * 构建 SpcIndirectDataContent（对齐 signtool 标准样本）：
     * SpcPeImageData.file = [0] EXPLICIT → [2] EXPLICIT → SpcString(空 80 00)；
     * SpcAttributeTypeAndOptionalValue.value = 直接 SEQUENCE（微软实测无 [0] 包装）；
     * DigestInfo = 摘要算法(NULL) + 文件哈希。
     */
    private static byte[] buildSpcIndirectData(byte[] fileHash, String digestOid) throws Exception {
        // SpcString 空 = [0] IMPLICIT OCTET STRING(空) → 80 00
        DERTaggedObject spcStringEmpty = new DERTaggedObject(false, 0, new DEROctetString(new byte[0]));
        // SpcLink.file = [2] EXPLICIT SpcString
        DERTaggedObject spcLinkFile = new DERTaggedObject(true, 2, spcStringEmpty);
        // SpcPeImageData: flags + file [0] EXPLICIT SpcLink
        ASN1EncodableVector peImage = new ASN1EncodableVector();
        peImage.add(new DERBitString(0));
        peImage.add(new DERTaggedObject(true, 0, spcLinkFile));
        byte[] peImageDer = new DERSequence(peImage).getEncoded();

        // SpcAttributeTypeAndOptionalValue: OID + value（直接，无 [0] 包装）
        ASN1EncodableVector attr = new ASN1EncodableVector();
        attr.add(new ASN1ObjectIdentifier(OID_SPC_PE_IMAGE_DATA));
        attr.add(ASN1Primitive.fromByteArray(peImageDer));
        byte[] dataDer = new DERSequence(attr).getEncoded();

        // DigestInfo: 摘要算法 + NULL + 文件哈希
        ASN1EncodableVector di = new ASN1EncodableVector();
        di.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE));
        di.add(new DEROctetString(fileHash));
        byte[] digestInfoDer = new DERSequence(di).getEncoded();

        ASN1EncodableVector spc = new ASN1EncodableVector();
        spc.add(ASN1Primitive.fromByteArray(dataDer));
        spc.add(ASN1Primitive.fromByteArray(digestInfoDer));
        return new DERSequence(spc).getEncoded();
    }

    /**
     * 手动构造 Authenticode SignedData（对齐 signtool 标准，eContent 直接 SEQUENCE 无 OCTET STRING 包装）：
     * SignedData v1, digestAlgorithms={摘要+NULL}, encapContentInfo={spcIndirectDataContext,
     * [0] EXPLICIT SpcIndirectData}, certificates[0]={根在前}, signerInfos=1(
     * signedAttrs={contentType, messageDigest}, signatureAlgorithm=算法+NULL, 签名 over signedAttrs)。
     * 自动请求 RFC3161 时间戳（messageImprint=SHA-256(签名值)）嵌入 unsignedAttrs，失败降级。
     */
    private static byte[] buildExeCms(byte[] spcDer, String keyType,
                                      X509Certificate cert, PrivateKey key,
                                      List<X509Certificate> chain, String baseDir) throws Exception {
        String digestOid = digestOid(keyType);
        String sigAlgOid = sigAlgOid(keyType);
        String jcaSig = jcaSigAlg(keyType);
        String jcaHash = digestJca(keyType);

        // messageDigest = hash(SpcIndirectData SEQUENCE 内容字节, 不含 30xx 头) —— 对齐 signtool 标准
        MessageDigest md = MessageDigest.getInstance(jcaHash);
        byte[] digest = md.digest(stripSequenceHeader(spcDer));

        // signedAttrs: { contentType(spcIndirectDataContext), messageDigest }（DER SET 按 OID 排序）
        ASN1EncodableVector attrs = new ASN1EncodableVector();
        attrs.add(new Attribute(CMSAttributes.contentType,
                new DERSet(new ASN1ObjectIdentifier(OID_SPC_INDIRECT_DATA))));
        attrs.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest))));
        byte[] signedAttrsDer = new DERSet(attrs).getEncoded();

        // 签名 over signedAttrs DER
        Signature sigEngine = Signature.getInstance(jcaSig);
        sigEngine.initSign(key);
        sigEngine.update(signedAttrsDer);
        byte[] sig = sigEngine.sign();

        // RFC3161 时间戳：messageImprint = SHA-256(签名值)；失败降级不影响签名
        byte[] tsToken = null;
        String tsInfo = null;
        try {
            byte[] imprint = MessageDigest.getInstance("SHA-256").digest(sig);
            tsToken = requestTimestamp(imprint, baseDir);
            tsInfo = "已附加 RFC3161 时间戳 (" + tsToken.length + "B)";
        } catch (Exception ex) {
            tsInfo = "时间戳请求失败，跳过（不影响签名）: " + ex.getMessage();
        }
        lastTsInfo = tsInfo;

        // SignerInfo v1: sid=(issuer=上级证书 subject, serial=签名证书 serial)
        X509Certificate issuer = (chain != null && chain.size() >= 2) ? chain.get(1) : cert;
        ASN1EncodableVector ias = new ASN1EncodableVector();
        ias.add(X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()));
        ias.add(new ASN1Integer(cert.getSerialNumber()));
        ASN1EncodableVector si = new ASN1EncodableVector();
        si.add(new ASN1Integer(1));
        si.add(new DERSequence(ias));
        si.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE));
        si.add(new DERTaggedObject(false, 0, ASN1Primitive.fromByteArray(signedAttrsDer))); // [0] IMPLICIT signedAttrs
        si.add(new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigAlgOid), DERNull.INSTANCE));
        si.add(new DEROctetString(sig));
        if (tsToken != null) {
            ASN1EncodableVector uattrs = new ASN1EncodableVector();
            uattrs.add(new Attribute(new ASN1ObjectIdentifier(OID_SPC_RFC3161_TS),
                    new DERSet(ASN1Primitive.fromByteArray(tsToken))));
            si.add(new DERTaggedObject(false, 1, new DERSet(uattrs)));
        }
        byte[] signerInfoDer = new DERSequence(si).getEncoded();

        // SignedData v1
        ASN1EncodableVector sd = new ASN1EncodableVector();
        sd.add(new ASN1Integer(1));
        sd.add(new DERSet(new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestOid), DERNull.INSTANCE)));
        ASN1EncodableVector eci = new ASN1EncodableVector();
        eci.add(new ASN1ObjectIdentifier(OID_SPC_INDIRECT_DATA));
        eci.add(new DERTaggedObject(true, 0, ASN1Primitive.fromByteArray(spcDer))); // [0] EXPLICIT 直接 SEQUENCE
        sd.add(new DERSequence(eci));
        ASN1EncodableVector certs = new ASN1EncodableVector();
        List<X509Certificate> ordered = (chain == null || chain.isEmpty())
                ? Collections.singletonList(cert) : chain;
        for (int i = ordered.size() - 1; i >= 0; i--) {   // 根在前
            certs.add(ASN1Primitive.fromByteArray(ordered.get(i).getEncoded()));
        }
        sd.add(new DERTaggedObject(false, 0, new DERSet(certs)));
        sd.add(new DERSet(ASN1Primitive.fromByteArray(signerInfoDer)));

        ASN1EncodableVector ci = new ASN1EncodableVector();
        ci.add(new ASN1ObjectIdentifier("1.2.840.113549.1.7.2"));  // pkcs7-signedData
        ci.add(new DERTaggedObject(true, 0, new DERSequence(sd)));
        return new DERSequence(ci).getEncoded();
    }

    /**
     * RFC3161 时间戳请求：POST 本机 MAIN /rfc3161（WEBPORT 从 PKI/CONFIG.txt 读取，默认 80）。
     * messageImprint 用 SHA-256。校验 PKIStatus，返回 TimeStampToken 的 ContentInfo DER。
     */
    static byte[] requestTimestamp(byte[] messageImprint, String baseDir) throws Exception {
        String port = "80";
        try {
            Path cfg = Paths.get(baseDir, "PKI", "CONFIG.txt");
            if (Files.exists(cfg)) {
                for (String line : Files.readAllLines(cfg, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.startsWith("WEBPORT=")) {
                        String v = t.substring("WEBPORT=".length()).trim();
                        if (!v.isEmpty()) {
                            port = v;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        String tsaUrl = "http://127.0.0.1:" + port + "/rfc3161";

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
        AlgorithmIdentifier hashAlg = new AlgorithmIdentifier(
                new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), DERNull.INSTANCE); // SHA-256
        TimeStampRequest tsReq = reqGen.generate(hashAlg, messageImprint);
        byte[] reqDer = tsReq.getEncoded();

        HttpURLConnection conn = (HttpURLConnection) new URL(tsaUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(20000);
        conn.setRequestProperty("Content-Type", "application/timestamp-query");
        conn.setRequestProperty("Content-Length", String.valueOf(reqDer.length));
        try (OutputStream os = conn.getOutputStream()) {
            os.write(reqDer);
        }
        int code = conn.getResponseCode();
        if (code != HttpURLConnection.HTTP_OK) {
            throw new IOException("TSA HTTP 状态码 " + code);
        }
        ByteArrayOutputStream resp = new ByteArrayOutputStream();
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                resp.write(buf, 0, n);
            }
        }
        TimeStampResponse tsResp = new TimeStampResponse(resp.toByteArray());
        int st = tsResp.getStatus();
        if (st != PKIStatus.GRANTED && st != PKIStatus.GRANTED_WITH_MODS) {
            throw new IOException("TSA 拒绝时间戳, PKIStatus=" + st);
        }
        TimeStampToken token = tsResp.getTimeStampToken();
        if (token == null) {
            throw new IOException("TSA 响应缺少时间戳令牌");
        }
        return token.getEncoded();
    }

    /** 去掉 DER SEQUENCE 的标签+长度头，返回内容字节（content octets）。 */
    static byte[] stripSequenceHeader(byte[] der) {
        if (der.length < 2 || (der[0] & 0xff) != 0x30) {
            return der;
        }
        int off = 1;
        int l = der[off++] & 0xff;
        if ((l & 0x80) != 0) {
            int n = l & 0x7f;
            l = 0;
            for (int i = 0; i < n; i++) {
                l = (l << 8) | (der[off + i] & 0xff);
            }
            off += n;
        }
        return Arrays.copyOfRange(der, off, off + l);
    }

    // ============================ EXE Authenticode 验证 ============================

    /**
     * 验证 PE 文件代码签名：CMS 签名有效、Authenticode 文件哈希一致、证书链可建立。
     * eContent 为直接 SEQUENCE（无 OCTET STRING），故先手工提取内容字节，再以带 signedContent
     * 的 CMSSignedData 构造验证（BC 才能按内容字节计算 messageDigest 比对）。
     */
    public static String verifyExe(byte[] exe) throws Exception {
        StringBuilder sb = new StringBuilder();
        if (exe.length < 0x40 || exe[0] != 'M' || exe[1] != 'Z') {
            return "[失败] 不是有效 PE 文件（缺 MZ 头）";
        }
        long eLfanew = readU32(exe, 0x3C);
        int magic = readU16(exe, (int) eLfanew + 24);
        boolean is64 = magic == 0x20B;
        int dataDirStart = is64 ? 112 : 96;
        long checksumOff = eLfanew + 24 + 64;
        long secDirOff = eLfanew + 24 + dataDirStart + 4 * 8;
        long certTableOffset = readU32(exe, (int) secDirOff);
        long certTableSize = readU32(exe, (int) secDirOff + 4);
        sb.append("PE格式: ").append(is64 ? "PE32+ (64位)" : "PE32 (32位)").append('\n');
        sb.append("Security Directory: offset=0x").append(Long.toHexString(certTableOffset))
                .append(" size=0x").append(Long.toHexString(certTableSize)).append('\n');
        if (certTableOffset == 0 || certTableSize == 0) {
            return sb.append("\n[结论] 该文件未包含代码签名证书表").toString();
        }
        if (certTableOffset + certTableSize > exe.length) {
            return sb.append("[失败] 证书表越界").toString();
        }

        byte[] certTable = Arrays.copyOfRange(exe, (int) certTableOffset,
                (int) (certTableOffset + certTableSize));
        long dwLength = readU32(certTable, 0);
        int wRevision = readU16(certTable, 4);
        int wCertType = readU16(certTable, 6);
        boolean winCertOk = dwLength == certTableSize && wRevision == 0x0200 && wCertType == 0x0002;
        sb.append("WIN_CERTIFICATE: dwLength=").append(dwLength)
                .append(" wRevision=0x").append(Integer.toHexString(wRevision))
                .append(" wCertificateType=0x").append(Integer.toHexString(wCertType))
                .append(" → ").append(winCertOk ? "符合规范" : "不符合规范").append('\n');
        int cmsLen = asn1ObjectTotalLength(certTable, 8);
        byte[] signedData = Arrays.copyOfRange(certTable, 8, 8 + cmsLen);
        sb.append("CMS 实际长度: ").append(cmsLen).append(" 字节（偏移 +8）\n");

        // 手工解析 ContentInfo → SignedData → encapContentInfo → eContent（直接 SEQUENCE）
        ASN1Sequence ci = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(signedData));
        ASN1TaggedObject sdTag = ASN1TaggedObject.getInstance(ci.getObjectAt(1));
        ASN1Sequence sd = ASN1Sequence.getInstance(sdTag.getBaseObject());
        ASN1Sequence eci = ASN1Sequence.getInstance(sd.getObjectAt(2));
        ASN1ObjectIdentifier eciType = ASN1ObjectIdentifier.getInstance(eci.getObjectAt(0));
        ASN1Primitive eContent = null;
        if (eci.size() > 1) {
            eContent = ASN1TaggedObject.getInstance(eci.getObjectAt(1)).getBaseObject().toASN1Primitive();
        }
        sb.append("\n[1] CMS SignedData 解析\n");
        sb.append("  contentType: ").append(eciType.getId())
                .append(OID_SPC_INDIRECT_DATA.equals(eciType.getId())
                        ? "  <-- spcIndirectDataContext (Authenticode)" : "")
                .append('\n');

        // 带 signedContent 的 CMSSignedData：content = eContent 内容字节（messageDigest 的哈希对象）
        CMSSignedData cms;
        if (eContent != null) {
            byte[] contentBytes = eContent instanceof ASN1OctetString
                    ? ((ASN1OctetString) eContent).getOctets()
                    : stripSequenceHeader(eContent.getEncoded("DER"));
            cms = new CMSSignedData(
                    new CMSProcessableByteArray(eciType, contentBytes), signedData);
        } else {
            cms = new CMSSignedData(signedData);
        }

        Collection<X509CertificateHolder> certs = cms.getCertificates().getMatches(null);
        sb.append("  证书数量: ").append(certs.size()).append('\n');
        JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
        for (X509CertificateHolder h : certs) {
            sb.append("    - ").append(h.getSubject()).append('\n');
        }

        SignerInformationStore sis = cms.getSignerInfos();
        if (sis.size() == 0) {
            return sb.append("[失败] 无 SignerInfo").toString();
        }
        SignerInformation si = sis.getSigners().iterator().next();
        Collection<X509CertificateHolder> matched = cms.getCertificates().getMatches(si.getSID());
        if (matched.isEmpty()) {
            return sb.append("[失败] 找不到签名者证书").toString();
        }
        X509Certificate signerCert = conv.getCertificate(matched.iterator().next());
        sb.append("  签名者证书: ").append(signerCert.getSubjectX500Principal()).append('\n');
        sb.append("  摘要算法: ").append(si.getDigestAlgOID())
                .append("  签名算法: ").append(si.getEncryptionAlgOID()).append('\n');
        boolean sigOk;
        try {
            sigOk = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build(signerCert));
            sb.append("  CMS 签名验证: ").append(sigOk ? "通过 ✓" : "失败 ✗").append('\n');
        } catch (Exception e) {
            sigOk = false;
            sb.append("  CMS 签名验证异常: ").append(e).append('\n');
        }

        // 时间戳检查（unsignedAttrs 中 SPC_RFC3161_TS）
        try {
            org.bouncycastle.asn1.cms.AttributeTable ua = si.getUnsignedAttributes();
            if (ua != null && ua.get(new ASN1ObjectIdentifier(OID_SPC_RFC3161_TS)) != null) {
                sb.append("  RFC3161 时间戳: 已嵌入（SPC_RFC3161_TS 1.3.6.1.4.1.311.3.3.1）\n");
            } else {
                sb.append("  RFC3161 时间戳: 未嵌入\n");
            }
        } catch (Exception e) {
            sb.append("  时间戳检查异常: ").append(e).append('\n');
        }

        // Authenticode 文件哈希比对
        sb.append("\n[2] Authenticode 文件哈希验证\n");
        String digestJca = digestJcaFromOid(si.getDigestAlgOID());
        sb.append("  摘要算法: ").append(digestJca).append('\n');
        MessageDigest md = MessageDigest.getInstance(digestJca);
        authenticodeDigest(md, exe, checksumOff, secDirOff, certTableOffset, certTableSize);
        byte[] computed = md.digest();
        sb.append("  计算摘要: ").append(Hex.toHexString(computed)).append('\n');
        byte[] embedded = null;
        try {
            byte[] spcDer = eContent.getEncoded("DER");
            ASN1Sequence spc = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(spcDer));
            ASN1Sequence digestInfo = ASN1Sequence.getInstance(spc.getObjectAt(1));
            embedded = ASN1OctetString.getInstance(digestInfo.getObjectAt(1)).getOctets();
            sb.append("  内嵌摘要: ").append(Hex.toHexString(embedded)).append('\n');
        } catch (Exception e) {
            sb.append("  内容摘要提取失败: ").append(e).append('\n');
        }
        boolean contentOk = embedded != null && MessageDigest.isEqual(computed, embedded);
        sb.append("  文件哈希比对: ").append(contentOk ? "通过 ✓" : "失败 ✗").append('\n');

        // 证书链验证（自签根检测）
        sb.append("\n[3] 证书链验证\n");
        boolean chainOk = verifyChain(sb, signerCert, certs, conv);
        sb.append("  证书链: ").append(chainOk ? "通过 ✓" : "失败 ✗").append('\n');

        sb.append("\n========================================\n");
        sb.append("最终结论: ").append((sigOk && contentOk && chainOk)
                ? "代码签名有效 ✓" : "代码签名无效 ✗").append('\n');
        return sb.toString();
    }

    /** 逐级验证签名证书 → 颁发者 → … → 自签根。 */
    private static boolean verifyChain(StringBuilder sb, X509Certificate signerCert,
                                       Collection<X509CertificateHolder> certs,
                                       JcaX509CertificateConverter conv) {
        if (signerCert == null) {
            sb.append("  无签名者证书，无法验证链\n");
            return false;
        }
        try {
            List<X509Certificate> pool = new ArrayList<>();
            for (X509CertificateHolder h : certs) {
                pool.add(conv.getCertificate(h));
            }
            X509Certificate cur = signerCert;
            int guard = 0;
            while (cur != null && guard++ < 32) {
                try {
                    cur.verify(cur.getPublicKey());
                    sb.append("  链顶: ").append(cur.getSubjectX500Principal()).append("（自签根）\n");
                    return true;
                } catch (Exception ignored) {
                }
                X509Certificate issuer = null;
                for (X509Certificate c : pool) {
                    try {
                        cur.verify(c.getPublicKey());
                        issuer = c;
                        break;
                    } catch (Exception ignored) {
                    }
                }
                if (issuer == null) {
                    sb.append("  链中断：").append(cur.getSubjectX500Principal())
                            .append(" 的颁发者不在 CMS 证书集中\n");
                    return false;
                }
                sb.append("  ").append(shortDn(cur.getSubjectX500Principal().toString()))
                        .append("\n    └─ 由 ").append(shortDn(issuer.getSubjectX500Principal().toString()))
                        .append(" 签发 ✓\n");
                cur = issuer;
            }
            return false;
        } catch (Exception e) {
            sb.append("  证书链验证失败: ").append(e).append('\n');
            return false;
        }
    }

    // ============================ PDF 签名（可选可见签章） ============================

    /**
     * 对 PDF 做标准 PKCS#7 detached 签名（adbe.pkcs7.detached）。
     * 基于 PDFBox 3.0.4 外部签名两段式：先得到 ByteRange 待签数据，签名后 setSignature 写入。
     *
     * @param imageBytes 可选签章图片（png/jpg/bmp/gif）；null 或空 = 不可见签名
     */
    public static byte[] signPdf(byte[] pdf, String keyType, X509Certificate cert,
                                 PrivateKey key, List<X509Certificate> chain,
                                 byte[] imageBytes) throws Exception {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            if (doc.isEncrypted()) {
                throw new IllegalArgumentException("加密 PDF 暂不支持签名");
            }
            PDSignature sig = new PDSignature();
            sig.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            sig.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            sig.setName(shortDn(cert.getSubjectX500Principal().toString()));
            sig.setLocation("MODPKICA");
            sig.setReason("MODPKICA PDF Document Signing");
            sig.setSignDate(Calendar.getInstance());

            SignatureOptions sigOptions = null;
            if (imageBytes != null && imageBytes.length > 0) {
                sigOptions = buildVisibleSignatureOptions(doc, imageBytes);
            }
            if (sigOptions != null) {
                doc.addSignature(sig, sigOptions);
            } else {
                doc.addSignature(sig);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ExternalSigningSupport es = doc.saveIncrementalForExternalSigning(out);
            byte[] toSign = readAllBytes(es.getContent());
            if (toSign.length == 0) {
                throw new IOException("PDFBox 未提供待签名数据（ByteRange 为空）");
            }
            // PDF 签名：eContentType = id-data，分离签名，messageDigest = ByteRange 数据哈希
            byte[] cms = buildCms(toSign, "1.2.840.113549.1.7.1", false,
                    keyType, cert, key, chain);
            es.setSignature(cms);
            return out.toByteArray();
        }
    }

    /**
     * 构建可见签章选项（参考 java-lening 的 SignatureOptions 外观文档模式）：
     * 独立外观 PDF 内放置带 Rect 与 AP 的签名 widget，PDFBox 会把 Rect/外观搬到
     * 主文档第 1 页右下角，避免在 addSignature 之后改动文档破坏 ByteRange。
     */
    private static SignatureOptions buildVisibleSignatureOptions(PDDocument doc,
                                                                 byte[] imageBytes) throws Exception {
        BufferedImage bi = ImageIO.read(new ByteArrayInputStream(imageBytes));
        if (bi == null) {
            throw new IllegalArgumentException("无法解码签章图片（支持 png/jpg/bmp/gif）");
        }
        float imgW = bi.getWidth();
        float imgH = bi.getHeight();
        float maxW = 150f;
        float maxH = 80f;
        float scale = Math.min(maxW / imgW, maxH / imgH);
        float w = Math.max(20f, imgW * scale);
        float h = Math.max(14f, imgH * scale);

        // 主文档第 1 页右下角的签章矩形（PDF 坐标系原点在左下）
        PDPage page = doc.getPage(0);
        float pageW = page.getMediaBox().getWidth();
        float pageH = page.getMediaBox().getHeight();
        float x = pageW - w - 30f;
        float y = 30f;
        if (y + h > pageH) {
            y = Math.max(0f, pageH - h - 5f);
        }
        PDRectangle rect = new PDRectangle(x, y, w, h);

        // 独立外观文档：签章图 + 文本，widget 带 Rect 与 AP（PDFBox 会拷贝到主文档）
        PDDocument visDoc = new PDDocument();
        try {
            PDPage visPage = new PDPage(new PDRectangle(w, h));
            visDoc.addPage(visPage);

            PDAppearanceStream aps = new PDAppearanceStream(visDoc);
            aps.setBBox(new PDRectangle(w, h));
            aps.setResources(new PDResources());
            PDImageXObject img = PDImageXObject.createFromByteArray(visDoc, imageBytes, "MODPKICA_STAMP");
            try (org.apache.pdfbox.pdmodel.PDPageContentStream pcs =
                         new org.apache.pdfbox.pdmodel.PDPageContentStream(visDoc, aps)) {
                pcs.drawImage(img, 0, 0, w, h);
                pcs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 7);
                pcs.beginText();
                pcs.newLineAtOffset(2, 2);
                pcs.showText("Signed by MODPKICA");
                pcs.endText();
            }

            PDAnnotationWidget visWidget = new PDAnnotationWidget();
            visWidget.setRectangle(rect);
            visWidget.getCOSObject().setItem(COSName.FT, COSName.SIG);
            PDAppearanceDictionary ad = new PDAppearanceDictionary();
            ad.setNormalAppearance(aps);
            visWidget.setAppearance(ad);
            visPage.getAnnotations().add(visWidget);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            visDoc.save(baos);
            byte[] visPdfBytes = baos.toByteArray();

            SignatureOptions so = new SignatureOptions();
            so.setPage(0);
            so.setVisualSignature(new ByteArrayInputStream(visPdfBytes));
            return so;
        } finally {
            visDoc.close();
        }
    }

    /** 生成 CMS SignedData（PDF detached 用 BC 生成器即可，标准 id-data 结构）。 */
    private static byte[] buildCms(byte[] content, String contentType, boolean encapsulate,
                                   String keyType, X509Certificate cert, PrivateKey key,
                                   List<X509Certificate> chain) throws Exception {
        ContentSigner signer = CertUtil.createContentSigner(key, keyType, digestName(keyType));
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        SignerInfoGeneratorBuilder b = new SignerInfoGeneratorBuilder(dcp);
        SignerInfoGenerator sigGen = b.build(signer, new JcaX509CertificateHolder(cert));

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(sigGen);
        gen.addCertificates(new JcaCertStore(chain != null && !chain.isEmpty() ? chain
                : Collections.singletonList(cert)));

        CMSTypedData cmsContent = new CMSTypedData() {
            @Override
            public ASN1ObjectIdentifier getContentType() {
                return new ASN1ObjectIdentifier(contentType);
            }

            @Override
            public void write(OutputStream out) throws IOException {
                out.write(content);
            }

            @Override
            public Object getContent() {
                return content;
            }
        };
        CMSSignedData signed = gen.generate(cmsContent, encapsulate);
        return signed.getEncoded("DER");
    }

    // ============================ PDF 验证 ============================

    /** 验证 PDF 签名：CMS 签名、ByteRange 摘要比对、证书链。 */
    public static String verifyPdf(byte[] pdf) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            List<PDSignature> sigs = doc.getSignatureDictionaries();
            if (sigs == null || sigs.isEmpty()) {
                return "未找到 PDF 签名";
            }
            sb.append("PDF 页数: ").append(doc.getNumberOfPages()).append('\n');
            sb.append("签名数量: ").append(sigs.size()).append('\n');
            PDSignature sig = sigs.get(0);
            sb.append("签名者: ").append(printable(sig.getName())).append('\n');
            sb.append("原因: ").append(printable(sig.getReason())).append('\n');
            if (sig.getSignDate() != null) {
                sb.append("签名时间: ").append(sig.getSignDate().getTime()).append('\n');
            }
            sb.append("SubFilter: ").append(sig.getSubFilter()).append('\n');

            byte[] contents = sig.getContents();
            if (contents == null || contents.length == 0) {
                return sb.append("[失败] 无签名内容").toString();
            }
            int realLen = contents.length;
            while (realLen > 0 && contents[realLen - 1] == 0) {
                realLen--;
            }
            byte[] cmsBytes = Arrays.copyOf(contents, realLen);
            sb.append("签名区长度: ").append(contents.length)
                    .append(" 字节（去除填充后 ").append(cmsBytes.length).append(" 字节）\n");
            int[] br = sig.getByteRange();
            if (br == null || br.length != 4 || br[1] <= 0) {
                return sb.append("[失败] ByteRange 缺失或非法").toString();
            }
            sb.append("ByteRange: [").append(br[0]).append(", ").append(br[1])
                    .append(", ").append(br[2]).append(", ").append(br[3]).append("]\n");

            ByteArrayOutputStream rangeOut = new ByteArrayOutputStream();
            rangeOut.write(pdf, (int) br[0], (int) br[1]);
            rangeOut.write(pdf, (int) br[2], (int) br[3]);
            byte[] range = rangeOut.toByteArray();
            sb.append("待签名数据长度: ").append(range.length).append(" 字节\n");

            CMSSignedData cms;
            try {
                cms = new CMSSignedData(new CMSProcessableByteArray(range), cmsBytes);
            } catch (Exception e) {
                return sb.append("[失败] CMS 解析异常: ").append(e).toString();
            }
            sb.append("contentType: ").append(cms.getSignedContentTypeOID()).append('\n');

            SignerInformationStore sis = cms.getSignerInfos();
            if (sis.size() == 0) {
                return sb.append("[失败] 无 SignerInfo").toString();
            }
            SignerInformation si = sis.getSigners().iterator().next();
            JcaX509CertificateConverter conv = new JcaX509CertificateConverter().setProvider("BC");
            Collection<X509CertificateHolder> certs = cms.getCertificates().getMatches(null);
            sb.append("证书数量: ").append(certs.size()).append('\n');
            X509Certificate signerCert = null;
            Collection<X509CertificateHolder> matched = cms.getCertificates().getMatches(si.getSID());
            if (!matched.isEmpty()) {
                signerCert = conv.getCertificate(matched.iterator().next());
                sb.append("签名者证书: ").append(signerCert.getSubjectX500Principal()).append('\n');
            }
            sb.append("摘要算法: ").append(si.getDigestAlgOID())
                    .append("  签名算法: ").append(si.getEncryptionAlgOID()).append('\n');

            boolean sigOk = false;
            if (signerCert != null) {
                try {
                    sigOk = si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                            .build(signerCert));
                } catch (Exception e) {
                    sb.append("  签名验证异常: ").append(e).append('\n');
                }
            }
            sb.append("CMS 签名验证: ").append(sigOk ? "通过 ✓" : "失败 ✗").append('\n');

            String digestJca = digestJcaFromOid(si.getDigestAlgOID());
            MessageDigest md = MessageDigest.getInstance(digestJca);
            byte[] calc = md.digest(range);
            byte[] msgDigest = si.getContentDigest();
            boolean hashOk = msgDigest != null && MessageDigest.isEqual(calc, msgDigest);
            sb.append("文档摘要(").append(digestJca).append("): ").append(Hex.toHexString(calc)).append('\n');
            sb.append("messageDigest      : ")
                    .append(Hex.toHexString(msgDigest == null ? new byte[0] : msgDigest)).append('\n');
            sb.append("文档摘要比对: ").append(hashOk ? "通过 ✓" : "失败 ✗").append('\n');

            sb.append("\n[3] 证书链验证\n");
            boolean chainOk = false;
            if (signerCert != null) {
                chainOk = verifyChain(sb, signerCert, certs, conv);
            } else {
                sb.append("  无签名者证书，无法验证链\n");
            }
            sb.append("  证书链: ").append(chainOk ? "通过 ✓" : "失败 ✗").append('\n');

            sb.append("\n========================================\n");
            sb.append("最终结论: ").append((sigOk && hashOk && chainOk)
                    ? "PDF 签名有效 ✓" : "PDF 签名无效 ✗").append('\n');
            return sb.toString();
        }
    }

    // ============================ 工具方法 ============================

    private static String shortDn(String dn) {
        if (dn != null && dn.length() > 120) {
            return dn.substring(0, 120) + "...";
        }
        return dn;
    }

    private static String printable(String s) {
        return s == null || s.isEmpty() ? "(未填写)" : s;
    }

    /** 解析 DER SEQUENCE 对象实际编码总长度（tag + 长度字段 + content），从指定偏移开始。 */
    private static int asn1ObjectTotalLength(byte[] d, int off) {
        int idx = off + 1; // 跳过 tag(0x30)
        int len = d[idx] & 0xFF;
        if ((len & 0x80) != 0) {
            int nb = len & 0x7F;
            len = 0;
            for (int i = 0; i < nb; i++) {
                len = (len << 8) | (d[idx + 1 + i] & 0xFF);
            }
            idx += nb;
        }
        return idx + 1 + len - off;
    }

    private static int readU16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long readU32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private static void writeU32(byte[] b, int off, int val) {
        b[off] = (byte) (val & 0xFF);
        b[off + 1] = (byte) ((val >>> 8) & 0xFF);
        b[off + 2] = (byte) ((val >>> 16) & 0xFF);
        b[off + 3] = (byte) ((val >>> 24) & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, int val) {
        out.write(val & 0xFF);
        out.write((val >>> 8) & 0xFF);
        out.write((val >>> 16) & 0xFF);
        out.write((val >>> 24) & 0xFF);
    }

    private static void writeU16(ByteArrayOutputStream out, int val) {
        out.write(val & 0xFF);
        out.write((val >>> 8) & 0xFF);
    }

    private static byte[] readAllBytes(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
