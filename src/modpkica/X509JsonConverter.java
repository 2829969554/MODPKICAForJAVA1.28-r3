package modpkica;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * X.509 PEM 证书 <-> JSON 结构文本 双向无损转换器
 *
 * 设计原则：
 *   1. JSON 纯可视化数据，不含任何 DER/hex 编码的扩展值字段
 *   2. DN(issuer/subject) 以 OID 为主键，每个属性含 name/value/encoding
 *   3. v3 扩展以 OID 为主键，每个扩展含 critical/name 及扩展特有字段
 *   4. 字节级无损：通过保留字符串编码类型、时间类型、BIT STRING unusedBits、
 *      AlgorithmIdentifier parameters 等元数据精确重建 ASN.1
 *   5. SCT 扩展(1.3.6.1.4.1.11129.2.4.2)按 RFC6962 解析为结构化字段
 *
 * 编译：javac -cp "BC185/*" X509JsonConverter.java
 * 运行：java  -cp ".;BC185/*" X509JsonConverter <mode> <input> <output>
 */
public class X509JsonConverter {

    private static final String VERSION = "1.0.0";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ==================== 主入口 ====================

    public static void main(String[] args) throws Exception {
        // 帮助请求
        if (args.length == 0 || isHelpArg(args[0])) {
            printUsage();
            System.exit(args.length == 0 ? 1 : 0);
        }

        String mode = args[0];

        // 模式校验
        if (!"toJson".equals(mode) && !"toCert".equals(mode) && !"roundtrip".equals(mode) && !"rekey".equals(mode)) {
            System.err.println("[ERROR] Unknown mode: " + mode);
            System.err.println();
            printUsage();
            System.exit(1);
        }

        // 参数数量校验
        if (args.length < 3) {
            System.err.println("[ERROR] Mode '" + mode + "' requires <input> and <output> arguments.");
            System.err.println();
            printUsage();
            System.exit(1);
        }

        String input = args[1];
        String output = args[2];

        // 输入文件存在性校验
        if (!Files.exists(Paths.get(input))) {
            System.err.println("[ERROR] Input file not found: " + input);
            System.exit(1);
        }

        switch (mode) {
            case "toJson": {
                byte[] pemBytes = Files.readAllBytes(Paths.get(input));
                String json = certToJson(pemBytes);
                Files.write(Paths.get(output), json.getBytes(StandardCharsets.UTF_8));
                System.out.println("[OK] PEM -> JSON");
                System.out.println("     input : " + input + " (" + pemBytes.length + " bytes)");
                System.out.println("     output: " + output + " (" + json.getBytes(StandardCharsets.UTF_8).length + " bytes)");
                break;
            }
            case "toCert": {
                String json = new String(Files.readAllBytes(Paths.get(input)), StandardCharsets.UTF_8);
                byte[] pemBytes = jsonToCertPem(json);
                Files.write(Paths.get(output), pemBytes);
                System.out.println("[OK] JSON -> PEM");
                System.out.println("     input : " + input + " (" + json.length() + " chars)");
                System.out.println("     output: " + output + " (" + pemBytes.length + " bytes)");
                break;
            }
            case "roundtrip": {
                byte[] originalPem = Files.readAllBytes(Paths.get(input));
                String json = certToJson(originalPem);
                Files.write(Paths.get(output), json.getBytes(StandardCharsets.UTF_8));
                System.out.println("[STEP 1] PEM -> JSON: " + output);

                byte[] regenPem = jsonToCertPem(json);
                byte[] origDer = pemToDer(originalPem);
                byte[] regenDer = pemToDer(regenPem);
                boolean match = Arrays.equals(origDer, regenDer);

                System.out.println("[STEP 2] JSON -> PEM (regenerated)");
                System.out.println("[VERIFY] original DER length     = " + origDer.length);
                System.out.println("[VERIFY] regenerated DER length  = " + regenDer.length);
                System.out.println("[VERIFY] byte-level match        = " + match);

                if (!match) {
                    System.err.println();
                    System.err.println("[FAIL] DER mismatch! Conversion is NOT lossless.");
                    int minLen = Math.min(origDer.length, regenDer.length);
                    for (int i = 0; i < minLen; i++) {
                        if (origDer[i] != regenDer[i]) {
                            System.err.printf("        first diff at offset %d: orig=0x%02x regen=0x%02x%n",
                                    i, origDer[i] & 0xFF, regenDer[i] & 0xFF);
                            // 输出上下文（前后各8字节）
                            int ctxStart = Math.max(0, i - 8);
                            int ctxEnd = Math.min(minLen, i + 9);
                            System.err.print("        orig  context: ");
                            for (int j = ctxStart; j < ctxEnd; j++) System.err.printf("%02x ", origDer[j] & 0xFF);
                            System.err.println();
                            System.err.print("        regen context: ");
                            for (int j = ctxStart; j < ctxEnd; j++) System.err.printf("%02x ", regenDer[j] & 0xFF);
                            System.err.println();
                            break;
                        }
                    }
                    if (origDer.length != regenDer.length) {
                        System.err.println("        length differs by " + Math.abs(origDer.length - regenDer.length) + " bytes");
                    }
                    System.exit(2);
                }
                System.out.println("[PASS] Round-trip is lossless — DER byte-for-byte identical.");
                break;
            }
            case "rekey": {
                String json = new String(Files.readAllBytes(Paths.get(input)), StandardCharsets.UTF_8);
                System.out.println("[STEP 1] Generating new key pair and re-signing...");
                byte[] newPem = rekeyJsonToPem(json);
                Files.write(Paths.get(output), newPem);
                System.out.println("[OK] Rekey complete — new key pair, new signature");
                System.out.println("     input : " + input + " (" + json.length() + " chars JSON)");
                System.out.println("     output: " + output + " (" + newPem.length + " bytes PEM)");
                break;
            }
        }
    }

    private static boolean isHelpArg(String arg) {
        return "-h".equals(arg) || "--help".equals(arg) || "help".equals(arg) || "/?".equals(arg);
    }

    private static void printUsage() {
        System.out.println("╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║  X509JsonConverter v" + VERSION + " — X.509 PEM <-> JSON 双向无损转换器  ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("USAGE:");
        System.out.println("  java -cp \".;BC185/*\" X509JsonConverter <mode> <input> <output>");
        System.out.println();
        System.out.println("MODES:");
        System.out.println("  toJson     <input.pem>  <output.json>");
        System.out.println("             将 PEM 证书转换为 JSON 结构文本");
        System.out.println("             - DN(issuer/subject) 以 OID 为主键");
        System.out.println("             - v3 扩展以 OID 为主键，含结构化解析");
        System.out.println("             - SCT 扩展按 RFC6962 解析为可读字段");
        System.out.println("             - 保留 encoding/type/unusedBits 等无损元数据");
        System.out.println();
        System.out.println("  toCert     <input.json> <output.pem>");
        System.out.println("             将 JSON 结构文本还原为 PEM 证书");
        System.out.println("             - 从结构化数据精确重建 ASN.1 DER");
        System.out.println("             - 输出与原始证书字节级一致");
        System.out.println();
        System.out.println("  roundtrip  <input.pem>  <output.json>");
        System.out.println("             PEM -> JSON -> PEM 完整往返验证");
        System.out.println("             - 生成 JSON 到 output.json");
        System.out.println("             - 自动重建 PEM 并对比 DER 字节");
        System.out.println("             - 验证无损性，不匹配时输出首个差异位置");
        System.out.println();
        System.out.println("  rekey      <input.json> <output.pem>");
        System.out.println("             密钥替换：生成同类型新密钥对并重签证书");
        System.out.println("             - 按 JSON 中密钥算法(RSA/EC/SM2/Ed25519...)生成新密钥对");
        System.out.println("             - 新公钥写入 subjectPublicKeyInfo.publicKey");
        System.out.println("             - 用新私钥对 TBSCertificate 重新签名");
        System.out.println("             - 新签名写入 signatureValue，输出 PEM 证书");
        System.out.println();
        System.out.println("OPTIONS:");
        System.out.println("  -h, --help, help    显示此帮助信息");
        System.out.println();
        System.out.println("JSON STRUCTURE (key fields):");
        System.out.println("  version              证书版本 (v1/v2/v3)");
        System.out.println("  serialNumber         序列号 (偶数长度小写 hex)");
        System.out.println("  signature            TBS 内签名算法 {algorithm, name, parameters}");
        System.out.println("  issuer               颁发者 DN，OID 主键 {name, value, encoding}");
        System.out.println("  validity             {notBefore:{type,value}, notAfter:{type,value}}");
        System.out.println("  subject              主体 DN，OID 主键");
        System.out.println("  subjectPublicKeyInfo {algorithm:{...}, publicKey:hex}");
        System.out.println("  extensions           v3 扩展，OID 主键 {critical, name, ...}");
        System.out.println("  signatureAlgorithm   证书签名算法");
        System.out.println("  signatureValue       签名值 hex");
        System.out.println();
        System.out.println("LOSSLESS GUARANTEE:");
        System.out.println("  转换通过保留以下元数据实现字节级无损：");
        System.out.println("  - DN 属性值编码: PrintableString / UTF8String / IA5String /");
        System.out.println("    TeletexString / BMPString / UniversalString / NumericString / VisibleString");
        System.out.println("  - 时间编码: UTCTime / GeneralizedTime");
        System.out.println("  - BIT STRING unusedBits (签名值、唯一标识符)");
        System.out.println("  - AlgorithmIdentifier parameters (NULL / null / hex)");
        System.out.println("  - 扩展值通过结构化字段精确重建，不依赖原始 DER");
        System.out.println();
        System.out.println("EXAMPLES:");
        System.out.println("  # 证书转 JSON");
        System.out.println("  java -cp \".;BC185/*\" X509JsonConverter toJson demo.crt demo.json");
        System.out.println();
        System.out.println("  # JSON 还原证书");
        System.out.println("  java -cp \".;BC185/*\" X509JsonConverter toCert demo.json rebuilt.crt");
        System.out.println();
        System.out.println("  # 往返验证（推荐首次使用时运行）");
        System.out.println("  java -cp \".;BC185/*\" X509JsonConverter roundtrip demo.crt demo.json");
        System.out.println();
        System.out.println("REQUIRES: BouncyCastle 1.85 (bcprov + bcpkix + bcutil)");
    }

    // ==================== 工具 ====================

    static byte[] pemToDer(byte[] pemBytes) throws Exception {
        PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(pemBytes), StandardCharsets.UTF_8));
        PemObject obj = reader.readPemObject();
        reader.close();
        if (obj == null) throw new IOException("Invalid PEM");
        return obj.getContent();
    }

    static String derToPem(byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der);
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    static String toHex(byte[] bytes) { return Hex.toHexString(bytes); }
    static byte[] fromHex(String hex) { return Hex.decode(hex); }

    /** BigInteger -> 偶数长度小写 hex（补前导零），与 ASN.1 INTEGER 原始字节一致 */
    static String toHexEven(BigInteger bi) {
        String hex = bi.toString(16);
        if (hex.length() % 2 != 0) hex = "0" + hex;
        return hex;
    }

    // ==================== OID 名称映射（仅用于可读性） ====================

    static final Map<String, String> ATTR_NAMES = new HashMap<>();
    static final Map<String, String> EXT_NAMES = new HashMap<>();
    static final Map<String, String> SIG_ALG_NAMES = new HashMap<>();
    static final Map<String, String> KEY_ALG_NAMES = new HashMap<>();
    static final Map<String, String> EKU_NAMES = new HashMap<>();
    static final Map<String, String> AIA_METHODS = new HashMap<>();
    static final Map<String, String> GN_TYPES = new HashMap<>();

    static {
        ATTR_NAMES.put("2.5.4.3", "CN");
        ATTR_NAMES.put("2.5.4.6", "C");
        ATTR_NAMES.put("2.5.4.7", "L");
        ATTR_NAMES.put("2.5.4.8", "ST");
        ATTR_NAMES.put("2.5.4.10", "O");
        ATTR_NAMES.put("2.5.4.11", "OU");
        ATTR_NAMES.put("2.5.4.12", "T");
        ATTR_NAMES.put("2.5.4.4", "SN");
        ATTR_NAMES.put("2.5.4.42", "GN");
        ATTR_NAMES.put("2.5.4.5", "serialNumber");
        ATTR_NAMES.put("2.5.4.9", "street");
        ATTR_NAMES.put("2.5.4.15", "businessCategory");
        ATTR_NAMES.put("2.5.4.17", "postalCode");
        ATTR_NAMES.put("2.5.4.97", "organizationIdentifier");
        ATTR_NAMES.put("1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL");
        ATTR_NAMES.put("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST");
        ATTR_NAMES.put("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC");
        ATTR_NAMES.put("0.9.2342.19200300.100.1.25", "DC");
        ATTR_NAMES.put("0.9.2342.19200300.100.1.1", "UID");
        ATTR_NAMES.put("1.2.840.113549.1.9.1", "emailAddress");

        EXT_NAMES.put("2.5.29.14", "SubjectKeyIdentifier");
        EXT_NAMES.put("2.5.29.35", "AuthorityKeyIdentifier");
        EXT_NAMES.put("2.5.29.17", "SubjectAltName");
        EXT_NAMES.put("2.5.29.18", "IssuerAltName");
        EXT_NAMES.put("2.5.29.15", "KeyUsage");
        EXT_NAMES.put("2.5.29.37", "ExtendedKeyUsage");
        EXT_NAMES.put("2.5.29.19", "BasicConstraints");
        EXT_NAMES.put("2.5.29.31", "CRLDistributionPoints");
        EXT_NAMES.put("2.5.29.32", "CertificatePolicies");
        EXT_NAMES.put("1.3.6.1.5.5.7.1.1", "AuthorityInfoAccess");
        EXT_NAMES.put("1.3.6.1.5.5.7.1.11", "SubjectInfoAccess");
        EXT_NAMES.put("2.5.29.30", "NameConstraints");
        EXT_NAMES.put("2.5.29.36", "PolicyConstraints");
        EXT_NAMES.put("2.5.29.33", "PolicyMappings");
        EXT_NAMES.put("2.5.29.54", "InhibitAnyPolicy");
        EXT_NAMES.put("2.5.29.46", "FreshestCRL");
        EXT_NAMES.put("2.5.29.9", "SubjectDirectoryAttributes");
        EXT_NAMES.put("2.5.29.16", "PrivateKeyUsagePeriod");
        EXT_NAMES.put("2.5.29.28", "IssuingDistributionPoint");
        EXT_NAMES.put("1.3.6.1.5.5.7.1.48", "OCSPNoCheck");
        EXT_NAMES.put("1.3.6.1.4.1.11129.2.4.2", "CTPrecertificateSCTs");
        EXT_NAMES.put("2.16.840.1.113730.1.1", "NetscapeCertType");

        SIG_ALG_NAMES.put("1.2.840.113549.1.1.5", "SHA1withRSA");
        SIG_ALG_NAMES.put("1.2.840.113549.1.1.11", "SHA256withRSA");
        SIG_ALG_NAMES.put("1.2.840.113549.1.1.12", "SHA384withRSA");
        SIG_ALG_NAMES.put("1.2.840.113549.1.1.13", "SHA512withRSA");
        SIG_ALG_NAMES.put("1.2.840.113549.1.1.14", "SHA224withRSA");
        SIG_ALG_NAMES.put("1.2.840.113549.1.1.10", "RSASSA-PSS");
        SIG_ALG_NAMES.put("1.2.840.10045.4.1", "SHA1withECDSA");
        SIG_ALG_NAMES.put("1.2.840.10045.4.3.2", "SHA256withECDSA");
        SIG_ALG_NAMES.put("1.2.840.10045.4.3.3", "SHA384withECDSA");
        SIG_ALG_NAMES.put("1.2.840.10045.4.3.4", "SHA512withECDSA");
        SIG_ALG_NAMES.put("1.3.101.112", "Ed25519");
        SIG_ALG_NAMES.put("1.3.101.113", "Ed448");

        KEY_ALG_NAMES.put("1.2.840.113549.1.1.1", "RSA");
        KEY_ALG_NAMES.put("1.2.840.10045.2.1", "EC");
        KEY_ALG_NAMES.put("1.3.101.112", "Ed25519");
        KEY_ALG_NAMES.put("1.3.101.113", "Ed448");
        KEY_ALG_NAMES.put("1.2.840.10040.4.1", "DSA");
        KEY_ALG_NAMES.put("1.3.101.110", "X25519");
        KEY_ALG_NAMES.put("1.3.101.111", "X448");

        EKU_NAMES.put("1.3.6.1.5.5.7.3.1", "serverAuth");
        EKU_NAMES.put("1.3.6.1.5.5.7.3.2", "clientAuth");
        EKU_NAMES.put("1.3.6.1.5.5.7.3.3", "codeSigning");
        EKU_NAMES.put("1.3.6.1.5.5.7.3.4", "emailProtection");
        EKU_NAMES.put("1.3.6.1.5.5.7.3.8", "timeStamping");
        EKU_NAMES.put("1.3.6.1.5.5.7.3.9", "OCSPSigning");

        AIA_METHODS.put("1.3.6.1.5.5.7.48.1", "OCSP");
        AIA_METHODS.put("1.3.6.1.5.5.7.48.2", "caIssuers");
        AIA_METHODS.put("1.3.6.1.5.5.7.48.3", "timeStamping");

        GN_TYPES.put("0", "otherName");
        GN_TYPES.put("1", "rfc822Name");
        GN_TYPES.put("2", "dNSName");
        GN_TYPES.put("3", "x400Address");
        GN_TYPES.put("4", "directoryName");
        GN_TYPES.put("5", "ediPartyName");
        GN_TYPES.put("6", "uniformResourceIdentifier");
        GN_TYPES.put("7", "iPAddress");
        GN_TYPES.put("8", "registeredID");
    }

    // ==================== PEM -> JSON ====================

    @SuppressWarnings("unchecked")
    public static String certToJson(byte[] pemBytes) throws Exception {
        byte[] der = pemToDer(pemBytes);
        ASN1InputStream ais = new ASN1InputStream(der);
        Certificate cert = Certificate.getInstance(ais.readObject());
        ais.close();
        TBSCertificate tbs = cert.getTBSCertificate();

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", "v" + (tbs.getVersion().getValue().intValue() + 1));
        root.put("serialNumber", toHexEven(tbs.getSerialNumber().getValue()));
        root.put("signature", algIdToJson(tbs.getSignature()));
        root.put("issuer", dnToJson(tbs.getIssuer()));
        root.put("validity", validityToJson(tbs));
        root.put("subject", dnToJson(tbs.getSubject()));
        root.put("subjectPublicKeyInfo", spkiToJson(tbs.getSubjectPublicKeyInfo()));

        ASN1BitString iuid = tbs.getIssuerUniqueId();
        root.put("issuerUniqueId", iuid != null ? toHex(iuid.getBytes()) : null);
        ASN1BitString suid = tbs.getSubjectUniqueId();
        root.put("subjectUniqueId", suid != null ? toHex(suid.getBytes()) : null);

        // 扩展：OID 主键
        Map<String, Object> exts = new LinkedHashMap<>();
        Extensions extensions = tbs.getExtensions();
        if (extensions != null) {
            Enumeration<?> oids = extensions.oids();
            while (oids.hasMoreElements()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) oids.nextElement();
                Extension ext = extensions.getExtension(oid);
                exts.put(oid.getId(), extensionToJson(ext));
            }
        }
        root.put("extensions", exts);

        root.put("signatureAlgorithm", algIdToJson(cert.getSignatureAlgorithm()));
        ASN1BitString sigBits = cert.getSignature();
        root.put("signatureValue", toHex(sigBits.getBytes()));
        if (sigBits.getPadBits() != 0) root.put("signatureValueUnusedBits", sigBits.getPadBits());

        return toJson(root);
    }

    static Map<String, Object> algIdToJson(AlgorithmIdentifier algId) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        String oid = algId.getAlgorithm().getId();
        r.put("algorithm", oid);
        r.put("name", SIG_ALG_NAMES.getOrDefault(oid, KEY_ALG_NAMES.getOrDefault(oid, oid)));
        ASN1Encodable p = algId.getParameters();
        if (p == null) r.put("parameters", null);
        else if (p instanceof DERNull) r.put("parameters", "NULL");
        else r.put("parameters", toHex(p.toASN1Primitive().getEncoded()));
        return r;
    }

    /**
     * DN 序列化为有序 RDN 数组（新格式，支持多值 RDN 无损）：
     *   [ [ {oid,name,value,encoding}, ... ], ... ]  每个元素是一个 RDN，RDN 内为 ATV 数组
     */
    static Object dnToJson(X500Name name) {
        List<Object> rdnList = new ArrayList<>();
        for (RDN rdn : name.getRDNs()) {
            AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
            List<Object> atvList = new ArrayList<>();
            for (AttributeTypeAndValue atv : atvs) {
                Map<String, Object> m = new LinkedHashMap<>();
                String oid = atv.getType().getId();
                m.put("oid", oid);
                m.put("name", ATTR_NAMES.getOrDefault(oid, oid));
                m.put("value", atv.getValue().toString());
                m.put("encoding", encodingName(atv.getValue()));
                atvList.add(m);
            }
            rdnList.add(atvList);
        }
        return rdnList;
    }

    static String encodingName(ASN1Encodable v) {
        String cn = v.getClass().getSimpleName();
        if (cn.contains("PrintableString")) return "PrintableString";
        if (cn.contains("UTF8String")) return "UTF8String";
        if (cn.contains("IA5String")) return "IA5String";
        if (cn.contains("T61String") || cn.contains("TeletexString")) return "TeletexString";
        if (cn.contains("UniversalString")) return "UniversalString";
        if (cn.contains("BMPString")) return "BMPString";
        if (cn.contains("NumericString")) return "NumericString";
        if (cn.contains("VisibleString")) return "VisibleString";
        return cn;
    }

    static Map<String, Object> validityToJson(TBSCertificate tbs) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("notBefore", timeToJson(tbs.getStartDate()));
        r.put("notAfter", timeToJson(tbs.getEndDate()));
        return r;
    }

    static Map<String, Object> timeToJson(Time time) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        ASN1Primitive p = time.toASN1Primitive();
        String type = p instanceof ASN1UTCTime ? "UTCTime" : "GeneralizedTime";
        r.put("type", type);
        // raw：时间节点的 DER 编码 hex，保留秒/小数秒/时区细节，确保字节级无损
        r.put("raw", toHex(p.getEncoded()));
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        r.put("value", sdf.format(time.getDate()));
        return r;
    }

    static Map<String, Object> spkiToJson(SubjectPublicKeyInfo spki) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("algorithm", algIdToJson(spki.getAlgorithm()));
        r.put("publicKey", toHex(spki.getPublicKeyData().getBytes()));
        return r;
    }

    static Map<String, Object> extensionToJson(Extension ext) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        String oid = ext.getExtnId().getId();
        r.put("critical", ext.isCritical());
        r.put("name", EXT_NAMES.getOrDefault(oid, "Unknown"));
        if ("1.3.6.1.4.1.11129.2.4.2".equals(oid)) {
            // SCT List: extnValue 是双重 OCTET STRING，getParsedValue() 解出内层 TLS 数据
            byte[] tlsData = ((ASN1OctetString) ext.getParsedValue()).getOctets();
            r.putAll(parseSCTList(tlsData));
        } else {
            ASN1Encodable parsed = ext.getParsedValue();
            if (parsed != null) {
                Map<String, Object> val = parseExtensionValue(oid, parsed.toASN1Primitive());
                if (val != null) r.putAll(val);
            }
        }
        return r;
    }

    /** 解析扩展值，返回扩展特有字段（不含 critical/name） */
    static Map<String, Object> parseExtensionValue(String oid, ASN1Primitive obj) throws Exception {
        switch (oid) {
            case "2.5.29.14": return parseSKI(obj);
            case "2.5.29.35": return parseAKI(obj);
            case "2.5.29.17": case "2.5.29.18": return parseGeneralNamesExt(obj);
            case "2.5.29.15": return parseKeyUsage(obj);
            case "2.5.29.37": return parseEKU(obj);
            case "2.5.29.19": return parseBasicConstraints(obj);
            case "2.5.29.31": case "2.5.29.46": return parseCRLDP(obj);
            case "2.5.29.32": return parseCertPolicies(obj);
            case "1.3.6.1.5.5.7.1.1": case "1.3.6.1.5.5.7.1.11": return parseAIA(obj);
            case "2.5.29.30": return parseNameConstraints(obj);
            case "2.5.29.36": return parsePolicyConstraints(obj);
            case "2.5.29.33": return parsePolicyMappings(obj);
            case "2.5.29.54": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("skipCerts", ASN1Integer.getInstance(obj).intValueExact());
                return r;
            }
            case "2.5.29.9": return parseSubjectDirAttrs(obj);
            case "2.5.29.16": return parsePrivKeyUsagePeriod(obj);
            case "2.5.29.28": return parseIssuingDP(obj);
            case "2.16.840.1.113730.1.1": return parseNetscapeCertType(obj);
            default: {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("rawHex", toHex(obj.getEncoded()));
                return r;
            }
        }
    }

    static Map<String, Object> parseSKI(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("keyIdentifier", toHex(SubjectKeyIdentifier.getInstance(obj).getKeyIdentifier()));
        return r;
    }

    static Map<String, Object> parseAKI(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(obj);
        if (aki.getKeyIdentifier() != null) r.put("keyIdentifier", toHex(aki.getKeyIdentifier()));
        if (aki.getAuthorityCertIssuer() != null) {
            List<Object> list = new ArrayList<>();
            for (GeneralName gn : aki.getAuthorityCertIssuer().getNames()) list.add(gnToJson(gn));
            r.put("authorityCertIssuer", list);
        }
        if (aki.getAuthorityCertSerialNumber() != null)
            r.put("authorityCertSerialNumber", aki.getAuthorityCertSerialNumber().toString(16));
        return r;
    }

    static Map<String, Object> parseGeneralNamesExt(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        GeneralNames gns = GeneralNames.getInstance(obj);
        List<Object> list = new ArrayList<>();
        for (GeneralName gn : gns.getNames()) list.add(gnToJson(gn));
        r.put("generalNames", list);
        return r;
    }

    static Map<String, Object> gnToJson(GeneralName gn) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        int tag = gn.getTagNo();
        r.put("tag", tag);
        r.put("type", GN_TYPES.getOrDefault(String.valueOf(tag), "unknown(" + tag + ")"));
        ASN1Encodable name = gn.getName();
        if (tag == GeneralName.directoryName) {
            r.put("value", dnToJson(X500Name.getInstance(name)));
        } else if (tag == GeneralName.iPAddress) {
            byte[] ip = ASN1OctetString.getInstance(name).getOctets();
            r.put("value", InetAddress.getByAddress(ip).getHostAddress());
        } else if (tag == GeneralName.registeredID) {
            r.put("value", ASN1ObjectIdentifier.getInstance(name).getId());
        } else if (tag == GeneralName.otherName) {
            r.put("value", toHex(name.toASN1Primitive().getEncoded()));
        } else {
            r.put("value", name.toString());
        }
        return r;
    }

    static Map<String, Object> parseKeyUsage(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        KeyUsage ku = KeyUsage.getInstance(obj);
        String[] names = {"digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment",
                          "keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"};
        int[] bits = {KeyUsage.digitalSignature,KeyUsage.nonRepudiation,KeyUsage.keyEncipherment,
                      KeyUsage.dataEncipherment,KeyUsage.keyAgreement,KeyUsage.keyCertSign,
                      KeyUsage.cRLSign,KeyUsage.encipherOnly,KeyUsage.decipherOnly};
        List<Object> usages = new ArrayList<>();
        for (int i = 0; i < names.length; i++) if (ku.hasUsages(bits[i])) usages.add(names[i]);
        r.put("keyUsage", usages);
        return r;
    }

    static Map<String, Object> parseEKU(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(obj);
        List<Object> usages = new ArrayList<>();
        for (KeyPurposeId kpi : eku.getUsages()) {
            Map<String, Object> u = new LinkedHashMap<>();
            String oid = kpi.getId();
            u.put("oid", oid);
            u.put("name", EKU_NAMES.getOrDefault(oid, oid));
            usages.add(u);
        }
        r.put("extendedKeyUsage", usages);
        return r;
    }

    static Map<String, Object> parseBasicConstraints(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        BasicConstraints bc = BasicConstraints.getInstance(obj);
        r.put("cA", bc.isCA());
        BigInteger pl = bc.getPathLenConstraint();
        r.put("pathLenConstraint", pl != null ? pl.intValue() : null);
        return r;
    }

    static Map<String, Object> parseCRLDP(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        CRLDistPoint cdp = CRLDistPoint.getInstance(obj);
        List<Object> points = new ArrayList<>();
        for (DistributionPoint dp : cdp.getDistributionPoints()) {
            Map<String, Object> dpm = new LinkedHashMap<>();
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null) {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("type", dpn.getType() == 0 ? "fullName" : "nameRelativeToCRLIssuer");
                if (dpn.getType() == 0) {
                    GeneralNames gns = GeneralNames.getInstance(dpn.getName());
                    List<Object> gnList = new ArrayList<>();
                    for (GeneralName gn : gns.getNames()) gnList.add(gnToJson(gn));
                    d.put("fullName", gnList);
                }
                dpm.put("distributionPoint", d);
            }
            if (dp.getReasons() != null) dpm.put("reasons", reasonFlagsToJson(dp.getReasons()));
            if (dp.getCRLIssuer() != null) {
                List<Object> ci = new ArrayList<>();
                for (GeneralName gn : dp.getCRLIssuer().getNames()) ci.add(gnToJson(gn));
                dpm.put("crlIssuer", ci);
            }
            points.add(dpm);
        }
        r.put("crlDistributionPoints", points);
        return r;
    }

    static Map<String, Object> parseCertPolicies(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        CertificatePolicies cps = CertificatePolicies.getInstance(obj);
        List<Object> policies = new ArrayList<>();
        for (PolicyInformation pi : cps.getPolicyInformation()) {
            Map<String, Object> pim = new LinkedHashMap<>();
            pim.put("policyIdentifier", pi.getPolicyIdentifier().getId());
            ASN1Sequence qs = pi.getPolicyQualifiers();
            if (qs != null) {
                List<Object> qList = new ArrayList<>();
                for (int i = 0; i < qs.size(); i++) {
                    PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qs.getObjectAt(i));
                    Map<String, Object> qm = new LinkedHashMap<>();
                    String qid = pqi.getPolicyQualifierId().getId();
                    qm.put("policyQualifierId", qid);
                    ASN1Encodable q = pqi.getQualifier();
                    if (q != null) {
                        if ("1.3.6.1.5.5.7.2.1".equals(qid)) qm.put("cpsUri", DERIA5String.getInstance(q).getString());
                        else if ("1.3.6.1.5.5.7.2.2".equals(qid)) qm.put("userNotice", parseUserNotice(q));
                        else qm.put("qualifierHex", toHex(q.toASN1Primitive().getEncoded()));
                    }
                    qList.add(qm);
                }
                pim.put("policyQualifiers", qList);
            }
            policies.add(pim);
        }
        r.put("certificatePolicies", policies);
        return r;
    }

    static Map<String, Object> parseUserNotice(ASN1Encodable q) {
        Map<String, Object> r = new LinkedHashMap<>();
        UserNotice un = UserNotice.getInstance(q);
        if (un.getNoticeRef() != null) {
            NoticeReference nr = un.getNoticeRef();
            Map<String, Object> nrm = new LinkedHashMap<>();
            DisplayText org = nr.getOrganization();
            nrm.put("organization", org.getString());
            nrm.put("organizationType", displayTextTypeName(org));
            List<Object> nums = new ArrayList<>();
            for (ASN1Integer n : nr.getNoticeNumbers()) nums.add(n.getValue().intValue());
            nrm.put("noticeNumbers", nums);
            r.put("noticeRef", nrm);
        }
        if (un.getExplicitText() != null) {
            r.put("explicitText", un.getExplicitText().getString());
            r.put("explicitTextType", displayTextTypeName(un.getExplicitText()));
        }
        return r;
    }

    // DisplayText 底层字符串类型名（与 DN 的 encoding 字段风格一致）
    static String displayTextTypeName(DisplayText dt) {
        ASN1Primitive p = dt.toASN1Primitive();
        if (p instanceof DERIA5String) return "IA5String";
        if (p instanceof DERBMPString) return "BMPString";
        if (p instanceof DERVisibleString) return "VisibleString";
        return "UTF8String";
    }

    static Map<String, Object> parseAIA(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(obj);
        List<Object> descs = new ArrayList<>();
        for (AccessDescription ad : aia.getAccessDescriptions()) {
            Map<String, Object> adm = new LinkedHashMap<>();
            String method = ad.getAccessMethod().getId();
            adm.put("accessMethod", method);
            adm.put("accessMethodName", AIA_METHODS.getOrDefault(method, method));
            adm.put("accessLocation", gnToJson(ad.getAccessLocation()));
            descs.add(adm);
        }
        r.put("authorityInfoAccess", descs);
        return r;
    }

    static Map<String, Object> parseNameConstraints(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        NameConstraints nc = NameConstraints.getInstance(obj);
        if (nc.getPermittedSubtrees() != null) r.put("permittedSubtrees", parseSubtrees(nc.getPermittedSubtrees()));
        if (nc.getExcludedSubtrees() != null) r.put("excludedSubtrees", parseSubtrees(nc.getExcludedSubtrees()));
        return r;
    }

    static List<Object> parseSubtrees(GeneralSubtree[] subtrees) throws Exception {
        List<Object> list = new ArrayList<>();
        for (GeneralSubtree gs : subtrees) {
            Map<String, Object> gsm = new LinkedHashMap<>();
            gsm.put("base", gnToJson(gs.getBase()));
            if (gs.getMinimum() != null) gsm.put("minimum", gs.getMinimum().intValue());
            if (gs.getMaximum() != null) gsm.put("maximum", gs.getMaximum().intValue());
            list.add(gsm);
        }
        return list;
    }

    static Map<String, Object> parsePolicyConstraints(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        PolicyConstraints pc = PolicyConstraints.getInstance(obj);
        if (pc.getRequireExplicitPolicyMapping() != null)
            r.put("requireExplicitPolicyMapping", pc.getRequireExplicitPolicyMapping().intValue());
        if (pc.getInhibitPolicyMapping() != null)
            r.put("inhibitPolicyMapping", pc.getInhibitPolicyMapping().intValue());
        return r;
    }

    static Map<String, Object> parsePolicyMappings(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        List<Object> mappings = new ArrayList<>();
        for (int i = 0; i < seq.size(); i++) {
            ASN1Sequence m = ASN1Sequence.getInstance(seq.getObjectAt(i));
            Map<String, Object> mm = new LinkedHashMap<>();
            mm.put("issuerDomainPolicy", ASN1ObjectIdentifier.getInstance(m.getObjectAt(0)).getId());
            mm.put("subjectDomainPolicy", ASN1ObjectIdentifier.getInstance(m.getObjectAt(1)).getId());
            mappings.add(mm);
        }
        r.put("policyMappings", mappings);
        return r;
    }

    static Map<String, Object> parseSubjectDirAttrs(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        ASN1Sequence seq = ASN1Sequence.getInstance(obj);
        List<Object> attrs = new ArrayList<>();
        for (int i = 0; i < seq.size(); i++) {
            Attribute a = Attribute.getInstance(seq.getObjectAt(i));
            Map<String, Object> am = new LinkedHashMap<>();
            am.put("type", a.getAttrType().getId());
            ASN1Set values = a.getAttrValues();
            List<Object> vl = new ArrayList<>();
            for (int j = 0; j < values.size(); j++) {
                ASN1Encodable val = values.getObjectAt(j);
                Map<String, Object> vm = new LinkedHashMap<>();
                String enc = encodingName(val);
                if (enc != null && isStringEncoding(enc)) {
                    vm.put("encoding", enc);
                    vm.put("value", ((ASN1String) val).getString());
                } else {
                    vm.put("hex", toHex(val.toASN1Primitive().getEncoded()));
                }
                vl.add(vm);
            }
            am.put("values", vl);
            attrs.add(am);
        }
        r.put("subjectDirectoryAttributes", attrs);
        return r;
    }

    static boolean isStringEncoding(String enc) {
        return "PrintableString".equals(enc) || "UTF8String".equals(enc) || "IA5String".equals(enc)
            || "TeletexString".equals(enc) || "UniversalString".equals(enc) || "BMPString".equals(enc)
            || "NumericString".equals(enc) || "VisibleString".equals(enc);
    }

    static Map<String, Object> parsePrivKeyUsagePeriod(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        PrivateKeyUsagePeriod pkup = PrivateKeyUsagePeriod.getInstance(obj);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        if (pkup.getNotBefore() != null) r.put("notBefore", sdf.format(pkup.getNotBefore().getDate()));
        if (pkup.getNotAfter() != null) r.put("notAfter", sdf.format(pkup.getNotAfter().getDate()));
        return r;
    }

    static Map<String, Object> parseIssuingDP(ASN1Primitive obj) throws Exception {
        Map<String, Object> r = new LinkedHashMap<>();
        IssuingDistributionPoint idp = IssuingDistributionPoint.getInstance(obj);
        if (idp.getDistributionPoint() != null) {
            DistributionPointName dpn = idp.getDistributionPoint();
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("type", dpn.getType() == 0 ? "fullName" : "nameRelativeToCRLIssuer");
            if (dpn.getType() == 0) {
                GeneralNames gns = GeneralNames.getInstance(dpn.getName());
                List<Object> gnList = new ArrayList<>();
                for (GeneralName gn : gns.getNames()) gnList.add(gnToJson(gn));
                d.put("fullName", gnList);
            }
            r.put("distributionPoint", d);
        }
        r.put("onlyContainsUserCerts", idp.onlyContainsUserCerts());
        r.put("onlyContainsCACerts", idp.onlyContainsCACerts());
        r.put("onlyContainsAttributeCerts", idp.onlyContainsAttributeCerts());
        r.put("indirectCRL", idp.isIndirectCRL());
        if (idp.getOnlySomeReasons() != null) r.put("onlySomeReasons", reasonFlagsToJson(idp.getOnlySomeReasons()));
        return r;
    }

    static Map<String, Object> parseNetscapeCertType(ASN1Primitive obj) {
        Map<String, Object> r = new LinkedHashMap<>();
        ASN1BitString bs = ASN1BitString.getInstance(obj);
        int value = new BigInteger(1, bs.getBytes()).intValue();
        String[] names = {"client","server","email","objsign","reserved","sslCA","emailCA","objCA"};
        List<Object> types = new ArrayList<>();
        for (int i = 0; i < names.length; i++) if ((value & (1 << (7 - i))) != 0) types.add(names[i]);
        r.put("netscapeCertType", types);
        return r;
    }

    // ==================== SCT List (RFC 6962) 解析 ====================

    static final Map<Integer, String> HASH_ALGS = new HashMap<>();
    static final Map<Integer, String> SIG_ALGS = new HashMap<>();
    static final Map<String, Integer> HASH_ALG_CODES = new HashMap<>();
    static final Map<String, Integer> SIG_ALG_CODES = new HashMap<>();
    static {
        HASH_ALGS.put(0, "none"); HASH_ALGS.put(1, "md5"); HASH_ALGS.put(2, "sha1");
        HASH_ALGS.put(3, "sha224"); HASH_ALGS.put(4, "sha256"); HASH_ALGS.put(5, "sha384"); HASH_ALGS.put(6, "sha512");
        SIG_ALGS.put(0, "anonymous"); SIG_ALGS.put(1, "rsa"); SIG_ALGS.put(2, "dsa"); SIG_ALGS.put(3, "ecdsa");
        for (Map.Entry<Integer, String> e : HASH_ALGS.entrySet()) HASH_ALG_CODES.put(e.getValue(), e.getKey());
        for (Map.Entry<Integer, String> e : SIG_ALGS.entrySet()) SIG_ALG_CODES.put(e.getValue(), e.getKey());
    }

    /**
     * 解析 TLS 编码的 SignedCertificateTimestampList
     * 结构: uint16 totalLen + [uint16 sctLen + sctRaw]*N
     */
    static Map<String, Object> parseSCTList(byte[] tlsData) {
        Map<String, Object> r = new LinkedHashMap<>();
        int pos = 0;
        int totalLen = readUint16(tlsData, pos); pos += 2;
        List<Object> scts = new ArrayList<>();
        int end = pos + totalLen;
        while (pos < end) {
            int sctLen = readUint16(tlsData, pos); pos += 2;
            scts.add(parseSCT(tlsData, pos, sctLen));
            pos += sctLen;
        }
        r.put("sctList", scts);
        return r;
    }

    /** 解析单个 SerializedSCT: version(1) + log_id(32) + timestamp(8) + extensions(uint16+data) + hash_alg(1) + sig_alg(1) + signature(uint16+data) */
    static Map<String, Object> parseSCT(byte[] data, int offset, int len) {
        Map<String, Object> r = new LinkedHashMap<>();
        int pos = offset;
        r.put("version", data[pos++] & 0xFF);
        byte[] logId = new byte[32];
        System.arraycopy(data, pos, logId, 0, 32); pos += 32;
        r.put("logId", toHex(logId));
        long timestamp = 0;
        for (int i = 0; i < 8; i++) timestamp = (timestamp << 8) | (data[pos++] & 0xFF);
        r.put("timestamp", timestamp);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        r.put("timestampIso", sdf.format(new Date(timestamp)));
        int extLen = readUint16(data, pos); pos += 2;
        if (extLen > 0) {
            byte[] ext = new byte[extLen];
            System.arraycopy(data, pos, ext, 0, extLen);
            r.put("extensions", toHex(ext));
        } else {
            r.put("extensions", "");
        }
        pos += extLen;
        int hashAlg = data[pos++] & 0xFF;
        r.put("hashAlgorithm", HASH_ALGS.getOrDefault(hashAlg, "unknown(" + hashAlg + ")"));
        r.put("hashAlgorithmCode", hashAlg);
        int sigAlg = data[pos++] & 0xFF;
        r.put("signatureAlgorithm", SIG_ALGS.getOrDefault(sigAlg, "unknown(" + sigAlg + ")"));
        r.put("signatureAlgorithmCode", sigAlg);
        int sigLen = readUint16(data, pos); pos += 2;
        byte[] sig = new byte[sigLen];
        System.arraycopy(data, pos, sig, 0, sigLen);
        r.put("signature", toHex(sig));
        return r;
    }

    static int readUint16(byte[] data, int pos) {
        return ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
    }

    static void writeUint16(ByteArrayOutputStream bos, int val) {
        bos.write((val >>> 8) & 0xFF);
        bos.write(val & 0xFF);
    }

    // ==================== JSON -> PEM（从结构化数据重建 ASN.1） ====================

    @SuppressWarnings("unchecked")
    static byte[] jsonToCertPem(String json) throws Exception {
        Map<String, Object> root = (Map<String, Object>) new JsonParser(json).parse();
        DERSequence tbsSeq = buildTBSCertificate(root);

        // signatureAlgorithm
        AlgorithmIdentifier sigAlg = buildAlgId((Map<String, Object>) root.get("signatureAlgorithm"));

        // signatureValue
        byte[] sigBytes = fromHex((String) root.get("signatureValue"));
        int unusedBits = root.containsKey("signatureValueUnusedBits") ?
                ((Number) root.get("signatureValueUnusedBits")).intValue() : 0;
        DERBitString sigValue = new DERBitString(sigBytes, unusedBits);

        // 组装 Certificate
        ASN1EncodableVector cv = new ASN1EncodableVector();
        cv.add(tbsSeq);
        cv.add(sigAlg);
        cv.add(sigValue);
        return derToPem(new DERSequence(cv).getEncoded()).getBytes(StandardCharsets.UTF_8);
    }

    /** 从 JSON 结构化数据构建 TBSCertificate（DERSequence），供 jsonToCertPem 和 rekey 复用 */
    @SuppressWarnings("unchecked")
    static DERSequence buildTBSCertificate(Map<String, Object> root) throws Exception {
        ASN1EncodableVector tv = new ASN1EncodableVector();

        // version [0] EXPLICIT INTEGER DEFAULT v1(0) —— v1 不编码
        int ver = ((String) root.get("version")).startsWith("v") ?
                Integer.parseInt(((String) root.get("version")).substring(1)) - 1 : 2;
        if (ver != 0) tv.add(new DERTaggedObject(true, 0, new ASN1Integer(ver)));

        // serialNumber
        tv.add(new ASN1Integer(new BigInteger((String) root.get("serialNumber"), 16)));

        // signature (TBS 内部)
        tv.add(buildAlgId((Map<String, Object>) root.get("signature")));

        // issuer
        tv.add(buildDN(root.get("issuer")));

        // validity
        Map<String, Object> validity = (Map<String, Object>) root.get("validity");
        ASN1EncodableVector vv = new ASN1EncodableVector();
        vv.add(buildTime((Map<String, Object>) validity.get("notBefore")));
        vv.add(buildTime((Map<String, Object>) validity.get("notAfter")));
        tv.add(new DERSequence(vv));

        // subject
        tv.add(buildDN(root.get("subject")));

        // subjectPublicKeyInfo
        tv.add(buildSPKI((Map<String, Object>) root.get("subjectPublicKeyInfo")));

        // issuerUniqueID [1] IMPLICIT
        String iuid = (String) root.get("issuerUniqueId");
        if (iuid != null) tv.add(new DERTaggedObject(false, 1, new DERBitString(fromHex(iuid), 0)));

        // subjectUniqueID [2] IMPLICIT
        String suid = (String) root.get("subjectUniqueId");
        if (suid != null) tv.add(new DERTaggedObject(false, 2, new DERBitString(fromHex(suid), 0)));

        // extensions [3] EXPLICIT
        Map<String, Object> exts = (Map<String, Object>) root.get("extensions");
        if (exts != null && !exts.isEmpty()) {
            tv.add(new DERTaggedObject(true, 3, buildExtensions(exts)));
        }

        return new DERSequence(tv);
    }

    // ==================== 密钥替换（rekey） ====================

    /**
     * 密钥替换（即时生成新密钥对）：根据 JSON 中的密钥算法生成同类型新密钥对，
     * 用新公钥替换 subjectPublicKeyInfo.publicKey，
     * 用新私钥对 TBSCertificate 重新签名，输出 PEM 证书。
     */
    @SuppressWarnings("unchecked")
    static byte[] rekeyJsonToPem(String json) throws Exception {
        Map<String, Object> root = (Map<String, Object>) new JsonParser(json).parse();
        Map<String, Object> spkiMap = (Map<String, Object>) root.get("subjectPublicKeyInfo");
        Map<String, Object> algMap = (Map<String, Object>) spkiMap.get("algorithm");
        String keyAlgOid = (String) algMap.get("algorithm");
        KeyPair newKp = generateKeyPair(keyAlgOid, spkiMap);
        return doRekey(root, newKp);
    }

    /**
     * 密钥替换（使用现有密钥对）：privKeyHex = PKCS#8 PrivateKeyInfo DER 的 hex，
     * pubKeyHex = SubjectPublicKeyInfo DER 的 hex。用外部密钥对替换公钥并重签。
     */
    static byte[] rekeyJsonToPem(String json, String privKeyHex, String pubKeyHex) throws Exception {
        Map<String, Object> root = (Map<String, Object>) new JsonParser(json).parse();
        KeyPair kp = hexToKeyPair(privKeyHex, pubKeyHex);
        return doRekey(root, kp);
    }

    /** rekey 内部共用逻辑：替换公钥 → 构建 TBS → 签名 → 组装证书 */
    @SuppressWarnings("unchecked")
    private static byte[] doRekey(Map<String, Object> root, KeyPair newKp) throws Exception {
        Map<String, Object> spkiMap = (Map<String, Object>) root.get("subjectPublicKeyInfo");

        // 提取新公钥 BIT STRING 内容，写回 JSON
        SubjectPublicKeyInfo newSpki = SubjectPublicKeyInfo.getInstance(newKp.getPublic().getEncoded());
        byte[] newPubKeyBits = newSpki.getPublicKeyData().getBytes();
        spkiMap.put("publicKey", toHex(newPubKeyBits));

        // 构建 TBSCertificate
        DERSequence tbsSeq = buildTBSCertificate(root);
        byte[] tbsDer = tbsSeq.getEncoded(ASN1Encoding.DER);

        // 确定签名算法（从 JSON 的 signature.algorithm 读取，保持原算法）
        String sigAlgOid = (String) ((Map<String, Object>) root.get("signature")).get("algorithm");
        String jcaSigName = sigAlgOidToJcaName(sigAlgOid);

        // 用新私钥签名
        Signature sig = Signature.getInstance(jcaSigName, BouncyCastleProvider.PROVIDER_NAME);
        sig.initSign(newKp.getPrivate(), new SecureRandom());
        sig.update(tbsDer);
        byte[] signature = sig.sign();

        // 更新 signatureValue（新签名 unusedBits 恒为 0）
        root.put("signatureValue", toHex(signature));
        root.remove("signatureValueUnusedBits");

        // 组装 Certificate 并输出 PEM
        AlgorithmIdentifier sigAlgId = buildAlgId((Map<String, Object>) root.get("signatureAlgorithm"));
        DERBitString sigValue = new DERBitString(signature, 0);
        ASN1EncodableVector cv = new ASN1EncodableVector();
        cv.add(tbsSeq);
        cv.add(sigAlgId);
        cv.add(sigValue);
        byte[] certDer = new DERSequence(cv).getEncoded(ASN1Encoding.DER);
        return derToPem(certDer).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 将 hex 编码的私钥/公钥解析为 KeyPair。
     * 私钥：PKCS#8 PrivateKeyInfo DER hex；公钥：SubjectPublicKeyInfo DER hex。
     */
    static KeyPair hexToKeyPair(String privKeyHex, String pubKeyHex) throws Exception {
        byte[] privDer = fromHex(privKeyHex.trim());
        byte[] pubDer = fromHex(pubKeyHex.trim());

        // 从公钥 SPKI 推断算法 OID，选择对应 KeyFactory
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pubDer);
        String algOid = spki.getAlgorithm().getAlgorithm().getId();
        String jcaName = keyAlgOidToJcaName(algOid);

        KeyFactory kf = KeyFactory.getInstance(jcaName, BouncyCastleProvider.PROVIDER_NAME);
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubDer));
        PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privDer));
        return new KeyPair(pubKey, privKey);
    }

    /** 密钥算法 OID -> JCA KeyFactory 算法名 */
    static String keyAlgOidToJcaName(String oid) {
        switch (oid) {
            case "1.2.840.113549.1.1.1": return "RSA";
            case "1.2.840.10045.2.1":    return "EC";
            case "1.2.156.10197.1.301":  return "EC";   // SM2 走 EC KeyFactory
            case "1.3.101.112":          return "Ed25519";
            case "1.3.101.113":          return "Ed448";
            case "1.2.840.10040.4.1":    return "DSA";
            default: throw new RuntimeException("Unsupported key algorithm for hex key pair: " + oid);
        }
    }

    /** 根据密钥算法 OID 和原 SPKI 信息生成同类型新密钥对 */
    @SuppressWarnings("unchecked")
    static KeyPair generateKeyPair(String keyAlgOid, Map<String, Object> spkiMap) throws Exception {
        switch (keyAlgOid) {
            case "1.2.840.113549.1.1.1": { // RSA
                // 从原公钥 RSAPublicKey DER 中解析模数长度，保持相同密钥长度
                String pubKeyHex = (String) spkiMap.get("publicKey");
                byte[] pubKeyBytes = fromHex(pubKeyHex);
                int keyLen;
                try {
                    ASN1Sequence seq = ASN1Sequence.getInstance(pubKeyBytes);
                    ASN1Integer modulus = ASN1Integer.getInstance(seq.getObjectAt(0));
                    keyLen = modulus.getPositiveValue().bitLength();
                } catch (Exception e) {
                    keyLen = 2048; // 解析失败默认 2048
                }
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(keyLen, new SecureRandom());
                return kpg.generateKeyPair();
            }
            case "1.2.840.10045.2.1": { // EC
                // 从 algorithm.parameters(hex) 解析曲线 OID
                Map<String, Object> alg = (Map<String, Object>) spkiMap.get("algorithm");
                String paramsHex = (String) alg.get("parameters");
                String curveOid;
                if (paramsHex != null && !paramsHex.isEmpty() && !"NULL".equals(paramsHex)) {
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(fromHex(paramsHex));
                    curveOid = oid.getId();
                } else {
                    curveOid = "1.2.840.10045.3.1.7"; // 默认 prime256v1
                }
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(new ECGenParameterSpec(curveOid), new SecureRandom());
                return kpg.generateKeyPair();
            }
            case "1.2.156.10197.1.301": { // SM2 (sm2p256v1)
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(new ECGenParameterSpec("1.2.156.10197.1.301"), new SecureRandom());
                return kpg.generateKeyPair();
            }
            case "1.3.101.112": { // Ed25519
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
                return kpg.generateKeyPair();
            }
            case "1.3.101.113": { // Ed448
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448", BouncyCastleProvider.PROVIDER_NAME);
                return kpg.generateKeyPair();
            }
            case "1.2.840.10040.4.1": { // DSA
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
                kpg.initialize(1024, new SecureRandom());
                return kpg.generateKeyPair();
            }
            default:
                throw new RuntimeException("Unsupported key algorithm for rekey: " + keyAlgOid);
        }
    }

    /** 签名算法 OID -> JCA Signature 名称 */
    static String sigAlgOidToJcaName(String oid) {
        switch (oid) {
            case "1.2.840.113549.1.1.2":  return "MD2withRSA";
            case "1.2.840.113549.1.1.4":  return "MD5withRSA";
            case "1.2.840.113549.1.1.5":  return "SHA1withRSA";
            case "1.2.840.113549.1.1.11": return "SHA256withRSA";
            case "1.2.840.113549.1.1.12": return "SHA384withRSA";
            case "1.2.840.113549.1.1.13": return "SHA512withRSA";
            case "1.2.840.113549.1.1.14": return "SHA224withRSA";
            case "1.2.840.10045.4.1":     return "SHA1withECDSA";
            case "1.2.840.10045.4.3.1":   return "SHA224withECDSA";
            case "1.2.840.10045.4.3.2":   return "SHA256withECDSA";
            case "1.2.840.10045.4.3.3":   return "SHA384withECDSA";
            case "1.2.840.10045.4.3.4":   return "SHA512withECDSA";
            case "1.3.101.112":           return "Ed25519";
            case "1.3.101.113":           return "Ed448";
            case "1.2.156.10197.1.501":   return "SM3withSM2";
            case "1.2.840.10040.4.3":     return "SHA1withDSA";
            case "2.16.840.1.101.3.4.3.1": return "SHA224withDSA";
            case "2.16.840.1.101.3.4.3.2": return "SHA256withDSA";
            default:
                throw new RuntimeException("Unsupported signature algorithm for rekey: " + oid);
        }
    }

    static AlgorithmIdentifier buildAlgId(Map<String, Object> m) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier((String) m.get("algorithm"));
        Object p = m.get("parameters");
        if (p == null) return new AlgorithmIdentifier(oid);
        if ("NULL".equals(p)) return new AlgorithmIdentifier(oid, DERNull.INSTANCE);
        // hex 编码的参数
        try {
            return new AlgorithmIdentifier(oid, ASN1Primitive.fromByteArray(fromHex((String) p)));
        } catch (Exception e) {
            throw new RuntimeException("Failed to build algorithm parameters: " + p, e);
        }
    }

    /** 从 JSON 重建 DN：兼容新格式（有序 RDN 数组）与旧格式（OID 主键 map） */
    @SuppressWarnings("unchecked")
    static X500Name buildDN(Object dnObj) {
        List<RDN> rdns = new ArrayList<>();
        if (dnObj instanceof Map) {
            // 旧格式：OID 主键 map，每项单值 RDN（无多值信息，保持原行为）
            for (Map.Entry<String, Object> e : ((Map<String, Object>) dnObj).entrySet()) {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(e.getKey());
                Map<String, Object> attr = (Map<String, Object>) e.getValue();
                ASN1Encodable value = buildStringValue((String) attr.get("encoding"), (String) attr.get("value"));
                rdns.add(new RDN(oid, value));
            }
        } else {
            // 新格式：List< RDN: List<ATV> >
            for (Object ro : (List<Object>) dnObj) {
                List<Object> atvList = (List<Object>) ro;
                AttributeTypeAndValue[] atvs = new AttributeTypeAndValue[atvList.size()];
                for (int i = 0; i < atvList.size(); i++) {
                    Map<String, Object> m = (Map<String, Object>) atvList.get(i);
                    ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier((String) m.get("oid"));
                    ASN1Encodable value = buildStringValue((String) m.get("encoding"), (String) m.get("value"));
                    atvs[i] = new AttributeTypeAndValue(oid, value);
                }
                rdns.add(new RDN(atvs));
            }
        }
        return new X500Name(rdns.toArray(new RDN[0]));
    }

    static ASN1Encodable buildStringValue(String encoding, String value) {
        if (encoding == null) encoding = "UTF8String";
        switch (encoding) {
            case "PrintableString": return new DERPrintableString(value);
            case "UTF8String": return new DERUTF8String(value);
            case "IA5String": return new DERIA5String(value);
            case "TeletexString": case "T61String": return new DERT61String(value);
            case "BMPString": return new DERBMPString(value);
            case "NumericString": return new DERNumericString(value);
            case "VisibleString": return new DERVisibleString(value);
            case "UniversalString": return new DERUniversalString(value.getBytes(StandardCharsets.UTF_16BE));
            default: return new DERUTF8String(value);
        }
    }

    static Time buildTime(Map<String, Object> t) throws Exception {
        // 优先使用 DER hex（无损），兼容旧 JSON 无 raw 字段的情况
        String raw = (String) t.get("raw");
        if (raw != null && !raw.isEmpty()) {
            return Time.getInstance(ASN1Primitive.fromByteArray(fromHex(raw)));
        }
        String type = (String) t.get("type");
        String iso = (String) t.get("value");
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date date = sdf.parse(iso);
        if ("UTCTime".equals(type)) return Time.getInstance(new ASN1UTCTime(date));
        return Time.getInstance(new ASN1GeneralizedTime(date));
    }

    static SubjectPublicKeyInfo buildSPKI(Map<String, Object> m) {
        AlgorithmIdentifier alg = buildAlgId((Map<String, Object>) m.get("algorithm"));
        byte[] keyBytes = fromHex((String) m.get("publicKey"));
        return new SubjectPublicKeyInfo(alg, keyBytes);
    }

    static Extensions buildExtensions(Map<String, Object> exts) throws Exception {
        List<Extension> extList = new ArrayList<>();
        for (Map.Entry<String, Object> e : exts.entrySet()) {
            String oid = e.getKey();
            Map<String, Object> em = (Map<String, Object>) e.getValue();
            boolean critical = (Boolean) em.get("critical");
            ASN1Object extValue = buildExtensionValue(oid, em);
            byte[] extDer = extValue.getEncoded();
            extList.add(new Extension(new ASN1ObjectIdentifier(oid), critical, new DEROctetString(extDer)));
        }
        return new Extensions(extList.toArray(new Extension[0]));
    }

    static ASN1Object buildExtensionValue(String oid, Map<String, Object> em) throws Exception {
        switch (oid) {
            case "2.5.29.14": return buildSKI(em);
            case "2.5.29.35": return buildAKI(em);
            case "2.5.29.17": case "2.5.29.18": return buildGeneralNames(em);
            case "2.5.29.15": return buildKeyUsage(em);
            case "2.5.29.37": return buildEKU(em);
            case "2.5.29.19": return buildBasicConstraints(em);
            case "2.5.29.31": case "2.5.29.46": return buildCRLDP(em);
            case "2.5.29.32": return buildCertPolicies(em);
            case "1.3.6.1.5.5.7.1.1": case "1.3.6.1.5.5.7.1.11": return buildAIA(em);
            case "2.5.29.30": return buildNameConstraints(em);
            case "2.5.29.36": return buildPolicyConstraints(em);
            case "2.5.29.33": return buildPolicyMappings(em);
            case "2.5.29.54": return new ASN1Integer(((Number) em.get("skipCerts")).intValue());
            case "2.5.29.9": return buildSubjectDirAttrs(em);
            case "2.5.29.16": return buildPrivKeyUsagePeriod(em);
            case "2.5.29.28": return buildIssuingDP(em);
            case "2.16.840.1.113730.1.1": return buildNetscapeCertType(em);
            case "1.3.6.1.4.1.11129.2.4.2": return buildSCTList(em);
            default:
                String rawHex = (String) em.get("rawHex");
                if (rawHex != null) return ASN1Primitive.fromByteArray(fromHex(rawHex));
                throw new RuntimeException("Unknown extension without rawHex: " + oid);
        }
    }

    static SubjectKeyIdentifier buildSKI(Map<String, Object> em) {
        return new SubjectKeyIdentifier(fromHex((String) em.get("keyIdentifier")));
    }

    static AuthorityKeyIdentifier buildAKI(Map<String, Object> em) {
        byte[] keyId = em.containsKey("keyIdentifier") ? fromHex((String) em.get("keyIdentifier")) : null;
        GeneralNames issuer = null;
        if (em.containsKey("authorityCertIssuer")) {
            List<Map<String, Object>> list = (List<Map<String, Object>>) em.get("authorityCertIssuer");
            GeneralName[] gns = new GeneralName[list.size()];
            for (int i = 0; i < list.size(); i++) gns[i] = buildGN(list.get(i));
            issuer = new GeneralNames(gns);
        }
        BigInteger serial = em.containsKey("authorityCertSerialNumber") ?
                new BigInteger((String) em.get("authorityCertSerialNumber"), 16) : null;
        return new AuthorityKeyIdentifier(keyId, issuer, serial);
    }

    static GeneralNames buildGeneralNames(Map<String, Object> em) {
        List<Map<String, Object>> list = (List<Map<String, Object>>) em.get("generalNames");
        GeneralName[] gns = new GeneralName[list.size()];
        for (int i = 0; i < list.size(); i++) gns[i] = buildGN(list.get(i));
        return new GeneralNames(gns);
    }

    static GeneralName buildGN(Map<String, Object> gn) {
        int tag = ((Number) gn.get("tag")).intValue();
        Object valueObj = gn.get("value");
        ASN1Encodable name;
        try {
            switch (tag) {
                case GeneralName.dNSName:
                case GeneralName.rfc822Name:
                case GeneralName.uniformResourceIdentifier:
                    name = new DERIA5String((String) valueObj); break;
                case GeneralName.iPAddress:
                    name = new DEROctetString(InetAddress.getByName((String) valueObj).getAddress()); break;
                case GeneralName.directoryName:
                    name = buildDN(valueObj); break;
                case GeneralName.registeredID:
                    name = new ASN1ObjectIdentifier((String) valueObj); break;
                case GeneralName.otherName:
                    name = ASN1Primitive.fromByteArray(fromHex((String) valueObj)); break;
                default:
                    name = new DERIA5String((String) valueObj);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to build GeneralName tag=" + tag, e);
        }
        return new GeneralName(tag, name);
    }

    static KeyUsage buildKeyUsage(Map<String, Object> em) {
        List<String> usages = (List<String>) em.get("keyUsage");
        int value = 0;
        for (String u : usages) {
            switch (u) {
                case "digitalSignature": value |= KeyUsage.digitalSignature; break;
                case "nonRepudiation": value |= KeyUsage.nonRepudiation; break;
                case "keyEncipherment": value |= KeyUsage.keyEncipherment; break;
                case "dataEncipherment": value |= KeyUsage.dataEncipherment; break;
                case "keyAgreement": value |= KeyUsage.keyAgreement; break;
                case "keyCertSign": value |= KeyUsage.keyCertSign; break;
                case "cRLSign": value |= KeyUsage.cRLSign; break;
                case "encipherOnly": value |= KeyUsage.encipherOnly; break;
                case "decipherOnly": value |= KeyUsage.decipherOnly; break;
            }
        }
        return new KeyUsage(value);
    }

    static ExtendedKeyUsage buildEKU(Map<String, Object> em) {
        List<Map<String, Object>> usages = (List<Map<String, Object>>) em.get("extendedKeyUsage");
        KeyPurposeId[] kpis = new KeyPurposeId[usages.size()];
        for (int i = 0; i < usages.size(); i++)
            kpis[i] = KeyPurposeId.getInstance(new ASN1ObjectIdentifier((String) usages.get(i).get("oid")));
        return new ExtendedKeyUsage(kpis);
    }

    static BasicConstraints buildBasicConstraints(Map<String, Object> em) {
        boolean cA = (Boolean) em.get("cA");
        Object pl = em.get("pathLenConstraint");
        if (pl != null) return new BasicConstraints(((Number) pl).intValue());
        return new BasicConstraints(cA);
    }

    static CRLDistPoint buildCRLDP(Map<String, Object> em) {
        List<Map<String, Object>> points = (List<Map<String, Object>>) em.get("crlDistributionPoints");
        DistributionPoint[] dps = new DistributionPoint[points.size()];
        for (int i = 0; i < points.size(); i++) {
            Map<String, Object> dpm = points.get(i);
            DistributionPointName dpn = null;
            if (dpm.containsKey("distributionPoint")) {
                Map<String, Object> d = (Map<String, Object>) dpm.get("distributionPoint");
                if ("fullName".equals(d.get("type"))) {
                    List<Map<String, Object>> fn = (List<Map<String, Object>>) d.get("fullName");
                    GeneralName[] gns = new GeneralName[fn.size()];
                    for (int j = 0; j < fn.size(); j++) gns[j] = buildGN(fn.get(j));
                    dpn = new DistributionPointName(new GeneralNames(gns));
                }
            }
            ReasonFlags reasons = null;
            if (dpm.containsKey("reasons")) {
                List<String> rs = (List<String>) dpm.get("reasons");
                reasons = new ReasonFlags(reasonNamesToMask(rs));
            }
            GeneralNames crlIssuer = null;
            if (dpm.containsKey("crlIssuer")) {
                List<Map<String, Object>> ci = (List<Map<String, Object>>) dpm.get("crlIssuer");
                GeneralName[] gns = new GeneralName[ci.size()];
                for (int j = 0; j < ci.size(); j++) gns[j] = buildGN(ci.get(j));
                crlIssuer = new GeneralNames(gns);
            }
            dps[i] = new DistributionPoint(dpn, reasons, crlIssuer);
        }
        return new CRLDistPoint(dps);
    }

    static CertificatePolicies buildCertPolicies(Map<String, Object> em) throws Exception {
        List<Map<String, Object>> policies = (List<Map<String, Object>>) em.get("certificatePolicies");
        PolicyInformation[] pis = new PolicyInformation[policies.size()];
        for (int i = 0; i < policies.size(); i++) {
            Map<String, Object> pim = policies.get(i);
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier((String) pim.get("policyIdentifier"));
            ASN1Sequence qualifiers = null;
            if (pim.containsKey("policyQualifiers")) {
                List<Map<String, Object>> qs = (List<Map<String, Object>>) pim.get("policyQualifiers");
                ASN1EncodableVector v = new ASN1EncodableVector();
                for (Map<String, Object> qm : qs) {
                    ASN1ObjectIdentifier qid = new ASN1ObjectIdentifier((String) qm.get("policyQualifierId"));
                    ASN1Encodable qualifier;
                    if ("1.3.6.1.5.5.7.2.1".equals(qid.getId())) {
                        qualifier = new DERIA5String((String) qm.get("cpsUri"));
                    } else if ("1.3.6.1.5.5.7.2.2".equals(qid.getId())) {
                        qualifier = buildUserNotice(qm);
                    } else if (qm.containsKey("qualifierHex")) {
                        qualifier = ASN1Primitive.fromByteArray(fromHex((String) qm.get("qualifierHex")));
                    } else {
                        qualifier = DERNull.INSTANCE;
                    }
                    v.add(new PolicyQualifierInfo(qid, qualifier));
                }
                qualifiers = new DERSequence(v);
            }
            pis[i] = new PolicyInformation(oid, qualifiers);
        }
        return new CertificatePolicies(pis);
    }

    // UserNotice ::= SEQUENCE { noticeRef NoticeReference OPTIONAL, explicitText DisplayText OPTIONAL }
    // NoticeReference ::= SEQUENCE { organization DisplayText, noticeNumbers SEQUENCE OF INTEGER }
    static UserNotice buildUserNotice(Map<String, Object> qm) throws Exception {
        // JSON 中 userNotice 字段嵌套在 "userNotice" 键下；兼容平铺写法
        Map<String, Object> un = (Map<String, Object>) qm.get("userNotice");
        if (un == null) un = qm;
        NoticeReference noticeRef = null;
        if (un.containsKey("noticeRef")) {
            Map<String, Object> nrm = (Map<String, Object>) un.get("noticeRef");
            String org = (String) nrm.get("organization");
            int orgType = displayTextTypeId((String) nrm.get("organizationType"),
                    DisplayText.CONTENT_TYPE_UTF8STRING);
            ASN1EncodableVector nums = new ASN1EncodableVector();
            for (Object num : (List<Object>) nrm.get("noticeNumbers")) {
                nums.add(new ASN1Integer(((Number) num).longValue()));
            }
            noticeRef = new NoticeReference(new DisplayText(orgType, org), nums);
        }
        DisplayText explicitText = null;
        if (un.containsKey("explicitText")) {
            String text = (String) un.get("explicitText");
            int type = displayTextTypeId((String) un.get("explicitTextType"),
                    DisplayText.CONTENT_TYPE_UTF8STRING);
            explicitText = new DisplayText(type, text);
        }
        return new UserNotice(noticeRef, explicitText);
    }

    // 类型名 -> BC DisplayText 常量；缺省或未知时返回默认值(UTF8String, 与 BC new DisplayText(String) 一致)
    static int displayTextTypeId(String name, int def) {
        if ("IA5String".equals(name)) return DisplayText.CONTENT_TYPE_IA5STRING;
        if ("BMPString".equals(name)) return DisplayText.CONTENT_TYPE_BMPSTRING;
        if ("UTF8String".equals(name)) return DisplayText.CONTENT_TYPE_UTF8STRING;
        if ("VisibleString".equals(name)) return DisplayText.CONTENT_TYPE_VISIBLESTRING;
        return def;
    }

    static AuthorityInformationAccess buildAIA(Map<String, Object> em) {
        List<Map<String, Object>> descs = (List<Map<String, Object>>) em.get("authorityInfoAccess");
        AccessDescription[] ads = new AccessDescription[descs.size()];
        for (int i = 0; i < descs.size(); i++) {
            Map<String, Object> adm = descs.get(i);
            ASN1ObjectIdentifier method = new ASN1ObjectIdentifier((String) adm.get("accessMethod"));
            GeneralName location = buildGN((Map<String, Object>) adm.get("accessLocation"));
            ads[i] = new AccessDescription(method, location);
        }
        return new AuthorityInformationAccess(ads);
    }

    static NameConstraints buildNameConstraints(Map<String, Object> em) {
        GeneralSubtree[] permitted = null;
        GeneralSubtree[] excluded = null;
        if (em.containsKey("permittedSubtrees")) permitted = buildSubtrees((List<Map<String, Object>>) em.get("permittedSubtrees"));
        if (em.containsKey("excludedSubtrees")) excluded = buildSubtrees((List<Map<String, Object>>) em.get("excludedSubtrees"));
        return new NameConstraints(permitted, excluded);
    }

    static GeneralSubtree[] buildSubtrees(List<Map<String, Object>> list) {
        GeneralSubtree[] gss = new GeneralSubtree[list.size()];
        for (int i = 0; i < list.size(); i++) {
            Map<String, Object> gsm = list.get(i);
            GeneralName base = buildGN((Map<String, Object>) gsm.get("base"));
            BigInteger min = gsm.containsKey("minimum") ? BigInteger.valueOf(((Number) gsm.get("minimum")).longValue()) : null;
            BigInteger max = gsm.containsKey("maximum") ? BigInteger.valueOf(((Number) gsm.get("maximum")).longValue()) : null;
            gss[i] = new GeneralSubtree(base, min, max);
        }
        return gss;
    }

    static PolicyConstraints buildPolicyConstraints(Map<String, Object> em) {
        BigInteger require = em.containsKey("requireExplicitPolicyMapping") ?
                BigInteger.valueOf(((Number) em.get("requireExplicitPolicyMapping")).longValue()) : null;
        BigInteger inhibit = em.containsKey("inhibitPolicyMapping") ?
                BigInteger.valueOf(((Number) em.get("inhibitPolicyMapping")).longValue()) : null;
        return new PolicyConstraints(require, inhibit);
    }

    static PolicyMappings buildPolicyMappings(Map<String, Object> em) {
        List<Map<String, Object>> mappings = (List<Map<String, Object>>) em.get("policyMappings");
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (Map<String, Object> mm : mappings) {
            ASN1EncodableVector mv = new ASN1EncodableVector();
            mv.add(new ASN1ObjectIdentifier((String) mm.get("issuerDomainPolicy")));
            mv.add(new ASN1ObjectIdentifier((String) mm.get("subjectDomainPolicy")));
            v.add(new DERSequence(mv));
        }
        return PolicyMappings.getInstance(new DERSequence(v));
    }

    static ASN1Sequence buildSubjectDirAttrs(Map<String, Object> em) throws Exception {
        List<Map<String, Object>> attrs = (List<Map<String, Object>>) em.get("subjectDirectoryAttributes");
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (Map<String, Object> am : attrs) {
            ASN1ObjectIdentifier type = new ASN1ObjectIdentifier((String) am.get("type"));
            ASN1EncodableVector vals = new ASN1EncodableVector();
            for (Object val : (List<Object>) am.get("values")) {
                if (val instanceof Map) {
                    Map<String, Object> vm = (Map<String, Object>) val;
                    if (vm.containsKey("hex")) {
                        vals.add(ASN1Primitive.fromByteArray(fromHex((String) vm.get("hex"))));
                    } else {
                        vals.add(buildStringValue((String) vm.get("encoding"), (String) vm.get("value")));
                    }
                } else {
                    // 兼容旧格式：纯字符串 -> UTF8String
                    vals.add(new DERUTF8String(val.toString()));
                }
            }
            v.add(new Attribute(type, new DERSet(vals)));
        }
        return new DERSequence(v);
    }

    static PrivateKeyUsagePeriod buildPrivKeyUsagePeriod(Map<String, Object> em) throws Exception {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        ASN1GeneralizedTime notBefore = null;
        ASN1GeneralizedTime notAfter = null;
        if (em.containsKey("notBefore")) notBefore = new ASN1GeneralizedTime(sdf.parse((String) em.get("notBefore")));
        if (em.containsKey("notAfter")) notAfter = new ASN1GeneralizedTime(sdf.parse((String) em.get("notAfter")));
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (notBefore != null) v.add(new DERTaggedObject(false, 0, notBefore));
        if (notAfter != null) v.add(new DERTaggedObject(false, 1, notAfter));
        return PrivateKeyUsagePeriod.getInstance(new DERSequence(v));
    }

    static IssuingDistributionPoint buildIssuingDP(Map<String, Object> em) {
        DistributionPointName dpn = null;
        if (em.containsKey("distributionPoint")) {
            Map<String, Object> d = (Map<String, Object>) em.get("distributionPoint");
            if ("fullName".equals(d.get("type"))) {
                List<Map<String, Object>> fn = (List<Map<String, Object>>) d.get("fullName");
                GeneralName[] gns = new GeneralName[fn.size()];
                for (int j = 0; j < fn.size(); j++) gns[j] = buildGN(fn.get(j));
                dpn = new DistributionPointName(new GeneralNames(gns));
            }
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (dpn != null) v.add(new DERTaggedObject(true, 0, dpn));
        if (boolVal(em, "onlyContainsUserCerts")) v.add(new DERTaggedObject(false, 1, ASN1Boolean.TRUE));
        if (boolVal(em, "onlyContainsCACerts")) v.add(new DERTaggedObject(false, 2, ASN1Boolean.TRUE));
        if (em.containsKey("onlySomeReasons") && em.get("onlySomeReasons") != null) {
            List<String> rs = (List<String>) em.get("onlySomeReasons");
            v.add(new DERTaggedObject(false, 3, new ReasonFlags(reasonNamesToMask(rs))));
        }
        if (boolVal(em, "indirectCRL")) v.add(new DERTaggedObject(false, 4, ASN1Boolean.TRUE));
        if (boolVal(em, "onlyContainsAttributeCerts")) v.add(new DERTaggedObject(false, 5, ASN1Boolean.TRUE));
        return IssuingDistributionPoint.getInstance(new DERSequence(v));
    }

    static boolean boolVal(Map<String, Object> m, String key) {
        return m.containsKey(key) && (Boolean) m.get(key);
    }

    // ==================== ReasonFlags 位列表 <-> 掩码 ====================

    static final String[] REASON_NAMES = {"unused","keyCompromise","cACompromise","affiliationChanged",
            "superseded","cessationOfOperation","certificateHold","privilegeWithdrawn","aACompromise"};
    static final int[] REASON_BITS = {ReasonFlags.unused, ReasonFlags.keyCompromise, ReasonFlags.cACompromise,
            ReasonFlags.affiliationChanged, ReasonFlags.superseded, ReasonFlags.cessationOfOperation,
            ReasonFlags.certificateHold, ReasonFlags.privilegeWithdrawn, ReasonFlags.aACompromise};

    /** ReasonFlags(DERBitString) -> 名称列表（JSON 可读） */
    static List<String> reasonFlagsToJson(ReasonFlags rf) {
        List<String> list = new ArrayList<>();
        if (rf == null) return list;
        int value = new BigInteger(1, rf.getBytes()).intValue();
        for (int i = 0; i < REASON_NAMES.length; i++)
            if ((value & REASON_BITS[i]) != 0) list.add(REASON_NAMES[i]);
        return list;
    }

    /** 名称列表 -> ReasonFlags 掩码 */
    static int reasonNamesToMask(List<String> names) {
        int mask = 0;
        for (String n : names)
            for (int i = 0; i < REASON_NAMES.length; i++)
                if (REASON_NAMES[i].equals(n)) { mask |= REASON_BITS[i]; break; }
        return mask;
    }

    static DERBitString buildNetscapeCertType(Map<String, Object> em) {
        List<String> types = (List<String>) em.get("netscapeCertType");
        String[] names = {"client","server","email","objsign","reserved","sslCA","emailCA","objCA"};
        int value = 0;
        for (String t : types) {
            for (int i = 0; i < names.length; i++) if (names[i].equals(t)) value |= (1 << (7 - i));
        }
        // Netscape cert type 是 8 位 BIT STRING，unusedBits 必须为 0（标准写法）
        return new DERBitString(new byte[]{(byte) value}, 0);
    }

    // ==================== SCT List (RFC 6962) 重建 ====================

    /** 构建 TLS 编码的 SCT List，返回 DEROctetString(TLS数据) */
    static DEROctetString buildSCTList(Map<String, Object> em) throws Exception {
        List<Map<String, Object>> scts = (List<Map<String, Object>>) em.get("sctList");
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        for (Map<String, Object> sct : scts) {
            byte[] sctRaw = buildSCTRaw(sct);
            writeUint16(inner, sctRaw.length);
            inner.write(sctRaw);
        }
        byte[] innerBytes = inner.toByteArray();
        ByteArrayOutputStream tls = new ByteArrayOutputStream();
        writeUint16(tls, innerBytes.length);
        tls.write(innerBytes);
        return new DEROctetString(tls.toByteArray());
    }

    static byte[] buildSCTRaw(Map<String, Object> sct) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(((Number) sct.get("version")).intValue());
        bos.write(fromHex((String) sct.get("logId")));
        long ts = ((Number) sct.get("timestamp")).longValue();
        for (int i = 7; i >= 0; i--) bos.write((int) ((ts >> (i * 8)) & 0xFF));
        String extHex = (String) sct.get("extensions");
        byte[] ext = (extHex != null && !extHex.isEmpty()) ? fromHex(extHex) : new byte[0];
        writeUint16(bos, ext.length);
        bos.write(ext);
        // 优先使用保留的原始算法字节码（国密 SCT 常用 07/04 等非标准值），兼容旧 JSON 只有名称的情况
        Number hashCode = (Number) sct.get("hashAlgorithmCode");
        Number sigCode = (Number) sct.get("signatureAlgorithmCode");
        bos.write(hashCode != null ? hashCode.intValue() : HASH_ALG_CODES.getOrDefault(sct.get("hashAlgorithm"), 4));
        bos.write(sigCode != null ? sigCode.intValue() : SIG_ALG_CODES.getOrDefault(sct.get("signatureAlgorithm"), 3));
        byte[] sig = fromHex((String) sct.get("signature"));
        writeUint16(bos, sig.length);
        bos.write(sig);
        return bos.toByteArray();
    }

    // ==================== JSON 序列化 ====================

    static String toJson(Object obj) {
        StringBuilder sb = new StringBuilder();
        writeJson(sb, obj, 0);
        sb.append("\n");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    static void writeJson(StringBuilder sb, Object obj, int indent) {
        if (obj == null) sb.append("null");
        else if (obj instanceof String) sb.append(jsonQuote((String) obj));
        else if (obj instanceof Number || obj instanceof Boolean) sb.append(obj.toString());
        else if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            if (map.isEmpty()) { sb.append("{}"); return; }
            sb.append("{\n");
            int i = 0;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                indent(sb, indent + 1);
                sb.append(jsonQuote(e.getKey())).append(": ");
                writeJson(sb, e.getValue(), indent + 1);
                if (i < map.size() - 1) sb.append(",");
                sb.append("\n");
                i++;
            }
            indent(sb, indent);
            sb.append("}");
        } else if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            if (list.isEmpty()) { sb.append("[]"); return; }
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                indent(sb, indent + 1);
                writeJson(sb, list.get(i), indent + 1);
                if (i < list.size() - 1) sb.append(",");
                sb.append("\n");
            }
            indent(sb, indent);
            sb.append("]");
        } else sb.append(jsonQuote(obj.toString()));
    }

    static void indent(StringBuilder sb, int level) { for (int i = 0; i < level; i++) sb.append("  "); }

    static String jsonQuote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c);
            }
        }
        return sb.append("\"").toString();
    }

    // ==================== JSON 解析器 ====================

    static class JsonParser {
        private final String s;
        private int pos;
        JsonParser(String s) { this.s = s; }

        Object parse() { skipWs(); Object v = value(); skipWs(); return v; }

        private Object value() {
            skipWs();
            char c = s.charAt(pos);
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't' || c == 'f') return bool();
            if (c == 'n') { nul(); return null; }
            return number();
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; skipWs();
            if (s.charAt(pos) == '}') { pos++; return map; }
            while (true) {
                skipWs();
                String key = string();
                skipWs(); pos++; // :
                map.put(key, value());
                skipWs();
                if (s.charAt(pos) == ',') { pos++; continue; }
                if (s.charAt(pos) == '}') { pos++; break; }
            }
            return map;
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            pos++; skipWs();
            if (s.charAt(pos) == ']') { pos++; return list; }
            while (true) {
                list.add(value());
                skipWs();
                if (s.charAt(pos) == ',') { pos++; continue; }
                if (s.charAt(pos) == ']') { pos++; break; }
            }
            return list;
        }

        private String string() {
            StringBuilder sb = new StringBuilder();
            pos++;
            while (s.charAt(pos) != '"') {
                char c = s.charAt(pos++);
                if (c == '\\') {
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u': sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16)); pos += 4; break;
                        default: sb.append(e);
                    }
                } else sb.append(c);
            }
            pos++;
            return sb.toString();
        }

        private Boolean bool() { if (s.startsWith("true", pos)) { pos += 4; return true; } pos += 5; return false; }
        private void nul() { pos += 4; }

        private Number number() {
            int start = pos;
            if (s.charAt(pos) == '-') pos++;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (Character.isDigit(c) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') pos++;
                else break;
            }
            String num = s.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E")) return Double.parseDouble(num);
            try { return Long.parseLong(num); } catch (NumberFormatException e) { return new BigInteger(num); }
        }

        private void skipWs() { while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++; }
    }
}
