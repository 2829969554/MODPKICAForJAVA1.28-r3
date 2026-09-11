package modpkica;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * RootGetCrl —— 签发吊销列表 CRL（对应 Go 版 cmd/rootgetcrl）。
 *
 * <p>遍历 CERTS.txt 中类型为 R（根）或 C（中间）的证书，对每一个颁发者：
 * <ul>
 *   <li>R 类型：从 PKI/ROOT/序列号.crt|.key 加载颁发者密钥对；</li>
 *   <li>C 类型：从 PKI/CA/序列号.crt|.key 加载颁发者密钥对；</li>
 * </ul>
 * 收集 CERTS.txt 中全部状态为 R（已吊销）的证书（序列号 / 吊销时间 / 吊销原因），
 * 用颁发者密钥对签名生成 CRL，输出：
 * <pre>
 *   PKI/WebPublic/CRL/序列号.crl     （PEM 格式 X509 CRL）
 *   PKI/WebPublic/CRL/序列号.der.crl （DER 原始格式）
 *   PKI/WebPublic/CRL/序列号.crl + 序列号.der.crl（多根模型，无 root.crl）
 * </pre>
 * CRL 的 thisUpdate=当前时间-24h，nextUpdate=当前时间+24h（对齐 Go 版）。
 */
public final class RootGetCrl {

    private static final DateTimeFormatter MOD_TIME =
            DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss");

    private RootGetCrl() {
    }

    public static void main(String[] args) throws Exception {
        run();
    }

    /** 供其它程序（如 MakeRoot / Admin）内部调用。 */
    public static void run() throws Exception {
        run(AppPaths.baseDir());
    }

    /** 供 ADMIN 内部调用：指定工作目录刷新 CRL。 */
    public static void run(String baseDir) throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);

        String rootDir = baseDir + "/PKI/ROOT/";
        String caDir = baseDir + "/PKI/CA/";
        String webCrlDir = baseDir + "/PKI/WebPublic/CRL/";
        java.nio.file.Files.createDirectories(java.nio.file.Paths.get(webCrlDir));

        int count = 0;
        for (CertsDB.CertEntry entry : db.getAll()) {
            if (entry.type == 'R' || entry.type == 'C') {
                generateCrl(entry, rootDir, caDir, webCrlDir, db);
                count++;
            }
        }
        System.out.println("CRL 生成完成，共处理颁发者 " + count + " 个");
    }

    private static void generateCrl(CertsDB.CertEntry issuer,
                                    String rootDir, String caDir, String webCrlDir,
                                    CertsDB db) throws Exception {
        // ---- 1. 加载颁发者证书与私钥 ----
        String issuerPath = issuer.type == 'R' ? rootDir : caDir;
        X509Certificate caCert = PemIO.readCert(issuerPath + issuer.serial + ".crt");
        AsymmetricKeyParameter akp = PemIO.readPrivateKey(issuerPath + issuer.serial + ".key");
        // BC 私钥参数 → JCA PrivateKey（CrlUtil 使用 JCA 接口）
        PrivateKey caKey = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(
                PrivateKeyInfoFactory.createPrivateKeyInfo(akp));

        // 签名算法：由证书的签名算法 OID 推导（对齐 Go 版 CreateCRL 使用证书自身签名算法）
        String keyType = certKeyType(caCert);
        String hash = certHashFromSigAlg(caCert);

        // ---- 2. 收集全部已吊销证书（状态 R） ----
        Date thisUpdate = Date.from(java.time.Instant.now().minusSeconds(24 * 3600));
        Date nextUpdate = Date.from(java.time.Instant.now().plusSeconds(24 * 3600));

        List<CertsDB.CertEntry> all = db.getAll();
        List<CrlUtil.RevokedCert> revoked = new ArrayList<>();
        for (CertsDB.CertEntry e : all) {
            if (e.status == 'R') {
                BigInteger serial = new BigInteger(e.serial, 16);
                Date revTime = parseModTime(e.time);
                revoked.add(new CrlUtil.RevokedCert(serial, revTime, e.reason));
            }
        }

        byte[] der = CrlUtil.generateCrl(caCert, caKey, revoked, thisUpdate, nextUpdate,
                keyType, hash);
        String pem = CrlUtil.derToPem(der);
        java.nio.file.Files.write(java.nio.file.Paths.get(webCrlDir + issuer.serial + ".der.crl"), der);
        java.nio.file.Files.write(java.nio.file.Paths.get(webCrlDir + issuer.serial + ".crl"),
                pem.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println("CRL 已生成: " + issuer.serial + " (算法 " + keyType + "/" + hash
                + ", 吊销 " + revokedCount(all) + " 条)");
    }

    private static int revokedCount(List<CertsDB.CertEntry> all) {
        int n = 0;
        for (CertsDB.CertEntry e : all) {
            if (e.status == 'R') {
                n++;
            }
        }
        return n;
    }

    /** CERTS.txt 内部时间（本地时间）转 Date。 */
    private static Date parseModTime(LocalDateTime t) {
        return Date.from(t.toInstant(ZoneOffset.ofHours(8))); // 按 UTC+8 解析（对齐 Go 文本时间）
    }

    /** 由证书签名算法 OID 推导证书类型（RSA/ECC/SM2）。 */
    private static String certKeyType(X509Certificate cert) {
        String oid = cert.getSigAlgOID();
        if (oid.contains("1.2.156.10197.1.501") || oid.contains("1.2.156.10197.1.301")) {
            return "SM2";
        }
        if (oid.contains("1.2.840.10045")) {
            return "ECC";
        }
        return "RSA";
    }

    /** 由证书签名算法 OID 推导哈希算法。 */
    private static String certHashFromSigAlg(X509Certificate cert) {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(cert.getSigAlgOID());
        if (oid.equals(new ASN1ObjectIdentifier("1.2.156.10197.1.501"))) {
            return "sm3";
        }
        // RSA: 1.2.840.113549.1.1.{5,11,12,13}
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"))) {
            return "sha1";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"))) {
            return "sha256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.12"))) {
            return "sha384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.113549.1.1.13"))) {
            return "sha512";
        }
        // ECDSA: 1.2.840.10045.4.1 / 4.3.2 / 4.3.3 / 4.3.4
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.1"))) {
            return "sha1";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.3.2"))) {
            return "sha256";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.3.3"))) {
            return "sha384";
        }
        if (oid.equals(new ASN1ObjectIdentifier("1.2.840.10045.4.3.4"))) {
            return "sha512";
        }
        return "sha256";
    }
}
