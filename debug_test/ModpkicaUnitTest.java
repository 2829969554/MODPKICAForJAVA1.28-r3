import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import modpkica.AppPaths;
import modpkica.CertUtil;
import modpkica.CertVerify;
import modpkica.CrlUtil;
import modpkica.Sm2Util;
import modpkica.X509JsonConverter;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * MODPKICA Java 版单元测试（debug_test）：
 * 覆盖本次审计整改的核心路径：
 *   1) X509JsonConverter KeyUsage BIT STRING 无损往返（RSA/ECC/SM2/PQC）；
 *   2) rekey / renew 后 KeyUsage 扩展 DER 与原始完全一致（审计 PKI-029 回归）；
 *   3) PQC（ML-DSA-65）自签 + rekey 冒烟；
 *   4) CertVerify 对真实 PKI 证书全链路验证（本地 issuer 回退冒烟）。
 *
 * 运行：java -cp "out;debug_test\classes;BC185\*" ModpkicaUnitTest
 */
public class ModpkicaUnitTest {

    static int pass = 0;
    static int fail = 0;

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("==========================================");
        System.out.println("  MODPKICA Unit Test (audit fix regression)");
        System.out.println("==========================================");

        testKeyUsageLossless("RSA", 2048, "sha256");
        testKeyUsageLossless("ECC", 256, "sha256");
        testKeyUsageLossless("SM2", 256, "sm3");
        testPqcSelfSigned();
        testRenewRoundtrip();
        testCrlExtensions();
        testSha3DsaEdDsa();
        testX509RoundtripMatrix();
        testX509FullExtRoundtrip();
        testX509RealPkiSamples();
        testPqcAllStrengthsRoundtrip();
        testDnMultiValueRoundtrip();
        testSctRealCertsRoundtrip();
        testSctConstructedRoundtrip();
        testCertVerifySmoke();
        testJsonMinimalization();
        testJsonTbsRawFallback();
        testJsonTimeRawFallback();
        testRsaPss();

        System.out.println("==========================================");
        System.out.println("  RESULT: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    // ---------- 1) KeyUsage lossless roundtrip for RSA/ECC/SM2 ----------
    static void testKeyUsageLossless(String algo, int bits, String hash) {
        try {
            System.out.println("\n[1] KeyUsage lossless roundtrip: " + algo);
            KeyPair kp = keyPairOf(algo, bits);
            X509Certificate c = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest Root, O=MODPKICA, C=CN"),
                    kp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    algo, hash);

            // 原始 KeyUsage 扩展的 BIT STRING DER（剥掉外层 OCTET STRING）
            byte[] kuDer = bitStringDerOf(c);
            String json = X509JsonConverter.certToJson(pem(c).getBytes(StandardCharsets.UTF_8));

            check(json.contains("keyUsageRaw"), algo + ": json contains keyUsageRaw");
            check(json.contains("keyUsageUnusedBits"), algo + ": json contains keyUsageUnusedBits");
            String rawHex = extract(json, "\"keyUsageRaw\"\\s*:\\s*\"([0-9a-fA-F]+)\"");
            int unused = extractInt(json, "\"keyUsageUnusedBits\"\\s*:\\s*(\\d+)");
            check(rawHex != null, algo + ": keyUsageRaw extracted");
            if (rawHex == null) {
                return;
            }
            byte[] rebuilt = rebuildBitStringDer(rawHex, unused);
            check(Arrays.equals(kuDer, rebuilt),
                    algo + ": KeyUsage BIT STRING rebuilt identically (unused=" + unused + ")");

            // rekey roundtrip: 新公钥 -> 重签名 -> KeyUsage DER 必须保持
            KeyPair newKp = X509JsonConverter.generateKeyPairFromJson(json);
            byte[] newPem = X509JsonConverter.rekeyJsonToPemByIssuer(
                    json, newKp, newKp.getPrivate(), algo);
            X509Certificate c2 = parsePem(newPem);
            byte[] kuDer2 = bitStringDerOf(c2);
            check(Arrays.equals(kuDer, kuDer2),
                    algo + ": rekey preserved KeyUsage DER byte-for-byte");
            // self-signed rekey: new keypair is the new issuer; new cert must verify with it
            try {
                c2.verify(newKp.getPublic());
                check(true, algo + ": rekey cert verifies with new public key");
            } catch (Exception ve) {
                if ("SM2".equals(algo)) {
                    // JCA SM3withSM2 may reject ZA handling; BC crypto verify directly
                    boolean ok = Sm2Util.sm2Verify(
                            Sm2Util.toEcPublicParams(newKp.getPublic()),
                            c2.getTBSCertificate(), c2.getSignature());
                    check(ok, "SM2: rekey cert verifies via Sm2Util (ZA-aware)");
                } else {
                    check(false, algo + ": rekey cert verify failed: " + ve);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            fail(algo + ": " + e);
        }
    }

    // ---------- 2) PQC (ML-DSA-65) self-signed + rekey ----------
    static void testPqcSelfSigned() {
        try {
            System.out.println("\n[2] PQC ML-DSA-65 self-signed + rekey");
            KeyPair kp = CertUtil.generatePqcKeyPair("ML-DSA-65");
            X509Certificate c = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest PQC Root, O=MODPKICA, C=CN"),
                    kp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "PQC", "NULL");
            String json = X509JsonConverter.certToJson(pem(c).getBytes(StandardCharsets.UTF_8));
            // ML-DSA-65 签名 OID = 2.16.840.1.101.3.4.3.18
            check(json.contains("2.16.840.1.101.3.4.3.18"),
                    "PQC: sig OID 2.16.840.1.101.3.4.3.18 present in JSON");

            KeyPair newKp = X509JsonConverter.generateKeyPairFromJson(json);
            byte[] newPem = X509JsonConverter.rekeyJsonToPemByIssuer(
                    json, newKp, newKp.getPrivate(), "PQC");
            X509Certificate c2 = parsePem(newPem);
            // self-signed rekey: new keypair is the new issuer; ML-DSA verifies with new public key
            c2.verify(newKp.getPublic());
            check(true, "PQC: rekey cert verifies with new public key");
        } catch (Exception e) {
            e.printStackTrace();
            fail("PQC: " + e);
        }
    }

    // ---------- 3) renew roundtrip keeps KeyUsage and updates validity ----------
    static void testRenewRoundtrip() {
        try {
            System.out.println("\n[3] renew roundtrip (validity update + KeyUsage preserved)");
            KeyPair rootKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate root = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest Renew Root, O=MODPKICA, C=CN"),
                    rootKp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");

            KeyPair eeKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate ee = CertUtil.buildSignedCert(
                    root, rootKp.getPrivate(),
                    new X500Principal("CN=www.unittest.com, O=MODPKICA, C=CN"),
                    eeKp.getPublic(), new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                    "RSA", "sha256", false, null, null, null, null, null);
            byte[] kuDer = bitStringDerOf(ee);
            String json = X509JsonConverter.certToJson(pem(ee).getBytes(StandardCharsets.UTF_8));

            Date nb2 = new Date(System.currentTimeMillis() + 10L * 24 * 3600 * 1000);
            Date na2 = new Date(System.currentTimeMillis() + 400L * 24 * 3600 * 1000);
            byte[] renewedPem = X509JsonConverter.renewJsonToPemByIssuer(
                    json, nb2, na2, rootKp.getPrivate(), "RSA");
            X509Certificate c2 = parsePem(renewedPem);
            check(c2.getNotBefore().getTime() / 1000 == nb2.getTime() / 1000,
                    "renew: notBefore updated");
            check(c2.getNotAfter().getTime() / 1000 == na2.getTime() / 1000,
                    "renew: notAfter updated");
            check(Arrays.equals(kuDer, bitStringDerOf(c2)),
                    "renew: KeyUsage DER preserved");
            c2.verify(root.getPublicKey());
            check(true, "renew: signature verifies with issuer public key");
        } catch (Exception e) {
            e.printStackTrace();
            fail("renew: " + e);
        }
    }

    // ---------- 5) CRL extensions per RFC 5280 (5.2.3 cRLNumber, 5.2.4 AKI) ----------
    static void testCrlExtensions() {
        try {
            System.out.println("\n[5] CRL extensions (RFC 5280 5.2.3 / 5.2.4)");
            KeyPair caKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate ca = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest CRL CA, O=MODPKICA, C=CN"),
                    caKp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");

            byte[] akiExpected = CertUtil.getSubjectKeyIdentifier(ca.getPublicKey());
            Date now = new Date();
            java.util.List<CrlUtil.RevokedCert> revoked = new java.util.ArrayList<>();
            revoked.add(new CrlUtil.RevokedCert(
                    new BigInteger("deadbeef", 16), now, 5));

            // cRLNumber 必须单调递增：第 1 次 = 1，第 2 次 = 2
            for (int expected = 1; expected <= 2; expected++) {
                java.security.cert.X509CRL crl = CrlUtil.generateCrlObject(
                        ca, caKp.getPrivate(), revoked,
                        new Date(now.getTime() - 3600_000L), new Date(now.getTime() + 3600_000L),
                        "RSA", "sha256", BigInteger.valueOf(expected));
                byte[] numDer = crl.getExtensionValue("2.5.29.20");
                check(numDer != null, "CRL[" + expected + "]: cRLNumber extension present");
                if (numDer != null) {
                    BigInteger num = org.bouncycastle.asn1.x509.CRLNumber.getInstance(
                            DEROctetString.getInstance(
                                    ASN1Primitive.fromByteArray(numDer)).getOctets()).getCRLNumber();
                    check(num.longValue() == expected,
                            "CRL[" + expected + "]: cRLNumber value = " + expected);
                }
                byte[] akiDer = crl.getExtensionValue("2.5.29.35");
                check(akiDer != null, "CRL[" + expected + "]: authorityKeyIdentifier present");
                if (akiDer != null) {
                    byte[] aki = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier.getInstance(
                            DEROctetString.getInstance(
                                    ASN1Primitive.fromByteArray(akiDer)).getOctets())
                            .getKeyIdentifier();
                    check(Arrays.equals(aki, akiExpected),
                            "CRL[" + expected + "]: AKI keyIdentifier = CA SKI");
                }
            }
            // 吊销条目本身（reasonCode 2.5.29.21）仍正常
            java.security.cert.X509CRL crl = CrlUtil.generateCrlObject(
                    ca, caKp.getPrivate(), revoked,
                    new Date(now.getTime() - 3600_000L), new Date(now.getTime() + 3600_000L),
                    "RSA", "sha256", BigInteger.ONE);
            check(!crl.getRevokedCertificates().isEmpty(),
                    "CRL: revoked entry present");

            // SHA3-256 签名 CRL：不抛异常且签名可验证（CRL 签发链路 SHA3 支持）
            java.security.cert.X509CRL crlSha3 = CrlUtil.generateCrlObject(
                    ca, caKp.getPrivate(), revoked,
                    new Date(now.getTime() - 3600_000L), new Date(now.getTime() + 3600_000L),
                    "RSA", "sha3-256", BigInteger.valueOf(9));
            crlSha3.verify(ca.getPublicKey(), "BC");
            check(true, "CRL: SHA3-256 signed CRL verifies");
        } catch (Exception e) {
            e.printStackTrace();
            fail("CRL extensions: " + e);
        }
    }

    // ---------- 6) SHA3 / DSA / EdDSA signing smoke ----------
    static void testSha3DsaEdDsa() {
        try {
            System.out.println("\n[6] SHA3 / DSA / EdDSA signing smoke");
            Date nb = new Date();
            Date na = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
            BigInteger serial = new BigInteger(64, new SecureRandom());

            // RSA + SHA3-256
            KeyPair rsa = CertUtil.generateRsaKeyPair(2048);
            X509Certificate c1 = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest SHA3 RSA, O=MODPKICA, C=CN"),
                    rsa, serial, nb, na, "RSA", "sha3-256");
            c1.verify(rsa.getPublic(), "BC");
            check(true, "RSA + SHA3-256 self-signed verifies");

            // ECC + SHA3-512
            KeyPair ecc = CertUtil.generateEccKeyPair(256);
            X509Certificate c2 = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest SHA3 ECC, O=MODPKICA, C=CN"),
                    ecc, serial, nb, na, "ECC", "sha3-512");
            c2.verify(ecc.getPublic(), "BC");
            check(true, "ECC + SHA3-512 self-signed verifies");

            // DSA 2048 + SHA256
            KeyPair dsa = CertUtil.generateDsaKeyPair(2048);
            X509Certificate c3 = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest DSA, O=MODPKICA, C=CN"),
                    dsa, serial, nb, na, "DSA", "sha256");
            c3.verify(dsa.getPublic(), "BC");
            check(true, "DSA + SHA256 self-signed verifies");

            // DSA + SHA3-256
            X509Certificate c4 = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest DSA SHA3, O=MODPKICA, C=CN"),
                    dsa, serial, nb, na, "DSA", "sha3-256");
            c4.verify(dsa.getPublic(), "BC");
            check(true, "DSA + SHA3-256 self-signed verifies");

            // Ed25519（哈希参数忽略，纯签名）
            KeyPair ed = CertUtil.generateEd25519KeyPair();
            X509Certificate c5 = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest Ed25519, O=MODPKICA, C=CN"),
                    ed, serial, nb, na, "EdDSA", "NULL");
            c5.verify(ed.getPublic(), "BC");
            check(true, "Ed25519 self-signed verifies");
        } catch (Exception e) {
            e.printStackTrace();
            fail("SHA3/DSA/EdDSA: " + e);
        }
    }

    // ---------- 7) X509JsonConverter 全算法×哈希 DER 字节级可逆往返 ----------
    // 覆盖：RSA(SHA1/224/256/384/512/SHA3-*)、ECC(同)、SM2(SM3)、DSA(SHA1..SHA3)、
    //      EdDSA(Ed25519)、PQC(ML-DSA-44/65/87)。
    // 断言：certToJson → jsonToCertPem 重建的 DER 与原始 DER 逐字节一致（强可逆）。
    static void testX509RoundtripMatrix() {
        String[][] mat = {
                {"RSA", "sha1", "2048"}, {"RSA", "sha224", "2048"},
                {"RSA", "sha256", "2048"}, {"RSA", "sha384", "2048"}, {"RSA", "sha512", "2048"},
                {"RSA", "sha3-224", "2048"}, {"RSA", "sha3-256", "2048"},
                {"RSA", "sha3-384", "2048"}, {"RSA", "sha3-512", "2048"},
                {"ECC", "sha1", "256"}, {"ECC", "sha224", "256"},
                {"ECC", "sha256", "256"}, {"ECC", "sha384", "384"}, {"ECC", "sha512", "521"},
                {"ECC", "sha3-224", "256"}, {"ECC", "sha3-256", "256"},
                {"ECC", "sha3-384", "384"}, {"ECC", "sha3-512", "521"},
                {"SM2", "sm3", "256"},
                {"DSA", "sha1", "1024"}, {"DSA", "sha224", "2048"}, {"DSA", "sha256", "2048"},
                {"DSA", "sha384", "3072"}, {"DSA", "sha512", "3072"}, {"DSA", "sha3-256", "2048"},
                {"EdDSA", "NULL", "256"},
        };
        System.out.println("\n[7] X509JsonConverter byte-exact roundtrip matrix ("
                + mat.length + " combos)");
        for (String[] m : mat) {
            String algo = m[0], hash = m[1], bits = m[2];
            try {
                KeyPair kp = keyPairOf(algo, Integer.parseInt(bits));
                X509Certificate c = CertUtil.buildSelfSignedRoot(
                        new X500Principal("CN=UnitTest RT " + algo + "-" + hash + ", O=MODPKICA, C=CN"),
                        kp, new BigInteger(64, new SecureRandom()),
                        new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                        algo, hash);
                byte[] origDer = c.getEncoded();
                String json = X509JsonConverter.certToJson(pem(c).getBytes(StandardCharsets.UTF_8));
                byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
                X509Certificate c2 = parsePem(rebuiltPem);
                byte[] rebuiltDer = c2.getEncoded();
                check(Arrays.equals(origDer, rebuiltDer),
                        algo + "/" + hash + ": DER byte-exact roundtrip");
                // 重建证书必须能用自己的公钥验签（签名值原样保留）
                c2.verify(kp.getPublic(), "BC");
            } catch (Exception e) {
                e.printStackTrace();
                fail(algo + "/" + hash + ": " + e);
            }
        }
    }

    // ---------- 8) 完整扩展集证书的 JSON 无损往返（标准扩展 + 未知扩展 rawHex） ----------
    static void testX509FullExtRoundtrip() {
        try {
            System.out.println("\n[8] Full-extension certificate roundtrip");
            KeyPair caKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate ca = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest Ext CA, O=MODPKICA, C=CN"),
                    caKp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");

            KeyPair eeKp = CertUtil.generateEccKeyPair(256);
            BigInteger serial = new BigInteger(64, new SecureRandom());
            Date nb = new Date();
            Date na = new Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000);
            JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                    ca, serial, nb, na,
                    new X500Principal("CN=www.ext-unittest.com, O=MODPKICA, C=CN"),
                    eeKp.getPublic());
            cb.addExtension(Extension.subjectKeyIdentifier, false,
                    new org.bouncycastle.asn1.x509.SubjectKeyIdentifier(
                            CertUtil.getSubjectKeyIdentifier(eeKp.getPublic())));
            cb.addExtension(Extension.authorityKeyIdentifier, false,
                    new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(
                            CertUtil.getSubjectKeyIdentifier(ca.getPublicKey())));
            cb.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            cb.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(new KeyPurposeId[]{
                            KeyPurposeId.getInstance(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1")),
                            KeyPurposeId.getInstance(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.3"))}));
            cb.addExtension(Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(false));
            cb.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[]{
                    new GeneralName(GeneralName.dNSName, "www.ext-unittest.com"),
                    new GeneralName(GeneralName.iPAddress, "192.168.1.10"),
                    new GeneralName(GeneralName.uniformResourceIdentifier, "https://gitee.com/wxgshuju/modpkica"),
                    new GeneralName(GeneralName.rfc822Name, "admin@ext-unittest.com")}));
            cb.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{
                    new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(
                            GeneralName.uniformResourceIdentifier, "http://localhost:80/CRL/" + serial.toString(16) + ".crl"))), null, null)}));
            cb.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1"), false,
                    new org.bouncycastle.asn1.x509.AuthorityInformationAccess(new org.bouncycastle.asn1.x509.AccessDescription[]{
                            new org.bouncycastle.asn1.x509.AccessDescription(
                                    org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp,
                                    new GeneralName(GeneralName.uniformResourceIdentifier, "http://localhost:80/ocsp")),
                            new org.bouncycastle.asn1.x509.AccessDescription(
                                    org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers,
                                    new GeneralName(GeneralName.uniformResourceIdentifier,
                                            "http://localhost:80/CRT/" + serial.toString(16) + ".crt"))}));
            // 自定义未知扩展（rawHex 无损路径）
            cb.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.9"),
                    false, new DEROctetString("custom-extension-value".getBytes(StandardCharsets.UTF_8)));

            org.bouncycastle.operator.ContentSigner cs = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC").build(caKp.getPrivate());
            X509Certificate ee = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(cb.build(cs));

            byte[] origDer = ee.getEncoded();
            String json = X509JsonConverter.certToJson(pem(ee).getBytes(StandardCharsets.UTF_8));
            byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
            X509Certificate c2 = parsePem(rebuiltPem);
            byte[] rebuiltDer = c2.getEncoded();
            check(Arrays.equals(origDer, rebuiltDer), "Full-ext: DER byte-exact roundtrip");
            check(json.contains("1.2.3.4.5.6.7.8.9"), "Full-ext: unknown ext OID preserved");
            check(json.contains("rawHex"), "Full-ext: unknown ext rawHex preserved");
            c2.verify(ca.getPublicKey(), "BC");
            check(true, "Full-ext: signature verifies with issuer");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Full-ext roundtrip: " + e);
        }
    }

    // ---------- 9) 真实 PKI 目录证书样本往返（只读，不修改） ----------
    static void testX509RealPkiSamples() {
        System.out.println("\n[9] Real PKI certificate samples roundtrip");
        java.io.File pki = new java.io.File(AppPaths.baseDir(), "PKI");
        String[] dirs = {"ROOT", "CA", "CERT", "OCSP", "TIMSTAMP"};
        int scanned = 0;
        for (String d : dirs) {
            java.io.File dir = new java.io.File(pki, d);
            java.io.File[] files = dir.listFiles((dd, n) ->
                    n.toLowerCase().endsWith(".crt") || n.toLowerCase().endsWith(".cer"));
            if (files == null) {
                continue;
            }
            for (java.io.File f : files) {
                scanned++;
                try {
                    byte[] pemBytes = java.nio.file.Files.readAllBytes(f.toPath());
                    String json = X509JsonConverter.certToJson(pemBytes);
                    byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
                    X509Certificate orig = parsePem(pemBytes);
                    X509Certificate c2 = parsePem(rebuiltPem);
                    check(Arrays.equals(orig.getEncoded(), c2.getEncoded()),
                            "sample " + d + "/" + f.getName() + ": DER byte-exact");
                } catch (Exception e) {
                    fail("sample " + d + "/" + f.getName() + ": " + e);
                }
            }
        }
        if (scanned == 0) {
            check(true, "Real samples: skipped (no PKI certs)");
        } else {
            System.out.println("      scanned " + scanned + " cert files");
        }
    }

    // ---------- 10) PQC 全强度（ML-DSA-44/65/87）DER 往返 ----------
    static void testPqcAllStrengthsRoundtrip() {
        System.out.println("\n[10] PQC all strengths roundtrip (44/65/87)");
        String[] specs = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
        for (String spec : specs) {
            try {
                KeyPair kp = CertUtil.generatePqcKeyPair(spec);
                X509Certificate c = CertUtil.buildSelfSignedRoot(
                        new X500Principal("CN=PQC RT " + spec + ", O=MODPKICA, C=CN"),
                        kp, new BigInteger(64, new SecureRandom()),
                        new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                        "PQC", "NULL");
                byte[] origDer = c.getEncoded();
                String json = X509JsonConverter.certToJson(pem(c).getBytes(StandardCharsets.UTF_8));
                byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
                byte[] rebuiltDer = parsePem(rebuiltPem).getEncoded();
                check(Arrays.equals(origDer, rebuiltDer), "PQC " + spec + ": DER byte-exact");
                check(json.contains("2.16.840.1.101.3.4.3.17")
                                || json.contains("2.16.840.1.101.3.4.3.18")
                                || json.contains("2.16.840.1.101.3.4.3.19"),
                        "PQC " + spec + ": sig OID present");
            } catch (Exception e) {
                e.printStackTrace();
                fail("PQC " + spec + ": " + e);
            }
        }
    }

    // ---------- 11) 多值 RDN / 特殊字符串编码 DN 证书 DER 往返 ----------
    static void testDnMultiValueRoundtrip() {
        System.out.println("\n[11] Multi-value RDN + special string encodings roundtrip");
        try {
            KeyPair caKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate ca = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest DN CA, O=MODPKICA, C=CN"),
                    caKp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");
            KeyPair eeKp = CertUtil.generateRsaKeyPair(2048);

            // 多值 RDN：CN=John Doe + OU=Dev 同一 RDN；BMPString 州名；IA5String 域
            org.bouncycastle.asn1.x500.RDN multi = new org.bouncycastle.asn1.x500.RDN(
                    new org.bouncycastle.asn1.x500.AttributeTypeAndValue[]{
                            new org.bouncycastle.asn1.x500.AttributeTypeAndValue(
                                    org.bouncycastle.asn1.x500.style.BCStyle.CN, new org.bouncycastle.asn1.DERUTF8String("John Doe")),
                            new org.bouncycastle.asn1.x500.AttributeTypeAndValue(
                                    org.bouncycastle.asn1.x500.style.BCStyle.OU, new org.bouncycastle.asn1.DERUTF8String("Dev"))});
            org.bouncycastle.asn1.x500.RDN bmp = new org.bouncycastle.asn1.x500.RDN(
                    org.bouncycastle.asn1.x500.style.BCStyle.ST, new org.bouncycastle.asn1.DERBMPString("河南"));
            org.bouncycastle.asn1.x500.RDN ia5 = new org.bouncycastle.asn1.x500.RDN(
                    org.bouncycastle.asn1.x500.style.BCStyle.C, new org.bouncycastle.asn1.DERIA5String("CN"));
            org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
                    new org.bouncycastle.asn1.x500.RDN[]{multi, bmp, ia5});

            org.bouncycastle.cert.X509v3CertificateBuilder cb = new org.bouncycastle.cert.X509v3CertificateBuilder(
                    new org.bouncycastle.asn1.x500.X500Name(ca.getSubjectX500Principal().getName()),
                    new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                    subject, org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded()));
            org.bouncycastle.operator.ContentSigner cs = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC").build(caKp.getPrivate());
            X509Certificate ee = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(cb.build(cs));

            byte[] origDer = ee.getEncoded();
            String json = X509JsonConverter.certToJson(pem(ee).getBytes(StandardCharsets.UTF_8));
            byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
            byte[] rebuiltDer = parsePem(rebuiltPem).getEncoded();
            check(Arrays.equals(origDer, rebuiltDer), "DN multi-value + BMPString/IA5String: DER byte-exact");
            check(json.contains("John Doe"), "DN: multi-value CN preserved");
        } catch (Exception e) {
            e.printStackTrace();
            fail("DN multi-value roundtrip: " + e);
        }
    }

    // ---------- 12) 真实含 SCT 的公网证书往返（桌面 demo 样本，存在则测） ----------
    static void testSctRealCertsRoundtrip() {
        System.out.println("\n[12] Real public certs with SCT lists roundtrip");
        java.io.File[] samples = {
                new java.io.File("C:\\Users\\28299\\Desktop\\demo1.crt"),
                new java.io.File("C:\\Users\\28299\\Desktop\\demo2.crt"),
                new java.io.File("C:\\Users\\28299\\Desktop\\demo3.crt"),
        };
        int tested = 0;
        for (java.io.File f : samples) {
            if (!f.isFile()) {
                continue;
            }
            tested++;
            try {
                byte[] pemBytes = java.nio.file.Files.readAllBytes(f.toPath());
                String json = X509JsonConverter.certToJson(pemBytes);
                check(json.contains("1.3.6.1.4.1.11129.2.4.2"), f.getName() + ": SCT ext parsed");
                byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
                byte[] origDer = parsePem(pemBytes).getEncoded();
                byte[] rebuiltDer = parsePem(rebuiltPem).getEncoded();
                check(Arrays.equals(origDer, rebuiltDer), f.getName() + ": DER byte-exact with SCT");
            } catch (Exception e) {
                fail(f.getName() + ": " + e);
            }
        }
        if (tested == 0) {
            check(true, "Real SCT samples: skipped (demo certs not on Desktop)");
        }
    }

    // ---------- 13) 手工构造含 RFC 6962 SCT 列表的证书：JSON 解析 + DER 往返 ----------
    static void testSctConstructedRoundtrip() {
        System.out.println("\n[13] Constructed SCT-list certificate roundtrip");
        try {
            KeyPair caKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate ca = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=UnitTest SCT CA, O=MODPKICA, C=CN"),
                    caKp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");
            KeyPair eeKp = CertUtil.generateEccKeyPair(256);

            // RFC 6962 SerializedSCT: version(1) log_id(32) timestamp(8) ext_len(2) hash(1) sig(1) sig_len(2) sig
            ByteArrayOutputStream sctRaw = new ByteArrayOutputStream();
            sctRaw.write(0);
            byte[] logId = new byte[32];
            new SecureRandom().nextBytes(logId);
            sctRaw.write(logId);
            long ts = System.currentTimeMillis();
            for (int i = 7; i >= 0; i--) sctRaw.write((int) ((ts >> (i * 8)) & 0xFF));
            sctRaw.write(0); sctRaw.write(0);                 // extensions len = 0
            sctRaw.write(4);                                  // hashAlgorithm = SHA256
            sctRaw.write(3);                                  // signatureAlgorithm = ECDSA
            byte[] sig = new byte[70];
            new SecureRandom().nextBytes(sig);
            sctRaw.write((sig.length >>> 8) & 0xFF); sctRaw.write(sig.length & 0xFF);
            sctRaw.write(sig);
            // TLS SCT list: uint16 totalLen + (uint16 sctLen + raw)
            ByteArrayOutputStream tls = new ByteArrayOutputStream();
            tls.write(0); tls.write((2 + sctRaw.size()) & 0xFF);
            tls.write(0); tls.write(sctRaw.size() & 0xFF);
            tls.write(sctRaw.toByteArray());

            // 扩展值（双重 OCTET STRING：OCTET STRING { OCTET STRING { TLS } }）
            org.bouncycastle.asn1.DEROctetString inner = new org.bouncycastle.asn1.DEROctetString(tls.toByteArray());

            JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
                    ca, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                    new X500Principal("CN=sct.example.com, O=MODPKICA, C=CN"), eeKp.getPublic());
            cb.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"), false, inner);
            org.bouncycastle.operator.ContentSigner cs = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider("BC").build(eeKp.getPrivate());
            X509Certificate ee = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(cb.build(cs));

            byte[] origDer = ee.getEncoded();
            String json = X509JsonConverter.certToJson(pem(ee).getBytes(StandardCharsets.UTF_8));
            check(json.contains("1.3.6.1.4.1.11129.2.4.2"), "SCT: ext OID in JSON");
            check(json.contains("sctList"), "SCT: sctList parsed");
            check(json.contains("timestamp"), "SCT: per-SCT timestamp parsed");
            byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
            byte[] rebuiltDer = parsePem(rebuiltPem).getEncoded();
            check(Arrays.equals(origDer, rebuiltDer), "SCT: DER byte-exact roundtrip with SCT list");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Constructed SCT roundtrip: " + e);
        }
    }

    // ---------- 4) CertVerify smoke against real PKI (local issuer fallback path) ----------
    static void testCertVerifySmoke() {
        try {
            System.out.println("\n[4] CertVerify smoke (real PKI, AIA-less fallback)");
            java.io.File rootDir = new java.io.File(AppPaths.baseDir(), "PKI/ROOT");
            java.io.File[] roots = rootDir.listFiles((d, n) ->
                    n.toLowerCase().endsWith(".crt") || n.toLowerCase().endsWith(".cer"));
            if (roots == null || roots.length == 0) {
                System.out.println("      (skip: no PKI/ROOT certs at " + rootDir + ")");
                check(true, "CertVerify: skipped (no PKI data)");
                return;
            }
            java.io.File target = roots[0];
            System.out.println("      verifying " + target.getName());
            CertVerify.run(target.getAbsolutePath());
            check(true, "CertVerify: ran without exception on " + target.getName());
        } catch (Exception e) {
            fail("CertVerify smoke: " + e);
        }
    }

    // ---------- 14) JSON 自适应精简：往返一致则省略 raw，减少体积 ----------
    static void testJsonMinimalization() {
        System.out.println("\n[14] JSON adaptive minimization (raw omitted when rebuilt identically)");
        try {
            // ECC：曲线参数结构化 {type:oid,value:...}，不再存 hex
            KeyPair ecc = CertUtil.generateEccKeyPair(256);
            X509Certificate ce = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=MinTest ECC, O=MODPKICA, C=CN"),
                    ecc, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "ECC", "sha256");
            String je = X509JsonConverter.certToJson(pem(ce).getBytes(StandardCharsets.UTF_8));
            check(je.contains("\"type\": \"oid\""),
                    "ECC: curve params structured (no hex raw)");
            byte[] re = parsePem(X509JsonConverter.jsonToCertPem(je)).getEncoded();
            check(Arrays.equals(ce.getEncoded(), re), "ECC: DER byte-exact after minimization");

            // DSA：p/q/g 结构化
            KeyPair dsa = CertUtil.generateDsaKeyPair(2048);
            X509Certificate cd = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=MinTest DSA, O=MODPKICA, C=CN"),
                    dsa, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "DSA", "sha256");
            String jd = X509JsonConverter.certToJson(pem(cd).getBytes(StandardCharsets.UTF_8));
            check(jd.contains("\"type\": \"dsa\""), "DSA: p/q/g params structured");
            byte[] rd = parsePem(X509JsonConverter.jsonToCertPem(jd)).getEncoded();
            check(Arrays.equals(cd.getEncoded(), rd), "DSA: DER byte-exact after minimization");

            // RSA：validity 时间由 value 可精确重建（UTCTime），省略 raw
            KeyPair rsa = CertUtil.generateRsaKeyPair(2048);
            X509Certificate cr = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=MinTest RSA, O=MODPKICA, C=CN"),
                    rsa, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");
            String jr = X509JsonConverter.certToJson(pem(cr).getBytes(StandardCharsets.UTF_8));
            int vi = jr.indexOf("\"validity\"");
            int si = jr.indexOf("\"signatureAlgorithm\"");
            String vseg = jr.substring(vi, si > 0 ? si : jr.length());
            check(!vseg.contains("\"raw\""), "RSA: validity times omit raw (rebuilt identically)");
            byte[] rr = parsePem(X509JsonConverter.jsonToCertPem(jr)).getEncoded();
            check(Arrays.equals(cr.getEncoded(), rr), "RSA: DER byte-exact after minimization");
        } catch (Exception e) {
            e.printStackTrace();
            fail("JSON minimization: " + e);
        }
    }

    // ---------- 15) tbsRaw 终极兜底：JSON 注入原始 TBS hex 后优先回用 ----------
    static void testJsonTbsRawFallback() {
        System.out.println("\n[15] tbsRaw ultimate fallback");
        try {
            KeyPair kp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate c = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=TbsRaw Test, O=MODPKICA, C=CN"),
                    kp, new BigInteger(64, new SecureRandom()),
                    new Date(), new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
                    "RSA", "sha256");
            byte[] origDer = c.getEncoded();
            String json = X509JsonConverter.certToJson(pem(c).getBytes(StandardCharsets.UTF_8));

            // 篡改 subject DN，使结构化重建必然与原始不同
            String tampered = json.replace("TbsRaw Test", "TbsRaw Tampered");
            check(!tampered.equals(json), "tbsRaw: tampered json differs");

            // 无 tbsRaw：重建结果反映篡改（结构化路径仍工作）
            byte[] rebuiltTampered = parsePem(X509JsonConverter.jsonToCertPem(tampered)).getEncoded();
            check(!Arrays.equals(origDer, rebuiltTampered), "tbsRaw: tampered rebuild differs from original");

            // 原始 TBS DER hex（Certificate ::= SEQUENCE{ tbs[0] alg[1] sig[2] }）
            org.bouncycastle.asn1.ASN1Sequence seq =
                    org.bouncycastle.asn1.ASN1Sequence.getInstance(origDer);
            String tbsHex = toHexStr(seq.getObjectAt(0).toASN1Primitive().getEncoded());

            // 注入 tbsRaw 到根对象末尾
            int lb = tampered.lastIndexOf('}');
            String withRaw = tampered.substring(0, lb) + ",\"tbsRaw\":\"" + tbsHex + "\""
                    + tampered.substring(lb);
            byte[] rebuiltRaw = parsePem(X509JsonConverter.jsonToCertPem(withRaw)).getEncoded();
            check(Arrays.equals(origDer, rebuiltRaw),
                    "tbsRaw: original TBS reused -> DER byte-exact despite tampered fields");
        } catch (Exception e) {
            e.printStackTrace();
            fail("tbsRaw fallback: " + e);
        }
    }

    // ---------- 16) 时间 raw 兜底：小数秒 GeneralizedTime 保留 raw ----------
    static void testJsonTimeRawFallback() {
        System.out.println("\n[16] time raw fallback (fractional seconds)");
        try {
            KeyPair kp = CertUtil.generateRsaKeyPair(2048);
            org.bouncycastle.asn1.ASN1GeneralizedTime g1 =
                    new org.bouncycastle.asn1.ASN1GeneralizedTime("20260913123456.123Z");
            org.bouncycastle.asn1.ASN1GeneralizedTime g2 =
                    new org.bouncycastle.asn1.ASN1GeneralizedTime("20270913123456.123Z");
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            org.bouncycastle.cert.X509v3CertificateBuilder cb = new org.bouncycastle.cert.X509v3CertificateBuilder(
                    new org.bouncycastle.asn1.x500.X500Name("CN=GTime Test, O=MODPKICA, C=CN"),
                    new BigInteger(64, new SecureRandom()),
                    new org.bouncycastle.asn1.x509.Time(g1),
                    new org.bouncycastle.asn1.x509.Time(g2),
                    new org.bouncycastle.asn1.x500.X500Name("CN=GTime Test, O=MODPKICA, C=CN"),
                    spki);
            org.bouncycastle.operator.ContentSigner cs =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                            .setProvider("BC").build(kp.getPrivate());
            X509Certificate c = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider("BC").getCertificate(cb.build(cs));
            String json = X509JsonConverter.certToJson(pem(c).getBytes(StandardCharsets.UTF_8));
            int vi = json.indexOf("\"validity\"");
            int si = json.indexOf("\"signatureAlgorithm\"");
            String vseg = json.substring(vi, si > 0 ? si : json.length());
            check(vseg.contains("\"raw\""), "GTime: fractional seconds keep raw");
            byte[] rebuilt = parsePem(X509JsonConverter.jsonToCertPem(json)).getEncoded();
            check(Arrays.equals(c.getEncoded(), rebuilt), "GTime: DER byte-exact with raw fallback");
        } catch (Exception e) {
            e.printStackTrace();
            fail("time raw fallback: " + e);
        }
    }

    static String toHexStr(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    // ============================ helpers ============================

    static KeyPair keyPairOf(String algo, int bits) throws Exception {
        switch (algo) {
            case "RSA": return CertUtil.generateRsaKeyPair(bits);
            case "ECC": return CertUtil.generateEccKeyPair(bits);
            case "SM2": return CertUtil.generateSm2KeyPair();
            case "DSA": return CertUtil.generateDsaKeyPair(bits);
            case "EdDSA": return CertUtil.generateEd25519KeyPair();
            default: throw new IllegalArgumentException(algo);
        }
    }

    /** 证书 KeyUsage 扩展（2.5.29.15）的 BIT STRING 完整 DER。 */
    static byte[] bitStringDerOf(X509Certificate c) throws Exception {
        byte[] octets = DEROctetString.getInstance(
                ASN1Primitive.fromByteArray(c.getExtensionValue("2.5.29.15"))).getOctets();
        return octets;
    }

    /** 由 JSON 中的 raw octets + unused bits 手工重建 BIT STRING 的完整 DER（03 len pad data）。 */
    static byte[] rebuildBitStringDer(String rawHex, int unused) {
        byte[] raw = hex(rawHex);
        byte[] der = new byte[3 + raw.length];
        der[0] = 0x03;
        der[1] = (byte) (raw.length + 1);
        der[2] = (byte) unused;
        System.arraycopy(raw, 0, der, 3, raw.length);
        return der;
    }

    static String pem(X509Certificate c) throws Exception {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(c.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64
                + "\n-----END CERTIFICATE-----\n";
    }

    static X509Certificate parsePem(byte[] pemBytes) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(pemBytes));
    }

    static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    | Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }

    static String extract(String text, String regex) {
        Matcher m = Pattern.compile(regex).matcher(text);
        return m.find() ? m.group(1) : null;
    }

    static int extractInt(String text, String regex) {
        Matcher m = Pattern.compile(regex).matcher(text);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    static void check(boolean cond, String name) {
        if (cond) {
            pass++;
            System.out.println("  PASS  " + name);
        } else {
            fail++;
            System.out.println("  FAIL  " + name);
        }
    }

    static void fail(String msg) {
        fail++;
        System.out.println("  FAIL  " + msg);
    }


    // ---------- RSA-PSS (RSASSA-PSS, RFC 4055) ----------
    static void testRsaPss() {
        try {
            System.out.println("\n[17] RSA-PSS (RSASSA-PSS, RFC 4055)");
            Date nb = new Date();
            Date na = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

            // 1) PSS self-signed root (SHA-256)
            KeyPair rootKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate root = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=PSS Root, O=MODPKICA, C=CN"),
                    rootKp, new BigInteger(64, new SecureRandom()), nb, na,
                    "RSA-PSS", "sha256");
            check("1.2.840.113549.1.1.10".equals(root.getSigAlgOID()),
                    "PSS root: sigAlgOID is RSASSA-PSS");
            check(root.getSigAlgName().toUpperCase().contains("PSS")
                            || root.getSigAlgName().toUpperCase().contains("MGF1"),
                    "PSS root: sigAlgName indicates PSS: " + root.getSigAlgName());
            try {
                root.verify(rootKp.getPublic());
                check(true, "PSS root: JCA verify OK");
            } catch (Exception ve) {
                check(false, "PSS root: JCA verify failed: " + ve);
            }
            try {
                byte[] pp = root.getSigAlgParams();
                org.bouncycastle.asn1.pkcs.RSASSAPSSparams pss =
                        org.bouncycastle.asn1.pkcs.RSASSAPSSparams.getInstance(pp);
                check("2.16.840.1.101.3.4.2.1".equals(pss.getHashAlgorithm().getAlgorithm().getId()),
                        "PSS root: params hashAlgorithm = SHA-256");
                check(pss.getSaltLength().intValue() == 32, "PSS root: saltLength = 32");
            } catch (Exception pe) {
                check(false, "PSS root: params parse failed: " + pe);
            }

            // 2) JSON roundtrip via X509JsonConverter
            String json = X509JsonConverter.certToJson(pem(root).getBytes(StandardCharsets.UTF_8));
            byte[] rebuiltPem = X509JsonConverter.jsonToCertPem(json);
            check(rebuiltPem != null && new String(rebuiltPem, StandardCharsets.UTF_8).contains("BEGIN CERTIFICATE"),
                    "PSS root: jsonToCertPem produced PEM");
            X509Certificate c2 = parsePem(rebuiltPem);
            check(Arrays.equals(root.getEncoded(), c2.getEncoded()),
                    "PSS root: JSON roundtrip DER byte-exact");

            // 3) PSS root signs PSS leaf
            KeyPair leafKp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate leaf = CertUtil.buildSignedCert(
                    root, rootKp.getPrivate(),
                    new X500Principal("CN=pss.example.com, O=MODPKICA, C=CN"),
                    leafKp.getPublic(), new BigInteger(64, new SecureRandom()),
                    nb, na, "RSA-PSS", "sha256", false,
                    "http://localhost/CRL/x.crl", "http://localhost/ocsp", "", "", "");
            check("1.2.840.113549.1.1.10".equals(leaf.getSigAlgOID()),
                    "PSS leaf: sigAlgOID is RSASSA-PSS");
            try {
                leaf.verify(rootKp.getPublic());
                check(true, "PSS leaf: verify with issuer pub OK");
            } catch (Exception ve) {
                check(false, "PSS leaf: verify failed: " + ve);
            }

            // 4) PSS root signs plain RSA leaf (PKCS#1)
            KeyPair leaf2Kp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate leaf2 = CertUtil.buildSignedCert(
                    root, rootKp.getPrivate(),
                    new X500Principal("CN=pkcs1.example.com, O=MODPKICA, C=CN"),
                    leaf2Kp.getPublic(), new BigInteger(64, new SecureRandom()),
                    nb, na, "RSA", "sha256", false, "", "", "", "", "");
            check("1.2.840.113549.1.1.11".equals(leaf2.getSigAlgOID()),
                    "PSS issuer signing RSA leaf: sigAlgOID = sha256WithRSAEncryption");
            try {
                leaf2.verify(rootKp.getPublic());
                check(true, "PKCS#1 leaf: verify OK");
            } catch (Exception ve) {
                check(false, "PKCS#1 leaf: verify failed: " + ve);
            }

            // 5) PSS root generates CRL (keyType=RSA-PSS)
            java.util.List<CrlUtil.RevokedCert> revoked = new java.util.ArrayList<>();
            revoked.add(new CrlUtil.RevokedCert(new BigInteger("1135deadbeef", 16), new Date(), 1));
            X509CRL crl = CrlUtil.generateCrlObject(
                    root, rootKp.getPrivate(), revoked, nb,
                    new Date(System.currentTimeMillis() + 30L * 24 * 3600 * 1000),
                    "RSA-PSS", "sha256", BigInteger.ONE);
            check("1.2.840.113549.1.1.10".equals(crl.getSigAlgOID()),
                    "PSS CRL: sigAlgOID is RSASSA-PSS");
            try {
                crl.verify(rootKp.getPublic());
                check(true, "PSS CRL: verify OK");
            } catch (Exception ve) {
                check(false, "PSS CRL: verify failed: " + ve);
            }

            // 6) SHA3-256 PSS self-signed
            KeyPair sha3Kp = CertUtil.generateRsaKeyPair(2048);
            X509Certificate sha3 = CertUtil.buildSelfSignedRoot(
                    new X500Principal("CN=PSS SHA3 Root, O=MODPKICA, C=CN"),
                    sha3Kp, new BigInteger(64, new SecureRandom()), nb, na,
                    "RSA-PSS", "SHA3-256");
            check("1.2.840.113549.1.1.10".equals(sha3.getSigAlgOID()),
                    "PSS SHA3 root: sigAlgOID is RSASSA-PSS");
            try {
                sha3.verify(sha3Kp.getPublic());
                check(true, "PSS SHA3 root: verify OK");
            } catch (Exception ve) {
                check(false, "PSS SHA3 root: verify failed: " + ve);
            }
        } catch (Throwable e) {
            check(false, "testRsaPss unexpected: " + e);
        }
    }

}
