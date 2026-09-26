package modpkica;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * CrlUtil —— X.509 v2 CRL 生成（RFC 5280）。
 *
 * <p>使用 BC 的 {@link X509v2CRLBuilder}。吊销原因扩展 OID = 2.5.29.21，
 * 值为 {@code 0A 01 <reason>}（ASN.1 ENUMERATED），BC 的 addCRL(serial,date,reason)
 * 会自动编码该扩展。
 *
 * <p>RSA/ECC 用标准 {@code JcaContentSignerBuilder}；SM2 走 CertUtil 的
 * 自定义 {@code SM2ContentSigner}（SM2Signer + ZA）。
 *
 * <p>同时提供 DER 与 PEM（Type=X509 CRL）两种输出。
 */
public final class CrlUtil {

    /** 注册 BC Provider */
    static {
        Bc.init();
    }

    private CrlUtil() {
    }

    /**
     * 一条吊销记录。
     */
    public static class RevokedCert {
        /** 证书序列号 */
        public BigInteger serial;
        /** 吊销时间 */
        public Date revocationTime;
        /** 吊销原因码（RFC5280） */
        public int reason;

        public RevokedCert(BigInteger serial, Date revocationTime, int reason) {
            this.serial = serial;
            this.revocationTime = revocationTime;
            this.reason = reason;
        }
    }

    /**
     * 生成 CRL（DER 字节）。
     *
     * @param caCert    签发 CA 证书
     * @param caKey     CA 私钥
     * @param revoked   吊销列表（可为空列表，表示当前无吊销）
     * @param thisUpdate 本次更新时间
     * @param nextUpdate 下次更新时间
     * @param keyType   "RSA" / "ECC" / "SM2"
     * @param hash      摘要名（RSA/ECC 用）
     */
    public static byte[] generateCrl(X509Certificate caCert, PrivateKey caKey,
                                     List<RevokedCert> revoked,
                                     Date thisUpdate, Date nextUpdate,
                                     String keyType, String hash,
                                     BigInteger crlNumber) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                org.bouncycastle.asn1.x500.X500Name.getInstance(
                        caCert.getSubjectX500Principal().getEncoded()), thisUpdate);
        builder.setNextUpdate(nextUpdate);

        // RFC 5280 5.2.3: cRLNumber (2.5.29.20) MUST be present and monotonically
        // increasing for each CRL issuer. Fallback to 1 when not supplied.
        if (crlNumber == null) {
            crlNumber = BigInteger.ONE;
        }
        builder.addExtension(Extension.cRLNumber, false,
                new org.bouncycastle.asn1.x509.CRLNumber(crlNumber));
        // RFC 5280 5.2.4: AuthorityKeyIdentifier (2.5.29.35) = issuing CA cert SKI,
        // matching the AKI written into certificates issued by this CA.
        byte[] aki = CertUtil.getSubjectKeyIdentifier(caCert.getPublicKey());
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(aki));

        if (revoked != null) {
            for (RevokedCert rc : revoked) {
                // addCRLEntry(serial, 吊销时间, 原因码)，BC 自动写入 reasonCode 扩展 OID 2.5.29.21
                builder.addCRLEntry(rc.serial, rc.revocationTime, rc.reason);
            }
        }

        ContentSigner signer = CertUtil.createContentSigner(caKey, keyType, hash);
        X509CRLHolder holder = builder.build(signer);
        return holder.getEncoded();
    }

    /**
     * 生成 CRL 并返回 X509CRL 对象。
     */
    public static X509CRL generateCrlObject(X509Certificate caCert, PrivateKey caKey,
                                            List<RevokedCert> revoked,
                                            Date thisUpdate, Date nextUpdate,
                                            String keyType, String hash,
                                            BigInteger crlNumber) throws Exception {
        byte[] der = generateCrl(caCert, caKey, revoked, thisUpdate, nextUpdate,
                keyType, hash, crlNumber);
        X509CRLHolder holder = new X509CRLHolder(der);
        return new JcaX509CRLConverter().setProvider("BC").getCRL(holder);
    }

    /**
     * 把 DER 编码的 CRL 转成 PEM 文本（Type=X509 CRL）。
     */
    public static String derToPem(byte[] der) throws Exception {
        PemObject po = new PemObject("X509 CRL", der);
        StringWriter sw = new StringWriter();
        try (PemWriter pw = new PemWriter(sw)) {
            pw.writeObject(po);
        }
        return sw.toString();
    }
}
