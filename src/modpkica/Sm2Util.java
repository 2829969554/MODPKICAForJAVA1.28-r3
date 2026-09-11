package modpkica;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/**
 * Sm2Util —— SM2/SM3 国密算法工具（最关键，签名规范以 Go 版 smocsp.go / tjfoc sm2.go 为权威）。
 *
 * <p><b>SM2 签名核心规范</b>：对 TBS 原文<b>直接签名</b>，由签名器内部完成
 * {@code e = SM3(ZA || TBS)}，其中
 * <pre>
 *   ZA = SM3(ENTLA(||ID||a||b||Gx||Gy||Qx||Qy))
 * </pre>
 * 最终输出 ASN.1 DER 编码的 (r, s)。BC 的 {@link SM2Signer} 在配合
 * {@link ParametersWithID} 时正是这一行为，因此<b>绝不能</b>改用普通 ECDSA 签名器。
 *
 * <p>默认用户 ID = {@code "1234567812345678"} 的 UTF-8 字节（GB/T 32918 与 tjfoc 默认一致）。
 */
public final class Sm2Util {

    // ====================== OID 常量（与 Go 版严格对齐，禁止臆造） ======================

    /** SM3WithSM2 签名算法 OID：1.2.156.10197.1.501 */
    public static final String OID_SM3_WITH_SM2 = "1.2.156.10197.1.501";
    /** SM3 摘要算法 OID：1.2.156.10197.1.401 */
    public static final String OID_SM3 = "1.2.156.10197.1.401";
    /** SM2 公钥算法 OID：1.2.156.10197.1.301 */
    public static final String OID_SM2_PUBLIC_KEY = "1.2.156.10197.1.301";

    /** 默认用户 ID（与 GB/T 32918、Go tjfoc default_uid 一致） */
    private static final String DEFAULT_UID = "1234567812345678";

    /** SM2 曲线名 */
    private static final String CURVE_NAME = "sm2p256v1";

    static {
        // 注册 BouncyCastle 提供者
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private Sm2Util() {
    }

    /**
     * 返回默认用户 ID 的 UTF-8 字节（16 字节）。
     */
    public static byte[] getSm2UidBytes() {
        // DEFAULT_UID 字符与字节都是 16 个 ASCII
        return DEFAULT_UID.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * SM3 摘要。
     *
     * @param data 原始数据
     * @return 32 字节摘要
     */
    public static byte[] sm3(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /**
     * 计算 SM2 公钥的 ZA 值（供需要显式预计算的场景使用）。
     *
     * @param pub 公钥参数
     * @param uid 用户 ID 字节，为空则用默认 ID
     * @return ZA 摘要（32 字节）
     */
    public static byte[] computeZa(ECPublicKeyParameters pub, byte[] uid) {
        if (uid == null || uid.length == 0) {
            uid = getSm2UidBytes();
        }
        ECDomainParameters domain = pub.getParameters();
        SM3Digest digest = new SM3Digest();
        // ENTLA = 8 * len(uid)，按大端 uint16 写入
        int entla = uid.length * 8;
        digest.update((byte) ((entla >> 8) & 0xff));
        digest.update((byte) (entla & 0xff));
        // IDA
        digest.update(uid, 0, uid.length);
        // a, b, Gx, Gy, Qx, Qy（均需补齐到 32 字节宽度）
        addFieldElement(digest, domain.getCurve().getA().toBigInteger());
        addFieldElement(digest, domain.getCurve().getB().toBigInteger());
        addFieldElement(digest, domain.getG().normalize().getAffineXCoord().toBigInteger());
        addFieldElement(digest, domain.getG().normalize().getAffineYCoord().toBigInteger());
        addFieldElement(digest, pub.getQ().normalize().getAffineXCoord().toBigInteger());
        addFieldElement(digest, pub.getQ().normalize().getAffineYCoord().toBigInteger());
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /** 把大整数补齐为 32 字节后喂给摘要器。 */
    private static void addFieldElement(SM3Digest d, BigInteger v) {
        byte[] b = BigIntegers.asUnsignedByteArray(32, v);
        d.update(b, 0, b.length);
    }

    /**
     * SM2 签名（对 TBS 原文直接签名，输出 DER 编码的 r||s）。
     *
     * @param priv SM2 私钥参数
     * @param tbs  待签名的 TBS 原文
     * @return DER 编码的 (r, s) 签名
     */
    public static byte[] sm2Sign(ECPrivateKeyParameters priv, byte[] tbs) {
        SM2Signer signer = new SM2Signer();
        // 关键：外层 ParametersWithID 指定用户ID（内部算 ZA），
        // 内层 ParametersWithRandom 提供随机源；SM2Signer 按此顺序解包。
        ParametersWithID p = new ParametersWithID(
                new ParametersWithRandom(priv, new SecureRandom()), getSm2UidBytes());
        signer.init(true, p);
        signer.update(tbs, 0, tbs.length);
        try {
            return signer.generateSignature();
        } catch (org.bouncycastle.crypto.CryptoException e) {
            throw new IllegalStateException("SM2 签名失败", e);
        }
    }

    /**
     * SM2 验签。
     *
     * @param pub  SM2 公钥参数
     * @param tbs  原 TBS 原文
     * @param sig  DER 编码签名
     * @return 验签是否通过
     */
    public static boolean sm2Verify(ECPublicKeyParameters pub, byte[] tbs, byte[] sig) {
        SM2Signer signer = new SM2Signer();
        signer.init(false, new ParametersWithID(pub, getSm2UidBytes()));
        signer.update(tbs, 0, tbs.length);
        return signer.verifySignature(sig);
    }

    /**
     * 生成 SM2 密钥对（基于 sm2p256v1 曲线）。
     *
     * @return AsymmetricCipherKeyPair（含 ECPrivateKeyParameters / ECPublicKeyParameters）
     */
    public static org.bouncycastle.crypto.AsymmetricCipherKeyPair generateSm2KeyPair() {
        X9ECParameters sm2Params = GMNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters domainParams = new ECDomainParameters(
                sm2Params.getCurve(), sm2Params.getG(), sm2Params.getN(),
                sm2Params.getH(), sm2Params.getSeed());

        org.bouncycastle.crypto.generators.ECKeyPairGenerator gen =
                new org.bouncycastle.crypto.generators.ECKeyPairGenerator();
        org.bouncycastle.crypto.params.ECKeyGenerationParameters gparams =
                new org.bouncycastle.crypto.params.ECKeyGenerationParameters(
                        domainParams, new SecureRandom());
        gen.init(gparams);
        return gen.generateKeyPair();
    }

    /**
     * 用 JCA 方式生成 SM2 KeyPair（便于写入证书 / PEM）。
     */
    public static KeyPair generateSm2JcaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(CURVE_NAME));
        return kpg.generateKeyPair();
    }

    /**
     * 把 JCA 的 BCECPublicKey 转为 ECPublicKeyParameters。
     */
    public static ECPublicKeyParameters toEcPublicParams(java.security.PublicKey pub) {
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pub.getEncoded());
        try {
            return (ECPublicKeyParameters)
                    org.bouncycastle.crypto.util.PublicKeyFactory.createKey(spki);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("公钥转换失败", e);
        }
    }

    /**
     * 把 JCA 的 BCECPrivateKey 转为 ECPrivateKeyParameters。
     */
    public static ECPrivateKeyParameters toEcPrivateParams(java.security.PrivateKey priv) {
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(priv.getEncoded());
        try {
            return (ECPrivateKeyParameters)
                    org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(pki);
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("私钥转换失败", e);
        }
    }

    /** 仅用于自测时输出。 */
    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    /**
     * 简易自测：生成密钥对 → 签名 → 验签，确认 SM2Signer + ParametersWithID 链路可用。
     */
    public static void main(String[] args) throws Exception {
        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = generateSm2KeyPair();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters) kp.getPrivate();
        ECPublicKeyParameters pub = (ECPublicKeyParameters) kp.getPublic();
        byte[] tbs = "MODPKICA-TEST".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] sig = sm2Sign(priv, tbs);
        boolean ok = sm2Verify(pub, tbs, sig);
        System.out.println("SM3(abc)=" + hex(sm3("abc".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        System.out.println("SM2 签名长度(DER)=" + sig.length + " 验签=" + ok);
    }
}
