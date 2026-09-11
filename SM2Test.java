import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;

import java.security.Security;
import java.util.Arrays;

public class SM2Test {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("BC 版本: " + BouncyCastleProvider.PROVIDER_NAME + " " + Security.getProvider("BC").getVersion());
        // 1. SM3 摘要
        SM3Digest d = new SM3Digest();
        byte[] msg = "abc".getBytes("UTF-8");
        d.update(msg, 0, msg.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        System.out.println("SM3(abc) = " + hex(out));
        System.out.println("SM3(abc) 标准值应为 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 : " + hex(out).equals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"));
        // 2. SM2 曲线
        X9ECParameters sm2p256v1 = GMNamedCurves.getByName("sm2p256v1");
        System.out.println("SM2 曲线存在: " + (sm2p256v1 != null));
        // 3. SM2 引擎
        SM2Engine engine = new SM2Engine();
        System.out.println("SM2Engine 可用: " + (engine != null));
        // 4. SM2 签名器
        SM2Signer signer = new SM2Signer();
        System.out.println("SM2Signer 可用: " + (signer != null));
        // 5. 密钥工厂是否可用（通过 JCA 访问 SM2 密钥对生成）
        try {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("sm2p256v1"));
            java.security.KeyPair kp = kpg.generateKeyPair();
            System.out.println("EC 密钥生成器可用 (sm2p256v1): " + kp.getPublic().getAlgorithm());
        } catch (Exception e) {
            System.out.println("EC 密钥生成器: " + e.getClass().getSimpleName() + " " + e.getMessage());
        }
        System.out.println("BC SM2/SM3 全家桶验证完成");
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
