package modpkica;

/**
 * Bc —— BC Provider 统一注册入口。
 *
 * <p>BC（BouncyCastle）的 JCA 接口（如 {@code KeyPairGenerator.getInstance("RSA","BC")}、
 * {@code JcaX509CertificateConverter().setProvider("BC")}）都要求 BC 已注册为
 * JCA Provider。为保证任意入口（MAIN/ADMIN/MAKEROOT/...）先用到哪共享类都不会
 * 抛 {@code NoSuchProviderException}，所有使用 BC 的共享类都在类加载时调用
 * {@link #init()} 注册。
 *
 * <p>注册是幂等的：已注册则直接返回。
 */
public final class Bc {

    private Bc() {
    }

    /** 注册 BC Provider（幂等，可重复调用）。 */
    public static void init() {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }
}
