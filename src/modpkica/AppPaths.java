package modpkica;

import java.io.File;

/**
 * AppPaths —— MODPKICA 根目录定位。
 *
 * <p>Go 版使用 {@code filepath.Dir(os.Executable())} 作为 MODTC（程序所在目录）。
 * Java 版对应规则：优先取 jar 包 / class 输出目录的<b>父目录</b>（编译产物放在
 * {@code out/} 时父目录即项目根），失败时回退到用户当前工作目录。
 *
 * <p>也可通过环境变量或系统属性 {@code MODPKICA_BASE} 显式指定根目录，优先级最高。
 */
public final class AppPaths {

    private AppPaths() {
    }

    /**
     * 返回 MODPKICA 根目录（其下应有 PKI 目录）。
     */
    public static String baseDir() {
        // 1. 环境变量 / 系统属性显式指定
        String env = System.getProperty("MODPKICA_BASE");
        if (env == null || env.isEmpty()) {
            env = System.getenv("MODPKICA_BASE");
        }
        if (env != null && !env.isEmpty()) {
            return env;
        }
        // 2. jar / class 所在目录的父目录
        try {
            File codeSource = new File(AppPaths.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            File dir = codeSource.isFile() ? codeSource.getParentFile() : codeSource;
            if (dir != null) {
                File parent = dir.getParentFile();
                if (parent != null && new File(parent, "PKI").exists()) {
                    return parent.getAbsolutePath();
                }
                if (new File(dir, "PKI").exists()) {
                    return dir.getAbsolutePath();
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        // 3. 当前工作目录
        return System.getProperty("user.dir");
    }
}
