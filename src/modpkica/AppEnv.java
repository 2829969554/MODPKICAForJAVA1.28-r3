package modpkica;

/**
 * AppEnv —— MODPKICA 应用环境信息（对应 Go 版 internal/appenv/appenv.go）。
 *
 * <p>Go 原版会按操作系统返回带后缀的可执行文件名：
 * <pre>
 *   windows -> MAIN.exe / ADMIN.exe / ...
 *   linux   -> MAIN / ADMIN / ...（无后缀）
 * </pre>
 * Java 版统一不使用 .exe 后缀，固定返回不带后缀的名称数组。
 *
 * <p>数组下标含义：
 * <pre>
 *   0 = MAIN        主服务（OCSP/CRL/时间戳 HTTP 服务）
 *   1 = ADMIN       管理员后台
 *   2 = MAKEROOT    生成根证书
 *   3 = MAKECERT    签发终端/中间证书
 *   4 = rootGETcrl  根证书下载 CRL
 *   5 = CERTVERIFY  证书验证
 *   6 = auto        自动化测试
 * </pre>
 */
public final class AppEnv {

    // 工具类禁止实例化
    private AppEnv() {
    }

    /**
     * 返回 MODPKICA 全部可执行应用名称（Java 版不带 .exe 后缀）。
     *
     * @return 长度为 7 的应用名称数组
     */
    public static String[] getExeNames() {
        return new String[]{
            "MAIN",
            "ADMIN",
            "MAKEROOT",
            "MAKECERT",
            "rootGETcrl",
            "CERTVERIFY",
            "auto"
        };
    }
}
