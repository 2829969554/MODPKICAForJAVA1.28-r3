package modpkica;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Config —— 读取并解析 PKI/CONFIG.txt 配置文件。
 *
 * <p>文件格式（对应 Go 版 main 程序读取的 CONFIG.txt）：
 * <ul>
 *   <li>以 {@code #} 开头的行是注释，整行忽略；</li>
 *   <li>非空非注释行按 {@code 键=值} 解析，等号左右不做 trim 之外的处理；</li>
 *   <li>常见键：CRL、CRT、OCSP、CPS、CPS_Nonice、WEBPORT。</li>
 * </ul>
 *
 * <p>CPS 字段中可使用 {@code {CID}} 占位符，{@link #getCpsWithCid(String)} 会把它
 * 替换为具体证书序列号（certId），与 Go 版行为一致。
 */
public class Config {

    /** CRL 分发点 URL（键 CRL） */
    private String crlUrl;
    /** 数字证书授权信息（AuthorityInfoAccess 的 caIssuers）URL（键 CRT） */
    private String crtUrl;
    /** OCSP 响应器 URL（键 OCSP） */
    private String ocspUrl;
    /** 证书策略 CPS URI（键 CPS），可能含 {CID} 变量 */
    private String cps;
    /** 证书策略 UserNotice 用户通告文本（键 CPS_Nonice） */
    private String cpsNonice;
    /** Web 服务监听端口（键 WEBPORT），默认 "80" */
    private String webPort;

    /** 原始键值映射，便于以后扩展 */
    private final Map<String, String> raw = new HashMap<>();

    /**
     * 读取并解析 &lt;baseDir&gt;/PKI/CONFIG.txt。
     *
     * @param baseDir MODPKICA 根目录（其下有 PKI 目录）
     */
    public Config(String baseDir) {
        load(baseDir);
    }

    /**
     * 加载配置文件。WEBPORT 缺省时回退为 "80"。
     *
     * @param baseDir MODPKICA 根目录
     */
    public final void load(String baseDir) {
        Path path = Paths.get(baseDir, "PKI", "CONFIG.txt");
        crlUrl = "";
        crtUrl = "";
        ocspUrl = "";
        cps = "";
        cpsNonice = "";
        webPort = "80";
        raw.clear();

        if (!Files.exists(path)) {
            return;
        }

        List<String> lines;
        try {
            // 配置文件按 UTF-8 读取，注释里含中文说明
            lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return;
        }

        for (String line : lines) {
            if (line == null) {
                continue;
            }
            // 去掉行尾 \r\n
            String trimmed = stripCrLf(line).trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            int idx = trimmed.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = trimmed.substring(0, idx).trim();
            String value = trimmed.substring(idx + 1).trim();
            raw.put(key, value);

            // 统一大写键名匹配
            switch (key.toUpperCase()) {
                case "CRL":
                    crlUrl = value;
                    break;
                case "CRT":
                    crtUrl = value;
                    break;
                case "OCSP":
                    ocspUrl = value;
                    break;
                case "CPS":
                    cps = value;
                    break;
                case "CPS_NONICE":
                    cpsNonice = value;
                    break;
                case "WEBPORT":
                    webPort = value;
                    break;
                default:
                    // 未知键保留在 raw 中，不影响主流程
                    break;
            }
        }
    }

    /**
     * 返回把 {@code {CID}} 替换为 certId 后的 CPS URL。
     *
     * @param certId 证书序列号（hex 字符串）
     * @return 替换后的 CPS URL；cps 为空时原样返回空串
     */
    public String getCpsWithCid(String certId) {
        if (cps == null) {
            return "";
        }
        return cps.replace("{CID}", certId == null ? "" : certId);
    }

    /**
     * 去掉一行末尾可能残留的 \r / \n（跨平台读写兼容）。
     */
    private static String stripCrLf(String s) {
        int end = s.length();
        while (end > 0) {
            char c = s.charAt(end - 1);
            if (c == '\r' || c == '\n') {
                end--;
            } else {
                break;
            }
        }
        return s.substring(0, end);
    }

    // ---- getter / setter ----

    public String getCrlUrl() {
        return crlUrl;
    }

    public String getCrtUrl() {
        return crtUrl;
    }

    public String getOcspUrl() {
        return ocspUrl;
    }

    public String getCps() {
        return cps;
    }

    public String getCpsNonice() {
        return cpsNonice;
    }

    public String getWebPort() {
        return webPort;
    }

    public Map<String, String> getRaw() {
        return raw;
    }
}
