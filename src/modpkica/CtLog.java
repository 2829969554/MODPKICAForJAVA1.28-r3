package modpkica;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CtLog —— 本地 CT 日志服务器核心（RFC 6962 / Certificate Transparency）。
 *
 * <p>功能：
 * <ul>
 *   <li>密钥管理：生成 ECDSA-P256 日志密钥对，写入
 *       {@code PKI/CTLOG/modpkica_ct_list.json}（结构参考 Google log_list v3，
 *       附加 {@code private_key} 字段供本地签名）；支持删除 / 启用（usable）/ 暂停（disable）。</li>
 *   <li>SCT 签发：按 RFC 6962 §3.1/§3.2 构造 precert_entry 签名输入
 *       （issuer_key_hash + 去 poison 的 TBS），用全部 usable 日志密钥逐一 ECDSA-P256
 *       签名，组装 SCTList（TLS 编码），可直接作为证书 1.3.6.1.4.1.11129.2.4.2 扩展值。</li>
 *   <li>请求日志：追加写入 {@code PKI/CTLOG/ctlogs.txt}，每行格式：
 *       {@code SCT待签名数据SHA256 || 毫秒时间戳 || 使用者SKI || 颁发者AKI || 日志公钥ID(base64)}。</li>
 * </ul>
 */
public final class CtLog {

    /** poison 扩展 OID（RFC 6962 §3.1）。 */
    public static final String OID_POISON = "1.3.6.1.4.1.11129.2.4.3";
    /** SCT 列表扩展 OID（RFC 6962 §3.2）。 */
    public static final String OID_SCT = "1.3.6.1.4.1.11129.2.4.2";

    private CtLog() {
    }

    /** 密钥库文件路径。 */
    public static String keysJsonPath(String baseDir) {
        return baseDir + "/PKI/CTLOG/modpkica_ct_list.json";
    }

    /** 请求日志文件路径。 */
    public static String logsTxtPath(String baseDir) {
        return baseDir + "/PKI/CTLOG/ctlogs.txt";
    }

    /** 可信公网 CT 日志列表文件路径（Google CT log list v3）。 */
    public static String publicListPath(String baseDir) {
        return baseDir + "/PKI/CTLOG/log_list.json";
    }

    /** 公网 CT 日志列表的远程地址。 */
    public static final String PUBLIC_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    /** 公网 CT 日志单条记录（只读参考数据，不含密钥）。 */
    public static final class PubLog {
        public String description = "";
        public String logIdHex = "";   // log_id base64 -> hex（SHA-256(公钥 SPKI)）
        public String state = "";      // usable / readonly / retired / pending / rejected
        public String url = "";
    }

    /**
     * 读取可信公网 CT 日志列表（log_list.json，Google log_list v3）。
     * 文件不存在返回空列表；state 为对象形式 {@code {"usable": {...}}} 时提取键名。
     * P2-12：改用 MiniJson DOM 解析（替代脆弱的正则提取）。
     */
    public static synchronized List<PubLog> loadPublicList(String baseDir) {
        List<PubLog> out = new ArrayList<>();
        Path p = Paths.get(publicListPath(baseDir));
        if (!Files.exists(p)) {
            return out;
        }
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            Map<String, Object> root = MiniJson.parse(json);
            java.util.List<Map<String, Object>> logs = MiniJson.collectLogs(root);
            if (!logs.isEmpty()) {
                for (Map<String, Object> lo : logs) {
                    PubLog k = new PubLog();
                    k.description = MiniJson.strVal(lo.get("description"));
                    k.url = MiniJson.strVal(lo.get("url"));
                    String b64 = MiniJson.strVal(lo.get("log_id"));
                    if (b64 != null && !b64.isEmpty()) {
                        try {
                            byte[] raw = Base64.getDecoder().decode(b64);
                            StringBuilder sb = new StringBuilder();
                            for (byte b : raw) {
                                sb.append(String.format("%02x", b & 0xff));
                            }
                            k.logIdHex = sb.toString();
                        } catch (Exception ex) {
                            k.logIdHex = b64;
                        }
                    }
                    Object st = lo.get("state");
                    if (st instanceof Map) {
                        for (Object key : ((Map<?, ?>) st).keySet()) {
                            k.state = String.valueOf(key);
                            break;
                        }
                    } else {
                        k.state = MiniJson.strVal(st);
                    }
                    if (!k.logIdHex.isEmpty()) {
                        out.add(k);
                    }
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CT公网日志列表读取异常", publicListPath(baseDir), String.valueOf(e));
        }
        return out;
    }

    /** 读取 log_list.json 的数据日期（log_list_timestamp）。文件不存在返回空串。 */
    public static synchronized String publicListTimestamp(String baseDir) {
        Path p = Paths.get(publicListPath(baseDir));
        if (!Files.exists(p)) {
            return "";
        }
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            Object ts = MiniJson.parse(json).get("log_list_timestamp");
            String v = MiniJson.strVal(ts);
            return v == null ? "" : v;
        } catch (Exception e) {
            return "";
        }
    }

    /** 从 gstatic 拉取最新 log_list.json 并保存到 PKI/CTLOG/log_list.json。返回结果描述。 */
    public static synchronized String fetchPublicList(String baseDir) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new java.net.URI(PUBLIC_LIST_URL).toURL().openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setRequestMethod("GET");
        c.setRequestProperty("User-Agent", "MODPKICA/1.0 (CT log_list fetcher)");
        c.setRequestProperty("Accept", "application/json");
        int code = c.getResponseCode();
        if (code != 200) {
            c.disconnect();
            throw new IOException("远程返回 HTTP " + code);
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = c.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
        }
        c.disconnect();
        byte[] data = bos.toByteArray();
        String txt = new String(data, StandardCharsets.UTF_8);
        if (!txt.contains("log_list_timestamp") || !txt.contains("\"log_id\"")) {
            throw new IOException("返回内容不是有效的 CT log_list v3 JSON");
        }
        Path p = Paths.get(publicListPath(baseDir));
        Files.createDirectories(p.getParent());
        Files.write(p, data);
        String ts = publicListTimestamp(baseDir);
        MLog.append(baseDir, "CTLog拉取公网日志列表", PUBLIC_LIST_URL,
                "已保存 " + data.length + " 字节，数据日期 " + ts);
        return "已保存 " + data.length + " 字节，数据日期 " + ts;
    }

    /** 单条日志密钥对（含私钥，仅本地使用）。 */
    public static final class LogKey {
        public String description = "";
        public String logId = "";       // base64：SHA-256(公钥 SPKI DER)
        public String key = "";         // base64：公钥 SPKI DER
        public String privateKey = "";  // base64：PKCS#8 私钥（本地签名用）
        public String state = "usable"; // usable / disable
        public String type = "ECDSA";   // ECDSA / RSA / SM2
        public String url = "";
        public String created = "";
    }

    // ============================================================
    // 密钥库读写（modpkica_ct_list.json，v3 风格）
    // ============================================================

    /** 读取全部日志密钥对。文件不存在返回空列表。P2-12：MiniJson DOM 解析。 */
    public static synchronized List<LogKey> loadKeys(String baseDir) {
        List<LogKey> out = new ArrayList<>();
        Path p = Paths.get(keysJsonPath(baseDir));
        if (!Files.exists(p)) {
            return out;
        }
        try {
            String json = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            Map<String, Object> root = MiniJson.parse(json);
            java.util.List<Map<String, Object>> logs = MiniJson.collectLogs(root);
            if (!logs.isEmpty()) {
                for (Map<String, Object> lo : logs) {
                    LogKey k = new LogKey();
                    k.logId = MiniJson.strVal(lo.get("log_id"));
                    k.description = MiniJson.strVal(lo.get("description"));
                    k.key = MiniJson.strVal(lo.get("key"));
                    k.privateKey = MiniJson.strVal(lo.get("private_key"));
                    String st = MiniJson.strVal(lo.get("state"));
                    k.state = (st == null || st.isEmpty()) ? "usable" : st;
                    String ty = MiniJson.strVal(lo.get("type"));
                    k.type = (ty == null || ty.isEmpty()) ? "ECDSA" : ty;
                    k.url = MiniJson.strVal(lo.get("url"));
                    k.created = MiniJson.strVal(lo.get("created"));
                    if (k.key != null && !k.key.isEmpty()) {
                        out.add(k);
                    }
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog密钥库读取异常", keysJsonPath(baseDir), String.valueOf(e));
        }
        return out;
    }

    /** 极简 JSON DOM 解析器（P2-12：替代脆弱的正则提取，支持对象/数组/字符串转义）。
     *  仅供本项目离线环境使用，无外部依赖。 */
    static final class MiniJson {
        static Map<String, Object> parse(String s) throws Exception {
            if (s == null) {
                throw new IllegalArgumentException("JSON 为空");
            }
            Ctx c = new Ctx(s);
            Object v = c.value();
            if (!(v instanceof Map)) {
                throw new IllegalArgumentException("JSON 顶层必须是对象");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) v;
            return m;
        }

        static String strVal(Object o) {
            return o == null ? null : String.valueOf(o);
        }

        /** 递归收集 JSON 树中所有日志对象（兼容顶层 logs 与 operators[].logs 两种 v3 结构）。 */
        static java.util.List<Map<String, Object>> collectLogs(Object node) {
            java.util.List<Map<String, Object>> out = new ArrayList<>();
            if (node instanceof Map) {
                Map<?, ?> m = (Map<?, ?>) node;
                if (m.containsKey("log_id") || m.containsKey("key") || m.containsKey("description")) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> asLog = (Map<String, Object>) m;
                    out.add(asLog);
                }
                for (Object v : m.values()) {
                    out.addAll(collectLogs(v));
                }
            } else if (node instanceof List) {
                for (Object o : (List<?>) node) {
                    out.addAll(collectLogs(o));
                }
            }
            return out;
        }

        private static final class Ctx {
            final String s;
            int i;

            Ctx(String s) {
                this.s = s;
            }

            void ws() {
                while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                    i++;
                }
            }

            Object value() throws Exception {
                ws();
                if (i >= s.length()) {
                    throw new IllegalArgumentException("JSON 意外结尾");
                }
                char c = s.charAt(i);
                if (c == '{') {
                    return obj();
                }
                if (c == '[') {
                    return arr();
                }
                if (c == '"') {
                    return str();
                }
                if (c == 't') {
                    expect("true");
                    return Boolean.TRUE;
                }
                if (c == 'f') {
                    expect("false");
                    return Boolean.FALSE;
                }
                if (c == 'n') {
                    expect("null");
                    return null;
                }
                return num();
            }

            Map<String, Object> obj() throws Exception {
                Map<String, Object> m = new java.util.LinkedHashMap<>();
                i++;
                ws();
                if (i < s.length() && s.charAt(i) == '}') {
                    i++;
                    return m;
                }
                while (true) {
                    ws();
                    if (i >= s.length() || s.charAt(i) != '"') {
                        throw new IllegalArgumentException("JSON 对象键应为字符串");
                    }
                    String key = str();
                    ws();
                    if (i >= s.length() || s.charAt(i) != ':') {
                        throw new IllegalArgumentException("JSON 缺冒号");
                    }
                    i++;
                    m.put(key, value());
                    ws();
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("JSON 对象未闭合");
                    }
                    char c = s.charAt(i);
                    if (c == ',') {
                        i++;
                        continue;
                    }
                    if (c == '}') {
                        i++;
                        return m;
                    }
                    throw new IllegalArgumentException("JSON 对象分隔符错误: " + c);
                }
            }

            List<Object> arr() throws Exception {
                List<Object> l = new ArrayList<>();
                i++;
                ws();
                if (i < s.length() && s.charAt(i) == ']') {
                    i++;
                    return l;
                }
                while (true) {
                    l.add(value());
                    ws();
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("JSON 数组未闭合");
                    }
                    char c = s.charAt(i);
                    if (c == ',') {
                        i++;
                        continue;
                    }
                    if (c == ']') {
                        i++;
                        return l;
                    }
                    throw new IllegalArgumentException("JSON 数组分隔符错误: " + c);
                }
            }

            String str() throws Exception {
                if (s.charAt(i) != '"') {
                    throw new IllegalArgumentException("JSON 应为字符串");
                }
                i++;
                StringBuilder sb = new StringBuilder();
                while (true) {
                    if (i >= s.length()) {
                        throw new IllegalArgumentException("JSON 字符串未闭合");
                    }
                    char c = s.charAt(i++);
                    if (c == '"') {
                        return sb.toString();
                    }
                    if (c == '\\') {
                        if (i >= s.length()) {
                            throw new IllegalArgumentException("JSON 转义未闭合");
                        }
                        char e = s.charAt(i++);
                        switch (e) {
                            case '"': sb.append('"'); break;
                            case '\\': sb.append('\\'); break;
                            case '/': sb.append('/'); break;
                            case 'b': sb.append('\b'); break;
                            case 'f': sb.append('\f'); break;
                            case 'n': sb.append('\n'); break;
                            case 'r': sb.append('\r'); break;
                            case 't': sb.append('\t'); break;
                            case 'u': {
                                if (i + 4 > s.length()) {
                                    throw new IllegalArgumentException("JSON \\u 转义截断");
                                }
                                String h = s.substring(i, i + 4);
                                i += 4;
                                sb.append((char) Integer.parseInt(h, 16));
                                break;
                            }
                            default: throw new IllegalArgumentException("JSON 非法转义 \\" + e);
                        }
                    } else {
                        sb.append(c);
                    }
                }
            }

            Object num() throws Exception {
                int st = i;
                while (i < s.length() && (Character.isDigit(s.charAt(i))
                        || s.charAt(i) == '+' || s.charAt(i) == '-'
                        || s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                    i++;
                }
                String t = s.substring(st, i);
                if (t.isEmpty()) {
                    throw new IllegalArgumentException("JSON 非法数字");
                }
                try {
                    return Long.parseLong(t);
                } catch (Exception ignore) {
                }
                try {
                    return Double.parseDouble(t);
                } catch (Exception e2) {
                    throw new IllegalArgumentException("JSON 非法数字: " + t);
                }
            }

            void expect(String w) throws Exception {
                if (!s.startsWith(w, i)) {
                    throw new IllegalArgumentException("JSON 非法字面量: " + w);
                }
                i += w.length();
            }
        }
    }

    /** 从 JSON 片段中提取字符串字段值。 */
    private static String grab(String seg, String field) {
        Pattern p = Pattern.compile(Pattern.quote(field) + "\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(seg);
        return m.find() ? m.group(1) : "";
    }

    /** 写回密钥库（v3 风格结构）。 */
    public static synchronized void saveKeys(String baseDir, List<LogKey> keys) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"operators\": [\n");
        sb.append("    {\n");
        sb.append("      \"name\": \"MODPKICA Local CT Log\",\n");
        sb.append("      \"logs\": [\n");
        for (int i = 0; i < keys.size(); i++) {
            LogKey k = keys.get(i);
            sb.append("        {\n");
            sb.append("          \"description\": \"").append(esc(k.description)).append("\",\n");
            sb.append("          \"log_id\": \"").append(k.logId).append("\",\n");
            sb.append("          \"key\": \"").append(k.key).append("\",\n");
            sb.append("          \"state\": \"").append(esc(k.state)).append("\",\n");
            sb.append("          \"type\": \"").append(esc(k.type)).append("\",\n");
            sb.append("          \"url\": \"").append(esc(k.url)).append("\",\n");
            sb.append("          \"created\": \"").append(esc(k.created)).append("\",\n");
            sb.append("          \"private_key\": \"").append(k.privateKey).append("\"\n");
            sb.append("        }").append(i < keys.size() - 1 ? "," : "").append("\n");
        }
        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");
        Path p = Paths.get(keysJsonPath(baseDir));
        if (p.getParent() != null && !Files.exists(p.getParent())) {
            Files.createDirectories(p.getParent());
        }
        Files.write(p, sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // ============================================================
    // 密钥操作：生成 / 删除 / 启用 / 暂停
    // ============================================================

    /** 生成日志密钥对并追加写入密钥库（type：ECDSA-P256 / RSA-2048 / SM2-P256）。返回新密钥。 */
    public static synchronized LogKey generateKey(String baseDir, String desc, String type)
            throws Exception {
        String t = type == null || type.isEmpty() ? "ECDSA" : type;
        KeyPair kp;
        if ("RSA".equalsIgnoreCase(t)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            kp = kpg.generateKeyPair();
        } else if ("SM2".equalsIgnoreCase(t)) {
            t = "SM2";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("sm2p256v1"));
            kp = kpg.generateKeyPair();
        } else {
            t = "ECDSA";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            kp = kpg.generateKeyPair();
        }
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        byte[] logId = sha256(spki);

        LogKey k = new LogKey();
        k.description = desc == null || desc.isEmpty() ? "MODPKICA CT Log " + t : desc;
        k.logId = Base64.getEncoder().encodeToString(logId);
        k.key = Base64.getEncoder().encodeToString(spki);
        k.privateKey = Base64.getEncoder().encodeToString(pkcs8);
        k.state = "usable";
        k.type = t;
        k.url = "http://localhost:80/ct/add";
        k.created = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        List<LogKey> keys = loadKeys(baseDir);
        keys.add(k);
        saveKeys(baseDir, keys);
        MLog.append(baseDir, "CTLog生成密钥",
                "描述=" + k.description + " 类型=" + t + " log_id=" + k.logId,
                "已写入 " + keysJsonPath(baseDir));
        return k;
    }

    /** 按 log_id 删除密钥对。返回是否删除成功。 */
    public static synchronized boolean deleteKey(String baseDir, String logIdB64) {
        List<LogKey> keys = loadKeys(baseDir);
        boolean removed = keys.removeIf(k -> k.logId.equals(logIdB64));
        if (removed) {
            try {
                saveKeys(baseDir, keys);
                MLog.append(baseDir, "CTLog删除密钥", "log_id=" + logIdB64, "已删除");
            } catch (Exception e) {
                MLog.appendErr(baseDir, "CTLog删除密钥异常", "log_id=" + logIdB64, String.valueOf(e));
                return false;
            }
        }
        return removed;
    }

    /** 设置密钥状态：usable（启用）/ disable（暂停）。 */
    public static synchronized boolean setState(String baseDir, String logIdB64, String state) {
        List<LogKey> keys = loadKeys(baseDir);
        boolean found = false;
        for (LogKey k : keys) {
            if (k.logId.equals(logIdB64)) {
                k.state = "usable".equalsIgnoreCase(state) ? "usable" : "disable";
                found = true;
                break;
            }
        }
        if (found) {
            try {
                saveKeys(baseDir, keys);
                MLog.append(baseDir, "CTLog设置密钥状态", "log_id=" + logIdB64
                        + " 状态=" + ("usable".equals(state) ? "usable" : "disable"), "OK");
            } catch (Exception e) {
                MLog.appendErr(baseDir, "CTLog设置状态异常", "log_id=" + logIdB64, String.valueOf(e));
                return false;
            }
        }
        return found;
    }

    // ============================================================
    // SCT 签发（RFC 6962 §3.1 / §3.2，precert_entry）
    // ============================================================

    /**
     * 按预证书类型随机选出参与 SCT 签名的日志密钥组（最多 3 组，仅 usable）：
     * SM2 预证书 → 只选 SM2 密钥；RSA/ECDSA 预证书 → 只选 RSA 或 ECDSA 密钥。
     */
    public static List<LogKey> pickLogKeys(String baseDir, boolean sm2Precert) {
        List<LogKey> keys = loadKeys(baseDir);
        List<LogKey> pool = new ArrayList<>();
        for (LogKey k : keys) {
            if (!"usable".equals(k.state) || k.privateKey.isEmpty()) {
                continue;
            }
            if (sm2Precert) {
                if ("SM2".equalsIgnoreCase(k.type)) {
                    pool.add(k);
                }
            } else if ("RSA".equalsIgnoreCase(k.type) || "ECDSA".equalsIgnoreCase(k.type)) {
                pool.add(k);
            }
        }
        Collections.shuffle(pool);
        return pool.size() > 3 ? new ArrayList<>(pool.subList(0, 3)) : pool;
    }

    /** 判断预证书是否 SM2 类型（签名算法 SM3withSM2，或公钥 named curve = SM2 曲线）。 */
    public static boolean isSm2Precert(X509Certificate cert) {
        try {
            String sigOid = cert.getSigAlgOID();
            if (sigOid != null && sigOid.startsWith("1.2.156.10197.1.501")) {
                return true;
            }
            // EC 公钥 SPKI 的算法 OID 固定为 id-ecPublicKey(1.2.840.10045.2.1)，
            // SM2 特性体现在 named curve 参数 OID：1.2.156.10197.1.301（sm2p256v1）
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
                    cert.getPublicKey().getEncoded());
            ASN1ObjectIdentifier curveOid = null;
            ASN1Encodable params = spki.getAlgorithm().getParameters();
            if (params != null) {
                ASN1Primitive p = params.toASN1Primitive();
                if (p instanceof ASN1Sequence) {
                    ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(
                            ((ASN1Sequence) p).getObjectAt(0));
                    curveOid = oid;
                } else if (p instanceof ASN1ObjectIdentifier) {
                    curveOid = (ASN1ObjectIdentifier) p;
                }
            }
            return curveOid != null && curveOid.getId().startsWith("1.2.156.10197.1.301");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 用选定的一组日志密钥对同一 precert 签发 SCT，组装 SCTList（TLS 编码）。
     *
     * @param baseDir        MODPKICA 根目录
     * @param tbsNoPoison    预证书 TBS 删除 poison 扩展后的 DER（RFC 6962 §3.1）
     * @param issuerKeyHash  颁发者公钥 SPKI 的 SHA-256（32 字节）
     * @param pool           本次参与签名的日志密钥（usable、类型匹配、≤3）
     * @return SCTList 字节（可直接作为 1.3.6.1.4.1.11129.2.4.2 扩展的 OCTET STRING 内容）
     */
    public static byte[] signSctList(String baseDir, byte[] tbsNoPoison, byte[] issuerKeyHash,
            List<LogKey> pool) throws Exception {
        if (pool == null || pool.isEmpty()) {
            throw new IllegalStateException("没有 usable 且类型匹配的 CT 日志密钥，请先在「SCT服务管理」生成并启用密钥");
        }
        ByteArrayOutputStream list = new ByteArrayOutputStream();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int total = 0;
        for (LogKey k : pool) {
            long ts = System.currentTimeMillis();
            byte[] input = buildSctInput(ts, tbsNoPoison, issuerKeyHash);
            byte[] sig = signInput(Base64.getDecoder().decode(k.privateKey), input, k.type);
            byte[] sct = buildSerializedSct(k.logId, ts, sig, k.type);
            body.write((sct.length >> 8) & 0xff);
            body.write(sct.length & 0xff);
            body.write(sct, 0, sct.length);
            total += sct.length + 2;
        }
        list.write((total >> 8) & 0xff);
        list.write(total & 0xff);
        list.write(body.toByteArray());
        return list.toByteArray();
    }

    /** 构造 RFC 6962 §3.2 签名输入（precert_entry）：TLS 编码。 */
    static byte[] buildSctInput(long ts, byte[] tbsNoPoison, byte[] issuerKeyHash) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(0);                                  // sct_version = v1
        bos.write(0);                                  // signature_type = certificate_timestamp
        writeU64(bos, ts);
        writeU16(bos, 1);                              // entry_type = precert_entry
        bos.write(issuerKeyHash, 0, 32);               // issuer_key_hash
        writeU24(bos, tbsNoPoison.length);
        bos.write(tbsNoPoison, 0, tbsNoPoison.length); // tbs_certificate（去 poison）
        writeU16(bos, 0);                              // CtExtensions（空）
        return bos.toByteArray();
    }

    /** 按日志密钥类型对输入签名：ECDSA=SHA256withECDSA、RSA=SHA256withRSA、SM2=SM3withSM2。 */
    static byte[] signInput(byte[] pkcs8, byte[] input, String type) throws Exception {
        boolean rsa = "RSA".equalsIgnoreCase(type);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance(
                rsa ? "RSA" : "EC", "BC");
        java.security.PrivateKey priv = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
        String alg = rsa ? "SHA256withRSA"
                : "SM2".equalsIgnoreCase(type) ? "SM3withSM2" : "SHA256withECDSA";
        Signature sig = Signature.getInstance(alg, "BC");
        sig.initSign(priv);
        sig.update(input);
        return sig.sign();
    }

    /** 组装 SerializedSCT（RFC 6962 §3.2）：version + log_id + ts + ext + hash/sig 枚举 + 签名。
     *  ECDSA→SHA256/ECDSA(4,3)；RSA→SHA256/RSA(4,1)；SM2→SM3/SM2(7,4，国密 CT 实现枚举，对齐零信 sm2ct.cn)。 */
    static byte[] buildSerializedSct(String logIdB64, long ts, byte[] signature, String type) {
        byte[] logId = Base64.getDecoder().decode(logIdB64);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0);                                   // version = v1
        out.write(logId, 0, 32);                        // log_id
        writeU64(out, ts);                              // timestamp
        writeU16(out, 0);                               // extensions（空）
        if ("SM2".equalsIgnoreCase(type)) {
            out.write(7);                               // hash = SM3
            out.write(4);                               // sig = SM2（国密 CT 实现枚举，对齐零信 sm2ct.cn）
        } else if ("RSA".equalsIgnoreCase(type)) {
            out.write(4);                               // hash = SHA-256
            out.write(1);                               // sig = RSA
        } else {
            out.write(4);                               // hash = SHA-256
            out.write(3);                               // sig = ECDSA
        }
        writeU16(out, signature.length);
        out.write(signature, 0, signature.length);
        return out.toByteArray();
    }

    // ============================================================
    // 提交预证书到自身 CT 日志服务
    // ============================================================

    /**
     * 将 PEM 预证书 + PEM 颁发者证书以 POST 提交到自身 MAIN /ct/add，
     * 返回 SCTList（二进制，直接作为 1.3.6.1.4.1.11129.2.4.2 扩展值）。
     * MAIN 服务未启动（HTTP 失败）时回退本地签名，保证签发流程可用。
     */
    public static byte[] submitPrecert(String baseDir, X509CertificateHolder precert,
                                       X509Certificate issuerCert, String port) throws Exception {
        String body = pemCert(precert.getEncoded()) + pemCert(issuerCert.getEncoded());
        String url = "http://127.0.0.1:" + port + "/ct/add";
        try {
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    java.net.URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(20000);
            conn.setRequestProperty("Content-Type", "text/plain");
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            java.io.InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            byte[] resp;
            try (java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    bos.write(buf, 0, n);
                }
                resp = bos.toByteArray();
            }
            if (code != 200) {
                throw new IOException("CT 日志服务 /ct/add 返回 " + code + ": "
                        + new String(resp, StandardCharsets.UTF_8));
            }
            MLog.append(baseDir, "CTLog提交预证书", "url=" + url + " 长度=" + body.length() + "字节",
                    "获取 SCT 列表 " + resp.length + "字节");
            return resp;
        } catch (Exception e) {
            // 本地回退：MAIN 未运行或连接失败时直接本地签名
            MLog.append(baseDir, "CTLog本地回退", "url=" + url + " 错误=" + e.getMessage(),
                    "改用本地签名生成 SCT 列表");
            X509Certificate pc = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(precert);
            byte[] tbs = tbsWithoutPoison(pc);
            byte[] ikh = sha256(issuerCert.getPublicKey().getEncoded());
            return signSctList(baseDir, tbs, ikh, pickLogKeys(baseDir, isSm2Precert(pc)));
        }
    }
    // ============================================================
    // 请求日志（ctlogs.txt，只追加）
    // ============================================================

    /**
     * 追加一行 CT 请求日志。行格式：
     * {@code SCT待签名数据SHA256 || 毫秒时间戳 || 使用者SKI || 颁发者AKI || 日志公钥ID(base64)}
     */
    public static synchronized void appendRequestLog(String baseDir, String line) {
        try {
            Path p = Paths.get(logsTxtPath(baseDir));
            if (p.getParent() != null && !Files.exists(p.getParent())) {
                Files.createDirectories(p.getParent());
            }
            // P2-11：轮转——超过 10MB 时归档为 ctlogs.old.txt（覆盖旧档，仅保留最近两份）
            if (Files.exists(p) && Files.size(p) > 10L * 1024 * 1024) {
                Path old = Paths.get(logsTxtPath(baseDir) + ".old");
                Files.move(p, old, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            Files.writeString(p, line + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
            // 日志失败不中断业务
        }
    }

    /** 读取全部 CT 请求日志行（按行拆分，供 Web 面板只读展示）。 */
    public static List<String> readLogs(String baseDir) {
        List<String> out = new ArrayList<>();
        try {
            Path p = Paths.get(logsTxtPath(baseDir));
            if (Files.exists(p)) {
                String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                for (String line : text.split("\n", -1)) {
                    if (!line.trim().isEmpty()) {
                        out.add(line.trim());
                    }
                }
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "CTLog日志读取异常", logsTxtPath(baseDir), String.valueOf(e));
        }
        return out;
    }

    // ============================================================
    // 工具
    // ============================================================

    /** 从 PEM 文本中解析全部证书（按块顺序）。 */
    public static List<X509Certificate> parsePemCerts(byte[] pemBytes) throws Exception {
        String text = new String(pemBytes, StandardCharsets.UTF_8);
        List<X509Certificate> out = new ArrayList<>();
        try (PemReader reader = new PemReader(new StringReader(text))) {
            PemObject po;
            while ((po = reader.readPemObject()) != null) {
                if ("CERTIFICATE".equals(po.getType())) {
                    X509CertificateHolder holder = new X509CertificateHolder(po.getContent());
                    out.add(new JcaX509CertificateConverter().setProvider("BC")
                            .getCertificate(holder));
                }
            }
        }
        if (out.isEmpty()) {
            // 兼容"非标准头"：手动正则提取
            Pattern p = Pattern.compile("-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\r\\n]+?)-----END CERTIFICATE-----",
                    Pattern.DOTALL);
            Matcher m = p.matcher(text);
            while (m.find()) {
                byte[] der = Base64.getDecoder().decode(m.group(1).replaceAll("\\s", ""));
                out.add(new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate(new X509CertificateHolder(der)));
            }
        }
        return out;
    }

    /** 证书 PEM 序列化。 */
    public static String pemCert(byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END CERTIFICATE-----\n");
        return sb.toString();
    }

    /** 从证书 TBS 中删除 poison 扩展（RFC 6962 §3.1），其余扩展原样保真。 */
    public static byte[] tbsWithoutPoison(X509Certificate cert) throws Exception {
        byte[] tbs = cert.getTBSCertificate();
        ASN1Sequence seq = ASN1Sequence.getInstance(tbs);
        ASN1EncodableVector v = new ASN1EncodableVector();
        boolean removed = false;
        for (int i = 0; i < seq.size(); i++) {
            Object el = seq.getObjectAt(i);
            if (el instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) el;
                if (tagged.getTagNo() == 3) {
                    ASN1Sequence extSeq = ASN1Sequence.getInstance(tagged, true);
                    ASN1EncodableVector newExts = new ASN1EncodableVector();
                    for (int j = 0; j < extSeq.size(); j++) {
                        Extension ext = Extension.getInstance(extSeq.getObjectAt(j));
                        if (!OID_POISON.equals(ext.getExtnId().getId())) {
                            newExts.add(ext);
                        } else {
                            removed = true;
                        }
                    }
                    v.add(new DERTaggedObject(true, 3, new DERSequence(newExts)));
                    continue;
                }
            }
            v.add((org.bouncycastle.asn1.ASN1Encodable) el);
        }
        // RFC 6962 SS3.1: a precertificate MUST carry the poison extension.
        if (!removed) {
            throw new IOException("precert is missing poison extension " + OID_POISON
                    + ", not a valid RFC 6962 precertificate");
        }
        return new DERSequence(v).getEncoded();
    }

    /** 证书扩展值（OCTET STRING 解壳后的内容）→ hex；无此扩展返回空串。 */
    public static String extHex(X509Certificate cert, String oid) {
        try {
            byte[] v = cert.getExtensionValue(oid);
            if (v == null) {
                return "";
            }
            ASN1Primitive p = ASN1Primitive.fromByteArray(v);
            DEROctetString os = (DEROctetString) p;
            return toHex(os.getOctets());
        } catch (Exception e) {
            return "";
        }
    }

    static byte[] sha256(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(b);
    }

    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    static void writeU16(ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    static void writeU24(ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 16) & 0xff);
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    static void writeU64(ByteArrayOutputStream bos, long v) {
        for (int i = 7; i >= 0; i--) {
            bos.write((int) ((v >>> (8 * i)) & 0xff));
        }
    }
}
