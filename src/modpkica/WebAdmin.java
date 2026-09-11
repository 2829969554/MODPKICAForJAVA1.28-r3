package modpkica;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * WebAdmin —— 浏览器版可视化管理界面（对应 Go 版 admin 的图形化替代）。
 *
 * <p>监听 <b>127.0.0.1:8080</b>（可通过系统属性 -Dmodpkica.admin.port 修改，
 * -Dmodpkica.admin.bind 修改绑定地址），单页 GUI 展示 ADMIN 全部功能：
 * <ul>
 *   <li>仪表盘：MAIN 服务状态、运行时长、API 调用计数、日志行数</li>
 *   <li>证书库：CERTS.txt 全量展示</li>
 *   <li>签发根证书 / 签发证书 / 吊销证书 / CRL / OCSP / 时间戳 / 证书验证 / 初始化环境</li>
 *   <li>日志：PKI/logs.log 尾部实时查看</li>
 * </ul>
 *
 * <p>所有操作复用 Admin.doXxx 公共方法（与控制台行为完全一致），
 * 并写入 PKI/logs.log 操作日志。MAIN 启动时会自动拉起本服务；
 * 也可单独运行 java modpkica.WebAdmin。
 */
public final class WebAdmin {

    /** 默认端口 8080。 */
    private static final int DEFAULT_PORT = 8080;
    /** 默认绑定地址：仅本机回环（管理界面不暴露公网）。 */
    private static final String DEFAULT_BIND = "127.0.0.1";

    /** MAIN 服务端口（同进程集成时由 MAIN 传入）。 */
    private static volatile String mainPort = "未运行";
    /** MAIN 是否同进程运行。 */
    private static volatile boolean mainRunning = false;
    /** 服务启动时间。 */
    private static volatile long startTime = System.currentTimeMillis();

    /** 总 API 调用次数。 */
    private static final AtomicLong TOTAL_CALLS = new AtomicLong();
    /** 各端点调用计数。 */
    private static final Map<String, Long> ENDPOINT_CALLS = new ConcurrentHashMap<>();

    private static volatile String baseDir = AppPaths.baseDir();
    private static HttpServer server;

    private WebAdmin() {
    }

    /** 独立启动入口：java modpkica.WebAdmin。 */
    public static void main(String[] args) throws Exception {
        baseDir = AppPaths.baseDir();
        start(mainPort);
        System.out.println("WebAdmin 管理界面已启动: http://localhost:" + port());
        System.out.println("（Ctrl+C 停止）");
    }

    /** 当前管理端口。 */
    public static int port() {
        return server != null ? server.getAddress().getPort() : DEFAULT_PORT;
    }

    /**
     * 启动 WebAdmin 管理服务（MAIN 启动时自动调用；端口被占用时静默跳过）。
     *
     * @param mainWebPort MAIN 的 WEBPORT（用于状态展示），可传 null
     */
    public static synchronized void start(String mainWebPort) {
        if (server != null) {
            return;
        }
        if (mainWebPort != null && !mainWebPort.isEmpty()) {
            mainPort = mainWebPort;
            mainRunning = true;
        }
        int port = Integer.getInteger("modpkica.admin.port", DEFAULT_PORT);
        String bind = System.getProperty("modpkica.admin.bind", DEFAULT_BIND);
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getByName(bind), port), 0);
            server.createContext("/", WebAdmin::route);
            server.setExecutor(null); // 单线程串行，避免并发操作 PKI 数据
            server.start();
        } catch (Exception e) {
            // 端口被占用或绑定失败：不影响 MAIN 主服务，打印提示后跳过
            System.out.println("[WebAdmin] 管理界面启动失败（端口 " + port + " 可能被占用）: " + e.getMessage());
            server = null;
        }
    }

    // ============================================================
    // HTTP 路由
    // ============================================================

    private static void route(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        String method = ex.getRequestMethod();

        // 页面与静态资源
        if ("GET".equalsIgnoreCase(method) && "/".equals(path)) {
            sendText(ex, 200, "text/html; charset=utf-8", PAGE_HTML);
            return;
        }
        if ("GET".equalsIgnoreCase(method) && "/favicon.ico".equals(path)) {
            ex.sendResponseHeaders(204, -1);
            return;
        }

        // API
        if (path.startsWith("/api/")) {
            handleApi(ex);
            return;
        }

        sendJson(ex, 404, Map.of("ok", false, "message", "404: " + path));
    }

    /** API 分发。 */
    private static void handleApi(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        String method = ex.getRequestMethod();
        TOTAL_CALLS.incrementAndGet();
        ENDPOINT_CALLS.merge(path, 1L, Long::sum);
        try {
            switch (path) {
                case "/api/status":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, statusJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/certs":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, certsJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/logs":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, logsJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/config":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, configJson());
                    } else if ("POST".equalsIgnoreCase(method)) {
                        saveConfig(ex);
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET/POST"));
                    }
                    return;
                case "/api/chain":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, chainJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/certjson":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, certJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/version":
                    sendJson(ex, 200, Map.of("ok", true, "message", Admin.VERSION));
                    return;
                case "/api/issuers":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, issuersJson());
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/init":
                    runAction(ex, m -> Admin.doInit(baseDir,
                            str(m, "dn"), str(m, "bits"), str(m, "hash"), str(m, "algo")));
                    return;
                case "/api/makeroot":
                    runAction(ex, m -> Admin.doMakeRoot(baseDir,
                            str(m, "dn"), str(m, "bits"), str(m, "hash"), str(m, "algo")));
                    return;
                case "/api/signcert":
                    runAction(ex, m -> Admin.doSignCert(baseDir,
                            str(m, "dn"), str(m, "bits"), str(m, "hash"),
                            str(m, "keyusage"), str(m, "exusage"), str(m, "isca"),
                            str(m, "days"), str(m, "dns"), str(m, "ips"),
                            str(m, "issuer"), str(m, "algo")));
                    return;
                case "/api/revoke":
                    runAction(ex, m -> Admin.doRevoke(baseDir,
                            str(m, "serial"), str(m, "reason")));
                    return;
                case "/api/crl":
                    runAction(ex, m -> Admin.doSignCrl(baseDir));
                    return;
                case "/api/initocsp":
                    runAction(ex, m -> Admin.doInitOcsp(baseDir, str(m, "algo")));
                    return;
                case "/api/inittimestamp":
                    runAction(ex, m -> Admin.doInitTimestamp(baseDir, str(m, "hash")));
                    return;
                case "/api/verify":
                    runAction(ex, m -> Admin.doVerifyCert(baseDir, str(m, "target")));
                    return;
                default:
                    sendJson(ex, 404, Map.of("ok", false, "message", "未知 API: " + path));
            }
        } catch (Exception e) {
            MLog.appendErr(baseDir, "WebAdmin API 异常", method + " " + path, String.valueOf(e));
            sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(e)));
        }
    }

    /** 执行一个管理动作：解析 JSON → 调用 doXxx → 返回输出。日志记录完整提交数据。 */
    private static void runAction(HttpExchange ex, ActionInvoker invoker) {
        try {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
                sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 POST"));
                return;
            }
            String bodyStr = new String(readAll(ex.getRequestBody()), StandardCharsets.UTF_8);
            Map<String, Object> m = parseJsonObject(bodyStr);
            String path = ex.getRequestURI().getPath();
            try {
                String out = invoker.run(m);
                // 完整命令 = 方法 + 路径 + 提交数据（JSON 原文，可视化）
                MLog.append(baseDir, "WebAdmin " + path,
                        "POST " + path + " 提交数据=" + bodyStr, out);
                sendJson(ex, 200, Map.of("ok", true, "message", out));
            } catch (Exception e) {
                MLog.appendErr(baseDir, "WebAdmin " + path + " 异常",
                        "POST " + path + " 提交数据=" + bodyStr, String.valueOf(e));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(e)));
            }
        } catch (Exception e) {
            try {
                sendJson(ex, 400, Map.of("ok", false, "message",
                        "请求解析失败: " + e));
            } catch (Exception ignored) { }
        }
    }

    @FunctionalInterface
    private interface ActionInvoker {
        String run(Map<String, Object> params) throws Exception;
    }

    // ============================================================
    // 数据组装
    // ============================================================

    /** MAIN 服务状态 + WebAdmin 自身统计。 */
    private static Map<String, Object> statusJson() {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("mainPort", mainPort);
        d.put("mainRunning", mainRunning);
        d.put("adminPort", port());
        d.put("uptimeSeconds", (System.currentTimeMillis() - startTime) / 1000);
        d.put("totalCalls", TOTAL_CALLS.get());
        d.put("endpointCalls", new LinkedHashMap<>(ENDPOINT_CALLS));
        d.put("version", Admin.VERSION);
        d.put("baseDir", baseDir);
        d.put("webPort", readConfigWebPort());
        long lines = countLogLines();
        d.put("logLines", lines);
        return Map.of("ok", true, "data", d);
    }

    /** 证书库列表。 */
    private static Map<String, Object> certsJson() throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        Path f = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (Files.exists(f)) {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                String[] p = t.split("\\s+");
                if (p.length < 7) {
                    continue;
                }
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("serial", p[0]);
                e.put("type", p[1]);
                e.put("status", p[2]);
                e.put("reason", p[3]);
                e.put("time", p[4]);
                e.put("issuer", p[5]);
                e.put("algo", p.length > 6 ? p[6] : "");
                list.add(e);
            }
        }
        return Map.of("ok", true, "data", list);
    }

    /** 可作颁发者的序列号（CERTS.txt 中类型 R 或 C），供签发证书下拉选择。 */
    private static Map<String, Object> issuersJson() throws Exception {
        java.util.List<String> serials = new java.util.ArrayList<>();
        Path f = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (Files.exists(f)) {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) {
                    continue;
                }
                String[] p = t.split("\\s+");
                if (p.length < 7) {
                    continue;
                }
                char type = p[1].isEmpty() ? '?' : p[1].charAt(0);
                if (type == 'R' || type == 'C') {
                    serials.add(p[0]);
                }
            }
        }
        return Map.of("ok", true, "issuers", serials);
    }

    /** 日志接口：支持 lines=N（尾部行数）与 hours=N（最近 N 小时，0=全部）。 */
    private static Map<String, Object> logsJson(HttpExchange ex) {
        String q = ex.getRequestURI().getQuery();
        int lines = 200;
        int hours = 0;
        if (q != null) {
            for (String kv : q.split("&")) {
                try {
                    if (kv.startsWith("lines=")) {
                        lines = Integer.parseInt(kv.substring(6));
                    } else if (kv.startsWith("hours=")) {
                        hours = Integer.parseInt(kv.substring(6));
                    }
                } catch (Exception ignore) {
                    // 非法参数保持默认
                }
            }
        }
        if (hours > 0) {
            return Map.of("ok", true, "data", tailFileHours("PKI/logs.log", hours));
        }
        if (lines < 1 || lines > 5000) {
            lines = 200;
        }
        return Map.of("ok", true, "data", tailFile("PKI/logs.log", lines));
    }

    /**
     * 系统配置接口（GET）：读取 PKI/CONFIG.txt 的 6 个已知参数。
     * 文件不存在时返回默认模板值（exists=false）。
     */
    private static Map<String, Object> configJson() {
        Map<String, String> d = new LinkedHashMap<>();
        Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
        boolean exists = Files.exists(f);
        String webport = "80", ocsp = "", crl = "", crt = "", cps = "", cpsNonice = "";
        if (exists) {
            try {
                for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    int idx = t.indexOf('=');
                    if (idx <= 0) {
                        continue;
                    }
                    String k = t.substring(0, idx).trim();
                    String v = t.substring(idx + 1).trim();
                    switch (k) {
                        case "WEBPORT":   webport = v; break;
                        case "OCSP":      ocsp = v; break;
                        case "CRL":       crl = v; break;
                        case "CRT":       crt = v; break;
                        case "CPS":       cps = v; break;
                        case "CPS_Nonice":
                            // 文件中以字面 \n 存储，读取时转回真实换行供多行显示
                            cpsNonice = v.replace("\\n", "\n");
                            break;
                        default: break;
                    }
                }
            } catch (Exception e) {
                // 读取失败：返回默认值
            }
        } else {
            // 文件不存在：返回默认模板内容
            webport = "80";
            ocsp = "http://localhost:80/OCSP";
            crl = "http://localhost:80/CRL/{CID}.crl";
            crt = "http://localhost:80/CRT/{CID}.crt";
            cps = "https://gitee.com/wxgshuju/modpkica";
            cpsNonice = "http://example.com/nonice";
        }
        d.put("webport", webport);
        d.put("ocsp", ocsp);
        d.put("crl", crl);
        d.put("crt", crt);
        d.put("cps", cps);
        d.put("cpsNonice", cpsNonice);
        return Map.of("ok", true, "exists", exists, "data", d);
    }

    /** 系统配置接口（POST）：参数化保存 CONFIG.txt（保留注释与未知键，缺失键自动补齐）。 */
    private static void saveConfig(HttpExchange ex) throws Exception {
        String bodyStr = new String(readAll(ex.getRequestBody()), StandardCharsets.UTF_8);
        Map<String, Object> m = parseJsonObject(bodyStr);
        Map<String, String> updates = new LinkedHashMap<>();
        updates.put("WEBPORT", str(m, "webport"));
        updates.put("OCSP", str(m, "ocsp"));
        updates.put("CRL", str(m, "crl"));
        updates.put("CRT", str(m, "crt"));
        updates.put("CPS", str(m, "cps"));
        // CPS_Nonice：多行文本保存时，真实换行统一转字面 \n（单行存储）
        String nonice = str(m, "cpsNonice");
        nonice = nonice.replace("\r\n", "\n").replace('\r', '\n').replace("\n", "\\n");
        updates.put("CPS_Nonice", nonice);

        Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
        java.util.List<String> lines;
        if (Files.exists(f)) {
            lines = Files.readAllLines(f, StandardCharsets.UTF_8);
        } else {
            // 文件不存在：先用默认模板初始化
            lines = new java.util.ArrayList<>(java.util.Arrays.asList(
                    "WEBPORT=80",
                    "OCSP=http://localhost:80/OCSP",
                    "CRL=http://localhost:80/CRL/{CID}.crl",
                    "CRT=http://localhost:80/CRT/{CID}.crt",
                    "CPS=https://gitee.com/wxgshuju/modpkica",
                    "CPS_Nonice=http://example.com/nonice"));
        }
        StringBuilder sb = new StringBuilder();
        java.util.Set<String> done = new java.util.HashSet<>();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                sb.append(line).append("\r\n");
                continue;
            }
            int idx = t.indexOf('=');
            if (idx <= 0) {
                sb.append(line).append("\r\n");
                continue;
            }
            String k = t.substring(0, idx).trim();
            if (updates.containsKey(k)) {
                sb.append(k).append('=').append(updates.get(k)).append("\r\n");
                done.add(k);
            } else {
                sb.append(line).append("\r\n");
            }
        }
        // 补齐缺失的已知键
        for (Map.Entry<String, String> e : updates.entrySet()) {
            if (!done.contains(e.getKey())) {
                sb.append(e.getKey()).append('=').append(e.getValue()).append("\r\n");
            }
        }
        Files.createDirectories(f.getParent());
        Files.write(f, sb.toString().getBytes(StandardCharsets.UTF_8)); // UTF-8 无 BOM
        MLog.append(baseDir, "WebAdmin /api/config",
                "POST /api/config 提交数据=" + bodyStr, "CONFIG.txt 已保存");
        sendJson(ex, 200, Map.of("ok", true, "message", "CONFIG.txt 已保存"));
    }

    /** 返回最近 N 小时内的日志条目（按条目级解析，兼容新旧格式）。 */    private static String tailFileHours(String rel, int hours) {
        try {
            Path p = Paths.get(baseDir, rel);
            if (!Files.exists(p)) {
                return "(暂无日志)";
            }
            String all = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            String[] entries = all.split("\r?\n\r?\n");
            long cutoff = System.currentTimeMillis() - (long) hours * 3600_000L;
            StringBuilder sb = new StringBuilder();
            for (String e : entries) {
                String t = e.trim();
                if (t.isEmpty()) {
                    continue;
                }
                if (entryMillis(t) >= cutoff) {
                    sb.append(t).append("\n\n");
                }
            }
            return sb.length() == 0 ? "(最近 " + hours + " 小时内无日志)" : sb.toString();
        } catch (Exception e) {
            return "读取日志失败: " + e;
        }
    }

    /** 从日志条目文本提取毫秒时间戳：优先「时间戳:」行，旧格式按首行时间解析。 */
    private static long entryMillis(String entry) {
        for (String line : entry.split("\r?\n")) {
            if (line.startsWith("时间戳: ")) {
                try {
                    return Long.parseLong(line.substring(5).trim());
                } catch (Exception ignore) { }
            }
        }
        String first = entry.split("\r?\n")[0].trim();
        try {
            java.time.LocalDateTime dt = java.time.LocalDateTime.parse(first,
                    java.time.format.DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
            return dt.atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli();
        } catch (Exception ignore) { }
        return Long.MAX_VALUE; // 无法解析的条目视为最新，避免被过滤掉
    }

    // ============================================================
    // 证书链树（仪表盘树形图数据源）
    // ============================================================

    /**
     * 从 CERTS.txt 构建证书链树：
     * R（自签根）为顶层 → C（中间CA）挂其下 → E（终端证书）挂最下。
     * 每个节点附带：序列号、DN、密钥对类型、哈希算法、OCSP 状态、CRL 状态。
     */
    private static Map<String, Object> chainJson() throws Exception {
        CertsDB db = new CertsDB();
        db.load(baseDir);
        List<CertsDB.CertEntry> all = db.getAll();

        // 节点容器：serial → 节点
        Map<String, Object> nodes = new LinkedHashMap<>();
        // 记录每行，便于校验
        for (CertsDB.CertEntry e : all) {
            nodes.put(e.serial, buildChainNode(e));
        }

        // 顶层：自签 R（多根模型：issuerId 为空 或 == 自身序列号，无 root 别名）
        List<Object> roots = new ArrayList<>();
        for (CertsDB.CertEntry e : all) {
            boolean selfSigned = "R".equals(String.valueOf(e.type))
                    && (e.issuerId == null || e.issuerId.isEmpty()
                        || e.issuerId.equals(e.serial));
            if (selfSigned) {
                roots.add(nodes.get(e.serial));
            }
        }

        // 挂载非顶层节点
        for (CertsDB.CertEntry e : all) {
            boolean selfSigned = "R".equals(String.valueOf(e.type))
                    && (e.issuerId == null || e.issuerId.isEmpty()
                        || e.issuerId.equals(e.serial));
            if (selfSigned) {
                continue;
            }
            String parentId = e.issuerId;
            Object parent;
            if (parentId != null && nodes.containsKey(parentId)) {
                parent = nodes.get(parentId);
            } else {
                parent = null;
            }
            @SuppressWarnings("unchecked")
            List<Object> children = parent == null ? null
                    : (List<Object>) ((Map<String, Object>) parent).get("children");
            if (children != null) {
                children.add(nodes.get(e.serial));
            } else {
                // 孤立节点（颁发者未知）作为独立顶层展示，避免丢失
                roots.add(nodes.get(e.serial));
            }
        }
        return Map.of("ok", true, "data", roots);
    }

    /** 构造单个链节点（含证书文件信息加载）。 */
    private static Map<String, Object> buildChainNode(CertsDB.CertEntry e) {
        Map<String, Object> n = new LinkedHashMap<>();
        n.put("serial", e.serial);
        n.put("type", String.valueOf(e.type));
        n.put("status", String.valueOf(e.status));
        n.put("reason", e.reason);
        n.put("algo", e.algo == null ? "" : e.algo);
        n.put("children", new ArrayList<Object>());

        // 加载证书文件读取 DN 与哈希算法（找不到文件则给占位）
        String certPath = findCertFile(e.serial);
        if (certPath != null) {
            try {
                java.security.cert.X509Certificate c = PemIO.readCert(baseDir + "/" + certPath);
                n.put("dn", c.getSubjectX500Principal().getName());
                n.put("hash", hashFromCert(c));
                n.put("bits", keyBits(c));      // 密钥长度（位）
                n.put("kind", certKind(c));     // 证书子类型（TSA/OCSP/SSL/代码签名/文档签名）
            } catch (Exception ex) {
                n.put("dn", "(证书文件读取失败: " + certPath + ")");
                n.put("hash", "");
                n.put("bits", 0);
                n.put("kind", "");
            }
        } else {
            n.put("dn", "(未找到证书文件)");
            n.put("hash", "");
            n.put("bits", 0);
            n.put("kind", "");
        }

        // OCSP / CRL 状态（基于 CERTS.txt 登记状态；两者都以此为准）
        if (e.status == 'R') {
            n.put("ocsp", "revoked");
            n.put("crl", "已吊销");
        } else if (e.status == 'V') {
            n.put("ocsp", "good");
            n.put("crl", "未吊销");
        } else {
            n.put("ocsp", "unknown");
            n.put("crl", "未知");
        }
        return n;
    }

    /** 按序列号查找证书文件（多目录回退；OCSP/TIMSTAMP 按内容扫描匹配）。 */
    static String findCertFile(String serial) {
        String[] dirs = {
            "PKI/WebPublic/CRT/", "PKI/ROOT/", "PKI/CA/", "PKI/CERT/", "PKI/KEY/"
        };
        for (String d : dirs) {
            String p = d + serial + ".crt";
            if (Files.exists(Paths.get(baseDir, p))) {
                return p;
            }
        }
        // OCSP：文件名为 颁发者序列号_ocsp.crt，按证书内容序列号扫描匹配
        String ocspHit = scanSerialInDir("PKI/OCSP/", serial);
        if (ocspHit != null) {
            return ocspHit;
        }
        // TIMSTAMP：文件名为 rsa_sha1.crt 等，同样扫描匹配
        String tsaHit = scanSerialInDir("PKI/TIMSTAMP/", serial);
        if (tsaHit != null) {
            return tsaHit;
        }
        return null;
    }

    /** 扫描目录下全部 .crt，返回证书序列号与目标一致的相对路径。 */
    private static String scanSerialInDir(String dir, String serial) {
        java.io.File folder = new java.io.File(baseDir, dir);
        java.io.File[] files = folder.listFiles((d, name) -> name.endsWith(".crt"));
        if (files == null) {
            return null;
        }
        for (java.io.File f : files) {
            try {
                java.security.cert.X509Certificate c = PemIO.readCert(f.getAbsolutePath());
                if (c.getSerialNumber().toString(16).equalsIgnoreCase(serial)) {
                    return dir + f.getName();
                }
            } catch (Exception ignored) { }
        }
        return null;
    }

    /** 从证书签名算法推导哈希算法名（sha1/sha256/sha384/sha512/sm3）。 */
    private static String hashFromCert(java.security.cert.X509Certificate c) {
        String alg = c.getSigAlgName();
        if (alg != null) {
            String up = alg.toUpperCase();
            if (up.contains("SM3")) {
                return "sm3";
            }
            if (up.contains("SHA512")) {
                return "sha512";
            }
            if (up.contains("SHA384")) {
                return "sha384";
            }
            if (up.contains("SHA256")) {
                return "sha256";
            }
            if (up.contains("SHA1") || up.contains("SHA-1")) {
                return "sha1";
            }
            if (up.contains("MD5")) {
                return "md5";
            }
            return alg;
        }
        // 兜底：从签名算法 OID 推导
        String oid = c.getSigAlgOID();
        if (oid != null) {
            if (oid.equals(Sm2Util.OID_SM3_WITH_SM2)) {
                return "sm3";
            }
            if (oid.contains(".11") || oid.endsWith(".2.1")) {
                return "sha256";
            }
            if (oid.endsWith(".2.2") || oid.endsWith(".12")) {
                return "sha384";
            }
            if (oid.endsWith(".2.3") || oid.endsWith(".13")) {
                return "sha512";
            }
            if (oid.endsWith(".5") || oid.endsWith(".29") || oid.endsWith(".3.1")) {
                return "sha1";
            }
        }
        return "";
    }

    /** 从证书公钥推导密钥长度（位）：RSA=模数位长，ECC/SM2=曲线域大小。 */
    private static int keyBits(java.security.cert.X509Certificate c) {
        try {
            java.security.PublicKey pk = c.getPublicKey();
            if (pk instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPublicKey) pk).getModulus().bitLength();
            }
            if (pk instanceof java.security.interfaces.ECPublicKey) {
                java.security.interfaces.ECPublicKey ec =
                        (java.security.interfaces.ECPublicKey) pk;
                return ec.getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception ignored) { }
        return 0;
    }

    /** EKU OID：TSA / OCSP 专用。 */
    private static final String OID_EKU_TSA = "1.3.6.1.5.5.7.3.8";
    private static final String OID_EKU_OCSP = "1.3.6.1.5.5.7.3.9";

    /**
     * 识别证书子类型（终端证书方括号内容，只能显示一种）：
     * TSA/OCSP/文档签名靠 EKU；SSL(DV/IV/OV/EV)、代码签名(普通/EV)靠证书策略 OID；
     * TSA 证书另有策略标记 OID 2.23.140.1.4.2。
     */
    private static String certKind(java.security.cert.X509Certificate c) {
        // 1) EKU 优先：TSA / OCSP / 文档签名（标准 1.3.6.1.5.5.7.3.36，微软 1.3.6.1.4.1.311.3.10.3.12）
        try {
            java.util.List<String> eku = c.getExtendedKeyUsage();
            if (eku != null) {
                if (eku.contains(OID_EKU_TSA)) {
                    return "TSA证书";
                }
                if (eku.contains(OID_EKU_OCSP)) {
                    return "OCSP证书";
                }
                if (eku.contains("1.3.6.1.5.5.7.3.36")) {
                    return "文档签名(标准)";
                }
                if (eku.contains("1.3.6.1.4.1.311.3.10.3.12")) {
                    return "文档签名(微软)";
                }
            }
        } catch (Exception ignored) { }
        // 2) 证书策略 OID（CA/B Forum 体系；按优先级匹配，只显示一种）
        // 优先级：TSA 标记 > SSL(EV) > 代码签名(EV) > 代码签名(普通) > SSL(DV/OV/IV)
        // 普通终端证书策略同时含 2.23.140.1.1 与 2.23.140.1.3，此时按 SSL(EV) 显示（默认用途）
        Set<String> oids = policyOidSet(c);
        if (oids.contains("2.23.140.1.4.2")) return "TSA证书";        // TSA 证书策略标记
        if (oids.contains("2.23.140.1.1"))   return "SSL证书(EV)";
        if (oids.contains("2.23.140.1.3"))   return "代码签名(EV)";
        if (oids.contains("2.23.140.1.4.1")) return "代码签名(普通)";
        if (oids.contains("2.23.140.1.2.1")) return "SSL证书(DV)";
        if (oids.contains("2.23.140.1.2.2")) return "SSL证书(OV)";
        if (oids.contains("2.23.140.1.2.3")) return "SSL证书(IV)";
        return "";
    }

    /** 读取证书策略扩展（2.5.29.32）中的全部策略 OID。 */
    private static Set<String> policyOidSet(java.security.cert.X509Certificate c) {
        Set<String> oids = new LinkedHashSet<>();
        try {
            byte[] ext = c.getExtensionValue("2.5.29.32");
            if (ext == null) {
                return oids;
            }
            org.bouncycastle.asn1.ASN1OctetString oct =
                    (org.bouncycastle.asn1.ASN1OctetString)
                            org.bouncycastle.asn1.ASN1Primitive.fromByteArray(ext);
            org.bouncycastle.asn1.x509.CertificatePolicies policies =
                    org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(oct.getOctets());
            for (org.bouncycastle.asn1.x509.PolicyInformation pi
                    : policies.getPolicyInformation()) {
                oids.add(pi.getPolicyIdentifier().getId());
            }
        } catch (Exception ignored) { }
        return oids;
    }

    // ============================================================
    // 证书 JSON 详情（复用 X509JsonConverter 无损转换）
    // ============================================================

    /** /api/certjson?serial=xxx：返回 X509JsonConverter 风格的证书 JSON 文本。 */
    private static Map<String, Object> certJson(HttpExchange ex) throws Exception {
        String q = ex.getRequestURI().getQuery();
        String serial = null;
        if (q != null && q.contains("serial=")) {
            serial = q.substring(q.indexOf("serial=") + 7).split("&")[0];
        }
        if (serial == null || serial.isEmpty()) {
            return Map.of("ok", false, "message", "缺少参数 serial");
        }
        String certPath = findCertFile(serial);
        if (certPath == null) {
            return Map.of("ok", false, "message", "未找到证书文件: " + serial);
        }
        try {
            byte[] pem = Files.readAllBytes(Paths.get(baseDir, certPath));
            String json = X509JsonConverter.certToJson(pem);
            return Map.of("ok", true, "serial", serial, "path", certPath, "data", json);
        } catch (Exception e) {
            return Map.of("ok", false, "message", "证书解析失败: " + e);
        }
    }

    // ============================================================
    // 小工具
    // ============================================================

    /** 读取 CONFIG.txt 的 WEBPORT（供状态展示）。 */
    private static String readConfigWebPort() {
        try {
            Path f = Paths.get(baseDir, "PKI", "CONFIG.txt");
            if (!Files.exists(f)) {
                return "未配置";
            }
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.toUpperCase().startsWith("WEBPORT")) {
                    int i = t.indexOf('=');
                    return i >= 0 ? t.substring(i + 1).trim() : t;
                }
            }
        } catch (Exception ignore) {
            // 读取失败返回默认
        }
        return "未配置";
    }

    /** logs.log 行数（快速统计）。 */
    private static long countLogLines() {
        try {
            Path f = Paths.get(baseDir, "PKI", "logs.log");
            if (!Files.exists(f)) {
                return 0;
            }
            // 用字节流数换行符，避免整文件读入内存
            long count = 0;
            try (InputStream in = Files.newInputStream(f)) {
                int b;
                while ((b = in.read()) != -1) {
                    if (b == '\n') {
                        count++;
                    }
                }
            }
            return count;
        } catch (Exception e) {
            return 0;
        }
    }

    /** 读文件尾部最多 lines 行。 */
    private static String tailFile(String relPath, int lines) {
        Path f = Paths.get(baseDir, relPath);
        if (!Files.exists(f)) {
            return "(日志文件不存在: " + relPath + ")";
        }
        try (RandomAccessFile raf = new RandomAccessFile(f.toFile(), "r")) {
            long length = raf.length();
            long pos = length;
            int newlines = 0;
            long block = Math.min(64 * 1024, length);
            // 从尾部向前扫描，统计换行
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[(int) block];
            while (pos > 0 && newlines <= lines) {
                long start = Math.max(0, pos - block);
                int readLen = (int) (pos - start);
                raf.seek(start);
                raf.readFully(buf, 0, readLen);
                // 检查该块中换行数
                int nl = 0;
                for (int i = readLen - 1; i >= 0; i--) {
                    if (buf[i] == '\n') {
                        nl++;
                        if (newlines + nl > lines) {
                            // 找到足够行数的起始点
                            byte[] tail = new byte[readLen - i - 1];
                            System.arraycopy(buf, i + 1, tail, 0, tail.length);
                            sb.insert(0, new String(tail, StandardCharsets.UTF_8));
                            pos = start + i;
                            return normalizeTail(sb.toString());
                        }
                    }
                }
                newlines += nl;
                sb.insert(0, new String(buf, 0, readLen, StandardCharsets.UTF_8));
                pos = start;
                if (start == 0) {
                    break;
                }
            }
            return normalizeTail(sb.toString());
        } catch (Exception e) {
            return "(读取日志失败: " + e.getMessage() + ")";
        }
    }

    /** 去掉可能截断的首行（若首行不是以换行结束则说明被切断）。 */
    private static String normalizeTail(String s) {
        if (s.isEmpty()) {
            return s;
        }
        int firstNl = s.indexOf('\n');
        if (firstNl < 0) {
            return s;
        }
        return s;
    }

    /** 读取请求体全部字节。 */
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** JSON 字符串转义。 */
    static String jsonEscape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    /** 发送 JSON 响应。 */
    private static void sendJson(HttpExchange ex, int code, Map<String, Object> map)
            throws IOException {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(jsonEscape(e.getKey())).append("\":");
            appendJsonValue(sb, e.getValue());
        }
        sb.append('}');
        sendText(ex, code, "application/json; charset=utf-8", sb.toString());
    }

    /** JSON 值序列化（支持 String/Number/Boolean/Map/List/null）。 */
    @SuppressWarnings("unchecked")
    private static void appendJsonValue(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            sb.append('"').append(jsonEscape((String) v)).append('"');
        } else if (v instanceof Boolean || v instanceof Number) {
            sb.append(v);
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<Object, Object> e : ((Map<Object, Object>) v).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append('"').append(jsonEscape(String.valueOf(e.getKey()))).append("\":");
                appendJsonValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object o : (List<Object>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                appendJsonValue(sb, o);
            }
            sb.append(']');
        } else {
            sb.append('"').append(jsonEscape(String.valueOf(v))).append('"');
        }
    }

    /** 发送文本响应。 */
    private static void sendText(HttpExchange ex, int code, String contentType, String text)
            throws IOException {
        byte[] msg = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(code, msg.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(msg);
        }
    }

    // ============================================================
    // 极简 JSON 解析（仅需扁平对象，无需通用 JSON 库，保持离线）
    // ============================================================

    /** 解析 JSON 对象为 Map（只处理扁平字符串值）。 */
    private static Map<String, Object> parseJsonObject(String json) {
        Map<String, Object> out = new LinkedHashMap<>();
        String s = json == null ? "" : json.trim();
        if (s.isEmpty() || !s.startsWith("{")) {
            return out;
        }
        s = s.substring(1);
        int i = 0;
        while (i < s.length()) {
            // 找 key
            while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == ',')) {
                i++;
            }
            if (i >= s.length() || s.charAt(i) == '}') {
                break;
            }
            if (s.charAt(i) == '"') {
                int end = s.indexOf('"', i + 1);
                if (end < 0) {
                    break;
                }
                String key = s.substring(i + 1, end);
                i = end + 1;
                while (i < s.length() && s.charAt(i) != ':') {
                    i++;
                }
                i++;
                while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) {
                    i++;
                }
                // 值
                if (i < s.length() && s.charAt(i) == '"') {
                    int vEnd = i + 1;
                    StringBuilder v = new StringBuilder();
                    while (vEnd < s.length()) {
                        char c = s.charAt(vEnd);
                        if (c == '\\' && vEnd + 1 < s.length()) {
                            char n = s.charAt(vEnd + 1);
                            if (n == 'n') {
                                v.append('\n');
                            } else if (n == 'r') {
                                v.append('\r');
                            } else if (n == 't') {
                                v.append('\t');
                            } else if (n == '"') {
                                v.append('"');
                            } else if (n == '\\') {
                                v.append('\\');
                            } else {
                                v.append(n);
                            }
                            vEnd += 2;
                            continue;
                        }
                        if (c == '"') {
                            break;
                        }
                        v.append(c);
                        vEnd++;
                    }
                    out.put(key, v.toString());
                    i = vEnd + 1;
                } else {
                    int vEnd = i;
                    while (vEnd < s.length() && s.charAt(vEnd) != ',' && s.charAt(vEnd) != '}') {
                        vEnd++;
                    }
                    out.put(key, s.substring(i, vEnd).trim());
                    i = vEnd;
                }
            } else {
                i++;
            }
        }
        return out;
    }

    /** 从解析出的参数取字符串值。 */
    private static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    // ============================================================
    // 内嵌前端页面（单文件原生 HTML/CSS/JS，无任何外部依赖，离线可用）
    // ============================================================

    private static final String PAGE_HTML = """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MODPKICA 管理控制台</title>
        <style>
          :root {
            --bg: #0f1419; --panel: #171e26; --panel2: #1d2630;
            --border: #263241; --text: #d8e1ea; --dim: #8b98a5;
            --accent: #38bdf8; --accent2: #22d3ee; --ok: #34d399; --warn: #fbbf24;
            --err: #f87171; --mono: Consolas, "Courier New", monospace;
          }
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { background: var(--bg); color: var(--text); font-family: "Segoe UI", "Microsoft YaHei", sans-serif; font-size: 14px; display: flex; height: 100vh; overflow: hidden; }
          /* ===== 侧边栏 ===== */
          #sidebar { width: 200px; min-width: 200px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
          .logo { padding: 18px 16px; font-size: 18px; font-weight: 700; letter-spacing: 1px; border-bottom: 1px solid var(--border); }
          .logo span { color: var(--accent); }
          nav { flex: 1; overflow-y: auto; padding: 8px 0; }
          nav a { display: block; padding: 10px 18px; color: var(--dim); text-decoration: none; cursor: pointer; border-left: 3px solid transparent; transition: all .15s; }
          nav a:hover { color: var(--text); background: var(--panel2); }
          nav a.active { color: var(--accent); background: var(--panel2); border-left-color: var(--accent); }
          .side-foot { padding: 12px 16px; font-size: 12px; color: var(--dim); border-top: 1px solid var(--border); }
          /* ===== 主区 ===== */
          #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
          #topbar { height: 56px; display: flex; align-items: center; gap: 14px; padding: 0 20px; background: var(--panel); border-bottom: 1px solid var(--border); }
          #topbar h1 { font-size: 16px; font-weight: 600; flex: 1; }
          #content { flex: 1; overflow-y: auto; padding: 20px; }
          .page { display: none; }
          .page.active { display: block; }
          /* ===== 组件 ===== */
          .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 16px; }
          .card h2 { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--accent); }
          .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
          .stat { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
          .stat .label { font-size: 12px; color: var(--dim); margin-bottom: 6px; }
          .stat .value { font-size: 20px; font-weight: 700; font-family: var(--mono); }
          .stat .value.ok { color: var(--ok); } .stat .value.warn { color: var(--warn); } .stat .value.err { color: var(--err); }
          .stat.stat-wide { grid-column: 1 / -1; }
          .stat.stat-wide .value { font-size: 13px; white-space: normal; word-break: break-all; line-height: 1.6; }
          .cfg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; margin-top: 14px; }
          .cfg-field { background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
          .cfg-field label { display: block; font-size: 13px; font-weight: 600; color: var(--fg); margin-bottom: 8px; }
          .cfg-tag { font-size: 11px; font-weight: 400; color: var(--dim); margin-left: 6px; }
          .cfg-field input { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 13px; }
          .cfg-field textarea { width: 100%; box-sizing: border-box; font-family: var(--mono); font-size: 13px; resize: vertical; min-height: 90px; line-height: 1.6; }
          .cfg-field-wide { grid-column: 1 / -1; }
          .cfg-hint { font-size: 11px; color: var(--dim); margin: 8px 0 0; line-height: 1.5; }
          .eku-modal { width: min(700px, 94vw); }
          .eku-body { display: grid; grid-template-columns: repeat(auto-fill, minmax(310px, 1fr)); gap: 4px; max-height: 55vh; overflow: auto; padding: 10px 4px; }
          .eku-item { display: flex; align-items: center; gap: 8px; font-size: 13px; padding: 7px 9px; border-radius: 6px; cursor: pointer; }
          .eku-item:hover { background: var(--panel2); }
          .eku-item input { width: auto; flex: none; }
          .eku-item code { color: var(--dim); font-size: 11px; margin-left: auto; white-space: nowrap; }
          .modal-foot { display: flex; gap: 10px; justify-content: flex-end; padding: 12px 18px; border-top: 1px solid var(--border); }
          .val-row { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
          .val-row label { width: 64px; font-size: 13px; color: var(--fg); flex: none; }
          .val-row input { width: 100%; font-family: var(--mono); font-size: 13px; }
          .fsec { margin-top: 16px; padding-top: 12px; border-top: 1px dashed var(--border); }
          .fsec:first-of-type { margin-top: 0; padding-top: 0; border-top: none; }
          .fsec-title { font-size: 12px; font-weight: 700; color: var(--accent); margin-bottom: 10px; letter-spacing: 1px; }
          select.t-box { cursor: pointer; }
          select.t-box:hover { border-color: var(--accent); }
          .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
          .badge.ok { background: rgba(52,211,153,.15); color: var(--ok); }
          .badge.err { background: rgba(248,113,113,.15); color: var(--err); }
          .badge.dim { background: var(--panel2); color: var(--dim); }
          label { display: block; font-size: 12px; color: var(--dim); margin: 10px 0 4px; }
          input, select, textarea { width: 100%; background: var(--panel2); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 8px 10px; font-family: var(--mono); font-size: 13px; outline: none; }
          input:focus, select:focus, textarea:focus { border-color: var(--accent); }
          .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
          button { background: var(--accent); color: #06202e; border: none; border-radius: 6px; padding: 9px 20px; font-size: 13px; font-weight: 700; cursor: pointer; transition: filter .15s; }
          button:hover { filter: brightness(1.15); }
          button.ghost { background: var(--panel2); color: var(--text); border: 1px solid var(--border); }
          button.danger { background: #7f1d1d; color: #fecaca; }
          button:disabled { opacity: .5; cursor: not-allowed; }
          table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12.5px; }
          th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; white-space: nowrap; }
          th { color: var(--dim); font-weight: 600; position: sticky; top: 0; background: var(--panel); }
          tr:hover td { background: var(--panel2); }
          pre.out { background: #0a0e13; border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: var(--mono); font-size: 12.5px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; max-height: 420px; overflow-y: auto; margin-top: 14px; }
          pre.out.ok { border-color: rgba(52,211,153,.4); } pre.out.err { border-color: rgba(248,113,113,.4); }
          .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
          .toolbar input { width: auto; } .toolbar select { width: auto; }
          .hint { font-size: 12px; color: var(--warn); background: rgba(251,191,36,.08); border: 1px solid rgba(251,191,36,.3); border-radius: 6px; padding: 8px 12px; margin-bottom: 10px; }
          .loading { opacity: .6; pointer-events: none; }
          ::-webkit-scrollbar { width: 8px; height: 8px; }
          ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
          /* ===== 证书链树 ===== */
          .t-row { display: flex; gap: 28px; align-items: flex-start; flex-wrap: wrap; }
          .t-node { position: relative; margin: 4px 0; }
          .t-head { display: flex; align-items: center; gap: 4px; }
          .t-toggle { flex: none; width: 16px; height: 16px; line-height: 14px; text-align: center; font-size: 9px; cursor: pointer; user-select: none; color: var(--accent); background: var(--panel2); border: 1px solid var(--border); border-radius: 4px; }
          .t-toggle:hover { background: var(--border); }
          .t-node-root > .t-head > .t-box { border-color: #b45309; }
          .t-node-c > .t-head > .t-box { border-color: #2563eb; }
          .t-node-e > .t-head > .t-box { border-color: #059669; }
          .t-box { display: inline-block; padding: 7px 12px; border: 1px solid var(--border); border-left-width: 4px; border-radius: 8px; background: var(--panel2); cursor: default; font-family: var(--mono); font-size: 12px; white-space: nowrap; }
          .t-box .t-badge { display: inline-block; width: 18px; height: 18px; line-height: 18px; text-align: center; border-radius: 4px; font-size: 11px; font-weight: 700; margin-right: 6px; }
          .t-badge.R { background: rgba(180,83,9,.25); color: #fbbf24; }
          .t-badge.C { background: rgba(37,99,235,.25); color: #60a5fa; }
          .t-badge.E { background: rgba(5,150,105,.25); color: #34d399; }
          .t-kind { color: var(--dim); font-size: 11px; margin-right: 8px; }
          .t-box .t-st { margin-left: 8px; font-size: 11px; }
          .t-box .t-st.V { color: var(--ok); } .t-box .t-st.R { color: var(--err); } .t-box .t-st.N { color: var(--warn); }
          .t-children { margin-left: 22px; padding-left: 14px; border-left: 2px solid var(--border); }
          .t-children.collapsed { display: none; }
          .t-tip, #tipFloat b { color: var(--accent); }
          .t-tip, #tipFloat .kv { font-family: var(--mono); }
          /* 悬浮详情：fixed 挂 body，避免被 #content 滚动容器裁剪或被顶栏遮挡 */
          #tipFloat { position: fixed; z-index: 9999; left: 0; top: 0; min-width: 260px; max-width: 420px; background: #0a0e13; border: 1px solid var(--accent); border-radius: 8px; padding: 10px 12px; font-size: 12px; line-height: 1.7; display: none; pointer-events: none; box-shadow: 0 8px 24px rgba(0,0,0,.5); }
          /* ===== 详情弹窗 ===== */
          .modal-mask { position: fixed; inset: 0; background: rgba(0,0,0,.65); z-index: 100; display: none; align-items: center; justify-content: center; }
          .modal-mask.show { display: flex; }
          .modal { width: min(900px, 92vw); max-height: 86vh; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; }
          .modal-head { display: flex; align-items: center; padding: 12px 18px; border-bottom: 1px solid var(--border); }
          .modal-head h3 { flex: 1; font-size: 14px; color: var(--accent); }
          .modal-body { overflow: auto; padding: 14px 18px; }
          .modal-body pre { font-family: var(--mono); font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }
        </style>
        </head>
        <body>
        <!-- ===== 侧边栏 ===== -->
        <aside id="sidebar">
          <div class="logo">MOD<span>PKICA</span></div>
          <nav id="nav">
            <a data-page="dashboard" class="active">仪表盘</a>
            <a data-page="certs">证书库</a>
            <a data-page="makeroot">签发根证书</a>
            <a data-page="signcert">签发证书</a>
            <a data-page="revoke">吊销证书</a>
            <a data-page="crl">CRL 刷新</a>
            <a data-page="ocsp">OCSP 签发</a>
            <a data-page="timestamp">时间戳签发</a>
            <a data-page="verify">证书验证</a>
            <a data-page="init">初始化环境</a>
            <a data-page="config">系统配置</a>
            <a data-page="logs">操作日志</a>
          </nav>
          <div class="side-foot" id="sideVersion">加载中...</div>
        </aside>

        <!-- ===== 主区 ===== -->
        <div id="main">
          <header id="topbar">
            <h1 id="pageTitle">仪表盘</h1>
            <span class="badge dim" id="mainPort">MAIN: --</span>
            <span class="badge ok" id="mainState">--</span>
            <button class="ghost" onclick="loadStatus()">刷新</button>
          </header>

          <section id="content">

            <!-- 仪表盘 -->
            <div class="page active" id="page-dashboard">
              <div class="grid">
                <div class="stat"><div class="label">MAIN 服务端口</div><div class="value ok" id="stPort">--</div></div>
                <div class="stat"><div class="label">服务运行时长</div><div class="value" id="stUptime">--</div></div>
                <div class="stat"><div class="label">管理界面端口</div><div class="value" id="stAdmin">--</div></div>
                <div class="stat"><div class="label">API 调用次数</div><div class="value" id="stCalls">--</div></div>
                <div class="stat"><div class="label">日志行数</div><div class="value" id="stLogs">--</div></div>
                <div class="stat stat-wide"><div class="label">工作目录</div><div class="value" id="stBase">--</div></div>
              </div>
              <div class="card" style="margin-top:16px">
                <h2>快捷操作</h2>
                <div class="toolbar">
                  <button onclick="quickAction('/api/crl')">刷新全部 CRL</button>
                  <button onclick="quickAction('/api/initocsp')">签发全部 OCSP</button>
                  <button onclick="quickAction('/api/inittimestamp')">签发全部时间戳</button>
                </div>
                <pre class="out" id="dashOut" hidden></pre>
              </div>
              <div class="card">
                <h2>证书链树</h2>
                <div class="toolbar">
                  <span style="color:var(--dim);font-size:12px">根 R → 中间 CA C → 终端 E；鼠标悬停节点查看证书参数</span>
                  <button class="ghost" onclick="loadChain()">刷新</button>
                </div>
                <div id="chainBox" style="overflow:auto;max-height:52vh;padding:10px">加载中...</div>
              </div>
              <div class="card">
                <h2>最近日志</h2>
                <pre class="out" id="dashLogs" style="max-height:260px"></pre>
              </div>
            </div>

            <!-- 证书库 -->
            <div class="page" id="page-certs">
              <div class="card">
                <h2>证书库 CERTS.txt</h2>
                <div class="toolbar">
                  <input id="certsFilter" placeholder="筛选：序列号 / 类型 / 状态 / 算法" style="flex:1;max-width:360px" oninput="renderCerts()">
                  <button class="ghost" onclick="loadCerts()">刷新列表</button>
                </div>
                <div style="overflow:auto;max-height:60vh">
                  <table id="certsTable">
                    <thead><tr><th>序列号</th><th>类型</th><th>状态</th><th>原因</th><th>时间</th><th>颁发者ID</th><th>算法</th><th>操作</th></tr></thead>
                    <tbody></tbody>
                  </table>
                </div>
              </div>
            </div>

            <!-- 签发根证书 -->
            <div class="page" id="page-makeroot">
              <div class="card">
                <h2>签发根证书（MakeRoot）</h2>
                <div class="row">
                  <div style="grid-column:1/-1"><label>证书 DN（逗号分隔 key=value）</label><input id="mkDn" value="CN=Test Root CA,O=My Org,C=CN"></div>
                  <div><label>密钥位数</label><input id="mkBits" value="2048" placeholder="RSA 1024-8192 / ECC 256 / SM2 256"></div>
                  <div><label>哈希算法</label><select id="mkHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SM3</option></select></div>
                  <div><label>密钥算法</label><select id="mkAlgo"><option>RSA</option><option>ECC</option><option>SM2</option></select></div>
                </div>
                <div style="margin-top:16px"><button onclick="postForm('/api/makeroot', {dn:v('mkDn'),bits:v('mkBits'),hash:v('mkHash'),algo:v('mkAlgo')}, 'mkOut')">签发根证书</button></div>
                <pre class="out" id="mkOut"></pre>
              </div>
            </div>

            <!-- 签发证书 -->
            <div class="page" id="page-signcert">
              <div class="card">
                <h2>签发证书（MakeCert 普通模式，12 参数）</h2>

                <div class="fsec"><div class="fsec-title">主体信息</div>
                  <div class="row">
                    <div style="grid-column:1/-1"><label>证书 DN（key=value 逗号分隔，key 可为标准属性或 OID）</label><input id="scDn" value="CN=www.test.com,O=My Org,C=CN"></div>
                    <div><label>证书类型</label><select id="scCa"><option value="0">终端证书</option><option value="1">中间 CA</option></select></div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">密钥与算法</div>
                  <div class="row">
                    <div><label>密钥算法</label><select id="scAlgo" onchange="algoChanged()"><option>RSA</option><option>ECC</option><option>SM2</option></select></div>
                    <div><label>密钥位数</label>
                      <div style="display:flex;gap:6px;align-items:center">
                        <input id="scBits" list="scBitsList" value="2048" title="RSA 可编辑；ECC/SM2 只读固定">
                        <datalist id="scBitsList">
                          <option value="1024"></option><option value="2048"></option>
                          <option value="3072"></option><option value="4096"></option><option value="8192"></option>
                        </datalist>
                        <select id="scBitsSel" style="display:none"></select>
                      </div>
                    </div>
                    <div><label>哈希算法</label><select id="scHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SM3</option></select></div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">密钥用途</div>
                  <div class="row">
                    <div><label>KeyUsage 编号</label>
                      <select id="scKu" onchange="kuSelChanged()">
                        <option value="1">1 - 数字签名+不可否认+密钥加密+数据加密+密钥协商（通用）</option>
                        <option value="2">2 - 数字签名+不可否认+证书签名+CRL签名（CA用途）</option>
                        <option value="3">3 - 仅加密 Encipher Only</option>
                        <option value="4">4 - 仅解密 Decipher Only</option>
                        <option value="5">5 - 数字签名+不可否认（签名用途）</option>
                        <option value="6">6 - 数据加密 Data Encipherment</option>
                        <option value="7">7 - 密钥加密 Key Encipherment</option>
                        <option value="8">8 - 密钥协商 Key Agreement</option>
                        <option value="custom">自定义组合…（密钥用法选择器）</option>
                      </select>
                      <div style="display:flex;gap:6px;align-items:center;margin-top:6px">
                        <input id="scKuCustom" placeholder="自定义数值：各位值相加，如 5=数字签名1+密钥加密4" style="display:none">
                        <button type="button" class="ghost" onclick="openKuModal()" style="white-space:nowrap;flex:none">密钥用法…</button>
                      </div>
                    </div>
                    <div><label>EKU 编号/OID（逗号分隔）</label>
                      <div style="display:flex;gap:6px;align-items:center">
                        <input id="scEu" value="1" onclick="openEkuModal()" title="点击输入框或右侧按钮弹出 EKU 选择器">
                        <button type="button" class="ghost" onclick="openEkuModal()" style="white-space:nowrap;flex:none">选择…</button>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">有效期</div>
                  <div class="row">
                    <div><label>有效期（年数或 起始T截至）</label>
                      <div style="display:flex;gap:6px;align-items:center">
                        <input id="scDays" value="1" title="数字=年数；或格式 起始T截至，如 2026/09/12-10:30:00T2027/09/12-10:30:00">
                        <button type="button" class="ghost" onclick="openValModal()" style="white-space:nowrap;flex:none">选择日期…</button>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">SAN 扩展</div>
                  <div class="row">
                    <div><label>SAN 域名（逗号分隔，无则 null）</label><input id="scDns" value="null"></div>
                    <div><label>SAN IP（逗号分隔，无则 null）</label><input id="scIps" value="null"></div>
                  </div>
                </div>

                <div class="fsec"><div class="fsec-title">颁发者</div>
                  <div class="row">
                    <div style="grid-column:1/-1"><label>颁发者证书（CERTS.txt 中 R/C 类型序列号，鼠标悬停显示详情）</label>
                      <select id="scIssuer" class="t-box" onchange="refreshIssuerTip()"></select>
                    </div>
                  </div>
                </div>

                <div style="margin-top:16px"><button onclick="postForm('/api/signcert', {dn:v('scDn'),bits:bitsVal(),hash:v('scHash'),keyusage:kuVal(),exusage:v('scEu'),isca:v('scCa'),days:v('scDays'),dns:v('scDns'),ips:v('scIps'),issuer:v('scIssuer'),algo:v('scAlgo')}, 'scOut')">签发证书</button></div>
                <pre class="out" id="scOut"></pre>
              </div>
            </div>

            <!-- 吊销证书 -->
            <div class="page" id="page-revoke">
              <div class="card">
                <h2>吊销证书（RevokeCERT）</h2>
                <div class="hint">吊销后自动刷新 CRL 吊销列表。请先在「证书库」中确认序列号。</div>
                <div class="row">
                  <div><label>证书序列号</label><input id="rvSerial" placeholder="如 13fbe86586bb0a4"></div>
                  <div><label>吊销原因编号（0~9）</label><select id="rvReason">
                    <option value="0">0 - 未指定</option><option value="1">1 - 密钥泄露</option><option value="2">2 - CA泄露</option>
                    <option value="3">3 - 信息变更</option><option value="4">4 - 被替换</option><option value="5">5 - 操作终止</option>
                    <option value="6">6 - 证书暂停</option><option value="9">9 - 其它</option>
                  </select></div>
                </div>
                <div style="margin-top:16px"><button class="danger" onclick="postForm('/api/revoke', {serial:v('rvSerial'),reason:v('rvReason')}, 'rvOut')">吊销该证书</button></div>
                <pre class="out" id="rvOut"></pre>
              </div>
            </div>

            <!-- CRL -->
            <div class="page" id="page-crl">
              <div class="card">
                <h2>签发吊销列表（RootGetCrl）</h2>
                <p style="color:var(--dim);margin-bottom:14px">遍历全部根/中间 CA，为每个颁发者重新签发 CRL（PEM + DER），输出到 PKI/WebPublic/CRL/序列号.crl。</p>
                <button onclick="postForm('/api/crl', {}, 'crlOut')">立即刷新全部 CRL</button>
                <pre class="out" id="crlOut"></pre>
              </div>
            </div>

            <!-- OCSP -->
            <div class="page" id="page-ocsp">
              <div class="card">
                <h2>签发 OCSP 签名证书（initOCSP）</h2>
                <p style="color:var(--dim);margin-bottom:14px">为证书库中全部 R（根）/ C（中间CA）证书逐个生成 OCSP 签名证书，输出到 PKI/OCSP/序列号_ocsp.crt|.key。</p>
                <div class="toolbar">
                  <select id="ocAlgo"><option value="">全部证书（按各自算法）</option><option>RSA</option><option>ECC</option><option>SM2</option></select>
                  <button onclick="postForm('/api/initocsp', {algo:v('ocAlgo')}, 'ocOut')">签发 OCSP 证书</button>
                </div>
                <pre class="out" id="ocOut"></pre>
              </div>
            </div>

            <!-- 时间戳 -->
            <div class="page" id="page-timestamp">
              <div class="card">
                <h2>签发时间戳证书（initTIMSTAMP）</h2>
                <p style="color:var(--dim);margin-bottom:14px">为全部根证书生成时间戳证书：RSA/ECC → rsa/ecc_sha1 + rsa/ecc_sha256，SM2 → sm2_sm3，输出到 PKI/TIMSTAMP/。</p>
                <div class="toolbar">
                  <select id="tsHash"><option value="">全部根证书（按各自算法）</option><option>SHA1</option><option>SHA256</option><option>SM3</option></select>
                  <button onclick="postForm('/api/inittimestamp', {hash:v('tsHash')}, 'tsOut')">签发时间戳证书</button>
                </div>
                <pre class="out" id="tsOut"></pre>
              </div>
            </div>

            <!-- 证书验证 -->
            <div class="page" id="page-verify">
              <div class="card">
                <h2>证书验证（CertVerify）</h2>
                <div class="toolbar">
                  <input id="vfTarget" placeholder="证书文件路径，或序列号（自动查 PKI/WebPublic/CRT/序列号.crt）" style="flex:1;max-width:520px">
                  <button onclick="postForm('/api/verify', {target:v('vfTarget')}, 'vfOut')">验证</button>
                </div>
                <pre class="out" id="vfOut"></pre>
              </div>
            </div>

            <!-- 初始化环境 -->
            <div class="page" id="page-init">
              <div class="card">
                <h2>初始化环境（Admin init）</h2>
                <div class="hint">注意：会备份现有 CERTS.txt 为 .old.时间戳，然后写入模板、签发根证书、全量 OCSP 与时间戳证书。仅在全新环境或确认无业务数据时执行。</div>
                <div class="row">
                  <div style="grid-column:1/-1"><label>根证书 DN</label><input id="inDn" value="CN=My Root CA,O=My Org,C=CN"></div>
                  <div><label>密钥位数</label><input id="inBits" value="2048"></div>
                  <div><label>哈希算法</label><select id="inHash"><option>sha256</option><option>sha1</option><option>sha384</option><option>sha512</option><option>SM3</option></select></div>
                  <div><label>密钥算法</label><select id="inAlgo"><option>RSA</option><option>ECC</option><option>SM2</option></select></div>
                </div>
                <div style="margin-top:16px"><button class="danger" onclick="postForm('/api/init', {dn:v('inDn'),bits:v('inBits'),hash:v('inHash'),algo:v('inAlgo')}, 'inOut')">执行初始化</button></div>
                <pre class="out" id="inOut"></pre>
              </div>
            </div>

            <!-- 系统配置 -->
            <div class="page" id="page-config">
              <div class="card">
                <h2>系统配置（PKI/CONFIG.txt）</h2>
                <div class="toolbar">
                  <span style="color:var(--dim);font-size:12px" id="cfgState">读取中...</span>
                  <button class="ghost" onclick="loadConfig()">重新读取</button>
                </div>
                <div class="cfg-grid">
                  <div class="cfg-field">
                    <label>WEBPORT <span class="cfg-tag">Web 服务端口</span></label>
                    <input id="cfgWebport" placeholder="80" spellcheck="false">
                    <p class="cfg-hint">MAIN 服务监听端口，修改后需重启 MAIN 生效。</p>
                  </div>
                  <div class="cfg-field">
                    <label>OCSP <span class="cfg-tag">OCSP 响应器 URL</span></label>
                    <input id="cfgOcsp" placeholder="http://localhost:80/OCSP" spellcheck="false">
                    <p class="cfg-hint">写入证书 AuthorityInfoAccess 扩展的 OCSP 地址。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CRL <span class="cfg-tag">CRL 分发点 URL</span></label>
                    <input id="cfgCrl" placeholder="http://localhost:80/CRL/{CID}.crl" spellcheck="false">
                    <p class="cfg-hint">支持 {CID} 变量（证书序列号），写入 CRL 分发点扩展。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CRT <span class="cfg-tag">证书下载 URL</span></label>
                    <input id="cfgCrt" placeholder="http://localhost:80/CRT/{CID}.crt" spellcheck="false">
                    <p class="cfg-hint">caIssuers 地址，支持 {CID} 变量。</p>
                  </div>
                  <div class="cfg-field">
                    <label>CPS <span class="cfg-tag">证书策略 CPS URI</span></label>
                    <input id="cfgCps" placeholder="https://gitee.com/wxgshuju/modpkica" spellcheck="false">
                    <p class="cfg-hint">证书策略限定符指向的 CPS 链接。</p>
                  </div>
                  <div class="cfg-field cfg-field-wide">
                    <label>CPS_Nonice <span class="cfg-tag">用户通告文本（支持多行）</span></label>
                    <textarea id="cfgCpsNonice" rows="5" spellcheck="false" placeholder="http://example.com/nonice"></textarea>
                    <p class="cfg-hint">多行输入；保存到 CONFIG.txt 时换行自动以 \n 代替（单行存储）。</p>
                  </div>
                </div>
                <div style="margin-top:18px;display:flex;gap:10px;align-items:center">
                  <button onclick="saveConfigBtn(this)">保存配置</button>
                  <button class="ghost" onclick="loadConfig()">放弃修改</button>
                </div>
                <pre class="out" id="cfgOut" hidden></pre>
              </div>
            </div>

            <!-- 日志 -->
            <div class="page" id="page-logs">
              <div class="card">
                <h2>操作日志（PKI/logs.log）</h2>
                <div class="toolbar">
                  <span style="margin:0;color:var(--dim)">时间范围</span>
                  <button class="ghost" onclick="loadLogsHours(1)">最近1小时</button>
                  <button class="ghost" onclick="loadLogsHours(6)">最近6小时</button>
                  <button class="ghost" onclick="loadLogsHours(12)">最近12小时</button>
                  <button class="ghost" onclick="loadLogsHours(24)">最近24小时</button>
                  <button class="ghost" onclick="loadLogsHours(0)">全部</button>
                  <span style="margin:0 4px 0 12px;color:var(--dim)">行数</span>
                  <select id="logLines" onchange="loadLogs()"><option>100</option><option selected>200</option><option>500</option><option>1000</option></select>
                  <label style="margin:0"><input type="checkbox" id="logAuto" checked style="width:auto"> 自动刷新(3s)</label>
                  <button class="ghost" onclick="loadLogs()">手动刷新</button>
                </div>
                <pre class="out" id="logsOut" style="max-height:calc(100vh - 260px)"></pre>
              </div>
            </div>

          </section>
        </div>

        <!-- 证书 JSON 详情弹窗 -->
        <div class="modal-mask" id="modal" onclick="if(event.target===this)closeModal()">
          <div class="modal">
            <div class="modal-head">
              <h3 id="modalTitle">证书详情</h3>
              <button class="ghost" onclick="closeModal()">关闭</button>
            </div>
            <div class="modal-body">
              <div id="modalMeta" style="color:var(--dim);font-size:12px;margin-bottom:10px"></div>
              <pre id="modalJson">加载中...</pre>
            </div>
          </div>
        </div>

        <!-- 有效期选择悬浮窗 -->
        <div class="modal-mask" id="valModal" style="display:none" onclick="if(event.target===this)closeValModal()">
          <div class="modal" style="width:min(460px,92vw)">
            <div class="modal-head">
              <h3>选择有效期（精确到秒）</h3>
              <button class="ghost" onclick="closeValModal()">取消</button>
            </div>
            <div class="modal-body">
              <div class="val-row"><label>起始时间</label><input type="datetime-local" id="valStart" step="1"></div>
              <div class="val-row"><label>截至时间</label><input type="datetime-local" id="valEnd" step="1"></div>
              <p class="cfg-hint">时间精确到秒；确定后以 起始T截至 格式写入有效期输入框（如 2026/09/12-10:30:00T2027/09/12-10:30:00），也可直接手输数字年数。</p>
            </div>
            <div class="modal-foot">
              <button onclick="valOk()">确定</button>
              <button class="ghost" onclick="closeValModal()">取消</button>
            </div>
          </div>
        </div>

        <!-- KeyUsage 密钥用法选择悬浮窗 -->
        <div class="modal-mask" id="kuModal" style="display:none" onclick="if(event.target===this)closeKuModal()">
          <div class="modal eku-modal">
            <div class="modal-head">
              <h3>选择密钥用法（KeyUsage</h3>
              <button class="ghost" onclick="closeKuModal()">取消</button>
            </div>
            <div class="eku-body" id="kuBody"></div>
            <div class="modal-foot">
              <button onclick="kuOk()">确定</button>
              <button class="ghost" onclick="closeKuModal()">取消</button>
            </div>
          </div>
        </div>

        <!-- EKU 增强型密钥用法选择悬浮窗 -->
        <div class="modal-mask" id="ekuModal" style="display:none" onclick="if(event.target===this)closeEkuModal()">
          <div class="modal eku-modal">
            <div class="modal-head">
              <h3>增强型密钥用法（EKU）选择</h3>
              <button class="ghost" onclick="closeEkuModal()">取消</button>
            </div>
            <div class="eku-body" id="ekuBody"></div>
            <div class="modal-foot">
              <button onclick="ekuOk()">确定</button>
              <button class="ghost" onclick="closeEkuModal()">取消</button>
            </div>
          </div>
        </div>

        <script>
        // ===== 工具 =====
        const $ = id => document.getElementById(id);
        const v = id => $(id).value.trim();
        const TITLES = { dashboard:'仪表盘', certs:'证书库', makeroot:'签发根证书', signcert:'签发证书', revoke:'吊销证书', crl:'CRL 刷新', ocsp:'OCSP 签发', timestamp:'时间戳签发', verify:'证书验证', init:'初始化环境', config:'系统配置', logs:'操作日志' };

        async function api(path, body) {
          const opt = { method: body ? 'POST' : 'GET', headers: {} };
          if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
          const r = await fetch(path, opt);
          return r.json();
        }

        function showOut(id, text, ok) {
          const el = $(id);
          el.hidden = false;
          el.textContent = text || '(无输出)';
          el.className = 'out ' + (ok ? 'ok' : 'err');
        }

        async function postForm(path, params, outId, btn) {
          const el = $(outId);
          el.hidden = false; el.className = 'out'; el.textContent = '执行中...';
          if (btn) btn.disabled = true;
          try {
            const r = await api(path, params);
            showOut(outId, r.message || 'OK', !!r.ok);
          } catch (e) {
            showOut(outId, '请求失败: ' + e, false);
          } finally {
            if (btn) btn.disabled = false;
          }
        }

        async function quickAction(path) {
          postForm(path, {}, 'dashOut');
        }

        // ===== 页面切换 =====
        document.querySelectorAll('#nav a').forEach(a => {
          a.onclick = () => {
            document.querySelectorAll('#nav a').forEach(x => x.classList.remove('active'));
            document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
            a.classList.add('active');
            const p = a.dataset.page;
            $('page-' + p).classList.add('active');
            $('pageTitle').textContent = TITLES[p] || p;
            if (p === 'dashboard') loadStatus();
            if (p === 'certs') loadCerts();
            if (p === 'config') loadConfig();
            if (p === 'logs') loadLogs();          };
        });

        // ===== 仪表盘 =====
        function fmtUptime(s) {
          if (s < 60) return s + ' 秒';
          if (s < 3600) return Math.floor(s/60) + ' 分 ' + (s%60) + ' 秒';
          if (s < 86400) return Math.floor(s/3600) + ' 时 ' + Math.floor(s%3600/60) + ' 分';
          return Math.floor(s/86400) + ' 天 ' + Math.floor(s%86400/3600) + ' 时';
        }
        async function loadStatus() {
          try {
            const r = await api('/api/status');
            if (!r.ok) return;
            const d = r.data;
            $('stPort').textContent = d.mainPort;
            $('stUptime').textContent = fmtUptime(d.uptimeSeconds);
            $('stAdmin').textContent = d.adminPort;
            $('stCalls').textContent = d.totalCalls;
            $('stLogs').textContent = d.logLines;
            $('stBase').textContent = d.baseDir;
            $('mainPort').textContent = 'MAIN: ' + d.mainPort;
            const st = $('mainState');
            st.textContent = d.mainRunning ? '● 运行中' : '○ 未运行';
            st.className = 'badge ' + (d.mainRunning ? 'ok' : 'err');
            $('sideVersion').textContent = d.version;
            // 最近日志
            const lr = await api('/api/logs?lines=30');
            if (lr.ok) $('dashLogs').textContent = lr.data;
          } catch (e) {
            $('mainState').textContent = '连接失败';
            $('mainState').className = 'badge err';
          }
        }

        // ===== 证书库 =====
        let certData = [];
        async function loadCerts() {
          try {
            const r = await api('/api/certs');
            if (r.ok) { certData = r.data; renderCerts(); }
          } catch (e) { /* ignore */ }
        }
        function renderCerts() {
          const f = v('certsFilter').toLowerCase();
          const rows = certData.filter(e => !f || JSON.stringify(e).toLowerCase().includes(f));
          const tb = $('certsTable').querySelector('tbody');
          tb.innerHTML = '';
          rows.forEach(e => {
            const tr = document.createElement('tr');
            const stCls = e.status === 'R' ? 'color:var(--err)' : e.status === 'V' ? 'color:var(--ok)' : '';
            tr.innerHTML = '<td>' + e.serial + '</td><td>' + e.type + '</td><td style="' + stCls + ';font-weight:700">' + e.status + '</td><td>' + e.reason + '</td><td>' + e.time + '</td><td>' + e.issuer + '</td><td>' + e.algo + '</td>' +
              '<td><button class="ghost" data-serial="' + e.serial + '" style="padding:4px 12px;font-size:12px">详情</button></td>';
            tb.appendChild(tr);
          });
          if (!rows.length) tb.innerHTML = '<tr><td colspan="8" style="color:var(--dim)">（无匹配记录）</td></tr>';
        }

        // 签发证书的颁发者下拉：CERTS.txt 中 R/C 类型序列号（悬停显示证书详情）
        let issuerMap = {};
        async function loadIssuers() {
          try {
            const [ri, rc] = await Promise.all([api('/api/issuers'), api('/api/chain')]);
            if (!ri.ok) return;
            issuerMap = {};
            if (rc.ok) {
              // /api/chain 返回嵌套树，展平为 serial → 节点
              const walk = nodes => (nodes || []).forEach(n => {
                issuerMap[n.serial] = n;
                if (n.children && n.children.length) walk(n.children);
              });
              walk(rc.data);
            }
            const sel = $('scIssuer');
            if (!sel) return;
            const keep = sel.value;
            sel.innerHTML = '';
            ri.issuers.forEach(s => {
              const opt = document.createElement('option');
              opt.value = s;
              opt.textContent = s;
              sel.appendChild(opt);
            });
            if (keep && [...sel.options].some(o => o.value === keep)) sel.value = keep;
            refreshIssuerTip();
          } catch (e) { /* ignore */ }
        }
        // 颁发者悬浮窗：与仪表盘证书链相同样式
        function issuerTip(serial) {
          const n = issuerMap[serial];
          if (!n) return '<div class="kv"><b>证书信息：</b>未找到（该序列号未登记详情）</div>';
          const stTxt = {V:'正常', R:'已吊销', N:'未知'}[n.status] || n.status;
          const kind = n.type === 'E' && n.kind ? '[' + n.kind + ']' : '';
          return '<div class="kv"><b>证书类型：</b>' + esc(typeName(n.type) + kind) + '</div>' +
            '<div class="kv"><b>序列号：</b>' + esc(n.serial) + '</div>' +
            '<div class="kv"><b>DN：</b>' + esc(n.dn) + '</div>' +
            '<div class="kv"><b>密钥对：</b>' + esc(n.algo || '-') + ' / 哈希：' + esc(n.hash || '-') + ' / 长度：' + (n.bits ? n.bits + '位' : '-') + '</div>' +
            '<div class="kv"><b>OCSP 状态：</b>' + esc(n.ocsp) + '</div>' +
            '<div class="kv"><b>CRL 状态：</b>' + esc(n.crl) + '（登记状态 ' + stTxt + '）</div>';
        }
        function refreshIssuerTip() {
          const sel = $('scIssuer');
          if (!sel) return;
          sel.dataset.tip = issuerTip(sel.value);
        }

        // ===== 证书 JSON 详情 =====
        async function showDetail(serial) {
          $('modal').classList.add('show');
          $('modalTitle').textContent = '证书详情 · ' + serial;
          $('modalJson').textContent = '加载中...';
          $('modalMeta').textContent = '';
          try {
            const r = await api('/api/certjson?serial=' + encodeURIComponent(serial));
            if (r.ok) {
              $('modalMeta').textContent = '路径: ' + r.path;
              $('modalJson').textContent = r.data;
            } else {
              $('modalJson').textContent = r.message || '解析失败';
            }
          } catch (e) {
            $('modalJson').textContent = '请求失败: ' + e;
          }
        }
        function closeModal() { $('modal').classList.remove('show'); }

        // ===== 证书链树 =====
        function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
        function typeName(t) { return {R:'根证书', C:'中间证书', E:'终端证书'}[t] || t; }
        function tipHtml(n) {
          const stTxt = {V:'正常', R:'已吊销', N:'未知'}[n.status] || n.status;
          const kind = n.type === 'E' && n.kind ? '[' + n.kind + ']' : '';
          return '<div class="kv"><b>证书类型：</b>' + esc(typeName(n.type) + kind) + '</div>' +
            '<div class="kv"><b>序列号：</b>' + esc(n.serial) + '</div>' +
            '<div class="kv"><b>DN：</b>' + esc(n.dn) + '</div>' +
            '<div class="kv"><b>密钥对：</b>' + esc(n.algo || '-') + ' / 哈希：' + esc(n.hash || '-') + ' / 长度：' + (n.bits ? n.bits + '位' : '-') + '</div>' +
            '<div class="kv"><b>OCSP 状态：</b>' + esc(n.ocsp) + '</div>' +
            '<div class="kv"><b>CRL 状态：</b>' + esc(n.crl) + '（登记状态 ' + stTxt + '）</div>';
        }
        function renderNode(n, isRoot, collapsed) {
          const kids = n.children || [];
          const hasKids = kids.length > 0;
          const kind = n.type === 'E' && n.kind ? '[' + n.kind + ']' : '';
          let h = '<div class="t-node t-node-' + n.type.toLowerCase() + (isRoot ? ' t-node-root' : '') + '">';
          h += '<div class="t-head">';
          if (hasKids) {
            h += '<span class="t-toggle" data-col="' + (collapsed ? '1' : '0') + '">' + (collapsed ? '▶' : '▼') + '</span>';
          }
          h += '<span class="t-box" data-tip="' + esc(tipHtml(n)) + '"><span class="t-badge ' + n.type + '">' + n.type + '</span>' +
            '<span class="t-kind">' + typeName(n.type) + kind + '</span>' + esc(n.dn || n.serial) +
            ' <span class="t-st ' + n.status + '">' + (n.status === 'V' ? '● 正常' : n.status === 'R' ? '● 已吊销' : '● 未知') + '</span></span>';
          h += '</div>';
          h += '</div>';
          if (hasKids) {
            h += '<div class="t-children' + (collapsed ? ' collapsed' : '') + '">';
            kids.forEach(k => { h += renderNode(k, false, k.type === 'C'); });
            h += '</div>';
          }
          return h;
        }
        async function loadChain() {
          const box = $('chainBox');
          box.textContent = '加载中...';
          try {
            const r = await api('/api/chain');
            if (!r.ok) { box.textContent = r.message || '加载失败'; return; }
            const roots = r.data;
            if (!roots.length) { box.innerHTML = '<span style="color:var(--dim)">（证书库为空，先签发根证书）</span>'; return; }
            let h = '<div class="t-row">';
            roots.forEach(root => { h += '<div>' + renderNode(root, true, false) + '</div>'; });
            h += '</div>';
            box.innerHTML = h;
          } catch (e) {
            box.textContent = '请求失败: ' + e;
          }
        }

        // 收起 / 展开（R 默认展开，C 默认收起，点箭头切换）
        document.addEventListener('click', function (e) {
          const tg = e.target.closest ? e.target.closest('.t-toggle') : null;
          if (!tg) return;
          const node = tg.closest('.t-node');
          if (!node) return;
          const kids = node.nextElementSibling;
          if (!kids || !kids.classList.contains('t-children')) return;
          const collapsed = tg.dataset.col === '1';
          if (collapsed) {
            kids.classList.remove('collapsed');
            tg.dataset.col = '0';
            tg.textContent = '▼';
          } else {
            kids.classList.add('collapsed');
            tg.dataset.col = '1';
            tg.textContent = '▶';
          }
        });

        // ===== 链树悬浮详情：fixed 浮层挂 body（不被滚动容器裁剪、不被顶栏遮挡、始终置顶） =====
        (function () {
          const tip = document.createElement('div');
          tip.id = 'tipFloat';
          document.body.appendChild(tip);
          document.addEventListener('mouseover', function (e) {
            const box = e.target.closest ? e.target.closest('.t-box') : null;
            if (box) {
              tip.innerHTML = box.dataset.tip || '';
              tip.style.display = 'block';
              return;
            }
            if (tip.style.display === 'block') {
              const rel = e.relatedTarget;
              if (!rel || !rel.closest || !rel.closest('.t-box')) tip.style.display = 'none';
            }
          });
          document.addEventListener('mousemove', function (e) {
            if (tip.style.display !== 'block') return;
            const pad = 14, gap = 8;
            const w = tip.offsetWidth, h = tip.offsetHeight;
            let x = e.clientX + gap;
            let y = e.clientY + gap;
            if (x + w > innerWidth - pad) x = e.clientX - w - gap;
            if (y + h > innerHeight - pad) y = e.clientY - h - gap;
            tip.style.left = Math.max(pad, x) + 'px';
            tip.style.top = Math.max(pad, y) + 'px';
          });
        })();

        // ===== 日志 =====
        async function loadLogs() {
          try {
            const n = v('logLines') || '200';
            const r = await api('/api/logs?lines=' + n);
            if (r.ok) $('logsOut').textContent = r.data;
          } catch (e) { /* ignore */ }
        }
        // 按最近 N 小时加载日志（0=全部）
        async function loadLogsHours(h) {
          try {
            const r = await api('/api/logs?hours=' + h);
            if (r.ok) $('logsOut').textContent = r.data;
          } catch (e) { /* ignore */ }
        }

        // ===== 密钥位数联动（RSA 可编辑下拉 / ECC·SM2 只读固定） =====
        const BITS_OPT = { RSA: [1024, 2048, 3072, 4096, 8192], ECC: [256, 384, 521], SM2: [256] };
        function algoChanged() {
          const algo = $('scAlgo').value;
          const opts = BITS_OPT[algo] || [];
          if (algo === 'RSA') {
            // 可编辑：input + datalist 下拉
            $('scBitsSel').style.display = 'none';
            $('scBits').style.display = '';
            $('scBitsList').innerHTML = opts.map(v => '<option value="' + v + '"></option>').join('');
            if (!opts.includes(parseInt($('scBits').value, 10))) { $('scBits').value = '2048'; }
          } else {
            // 只读：隐藏 input，显示固定选项 select
            $('scBits').style.display = 'none';
            $('scBitsSel').style.display = '';
            $('scBitsSel').innerHTML = opts.map(v => '<option>' + v + '</option>').join('');
            $('scBitsSel').value = String(opts[0]);
          }
        }
        // 取当前密钥位数实际值
        function bitsVal() {
          return $('scBits').style.display === 'none' ? $('scBitsSel').value : $('scBits').value;
        }

        // ===== 有效期选择器 =====
        // 前端 datetime-local: '2026-09-12T10:30:00' ↔ 后端格式 '2026/09/12-10:30:00'
        function toBackendFmt(v) {
          const i = v.indexOf('T');
          return (i > 0 ? v.substring(0, i) : v).replace(/-/g, '/') + (i > 0 ? '-' + v.substring(i + 1) : '');
        }
        function fromBackendFmt(v) {
          const i = v.indexOf('-', 10); // 日期部分 '2026/09/12' 占 10 位
          if (i < 0) return '';
          return v.substring(0, i).replace(/\\//g, '-') + 'T' + v.substring(i + 1);
        }
        function openValModal() {
          let s = '', e = '';
          const cur = ($('scDays').value || '').trim();
          if (cur && cur.length >= 5 && isNaN(parseInt(cur, 10))) {
            const parts = cur.split('T');
            if (parts.length === 2) { s = fromBackendFmt(parts[0]); e = fromBackendFmt(parts[1]); }
          }
          $('valStart').value = s;
          $('valEnd').value = e;
          $('valModal').style.display = 'flex';
        }
        function valOk() {
          const s = $('valStart').value, e = $('valEnd').value;
          if (s && e) { $('scDays').value = toBackendFmt(s) + 'T' + toBackendFmt(e); }
          else if (s) { $('scDays').value = toBackendFmt(s); }
          closeValModal();
        }
        function closeValModal() { $('valModal').style.display = 'none'; }

        // ===== KeyUsage 密钥用法选择器 =====
        // 位值对齐 Go 版 x509.KeyUsage：1=数字签名 2=不可否认 4=密钥加密 8=数据加密
        // 16=密钥协商 32=证书签名 64=CRL签名 128=仅加密 256=仅解密
        const KU_OPTS = [
          ['数字签名 Digital Signature', 1],
          ['不可否认 Non Repudiation', 2],
          ['密钥加密 Key Encipherment', 4],
          ['数据加密 Data Encipherment', 8],
          ['密钥协商 Key Agreement', 16],
          ['证书签名 Certificate Sign', 32],
          ['CRL签名 CRL Sign', 64],
          ['仅加密 Encipher Only', 128],
          ['仅解密 Decipher Only', 256]
        ];
        const KU_PRESETS = { '1': 1 | 2 | 4 | 8 | 16, '2': 1 | 2 | 32 | 64, '3': 128, '4': 256, '5': 1 | 2, '6': 8, '7': 4, '8': 16 };
        function renderKuOpts() {
          const b = $('kuBody');
          if (!b || b.childElementCount) return;
          b.innerHTML = KU_OPTS.map(o =>
            '<label class="eku-item"><input type="checkbox" value="' + o[1] + '"><span>' + o[0] + '</span><code>' + o[1] + '</code></label>'
          ).join('');
        }
        function kuSelChanged() {
          $('scKuCustom').style.display = $('scKu').value === 'custom' ? 'block' : 'none';
          if ($('scKu').value === 'custom' && !$('scKuCustom').value) {
            $('scKuCustom').value = '1';
          }
        }
        // 取当前 KeyUsage 实际数值（预设编号或自定义组合值；自定义加 C 前缀避免与编号冲突）
        function kuVal() {
          const s = $('scKu').value;
          return s === 'custom' ? 'C' + ($('scKuCustom').value || '1') : s;
        }
        function openKuModal() {
          renderKuOpts();
          const cur = parseInt(kuVal(), 10) || 0;
          document.querySelectorAll('#kuBody input[type=checkbox]').forEach(c => { c.checked = (cur & parseInt(c.value, 10)) !== 0; });
          $('kuModal').style.display = 'flex';
        }
        function kuOk() {
          let sum = 0;
          document.querySelectorAll('#kuBody input[type=checkbox]:checked').forEach(c => { sum += parseInt(c.value, 10); });
          if (sum === 0) { closeKuModal(); return; }
          // 命中预设编号则选中下拉，否则用自定义数值
          let preset = null;
          for (const k in KU_PRESETS) { if (KU_PRESETS[k] === sum) { preset = k; break; } }
          if (preset) {
            $('scKu').value = preset;
            $('scKuCustom').style.display = 'none';
          } else {
            $('scKu').value = 'custom';
            $('scKuCustom').value = String(sum);
            $('scKuCustom').style.display = 'block';
          }
          closeKuModal();
        }
        function closeKuModal() { $('kuModal').style.display = 'none'; }

        // ===== EKU 增强型密钥用法选择器 =====
        const EKU_OPTS = [
          ['服务器身份验证', '1.3.6.1.5.5.7.3.1'],
          ['客户端身份验证', '1.3.6.1.5.5.7.3.2'],
          ['代码签名', '1.3.6.1.5.5.7.3.3'],
          ['安全电子邮件', '1.3.6.1.5.5.7.3.4'],
          ['IP 安全终端系统', '1.3.6.1.5.5.7.3.5'],
          ['IP 安全隧道终止', '1.3.6.1.5.5.7.3.6'],
          ['IP 安全用户', '1.3.6.1.5.5.7.3.7'],
          ['时间戳', '1.3.6.1.5.5.7.3.8'],
          ['OCSP 签名', '1.3.6.1.5.5.7.3.9'],
          ['内核模式代码签名', '1.3.6.1.4.1.311.61.1.1'],
          ['Windows 硬件驱动程序验证', '1.3.6.1.4.1.311.10.3.5'],
          ['Windows 系统组件验证', '1.3.6.1.4.1.311.10.3.6'],
          ['OEM Windows 系统组件验证', '1.3.6.1.4.1.311.10.3.7'],
          ['内嵌 Windows 系统组件验证', '1.3.6.1.4.1.311.10.3.8'],
          ['域名系统(DNS)服务器信任', '1.3.6.1.4.1.311.64.1.1'],
          ['通用文档签名', '1.3.6.1.5.5.7.3.36'],
          ['已吊销列表签名者', '1.3.6.1.4.1.311.10.3.19'],
          ['KDC 身份验证', '1.3.6.1.5.2.3.5'],
          ['生存时间签名', '1.3.6.1.4.1.311.10.3.13'],
          ['私钥存档', '1.3.6.1.4.1.311.21.5'],
          ['合格的部属', '1.3.6.1.4.1.311.10.3.10'],
          ['密钥恢复', '1.3.6.1.4.1.311.10.3.11'],
          ['文档签名', '1.3.6.1.4.1.311.10.3.12'],
          ['Microsoft 时间戳', '1.3.6.1.4.1.311.10.3.2'],
          ['加密文件系统', '1.3.6.1.4.1.311.10.3.4'],
          ['密钥恢复代理', '1.3.6.1.4.1.311.21.6'],
          ['目录服务电子邮件复制', '1.3.6.1.4.1.311.21.19'],
          ['IP 安全 IKE 中级', '1.3.6.1.5.5.8.2.2'],
          ['文件恢复', '1.3.6.1.4.1.311.10.3.4.1'],
          ['根列表签名者', '1.3.6.1.4.1.311.10.3.9'],
          ['数字权利', '1.3.6.1.4.1.311.10.5.1'],
          ['CTL 用法', '1.3.6.1.4.1.311.20.1'],
          ['密钥数据包许可证', '1.3.6.1.4.1.311.10.6.1'],
          ['许可证服务器验证', '1.3.6.1.4.1.311.10.6.2'],
          ['智能卡登录', '1.3.6.1.4.1.311.20.2.2']
        ];
        function renderEkuOpts() {
          const b = $('ekuBody');
          if (!b || b.childElementCount) return;
          b.innerHTML = EKU_OPTS.map(o =>
            '<label class="eku-item"><input type="checkbox" value="' + o[1] + '"><span>' + o[0] + '</span><code>' + o[1] + '</code></label>'
          ).join('');
        }
        function openEkuModal() {
          renderEkuOpts();
          const cur = $('scEu').value.split(',').map(s => s.trim()).filter(Boolean);
          document.querySelectorAll('#ekuBody input[type=checkbox]').forEach(c => { c.checked = cur.includes(c.value); });
          $('ekuModal').style.display = 'flex';
        }
        function ekuOk() {
          const checked = [...document.querySelectorAll('#ekuBody input[type=checkbox]:checked')].map(c => c.value);
          // 保留输入框中未被勾选的旧值（编号 / 自定义 OID）；
          // 编号若对应 OID 已被勾选，或旧值本身就是重复 OID，则丢弃，避免重复
          const old = $('scEu').value.split(',').map(s => s.trim()).filter(s => {
            if (!s) return false;
            if (checked.includes(s)) return false;
            const oid = NUM_EKU[s];
            return !(oid && checked.includes(oid));
          });
          $('scEu').value = checked.concat(old).join(',');
          closeEkuModal();
        }
        // 编号 → OID（对齐 MakeCert builtinEku 0~11 与 EXT_OIDS 12~46）
        const NUM_EKU = {
          '0': '2.5.29.37.0', '1': '1.3.6.1.5.5.7.3.1', '2': '1.3.6.1.5.5.7.3.2',
          '3': '1.3.6.1.5.5.7.3.3', '4': '1.3.6.1.5.5.7.3.4', '5': '1.3.6.1.5.5.7.3.5',
          '6': '1.3.6.1.5.5.7.3.6', '7': '1.3.6.1.5.5.7.3.7', '8': '1.3.6.1.5.5.7.3.8',
          '9': '1.3.6.1.5.5.7.3.9', '10': '1.3.6.1.4.1.311.10.3.3', '11': '2.16.840.1.113730.4.1',
          '12': '1.3.6.1.4.1.311.2.1.22', '13': '1.3.6.1.4.1.311.61.1.1', '14': '1.3.6.1.4.1.311.10.3.5',
          '15': '1.3.6.1.4.1.311.10.3.6', '16': '1.3.6.1.4.1.311.10.3.7', '17': '1.3.6.1.4.1.311.10.3.8',
          '18': '1.3.6.1.4.1.311.64.1.1', '19': '1.3.6.1.4.1.311.47.1.1', '20': '1.3.6.1.4.1.311.10.3.19',
          '21': '1.3.6.1.5.2.3.5', '22': '1.3.6.1.4.1.311.10.3.13', '23': '1.3.6.1.4.1.311.21.5',
          '24': '1.3.6.1.4.1.311.10.3.10', '25': '1.3.6.1.4.1.311.10.3.11', '26': '1.3.6.1.4.1.311.10.3.12',
          '27': '1.3.6.1.4.1.311.10.3.2', '28': '1.3.6.1.4.1.311.10.3.4', '29': '1.3.6.1.4.1.311.21.6',
          '30': '1.3.6.1.4.1.311.21.19', '31': '1.3.6.1.5.5.8.2.2', '32': '1.3.6.1.4.1.311.10.3.4.1',
          '33': '1.3.6.1.4.1.311.10.3.9', '34': '1.3.6.1.4.1.311.10.5.1', '35': '1.3.6.1.4.1.311.20.1',
          '36': '1.3.6.1.4.1.311.10.6.1', '37': '1.3.6.1.4.1.311.10.6.2', '38': '1.3.6.1.4.1.311.20.2.1',
          '39': '1.3.6.1.4.1.311.20.2.2', '40': '1.3.6.1.4.1.311.21.30', '41': '1.3.6.1.4.1.311.21.31',
          '42': '1.3.6.1.4.1.311.21.32', '43': '1.2.840.113635.100.4.1', '44': '1.2.840.113635.100.4.1.1',
          '45': '1.2.840.113635.100.4.1.4', '46': '1.2.840.113635.100.4.2'
        };
        function closeEkuModal() { $('ekuModal').style.display = 'none'; }

        // ===== 系统配置 =====
        async function loadConfig() {
          try {
            const r = await api('/api/config');
            if (!r.ok) { $('cfgState').textContent = '读取失败: ' + (r.message || ''); return; }
            const d = r.data;
            $('cfgWebport').value = d.webport;
            $('cfgOcsp').value = d.ocsp;
            $('cfgCrl').value = d.crl;
            $('cfgCrt').value = d.crt;
            $('cfgCps').value = d.cps;
            $('cfgCpsNonice').value = d.cpsNonice;
            $('cfgState').textContent = r.exists
              ? '已加载 PKI/CONFIG.txt'
              : 'PKI/CONFIG.txt 不存在，保存时将按默认模板创建';
            $('cfgOut').hidden = true;
          } catch (e) {
            $('cfgState').textContent = '读取失败: ' + e;
          }
        }
        async function saveConfigBtn(btn) {
          const el = $('cfgOut');
          el.hidden = false; el.className = 'out'; el.textContent = '保存中...';
          btn.disabled = true;
          try {
            const r = await api('/api/config', {
              webport: $('cfgWebport').value.trim(),
              ocsp: $('cfgOcsp').value.trim(),
              crl: $('cfgCrl').value.trim(),
              crt: $('cfgCrt').value.trim(),
              cps: $('cfgCps').value.trim(),
              cpsNonice: $('cfgCpsNonice').value.trim()
            });
            showOut('cfgOut', r.message || 'OK', !!r.ok);
            if (r.ok) $('cfgState').textContent = '已保存 PKI/CONFIG.txt';
          } catch (e) {
            showOut('cfgOut', '请求失败: ' + e, false);
          } finally {
            btn.disabled = false;
          }
        }
        setInterval(() => {
          if ($('logAuto') && $('logAuto').checked && $('page-logs').classList.contains('active')) loadLogs();
          if ($('page-dashboard').classList.contains('active')) loadStatus();
        }, 3000);

        // ===== 启动 =====
        loadStatus();
        loadChain();
        loadIssuers();
        loadCerts();

        // 证书库「详情」按钮：事件委托，避免内联 onclick 引号转义问题
        $('certsTable').querySelector('tbody').addEventListener('click', function (ev) {
          const btn = ev.target.closest ? ev.target.closest('button[data-serial]') : null;
          if (btn) showDetail(btn.getAttribute('data-serial'));
        });
        </script>
        </body>
        </html>
        """;
}
