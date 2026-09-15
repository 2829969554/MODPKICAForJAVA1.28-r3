package modpkica;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

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

    /** 注册 BC Provider（独立运行时也必须可用 SM2/SM3 等算法）。 */
    static {
        Bc.init();
    }

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
                case "/api/restore":
                    runAction(ex, m -> Admin.doRestore(baseDir, str(m, "serial")));
                    return;
                case "/api/debug/ocsp":
                    runAction(ex, m -> debugOcsp(str(m, "serial"), str(m, "hash")));
                    return;
                case "/api/debug/tsa":
                    runAction(ex, m -> debugTsa(str(m, "hash")));
                    return;
                case "/api/rekey":
                    runAction(ex, m -> rekeyAction(str(m, "serial")));
                    return;
                case "/api/renew":
                    runAction(ex, m -> renewAction(str(m, "serial"),
                            str(m, "notBefore"), str(m, "notAfter")));
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
                case "/api/signcerts":
                    if ("GET".equalsIgnoreCase(method)) {
                        sendJson(ex, 200, signCertsJson(ex));
                    } else {
                        sendJson(ex, 405, Map.of("ok", false, "message", "仅支持 GET"));
                    }
                    return;
                case "/api/sign/exe":
                    signAction(ex, false);
                    return;
                case "/api/sign/pdf":
                    signAction(ex, true);
                    return;
                case "/api/verify/exe":
                    verifyAction(ex, false);
                    return;
                case "/api/verify/pdf":
                    verifyAction(ex, true);
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
    // 调试专区：模拟 OCSP / 时间戳请求（RFC 6960 / RFC 3161 标准构造与解析）
    // ============================================================

    /** 哈希名称 → 算法 OID。 */
    private static String hashOidOf(String name) {
        if (name == null) {
            return "2.16.840.1.101.3.4.2.1";
        }
        switch (name.toLowerCase()) {
            case "sha1":
                return "1.3.14.3.2.26";
            case "sha384":
                return "2.16.840.1.101.3.4.2.2";
            case "sha512":
                return "2.16.840.1.101.3.4.2.3";
            case "sm3":
                return Sm2Util.OID_SM3;
            case "sha256":
            default:
                return "2.16.840.1.101.3.4.2.1";
        }
    }

    /** 哈希名称 → JCA 摘要算法名。 */
    private static String jcaHashOf(String name) {
        if (name == null) {
            return "SHA-256";
        }
        switch (name.toLowerCase()) {
            case "sha1":
                return "SHA-1";
            case "sha384":
                return "SHA-384";
            case "sha512":
                return "SHA-512";
            case "sm3":
                return "SM3";
            default:
                return "SHA-256";
        }
    }

    /** 哈希名称 → 展示名。 */
    private static String hashLabel(String name) {
        return (name == null ? "sha256" : name).toUpperCase();
    }

    /** hex 编码。 */
    private static String hexOf(byte[] b) {
        if (b == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    /** POST DER 到本机 MAIN 端点（WEBPORT），返回响应字节。 */
    private static byte[] postMain(String path, String contentType, byte[] body) throws Exception {
        String port = readConfigWebPort();
        if (port == null || port.isEmpty() || "未配置".equals(port)) {
            port = "80";
        }
        URL url = new URL("http://127.0.0.1:" + port + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", contentType);
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
        int code = conn.getResponseCode();
        byte[] respBody;
        try (InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
            if (is == null) {
                respBody = new byte[0];
            } else {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0) {
                    bos.write(buf, 0, n);
                }
                respBody = bos.toByteArray();
            }
        }
        if (code >= 400) {
            String errText = new String(respBody, StandardCharsets.UTF_8).trim();
            if (errText.length() > 300) {
                errText = errText.substring(0, 300);
            }
            throw new IOException("MAIN 返回 HTTP " + code + (errText.isEmpty() ? "" : ": " + errText));
        }
        return respBody;
    }

    /** 模拟 OCSP 请求（RFC 6960）：标准 CertID + Nonce → POST /OCSP → 解析响应并验签。 */
    private static String debugOcsp(String serial, String hash) throws Exception {
        StringBuilder log = new StringBuilder();
        String hashName = (hash == null || hash.isEmpty()) ? "sha256" : hash.toLowerCase();
        String hashOid = hashOidOf(hashName);
        String jcaHash = jcaHashOf(hashName);

        // 1. 目标证书（未指定序列号时自动选第一个终端证书）
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry;
        if (serial != null && !serial.isEmpty()) {
            entry = db.findBySerial(serial.trim().toLowerCase());
        } else {
            entry = db.getAll().stream().filter(e -> e.type == 'E').findFirst().orElse(null);
        }
        if (entry == null) {
            return "未找到目标证书（序列号 " + serial + "），无法构造 OCSP 请求";
        }
        String issuerId = entry.issuerId;
        log.append("== 模拟 OCSP 请求（RFC 6960）==\n");
        log.append("[1] 目标证书\n");
        log.append("    序列号: ").append(entry.serial).append("  类型: ").append(entry.type)
                .append("  状态: ").append(entry.status).append("  颁发者: ").append(issuerId).append('\n');

        // 2. 加载颁发者证书（CertID 的 issuerNameHash/issuerKeyHash 基于真正颁发者）
        Path issuerPath = null;
        for (String p : new String[]{"PKI/ROOT/" + issuerId + ".crt", "PKI/CA/" + issuerId + ".crt"}) {
            if (Files.exists(Paths.get(baseDir, p))) {
                issuerPath = Paths.get(baseDir, p);
                break;
            }
        }
        if (issuerPath == null) {
            return "未找到颁发者证书: " + issuerId + "（ROOT/CA 目录均无）";
        }
        java.security.cert.X509Certificate issuerCert = PemIO.readCert(issuerPath.toString());

        // 3. 构造标准 OCSP 请求（RFC 6960 4.1.1：CertID + Nonce 扩展）
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashOid));
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC").build();
        DigestCalculator dc = dcp.get(algId);
        CertificateID cid = new CertificateID(dc,
                new JcaX509CertificateHolder(issuerCert),
                new java.math.BigInteger(entry.serial, 16));
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(cid);
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        gen.setRequestExtensions(new Extensions(new Extension(
                OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce))));
        OCSPReq ocspReq = gen.build();
        byte[] reqDer = ocspReq.getEncoded();

        log.append("[2] 构造请求\n");
        log.append("    CertID 哈希算法: ").append(hashLabel(hashName)).append(" (").append(hashOid).append(")\n");
        log.append("    issuerNameHash: ").append(hexOf(cid.getIssuerNameHash())).append('\n');
        log.append("    issuerKeyHash: ").append(hexOf(cid.getIssuerKeyHash())).append('\n');
        log.append("    Nonce: ").append(hexOf(nonce)).append('\n');
        log.append("    请求 DER 长度: ").append(reqDer.length).append(" 字节\n");

        // 4. POST 到本机 MAIN
        String port = readConfigWebPort();
        log.append("[3] POST http://127.0.0.1:").append(port).append("/OCSP\n");
        byte[] respDer;
        try {
            respDer = postMain("/OCSP", "application/ocsp-request", reqDer);
            log.append("    响应长度: ").append(respDer.length).append(" 字节\n");
        } catch (Exception e) {
            log.append("    请求失败: ").append(e).append('\n');
            log.append("    （请确认 MAIN 服务已启动且 WEBPORT 配置正确）\n");
            return log.toString();
        }

        // 5. 解析响应
        log.append("[4] 响应解析（RFC 6960 OCSPResp）\n");
        OCSPResp resp = new OCSPResp(respDer);
        int st = resp.getStatus();
        log.append("    responseStatus: ").append(ocspStatusName(st)).append('\n');
        if (st != 0) {
            log.append("    （非 successful，无 responseBytes）\n");
            return log.toString();
        }
        Object obj = resp.getResponseObject();
        if (!(obj instanceof BasicOCSPResp)) {
            log.append("    responseBytes 不是 BasicOCSPResp\n");
            return log.toString();
        }
        BasicOCSPResp basic = (BasicOCSPResp) obj;
        org.bouncycastle.asn1.ocsp.ResponderID rid =
                basic.getResponderId().toASN1Primitive();
        if (rid.getKeyHash() != null) {
            log.append("    responderID: byKey ").append(hexOf(rid.getKeyHash())).append('\n');
        } else if (rid.getName() != null) {
            log.append("    responderID: byName ").append(rid.getName()).append('\n');
        } else {
            log.append("    responderID: (空)\n");
        }
        log.append("    producedAt: ").append(basic.getProducedAt()).append('\n');
        SingleResp[] singles = basic.getResponses();
        for (int i = 0; i < singles.length; i++) {
            SingleResp sr = singles[i];
            log.append("    [单条响应 ").append(i + 1).append("]\n");
            log.append("       CertID 序列号: ")
                    .append(sr.getCertID().getSerialNumber().toString(16)).append('\n');
            Object cs = sr.getCertStatus();
            if (cs == CertificateStatus.GOOD) {
                log.append("       证书状态: good（正常）\n");
            } else if (cs instanceof RevokedStatus) {
                RevokedStatus rs = (RevokedStatus) cs;
                log.append("       证书状态: revoked（已吊销） 时间=").append(rs.getRevocationTime())
                        .append(" 原因=").append(rs.getRevocationReason()).append('\n');
            } else if (cs instanceof UnknownStatus) {
                log.append("       证书状态: unknown（未知）\n");
            }
            log.append("       thisUpdate: ").append(sr.getThisUpdate()).append('\n');
            if (sr.getNextUpdate() != null) {
                log.append("       nextUpdate: ").append(sr.getNextUpdate()).append('\n');
            }
        }
        // Nonce 回显比对
        Extension ne = basic.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ne != null) {
            byte[] echo = org.bouncycastle.asn1.ASN1OctetString.getInstance(
                    ne.getExtnValue()).getOctets();
            log.append("    Nonce 回显: ").append(hexOf(echo))
                    .append(java.util.Arrays.equals(echo, nonce)
                            ? "  （与请求一致）" : "  （与请求不一致！）").append('\n');
        } else {
            log.append("    Nonce 回显: 无\n");
        }

        // 6. 签名验证
        log.append("[5] 签名验证\n");
        X509CertificateHolder[] certs = basic.getCerts();
        if (certs == null || certs.length == 0) {
            log.append("    响应未携带响应者证书（byName 时客户端可从受信库加载）\n");
        } else {
            java.security.cert.X509Certificate responder =
                    new JcaX509CertificateConverter().setProvider("BC")
                            .getCertificate(certs[0]);
            log.append("    响应者证书: ").append(responder.getSubjectX500Principal())
                    .append("（序列号 ").append(responder.getSerialNumber().toString(16)).append("）\n");
            ContentVerifierProvider cvp = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(responder);
            boolean ok = basic.isSignatureValid(cvp);
            log.append("    签名验证: ").append(ok ? "通过" : "失败").append('\n');
        }
        return log.toString();
    }

    /** 模拟时间戳请求（RFC 3161）：随机消息 → messageImprint → POST /rfc3161 → 解析响应并验签。 */
    private static String debugTsa(String hash) throws Exception {
        StringBuilder log = new StringBuilder();
        String hashName = (hash == null || hash.isEmpty()) ? "sha256" : hash.toLowerCase();
        String hashOid = hashOidOf(hashName);
        String jcaHash = jcaHashOf(hashName);

        log.append("== 模拟时间戳请求（RFC 3161）==\n");
        // 1. 随机数据 + 摘要
        byte[] msg = new byte[32];
        new SecureRandom().nextBytes(msg);
        byte[] digest = MessageDigest.getInstance(jcaHash).digest(msg);
        log.append("[1] 随机数据\n");
        log.append("    数据内容: ").append(hexOf(msg)).append('\n');
        log.append("    摘要算法: ").append(hashLabel(hashName)).append(" (").append(hashOid).append(")\n");
        log.append("    消息摘要: ").append(hexOf(digest)).append('\n');

        // 2. 构造 RFC 3161 请求（messageImprint + nonce + certReq=true）
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        gen.setCertReq(true);
        TimeStampRequest tsReq = gen.generate(
                new ASN1ObjectIdentifier(hashOid), digest,
                new java.math.BigInteger(1, nonce));
        byte[] reqDer = tsReq.getEncoded();
        log.append("[2] 构造请求\n");
        log.append("    version: ").append(tsReq.getVersion()).append('\n');
        log.append("    messageImprint: {alg=")
                .append(tsReq.getMessageImprintAlgID().getAlgorithm().getId())
                .append(", digest=").append(hexOf(tsReq.getMessageImprintDigest())).append("}\n");
        log.append("    nonce: ").append(hexOf(nonce)).append('\n');
        log.append("    certReq: true\n");
        log.append("    请求 DER 长度: ").append(reqDer.length).append(" 字节\n");

        // 3. POST 到本机 MAIN
        String port = readConfigWebPort();
        log.append("[3] POST http://127.0.0.1:").append(port).append("/rfc3161\n");
        byte[] respDer;
        try {
            respDer = postMain("/rfc3161", "application/timestamp-query", reqDer);
            log.append("    响应长度: ").append(respDer.length).append(" 字节\n");
        } catch (Exception e) {
            log.append("    请求失败: ").append(e).append('\n');
            log.append("    （请确认 MAIN 服务已启动、WEBPORT 配置正确，且存在对应的 TSA 证书：")
                    .append("SHA1→rsa_sha1/ecc_sha1，SHA256→rsa_sha256/ecc_sha256，SM3→sm2_sm3）\n");
            return log.toString();
        }

        // 4. 解析响应
        log.append("[4] 响应解析（RFC 3161 TimeStampResp）\n");
        TimeStampResponse resp = new TimeStampResponse(respDer);
        int st = resp.getStatus();
        log.append("    status: ").append(tsStatusName(st)).append('\n');
        String statusStr = resp.getStatusString();
        if (statusStr != null && !statusStr.isEmpty()) {
            log.append("    statusString: ").append(statusStr).append('\n');
        }
        if (st != 0) {
            log.append("    （非 granted，无 TimeStampToken）\n");
            return log.toString();
        }
        TimeStampToken token = resp.getTimeStampToken();
        if (token == null) {
            log.append("    （未返回 TimeStampToken）\n");
            return log.toString();
        }
        TimeStampTokenInfo info = token.getTimeStampInfo();
        log.append("    [TimeStampToken]\n");
        log.append("       serialNumber: ").append(info.getSerialNumber().toString(16)).append('\n');
        log.append("       genTime: ").append(info.getGenTime()).append('\n');
        if (info.getPolicy() != null) {
            log.append("       policy: ").append(info.getPolicy().getId()).append('\n');
        }
        byte[] echoDigest = info.getMessageImprintDigest();
        log.append("       messageImprint 回显: ").append(hexOf(echoDigest))
                .append(java.util.Arrays.equals(echoDigest, digest)
                        ? "  （与请求一致）" : "  （与请求不一致！）").append('\n');

        // 5. 签名验证（RFC 3161 5.3.2）
        log.append("[5] 签名验证\n");
        java.util.Collection<X509CertificateHolder> certs =
                token.getCertificates().getMatches(null);
        if (certs == null || certs.isEmpty()) {
            log.append("    token 未携带证书链\n");
        } else {
            boolean anyOk = false;
            for (X509CertificateHolder h : certs) {
                java.security.cert.X509Certificate c =
                        new JcaX509CertificateConverter().setProvider("BC").getCertificate(h);
                try {
                    org.bouncycastle.cms.SignerInformationVerifier siv =
                            new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
                                    .setProvider("BC").build(c);
                    token.validate(siv); // 校验 messageImprint 匹配 + 数字签名（失败抛异常）
                    log.append("    签名者证书: ").append(c.getSubjectX500Principal())
                            .append("（序列号 ").append(c.getSerialNumber().toString(16)).append("）\n");
                    anyOk = true;
                    break;
                } catch (Exception ignore) {
                    // 链中非签名者证书不匹配 ESSCertID，跳过继续尝试
                }
            }
            log.append("    签名验证: ").append(anyOk
                    ? "通过（messageImprint 匹配、数字签名有效）"
                    : "失败（无匹配签名者证书）").append('\n');
        }
        return log.toString();
    }

    private static String ocspStatusName(int st) {
        switch (st) {
            case 0: return "successful (0)";
            case 1: return "malformedRequest (1)";
            case 2: return "internalError (2)";
            case 3: return "tryLater (3)";
            case 5: return "sigRequired (5)";
            case 6: return "unauthorized (6)";
            default: return "未知 (" + st + ")";
        }
    }

    private static String tsStatusName(int st) {
        switch (st) {
            case 0: return "granted (0)";
            case 1: return "grantedWithMods (1)";
            case 2: return "rejection (2)";
            case 3: return "waiting (3)";
            case 4: return "revocationWarning (4)";
            case 5: return "revocationNotification (5)";
            default: return "未知 (" + st + ")";
        }
    }

    // ============================================================
    // 密钥更换（证书库「操作」按钮 → 密钥更换分组）
    // ============================================================

    /**
     * 密钥更换：按当前证书序列号识别公钥类型 → 生成同类型新密钥对 →
     * 随机数据测试（加解密 / 数字签名 / 签名验证）→ 加载颁发者 CA 证书与私钥 →
     * 对替换公钥后的 JSON 重建 TBS 并用 CA 私钥重签 → 新证书与私钥写回原位置替换。
     */
    private static String rekeyAction(String serial) throws Exception {
        if (serial == null || serial.trim().isEmpty()) {
            throw new IllegalArgumentException("缺少证书序列号");
        }
        serial = serial.trim().toLowerCase();

        // 1) 登记表
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry = db.findBySerial(serial);
        if (entry == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到序列号 " + serial);
        }

        // 2) 读原证书（WebPublic/CRT 是全部证书的统一对外目录）
        String certPath = baseDir + "/PKI/WebPublic/CRT/" + serial + ".crt";
        if (!Files.exists(Paths.get(certPath))) {
            throw new IllegalArgumentException("缺少证书文件: " + certPath);
        }
        byte[] pemBytes = Files.readAllBytes(Paths.get(certPath));
        String json = X509JsonConverter.certToJson(pemBytes);

        // 3) 识别公钥算法 → 生成同类型新密钥对
        KeyPair kp = X509JsonConverter.generateKeyPairFromJson(json);
        String keyType = X509JsonConverter.keyTypeFromJson(json);

        // 4) 随机数据密钥测试
        String tests = testKeyPair(kp, keyType);

        // 5) 加载颁发者 CA 证书与私钥（R→ROOT，C→CA）
        if (entry.issuerId == null || entry.issuerId.isEmpty()) {
            throw new IllegalArgumentException("登记表缺少颁发者序列号（" + serial + "）");
        }
        CertsDB.CertEntry issuer = db.findBySerial(entry.issuerId);
        if (issuer == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到颁发者 " + entry.issuerId);
        }
        String issuerDir = issuer.type == 'R' ? "ROOT" : (issuer.type == 'C' ? "CA" : null);
        if (issuerDir == null) {
            throw new IllegalArgumentException("颁发者类型必须为 R(根) 或 C(CA)，实际为 " + issuer.type);
        }
        String issuerKeyPath = baseDir + "/PKI/" + issuerDir + "/" + entry.issuerId + ".key";
        if (!Files.exists(Paths.get(issuerKeyPath))) {
            throw new IllegalArgumentException("缺少颁发者私钥: " + issuerKeyPath);
        }
        PrivateKey issuerKey = CertUtil.readJcaPrivateKey(issuerKeyPath);
        String issuerKeyType = PemIO.detectKeyType(issuerKeyPath);

        // 6) CA 重签：换公钥 → 重建 TBS → 颁发者私钥签名 → 新证书 PEM
        byte[] newCertPem = X509JsonConverter.rekeyJsonToPemByIssuer(
                json, kp, issuerKey, issuerKeyType);

        // 7) 写回原位置（按证书身份定位 OCSP / TSA / 登记类型目录），替换旧文件
        String saved = saveRekeyFiles(serial, entry, newCertPem, kp, keyType);

        String msg = "密钥更换完成\n"
                + "证书算法: " + keyType + "（已按原算法生成同类型新密钥对）\n"
                + "密钥测试结果:\n" + tests
                + "重签算法: " + issuerKeyType + "（颁发者 " + entry.issuerId + " 签名）\n"
                + saved;
        MLog.append(baseDir, "WebAdmin /api/rekey 详细",
                "密钥更换 序列号=" + serial + " 新密钥=" + keyType
                        + " 颁发者=" + entry.issuerId,
                msg.replace("\n", " | "));
        return msg;
    }

    /**
     * 续签证书：按当前证书序列号读取证书 → 更新 validity 的生效/失效时间 →
     * 加载颁发者 CA 证书与私钥 → 对 JSON 重建 TBS 并用 CA 私钥重签 →
     * 新证书写回原位置（公钥与扩展保持不变，仅时间更新）。
     */
    private static String renewAction(String serial, String notBeforeStr, String notAfterStr) throws Exception {
        if (serial == null || serial.trim().isEmpty()) {
            throw new IllegalArgumentException("缺少证书序列号");
        }
        serial = serial.trim().toLowerCase();
        Date notBefore = parseLocalDateTime(notBeforeStr);
        Date notAfter = parseLocalDateTime(notAfterStr);
        if (!notAfter.after(notBefore)) {
            throw new IllegalArgumentException("失效时间必须晚于生效时间");
        }

        // 1) 登记表
        CertsDB db = new CertsDB();
        db.load(baseDir);
        CertsDB.CertEntry entry = db.findBySerial(serial);
        if (entry == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到序列号 " + serial);
        }

        // 2) 读原证书（WebPublic/CRT 是全部证书的统一对外目录）
        String certPath = baseDir + "/PKI/WebPublic/CRT/" + serial + ".crt";
        if (!Files.exists(Paths.get(certPath))) {
            throw new IllegalArgumentException("缺少证书文件: " + certPath);
        }
        byte[] pemBytes = Files.readAllBytes(Paths.get(certPath));
        String json = X509JsonConverter.certToJson(pemBytes);

        // 3) 加载颁发者 CA 证书与私钥（R→ROOT，C→CA）
        if (entry.issuerId == null || entry.issuerId.isEmpty()) {
            throw new IllegalArgumentException("登记表缺少颁发者序列号（" + serial + "）");
        }
        CertsDB.CertEntry issuer = db.findBySerial(entry.issuerId);
        if (issuer == null) {
            throw new IllegalArgumentException("CERTS.txt 中未找到颁发者 " + entry.issuerId);
        }
        String issuerDir = issuer.type == 'R' ? "ROOT" : (issuer.type == 'C' ? "CA" : null);
        if (issuerDir == null) {
            throw new IllegalArgumentException("颁发者类型必须为 R(根) 或 C(CA)，实际为 " + issuer.type);
        }
        String issuerKeyPath = baseDir + "/PKI/" + issuerDir + "/" + entry.issuerId + ".key";
        if (!Files.exists(Paths.get(issuerKeyPath))) {
            throw new IllegalArgumentException("缺少颁发者私钥: " + issuerKeyPath);
        }
        PrivateKey issuerKey = CertUtil.readJcaPrivateKey(issuerKeyPath);
        String issuerKeyType = PemIO.detectKeyType(issuerKeyPath);

        // 4) CA 重签：更新有效期 → 重建 TBS → 颁发者私钥签名 → 新证书 PEM
        byte[] newCertPem = X509JsonConverter.renewJsonToPemByIssuer(
                json, notBefore, notAfter, issuerKey, issuerKeyType);

        // 5) 写回原位置（按证书身份定位 OCSP / TSA / 登记类型目录），替换旧文件
        String saved = saveRekeyFiles(serial, entry, newCertPem, null, null);

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        String msg = "续签完成\n"
                + "新生效时间: " + sdf.format(notBefore) + " UTC\n"
                + "新失效时间: " + sdf.format(notAfter) + " UTC\n"
                + "重签算法: " + issuerKeyType + "（颁发者 " + entry.issuerId + " 签名）\n"
                + "公钥与扩展保持不变，仅更新时间\n"
                + saved;
        MLog.append(baseDir, "WebAdmin /api/renew 详细",
                "续签 序列号=" + serial + " 生效=" + notBeforeStr + " 失效=" + notAfterStr,
                msg.replace("\n", " | "));
        return msg;
    }

    /** 解析前端 datetime-local 的本地时间（yyyy-MM-ddTHH:mm[:ss]），转 UTC Date。 */
    private static Date parseLocalDateTime(String s) throws Exception {
        if (s == null || s.trim().isEmpty()) {
            throw new IllegalArgumentException("缺少时间");
        }
        String v = s.trim().replace(' ', 'T');
        if (v.endsWith("Z")) {
            v = v.substring(0, v.length() - 1); // 兼容 UTC 后缀
        }
        LocalDateTime ldt = LocalDateTime.parse(
                v.length() == 16 ? v + ":00" : v,
                DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        return Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
    }

    /** 随机数据密钥对测试：RSA（加解密+签名验签）/ ECC（签名验签）/ SM2（SM2加解密+签名验签）。 */    private static String testKeyPair(KeyPair kp, String keyType) throws Exception {
        StringBuilder sb = new StringBuilder();
        byte[] data = new byte[64];
        new SecureRandom().nextBytes(data);
        if ("RSA".equalsIgnoreCase(keyType)) {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            c.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] enc = c.doFinal(data);
            c.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] dec = c.doFinal(enc);
            sb.append("    RSA 加解密     : ")
                    .append(Arrays.equals(data, dec) ? "通过 ✓" : "失败 ✗")
                    .append("（64 字节随机数据）\n");
            sb.append("    RSA 签名/验签  : ")
                    .append(signAndVerify(kp, "SHA256withRSA", data) ? "通过 ✓" : "失败 ✗")
                    .append("（SHA256）\n");
        } else if ("ECC".equalsIgnoreCase(keyType)) {
            sb.append("    ECC 签名/验签  : ")
                    .append(signAndVerify(kp, "SHA256withECDSA", data) ? "通过 ✓" : "失败 ✗")
                    .append("（SHA256；ECC 为签名算法，无传统公钥加解密）\n");
        } else if ("SM2".equalsIgnoreCase(keyType)) {
            ECPublicKeyParameters pub = Sm2Util.toEcPublicParams(kp.getPublic());
            ECPrivateKeyParameters priv = Sm2Util.toEcPrivateParams(kp.getPrivate());
            SM2Engine eng = new SM2Engine(SM2Engine.Mode.C1C3C2);
            eng.init(true, new ParametersWithRandom(pub, new SecureRandom()));
            byte[] enc = eng.processBlock(data, 0, data.length);
            SM2Engine dEng = new SM2Engine(SM2Engine.Mode.C1C3C2);
            dEng.init(false, priv);
            byte[] dec = dEng.processBlock(enc, 0, enc.length);
            sb.append("    SM2 加解密     : ")
                    .append(Arrays.equals(data, dec) ? "通过 ✓" : "失败 ✗")
                    .append("（64 字节随机数据，C1C3C2）\n");
            byte[] sig = Sm2Util.sm2Sign(priv, data);
            sb.append("    SM2 签名/验签  : ")
                    .append(Sm2Util.sm2Verify(pub, data, sig) ? "通过 ✓" : "失败 ✗")
                    .append("（SM3withSM2，含 ZA）\n");
        } else {
            throw new IllegalArgumentException("不支持的密钥类型: " + keyType);
        }
        return sb.toString();
    }

    /** 用 JCA Signature 对随机数据做签名并验证。 */
    private static boolean signAndVerify(KeyPair kp, String jcaAlg, byte[] data) throws Exception {
        Signature s = Signature.getInstance(jcaAlg, "BC");
        s.initSign(kp.getPrivate());
        s.update(data);
        byte[] sig = s.sign();
        Signature v = Signature.getInstance(jcaAlg, "BC");
        v.initVerify(kp.getPublic());
        v.update(data);
        return v.verify(sig);
    }

    /**
     * 按证书身份定位保存位置并替换旧文件：
     * OCSP 证书（OCSP/{颁发者ID}_ocsp.crt 序列号匹配）→ OCSP 目录；
     * TSA 证书（TIMSTAMP 目录内证书序列号匹配）→ TIMSTAMP 目录；
     * 否则按登记类型 R→ROOT、C→CA、E→CERT/KEY。始终同步 WebPublic/CRT。
     */
    private static String saveRekeyFiles(String serial, CertsDB.CertEntry entry,
                                         byte[] certPem, KeyPair kp, String keyType) throws Exception {
        StringBuilder sb = new StringBuilder();
        Path base = Paths.get(baseDir, "PKI");
        String syncDir = "PKI/WebPublic/CRT/" + serial + ".crt";

        // 1) 统一对外目录（所有证书类型）
        Files.write(Paths.get(baseDir, "PKI", "WebPublic", "CRT", serial + ".crt"), certPem);
        sb.append("证书已同步: ").append(syncDir).append("\n");

        // 2) 定位主位置
        Path certOut = null;
        Path keyOut = null;
        String kind = null;

        // 2a) OCSP 签名证书：OCSP/{颁发者ID}_ocsp.crt 的序列号 == 目标序列号
        Path ocspCert = Paths.get(base.toString(), "OCSP", entry.issuerId + "_ocsp.crt");
        if (Files.exists(ocspCert) && certSerialOf(ocspCert).equals(serial)) {
            certOut = ocspCert;
            keyOut = Paths.get(base.toString(), "OCSP", entry.issuerId + "_ocsp.key");
            kind = "OCSP 签名证书";
        }

        // 2b) TSA 时间戳证书：TIMSTAMP 目录内证书序列号匹配
        if (certOut == null) {
            Path tsDir = Paths.get(base.toString(), "TIMSTAMP");
            if (Files.isDirectory(tsDir)) {
                try (Stream<Path> stream = Files.list(tsDir)) {
                    List<Path> crts = stream.filter(p -> p.toString().toLowerCase().endsWith(".crt"))
                            .collect(Collectors.toList());
                    for (Path p : crts) {
                        if (certSerialOf(p).equals(serial)) {
                            certOut = p;
                            keyOut = Paths.get(p.toString().replace(".crt", ".key"));
                            kind = "TSA 时间戳证书";
                            break;
                        }
                    }
                }
            }
        }

        // 2c) 按登记类型
        if (certOut == null) {
            switch (entry.type) {
                case 'R':
                    certOut = Paths.get(base.toString(), "ROOT", serial + ".crt");
                    keyOut = Paths.get(base.toString(), "ROOT", serial + ".key");
                    kind = "根证书(R)";
                    break;
                case 'C':
                    certOut = Paths.get(base.toString(), "CA", serial + ".crt");
                    keyOut = Paths.get(base.toString(), "CA", serial + ".key");
                    kind = "CA证书(C)";
                    break;
                case 'E':
                    certOut = Paths.get(base.toString(), "CERT", serial + ".crt");
                    keyOut = Paths.get(base.toString(), "KEY", serial + ".key");
                    kind = "终端证书(E)";
                    break;
                default:
                    throw new IllegalArgumentException("不支持的证书类型: " + entry.type);
            }
        }

        // 3) 写证书 + 私钥（续签场景 kp 为 null，仅更新证书、私钥保持不变）
        Files.write(certOut, certPem);
        sb.append("证书类型: ").append(kind).append("\n");
        sb.append("证书已替换: ").append(relPath(certOut)).append("\n");
        if (kp != null && keyType != null) {
            PemIO.writePrivateKey(keyOut.toString(), kp.getPrivate(), keyType);
            sb.append("私钥已替换: ").append(relPath(keyOut)).append("\n");
        } else {
            sb.append("私钥保持不变（续签不更换密钥）\n");
        }
        return sb.toString();
    }

    /** 读取证书文件的序列号（hex 小写）。 */
    private static String certSerialOf(Path certPath) throws Exception {
        return PemIO.readCert(certPath.toString()).getSerialNumber()
                .toString(16).toLowerCase();
    }

    /** 相对 baseDir 的路径显示。 */
    private static String relPath(Path p) {
        String abs = p.toString().replace('\\', '/');
        String b = baseDir.replace('\\', '/') + "/";
        return abs.startsWith(b) ? abs.substring(b.length()) : abs;
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

    // ============================================================
    // 签名专区：微软代码签名 / PDF 文档签名（multipart 上传 → SignTool）
    // ============================================================

    /** 解析 multipart/form-data 请求体，返回 字段名 → 字节。 */
    private static Map<String, byte[]> readMultipart(HttpExchange ex) throws Exception {
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        if (ct == null || !ct.startsWith("multipart/form-data")) {
            throw new IllegalArgumentException("需要 multipart/form-data 上传");
        }
        String boundary = null;
        for (String part : ct.split(";")) {
            String t = part.trim();
            if (t.startsWith("boundary=")) {
                boundary = t.substring("boundary=".length()).replace("\"", "").trim();
            }
        }
        if (boundary == null || boundary.isEmpty()) {
            throw new IllegalArgumentException("缺少 multipart boundary");
        }
        byte[] body = readAll(ex.getRequestBody());
        byte[] delim = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        Map<String, byte[]> fields = new LinkedHashMap<>();
        int pos = 0;
        while (true) {
            int start = indexOfBytes(body, delim, pos);
            if (start < 0) {
                break;
            }
            int after = start + delim.length;
            // 结束标记 "--"
            if (after + 1 < body.length && body[after] == '-' && body[after + 1] == '-') {
                break;
            }
            if (after < body.length && body[after] == '\r') {
                after++;
            }
            if (after < body.length && body[after] == '\n') {
                after++;
            }
            // part 头（到空行 \r\n\r\n 或 \n\n）
            int headerEnd = indexOfBytes(body, new byte[]{'\r', '\n', '\r', '\n'}, after);
            int lf = indexOfBytes(body, new byte[]{'\n', '\n'}, after);
            int dataStart;
            if (headerEnd >= 0 && (lf < 0 || headerEnd <= lf)) {
                dataStart = headerEnd + 4;
            } else if (lf >= 0) {
                headerEnd = lf;
                dataStart = lf + 2;
            } else {
                break;
            }
            String headers = new String(body, after, headerEnd - after,
                    StandardCharsets.ISO_8859_1);
            String name = null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("name=\"([^\"]*)\"").matcher(headers);
            if (m.find()) {
                name = m.group(1);
            }
            // 数据区到下一个 boundary
            int next = indexOfBytes(body, delim, dataStart);
            if (next < 0) {
                break;
            }
            int dataEnd = next;
            if (dataEnd >= 2 && body[dataEnd - 2] == '\r' && body[dataEnd - 1] == '\n') {
                dataEnd -= 2;
            } else if (dataEnd >= 1 && body[dataEnd - 1] == '\n') {
                dataEnd -= 1;
            }
            if (name != null) {
                fields.put(name, Arrays.copyOfRange(body, dataStart, dataEnd));
            }
            pos = next;
        }
        return fields;
    }

    /** 字节数组查找。 */
    private static int indexOfBytes(byte[] hay, byte[] needle, int from) {
        outer:
        for (int i = from; i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** 签名动作（pdf=true 时走 PDF 签名，否则 EXE Authenticode 签名）。 */
    private static void signAction(HttpExchange ex, boolean pdf) {
        String path = ex.getRequestURI().getPath();
        try {
            Map<String, byte[]> f = readMultipart(ex);
            String serial = new String(f.getOrDefault("serial", new byte[0]),
                    StandardCharsets.UTF_8).trim();
            byte[] fileBytes = f.get("file");
            String fileName = f.containsKey("name")
                    ? new String(f.get("name"), StandardCharsets.UTF_8).trim() : "";
            if (fileBytes == null || fileBytes.length == 0) {
                throw new IllegalArgumentException("未上传文件");
            }
            if (serial.isEmpty()) {
                throw new IllegalArgumentException("未选择签名证书序列号");
            }
            String base = AppPaths.baseDir();
            CertsDB db = new CertsDB();
            db.load(base);
            CertsDB.CertEntry e = db.findBySerial(serial);
            if (e == null) {
                throw new IllegalArgumentException("CERTS.txt 无序列号 " + serial);
            }
            String keyType = e.algo;
            java.security.cert.X509Certificate cert = SignTool.loadCertBySerial(base, serial);
            PrivateKey key = SignTool.loadKeyBySerial(base, serial);
            List<java.security.cert.X509Certificate> chain = SignTool.loadChain(base, serial);

            byte[] result;
            String op;
            if (pdf) {
                byte[] image = f.get("image");
                String sealType = new String(f.getOrDefault("sealType", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                if (sealType.isEmpty()) {
                    sealType = "ADOBE";
                }
                String tsUrl = new String(f.getOrDefault("tsUrl", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                result = SignTool.signPdf(fileBytes, keyType, cert, key, chain, image,
                        sealType, tsUrl);
                String sealLabel = "ADOBE".equalsIgnoreCase(sealType) ? "Adobe 标准文档签名"
                        : "GM38540".equalsIgnoreCase(sealType) ? "国密 GB/T 38540-2020"
                        : "GM0031".equalsIgnoreCase(sealType) ? "国密 GM/T 0031-2025"
                        : "国密 GB/T 35275-2017";
                op = "PDF 文档签名\n"
                        + "  签章类型: " + sealLabel + "\n"
                        + "  签章: " + (image != null && image.length > 0
                        ? "已附加可见签章（" + image.length + "B 图片）" : "无（不可见签名）") + "\n"
                        + "  时间戳地址: " + (tsUrl.isEmpty() ? "（本机 MAIN /rfc3161 默认）" : tsUrl);
            } else {
                if (fileName.isEmpty()) {
                    fileName = "file.bin";
                }
                String tsType = new String(f.getOrDefault("tsType", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                if (tsType.isEmpty()) {
                    tsType = "RFC3161";
                }
                String tsUrl = new String(f.getOrDefault("tsUrl", new byte[0]),
                        StandardCharsets.UTF_8).trim();
                SignTool.lastTsInfo = "未请求";
                result = SignTool.signExe(fileBytes, keyType, cert, key, chain, base,
                        tsType, tsUrl);
                op = "微软代码签名（Authenticode）\n"
                        + "  时间戳类型: " + tsType + "\n"
                        + "  时间戳地址: " + (tsUrl.isEmpty() ? "（本机 MAIN 默认）" : tsUrl) + "\n"
                        + "  时间戳: " + SignTool.lastTsInfo;
            }
            String out = op + "\n"
                    + "  输入: " + fileName + "（" + fileBytes.length + " 字节）\n"
                    + "  证书: " + cert.getSubjectX500Principal() + "\n"
                    + "  序列号: " + serial + "   算法: " + keyType
                    + "   摘要: " + SignTool.digestName(keyType) + "\n"
                    + "  输出: " + result.length + " 字节";
            MLog.append(base, "WebAdmin " + path,
                    "POST " + path + " serial=" + serial + " file=" + fileName
                            + " size=" + fileBytes.length,
                    out);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("ok", true);
            r.put("message", out);
            r.put("b64", Base64.getEncoder().encodeToString(result));
            r.put("name", (pdf ? "signed_" : "signed_") + fileName);
            sendJson(ex, 200, r);
        } catch (Exception ex2) {
            try {
                MLog.appendErr(AppPaths.baseDir(), "WebAdmin " + path + " 异常",
                        "POST " + path, String.valueOf(ex2));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(ex2)));
            } catch (Exception ignored) {
            }
        }
    }

    /** 验证动作（pdf=true 走 PDF 验证，否则 EXE Authenticode 验证）。 */
    private static void verifyAction(HttpExchange ex, boolean pdf) {
        String path = ex.getRequestURI().getPath();
        try {
            Map<String, byte[]> f = readMultipart(ex);
            byte[] fileBytes = f.get("file");
            if (fileBytes == null || fileBytes.length == 0) {
                throw new IllegalArgumentException("未上传文件");
            }
            String out = pdf ? SignTool.verifyPdf(fileBytes) : SignTool.verifyExe(fileBytes);
            MLog.append(AppPaths.baseDir(), "WebAdmin " + path,
                    "POST " + path + " size=" + fileBytes.length, out);
            sendJson(ex, 200, Map.of("ok", true, "message", out));
        } catch (Exception ex2) {
            try {
                MLog.appendErr(AppPaths.baseDir(), "WebAdmin " + path + " 异常",
                        "POST " + path, String.valueOf(ex2));
                sendJson(ex, 500, Map.of("ok", false, "message", String.valueOf(ex2)));
            } catch (Exception ignored) {
            }
        }
    }

    /** 可签名证书列表：kind=exe 筛代码签名 EKU；kind=pdf 筛文档签名/代码签名 EKU。 */
    private static Map<String, Object> signCertsJson(HttpExchange ex) {
        String kind = ex.getRequestURI().getQuery() == null ? "exe"
                : (ex.getRequestURI().getQuery().contains("kind=pdf") ? "pdf" : "exe");
        String base = AppPaths.baseDir();
        CertsDB db = new CertsDB();
        db.load(base);
        List<Map<String, Object>> list = new ArrayList<>();
        for (CertsDB.CertEntry e : db.getAll()) {
            if (e.type != 'E') {
                continue;
            }
            try {
                java.security.cert.X509Certificate c = SignTool.loadCertBySerial(base, e.serial);
                boolean usable = "pdf".equals(kind)
                        ? SignTool.isDocSignCert(c) : SignTool.isCodeSignCert(c);
                if (!usable) {
                    continue;
                }
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("serial", e.serial);
                m.put("dn", c.getSubjectX500Principal().toString());
                m.put("issuer", c.getIssuerX500Principal().toString());
                m.put("algo", e.algo);
                m.put("bits", SignTool.keyBits(c));
                m.put("validFrom", c.getNotBefore().toString());
                m.put("validTo", c.getNotAfter().toString());
                m.put("status", String.valueOf(e.status));
                m.put("ekus", new ArrayList<>(SignTool.ekusOf(c)));
                list.add(m);
            } catch (Exception ignored) {
                // 证书文件缺失或损坏则跳过
            }
        }
        return Map.of("ok", true, "data", list);
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

    private static final String PAGE_P1 = """
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
          button.success { background: #14532d; color: #bbf7d0; }
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
          /* ===== 证书操作弹窗（吊销/续签/密钥更换） ===== */
          .op-tabs { display: flex; gap: 4px; margin-bottom: 14px; border-bottom: 1px solid var(--border); }
          .op-tab { padding: 8px 18px; cursor: pointer; color: var(--dim); border-bottom: 2px solid transparent; font-size: 13px; user-select: none; }
          .op-tab:hover { color: var(--text); }
          .op-tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 700; }
          .op-pane label { display: block; color: var(--dim); font-size: 12px; margin: 10px 0 6px; }
          .op-pane input[list] { width: 100%; }
          .op-serial-info { margin-top: 12px; padding: 10px 14px; background: var(--panel2); border: 1px solid var(--border); border-radius: 8px; font-size: 12px; line-height: 1.8; }
          .op-serial-info .kv { font-family: var(--mono); }
          .op-serial-info .kv b { color: var(--accent); }
          #opSerialList { display: none; }
          /* ===== 证书验证弹窗：状态徽标 + 标题三态配色 ===== */
          .v-badge { padding: 3px 14px; border-radius: 6px; font-weight: 700; font-size: 12px; margin-right: 10px; white-space: nowrap; }
          .v-text { font-size: 13px; color: var(--text); margin-right: 12px; white-space: nowrap; }
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
            <a data-page="debug">调试专区</a>
            <a data-page="sign">签名专区</a>
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

            <!-- 调试专区 -->
            <div class="page" id="page-debug">
              <div class="card">
                <h2>模拟 OCSP 请求（RFC 6960）</h2>
                <div class="hint">按标准构造 CertID（issuerNameHash/issuerKeyHash 基于真正颁发者证书）+ Nonce 扩展，POST 本机 MAIN 的 /OCSP，解析响应并验证签名与 Nonce 回显。</div>
                <div class="row">
                  <div><label>目标证书序列号（留空自动选第一个终端证书）</label><input id="dbgOcspSerial" placeholder="例如 1135228a2"></div>
                  <div><label>CertID 哈希算法</label><select id="dbgOcspHash">
                    <option value="sha256" selected>SHA256</option>
                    <option value="sha1">SHA1</option>
                    <option value="sha384">SHA384</option>
                    <option value="sha512">SHA512</option>
                    <option value="sm3">SM3</option>
                  </select></div>
                  <div style="align-self:end"><button onclick="sendDebugOcsp()">发送模拟请求</button></div>
                </div>
                <pre class="out" id="dbgOcspOut" style="max-height:56vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
              </div>
              <div class="card" style="margin-top:16px">
                <h2>模拟时间戳请求（RFC 3161）</h2>
                <div class="hint">随机生成 32 字节数据 → 按所选摘要算法计算 messageImprint → 构造 TimeStampReq（含 Nonce、certReq=true）→ POST 本机 MAIN 的 /rfc3161 → 解析 TimeStampResp 并验证签名。</div>
                <div class="row">
                  <div><label>摘要算法</label><select id="dbgTsaHash">
                    <option value="sha256" selected>SHA256</option>
                    <option value="sha1">SHA1</option>
                    <option value="sha384">SHA384</option>
                    <option value="sha512">SHA512</option>
                    <option value="sm3">SM3</option>
                  </select></div>
                  <div style="align-self:end"><button onclick="sendDebugTsa()">对随机数据签名</button></div>
                </div>
                <pre class="out" id="dbgTsaOut" style="max-height:56vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
              </div>
            </div>

            <!-- 签名专区 -->
            <div class="page" id="page-sign">
              <div class="card">
                <h2>微软代码签名（Authenticode）</h2>
                <div class="hint">选择 PE 可执行文件（exe / dll / sys）与带代码签名 EKU 的证书进行签名，或验证已签名文件。支持 RSA / ECC / SM2（摘要分别用 SHA256 / SHA256 / SM3），证书表按 Microsoft PE/COFF 规范嵌入。时间戳类型可选 RFC3161（标准 TimeStampToken）或 Authenticode（微软老式 PKCS#7）；地址可指向本机 MAIN（留空）或任意外部 TSA。</div>
                <div class="row">
                  <div style="grid-column:1/2"><label>选择文件</label><input type="file" id="sgExeFile" accept=".exe,.dll,.sys,.cab,.cat,.msi,application/octet-stream"></div>
                  <div><label>签名证书（代码签名 EKU）</label><select id="sgExeCert" title="鼠标悬停查看证书简介"><option value="">（加载中...）</option></select></div>
                  <div><label>时间戳类型</label><select id="sgExeTsType">
                    <option value="RFC3161" selected>RFC3161（标准）</option>
                    <option value="AUTHENTICODE">Authenticode（老式 PKCS#7）</option>
                  </select></div>
                  <div style="grid-column:1/2"><label>时间戳请求地址（留空 = 本机 MAIN）</label>
                    <input id="sgExeTsUrl" list="tsUrlList" placeholder="http://timestamp.digicert.com" spellcheck="false">
                    <datalist id="tsUrlList">
                      <option value="http://timestamp.digicert.com">
                      <option value="http://sha256timestamp.ws.symantec.com/sha256/">
                      <option value="http://timestamp.comodoca.com">
                      <option value="http://time.certum.pl">
                    </datalist>
                  </div>
                  <div style="align-self:end"><button onclick="signExeDo()">签名</button></div>
                  <div style="align-self:end"><button class="ghost" onclick="verifyExeDo()">验证签名</button></div>
                </div>
                <pre class="out" id="sgExeOut" style="max-height:52vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
              </div>
              <div class="card" style="margin-top:16px">
                <h2>PDF 文档签名</h2>
                <div class="hint">选择 PDF 文件与带文档签名 EKU 的证书进行签名，或验证已签名 PDF。证书筛选：微软文档签名 OID（1.3.6.1.4.1.311.10.3.12）或通用文档签名 OID（1.3.6.1.5.5.7.3.36）任一即可。<br>签章类型：Adobe 标准文档签名（adbe.pkcs7.detached，RSA/ECC/SM2 均可）；国密 GB/T 35275-2017（GM.sm2cms.detached，仅 SM2 证书）；国密 GB/T 38540-2020（GM.sm2seal SES_Signature，仅 SM2 证书，需签章图片）；国密 GM/T 0031-2025（安全电子签章密码技术规范，GM.sm2seal 两层 SES_Signature，仅 SM2 证书，需签章图片）。</div>
                <div class="row">
                  <div><label>选择文件</label><input type="file" id="sgPdfFile" accept=".pdf,application/pdf"></div>
                  <div><label>签章图片（png/jpg/bmp/gif）</label><input type="file" id="sgPdfImage" accept="image/png,image/jpeg,image/bmp,image/gif"></div>
                  <div><label>签名证书（文档签名 EKU）</label><select id="sgPdfCert" title="鼠标悬停查看证书简介"><option value="">（加载中...）</option></select></div>
                  <div><label>签章类型</label><select id="sgPdfSeal">
                    <option value="ADOBE" selected>Adobe 标准文档签名</option>
                    <option value="GM35275">国密 GB/T 35275-2017</option>
                    <option value="GM38540">国密 GB/T 38540-2020</option>
                    <option value="GM0031">国密 GM/T 0031-2025</option>
                  </select></div>
                  <div style="grid-column:1/3"><label>时间戳请求地址（留空 = 本机 MAIN；国密 38540 无标准时间戳扩展）</label>
                    <input id="sgPdfTsUrl" list="tsUrlListPdf" placeholder="http://timestamp.digicert.com" spellcheck="false">
                    <datalist id="tsUrlListPdf">
                      <option value="http://timestamp.digicert.com">
                      <option value="http://sha256timestamp.ws.symantec.com/sha256/">
                      <option value="http://timestamp.comodoca.com">
                      <option value="http://time.certum.pl">
                    </datalist>
                  </div>
                  <div style="align-self:end"><button onclick="signPdfDo()">签名</button></div>
                  <div style="align-self:end"><button class="ghost" onclick="verifyPdfDo()">验证签名</button></div>
                </div>
                <pre class="out" id="sgPdfOut" style="max-height:52vh;overflow:auto;white-space:pre;font-family:var(--mono);font-size:12px;line-height:1.55"></pre>
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
                    <p class="cfg-hint">多行输入；保存到 CONFIG.txt 时换行自动以 \\n 代替（单行存储）。</p>
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

        <!-- 证书操作弹窗：吊销证书 / 续签证书 / 密钥更换 -->
        <div class="modal-mask" id="opModal" style="display:none" onclick="if(event.target===this)closeOp()">
          <div class="modal" style="width:min(580px,92vw)">
            <div class="modal-head">
              <h3>证书操作</h3>
              <button class="ghost" onclick="closeOp()">关闭</button>
            </div>
            <div class="modal-body">
              <div class="op-tabs">
                <span class="op-tab active" id="opTabRevoke" onclick="switchOp('revoke')">吊销证书</span>
                <span class="op-tab" id="opTabRenew" onclick="switchOp('renew')">续签证书</span>
                <span class="op-tab" id="opTabKey" onclick="switchOp('key')">密钥更换</span>
              </div>
              <!-- 吊销证书 -->
              <div class="op-pane" id="opPaneRevoke">
                <label>证书序列号（可输入，也可从下拉中选择）</label>
                <input id="opSerial" list="opSerialList" placeholder="输入或选择证书序列号" oninput="opInfo()">
                <datalist id="opSerialList"></datalist>
                <div class="op-serial-info" id="opSerialInfo">未选择证书</div>
                <label>吊销理由</label>
                <select id="opReason"></select>
                <pre class="out" id="opOut" style="margin-top:14px"></pre>
              </div>
              <!-- 续签证书：保持公钥与扩展，仅更新生效/失效时间并 CA 重签 -->
              <div class="op-pane" id="opPaneRenew" style="display:none">
                <label>证书序列号（可输入，也可从下拉中选择）</label>
                <input id="renewSerial" list="opSerialList" placeholder="输入或选择证书序列号" oninput="renewInfo()">
                <div class="op-serial-info" id="renewInfoBox">未选择证书</div>
                <div style="display:flex;gap:12px;margin-top:12px">
                  <div style="flex:1">
                    <label>生效时间（本地时间）</label>
                    <input type="datetime-local" id="renewNotBefore" step="1">
                  </div>
                  <div style="flex:1">
                    <label>失效时间（本地时间）</label>
                    <input type="datetime-local" id="renewNotAfter" step="1">
                  </div>
                </div>
                <div id="renewTests" style="margin-top:10px;font-size:13px;line-height:1.9"></div>
                <pre class="out" id="renewOut" style="margin-top:14px"></pre>
              </div>
              <!-- 密钥更换：生成同类型新密钥对 → 测试 → CA 重签 → 替换旧文件 -->
              <div class="op-pane" id="opPaneKey" style="display:none">
                <label>证书序列号（可输入，也可从下拉中选择）</label>
                <input id="keySerial" list="opSerialList" placeholder="输入或选择证书序列号" oninput="keyInfo()">
                <div class="op-serial-info" id="keyInfoBox">未选择证书</div>
                <div id="keyTests" style="margin-top:10px;font-size:13px;line-height:1.9"></div>
                <pre class="out" id="keyOut" style="margin-top:14px"></pre>
              </div>
            </div>
            <div class="modal-foot" id="opFoot">
              <button class="danger" id="opFootRevoke" onclick="doOpRevoke()">确认吊销</button>
              <button class="success" id="opFootRestore" onclick="doOpRestore()" style="display:none">恢复证书</button>
              <button class="primary" id="opFootRenew" onclick="doOpRenew()" style="display:none">确认续签</button>
              <button class="primary" id="opFootKey" onclick="doOpKey()" style="display:none">确认密钥更换</button>
              <button class="ghost" onclick="closeOp()">取消</button>
            </div>
          </div>
        </div>

        <!-- 证书验证弹窗：按序列号调用 /api/verify -->
        <div class="modal-mask" id="verifyModal" style="display:none" onclick="if(event.target===this)closeVerifyModal()">
          <div class="modal">
            <div class="modal-head" id="verifyHead">
              <h3 id="verifyModalTitle">证书验证</h3>
              <span class="v-badge" id="verifyBadge" style="display:none">状态</span>
              <span class="v-text" id="verifyText"></span>
              <button class="ghost" onclick="closeVerifyModal()">关闭</button>
            </div>
            <div class="modal-body">
              <pre class="out" id="verifyModalOut">验证中...</pre>
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

""";
    private static final String PAGE_P2 = """
        <script>
        // ===== 工具 =====
        const $ = id => document.getElementById(id);
        const v = id => $(id).value.trim();
        const TITLES = { dashboard:'仪表盘', certs:'证书库', makeroot:'签发根证书', signcert:'签发证书', revoke:'吊销证书', crl:'CRL 刷新', ocsp:'OCSP 签发', timestamp:'时间戳签发', verify:'证书验证', debug:'调试专区', sign:'签名专区', init:'初始化环境', config:'系统配置', logs:'操作日志' };

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

        // ===== 调试专区：模拟 OCSP / 时间戳请求 =====
        async function sendDebugOcsp() {
          const out = $('dbgOcspOut');
          out.hidden = false; out.className = 'out'; out.textContent = '正在构造标准 OCSP 请求并发送...';
          try {
            const r = await api('/api/debug/ocsp', {
              serial: $('dbgOcspSerial').value.trim(),
              hash: $('dbgOcspHash').value
            });
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
          }
        }
        async function sendDebugTsa() {
          const out = $('dbgTsaOut');
          out.hidden = false; out.className = 'out'; out.textContent = '正在构造标准 RFC3161 请求并发送...';
          try {
            const r = await api('/api/debug/tsa', { hash: $('dbgTsaHash').value });
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
          }
        }

        // ===== 签名专区：微软代码签名 / PDF 文档签名 =====
        async function loadSignCerts() {
          try {
            const re = await api('/api/signcerts?kind=exe');
            const rp = await api('/api/signcerts?kind=pdf');
            fillSignSel($('sgExeCert'), (re.data || []).length ? re.data : null, 'exe');
            fillSignSel($('sgPdfCert'), (rp.data || []).length ? rp.data : null, 'pdf');
          } catch (e) {
            $('sgExeCert').innerHTML = '<option value="">（加载失败: ' + e + '）</option>';
            $('sgPdfCert').innerHTML = '<option value="">（加载失败: ' + e + '）</option>';
          }
        }
        function fillSignSel(sel, list, kind) {
          if (!list) {
            sel.innerHTML = '<option value="">（无可用证书）</option>';
            return;
          }
          const hint = kind === 'exe' ? '代码签名 EKU' : '文档签名 EKU';
          sel.innerHTML = '<option value="">（请选择 ' + hint + ' 证书）</option>';
          list.forEach(c => {
            const o = document.createElement('option');
            o.value = c.serial;
            o.textContent = c.serial + ' ｜ ' + (c.algo || '') + (c.bits ? ' ' + c.bits : '') + ' ｜ ' + c.dn;
            o.title = '序列号: ' + c.serial + '\\n算法: ' + (c.algo || '') + (c.bits ? ' ' + c.bits + ' 位' : '') +
              '\\n颁发者: ' + (c.issuer || '') + '\\n有效期: ' + (c.validFrom || '') + ' ~ ' + (c.validTo || '') +
              '\\n状态: ' + (c.status === 'V' ? '正常' : c.status === 'R' ? '已吊销' : '未知') +
              '\\nEKU: ' + ((c.ekus || []).join(', ') || '（无）') +
              '\\nDN: ' + c.dn;
            sel.appendChild(o);
          });
        }
        async function signDo(url, fileInput, certSel, outId, isPdf, tsTypeId, tsUrlId, sealId) {
          const f = fileInput.files[0];
          const serial = certSel.value;
          const out = $(outId);
          if (!f) { out.hidden = false; out.className = 'out err'; out.textContent = '请先选择文件'; return; }
          if (!serial) { out.hidden = false; out.className = 'out err'; out.textContent = '请先选择签名证书'; return; }
          out.hidden = false; out.className = 'out'; out.textContent = '正在签名 ' + f.name + ' ...';
          const fd = new FormData();
          fd.append('serial', serial);
          fd.append('name', f.name);
          fd.append('file', f);
          if (isPdf) {
            const imgInput = $('sgPdfImage');
            if (imgInput && imgInput.files && imgInput.files[0]) {
              fd.append('image', imgInput.files[0]);
            }
            if (sealId) fd.append('sealType', $(sealId).value);
          } else if (tsTypeId) {
            fd.append('tsType', $(tsTypeId).value);
          }
          if (tsUrlId) fd.append('tsUrl', $(tsUrlId).value);
          try {
            const resp = await fetch(url, { method: 'POST', body: fd });
            const r = await resp.json();
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
            if (r.ok && r.b64) {
              const a = document.createElement('a');
              a.href = 'data:application/octet-stream;base64,' + r.b64;
              a.download = r.name || ('signed_' + f.name);
              a.textContent = ' ⬇ 下载签名后文件';
              a.style.marginLeft = '12px'; a.style.fontWeight = '700';
              out.appendChild(a);
            }
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
          }
        }
        async function verifyDo(url, fileInput, outId) {
          const f = fileInput.files[0];
          const out = $(outId);
          if (!f) { out.hidden = false; out.className = 'out err'; out.textContent = '请先选择文件'; return; }
          out.hidden = false; out.className = 'out'; out.textContent = '正在验证 ' + f.name + ' ...';
          const fd = new FormData();
          fd.append('file', f);
          try {
            const resp = await fetch(url, { method: 'POST', body: fd });
            const r = await resp.json();
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            out.textContent = r.message || '(无输出)';
          } catch (e) {
            out.className = 'out err';
            out.textContent = '请求失败: ' + e;
          }
        }
        function signExeDo() { signDo('/api/sign/exe', $('sgExeFile'), $('sgExeCert'), 'sgExeOut', false, 'sgExeTsType', 'sgExeTsUrl', null); }
        function verifyExeDo() { verifyDo('/api/verify/exe', $('sgExeFile'), 'sgExeOut'); }
        function signPdfDo() { signDo('/api/sign/pdf', $('sgPdfFile'), $('sgPdfCert'), 'sgPdfOut', true, null, 'sgPdfTsUrl', 'sgPdfSeal'); }
        function verifyPdfDo() { verifyDo('/api/verify/pdf', $('sgPdfFile'), 'sgPdfOut'); }

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
            if (p === 'certs') { loadCerts(); loadIssuers(); }
            if (p === 'config') loadConfig();
            if (p === 'logs') loadLogs();
            if (p === 'sign') loadSignCerts();          };
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
            // 状态文本：V.正常 / R.已吊销 / N.未知；配色：正常绿、已吊销深红、未知橙
            const stTxt = {V:'V.正常', R:'R.已吊销', N:'N.未知'}[e.status] || e.status;
            const stCls = e.status === 'R' ? 'color:#dc2626' : e.status === 'V' ? 'color:var(--ok)' : e.status === 'N' ? 'color:#f59e0b' : '';
            // 序列号列：鼠标悬浮显示证书详情（与仪表盘证书链同款悬浮窗）
            const tip = certTip(e.serial);
            tr.innerHTML = '<td class="t-box" data-tip="' + esc(tip) + '">' + esc(e.serial) + '</td>' +
              '<td>' + esc(typeName(e.type)) + '</td><td style="' + stCls + ';font-weight:700">' + esc(stTxt) + '</td>' +
              '<td>' + esc(e.reason) + '</td><td>' + esc(e.time) + '</td>' +
              '<td class="t-box" data-tip="' + esc(certTip(e.issuer)) + '">' + esc(e.issuer) + '</td><td>' + esc(e.algo) + '</td>' +
              '<td><button class="ghost" data-serial="' + e.serial + '" style="padding:4px 12px;font-size:12px">详情</button> ' +
              '<button class="ghost" data-verify="' + e.serial + '" style="padding:4px 12px;font-size:12px">验证</button> ' +
              '<button class="ghost" data-op="' + e.serial + '" style="padding:4px 12px;font-size:12px">操作</button></td>';
            tb.appendChild(tr);
          });
          if (!rows.length) tb.innerHTML = '<tr><td colspan="8" style="color:var(--dim)">（无匹配记录）</td></tr>';
        }
        // 证书悬浮窗：优先用证书链树的详情（DN/密钥/哈希/长度/OCSP/CRL），未登记链数据时回退登记表信息
        function certTip(serial) {
          const n = issuerMap[serial];
          if (n) return issuerTip(serial);
          const e = certData.find(x => x.serial.toLowerCase() === String(serial).toLowerCase());
          if (!e) return '<div class="kv"><b>证书信息：</b>未找到（该序列号未登记详情）</div>';
          const stTxt = {V:'正常', R:'已吊销', N:'未知'}[e.status] || e.status;
          return '<div class="kv"><b>序列号：</b>' + esc(e.serial) + '</div>' +
            '<div class="kv"><b>证书类型：</b>' + esc(typeName(e.type)) + '</div>' +
            '<div class="kv"><b>状态：</b>' + esc(stTxt) + ' / 算法：' + esc(e.algo || '-') + '</div>' +
            '<div class="kv"><b>颁发者：</b>' + esc(e.issuer) + '</div>' +
            '<div class="kv"><b>时间：</b>' + esc(e.time) + '</div>';
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

        // ===== 证书操作弹窗（吊销证书 / 续签证书 / 密钥更换） =====
        const OP_REASONS = [['0','未指定'],['1','密钥泄露'],['2','CA泄露'],['3','从属关系变更'],['4','证书超期'],['5','停止运营'],['6','证书吊销'],['8','从CRL移除'],['9','其他']];
        function openOp(serial) {
          $('opSerial').value = serial || '';
          $('keySerial').value = serial || '';
          $('renewSerial').value = serial || '';
          // 续签默认：生效=当前时间，失效=一年后（可自行修改）
          const now = new Date();
          const pad = n => String(n).padStart(2, '0');
          const fmt = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
          const oneYear = new Date(now.getTime());
          oneYear.setFullYear(oneYear.getFullYear() + 1);
          $('renewNotBefore').value = fmt(now);
          $('renewNotAfter').value = fmt(oneYear);
          $('opSerialList').innerHTML = certData.map(e => '<option value="' + esc(e.serial) + '"></option>').join('');
          const sel = $('opReason');
          sel.innerHTML = OP_REASONS.map(r => '<option value="' + r[0] + '">' + r[0] + ' - ' + r[1] + '</option>').join('');
          sel.value = '0';
          $('opOut').textContent = '';
          $('opOut').hidden = true;
          $('keyOut').textContent = '';
          $('keyOut').hidden = true;
          $('keyTests').innerHTML = '';
          $('renewOut').textContent = '';
          $('renewOut').hidden = true;
          $('renewTests').innerHTML = '';
          switchOp('revoke');
          $('opModal').style.display = 'flex';
          opInfo();
          keyInfo();
          renewInfo();
        }
        function closeOp() { $('opModal').style.display = 'none'; }
        // 分组切换：吊销（含恢复）/ 续签 / 密钥更换均有实际功能
        function switchOp(tab) {
          ['revoke', 'renew', 'key'].forEach(t => {
            const cap = t[0].toUpperCase() + t.slice(1);
            $('opTab' + cap).classList.toggle('active', t === tab);
            $('opPane' + cap).style.display = t === tab ? '' : 'none';
          });
          $('opFootRevoke').style.display = tab === 'revoke' ? '' : 'none';
          $('opFootRestore').style.display = tab === 'revoke' ? '' : 'none';
          $('opFootRenew').style.display = tab === 'renew' ? '' : 'none';
          $('opFootKey').style.display = tab === 'key' ? '' : 'none';
          if (tab === 'key') keyInfo();
          if (tab === 'renew') renewInfo();
        }
        // 序列号输入/选择后：显示证书简要信息（同仪表盘证书链悬浮窗数据）
        function opInfo() {
          renderCertInfo($('opSerialInfo'), $('opSerial').value.trim().toLowerCase());
        }
        // 密钥更换分组的序列号简要信息
        function keyInfo() {
          renderCertInfo($('keyInfoBox'), $('keySerial').value.trim().toLowerCase());
        }
        // 续签分组的序列号简要信息
        function renewInfo() {
          renderCertInfo($('renewInfoBox'), $('renewSerial').value.trim().toLowerCase());
        }
        function renderCertInfo(box, s) {
          if (!s) { box.innerHTML = '<span style="color:var(--dim)">未选择证书</span>'; return; }
          const n = issuerMap[s];
          if (n) {
            box.innerHTML = '<div class="kv"><b>证书类型：</b>' + esc(typeName(n.type) + (n.type === 'E' && n.kind ? '[' + n.kind + ']' : '')) + '</div>' +
              '<div class="kv"><b>序列号：</b>' + esc(n.serial) + '</div>' +
              '<div class="kv"><b>DN：</b>' + esc(n.dn) + '</div>' +
              '<div class="kv"><b>密钥对：</b>' + esc(n.algo || '-') + ' / 哈希：' + esc(n.hash || '-') + ' / 长度：' + (n.bits ? n.bits + '位' : '-') + '</div>' +
              '<div class="kv"><b>OCSP 状态：</b>' + esc(n.ocsp) + '</div>' +
              '<div class="kv"><b>CRL 状态：</b>' + esc(n.crl) + '（登记状态 ' + esc({V:'正常', R:'已吊销', N:'未知'}[n.status] || n.status) + '）</div>';
          } else {
            const e = certData.find(x => x.serial.toLowerCase() === s);
            if (e) {
              box.innerHTML = '<div class="kv"><b>序列号：</b>' + esc(e.serial) + '</div>' +
                '<div class="kv"><b>证书类型：</b>' + esc(typeName(e.type)) + ' / 状态：' + esc({V:'正常', R:'已吊销', N:'未知'}[e.status] || e.status) + '</div>' +
                '<div class="kv"><b>算法：</b>' + esc(e.algo || '-') + ' / 颁发者：' + esc(e.issuer) + '</div>' +
                '<div class="kv"><b>时间：</b>' + esc(e.time) + '</div>';
            } else {
              box.innerHTML = '<div class="kv" style="color:var(--err)"><b>提示：</b>未找到该序列号（请检查 CERTS.txt 登记表）</div>';
            }
          }
        }
        // 确认吊销：调用 /api/revoke，成功后刷新证书库列表
        async function doOpRevoke() {
          const s = $('opSerial').value.trim();
          if (!s) { $('opOut').hidden = false; showOut('opOut', '请先输入证书序列号', false); return; }
          await postForm('/api/revoke', { serial: s, reason: $('opReason').value }, 'opOut');
          loadCerts();
          loadIssuers();
        }
        // 恢复证书：调用 /api/restore（R→V、原因 0，同步刷新 CRL）
        async function doOpRestore() {
          const s = $('opSerial').value.trim();
          if (!s) { $('opOut').hidden = false; showOut('opOut', '请先输入证书序列号', false); return; }
          $('opOut').hidden = false;
          $('opOut').textContent = '正在恢复证书并刷新 CRL...';
          await postForm('/api/restore', { serial: s }, 'opOut');
          loadCerts();
          loadIssuers();
        }
        // 确认密钥更换：调用 /api/rekey（生成新密钥对 → 测试 → CA 重签 → 替换文件）
        async function doOpKey() {
          const s = $('keySerial').value.trim();
          if (!s) { $('keyOut').hidden = false; showOut('keyOut', '请先输入证书序列号', false); return; }
          $('keyTests').innerHTML = '<div class="kv" style="color:var(--dim)">正在生成新密钥对并执行加解密 / 签名验签测试...</div>';
          await postForm('/api/rekey', { serial: s }, 'keyOut');
          loadCerts();
          loadIssuers();
        }
        // 确认续签：调用 /api/renew（更新生效/失效时间 → CA 重签 → 替换文件）
        async function doOpRenew() {
          const s = $('renewSerial').value.trim();
          if (!s) { $('renewOut').hidden = false; showOut('renewOut', '请先输入证书序列号', false); return; }
          const nb = $('renewNotBefore').value;
          const na = $('renewNotAfter').value;
          if (!nb || !na) { $('renewOut').hidden = false; showOut('renewOut', '请选择生效时间和失效时间', false); return; }
          if (nb >= na) { $('renewOut').hidden = false; showOut('renewOut', '失效时间必须晚于生效时间', false); return; }
          $('renewTests').innerHTML = '<div class="kv" style="color:var(--dim)">正在按新时间重建 TBS 并由颁发者 CA 重签...</div>';
          await postForm('/api/renew', { serial: s, notBefore: nb, notAfter: na }, 'renewOut');
          loadCerts();
          loadIssuers();
        }

        // ===== 证书验证弹窗：按当前行序列号调用 /api/verify =====
        const V_REASONS = {0:'未指定', 1:'密钥泄露', 2:'CA泄露', 3:'从属关系变更', 4:'证书超期', 5:'停止运营', 6:'证书吊销', 8:'从CRL移除', 9:'其他'};
        // 从验证输出文本解析证书状态：正常 / 已吊销（含原因）/ 未知（实时数据获取失败）
        function parseVerifyState(text) {
          const t = text || '';
          if (/无法|失败|未知|None|解析失败/.test(t)) {
            return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
          }
          if (t.includes('已吊销') || t.includes('已被')) {
            const m = t.match(/原因[:：]?\\s*(\\d+)/);
            const reason = m ? (V_REASONS[parseInt(m[1], 10)] || ('原因码 ' + m[1])) : '';
            return { k: 'revoked', badge: '已吊销', txt: reason ? '因' + reason + '，证书已被吊销' : '证书已被吊销' };
          }
          if (t.includes('证书正常') || t.includes('正常')) {
            return { k: 'ok', badge: '正常', txt: '证书有效，状态正常' };
          }
          return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
        }
        const V_HEAD_BG = { ok: 'rgba(16,185,129,0.16)', revoked: 'rgba(239,68,68,0.16)', unknown: 'rgba(245,158,11,0.16)' };
        const V_BADGE_BG = { ok: '#dcfce7', revoked: '#fee2e2', unknown: '#ffedd5' };
        const V_BADGE_FG = { ok: '#065f46', revoked: '#991b1b', unknown: '#b45309' };
        const V_TEXT_FG = { ok: '#6ee7b7', revoked: '#fca5a5', unknown: '#fcd34d' };
        async function openVerify(serial) {
          $('verifyModal').style.display = 'flex';
          $('verifyModalTitle').textContent = '证书验证 · ' + serial;
          const out = $('verifyModalOut');
          out.className = 'out';
          out.textContent = '验证中...';
          try {
            const r = await api('/api/verify', { target: serial });
            out.textContent = r.message || (r.ok ? 'OK' : '失败');
            out.className = 'out ' + (r.ok ? 'ok' : 'err');
            const st = parseVerifyState(out.textContent);
            $('verifyHead').style.background = V_HEAD_BG[st.k];
            $('verifyHead').style.borderBottomColor = V_HEAD_BG[st.k];
            const b = $('verifyBadge');
            b.style.display = 'inline-block';
            b.style.background = V_BADGE_BG[st.k];
            b.style.color = V_BADGE_FG[st.k];
            b.textContent = st.badge;
            $('verifyText').textContent = st.txt;
            $('verifyText').style.color = V_TEXT_FG[st.k];
          } catch (e) {
            out.textContent = '请求失败: ' + e;
            out.className = 'out err';
          }
        }
        function closeVerifyModal() { $('verifyModal').style.display = 'none'; }

        // ===== 证书链树 =====
        function esc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
        function typeName(t) { return {R:'根证书', C:'CA证书', E:'终端证书'}[t] || t; }
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

        // 证书库「详情 / 验证 / 操作」按钮：事件委托，避免内联 onclick 引号转义问题
        $('certsTable').querySelector('tbody').addEventListener('click', function (ev) {
          const btn = ev.target.closest ? ev.target.closest('button[data-serial]') : null;
          if (btn) showDetail(btn.getAttribute('data-serial'));
          const vbtn = ev.target.closest ? ev.target.closest('button[data-verify]') : null;
          if (vbtn) openVerify(vbtn.getAttribute('data-verify'));
          const obtn = ev.target.closest ? ev.target.closest('button[data-op]') : null;
          if (obtn) openOp(obtn.getAttribute('data-op'));
        });
        </script>
        </body>
        </html>
        



""";
    private static final String PAGE_HTML = PAGE_P1.concat(PAGE_P2);
}
