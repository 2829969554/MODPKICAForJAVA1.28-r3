package modpkica;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * auto —— 自动化证书库操作（对应 Go 版 cmd/auto）。
 *
 * <p>提供三个子命令（Java 版直接操作 PKI/CERTS.txt，不派生进程）：
 * <ul>
 *   <li><b>auto init</b>：初始化环境——把现有 CERTS.txt 备份为
 *       {@code CERTS.txt.old.<Unix时间戳>}，然后写入 CERTS.txt 模板与模板副本
 *       CERTS.txt.sm。</li>
 *   <li><b>auto revoke 序列号 [原因编号]</b>：吊销证书——把对应记录状态改为 R、
 *       原因与时间（时间 = 当前时间 - 3 天，对齐 Go 版）。</li>
 *   <li><b>auto newcert 序列号 类型 状态 原因 时间 颁发者ID 算法</b>：
 *       追加一条证书记录（时间为 "null" 时用当前时间 - 3 天）。</li>
 * </ul>
 */
public final class Auto {

    /** CERTS.txt 行时间格式 */
    private static final DateTimeFormatter MOD_TIME =
            DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss");

    /** CERTS.txt 模板内容（对齐 Go 版 echo 出的字节内容） */
    private static final String CERTS_TEMPLATE =
            "# 序列号    类型        状态         状态原因编号   签发时间/吊销时间\r\n"
                    + "#    ROOT/CA/END   V正常R吊销N未知     0-9     例如 2000/06/17-12:12:12\r\n";

    private Auto() {
    }

    public static void main(String[] args) throws Exception {
        String baseDir = AppPaths.baseDir();
        String cmd = args.length >= 1 ? args[0] : "";

        if ("init".equalsIgnoreCase(cmd)) {
            initEnv(baseDir);
            System.out.println("初始化环境完成");
            return;
        }
        if ("revoke".equalsIgnoreCase(cmd) && args.length >= 2) {
            String reason = args.length >= 3 ? args[2] : "0";
            revokeCert(baseDir, args[1], reason);
            return;
        }
        if ("newcert".equalsIgnoreCase(cmd) && args.length >= 5) {
            // 参数：序列号 类型 状态 原因 时间 颁发者ID 算法
            String time = "null".equals(args[4]) ? nowMinus3Days() : args[4];
            addCert(baseDir, args[1], args[2], args[3], time, args[5], args[6]);
            return;
        }
        System.out.println("错误:无效操作");
        System.out.println("用法: auto init | auto revoke 序列号 [原因] | auto newcert 序列号 类型 状态 原因 时间 颁发者ID 算法");
    }

    /** 当前时间 - 3 天（对齐 Go 版 getmodtimeNow）。 */
    private static String nowMinus3Days() {
        return LocalDateTime.now().minusDays(3).format(MOD_TIME);
    }

    /** 供 ADMIN 内部调用：初始化环境（备份 + 模板）。 */
    public static void runInit(String baseDir) throws Exception {
        initEnv(baseDir);
    }

    /** 供 ADMIN 内部调用：吊销证书。 */
    public static void revoke(String baseDir, String serial, String reason) throws Exception {
        revokeCert(baseDir, serial, reason);
    }

    /** 供 ADMIN/WebAdmin 内部调用：恢复证书（R→V、原因 0、时间刷新为当前时间）。 */
    public static void restore(String baseDir, String serial) throws Exception {
        restoreCert(baseDir, serial);
    }

    /** auto init：清理证书目录旧文件、备份 CERTS.txt 并写入模板。 */
    private static void initEnv(String baseDir) throws Exception {
        // 1) 清理各证书目录下所有 cer/crt/key/crl/der 文件（初始化环境即清空重来）
        String[] dirs = {
            "PKI/CERT", "PKI/CA", "PKI/ROOT", "PKI/KEY",
            "PKI/OCSP", "PKI/TIMSTAMP",
            "PKI/WebPublic/CRT", "PKI/WebPublic/CRL"
        };
        String[] exts = {"cer", "crt", "key", "crl", "der"};
        int deleted = 0;
        for (String d : dirs) {
            java.io.File folder = new java.io.File(baseDir, d);
            java.io.File[] files = folder.listFiles();
            if (files == null) {
                continue;
            }
            for (java.io.File f : files) {
                if (!f.isFile()) {
                    continue;
                }
                String name = f.getName().toLowerCase();
                for (String ext : exts) {
                    if (name.endsWith("." + ext)) {
                        f.delete();
                        deleted++;
                        break;
                    }
                }
            }
        }
        System.out.println("已清理 " + deleted + " 个证书/密钥/吊销列表文件");
        // 2) 备份 CERTS.txt 并重建模板
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        if (Files.exists(certs)) {
            String backup = certs + ".old." + (System.currentTimeMillis() / 1000L);
            Files.move(certs, Paths.get(backup));
        }
        Files.write(certs, CERTS_TEMPLATE.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get(baseDir, "PKI", "CERTS.txt.sm"),
                CERTS_TEMPLATE.getBytes(StandardCharsets.UTF_8));
        System.out.println("CERTS.txt 已备份并重建模板");
    }

    /** auto revoke：把 CERTS.txt 中指定序列号记录改为 R 状态。 */
    private static void revokeCert(String baseDir, String serial, String reason) throws Exception {
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        List<String> lines = Files.readAllLines(certs, StandardCharsets.UTF_8);
        String newTime = nowMinus3Days();
        boolean found = false;
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                sb.append(line).append(System.lineSeparator());
                continue;
            }
            String[] f = t.split("\\s+");
            if (f[0].equals(serial) && f.length >= 7) {
                // 新行：序列号 类型 R 原因 时间 颁发者ID 算法
                sb.append(f[0]).append(' ').append(f[1]).append(" R ").append(reason)
                        .append(' ').append(newTime).append(' ')
                        .append(f[5]).append(' ').append(f[6])
                        .append(System.lineSeparator());
                found = true;
            } else {
                sb.append(line).append(System.lineSeparator());
            }
        }
        if (!found) {
            System.out.println("吊销失败:CERTS.txt证书库不存在此编号");
            return;
        }
        Files.write(certs, sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("吊销成功");
    }

    /** auto restore：把 CERTS.txt 中指定序列号记录改为 V 状态、原因 0（撤销吊销）。 */
    private static void restoreCert(String baseDir, String serial) throws Exception {
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        List<String> lines = Files.readAllLines(certs, StandardCharsets.UTF_8);
        String newTime = LocalDateTime.now().format(MOD_TIME);
        boolean found = false;
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                sb.append(line).append(System.lineSeparator());
                continue;
            }
            String[] f = t.split("\\s+");
            if (f[0].equals(serial) && f.length >= 7) {
                // 新行：序列号 类型 V 0 时间 颁发者ID 算法
                sb.append(f[0]).append(' ').append(f[1]).append(" V 0 ")
                        .append(newTime).append(' ')
                        .append(f[5]).append(' ').append(f[6])
                        .append(System.lineSeparator());
                found = true;
            } else {
                sb.append(line).append(System.lineSeparator());
            }
        }
        if (!found) {
            System.out.println("恢复失败:CERTS.txt证书库不存在此编号");
            return;
        }
        Files.write(certs, sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("恢复成功");
    }

    /** auto newcert：追加一条证书记录。 */
    private static void addCert(String baseDir, String serial, String type, String status,
                                String time, String issuerId, String algo) throws Exception {
        String newline = serial + " " + type + " " + status + " " + "0" + " "
                + time + " " + issuerId + " " + algo + "\r\n";
        Path certs = Paths.get(baseDir, "PKI", "CERTS.txt");
        Files.write(certs, newline.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        System.out.println("增加证书成功: " + serial);
    }
}
