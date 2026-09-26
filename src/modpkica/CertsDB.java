package modpkica;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * CertsDB —— 证书台账 CERTS.txt 的读取 / 追加 / 吊销修改。
 *
 * <p>文件每行格式（# 开头为注释行）：
 * <pre>
 *   序列号  类型  状态  原因  时间  颁发者ID  算法
 *   13fbe865867a8ed R V 0 2026/09/04-20:07:09 13fbe865867a8ed SM2
 * </pre>
 * <ul>
 *   <li>类型 type：R=根证书, C=中间 CA, E=终端证书</li>
 *   <li>状态 status：V=正常(valid), R=吊销(revoked), N=未知(unknown)</li>
 *   <li>原因 reason：整数，RFC5280 吊销原因码，未吊销时为 0</li>
 *   <li>时间 time：yyyy/MM/dd-HH:mm:ss</li>
 *   <li>颁发者ID issuerId：签发该证书的证书序列号，自签根证书等于自身序列号</li>
 *   <li>算法 algo：RSA / ECC / SM2</li>
 * </ul>
 */
public class CertsDB {

    /** 时间列的解析格式 */
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss");

    /** 内存中缓存的全部台账条目 */
    private final List<CertEntry> entries = new ArrayList<>();

    /** CERTS.txt 的完整路径 */
    private Path dbPath;

    /**
     * 单条证书台账记录。
     */
    public static class CertEntry {
        /** 证书序列号（hex，小写，无冒号） */
        public String serial;
        /** 类型：R / C / E */
        public char type;
        /** 状态：V / R / N */
        public char status;
        /** 吊销原因码（未吊销为 0） */
        public int reason;
        /** 时间 */
        public LocalDateTime time;
        /** 颁发者序列号 */
        public String issuerId;
        /** 算法：RSA / ECC / SM2 */
        public String algo;
    }

    /**
     * 加载 &lt;baseDir&gt;/PKI/CERTS.txt。
     *
     * @param baseDir MODPKICA 根目录
     */
    public void load(String baseDir) {
        dbPath = Paths.get(baseDir, "PKI", "CERTS.txt");
        entries.clear();
        if (!Files.exists(dbPath)) {
            return;
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(dbPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return;
        }
        for (String raw : lines) {
            String line = stripCrLf(raw).trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            // 按空白切分：serial type status reason time issuerId algo
            String[] p = line.split("\\s+");
            if (p.length < 7) {
                continue;
            }
            try {
                CertEntry e = new CertEntry();
                e.serial = p[0];
                e.type = p[1].charAt(0);
                e.status = p[2].charAt(0);
                e.reason = Integer.parseInt(p[3]);
                e.time = LocalDateTime.parse(p[4], TIME_FMT);
                e.issuerId = p[5];
                e.algo = p[6];
                entries.add(e);
            } catch (Exception ignore) {
                // 单行解析失败跳过，不影响整体
            }
        }
    }

    /** 重新从磁盘加载（外部修改后调用）。 */
    public void reload() {
        if (dbPath == null) {
            return;
        }
        String baseDir = dbPath.getParent().getParent().toString();
        load(baseDir);
    }

    /** 按序列号查找条目。
     *
     * @param serial 证书序列号
     * @return 命中的条目，未命中返回 null
     */
    public CertEntry findBySerial(String serial) {
        if (serial == null) {
            return null;
        }
        for (CertEntry e : entries) {
            if (e.serial.equalsIgnoreCase(serial)) {
                return e;
            }
        }
        return null;
    }

    /**
     * 按颁发者序列号 + 证书序列号查找（issuer+serial 才是全局唯一键）。
     *
     * @param issuerId 颁发者序列号
     * @param serial   证书序列号
     * @return 命中的条目，未命中返回 null
     */
    public CertEntry findByIssuerAndSerial(String issuerId, String serial) {
        if (issuerId == null || serial == null) {
            return null;
        }
        for (CertEntry e : entries) {
            if (serial.equalsIgnoreCase(e.serial)
                    && issuerId.equalsIgnoreCase(e.issuerId)) {
                return e;
            }
        }
        return null;
    }

    /**
     * 按序列号查找其颁发者序列号。
     *
     * @param serial 证书序列号
     * @return 颁发者序列号；找不到时返回 "null"（与 Go 版字符串约定一致）
     */
    public String findIssuerIdBySerial(String serial) {
        CertEntry e = findBySerial(serial);
        if (e == null) {
            return "null";
        }
        return e.issuerId == null ? "null" : e.issuerId;
    }

    /**
     * 追加一条新条目到内存并写回 CERTS.txt 文件末尾。
     *
     * @param e 新条目
     */
    public void addEntry(CertEntry e) {
        String line = formatLine(e);
        try {
            Files.createDirectories(dbPath.getParent());
            Files.writeString(dbPath, line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException ex) {
            // 写文件失败必须暴露：否则内存记录与磁盘不一致（重启后记录丢失）
            throw new java.io.UncheckedIOException("写 CERTS.txt 失败: " + dbPath, ex);
        }
        entries.add(e); // 写成功后才加入内存
    }

    /**
     * 把指定序列号证书状态改为 R（吊销），更新原因与时间，并整文件重写。
     *
     * @param serial 证书序列号
     * @param reason 吊销原因码
     * @param time   吊销时间
     */
    public void revokeCert(String serial, int reason, LocalDateTime time) {
        CertEntry e = findBySerial(serial);
        if (e == null) {
            return;
        }
        e.status = 'R';
        e.reason = reason;
        e.time = time;
        rewriteAll();
    }

    /**
     * 返回所有类型为 R（根）或 C（中间 CA）的条目。
     */
    public List<CertEntry> getAllRootAndCA() {
        List<CertEntry> out = new ArrayList<>();
        for (CertEntry e : entries) {
            if (e.type == 'R' || e.type == 'C') {
                out.add(e);
            }
        }
        return out;
    }

    /**
     * 返回所有状态为 R（吊销）的条目。
     */
    public List<CertEntry> getAllRevoked() {
        List<CertEntry> out = new ArrayList<>();
        for (CertEntry e : entries) {
            if (e.status == 'R') {
                out.add(e);
            }
        }
        return out;
    }

    /** 返回全部条目（只读语义，调用方不要修改）。 */
    public List<CertEntry> getAll() {
        return entries;
    }

    /** 把内存中全部条目按行重写回文件。 */
    private void rewriteAll() {
        StringBuilder sb = new StringBuilder();
        for (CertEntry e : entries) {
            sb.append(formatLine(e)).append(System.lineSeparator());
        }
        try {
            Files.writeString(dbPath, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException ex) {
            // Rewrite failure must NOT be swallowed (PKI-015): memory and disk would diverge.
            throw new java.io.UncheckedIOException("rewrite CERTS.txt failed: " + dbPath, ex);
        }
    }

    /** 把条目格式化为文件中的一行（不补换行）。 */
    private static String formatLine(CertEntry e) {
        String timeStr = e.time == null
                ? LocalDateTime.now().format(TIME_FMT)
                : e.time.format(TIME_FMT);
        return e.serial + " " + e.type + " " + e.status + " " + e.reason
                + " " + timeStr + " " + e.issuerId + " " + e.algo;
    }

    /** 去掉行尾 \r\n。 */
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
}
