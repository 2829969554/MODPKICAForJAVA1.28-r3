package modpkica;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * MLog —— 追加式操作日志（对应 Go 版 golib/mlog/mlog.go）。
 *
 * <p>每条日志追加写入 &lt;baseDir&gt;/PKI/logs.log，格式（键值对分行，双换行分隔条目）：
 * <pre>
 *   时间: 2026/09/11 14:30:00
 *   时间戳: 1789139400000
 *   操作: ADMIN init
 *   命令: init "CN=Test,O=Org" 2048 sha256 RSA
 *   结果: 初始化环境完成
 *
 * </pre>
 * 错误条目额外带「错误:」行。命令/结果/错误中的换行会被转义为 \n，保证每条日志单块可解析。
 * 目录不存在时自动创建；写日志失败不中断业务。
 */
public final class MLog {

    /** 时间格式：yyyy/MM/dd HH:mm:ss */
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");

    private MLog() {
    }

    /**
     * 追加一条普通日志（旧签名兼容：无命令字段，命令留空）。
     *
     * @param baseDir   MODPKICA 根目录
     * @param operation 操作名（命令 / 动作）
     * @param result    结果 / 详情
     */
    public static void append(String baseDir, String operation, String result) {
        append(baseDir, operation, "", result);
    }

    /**
     * 追加一条普通日志。
     *
     * @param baseDir   MODPKICA 根目录
     * @param operation 操作名（命令 / 动作）
     * @param command   输入的完整命令 / 请求数据（可为空串）
     * @param result    输出结果 / 响应详情
     */
    public static void append(String baseDir, String operation, String command, String result) {
        write(baseDir, operation, command, result, "");
    }

    /**
     * 追加一条错误日志（含报错详情）。
     *
     * @param baseDir   MODPKICA 根目录
     * @param operation 操作名（命令 / 动作）
     * @param command   输入的完整命令 / 请求数据（可为空串）
     * @param error     报错详情
     */
    public static void appendErr(String baseDir, String operation, String command, String error) {
        write(baseDir, operation, command, "", error);
    }

    /** 统一写入：时间 / 时间戳 / 操作 / 命令 / 结果 / 错误，条目间双换行。 */
    private static void write(String baseDir, String operation, String command,
                              String result, String error) {
        try {
            Path dir = Paths.get(baseDir, "PKI");
            Files.createDirectories(dir);
            Path logFile = dir.resolve("logs.log");
            StringBuilder sb = new StringBuilder();
            sb.append("时间: ").append(LocalDateTime.now().format(TIME_FMT)).append('\n');
            sb.append("时间戳: ").append(System.currentTimeMillis()).append('\n');
            sb.append("操作: ").append(sanitize(operation)).append('\n');
            sb.append("命令: ").append(sanitize(command)).append('\n');
            sb.append("结果: ").append(sanitize(result)).append('\n');
            if (error != null && !error.isEmpty()) {
                sb.append("错误: ").append(sanitize(error)).append('\n');
            }
            sb.append('\n'); // 双换行分隔条目
            Files.writeString(logFile, sb.toString(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // 日志失败不应中断业务，静默忽略
        }
    }

    /** 清洗内容：换行转义为 \n，避免破坏条目结构。 */
    private static String sanitize(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\r", "\\r").replace("\n", "\\n");
    }
}
