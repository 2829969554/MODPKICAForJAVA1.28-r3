import modpkica.RootGetCrl;
import modpkica.WebAdmin;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Smoke: CERTS.txt right-click delete (comment-out row; CRL/OCSP skip it). Uses temp PKI + temp admin port. */
public class TestCertsDelete {
  static Path src = Paths.get("C:\\Users\\28299\\Desktop\\modpkica4JAVA\\PKI");
  static Path tmp = Paths.get(System.getenv("TEMP"), "modpkica_del_smoke");
  static String rootSerial = "6cfbd3ad26f760570e04dd10a8f42822";
  static String caSerial = "9f79048f22b7dbe4e83fdd69029f844c";
  static String eeSerial = "8eeff77755c5356a7eadeeb52874c893";
  static int fails = 0;

  public static void main(String[] args) throws Exception {
    setup();
    System.setProperty("MODPKICA_BASE", tmp.toString());
    System.setProperty("modpkica.admin.port", "18099");
    Thread t = new Thread(() -> {
      try { WebAdmin.main(new String[0]); }
      catch (Exception e) { e.printStackTrace(); }
    });
    t.setDaemon(true);
    t.start();
    Thread.sleep(2800);

    // 1) POST delete (comment-out) the EE cert
    String resp = http("http://127.0.0.1:18099/api/certs/delete", "POST",
        "{\"serial\":\"" + eeSerial + "\"}");
    System.out.println("delete resp=" + resp);
    check("delete returns ok", resp.contains("\"ok\":true") || resp.contains("已删除"));

    // 2) CERTS.txt: EE row now commented, other rows untouched
    String txt = new String(Files.readAllBytes(tmp.resolve("PKI/CERTS.txt")), StandardCharsets.UTF_8);
    check("row commented", txt.contains("# " + eeSerial) || txt.contains("#" + eeSerial));
    check("row not active", !Arrays.stream(txt.split("\\r?\\n"))
        .anyMatch(l -> l.startsWith(eeSerial + " ")));
    check("root row kept", txt.contains(rootSerial + " R "));
    check("ca row kept", txt.contains(caSerial + " C "));

    // 3) GET /api/certs list excludes the commented EE
    String list = http("http://127.0.0.1:18099/api/certs", "GET", null);
    check("list excludes ee", !list.contains("\"" + eeSerial + "\""));
    check("list keeps root", list.contains("\"" + rootSerial + "\""));

    // 4) RootGetCrl still generates CRL (CertsDB skips # rows)
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    PrintStream old = System.out;
    System.setOut(new PrintStream(bos, true, "UTF-8"));
    try { RootGetCrl.run(tmp.toString()); } finally { System.setOut(old); }
    String crlOut = bos.toString("UTF-8");
    check("CRL generated", crlOut.contains("CRL") || crlOut.contains("完成"));

    System.out.println(fails == 0 ? "SMOKE PASS (all checks)" : "SMOKE FAIL: " + fails + " checks");
    if (fails > 0) System.exit(1);
  }

  static String http(String url, String method, String body) throws Exception {
    HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
    c.setRequestMethod(method);
    c.setConnectTimeout(8000);
    c.setReadTimeout(8000);
    if (body != null) {
      c.setDoOutput(true);
      c.setRequestProperty("Content-Type", "application/json");
      try (OutputStream os = c.getOutputStream()) { os.write(body.getBytes(StandardCharsets.UTF_8)); }
    }
    int code = c.getResponseCode();
    InputStream is = code >= 400 ? c.getErrorStream() : c.getInputStream();
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    if (is != null) { byte[] buf = new byte[4096]; int n; while ((n = is.read(buf)) > 0) b.write(buf, 0, n); }
    return new String(b.toByteArray(), StandardCharsets.UTF_8);
  }

  static void setup() throws Exception {
    deleteRecursive(tmp);
    Files.createDirectories(tmp.resolve("PKI/ROOT"));
    Files.createDirectories(tmp.resolve("PKI/CA"));
    Files.createDirectories(tmp.resolve("PKI/CERT"));
    Files.createDirectories(tmp.resolve("PKI/KEY"));
    Files.createDirectories(tmp.resolve("PKI/WebPublic/CRT"));
    Files.createDirectories(tmp.resolve("PKI/WebPublic/CRL"));
    copy("ROOT/" + rootSerial, "PKI/ROOT/" + rootSerial);
    copy("CA/" + caSerial, "PKI/CA/" + caSerial);
    copy("CERT/" + eeSerial, "PKI/CERT/" + eeSerial);
    copy("KEY/" + eeSerial, "PKI/KEY/" + eeSerial);
    Files.write(tmp.resolve("PKI/CERTS.txt"), Arrays.asList(
        "# \u5e8f\u5217\u53f7    \u7c7b\u578b   \u72b6\u6001   \u539f\u56e0   \u65f6\u95f4                \u9881\u53d1\u8005ID         \u7b97\u6cd5",
        rootSerial + " R V 0 2026/09/23-20:43:53 " + rootSerial + " RSA-PSS",
        caSerial + " C V 0 2026/09/23-20:56:44 " + rootSerial + " RSA-PSS",
        eeSerial + " E V 0 2026/09/23-21:02:17 " + caSerial + " RSA-PSS"),
        StandardCharsets.UTF_8);
    Files.write(tmp.resolve("PKI/CONFIG.txt"), Arrays.asList(
        "WEBPORT=80", "SUPORT=8080", "OCSP=http://localhost:80/OCSP",
        "CRL=http://localhost:80/CRL/{CID}.crl", "CRT=http://localhost:80/CRT/{CID}.crt",
        "CPS=https://gitee.com/wxgshuju/modpkica", "CPS_Nonice=http://example.com/nonice"),
        StandardCharsets.UTF_8);
  }

  static void copy(String relSrc, String relDst) throws Exception {
    for (String ext : new String[]{".crt", ".key"}) {
      Path a = src.resolve(relSrc + ext);
      Path b = tmp.resolve(relDst + ext);
      if (Files.exists(a)) Files.copy(a, b);
    }
  }

  static void deleteRecursive(Path p) throws Exception {
    if (!Files.exists(p)) return;
    Files.walk(p).sorted(Comparator.reverseOrder()).forEach(x -> {
      try { Files.deleteIfExists(x); } catch (Exception ignore) {}
    });
  }

  static void check(String name, boolean ok) {
    System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
    if (!ok) fails++;
  }
}
