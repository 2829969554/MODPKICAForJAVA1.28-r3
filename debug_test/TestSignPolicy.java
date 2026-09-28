import modpkica.MakeCert;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.Security;
import java.util.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Smoke: intermediate-CA pathLen + end-entity cert policy checkboxes (uses a temp PKI copy). */
public class TestSignPolicy {
  static Path src = Paths.get("C:\\Users\\28299\\Desktop\\modpkica4JAVA\\PKI");
  static Path tmp = Paths.get(System.getenv("TEMP"), "modpkica_smoke_sign");
  static String rootSerial = "6cfbd3ad26f760570e04dd10a8f42822";
  static int fails = 0;

  public static void main(String[] args) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    setup();
    // 1) intermediate CA with pathLen=1
    MakeCert.run(tmp.toString(), new String[]{"CN=TestSubCA,O=MyOrg,C=CN", "2048", "sha256",
        "99", "", "1", "1", "null", "null", "null", rootSerial, "RSA", "1", ""});
    String caSerial = lastSerialOfType('C');
    check("CA created", caSerial != null);
    X509CertificateHolder ca = holder(Paths.get(tmp.toString(), "PKI", "CA", caSerial + ".crt"));
    BasicConstraints bc = BasicConstraints.getInstance(ca.getExtensions()
        .getExtensionParsedValue(Extension.basicConstraints));
    check("CA pathLen=1", bc != null && bc.isCA() && bc.getPathLenConstraint() != null
        && bc.getPathLenConstraint().intValue() == 1);
    System.out.println("  pathLenConstraint=" + (bc == null ? "null" : bc.getPathLenConstraint()));

    // 2) end-entity with checked policies DV + TSA (no EV)
    MakeCert.run(tmp.toString(), new String[]{"CN=www.test.com,O=MyOrg,C=CN", "2048", "sha256",
        "1", "", "0", "1", "www.test.com", "null", "null", caSerial, "RSA", "null", "2.23.140.1.2.1,2.23.140.1.4.2"});
    String eeSerial = lastSerialOfType('E');
    check("EE created", eeSerial != null);
    X509CertificateHolder ee = holder(Paths.get(tmp.toString(), "PKI", "CERT", eeSerial + ".crt"));
    CertificatePolicies cp = CertificatePolicies.getInstance(ee.getExtensions()
        .getExtensionParsedValue(Extension.certificatePolicies));
    Set<String> oids = policyOids(cp);
    System.out.println("  EE policy OIDs=" + oids);
    check("EE has base 4146.1.95", oids.contains("1.3.6.1.4.1.4146.1.95"));
    check("EE has DV 2.23.140.1.2.1", oids.contains("2.23.140.1.2.1"));
    check("EE has TSA 2.23.140.1.4.2", oids.contains("2.23.140.1.4.2"));
    check("EE NOT has EV 2.23.140.1.1", !oids.contains("2.23.140.1.1"));
    check("EE NOT has codeSign-EV 2.23.140.1.3", !oids.contains("2.23.140.1.3"));

    // 3) end-entity with no checked policy -> only base 4146.1.95
    MakeCert.run(tmp.toString(), new String[]{"CN=no-policy.test.com,O=MyOrg,C=CN", "2048", "sha256",
        "1", "", "0", "1", "null", "null", "null", caSerial, "RSA", "null", ""});
    String ee2Serial = lastSerialOfType('E');
    X509CertificateHolder ee2 = holder(Paths.get(tmp.toString(), "PKI", "CERT", ee2Serial + ".crt"));
    CertificatePolicies cp2 = CertificatePolicies.getInstance(ee2.getExtensions()
        .getExtensionParsedValue(Extension.certificatePolicies));
    Set<String> oids2 = policyOids(cp2);
    System.out.println("  EE2 policy OIDs=" + oids2);
    check("EE2 only base policy", oids2.size() == 1 && oids2.contains("1.3.6.1.4.1.4146.1.95"));

    // 4) CA with pathLen=null -> unrestricted
    MakeCert.run(tmp.toString(), new String[]{"CN=TestSubCA2,O=MyOrg,C=CN", "2048", "sha256",
        "99", "", "1", "1", "null", "null", "null", rootSerial, "RSA", "null", ""});
    String ca2Serial = lastSerialOfType('C');
    X509CertificateHolder ca2 = holder(Paths.get(tmp.toString(), "PKI", "CA", ca2Serial + ".crt"));
    BasicConstraints bc2 = BasicConstraints.getInstance(ca2.getExtensions()
        .getExtensionParsedValue(Extension.basicConstraints));
    check("CA2 pathLen=null (unrestricted)", bc2 != null && bc2.isCA()
        && bc2.getPathLenConstraint() == null);

    System.out.println(fails == 0 ? "SMOKE PASS (all checks)" : "SMOKE FAIL: " + fails + " checks");
    if (fails > 0) System.exit(1);
  }

  static Set<String> policyOids(CertificatePolicies cp) {
    Set<String> s = new LinkedHashSet<>();
    if (cp != null) for (PolicyInformation pi : cp.getPolicyInformation())
      s.add(pi.getPolicyIdentifier().getId());
    return s;
  }

  static X509CertificateHolder holder(Path pem) throws Exception {
    String pemText = new String(Files.readAllBytes(pem), StandardCharsets.US_ASCII);
    String b64 = pemText.replaceAll("-----BEGIN CERTIFICATE-----", "")
        .replaceAll("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
    return new X509CertificateHolder(Base64.getDecoder().decode(b64));
  }

  static String lastSerialOfType(char t) throws Exception {
    List<String> lines = Files.readAllLines(tmp.resolve("PKI/CERTS.txt"), StandardCharsets.UTF_8);
    for (int i = lines.size() - 1; i >= 0; i--) {
      String l = lines.get(i).trim();
      if (l.isEmpty() || l.startsWith("#")) continue;
      String[] p = l.split("\\s+");
      if (p.length >= 2 && p[1].length() == 1 && p[1].charAt(0) == t) return p[0];
    }
    return null;
  }

  static void setup() throws Exception {
    deleteRecursive(tmp);
    Files.createDirectories(tmp.resolve("PKI/ROOT"));
    Files.createDirectories(tmp.resolve("PKI/CA"));
    Files.createDirectories(tmp.resolve("PKI/CERT"));
    Files.createDirectories(tmp.resolve("PKI/KEY"));
    Files.createDirectories(tmp.resolve("PKI/WebPublic/CRT"));
    Files.copy(src.resolve("ROOT/" + rootSerial + ".crt"), tmp.resolve("PKI/ROOT/" + rootSerial + ".crt"));
    Files.copy(src.resolve("ROOT/" + rootSerial + ".key"), tmp.resolve("PKI/ROOT/" + rootSerial + ".key"));
    Files.write(tmp.resolve("PKI/CERTS.txt"), List.of(
        rootSerial + " R V 0 2026/09/23-20:43:53 " + rootSerial + " RSA-PSS"),
        StandardCharsets.UTF_8);
    Files.write(tmp.resolve("PKI/CONFIG.txt"), List.of(
        "WEBPORT=80", "SUPORT=8080", "OCSP=http://localhost:80/OCSP",
        "CRL=http://localhost:80/CRL/{CID}.crl", "CRT=http://localhost:80/CRT/{CID}.crt",
        "CPS=https://gitee.com/wxgshuju/modpkica", "CPS_Nonice=http://example.com/nonice"),
        StandardCharsets.UTF_8);
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
