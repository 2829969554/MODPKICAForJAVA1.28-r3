import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import org.bouncycastle.cert.ocsp.*;
import modpkica.*;

public class Sm2OcspGen {
    public static void main(String[] args) throws Exception {
        String base = "C:\\Users\\28299\\Desktop\\modpkica4JAVA\\PKI";
        String serialHex = "113549365";
        // 从 CERTS.txt 取 issuer/reason/time
        String issuerId = "1cdd33203a2ce", timeStr = "2026/09/10-21:53:19";
        int reason = 3;
        for (String line : Files.readAllLines(Paths.get(base, "CERTS.txt"), StandardCharsets.UTF_8)) {
            String[] p = line.trim().split("\\s+");
            if (p.length >= 6 && p[0].equalsIgnoreCase(serialHex)) {
                reason = Integer.parseInt(p[3]);
                timeStr = p[4];
                issuerId = p[5];
            }
        }
        System.out.println("issuer=" + issuerId + " reason=" + reason + " time=" + timeStr);

        // 颁发者证书：ROOT 优先，其次 CA
        Path issuerPath = Paths.get(base, "ROOT", issuerId + ".crt");
        if (!Files.exists(issuerPath)) issuerPath = Paths.get(base, "CA", issuerId + ".crt");
        System.out.println("issuer cert=" + issuerPath);
        X509Certificate issuerCert = PemIO.readCert(issuerPath.toString());

        // OCSP 响应者证书/密钥
        String ocspCertPath = base + "/OCSP/" + issuerId + "_ocsp.crt";
        String ocspKeyPath = ocspCertPath.replace(".crt", ".key");
        System.out.println("responder=" + ocspCertPath + " exists=" + Files.exists(Paths.get(ocspCertPath)));
        X509Certificate responderCert = PemIO.readCert(ocspCertPath);
        String keyType = PemIO.detectKeyType(ocspKeyPath);
        System.out.println("keyType=" + keyType);
        PrivateKey ocspKey = CertUtil.readJcaPrivateKey(ocspKeyPath);
        org.bouncycastle.crypto.params.ECPrivateKeyParameters sm2Priv =
                Sm2Util.toEcPrivateParams(ocspKey);

        Date revokedAt = java.sql.Timestamp.valueOf(
                LocalDateTime.parse(timeStr, DateTimeFormatter.ofPattern("yyyy/MM/dd-HH:mm:ss")));

        byte[] resp = OcspUtil.createResponse("SM2", issuerCert, responderCert,
                null, sm2Priv, new BigInteger(serialHex, 16), "1.3.14.3.2.26",
                OcspUtil.REVOKED, reason, revokedAt, null);
        Files.write(Paths.get("tmp_probe", "resp2.der"), resp);
        System.out.println("generated " + resp.length + " bytes -> tmp_probe/resp2.der");

        // BC 解析验证
        try {
            OCSPResp ocspResp = new OCSPResp(resp);
            BasicOCSPResp basic = (BasicOCSPResp) ocspResp.getResponseObject();
            SingleResp single = basic.getResponses()[0];
            Object st = single.getCertStatus();
            if (st instanceof RevokedStatus) {
                RevokedStatus rs = (RevokedStatus) st;
                System.out.println("BC PARSE OK: REVOKED time=" + rs.getRevocationTime()
                        + " reason=" + rs.getRevocationReason());
            } else {
                System.out.println("BC PARSE: status=" + st);
            }
        } catch (Throwable t) {
            System.out.println("BC PARSE FAILED: " + t);
            t.printStackTrace(System.out);
        }
    }
}
