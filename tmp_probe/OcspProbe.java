import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;

public class OcspProbe {
    public static void main(String[] args) throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String certFile = args.length > 0 ? args[0]
                : "C:\\Users\\28299\\Desktop\\modpkica4JAVA\\PKI\\WebPublic\\CRT\\113549365.crt";
        String url = args.length > 1 ? args[1] : "http://localhost:80/ocsp";
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert;
        try (FileInputStream fin = new FileInputStream(certFile)) {
            cert = (X509Certificate) cf.generateCertificate(fin);
        }
        System.out.println("cert subject=" + cert.getSubjectX500Principal()
                + " serial=" + cert.getSerialNumber().toString(16));

        // 与 CertVerify.buildOcspRequest 相同
        CertificateID cid = new CertificateID(
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                        .setProvider("BC").build()
                        .get(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"))),
                new JcaX509CertificateHolder(cert),
                cert.getSerialNumber());
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(cid);
        byte[] req = builder.build().getEncoded();
        System.out.println("request bytes=" + req.length);

        // POST
        HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/ocsp-request");
        conn.setRequestProperty("Accept", "application/ocsp-response");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(req);
        }
        int code = conn.getResponseCode();
        System.out.println("HTTP " + code);
        InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) bout.write(buf, 0, n);
        byte[] resp = bout.toByteArray();
        System.out.println("response bytes=" + resp.length);
        try (java.io.FileOutputStream fo = new java.io.FileOutputStream("tmp_probe/resp.der")) {
            fo.write(resp);
        }
        System.out.println("saved tmp_probe/resp.der");
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < Math.min(48, resp.length); i++) hex.append(String.format("%02x", resp[i] & 0xff));
        System.out.println("resp hex head=" + hex);

        try {
            OCSPResp ocspResp = new OCSPResp(resp);
            System.out.println("OCSPResp status=" + ocspResp.getStatus());
            Object obj = ocspResp.getResponseObject();
            System.out.println("responseObject class=" + obj.getClass().getName());
            BasicOCSPResp basic = (BasicOCSPResp) obj;
            System.out.println("basic responses=" + basic.getResponses().length
                    + " sigAlg=" + basic.getSignatureAlgorithmID().getAlgorithm().getId());
            SingleResp single = basic.getResponses()[0];
            Object st = single.getCertStatus();
            System.out.println("certStatus class=" + st.getClass().getName());
            if (st instanceof RevokedStatus) {
                RevokedStatus rs = (RevokedStatus) st;
                System.out.println("REVOKED time=" + rs.getRevocationTime()
                        + " reason=" + rs.getRevocationReason());
            } else if (st == CertificateStatus.GOOD) {
                System.out.println("GOOD");
            } else {
                System.out.println("status=" + st);
            }
        } catch (Throwable t) {
            System.out.println("PARSE FAILED: " + t);
            t.printStackTrace(System.out);
        }
    }
}
