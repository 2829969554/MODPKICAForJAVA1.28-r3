package modpkica;

import java.nio.file.*;
import java.util.List;

/** 冒烟：验证 CtLog MiniJson 解析（P2-12）不回归。 */
public final class TestCtLog {
    public static void main(String[] args) throws Exception {
        String base = args.length >= 1 ? args[0] : System.getProperty("modpkica.test.base");
        List<CtLog.LogKey> keys = CtLog.loadKeys(base);
        System.out.println("loadKeys count=" + keys.size());
        for (CtLog.LogKey k : keys) {
            System.out.println("  key: desc=" + k.description + " type=" + k.type
                    + " state=" + k.state + " hasPriv=" + (!k.privateKey.isEmpty())
                    + " logId=" + k.logId);
        }
        List<CtLog.PubLog> pubs = CtLog.loadPublicList(base);
        System.out.println("loadPublicList count=" + pubs.size());
        for (CtLog.PubLog p : pubs) {
            System.out.println("  pub: desc=" + p.description + " state=" + p.state
                    + " logIdHex=" + p.logIdHex + " url=" + p.url);
        }
        System.out.println("timestamp=" + CtLog.publicListTimestamp(base));
    }
}
