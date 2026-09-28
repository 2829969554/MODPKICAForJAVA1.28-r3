import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType0Font;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * 开发助手 PDF 生成器（pdfbox 3.0.4，中文渲染）。
 * 用法: java PdfGen <content.txt> <out.pdf>
 * 行前缀: # 一级标题 / ## 二级标题 / ### 三级标题 / - 列表项 / 其余正文。
 */
public class PdfGen {
    static PDDocument doc;
    static PDType0Font titleFont;   // simhei 黑体
    static PDType0Font bodyFont;    // simsunb 宋体
    static float pageW = PDRectangle.A4.getWidth();   // 595
    static float pageH = PDRectangle.A4.getHeight();  // 842
    static float margin = 46f;
    static float contentW = pageW - margin * 2;
    static float y;                   // 当前基线（从 pageH-margin 向下递减）
    static PDPageContentStream cs;
    static int pageNo = 0;
    static String coverTitle = "";

    public static void main(String[] args) throws Exception {
        String in = args[0], out = args[1];
        List<String> lines = Files.readAllLines(Paths.get(in), StandardCharsets.UTF_8);
        doc = new PDDocument();
        titleFont = PDType0Font.load(doc, new File("C:/Windows/Fonts/simhei.ttf"));
        bodyFont = PDType0Font.load(doc, new File("C:/Windows/Fonts/Deng.ttf"));

        newPage(false);
        // ---- 封面 ----
        coverTitle = "MODPKICA Java 复刻版 v1.28";
        String sub1 = "开发助手 · 源码分析";
        String sub2 = "2026-09-28";
        String sub3 = "基于 Java + BouncyCastle 1.85 离线构建";
        String sub4 = "作者：@魔帝本尊（QQ：2829969554）";
        drawCentered(titleFont, 22f, coverTitle, 300f);
        drawCentered(titleFont, 15f, sub1, 250f);
        drawCentered(bodyFont, 12f, sub2, 215f);
        drawCentered(bodyFont, 11f, sub3, 190f);
        drawCentered(bodyFont, 10.5f, sub4, 168f);
        String toc = "目录";
        drawCentered(titleFont, 14f, toc, 120f);
        drawCentered(bodyFont, 9.5f,
                "一、项目概述      二、源码结构总览      三、运行流程解析      四、关键常量与数据格式",
                96f);
        drawCentered(bodyFont, 9.5f,
                "五、v1.28 今日更新      六、构建与测试", 78f);

        // ---- 正文 ----
        boolean first = true;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            if (first && (line.startsWith("#") || line.startsWith("MODPKICA"))) {
                // 跳过封面标记行（内容文件前三行是封面，已在上面手工绘制）
                if (line.startsWith("#")) { first = false; newPage(true); continue; }
            }
            if (line.startsWith("# ")) { newPage(true); header(titleFont, 14.5f, line.substring(2), true); }
            else if (line.startsWith("## ")) { header(titleFont, 12.5f, line.substring(3), false); }
            else if (line.startsWith("### ")) { header(titleFont, 10.8f, line.substring(4), false); }
            else if (line.startsWith("- ")) { para(bodyFont, 9.5f, "\u2022 " + line.substring(2), 14f, 14f); }
            else { para(bodyFont, 9.5f, line, 14f, 0f); }
        }
        endPage();
        doc.save(out);
        doc.close();
        System.out.println("PDF written: " + out + "  pages=" + pageNo);
    }

    static void newPage(boolean body) {
        if (cs != null) endPage();
        PDPage page = new PDPage(PDRectangle.A4);
        doc.addPage(page);
        pageNo++;
        try {
            cs = new PDPageContentStream(doc, page);
            y = pageH - margin;
            // 页脚
            cs.beginText();
            cs.setFont(bodyFont, 8f);
            cs.newLineAtOffset(pageW / 2 - 14, 26);
            cs.showText("MODPKICA 开发助手 · 第 " + pageNo + " 页");
            cs.endText();
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    static void endPage() {
        try { cs.close(); } catch (IOException ignored) {}
        cs = null;
    }

    static void header(PDType0Font f, float size, String text, boolean pageBreakBefore) {
        ensure(24f);
        y -= 8f;
        drawText(f, size, text);
        y -= 10f;
        // 分隔线
        try {
            cs.setStrokingColor(0.35f, 0.45f, 0.65f);
            cs.moveTo(margin, y + 3);
            cs.lineTo(margin + contentW, y + 3);
            cs.stroke();
        } catch (IOException ignored) {}
        y -= 6f;
    }

    static void para(PDType0Font f, float size, String text, float leading, float indent) throws IOException {
        ensure(leading);
        float x = margin + indent;
        for (String l : wrap(text, f, size, contentW - indent)) {
            if (y - size < margin) { newPage(true); x = margin + indent; }
            drawTextAt(f, size, l, x);
            y -= leading;
        }
    }

    static void ensure(float need) {
        if (y - need < margin + 20f) newPage(true);
    }

    static void drawText(PDType0Font f, float size, String text) {
        drawTextAt(f, size, text, margin);
        y -= size * 1.15f;
    }

    static void drawTextAt(PDType0Font f, float size, String text, float x) {
        try {
            cs.beginText();
            cs.setFont(f, size);
            cs.newLineAtOffset(x, y - size);
            cs.showText(text);
            cs.endText();
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    static void drawCentered(PDType0Font f, float size, String text, float yPos) throws IOException {
        float w = f.getStringWidth(text) / 1000f * size;
        try {
            cs.beginText();
            cs.setFont(f, size);
            cs.newLineAtOffset((pageW - w) / 2, yPos);
            cs.showText(text);
            cs.endText();
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    /** 按宽度换行（支持全角字符）。 */
    static java.util.List<String> wrap(String text, PDType0Font f, float size, float maxW) throws IOException {
        java.util.List<String> out = new java.util.ArrayList<>();
        StringBuilder cur = new StringBuilder();
        float curW = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            String s = String.valueOf(c);
            float w = f.getStringWidth(s) / 1000f * size;
            if (curW + w > maxW && cur.length() > 0) {
                out.add(cur.toString());
                cur = new StringBuilder();
                curW = 0;
            }
            cur.append(c);
            curW += w;
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }
}
