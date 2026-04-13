import { Hono } from "hono";
import PDFDocument from "pdfkit";
import { Document, Packer, Paragraph, TextRun } from "docx";

const exportRoute = new Hono();

// ================= HELPER =================
function parseBoldText(text: string) {
  const parts = text.split(/(\*\*.*?\*\*)/g);

  return parts.map((part) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return {
        text: part.replace(/\*\*/g, ""),
        bold: true,
      };
    }
    return {
      text: part,
      bold: false,
    };
  });
}

// ================= ROUTE =================
exportRoute.post("/export", async (c) => {
  const { content, format } = await c.req.json();

  if (!content) {
    return c.text("No content provided", 400);
  }

  // ================= PDF =================
  if (format === "pdf") {
    const doc = new PDFDocument({
      margin: 50, // 🔥 margin biar rapi
    });
    doc.lineGap(2);
    const stream = new ReadableStream({
      start(controller) {
        doc.on("data", (chunk) => controller.enqueue(chunk));
        doc.on("end", () => controller.close());

        // ================= TITLE =================
        doc
          .font("Helvetica-Bold")
          .fontSize(16)
          .text("AI-Generated Analysis Report", {
            align: "center",
          });

        doc.moveDown(1.5);

        // ================= CONTENT =================
        content.split("\n").forEach((line: string) => {
          const trimmed = line.trim();

          // ================= EMPTY LINE =================
          if (!trimmed) {
            doc.moveDown(0.7);
            return;
          }

          // ================= SECTION TITLE =================
          if (
            trimmed.includes("EXECUTIVE SUMMARY") ||
            trimmed.includes("DETAILED ANALYSIS") ||
            trimmed.includes("THREAT LEVEL ASSESSMENT") ||
            trimmed.match(/^\d+\./)
          ) {
            doc.font("Helvetica-Bold").fontSize(13).text(trimmed, {
              lineGap: 4,
            });

            doc.moveDown(0.5);
            return;
          }

          // ================= SEPARATOR =================
          if (trimmed === "---") {
            doc.moveDown(1);
            return;
          }

          // ================= BULLET POINT =================
          if (trimmed.startsWith("-")) {
            doc.font("Helvetica").fontSize(10).text(trimmed, {
              indent: 15,
              lineGap: 3,
            });

            return;
          }

          // ================= NORMAL TEXT WITH BOLD =================
          const parts = parseBoldText(trimmed);

          parts.forEach((part, index) => {
            doc
              .font(part.bold ? "Helvetica-Bold" : "Helvetica")
              .fontSize(10)
              .text(part.text, {
                continued: index !== parts.length - 1,
                lineGap: 3,
              });
          });

          doc.moveDown(0.5);
        });

        doc.end();
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": "attachment; filename=cti_report.pdf",
      },
    });
  }

  // ================= DOCX =================
  if (format === "docx") {
    const doc = new Document({
      sections: [
        {
          children: content.split("\n").map((line: string) => {
            const parts = parseBoldText(line);

            return new Paragraph({
              spacing: { after: 200 }, // 🔥 spacing antar line
              children: parts.map(
                (part) =>
                  new TextRun({
                    text: part.text,
                    bold: part.bold,
                    size: 22, // font size
                  }),
              ),
            });
          }),
        },
      ],
    });

    const buffer = await Packer.toBuffer(doc);

    return new Response(new Uint8Array(buffer), {
      headers: {
        "Content-Type":
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "Content-Disposition": "attachment; filename=cti_report.docx",
      },
    });
  }

  return c.text("Invalid format", 400);
});

export default exportRoute;
