import { Hono } from "hono";
import PDFDocument from "pdfkit";
import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  AlignmentType,
  LevelFormat,
} from "docx";
import MarkdownIt from "markdown-it";

type Token = ReturnType<MarkdownIt["parse"]>[number];

const exportRoute = new Hono();
const md = new MarkdownIt();

// ================= TRANSFORM TABLE =================
function transformTableForExport(content: string): string {
  const lines = content.split("\n");
  const result: string[] = [];

  for (let line of lines) {
    if (line.trim().startsWith("|")) {
      const cells = line
        .split("|")
        .map((c) => c.trim())
        .filter(Boolean);

      // skip header & separator
      if (cells[0]?.toLowerCase() === "field" || cells[0]?.includes("---")) {
        continue;
      }

      // convert to key-value
      if (cells.length >= 2) {
        result.push(`${cells[0]}: ${cells[1]}`);
        continue;
      }
    }

    result.push(line);
  }

  return result.join("\n");
}

// ================= CLEAN INLINE CONTENT =================
// Converts markdown syntax to plain text for PDF/DOCX rendering
function cleanInlineContent(text: string): string {
  return (
    text
      // [label](url) → label: url
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1: $2")
      // hapus backtick
      .replace(/`([^`]+)`/g, "$1")
      // hapus bold **text**
      .replace(/\*\*(.*?)\*\*/g, "$1")
      // hapus italic *text*
      .replace(/\*(.*?)\*/g, "$1")
      // hapus underscore bold/italic __text__ dan _text_
      .replace(/__(.*?)__/g, "$1")
      .replace(/_(.*?)_/g, "$1")
      .trim()
  );
}

// ================= REMOVE DUPLICATE LINES =================
function removeDuplicateLines(text: string): string {
  const seen = new Set<string>();
  const result: string[] = [];

  for (let line of text.split("\n")) {
    // normalize untuk keperluan pengecekan duplikat
    const clean = line
      .replace(/^[•\-\*]\s*/, "") // hapus bullet
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1") // hapus markdown link → label saja
      .replace(/`/g, "") // hapus backtick
      .replace(/\*\*(.*?)\*\*/g, "$1") // hapus bold
      .replace(/\*(.*?)\*/g, "$1") // hapus italic
      .replace(/\s+/g, " ") // normalize spasi
      .trim()
      .toLowerCase();

    if (!clean) {
      result.push("");
      continue;
    }

    if (seen.has(clean)) continue;

    seen.add(clean);
    result.push(line);
  }

  return result.join("\n");
}

// ================= PARSE =================
function parseMarkdown(content: string): Token[] {
  return md.parse(content, {}) as Token[];
}

// ================= ROUTE =================
exportRoute.post("/export", async (c) => {
  const { content, format } = await c.req.json();

  if (!content) {
    return c.text("No content provided", 400);
  }

  // transform tabel ke key-value
  const transformed = transformTableForExport(content);

  // hapus duplikat
  const cleanContent = removeDuplicateLines(transformed);

  const tokens = parseMarkdown(cleanContent);

  // =========================================================
  // ========================== PDF ============================
  // =========================================================
  if (format === "pdf") {
    const doc = new PDFDocument({ margin: 50 });

    const stream = new ReadableStream({
      start(controller) {
        doc.on("data", (chunk) => controller.enqueue(chunk));
        doc.on("end", () => controller.close());

        // TITLE
        doc
          .font("Helvetica-Bold")
          .fontSize(16)
          .text("AI-Generated Analysis Report", { align: "center" });

        doc.moveDown(1.5);

        // RENDER TOKENS
        for (let i = 0; i < tokens.length; i++) {
          const token = tokens[i]!;

          // HEADING
          if (token.type === "heading_open") {
            const next = tokens[i + 1];
            if (!next) continue;

            if (next.type === "inline") {
              const size =
                token.tag === "h1" ? 16 : token.tag === "h2" ? 14 : 12;

              doc.moveDown(0.8);
              doc
                .font("Helvetica-Bold")
                .fontSize(size)
                .text(cleanInlineContent(next.content));
              doc.moveDown(0.3);

              i++; // skip inline token
            }
          }

          // PARAGRAPH
          else if (token.type === "paragraph_open") {
            const next = tokens[i + 1];
            if (!next) continue;

            if (next.type === "inline") {
              doc
                .font("Helvetica")
                .fontSize(10)
                .text(cleanInlineContent(next.content), {
                  lineGap: 3,
                });
              doc.moveDown(0.3);

              i++; // skip inline token
            }
          }

          // BULLET LIST ITEM
          else if (token.type === "list_item_open") {
            const next = tokens[i + 2];
            if (!next) continue;

            if (next.type === "inline") {
              doc
                .font("Helvetica")
                .fontSize(10)
                .text("• " + cleanInlineContent(next.content), {
                  lineGap: 2,
                });
              doc.moveDown(0.2);

              i += 2; // skip paragraph_open + inline token
            }
          }

          // HORIZONTAL RULE
          else if (token.type === "hr") {
            doc.moveDown(0.5);
            doc
              .moveTo(doc.x, doc.y)
              .lineTo(doc.page.width - 50, doc.y)
              .stroke();
            doc.moveDown(0.5);
          }
        }

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

  // =========================================================
  // ========================== DOCX ===========================
  // =========================================================
  if (format === "docx") {
    const children: Paragraph[] = [];

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]!;

      // HEADING
      if (token.type === "heading_open") {
        const next = tokens[i + 1];
        if (!next) continue;

        if (next.type === "inline") {
          const fontSize =
            token.tag === "h1" ? 32 : token.tag === "h2" ? 28 : 24;

          children.push(
            new Paragraph({
              spacing: { before: 300, after: 200 },
              children: [
                new TextRun({
                  text: cleanInlineContent(next.content),
                  bold: true,
                  size: fontSize,
                }),
              ],
            }),
          );

          i++; // skip inline token
        }
      }

      // PARAGRAPH
      else if (token.type === "paragraph_open") {
        const next = tokens[i + 1];
        if (!next) continue;

        if (next.type === "inline") {
          children.push(
            new Paragraph({
              spacing: { after: 150 },
              children: [
                new TextRun({
                  text: cleanInlineContent(next.content),
                  size: 22,
                }),
              ],
            }),
          );

          i++; // skip inline token
        }
      }

      // BULLET LIST ITEM
      else if (token.type === "list_item_open") {
        const next = tokens[i + 2];
        if (!next) continue;

        if (next.type === "inline") {
          children.push(
            new Paragraph({
              spacing: { after: 100 },
              numbering: { reference: "bullets", level: 0 },
              children: [
                new TextRun({
                  text: cleanInlineContent(next.content),
                  size: 22,
                }),
              ],
            }),
          );

          i += 2; // skip paragraph_open + inline token
        }
      }
    }

    const docx = new Document({
      numbering: {
        config: [
          {
            reference: "bullets",
            levels: [
              {
                level: 0,
                format: LevelFormat.BULLET,
                text: "•",
                alignment: AlignmentType.LEFT,
                style: {
                  paragraph: {
                    indent: { left: 720, hanging: 360 },
                  },
                },
              },
            ],
          },
        ],
      },
      sections: [
        {
          children,
        },
      ],
    });

    const buffer = await Packer.toBuffer(docx);

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
