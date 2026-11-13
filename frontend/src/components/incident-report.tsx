"use client";

import { Children, isValidElement, useRef, type ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import { AlertTriangle, Download, Printer } from "lucide-react";
import { formatTicketId, type IncidentReport } from "@/lib/api";
import { parseDate } from "@/lib/time";

export type ReportIncident = {
  ticketId: string;
  title: string;
  severity?: string | null;
  status?: string | null;
  assignee?: string | null;
};

const STATUS_LABELS: Record<string, string> = { OPEN: "Open", IN_PROGRESS: "In progress", CLOSED: "Closed" };

/**
 * Models often wrap the report in ```markdown ... ``` (rendered as a code block).
 * Remove that wrapper, even when the closing fence is missing.
 */
export function stripCodeFence(text: string): string {
  const full = text.match(/^\s*```[a-zA-Z]*[ \t]*\r?\n([\s\S]*?)\r?\n?```\s*$/);
  if (full) return full[1].trim();
  return text.replace(/^\s*```(?:markdown|md)?[ \t]*\r?\n/i, "").trim();
}

/** Clean the generated Markdown for display: no fence, no duplicated "# Incident Report" title. */
function prepareMarkdown(content: string): string {
  return stripCodeFence(content).replace(/^\s*#\s+[^\n]*\n+/, "");
}

/** "1. Incident Summary" -> "Incident Summary" (sections are numbered by CSS). */
function cleanHeading(text: string): string {
  return text.replace(/[*_`]/g, "").replace(/^\s*\d+[.)]\s*/, "").trim();
}

function slugify(text: string): string {
  return "sec-" + cleanHeading(text).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function textOf(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textOf).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return textOf(node.props.children);
  return "";
}

function formatDate(value?: string | null): string {
  const d = parseDate(value);
  return d ? d.toLocaleString() : value ?? "—";
}

const markdownComponents: Components = {
  h2: ({ children }) => {
    const text = textOf(children);
    return <h2 id={slugify(text)}>{cleanHeading(text)}</h2>;
  },
  // "**Label**: value" list items become a two-column row.
  li: ({ children }) => {
    const items = Children.toArray(children);
    const [first, second, ...rest] = items;
    if (
      isValidElement(first) &&
      first.type === "strong" &&
      typeof second === "string" &&
      second.trimStart().startsWith(":")
    ) {
      const value = [second.replace(/^\s*:\s*/, ""), ...rest];
      return (
        <li className="kv">
          <span className="kv-label">{textOf(first)}</span>
          <span className="kv-value">{value}</span>
        </li>
      );
    }
    // "**Label:** value" variant
    if (isValidElement(first) && first.type === "strong" && textOf(first).trim().endsWith(":")) {
      return (
        <li className="kv">
          <span className="kv-label">{textOf(first).trim().replace(/:$/, "")}</span>
          <span className="kv-value">{[typeof second === "string" ? second.trimStart() : second, ...rest]}</span>
        </li>
      );
    }
    return <li>{children}</li>;
  },
};

export function IncidentReportDocument({ report, incident }: { report: IncidentReport; incident: ReportIncident }) {
  const docRef = useRef<HTMLDivElement>(null);
  const markdown = prepareMarkdown(report.content);
  const sections = [...markdown.matchAll(/^##\s+(.+)$/gm)].map((m) => ({
    id: slugify(m[1]),
    label: cleanHeading(m[1]),
  }));
  const ticketLabel = formatTicketId(incident.ticketId);

  const download = () => {
    const blob = new Blob([stripCodeFence(report.content)], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${ticketLabel}-report-v${report.version}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Print in a separate light, A4-friendly page so the app layout never interferes.
  // The HTML comes from react-markdown + rehype-sanitize, so it is already sanitised.
  const print = () => {
    if (!docRef.current) return;
    const win = window.open("", "_blank", "width=900,height=1000");
    if (!win) return;
    const title = `${ticketLabel} incident report v${report.version}`.replace(/[<>&"]/g, "");
    win.document.write(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title}</title>` +
        `<style>${PRINT_CSS}</style></head><body>${docRef.current.outerHTML}</body></html>`
    );
    win.document.close();
    win.focus();
    // Let the new window lay out the document once before opening the print dialog.
    setTimeout(() => win.print(), 300);
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[1fr_220px] gap-6 items-start">
      <div className="space-y-3 min-w-0">
        <div className="flex flex-wrap justify-end gap-2">
          <button
            onClick={download}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-muted"
          >
            <Download className="h-4 w-4" />
            Download .md
          </button>
          <button
            onClick={print}
            className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-muted"
          >
            <Printer className="h-4 w-4" />
            Print / Save as PDF
          </button>
        </div>

        <div ref={docRef} className="report-doc">
          <header className="report-doc-header">
            <p className="report-eyebrow">Incident report</p>
            <h1>{incident.title}</h1>
            <dl className="report-meta">
              <div>
                <dt>Incident</dt>
                <dd className="mono">{ticketLabel}</dd>
              </div>
              {incident.severity && (
                <div>
                  <dt>Severity</dt>
                  <dd>
                    <span className={`report-sev sev-${incident.severity.toLowerCase()}`}>{incident.severity}</span>
                  </dd>
                </div>
              )}
              {incident.status && (
                <div>
                  <dt>Status</dt>
                  <dd>{STATUS_LABELS[incident.status] ?? incident.status}</dd>
                </div>
              )}
              {incident.assignee && (
                <div>
                  <dt>Investigator</dt>
                  <dd>{incident.assignee}</dd>
                </div>
              )}
              <div>
                <dt>Version</dt>
                <dd>{report.version}</dd>
              </div>
              <div>
                <dt>Generated</dt>
                <dd>
                  {formatDate(report.generated_at)} · {report.generated_by}
                </dd>
              </div>
            </dl>
          </header>

          <aside className="report-disclaimer" role="note">
            <AlertTriangle aria-hidden className="report-disclaimer-icon" />
            <p>
              <strong>AI-generated draft.</strong> Check every fact against the evidence before sharing it. An analyst
              stays responsible for the final report.
            </p>
          </aside>

          <div className="report-body">
            <ReactMarkdown rehypePlugins={[rehypeSanitize]} components={markdownComponents}>
              {markdown}
            </ReactMarkdown>
          </div>

          <footer className="report-footer">
            SOCVision · {ticketLabel} · report v{report.version} · AI-assisted draft
          </footer>
        </div>
      </div>

      {sections.length > 2 && (
        <nav aria-label="Report contents" className="hidden xl:block sticky top-4 text-sm">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">Contents</p>
          <ol className="space-y-1">
            {sections.map((s, i) => (
              <li key={s.id}>
                <a
                  href={`#${s.id}`}
                  className="flex gap-2 py-1 text-muted-foreground hover:text-foreground"
                >
                  <span className="tabular-nums w-5 text-right shrink-0">{i + 1}</span>
                  <span>{s.label}</span>
                </a>
              </li>
            ))}
          </ol>
        </nav>
      )}
    </div>
  );
}

/** Stand-alone stylesheet for the print window (light, A4). Mirrors .report-doc in globals.css. */
const PRINT_CSS = `
@page { size: A4; margin: 18mm 16mm; }
* { box-sizing: border-box; }
body { margin: 0; font-family: "Segoe UI", system-ui, -apple-system, sans-serif; color: #111827; background: #fff;
  font-size: 10.5pt; line-height: 1.6; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.report-doc { max-width: 760px; margin: 0 auto; counter-reset: section; }
.report-doc-header { border-bottom: 2px solid #111827; padding-bottom: 14px; margin-bottom: 16px; }
.report-eyebrow { margin: 0; font-size: 8.5pt; letter-spacing: .12em; text-transform: uppercase; color: #6b7280; font-weight: 600; }
.report-doc h1 { margin: 4px 0 14px; font-size: 18pt; line-height: 1.25; }
.report-meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px 20px; margin: 0; }
.report-meta dt { font-size: 8pt; text-transform: uppercase; letter-spacing: .06em; color: #6b7280; }
.report-meta dd { margin: 2px 0 0; font-weight: 600; }
.mono { font-family: Consolas, "Courier New", monospace; }
.report-sev { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 8.5pt; border: 1px solid; }
.sev-critical { color: #b91c1c; border-color: #b91c1c; } .sev-high { color: #c2410c; border-color: #c2410c; }
.sev-medium { color: #a16207; border-color: #a16207; } .sev-low { color: #475569; border-color: #475569; }
.report-disclaimer { display: flex; gap: 8px; padding: 8px 12px; border: 1px solid #f59e0b; background: #fffbeb; border-radius: 6px; font-size: 9pt; }
.report-disclaimer p { margin: 0; }
.report-disclaimer-icon { width: 14px; height: 14px; flex: none; margin-top: 2px; color: #b45309; }
.report-body h2 { counter-increment: section; font-size: 12.5pt; margin: 22px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #d1d5db; break-after: avoid; }
.report-body h2::before { content: counter(section) ". "; color: #6b7280; }
.report-body h3 { font-size: 10.5pt; margin: 14px 0 6px; break-after: avoid; }
.report-body p { margin: 6px 0; }
.report-body ul, .report-body ol { margin: 6px 0; padding-left: 18px; }
.report-body ul:has(> li.kv) { list-style: none; padding: 0; border: 1px solid #e5e7eb; border-radius: 6px; }
.report-body li.kv { display: grid; grid-template-columns: 34% 1fr; gap: 12px; padding: 5px 10px; border-top: 1px solid #e5e7eb; break-inside: avoid; }
.report-body li.kv:first-child { border-top: 0; }
.kv-label { color: #4b5563; font-weight: 600; }
.report-body code { font-family: Consolas, monospace; font-size: 9pt; background: #f3f4f6; padding: 0 3px; border-radius: 3px; }
.report-body table { width: 100%; border-collapse: collapse; } .report-body th, .report-body td { border: 1px solid #d1d5db; padding: 4px 6px; text-align: left; }
.report-footer { margin-top: 24px; padding-top: 8px; border-top: 1px solid #d1d5db; font-size: 8pt; color: #6b7280; }
`;
