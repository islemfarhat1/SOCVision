import { cn } from "@/lib/utils";

/** Product mark: a bracketed target, drawn rather than a stock shield icon. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={cn("h-6 w-6 text-primary", className)} aria-hidden>
      <path d="M3 8V3h5M16 3h5v5M21 16v5h-5M8 21H3v-5" fill="none" stroke="currentColor" strokeWidth="2" />
      <circle cx="12" cy="12" r="3" fill="currentColor" />
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("font-semibold tracking-tight text-foreground", className)}>
      SOC<span className="font-normal text-muted-foreground">Vision</span>
    </span>
  );
}
