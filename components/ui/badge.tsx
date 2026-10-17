import { cn } from "@/lib/utils";

const tones = {
  slate: "border-slate-200 bg-slate-50 text-slate-700",
  blue: "border-blue-200 bg-blue-50 text-blue-700",
  green: "border-emerald-200 bg-emerald-50 text-emerald-700",
  amber: "border-amber-200 bg-amber-50 text-amber-800",
  red: "border-red-200 bg-red-50 text-red-700",
  purple: "border-violet-200 bg-violet-50 text-violet-700"
};

export function Badge({
  children,
  tone = "slate",
  className
}: {
  children: React.ReactNode;
  tone?: keyof typeof tones;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded border px-2 py-0.5 text-[11px] font-semibold",
        tones[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone =
    severity === "CRITICAL" || severity === "HIGH"
      ? "red"
      : severity === "MEDIUM"
        ? "amber"
        : severity === "LOW"
          ? "blue"
          : "slate";
  return <Badge tone={tone}>{severity.replaceAll("_", " ")}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "COMPLETED" ||
    status === "VERIFIED" ||
    status === "RESOLVED" ||
    status === "ACTIVE"
      ? "green"
      : status === "FAILED" || status === "FALSE_POSITIVE"
        ? "red"
        : status === "RUNNING" || status === "IN_PROGRESS"
          ? "blue"
          : status === "QUEUED" || status === "PENDING"
            ? "amber"
            : "slate";
  return <Badge tone={tone}>{status.replaceAll("_", " ")}</Badge>;
}
