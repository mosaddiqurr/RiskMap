import { cn } from "@/lib/utils";

const tones = {
  slate: "badge-slate",
  blue: "badge-blue",
  green: "badge-green",
  amber: "badge-amber",
  red: "badge-red",
  purple: "badge-purple"
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
        "ui-badge inline-flex shrink-0 items-center rounded border px-2 py-0.5 font-semibold",
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
