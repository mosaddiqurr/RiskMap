import { cn } from "@/lib/utils";

export function Metric({
  label,
  value,
  detail,
  className
}: {
  label: string;
  value: string | number;
  detail?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("surface p-5", className)}>
      <p className="text-sm font-medium text-muted">{label}</p>
      <div className="mt-2 text-3xl font-semibold tracking-tight text-ink">{value}</div>
      {detail ? <div className="mt-2 text-xs text-muted">{detail}</div> : null}
    </div>
  );
}
