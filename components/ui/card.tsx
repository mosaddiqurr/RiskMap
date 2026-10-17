import { cn } from "@/lib/utils";

export function Card({
  className,
  children
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return <section className={cn("surface", className)}>{children}</section>;
}

export function CardHeader({
  className,
  title,
  description,
  action
}: {
  className?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex items-start justify-between gap-4 border-b border-line px-5 py-4",
        className
      )}
    >
      <div>
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {description ? (
          <p className="mt-1 text-sm leading-6 text-muted">{description}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

export function CardContent({
  className,
  children
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return <div className={cn("p-5", className)}>{children}</div>;
}
