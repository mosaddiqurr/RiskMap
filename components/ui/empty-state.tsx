import { CircleDashed } from "lucide-react";

export function EmptyState({
  title,
  description,
  action
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="surface flex min-h-56 flex-col items-center justify-center px-6 py-12 text-center">
      <div className="rounded-2xl bg-slate-100 p-3 text-slate-500">
        <CircleDashed size={22} />
      </div>
      <h2 className="mt-4 text-base font-semibold text-ink">{title}</h2>
      <p className="mt-2 max-w-md text-sm leading-6 text-muted">{description}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}
