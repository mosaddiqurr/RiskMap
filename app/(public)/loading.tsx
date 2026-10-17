export default function PublicLoading() {
  return (
    <div className="mx-auto max-w-5xl px-5 py-20" role="status" aria-live="polite">
      <div className="h-8 w-64 animate-pulse rounded bg-slate-200" />
      <span className="sr-only">Loading page</span>
    </div>
  );
}
