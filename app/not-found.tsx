import Link from "next/link";
import { buttonClass } from "@/components/ui/button";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-[70vh] max-w-2xl flex-col items-center justify-center px-6 text-center">
      <p className="text-sm font-semibold uppercase tracking-[0.2em] text-brand">404</p>
      <h1 className="mt-3 text-3xl font-semibold tracking-tight text-ink">
        Page not found
      </h1>
      <p className="mt-3 max-w-md text-sm leading-6 text-muted">
        The requested RiskMap page does not exist or is no longer available.
      </p>
      <Link href="/" className={`${buttonClass()} mt-6`}>
        Return home
      </Link>
    </main>
  );
}
