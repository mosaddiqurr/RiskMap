"use client";

export default function PublicError({ reset }: { reset: () => void }) {
  return (
    <div className="page-container reading-container page-space" role="alert">
      <h1 className="text-3xl font-semibold">This page could not be loaded.</h1>
      <p className="mt-3 text-muted">Retry the request to continue.</p>
      <button
        className="mt-5 rounded-xl bg-brand px-4 py-2 font-semibold text-white"
        onClick={reset}
      >
        Try again
      </button>
    </div>
  );
}
