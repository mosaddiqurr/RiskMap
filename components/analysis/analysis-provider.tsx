"use client";

import { createContext, useCallback, useContext, useRef, useState } from "react";
import type { AnalysisResult } from "@/lib/analysis/analyze";
import type { Dataset } from "@/lib/analysis/dataset";
import { demoDataset } from "@/lib/analysis/demo";
import { analysisApiUrl } from "@/lib/analysis/api-url";

type AnalysisContextValue = {
  result: AnalysisResult | null;
  busy: boolean;
  error: string;
  analyze: (dataset: Dataset) => Promise<boolean>;
  loadDemo: () => Promise<boolean>;
  clear: () => void;
};
const AnalysisContext = createContext<AnalysisContextValue | null>(null);

export function AnalysisProvider({ children }: { children: React.ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const active = useRef<AbortController | null>(null);
  const analyze = useCallback(async (dataset: Dataset) => {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError("");
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const response = await fetch(analysisApiUrl(), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dataset),
        signal: controller.signal
      });
      const payload = await response.json();
      if (!response.ok || !payload.data)
        throw new Error(payload.error ?? "Analysis could not be completed.");
      if (active.current === controller) {
        setResult(payload.data);
        return true;
      }
      return false;
    } catch (caught) {
      if (active.current === controller)
        setError(
          controller.signal.aborted
            ? "Analysis timed out. Try again with a smaller dataset."
            : caught instanceof Error
              ? caught.message
              : "Analysis could not be completed."
        );
      return false;
    } finally {
      clearTimeout(timeout);
      if (active.current === controller) {
        setBusy(false);
        active.current = null;
      }
    }
  }, []);
  const loadDemo = useCallback(() => analyze(demoDataset), [analyze]);
  function clear() {
    active.current?.abort();
    active.current = null;
    setResult(null);
    setError("");
    setBusy(false);
  }
  return (
    <AnalysisContext.Provider value={{ result, busy, error, analyze, loadDemo, clear }}>
      {children}
    </AnalysisContext.Provider>
  );
}
export function useAnalysis() {
  const value = useContext(AnalysisContext);
  if (!value) throw new Error("Analysis provider is missing.");
  return value;
}
