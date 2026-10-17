import type { Metadata } from "next";
import { AnalyzeWorkspace } from "@/components/analysis/workspace";
export const metadata: Metadata = { title: "Analyze exposure" };
export default function AnalyzePage() {
  return <AnalyzeWorkspace />;
}
