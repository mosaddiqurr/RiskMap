import type { Metadata } from "next";
import { AnalysisReport } from "@/components/analysis/report";
export const metadata: Metadata = { title: "Report" };
export default function ReportPage() {
  return <AnalysisReport />;
}
