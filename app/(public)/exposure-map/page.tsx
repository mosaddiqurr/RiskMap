import type { Metadata } from "next";
import { MapWorkspace } from "@/components/analysis/workspace";
export const metadata: Metadata = { title: "Exposure Map" };
export default function MapPage() {
  return <MapWorkspace />;
}
