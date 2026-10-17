import { NextResponse } from "next/server";
export function GET() {
  return NextResponse.json(
    { status: "ok", product: "RiskMap", mode: "stateless-analysis" },
    { headers: { "Cache-Control": "no-store" } }
  );
}
