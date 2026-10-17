import { NextResponse } from "next/server";
import { parseDataset } from "@/lib/analysis/dataset";
import { analyzeDataset } from "@/lib/analysis/analyze";
import {
  AnalysisRequestError,
  readAnalysisRequest,
  analysisOriginAllowed,
  analysisResponseHeaders
} from "@/lib/analysis/request";
import { checkRateLimit } from "@/lib/services/rate-limit";

export const runtime = "nodejs";
export async function OPTIONS(request: Request) {
  try {
    if (!analysisOriginAllowed(request)) return new Response(null, { status: 403 });
    return new Response(null, {
      status: 204,
      headers: {
        ...analysisResponseHeaders(request),
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "600"
      }
    });
  } catch {
    return new Response(null, { status: 500 });
  }
}
export async function POST(request: Request) {
  let headers: Record<string, string> = { "Cache-Control": "no-store", Vary: "Origin" };
  try {
    headers = analysisResponseHeaders(request);
    if (!analysisOriginAllowed(request))
      throw new AnalysisRequestError(
        "Cross-origin analysis requests are not allowed.",
        403
      );
    // A bounded global budget avoids trusting spoofable forwarded IP headers.
    if (!checkRateLimit("stateless-analysis", 60, 60_000).allowed)
      return NextResponse.json(
        { error: "Analysis is at capacity. Try again in a minute." },
        { status: 429, headers: { ...headers, "Retry-After": "60" } }
      );
    const source = await readAnalysisRequest(request);
    let dataset;
    try {
      dataset = parseDataset(source);
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "Dataset is invalid." },
        { status: 422, headers }
      );
    }
    return NextResponse.json({ data: analyzeDataset(dataset) }, { headers });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof AnalysisRequestError
            ? error.message
            : "Analysis could not be completed. Try a smaller dataset."
      },
      {
        status: error instanceof AnalysisRequestError ? error.status : 500,
        headers
      }
    );
  }
}
