import { INPUT_LIMIT_BYTES } from "@/lib/analysis/dataset";

export class AnalysisRequestError extends Error {
  constructor(
    message: string,
    public status: number
  ) {
    super(message);
  }
}

export function analysisOriginAllowed(
  request: Request,
  configured = process.env.ANALYSIS_ALLOWED_ORIGINS ?? ""
) {
  const site = request.headers.get("sec-fetch-site");
  const origin = request.headers.get("origin");
  // Next's internal URL can use localhost while the browser uses 127.0.0.1.
  // Host is the browser's request authority; forwarded hosts are deliberately ignored.
  const requestUrl = new URL(request.url);
  const authority = (request.headers.get("host") ?? requestUrl.host).toLowerCase();
  const allowedOrigins = configured
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => {
      const url = new URL(value);
      if (
        url.origin !== value ||
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        (url.protocol === "http:" &&
          !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
      )
        throw new Error("Invalid analysis origin configuration.");
      return url.origin;
    });
  let sameOrigin = !origin && (!site || ["same-origin", "none"].includes(site));
  if (origin) {
    try {
      const supplied = new URL(origin);
      sameOrigin =
        supplied.origin === origin &&
        (allowedOrigins.length
          ? allowedOrigins.includes(origin)
          : supplied.host.toLowerCase() === authority &&
            supplied.protocol === requestUrl.protocol &&
            (!site || ["same-origin", "none"].includes(site)));
    } catch {
      sameOrigin = false;
    }
  }
  return sameOrigin;
}

export function analysisResponseHeaders(request: Request) {
  const headers: Record<string, string> = { "Cache-Control": "no-store", Vary: "Origin" };
  const origin = request.headers.get("origin");
  if (origin && analysisOriginAllowed(request))
    headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

export async function readAnalysisRequest(request: Request) {
  if (!analysisOriginAllowed(request))
    throw new AnalysisRequestError("Cross-origin analysis requests are not allowed.", 403);
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? ""))
    throw new AnalysisRequestError("Send an application/json dataset.", 415);
  const length = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(length) || length < 0 || length > INPUT_LIMIT_BYTES)
    throw new AnalysisRequestError("Dataset exceeds the 1 MiB limit.", 413);
  const reader = request.body?.getReader();
  if (!reader)
    throw new AnalysisRequestError("Choose a JSON dataset before analyzing.", 400);
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > INPUT_LIMIT_BYTES) {
        await reader.cancel();
        throw new AnalysisRequestError("Dataset exceeds the 1 MiB limit.", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new AnalysisRequestError("Dataset must use UTF-8 text.", 400);
  }
}
