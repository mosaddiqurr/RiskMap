export function analysisApiUrl(base = process.env.NEXT_PUBLIC_API_BASE_URL ?? "") {
  if (!base) return "/api/analyze";
  const url = new URL(base);
  if (
    url.origin !== base ||
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    (url.protocol === "http:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
  )
    throw new Error(
      "API base URL must be an HTTPS origin (or HTTP loopback for local testing)."
    );
  return `${base}/api/analyze`;
}
