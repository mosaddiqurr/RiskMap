const baseURL = process.env.APP_URL || `http://127.0.0.1:${process.env.PORT || 3000}`;
try {
  const response = await fetch(new URL("/api/health", baseURL), {
    signal: AbortSignal.timeout(5000)
  });
  const payload = await response.json();
  if (!response.ok || payload.status !== "ok")
    throw new Error("Health endpoint did not report readiness.");
  console.log("RiskMap analysis server is ready.");
} catch (error) {
  console.error(error instanceof Error ? error.message : "RiskMap health check failed.");
  process.exitCode = 1;
}
