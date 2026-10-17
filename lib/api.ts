import { NextResponse } from "next/server";
import { ZodError } from "zod";
import { env } from "@/lib/env";
import { logger } from "@/lib/observability/logger";

export function ok<T>(data: T, init?: ResponseInit) {
  return NextResponse.json({ ok: true, data }, init);
}

export function fail(
  message: string,
  status = 400,
  code = "BAD_REQUEST",
  details?: unknown
) {
  return NextResponse.json({ ok: false, error: { code, message, details } }, { status });
}

export function apiError(error: unknown) {
  if (error instanceof ZodError) {
    const validationError = error as ZodError;
    return fail(
      "Please correct the highlighted fields.",
      422,
      "VALIDATION_ERROR",
      validationError.flatten()
    );
  }
  if (error instanceof Error) {
    if (error.message === "UNAUTHENTICATED")
      return fail("Please log in to continue.", 401, "UNAUTHENTICATED");
    if (error.message === "FORBIDDEN")
      return fail("You do not have permission to perform this action.", 403, "FORBIDDEN");
    if (error.message === "NOT_FOUND")
      return fail("The requested record was not found.", 404, "NOT_FOUND");
    if (error.message === "PLAN_LIMIT")
      return fail("Your current plan does not allow this action.", 403, "PLAN_LIMIT");
    if (error.message === "DOMAIN_NOT_VERIFIED")
      return fail(
        "Verify this domain before starting active checks.",
        409,
        "DOMAIN_NOT_VERIFIED"
      );
    if (error.message === "RATE_LIMITED")
      return fail("Too many requests. Please try again later.", 429, "RATE_LIMITED");
    if (error.message === "GLOBAL_RATE_LIMITED")
      return fail(
        "The scan service is currently at capacity. Please try again later.",
        429,
        "GLOBAL_RATE_LIMITED"
      );
    if (error.message === "INVITATION_EXPIRED")
      return fail("This invitation has expired.", 410, "INVITATION_EXPIRED");
  }
  logger.error("API request failed", { error });
  return fail("An unexpected error occurred.", 500, "INTERNAL_ERROR");
}

export function assertSameOrigin(request: Request) {
  const fetchSite = request.headers.get("sec-fetch-site")?.toLowerCase();
  if (fetchSite && !["same-origin", "same-site", "none"].includes(fetchSite)) {
    throw new Error("FORBIDDEN");
  }

  const origin = request.headers.get("origin");
  if (!origin) return;
  const expected = new URL(env.APP_URL).origin;
  if (origin !== expected) throw new Error("FORBIDDEN");
}
