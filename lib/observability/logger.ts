import { env } from "@/lib/env";

type LogLevel = "debug" | "info" | "warn" | "error";
type LogFields = Record<string, unknown>;

const levelOrder: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

function serialiseError(error: unknown) {
  if (!(error instanceof Error)) return error;
  return {
    name: error.name,
    message: error.message,
    stack: env.NODE_ENV === "development" ? error.stack : undefined
  };
}

export function log(level: LogLevel, message: string, fields: LogFields = {}) {
  if (levelOrder[level] < levelOrder[env.LOG_LEVEL]) return;
  const payload = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...Object.fromEntries(
      Object.entries(fields).map(([key, value]) => [key, serialiseError(value)])
    )
  });
  if (level === "error") console.error(payload);
  else if (level === "warn") console.warn(payload);
  else console.log(payload);
}

export const logger = {
  debug: (message: string, fields?: LogFields) => log("debug", message, fields),
  info: (message: string, fields?: LogFields) => log("info", message, fields),
  warn: (message: string, fields?: LogFields) => log("warn", message, fields),
  error: (message: string, fields?: LogFields) => log("error", message, fields)
};
