/**
 * Parses a simple UTC schedule such as `02:00`, `02:00 UTC`, or
 * `Daily, 02:00–04:00 UTC`. A single time represents a one-hour window.
 */
export function parseUtcScanWindow(value: string | null | undefined) {
  if (!value) return null;
  const matches = [...value.matchAll(/(?:^|\D)([01]\d|2[0-3]):([0-5]\d)(?=\D|$)/g)];
  if (!matches.length) return null;
  const toMinutes = (match: RegExpMatchArray) => Number(match[1]) * 60 + Number(match[2]);
  const start = toMinutes(matches[0]!);
  const end = matches[1] ? toMinutes(matches[1]) : (start + 60) % 1440;
  return { start, end };
}

export function isWithinPreferredScanWindow(
  value: string | null | undefined,
  now = new Date()
) {
  const window = parseUtcScanWindow(value);
  if (!window) return false;
  const current = now.getUTCHours() * 60 + now.getUTCMinutes();
  if (window.start === window.end) return true;
  if (window.start < window.end) return current >= window.start && current < window.end;
  return current >= window.start || current < window.end;
}
