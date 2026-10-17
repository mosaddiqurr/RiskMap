const dangerousPrefix = /^(?:[\t\r\n]|\s*[=+\-@])/;

export function sanitizeCsvCell(value: unknown) {
  const text = value == null ? "" : String(value);
  return dangerousPrefix.test(text) ? `'${text}` : text;
}

function quoteCsvCell(value: unknown) {
  const safe = sanitizeCsvCell(value);
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCsv(rows: Array<Record<string, unknown>>) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0] ?? {});
  return [
    headers.map(quoteCsvCell).join(","),
    ...rows.map((row) => headers.map((header) => quoteCsvCell(row[header])).join(","))
  ].join("\r\n");
}
