export function flattenTxtRecords(records: string[][]) {
  return records.map((record) => record.join(""));
}

export function matchesDnsVerification(records: string[][], expectedToken: string) {
  return flattenTxtRecords(records).some(
    (record) => record.trim() === expectedToken.trim()
  );
}

export function matchesFileVerification(body: string, expectedToken: string) {
  const expectedValue = expectedToken.replace(/^riskmap-verification=/, "").trim();
  const actual = body.trim();
  return actual === expectedToken.trim() || actual === expectedValue;
}
