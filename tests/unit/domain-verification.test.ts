import { describe, expect, it } from "vitest";
import {
  flattenTxtRecords,
  matchesDnsVerification,
  matchesFileVerification
} from "@/lib/services/domain-verification";

describe("domain verification evidence", () => {
  const token = "riskmap-verification=abc123";

  it("joins split TXT fragments before comparison", () => {
    const records = [
      ["riskmap-verification=", "abc123"],
      ["v=spf1 ", "-all"]
    ];
    expect(flattenTxtRecords(records)).toContain(token);
    expect(matchesDnsVerification(records, token)).toBe(true);
  });

  it("accepts the full or value-only verification file", () => {
    expect(matchesFileVerification(`${token}\n`, token)).toBe(true);
    expect(matchesFileVerification("abc123\n", token)).toBe(true);
    expect(matchesFileVerification("wrong", token)).toBe(false);
  });
});
