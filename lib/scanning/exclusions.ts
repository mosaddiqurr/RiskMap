export function wildcardToRegExp(pattern: string) {
  const escaped = pattern
    .trim()
    .toLowerCase()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

export function matchesAnyExclusion(value: string, patterns: string[]) {
  const normalized = value.trim().toLowerCase();
  return patterns.some((pattern) => wildcardToRegExp(pattern).test(normalized));
}
