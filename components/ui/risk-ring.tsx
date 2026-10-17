export function RiskRing({ score, size = "lg" }: { score: number; size?: "sm" | "lg" }) {
  const dimensions = size === "lg" ? "h-36 w-36" : "h-20 w-20";
  const color =
    score >= 75 ? "#dc2626" : score >= 50 ? "#d97706" : score >= 25 ? "#2563eb" : "#059669";
  return (
    <div
      className={`relative ${dimensions} rounded-full p-2`}
      style={{ background: `conic-gradient(${color} ${score * 3.6}deg, #eef1f5 0deg)` }}
      aria-label={`Risk score ${score} out of 100`}
    >
      <div className="flex h-full w-full flex-col items-center justify-center rounded-full bg-white">
        <span
          className={size === "lg" ? "text-4xl font-semibold" : "text-2xl font-semibold"}
        >
          {score}
        </span>
        <span className="text-[10px] uppercase tracking-wide text-muted">out of 100</span>
      </div>
    </div>
  );
}
