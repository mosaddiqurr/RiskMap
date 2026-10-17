import Image from "next/image";
import riskmapMark from "@/assets/riskmap-mark.png";

export function BrandLogo() {
  return (
    <span className="brand-lockup">
      <Image
        src={riskmapMark}
        className="brand-mark"
        alt=""
        width={44}
        height={Math.round((riskmapMark.height / riskmapMark.width) * 44)}
        unoptimized
        loading="eager"
      />
      <span>RiskMap</span>
    </span>
  );
}
