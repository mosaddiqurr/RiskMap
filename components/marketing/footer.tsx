import Link from "next/link";
import { ArrowUpRight, ShieldCheck } from "lucide-react";
import { BrandLogo } from "@/components/marketing/brand-logo";

export function MarketingFooter() {
  return (
    <footer className="site-footer no-print">
      <div className="page-container footer-inner">
        <div className="footer-brand">
          <BrandLogo />
          <p>See what is exposed. Break the path.</p>
        </div>
        <div className="footer-links">
          <span className="footer-evidence">
            <ShieldCheck size={14} /> Built around your evidence
          </span>
          <Link href="/about#limitations">
            Methodology & limitations <ArrowUpRight size={13} />
          </Link>
        </div>
      </div>
    </footer>
  );
}
