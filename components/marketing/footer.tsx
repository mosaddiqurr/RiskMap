import Link from "next/link";

export function MarketingFooter() {
  return (
    <footer className="site-footer no-print">
      <div className="page-container footer-inner">
        <p>
          RiskMap <span>·</span> See what is exposed. Break the path.
        </p>
        <Link href="/about#limitations">Evidence, methodology & limitations</Link>
      </div>
    </footer>
  );
}
