"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { BrandLogo } from "@/components/marketing/brand-logo";

export function MarketingHeader() {
  const pathname = usePathname();
  const links = [
    ["/", "Home"],
    ["/analyze", "Analyze"],
    ["/exposure-map", "Exposure Map"],
    ["/report", "Report"],
    ["/about", "About"]
  ];
  return (
    <header className="site-header no-print">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <div className="page-container header-inner">
        <Link href="/" className="brand-link" aria-label="RiskMap home">
          <BrandLogo />
        </Link>
        <nav className="main-nav" aria-label="Main navigation">
          {links.map(([href, label]) => (
            <Link
              key={href}
              href={href!}
              aria-current={pathname === href ? "page" : undefined}
            >
              {label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  );
}
