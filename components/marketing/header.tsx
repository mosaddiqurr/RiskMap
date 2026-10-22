"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { BrandLogo } from "@/components/marketing/brand-logo";

export function MarketingHeader() {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => {
    if (!menuOpen) return;
    const dismissMenu = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setMenuOpen(false);
      document.getElementById("navigation-toggle")?.focus();
    };
    document.addEventListener("keydown", dismissMenu);
    return () => document.removeEventListener("keydown", dismissMenu);
  }, [menuOpen]);
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
        <nav
          id="main-navigation"
          className={`main-nav ${menuOpen ? "is-open" : ""}`}
          aria-label="Main navigation"
        >
          {links.map(([href, label]) => (
            <Link
              key={href}
              href={href!}
              aria-current={pathname === href ? "page" : undefined}
              onClick={() => setMenuOpen(false)}
            >
              {label}
            </Link>
          ))}
        </nav>
        <div className="header-actions">
          <Link href="/analyze?demo=1" className="header-cta">
            Launch demo <ArrowUpRight size={15} />
          </Link>
          <button
            type="button"
            className="menu-toggle"
            id="navigation-toggle"
            aria-label={menuOpen ? "Close navigation" : "Open navigation"}
            aria-controls="main-navigation"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen(!menuOpen)}
          >
            {menuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>
    </header>
  );
}
