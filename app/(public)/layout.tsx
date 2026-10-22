import { MarketingFooter } from "@/components/marketing/footer";
import { MarketingHeader } from "@/components/marketing/header";
import { AnalysisProvider } from "@/components/analysis/analysis-provider";
import { PageMotion } from "@/components/marketing/site-motion";

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return (
    <AnalysisProvider>
      <div className="site-shell">
        <PageMotion />
        <MarketingHeader />
        <main id="main-content" tabIndex={-1}>
          {children}
        </main>
        <MarketingFooter />
      </div>
    </AnalysisProvider>
  );
}
