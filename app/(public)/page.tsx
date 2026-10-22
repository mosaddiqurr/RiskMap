import Link from "next/link";
import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Braces,
  Check,
  FileSearch,
  GitBranch,
  LockKeyhole,
  Play,
  ShieldCheck,
  Workflow,
  Wrench
} from "lucide-react";
import { buttonClass } from "@/components/ui/button";
import { ExposurePreview } from "@/components/marketing/exposure-preview";
import { EvidenceExplorer } from "@/components/marketing/evidence-explorer";
import { SignalField } from "@/components/marketing/site-motion";
import { analyzeDataset, compareFix } from "@/lib/analysis/analyze";
import { demoDataset } from "@/lib/analysis/demo";

export default function Home() {
  const demo = analyzeDataset(demoDataset, new Date("2026-07-01T00:00:00Z"));
  const best = demo.recommendations[0]!;
  const comparison = compareFix(demo, best.findingId);
  return (
    <div className="home-page">
      <div className="hero-stage">
        <SignalField />
        <div className="hero-ambient" aria-hidden="true" />
        <div className="page-container home-container">
          <section className="home-hero">
            <div className="hero-copy">
              <p className="hero-eyebrow">
                <ShieldCheck size={14} /> Exposure & attack path analysis
              </p>
              <h1>
                Know what to
                <br />
                <span className="hero-title-accent">fix first.</span>
              </h1>
              <p className="hero-description">
                Connect the findings. See the attack paths.
                <br className="wide-break" /> Turn your security evidence into a clear next
                move.
              </p>
              <div className="hero-actions">
                <Link href="/analyze" className={buttonClass("primary", "lg")}>
                  Analyze exposure <ArrowUpRight size={17} />
                </Link>
                <Link href="/analyze?demo=1" className={buttonClass("secondary", "lg")}>
                  <Play size={13} fill="currentColor" /> Explore the demo
                </Link>
              </div>
              <p className="hero-note">
                <LockKeyhole size={12} /> Your evidence. Explainable priorities. No account
                required.
              </p>
            </div>
            <div className="hero-visual">
              <ExposurePreview result={demo} />
            </div>
          </section>
        </div>
      </div>
      <section
        className="page-container home-container product-section"
        aria-labelledby="product-title"
      >
        <div className="product-intro" data-reveal>
          <h2 id="product-title">
            A finding is only
            <br />
            <span>part of the story.</span>
          </h2>
          <p>
            The real question is what it connects to. RiskMap puts assets, identities, and
            weaknesses into context so you can act with confidence.
          </p>
        </div>
        <div className="product-grid">
          <article className="feature-evidence" data-reveal>
            <div className="feature-icon">
              <Workflow size={21} strokeWidth={1.5} />
            </div>
            <h3>
              See the connections.
              <br />
              Understand the exposure.
            </h3>
            <p>
              Follow potential paths from public entry points to sensitive assets, with
              evidence behind every step.
            </p>
            <EvidenceExplorer />
            <Link href="/about" className="feature-link">
              Explore the methodology <ArrowUpRight size={15} />
            </Link>
          </article>
          <article className="feature-impact" data-reveal data-delay="100">
            <div className="feature-icon">
              <Wrench size={21} strokeWidth={1.5} />
            </div>
            <h3>One fix. A meaningful difference.</h3>
            <p>
              Preview a recommendation before you act. See exactly which mapped paths it
              removes.
            </p>
            <div
              className="impact-visual"
              aria-label={`Demo remediation changes ${demo.paths.length} mapped paths to ${comparison.after.paths.length}`}
            >
              <div>
                <strong>{demo.paths.length.toString().padStart(2, "0")}</strong>
                <span>Before the fix</span>
              </div>
              <ArrowRight size={23} strokeWidth={1} />
              <div>
                <strong>{comparison.after.paths.length.toString().padStart(2, "0")}</strong>
                <span>After the fix</span>
              </div>
            </div>
            <p className="feature-caption">
              <ShieldCheck size={13} /> Northstar demo · Assumes full remediation
            </p>
          </article>
          <article className="feature-report" data-reveal data-delay="150">
            <div className="feature-report-copy">
              <div className="feature-icon">
                <FileSearch size={21} strokeWidth={1.5} />
              </div>
              <h3>Make the next decision clear.</h3>
              <p>
                Export the evidence, priorities, and next steps in JSON, CSV, or a
                print-ready report.
              </p>
            </div>
            <div className="report-formats" aria-label="Export formats">
              <span>
                <Braces size={16} /> JSON
              </span>
              <span>
                <FileSearch size={16} /> CSV
              </span>
              <span>
                <ArrowDownToLine size={16} /> PDF
              </span>
            </div>
          </article>
        </div>
      </section>
      <section
        className="page-container home-container workflow-section"
        aria-labelledby="workflow-title"
      >
        <div className="workflow-intro" data-reveal>
          <h2 id="workflow-title">
            From evidence to action.
            <br />
            <span>Without the complexity.</span>
          </h2>
          <p>A focused workflow. A decision you can explain.</p>
        </div>
        <div className="workflow-grid">
          {[
            {
              icon: FileSearch,
              title: "Bring your evidence",
              text: "Upload a JSON dataset of assets, services, findings, and relationships."
            },
            {
              icon: GitBranch,
              title: "Follow the paths",
              text: "Explore potential attack paths and inspect the evidence behind each connection."
            },
            {
              icon: Wrench,
              title: "Make your next move",
              text: "Preview the Best Next Fix and export a report that explains the decision."
            }
          ].map(({ icon: Icon, title, text }, i) => (
            <article key={title} className="workflow-item" data-reveal data-delay={i * 90}>
              <div className="workflow-step">
                <span>0{i + 1}</span>
                <Icon size={23} strokeWidth={1.4} />
              </div>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>
      <section className="page-container home-container home-cta-section">
        <div className="home-cta" data-reveal data-ambient>
          <div className="cta-orbit" aria-hidden="true">
            <div />
            <div />
            <div />
          </div>
          <ShieldCheck size={30} strokeWidth={1.3} />
          <h2>
            Your next security decision
            <br />
            starts with the full picture.
          </h2>
          <p>
            Explore a complete fictional scenario. See the evidence, follow the paths, and
            preview the fix.
          </p>
          <Link href="/analyze?demo=1" className={buttonClass("primary", "lg")}>
            See RiskMap in action <ArrowUpRight size={17} />
          </Link>
          <div className="cta-assurances">
            <span>
              <Check size={13} /> No account required
            </span>
            <span>
              <Check size={13} /> No network scanning
            </span>
          </div>
        </div>
      </section>
    </div>
  );
}
