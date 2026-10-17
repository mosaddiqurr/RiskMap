import Link from "next/link";
import {
  ArrowRight,
  Check,
  GitBranch,
  FileSearch,
  Wrench,
  Database,
  Globe,
  KeyRound
} from "lucide-react";
import { buttonClass } from "@/components/ui/button";

export default function Home() {
  return (
    <div className="page-container home-container">
      <section className="home-hero">
        <div className="hero-copy">
          <p className="eyebrow">EXPOSURE & ATTACK PATH ANALYSIS</p>
          <h1>
            Know what to
            <br className="desktop-break" /> fix first.
          </h1>
          <p className="hero-description">
            See how security findings connect into attack paths and identify the fix that
            makes the biggest difference.
          </p>
          <div className="hero-actions">
            <Link href="/analyze" className={buttonClass()}>
              Analyze exposure <ArrowRight size={16} />
            </Link>
            <Link href="/analyze?demo=1" className={buttonClass("secondary")}>
              Explore the demo
            </Link>
          </div>
          <p className="hero-note">
            Your evidence. Explainable priorities. No account required.
          </p>
        </div>
        <div
          className="story-panel"
          aria-label="Illustrative attack path: Internet to web server, deployment identity and sensitive database"
        >
          <div className="story-heading">
            <span className="eyebrow">FROM EXPOSURE TO A DECISION</span>
            <span className="text-xs text-muted">Fictional scenario</span>
          </div>
          <div className="story-path">
            <div className="story-node">
              <Globe size={18} />
              <div>
                <strong>Internet</strong>
                <span>Public entry point</span>
              </div>
            </div>
            <div className="story-connector">
              <span>Public SSH</span>
            </div>
            <div className="story-node">
              <FileSearch size={18} />
              <div>
                <strong>WEB-01</strong>
                <span>Administrative exposure</span>
              </div>
            </div>
            <div className="story-connector">
              <span>Potential identity access</span>
            </div>
            <div className="story-node">
              <KeyRound size={18} />
              <div>
                <strong>SVC-DEPLOY</strong>
                <span>Excessive privileges</span>
              </div>
            </div>
            <div className="story-connector">
              <span>Customer data access</span>
            </div>
            <div className="story-node story-target">
              <Database size={18} />
              <div>
                <strong>DB-01</strong>
                <span>Sensitive database</span>
              </div>
            </div>
          </div>
          <div className="story-fix">
            <Wrench size={18} />
            <div>
              <p className="eyebrow">BEST NEXT FIX</p>
              <strong>Restrict public SSH on WEB-01</strong>
              <p>Remove an entry into the deployment account path.</p>
            </div>
          </div>
        </div>
      </section>
      <section className="workflow-section" aria-labelledby="workflow-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">ONE FOCUSED WORKFLOW</p>
            <h2 id="workflow-title">Turn findings into a clear next action.</h2>
          </div>
          <span className="text-sm text-muted">Built around the evidence you provide</span>
        </div>
        <div className="workflow-grid">
          {[
            {
              icon: FileSearch,
              title: "Assets + findings",
              text: "Upload a structured dataset with assets, services, findings and relationships."
            },
            {
              icon: GitBranch,
              title: "Attack paths",
              text: "Trace potential exposure chains and inspect the evidence behind every step."
            },
            {
              icon: Wrench,
              title: "Best Next Fix",
              text: "Compare remediation opportunities and export a decision-focused report."
            }
          ].map(({ icon: Icon, title, text }, i) => (
            <article key={title} className="workflow-item">
              <div className="workflow-number">
                <Icon size={19} />
                <span>0{i + 1}</span>
              </div>
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>
      <div className="home-trust">
        {[
          "Evidence attached to every path",
          "Observed and inferred steps distinguished",
          "Scores explained, assumptions visible"
        ].map((s) => (
          <p key={s}>
            <Check size={15} />
            {s}
          </p>
        ))}
      </div>
    </div>
  );
}
