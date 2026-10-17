import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { buttonClass } from "@/components/ui/button";
export const metadata: Metadata = { title: "About & methodology" };

export default function AboutPage() {
  return (
    <div className="page-container reading-container page-space">
      <div className="page-heading">
        <p className="eyebrow">ABOUT RISKMAP</p>
        <h1>Priorities you can explain.</h1>
        <p>
          RiskMap answers one question: which security weakness should I fix first, and why?
        </p>
      </div>
      <section className="prose-section">
        <h2>From isolated findings to connected exposure</h2>
        <p>
          A severity label tells you about a finding. The exposure graph adds context: where
          it sits, how it connects to other assets and whether a potential path reaches a
          sensitive target. RiskMap keeps the supporting evidence alongside that context.
        </p>
      </section>
      <section className="prose-section">
        <h2>The graph model</h2>
        <p>
          The graph contains Internet entry points, assets, services, identities, findings
          and sensitive targets. Directed relationships carry evidence, confidence and an
          observed or inferred state. Public exposure must be explicitly supplied. Use{" "}
          <code>viaFindingId</code> for a transition that depends on a specific weakness;
          general relationships remain independent of fixes. Sensitive targets are assets
          marked CRITICAL or of type CRITICAL_ASSET.
        </p>
      </section>
      <section className="prose-section">
        <h2>How attack paths are found</h2>
        <p>
          A cycle-safe depth-first search begins at the Internet and follows directed
          relationships. A mapped path needs a finding, a meaningful exposure or service
          step, and a sensitive target. Search stops at eight nodes, 400 recorded paths or
          30,000 explored states. If a bound is reached, the results tell you the path set
          is incomplete.
        </p>
      </section>
      <section className="prose-section">
        <h2>Scoring philosophy</h2>
        <p>
          Path scores combine public entry, finding severity, asset criticality, service
          sensitivity and chain length. Inferred steps reduce the score; confidence adjusts
          the result. Finding scores also reflect explicit public exposure, supplied age and
          path involvement. Contributions are capped and weighted with diminishing returns.
          The 0–100 scores are relative prioritisation aids, never exploitation
          probabilities.
        </p>
        <p>
          Path labels use score thresholds: critical ≥80, high ≥60, medium ≥35, otherwise
          low. Finding severity is supplied separately.
        </p>
      </section>
      <section className="prose-section">
        <h2>Best Next Fix methodology</h2>
        <p>
          Each candidate finding is removed in memory together with its dependent
          transitions. Paths and finding scores are recalculated. Ranking weighs model score
          reduction, removed paths, the scores of affected paths, severity, asset
          importance, confidence and a rough category-based effort estimate. A tie follows
          the input order. The recommendation shows the action, evidence and qualitative
          benefit.
        </p>
        <p>
          The preview assumes successful remediation of that finding. It leaves general
          relationships and other weaknesses in place. The exact path counts describe
          changes in this model; they do not measure real-world risk reduction.
        </p>
      </section>
      <section className="prose-section">
        <h2>Data and security</h2>
        <p>
          A UTF-8 JSON dataset contains assets, services, findings and relationships. Strict
          validation checks references, IDs, field lengths and collection limits. The server
          handles at most 1 MiB per request. Analysis makes no network calls and writes no
          dataset to the database. Results stay in this tab’s memory until refresh or Clear
          analysis. The server receives uploaded evidence transiently; use a trusted local
          deployment for private data.
        </p>
        <p>
          Reports support JSON, formula-safe CSV, and a print layout you can save as PDF in
          your browser. No accounts, subscriptions, team assignments or background worker
          are needed.
        </p>
      </section>
      <section className="prose-section" id="limitations">
        <h2>Limitations</h2>
        <ul>
          <li>
            Supplied data can be incomplete, incorrect or stale. Confidence is an analyst
            input, not independent verification.
          </li>
          <li>
            A CVE reference does not prove exploitability; an open service does not
            establish a vulnerability.
          </li>
          <li>Potential attack paths do not establish that exploitation occurred.</li>
          <li>
            Finding removal is a model assumption. Validate actual access controls and
            reanalyze updated evidence after a real fix.
          </li>
          <li>
            Dense graphs may exceed search limits. Recommendations and counts then cover
            only the mapped subset.
          </li>
          <li>
            The global per-process request budget is intended for a local portfolio
            deployment. Public hosting needs infrastructure-level request and concurrency
            controls.
          </li>
        </ul>
      </section>
      <Link href="/analyze" className={buttonClass()}>
        Analyze exposure <ArrowRight size={16} />
      </Link>
    </div>
  );
}
