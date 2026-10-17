import type { Metadata } from "next";
import branding from "@/assets/branding.json";
import "./globals.css";
import "@xyflow/react/dist/style.css";

const brandingVersion = branding.version;

export const metadata: Metadata = {
  title: { default: "RiskMap", template: "%s | RiskMap" },
  description:
    "Connect security findings into potential attack paths and identify the Best Next Fix with evidence-based exposure analysis.",
  icons: {
    icon: [
      { url: `/favicon.ico?v=${brandingVersion}`, sizes: "16x16 32x32 48x48" },
      {
        url: `/favicon-32x32.png?v=${brandingVersion}`,
        type: "image/png",
        sizes: "32x32"
      },
      { url: `/favicon.svg?v=${brandingVersion}`, type: "image/svg+xml", sizes: "any" }
    ],
    apple: {
      url: `/apple-touch-icon.png?v=${brandingVersion}`,
      type: "image/png",
      sizes: "180x180"
    }
  },
  robots: { index: false, follow: false }
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
