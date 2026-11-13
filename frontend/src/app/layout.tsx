import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";

// IBM Plex: an engineering typeface with a clear monospace companion for IPs, IDs and hashes.
const plexSans = IBM_Plex_Sans({ subsets: ["latin"], variable: "--font-plex-sans" });
const plexMono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-plex-mono" });

export const metadata: Metadata = {
  title: "SOCVision",
  description: "Plateforme d'enrichissement et de qualification des alertes SOC",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr" className={`dark ${plexSans.variable} ${plexMono.variable}`}>
      <body className="bg-background text-foreground antialiased">
        <div className="flex h-screen overflow-hidden">
          {children}
        </div>
      </body>
    </html>
  );
}