import type { Metadata } from "next";
import "./globals.css";

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
    <html lang="fr" className="dark">
      <body className="bg-background text-foreground antialiased">
        <div className="flex h-screen overflow-hidden">
          {children}
        </div>
      </body>
    </html>
  );
}