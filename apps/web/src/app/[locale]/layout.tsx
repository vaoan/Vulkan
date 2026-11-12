import { notFound } from "next/navigation";
import { hasLocale, NextIntlClientProvider } from "next-intl";

import "../globals.css";
import { routing } from "../../i18n/routing";
import { Header } from "../../shared/presentation/header";

/** The locales to prerender. @returns one params object per locale */
export function generateStaticParams(): { locale: string }[] {
  return routing.locales.map((locale) => ({ locale }));
}

/** The root layout: one document per locale, its language taken from the route. */
export default async function LocaleLayout({
  children,
  params,
}: {
  readonly children: React.ReactNode;
  readonly params: Promise<{ locale: string }>;
}): Promise<React.JSX.Element> {
  const { locale } = await params;
  if (!hasLocale(routing.locales, locale)) notFound();
  return (
    <html lang={locale}>
      <body>
        <NextIntlClientProvider>
          <Header />
          {children}
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
