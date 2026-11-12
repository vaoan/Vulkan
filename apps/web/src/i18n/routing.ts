import { defineRouting } from "next-intl/routing";

/** The locales the app speaks; Spanish is the default. */
export const routing = defineRouting({ locales: ["es", "en"], defaultLocale: "es" });
