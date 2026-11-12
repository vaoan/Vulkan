import { locale as routeLocale } from "next/root-params";
import { hasLocale } from "next-intl";
import { getRequestConfig } from "next-intl/server";

import { routing } from "./routing";

/** Resolves the request's locale from the route's root param and loads its messages. */
export default getRequestConfig(async () => {
  const requested = await routeLocale();
  const locale = hasLocale(routing.locales, requested) ? requested : routing.defaultLocale;
  const messages = (await import(`../../messages/${locale}.json`)) as { default: Record<string, unknown> };
  return { locale, messages: messages.default };
});
