import { render, screen } from "@testing-library/react";
import { NextIntlClientProvider } from "next-intl";
import { describe, expect, it } from "vitest";
import en from "../messages/en.json";
import es from "../messages/es.json";
import { Home } from "../src/app/[locale]/home";
import { APP_NAME } from "../src/shared/config/app-name";

describe("Home", () => {
  it.each([
    ["es", es, "el punto de partida"],
    ["en", en, "the starting point"],
  ])("renders its title in %s", (locale, messages, tagline) => {
    render(
      <NextIntlClientProvider locale={locale} messages={messages}>
        <Home />
      </NextIntlClientProvider>,
    );
    const title = screen.getByRole("heading", { level: 1 }).textContent;
    expect(title).toContain(APP_NAME);
    expect(title).toContain(tagline);
  });
});
