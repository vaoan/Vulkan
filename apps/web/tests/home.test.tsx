import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import HomePage from "../src/app/[locale]/page";
import { APP_NAME } from "../src/shared/config/app-name";

describe("HomePage", () => {
  it.each([
    ["es", "el punto de partida"],
    ["en", "the starting point"],
  ])("renders its title in %s", async (locale, tagline) => {
    render(await HomePage({ params: Promise.resolve({ locale }) }));
    const title = screen.getByRole("heading", { level: 1 }).textContent;
    expect(title).toContain(APP_NAME);
    expect(title).toContain(tagline);
  });
});
