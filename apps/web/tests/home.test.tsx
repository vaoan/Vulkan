import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import HomePage from "../src/app/[locale]/page";

describe("HomePage", () => {
  it.each([
    ["es", "Vulkan, el punto de partida"],
    ["en", "Vulkan, the starting point"],
  ])("renders its title in %s", async (locale, title) => {
    render(await HomePage({ params: Promise.resolve({ locale }) }));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(title);
  });
});
