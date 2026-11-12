import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import en from "../messages/en.json";
import es from "../messages/es.json";
import proxy from "../src/proxy";

const keysOf = (value: unknown, prefix = ""): string[] =>
  typeof value === "object" && value !== null
    ? Object.entries(value).flatMap(([key, child]) => keysOf(child, `${prefix}${key}.`))
    : [prefix];

describe("messages", () => {
  it("have the same keys in Spanish and English", () => {
    expect(keysOf(es).sort()).toEqual(keysOf(en).sort());
  });
});

describe("proxy", () => {
  it("redirects / to the default locale, es", () => {
    const response = proxy(new NextRequest("http://localhost/"));
    expect(response.status).toBe(307);
    expect(new URL(response.headers.get("location") ?? "").pathname).toBe("/es");
  });

  it("serves /en as English without redirecting", () => {
    const response = proxy(new NextRequest("http://localhost/en"));
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("x-middleware-request-x-next-intl-locale")).toBe("en");
  });
});
