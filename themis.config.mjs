export default {
  class: "next-supabase-mono",
  workspacePackages: [],
  floatingPeers: [],
  tailwind: { entryPoint: "apps/web/src/app/globals.css" },
  boundaries: {
    elements: [{ type: "i18n", pattern: "apps/*/src/i18n" }],
    allow: [{ from: { type: ["app", "proxy"] }, allow: { to: { type: "i18n" } } }],
  },
  // The proxy matcher must be a static literal for Next to read it; excluded words are regular expressions.
  i18n: { excludedWords: [String.raw`^/\(\(\?!api\|.*\)\.\*\)$`] },
  spelling: ["vulkan"],
};
