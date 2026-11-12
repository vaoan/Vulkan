# Vulkan

Vulkan is the starter every `vaoan` body is generated from: a thin Next.js and
Supabase monorepo of class `next-supabase-mono`. `themis init` creates a new
repository from it, so whatever lands here lands in every body made from it.

It is governed by Themis, the vaoan/Themis repository on GitHub. Lint, TypeScript and Prettier settings
come from the `@vaoan/themis` package; the files at the root only point at it.
Never copy a rule into this repository: a body adds data in `themis.config.mjs`
and its own rules in `eslint.local.mjs`, and it never loosens a shared rule.

## Layout

- `apps/web`: the Next.js app router app, one route segment per locale (`es`, `en`).
- `themis.config.mjs`: this body's data for the class configuration.

## Commands

```
pnpm install      install (pnpm and Node versions come from package.json)
pnpm dev          run the web app
pnpm build        build the web app
pnpm lint         eslint with the class configuration, zero warnings
pnpm typecheck    tsc over every app and package
pnpm test         vitest
pnpm test:db      database tests (a placeholder until Supabase is added)
pnpm themis <verb>  the Themis CLI (ci, hook, references, skills, ...)
```

## Rules

Path-scoped rules for agents will live in a rules folder under .claude once
there are rules to write; until then, this file is the rules.

## Git flow

`develop` is the default branch and takes `type/*` branches by squash; `main`
is the release line. PR titles are `type(scope): subject [GH-n]`. The git hooks
in `.husky/` and the checks in `.github/workflows/ci.yml` enforce both.
