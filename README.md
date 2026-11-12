# Vulkan

## Why tailwindcss is at the root

The class lint rules from `eslint-plugin-better-tailwindcss` resolve `tailwindcss` from the repository root and switch themselves off when it is missing there, so it is a root devDependency as well as the web app's.
