// Flat eslint config for the browser extension. Run via `npm run lint` in
// js/ (which invokes eslint from this directory so this config applies).
// Self-contained — no imports, since the extension has no node_modules.

export default [
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: {
        chrome: "readonly",
        window: "readonly",
        document: "readonly",
        console: "readonly",
        fetch: "readonly",
        URL: "readonly",
        Blob: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        crypto: "readonly",
        atob: "readonly",
        btoa: "readonly",
        alert: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
      "no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-unreachable": "error",
      "no-dupe-keys": "error",
      "no-dupe-args": "error",
      "no-fallthrough": "error",
      "no-redeclare": "error",
      "use-isnan": "error",
      "valid-typeof": "error",
      eqeqeq: ["error", "smart"],
      "no-var": "error",
      "prefer-const": "error",
    },
  },
];
