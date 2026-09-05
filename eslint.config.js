import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

/**
 * Flat ESLint config for the workspaces.
 *
 * Deliberately thin: `tsconfig.base.json` already turns on `strict`,
 * `noUnusedLocals`, `noUnusedParameters` and `noImplicitOverride`, so the
 * compiler is the primary gate and this file only adds what a type checker
 * cannot see. Rules duplicated from the compiler are worse than absent — they
 * report the same problem twice, in two formats, and drift apart.
 *
 * All three workspaces are linted. That was not true for most of this build —
 * the root `lint` script globbed `api/src/**` alone, so `ui/` and `client/`
 * were never seen by it, and the only reason nothing rotted is that the agents
 * writing them ran eslint over their own files by hand. A gate that covers
 * less than it appears to is worse than no gate, so it covers everything now.
 *
 * @type {import('eslint').Linter.Config[]}
 */
export default [
  { ignores: ["**/dist/**", "**/node_modules/**"] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    /**
     * React rules for the UI, and they are not decoration.
     *
     * A React codebase linted without React rules is the shape this repo was in
     * until the UI landed. Newspapper's own config records why two of these
     * matter enough to be errors: `set-state-in-effect` and `refs` each hid
     * real findings there behind a config-level blanket.
     *
     * Worth knowing, and newspapper records this too: the rule is **not
     * exhaustive**. The compiler bails out silently on some components and
     * reports nothing inside them, so a clean run means "nothing found", not
     * "nothing there".
     */
    files: ["ui/src/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-hooks/set-state-in-effect": "error",
      "react-hooks/refs": "error",
    },
  },

  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parserOptions: { ecmaVersion: 2022, sourceType: "module" },
    },
    rules: {
      // A leading underscore is the estate's signal for "required by the
      // signature, deliberately unused" — the same convention newspapper uses.
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
];
