import js from "@eslint/js";
import tseslint from "typescript-eslint";

/**
 * Flat ESLint config for the workspaces.
 *
 * Deliberately thin: `tsconfig.base.json` already turns on `strict`,
 * `noUnusedLocals`, `noUnusedParameters` and `noImplicitOverride`, so the
 * compiler is the primary gate and this file only adds what a type checker
 * cannot see. Rules duplicated from the compiler are worse than absent — they
 * report the same problem twice, in two formats, and drift apart.
 *
 * Only `api/` is linted today. `ui/` and `client/` are empty scaffolds; briefs
 * 08 and 09 add their own blocks here (the ui one needs the react-hooks plugin,
 * which is why the base config carries no `jsx` settings).
 *
 * @type {import('eslint').Linter.Config[]}
 */
export default [
  { ignores: ["**/dist/**", "**/node_modules/**"] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ["**/*.ts"],
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
