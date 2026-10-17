import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";

export default tseslint.config(
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "coverage/**",
      "playwright-report/**",
      "test-results/**",
      ".runtime/**",
      "next-env.d.ts"
    ]
  },
  {
    files: ["**/*.ts", "**/*.tsx"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended]
  },
  {
    files: ["app/**/*.tsx", "components/**/*.tsx"],
    plugins: { "react-hooks": reactHooks, "jsx-a11y": jsxA11y },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      ...jsxA11y.configs.recommended.rules,
      "jsx-a11y/no-noninteractive-tabindex": ["error", { roles: ["tabpanel", "region"] }]
    }
  }
);
