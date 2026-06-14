import js from "@eslint/js";
import tseslint from "typescript-eslint";
import functional from "eslint-plugin-functional";

export default tseslint.config(
  // 1. Global ignores
  { ignores: ["dist/", "node_modules/"] },

  // 2. Register the functional plugin for all files
  {
    plugins: { functional },
  },

  // 3. Base recommended configs (apply to all .ts files)
  //    Non-type-checked recommended (mirrors pre-purify behavior). The
  //    type-aware `functional/prefer-immutable-types` rule below uses
  //    `parserOptions.projectService` directly without pulling in the full
  //    recommendedTypeChecked bundle (which enables a swarm of `no-unsafe-*`
  //    rules not in scope here).
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // 4. Engine: strict — it's already pure, lock it in
  {
    files: ["bash-deny/engine.ts"],
    rules: {
      "functional/no-this-expressions": "error",
      "functional/prefer-immutable-types": [
        "warn",
        {
          // The plan's goal: public API parameters are Readonly. Internal
          // return types (unwrapCommand returns string[]) and internal
          // locals (splitCommands' let accumulators) are deferred per
          // plan §3.3 / §4 — out of scope for this lint check.
          enforcement: "ReadonlyShallow",
          ignoreInferredTypes: true,
          returnTypes: false,
          variables: false,
        },
      ],
    },
  },

  // 5. CLI: relax — the I/O shells and main legitimately hold mutable
  //    state (the stdin loop's let denied = false, file existence checks,
  //    etc.). The pure helpers (loadRulesPure, classify) live in this file
  //    too, but they're small enough that the noise of partial overrides
  //    isn't worth it — relax the whole file.
  {
    files: ["bash-deny/cli.ts"],
    rules: {
      "functional/no-this-expressions": "error",
      "functional/prefer-immutable-types": "off",
    },
  },

  // 6. Tests + scripts: permissive — they exist to exercise state
  {
    files: ["tests/**/*.ts", "scripts/**/*.ts"],
    rules: {
      "functional/no-this-expressions": "off",
      "functional/prefer-immutable-types": "off",
    },
  },
);
