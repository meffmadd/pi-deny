import js from "@eslint/js";
import tseslint from "typescript-eslint";
import functional from "eslint-plugin-functional";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/"] },

  {
    plugins: { functional },
  },

  js.configs.recommended,
  tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "prefer-const": "error",
      "no-param-reassign": "error",
      "no-var": "error",
      "functional/no-mixed-types": "error",
    },
  },

  {
    files: ["bash-deny/engine.ts"],
    rules: {
      "functional/no-this-expressions": "error",
      "functional/prefer-immutable-types": [
        "error",
        {
          enforcement: "ReadonlyShallow",
          ignoreInferredTypes: true,
          returnTypes: false,
          variables: false,
        },
      ],
    },
  },

  {
    files: ["bash-deny/cli.ts"],
    rules: {
      "functional/no-this-expressions": "error",
      "functional/prefer-immutable-types": "off",
    },
  },

  {
    files: ["tests/**/*.ts", "scripts/**/*.ts"],
    rules: {
      "functional/no-this-expressions": "off",
      "functional/prefer-immutable-types": "off",
    },
  },
);
