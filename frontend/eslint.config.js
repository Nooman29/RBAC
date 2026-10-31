import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      // Reported as warnings, not errors. The flagged code is ordinary, working React: resetting state when
      // the route or token changes, and a loading flag set before a fetch. Rewriting it adds risk for no
      // change in behaviour; new code should still avoid these patterns.
      'react-hooks/set-state-in-effect': 'warn',
      // Only affects hot reload during development (context files export a provider and its hook together).
      'react-refresh/only-export-components': 'warn',
    },
  },
])
