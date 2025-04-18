// eslint.config.mjs
import globals from 'globals';
import typescriptParser from '@typescript-eslint/parser';
import typescriptPlugin from '@typescript-eslint/eslint-plugin';
import promisePlugin from 'eslint-plugin-promise';
import importPlugin from 'eslint-plugin-import';
import sonarjsPlugin from 'eslint-plugin-sonarjs';
import securityPlugin from 'eslint-plugin-security';

export default [
    {
        files: ['**/*.ts', '**/*.tsx'],
        ignores: ['dist/**', '**/*.d.ts', 'node_modules/**', 'coverage/**'],
        languageOptions: {
            globals: {
                ...globals.node, // Node.js global variables
                ...globals.es2022, // Updated to ES2022 to match tsconfig
                ...globals.browser // Browser environment variables
            },
            parser: typescriptParser,
            parserOptions: {
                project: true, // Automatically find tsconfig.json
                tsconfigRootDir: import.meta.dirname,
                ecmaVersion: 2022,
                sourceType: 'module'
            }
        },
        plugins: {
            '@typescript-eslint': typescriptPlugin,
            promise: promisePlugin,
            import: importPlugin,
            sonarjs: sonarjsPlugin,
            security: securityPlugin
        },
        rules: {
            // --- TypeScript Rules ---
            ...typescriptPlugin.configs.recommended.rules,
            ...typescriptPlugin.configs['recommended-requiring-type-checking'].rules,
            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/consistent-type-exports': 'error',
            '@typescript-eslint/no-unused-vars': [
                'warn',
                {
                    argsIgnorePattern: '^_',
                    varsIgnorePattern: '^_'
                }
            ],
            '@typescript-eslint/no-explicit-any': 'warn',
            '@typescript-eslint/ban-ts-comment': [
                'warn',
                {
                    'ts-ignore': 'allow-with-description'
                }
            ],
            '@typescript-eslint/await-thenable': 'error',
            '@typescript-eslint/no-floating-promises': 'error',
            '@typescript-eslint/explicit-function-return-type': [
                'warn',
                {
                    allowExpressions: true
                }
            ],

            // --- Import Rules ---
            ...importPlugin.configs.recommended.rules,
            'import/order': [
                'error',
                {
                    groups: ['builtin', 'external', 'internal', ['parent', 'sibling'], 'index', 'object', 'type'],
                    'newlines-between': 'always',
                    alphabetize: { order: 'asc', caseInsensitive: true }
                }
            ],
            'import/no-cycle': 'error',
            'import/no-self-import': 'error',
            'import/first': 'error',
            'import/no-duplicates': 'error',
            'import/no-unresolved': 'off', // TypeScript handles this

            // --- Promise Rules ---
            ...promisePlugin.configs.recommended.rules,
            'promise/catch-or-return': ['error', { allowFinally: true }],
            'promise/no-return-wrap': 'error',
            'promise/param-names': 'error',
            'promise/always-return': 'error',
            'require-await': 'error',
            'no-async-promise-executor': 'error',

            // --- Code Quality (SonarJS) ---
            'sonarjs/cognitive-complexity': ['error', 15],
            'sonarjs/no-duplicate-string': 'warn',
            'sonarjs/no-identical-functions': 'warn',

            // --- Security ---
            'security/detect-object-injection': 'warn',
            'security/detect-non-literal-regexp': 'warn',
            'security/detect-possible-timing-attacks': 'warn',

            // --- Best Practices ---
            'no-constant-condition': 'error',
            'no-console': 'warn',
            curly: 'error',
            eqeqeq: ['error', 'smart'],

            // --- Code Style ---
            '@typescript-eslint/naming-convention': [
                'error',
                {
                    selector: 'interface',
                    format: ['PascalCase'],
                    prefix: ['I']
                },
                {
                    selector: 'typeAlias',
                    format: ['PascalCase'],
                    prefix: ['T']
                },
                {
                    selector: 'enum',
                    format: ['PascalCase'],
                    prefix: ['E']
                }
            ]
        }
    },
    {
        // Entry point validation
        files: ['src/**/index.ts', 'src/**/index.tsx'],
        rules: {
            'import/no-unused-modules': [
                'error',
                {
                    missingExports: true,
                    unusedExports: true
                }
            ]
        }
    },
    {
        // Test file relaxations
        files: ['**/*.test.ts', '**/*.spec.ts', '**/*.test.tsx', '**/*.spec.tsx'],
        rules: {
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/explicit-function-return-type': 'off',
            'sonarjs/no-duplicate-string': 'off',
            'sonarjs/no-identical-functions': 'off',
            'no-console': 'off'
        }
    }
];
