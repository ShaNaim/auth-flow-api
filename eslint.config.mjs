import globals from 'globals';
import typescriptParser from '@typescript-eslint/parser';
import typescriptPlugin from '@typescript-eslint/eslint-plugin';
import promisePlugin from 'eslint-plugin-promise';
import importPlugin from 'eslint-plugin-import';

export default [
    {
        files: ['**/*.ts'],
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node
            },
            parser: typescriptParser,
            parserOptions: {
                project: './tsconfig.json'
            }
        },
        plugins: {
            '@typescript-eslint': typescriptPlugin,
            promise: promisePlugin,
            import: importPlugin
        },
        rules: {
            ...typescriptPlugin.configs.recommended.rules,
            ...promisePlugin.configs.recommended.rules,
            '@typescript-eslint/await-thenable': 'warn',
            '@typescript-eslint/no-floating-promises': 'warn',
            'promise/param-names': 'warn',
            'promise/catch-or-return': 'warn',
            'require-await': 'warn',
            '@typescript-eslint/require-await': 'warn',
            'promise/always-return': 'warn',
            'no-async-promise-executor': 'warn',
            '@typescript-eslint/no-unused-vars': 'warn',
            '@typescript-eslint/no-explicit-any': 'off'
        }
    },
    {
        // Override specifically for *.services.ts files
        files: ['**/**/index.ts'],
        rules: {
            'import/no-unused-modules': [
                'error',
                {
                    missingExports: true,
                    unusedExports: true
                }
            ]
        }
    }
];
