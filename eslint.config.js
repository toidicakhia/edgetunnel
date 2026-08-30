export default [
	{
		ignores: ['_worker.js', 'dist/**', '.wrangler/**', 'node_modules/**'],
	},
	{
		languageOptions: {
			ecmaVersion: 2022,
			sourceType: 'module',
			globals: {
				// Cloudflare Workers globals
				fetch: 'readonly',
				Request: 'readonly',
				Response: 'readonly',
				Headers: 'readonly',
				URL: 'readonly',
				WebSocket: 'readonly',
				crypto: 'readonly',
				TextEncoder: 'readonly',
				TextDecoder: 'readonly',
				atob: 'readonly',
				btoa: 'readonly',
				console: 'readonly',
			},
		},
		rules: {
			'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
			'no-console': 'off',
			'prefer-const': 'warn',
		},
	},
];
