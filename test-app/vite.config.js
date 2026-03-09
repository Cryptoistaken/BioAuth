import { defineConfig } from 'vite'

export default defineConfig({
	server: {
		host: true,
		port: 5173
	},
	define: {
		// Convex HTTP actions URL — override with VITE_SERVER_URL env var for other backends
		// Default points to the live Convex deployment
		__SERVER_URL__: JSON.stringify(
			process.env.VITE_SERVER_URL ?? 'https://pleasant-pelican-278.eu-west-1.convex.site'
		)
	}
})
