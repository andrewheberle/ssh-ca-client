// Bundles server.mjs and the CA package into dist/server.mjs.
//
// The published package uses extensionless relative imports, which are
// resolved when bundled (as Wrangler does for deployments) but are rejected
// by the Node.js ES module loader, so it cannot be imported directly.
import { build } from "esbuild"

await build({
	entryPoints: ["server.mjs"],
	bundle: true,
	platform: "node",
	format: "esm",
	outfile: "dist/server.mjs",
	logLevel: "warning",
	// some CommonJS dependencies call require() for Node.js built-ins
	banner: {
		js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
	},
})
