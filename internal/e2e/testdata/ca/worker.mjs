// Worker entry point for running the published Serverless SSH CA under
// workerd with workerd.mjs.
//
// The CA's default export is used as on Cloudflare Workers, wrapped only to
// log each request and to write console output as JSON lines, as server.mjs
// does under Node.js.
import ca from "@andrewheberle/serverless-ssh-ca"

// workerd formats objects passed to console for display rather than as JSON,
// so format them here
const format = (v) => typeof v === "string"
	? v
	: JSON.stringify(v, (_, x) => x instanceof Error ? { name: x.name, message: x.message, stack: x.stack } : typeof x === "bigint" ? x.toString() : x)
for (const level of ["debug", "info", "log", "warn", "error"]) {
	const write = console[level].bind(console)
	console[level] = (...args) => write(args.map(format).join(" "))
}

export default {
	...ca,
	async fetch(request, env, ctx) {
		const response = await ca.fetch(request, env, ctx)
		const url = new URL(request.url)

		console.log(JSON.stringify({ level: "info", message: "harness request", method: request.method, url: url.pathname + url.search, status: response.status, ...(response.status >= 400 ? { body: await response.clone().text() } : {}) }))

		return response
	},
}
