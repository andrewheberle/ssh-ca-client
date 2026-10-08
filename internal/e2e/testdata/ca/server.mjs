// Runs the published Serverless SSH CA under Node.js for end-to-end tests.
//
// The CA is created with the Node.js helpers from the package, using an
// in-memory node:sqlite database, and served by an HTTP server that passes
// requests to its fetch handler.
//
// Usage: node server.mjs <config.json>
//
// The config file is a JSON object with the following properties:
//   private_key: the CA private key in OpenSSH format
//   bindings:    the CA configuration, as the Worker vars (environment variables)
//   port_file:   path the listening port is written to once ready
//   log_file:    path that log output from the CA is appended to
//
// The process exits when its stdin is closed so it does not outlive the test
// that started it.
import { appendFileSync, readFileSync, writeFileSync } from "node:fs"
import { createServer } from "node:http"
import { DatabaseSync } from "node:sqlite"
import { createSshCa } from "@andrewheberle/serverless-ssh-ca"
import { bindingsFromEnv, fromNodeSqlite, secretFromString } from "@andrewheberle/serverless-ssh-ca/node"

const config = JSON.parse(readFileSync(process.argv[2], "utf8"))

const log = (line) => appendFileSync(config.log_file, line + "\n")

// The CA logs JSON lines via console, so send them to the log file
const format = (v) => typeof v === "string"
	? v
	: JSON.stringify(v, (_, x) => x instanceof Error ? { name: x.name, message: x.message, stack: x.stack } : typeof x === "bigint" ? x.toString() : x)
for (const level of ["debug", "info", "log", "warn", "error"]) {
	console[level] = (...args) => log(args.map(format).join(" "))
}

process.on("uncaughtException", (err) => {
	log(JSON.stringify({ level: "error", message: "harness uncaught exception", error: format(err) }))
	process.exit(1)
})

// bindingsFromEnv validates the configuration so a mistake fails at start up
const ca = createSshCa(bindingsFromEnv({
	DB: fromNodeSqlite(new DatabaseSync(":memory:")),
	PRIVATE_KEY: secretFromString(config.private_key),
}, config.bindings))

const server = createServer(async (req, res) => {
	try {
		const chunks = []
		for await (const chunk of req) {
			chunks.push(chunk)
		}

		const request = new Request(`http://${req.headers.host ?? "localhost"}${req.url}`, {
			method: req.method,
			headers: req.headers,
			body: req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.concat(chunks),
		})

		const response = await ca.fetch(request)
		const body = Buffer.from(await response.arrayBuffer())

		log(JSON.stringify({ level: "info", message: "harness request", method: req.method, url: req.url, status: response.status, ...(response.status >= 400 ? { body: body.toString() } : {}) }))

		res.writeHead(response.status, Object.fromEntries(response.headers))
		res.end(body)
	} catch (err) {
		log(JSON.stringify({ level: "error", message: "harness request failed", error: format(err) }))
		res.writeHead(502)
		res.end()
	}
})

server.listen(0, "127.0.0.1", () => {
	writeFileSync(config.port_file, String(server.address().port))
})

process.stdin.on("end", () => process.exit(0))
process.stdin.resume()
