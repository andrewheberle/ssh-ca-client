// Runs the published Serverless SSH CA under Node.js for end-to-end tests.
//
// The package is written for Cloudflare Workers, so this provides the parts
// of that environment it relies on:
//   - an HTTP server that passes requests to its fetch handler
//   - a minimal D1Database implementation backed by an in-memory node:sqlite
//     database
//   - a Secrets Store binding returning the CA private key
//
// Usage: node server.mjs <config.json>
//
// The config file is a JSON object with the following properties:
//   private_key: the CA private key in OpenSSH format
//   bindings:    the remaining Worker bindings (environment variables)
//   port_file:   path the listening port is written to once ready
//   log_file:    path that log output from the CA is appended to
//
// The process exits when its stdin is closed so it does not outlive the test
// that started it.
import { appendFileSync, readFileSync, writeFileSync } from "node:fs"
import { createServer } from "node:http"
import { DatabaseSync } from "node:sqlite"
import ca from "@andrewheberle/serverless-ssh-ca"

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

// D1PreparedStatement implementation covering what workers-qb uses
class PreparedStatement {
	#db
	#sql
	#args

	constructor(db, sql, args = []) {
		this.#db = db
		this.#sql = sql
		this.#args = args
	}

	bind(...args) {
		return new PreparedStatement(this.#db, this.#sql, args)
	}

	async all() {
		return this.#execute()
	}

	async run() {
		return this.#execute()
	}

	async first(column) {
		const { results } = await this.#execute()
		const row = results[0] ?? null
		return column !== undefined && row !== null ? row[column] : row
	}

	#execute() {
		// D1 accepts several statements in one prepare() but node:sqlite does
		// not, so run each in turn and hand out the bound arguments in order.
		// This is only intended for simple SQL such as the CA's migrations.
		const statements = this.#sql.split(";").map((s) => s.trim()).filter((s) => s !== "")
		const args = this.#args.map((a) => a === undefined ? null : typeof a === "boolean" ? Number(a) : a)

		let results = []
		let changes = 0
		let lastRowId = 0
		for (const sql of statements) {
			const count = statements.length === 1 ? args.length : (sql.match(/\?/g) ?? []).length
			const stmt = this.#db.prepare(sql)
			const params = args.splice(0, count)
			if (stmt.columns().length > 0) {
				results = stmt.all(...params).map((row) => ({ ...row }))
			} else {
				const res = stmt.run(...params)
				changes += Number(res.changes)
				lastRowId = Number(res.lastInsertRowid)
				results = []
			}
		}

		return {
			success: true,
			results: results,
			meta: { changes: changes, last_row_id: lastRowId, duration: 0, rows_read: 0, rows_written: changes },
		}
	}
}

// D1Database implementation covering what workers-qb uses
class Database {
	#db = new DatabaseSync(":memory:")

	prepare(sql) {
		return new PreparedStatement(this.#db, sql)
	}

	async batch(statements) {
		const results = []
		for (const stmt of statements) {
			results.push(await stmt.all())
		}
		return results
	}

	async exec(sql) {
		this.#db.exec(sql)
		return { count: 0, duration: 0 }
	}
}

const env = {
	...config.bindings,
	DB: new Database(),
	PRIVATE_KEY: { get: async () => config.private_key },
}

// not used by the fetch handler but provided for completeness
const ctx = {
	waitUntil() { },
	passThroughOnException() { },
}

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

		const response = await ca.fetch(request, env, ctx)
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
