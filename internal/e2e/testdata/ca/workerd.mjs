// Runs the published Serverless SSH CA under workerd for end-to-end tests.
//
// The CA is bundled from worker.mjs and run by the Wrangler test harness, as
// it would be by "wrangler dev", with a local D1 database and Secrets Store
// that are not persisted.
//
// Usage: node workerd.mjs <config.json>
//
// The config file is the same as for server.mjs:
//   private_key: the CA private key in OpenSSH format
//   bindings:    the CA configuration, as the Worker vars (environment variables)
//   port_file:   path the listening port is written to once ready
//   log_file:    path that log output from the CA is appended to
//
// Wrangler's working files are written alongside the config file.
//
// The process exits when its stdin is closed so it does not outlive the test
// that started it.
import { appendFileSync, readFileSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { createTestHarness } from "wrangler"

const configFile = resolve(process.argv[2])
const config = JSON.parse(readFileSync(configFile, "utf8"))

const log = (line) => appendFileSync(config.log_file, line + "\n")

process.on("uncaughtException", (err) => {
	log(JSON.stringify({ level: "error", message: "harness uncaught exception", error: { name: err.name, message: err.message, stack: err.stack } }))
	process.exit(1)
})

// the test harness keeps the runtime logs, so copy them to the log file. Errors
// that are not JSON lines from the CA are from workerd, such as an uncaught
// exception, so are logged as a harness fault.
const flushLogs = () => {
	for (const entry of server.getLogs()) {
		let json = true
		try {
			JSON.parse(entry.message)
		} catch {
			json = false
		}

		if (json || entry.level !== "error") {
			log(entry.message)
		} else {
			log(JSON.stringify({ level: "error", message: "harness runtime error", error: entry.message }))
		}
	}
	server.clearLogs()
}

// use placeholder request.cf data rather than downloading it from Cloudflare
// and caching it in the working directory
process.env.CLOUDFLARE_CF_FETCH_ENABLED = "false"

const server = createTestHarness({
	root: dirname(configFile),
	workers: [{
		config: {
			name: "serverless-ssh-ca",
			main: join(import.meta.dirname, "worker.mjs"),
			// matches the Workers configuration the CA is tested with
			compatibility_date: "2026-03-13",
			compatibility_flags: ["nodejs_compat"],
			vars: config.bindings,
			d1_databases: [{
				binding: "DB",
				database_name: "ssh-ca-database",
				database_id: "00000000-0000-0000-0000-000000000000",
			}],
			secrets_store_secrets: [{
				binding: "PRIVATE_KEY",
				store_id: "e2e",
				secret_name: "ssh-ca-private-key",
			}],
		},
	}],
})

const { url } = await server.listen()

// the secret must exist before the port is written and requests are made
const env = await server.getWorker().getEnv()
const secrets = await env.PRIVATE_KEY["SecretsStoreSecret::admin_api"]()
await secrets.create(config.private_key)

const timer = setInterval(flushLogs, 100)

writeFileSync(config.port_file, url.port)

process.stdin.on("end", async () => {
	clearInterval(timer)
	flushLogs()
	await server.close()
	process.exit(0)
})
process.stdin.resume()
