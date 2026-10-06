# AGENTS.md

## Project overview
This provides the client-side service to interact with the [Serverless
Certificate Authority](https://github.com/andrewheberle/serverless-ssh-ca).

## Repository layout
- `cmd/` - entrypoints for commands; should only include minimal code then call Execute of the relevant package
- `deb/` - Debian package specific files
- `docs/` - documentation of commands
- `internal/pkg/` - application packages; not importable by other modules
- `internal/e2e/` - end-to-end tests against the published server package; `testdata/ca/` runs the CA under Node.js
- `internal/pkg/api/` - generated OpenAPI primitives to interact with the server implementation. Do not edit `api.gen.go` or `openapi.json`.
- `internal/pkg/cli/` - primary package used by the CLI
- `internal/pkg/gui/` - primary package used by the GUI
- `pkg/` - application packages; importable by others
- `policy/` - Group Policy Object's for Windows to manage GUI on Windows; included in MSI build
- `snap/` - Snap specific scripts and files
- `systemd/` - Systemd units for host key renewals; included in APT package
- `templates/` - templates used for MSI build

## Build, test, lint
Run these before considering any change complete:
- Build: `go build ./...`
- Test: `go test -race ./...`
- End-to-end test (needs Node.js 22.5+ and npm): `go test -tags e2e -race ./internal/e2e/...`
- Vet: `go vet ./...`
- Lint: `golangci-lint run`
- Format: `gofmt -s -w .` (or `goimports`); never commit unformatted code

## Code conventions
- Go version: [1.26], per `go.mod`. Don't bump it unless asked.
- Logging: use `log/slog` with structured key/value attributes. No `fmt.Println` or `log.Printf` in service code.
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`. Return errors rather than logging and continuing, unless at the top level or the parent contains a `*slog.Logger`.
- Context: pass `context.Context` as the first parameter for anything doing I/O; respect cancellation.
- Concurrency: guard shared state with `sync.RWMutex` (or channels). Run tests with `-race`.
- Interfaces: define them where they're consumed, keep them small. Decorators (caching, metrics) wrap the interface rather than modifying the implementation.
- Dependencies: prefer the standard library. Ask before adding a new module dependency. Run `go mod tidy` after any dependency change.

## Documentation
- Command line flag or behaviour changes must be reflected in `docs/` and `README.md`

## Testing
- Table-driven tests with `t.Run` subtests.
- Use fakes implementing the package interfaces; no network or external services in unit tests.
- New behaviour needs a test; bug fixes need a test that fails without the fix.

## Releases
- Releases are built by GoReleaser from git tags (`vX.Y.Z`).
- Never delete, move, or force-push an existing tag. The Go module proxy caches versions immutably, so a retagged version won't be picked up. Fix forward with a new patch version.
- Don't edit `.goreleaser.yaml` or CI config unless the task is specifically about them.
- Do not create or push a tag unless specifically directed to as this triggers the release workflow.

## Boundaries
- Don't commit secrets, tokens, or real config values.
- Don't modify generated files; regenerate them with `go generate ./...`.
- Keep changes scoped to the task. No drive-by refactors or renames.
