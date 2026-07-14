# macarune examples

Runnable, self-contained demonstrations. Each script cleans up after itself
and needs nothing but a built `macarune` binary on `PATH` (or exported as
`MACARUNE=/path/to/macarune`).

```bash
go build -o macarune ./cmd/macarune
MACARUNE=./macarune bash examples/delegate.sh
MACARUNE=./macarune bash examples/toolhost-gate.sh
```

## delegate.sh

The core delegation story: the verifier mints one broad token for an
orchestrator agent, the orchestrator narrows it **offline** for a read-only
research sub-agent, and the tool host then allows the in-scope call while
denying tool escapes, path escapes, and expired requests — each with a
quotable reason.

## toolhost-gate.sh

macarune as a shell-level policy gate: a `run_tool` function asks
`macarune verify --quiet` before executing anything, so the exit code alone
decides whether the wrapped command runs. This is the pattern for guarding
an agent's shell or MCP tool dispatcher without linking against Go.
