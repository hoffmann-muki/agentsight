# Research Profiling

AgentSight can run as a zero-instrumentation profiling companion to an agent
harness. The harness keeps its native semantic trace; AgentSight independently
records the operating-system and transport evidence visible at the kernel
boundary. Neither source replaces the other.

The integration boundary is deliberately benchmark-agnostic. A harness adapter
only identifies the runtime scopes that contain agent work:

- a host PID for the harness process and its descendants;
- a process session or cgroup when that is the stable ownership boundary; or
- a task container's PID namespace, which includes later `docker exec`
  processes as well as the container init process.

AgentSight owns capture, normalization, readiness, health, and artifact
production. It does not need to know the dataset, prompt format, evaluator, or
benchmark lifecycle.

## Research capture

`--capture-level research` enables process execution, file activity, network
activity, signals, memory activity, and periodic system metrics in addition to
the standard TLS/HTTP and stdio sources. Copy-on-write page-fault capture has
higher overhead and remains an explicit `--trace-cow` opt-in.

Use `--profile-dir` to request a self-contained profile:

```bash
sudo agentsight record \
  --pid 12345 \
  --capture-level research \
  --profile-dir ./profile/sources/host \
  --profile-id run-123 \
  --scope-id host \
  --ready-file ./profile/sources/host/ready.json \
  --no-server
```

For a container, run AgentSight beside the task container in the same Docker
engine. PID-namespace selection is important: filtering only the original init
PID misses sibling processes created by later `docker exec` calls.

```bash
task_pid="$(docker inspect --format '{{.State.Pid}}' task-container)"

docker run --detach \
  --name agentsight-run-123 \
  --privileged \
  --pid host \
  --network none \
  --stop-timeout 15 \
  --volume /sys:/sys:ro \
  --volume "$PWD/profile/sources/task-container:/output" \
  agentsight:play \
  record \
  --pidns-filter "/proc/$task_pid/ns/pid" \
  --capture-level research \
  --profile-dir /output \
  --profile-id run-123 \
  --scope-id task-container \
  --ready-file /output/ready.json \
  --no-server \
  --no-ssl \
  --no-stdio
```

The sidecar needs no network when the web UI and exporters are disabled. TLS
capture can be enabled for a statically linked agent binary by making the
binary visible through `/proc/<task-pid>/root`, passing it with
`--binary-path`, and adding `--tls-binary-only`.

The current process probes used by profiles require Linux 5.13 or newer. The
collector also needs root or equivalent eBPF privileges. For an unprivileged host
collector, authenticate once with `sudo -v`; probe subprocesses use
non-interactive sudo and fail visibly instead of prompting in the background.

## Profile contract

One source scope contains:

```text
<profile-dir>/
├── profile.json
├── health.json
├── ready.json
├── capture.db
└── system-events.jsonl.zst
```

- `profile.json` records `agentsight-profile/v1` provenance, target selectors,
  enabled sources, timestamps, runtime version, kernel, and artifact names.
- `ready.json` is written only after all configured runners survive startup. A
  supervisor must match its schema, profile ID, and scope ID before allowing
  agent work to begin.
- `health.json` records `agentsight-capture-health/v1`, completion state,
  evidence counts, write failures, source counts, and runner diagnostics.
- `capture.db` is AgentSight's queryable materialized view.
- `system-events.jsonl.zst` is the lossless normalized evidence journal. Each
  `agentsight-evidence/v1` row has a durable capture sequence, source and capture
  timestamps, source name, PID, command name, and the full sanitized event
  payload.

Known artifacts are cleared when a profile directory is reused, preventing a
stale readiness marker or an earlier SQLite/evidence stream from contaminating
the new capture. Supervisors should still allocate a distinct directory for
each profile scope. When a root collector writes into a pre-created bind-mounted
directory, artifacts inherit that directory's UID and GID while retaining
private modes, so the unprivileged harness can read readiness and results.

Graceful shutdown finalizes the compressed stream and writes terminal health.
If the collector exits through normal stack unwinding before explicit
finalization, health is marked failed. A hard process or machine failure can
leave the compressed evidence stream incomplete; `capture.db`, collector logs,
and the harness-native trace remain independent recovery evidence.

## Harness integration

A benchmark integration should:

1. create its semantic trace and task runtime;
2. map the runtime to one or more AgentSight scopes;
3. start collectors and wait for matching readiness before model inference;
4. run the agent without changing its prompt, delegation, or retry behavior;
5. stop collectors before destroying the observed runtime; and
6. store the profile below that attempt's trace directory.

Host and task-container scopes are separate on Docker Desktop and WSL because
they observe different Linux execution planes. OpenCode runs the coding agent
inside the task container, so one container scope is sufficient. OpenHands and
Hermes perform harness/model work on the host and repository work in the task
container, so their integrations use both scopes.

Profiling should be best-effort by default and report its own health without
changing benchmark success or retry decisions. A harness may offer an explicit
strict mode that requires every expected scope before any provider request.

## Privacy and interpretation

AgentSight removes parsed authentication headers before profile persistence and
does not need provider credentials. Raw TLS records are disabled by the
research profile path. Profiles can still contain prompts, responses, commands,
command output, paths, and network destinations, so profile directories are
private artifacts and must be handled as sensitive research data.

OS evidence supplies independent execution facts, but it cannot reconstruct
hidden framework semantics. Use the harness-native trace for model turns,
delegation relationships, tool identities, context operations, and framework
state; use AgentSight for processes, files, system resources, stdio, TLS/HTTP,
and network behavior. Correlate the two by profile/trace identity, scope, PID,
and timestamps without forcing concurrent activity into a serial history.
