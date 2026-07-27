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
`--binary-path`, and adding `--tls-binary-only`. When `--pidns-filter` is also
present, AgentSight applies that namespace boundary to TLS events as well as
process and resource events. This permits a sidecar to attach an exact
container `libssl` without observing other host or container workloads.

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

## Unified multi-scope view

Keep host and task-container captures as separate evidence databases. To inspect
them together, point any report command at the aggregate profile directory
instead of an individual `capture.db`:

```bash
agentsight report --profile-dir ./attempt/profiles/agentsight summary
agentsight report --profile-dir ./attempt/profiles/agentsight audit --limit 500
agentsight report --profile-dir ./attempt/profiles/agentsight export \
  --output ./unified-snapshot.json
agentsight report --profile-dir ./attempt/profiles/agentsight serve
```

`--profile-dir` is an explicit alias for `--db`; both accept either a single
SQLite database or a profile directory. AgentSight discovers
`sources/*/capture.db`, validates that each source manifest has the same profile
identity and a scope matching its directory, and merges the materialized views
in memory. It does not rewrite or duplicate the evidence databases.

Every merged row retains `scope_id`, and row identity is the pair
`(scope_id, id)`. PID relationships are likewise resolved within a scope, so a
host PID and an unrelated container PID with the same number remain distinct.
Both collectors normalize kernel timestamps to Unix-epoch milliseconds before
persistence; the unified timeline therefore preserves real overlap and does
not serialize concurrent activity. The web timeline exposes scope lanes and a
scope filter, while the process tree and resource view keep scope-local process
identity.

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
inside the task container, so one container scope is sufficient. In SWE-bench,
OpenHands keeps orchestration on the host but runs its agent-server, provider
client, and repository tools in the task container. Hermes keeps its
coordinator and provider client on the host while repository tools run in the
task container. Both integrations therefore use both scopes. In Harbor-backed
Terminal-Bench integrations, all three frameworks run
their coding agent and provider client inside Harbor's `main` task container.
Those integrations therefore use one PID-namespace sidecar per attempt, with
no redundant host collector. The sidecar starts after container setup, reports
matching readiness before agent work, and stops before Harbor teardown.
OpenCode keeps TLS/HTTP capture enabled and narrows static attachment to its
exact installed binary. OpenHands SWE-bench and all Terminal-Bench adapters
resolve the TLS-bearing binary used by their exact container Python runtime
with one short local probe: its loaded `libssl`, or the Python executable when
OpenSSL is statically embedded. They attach that inode through
`/proc/<task-pid>/root`, and restrict the TLS probe to the task PID namespace.
Hermes SWE-bench resolves and pins the equivalent binary used by its host
worker instead. Namespace-wide stdio remains disabled.
On Docker Desktop and WSL, the target path is validated inside the task
container and dereferenced inside the PID-host sidecar; it is not expected to
be visible in the harness host's `/proc` namespace.

When the semantic trace itself is finalized inside the task container, the
harness may stage AgentSight output in the trial log and attach it during
canonical trace promotion. The aggregate profile should carry explicit
run/benchmark/framework/instance/attempt correlation rather than depending on
directory names or timestamps alone.

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
