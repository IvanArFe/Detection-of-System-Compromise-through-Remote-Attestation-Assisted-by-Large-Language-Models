# Autonomous EDR with eBPF, MCP and a local LLM

An endpoint detection and response system that watches the Linux kernel with eBPF, exposes forensic
tools to a language model over MCP, and lets the model reason and decide the response without a
person present.

Final Degree Project.

---

## Architecture

Three layers talking over MCP on a stdio transport:

```
┌─ forensic_mcp.py ──────────────┐      ┌─ orchestrator.py ─────────────────┐
│  (root process)                │      │  (root process)                   │
│                                │      │                                   │
│  eBPF sensor threads           │      │  MCP client                       │
│   kprobe init_module           │      │   → polls alerts every 20 s       │
│   tracepoint sys_enter_execve  │      │   → sanitises and budgets prompt  │
│            │                   │ MCP  │   → queries Ollama                │
│            ▼                   │stdio │   → interprets the verdict        │
│      EventStore  ──────────────┼─────►│   → calls MCP tools               │
│   (memory + events.jsonl)      │      │   → two-round loop                │
│                                │      │                                   │
│  FastMCP server                │      │   → confirms with ack_alerts      │
│   forensic tools ──────────────┼──────┤   → persists to Supabase          │
└────────────────────────────────┘      └───────────────────────────────────┘
                                                        │
                                                        ▼
                                              Ollama (container, GPU)
```

**Decision flow:**

1. eBPF kprobes on `init_module` / `finit_module` capture kernel module loads.
2. A tracepoint on `sys_enter_execve` captures every process execution, with its command line.
3. Both callbacks push the event into the `EventStore`: in memory under a lock, and as a line in
   `events.jsonl` for the forensic record. Executions are scored on the way in by `edr/triage.py`.
4. The orchestrator calls `get_kernel_alerts` every 20 seconds and gets module loads plus executions
   above the triage threshold. **Only what has not been acknowledged comes back.**
5. The telemetry is sanitised and trimmed before it enters the prompt. The LLM answers in **round 1**
   with `INVESTIGATE`, `MITIGATE` or `NOTHING`, through structured JSON output or, failing that,
   through a `DECISION:` line parsed anchored from the end.
6. On `INVESTIGATE`, forensic evidence is gathered (descriptors, connections, executions of the
   process and its children) and sent in **round 2** for the final verdict.
7. On `MITIGATE`, `remediate_incident` is called with the `starttime` of the original event, and it
   passes the nine safeguards before anything is signalled.
8. `ack_alerts` closes the cycle so those alerts are not analysed again.

### MCP tools

| Tool | Description |
|---|---|
| `get_kernel_alerts()` | Alerts **not yet acknowledged**: module loads and processes the triage escalated |
| `ack_alerts(max_seq)` | Marks alerts up to `max_seq` as consumed |
| `inspect_pid_resources(pid)` | Open file descriptors through `/proc/{pid}/fd` |
| `inspect_pid_network(pid)` | Active TCP connections, matching socket inodes against `/proc/{pid}/net/tcp` |
| `get_execve_events(pid)` | Executions of that PID or of its direct children |
| `remediate_incident(pid, action, expected_starttime, reason)` | Freezes (`SIGSTOP`) or terminates (`SIGKILL`) a process, after nine checks |
| `sensor_stats()` | Event counters, losses and the coverage actually achieved |

### Telemetry

Every sensor emits a **common header** (`ts`, identity, `cgroup_id`, `pid`, `ppid`, `uid`, `comm`)
embedded at the start of its own structure, over a **single ring buffer**. One buffer gives global
ordering between event types and copies less than one buffer per sensor would.

Process identity is read **inside the probe**, not in the user-space callback. It is the only way to
get it: the callback runs hundreds of milliseconds later, and by then short-lived processes are gone.
The previous approach captured 0 identities over 2905 events.

Losses are counted separately at two points: `ringbuf_dropped` when the kernel discards because the
buffer is full, and `dropped` when the in-memory store reaches its cap. Events used to be lost in
silence.

If a probe cannot be attached, it is logged and **the rest keep working**. `sensor_stats()` declares
the coverage the run actually achieved.

The execution sensor also captures the **command line**. Without it, `curl` fetching a patch and
`curl` fetching a script to pipe into a shell produce exactly the same event, and neither a rule nor
the model has any way to tell them apart.

### What the model is asked, and what it is not

Consulting the model on every execution is not viable. A short session measured 3601 of them, the
vast majority the editor polling `git` and Docker launching `runc`. They would drown the context and
dilute the signal in noise.

`edr/triage.py` scores each execution with deterministic rules, and **only what passes a threshold is
escalated**:

| Rule | Weight | Signal |
|---|---|---|
| `exec_from_world_writable` | 40 | Execution from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm` |
| `hidden_binary` | 30 | The binary name begins with a dot |
| `pipe_to_shell` | 40 | The command pipes its output into a shell |
| `downloader_to_shell` | 60 | `curl`/`wget` **and** a pipe into a shell |
| `download_from_public_ip` | 50 | Download from a literal address routable on the internet |
| `shell_net_redirect` | 60 | Shell redirected to `/dev/tcp/`, the canonical reverse shell |
| `netcat_exec` | 60 | `netcat` executing a program |

The weights are calibrated so that **one weak signal does not escalate and two do**. Running
something from `/tmp` is ordinary; running from `/tmp` a binary whose name begins with a dot is not.

That division of labour is the central argument of the hybrid design: a rule settles what is cheap
and objective, and the expensive reasoning is kept for what has already given grounds. The model also
receives the `rules_fired` field, which tells it **why** it is being asked about that process and not
about the other thousands, presented explicitly as an indication to verify and not as proof.

**Alerts are ordered by what can still be done about them, not by severity.** Each one is annotated
with `alive`, and the ones still running are placed last, which is what survives both the context
budget trim and the one Ollama performs by discarding the head of the prompt.

The reason came from the first autonomous run. The most severe events belong to a dropper chain
(`bash -c 'curl … | sh'`) that lives three seconds while the system polls every twenty. The model
spent both of its rounds reasoning about processes that were already dead, and asked to freeze them.
**A dead process cannot be remediated however grave it was.** Dead alerts are still shown, since they
carry forensic value, but the prompt warns that no signal can be sent to them.

### Response safeguards

The autonomous response is not unconditional. Before any signal is sent, `edr/safety.py` evaluates
**nine checks in order** and returns on the first that fails. Each produces a stable, machine-readable
`reason`, because they are aggregated in the laboratory statistics:

| # | Check | `reason` | Why |
|---|---|---|---|
| 1 | Remediable PID | `invalid_pid` | `os.kill(0, …)` signals the EDR's **whole process group**; negatives signal arbitrary groups; 1 is systemd |
| 2 | Valid action | `invalid_action` | Only `freeze` and `kill` |
| 3 | The process exists | `no_such_process` | First read of `/proc`; everything else depends on it |
| 4 | Self-protection | `self_protection` | The PID cannot be the EDR nor any of its ancestors |
| 5 | Kernel thread | `kernel_thread` | It has no user space to signal |
| 6 | Protected process | `protected_process` | Killing `sshd` during an incident locks you out of the machine |
| 7 | **Known identity** | `identity_unknown` | With no captured `starttime` there is no remediation: it fails closed |
| 8 | **Matching identity** | `pid_reused` | The `starttime` of the event has to still be the same |
| 9 | Rate limit | `rate_limited` | 3 every 5 min: a hallucination loop cannot sweep the machine |

Checks 7 and 8 are the core. Tens of seconds pass between the sensor capturing the event and the
model deciding, which is time enough for the kernel to recycle the PID. **The real identity of a
process is the pair `(pid, starttime)`, not the PID.**

The rate limit goes **last on purpose**: a rejected proposal should not consume remediation budget.
And **every attempt is recorded, denials included**, because without that trace there is no way to
show the safeguards fired.

**`EDR_MODE` defaults to `dry-run`**: the system reasons, decides and validates, but sends no signal.
For it to act for real, `EDR_MODE=autonomous`.

### Robustness of the decision

The model's verdict is not taken at face value. It is read two ways, in order of preference: the
**native structured output** of Ollama with a JSON Schema, and as a fallback an **anchored parser**
that walks the lines from the bottom up requiring the whole line to be the verdict.

Three defences reinforce one another:

| Defence | Attack it cuts |
|---|---|
| `fullmatch` on the whole line, bottom-up | A sentence that *mentions* or *negates* a verdict stops counting |
| Examples with the literal `pid=<PID>` | The model repeats the instructions and the echo is not actionable |
| `allowed_pids` derived from the telemetry shown | A hallucinated or injected PID is rejected |

On top of that, everything an attacker controls (`comm`, paths, arguments) is sanitised before it
enters the prompt, and the evidence is wrapped between delimiters marked explicitly as untrusted data.

**`INVALID` is not the same as `NOTHING`.** They used to collapse together, so "the model could not
answer" was indistinguishable from "the model chose not to act", which are very different things when
computing false negatives.

---

## Requirements

- Debian on WSL2, kernel 6.6+ with eBPF support
- Python 3.13 (venv in `./venv`)
- BCC as a system package (`python3-bpfcc`) — **it does not install with pip**
- Docker Engine inside WSL2, with the NVIDIA Container Toolkit for GPU passthrough
- A Supabase account, for persisting detections and evidence

### Installation

```bash
# 1. System dependencies
sudo apt install python3-bpfcc

# 2. Docker Engine + NVIDIA Container Toolkit inside WSL2
sudo bash scripts/install-docker-wsl.sh

# 3. Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Credentials
cp .env.example .env    # fill in SUPABASE_URL, SUPABASE_KEY, SUPABASE_ACCESS_TOKEN

# 5. Create the Supabase tables (first time only)
python setup_db.py
```

**BCC inside the venv:** BCC cannot be installed with pip. The approach taken is to link the system
libraries into the venv's `site-packages`. If `from bcc import BPF` fails inside the venv, check that
the links exist under `venv/lib/python3.13/site-packages/`.

---

## Running it

```bash
# 1. Check everything is in place
bash scripts/preflight.sh
sudo venv/bin/python3 scripts/check_sensor.py # checks the sensor end to end

# 2. Bring Ollama up
docker compose up -d
docker exec ollama ollama pull llama3.1:8b     # first time only

# 3. Start the whole system
sudo venv/bin/python3 orchestrator.py
```

The orchestrator launches `forensic_mcp.py` itself as an MCP subprocess, with the same interpreter
and the same privileges. There is no need to start it separately.

Because every path derives from the base directory, **the system runs from any directory**.

### Configuration

Everything tunable is read from the environment with a default, in `edr/config.py`. These are the ones
actually worth touching; the full list is 26 and lives in that file.

| Variable | Default | What it changes |
|---|---|---|
| `EDR_MODE` | `dry-run` | `autonomous` so that signals are really sent |
| `EDR_TRIAGE_THRESHOLD` | `50` | Score above which an execution is escalated to the model |
| `EDR_MODEL` | `llama3.1:8b` | The model answering the queries |
| `OLLAMA_URL` | `http://localhost:11434` | Where Ollama listens |
| `EDR_RATE_LIMIT_MAX` | `3` | Remediations allowed per window |
| `EDR_RATE_LIMIT_WINDOW` | `300` | Length of that window, in seconds |
| `EDR_EVENT_CAP` | `2000` | Events the in-memory store holds |
| `EDR_LLM_NUM_CTX` | `8192` | Context requested from Ollama |
| `EDR_EVENTS_FILE` | `events.jsonl` | Where the forensic record is written |
| `EDR_RUN_ID` | empty | Tags a campaign and turns on the journal under `results/` |

They can go in front of the command for a single run, or in `.env` to persist. Watch out with the
second: `.env` does not end in a newline, so append with `printf '\nVAR=value\n' >> .env` or the new
variable will be glued onto the previous one.

### Generating test events

In another terminal, with the orchestrator running:

```bash
sudo modprobe tcrypt && sudo rmmod tcrypt   # successful module load
sudo insmod /etc/hostname                   # failed attempt (-ENOEXEC), the kprobe still fires
sudo modprobe dummy && sudo modprobe -r dummy
curl -s http://example.com > /dev/null      # ordinary execution: does not escalate
```

To watch the triage work, `scripts/demo_detection.sh` first generates ordinary activity and then two
behaviours that do pass the threshold: a download piped into a shell, and a long-lived process running
from `/tmp` under a hidden name. Nothing it does is harmful. The "threat" is `/bin/sleep` copied under
another name, which is enough because the system decides from **how** a process was started and not
from what the binary does inside.

```bash
bash scripts/demo_detection.sh
```

And look at the raw telemetry:

```bash
tail -f events.jsonl      # forensic record: one JSON line per event
```

`events.jsonl` is append-only and never rewritten. The live events are in memory, shared between the
sensor thread and the MCP tools under a lock, and the file is only the record. That way a corrupted
line invalidates nothing else and there is no write to race over.

### Running components separately (debugging)

```bash
# Only the MCP server and the sensors. Speaks JSON-RPC on stdin: useful with an MCP inspector.
sudo venv/bin/python3 forensic_mcp.py
```

### Tests

```bash
venv/bin/python3 -m pytest -q
```

313 tests in about 4 seconds. **No root, no BCC and no network**, on purpose: they are meant to be run
constantly while developing. They cover `/proc` parsing (including pathological `comm` values such as
`(sd-pam)`), the concurrency of the event store (20 threads × 500 writes with simultaneous reads), the
remediation safeguards, the interpretation of the model's verdict — prompt injections and instruction
echoes included — and the contract that binds each laboratory scenario to the rules it claims to fire.

### Reproducing the evaluation

The figures in the report were not copied by hand from any terminal. They are produced by
`scripts/lab/`, and every table in the results chapter comes out of one of these programs.

| Instrument | What it does |
|---|---|
| `scenarios.py` | The catalogue: what each scenario runs, the score expected and the verdict that is correct |
| `workload.py` | Generates reproducible host activity, from a fixed seed, to measure over |
| `triage_replay.py` | Re-scores already recorded telemetry with the current rules |
| `safeguards_matrix.py` | Provokes each safeguard individually against a real process |
| `overhead.py` | Cost per execution, cost per event and the saturation point |
| `run_lab.py` | Runs the scenario campaign, one orchestrator per repetition |
| `lab_report.py` | Aggregates the runs into the tables of the report |

The catalogue is a Python list and not a configuration file on purpose, so that the tests can check
that each scenario scores exactly what it declares. One that misdescribes what it fires breaks the
suite instead of producing a misleading result.

```bash
# Safeguards and cost: independent of everything else.
sudo venv/bin/python3 scripts/lab/safeguards_matrix.py --out results/safeguards.md
sudo venv/bin/python3 scripts/lab/overhead.py --out results/overhead.md

# Telemetry: the sensor records while the generator produces the activity.
sudo EDR_EVENTS_FILE=results/telemetry-clean.jsonl venv/bin/python3 forensic_mcp.py
venv/bin/python3 scripts/lab/workload.py --minutes 20 --seed 1

# The triage replayed over what was just recorded.
venv/bin/python3 scripts/lab/triage_replay.py results/telemetry-clean.jsonl \
     --out results/triage-clean.md

# The scenario campaign and its report.
sudo venv/bin/python3 scripts/lab/run_lab.py --mode autonomous --repeat 5
venv/bin/python3 scripts/lab/lab_report.py --run-id <run_id>
```

The sensor in the third block runs in another terminal and has to stay alive while the generator
works. `run_lab.py` starts one orchestrator per scenario and repetition, so the rate limiter's budget
resets between them and one repetition cannot poison the next.

---

## Supabase persistence

Implemented in `db.py`, called from the orchestrator at three points of the decision cycle.

**Tables** (created by `setup_db.py` through the Management API over HTTPS):

- **`detections`** — one row per LLM decision cycle. The core is `pid`, `process`, `decision`,
  `action`, `llm_round1`, `llm_round2` and `remediation`. To that are added the metrics of each call
  to the model (`model`, `latency_ms`, `tokens_in`, `tokens_out`) and the columns the laboratory uses
  (`severity`, `mitre_technique`, `rules_fired`, `run_id`, `scenario`).
- **`evidence`** — results of the forensic tools, linked to a detection: `detection_id` (FK), `tool`,
  `result`.

`pid` and `process` are nullable on purpose: a `NOTHING` verdict carries no PID, and those rows are
exactly the ones the false-negative rate is computed from. There are indices on `(pid, process,
created_at)` for the deduplication query, which used to scan the whole table on every cycle.

`setup_db.py` is idempotent. Run it again whenever the schema changes: it creates what is missing and
leaves alone what already exists.

When `EDR_RUN_ID` is set, every detection is also written to `results/<run_id>/detections.jsonl`. The
laboratory report reads from there and not from Supabase, so that a database that is down or a free
project that has been paused cannot invalidate a campaign.

**A note on WSL2:** direct PostgreSQL connections to `db.*.supabase.co:5432` fail because of how WSL2
resolves names. Both `setup_db.py` and `db.py` use HTTPS APIs to avoid it.

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| The MCP session hangs with no message | `sudo` asking for a password inside the stdio channel | Already resolved: the server is launched with `sys.executable`. If it comes back, run `sudo -v` first |
| `Ollama does not respond` in the preflight | The container is not up | `docker compose up -d` |
| The model is extremely slow | Ollama loaded the model on the CPU | `docker exec ollama ollama ps` has to say 100% GPU. The RTX 5070 is Blackwell: it needs CUDA 12.8+ and a Windows driver ≥572 |
| `from bcc import BPF` fails | The BCC links are missing from the venv | See the installation note above |
| The LLM keeps analysing the same alert | The events were never acknowledged | Resolved: `ack_alerts` marks what has been consumed. Check `sensor_stats()` |
| The EDR decides MITIGATE but kills nothing | It is in `dry-run`, the default mode | `EDR_MODE=autonomous` for it to act for real |
| `[BLOCKED] pid_reused` when remediating | The PID already belongs to another process | Nothing to fix: this is exactly the correct behaviour |
| `Supabase unavailable` at startup | Database down or free project paused | The EDR keeps detecting and writes to `detections_fallback.jsonl`. Reactivate it in the dashboard |

---

## Repository layout

```
forensic_mcp.py          MCP server + eBPF sensors (needs root)
orchestrator.py          MCP client + decision loop with the LLM
db.py                    Supabase persistence, with a local fallback
setup_db.py              Table creation (run once)
edr/                     Core: pure logic, importable without root or BCC
  config.py              Configuration from the environment
  procinfo.py            /proc reading and identity (pid, starttime)
  eventstore.py          Thread-safe event store
  safety.py              Remediation safeguards and operating modes
  llm.py                 Ollama client with timeout, options and metrics
  prompts.py             Sanitisation and context budgeting
  decision.py            Verdict interpretation (structured + parser)
  netinfo.py             /proc/net/tcp and IPv6 decoding
  triage.py              Deterministic rules: what is worth asking the model
tests/                   Suite with no root, no BCC and no network
  data/                  Fixtures for the laboratory report
docker-compose.yml       Ollama with GPU passthrough
requirements.txt         Python dependencies
.env.example             Credentials template
scripts/
  preflight.sh           Checks to run before starting
  check_sensor.py        Checks the sensor end to end (needs root)
  demo_detection.sh      Generates the demonstration activity
  install-docker-wsl.sh  Docker Engine + NVIDIA Container Toolkit on WSL2
  lab/                   Evaluation instruments: they produce the report's tables
    scenarios.py         Scenario catalogue, with expected score and verdict
    workload.py          Reproducible host activity, from a fixed seed
    triage_replay.py     Replays the triage over recorded telemetry
    safeguards_matrix.py Provokes each safeguard separately
    overhead.py          Cost per execution, per event and saturation point
    run_lab.py           Runs the scenario campaign
    lab_report.py        Aggregates the runs into tables
```
