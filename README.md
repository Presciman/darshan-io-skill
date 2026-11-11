# Darshan I/O analysis: skill, schema and tools

For an LLM agent that answers questions about a [Darshan](https://www.mcs.anl.gov/research/projects/darshan/)
I/O log, where every number in the answer is retrieved from the log by a tool rather than estimated
by the model.

| Part | Where | What it is |
|---|---|---|
| **Skill** | `.claude/skills/darshan-analysis/SKILL.md` | The analysis method: which bottleneck classes to check and in what order, ranked fixes, and how to treat zeros, absent modules and `-1`. |
| **Schema** | `darshan_tools/schema/darshan_schema.yaml` | The two-layer Darshan schema template. Layer 1 holds the counter families grouped by concern; layer 2 holds the relations derived from them. `darshan_to_schema.py` fills it from a log. |
| **Tools** | `darshan_tools/` | `outline` / `search` / `get` over the filled schema. `darshan(view)` returns exact facts from the binary log, including `cards`: one card of canonical measures per analysis concern (volume, bandwidth, request sizes, metadata, files, rank balance, MPI-IO, Lustre, DXT, bottleneck, verdict, ...). `calc` does exact arithmetic. |

## Install

Requires Python ≥ 3.10 and PyDarshan (`pip install darshan`). PyDarshan needs `libdarshan-util`. The
PyPI wheels bundle it on x86-64 Linux; elsewhere, put a darshan-util install on `LD_LIBRARY_PATH`
or `darshan-parser` on `PATH`.

```bash
pip install -e .
```

## Use

**In Claude Code**, open this repository as the project. The skill loads from `.claude/skills/`, and
`.mcp.json` starts the tools as the `darshan-tools` MCP server, whose instructions explain the
schema and how to answer from the cards. Then ask:

> analyze /path/to/job.darshan — is it I/O-bound, and what limits its bandwidth?

**In any other MCP client**, run `darshan-tools-mcp` over stdio. Call `open_log(log)` first, then
`darshan(view="cards")`, `outline`, `search`, `get` and `calc`.

**From a shell**:

```bash
darshan-tools schema job.darshan -o job.schema.json   # the filled two-layer schema
darshan-tools view job.darshan cards                  # all cards; also derived, job, ranks, files, ...
darshan-tools calc "10963279 / MiB"
```

`--nodes N` (CLI) or `open_log(log, nodes=N)` gives the node count. It is needed only when DXT did
not trace every rank; otherwise the DXT hostnames give it.

## Conventions worth knowing

- Every measure is computed from the log as Darshan's own tools reduce it: `accumulate_records`,
  the same reduction as `darshan-parser --total`. Bandwidth is `darshan-parser --perf`'s
  `agg_perf_by_slowest`.
- A size is "small" when it falls in a Darshan size bin up to 1 MiB. "Strictly small" excludes
  accesses of exactly 1 MiB, which Darshan counts in its 100K–1M bin.
- A card whose concern does not exist in the job (e.g. MPI-IO in a POSIX-only run) says
  `not_applicable` with the reason and carries no numbers.
- `darshan(view="derived")` lists every derived metric with the formula that produced it.

## License

[MIT](LICENSE).
