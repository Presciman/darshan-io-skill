---
name: darshan-analysis
description: Analyze a Darshan I/O report (darshan-parser text output, or PyDarshan summary) for HPC jobs. Finds the primary I/O bottleneck — small/unaligned accesses, metadata/open storms, missing MPI-IO/collective I/O, rank load imbalance, Lustre striping — with counter evidence and ranked fixes. Use for "analyze this Darshan log", "why is my I/O slow", "characterize my job's I/O", or when handed a Darshan report/log file.
---

# Darshan I/O analysis

Given a Darshan report, find the primary I/O bottleneck and how to fix it.
**Ground every claim in a specific counter value** — never guess or infer beyond
what the counters show. If a module (e.g. MPI-IO) is absent or a counter isn't
present in the report, say so explicitly rather than assuming a value.

## Steps

1. Read the report the user names. If none is given, ask for the path (a
   `darshan-parser --total <file>.darshan` text dump, or an equivalent summary).
2. Compute/check each candidate bottleneck class below — don't stop at the first
   one that looks bad. Multiple anti-patterns can co-occur; rank them by evidence.
3. Produce the structured report (see **Output**).

## Candidate bottleneck classes to check, in this order

1. **Workload shape** — `nprocs`, run time. Establishes scale for later ratios.
2. **I/O volume** — total bytes read/written per module. Read-heavy vs
   write-heavy vs balanced shapes the rest of the analysis.
3. **Access size** — mean size = bytes / ops; inspect the `SIZE_READ_*` /
   `SIZE_WRITE_*` histograms and `ACCESS1_ACCESS`/`ACCESS1_COUNT` (most common
   access size). Flag small accesses (well under ~1 MiB) as a bandwidth problem.
4. **Alignment & sequentiality** — `*_FILE_NOT_ALIGNED`, `*_SEQ_READS`/`WRITES`,
   `*_CONSEC_READS`/`WRITES` vs total ops. High misalignment or low
   sequential/consecutive fraction compounds a small-access problem.
5. **Op counts / file count** — `*_OPENS` and `*_FILES` vs total ops. Opens
   approaching or exceeding the read/write count, or file counts in the
   hundreds-of-thousands to millions, signal a metadata/open storm
   (especially file-per-sample or file-per-rank-per-step layouts).
6. **Time breakdown** — compare `F_READ_TIME` / `F_WRITE_TIME` vs `F_META_TIME`
   (aggregated across ranks — divide by nprocs for a per-rank estimate). META
   time rivaling or exceeding read/write time means metadata-bound, not
   bandwidth-bound. Also derive effective throughput (bytes / read-or-write time
   per rank) to sanity-check against plausible Lustre bandwidth.
7. **Interface** — POSIX vs MPI-IO vs STDIO module presence. Missing MPI-IO
   module means no collective/two-phase I/O was used, regardless of access
   pattern.
8. **Load balance** — `F_FASTEST_RANK_TIME` vs `F_SLOWEST_RANK_TIME` (and, if
   present, `RANK0_BYTES_*` vs total bytes). A large spread, or one rank owning
   all the bytes, indicates serialization through a single rank (e.g. rank-0
   funneled checkpoint writes) rather than a parallel-I/O problem.
9. **Lustre striping** — `*_STRIPE_WIDTH`/`*_STRIPE_SIZE` if present.
   `STRIPE_WIDTH: 1` on large shared files means no striping parallelism was
   available regardless of access pattern.

Only report on classes for which the report actually has counters. Explicitly
note absent modules/counters rather than filling gaps with assumption.

## Output — structured report

1. **Workload shape** — ranks, runtime.
2. **I/O volume** — bytes read/written per module, read:write ratio.
3. **Dominant interface** — POSIX/MPI-IO/STDIO; note explicitly if a module is
   absent and what that implies (e.g. no MPI-IO ⇒ no collective I/O).
4. **Access pattern** — mean/typical size, sequential vs random, alignment,
   #files/#opens.
5. **Time breakdown** — read/write vs metadata time (aggregate and per-rank),
   effective throughput.
6. **Load balance** — fastest vs slowest rank, and rank-0-funneling if visible.
7. **Primary bottleneck** — one line, naming the dominant anti-pattern.
8. **Ranked fixes** — concrete and specific to the evidence found, e.g.:
   - small/unaligned/metadata-bound: aggregate many small files into fewer
     large containers (HDF5, TFRecord, WebDataset, tar), read in larger
     stripe-aligned chunks, reduce opens, consider node-local SSD staging.
   - serial/rank-0-bound writes: parallelize via collective MPI-IO / HDF5 /
     ADIOS, or file-per-rank, to spread the write across ranks.
   - poor striping: increase Lustre stripe count/size (`lfs setstripe`) to
     match access size and rank count.
   - missing MPI-IO: consider collective/two-phase I/O APIs if the access
     pattern would benefit from coordinated requests.
   - does it affect application specific performance or correctness? If not, 
     provide specific fix method to avoid. If yes, describe the necessary 
     changes to the application or I/O pattern. 
9. **What to measure next** — e.g. Darshan DXT (`--enable-dxt` /
   `darshan-dxt-parser`) for per-file, per-rank, time-resolved detail;
   `lfs getstripe` on the dataset directory; per-file (not just `--total`)
   `darshan-parser` output for shared-vs-unique file breakdowns.

## Numbers, zeros and absence

- Every number you state is read from the evidence or computed from it. When
  you have a calculator or code tool, do every computation with it; never do
  arithmetic in your head, and never estimate or invent a number the evidence
  does not hold.
- **Zero means none.** A counter that is 0 (or left out of a group because it
  is 0) means the thing did not happen. Say so plainly and cite the counter:
  "no strided access (POSIX_STRIDE1_COUNT = 0)", "no fsync calls
  (POSIX_FSYNCS = 0)". That is a complete answer, not missing data.
- **Absent means not applicable.** When what a question asks about does not
  exist in this job, say so and why, and give no number for it: "Not
  applicable: the log has no MPI-IO module, so there are no collective
  operations." "Not applicable: only 1 rank did I/O, so there is no rank
  imbalance." "Not applicable: every record is a shared-file record, so no
  per-rank split exists." That is a correct answer, not a gap.
- **-1 means not recorded.** Darshan writes -1 where a value could not be kept
  in this reduction (e.g. `*_FASTEST_RANK` on aggregated records). Say it is not
  recorded at this level; never report -1 as a value.
- Keep "not available in this evidence" for data the log may well hold but your
  evidence does not show (e.g. per-file detail in a `--total` dump), and say
  what would provide it.
- Write every count and quantity in digits ("1 rank", not "one rank").

## Guardrails

- Cite the actual counter name and value for every claim ("X of Y counter" or
  a derived ratio with its inputs shown).
- Never invent counters or values not present in the report.
- If two anti-patterns are both present (e.g. small-read storm AND load
  imbalance), report both, ranked by evidence strength — don't fixate on
  whichever is found first.
- Note explicitly when a needed counter (e.g. Lustre striping) isn't in the
  report, and say what additional data (DXT, `lfs getstripe`) would confirm it.
