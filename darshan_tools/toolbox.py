#!/usr/bin/env python3
"""Exact number retrieval from a Darshan log, for an agent to answer with.

  darshan(view)  exact facts from the job's binary log at full precision, by view. "cards" holds
                 one card per analysis concern with that concern's canonical measures, so the
                 agent reports a value instead of computing one.
  calc(expr)     exact arithmetic, for anything no card or view holds.

The facts come from facts.extract() (PyDarshan + accumulate_records, the same reduction as
darshan-parser --total). Nothing here needs to know which machine the job ran on: the node count
comes from the DXT hostnames when DXT traced every rank, else from the caller, else 1.
"""
import ast
import json
import math
import os
import re


HERE = os.path.dirname(os.path.abspath(__file__))
MiB = 2 ** 20
SMALL_BINS = ["0_100", "100_1K", "1K_10K", "10K_100K", "100K_1M"]
RESULT_CHARS = 14000

def div(a, b):
    return (a / b) if (a is not None and b) else None


def _clean(d):
    """Drop pydarshan's stringified DataFrame leftovers."""
    return {k: v for k, v in (d or {}).items() if k not in ("agg_counters", "agg_fcounters")}


def _mount_of(f, path):
    best = None
    for m in f.get("mounts", []):
        if path.startswith(m["mount"]) and (best is None or len(m["mount"]) > len(best["mount"])):
            best = m
    return best


def _nodes(f):
    """Node count: DXT hostnames when DXT traced every rank, else the job name."""
    dx = f.get("dxt_posix") or {}
    seen = len(dx.get("hosts") or []) or None
    named = f.get("nodes")              # the caller's node count, if given
    named = int(named) if named else None
    if seen and dx.get("n_ranks") == f["job"]["nprocs"]:
        return seen, "DXT hostnames (DXT traced every rank)"
    if named:
        return named, "given by the caller" + ("; DXT saw %d host(s) but traced only %s of %d ranks"
                                    % (seen, dx.get("n_ranks"), f["job"]["nprocs"]) if seen else "")
    return (seen or 1), ("DXT hostnames, a lower bound" if seen else "no DXT hostnames; assumed 1")


# ------------------------------------------------------------------ derived
def derived(f):
    """Standard derived metrics, each {value, formula}. Pure arithmetic over the facts."""
    j, p = f["job"], f.get("posix") or {}
    a, ft, sp = p.get("agg") or {}, p.get("ftimes") or {}, p.get("span") or {}
    d = p.get("derived") or {}
    np_, rt = j["nprocs"], j["run_time"]
    nodes, _ = _nodes(f)
    rd, wr = a.get("POSIX_BYTES_READ", 0), a.get("POSIX_BYTES_WRITTEN", 0)
    nr, nw = a.get("POSIX_READS", 0), a.get("POSIX_WRITES", 0)
    by, ops = rd + wr, nr + nw
    rtime, wtime, mtime = (ft.get("POSIX_F_READ_TIME", 0), ft.get("POSIX_F_WRITE_TIME", 0),
                           ft.get("POSIX_F_META_TIME", 0))
    iot = rtime + wtime + mtime
    perf, slow = d.get("agg_perf_by_slowest"), d.get("agg_time_by_slowest")
    mdops = sum(a.get(k, 0) for k in ("POSIX_OPENS", "POSIX_STATS", "POSIX_SEEKS", "POSIX_FSYNCS",
                                      "POSIX_FDSYNCS", "POSIX_DUPS", "POSIX_FILENOS"))
    hr, hw = p.get("hist_read") or {}, p.get("hist_write") or {}
    small = sum(hr.get(b, 0) for b in SMALL_BINS) + sum(hw.get(b, 0) for b in SMALL_BINS)
    acc = sum(hr.values()) + sum(hw.values())
    exact1 = sum(c for s, c in p.get("common_access") or [] if s == MiB)
    strict = max(small - exact1, 0)
    rwin = (sp.get("last_read", 0) - sp.get("first_read", 0)) if rd else 0
    wwin = (sp.get("last_write", 0) - sp.get("first_write", 0)) if wr else 0
    files = p.get("n_unique_files", 0)
    cat = (d.get("categories") or {}).get("all") or {}
    stride = sum(c for _, c in p.get("common_stride") or [])
    al = p.get("alignment") or {}
    pr = p.get("per_rank") or {}
    sb, sl = p.get("shared_balance"), p.get("shared_balance_slowest")
    iofr = div(slow, rt)
    lus = f.get("lustre") or {}

    M = {}

    def put(name, value, formula, unit=""):
        M[name] = dict(value=value, formula=formula, **({"unit": unit} if unit else {}))

    put("bytes_total", by, "POSIX_BYTES_READ + POSIX_BYTES_WRITTEN", "B")
    put("data_ops", ops, "POSIX_READS + POSIX_WRITES")
    put("read_fraction_of_bytes", div(rd, by), "POSIX_BYTES_READ / bytes_total  (how read- or write-dominated the job is)")
    put("agg_perf_by_slowest", perf, "darshan-parser --perf: total_bytes / agg_time_by_slowest  (Darshan's standard aggregate bandwidth)", "MiB/s")
    put("agg_time_by_slowest", slow, "darshan-parser --perf: I/O time on the critical path (slowest rank)", "s")
    put("io_fraction_of_runtime", iofr, "agg_time_by_slowest / run_time")
    put("cumulative_io_time", iot, "POSIX_F_READ_TIME + POSIX_F_WRITE_TIME + POSIX_F_META_TIME (summed over ranks)", "s")
    put("read_bw_busy", div(div(rd, MiB), rtime), "POSIX_BYTES_READ / 2^20 / POSIX_F_READ_TIME  (rate per busy second)", "MiB/s")
    put("write_bw_busy", div(div(wr, MiB), wtime), "POSIX_BYTES_WRITTEN / 2^20 / POSIX_F_WRITE_TIME", "MiB/s")
    put("read_window", rwin, "last_read - first_read  (wall-clock read window)", "s")
    put("write_window", wwin, "last_write - first_write", "s")
    put("read_bw_wall", div(div(rd, MiB), rwin), "POSIX_BYTES_READ / 2^20 / read_window", "MiB/s")
    put("write_bw_wall", div(div(wr, MiB), wwin), "POSIX_BYTES_WRITTEN / 2^20 / write_window", "MiB/s")
    put("bytes_per_rank", div(by, np_), "bytes_total / nprocs", "B")
    put("bw_per_rank", div(perf, np_), "agg_perf_by_slowest / nprocs", "MiB/s")
    put("bytes_per_node", div(by, nodes), "bytes_total / nodes  (nodes: view job)", "B")
    put("bw_per_node", div(perf, nodes), "agg_perf_by_slowest / nodes", "MiB/s")
    put("bytes_per_wallsecond", div(by, rt), "bytes_total / run_time  (job-average I/O intensity)", "B/s")
    put("MiBps_wall", div(div(by, rt), MiB), "bytes_per_wallsecond / 2^20", "MiB/s")
    put("mean_read_size", div(rd, nr), "POSIX_BYTES_READ / POSIX_READS", "B")
    put("mean_write_size", div(wr, nw), "POSIX_BYTES_WRITTEN / POSIX_WRITES", "B")
    put("mean_bytes_per_op", div(by, ops), "bytes_total / data_ops", "B")
    put("small_accesses", small, "sum of the five size bins <= 1 MiB, reads + writes (Darshan's 100K-1M bin includes exactly 1 MiB)")
    put("total_accesses", acc, "sum of all size bins, reads + writes")
    put("small_fraction", div(small, acc), "small_accesses / total_accesses")
    put("exactly_1MiB_accesses", exact1, "common-access count at exactly 1048576 B")
    put("strictly_small_accesses", strict, "small_accesses - exactly_1MiB_accesses")
    put("strictly_small_fraction", div(strict, acc), "strictly_small_accesses / total_accesses")
    put("sequential_fraction", div(a.get("POSIX_SEQ_READS", 0) + a.get("POSIX_SEQ_WRITES", 0), ops), "(SEQ_READS + SEQ_WRITES) / data_ops")
    put("consecutive_fraction", div(a.get("POSIX_CONSEC_READS", 0) + a.get("POSIX_CONSEC_WRITES", 0), ops), "(CONSEC_READS + CONSEC_WRITES) / data_ops")
    put("strided_ops", stride, "sum of the common-stride counts")
    put("strided_fraction", div(stride, ops), "strided_ops / data_ops")
    put("rw_switches_per_file", div(a.get("POSIX_RW_SWITCHES", 0), files), "POSIX_RW_SWITCHES / unique files")
    put("file_not_aligned_fraction", div(al.get("file_not_aligned", 0), ops), "POSIX_FILE_NOT_ALIGNED / data_ops")
    put("mem_not_aligned_fraction", div(al.get("mem_not_aligned", 0), ops), "POSIX_MEM_NOT_ALIGNED / data_ops")
    put("metadata_ops", mdops, "OPENS + STATS + SEEKS + FSYNCS + FDSYNCS + DUPS + FILENOS")
    put("metadata_to_data_ratio", div(mdops, ops), "metadata_ops / data_ops")
    put("metadata_rate_busy", div(mdops, mtime) if mtime else None, "metadata_ops / POSIX_F_META_TIME  (ops/s while inside metadata calls)", "ops/s")
    put("metadata_rate_wall", div(mdops, rt), "metadata_ops / run_time", "ops/s")
    put("meta_time_fraction", div(mtime, iot), "POSIX_F_META_TIME / cumulative_io_time")
    put("read_time_fraction", div(rtime, iot), "POSIX_F_READ_TIME / cumulative_io_time")
    put("write_time_fraction", div(wtime, iot), "POSIX_F_WRITE_TIME / cumulative_io_time")
    put("opens_per_file", div(a.get("POSIX_OPENS", 0), files), "POSIX_OPENS / unique files")
    put("reuse_factor", div(by, cat.get("total_max_offset")), "bytes_total / total_max_offset  (bytes moved per byte of file address space)")
    if sb:
        put("shared_slow_fast_ratio", div(sb["slowest_time"], sb["fastest_time"]), "slowest_time / fastest_time on the busiest shared file by bytes")
    if sl:
        put("shared_slowest_by_time_ratio", div(sl["slowest_time"], sl["fastest_time"]), "slowest_time / fastest_time on the shared file with the slowest rank time")
        put("straggler_share_of_critical_path", div(sl["slowest_time"], slow), "that slowest_time / agg_time_by_slowest")
    if pr:
        put("iotime_max_over_mean", div(pr.get("iotime_max"), pr.get("iotime_mean")), "per_rank iotime_max / iotime_mean")
        put("rank0_fair_share", div(1.0, max(pr.get("n_ranks_with_io") or 1, 1)), "1 / n_ranks_with_io  (an even split)")
    if lus:
        put("ranks_per_ost", div(np_, lus.get("distinct_osts")), "nprocs / distinct_osts")
    dx = f.get("dxt_posix") or {}
    if dx:
        put("dxt_segments", dx.get("n_read_segments", 0) + dx.get("n_write_segments", 0), "n_read_segments + n_write_segments")
        if dx.get("t_first") is not None:
            put("dxt_span", dx["t_last"] - dx["t_first"], "t_last - t_first", "s")
    for mod, ent in (f.get("heatmap") or {}).items():
        if not isinstance(ent, dict):
            continue
        for op, o in (ent.get("ops") or {}).items():
            if o.get("active_bins"):
                put("heatmap_%s_%s_duty_cycle" % (mod, op), div(o["active_bins"], ent.get("n_bins")),
                    "active_bins / n_bins")
    m = f.get("mpiio")
    if m:
        ma = m["agg"]
        coll = ma.get("MPIIO_COLL_READS", 0) + ma.get("MPIIO_COLL_WRITES", 0)
        ind = ma.get("MPIIO_INDEP_READS", 0) + ma.get("MPIIO_INDEP_WRITES", 0)
        mb = ma.get("MPIIO_BYTES_READ", 0) + ma.get("MPIIO_BYTES_WRITTEN", 0)
        put("mpiio_collective_ops", coll, "MPIIO_COLL_READS + MPIIO_COLL_WRITES")
        put("mpiio_independent_ops", ind, "MPIIO_INDEP_READS + MPIIO_INDEP_WRITES")
        put("mpiio_collective_fraction", div(coll, coll + ind), "collective / (collective + independent)")
        put("mpiio_bytes", mb, "MPIIO_BYTES_READ + MPIIO_BYTES_WRITTEN", "B")
        put("posix_over_mpiio_bytes", div(by, mb), "bytes_total / mpiio_bytes  (amplification)")
        put("mpiio_nonblocking_ops", ma.get("MPIIO_NB_READS", 0) + ma.get("MPIIO_NB_WRITES", 0), "NB_READS + NB_WRITES")
        put("mpiio_split_ops", ma.get("MPIIO_SPLIT_READS", 0) + ma.get("MPIIO_SPLIT_WRITES", 0), "SPLIT_READS + SPLIT_WRITES")
    s = f.get("stdio")
    if s:
        sa = s["agg"]
        sbytes = sa.get("STDIO_BYTES_READ", 0) + sa.get("STDIO_BYTES_WRITTEN", 0)
        put("stdio_bytes", sbytes, "STDIO_BYTES_READ + STDIO_BYTES_WRITTEN", "B")
        put("stdio_calls", sa.get("STDIO_READS", 0) + sa.get("STDIO_WRITES", 0), "STDIO_READS + STDIO_WRITES")
        put("stdio_time", sum((s.get("times") or {}).values()), "STDIO_F_READ_TIME + WRITE_TIME + META_TIME", "s")
        put("stdio_share_of_bytes", div(sbytes, by + sbytes), "stdio_bytes / (bytes_total + stdio_bytes)")
    return M


# ------------------------------------------------------------------ cards
# One card per analysis concern, each holding the canonical measures an I/O
# analyst reports for it, computed from the log facts. The card decides WHICH
# correct number answers a concern (e.g. per-rank I/O time rather than the
# shared-file fastest/slowest pair). A concern that does not exist in this job
# says so in "not_applicable" and carries no numbers.
SMALL = ["0_100", "100_1K", "1K_10K", "10K_100K", "100K_1M"]
BINS = SMALL + ["1M_4M", "4M_10M", "10M_100M", "100M_1G", "1G_PLUS"]


def _na(why):
    return {"not_applicable": why}


def _bottleneck(f, M):
    """Rule-based ranking of I/O issues (fixed thresholds, highest score first)."""
    p = f.get("posix") or {}
    a = p.get("agg") or {}
    v = lambda k: (M.get(k) or {}).get("value")              # noqa: E731
    by, ops = v("bytes_total") or 0, v("data_ops") or 0
    small_fr = v("strictly_small_fraction") or 0
    mean_op = v("mean_bytes_per_op") or 0
    meta_fr = v("meta_time_fraction") or 0
    opf = (p.get("file_stats") or {}).get("open_redundancy") or 0
    unal = v("file_not_aligned_fraction") or 0
    m = f.get("mpiio")
    coll = (m["agg"].get("MPIIO_COLL_READS", 0) + m["agg"].get("MPIIO_COLL_WRITES", 0)) if m else None
    sl, pr = p.get("shared_balance_slowest"), p.get("per_rank")
    slow = ((p.get("derived") or {}).get("agg_time_by_slowest"))
    imb = (div(sl["slowest_time"], sl["fastest_time"]) if sl and sl["fastest_time"] else 0) or 0
    imb_cost = (div(sl["slowest_time"], slow) if sl and slow else 0) or 0
    imb_material = imb_cost > 0.05 or bool(sl and sl["slowest_time"] > 1.0)
    rank_cv = (pr["iotime_cv"] if pr else 0) or 0
    perf = v("agg_perf_by_slowest")
    l = f.get("lustre")
    stripe1 = bool(l and l["stripe_counts"] == [1])
    cand = []
    if meta_fr > 0.5:
        cand.append((90 + meta_fr * 10, "Metadata-bound", dict(meta_time_fraction=meta_fr)))
    if opf > 4:
        cand.append((40 + min(opf, 20) * 2 + meta_fr * 100, "Redundant opens (open storm)",
                     dict(open_redundancy=opf, meta_time_fraction=meta_fr)))
    if small_fr > 0.5 and mean_op < MiB:
        cand.append((60 + small_fr * 30, "Small-request bound",
                     dict(strictly_small_fraction=small_fr, mean_bytes_per_op=mean_op)))
    if m:
        ind = m["agg"].get("MPIIO_INDEP_READS", 0) + m["agg"].get("MPIIO_INDEP_WRITES", 0)
        if coll == 0 and ind == 0:
            cand.append((62, "MPI-IO opened but bypassed",
                         dict(collective_opens=m["agg"].get("MPIIO_COLL_OPENS", 0), posix_bytes=by)))
        elif coll == 0:
            cand.append((65, "Independent-only MPI-IO on a shared file", dict(independent_ops=ind)))
    if unal > 0.5:
        cand.append((55, "Unaligned accesses", dict(file_not_aligned_fraction=unal)))
    if stripe1 and by > 2 ** 30:
        cand.append((58, "Single-OST striping on a large file", dict(stripe_count=1)))
    if imb > 2.0 and imb_material:
        cand.append((50 + min(imb, 20) * 1.5, "Rank imbalance / stragglers",
                     dict(slowest_to_fastest=imb, straggler_share_of_critical_path=imb_cost)))
    elif rank_cv > 0.5 and pr:
        cand.append((48, "Rank imbalance / stragglers",
                     dict(rank_time_cv=rank_cv, n_ranks_with_io=pr["n_ranks_with_io"])))
    if not cand:
        cand = [(10, "No dominant I/O pathology",
                 dict(agg_perf_by_slowest_MiBps=perf, mean_bytes_per_op=mean_op,
                      strictly_small_fraction=small_fr, meta_time_fraction=meta_fr))]
    cand.sort(key=lambda x: -x[0])
    return dict(ranked=[dict(rank=i + 1, issue=c[1], evidence=c[2]) for i, c in enumerate(cand[:4])],
                signals=dict(strictly_small_fraction=small_fr, mean_bytes_per_op=mean_op, meta_fraction=meta_fr,
                             open_redundancy=opf, unaligned_fraction=unal, imbalance=imb,
                             imbalance_cost_share=imb_cost, rank_time_cv=rank_cv))


def cards(f):
    M = derived(f)
    v = lambda k: (M.get(k) or {}).get("value")              # noqa: E731
    p, j = f.get("posix") or {}, f["job"]
    a, fs = p.get("agg") or {}, p.get("file_stats") or {}
    cat = (p.get("derived") or {}).get("categories") or {}
    al, mx, sp = p.get("alignment") or {}, p.get("maxes") or {}, p.get("span") or {}
    pr = p.get("per_rank")
    nodes, how = _nodes(f)
    C = {}
    C["provenance"] = dict(exe=j.get("exe_bin"), args=j.get("exe_args"), nprocs=j["nprocs"], nodes=nodes,
                           nodes_source=how, run_time_s=j["run_time"], jobid=j.get("jobid"), uid=j.get("uid"),
                           start_utc=__import__("datetime").datetime.fromtimestamp(
                               j["start"], __import__("datetime").timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
                           darshan_library_version=j.get("lib_ver"), log_format_version=j.get("log_ver"),
                           log_file_bytes=f.get("log_bytes"), runtime_metadata=j.get("darshan_h") or None)
    usual = ["MPI-IO", "LUSTRE", "DXT_POSIX", "STDIO", "HEATMAP"]
    C["modules"] = dict(present=f.get("modules"), missing=[m for m in usual if m not in f.get("modules", [])])
    hot = {}
    for t in p.get("top_files") or []:
        mt = _mount_of(f, t["name"])
        if mt:
            k = "%s (%s)" % (mt["mount"], mt["fstype"])
            hot[k] = hot.get(k, 0) + 1
    ms = f.get("mounts") or []
    C["file_systems"] = dict(hot_files_per_mount=hot, mount_table_entries=len(ms),
                             summary="%s; the mount table has %d entries." % (
                                 "; ".join("%d hot file(s) on %s" % (n, k) for k, n in hot.items())
                                 or "no hot file matches a mount", len(ms)))
    mm = f.get("module_meta") or {}
    part = [k for k, m in mm.items() if m.get("partial_flag")]
    recs = {k: m.get("num_records") for k, m in mm.items() if m.get("num_records") is not None}
    C["completeness"] = dict(partial_modules=part, records_per_module=recs,
                             summary="%s; records per module: %s." % (
                                 "Incomplete: partial flag on %s" % ", ".join(part) if part
                                 else "Complete: no module has the partial flag",
                                 ", ".join("%s %d" % kv for kv in recs.items())))
    C["volume"] = dict(bytes_read=a.get("POSIX_BYTES_READ", 0), bytes_written=a.get("POSIX_BYTES_WRITTEN", 0),
                       bytes_total=v("bytes_total"), reads=a.get("POSIX_READS", 0), writes=a.get("POSIX_WRITES", 0))
    rd, wr = a.get("POSIX_BYTES_READ", 0), a.get("POSIX_BYTES_WRITTEN", 0)
    rf = v("read_fraction_of_bytes")
    C["read_write_mix"] = dict(read_fraction_of_bytes=rf, label=(
        "write-only" if rd == 0 else "read-only" if wr == 0 else "read-dominated" if rf > 0.8 else
        "write-dominated" if rf < 0.2 else "mixed / balanced"))
    C["bandwidth"] = dict(agg_perf_by_slowest_MiBps=v("agg_perf_by_slowest"), total_bytes=(p.get("derived") or {}).get("total_bytes"),
                          agg_time_by_slowest_s=v("agg_time_by_slowest"))
    C["read_write_rates"] = dict(read_bw_busy_MiBps=v("read_bw_busy") if a.get("POSIX_READS") else None,
                                 write_bw_busy_MiBps=v("write_bw_busy") if a.get("POSIX_WRITES") else None,
                                 read_bw_wall_MiBps=v("read_bw_wall"), write_bw_wall_MiBps=v("write_bw_wall"),
                                 read_window_s=v("read_window"), write_window_s=v("write_window"))
    C["io_time_share"] = dict(io_fraction_of_runtime=v("io_fraction_of_runtime"), agg_time_by_slowest_s=v("agg_time_by_slowest"),
                              cumulative_io_time_s=v("cumulative_io_time"), run_time_s=j["run_time"])
    C["per_rank_and_node"] = dict(bytes_per_rank=v("bytes_per_rank"), bw_per_rank_MiBps=v("bw_per_rank"),
                                  bytes_per_node=v("bytes_per_node"), bw_per_node_MiBps=v("bw_per_node"))
    C["io_intensity"] = dict(bytes_per_wallsecond=v("bytes_per_wallsecond"), MiBps_wall=v("MiBps_wall"))
    C["request_size"] = dict(mean_read_bytes=v("mean_read_size"), mean_write_bytes=v("mean_write_size"),
                             mean_bytes_per_op=v("mean_bytes_per_op"))
    ca = p.get("common_access") or []
    C["common_access_sizes"] = dict(top=[dict(size_bytes=s, count=c) for s, c in ca],
                                    uniform=bool(len(ca) == 1 or (ca and ca[0][1] / (sum(c for _, c in ca) or 1) > 0.9)))
    for side in ("read", "write"):
        h = p.get("hist_" + side) or {}
        C["size_histogram_" + side] = dict(bins=h, total=sum(h.values()))
    C["small_accesses"] = dict(small_accesses=v("small_accesses"), total_accesses=v("total_accesses"),
                               small_fraction=v("small_fraction"), exactly_1MiB=v("exactly_1MiB_accesses"),
                               strictly_small=v("strictly_small_accesses"), strictly_small_fraction=v("strictly_small_fraction"))
    C["sequentiality"] = dict(seq_reads=a.get("POSIX_SEQ_READS", 0), seq_writes=a.get("POSIX_SEQ_WRITES", 0),
                              consec_reads=a.get("POSIX_CONSEC_READS", 0), consec_writes=a.get("POSIX_CONSEC_WRITES", 0),
                              sequential_fraction=v("sequential_fraction"), consecutive_fraction=v("consecutive_fraction"))
    st = p.get("common_stride") or []
    C["strided_access"] = (dict(strides=[dict(stride_bytes=s, count=c) for s, c in st], strided_ops=v("strided_ops"))
                           if st else dict(strided_ops=0, summary="No strided access: strided_ops = 0 (all stride slots empty)."))
    C["read_write_switches"] = dict(rw_switches=a.get("POSIX_RW_SWITCHES", 0), switches_per_file=v("rw_switches_per_file"))
    C["largest_requests"] = {k: mx.get(k) for k in mx}
    C["file_alignment"] = dict(file_not_aligned=al.get("file_not_aligned", 0), fraction=v("file_not_aligned_fraction"),
                               file_alignment_bytes=al.get("file_alignment"))
    C["memory_alignment"] = dict(mem_not_aligned=al.get("mem_not_aligned", 0), fraction=v("mem_not_aligned_fraction"),
                                 mem_alignment_bytes=al.get("mem_alignment"))
    C["metadata_ops"] = dict(total_metadata_ops=v("metadata_ops"), opens=a.get("POSIX_OPENS", 0), stats=a.get("POSIX_STATS", 0),
                             seeks=a.get("POSIX_SEEKS", 0), fsyncs=a.get("POSIX_FSYNCS", 0), fdsyncs=a.get("POSIX_FDSYNCS", 0),
                             md_to_data_ratio=v("metadata_to_data_ratio"))
    ft = p.get("ftimes") or {}
    C["metadata_time"] = dict(meta_time_s=ft.get("POSIX_F_META_TIME", 0), read_time_s=ft.get("POSIX_F_READ_TIME", 0),
                              write_time_s=ft.get("POSIX_F_WRITE_TIME", 0), meta_fraction=v("meta_time_fraction"),
                              total_io_time_s=v("cumulative_io_time"))
    C["open_redundancy"] = dict(opens=a.get("POSIX_OPENS", 0), unique_files=p.get("n_unique_files"),
                                opens_per_file=v("opens_per_file"), max_opens_one_file=fs.get("max_opens_one_file"),
                                expected_min_opens=fs.get("expected_min_opens"), open_redundancy=fs.get("open_redundancy"))
    C["metadata_rate"] = dict(md_rate_busy_ops_per_s=v("metadata_rate_busy"), md_rate_wall_ops_per_s=v("metadata_rate_wall"))
    C["metadata_only_files"] = dict(metadata_only_files=fs.get("metadata_only_files", 0), zero_byte_files=fs.get("zero_byte_files"),
                                    n_files=fs.get("n_files"))
    C["file_count"] = dict(unique_files=p.get("n_unique_files"), records=p.get("n_records"),
                           shared_records=p.get("n_shared_recs"), rank_private_records=p.get("n_uniq_recs"))
    g = lambda k: (cat.get(k) or {}).get("count")              # noqa: E731
    C["file_access_modes"] = dict(read_only=g("read_only"), write_only=g("write_only"), read_write=g("read_write"),
                                  all=g("all"), read_only_bytes_read=(cat.get("read_only") or {}).get("read_bytes"),
                                  write_only_bytes_written=(cat.get("write_only") or {}).get("write_bytes"))
    sh, un = fs.get("shared_files", 0), fs.get("uniq_files", 0)
    C["sharing_mode"] = dict(mode=("single shared file" if sh == 1 and un == 0 else "shared-file" if sh and not un else
                                   "file-per-process" if un and not sh else "mixed (shared + rank-private)"),
                             shared_files=sh, rank_private_files=un, category_unique=g("unique"),
                             category_shared=g("shared"), category_part_shared=g("part_shared"),
                             summary="%d shared file(s), %d rank-private file(s)." % (sh, un))
    tf = p.get("top_files") or []
    C["dominant_file"] = (dict(file=tf[0]["name"], bytes=tf[0]["bytes"], share_of_all_bytes=fs.get("top1_share"),
                               bytes_read=tf[0]["rd"], bytes_written=tf[0]["wr"], opens=tf[0]["opens"],
                               shared=tf[0].get("shared"),
                               top_files=[dict(file=t["name"], bytes=t["bytes"]) for t in tf[:5]])
                          if tf else _na("no file records"))
    C["small_files"] = dict(files_lt_1MiB=fs.get("lt1MiB_files", 0), files_ge_1GiB=fs.get("ge1GiB_files"),
                            n_files=fs.get("n_files"), small_file_fraction=div(fs.get("lt1MiB_files", 0), fs.get("n_files")))
    ca_all = cat.get("all") or {}
    C["file_footprint"] = dict(max_offset=ca_all.get("max_offset"), total_max_offset=ca_all.get("total_max_offset"),
                               reuse_factor=v("reuse_factor"))
    sb, sl = p.get("shared_balance"), p.get("shared_balance_slowest")
    C["shared_file_rank_spread"] = (dict(busiest_shared_file_by_bytes=sb, slow_fast_time_ratio=v("shared_slow_fast_ratio"),
                                         slowest_by_time=sl, straggler_share_of_critical_path=v("straggler_share_of_critical_path"))
                                    if sb else _na("no shared-file record: every file is rank-private"))
    C["rank_byte_balance"] = (dict(pr)
                              if pr else _na("all I/O is in shared-file records, so no per-rank byte split survives"))
    C["rank_time_balance"] = (dict(iotime_min_s=pr["iotime_min"], iotime_mean_s=pr["iotime_mean"], iotime_max_s=pr["iotime_max"],
                                   iotime_cv=pr["iotime_cv"])
                              if pr else _na("no rank-private records, so per-rank I/O time is not separable"))
    C["rank0_share"] = (dict(rank0_byte_share=pr["rank0_byte_share"], fair_share=div(1.0, max(pr["n_ranks_with_io"], 1)),
                             n_ranks_with_io=pr["n_ranks_with_io"])
                        if pr else _na("all I/O is through shared-file records, so rank 0's share is not recorded"))
    m = f.get("mpiio")
    if m:
        ma = m["agg"]
        C["mpiio_use"] = dict(n_files=m["n_files"], collective_opens=ma.get("MPIIO_COLL_OPENS"), independent_opens=ma.get("MPIIO_INDEP_OPENS"),
                              bytes_read=ma.get("MPIIO_BYTES_READ"), bytes_written=ma.get("MPIIO_BYTES_WRITTEN"))
        C["mpiio_collective"] = dict(coll_reads=ma.get("MPIIO_COLL_READS"), coll_writes=ma.get("MPIIO_COLL_WRITES"),
                                     indep_reads=ma.get("MPIIO_INDEP_READS"), indep_writes=ma.get("MPIIO_INDEP_WRITES"),
                                     collective_fraction=v("mpiio_collective_fraction"))
        C["mpiio_vs_posix"] = dict(mpiio_bytes=v("mpiio_bytes"), posix_bytes=v("bytes_total"), amplification=v("posix_over_mpiio_bytes"),
                                   mpiio_ops=v("mpiio_collective_ops") + v("mpiio_independent_ops"), posix_ops=v("data_ops"))
        C["mpiio_hints_views"] = dict(runtime_metadata=j.get("darshan_h") or None, hint_calls=ma.get("MPIIO_HINTS"),
                                      file_views=ma.get("MPIIO_VIEWS"), nonblocking_ops=v("mpiio_nonblocking_ops"),
                                      split_collective_ops=v("mpiio_split_ops"))
    else:
        why = "no MPI-IO module in this log: the application made no MPI-IO calls"
        C["mpiio_use"] = dict(_na(why), posix_bytes=v("bytes_total"))
        C["mpiio_collective"] = _na(why)
        C["mpiio_vs_posix"] = _na(why + ", so POSIX is the only layer")
        C["mpiio_hints_views"] = dict(_na(why + ", so no hints, views or nonblocking ops"), runtime_metadata=j.get("darshan_h") or None)
    s = f.get("stdio")
    C["stdio"] = (dict(n_streams=s["n_files"], bytes=v("stdio_bytes"), calls=v("stdio_calls"), time_s=v("stdio_time"),
                       reads=s["agg"].get("STDIO_READS"), writes=s["agg"].get("STDIO_WRITES"))
                  if s else _na("no STDIO module: the job did no buffered stdio I/O that Darshan saw"))
    l = f.get("lustre")
    C["lustre_striping"] = (dict(n_files=l["n_files"], stripe_counts=l["stripe_counts"], stripe_sizes_bytes=l["stripe_sizes"],
                                 pools=[x or "(default)" for x in l["pools"]])
                            if l else _na("no LUSTRE module: striping was not captured"))
    C["lustre_osts"] = (dict(distinct_osts=l["distinct_osts"], ranks_per_ost=v("ranks_per_ost"))
                        if l else _na("no LUSTRE records"))
    d = f.get("dxt_posix")
    C["dxt_trace"] = (dict(segments=v("dxt_segments"), read_segments=d["n_read_segments"], write_segments=d["n_write_segments"],
                           ranks=d["n_ranks"], hosts=len(d.get("hosts") or []), t_first_s=d["t_first"], t_last_s=d["t_last"],
                           span_s=v("dxt_span"), write_len_mean=d["write_len_mean"], read_len_mean=d["read_len_mean"])
                      if d else _na("DXT was not enabled: no per-operation trace"))
    hm = {}
    for mod, ent in (f.get("heatmap") or {}).items():
        if not isinstance(ent, dict):
            continue
        for op, o in (ent.get("ops") or {}).items():
            if o.get("active_bins"):
                hm["%s %s" % (mod, op)] = dict(o, duty_cycle=div(o["active_bins"], ent.get("n_bins")))
    C["temporal_shape"] = hm or _na("no usable HEATMAP data")
    C["bottleneck"] = _bottleneck(f, M)
    C["bottleneck"]["summary"] = "; ".join(
        "%d. %s (%s)" % (r["rank"], r["issue"], ", ".join("%s = %.4g" % (k, x) for k, x in r["evidence"].items()
                                                          if isinstance(x, (int, float)) and not isinstance(x, bool)))
        for r in C["bottleneck"]["ranked"]) + "."
    C["verdict"] = dict(io_fraction_of_runtime=v("io_fraction_of_runtime"), achieved_MiBps=v("agg_perf_by_slowest"),
                        run_time_s=j["run_time"],
                        verdict=("I/O-bound" if (v("io_fraction_of_runtime") or 0) > 0.5 else "I/O-significant"
                                 if (v("io_fraction_of_runtime") or 0) > 0.2 else "compute/other-bound"
                                 if (v("io_fraction_of_runtime") or 0) < 0.05 else "mixed"))
    return C


# -------------------------------------------------------------------- views
VIEW_DOC = {
    "cards": "one card per analysis concern (provenance, volume, bandwidth, request size, metadata, files, "
             "rank balance, MPI-IO, Lustre, DXT, temporal shape, bottleneck, verdict ...), each with the canonical "
             "measures to report for that concern -- call this first",
    "all": "every view below in one result (about 25k characters)",
    "derived": "every standard derived metric (bandwidth, I/O fraction, busy/wall rates, per-rank/node, "
               "request sizes, small-access, sequentiality, alignment, metadata rates and shares, reuse, "
               "stragglers, MPI-IO, stdio), each with its formula",
    "job": "header: nprocs, nodes (+ how counted), run_time, start/end, jobid, uid, exe, args, "
           "Darshan lib/log version, runtime metadata string (hints), log file size in bytes",
    "modules": "every module in the log with num_records, partial_flag and on-disk length",
    "perf": "darshan-parser --perf per module: total_bytes, agg_perf_by_slowest (MiB/s), "
            "agg_time_by_slowest and the unique/shared time split",
    "file_categories": "darshan-parser --file categories per module: all / read_only / write_only / read_write / "
                       "unique / shared / part_shared, each with count, bytes, max offsets",
    "files": "record and file counts (records, unique files, shared vs rank-private records) and file "
             "statistics: zero-byte, <1 MiB, >=1 GiB, metadata-only files, top-file share, open redundancy",
    "top_files": "the files with the most traffic, each with bytes, read/written, opens, reads, writes, "
                 "shared flag, and the mount point + file-system type it lives on",
    "counters": "aggregate POSIX counters, max-offset/max-time sizes, cumulative times, slowest/variance fields",
    "access": "read and write size histograms, the four most common access sizes and strides, alignment, "
              "first/last read/write timestamps",
    "ranks": "per-rank byte and time distribution (min/mean/max/CV, busiest/quietest, rank-0 share, opens) "
             "and the fastest/slowest rank on the busiest shared files",
    "mounts": "the job's mount table (count, and each mount point with its file-system type)",
    "lustre": "stripe counts, stripe sizes, pools, distinct OSTs and OST ids",
    "dxt": "DXT trace summary: segments, ranks, hosts, first/last timestamps, mean/max traced sizes",
    "heatmap": "HEATMAP per module and operation: bin width, active bins, first/last/peak bins, "
               "top-10%-bin share of bytes",
    "stdio": "STDIO module counters and times",
    "mpiio": "MPI-IO module counters (opens, collective/independent/nonblocking/split ops, hints, views, bytes)",
}


def view(f, name):
    p = f.get("posix") or {}
    j = f["job"]
    if name == "cards":
        return cards(f)
    if name == "all":
        return {k: view(f, k) for k in VIEW_DOC if k not in ("all", "cards")}
    if name == "derived":
        return derived(f)
    if name == "job":
        nodes, how = _nodes(f)
        return dict(j, nodes=nodes, nodes_source=how,
                    log_bytes=f.get("log_bytes"), modules=f.get("modules"))
    if name == "modules":
        return dict(modules=f.get("modules"), module_meta=f.get("module_meta"), has_apmpi=f.get("has_apmpi"))
    if name == "perf":
        out = {"POSIX": {k: v for k, v in _clean(p.get("derived")).items() if k != "categories"}}
        for mod in ("stdio", "mpiio"):
            if f.get(mod) and f[mod].get("derived"):
                out[mod.upper()] = {k: v for k, v in _clean(f[mod]["derived"]).items() if k != "categories"}
        return out
    if name == "file_categories":
        out = {"POSIX": (p.get("derived") or {}).get("categories")}
        for mod in ("stdio", "mpiio"):
            if f.get(mod) and (f[mod].get("derived") or {}).get("categories"):
                out[mod.upper()] = f[mod]["derived"]["categories"]
        return out
    if name == "files":
        return dict(n_records=p.get("n_records"), n_unique_files=p.get("n_unique_files"),
                    n_shared_records=p.get("n_shared_recs"), n_rank_private_records=p.get("n_uniq_recs"),
                    file_stats=p.get("file_stats"))
    if name == "top_files":
        out = []
        for t in p.get("top_files") or []:
            m = _mount_of(f, t["name"])
            out.append(dict(t, mount=m["mount"] if m else None, fstype=m["fstype"] if m else None))
        by_mount = {}
        for t in out:
            k = "%s (%s)" % (t["mount"], t["fstype"]) if t["mount"] else "(no mount match)"
            by_mount[k] = by_mount.get(k, 0) + 1
        return dict(top_files=out, top_files_by_mount=by_mount,
                    n_mounts_in_job=len(f.get("mounts") or []),
                    note="ordered by bytes moved; file_stats.top1_share in view files")
    if name == "counters":
        return dict(agg=p.get("agg"), maxes=p.get("maxes"), ftimes=p.get("ftimes"), fmax=p.get("fmax"))
    if name == "access":
        return dict(hist_read=p.get("hist_read"), hist_write=p.get("hist_write"),
                    common_access=p.get("common_access"), common_stride=p.get("common_stride"),
                    alignment=p.get("alignment"), span=p.get("span"))
    if name == "ranks":
        return dict(ranks_present=p.get("ranks_present"), per_rank=p.get("per_rank"),
                    shared_balance_busiest_by_bytes=p.get("shared_balance"),
                    shared_balance_slowest_by_time=p.get("shared_balance_slowest"))
    if name == "mounts":
        ms = f.get("mounts") or []
        return dict(n_mounts=len(ms), n_lustre_mounts=sum(1 for m in ms if m["fstype"] == "lustre"), mounts=ms)
    if name == "lustre":
        return f.get("lustre") or "no LUSTRE module in this log"
    if name == "dxt":
        out = {}
        for k in ("dxt_posix", "dxt_mpiio"):
            if f.get(k):
                out[k] = f[k]
        return out or "no DXT module in this log"
    if name == "heatmap":
        return f.get("heatmap") or "no HEATMAP module in this log"
    if name == "stdio":
        s = f.get("stdio")
        return {k: v for k, v in s.items() if k != "derived"} if s else "no STDIO module in this log"
    if name == "mpiio":
        m = f.get("mpiio")
        return {k: v for k, v in m.items() if k != "derived"} if m else "no MPI-IO module in this log"
    return None


# --------------------------------------------------------------------- calc
_FUN = dict(min=min, max=max, abs=abs, round=round, sqrt=math.sqrt, log2=math.log2, log10=math.log10,
            sum=lambda *x: sum(x[0]) if len(x) == 1 and isinstance(x[0], (list, tuple)) else sum(x),
            mean=lambda *x: (lambda v: sum(v) / len(v))(x[0] if len(x) == 1 and isinstance(x[0], (list, tuple)) else x))
_CONST = dict(KiB=2 ** 10, MiB=2 ** 20, GiB=2 ** 30, TiB=2 ** 40, KB=1e3, MB=1e6, GB=1e9)


def calc(expr):
    """Exact arithmetic: numbers, + - * / ** %, parentheses, lists, min/max/abs/round/sqrt/log2/log10/sum/mean, KiB..TiB."""
    tree = ast.parse(expr.replace(",", "") if re.fullmatch(r"[\d,.\s+\-*/()eE]+", expr) else expr, mode="eval")

    def ev(n):
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.BinOp):
            l, r = ev(n.left), ev(n.right)
            ops = {ast.Add: lambda: l + r, ast.Sub: lambda: l - r, ast.Mult: lambda: l * r,
                   ast.Div: lambda: l / r, ast.Pow: lambda: l ** r, ast.Mod: lambda: l % r,
                   ast.FloorDiv: lambda: l // r}
            if type(n.op) in ops:
                if isinstance(n.op, ast.Pow) and abs(r) > 64:
                    raise ValueError("exponent too large")
                return ops[type(n.op)]()
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd)):
            v = ev(n.operand)
            return -v if isinstance(n.op, ast.USub) else v
        if isinstance(n, (ast.List, ast.Tuple)):
            return [ev(e) for e in n.elts]
        if isinstance(n, ast.Name) and n.id in _CONST:
            return _CONST[n.id]
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _FUN and not n.keywords:
            return _FUN[n.func.id](*[ev(x) for x in n.args])
        raise ValueError("unsupported expression element: %s" % type(n).__name__)
    return ev(tree)


class Toolbox:
    """The tools over one log's facts."""

    def __init__(self, f):
        self.f = f

    def darshan(self, name):
        name = (name or "index").strip().lower()
        if name in ("", "index", "list", "help"):
            return "VIEWS -- darshan(<view>):\n" + "\n".join("  %-18s %s" % kv for kv in VIEW_DOC.items())
        if name not in VIEW_DOC:
            return "no view %r. Views: %s" % (name, ", ".join(VIEW_DOC))
        out = view(self.f, name)
        if name in ("all", "cards"):
            return json.dumps(out, separators=(",", ":"), default=str)
        return json.dumps(out, indent=1, default=str)[:RESULT_CHARS]

    def calc(self, expression):
        v = calc(expression)
        if isinstance(v, list):
            return json.dumps(v)
        return "%s = %r" % (expression, v)


TOOLS = [
    {"type": "function", "function": {
        "name": "darshan",
        "description": "Exact facts from this job's binary Darshan log, at full precision, by view. "
                       "darshan('cards') returns one card of canonical measures per analysis concern; call it first. "
                       "darshan('index') lists the views. Use darshan('derived') for any rate, fraction, "
                       "ratio, mean or efficiency: it holds Darshan's standard derived metrics, each with the "
                       "formula that produced it.",
        "parameters": {"type": "object", "properties": {
            "view": {"type": "string", "description": "one of: " + ", ".join(VIEW_DOC)}},
            "required": ["view"]}}},
    {"type": "function", "function": {
        "name": "calc",
        "description": "Exact arithmetic. Use it for every computation instead of doing math in your head. "
                       "Supports + - * / ** %, parentheses, lists, min max abs round sqrt log2 log10 sum mean, "
                       "and the constants KiB MiB GiB TiB KB MB GB. Example: calc('1554195 / MiB / 0.0772').",
        "parameters": {"type": "object", "properties": {
            "expression": {"type": "string"}}, "required": ["expression"]}}},
]

PRECISION_NOTE = """YOUR EXACT TOOLS -- in addition to outline / search / get over the schema:
  darshan(view)   exact facts from this job's binary log, full precision.
                  darshan("cards") returns one card per analysis concern (provenance, file systems,
                  completeness, volume, read/write mix, bandwidth, rates, request size, access
                  sizes, histograms, small accesses, sequentiality, strides, alignment, metadata,
                  files, sharing, dominant file, rank balance, MPI-IO, stdio, Lustre, DXT,
                  temporal shape, bottleneck, verdict), each holding the canonical measures for
                  that concern. darshan("index") lists the other views.
  calc(expr)      exact arithmetic.

PRECISION RULES
0. Call darshan("cards") first. For every question, find the card for its concern and answer
   from that card.
1. Report the card's measures for the concern -- all of those the question asks about, with
   units -- and no other numbers. Copy each number from the card with at least 4 significant
   digits: 0.01583 stays 0.01583 (never 0.02), 482.4317 may become 482.4. Do not restate the
   counters a measure was computed from, do not add or combine measures (no sums of two card
   values), and do not add numbers from other cards. A fraction may be given as a percentage
   (fraction x 100).
2. Verdicts come with their figures, always:
   - completeness: "Complete: no module has the partial flag; records: POSIX 56, LUSTRE 54,
     DXT_POSIX 114."
   - file systems: "All 8 hot files are on /scratch (lustre); the mount table has 26 entries."
   - temporal shape: active bins, duty cycle, first and last active second, peak.
   - balance: min, mean, max and CV.
2a. A card with a "summary" field: use the summary sentence as the core of the answer.
3. A card that says "not_applicable" is answered "Not applicable: <its reason>." with no number.
   A measure that is 0 means none ("no strided access"), not missing data.
4. Use calc() only when a question asks for something no card holds; never compute in your
   head. Refer to size bins by their Darshan names (POSIX_SIZE_READ_100K_1M), not as numeric
   ranges, and write counts in digits.
5. Answer each question from ONE card and name it, e.g. "(volume card)"."""
