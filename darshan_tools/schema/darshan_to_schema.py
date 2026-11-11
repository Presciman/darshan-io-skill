#!/usr/bin/env python3
"""
darshan_to_schema.py
====================================================================
Process a .darshan log and emit a JSON document that fills the
darshan_schema.yaml template, for consumption by a Darshan log-analysis agent.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 6

MODULE_TO_SCHEMA = {
    "POSIX": ("modules", "POSIX_IO", None),
    "STDIO": ("modules", "STDIO", None),
    "MPI-IO": ("modules", "MPIIO", None),
    "MPIIO": ("modules", "MPIIO", None),
    "H5F": ("modules", "HDF5", "H5F"),
    "H5D": ("modules", "HDF5", "H5D"),
    "PNETCDF_FILE": ("modules", "PNETCDF", "file"),
    "PNETCDF_VAR": ("modules", "PNETCDF", "variable"),
    "LUSTRE": ("storage", "LUSTRE", None),
    "DXT_POSIX": ("traces", "DXT", "POSIX"),
    "DXT_MPIIO": ("traces", "DXT", "MPIIO"),
    "HEATMAP": ("traces", "HEATMAP", None),
}


# Counters Darshan derives from file offsets. The parser prints a WARNING that
# all of them "may be incorrect if a file is simultaneously accessed by both
# POSIX and STDIO (e.g., using fileno())". v3 and earlier carried the numbers
# and not the warning, so a reader treated them as clean measurements.
OFFSET_DERIVED = re.compile(
    r"_(MAX_BYTE_(READ|WRITTEN)|CONSEC_(READS|WRITES)|SEQ_(READS|WRITES)"
    r"|(MEM|FILE)_NOT_ALIGNED|STRIDE[0-9]*_STRIDE)$")

SENTINEL = -1


def iter_counters(doc):
    """(dotted path, name, value) for every counter leaf in a filled doc."""
    for section in ("modules", "storage", "traces"):
        for mod, body in (doc.get(section) or {}).items():
            stack = [("%s.%s" % (section, mod), body)]
            while stack:
                prefix, node = stack.pop()
                if not isinstance(node, dict):
                    continue
                for k, v in node.items():
                    path = "%s.%s" % (prefix, k)
                    if isinstance(v, dict):
                        stack.append((path, v))
                    elif isinstance(v, (int, float)) and not isinstance(v, bool):
                        yield path, k, v


def unavailable_counters(doc):
    """Counter paths carrying Darshan's -1 "not available" sentinel.

    `-1` is not a measurement. It is what a rank-scoped pick
    (*_FASTEST_RANK*, *_SLOWEST_RANK*) or *_MMAPS reads when the value cannot
    be derived from this reduction. Published as a list so a reader can tell
    "absent" from "minus one" without having to know the convention.
    """
    return sorted(p for p, _, v in iter_counters(doc) if v == SENTINEL)


def offset_reliability(doc):
    """Whether Darshan's offset-derived counters are trustworthy HERE.

    darshan-parser warns that offset-derived counters may be incorrect when a
    file is reached through both POSIX and STDIO. The detectable precondition
    is a descriptor/stream conversion: fileno() (POSIX_FILENOS) or fdopen()
    (STDIO_FDOPENS). POSIX_DUPS is dup()/dup2() -- duplication WITHIN one
    interface -- so it is not evidence of the condition and is not consulted.

    What this field can and cannot say, written down because the first
    version overclaimed it: a positive count proves the job performed such a
    conversion, NOT that any particular file was read through both
    interfaces. A zero count means the conversion was not counted in this
    log, which is weaker than proof that no cross-interface access occurred.
    """
    counts = {}
    for _, name, value in iter_counters(doc):
        if name in ("POSIX_FILENOS", "STDIO_FDOPENS"):
            counts[name] = max(counts.get(name, 0), value)
    suspect = any(v > 0 for v in counts.values())
    affected = sorted({p for p, name, _ in iter_counters(doc)
                       if OFFSET_DERIVED.search(name)}) if suspect else []
    why = (", ".join("%s=%d" % kv for kv in sorted(counts.items()) if kv[1])
           or "no fileno()/fdopen() conversion counted in this log")
    return {
        "suspect": suspect,
        "evidence": why,
        "meaning": ("This job converted between file descriptors and STDIO "
                    "streams, the precondition darshan-parser warns about, so "
                    "the offset-derived counters listed below MAY be "
                    "incorrect. This does not establish that any particular "
                    "file was reached through both interfaces: treat those "
                    "counters as caveated, not as wrong."
                    if suspect else
                    "No fileno()/fdopen() conversion was counted, so the "
                    "condition darshan-parser warns about was not detected. "
                    "That is weaker than proof it did not occur."),
        "affected": affected,
    }


def modules_in_log(data, doc):
    """Every module the LOG carries, and whether this schema carries it.

    `presence` can only speak for a module the document already has a key
    for. HEATMAP is in most logs and in none of these documents, so to a
    reader it would look absent. This says it plainly instead.
    """
    carried = set()
    for section in ("modules", "storage", "traces"):
        for key in (doc.get(section) or {}):
            carried.add(key)
    out = {}
    for mod in (data.get("modules_present")
                or sorted(data.get("modules") or {})):
        target = MODULE_TO_SCHEMA.get(mod)
        key = target[1] if target else None
        out[mod] = ("carried" if key in carried else
                    "in_log_but_not_carried_by_this_schema")
    return out


def read_after_write(doc):
    """Did this job read data it had just written? Then reads may be cached.

    Layer 2 publishes a finished bandwidth, and an analyst handed a finished
    number stops interrogating it.

    Two things this deliberately does NOT claim, after review: job-level
    timestamps cannot show the SAME file was read and written, and ordering
    is not proof of a cache hit. The same-file question is answered
    separately from `top_files`, and the wording only ever says "may".
    """
    posix = (doc.get("modules") or {}).get("POSIX_IO") or {}
    tim = posix.get("aggregate", {}).get("timing", {}) or {}
    w0 = tim.get("POSIX_F_WRITE_START_TIMESTAMP")
    r0 = tim.get("POSIX_F_READ_START_TIMESTAMP")
    # Darshan min-folds an unset start timestamp to 0, so 0 means "no
    # operation of this class" -- but `not w0` conflated that with a missing
    # key, which is the same mistake wearing a different hat. Say both.
    if w0 is None or r0 is None:
        return None
    if w0 == 0 or r0 == 0:
        return {"applicable": False,
                "meaning": "This job recorded no POSIX %s, so read-after-write "
                           "within the job does not arise."
                           % ("writes" if w0 == 0 else "reads")}
    # ACROSS modules, not within POSIX. A job can write its dataset through
    # STDIO and read it back through POSIX (DLIO does), so a within-POSIX
    # check reports 0 on exactly the runs where read-after-write is the whole
    # story.
    seen = {}
    for mod in (doc.get("modules") or {}).values():
        for f in ((mod or {}).get("top_files") or []):
            e = seen.setdefault(f["file"], [0, 0])
            e[0] += f.get("bytes_read") or 0
            e[1] += f.get("bytes_written") or 0
    both = sorted(n for n, (rd, wr) in seen.items() if rd > 0 and wr > 0)
    overlap = r0 > w0
    return {
        "applicable": True,
        "write_started_first": bool(overlap),
        "write_start_s": w0,
        "read_start_s": r0,
        "files_both_read_and_written": len(both),
        "example_files": both[:3],
        "meaning": (("Writes began before reads in this job%s, so some reads MAY "
                     "have been served from page cache, which makes "
                     "insights.throughput.read_bw_* an upper bound on the "
                     "filesystem read rate rather than a measurement of it. "
                     "Ordering alone is not proof of a cache hit."
                     % (" and %d recorded file(s) were both written and read"
                        % len(both) if both else
                        ", though no single recorded file is both written and "
                        "read"))
                    if overlap else
                    "Reads began before any write, so reuse of this job's own "
                    "writes is unlikely to inflate the read rate."),
    }


def classify_counter(name: str) -> str:
    """Map a raw Darshan counter name to its schema group."""
    n = name.upper()
    body = re.sub(r"^[A-Z0-9]+_", "", n)

    if "BYTES_READ" in n or "BYTES_WRITTEN" in n or "MAX_BYTE" in n:
        return "volume"
    if re.search(r"SIZE_(READ|WRITE)", n) or "ACCESS" in body or "STRIDE" in body:
        return "access_sizes"
    # Alignment is its OWN group, not part of access_pattern. The two
    # alignment counters mean opposite kinds of thing -- `*_ALIGNMENT` is the
    # configured boundary in bytes, `*_NOT_ALIGNED` is a count of operations --
    # and sitting them unlabelled among CONSEC/SEQ/RW_SWITCH is what let a
    # reader call `POSIX_MEM_ALIGNMENT: 8` a defect while
    # `POSIX_MEM_NOT_ALIGNED` was 0.
    if "ALIGN" in n:
        return "alignment"
    if any(k in n for k in ("CONSEC", "SEQ_", "RW_SWITCH")):
        return "access_pattern"
    if "_F_" in n and ("TIME" in n or "TIMESTAMP" in n):
        return "timing"
    if any(k in n for k in ("FASTEST_RANK", "SLOWEST_RANK", "VARIANCE_RANK")):
        return "rank_balance"
    if any(k in n for k in ("SELECT", "HYPERSLAB", "NDIMS", "NPOINTS",
                            "CHUNK", "DATASPACE", "MEMSPACE")):
        return "dimensionality"
    if any(k in n for k in ("STRIPE", "OST", "MDT")):
        return "layout"
    return "operations"


# Darshan reduces each counter by its own semantics, not by which schema group
# it lands in. These rules were derived empirically by testing every candidate
# fold against `darshan-parser --total` over all 17 reference logs. They are
# only used by the text-parser fallback loader -- when pydarshan is available
# the library accumulator below supersedes them and is exact.
_RE_MAX = re.compile(r"(_MAX_BYTE_(READ|WRITTEN)"
                     r"|_F_MAX_(READ|WRITE)_TIME"
                     r"|_F_[A-Z]+_END_TIMESTAMP"
                     r"|_(MEM|FILE)_ALIGNMENT)$")
_RE_MIN = re.compile(r"_F_[A-Z]+_START_TIMESTAMP$")
_RE_CONST = re.compile(r"(_MODE|_MMAPS)$")
# Rank-scoped picks and top-N histograms are re-derived by libdarshan-util from
# per-rank state that a text dump no longer carries; they cannot be refolded.
_RE_DERIVED = re.compile(r"((_(FASTEST|SLOWEST)_RANK(_BYTES)?)"
                         r"|_F_(FASTEST|SLOWEST)_RANK_TIME"
                         r"|_F_VARIANCE_RANK_(TIME|BYTES)"
                         r"|_MAX_(READ|WRITE)_TIME_SIZE"
                         r"|_(ACCESS|STRIDE)[1-4]_(ACCESS|STRIDE|COUNT))$")


def reduce_op(name: str) -> str:
    """How a counter must be combined across records."""
    n = name.upper()
    if _RE_DERIVED.search(n):
        return "derived"
    if _RE_MAX.search(n):
        return "max"
    if _RE_MIN.search(n):
        return "min"
    if _RE_CONST.search(n):
        return "const"
    return "sum"


def load_with_pydarshan(path: str) -> Optional[Dict[str, Any]]:
    try:
        import darshan  # noqa
    except ImportError:
        return None

    report = darshan.DarshanReport(path, read_all=True)
    data: Dict[str, Any] = {"loader": "pydarshan"}

    job = dict(report.metadata.get("job", {}))
    data["job"] = job
    data["exe"] = report.metadata.get("exe", job.get("exe", ""))
    data["mounts"] = report.mounts if hasattr(report, "mounts") else \
        report.data.get("mounts", [])
    data["name_records"] = report.name_records

    # The authoritative module list, captured BEFORE the per-module loop.
    # That loop `continue`s past any module whose to_df() raises, which is how
    # HEATMAP -- present in most Darshan 3.4+ logs -- vanished from the
    # document entirely and read to a reader as "not instrumented".
    data["modules_present"] = sorted(report.modules)

    modules: Dict[str, List[Dict[str, Any]]] = {}
    for mod in report.modules:
        recs: List[Dict[str, Any]] = []
        try:
            dfs = report.records[mod].to_df()
        except Exception:
            continue
        if isinstance(dfs, dict):
            # counters/fcounters DataFrame pair (POSIX/STDIO/MPIIO/H5*/PNETCDF/LUSTRE)
            cdf = dfs.get("counters")
            fdf = dfs.get("fcounters")
            n = len(cdf) if cdf is not None else (len(fdf) if fdf is not None else 0)
            # Column-wise, NOT `cdf.iloc[i].to_dict()`. A DataFrame row is a
            # Series with ONE dtype, so that call upcast every row to float64
            # and the uint64 `id` lost its low bits (delta 112 on the first
            # POSIX record). The id then matched nothing in name_records, so
            # 0 of 116 POSIX and 0 of 81 STDIO files resolved to a name while
            # DXT -- which takes a different path -- resolved 106 of 106. The
            # schema has therefore never carried a POSIX or STDIO filename.
            # Counter values were unaffected (checked across 8 logs: none
            # exceeds float64's exact-integer range).
            ccols = {c: cdf[c].to_numpy() for c in cdf.columns} if cdf is not None else {}
            fcols = {c: fdf[c].to_numpy() for c in fdf.columns} if fdf is not None else {}
            for i in range(n):
                rec: Dict[str, Any] = {}
                if cdf is not None:
                    rec["id"] = int(ccols["id"][i])
                    rec["rank"] = int(ccols["rank"][i])
                    rec["counters"] = {k: _num(v[i]) for k, v in ccols.items()
                                       if k not in ("id", "rank")}
                if fdf is not None:
                    frow = {k: v[i] for k, v in fcols.items()}
                    frow.pop("id", None)
                    frow.pop("rank", None)
                    rec.setdefault("counters", {}).update(
                        {k: _num(v) for k, v in frow.items()})
                recs.append(rec)
        elif isinstance(dfs, list):
            # DXT-style: list of per-record dicts with hostname + segments
            for row in dfs:
                if not isinstance(row, dict):
                    continue
                rec = {
                    "id": int(row.get("id")) if row.get("id") is not None else None,
                    "rank": int(row.get("rank")) if row.get("rank") is not None else None,
                    "hostname": row.get("hostname"),
                    "counters": {
                        "DXT_WRITE_COUNT": _num(row.get("write_count", 0)),
                        "DXT_READ_COUNT": _num(row.get("read_count", 0)),
                    },
                }
                recs.append(rec)
        else:
            continue
        modules[mod] = recs

    # Aggregate with the same C code `darshan-parser --total` uses, rather than
    # refolding counters in Python. Verified counter-for-counter against the
    # --total dumps of all 17 reference logs: 2130/2130 exact. Modules with no
    # accumulator (LUSTRE, HEATMAP, DXT_*) are absent from --total as well, and
    # keep their per-record form downstream.
    totals: Dict[str, Dict[str, float]] = {}
    try:
        from darshan.backend import cffi_backend as _cb
    except ImportError:
        _cb = None
    nprocs = job.get("nprocs")
    if _cb is not None and nprocs:
        for mod in modules:
            try:
                acc = _cb.accumulate_records(
                    report.records[mod].to_df(), mod, nprocs)
            except Exception:
                continue          # module has no accumulator; not in --total
            flat: Dict[str, float] = {}
            for key in ("counters", "fcounters"):
                df = acc.summary_record.get(key)
                if df is None or len(df) == 0:
                    continue
                for k, v in df.iloc[0].to_dict().items():
                    if k in ("id", "rank"):
                        continue
                    nv = _num(v)
                    if isinstance(nv, (int, float)) and not isinstance(nv, bool):
                        flat[k] = nv
            if flat:
                totals[mod] = flat
    data["totals"] = totals

    data["modules"] = modules
    return data


def load_with_parser(path: str) -> Dict[str, Any]:
    exe = shutil.which("darshan-parser")
    if not exe:
        raise RuntimeError(
            "Neither pydarshan nor darshan-parser is available. "
            "Install with `pip install darshan`."
        )
    out = subprocess.run([exe, path], capture_output=True, text=True, check=True).stdout
    data: Dict[str, Any] = {"loader": "darshan-parser", "job": {}, "mounts": [],
                            "name_records": {}, "modules": defaultdict(list),
                            "exe": ""}
    rec_index: Dict[Tuple[str, int, int], Dict[str, Any]] = {}

    for line in out.splitlines():
        if line.startswith("#"):
            _parse_header_line(line, data)
            continue
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            parts = line.split()
        if len(parts) < 5:
            continue
        module, rank, rec_id, counter, value = parts[:5]
        fname = parts[5] if len(parts) > 5 else ""
        key = (module, int(rank), int(rec_id))
        rec = rec_index.get(key)
        if rec is None:
            rec = {"id": int(rec_id), "rank": int(rank), "counters": {}}
            rec_index[key] = rec
            data["modules"][module].append(rec)
        rec["counters"][counter] = _num(value)
        if fname:
            data["name_records"][int(rec_id)] = fname

    data["modules"] = dict(data["modules"])
    return data


def _parse_header_line(line: str, data: Dict[str, Any]) -> None:
    m = {
        "exe:": "exe", "jobid:": "jobid", "uid:": "uid",
        "start_time:": "start_time", "end_time:": "end_time",
        "nprocs:": "nprocs", "run time:": "run_time",
    }
    for token, key in m.items():
        if token in line:
            val = line.split(token, 1)[1].strip()
            if key == "exe":
                data["exe"] = val
            else:
                data["job"][key] = _num(val)
    if "# mount entry:" in line:
        entry = line.split("# mount entry:", 1)[1].strip()
        bits = entry.split("\t") if "\t" in entry else entry.split()
        if len(bits) >= 2:
            data["mounts"].append({"mount": bits[0], "type": bits[1]})


def _num(v: Any):
    try:
        f = float(v)
        return int(f) if f.is_integer() else f
    except (ValueError, TypeError):
        return v


def field(value, source):
    return {"value": value, "source": source}


IO_LIB_FROM_MODULE = {
    "POSIX": "POSIX", "STDIO": "STDIO", "MPI-IO": "MPIIO", "MPIIO": "MPIIO",
    "H5F": "HDF5", "H5D": "HDF5", "PNETCDF_FILE": "PnetCDF",
    "PNETCDF_VAR": "PnetCDF",
}


def build_application(data, env) -> Dict[str, Any]:
    exe = data.get("exe", "") or ""
    exe_path = exe.split()[0] if exe else ""
    shell = " ".join(exe.split()[1:]) if exe else ""
    app_name = os.path.basename(exe_path) if exe_path else None

    io_libs = sorted({IO_LIB_FROM_MODULE[m] for m in data["modules"]
                      if m in IO_LIB_FROM_MODULE})

    return {
        "app_name": field(app_name, "derived"),
        "exe_path": field(exe_path or None, "log"),
        "shell": field(shell or None, "log"),
        "app_version": field(None, "derived"),
        "science_domain": field(None, "derived"),
        "io_libraries": field(io_libs, "log"),
        "io_library_versions": field(
            data["job"].get("metadata", {}) if isinstance(
                data["job"].get("metadata"), dict) else {}, "log"),
        "tags": field([], "derived"),
    }


def derive_shape(data, env):
    """(num_nodes, nprocs_per_node, hostlist) -- the run's layout.

    Neither number is in the .darshan header, so both are `derived`: num_nodes
    comes from the batch env, else from the count of distinct DXT hostnames,
    and nprocs_per_node is a division. Both are None when the log carries no
    DXT and no batch environment was supplied.
    Shared by build_job (which emits the two numbers since 2026-09-17) and
    build_system (which still wants the hostlist for the scheduler group).
    """
    nprocs = data["job"].get("nprocs")
    num_nodes = _int(env.get("SLURM_JOB_NUM_NODES") or env.get("SLURM_NNODES")
                     or env.get("PBS_NUM_NODES"))
    hostlist = _hostlist_from_env(env)
    if num_nodes is None:
        hosts = _hosts_from_dxt(data)
        if hosts:
            num_nodes = len(hosts)
            hostlist = hostlist or sorted(hosts)
    per_node = (nprocs // num_nodes) if (nprocs and num_nodes) else None
    return num_nodes, per_node, hostlist


def build_job(data, env) -> Dict[str, Any]:
    j = data["job"]
    num_nodes, nprocs_per_node, _ = derive_shape(data, env)
    start = j.get("start_time", j.get("start_time_sec"))
    end = j.get("end_time", j.get("end_time_sec"))
    run_time = j.get("run_time")
    if run_time is None and start is not None and end is not None:
        run_time = float(end) - float(start)
    return {
        "jobid": field(j.get("jobid"), "log"),
        "uid": field(j.get("uid"), "log"),
        # num_nodes and nprocs_per_node are the only `derived` fields in an
        # otherwise all-`log` section -- see derive_shape().
        "nprocs_total": field(j.get("nprocs"), "log"),
        "num_nodes": field(num_nodes, "derived"),
        "nprocs_per_node": field(nprocs_per_node, "derived"),
        "start_time": field(start, "log"),
        "end_time": field(end, "log"),
        "run_time": field(run_time, "log"),
        "darshan_version": field(j.get("metadata", {}).get("lib_ver")
                                 if isinstance(j.get("metadata"), dict) else None, "log"),
        "log_version": field(data.get("log_version"), "log"),
        # The loader-level keys below (j["metadata"], data["mounts"]) mirror
        # pydarshan's own names; the schema names are what we emit.
        "darshan_metadata": field(j.get("metadata", {}), "log"),
        "fs_mount": field(data.get("mounts", []), "log"),
    }


def build_system(data, env, spec) -> Dict[str, Any]:
    nprocs = data["job"].get("nprocs")
    _, _, hostlist = derive_shape(data, env)
    threads = _int(env.get("OMP_NUM_THREADS"))
    total_threads = (nprocs * threads) if (nprocs and threads) else None  # noqa: F841

    system_name = env.get("LMOD_SYSTEM_NAME") or env.get("NERSC_HOST") \
        or env.get("SYSTEM_NAME")
    cap = (spec.get(system_name, {}) if system_name else {}) or {}

    def cfg(key):
        return field(cap.get(key), "config")

    return {
        # `scale` is gone as of 2026-09-17: num_nodes and nprocs_per_node moved
        # to build_job, next to nprocs_total, so the run's shape is described in
        # one place. Everything else this group held was null on every card --
        # a .darshan log does not carry it and the prep runs with an empty env.
        #   "nprocs": field(nprocs, "log"),                  # == job.nprocs_total
        #   "threads_per_rank": field(threads, "derived"),
        #   "total_threads": field(total_threads, "derived"),
        #   "gpus_per_node": field(_int(env.get("SLURM_GPUS_PER_NODE")), "derived"),
        # "parallelism": {
        #     "exec_model": field(_infer_exec_model(data, env), "derived"),
        #     "language": field(None, "derived"),
        #     "mpi_library": field(env.get("MPICH_VERSION") or env.get("OMPI_VERSION"), "derived"),
        #     "threading_runtime": field("openmp" if threads else None, "derived"),
        #     "launcher": field(env.get("SLURM_JOB_ID") and "srun" or None, "derived"),
        # },
        "hardware_specs": {
            "system_name": field(system_name, "derived"),
            "cpu_model": cfg("cpu_model"),
            "cores_per_node": cfg("cores_per_node"),
            "memory_per_node": cfg("memory_per_node"),
            "interconnect": cfg("interconnect"),
        },
        "scheduler": {
            "scheduler": field(_infer_scheduler(env, hostlist), "derived"),
            "queue": field(env.get("SLURM_JOB_PARTITION") or env.get("PBS_QUEUE"),
                           "derived"),
            "allocation": field(env.get("SLURM_JOB_ACCOUNT"), "derived"),
            "hostlist": field(hostlist, "derived"),
        },
        "rated_peak_performance": {
            "peak_read_bw": cfg("peak_read_bw"),
            "peak_write_bw": cfg("peak_write_bw"),
            "per_ost_bw": cfg("per_ost_bw"),
            "per_node_bw": cfg("per_node_bw"),
            "measured_ior_bw": cfg("measured_ior_bw"),
            "peak_metadata_rate": cfg("peak_metadata_rate"),
            "total_osts": cfg("total_osts"),
            "recommended_stripe_size": cfg("recommended_stripe_size"),
            "network_injection_bw": cfg("network_injection_bw"),
        },
    }


TOP_FILES = 8


def top_files(recs, prefix):
    """The files that carry the traffic, by name. Capped at TOP_FILES.

    Aggregate byte totals cannot say WHAT was written: without names, a
    reader can mistake a workload's dataset generation for log spam and
    advise redirecting it to /dev/null. Names make the attribution checkable
    instead of guessable.
    """
    agg = {}
    for r in recs:
        name = r.get("file")
        if not name:
            continue
        c = r.get("counters") or {}
        e = agg.setdefault(name, {"file": name, "bytes_read": 0,
                                  "bytes_written": 0, "opens": 0, "records": 0})
        e["bytes_read"] += c.get(prefix + "_BYTES_READ", 0) or 0
        e["bytes_written"] += c.get(prefix + "_BYTES_WRITTEN", 0) or 0
        e["opens"] += c.get(prefix + "_OPENS", 0) or 0
        e["records"] += 1
    rows = sorted(agg.values(),
                  key=lambda e: -(e["bytes_read"] + e["bytes_written"]))
    return [{k: (int(v) if isinstance(v, float) and v.is_integer() else v)
             for k, v in e.items()} for e in rows[:TOP_FILES]]


def _presence(recs) -> str:
    """Why a module section is empty, which `n_records: 0` alone cannot say.

    A module reaches this function only if the log carries it, so an empty
    record list means the module was INSTRUMENTED but contributed nothing to
    this reduction -- which is the normal state of LUSTRE in a
    `darshan-parser --total` reduction. Rendering that as `{"n_records": 0}` and
    nothing else read as "this job did not use Lustre", and readers duly
    recommended enabling striping that was already on. A module genuinely
    absent from the log has no key here at all.
    """
    return "instrumented" if recs else "instrumented_no_records"


def build_modules_and_storage(data) -> Tuple[Dict, Dict, Dict]:
    """Return (modules_section, storage_section, traces_section)."""
    name_records = data.get("name_records", {})
    modules_out: Dict[str, Any] = {}
    storage_out: Dict[str, Any] = {}
    traces_out: Dict[str, Any] = {}

    for mod, recs in data["modules"].items():
        if mod not in MODULE_TO_SCHEMA:
            continue
        section, key, sub = MODULE_TO_SCHEMA[mod]

        for r in recs:
            r["file"] = name_records.get(r.get("id"), None)

        if section == "traces":
            traces_out.setdefault(key, {})
            slot = sub or "_"
            traces_out[key][slot] = {
                "n_records": len(recs),
                "presence": _presence(recs),
                "records": recs,
            }
            continue

        if section == "storage":
            storage_out.setdefault(key, {"n_records": len(recs),
                                         "presence": _presence(recs),
                                         "files": []})
            for r in recs:
                storage_out[key]["files"].append({
                    "file": r["file"], "rank": r.get("rank"),
                    "layout": r.get("counters", {}),
                })
            continue

        target = modules_out.setdefault(key, {})
        if sub:
            target = target.setdefault(sub, {})
        _fill_module(target, recs, data.get("totals", {}).get(mod))

    return modules_out, storage_out, traces_out


def _fill_module(target: Dict[str, Any], recs: List[Dict[str, Any]],
                 totals: Optional[Dict[str, float]] = None) -> None:
    """Fill one module section.

    `totals`, when given, are libdarshan-util's own aggregates and are
    authoritative -- they match `darshan-parser --total` exactly. Only the
    text-parser fallback loader takes the manual path, which reduces per
    counter (see `reduce_op`) rather than summing whole groups.
    """
    grouped_agg: Dict[str, Dict[str, float]] = defaultdict(dict)
    n_shared = n_fpp = 0
    files = set()

    for r in recs:
        rank = r.get("rank")
        if rank == -1:
            n_shared += 1
        elif rank is not None and rank >= 0:
            n_fpp += 1
        if r.get("file"):
            files.add(r["file"])

    if totals:
        for cname, cval in totals.items():
            grouped_agg[classify_counter(cname)][cname] = cval
    else:
        for r in recs:
            for cname, cval in r.get("counters", {}).items():
                if not isinstance(cval, (int, float)) or isinstance(cval, bool):
                    continue
                grp = classify_counter(cname)
                cur = grouped_agg[grp].get(cname)
                if cur is None:
                    grouped_agg[grp][cname] = cval
                    continue
                op = reduce_op(cname)
                if op == "sum":
                    grouped_agg[grp][cname] = cur + cval
                elif op == "max":
                    grouped_agg[grp][cname] = max(cur, cval)
                elif op == "min":
                    # 0 means the phase never happened, not a real minimum.
                    if cval > 0:
                        grouped_agg[grp][cname] = min(cur, cval) if cur > 0 else cval
                elif op == "const":
                    if cur != cval:
                        grouped_agg[grp][cname] = -1.0
                # "derived": keep the first record's value; it cannot be refolded.

    target["n_records"] = len(recs)
    target["presence"] = _presence(recs)
    pfx = (recs[0].get("_prefix") if recs else None) or _counter_prefix(recs)
    if pfx:
        target["top_files"] = top_files(recs, pfx)
    target["aggregate_source"] = "darshan_accumulator" if totals else "manual_reduce"
    target["n_files"] = len(files)
    target["access_scope"] = (
        "shared" if n_shared and not n_fpp else
        "file_per_process" if n_fpp and not n_shared else
        "mixed" if n_shared and n_fpp else "unknown")
    target["aggregate"] = {g: dict(c) for g, c in grouped_agg.items()}
    target["records"] = recs


def _counter_prefix(recs):
    """`POSIX` / `STDIO` / `MPIIO` -- taken from the counters actually present."""
    for r in recs:
        for name in (r.get("counters") or {}):
            if "_BYTES_" in name:
                return name.split("_BYTES_")[0]
    return None


def _span(tim, start_key, end_key):
    """Wall-clock window of one operation class, across all ranks.

    The START timestamp folds by min and the END by max, so the difference is
    the whole job's read (or write) window -- the denominator a wall-clock
    rate needs, as opposed to the summed per-rank seconds in F_*_TIME.
    """
    t0, t1 = tim.get(start_key), tim.get(end_key)
    if t0 is None or t1 is None:
        return None
    span = t1 - t0
    return span if span > 0 else None


def build_insights(modules_out, storage_out, system, job) -> Dict[str, Any]:
    posix = modules_out.get("POSIX_IO", {}).get("aggregate", {})
    vol = posix.get("volume", {})
    ops = posix.get("operations", {})
    tim = posix.get("timing", {})
    pat = posix.get("access_pattern", {})
    algn = posix.get("alignment", {})
    sizes = posix.get("access_sizes", {})

    def pat_or_align(key, default=0):
        """Alignment moved out of access_pattern in schema v3; read both so a
        v2 document still fills rather than silently reading 0."""
        if key in algn:
            return algn[key]
        return pat.get(key, default)

    br = vol.get("POSIX_BYTES_READ", 0)
    bw = vol.get("POSIX_BYTES_WRITTEN", 0)
    tr = tim.get("POSIX_F_READ_TIME", 0.0)
    tw = tim.get("POSIX_F_WRITE_TIME", 0.0)
    tm = tim.get("POSIX_F_META_TIME", 0.0)
    reads = ops.get("POSIX_READS", 0)
    writes = ops.get("POSIX_WRITES", 0)
    # POSIX_OPENS is NOT a count of open() calls: darshan-parser prints
    # "WARNING: POSIX_OPENS counter includes both POSIX_FILENOS and
    # POSIX_DUPS counts". Every per-open figure below divided by the raw
    # counter and so over-reported -- redundant_open_ratio, opens_per_rank and
    # the metadata rate alike. `distinct_opens` is the real one; `opens` is
    # kept only where the raw counter is genuinely what is wanted.
    opens = ops.get("POSIX_OPENS", 0)
    distinct_opens = max(0, opens
                         - ops.get("POSIX_FILENOS", 0)
                         - ops.get("POSIX_DUPS", 0))
    total_ops = reads + writes

    MIB = 1024.0 * 1024.0
    run_time = _val(job.get("run_time"))
    # Both moved into `job` on 2026-09-17. Until then this read
    # system["scale"]["nprocs"], which the 2026-09-17 scale cut had already
    # stopped emitting -- every fresh fill died here with a KeyError.
    nprocs = _val(job["nprocs_total"]) or 0
    num_nodes = _val(job["num_nodes"])
    cap = {k: _val(v) for k, v in system["rated_peak_performance"].items()}

    def ratio(a, b):
        return (a / b) if b else None

    # POSIX_F_*_TIME are rank-seconds (accumulate_records sums over ranks), so the
    # denominator of a time *share* is the rank-seconds the job had available, not
    # wall-clock. Dividing by run_time alone overstates by a factor of nprocs and
    # puts a many-rank job far above 100%.
    core_seconds = (run_time * nprocs) if (run_time and nprocs) else None
    posix_io_time = tr + tw + tm

    # Layer 2 is POSIX-only. Where STDIO or MPI-IO spent more time than POSIX did,
    # a POSIX-derived verdict is not a job-level verdict -- it called a 128-rank
    # IOR run "healthy" while MPI-IO held 60x more time. Compare
    # the modules (never add them: MPI-IO and buffered stdio descend to POSIX, so
    # a sum double-counts) and decline to rule when POSIX is not the whole story.
    def _mod_io_time(mod):
        t = modules_out.get(mod, {}).get("aggregate", {}).get("timing", {}) or {}
        return sum(v for k, v in t.items() if isinstance(v, (int, float))
                   and k.endswith(("_F_READ_TIME", "_F_WRITE_TIME", "_F_META_TIME")))

    # The margin is mechanistic, not tuned to an outcome: when MPI-IO is a thin
    # ROMIO passthrough its time ~= POSIX's, and POSIX does see that whole job.
    # Real divergence is nowhere near 1, so 1.25 sits between the two cases.
    POSIX_BLIND_RATIO = 1.25
    posix_blind = posix_io_time > 0 and any(
        _mod_io_time(m) > POSIX_BLIND_RATIO * posix_io_time for m in ("MPIIO", "STDIO"))

    read_bw = ratio(br / MIB, tr)
    write_bw = ratio(bw / MIB, tw)
    agg_bw = ratio((br + bw) / MIB, (tr + tw))
    meta_rate = ratio(distinct_opens + ops.get("POSIX_STATS", 0)
                      + ops.get("POSIX_SEEKS", 0), tm)

    small = sum(v for k, v in sizes.items()
                if re.search(r"SIZE_(READ|WRITE)_(0_100|100_1K|1K_10K)$", k))
    seq = pat.get("POSIX_SEQ_READS", 0) + pat.get("POSIX_SEQ_WRITES", 0)
    unaligned = pat_or_align("POSIX_FILE_NOT_ALIGNED", 0)

    mpi = modules_out.get("MPIIO", {}).get("aggregate", {}).get("operations", {})
    coll = mpi.get("MPIIO_COLL_READS", 0) + mpi.get("MPIIO_COLL_WRITES", 0)
    indep = mpi.get("MPIIO_INDEP_READS", 0) + mpi.get("MPIIO_INDEP_WRITES", 0)

    def eff(achieved, *ceilings):
        for c in ceilings:
            if achieved is not None and c:
                return achieved / (c * 1024.0)
        return None

    # TWO bandwidths, both named for their denominator. v5 and earlier
    # published one `read_bandwidth_MiBps` -- bytes over SUMMED RANK SECONDS --
    # and readers spent it as though it were a wall-clock rate, muddling
    # per-stream and aggregate bandwidth. So publish both, each named for its
    # denominator, and never a bare "bandwidth".
    rd_span = _span(tim, "POSIX_F_READ_START_TIMESTAMP",
                    "POSIX_F_READ_END_TIMESTAMP")
    wr_span = _span(tim, "POSIX_F_WRITE_START_TIMESTAMP",
                    "POSIX_F_WRITE_END_TIMESTAMP")
    insights = {
        "throughput": {
            "read_bw_busytime_MiBps": read_bw,
            "write_bw_busytime_MiBps": write_bw,
            "aggregate_bw_busytime_MiBps": agg_bw,
            "read_bw_wallspan_MiBps": ratio(br / MIB, rd_span),
            "write_bw_wallspan_MiBps": ratio(bw / MIB, wr_span),
            "aggregate_bw_jobwall_MiBps": ratio((br + bw) / MIB, run_time),
            "read_wallspan_s": rd_span,
            "write_wallspan_s": wr_span,
            "metadata_rate_opsps": meta_rate,
        },
        "behavior": {
            # Renamed from percent_runtime_in_io: that name said neither which
            # modules it covers (POSIX only -- STDIO/MPIIO time is excluded and
            # exceeds it in 7 of 25 runs) nor what it divides by, and 8 reports
            # spent a paragraph reconstructing both. The name now states each.
            "posix_io_coretime_share": ratio(posix_io_time, core_seconds),
            "metadata_overhead": ratio(tm, posix_io_time),
            "small_access_ratio": ratio(small, total_ops),
            "sequential_ratio": ratio(seq, total_ops),
            "unaligned_ratio": ratio(unaligned, total_ops),
            "collective_ratio": ratio(coll, coll + indep),
            "file_access_mode": modules_out.get("POSIX_IO", {}).get("access_scope"),
            "distinct_opens": distinct_opens,
            "redundant_open_ratio": ratio(distinct_opens,
                                          modules_out.get("POSIX_IO", {}).get("n_files")),
        },
        "scale_normalized": {
            "bytes_per_rank": ratio(br + bw, nprocs),
            "bytes_per_node": ratio(br + bw, num_nodes),
            "bw_per_rank_busytime_MiBps": ratio(agg_bw, nprocs) if agg_bw else None,
            "bw_per_node_busytime_MiBps": ratio(agg_bw, num_nodes) if agg_bw else None,
            "opens_per_rank": ratio(distinct_opens, nprocs),
        },
        "efficiency": {
            "read_bw_efficiency": eff(read_bw, cap.get("measured_ior_bw"),
                                      cap.get("peak_read_bw")),
            "write_bw_efficiency": eff(write_bw, cap.get("measured_ior_bw"),
                                       cap.get("peak_write_bw")),
            "metadata_rate_efficiency": ratio(meta_rate, cap.get("peak_metadata_rate")),
            "node_bw_saturation": (
                ratio(agg_bw, num_nodes) / (cap["per_node_bw"] * 1024.0)
                if (agg_bw and num_nodes and cap.get("per_node_bw")) else None),
            "io_bound_verdict": _verdict(ratio(posix_io_time, core_seconds),
                                         ratio(tm, posix_io_time),
                                         ratio(small, total_ops),
                                         posix_blind),
        },
        "_notes": [
            "TWO bandwidths are published and they are not interchangeable. "
            "*_busytime_MiBps divides bytes by SUMMED PER-RANK I/O seconds: it is "
            "the rate a single stream sustained while it was actually in a read or "
            "write call, and with N ranks it is roughly N times any wall-clock "
            "figure. *_wallspan_MiBps divides by the elapsed window between the "
            "first and last operation of that class across all ranks, and "
            "aggregate_bw_jobwall_MiBps divides by job run_time. Quote the "
            "wallspan or jobwall figure when asked what the job achieved; quote "
            "busytime only when asked what one stream sustained, and say which "
            "one you are quoting. Never write a bare \"bandwidth\".",
            "efficiency.* are null unless system.rated_peak_performance was provided "
            "via --system-spec.",
            "Per-open figures (behavior.distinct_opens, redundant_open_ratio, "
            "scale_normalized.opens_per_rank, throughput.metadata_rate_opsps) use "
            "POSIX_OPENS minus POSIX_FILENOS and POSIX_DUPS, which the raw counter "
            "includes. Schema v2 divided by the raw counter and over-reported all "
            "four.",
            "behavior.posix_io_coretime_share and metadata_overhead are POSIX-only "
            "and divide rank-seconds by run_time*nprocs. STDIO and MPI-IO time is "
            "NOT included and can exceed it; read those modules' *_F_*_TIME "
            "counters directly rather than adding them (the modules overlap).",
        ],
    }
    return insights


def _verdict(pct_io, meta_over, small_ratio, posix_blind=False):
    if pct_io is None:
        return "unknown"
    if posix_blind:
        # Not a hedge: STDIO or MPI-IO outweighs POSIX here, so any POSIX-derived
        # ruling would be about a minority of the job's I/O time.
        return "unknown_non_posix_dominant"
    if pct_io < 0.05:
        return "healthy"
    if meta_over and meta_over > 0.5:
        return "metadata_bound"
    if small_ratio and small_ratio > 0.5:
        return "pattern_bound"
    return "io_intensive"


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _val(f):
    return f["value"] if isinstance(f, dict) and "value" in f else f


def _infer_scheduler(env, hosts=None):
    # Only the job's own batch environment (--env-file) speaks to this; a host
    # naming convention does not identify a scheduler across sites, so none is
    # guessed from host names.
    if any(k.startswith("PBS_") for k in env):
        return "pbs"
    if any(k.startswith("SLURM_") for k in env):
        return "slurm"
    if any(k.startswith("LSB_") for k in env):
        return "lsf"
    if any(k.startswith("COBALT_") for k in env):
        return "cobalt"
    return None


def _infer_exec_model(data, env):
    mods = set(data["modules"])
    mpi = {"MPI-IO", "MPIIO"} & mods
    omp = bool(_int(env.get("OMP_NUM_THREADS")))
    if mpi and omp:
        return "mpi+openmp"
    if mpi:
        return "mpi"
    if (data["job"].get("nprocs") or 1) > 1:
        return "multiproc"
    return "serial"


def _hostlist_from_env(env):
    nl = env.get("SLURM_JOB_NODELIST") or env.get("PBS_NODEFILE")
    if nl and os.path.isfile(nl):
        with open(nl) as fh:
            return sorted({ln.strip() for ln in fh if ln.strip()})
    return None


def _hosts_from_dxt(data):
    hosts = set()
    for mod in ("DXT_POSIX", "DXT_MPIIO"):
        for r in data["modules"].get(mod, []):
            h = r.get("hostname") or r.get("counters", {}).get("hostname")
            if h:
                hosts.add(h)
    return hosts


def load_env_file(path: Optional[str]) -> Dict[str, str]:
    # The JOB's saved batch environment only. Never seeded from os.environ: that
    # is the shell running this script, not the job, and it would stamp the
    # operator's host (system name, scheduler, node list) onto the log.
    env: Dict[str, str] = {}
    if path and os.path.isfile(path):
        with open(path) as fh:
            for line in fh:
                if "=" in line and not line.startswith("#"):
                    k, v = line.rstrip("\n").split("=", 1)
                    env[k] = v
    return env


def load_json(path: Optional[str]) -> Dict[str, Any]:
    if path and os.path.isfile(path):
        with open(path) as fh:
            return json.load(fh)
    return {}


def process(path, env, spec) -> Dict[str, Any]:
    data = load_with_pydarshan(path)
    if data is None:
        data = load_with_parser(path)

    modules_out, storage_out, traces_out = build_modules_and_storage(data)
    system = build_system(data, env, spec)
    job = build_job(data, env)
    insights = build_insights(modules_out, storage_out, system, job)

    doc = {
        "meta": {
            "schema": "darshan",
            "schema_version": SCHEMA_VERSION,
            "source_log": os.path.abspath(path),
            "loader": data.get("loader"),
            # These three entries are the v3 fix. The schema used to carry
            # darshan-parser's counters without darshan-parser's own warnings
            # and legend, so a reader got the numbers and not the semantics
            # that keep them from being misread. Each line below is the
            # schema's restatement of a line the text dump prints and the
            # structured form had dropped.
            "conventions": {
                "rank": "-1 = shared-file aggregate; >=0 = per-rank",
                "field_source": "log=from .darshan | derived=enriched | config=spec table",
                "counter_overlaps": {
                    "POSIX_OPENS": "includes POSIX_FILENOS and POSIX_DUPS; "
                                   "distinct open() calls = POSIX_OPENS - "
                                   "POSIX_FILENOS - POSIX_DUPS, reported as "
                                   "insights.behavior.distinct_opens. Do not add "
                                   "POSIX_FILENOS to POSIX_OPENS.",
                    "STDIO_OPENS": "includes STDIO_FDOPENS; distinct opens = "
                                   "STDIO_OPENS - STDIO_FDOPENS.",
                },
                "counter_semantics": {
                    "*_ALIGNMENT": "the configured alignment boundary IN BYTES "
                                   "(e.g. 8). It is a setting, not a fault, and a "
                                   "small value is not itself a defect.",
                    "*_NOT_ALIGNED": "the NUMBER OF OPERATIONS that were not "
                                     "aligned. This is the one that indicates a "
                                     "problem; zero means nothing was misaligned.",
                },
                "sentinels": "A counter value of -1 means NOT AVAILABLE in "
                             "this reduction. It is not a measurement of minus "
                             "one and must never be reported, averaged or "
                             "compared as a number. Rank-scoped picks "
                             "(*_FASTEST_RANK*, *_SLOWEST_RANK*) and *_MMAPS "
                             "carry it most often. meta.unavailable_counters "
                             "lists every one in this document.",
                "counter_reliability": "Darshan derives some counters from file "
                                       "offsets and warns that they may be "
                                       "incorrect when one file is reached "
                                       "through both POSIX and STDIO. "
                                       "meta.reliability.offset_counters "
                                       "evaluates that condition FOR THIS LOG "
                                       "and names the counters it touches.",
                "module_presence": "A module key is present here only if the log "
                                   "carries that module. `presence: instrumented` "
                                   "= it also contributed records; "
                                   "`presence: instrumented_no_records` = it was "
                                   "instrumented but contributed none to this "
                                   "reduction, which is NOT the same as the job "
                                   "not using it. A module missing from the log "
                                   "has no key at all.",
            },
        },
        "application": build_application(data, env),
        "job": job,
        "system": system,
        "modules": modules_out,
        "storage": storage_out,
        "traces": traces_out,
        "insights": insights,
    }
    # Computed last: both read the finished counter tree.
    doc["meta"]["unavailable_counters"] = unavailable_counters(doc)
    doc["meta"]["reliability"] = {"offset_counters": offset_reliability(doc)}
    doc["meta"]["modules_in_log"] = modules_in_log(data, doc)
    doc["insights"]["behavior"]["read_after_write_same_job"] = \
        read_after_write(doc)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="path to a .darshan log")
    ap.add_argument("-o", "--output", help="output JSON path (default: stdout)")
    ap.add_argument("--env-file", help="saved batch-job environment (KEY=VALUE lines)")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("--no-records", action="store_true",
                    help="drop per-record arrays (smaller output for the agent)")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.log):
        ap.error(f"log not found: {args.log}")

    env = load_env_file(args.env_file)
    spec = {}
    doc = process(args.log, env, spec)

    if args.no_records:
        _strip_records(doc)

    text = json.dumps(doc, indent=2 if args.pretty else None, default=str)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)


def _strip_records(doc):
    for key, mod in doc.get("modules", {}).items():
        for v in list(mod.values()) + [mod]:
            if isinstance(v, dict):
                v.pop("records", None)
    for key in doc.get("traces", {}):
        for slot in doc["traces"][key].values():
            if isinstance(slot, dict):
                slot.pop("records", None)
    for key in doc.get("storage", {}):
        doc["storage"][key].pop("files", None)


if __name__ == "__main__":
    main()
