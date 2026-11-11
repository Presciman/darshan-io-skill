#!/usr/bin/env python3
"""Exact facts from one .darshan log: PyDarshan + accumulate_records, i.e. the same reduction as
darshan-parser --total, plus --perf, --file categories, per-rank and per-file statistics, DXT,
HEATMAP and Lustre summaries. Call extract(path) on any log."""
import os, glob, json, math, warnings, collections
warnings.filterwarnings('ignore')
import numpy as np, pandas as pd, darshan
from darshan.backend.cffi_backend import accumulate_records

CATS = ['all','read_only','write_only','read_write','unique','shared','part_shared']
RBINS = ['0_100','100_1K','1K_10K','10K_100K','100K_1M','1M_4M','4M_10M','10M_100M','100M_1G','1G_PLUS']

def jnum(x):
    if x is None: return None
    if isinstance(x,(np.integer,)): return int(x)
    if isinstance(x,(np.floating,)): return float(x)
    return x

def catdict(dm):
    out={}
    for i,name in enumerate(CATS):
        c=dm.category_counters[i]
        out[name]=dict(count=int(c.count), read_bytes=int(c.total_read_volume_bytes),
                       write_bytes=int(c.total_write_volume_bytes),
                       max_read=int(c.max_read_volume_bytes), max_write=int(c.max_write_volume_bytes),
                       total_max_offset=int(c.total_max_offset_bytes), max_offset=int(c.max_offset_bytes),
                       nprocs=int(c.nprocs))
    return out

def accum(rep, mod):
    try:
        a = accumulate_records(rep.records[mod].to_df(), mod, rep.metadata['job']['nprocs'])
        dm = a.derived_metrics
        return dict(total_bytes=int(dm.total_bytes),
                    agg_perf_by_slowest=float(dm.agg_perf_by_slowest),
                    agg_time_by_slowest=float(dm.agg_time_by_slowest),
                    unique_io_total_time_by_slowest=float(dm.unique_io_total_time_by_slowest),
                    shared_io_total_time_by_slowest=float(dm.shared_io_total_time_by_slowest),
                    unique_md_only_time_by_slowest=float(dm.unique_md_only_time_by_slowest),
                    unique_rw_only_time_by_slowest=float(dm.unique_rw_only_time_by_slowest),
                    unique_io_slowest_rank=int(dm.unique_io_slowest_rank),
                    categories=catdict(dm),
                    agg_counters={k:jnum(v) for k,v in a.summary_record['counters'].items()},
                    agg_fcounters={k:jnum(v) for k,v in a.summary_record['fcounters'].items()})
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}

def extract(path, workload=None):
    # workload: a label for the run; by default the name of the directory holding the log.
    F = {'path': path, 'workload': workload or os.path.basename(os.path.dirname(os.path.abspath(path))),
         'logfile': os.path.basename(path)}
    rep = darshan.DarshanReport(path, read_all=True)
    j = rep.metadata['job']
    exe_full = rep.metadata['exe']
    F['job'] = dict(jobid=j['jobid'], uid=j['uid'], nprocs=j['nprocs'],
                    start=j['start_time_sec'], end=j['end_time_sec'],
                    run_time=float(j['run_time']), log_ver=j['log_ver'],
                    lib_ver=j.get('metadata',{}).get('lib_ver'),
                    darshan_h=j.get('metadata',{}).get('h'),
                    exe=exe_full, exe_bin=exe_full.split()[0] if exe_full else '',
                    exe_args=' '.join(exe_full.split()[1:]) if exe_full else '')
    F['modules'] = list(rep.modules.keys())
    F['module_meta'] = {k: {kk: jnum(vv) for kk, vv in v.items()} for k, v in rep.modules.items()}
    F['log_bytes'] = os.path.getsize(path)
    F['mounts'] = [dict(mount=m[0], fstype=m[1]) for m in rep.mounts] if hasattr(rep,'mounts') else []
    F['name_records'] = {str(k): v for k, v in rep.name_records.items()}

    # ---- POSIX ----
    if 'POSIX' in rep.modules:
        c = rep.records['POSIX'].to_df()['counters'].copy()
        f = rep.records['POSIX'].to_df()['fcounters'].copy()
        m = c.merge(f, on=['rank','id'], suffixes=('',''))
        F['posix'] = dict(
            n_records=int(len(c)), n_unique_files=int(c['id'].nunique()),
            n_shared_recs=int((c['rank']==-1).sum()), n_uniq_recs=int((c['rank']>=0).sum()),
            ranks_present=sorted(set(int(x) for x in c['rank'].unique())),
        )
        F['posix']['agg'] = {k: int(c[k].sum()) for k in c.columns
                             if k not in ('rank','id') and not k.startswith('POSIX_ACCESS')
                             and not k.endswith('_RANK') and 'ALIGNMENT' not in k
                             and 'MODE' not in k and not k.startswith('POSIX_STRIDE')
                             and 'MAX_BYTE' not in k and 'RANK_BYTES' not in k
                             and 'MAX_READ_TIME_SIZE' not in k and 'MAX_WRITE_TIME_SIZE' not in k}
        F['posix']['maxes'] = {k: int(c[k].max()) for k in
                               ['POSIX_MAX_BYTE_READ','POSIX_MAX_BYTE_WRITTEN',
                                'POSIX_MAX_READ_TIME_SIZE','POSIX_MAX_WRITE_TIME_SIZE']}
        F['posix']['alignment'] = dict(
            mem_alignment=sorted(set(int(x) for x in c['POSIX_MEM_ALIGNMENT'].unique())),
            file_alignment=sorted(set(int(x) for x in c['POSIX_FILE_ALIGNMENT'].unique())),
            mem_not_aligned=int(c['POSIX_MEM_NOT_ALIGNED'].sum()),
            file_not_aligned=int(c['POSIX_FILE_NOT_ALIGNED'].sum()))
        F['posix']['ftimes'] = {k: float(f[k].sum()) for k in
                                ['POSIX_F_READ_TIME','POSIX_F_WRITE_TIME','POSIX_F_META_TIME']}
        F['posix']['fmax'] = {k: float(f[k].max()) for k in
                              ['POSIX_F_MAX_READ_TIME','POSIX_F_MAX_WRITE_TIME',
                               'POSIX_F_SLOWEST_RANK_TIME','POSIX_F_VARIANCE_RANK_TIME',
                               'POSIX_F_VARIANCE_RANK_BYTES']}
        F['posix']['span'] = dict(
            open_start=float(f['POSIX_F_OPEN_START_TIMESTAMP'].replace(0,np.nan).min() or 0),
            first_read=float(f['POSIX_F_READ_START_TIMESTAMP'].replace(0,np.nan).min() or 0),
            first_write=float(f['POSIX_F_WRITE_START_TIMESTAMP'].replace(0,np.nan).min() or 0),
            last_read=float(f['POSIX_F_READ_END_TIMESTAMP'].max()),
            last_write=float(f['POSIX_F_WRITE_END_TIMESTAMP'].max()),
            last_close=float(f['POSIX_F_CLOSE_END_TIMESTAMP'].max()))
        # access-size histogram
        F['posix']['hist_read'] = {b: int(c[f'POSIX_SIZE_READ_{b}'].sum()) for b in RBINS}
        F['posix']['hist_write'] = {b: int(c[f'POSIX_SIZE_WRITE_{b}'].sum()) for b in RBINS}
        # common access sizes (ACCESS1..4 pairs), merged across records
        acc = collections.Counter()
        for i in (1,2,3,4):
            for sz, cnt in zip(c[f'POSIX_ACCESS{i}_ACCESS'], c[f'POSIX_ACCESS{i}_COUNT']):
                if cnt and cnt > 0: acc[int(sz)] += int(cnt)
        F['posix']['common_access'] = sorted(acc.items(), key=lambda kv: -kv[1])[:6]
        # strides
        st = collections.Counter()
        for i in (1,2,3,4):
            for sz, cnt in zip(c[f'POSIX_STRIDE{i}_STRIDE'], c[f'POSIX_STRIDE{i}_COUNT']):
                if cnt and cnt > 0: st[int(sz)] += int(cnt)
        F['posix']['common_stride'] = sorted(st.items(), key=lambda kv: -kv[1])[:4]
        # per-file rollup
        perfile = m.groupby('id').agg(
            rd=('POSIX_BYTES_READ','sum'), wr=('POSIX_BYTES_WRITTEN','sum'),
            opens=('POSIX_OPENS','sum'), reads=('POSIX_READS','sum'),
            writes=('POSIX_WRITES','sum'), stats=('POSIX_STATS','sum'),
            seeks=('POSIX_SEEKS','sum'), nrec=('rank','count'),
            minrank=('rank','min'), rtime=('POSIX_F_READ_TIME','sum'),
            wtime=('POSIX_F_WRITE_TIME','sum'), mtime=('POSIX_F_META_TIME','sum')).reset_index()
        perfile['total'] = perfile.rd + perfile.wr
        perfile['name'] = perfile['id'].map(lambda x: rep.name_records.get(x, str(x)))
        pf = perfile.sort_values('total', ascending=False)
        F['posix']['top_files'] = [dict(name=r['name'], bytes=int(r.total), rd=int(r.rd),
                                        wr=int(r.wr), opens=int(r.opens), reads=int(r.reads),
                                        writes=int(r.writes), stats=int(r.stats),
                                        shared=bool(r.minrank == -1))
                                   for _, r in pf.head(8).iterrows()]
        F['posix']['file_stats'] = dict(
            n_files=int(len(perfile)),
            zero_byte_files=int((perfile.total == 0).sum()),
            lt1MiB_files=int(((perfile.total > 0) & (perfile.total < 2**20)).sum()),
            ge1GiB_files=int((perfile.total >= 2**30).sum()),
            top1_share=float(pf.total.iloc[0] / perfile.total.sum()) if perfile.total.sum() > 0 else None,
            shared_files=int((perfile.minrank == -1).sum()),
            uniq_files=int((perfile.minrank >= 0).sum()),
            max_opens_one_file=int(perfile.opens.max()),
            metadata_only_files=int(((perfile.reads == 0) & (perfile.writes == 0)).sum()))
        # minimum opens any correct program would need: 1 per (file, accessing rank).
        # A shared record (rank -1) was touched by all nprocs ranks; a rank-private
        # record by exactly the ranks that hold a record for it.
        nproc = rep.metadata['job']['nprocs']
        exp = 0
        for fid, grp in m.groupby('id'):
            exp += nproc if (grp['rank'] == -1).any() else grp['rank'].nunique()
        F['posix']['file_stats']['expected_min_opens'] = int(exp)
        F['posix']['file_stats']['open_redundancy'] = float(perfile.opens.sum()/exp) if exp else None
        # per-rank rollup (only meaningful for rank>=0 records)
        ur = m[m['rank'] >= 0]
        if len(ur):
            g = ur.groupby('rank').agg(b=('POSIX_BYTES_READ','sum'), w=('POSIX_BYTES_WRITTEN','sum'),
                                       rt=('POSIX_F_READ_TIME','sum'), wt=('POSIX_F_WRITE_TIME','sum'),
                                       mt=('POSIX_F_META_TIME','sum'), op=('POSIX_OPENS','sum'))
            tot = (g.b + g.w); iot = (g.rt + g.wt + g.mt)
            F['posix']['per_rank'] = dict(
                n_ranks_with_io=int(len(g)), bytes_min=int(tot.min()), bytes_max=int(tot.max()),
                bytes_mean=float(tot.mean()), bytes_cv=float(tot.std(ddof=0)/tot.mean()) if tot.mean() else 0.0,
                iotime_min=float(iot.min()), iotime_max=float(iot.max()),
                iotime_mean=float(iot.mean()),
                iotime_cv=float(iot.std(ddof=0)/iot.mean()) if iot.mean() else 0.0,
                busiest_rank=int(tot.idxmax()), quietest_rank=int(tot.idxmin()),
                rank0_byte_share=float(tot.get(0,0)/tot.sum()) if tot.sum() else 0.0,
                opens_max=int(g.op.max()), opens_min=int(g.op.min()))
        else:
            F['posix']['per_rank'] = None
        # shared-record fastest/slowest
        sh = m[m['rank'] == -1]
        def _bal(idx):
            row = sh.loc[idx]
            fid = int(sh.at[idx, 'id'])
            return dict(
                fastest_rank=int(row['POSIX_FASTEST_RANK']), slowest_rank=int(row['POSIX_SLOWEST_RANK']),
                fastest_bytes=int(row['POSIX_FASTEST_RANK_BYTES']), slowest_bytes=int(row['POSIX_SLOWEST_RANK_BYTES']),
                fastest_time=float(row['POSIX_F_FASTEST_RANK_TIME']), slowest_time=float(row['POSIX_F_SLOWEST_RANK_TIME']),
                var_bytes=float(row['POSIX_F_VARIANCE_RANK_BYTES']), var_time=float(row['POSIX_F_VARIANCE_RANK_TIME']),
                bytes=int(row['POSIX_BYTES_READ'] + row['POSIX_BYTES_WRITTEN']),
                file=rep.name_records.get(fid, str(fid)))
        if len(sh):
            # two different questions: which shared file carries the bytes, and
            # which one actually costs the slowest rank the most time.
            F['posix']['shared_balance'] = _bal(
                sh['POSIX_BYTES_READ'].add(sh['POSIX_BYTES_WRITTEN']).idxmax())
            F['posix']['shared_balance_slowest'] = _bal(
                sh['POSIX_F_SLOWEST_RANK_TIME'].idxmax())
        else:
            F['posix']['shared_balance'] = None
            F['posix']['shared_balance_slowest'] = None
        F['posix']['derived'] = accum(rep, 'POSIX')

    # ---- MPI-IO ----
    if 'MPI-IO' in rep.modules:
        c = rep.records['MPI-IO'].to_df()['counters']
        f = rep.records['MPI-IO'].to_df()['fcounters']
        F['mpiio'] = dict(n_records=int(len(c)), n_files=int(c['id'].nunique()),
                          agg={k:int(c[k].sum()) for k in c.columns if k not in ('rank','id')
                               and not k.endswith('_RANK') and 'MODE' not in k
                               and not k.startswith('MPIIO_ACCESS')},
                          times={k: float(f[k].sum()) for k in
                                 ['MPIIO_F_READ_TIME','MPIIO_F_WRITE_TIME','MPIIO_F_META_TIME']},
                          hist_read={b:int(c[f'MPIIO_SIZE_READ_AGG_{b}'].sum()) for b in RBINS},
                          hist_write={b:int(c[f'MPIIO_SIZE_WRITE_AGG_{b}'].sum()) for b in RBINS},
                          derived=accum(rep, 'MPI-IO'))
    # ---- STDIO ----
    if 'STDIO' in rep.modules:
        c = rep.records['STDIO'].to_df()['counters']
        f = rep.records['STDIO'].to_df()['fcounters']
        names = [rep.name_records.get(i, str(i)) for i in c['id'].unique()]
        F['stdio'] = dict(n_records=int(len(c)), n_files=int(c['id'].nunique()),
                          names=names[:10],
                          agg={k:int(c[k].sum()) for k in c.columns if k not in ('rank','id')
                               and not k.endswith('_RANK')},
                          times={k: float(f[k].sum()) for k in
                                 ['STDIO_F_READ_TIME','STDIO_F_WRITE_TIME','STDIO_F_META_TIME']},
                          derived=accum(rep, 'STDIO'))
    # ---- LUSTRE ----
    if 'LUSTRE' in rep.modules:
        d = rep.records['LUSTRE'].to_df()
        comp = d['components'] if isinstance(d, dict) else d
        osts = set()
        for v in comp['LUSTRE_OST_IDS']:
            try: osts.update(int(x) for x in np.atleast_1d(v))
            except Exception: pass
        F['lustre'] = dict(n_records=int(len(comp)),
                           n_files=int(comp['id'].nunique()),
                           stripe_sizes=sorted(set(int(x) for x in comp['LUSTRE_COMP_STRIPE_SIZE'])),
                           stripe_counts=sorted(set(int(x) for x in comp['LUSTRE_COMP_STRIPE_COUNT'])),
                           pools=sorted(set(str(x) for x in comp['LUSTRE_POOL_NAME'])),
                           distinct_osts=len(osts), ost_ids=sorted(osts)[:40])
    # ---- DXT ----
    for dm_ in ('DXT_POSIX','DXT_MPIIO'):
        if dm_ in rep.modules:
            recs = rep.records[dm_].to_df()
            nseg_r = nseg_w = 0; t0 = None; t1 = None; ranks=set(); hosts=set()
            wlen=[]; rlen=[]
            for rec in recs:
                ranks.add(int(rec['rank'])); hosts.add(rec.get('hostname'))
                for key, n in (('write_segments','w'), ('read_segments','r')):
                    seg = rec.get(key)
                    if seg is None or len(seg)==0: continue
                    if n=='w': nseg_w += len(seg); wlen += list(seg['length'])
                    else: nseg_r += len(seg); rlen += list(seg['length'])
                    a=float(seg['start_time'].min()); b=float(seg['end_time'].max())
                    t0 = a if t0 is None else min(t0,a); t1 = b if t1 is None else max(t1,b)
            F[dm_.lower()] = dict(n_records=len(recs), n_write_segments=nseg_w, n_read_segments=nseg_r,
                                  ranks=sorted(ranks)[:20], n_ranks=len(ranks),
                                  hosts=sorted(str(h) for h in hosts if h)[:8],
                                  t_first=t0, t_last=t1,
                                  write_len_mean=float(np.mean(wlen)) if wlen else None,
                                  write_len_max=int(np.max(wlen)) if wlen else None,
                                  read_len_mean=float(np.mean(rlen)) if rlen else None,
                                  read_len_max=int(np.max(rlen)) if rlen else None)
    # ---- HEATMAP ----
    try:
        hm = {}
        for k, v in rep.heatmaps.items():
            bw = float(getattr(v, '_bin_width_seconds', 0) or 0)
            ent = dict(bin_width=bw, n_bins=int(getattr(v, '_nbins', 0) or 0),
                       n_ranks=len(getattr(v, '_ranks', []) or []), ops={})
            for op in ('read', 'write'):
                try:
                    arr = v.to_df([op]).to_numpy()
                except Exception:
                    continue
                colsum = arr.sum(axis=0)
                nz = np.nonzero(colsum)[0]
                if not len(nz):
                    ent['ops'][op] = dict(total=0.0, active_bins=0); continue
                ent['ops'][op] = dict(
                    total=float(arr.sum()), active_bins=int(len(nz)),
                    first_active=int(nz[0]), last_active=int(nz[-1]),
                    first_active_s=float(nz[0]*bw), last_active_s=float((nz[-1]+1)*bw),
                    peak_bin=int(colsum.argmax()), peak_bin_s=float(colsum.argmax()*bw),
                    peak_val=float(colsum.max()),
                    # share of the total that lands in the busiest 10% of active time
                    top10pct_share=float(np.sort(colsum)[::-1][:max(1, len(nz)//10)].sum()/colsum.sum()))
            hm[k] = ent
        F['heatmap'] = hm
    except Exception as e:
        F['heatmap'] = {'error': f'{type(e).__name__}: {e}'}
    # ---- APMPI presence ----
    F['has_apmpi'] = 'APMPI' in rep.modules
    return F
