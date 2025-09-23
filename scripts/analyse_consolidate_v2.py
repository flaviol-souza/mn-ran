# -*- coding: utf-8 -*-
"""
consolidate_pcap_results.py
Autônomo: NÃO depende de per_exec_df.

- Varre logs/<exec_dir> para obter event_group (ex.: events_outage-1 -> outage).
- Lê CSVs do pcap em out/<exec_dir>/ (gerados via transfer.sh).
- (Opcional) Lê JSONL do controlador em logs/<exec_dir>/ e cruza com pcap.
- Consolida e gera gráficos alinhados ao abstract.

Requisitos: pandas, numpy, matplotlib
"""

import argparse, json, math
from pathlib import Path
from typing import Optional, Tuple, Dict, List
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ---------------- utils ----------------
def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)

def event_group_from_exec(exec_name: str) -> str:
    # "events_outage-2" -> "outage"
    if exec_name.startswith("events_"):
        name = exec_name[len("events_"):]
    else:
        name = exec_name
    if "-" in name:
        name = name.split("-", 1)[0]
    return name

def read_jsonl(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_json(path, lines=True)
    except ValueError:
        rows=[]
        for ln in path.read_text().splitlines():
            ln=ln.strip()
            if not ln: continue
            try:
                rows.append(json.loads(ln))
            except Exception:
                pass
        return pd.DataFrame(rows)

def ci95(series: pd.Series) -> float:
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.size <= 1:
        return 0.0
    return 1.96 * s.std(ddof=1) / math.sqrt(s.size)

# --------------- C2 (pcap CSV) ---------------
def mav_seq_from_hex(hex_payload: str) -> Optional[int]:
    try:
        b = bytes.fromhex(str(hex_payload).replace(":","").replace(" ",""))
        if not b: return None
        if b[0]==0xFD and len(b)>=5: return b[4]  # MAVLink v2
        if b[0]==0xFE and len(b)>=3: return b[2]  # MAVLink v1
        return None
    except Exception:
        return None

def loss_pct_from_seq(seq_arr: np.ndarray) -> float:
    if seq_arr.size < 2:
        return np.nan
    lost=0
    expected=(int(seq_arr[0])+1) & 0xFF
    for s in seq_arr[1:]:
        s=int(s)
        if s != expected:
            diff=(s - expected) & 0xFF
            if diff > 0:
                lost += diff
        expected=(s+1) & 0xFF
    return 100.0 * lost / float(seq_arr.size + lost)

def jitter_p95_and_gaps_ms(times: np.ndarray) -> Tuple[float, np.ndarray]:
    if times.size < 2:
        return (np.nan, np.array([]))
    dt = np.diff(times) * 1000.0
    return float(np.percentile(dt, 95)), dt

def pcap_c2_metrics(exec_dir: Path, pcap_out_root: Path, gap_ms: float) -> Optional[Dict]:
    p = exec_dir.name/"c2_mavlink_raw.csv"
    if not p.exists() or p.stat().st_size == 0:
        return None
    df = pd.read_csv(p)
    t = pd.to_numeric(df.get("frame.time_epoch") or df.get("time_epoch"), errors="coerce").dropna().values
    jp95, dt = jitter_p95_and_gaps_ms(t)
    max_gap = float(dt.max()) if dt.size else np.nan
    frac_gaps = float(np.mean(dt > gap_ms)) if dt.size else np.nan
    loss = np.nan
    if "data.data" in df.columns:
        seqs = (
            pd.Series(df["data.data"])
            .fillna("")
            .astype(str)
            .apply(mav_seq_from_hex)
            .dropna()
            .astype(int)
            .values
        )
        if seqs.size >= 2:
            loss = loss_pct_from_seq(seqs)
    return {
        "exec": exec_dir.name,
        "event_group": event_group_from_exec(exec_dir.name),
        "pcap_c2_jitter_p95_ms": jp95,
        "pcap_c2_max_gap_ms": max_gap,
        "pcap_c2_frac_gaps_gt_ms": frac_gaps,
        "pcap_c2_loss_pct": loss,
        "pcap_c2_n_pkts": int(df.shape[0])
    }

# --------------- Vídeo (pcap CSV) ---------------
def pcap_video_metrics(exec_dir: Path, pcap_out_root: Path, gap_ms: float, bw_min_mbps: float) -> Optional[Dict]:
    p = exec_dir.name/"video_udp.csv"
    if not p.exists() or p.stat().st_size == 0:
        return None
    df = pd.read_csv(p)
    t = pd.to_numeric(df.get("frame.time_epoch") or df.get("time_epoch"), errors="coerce").dropna().values
    fl = pd.to_numeric(df.get("frame.len"), errors="coerce").fillna(0).values
    jp95, dt = jitter_p95_and_gaps_ms(t)
    max_gap = float(dt.max()) if dt.size else np.nan
    frac_gaps = float(np.mean(dt > gap_ms)) if dt.size else np.nan
    # bitrate médio (janela de 1 s)
    if t.size:
        t0, t1 = t.min(), t.max()
        edges = np.arange(t0, t1 + 1.0, 1.0)
        idx = np.clip(np.digitize(t, edges) - 1, 0, len(edges) - 2)
        bins_bytes = np.bincount(idx, weights=fl, minlength=len(edges)-1)
        bitrate = bins_bytes * 8.0 / 1e6  # Mbps
        goodput_mean = float(np.mean(bitrate)) if bitrate.size else np.nan
        pct_time_ge = float(np.mean(bitrate >= bw_min_mbps)) * 100.0 if bitrate.size else np.nan
    else:
        goodput_mean = np.nan
        pct_time_ge = np.nan
    return {
        "exec": exec_dir.name,
        "event_group": event_group_from_exec(exec_dir.name),
        "pcap_video_goodput_mean_mbps": goodput_mean,
        "pcap_video_pct_time_ge_min": pct_time_ge,
        "pcap_video_jitter_p95_ms": jp95,
        "pcap_video_max_gap_ms": max_gap,
        "pcap_video_frac_gaps_gt_ms": frac_gaps,
        "pcap_video_n_pkts": int(df.shape[0])
    }

# --------------- DSCP (pcap CSV) ---------------
def pcap_dscp_counts(exec_dir: Path, pcap_out_root: Path) -> Optional[pd.DataFrame]:
    p = exec_dir.name/"dscp.csv"
    if not p.exists() or p.stat().st_size == 0:
        return None
    df = pd.read_csv(p)
    if df.empty: return None
    ds = df.get("ip.dsfield.dscp")
    if ds is None and "ipv6.tclass.dsfield.dscp" in df.columns:
        ds = df["ipv6.tclass.dsfield.dscp"]
    df["dscp"] = ds
    df["sport"] = df.get("udp.srcport").astype(str)
    df["dport"] = df.get("udp.dstport").astype(str)
    def flow(s,d):
        if s=="14550" or d=="14550": return "C2"
        if s=="5600"  or d=="5600":  return "VIDEO"
        return "OTHER"
    df["flow"] = df.apply(lambda r: flow(r["sport"], r["dport"]), axis=1)
    g = df.groupby(["flow","dscp"]).size().reset_index(name="count")
    g["exec"] = exec_dir.name
    g["event_group"] = event_group_from_exec(exec_dir.name)
    return g

# --------------- Controller JSONL (opcional) ---------------
def _as_series(df_or_val, colnames):
    """
    Tenta obter uma Series numérica a partir de um DataFrame + lista de nomes de coluna,
    ou a partir de um valor escalar. Retorna uma Series (possivelmente vazia).
    """
    import numpy as np
    import pandas as pd

    # Se já for Series
    if isinstance(df_or_val, pd.Series):
        return pd.to_numeric(df_or_val, errors="coerce")

    # Se for DataFrame, procure a 1ª coluna existente na ordem dos colnames
    if isinstance(df_or_val, pd.DataFrame):
        for k in colnames:
            if k in df_or_val.columns:
                return pd.to_numeric(df_or_val[k], errors="coerce")
        # nada encontrado -> série vazia
        return pd.Series(dtype=float)

    # Se for escalar (numpy.float64, int, etc.)
    if np.isscalar(df_or_val):
        return pd.to_numeric(pd.Series([df_or_val]), errors="coerce")

    # Outro tipo -> série vazia
    return pd.Series(dtype=float)


def controller_metrics(exec_dir: Path) -> Tuple[Optional[Dict], Optional[Dict]]:
    c2 = exec_dir / "controller_c2_kpi.jsonl"
    vd = exec_dir / "controller_video_kpi.jsonl"
    c2m = None
    vdm = None

    # ----- C2 -----
    if c2.exists():
        d = read_jsonl(c2)
        if not d.empty:
            # tente vários aliases comuns de coluna
            jitter_ser = _as_series(d, ["jitter_ms", "c2_jitter_ms", "jitter"])
            gap_ser    = _as_series(d, ["gap_ms", "c2_gap_ms", "gap"])
            cont_ser   = _as_series(d, ["drop_continuity_pct", "drop_pct", "continuity_drop_pct"])

            jit_p95 = float(np.percentile(jitter_ser.dropna().values, 95)) if jitter_ser.dropna().size else np.nan
            gap_max = float(gap_ser.dropna().max()) if gap_ser.dropna().size else np.nan
            cont_mean = float(cont_ser.dropna().mean()) if cont_ser.dropna().size else np.nan

            c2m = {
                "exec": exec_dir.name,
                "event_group": event_group_from_exec(exec_dir.name),
                "ctl_c2_jitter_p95_ms": jit_p95,
                "ctl_c2_max_gap_ms": gap_max,
                "ctl_c2_drop_continuity_pct_mean": cont_mean,
            }

    # ----- Vídeo -----
    if vd.exists():
        d = read_jsonl(vd)
        if not d.empty:
            goodput_ser = _as_series(d, ["goodput_mbps", "video_goodput_mbps", "goodput"])
            jitter_ser  = _as_series(d, ["jitter_ms", "video_jitter_ms", "jitter"])

            goodput_mean = float(goodput_ser.dropna().mean()) if goodput_ser.dropna().size else np.nan
            jit_p95      = float(np.percentile(jitter_ser.dropna().values, 95)) if jitter_ser.dropna().size else np.nan

            vdm = {
                "exec": exec_dir.name,
                "event_group": event_group_from_exec(exec_dir.name),
                "ctl_video_goodput_mean_mbps": goodput_mean,
                "ctl_video_jitter_p95_ms": jit_p95,
            }

    return c2m, vdm


# --------------- Main ---------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="pasta com as execuções (onde ficam os JSONL)")
    ap.add_argument("--out", required=True, help="pasta de saída")
    ap.add_argument("--gap-ms", type=float, default=500.0, help="limiar de gap para continuidade proxy")
    ap.add_argument("--video-bw-min", type=float, default=0.2, help="Mbps mínimo para vídeo estável")
    args = ap.parse_args()

    data_src = Path(args.data)
    outdir = Path(args.out); ensure_dir(outdir)

    exec_dirs = [p for p in sorted(data_src.iterdir()) if p.is_dir()]

    c2_rows=[]; vid_rows=[]; dscp_all=[]
    ctl_c2_rows=[]; ctl_vid_rows=[]

    for ed in exec_dirs:
        print(ed)
        # métricas do pcap
        c2m = pcap_c2_metrics(ed, outdir, gap_ms=args.gap_ms)
        if c2m: c2_rows.append(c2m)
        vm  = pcap_video_metrics(ed, outdir, gap_ms=args.gap_ms, bw_min_mbps=args.video_bw_min)
        if vm: vid_rows.append(vm)
        dc  = pcap_dscp_counts(ed, outdir)
        if dc is not None and not dc.empty: dscp_all.append(dc)
        # (opcional) métricas do controlador (se existirem JSONL)
        cctl, vctl = controller_metrics(ed)
        if cctl: ctl_c2_rows.append(cctl)
        if vctl: ctl_vid_rows.append(vctl)

    # DataFrames finais (pcap)
    df_c2 = pd.DataFrame(c2_rows)
    df_vid = pd.DataFrame(vid_rows)
    df_dscp = pd.concat(dscp_all, ignore_index=True) if dscp_all else pd.DataFrame()

    if not df_c2.empty: df_c2.to_csv(outdir/"pcap_per_exec_c2.csv", index=False)
    if not df_vid.empty: df_vid.to_csv(outdir/"pcap_per_exec_video.csv", index=False)
    if not df_dscp.empty: df_dscp.to_csv(outdir/"pcap_per_exec_dscp.csv", index=False)

    # Gráficos por grupo (pcap puro)
    if not df_c2.empty:
        plt.figure()
        data=[]; labels=[]
        for g, sub in df_c2.groupby("event_group"):
            vals = pd.to_numeric(sub["pcap_c2_jitter_p95_ms"], errors="coerce").dropna().values
            if vals.size: data.append(vals); labels.append(g)
        if data:
            plt.boxplot(data, tick_labels=labels, showmeans=True)
            plt.ylabel("C2 jitter p95 (ms)")
            plt.title("C2 jitter p95 por tipo de evento (pcap)")
            plt.tight_layout(); plt.savefig(outdir/"box_c2_jitter_p95_by_group_pcap.png", dpi=200)
        plt.close()

    if not df_vid.empty:
        plt.figure()
        for g, sub in df_vid.groupby("event_group"):
            xs = np.sort(pd.to_numeric(sub["pcap_video_goodput_mean_mbps"], errors="coerce").dropna().values)
            if xs.size:
                ys = np.arange(1, xs.size+1)/xs.size
                plt.plot(xs, ys, label=g)
        plt.xlabel("Goodput médio por execução (Mbps)")
        plt.ylabel("F(x)")
        plt.title("ECDF do goodput de vídeo por tipo de evento (pcap)")
        plt.legend(); plt.tight_layout(); plt.savefig(outdir/"ecdf_video_bitrate_by_group_pcap.png", dpi=200)
        plt.close()

    if not df_dscp.empty:
        for flow in ["C2","VIDEO"]:
            sub = df_dscp[df_dscp["flow"]==flow]
            if sub.empty: continue
            piv = sub.pivot_table(index="event_group", columns="dscp", values="count", aggfunc="sum").fillna(0)
            if piv.empty: continue
            piv = piv.div(piv.sum(axis=1), axis=0) * 100.0
            ax = piv.plot(kind="bar", stacked=True, figsize=(8,4))
            ax.set_ylabel("% dos pacotes"); ax.set_title(f"DSCP observado ({flow}) por tipo de evento (pcap)")
            ax.legend(title="DSCP", bbox_to_anchor=(1.02,1), loc="upper left")
            plt.tight_layout(); plt.savefig(outdir/f"stacked_dscp_{flow.lower()}_by_group.png", dpi=200)
            plt.close()

    # Cruzamentos com controlador (se existirem JSONL)
    df_ctl_c2 = pd.DataFrame(ctl_c2_rows)
    df_ctl_vid = pd.DataFrame(ctl_vid_rows)

    if not df_ctl_c2.empty and not df_c2.empty:
        m = df_ctl_c2.merge(df_c2, on=["exec","event_group"], how="inner")
        m.to_csv(outdir/"merged_controller_vs_pcap_c2.csv", index=False)
        # Scatter validação jitter C2
        x = pd.to_numeric(m["ctl_c2_jitter_p95_ms"], errors="coerce")
        y = pd.to_numeric(m["pcap_c2_jitter_p95_ms"], errors="coerce")
        keep = ~(x.isna() | y.isna())
        if keep.any():
            plt.figure()
            for g, sub in m[keep].groupby("event_group"):
                plt.scatter(sub["ctl_c2_jitter_p95_ms"], sub["pcap_c2_jitter_p95_ms"], label=g, alpha=0.85)
            lim = [0, float(max(x[keep].max(), y[keep].max())*1.05)]
            plt.plot(lim, lim, linestyle="--", linewidth=1)
            plt.xlabel("C2 jitter p95 (controller, ms)")
            plt.ylabel("C2 jitter p95 (pcap, ms)")
            plt.title("Validação C2: controller vs pcap")
            plt.legend(); plt.tight_layout(); plt.savefig(outdir/"scatter_c2_jitter_controller_vs_pcap.png", dpi=200)
            plt.close()

    if not df_ctl_vid.empty and not df_vid.empty:
        m = df_ctl_vid.merge(df_vid, on=["exec","event_group"], how="inner")
        m.to_csv(outdir/"merged_controller_vs_pcap_video.csv", index=False)
        # ECDF de goodput (controller vs pcap), média por execução
        plt.figure()
        for g, sub in m.groupby("event_group"):
            xs1 = np.sort(pd.to_numeric(sub["ctl_video_goodput_mean_mbps"], errors="coerce").dropna().values)
            xs2 = np.sort(pd.to_numeric(sub["pcap_video_goodput_mean_mbps"], errors="coerce").dropna().values)
            if xs1.size: plt.plot(xs1, np.arange(1,len(xs1)+1)/len(xs1), label=f"{g} controller")
            if xs2.size: plt.plot(xs2, np.arange(1,len(xs2)+1)/len(xs2), label=f"{g} pcap", linestyle="--")
        plt.xlabel("Goodput médio por execução (Mbps)")
        plt.ylabel("F(x)")
        plt.title("ECDF de goodput de vídeo (controller vs pcap)")
        plt.legend(); plt.tight_layout(); plt.savefig(outdir/"ecdf_video_goodput_controller_vs_pcap.png", dpi=200)
        plt.close()

    print(f"[OK] Saídas em: {outdir}")

if __name__ == "__main__":
    main()
