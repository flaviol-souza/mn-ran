# -*- coding: utf-8 -*-
"""
consolidate_by_event_type.py
----------------------------

Uso:
  python consolidate_by_event_type.py --logs-root /caminho/logs --out /caminho/saida

Estrutura esperada do --logs-root:
  logs/
    events_outage-1/
      controller_c2_kpi.jsonl
      controller_video_kpi.jsonl
      events.jsonl
      profile_changes.jsonl
    events_outage-2/
      ...
    events_bursty_loss-1/
      ...
    events_congestion-1/
      ...

Saídas (em --out), consolidadas por *tipo de evento* (ex.: outage, bursty_loss, congestion):
  - bar_ttr_ci95_by_group.png                 (TTR médio por tipo com IC95%)
  - bar_drop_continuity_ci95_by_group.png     (Queda de continuidade média por tipo com IC95%)
  - box_jitter_p95_by_group.png               (Boxplot do jitter p95 por tipo)
  - ecdf_video_goodput_by_group.png           (ECDF do goodput de vídeo por tipo)
  - stacked_time_per_profile_by_group.png     (Tempo médio em baseline/degraded por tipo)
  - per_event_group_summary.csv               (tabela consolidada por tipo de evento)
  - per_event_group_summary.tex               (tabela LaTeX equivalente)

Notas:
- Baseline dinâmico: janela [-min(5, t_event), 0); se ainda vazio, usa tudo que houver < t_event.
- TTR: primeiro t ≥ t_event com continuity ≥ max(0.9×baseline, 90). Sem recuperação em 30s ⇒ CAP=30.0.
- IC95%: 1.96 * (std / sqrt(N)) por tipo (se N=1, IC=0).
"""

import argparse
import json
import math
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ----------------- Utilidades básicas -----------------

def read_jsonl(p: Path) -> pd.DataFrame:
    if not p.exists():
        return pd.DataFrame()
    try:
        return pd.read_json(p, lines=True)
    except ValueError:
        rows = []
        with p.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        return pd.DataFrame(rows)


def norm_time(data: Dict[str, pd.DataFrame]) -> Dict[str, pd.DataFrame]:
    bases = []
    for k in ("c2", "video"):
        if not data[k].empty and "ts" in data[k].columns:
            bases.append(data[k]["ts"].min())
    if bases:
        t0 = min(bases)
        for k in ("c2", "video", "events", "profiles"):
            if not data[k].empty and "ts" in data[k].columns:
                data[k] = data[k].assign(t=(data[k]["ts"] - t0))
    return data


def load_exec(exec_dir: Path) -> Dict[str, pd.DataFrame]:
    data = {
        "c2": read_jsonl(exec_dir / "controller_c2_kpi.jsonl"),
        "video": read_jsonl(exec_dir / "controller_video_kpi.jsonl"),
        "events": read_jsonl(exec_dir / "events.jsonl"),
        "profiles": read_jsonl(exec_dir / "profile_changes.jsonl"),
    }
    data = norm_time(data)
    # duração
    dur = 0.0
    for k in ("c2", "video"):
        if not data[k].empty and "t" in data[k].columns:
            dur = max(dur, float(data[k]["t"].max()))
    data["duration"] = dur
    return data


def detect_event_group(dir_name: str) -> str:
    """
    Extrai o "tipo" do evento a partir do nome da pasta.
    Aceita formatos: events_outage-1, events_bursty_loss-2, etc.
    Retorna somente a parte após 'events_' e antes do traço, se houver.
    """
    name = dir_name
    if name.startswith("events_"):
        name = name[len("events_"):]
    # corta sufixo '-N' se existir
    if "-" in name:
        name = name.split("-", 1)[0]
    return name  # ex.: 'outage', 'bursty_loss', 'congestion'


# ----------------- Métricas por execução/evento -----------------

def baseline_window(df: pd.DataFrame, te: float, max_span: float = 5.0) -> pd.DataFrame:
    if df.empty or "t" not in df.columns:
        return pd.DataFrame()
    a = max(0.0, te - max_span)
    win = df[(df["t"] >= a) & (df["t"] < te)]
    if win.empty and te > 0:
        # fallback: usa tudo que houver antes de te
        win = df[df["t"] < te]
    return win


def per_event_metrics(c2: pd.DataFrame, events: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "event_type", "t_event",
        "baseline_continuity_pct", "impact_min_continuity_pct", "drop_continuity_pct",
        "baseline_jitter_p95_ms", "impact_peak_jitter_p95_ms", "delta_jitter_ms",
        "ttr_s"
    ]
    if c2.empty or events.empty or "t" not in c2.columns:
        return pd.DataFrame(columns=cols)

    rows = []
    for _, ev in events.iterrows():
        te = float(ev.get("t", np.nan))
        if not np.isfinite(te):
            continue
        etype = f"{ev.get('action','')}_{ev.get('target','')}"
        base_win = baseline_window(c2, te, max_span=5.0)
        post_win = c2[(c2["t"] >= te) & (c2["t"] < te + 10)]

        # continuidade
        base_cont = float(base_win["continuity_uptime_pct"].mean()) if "continuity_uptime_pct" in base_win else float("nan")
        min_cont  = float(post_win["continuity_uptime_pct"].min())  if "continuity_uptime_pct" in post_win else float("nan")
        drop_cont = base_cont - min_cont if (np.isfinite(base_cont) and np.isfinite(min_cont)) else float("nan")

        # jitter
        base_jit = float(base_win["jitter_p95_ms"].mean()) if "jitter_p95_ms" in base_win else float("nan")
        peak_jit = float(post_win["jitter_p95_ms"].max())  if "jitter_p95_ms" in post_win else float("nan")
        delta_jit = peak_jit - base_jit if (np.isfinite(base_jit) and np.isfinite(peak_jit)) else float("nan")

        # TTR (CAP=30s)
        target = 90.0 if not np.isfinite(base_cont) else max(0.9 * base_cont, 90.0)
        seg = c2[(c2["t"] >= te) & (c2["t"] <= te + 30)]
        if not seg.empty and "continuity_uptime_pct" in seg:
            ok = seg[seg["continuity_uptime_pct"] >= target]
            ttr = float(ok["t"].iloc[0] - te) if not ok.empty else 30.0
        else:
            ttr = 30.0

        rows.append({
            "event_type": etype,
            "t_event": te,
            "baseline_continuity_pct": base_cont,
            "impact_min_continuity_pct": min_cont,
            "drop_continuity_pct": drop_cont,
            "baseline_jitter_p95_ms": base_jit,
            "impact_peak_jitter_p95_ms": peak_jit,
            "delta_jitter_ms": delta_jit,
            "ttr_s": ttr
        })
    return pd.DataFrame(rows, columns=cols)


def time_by_profile(profiles: pd.DataFrame, duration: float) -> Dict[str, float]:
    """
    Constrói timeline simples com base em profile_changes.
    Assume 'baseline' inicial; se não houver info, considera toda duração em baseline.
    Retorna durações (s) em {'baseline', 'degraded'}.
    """
    out = {"baseline": 0.0, "degraded": 0.0}
    if duration <= 0:
        return out
    if profiles.empty or "t" not in profiles.columns:
        out["baseline"] = duration
        return out

    profs = profiles.sort_values("t").reset_index(drop=True)
    cur = "baseline"
    tcur = 0.0
    for _, row in profs.iterrows():
        tchg = float(row["t"])
        if tchg > duration:
            tchg = duration
        out[cur] = out.get(cur, 0.0) + max(0.0, tchg - tcur)
        nxt = None
        if isinstance(row.get("profile", None), str) and row["profile"]:
            nxt = row["profile"]
        elif isinstance(row.get("new_state", None), str) and row["new_state"]:
            nxt = row["new_state"]
        if nxt is None:
            nxt = "degraded"
        cur = "baseline" if "base" in nxt else "degraded"
        tcur = tchg
        if tcur >= duration:
            break
    if tcur < duration:
        out[cur] = out.get(cur, 0.0) + (duration - tcur)
    return {"baseline": out.get("baseline", 0.0), "degraded": out.get("degraded", 0.0)}


# ----------------- Consolidação por *tipo* de evento -----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-root", required=True, type=str, help="Pasta raiz com as execuções")
    ap.add_argument("--out", required=True, type=str, help="Pasta de saída")
    args = ap.parse_args()

    root = Path(args.logs_root)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    # Agrupadores por tipo
    jitter_by_group: Dict[str, List[np.ndarray]] = {}
    goodput_by_group: Dict[str, List[np.ndarray]] = {}
    time_profile_by_group: Dict[str, List[Dict[str, float]]] = {}
    per_event_rows: List[pd.DataFrame] = []

    for exec_dir in sorted([p for p in root.iterdir() if p.is_dir()]):
        group = detect_event_group(exec_dir.name)  # ex.: outage, bursty_loss, congestion
        data = load_exec(exec_dir)

        # C2 jitter p95 por tipo
        if not data["c2"].empty and "jitter_p95_ms" in data["c2"]:
            jitter_by_group.setdefault(group, []).append(
                data["c2"]["jitter_p95_ms"].dropna().astype(float).values
            )

        # Vídeo goodput por tipo
        if not data["video"].empty and "bitrate_mbps" in data["video"]:
            goodput_by_group.setdefault(group, []).append(
                data["video"]["bitrate_mbps"].dropna().astype(float).values
            )

        # Tempo em perfis (baseline/degraded)
        time_profile_by_group.setdefault(group, []).append(
            time_by_profile(data["profiles"], data["duration"])
        )

        # Métricas por evento (para TTR/queda continuidade)
        pem = per_event_metrics(data["c2"], data["events"])
        if not pem.empty:
            pem["exec"] = exec_dir.name
            pem["event_group"] = group
            per_event_rows.append(pem)

    per_event_df = pd.concat(per_event_rows, ignore_index=True) if per_event_rows else pd.DataFrame()

    # ---------- Boxplot jitter p95 por grupo ----------
    if jitter_by_group:
        labels = list(jitter_by_group.keys())
        series = [np.concatenate(jitter_by_group[g]) for g in labels if len(jitter_by_group[g]) > 0]
        labels = [g for g in labels if g in jitter_by_group and len(jitter_by_group[g]) > 0]
        if series:
            plt.figure()
            plt.boxplot(series, tick_labels=labels, showmeans=True)
            plt.title("C2 jitter p95 por tipo de evento")
            plt.ylabel("Jitter p95 (ms)")
            plt.tight_layout()
            plt.savefig(outdir / "box_jitter_p95_by_group.png", dpi=200)
            plt.close()

    # ---------- ECDF goodput por grupo ----------
    def ecdf(x):
        x = np.sort(np.asarray(x))
        y = np.arange(1, len(x) + 1) / len(x) if len(x) else np.array([])
        return x, y

    if goodput_by_group:
        plt.figure()
        for g, arrs in goodput_by_group.items():
            if not arrs:
                continue
            x = np.concatenate(arrs)
            xs, ys = ecdf(x)
            plt.plot(xs, ys, label=g)
        plt.title("ECDF do video goodput (Mbps) por tipo de evento")
        plt.xlabel("Goodput (Mbps)")
        plt.ylabel("F(x)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(outdir / "ecdf_video_goodput_by_group.png", dpi=200)
        plt.close()

    # ---------- Stacked bars: tempo médio em perfis por grupo ----------
    if time_profile_by_group:
        groups = []
        base_means = []
        degr_means = []
        for g, lst in time_profile_by_group.items():
            if not lst:
                continue
            b = np.array([d["baseline"] for d in lst], dtype=float)
            d = np.array([d["degraded"] for d in lst], dtype=float)
            groups.append(g)
            base_means.append(float(np.nanmean(b)))
            degr_means.append(float(np.nanmean(d)))
        if groups:
            ind = np.arange(len(groups))
            plt.figure()
            plt.bar(ind, base_means, label="baseline")
            plt.bar(ind, degr_means, bottom=base_means, label="degraded")
            plt.xticks(ind, groups, rotation=20, ha='right')
            plt.ylabel("Tempo médio (s)")
            plt.title("Tempo médio em baseline/degraded por tipo de evento")
            plt.legend()
            plt.tight_layout()
            plt.savefig(outdir / "stacked_time_per_profile_by_group.png", dpi=200)
            plt.close()

    # ---------- Barras com IC95%: TTR e Queda de continuidade por grupo ----------
    if not per_event_df.empty:
        # Filtra valores válidos por métrica
        df_ttr  = per_event_df[np.isfinite(per_event_df["ttr_s"])]
        if df_ttr.empty:
            print("[WARN] Sem valores válidos de TTR para consolidar por tipo.")

        df_drop = per_event_df[np.isfinite(per_event_df["drop_continuity_pct"])]
        if df_drop.empty:
            print("[WARN] Sem valores válidos de Queda de continuidade para consolidar por tipo.")

        def agg_ci95(df: pd.DataFrame, value_col: str, title: str, ylabel: str, outname: str):
            if df.empty:
                return
            agg = df.groupby("event_group").agg(
                mean=(value_col, "mean"),
                count=(value_col, "count"),
                std=(value_col, "std")
            ).reset_index()
            if agg.empty:
                return
            means = agg["mean"].astype(float).values
            ns    = agg["count"].astype(int).values
            stds  = agg["std"].fillna(0.0).astype(float).values
            se = np.zeros_like(means)
            mask = ns > 1
            se[mask] = stds[mask] / np.sqrt(ns[mask])
            ci = 1.96 * se
            lo = means - ci
            hi = means + ci
            yerr = np.vstack([np.maximum(0.0, means - lo), np.maximum(0.0, hi - means)])

            x = np.arange(len(agg))
            plt.figure()
            plt.bar(x, means, yerr=yerr, capsize=4)
            plt.xticks(x, agg["event_group"].values, rotation=20, ha='right')
            plt.ylabel(ylabel)
            plt.title(title)
            plt.tight_layout()
            plt.savefig(outdir / outname, dpi=200)
            plt.close()

        # TTR (s) por tipo
        agg_ci95(df_ttr,  "ttr_s",
                 "TTR por tipo de evento (média, IC95%)",
                 "TTR (s)", "bar_ttr_ci95_by_group.png")

        # Queda continuidade (%) por tipo
        agg_ci95(df_drop, "drop_continuity_pct",
                 "Queda de continuidade por tipo de evento (média, IC95%)",
                 "Queda de continuidade (%)", "bar_drop_continuity_ci95_by_group.png")

        # ---------- Tabela consolidada por tipo ----------
        # Para a tabela: média/mediana/p95 e N por grupo, para TTR e queda de continuidade (e opcionalmente delta_jitter)
        # ---------- Tabela consolidada por tipo ----------
        def summarize(df: pd.DataFrame, col: str) -> pd.DataFrame:
            """Resumo por event_group: mean, median, p95, N. Retorna tipos corretos mesmo com 1 grupo."""
            import numpy as np
            import pandas as pd

            if df.empty or col not in df.columns or "event_group" not in df.columns:
                return pd.DataFrame(columns=["event_group","mean","median","p95","N"])

            d = df[np.isfinite(df[col])].copy()
            if d.empty:
                return pd.DataFrame(columns=["event_group","mean","median","p95","N"])

            out = d.groupby("event_group").agg(
                mean   =(col, "mean"),
                median =(col, "median"),
                p95    =(col, lambda s: float(np.percentile(s.dropna(), 95)) if s.dropna().size else np.nan),
                N      =(col, "size"),
            ).reset_index()

            out["mean"]   = out["mean"].astype(float)
            out["median"] = out["median"].astype(float)
            out["p95"]    = out["p95"].astype(float)
            out["N"]      = out["N"].astype(int)
            return out

        # Tabelas parciais (podem estar vazias)
        tbl_ttr  = summarize(df_ttr,  "ttr_s").rename(columns={"mean":"ttr_mean","median":"ttr_median","p95":"ttr_p95","N":"ttr_N"})
        tbl_drop = summarize(df_drop, "drop_continuity_pct").rename(columns={"mean":"drop_mean","median":"drop_median","p95":"drop_p95","N":"drop_N"})
        df_djit  = per_event_df[np.isfinite(per_event_df["delta_jitter_ms"])]
        tbl_djit = summarize(df_djit, "delta_jitter_ms").rename(columns={"mean":"djit_mean","median":"djit_median","p95":"djit_p95","N":"djit_N"})

        # Merge seguro (pode faltar uma das tabelas)
        summary = tbl_ttr.merge(tbl_drop, on="event_group", how="outer").merge(tbl_djit, on="event_group", how="outer")

        # Helper de formatação segura
        def fmt(v, nd=2):
            try:
                if v is None or (isinstance(v, float) and np.isnan(v)):
                    return ""
                return f"{float(v):.{nd}f}"
            except Exception:
                return ""

        def fmt_int(v):
            try:
                return str(int(v))
            except Exception:
                return "0"

        tex_path = outdir / "per_event_group_summary.tex"
        with tex_path.open("w") as f:
            f.write("% Auto-generated by consolidate_by_event_type.py\n")
            f.write("\\begin{table}[t]\n\\centering\n")
            f.write("\\caption{Resumo estatístico consolidado por tipo de evento}\n")
            f.write("\\label{tab:per_event_group_summary}\n")
            f.write("\\begin{tabular}{l r r r r r r r r r}\n")
            f.write("\\hline\n")
            f.write("Tipo & TTR$_{mean}$ & TTR$_{median}$ & TTR$_{p95}$ & N$_{TTR}$ & ")
            f.write("$\\Delta$Cont$_{mean}$ & $\\Delta$Cont$_{median}$ & $\\Delta$Cont$_{p95}$ & N_{\\Delta Cont} & ")
            f.write("$\\Delta$Jit$_{mean}$\\\\\n")
            f.write("\\hline\n")
            for _, r in summary.iterrows():
                f.write(
                    f"{r.get('event_group','')} & "
                    f"{fmt(r.get('ttr_mean'))} & {fmt(r.get('ttr_median'))} & {fmt(r.get('ttr_p95'))} & {fmt_int(r.get('ttr_N'))} & "
                    f"{fmt(r.get('drop_mean'))} & {fmt(r.get('drop_median'))} & {fmt(r.get('drop_p95'))} & {fmt_int(r.get('drop_N'))} & "
                    f"{fmt(r.get('djit_mean'))}\\\\\n"
                )
            f.write("\\hline\n\\end{tabular}\n\\end{table}\n")
        print(f"LaTeX table escrita em: {tex_path}")

if __name__ == "__main__":
    main()