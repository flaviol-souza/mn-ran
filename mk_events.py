#!/usr/bin/env python3
import sys, yaml, argparse

def expand(repeat_cfg, targets, role2iface):
    at0    = int(repeat_cfg.get("warmup_s", 60))
    on     = int(repeat_cfg.get("on_s", 45))
    off    = int(repeat_cfg.get("off_s", 30))
    cycles = int(repeat_cfg.get("cycles", 5))
    netem  = dict(repeat_cfg.get("netem", {}))

    t = at0
    evs = []
    for _ in range(cycles):
        # aplica netem nas targets
        for role in targets:
            iface = role2iface[role]
            evs.append({"at": t, "iface": iface, "netem": dict(netem)})
        t += on
        # limpa nas mesmas targets
        for role in targets:
            iface = role2iface[role]
            evs.append({"at": t, "iface": iface, "clear": True})
        t += off
    evs.sort(key=lambda e: e.get("at", 0))
    return evs

def main():
    p = argparse.ArgumentParser(description="Expand link impairment templates into flat event lists.")
    p.add_argument("--uplink",   default="s1-eth2", help="iface egress UAV→GCS (uplink), ex.: s1-eth2")
    p.add_argument("--downlink", default="s1-eth3", help="iface egress GCS→UAV (downlink), ex.: s1-eth3")
    p.add_argument("--template", required=True,     help="YAML template with {targets, repeat:{warmup_s,on_s,off_s,cycles,netem:{...}}}")
    p.add_argument("--out",      required=True,     help="output events YAML (flat list)")
    args = p.parse_args()

    role2iface = {"uplink": args.uplink, "downlink": args.downlink}
    tpl = yaml.safe_load(open(args.template))

    if isinstance(tpl, dict) and "repeat" in tpl:
        targets = tpl.get("targets", ["uplink", "downlink"])
        evs = expand(tpl["repeat"], targets, role2iface)
        yaml.safe_dump(evs, open(args.out, "w"), sort_keys=False)
        print(f"[ok] written: {args.out} ({len(evs)} events) targets={targets}")
    elif isinstance(tpl, list):
        # também aceita lista plana e só grava de volta (útil para reformatar/validar)
        yaml.safe_dump(tpl, open(args.out, "w"), sort_keys=False)
        print(f"[ok] copied flat list to: {args.out} ({len(tpl)} events)")
    else:
        sys.exit("Unsupported template. Provide dict with 'repeat' or a flat list.")

if __name__ == "__main__":
    main()
