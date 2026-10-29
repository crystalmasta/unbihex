"""Throughput A/B of two engine binaries on the load-test stand (bench/tools/run.py).

Alternates the binaries round by round so background noise hits both alike.
usage: python tput_ab.py BENCH_DIR OLD_BIN NEW_BIN ROUNDS
"""
import json, os, socket, statistics, subprocess, sys, threading, time

import psutil

S, OLD, NEW, ROUNDS = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
UB = os.path.join(S, "ubench", "target", "release", "ubench.exe")
CFG = os.path.join(S, "cfg")
OUT = os.path.join(S, "ab")
os.makedirs(OUT, exist_ok=True)
SINK_IP = "192.168.56.1"
DOWN, UP = f"{SINK_IP}:9700", f"{SINK_IP}:9701"
PATHS = dict(p.split("=") for p in os.environ.get("AB_PATHS", "reality=127.0.0.1:1091,vision=127.0.0.1:1092").split(","))
SECS = 6


def wait_port(addr, timeout=10):
    host, port = addr.rsplit(":", 1)
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((host, int(port)), 0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"{addr} not listening")


def cpu_during(pids, proc):
    """Average CPU % (of one thread) of each pid while `proc` runs."""
    ps = {k: psutil.Process(v) for k, v in pids.items()}
    for p in ps.values():
        p.cpu_percent(None)
    samples = {k: [] for k in ps}
    while proc.poll() is None:
        time.sleep(0.25)
        for k, p in ps.items():
            samples[k].append(p.cpu_percent(None))
    return {k: round(statistics.mean(v[1:] or v), 0) for k, v in samples.items() if v}


def round_for(label, binary, results):
    procs = {}
    try:
        procs["sink"] = subprocess.Popen([UB, "serve", SINK_IP, "9700"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for role in ("dest", "server", "client"):
            procs[role] = subprocess.Popen([binary, "run", "-c", os.path.join(CFG, f"{role}.json")], cwd=CFG,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for a in (DOWN, UP, "127.0.0.1:9450", "127.0.0.1:9444", "127.0.0.1:1091", "127.0.0.1:1092"):
            wait_port(a)
        time.sleep(1)
        for path, addr in PATHS.items():
            for d, tgt in (("down", DOWN), ("up", UP)):
                for n in (1, 8):
                    p = subprocess.Popen([UB, "tput", addr, tgt, d, str(n), str(SECS)], stdout=subprocess.PIPE, text=True)
                    cpu = cpu_during({"client": procs["client"].pid, "server": procs["server"].pid}, p)
                    out = p.communicate()[0]
                    r = json.loads(out.strip().splitlines()[-1])
                    key = f"{path} {d} {n}"
                    results.setdefault(key, {}).setdefault(label, []).append((r["gbit_s"], cpu))
                    print(f"{label:3} {key:16} {r['gbit_s']:6.2f} Gbit/s  client {cpu['client']:4.0f}%  server {cpu['server']:4.0f}%", flush=True)
    finally:
        for p in procs.values():
            p.terminate()
        time.sleep(2)


results = {}
for rnd in range(ROUNDS):
    for label, binary in (("old", OLD), ("new", NEW)) if rnd % 2 == 0 else (("new", NEW), ("old", OLD)):
        round_for(label, binary, results)

print("\nmedian Gbit/s (CPU client/server at that run)")
for key, by in results.items():
    row = []
    for label in ("old", "new"):
        runs = sorted(by.get(label, []), key=lambda x: x[0])
        g, cpu = runs[len(runs) // 2]
        row.append(f"{label} {g:6.2f} ({cpu['client']:.0f}/{cpu['server']:.0f}%)")
    old_g = sorted(x[0] for x in by["old"])[len(by["old"]) // 2]
    new_g = sorted(x[0] for x in by["new"])[len(by["new"]) // 2]
    print(f"{key:16} " + "   ".join(row) + f"   x{new_g / old_g:.2f}")
with open(os.path.join(OUT, "ab.json"), "w") as f:
    json.dump(results, f, indent=1)
