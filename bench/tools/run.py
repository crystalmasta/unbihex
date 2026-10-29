"""Load test of the Unbihex engine: throughput, many connections, connection rate.

Starts: sink (ubench serve), dest (REALITY dest, a TLS inbound), server (REALITY), client
(mixed inbounds -> direct / REALITY / REALITY+Vision), samples CPU and memory of each
process with psutil while ubench runs, and writes results.json.

usage: python run.py SCRATCH BIN [quick]
"""
import json, os, socket, subprocess, sys, threading, time

import psutil

S, BIN = sys.argv[1], sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else "full"
QUICK = MODE == "quick"
UB = os.path.join(S, "ubench", "target", "release", "ubench.exe")
CFG = os.path.join(S, "cfg")
OUT = os.path.join(S, "results")
os.makedirs(OUT, exist_ok=True)
SINK_IP = "192.168.56.1"
DOWN, UP, ECHO = f"{SINK_IP}:9700", f"{SINK_IP}:9701", f"{SINK_IP}:9702"
PATHS = {"base": "direct", "engine": "127.0.0.1:1090", "reality": "127.0.0.1:1091", "vision": "127.0.0.1:1092"}
ROLES = {"base": ["sink"], "engine": ["client", "sink"],
         "reality": ["client", "server", "dest", "sink"], "vision": ["client", "server", "dest", "sink"]}
NCPU = psutil.cpu_count()

procs = {}


def start(name, args, cwd=None):
    log = open(os.path.join(OUT, f"{name}.log"), "w")
    p = subprocess.Popen(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
    procs[name] = p
    with open(os.path.join(OUT, "pids.txt"), "a") as f:
        f.write(f"{p.pid}\n")
    return p


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


class Sampler:
    def __init__(self, roles, extra=None):
        self.ps = {r: psutil.Process(procs[r].pid) for r in roles}
        if extra:
            self.ps.update(extra)
        self.samples = {r: [] for r in self.ps}
        self.stop = threading.Event()
        for p in self.ps.values():
            p.cpu_percent(None)
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.wait(0.25):
            for r, p in self.ps.items():
                try:
                    m = p.memory_info()
                    self.samples[r].append(dict(t=time.time(), cpu=p.cpu_percent(None), rss=m.rss,
                                                priv=getattr(m, "private", m.rss),
                                                handles=p.num_handles() if hasattr(p, "num_handles") else 0,
                                                threads=p.num_threads()))
                except psutil.Error:
                    pass

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *a):
        self.stop.set()
        self.t.join()

    def summary(self):
        out = {}
        for r, s in self.samples.items():
            if not s:
                continue
            busy = s[1:] or s
            cpu = [x["cpu"] for x in busy]
            out[r] = dict(
                cpu_avg=round(sum(cpu) / len(cpu), 1), cpu_peak=round(max(cpu), 1),
                rss_start_mb=round(s[0]["rss"] / 2**20, 1), rss_peak_mb=round(max(x["rss"] for x in s) / 2**20, 1),
                rss_end_mb=round(s[-1]["rss"] / 2**20, 1),
                priv_start_mb=round(s[0]["priv"] / 2**20, 1), priv_peak_mb=round(max(x["priv"] for x in s) / 2**20, 1),
                handles_peak=max(x["handles"] for x in s), threads_peak=max(x["threads"] for x in s))
        return out


results = []


def ub(path, *args, timeout=600):
    """Runs ubench through `path`, sampling the processes that path uses and ubench itself."""
    roles = ROLES[path]
    cmd = [UB, args[0], PATHS[path], *map(str, args[1:])]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    with Sampler(roles, {"loadgen": psutil.Process(p.pid)}) as smp:
        out, err = p.communicate(timeout=timeout)
    line = (out.strip().splitlines() or ["{}"])[-1]
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        r = {"raw": out, "stderr": err[-500:]}
    r["path"] = path
    r["procs"] = smp.summary()
    results.append(r)
    pr = r["procs"]
    cpu = " ".join(f"{k}={v['cpu_avg']:.0f}%/{v['rss_peak_mb']:.0f}MB" for k, v in pr.items())
    keys = [k for k in ("gbit_s", "opened", "alive_after_hold", "conn_per_s", "lat_p50_ms", "lat_p99_ms", "setup_p99_ms", "errors") if k in r]
    print(f"[{path:7}] {args[0]} {' '.join(map(str, args[1:]))}: " + ", ".join(f"{k}={r[k]}" for k in keys) + f" | {cpu}", flush=True)
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=1)
    return r


def idle(label, secs):
    with Sampler(["client", "server", "dest", "sink"]) as smp:
        time.sleep(secs)
    r = {"test": "idle", "label": label, "secs": secs, "procs": smp.summary()}
    results.append(r)
    print(f"[idle {label}] " + " ".join(f"{k}={v['cpu_avg']:.1f}%/{v['priv_peak_mb']:.1f}MBpriv" for k, v in r["procs"].items()), flush=True)


def main():
    start("sink", [UB, "serve", SINK_IP, "9700"])
    start("dest", [BIN, "run", "-c", os.path.join(CFG, "dest.json")], cwd=CFG)
    start("server", [BIN, "run", "-c", os.path.join(CFG, "server.json")], cwd=CFG)
    start("client", [BIN, "run", "-c", os.path.join(CFG, "client.json")], cwd=CFG)
    for a in (DOWN, UP, ECHO, "127.0.0.1:9450", "127.0.0.1:9444", "127.0.0.1:1090", "127.0.0.1:1091", "127.0.0.1:1092"):
        wait_port(a)
    print(f"CPU threads: {NCPU}; cpu% below is of ONE thread (machine = {NCPU * 100}%)", flush=True)
    idle("start", 5)

    secs = 3 if QUICK else 8
    streams = [1, 8] if QUICK else [1, 8, 64]
    for path in PATHS:
        for d, tgt in (("down", DOWN), ("up", UP)):
            for n in streams:
                ub(path, "tput", tgt, d, n, secs)
    if not QUICK:
        for path in ("reality", "vision"):
            ub(path, "tput", DOWN, "down", 256, 15)
    idle("after-tput", 10)

    counts = [200] if QUICK else [1000, 5000, 10000]
    for path in ("engine", "reality", "vision"):
        for c in counts:
            ub(path, "conns", ECHO, c, 3 if QUICK else 10)
            time.sleep(2 if QUICK else 15)
    idle("after-conns", 10 if QUICK else 30)

    for path in ("base", "engine", "reality", "vision"):
        ub(path, "rate", ECHO, 64, 3 if QUICK else 10)
        time.sleep(2 if QUICK else 10)
    idle("end", 10 if QUICK else 30)


def private_mb(role):
    return round(psutil.Process(procs[role].pid).memory_info().private / 2**20, 1)


def extra():
    """Repeats for spread, a no-engine reference for connection setup, and a leak check."""
    start("sink", [UB, "serve", SINK_IP, "9700"])
    start("dest", [BIN, "run", "-c", os.path.join(CFG, "dest.json")], cwd=CFG)
    start("server", [BIN, "run", "-c", os.path.join(CFG, "server.json")], cwd=CFG)
    start("client", [BIN, "run", "-c", os.path.join(CFG, "client.json")], cwd=CFG)
    for a in (DOWN, UP, ECHO, "127.0.0.1:9450", "127.0.0.1:9444", "127.0.0.1:1090", "127.0.0.1:1091", "127.0.0.1:1092"):
        wait_port(a)
    for rep in range(3):
        for path in ("engine", "reality", "vision"):
            for d, tgt in (("down", DOWN), ("up", UP)):
                for n in (1, 8):
                    ub(path, "tput", tgt, d, n, 6)
    ub("base", "conns", ECHO, 1000, 3)
    time.sleep(10)
    for rep in range(2):
        for path in ("engine", "reality", "vision"):
            ub(path, "rate", ECHO, 64, 8)
            time.sleep(8)
    # Leak check: rounds of new connections, private memory after each round and a rest.
    leak = {"test": "leak", "rounds": []}
    for rnd in range(6):
        ub("reality", "rate", ECHO, 64, 10)
        time.sleep(15)
        row = {r: private_mb(r) for r in ("client", "server", "dest")}
        leak["rounds"].append(row)
        print(f"[leak round {rnd + 1}] private MB {row}", flush=True)
    results.append(leak)


try:
    extra() if MODE == "extra" else main()
finally:
    for p in procs.values():
        p.terminate()
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=1)
