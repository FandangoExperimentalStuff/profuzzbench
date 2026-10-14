"""Checks for every hang reported whether the server really hangs.

Takes the results directory of a campaign (results-<target>/out-<target>-<fuzzer>_<run>.tar.gz), replays the hang
files of every run against the fuzzing build in the base image of the target with classify_hangs.py, and prints
how many hangs are real per target and fuzzer. Needs the base images (e.g. 'lightftp'). Rerunning resumes.

python3 check_hangs.py <results dir> <out dir> [--jobs 12] [--cpus 0-11,24-35] [--sample 0] [--targets ...]
"""
import argparse, collections, concurrent.futures, csv, json, pathlib, re, subprocess, tarfile
from typing import NamedTuple

HERE = pathlib.Path(__file__).resolve().parent
RECORD_PREFIX = "RECORD "  # as classify_hangs.py marks its records on stdout
W = "$WORKDIR"
DAAPD_DAEMONS = "sudo /etc/init.d/dbus start >/dev/null; sudo /etc/init.d/avahi-daemon start >/dev/null;"


class Target(NamedTuple):
    port: int
    transport: str
    cwd: str
    command: str
    cleanup: str = ""
    options: str = ""  # further options of classify_hangs.py
    before: str = ""   # shell commands before the server starts


TARGETS = {
    "lightftp": Target(2200, "tcp", f"{W}/LightFTP/Source/Release", "./fftp fftp.conf 2200", cleanup=f"{W}/ftpclean"),
    "bftpd": Target(21, "tcp", f"{W}/bftpd", f"./bftpd -D -c {W}/basic.conf", cleanup=f"{W}/clean"),
    "proftpd": Target(21, "tcp", f"{W}/proftpd", f"./proftpd -n -c {W}/basic.conf -X", cleanup=f"{W}/clean"),
    "pure-ftpd": Target(21, "tcp", f"{W}/pure-ftpd", "src/pure-ftpd -A", cleanup=f"{W}/clean"),
    "exim": Target(25, "tcp", f"{W}/exim", "exim -bd -d -oX 25 -oP /var/lock/exim.pid", cleanup=f"{W}/clean",
                   before=f"cp {W}/exim/src/build-Linux-x86_64/exim /usr/exim/bin/exim;"),
    "dnsmasq": Target(5353, "udp", f"{W}/dnsmasq/src", "./dnsmasq"),
    "live555": Target(8554, "tcp", f"{W}/live555/testProgs", "./testOnDemandRTSPServer 8554"),
    "kamailio": Target(5060, "udp", f"{W}/kamailio",
                       f"KAMAILIO_MODULES=src/modules KAMAILIO_RUNTIME_DIR=runtime_dir ./src/kamailio "
                       f"-f {W}/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E",
                       cleanup=f"{W}/run_pjsip", options="--local-port 5061"),
    "openssh": Target(22, "tcp", f"{W}/openssh", "./sshd -d -e -p 22 -r -f sshd_config"),
    "openssl": Target(4433, "tcp", f"{W}/openssl",
                      "./apps/openssl s_server -key key.pem -cert cert.pem -4 -naccept 1 -no_anti_replay"),
    "tinydtls": Target(20220, "udp", W, "./tinydtls/tests/dtls-server"),
    "dcmtk": Target(5158, "tcp", f"{W}/dcmtk/build/bin", "./dcmqrscp --single-process", cleanup=f"{W}/clean"),
    "forked-daapd": Target(3689, "tcp", W, f"{W}/forked-daapd/src/forked-daapd -d 0 -c {W}/forked-daapd.conf -f",
                           options="--settle-s 20", before=DAAPD_DAEMONS),
}
REAL = ("busy", "slow")
CLASSES = ("busy", "slow", "fast", "silent", "closed", "crashed")


def cpu_list(text):
    cpus = []
    for part in text.split(","):
        first, _, last = part.partition("-")
        cpus += range(int(first), int(last or first) + 1)
    return cpus


def extract_hangs(results, work, sample, targets):
    """Hang files per run, as (target, fuzzer, run, directory)."""
    runs = []
    for archive in sorted(results.glob("results-*/out-*.tar.gz")):
        m = re.match(r"out-(.+)-(aflnet|stateafl)_(\d+)\.tar\.gz", archive.name)
        if not m or m.group(1) not in targets:
            continue
        directory = work / f"{m.group(1)}-{m.group(2)}_{m.group(3)}"
        if not directory.exists():
            with tarfile.open(archive) as tar:
                members = [x for x in tar if x.isfile() and "/replayable-hangs/id" in x.name]
                if not members:
                    continue
                directory.mkdir(parents=True)
                for member in members[:sample or None]:
                    (directory / pathlib.Path(member.name).name).write_bytes(tar.extractfile(member).read())
        if any(directory.iterdir()):
            runs.append((m.group(1), m.group(2), int(m.group(3)), directory))
    return runs


def check_run(run, out, cpu, wait_s, slow_s):
    target, fuzzer, number, directory = run
    config = TARGETS[target]
    cleanup_option = f"--cleanup {config.cleanup}" if config.cleanup else ""
    result = out / f"{directory.name}.jsonl"
    classify = (f"python3 /hangs-tool/classify_hangs.py --hangs /hangs --done /out/{result.name} "
                f"--cwd {config.cwd} --command \"{config.command}\" {cleanup_option} --transport {config.transport} "
                f"--port {config.port} --wait-s {wait_s} --slow-s {slow_s} {config.options}")
    # The container only reads /out; its records come over stdout and are written here, by the host's user
    container = subprocess.Popen(["docker", "run", "--rm", "--cpuset-cpus", str(cpu), "-v", f"{HERE}:/hangs-tool:ro",
                                  "-v", f"{directory.resolve()}:/hangs:ro", "-v", f"{out.resolve()}:/out:ro", target,
                                  "/bin/bash", "-c", config.before + classify],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    last_other_line = "no output"
    with open(result, "a") as records:
        for line in container.stdout:
            if line.startswith(RECORD_PREFIX):
                records.write(line[len(RECORD_PREFIX):])
                records.flush()
            elif line.strip():
                last_other_line = line.strip()
    if container.wait() != 0:
        error = last_other_line
        print(f"WARNING {directory.name}: container ended with {container.returncode}: {error}", flush=True)
    return run


def summarize(runs, out):
    counts = collections.defaultdict(collections.Counter)
    rows = []
    for target, fuzzer, number, directory in runs:
        result = out / f"{directory.name}.jsonl"
        records = [json.loads(line) for line in result.read_text().splitlines() if line] if result.exists() else []
        run_counts = collections.Counter(record["class"] for record in records)
        counts[(target, fuzzer)].update(run_counts)
        rows.append({"target": target, "fuzzer": fuzzer, "run": number, "hangs": len(records),
                     **{c: run_counts.get(c, 0) for c in CLASSES}})
    with open(out / "summary.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["target", "fuzzer", "run", "hangs", *CLASSES])
        writer.writeheader()
        writer.writerows(rows)
    print(f"{'target':13} {'fuzzer':9} {'hangs':>6} {'real':>6}  " + " ".join(f"{c:>6}" for c in CLASSES))
    for (target, fuzzer), c in sorted(counts.items()):
        total = sum(c.values())
        print(f"{target:13} {fuzzer:9} {total:6} {sum(c[r] for r in REAL):6}  " + " ".join(f"{c[k]:6}" for k in CLASSES))
    print("real = busy (the server computes without answering) + slow (one answer takes at least --slow-s)")


parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("results", type=pathlib.Path, help="directory with the results-<target> directories")
parser.add_argument("out", type=pathlib.Path, help="output directory; rerunning resumes from it")
parser.add_argument("--targets", nargs="*", default=list(TARGETS), choices=list(TARGETS))
parser.add_argument("--jobs", type=int, default=12, help="containers at the same time, one CPU each")
parser.add_argument("--cpus", default="0-11", help="CPUs for the containers, as taskset -c")
parser.add_argument("--sample", type=int, default=0, help="at most this many hang files per run; 0 for all")
parser.add_argument("--wait-s", type=float, default=6.0, help="wait this long for each answer; must exceed --slow-s")
parser.add_argument("--slow-s", type=float, default=5.0, help="an answer this late is a real hang, like TEST_TIMEOUT")
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
runs = extract_hangs(args.results, args.out / "hangs", args.sample, args.targets)
cpus = cpu_list(args.cpus)
print(f"{len(runs)} runs with hangs, {sum(len(list(r[3].iterdir())) for r in runs)} hang files")
with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(cpus))) as pool:
    free_cpus = list(cpus)
    pending = {}
    for run in runs:
        if len(pending) >= min(args.jobs, len(cpus)):
            done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                free_cpus.append(pending.pop(future))
                print(f"done {future.result()[3].name}", flush=True)
        cpu = free_cpus.pop(0)
        pending[pool.submit(check_run, run, args.out, cpu, args.wait_s, args.slow_s)] = cpu
    for future in concurrent.futures.as_completed(pending):
        print(f"done {future.result()[3].name}", flush=True)
summarize(runs, args.out)