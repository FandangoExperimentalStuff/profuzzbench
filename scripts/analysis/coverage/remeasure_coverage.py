"""
Measures the coverage of finished fuzzing runs again with the current cov_script of each target.

Takes the results directory of a campaign (results-<target>/out-<target>-<fuzzer>_<run>.tar.gz), replays the
replayable-queue of every run in the base image of its target, as run.sh does after fuzzing, and writes a new
cov_over_time.csv per run. Docker base images need to be compiled. Rerunning resumes.

python3 remeasure_coverage.py <results dir> <out dir> [--jobs 12] [--cpus 0-11] [--targets ...] [--fuzzers ...]
"""
import argparse, concurrent.futures, pathlib, re, subprocess, tarfile
from typing import NamedTuple

W = "$WORKDIR"


class Target(NamedTuple):
    """Where run.sh measures the coverage of a target."""
    port: int
    gcov_dir: str
    before: str = ""  # shell commands before cov_script


TARGETS = {
    "lightftp": Target(2200, f"{W}/LightFTP-gcov/Source/Release"),
    "bftpd": Target(21, f"{W}/bftpd-gcov"),
    "proftpd": Target(21, f"{W}/proftpd-gcov"),
    "pure-ftpd": Target(21, f"{W}/pure-ftpd-gcov"),
    "exim": Target(25, f"{W}/exim-gcov", before=f"cp {W}/exim-gcov/src/build-Linux-x86_64/exim /usr/exim/bin/exim;"),
    "dnsmasq": Target(5353, f"{W}/dnsmasq-gcov/src"),
    "live555": Target(8554, f"{W}/live555-cov/testProgs"),
    "kamailio": Target(5060, W),
    "openssh": Target(22, f"{W}/openssh-gcov"),
    "openssl": Target(4433, f"{W}/openssl-gcov"),
    "tinydtls": Target(20220, W),
    "dcmtk": Target(5158, f"{W}/dcmtk-gcov/build/bin"),
    "forked-daapd": Target(3689, W, before="sudo /etc/init.d/dbus start >/dev/null; "
                                          "sudo /etc/init.d/avahi-daemon start >/dev/null;"),
}


class Run(NamedTuple):
    target: str
    fuzzer: str
    number: int
    archive: pathlib.Path

    @property
    def name(self) -> str:
        return f"{self.target}-{self.fuzzer}_{self.number}"


def cpu_list(text):
    cpus = []
    for part in text.split(","):
        first, _, last = part.partition("-")
        cpus += range(int(first), int(last or first) + 1)
    return cpus


def finished_runs(results, targets, fuzzers):
    runs = []
    for archive in sorted(results.glob("results-*/out-*.tar.gz")):
        m = re.match(r"out-(.+)-(aflnet|stateafl|aflnwe)_(\d+)\.tar\.gz", archive.name)
        if m and m.group(1) in targets and m.group(2) in fuzzers:
            runs.append(Run(m.group(1), m.group(2), int(m.group(3)), archive))
    return runs


def unpack_queue(run, work):
    """The replayable-queue of a run, with the file times the fuzzer gave them."""
    directory = work / run.name
    if not (directory / "replayable-queue").is_dir():
        with tarfile.open(run.archive) as tar:
            members = [m for m in tar if m.isfile() and "/replayable-queue/" in m.name]
            for member in members:
                member.name = "replayable-queue/" + pathlib.Path(member.name).name
            tar.extractall(directory, members)
    return directory


def remeasure(run, work, out, cpu, skipcount):
    csv = out / f"{run.name}.csv"
    if csv.exists():
        return run, "already measured"
    directory = unpack_queue(run, work).resolve()
    config = TARGETS[run.target]
    measure = (f"{config.before} cd {config.gcov_dir} && "
               f"cov_script /queue/ {config.port} {skipcount} /out/{run.name}.csv.part 1 > /dev/null 2>&1")
    completed = subprocess.run(["docker", "run", "--rm", "--cpuset-cpus", str(cpu), "-v", f"{directory}:/queue",
                                "-v", f"{out.resolve()}:/out", run.target, "/bin/bash", "-c", measure],
                               capture_output=True, text=True)
    part = out / f"{run.name}.csv.part"
    if completed.returncode != 0 or not part.exists() or len(part.read_text().splitlines()) < 2:
        error = (completed.stderr.strip().splitlines() or ["no output"])[-1]
        return run, f"FAILED (exit {completed.returncode}): {error}"
    part.replace(csv)
    return run, f"{len(csv.read_text().splitlines()) - 1} rows"


parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("results", type=pathlib.Path, help="directory with the results-<target> directories")
parser.add_argument("out", type=pathlib.Path, help="output directory; rerunning resumes from it")
parser.add_argument("--targets", nargs="*", default=list(TARGETS), choices=list(TARGETS))
parser.add_argument("--fuzzers", nargs="*", default=["aflnet", "stateafl"], choices=["aflnet", "stateafl", "aflnwe"])
parser.add_argument("--jobs", type=int, default=12, help="containers at the same time, one CPU each")
parser.add_argument("--cpus", default="0-11", help="CPUs for the containers, as taskset -c")
parser.add_argument("--skipcount", type=int, default=5, help="run gcovr after every this many test cases, as SKIPCOUNT")
args = parser.parse_args()
(args.out / "csv").mkdir(parents=True, exist_ok=True)
runs = finished_runs(args.results, args.targets, args.fuzzers)
cpus = cpu_list(args.cpus)[:args.jobs]
print(f"{len(runs)} runs on CPUs {cpus}", flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=len(cpus)) as pool:
    free_cpus, pending = list(cpus), {}

    def report(done):
        for future in done:
            free_cpus.append(pending.pop(future))
            run, outcome = future.result()
            print(f"{run.name}: {outcome}", flush=True)

    for run in runs:
        if len(pending) >= len(cpus):
            report(concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)[0])
        cpu = free_cpus.pop(0)
        pending[pool.submit(remeasure, run, args.out / "queues", args.out / "csv", cpu, args.skipcount)] = cpu
    report(concurrent.futures.wait(pending)[0])
