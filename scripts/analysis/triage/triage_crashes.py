"""Groups the crash files of each fuzzer into bugs.

Replays every distinct crash file of results-<target>/out-<target>-<fuzzer>_<run>.tar.gz REPETITIONS times with
replay_crashes.py against the sanitizer build of its fuzzer. A crash file is reproducible if every replay gives the same
bug key: the sanitizer error and the top FRAMES functions of the crashing stack. Writes <out>/<fuzzer>/triage.json and
<out>/<fuzzer>/bugs/<bug>/. Rerunning resumes.

python3 triage_crashes.py <results dir> <out dir> [--fuzzers fandango] [--cpus 2-5]
"""
import argparse, collections, concurrent.futures, hashlib, json, pathlib, queue, re, shutil, signal, subprocess, tarfile
from typing import NamedTuple

REPETITIONS = 3  # replays per crash file
FRAMES = 3  # frames in the bug key, as ClusterFuzz
MEMORY = "4g"  # memory limit per container
HERE = pathlib.Path(__file__).resolve().parent
RECORD_PREFIX = "RECORD "  # as replay_crashes.py marks its records on stdout
W = "$WORKDIR"
FUZZERS = ("aflnet", "stateafl", "fandango")
ARCHIVE_NAME = re.compile(rf"out-(.+)-({'|'.join(FUZZERS)})_(\d+)\.tar\.gz")
# e.g. "ERROR: AddressSanitizer: heap-use-after-free on address 0x...", "ERROR: AddressSanitizer: SEGV on unknown address"
ERROR = re.compile(r"ERROR: \w+Sanitizer: (.+?)(?: on | at |$)", re.M)
VARIABLE_PARTS = re.compile(r"\s*(\([^)]*\)|0x[0-9a-f]+)")  # addresses and sizes, in parentheses or not
# e.g. "#1 0x61b9bf in MatroskaDemux::newDemuxedTrack(unsigned int) /src/MatroskaFile.cpp:727:56", without symbols
# "#1 0x61b9bf  (/src/testOnDemandRTSPServer+0x61b9bf)"
FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+\s+(?:in (.+) )?(\S+)$")
RUNTIME = ("__asan", "__interceptor", "__sanitizer", "__lsan", "__ubsan")  # function prefixes of the sanitizer runtime


class Target(NamedTuple):
    port: int
    transport: str
    protocol: str  # as aflnet-replay names it
    directory: str  # of the build of aflnet
    cwd: str  # {build} stands for the build directory
    command: str
    cleanup: str = ""
    before: str = ""  # shell commands before the replays
    fandango_directory: str = ""  # if Fandango does not use the build of aflnet
    settle_s: float = 0  # wait after the port is ready, e.g. for a startup scan

    def image_and_build(self, target, fuzzer):
        """The image a fuzzer runs in, as jobs.conf names it, and the directory of the sanitizer build to replay on."""
        # The stateafl builds have no sanitizer; the stateafl image also holds the build of aflnet, from the same patches
        directory = self.fandango_directory if fuzzer == "fandango" and self.fandango_directory else self.directory
        return (target if fuzzer == "aflnet" else f"{target}-{fuzzer}"), f"{W}/{directory}"


# As the run scripts of the subjects start the servers
TARGETS = {
    "lightftp": Target(2200, "tcp", "FTP", "LightFTP", "{build}/Source/Release", "./fftp fftp.conf 2200",
                       cleanup=f"{W}/ftpclean"),
    "bftpd": Target(21, "tcp", "FTP", "bftpd", "{build}", f"./bftpd -D -c {W}/basic.conf", cleanup=f"{W}/clean"),
    "proftpd": Target(21, "tcp", "FTP", "proftpd", "{build}", f"./proftpd -n -c {W}/basic.conf -X",
                      cleanup=f"{W}/clean"),
    "pure-ftpd": Target(21, "tcp", "FTP", "pure-ftpd", "{build}", "src/pure-ftpd -A", cleanup=f"{W}/clean"),
    "exim": Target(25, "tcp", "SMTP", "exim", "{build}", "exim -bd -d -oX 25 -oP /var/lock/exim.pid",
                   cleanup=f"{W}/clean", before="cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim;"),
    "dnsmasq": Target(5353, "udp", "DNS", "dnsmasq", "{build}/src", "./dnsmasq"),
    "live555": Target(8554, "tcp", "RTSP", "live555", "{build}/testProgs", "./testOnDemandRTSPServer 8554",
                      fandango_directory="live555-fandango"),
    "kamailio": Target(5060, "udp", "SIP", "kamailio", "{build}",
                       f"./src/kamailio -f {W}/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E",
                       cleanup=f"{W}/run_pjsip"),
    "openssh": Target(22, "tcp", "SSH", "openssh", "{build}", "./sshd -d -e -p 22 -r -f sshd_config"),
    "openssl": Target(4433, "tcp", "TLS", "openssl", "{build}",
                      "./apps/openssl s_server -key key.pem -cert cert.pem -4 -naccept 1 -no_anti_replay"),
    "tinydtls": Target(20220, "udp", "DTLS12", "tinydtls", W, "{build}/tests/dtls-server"),
    "dcmtk": Target(5158, "tcp", "DICOM", "dcmtk", "{build}/build/bin", "./dcmqrscp --single-process",
                    cleanup=f"{W}/clean"),
    "forked-daapd": Target(3689, "tcp", "HTTP", "forked-daapd", W,
                           f"{{build}}/src/forked-daapd -d 0 -c {W}/forked-daapd.conf -f",
                           before="sudo /etc/init.d/dbus start >/dev/null; sudo /etc/init.d/avahi-daemon start >/dev/null;",
                           fandango_directory="forked-daapd-fandango", settle_s=20),
}


def cpu_list(text):
    cpus = []
    for part in text.split(","):
        first, _, last = part.partition("-")
        cpus += range(int(first), int(last or first) + 1)
    return cpus


def extract_crashes(results, fuzzer, inputs):
    """Every run of a fuzzer as (target, run), and every crash file found as a dict with its content hash."""
    runs, crashes = [], []
    for archive in sorted(results.glob(f"results-*/out-*-{fuzzer}_*.tar.gz")):
        m = ARCHIVE_NAME.fullmatch(archive.name)
        if not m or m.group(1) not in TARGETS:
            continue
        target, run = m.group(1), int(m.group(3))
        runs.append((target, run))
        start_time, found = None, []
        with tarfile.open(archive) as tar:
            for member in filter(tarfile.TarInfo.isfile, tar):
                path = pathlib.Path(member.name)
                if path.name == "fuzzer_stats":
                    start_time = int(re.search(r"^start_time\s*:\s*(\d+)", tar.extractfile(member).read().decode(), re.M)[1])
                elif path.parent.name == "replayable-crashes" and path.name.startswith("id"):
                    content = tar.extractfile(member).read()
                    digest = hashlib.sha256(content).hexdigest()[:16]
                    (inputs / digest).write_bytes(content)
                    found.append({"target": target, "run": run, "file": path.name, "input": digest,
                                  "size": len(content), "found_at": member.mtime})
        for crash in found:
            crash["found_s"] = crash.pop("found_at") - start_time if start_time else None
        crashes += found
    return runs, crashes


def replay_chunk(target, fuzzer, names, replays, cpu, out):
    """Replays crash files in one container on one CPU and appends the records to <replays>/cpu<cpu>.jsonl."""
    config = TARGETS[target]
    image, build = config.image_and_build(target, fuzzer)
    cwd, command = config.cwd.format(build=build), config.command.format(build=build)
    (replays / f"cpu{cpu}.files").write_text("\n".join(names) + "\n")
    cleanup_option = f"--cleanup {config.cleanup}" if config.cleanup else ""
    replay = (f"python3 /triage-tool/replay_crashes.py --inputs /inputs --files /replays/cpu{cpu}.files "
              f"--cwd {cwd} --command \"{command}\" {cleanup_option} --transport {config.transport} "
              f"--protocol {config.protocol} --port {config.port} --settle-s {config.settle_s} "
              f"--repetitions {REPETITIONS}")
    # The container only reads; its records come over stdout and are written here, by the host's user
    container = subprocess.Popen(["docker", "run", "--rm", "--cpuset-cpus", str(cpu), "--memory", MEMORY,
                                  "-v", f"{HERE}:/triage-tool:ro", "-v", f"{(out / 'inputs').resolve()}:/inputs:ro",
                                  "-v", f"{replays.resolve()}:/replays:ro", image,
                                  "/bin/bash", "-c", f"cd {cwd}; {config.before} {replay}"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    last_other_line = "no output"
    with open(replays / f"cpu{cpu}.jsonl", "a") as records:
        for line in container.stdout:
            if line.startswith(RECORD_PREFIX):
                records.write(line[len(RECORD_PREFIX):])
                records.flush()
            elif line.strip():
                last_other_line = line.strip()
    if container.wait() != 0:
        print(f"WARNING {target} {fuzzer} on cpu {cpu}: container ended with {container.returncode}: {last_other_line}")


def read_replays(replays):
    """The records of the replays in a directory, by crash file and repetition."""
    records = {}
    for path in sorted(replays.glob("*.jsonl")):
        for record in map(json.loads, filter(None, path.read_text().splitlines())):
            records.setdefault((record["file"], record["repetition"]), record)
    return records


def replay_all(crashes, fuzzer, out, cpus):
    """Replays every crash file of a fuzzer not yet replayed, one container per CPU and target."""
    chunks = []
    for target in sorted({crash["target"] for crash in crashes}):
        replays = out / fuzzer / "replays" / target
        replays.mkdir(parents=True, exist_ok=True)
        records = read_replays(replays)
        missing = sorted({crash["input"] for crash in crashes if crash["target"] == target
                          and not all((crash["input"], r) in records for r in range(REPETITIONS))})
        chunks += [(target, missing[i::len(cpus)], replays) for i in range(len(cpus)) if missing[i::len(cpus)]]
    print(f"{fuzzer}: {sum(len(chunk[1]) for chunk in chunks)} crash files to replay")
    free_cpus = queue.Queue()
    for cpu in cpus:
        free_cpus.put(cpu)

    def replay_on_free_cpu(chunk):
        target, names, replays = chunk
        cpu = free_cpus.get()
        try:
            replay_chunk(target, fuzzer, names, replays, cpu, out)
        finally:
            free_cpus.put(cpu)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cpus)) as pool:
        list(pool.map(replay_on_free_cpu, chunks))


def function_name(frame_function):
    """The function of a frame without its argument list and qualifiers."""
    name = re.sub(r"\s+(const|volatile|&&|&)$", "", frame_function.strip())
    if name.endswith(")"):
        depth = 0
        for index in range(len(name) - 1, -1, -1):
            depth += {")": 1, "(": -1}.get(name[index], 0)
            if depth == 0:
                return name[:index]
    return name


def bug_key(record):
    """
    The sanitizer error and the top frames of the crashing stack, the first stack after the error; or the signal the
    server ended by if there is no report; or None if the server did not crash.
    """
    error = ERROR.search(record["report"])
    if not error:
        return f"{signal.Signals(-record['exit']).name} without report" if (record["exit"] or 0) < 0 else None
    stack = []
    for line in record["report"][error.end():].splitlines():
        frame = FRAME.match(line)
        if frame:
            stack.append(frame.groups())
        elif stack:
            break
    # Frames without a source location are in the sanitizer runtime, e.g. its interceptors of libc functions, or in
    # system libraries; they count only if no frame has one, as in a build without debug information
    located = [(function, location) for function, location in stack if function and not location.startswith("(")]
    unlocated = [(function, location) for function, location in stack if not (function or "").startswith(RUNTIME)]
    functions = [function_name(function) if function else re.sub(r"^\(.*/", "", location).rstrip(")")
                 for function, location in located or unlocated][:FRAMES]
    return " | ".join([VARIABLE_PARTS.sub("", error.group(1)).strip(), *functions])


def triage(runs, crashes, fuzzer, out):
    """Writes the bugs of a fuzzer and the crash files that did not reproduce to <out>/<fuzzer>, and prints them."""
    bugs = collections.defaultdict(list)
    unreproduced = []
    records = {target: read_replays(out / fuzzer / "replays" / target) for target in {c["target"] for c in crashes}}
    for crash in crashes:
        replays = [records[crash["target"]][(crash["input"], r)] for r in range(REPETITIONS)]
        keys = [bug_key(replay) for replay in replays]
        if keys[0] is not None and keys.count(keys[0]) == REPETITIONS:
            bugs[(crash["target"], keys[0])].append({**crash, "report": replays[0]["report"]})
        else:
            unreproduced.append({**crash, "replays": "flaky" if any(keys) else "no crash"})
    shutil.rmtree(out / fuzzer / "bugs", ignore_errors=True)
    (out / fuzzer).mkdir(exist_ok=True)
    result = []
    print(f"\n{fuzzer}: {len(crashes)} crash files, {len({c['input'] for c in crashes})} distinct, {len(bugs)} bugs")
    for (target, key), found in sorted(bugs.items()):
        bug_id = hashlib.sha1(f"{target} | {key}".encode()).hexdigest()[:8]
        smallest = min(found, key=lambda crash: (crash["size"], crash["input"]))
        directory = out / fuzzer / "bugs" / bug_id
        directory.mkdir(parents=True)
        shutil.copy(out / "inputs" / smallest["input"], directory / "smallest-crash")
        (directory / "report.txt").write_text(smallest.pop("report"))
        times = [crash["found_s"] for crash in found if crash["found_s"] is not None]
        error, *functions = key.split(" | ")
        bug = {"bug": bug_id, "target": target, "error": error, "frames": functions, "crash_files": len(found),
               "runs": sorted({crash["run"] for crash in found}), "runs_total": sum(t == target for t, _ in runs),
               "first_found_s": min(times, default=None), "smallest_crash": smallest}
        result.append(bug)
        first = f"{bug['first_found_s'] // 3600}h{bug['first_found_s'] % 3600 // 60:02}m" if times else "?"
        print(f"  {bug_id}  {target}  {error}: {len(found)} crash files in {len(bug['runs'])}/{bug['runs_total']} "
              f"runs, first after {first}")
        for function in functions:
            print(f"      in {function}")
    for crash in unreproduced:
        print(f"  not reproduced ({crash['replays']}): {crash['target']} run {crash['run']} {crash['file']}")
    (out / fuzzer / "triage.json").write_text(json.dumps({"bugs": result, "unreproduced": unreproduced}, indent=2) + "\n")


parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("results", type=pathlib.Path, help="directory with the results-<target> directories")
parser.add_argument("out", type=pathlib.Path, help="output directory; rerunning resumes from it")
parser.add_argument("--fuzzers", nargs="*", default=list(FUZZERS), choices=FUZZERS)
parser.add_argument("--cpus", default="0-3", help="CPUs for the containers, one container each, as taskset -c")
args = parser.parse_args()
(args.out / "inputs").mkdir(parents=True, exist_ok=True)
for fuzzer in args.fuzzers:
    runs, crashes = extract_crashes(args.results, fuzzer, args.out / "inputs")
    if not runs:
        continue
    replay_all(crashes, fuzzer, args.out, cpu_list(args.cpus))
    triage(runs, crashes, fuzzer, args.out)
