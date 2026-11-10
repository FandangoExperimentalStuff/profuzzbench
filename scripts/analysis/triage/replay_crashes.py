"""Replays crash files, each against a freshly started server, and prints one record per replay.

A record holds the file, the repetition, the exit status of the server (None if it still ran) and the sanitizer
report ("" if there is none).
"""
import argparse, glob, json, os, pathlib, signal, subprocess, time

RECORD_PREFIX = "RECORD "
ASAN_LOG = "/tmp/asan"
READY_S = 30  # longest wait for the server port
REPLAY_TIMEOUT_S = 60  # longest time of one replay
EXIT_WAIT_S = 3  # wait this long after a replay for the server to end


def port_ready(transport, port):
    tables, state = ((("/proc/net/udp", "/proc/net/udp6"), "07") if transport == "udp"
                     else (("/proc/net/tcp", "/proc/net/tcp6"), "0A"))
    for table in tables:
        try:
            rows = open(table).read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if int(fields[1].rsplit(":", 1)[1], 16) == port and fields[3] == state:
                return True
    return False


def replay(path, repetition):
    for log in glob.glob(ASAN_LOG + ".*"):
        os.remove(log)
    if args.cleanup:
        subprocess.run(args.cleanup, shell=True, capture_output=True)
    # handle_abort and handle_sigill give aborts, e.g. of failed assertions, and illegal instructions a report
    options = os.environ.get("ASAN_OPTIONS", "") + f":symbolize=1:handle_abort=1:handle_sigill=1:log_path={ASAN_LOG}"
    # exec makes the exit status of the shell that of the server, negative if a signal ended it
    server = subprocess.Popen(f"exec {args.command}", shell=True, cwd=args.cwd,
                              env=dict(os.environ, ASAN_OPTIONS=options), start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ready_by = time.monotonic() + READY_S
    while not port_ready(args.transport, args.port) and time.monotonic() < ready_by:
        time.sleep(0.01)
    time.sleep(args.settle_s)
    try:
        subprocess.run(["aflnet-replay", str(path), args.protocol, str(args.port), "1"], cwd=args.cwd,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=REPLAY_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        pass
    try:
        server.wait(timeout=EXIT_WAIT_S)
    except subprocess.TimeoutExpired:
        pass
    exit_status = server.poll()
    try:
        os.killpg(server.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    server.wait()
    report = "".join(open(log, errors="replace").read() for log in sorted(glob.glob(ASAN_LOG + ".*")))
    return {"file": path.name, "repetition": repetition, "exit": exit_status, "report": report}


parser = argparse.ArgumentParser()
parser.add_argument("--inputs", required=True, help="directory of crash files in the replay format")
parser.add_argument("--files", required=True, help="file with the names of the crash files to replay, one per line")
parser.add_argument("--command", required=True, help="command line of the server build")
parser.add_argument("--cwd", required=True)
parser.add_argument("--cleanup", default=None, help="shell command run before every replay")
parser.add_argument("--transport", default="tcp", choices=["tcp", "udp"])
parser.add_argument("--protocol", required=True, help="protocol name of aflnet-replay")
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--settle-s", type=float, default=0.0, help="wait after the port is ready, e.g. for a startup scan")
parser.add_argument("--repetitions", type=int, required=True)
args = parser.parse_args()
for name in pathlib.Path(args.files).read_text().split():
    for repetition in range(args.repetitions):
        print(RECORD_PREFIX + json.dumps(replay(pathlib.Path(args.inputs) / name, repetition)), flush=True)
