"""
Replays the hang files of one run against the fuzzing build of the server and classifies each one.

Classes:
 - busy:    the server computes for at least --busy-cpu-s without answering      -> a real hang
 - memory:  the server is killed for its memory (SIGKILL before the replay ends) -> a real hang
 - slow:    one answer takes at least --slow-s                                   -> a real hang
 - fast:    every answer comes quickly; only the sum of the session exceeded -t  -> no hang
 - silent:  the server is idle and does not answer any more from some message on -> no hang
 - closed:  the server ends the session itself                                   -> no hang
 - crashed: the server ends by a signal, e.g. an ASAN abort                      -> no hang, a crash
"""
import argparse, json, os, pathlib, select, signal, socket, struct, subprocess, time

LENGTH = struct.Struct("=I")
TICK_S = 1 / os.sysconf("SC_CLK_TCK")
RECORD_PREFIX = "RECORD "
OOM_KILLED = (-signal.SIGKILL, 128 + signal.SIGKILL)  # the server itself, or the shell that started it
REPLY_END_S = 0.1  # an answer ends after this long without further bytes


class FileCapReached(Exception):
    pass


def raise_file_cap(signum, frame):
    raise FileCapReached


def messages_of(data):
    messages, offset = [], 0
    while offset + 4 <= len(data):
        (length,) = LENGTH.unpack_from(data, offset)
        messages.append(data[offset + 4:offset + 4 + length])
        offset += 4 + length
    return messages


def server_cpu_s(pgid):
    total = 0.0
    for stat in pathlib.Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat.read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        if int(fields[2]) == pgid:
            total += (int(fields[11]) + int(fields[12])) * TICK_S
    return total


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


def await_answer(sock, server, wait_s):
    """Seconds until the first byte of an answer, or None, 'busy' or 'closed'."""
    cpu_before = server_cpu_s(server.pid)
    sent_at = time.monotonic()
    first = None
    while True:
        now = time.monotonic()
        timeout = REPLY_END_S if first is not None else sent_at + wait_s - now
        if first is None and timeout <= 0:
            return "busy" if server_cpu_s(server.pid) - cpu_before >= args.busy_cpu_s else None
        ready, _, _ = select.select([sock], [], [], timeout)
        if not ready:
            if first is not None:
                return first
            continue
        try:
            chunk = sock.recv(65536)
        except OSError:
            chunk = b""
        if not chunk:
            return first if first is not None else "closed"
        if first is None:
            first = time.monotonic() - sent_at


def classify(path):
    messages = messages_of(path.read_bytes())
    if args.cleanup:
        subprocess.run(args.cleanup, shell=True, capture_output=True)
    server = subprocess.Popen(args.command, shell=True, cwd=args.cwd, start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ready_by = time.monotonic() + args.ready_s
    while not port_ready(args.transport, args.port) and time.monotonic() < ready_by:
        time.sleep(0.01)
    time.sleep(args.settle_s)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if args.transport == "udp" else socket.SOCK_STREAM)
    if args.local_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.local_port))
    record = {"file": path.name, "messages": len(messages), "answers": [], "end": "replayed"}
    started = time.monotonic()
    signal.signal(signal.SIGALRM, raise_file_cap)
    signal.alarm(int(args.file_cap_s + len(messages) * args.wait_s))
    try:
        sock.connect(("127.0.0.1", args.port))
        sock.setblocking(False)
        await_answer(sock, server, 0.5)  # a greeting, if the server sends one
        for message in messages:
            if server.poll() is not None:
                record["end"] = "exited"
                break
            try:
                sock.send(message)
            except OSError:
                record["end"] = "closed"
                break
            answer = await_answer(sock, server, args.wait_s)
            record["answers"].append(answer)
            if answer == "closed":
                record["end"] = answer
                break
    except FileCapReached:
        record["end"] = "file_cap"
    finally:
        signal.alarm(0)
        record["duration_s"] = round(time.monotonic() - started, 2)
        record["server_cpu_s"] = round(server_cpu_s(server.pid), 2)
        exit_status = server.poll()
        alive = exit_status is None
        record["server_exit"] = exit_status
        try:
            os.killpg(server.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        sock.close()
    latencies = [a for a in record["answers"] if isinstance(a, float)]
    answered = [isinstance(a, float) for a in record["answers"]]
    last_answered = max((i for i, a in enumerate(answered) if a), default=-1)
    # busy only if the server never answers again after computing without an answer
    busy_for_good = "busy" in record["answers"][last_answered + 1:]
    if busy_for_good or (record["end"] == "file_cap" and record["server_cpu_s"] >= args.busy_cpu_s):
        record["class"] = "busy"
    elif latencies and max(latencies) >= args.slow_s:
        record["class"] = "slow"
    elif exit_status in OOM_KILLED:
        # Only the out-of-memory killer sends SIGKILL while the replay runs; this script sends it afterwards
        record["class"] = "memory"
    elif exit_status is not None and (exit_status < 0 or exit_status > 128):
        record["class"] = "crashed"
    elif record["end"] in ("closed", "exited"):
        record["class"] = "closed"
    elif alive and len(answered) - (last_answered + 1) >= 2:
        record["class"] = "silent"
        record["silent_after"] = messages[last_answered + 1][:80].decode("latin-1") if last_answered + 1 < len(messages) else ""
    else:
        record["class"] = "fast"
    record["max_answer_s"] = round(max(latencies), 3) if latencies else None
    record["answers"] = [round(a, 3) if isinstance(a, float) else a for a in record["answers"]]
    return record


parser = argparse.ArgumentParser()
parser.add_argument("--hangs", required=True, help="directory of hang files in the replay format")
parser.add_argument("--done", default=None, help="JSON lines of hang files already classified, which are skipped")
parser.add_argument("--command", required=True, help="command line of the fuzzing build of the server")
parser.add_argument("--cwd", required=True)
parser.add_argument("--cleanup", default=None, help="shell command run before every hang file")
parser.add_argument("--transport", default="tcp", choices=["tcp", "udp"])
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--local-port", type=int, default=None, help="local port to send from, for servers that reply to a fixed port")
parser.add_argument("--ready-s", type=float, default=30.0, help="longest wait for the server port")
parser.add_argument("--settle-s", type=float, default=0.0, help="wait after the port is ready, e.g. for a startup scan")
parser.add_argument("--wait-s", type=float, default=6.0, help="wait this long for each answer; must exceed --slow-s")
parser.add_argument("--slow-s", type=float, default=5.0, help="an answer this late is a real hang, like TEST_TIMEOUT")
parser.add_argument("--busy-cpu-s", type=float, default=5.0, help="CPU time without answering that is a real hang")
parser.add_argument("--file-cap-s", type=float, default=60.0, help="plus --wait-s per message: longest time per hang file")
args = parser.parse_args()
done = set()
if args.done and os.path.exists(args.done):
    done = {json.loads(line)["file"] for line in open(args.done) if line.strip()}
for path in sorted(pathlib.Path(args.hangs).iterdir()):
    if path.name not in done:
        print(RECORD_PREFIX + json.dumps(classify(path)), flush=True)
