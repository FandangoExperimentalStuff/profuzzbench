# Real Time Streaming Protocol (RTSP 1.0, RFC 2326 and its erratum), testing servers over a TCP control connection.
# The HTTP syntax RTSP imports comes from RFC 9110/9112, the URI syntax from RFC 3986.
# Fandango is the Client; the Server is the implementation under test.
# Section numbers in the comments are those of RFC 2326 unless another RFC is named.

# ============================================================================================
# Test setup: everything the test setup decides is read here, from the environment, with defaults.
# ============================================================================================
import os
import re
import random
import base64
import threading

# host[:port] of the server as it appears in request URLs
RTSP_AUTHORITY = os.environ.get("RTSP_AUTHORITY", "127.0.0.1")
# Presentation paths the server setup offers; each session picks from them
RTSP_TARGETS = [t for t in os.environ.get("RTSP_TARGETS", "/test").split(",") if t]
# Stream control paths (appended to the presentation path) the server setup offers
RTSP_CONTROLS = [t for t in os.environ.get("RTSP_CONTROLS", "/trackID=0").split(",") if t]
# Paths the server setup accepts for publishing with ANNOUNCE and RECORD
RTSP_PUBLISH_TARGETS = [t for t in os.environ.get("RTSP_PUBLISH_TARGETS", "/publish").split(",") if t]
# Credentials that the accepting exchange sends; the refusing exchange sends other values
RTSP_USER = os.environ.get("RTSP_USER", "user")
RTSP_PASSWORD = os.environ.get("RTSP_PASSWORD", "pass")
# Comma-separated names of the deviations of the server under test that the grammar tolerates
TOLERATED = os.environ.get("TOLERATED", "")
# Seconds Fandango waits for the reply to a queued PLAY (10.5): the server may hold it back until the running PLAY has ended
RTSP_WAIT = os.environ.get("RTSP_WAIT", "6.0")
# Seconds Fandango waits for the reply to a request (9.2: the server may leave it unanswered, and the sender may resend after a timeout)
RTSP_REPLY_WAIT = os.environ.get("RTSP_REPLY_WAIT", "1.5")
# Seconds Fandango waits for the server to close the connection after a request with Connection: close (the server may keep it open)
RTSP_CLOSE_WAIT = os.environ.get("RTSP_CLOSE_WAIT", "1.0")
# Interleaved frames the Client party hands to Fandango per session; the media payload is not carried (RFC 3550)
RTSP_FRAME_LIMIT = int(os.environ.get("RTSP_FRAME_LIMIT", "2"))


def reply_wait(longest):  # the longest wait of a timer, see the setup block
    """How long Fandango waits for a reply: 2/3 of the longest wait up to all of it. Fandango's packet filter holds back a packet that is identical to one already sent for seconds
    when it adds no coverage, so the start of the timer varies in the milliseconds instead of repeating one string."""
    longest = float(longest)
    return str(round(random.uniform(longest * 2 / 3, longest), 3))


def tolerated(name):
    return name in [n.strip() for n in TOLERATED.split(",") if n.strip()]


# ============================================================================================
# What earlier messages of the session name, for the requests that follow (recording and recalling).
# ============================================================================================
MEMORY = {}


def reset_memory():
    MEMORY.clear()
    MEMORY["cseq"] = 0
    MEMORY["session"] = None
    MEMORY["base"] = None
    MEMORY["location"] = None
    MEMORY["request_url"] = None
    MEMORY["message_url"] = None
    MEMORY["controls"] = []
    MEMORY["aggregate"] = None
    MEMORY["etag"] = None
    MEMORY["frames"] = 0
    MEMORY["target"] = random.choice(RTSP_TARGETS)
    MEMORY["publish"] = random.choice(RTSP_PUBLISH_TARGETS)


reset_memory()


def record_session(value):
    MEMORY["session"] = str(value)
    return str(value)


def record_cseq(value):
    try:
        MEMORY["cseq"] = int(str(value))
    except ValueError:
        pass
    return str(value)


def record_base(value):
    MEMORY["base"] = str(value)
    return str(value)


def record_location(value):
    MEMORY["location"] = str(value)
    return str(value)


def message_base(piece):
    """Content-Base and Content-Location of one message, read from its header block as it arrives: they belong to that message and to no other (C.1.1)."""
    head = bytes(piece).split(b"\r\n\r\n", 1)[0].decode("latin-1")
    found = {}
    for line in re.sub(r"\r\n[ \t]+", " ", head).split("\r\n")[1:]:
        key, _, value = line.partition(":")
        if key.strip().lower() in ("content-base", "content-location"):
            found[key.strip().lower()] = value.strip()
    return found.get("content-base"), found.get("content-location")


def message_url(piece):
    """The request URL of one message (C.1.1, third place): the URL of the request line of a request, of the request a reply answers otherwise."""
    line = bytes(piece)[:300].split(b"\r\n", 1)[0].decode("latin-1")
    if line.startswith("RTSP/"):
        return MEMORY.get("request_url")
    parts = line.split(" ")
    return parts[1] if len(parts) == 3 and parts[1] != "*" else None


def reset_description(value):
    """A new description: its controls, aggregate control and entity tag start afresh, and its presentation URL is the base of the message that carries it."""
    MEMORY["controls"] = []
    MEMORY["description_base"] = resolve_control("*")
    MEMORY["aggregate"] = None
    MEMORY["etag"] = None
    return str(value)


def record_aggregate(value):
    MEMORY["aggregate"] = resolve_control(str(value))
    return str(value)


def record_etag(value):
    MEMORY["etag"] = str(value)
    return str(value)


def recall_etag():
    return MEMORY.get("etag") or "".join(random.choice("abcdef0123456789") for _ in range(8))


def record_control(value):
    MEMORY["controls"].append(resolve_control(str(value)))
    return str(value)


def next_cseq():
    return str(MEMORY["cseq"] + 1)


def session_count():
    return 1 if MEMORY["session"] else 0


def recall_session():
    return MEMORY["session"] or "".join(random.choice("0123456789ABCDEF") for _ in range(8))


def url_path(url):
    m = re.match(r"(?i)^[a-z][a-z0-9+.-]*://[^/]*(/.*)?$", url)
    return (m.group(1) or "/") if m else None


def absolute_url(url):
    return url if "://" in url else "rtsp://" + RTSP_AUTHORITY + url


def resolve_control(control):
    """The abs_path a control URL of a presentation description names, resolved as RFC 1808 does against the base (Appendix C.1.1:
    Content-Base, else Content-Location, else the request URL); "*" inherits the entire base URL. A Content-Base or Content-Location that is a
    relative reference (RFC 9110 8.7 allows a partial URI) is first resolved against the request URL of the message."""
    from urllib.parse import urljoin
    request_url = absolute_url(MEMORY.get("message_url") or MEMORY["target"])
    base_url = urljoin(request_url, MEMORY["base"] or MEMORY["location"] or request_url)
    if control == "*":
        return url_path(base_url)
    return url_path(urljoin(base_url, control))


def recall_setup_path():
    controls = MEMORY["controls"]
    if controls:
        return random.choice(controls)
    return MEMORY["target"] + random.choice(RTSP_CONTROLS)


def recall_presentation_path():
    """The aggregate control URL of the description, else the base it names, else the target (C.1.1)."""
    if MEMORY.get("aggregate"):
        return MEMORY["aggregate"]
    return MEMORY.get("description_base") or MEMORY["target"]


def recall_cseq():
    return str(MEMORY.get("cseq", 0))


def publish_default_path():
    return MEMORY["publish"] + "/streamid=0"


def ext_method():
    return random.choice(["XTEST", "X-PING", "FOOBAR", "DUMMY_OP"])


def basic_credentials(user, password):
    return base64.b64encode((user + ":" + password).encode()).decode()


def pick_target():
    return MEMORY["target"]


def pick_publish_target():
    return MEMORY["publish"]


def pick_control():
    return random.choice(RTSP_CONTROLS)


def clen(headers):
    m = re.search(r"(?im)^content-length:[ \t]*([0-9]+)", str(headers))
    return int(m.group(1)) if m else 0


def prefix_pattern(literal):
    """A regex for the prefixes of `literal` (the bytes of a message start that have arrived so far)."""
    out = ""
    for char in reversed(literal):
        out = "(?:" + re.escape(char) + out + ")?"
    return out


STATUS_LINE_START = re.compile(rb"RTSP/[0-9]+\.[0-9]+ [0-9]{3} ")
REQUEST_LINE = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^ \r\n]+ RTSP/[0-9]+\.[0-9]+\r\n")
REQUEST_LINE_PREFIX = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+(?: (?:[^ \r\n]+(?: " + prefix_pattern("RTSP/").encode() + rb"(?:[0-9]+(?:\.[0-9]*)?)?)?)?)?\r?")
STATUS_LINE_PREFIX = re.compile(prefix_pattern("RTSP/").encode() + rb"(?:[0-9]+(?:\.[0-9]*)?(?: [0-9]{0,3})?)?")


def starts_message(buffer):
    """Whether `buffer` is, or may still become, the start of an RTSP message (a status line or a request line, 7, 6): False for bytes that no message begins with."""
    if buffer[:1] == b"$":
        return True
    line = buffer.split(b"\r\n", 1)[0] + (b"\r\n" if b"\r\n" in buffer else b"")
    if line.endswith(b"\r\n"):
        return bool(STATUS_LINE_START.match(line) or REQUEST_LINE.fullmatch(line))
    if len(line) > 4000:
        return False
    return bool(STATUS_LINE_START.match(line) or STATUS_LINE_PREFIX.fullmatch(line) or REQUEST_LINE_PREFIX.fullmatch(line))


def split_stream(buffer, state):
    """Cuts the bytes of the control connection into RTSP messages and interleaved frames (Section 10.12). Bytes that no message begins with are the payload of a
    message that has no Content-Length (4.4 rule 2: length zero; 9.2: a payload needs the header): they are handed over behind a marker, as a piece no rule derives."""
    out = []
    while buffer:
        if not starts_message(buffer):
            out.append(b"\x00body\x00" + buffer)
            return out, b""
        if buffer[:1] == b"$":
            if len(buffer) < 4:
                break
            size = 4 + int.from_bytes(buffer[2:4], "big")
            if len(buffer) < size:
                break
            if state["frames"] < RTSP_FRAME_LIMIT:
                out.append(buffer[:4])
            state["frames"] += 1
            buffer = buffer[size:]
            continue
        end = buffer.find(b"\r\n\r\n")
        if end < 0:
            break
        head = buffer[:end + 4]
        size = len(head)
        first = head.split(b"\r\n", 1)[0]
        no_body = re.match(rb"^RTSP/\d+\.\d+ (1\d\d|204|304) ", first)
        if not no_body:
            size += clen(head.decode("latin-1"))
        if len(buffer) < size:
            break
        out.append(buffer[:size])
        buffer = buffer[size:]
    return out, buffer


# Every request is followed by the start of a timer (the reply may stay away, 9.2) and every reply by its cancel. A server answers within a few milliseconds, faster than
# Fandango sends the start, and a reply that arrives while Fandango expects the start or the cancel is an unexpected message. The party therefore hands what the server sends
# to Fandango while Fandango can take it: from the timer start on, and from the cancel on.
GATE = True


def is_final(piece):
    """A reply that answers the request (not an interim 1xx), or the close of the connection."""
    return piece is None or (piece.startswith(b"RTSP/") and not re.match(rb"RTSP/\d+\.\d+ 1\d\d ", piece))


class ClientNetworkParty(NetworkParty):
    def __init__(self, *args, **kwargs):
        reset_memory()
        self.pending = b""
        self.held = []
        self.shut = False
        self.watching = False
        self.outstanding = set()
        self.last_cseq = None
        self.expired = False
        self.lock = threading.RLock()
        super().__init__(*args, **kwargs)

    def watch_timers(self):
        timer = self.io_instance.parties.get("TimerControl")
        if timer is None or self.watching:
            return
        self.watching = True
        send_timer = timer.send

        def timer_send(message, recipient):
            send_timer(message, recipient)
            self.open_gate()

        timer.send = timer_send
        expire = timer._on_timer_expire

        def on_expire(name):
            self.expired = True
            expire(name)

        timer._on_timer_expire = on_expire

    def send(self, message, recipient):
        raw = bytes(message) if isinstance(message, (bytes, bytearray)) else str(message).encode("latin-1", "replace")
        parts = raw[:300].split(b"\r\n", 1)[0].decode("latin-1").split(" ")
        if len(parts) == 3 and parts[2].startswith("RTSP/"):
            cseq = re.search(rb"\r\nCSeq:[ \t]*(\d+)", raw[:2000])
            if cseq:
                self.outstanding.add(cseq.group(1))
                self.last_cseq = cseq.group(1)
                self.expired = False
            if parts[1] != "*":
                MEMORY["request_url"] = parts[1]
            if GATE:
                self.watch_timers()
                with self.lock:
                    self.shut = True
        super().send(message, recipient)

    def mark_late(self, piece):
        """A final reply to an earlier request that the client has stopped waiting for (its timer expired, or a later request has been sent): the reply is late (9.2)
        and is handed over behind a marker, as a message of its own that is not the reply of the exchange running now."""
        if not piece.startswith(b"RTSP/") or re.match(rb"RTSP/\d+\.\d+ 1\d\d ", piece):
            return piece
        cseq = re.search(rb"\r\nCSeq:[ \t]*(\d+)", piece[:2000])
        if not cseq or cseq.group(1) not in self.outstanding:
            return piece
        self.outstanding.discard(cseq.group(1))
        if cseq.group(1) != self.last_cseq or self.expired:
            return b"\x00late\x00" + piece
        return piece

    def open_gate(self):
        with self.lock:
            self.shut = False
            held, self.held = self.held, []
            for piece, sender in held:
                self.hand_over(piece, sender)

    def hand_over(self, piece, sender):
        with self.lock:
            if GATE and self.shut:
                self.held.append((piece, sender))
                return
            if piece is None:
                super().receive(b"\x00closed\x00", sender)
            else:
                if not piece.startswith(b"$"):
                    # Content-Base and Content-Location belong to the message that carries them (C.1.1): a message without them has none
                    MEMORY["base"], MEMORY["location"] = message_base(piece)
                    MEMORY["message_url"] = message_url(piece)
                super().receive(piece, sender)
            if GATE and is_final(piece):
                self.shut = True

    def receive(self, message, sender):
        with self.lock:
            if message is None:
                # The server closed the connection: the grammar sees it as a message of its own
                if self.pending:
                    # the start of a message that the close cut off
                    self.hand_over(self.pending, sender)
                    self.pending = b""
                self.hand_over(None, sender)
                return
            pieces, self.pending = split_stream(self.pending + bytes(message), MEMORY)
            for piece in pieces:
                self.hand_over(self.mark_late(piece), sender)


# ============================================================================================
# Sessions: one connection; the client states of Appendix A.1.
# ============================================================================================
# A session opens with OPTIONS (10.1), which may be issued at any time and does not influence the server state
# A connection may open with any request the Init state allows (OPTIONS first is not required, 9, A.1); the exchange and the state it leads to are the Init rules
<start> ::= <init_exchange>

# Init: SETUP has not succeeded yet (A.1: Init -SETUP-> Ready, TEARDOWN keeps Init)
<init_exchange> ::= (<x_options_init> <state_init>
    | <x_options_init_closed>
    | <x_options_headers_init> <state_init>
    | <x_options_headers_init_closed>
    | <x_describe_init> <state_init>
    | <x_describe_init_closed>
    | <x_describe_conditional_init> <state_init>
    | <x_describe_conditional_init_closed>
    | <x_describe_unknown_init_ok> <state_init>
    | <x_describe_unknown_init_redirect> <state_init>
    | <x_describe_unknown_init_err> <state_init>
    | <x_describe_unknown_init_closed>
    | <x_get_parameter_init> <state_init>
    | <x_get_parameter_init_closed>
    | <x_blocksize_init> <state_init>
    | <x_blocksize_init_closed>
    | <x_set_parameter_init> <state_init>
    | <x_set_parameter_init_closed>
    | <x_announce_init> <state_init>
    | <x_announce_init_closed>
    | <x_announce_publish_init> <state_init>
    | <x_announce_publish_init_closed>
    | <x_extension_init> <state_init>
    | <x_extension_init_closed>
    | <x_version_init> <state_init>
    | <x_version_init_closed>
    | <x_auth_init> <state_init>
    | <x_auth_init_closed>
    | <x_auth_wrong_init> <state_init>
    | <x_auth_wrong_init_closed>
    | <x_options_close_init> <state_closing>
    | <x_options_close_init_closed>
    | <x_setup_init_ok> <state_ready>
    | <x_setup_init_redirect> <state_init>
    | <x_setup_init_err> <state_init>
    | <x_setup_init_closed>
    | <x_setup_record_init_ok> <state_ready>
    | <x_setup_record_init_redirect> <state_init>
    | <x_setup_record_init_err> <state_init>
    | <x_setup_record_init_closed>
    | <x_setup_full_init_ok> <state_ready>
    | <x_setup_full_init_redirect> <state_init>
    | <x_setup_full_init_err> <state_init>
    | <x_setup_full_init_closed>
    | <x_teardown_init_ok> <state_init>
    | <x_teardown_init_redirect> <state_init>
    | <x_teardown_init_err> <state_init>
    | <x_teardown_init_closed>
    | <x_play_without_setup_init_ok> <state_playing>
    | <x_play_without_setup_init_redirect> <state_init>
    | <x_play_without_setup_init_err> <state_init>
    | <x_play_without_setup_init_closed>
    | <x_play_unknown_session_init_ok> <state_init>
    | <x_play_unknown_session_init_redirect> <state_init>
    | <x_play_unknown_session_init_err> <state_init>
    | <x_play_unknown_session_init_closed>
    | <x_pause_unknown_session_init_ok> <state_init>
    | <x_pause_unknown_session_init_redirect> <state_init>
    | <x_pause_unknown_session_init_err> <state_init>
    | <x_pause_unknown_session_init_closed>
    | <x_record_unknown_session_init_ok> <state_init>
    | <x_record_unknown_session_init_redirect> <state_init>
    | <x_record_unknown_session_init_err> <state_init>
    | <x_record_unknown_session_init_closed>
    | <x_teardown_unknown_session_init_ok> <state_init>
    | <x_teardown_unknown_session_init_redirect> <state_init>
    | <x_teardown_unknown_session_init_err> <state_init>
    | <x_teardown_unknown_session_init_closed>
    | <x_get_parameter_unknown_session_init_ok> <state_init>
    | <x_get_parameter_unknown_session_init_redirect> <state_init>
    | <x_get_parameter_unknown_session_init_err> <state_init>
    | <x_get_parameter_unknown_session_init_closed>
    | <x_set_parameter_unknown_session_init_ok> <state_init>
    | <x_set_parameter_unknown_session_init_redirect> <state_init>
    | <x_set_parameter_unknown_session_init_err> <state_init>
    | <x_set_parameter_unknown_session_init_closed>
    | <x_init_options_init_silent> <state_init>
    | <x_init_options_headers_init_silent> <state_init>
    | <x_init_describe_init_silent> <state_init>
    | <x_init_describe_conditional_init_silent> <state_init>
    | <x_init_describe_unknown_init_silent> <state_init>
    | <x_init_get_parameter_init_silent> <state_init>
    | <x_init_blocksize_init_silent> <state_init>
    | <x_init_set_parameter_init_silent> <state_init>
    | <x_init_announce_init_silent> <state_init>
    | <x_init_announce_publish_init_silent> <state_init>
    | <x_init_extension_init_silent> <state_init>
    | <x_init_version_init_silent> <state_init>
    | <x_init_auth_init_silent> <state_init>
    | <x_init_auth_wrong_init_silent> <state_init>
    | <x_init_options_close_init_silent> <state_init>
    | <x_init_setup_silent> <state_init>
    | <x_init_setup_record_silent> <state_init>
    | <x_init_setup_full_silent> <state_init>
    | <x_init_teardown_init_silent> <state_init>
    | <x_init_play_without_setup_silent> <state_init>
    | <x_init_play_unknown_session_silent> <state_init>
    | <x_init_pause_unknown_session_silent> <state_init>
    | <x_init_record_unknown_session_silent> <state_init>
    | <x_init_teardown_unknown_session_silent> <state_init>
    | <x_init_get_parameter_unknown_session_silent> <state_init>
    | <x_init_set_parameter_unknown_session_silent> <state_init>)

# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<state_init> ::= (<init_exchange>
    | <x_frame> <state_init>
    | <x_server_request> <state_init>
    | <x_server_redirect> <state_init>
    | <x_closed>
    | <x_late_reply> <state_init>
    | <end_of_session>)

# Ready: SETUP reply received, or PAUSE reply received while playing or recording
<state_ready> ::= (<x_options_ready> <state_ready>
    | <x_options_ready_redirect> <state_init>
    | <x_options_ready_closed>
    | <x_options_headers_ready> <state_ready>
    | <x_options_headers_ready_redirect> <state_init>
    | <x_options_headers_ready_closed>
    | <x_describe_ready> <state_ready>
    | <x_describe_ready_redirect> <state_init>
    | <x_describe_ready_closed>
    | <x_describe_conditional_ready> <state_ready>
    | <x_describe_conditional_ready_redirect> <state_init>
    | <x_describe_conditional_ready_closed>
    | <x_play_unknown_session_ready_ok> <state_ready>
    | <x_play_unknown_session_ready_redirect> <state_init>
    | <x_play_unknown_session_ready_err> <state_ready>
    | <x_play_unknown_session_ready_closed>
    | <x_pause_unknown_session_ready_ok> <state_ready>
    | <x_pause_unknown_session_ready_redirect> <state_init>
    | <x_pause_unknown_session_ready_err> <state_ready>
    | <x_pause_unknown_session_ready_closed>
    | <x_record_unknown_session_ready_ok> <state_ready>
    | <x_record_unknown_session_ready_redirect> <state_init>
    | <x_record_unknown_session_ready_err> <state_ready>
    | <x_record_unknown_session_ready_closed>
    | <x_teardown_unknown_session_ready_ok> <state_ready>
    | <x_teardown_unknown_session_ready_redirect> <state_init>
    | <x_teardown_unknown_session_ready_err> <state_ready>
    | <x_teardown_unknown_session_ready_closed>
    | <x_get_parameter_unknown_session_ready_ok> <state_ready>
    | <x_get_parameter_unknown_session_ready_redirect> <state_init>
    | <x_get_parameter_unknown_session_ready_err> <state_ready>
    | <x_get_parameter_unknown_session_ready_closed>
    | <x_set_parameter_unknown_session_ready_ok> <state_ready>
    | <x_set_parameter_unknown_session_ready_redirect> <state_init>
    | <x_set_parameter_unknown_session_ready_err> <state_ready>
    | <x_set_parameter_unknown_session_ready_closed>
    | <x_describe_session_ready> <state_ready>
    | <x_describe_session_ready_redirect> <state_init>
    | <x_describe_session_ready_closed>
    | <x_announce_session_ready> <state_ready>
    | <x_announce_session_ready_redirect> <state_init>
    | <x_announce_session_ready_closed>
    | <x_setup_full_session_ready_ok> <state_ready>
    | <x_setup_full_session_ready_redirect> <state_init>
    | <x_setup_full_session_ready_err> <state_ready>
    | <x_setup_full_session_ready_closed>
    | <x_describe_unknown_ready_ok> <state_ready>
    | <x_describe_unknown_ready_redirect> <state_init>
    | <x_describe_unknown_ready_err> <state_ready>
    | <x_describe_unknown_ready_closed>
    | <x_get_parameter_ready> <state_ready>
    | <x_get_parameter_ready_redirect> <state_init>
    | <x_get_parameter_ready_closed>
    | <x_blocksize_ready> <state_ready>
    | <x_blocksize_ready_redirect> <state_init>
    | <x_blocksize_ready_closed>
    | <x_blocksize_session_ready> <state_ready>
    | <x_blocksize_session_ready_redirect> <state_init>
    | <x_blocksize_session_ready_closed>
    | <x_set_parameter_ready> <state_ready>
    | <x_set_parameter_ready_redirect> <state_init>
    | <x_set_parameter_ready_closed>
    | <x_announce_ready> <state_ready>
    | <x_announce_ready_redirect> <state_init>
    | <x_announce_ready_closed>
    | <x_announce_publish_ready> <state_ready>
    | <x_announce_publish_ready_redirect> <state_init>
    | <x_announce_publish_ready_closed>
    | <x_extension_ready> <state_ready>
    | <x_extension_ready_redirect> <state_init>
    | <x_extension_ready_closed>
    | <x_version_ready> <state_ready>
    | <x_version_ready_redirect> <state_init>
    | <x_version_ready_closed>
    | <x_auth_ready> <state_ready>
    | <x_auth_ready_redirect> <state_init>
    | <x_auth_ready_closed>
    | <x_auth_wrong_ready> <state_ready>
    | <x_auth_wrong_ready_redirect> <state_init>
    | <x_auth_wrong_ready_closed>
    | <x_options_close_ready> <state_closing>
    | <x_options_close_ready_closed>
    | <x_play_ready_ok> <state_playing>
    | <x_play_ready_redirect> <state_init>
    | <x_play_ready_err> <state_ready>
    | <x_play_ready_closed>
    | <x_record_ready_ok> <state_recording>
    | <x_record_ready_redirect> <state_init>
    | <x_record_ready_err> <state_ready>
    | <x_record_ready_closed>
    | <x_setup_ready_ok> <state_ready>
    | <x_setup_ready_redirect> <state_init>
    | <x_setup_ready_err> <state_ready>
    | <x_setup_ready_closed>
    | <x_setup_record_ready_ok> <state_ready>
    | <x_setup_record_ready_redirect> <state_init>
    | <x_setup_record_ready_err> <state_ready>
    | <x_setup_record_ready_closed>
    | <x_setup_second_ready_ok> <state_ready>
    | <x_setup_second_ready_redirect> <state_init>
    | <x_setup_second_ready_err> <state_ready>
    | <x_setup_second_ready_closed>
    | <x_setup_second_narrow_ready_ok> <state_ready>
    | <x_setup_second_narrow_ready_redirect> <state_init>
    | <x_setup_second_narrow_ready_err> <state_ready>
    | <x_setup_second_narrow_ready_closed>
    | <x_teardown_ready_ok> <state_init>
    | <x_teardown_ready_redirect> <state_init>
    | <x_teardown_ready_err> <state_ready>
    | <x_teardown_ready_closed>
    | <x_pause_ready> <state_ready>
    | <x_pause_ready_redirect> <state_init>
    | <x_pause_ready_closed>
    | <x_teardown_stream_ready> <state_ready>
    | <x_teardown_stream_ready_redirect> <state_init>
    | <x_teardown_stream_ready_closed>
    | <x_ready_options_ready_silent> <state_ready>
    | <x_ready_options_headers_ready_silent> <state_ready>
    | <x_ready_describe_ready_silent> <state_ready>
    | <x_ready_describe_conditional_ready_silent> <state_ready>
    | <x_ready_play_unknown_session_ready_silent> <state_ready>
    | <x_ready_pause_unknown_session_ready_silent> <state_ready>
    | <x_ready_record_unknown_session_ready_silent> <state_ready>
    | <x_ready_teardown_unknown_session_ready_silent> <state_ready>
    | <x_ready_get_parameter_unknown_session_ready_silent> <state_ready>
    | <x_ready_set_parameter_unknown_session_ready_silent> <state_ready>
    | <x_ready_describe_session_ready_silent> <state_ready>
    | <x_ready_announce_session_ready_silent> <state_ready>
    | <x_ready_setup_full_session_ready_silent> <state_ready>
    | <x_ready_describe_unknown_ready_silent> <state_ready>
    | <x_ready_get_parameter_ready_silent> <state_ready>
    | <x_ready_blocksize_ready_silent> <state_ready>
    | <x_ready_blocksize_session_ready_silent> <state_ready>
    | <x_ready_set_parameter_ready_silent> <state_ready>
    | <x_ready_announce_ready_silent> <state_ready>
    | <x_ready_announce_publish_ready_silent> <state_ready>
    | <x_ready_extension_ready_silent> <state_ready>
    | <x_ready_version_ready_silent> <state_ready>
    | <x_ready_auth_ready_silent> <state_ready>
    | <x_ready_auth_wrong_ready_silent> <state_ready>
    | <x_ready_options_close_ready_silent> <state_ready>
    | <x_ready_play_silent> <state_ready>
    | <x_ready_record_silent> <state_ready>
    | <x_ready_setup_again_silent> <state_ready>
    | <x_ready_setup_record_again_silent> <state_ready>
    | <x_ready_setup_second_session_silent> <state_ready>
    | <x_ready_setup_second_narrow_silent> <state_ready>
    | <x_ready_teardown_silent> <state_ready>
    | <x_ready_pause_ready_silent> <state_ready>
    | <x_ready_teardown_stream_ready_silent> <state_ready>
    | <x_frame> <state_ready>
    | <x_server_request> <state_ready>
    | <x_server_redirect> <state_init>
    | <x_closed>
    | <x_late_reply> <state_ready>
    | <end_of_session>)

# Playing: PLAY reply received
<state_playing> ::= (<x_options_playing> <state_playing>
    | <x_options_playing_redirect> <state_init>
    | <x_options_playing_closed>
    | <x_options_headers_playing> <state_playing>
    | <x_options_headers_playing_redirect> <state_init>
    | <x_options_headers_playing_closed>
    | <x_describe_playing> <state_playing>
    | <x_describe_playing_redirect> <state_init>
    | <x_describe_playing_closed>
    | <x_describe_conditional_playing> <state_playing>
    | <x_describe_conditional_playing_redirect> <state_init>
    | <x_describe_conditional_playing_closed>
    | <x_play_unknown_session_playing_ok> <state_playing>
    | <x_play_unknown_session_playing_redirect> <state_init>
    | <x_play_unknown_session_playing_err> <state_playing>
    | <x_play_unknown_session_playing_closed>
    | <x_pause_unknown_session_playing_ok> <state_playing>
    | <x_pause_unknown_session_playing_redirect> <state_init>
    | <x_pause_unknown_session_playing_err> <state_playing>
    | <x_pause_unknown_session_playing_closed>
    | <x_record_unknown_session_playing_ok> <state_playing>
    | <x_record_unknown_session_playing_redirect> <state_init>
    | <x_record_unknown_session_playing_err> <state_playing>
    | <x_record_unknown_session_playing_closed>
    | <x_teardown_unknown_session_playing_ok> <state_playing>
    | <x_teardown_unknown_session_playing_redirect> <state_init>
    | <x_teardown_unknown_session_playing_err> <state_playing>
    | <x_teardown_unknown_session_playing_closed>
    | <x_get_parameter_unknown_session_playing_ok> <state_playing>
    | <x_get_parameter_unknown_session_playing_redirect> <state_init>
    | <x_get_parameter_unknown_session_playing_err> <state_playing>
    | <x_get_parameter_unknown_session_playing_closed>
    | <x_set_parameter_unknown_session_playing_ok> <state_playing>
    | <x_set_parameter_unknown_session_playing_redirect> <state_init>
    | <x_set_parameter_unknown_session_playing_err> <state_playing>
    | <x_set_parameter_unknown_session_playing_closed>
    | <x_describe_session_playing> <state_playing>
    | <x_describe_session_playing_redirect> <state_init>
    | <x_describe_session_playing_closed>
    | <x_announce_session_playing> <state_playing>
    | <x_announce_session_playing_redirect> <state_init>
    | <x_announce_session_playing_closed>
    | <x_setup_full_session_playing_ok> <state_playing>
    | <x_setup_full_session_playing_redirect> <state_init>
    | <x_setup_full_session_playing_err> <state_playing>
    | <x_setup_full_session_playing_closed>
    | <x_describe_unknown_playing_ok> <state_playing>
    | <x_describe_unknown_playing_redirect> <state_init>
    | <x_describe_unknown_playing_err> <state_playing>
    | <x_describe_unknown_playing_closed>
    | <x_get_parameter_playing> <state_playing>
    | <x_get_parameter_playing_redirect> <state_init>
    | <x_get_parameter_playing_closed>
    | <x_blocksize_playing> <state_playing>
    | <x_blocksize_playing_redirect> <state_init>
    | <x_blocksize_playing_closed>
    | <x_blocksize_session_playing> <state_playing>
    | <x_blocksize_session_playing_redirect> <state_init>
    | <x_blocksize_session_playing_closed>
    | <x_set_parameter_playing> <state_playing>
    | <x_set_parameter_playing_redirect> <state_init>
    | <x_set_parameter_playing_closed>
    | <x_announce_playing> <state_playing>
    | <x_announce_playing_redirect> <state_init>
    | <x_announce_playing_closed>
    | <x_announce_publish_playing> <state_playing>
    | <x_announce_publish_playing_redirect> <state_init>
    | <x_announce_publish_playing_closed>
    | <x_extension_playing> <state_playing>
    | <x_extension_playing_redirect> <state_init>
    | <x_extension_playing_closed>
    | <x_version_playing> <state_playing>
    | <x_version_playing_redirect> <state_init>
    | <x_version_playing_closed>
    | <x_auth_playing> <state_playing>
    | <x_auth_playing_redirect> <state_init>
    | <x_auth_playing_closed>
    | <x_auth_wrong_playing> <state_playing>
    | <x_auth_wrong_playing_redirect> <state_init>
    | <x_auth_wrong_playing_closed>
    | <x_options_close_playing> <state_closing>
    | <x_options_close_playing_closed>
    | <x_pause_playing_ok> <state_ready>
    | <x_pause_playing_redirect> <state_init>
    | <x_pause_playing_err> <state_playing>
    | <x_pause_playing_closed>
    | <x_play_playing_ok> <state_playing>
    | <x_play_playing_redirect> <state_init>
    | <x_play_playing_err> <state_playing>
    | <x_play_playing_closed>
    | <x_setup_playing_ok> <state_playing>
    | <x_setup_playing_redirect> <state_init>
    | <x_setup_playing_err> <state_playing>
    | <x_setup_playing_closed>
    | <x_setup_narrow_playing_ok> <state_playing>
    | <x_setup_narrow_playing_redirect> <state_init>
    | <x_setup_narrow_playing_err> <state_playing>
    | <x_setup_narrow_playing_closed>
    | <x_teardown_playing_ok> <state_init>
    | <x_teardown_playing_redirect> <state_init>
    | <x_teardown_playing_err> <state_playing>
    | <x_teardown_playing_closed>
    | <x_record_playing> <state_playing>
    | <x_record_playing_redirect> <state_init>
    | <x_record_playing_closed>
    | <x_teardown_stream_playing> <state_playing>
    | <x_teardown_stream_playing_redirect> <state_init>
    | <x_teardown_stream_playing_closed>
    | <x_playing_options_playing_silent> <state_playing>
    | <x_playing_options_headers_playing_silent> <state_playing>
    | <x_playing_describe_playing_silent> <state_playing>
    | <x_playing_describe_conditional_playing_silent> <state_playing>
    | <x_playing_play_unknown_session_playing_silent> <state_playing>
    | <x_playing_pause_unknown_session_playing_silent> <state_playing>
    | <x_playing_record_unknown_session_playing_silent> <state_playing>
    | <x_playing_teardown_unknown_session_playing_silent> <state_playing>
    | <x_playing_get_parameter_unknown_session_playing_silent> <state_playing>
    | <x_playing_set_parameter_unknown_session_playing_silent> <state_playing>
    | <x_playing_describe_session_playing_silent> <state_playing>
    | <x_playing_announce_session_playing_silent> <state_playing>
    | <x_playing_setup_full_session_playing_silent> <state_playing>
    | <x_playing_describe_unknown_playing_silent> <state_playing>
    | <x_playing_get_parameter_playing_silent> <state_playing>
    | <x_playing_blocksize_playing_silent> <state_playing>
    | <x_playing_blocksize_session_playing_silent> <state_playing>
    | <x_playing_set_parameter_playing_silent> <state_playing>
    | <x_playing_announce_playing_silent> <state_playing>
    | <x_playing_announce_publish_playing_silent> <state_playing>
    | <x_playing_extension_playing_silent> <state_playing>
    | <x_playing_version_playing_silent> <state_playing>
    | <x_playing_auth_playing_silent> <state_playing>
    | <x_playing_auth_wrong_playing_silent> <state_playing>
    | <x_playing_options_close_playing_silent> <state_playing>
    | <x_playing_pause_silent> <state_playing>
    | <x_playing_play_playing_silent> <state_playing>
    | <x_playing_setup_change_playing_silent> <state_playing>
    | <x_playing_setup_change_narrow_playing_silent> <state_playing>
    | <x_playing_teardown_playing_silent> <state_playing>
    | <x_playing_record_playing_silent> <state_playing>
    | <x_playing_teardown_stream_playing_silent> <state_playing>
    | <x_frame> <state_playing>
    | <x_frame_up> <state_playing>
    | <x_play_queued_start> <play_queued_outcome>
    | <x_server_request> <state_playing>
    | <x_server_redirect> <state_init>
    | <x_closed>
    | <x_late_reply> <state_playing>
    | <end_of_session>)

# Recording: RECORD reply received
<state_recording> ::= (<x_options_recording> <state_recording>
    | <x_options_recording_redirect> <state_init>
    | <x_options_recording_closed>
    | <x_options_headers_recording> <state_recording>
    | <x_options_headers_recording_redirect> <state_init>
    | <x_options_headers_recording_closed>
    | <x_describe_recording> <state_recording>
    | <x_describe_recording_redirect> <state_init>
    | <x_describe_recording_closed>
    | <x_describe_conditional_recording> <state_recording>
    | <x_describe_conditional_recording_redirect> <state_init>
    | <x_describe_conditional_recording_closed>
    | <x_play_unknown_session_recording_ok> <state_recording>
    | <x_play_unknown_session_recording_redirect> <state_init>
    | <x_play_unknown_session_recording_err> <state_recording>
    | <x_play_unknown_session_recording_closed>
    | <x_pause_unknown_session_recording_ok> <state_recording>
    | <x_pause_unknown_session_recording_redirect> <state_init>
    | <x_pause_unknown_session_recording_err> <state_recording>
    | <x_pause_unknown_session_recording_closed>
    | <x_record_unknown_session_recording_ok> <state_recording>
    | <x_record_unknown_session_recording_redirect> <state_init>
    | <x_record_unknown_session_recording_err> <state_recording>
    | <x_record_unknown_session_recording_closed>
    | <x_teardown_unknown_session_recording_ok> <state_recording>
    | <x_teardown_unknown_session_recording_redirect> <state_init>
    | <x_teardown_unknown_session_recording_err> <state_recording>
    | <x_teardown_unknown_session_recording_closed>
    | <x_get_parameter_unknown_session_recording_ok> <state_recording>
    | <x_get_parameter_unknown_session_recording_redirect> <state_init>
    | <x_get_parameter_unknown_session_recording_err> <state_recording>
    | <x_get_parameter_unknown_session_recording_closed>
    | <x_set_parameter_unknown_session_recording_ok> <state_recording>
    | <x_set_parameter_unknown_session_recording_redirect> <state_init>
    | <x_set_parameter_unknown_session_recording_err> <state_recording>
    | <x_set_parameter_unknown_session_recording_closed>
    | <x_describe_session_recording> <state_recording>
    | <x_describe_session_recording_redirect> <state_init>
    | <x_describe_session_recording_closed>
    | <x_announce_session_recording> <state_recording>
    | <x_announce_session_recording_redirect> <state_init>
    | <x_announce_session_recording_closed>
    | <x_setup_full_session_recording_ok> <state_recording>
    | <x_setup_full_session_recording_redirect> <state_init>
    | <x_setup_full_session_recording_err> <state_recording>
    | <x_setup_full_session_recording_closed>
    | <x_describe_unknown_recording_ok> <state_recording>
    | <x_describe_unknown_recording_redirect> <state_init>
    | <x_describe_unknown_recording_err> <state_recording>
    | <x_describe_unknown_recording_closed>
    | <x_get_parameter_recording> <state_recording>
    | <x_get_parameter_recording_redirect> <state_init>
    | <x_get_parameter_recording_closed>
    | <x_blocksize_recording> <state_recording>
    | <x_blocksize_recording_redirect> <state_init>
    | <x_blocksize_recording_closed>
    | <x_blocksize_session_recording> <state_recording>
    | <x_blocksize_session_recording_redirect> <state_init>
    | <x_blocksize_session_recording_closed>
    | <x_set_parameter_recording> <state_recording>
    | <x_set_parameter_recording_redirect> <state_init>
    | <x_set_parameter_recording_closed>
    | <x_announce_recording> <state_recording>
    | <x_announce_recording_redirect> <state_init>
    | <x_announce_recording_closed>
    | <x_announce_publish_recording> <state_recording>
    | <x_announce_publish_recording_redirect> <state_init>
    | <x_announce_publish_recording_closed>
    | <x_extension_recording> <state_recording>
    | <x_extension_recording_redirect> <state_init>
    | <x_extension_recording_closed>
    | <x_version_recording> <state_recording>
    | <x_version_recording_redirect> <state_init>
    | <x_version_recording_closed>
    | <x_auth_recording> <state_recording>
    | <x_auth_recording_redirect> <state_init>
    | <x_auth_recording_closed>
    | <x_auth_wrong_recording> <state_recording>
    | <x_auth_wrong_recording_redirect> <state_init>
    | <x_auth_wrong_recording_closed>
    | <x_options_close_recording> <state_closing>
    | <x_options_close_recording_closed>
    | <x_pause_recording_ok> <state_ready>
    | <x_pause_recording_redirect> <state_init>
    | <x_pause_recording_err> <state_recording>
    | <x_pause_recording_closed>
    | <x_record_recording_ok> <state_recording>
    | <x_record_recording_redirect> <state_init>
    | <x_record_recording_err> <state_recording>
    | <x_record_recording_closed>
    | <x_setup_recording_ok> <state_recording>
    | <x_setup_recording_redirect> <state_init>
    | <x_setup_recording_err> <state_recording>
    | <x_setup_recording_closed>
    | <x_setup_narrow_recording_ok> <state_recording>
    | <x_setup_narrow_recording_redirect> <state_init>
    | <x_setup_narrow_recording_err> <state_recording>
    | <x_setup_narrow_recording_closed>
    | <x_teardown_recording_ok> <state_init>
    | <x_teardown_recording_redirect> <state_init>
    | <x_teardown_recording_err> <state_recording>
    | <x_teardown_recording_closed>
    | <x_play_recording> <state_recording>
    | <x_play_recording_redirect> <state_init>
    | <x_play_recording_closed>
    | <x_teardown_stream_recording> <state_recording>
    | <x_teardown_stream_recording_redirect> <state_init>
    | <x_teardown_stream_recording_closed>
    | <x_recording_options_recording_silent> <state_recording>
    | <x_recording_options_headers_recording_silent> <state_recording>
    | <x_recording_describe_recording_silent> <state_recording>
    | <x_recording_describe_conditional_recording_silent> <state_recording>
    | <x_recording_play_unknown_session_recording_silent> <state_recording>
    | <x_recording_pause_unknown_session_recording_silent> <state_recording>
    | <x_recording_record_unknown_session_recording_silent> <state_recording>
    | <x_recording_teardown_unknown_session_recording_silent> <state_recording>
    | <x_recording_get_parameter_unknown_session_recording_silent> <state_recording>
    | <x_recording_set_parameter_unknown_session_recording_silent> <state_recording>
    | <x_recording_describe_session_recording_silent> <state_recording>
    | <x_recording_announce_session_recording_silent> <state_recording>
    | <x_recording_setup_full_session_recording_silent> <state_recording>
    | <x_recording_describe_unknown_recording_silent> <state_recording>
    | <x_recording_get_parameter_recording_silent> <state_recording>
    | <x_recording_blocksize_recording_silent> <state_recording>
    | <x_recording_blocksize_session_recording_silent> <state_recording>
    | <x_recording_set_parameter_recording_silent> <state_recording>
    | <x_recording_announce_recording_silent> <state_recording>
    | <x_recording_announce_publish_recording_silent> <state_recording>
    | <x_recording_extension_recording_silent> <state_recording>
    | <x_recording_version_recording_silent> <state_recording>
    | <x_recording_auth_recording_silent> <state_recording>
    | <x_recording_auth_wrong_recording_silent> <state_recording>
    | <x_recording_options_close_recording_silent> <state_recording>
    | <x_recording_pause_recording_silent> <state_recording>
    | <x_recording_record_recording_silent> <state_recording>
    | <x_recording_setup_change_recording_silent> <state_recording>
    | <x_recording_setup_change_narrow_recording_silent> <state_recording>
    | <x_recording_teardown_recording_silent> <state_recording>
    | <x_recording_play_recording_silent> <state_recording>
    | <x_recording_teardown_stream_recording_silent> <state_recording>
    | <x_frame> <state_recording>
    | <x_frame_up> <state_recording>
    | <x_server_request> <state_recording>
    | <x_server_redirect> <state_init>
    | <x_closed>
    | <x_late_reply> <state_recording>
    | <end_of_session>)

# Messages the server sends on its own initiative, accepted between two exchanges in every state
<x_frame> ::= <Server:interleaved_frame>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_frame_up> ::= <Client:interleaved_frame_sent>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_closed> ::= <Server:server_closed>
# A reply that arrives after the client's timer expired (9.2), marked by the party: accepted between two exchanges and inside an exchange before its reply
<x_late_reply> ::= <Server:server_late_reply>

# Timers (Fandango's built-in parties): one per reply the server may leave unsent; the timeout is the longest the client waits
#   1: the reply to a PLAY the server queues behind the running PLAY (10.5)
#   2: the close of the connection after a request with Connection: close (RFC 9112 9.6 is HTTP's; RTSP 12.10 only refers to it), which a server may leave out
#   3: the reply to any request (9.2: requests are acknowledged, and the sender may resend after a timeout when there is none)
<timer_start_1> ::= 'start: ' <timer_id_1> ' (' <timer_timeout_1> ')\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_cancel_1> ::= 'cancel: ' <timer_id_1> '\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_expired_1> ::= 'expired: ' <timer_id> '\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_id_1> ::= <timer_id> := '1'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_timeout_1> ::= <timer_timeout> := reply_wait(RTSP_WAIT)
where forall <m> in <timer_expired_1>: <m>.<timer_id> == '1'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_start_2> ::= 'start: ' <timer_id_2> ' (' <timer_timeout_2> ')\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_cancel_2> ::= 'cancel: ' <timer_id_2> '\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_expired_2> ::= 'expired: ' <timer_id> '\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_id_2> ::= <timer_id> := '2'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_timeout_2> ::= <timer_timeout> := reply_wait(RTSP_CLOSE_WAIT)
where forall <m> in <timer_expired_2>: <m>.<timer_id> == '2'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_start_3> ::= 'start: ' <timer_id_3> ' (' <timer_timeout_3> ')\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_cancel_3> ::= 'cancel: ' <timer_id_3> '\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_expired_3> ::= 'expired: ' <timer_id> '\n'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_id_3> ::= <timer_id> := '3'
# Fandango timers (built-in TimerControl/TimerEvent parties)
<timer_timeout_3> ::= <timer_timeout> := reply_wait(RTSP_REPLY_WAIT)
where forall <m> in <timer_expired_3>: <m>.<timer_id> == '3'
# The server closes the connection after a reply to a request with Connection: close
<state_closing> ::= (<x_frame> <state_closing> | <TimerControl:timer_start_2> <x_frame>* (<x_closed> <TimerControl:timer_cancel_2> | <TimerEvent:timer_expired_2>))
# TODO: RFC 2326 9 - one connection per transaction (nearest <end_of_session>): the next transaction of the same RTSP session runs on a new connection that carries the Session identifier over;
#   a session of the test setup is one connection, so a second connection after the first one closed cannot be held. Connectionless operation is the TODO at <rtsp_scheme>.
<end_of_session> ::= ''
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<server_closed> ::= '\x00closed\x00'

# Exchanges: a request and the reply class that selects the next state (A.1: 2xx next state, 3xx Init, 4xx no change)
<x_options_init> ::= <Client:req_options_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_init_closed> ::= <Client:req_options_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_init> ::= <Client:req_options_headers_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_init_closed> ::= <Client:req_options_headers_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_init> ::= <Client:req_describe_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_init_closed> ::= <Client:req_describe_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_init> ::= <Client:req_describe_conditional_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_init_closed> ::= <Client:req_describe_conditional_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_init_ok> ::= <Client:req_describe_unknown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_init_redirect> ::= <Client:req_describe_unknown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_init_err> ::= <Client:req_describe_unknown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_init_closed> ::= <Client:req_describe_unknown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_init> ::= <Client:req_get_parameter_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_init_closed> ::= <Client:req_get_parameter_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_init> ::= <Client:req_blocksize_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_init_closed> ::= <Client:req_blocksize_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_init> ::= <Client:req_set_parameter_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_init_closed> ::= <Client:req_set_parameter_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_init> ::= <Client:req_announce_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_init_closed> ::= <Client:req_announce_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_init> ::= <Client:req_announce_publish_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_init_closed> ::= <Client:req_announce_publish_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_init> ::= <Client:req_extension_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_init_closed> ::= <Client:req_extension_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_init> ::= <Client:req_version_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_init_closed> ::= <Client:req_version_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_init> ::= <Client:req_auth_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_init_closed> ::= <Client:req_auth_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_init> ::= <Client:req_auth_wrong_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_init_closed> ::= <Client:req_auth_wrong_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_init> ::= <Client:req_options_close_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_init_closed> ::= <Client:req_options_close_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_ready> ::= <Client:req_options_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_ready_redirect> ::= <Client:req_options_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_ready_closed> ::= <Client:req_options_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_ready> ::= <Client:req_options_headers_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_ready_redirect> ::= <Client:req_options_headers_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_ready_closed> ::= <Client:req_options_headers_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_ready> ::= <Client:req_describe_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_ready_redirect> ::= <Client:req_describe_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_ready_closed> ::= <Client:req_describe_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_ready> ::= <Client:req_describe_conditional_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_ready_redirect> ::= <Client:req_describe_conditional_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_ready_closed> ::= <Client:req_describe_conditional_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_ready_ok> ::= <Client:req_play_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_ready_redirect> ::= <Client:req_play_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_ready_err> ::= <Client:req_play_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_ready_closed> ::= <Client:req_play_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_ready_ok> ::= <Client:req_pause_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_ready_redirect> ::= <Client:req_pause_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_ready_err> ::= <Client:req_pause_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_ready_closed> ::= <Client:req_pause_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_ready_ok> ::= <Client:req_record_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_ready_redirect> ::= <Client:req_record_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_ready_err> ::= <Client:req_record_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_ready_closed> ::= <Client:req_record_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_ready_ok> ::= <Client:req_teardown_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_ready_redirect> ::= <Client:req_teardown_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_ready_err> ::= <Client:req_teardown_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_ready_closed> ::= <Client:req_teardown_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_ready_ok> ::= <Client:req_get_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_ready_redirect> ::= <Client:req_get_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_ready_err> ::= <Client:req_get_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_ready_closed> ::= <Client:req_get_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_ready_ok> ::= <Client:req_set_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_ready_redirect> ::= <Client:req_set_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_ready_err> ::= <Client:req_set_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_ready_closed> ::= <Client:req_set_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_ready> ::= <Client:req_describe_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_ready_redirect> ::= <Client:req_describe_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_ready_closed> ::= <Client:req_describe_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_ready> ::= <Client:req_announce_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_ready_redirect> ::= <Client:req_announce_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_ready_closed> ::= <Client:req_announce_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_ready_ok> ::= <Client:req_setup_full_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_ready_redirect> ::= <Client:req_setup_full_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_ready_err> ::= <Client:req_setup_full_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_ready_closed> ::= <Client:req_setup_full_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_ready_ok> ::= <Client:req_describe_unknown_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_ready_redirect> ::= <Client:req_describe_unknown_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_ready_err> ::= <Client:req_describe_unknown_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_ready_closed> ::= <Client:req_describe_unknown_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_ready> ::= <Client:req_get_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_ready_redirect> ::= <Client:req_get_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_ready_closed> ::= <Client:req_get_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_ready> ::= <Client:req_blocksize_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_ready_redirect> ::= <Client:req_blocksize_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_ready_closed> ::= <Client:req_blocksize_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_ready> ::= <Client:req_blocksize_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_ready_redirect> ::= <Client:req_blocksize_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_ready_closed> ::= <Client:req_blocksize_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_ready> ::= <Client:req_set_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_ready_redirect> ::= <Client:req_set_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_ready_closed> ::= <Client:req_set_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_ready> ::= <Client:req_announce_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_ready_redirect> ::= <Client:req_announce_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_ready_closed> ::= <Client:req_announce_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_ready> ::= <Client:req_announce_publish_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_ready_redirect> ::= <Client:req_announce_publish_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_ready_closed> ::= <Client:req_announce_publish_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_ready> ::= <Client:req_extension_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_ready_redirect> ::= <Client:req_extension_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_ready_closed> ::= <Client:req_extension_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_ready> ::= <Client:req_version_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_ready_redirect> ::= <Client:req_version_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_ready_closed> ::= <Client:req_version_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_ready> ::= <Client:req_auth_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_ready_redirect> ::= <Client:req_auth_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_ready_closed> ::= <Client:req_auth_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_ready> ::= <Client:req_auth_wrong_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_ready_redirect> ::= <Client:req_auth_wrong_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_ready_closed> ::= <Client:req_auth_wrong_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_ready> ::= <Client:req_options_close_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_ready_closed> ::= <Client:req_options_close_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_playing> ::= <Client:req_options_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_playing_redirect> ::= <Client:req_options_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_playing_closed> ::= <Client:req_options_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_playing> ::= <Client:req_options_headers_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_playing_redirect> ::= <Client:req_options_headers_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_playing_closed> ::= <Client:req_options_headers_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_playing> ::= <Client:req_describe_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_playing_redirect> ::= <Client:req_describe_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_playing_closed> ::= <Client:req_describe_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_playing> ::= <Client:req_describe_conditional_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_playing_redirect> ::= <Client:req_describe_conditional_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_playing_closed> ::= <Client:req_describe_conditional_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_playing_ok> ::= <Client:req_play_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_playing_redirect> ::= <Client:req_play_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_playing_err> ::= <Client:req_play_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_playing_closed> ::= <Client:req_play_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_playing_ok> ::= <Client:req_pause_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_playing_redirect> ::= <Client:req_pause_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_playing_err> ::= <Client:req_pause_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_playing_closed> ::= <Client:req_pause_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_playing_ok> ::= <Client:req_record_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_playing_redirect> ::= <Client:req_record_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_playing_err> ::= <Client:req_record_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_playing_closed> ::= <Client:req_record_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_playing_ok> ::= <Client:req_teardown_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_playing_redirect> ::= <Client:req_teardown_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_playing_err> ::= <Client:req_teardown_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_playing_closed> ::= <Client:req_teardown_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_playing_ok> ::= <Client:req_get_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_playing_redirect> ::= <Client:req_get_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_playing_err> ::= <Client:req_get_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_playing_closed> ::= <Client:req_get_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_playing_ok> ::= <Client:req_set_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_playing_redirect> ::= <Client:req_set_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_playing_err> ::= <Client:req_set_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_playing_closed> ::= <Client:req_set_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_playing> ::= <Client:req_describe_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_playing_redirect> ::= <Client:req_describe_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_playing_closed> ::= <Client:req_describe_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_playing> ::= <Client:req_announce_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_playing_redirect> ::= <Client:req_announce_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_playing_closed> ::= <Client:req_announce_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_playing_ok> ::= <Client:req_setup_full_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_playing_redirect> ::= <Client:req_setup_full_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_playing_err> ::= <Client:req_setup_full_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_playing_closed> ::= <Client:req_setup_full_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_playing_ok> ::= <Client:req_describe_unknown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_playing_redirect> ::= <Client:req_describe_unknown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_playing_err> ::= <Client:req_describe_unknown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_playing_closed> ::= <Client:req_describe_unknown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_playing> ::= <Client:req_get_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_playing_redirect> ::= <Client:req_get_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_playing_closed> ::= <Client:req_get_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_playing> ::= <Client:req_blocksize_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_playing_redirect> ::= <Client:req_blocksize_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_playing_closed> ::= <Client:req_blocksize_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_playing> ::= <Client:req_blocksize_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_playing_redirect> ::= <Client:req_blocksize_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_playing_closed> ::= <Client:req_blocksize_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_playing> ::= <Client:req_set_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_playing_redirect> ::= <Client:req_set_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_playing_closed> ::= <Client:req_set_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_playing> ::= <Client:req_announce_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_playing_redirect> ::= <Client:req_announce_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_playing_closed> ::= <Client:req_announce_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_playing> ::= <Client:req_announce_publish_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_playing_redirect> ::= <Client:req_announce_publish_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_playing_closed> ::= <Client:req_announce_publish_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_playing> ::= <Client:req_extension_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_playing_redirect> ::= <Client:req_extension_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_playing_closed> ::= <Client:req_extension_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_playing> ::= <Client:req_version_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_playing_redirect> ::= <Client:req_version_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_playing_closed> ::= <Client:req_version_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_playing> ::= <Client:req_auth_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_playing_redirect> ::= <Client:req_auth_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_playing_closed> ::= <Client:req_auth_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_playing> ::= <Client:req_auth_wrong_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_playing_redirect> ::= <Client:req_auth_wrong_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_playing_closed> ::= <Client:req_auth_wrong_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_playing> ::= <Client:req_options_close_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_playing_closed> ::= <Client:req_options_close_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_recording> ::= <Client:req_options_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_recording_redirect> ::= <Client:req_options_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_recording_closed> ::= <Client:req_options_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_recording> ::= <Client:req_options_headers_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_recording_redirect> ::= <Client:req_options_headers_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_headers_recording_closed> ::= <Client:req_options_headers_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_recording> ::= <Client:req_describe_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_recording_redirect> ::= <Client:req_describe_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_recording_closed> ::= <Client:req_describe_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_recording> ::= <Client:req_describe_conditional_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_recording_redirect> ::= <Client:req_describe_conditional_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_conditional_recording_closed> ::= <Client:req_describe_conditional_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_recording_ok> ::= <Client:req_play_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_recording_redirect> ::= <Client:req_play_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_recording_err> ::= <Client:req_play_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_recording_closed> ::= <Client:req_play_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_recording_ok> ::= <Client:req_pause_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_recording_redirect> ::= <Client:req_pause_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_recording_err> ::= <Client:req_pause_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_recording_closed> ::= <Client:req_pause_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_recording_ok> ::= <Client:req_record_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_recording_redirect> ::= <Client:req_record_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_recording_err> ::= <Client:req_record_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_recording_closed> ::= <Client:req_record_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_recording_ok> ::= <Client:req_teardown_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_recording_redirect> ::= <Client:req_teardown_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_recording_err> ::= <Client:req_teardown_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_recording_closed> ::= <Client:req_teardown_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_recording_ok> ::= <Client:req_get_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_recording_redirect> ::= <Client:req_get_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_recording_err> ::= <Client:req_get_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_recording_closed> ::= <Client:req_get_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_recording_ok> ::= <Client:req_set_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_recording_redirect> ::= <Client:req_set_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_recording_err> ::= <Client:req_set_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_recording_closed> ::= <Client:req_set_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_recording> ::= <Client:req_describe_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_recording_redirect> ::= <Client:req_describe_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_session_recording_closed> ::= <Client:req_describe_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_recording> ::= <Client:req_announce_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_recording_redirect> ::= <Client:req_announce_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_session_recording_closed> ::= <Client:req_announce_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_recording_ok> ::= <Client:req_setup_full_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_recording_redirect> ::= <Client:req_setup_full_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_recording_err> ::= <Client:req_setup_full_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_session_recording_closed> ::= <Client:req_setup_full_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_recording_ok> ::= <Client:req_describe_unknown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_recording_redirect> ::= <Client:req_describe_unknown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_recording_err> ::= <Client:req_describe_unknown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_describe_unknown_recording_closed> ::= <Client:req_describe_unknown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_recording> ::= <Client:req_get_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_recording_redirect> ::= <Client:req_get_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_recording_closed> ::= <Client:req_get_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_recording> ::= <Client:req_blocksize_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_recording_redirect> ::= <Client:req_blocksize_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_recording_closed> ::= <Client:req_blocksize_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_recording> ::= <Client:req_blocksize_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_recording_redirect> ::= <Client:req_blocksize_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_blocksize_session_recording_closed> ::= <Client:req_blocksize_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_recording> ::= <Client:req_set_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_recording_redirect> ::= <Client:req_set_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_recording_closed> ::= <Client:req_set_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_recording> ::= <Client:req_announce_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_recording_redirect> ::= <Client:req_announce_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_recording_closed> ::= <Client:req_announce_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_recording> ::= <Client:req_announce_publish_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_recording_redirect> ::= <Client:req_announce_publish_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_announce_publish_recording_closed> ::= <Client:req_announce_publish_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_recording> ::= <Client:req_extension_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_recording_redirect> ::= <Client:req_extension_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_extension_recording_closed> ::= <Client:req_extension_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_recording> ::= <Client:req_version_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_recording_redirect> ::= <Client:req_version_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_version_recording_closed> ::= <Client:req_version_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_recording> ::= <Client:req_auth_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_recording_redirect> ::= <Client:req_auth_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_recording_closed> ::= <Client:req_auth_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_recording> ::= <Client:req_auth_wrong_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_recording_redirect> ::= <Client:req_auth_wrong_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_auth_wrong_recording_closed> ::= <Client:req_auth_wrong_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_recording> ::= <Client:req_options_close_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_any_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_options_close_recording_closed> ::= <Client:req_options_close_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_init_ok> ::= <Client:req_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_init_redirect> ::= <Client:req_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_init_err> ::= <Client:req_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_init_closed> ::= <Client:req_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_init_ok> ::= <Client:req_setup_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_init_redirect> ::= <Client:req_setup_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_init_err> ::= <Client:req_setup_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_init_closed> ::= <Client:req_setup_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_init_ok> ::= <Client:req_setup_full> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_init_redirect> ::= <Client:req_setup_full> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_init_err> ::= <Client:req_setup_full> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_full_init_closed> ::= <Client:req_setup_full> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_init_ok> ::= <Client:req_teardown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_init_redirect> ::= <Client:req_teardown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_init_err> ::= <Client:req_teardown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_init_closed> ::= <Client:req_teardown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_without_setup_init_ok> ::= <Client:req_play_without_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_without_setup_init_redirect> ::= <Client:req_play_without_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_without_setup_init_err> ::= <Client:req_play_without_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_without_setup_init_closed> ::= <Client:req_play_without_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_init_ok> ::= <Client:req_play_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_init_redirect> ::= <Client:req_play_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_init_err> ::= <Client:req_play_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_unknown_session_init_closed> ::= <Client:req_play_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_init_ok> ::= <Client:req_pause_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_init_redirect> ::= <Client:req_pause_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_init_err> ::= <Client:req_pause_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_unknown_session_init_closed> ::= <Client:req_pause_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_init_ok> ::= <Client:req_record_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_init_redirect> ::= <Client:req_record_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_init_err> ::= <Client:req_record_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_unknown_session_init_closed> ::= <Client:req_record_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_init_ok> ::= <Client:req_teardown_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_init_redirect> ::= <Client:req_teardown_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_init_err> ::= <Client:req_teardown_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_unknown_session_init_closed> ::= <Client:req_teardown_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_init_ok> ::= <Client:req_get_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_init_redirect> ::= <Client:req_get_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_init_err> ::= <Client:req_get_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_get_parameter_unknown_session_init_closed> ::= <Client:req_get_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_init_ok> ::= <Client:req_set_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_init_redirect> ::= <Client:req_set_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_init_err> ::= <Client:req_set_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_set_parameter_unknown_session_init_closed> ::= <Client:req_set_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_ready_ok> ::= <Client:req_play> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_ready_redirect> ::= <Client:req_play> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_ready_err> ::= <Client:req_play> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_ready_closed> ::= <Client:req_play> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_ready_ok> ::= <Client:req_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_ready_redirect> ::= <Client:req_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_ready_err> ::= <Client:req_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_ready_closed> ::= <Client:req_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_ready_ok> ::= <Client:req_setup_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_ready_redirect> ::= <Client:req_setup_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_ready_err> ::= <Client:req_setup_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_ready_closed> ::= <Client:req_setup_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_ready_ok> ::= <Client:req_setup_record_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_ready_redirect> ::= <Client:req_setup_record_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_ready_err> ::= <Client:req_setup_record_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_record_ready_closed> ::= <Client:req_setup_record_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_ready_ok> ::= <Client:req_setup_second_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_second_session> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_ready_redirect> ::= <Client:req_setup_second_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_ready_err> ::= <Client:req_setup_second_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_ready_closed> ::= <Client:req_setup_second_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_narrow_ready_ok> ::= <Client:req_setup_second_narrow> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_second_session> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_narrow_ready_redirect> ::= <Client:req_setup_second_narrow> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_narrow_ready_err> ::= <Client:req_setup_second_narrow> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_second_narrow_ready_closed> ::= <Client:req_setup_second_narrow> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_ready_ok> ::= <Client:req_teardown> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_ready_redirect> ::= <Client:req_teardown> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_ready_err> ::= <Client:req_teardown> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_ready_closed> ::= <Client:req_teardown> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_ready> ::= <Client:req_pause_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_ready_redirect> ::= <Client:req_pause_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_ready_closed> ::= <Client:req_pause_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_ready> ::= <Client:req_teardown_stream_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_ready_redirect> ::= <Client:req_teardown_stream_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_ready_closed> ::= <Client:req_teardown_stream_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_queued_start> ::= <Client:req_play_queued_playing> <TimerControl:timer_start_1>
# RFC 2326
<play_queued_outcome> ::= (<Server:reply_2xx_media> <TimerControl:timer_cancel_1> <state_playing>
    | <Server:reply_err_media> <TimerControl:timer_cancel_1> <state_playing>
    | <Server:reply_3xx_media> <TimerControl:timer_cancel_1> <state_init>
    | <x_frame>* (<x_closed> <TimerControl:timer_cancel_1> | <TimerEvent:timer_expired_1> <state_playing>))
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_playing_ok> ::= <Client:req_pause> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_playing_redirect> ::= <Client:req_pause> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_playing_err> ::= <Client:req_pause> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_playing_closed> ::= <Client:req_pause> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_playing_ok> ::= <Client:req_play_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_playing_redirect> ::= <Client:req_play_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_playing_err> ::= <Client:req_play_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_playing_closed> ::= <Client:req_play_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_playing_ok> ::= <Client:req_setup_change_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_playing_redirect> ::= <Client:req_setup_change_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_playing_err> ::= <Client:req_setup_change_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_playing_closed> ::= <Client:req_setup_change_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_playing_ok> ::= <Client:req_setup_change_narrow_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_playing_redirect> ::= <Client:req_setup_change_narrow_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_playing_err> ::= <Client:req_setup_change_narrow_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_playing_closed> ::= <Client:req_setup_change_narrow_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_playing_ok> ::= <Client:req_teardown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_playing_redirect> ::= <Client:req_teardown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_playing_err> ::= <Client:req_teardown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_playing_closed> ::= <Client:req_teardown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_playing> ::= <Client:req_record_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_playing_redirect> ::= <Client:req_record_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_playing_closed> ::= <Client:req_record_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_playing> ::= <Client:req_teardown_stream_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_playing_redirect> ::= <Client:req_teardown_stream_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_playing_closed> ::= <Client:req_teardown_stream_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_recording_ok> ::= <Client:req_pause_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_recording_redirect> ::= <Client:req_pause_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_recording_err> ::= <Client:req_pause_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_pause_recording_closed> ::= <Client:req_pause_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_recording_ok> ::= <Client:req_record_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_recording_redirect> ::= <Client:req_record_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_recording_err> ::= <Client:req_record_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_record_recording_closed> ::= <Client:req_record_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_recording_ok> ::= <Client:req_setup_change_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_recording_redirect> ::= <Client:req_setup_change_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_recording_err> ::= <Client:req_setup_change_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_recording_closed> ::= <Client:req_setup_change_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_recording_ok> ::= <Client:req_setup_change_narrow_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_recording_redirect> ::= <Client:req_setup_change_narrow_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_recording_err> ::= <Client:req_setup_change_narrow_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_setup_narrow_recording_closed> ::= <Client:req_setup_change_narrow_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_recording_ok> ::= <Client:req_teardown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_2xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_recording_redirect> ::= <Client:req_teardown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_recording_err> ::= <Client:req_teardown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_err_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_recording_closed> ::= <Client:req_teardown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_recording> ::= <Client:req_play_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_recording_redirect> ::= <Client:req_play_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_play_recording_closed> ::= <Client:req_play_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_recording> ::= <Client:req_teardown_stream_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_non_redirect_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_recording_redirect> ::= <Client:req_teardown_stream_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <Server:reply_3xx_media> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_teardown_stream_recording_closed> ::= <Client:req_teardown_stream_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <x_closed> <TimerControl:timer_cancel_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_options_init_silent> ::= <Client:req_options_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_options_headers_init_silent> ::= <Client:req_options_headers_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_describe_init_silent> ::= <Client:req_describe_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_describe_conditional_init_silent> ::= <Client:req_describe_conditional_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_describe_unknown_init_silent> ::= <Client:req_describe_unknown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_get_parameter_init_silent> ::= <Client:req_get_parameter_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_blocksize_init_silent> ::= <Client:req_blocksize_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_set_parameter_init_silent> ::= <Client:req_set_parameter_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_announce_init_silent> ::= <Client:req_announce_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_announce_publish_init_silent> ::= <Client:req_announce_publish_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_extension_init_silent> ::= <Client:req_extension_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_version_init_silent> ::= <Client:req_version_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_auth_init_silent> ::= <Client:req_auth_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_auth_wrong_init_silent> ::= <Client:req_auth_wrong_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_options_close_init_silent> ::= <Client:req_options_close_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_setup_silent> ::= <Client:req_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_setup_record_silent> ::= <Client:req_setup_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_setup_full_silent> ::= <Client:req_setup_full> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_teardown_init_silent> ::= <Client:req_teardown_init> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_play_without_setup_silent> ::= <Client:req_play_without_setup> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_play_unknown_session_silent> ::= <Client:req_play_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_pause_unknown_session_silent> ::= <Client:req_pause_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_record_unknown_session_silent> ::= <Client:req_record_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_teardown_unknown_session_silent> ::= <Client:req_teardown_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_get_parameter_unknown_session_silent> ::= <Client:req_get_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_init_set_parameter_unknown_session_silent> ::= <Client:req_set_parameter_unknown_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_options_ready_silent> ::= <Client:req_options_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_options_headers_ready_silent> ::= <Client:req_options_headers_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_describe_ready_silent> ::= <Client:req_describe_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_describe_conditional_ready_silent> ::= <Client:req_describe_conditional_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_play_unknown_session_ready_silent> ::= <Client:req_play_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_pause_unknown_session_ready_silent> ::= <Client:req_pause_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_record_unknown_session_ready_silent> ::= <Client:req_record_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_teardown_unknown_session_ready_silent> ::= <Client:req_teardown_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_get_parameter_unknown_session_ready_silent> ::= <Client:req_get_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_set_parameter_unknown_session_ready_silent> ::= <Client:req_set_parameter_unknown_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_describe_session_ready_silent> ::= <Client:req_describe_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_announce_session_ready_silent> ::= <Client:req_announce_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_setup_full_session_ready_silent> ::= <Client:req_setup_full_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_describe_unknown_ready_silent> ::= <Client:req_describe_unknown_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_get_parameter_ready_silent> ::= <Client:req_get_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_blocksize_ready_silent> ::= <Client:req_blocksize_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_blocksize_session_ready_silent> ::= <Client:req_blocksize_session_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_set_parameter_ready_silent> ::= <Client:req_set_parameter_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_announce_ready_silent> ::= <Client:req_announce_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_announce_publish_ready_silent> ::= <Client:req_announce_publish_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_extension_ready_silent> ::= <Client:req_extension_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_version_ready_silent> ::= <Client:req_version_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_auth_ready_silent> ::= <Client:req_auth_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_auth_wrong_ready_silent> ::= <Client:req_auth_wrong_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_options_close_ready_silent> ::= <Client:req_options_close_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_play_silent> ::= <Client:req_play> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_record_silent> ::= <Client:req_record> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_setup_again_silent> ::= <Client:req_setup_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_setup_record_again_silent> ::= <Client:req_setup_record_again> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_setup_second_session_silent> ::= <Client:req_setup_second_session> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_setup_second_narrow_silent> ::= <Client:req_setup_second_narrow> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_teardown_silent> ::= <Client:req_teardown> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_pause_ready_silent> ::= <Client:req_pause_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_ready_teardown_stream_ready_silent> ::= <Client:req_teardown_stream_ready> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_options_playing_silent> ::= <Client:req_options_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_options_headers_playing_silent> ::= <Client:req_options_headers_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_describe_playing_silent> ::= <Client:req_describe_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_describe_conditional_playing_silent> ::= <Client:req_describe_conditional_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_play_unknown_session_playing_silent> ::= <Client:req_play_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_pause_unknown_session_playing_silent> ::= <Client:req_pause_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_record_unknown_session_playing_silent> ::= <Client:req_record_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_teardown_unknown_session_playing_silent> ::= <Client:req_teardown_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_get_parameter_unknown_session_playing_silent> ::= <Client:req_get_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_set_parameter_unknown_session_playing_silent> ::= <Client:req_set_parameter_unknown_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_describe_session_playing_silent> ::= <Client:req_describe_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_announce_session_playing_silent> ::= <Client:req_announce_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_setup_full_session_playing_silent> ::= <Client:req_setup_full_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_describe_unknown_playing_silent> ::= <Client:req_describe_unknown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_get_parameter_playing_silent> ::= <Client:req_get_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_blocksize_playing_silent> ::= <Client:req_blocksize_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_blocksize_session_playing_silent> ::= <Client:req_blocksize_session_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_set_parameter_playing_silent> ::= <Client:req_set_parameter_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_announce_playing_silent> ::= <Client:req_announce_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_announce_publish_playing_silent> ::= <Client:req_announce_publish_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_extension_playing_silent> ::= <Client:req_extension_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_version_playing_silent> ::= <Client:req_version_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_auth_playing_silent> ::= <Client:req_auth_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_auth_wrong_playing_silent> ::= <Client:req_auth_wrong_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_options_close_playing_silent> ::= <Client:req_options_close_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_pause_silent> ::= <Client:req_pause> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_play_playing_silent> ::= <Client:req_play_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_setup_change_playing_silent> ::= <Client:req_setup_change_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_setup_change_narrow_playing_silent> ::= <Client:req_setup_change_narrow_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_teardown_playing_silent> ::= <Client:req_teardown_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_record_playing_silent> ::= <Client:req_record_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_playing_teardown_stream_playing_silent> ::= <Client:req_teardown_stream_playing> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_options_recording_silent> ::= <Client:req_options_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_options_headers_recording_silent> ::= <Client:req_options_headers_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_describe_recording_silent> ::= <Client:req_describe_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_describe_conditional_recording_silent> ::= <Client:req_describe_conditional_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_play_unknown_session_recording_silent> ::= <Client:req_play_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_pause_unknown_session_recording_silent> ::= <Client:req_pause_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_record_unknown_session_recording_silent> ::= <Client:req_record_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_teardown_unknown_session_recording_silent> ::= <Client:req_teardown_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_get_parameter_unknown_session_recording_silent> ::= <Client:req_get_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_set_parameter_unknown_session_recording_silent> ::= <Client:req_set_parameter_unknown_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_describe_session_recording_silent> ::= <Client:req_describe_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_announce_session_recording_silent> ::= <Client:req_announce_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_setup_full_session_recording_silent> ::= <Client:req_setup_full_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_describe_unknown_recording_silent> ::= <Client:req_describe_unknown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_get_parameter_recording_silent> ::= <Client:req_get_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_blocksize_recording_silent> ::= <Client:req_blocksize_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_blocksize_session_recording_silent> ::= <Client:req_blocksize_session_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_set_parameter_recording_silent> ::= <Client:req_set_parameter_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_announce_recording_silent> ::= <Client:req_announce_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_announce_publish_recording_silent> ::= <Client:req_announce_publish_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_extension_recording_silent> ::= <Client:req_extension_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_version_recording_silent> ::= <Client:req_version_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_auth_recording_silent> ::= <Client:req_auth_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_auth_wrong_recording_silent> ::= <Client:req_auth_wrong_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_options_close_recording_silent> ::= <Client:req_options_close_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_pause_recording_silent> ::= <Client:req_pause_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_record_recording_silent> ::= <Client:req_record_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_setup_change_recording_silent> ::= <Client:req_setup_change_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_setup_change_narrow_recording_silent> ::= <Client:req_setup_change_narrow_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_teardown_recording_silent> ::= <Client:req_teardown_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_play_recording_silent> ::= <Client:req_play_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>
# RFC 2326 A.1 Client State Machine (exchange: request and reply class)
<x_recording_teardown_stream_recording_silent> ::= <Client:req_teardown_stream_recording> <TimerControl:timer_start_3> <x_late_reply>{0,2} <TimerEvent:timer_expired_3>

# A reply may follow interim replies (7.1.1: 1xx) and, where media flows, interleaved frames (10.12) the server sends on its own initiative
<reply_2xx> ::= <resp_1xx>* <resp_2xx>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_3xx> ::= <resp_1xx>* <resp_3xx>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_err> ::= <resp_1xx>* <resp_err>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_any> ::= <resp_1xx>* <resp_any>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_non_redirect> ::= <resp_1xx>* <resp_non_redirect>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_2xx_second_session> ::= <resp_1xx>* <resp_2xx>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_2xx_media> ::= <prelude_media>* <resp_2xx>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_3xx_media> ::= <prelude_media>* <resp_3xx>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_err_media> ::= <prelude_media>* <resp_err>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_any_media> ::= <prelude_media>* <resp_any>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<reply_non_redirect_media> ::= <prelude_media>* <resp_non_redirect>
# RFC 2326 7.1.1 (1xx before the final reply), 10.12 (frames)
<prelude_media> ::= <resp_1xx> | <interleaved_frame>

# Requests and replies the server starts on its own (Table 2: S->C); the reply each requires is the client's
# TODO: RFC 2326 9.1 - pipelined requests (nearest <req_play>): a second request is sent before the reply to the first arrives, which depends on the time between messages;
#   a reply that arrives while Fandango generates the second request is an unexpected message. A queued PLAY is modeled without pipelining (<x_play_queued_*>).
# TODO: RFC 2326 11.3.5, 12.37 - session timeout (nearest <srv_options>): the idle timeout of a session lasts 60 s by default; the test setup has no clock beyond Fandango's timers, so a session is not left idle.
<srv_options> ::= <method_options> ' ' <uri_options_received> ' ' <rtsp_version> <crlf> <resp_rest>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<srv_get_parameter> ::= <method_get_parameter> ' ' <absolute_uri_received> ' ' <rtsp_version> <crlf> <resp_rest>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<srv_set_parameter> ::= <method_set_parameter> ' ' <absolute_uri_received> ' ' <rtsp_version> <crlf> <resp_rest>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<srv_announce> ::= <method_announce> ' ' <absolute_uri_received> ' ' <rtsp_version> <crlf> <resp_rest>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<srv_extension> ::= <method_other_received> ' ' <absolute_uri_received> ' ' <rtsp_version> <crlf> <resp_rest>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_other_received> ::= r"(?:[A](?:[N](?:[N](?:[O](?:[U](?:[N](?:[C](?:[E](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[D](?:[E](?:[S](?:[C](?:[R](?:[I](?:[B](?:[E](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9AC-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[G](?:[E](?:[T](?:[_](?:[P](?:[A](?:[R](?:[A](?:[M](?:[E](?:[T](?:[E](?:[R](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-LN-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-Z\^`-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[O](?:[P](?:[T](?:[I](?:[O](?:[N](?:[S](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-RT-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[P](?:[A](?:[U](?:[S](?:[E](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[L](?:[A](?:[Y](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-XZ\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-KM-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[R](?:[E](?:[C](?:[O](?:[R](?:[D](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-CE-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[D](?:[I](?:[R](?:[E](?:[C](?:[T](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-SU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABE-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[S](?:[E](?:[T](?:[U](?:[P](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-OQ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[_](?:[P](?:[A](?:[R](?:[A](?:[M](?:[E](?:[T](?:[E](?:[R](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-LN-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^`-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[T](?:[E](?:[A](?:[R](?:[D](?:[O](?:[W](?:[N](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-MO-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-VX-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-CE-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9BCEFH-NQU-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)"
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<srv_redirect> ::= <method_redirect> ' ' <absolute_uri_received> ' ' <rtsp_version> <crlf> <resp_rest>
# 6.1: Request-URI = "*" | absolute_URI; "*" is only for a method that applies to no resource (6.2, OPTIONS)
<uri_options_received> ::= '*' | <absolute_uri_received>
# RFC 2326
<absolute_uri_received> ::= r'[A-Za-z][A-Za-z0-9+.-]*:[^\s]*'
# The client's answer to a request of the server (D.1): positively or negatively. A method it does not support gets 501 (10, Notes on Table 2).
<x_server_request> ::= (<x_server_options> | <x_server_get_parameter> | <x_server_set_parameter> | <x_server_announce> | <x_server_extension>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_server_options> ::= <Server:srv_options> <Client:cli_reply_options>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_server_get_parameter> ::= <Server:srv_get_parameter> <Client:cli_reply_get_parameter>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_server_set_parameter> ::= <Server:srv_set_parameter> <Client:cli_reply_set_parameter>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_server_announce> ::= <Server:srv_announce> <Client:cli_reply_announce>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_server_extension> ::= <Server:srv_extension> <Client:cli_reply_extension>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<x_server_redirect> ::= <Server:srv_redirect> <Client:cli_reply_redirect>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_options> ::= (<cli_reply_ok_options> | <cli_reply_error>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_get_parameter> ::= (<cli_reply_ok_get_parameter> | <cli_reply_error>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_set_parameter> ::= (<cli_reply_ok> | <cli_reply_error>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_announce> ::= (<cli_reply_ok> | <cli_reply_error>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_redirect> ::= (<cli_reply_ok> | <cli_reply_error>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_extension> ::= <cli_reply_501>
# TODO: RFC 2326 7.1.1, 11 - replies of the client to a request of the server (nearest <cli_reply_error>): the status codes are drawn from the shared <code_*> and <code_extension_*> rules of the 4xx and 5xx classes;
#   2xx codes other than 200 and the 3xx class are not sent (a client has nothing to redirect or to create); 401/407 carry a Basic challenge, 405 Allow, 551 Unsupported, as 7.1.1 and 12.40 require.
<cli_reply_ok> ::= <rtsp_version_10> ' ' <code_200> ' OK' <crlf> <h_cseq_echo> <h_session_sent>? <cli_reply_headers> <crlf>
# An OPTIONS reply names the methods the client supports (Public); a GET_PARAMETER reply carries the values asked for
<cli_reply_ok_options> ::= <rtsp_version_10> ' ' <code_200> ' OK' <crlf> <h_cseq_echo> <h_session_sent>? <h_public_sent>? <cli_reply_headers> <crlf>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_ok_get_parameter> ::= <rtsp_version_10> ' ' <code_200> ' OK' <crlf> <h_cseq_echo> <h_session_sent>? <cli_reply_headers> (<crlf> | <parameter_assignment_content>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_error> ::= (<rtsp_version_10> ' ' <cli_status_plain> ' ' <reason_phrase_sent> <crlf> <h_cseq_echo> <h_session_sent>? <cli_reply_headers> <crlf>
    | <rtsp_version_10> ' ' <code_401> ' ' <reason_phrase_sent> <crlf> <h_cseq_echo> <h_www_authenticate_sent> <cli_reply_headers> <crlf>
    | <rtsp_version_10> ' ' <code_405> ' ' <reason_phrase_sent> <crlf> <h_cseq_echo> <h_allow_sent> <cli_reply_headers> <crlf>
    | <rtsp_version_10> ' ' <code_407> ' ' <reason_phrase_sent> <crlf> <h_cseq_echo> <h_proxy_authenticate_sent> <cli_reply_headers> <crlf>
    | <rtsp_version_10> ' ' <code_551> ' ' <reason_phrase_sent> <crlf> <h_cseq_echo> <h_unsupported_sent> <cli_reply_headers> <crlf>)
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cli_reply_501> ::= <rtsp_version_10> ' ' <code_501> ' ' <reason_phrase_sent> <crlf> <h_cseq_echo> <h_session_sent>? <cli_reply_headers> <crlf>
# every 4xx and 5xx code of the shared rules but the ones that need a header of their own (401, 405, 407, 551, above)
<cli_status_plain> ::= (<code_400> | <code_402> | <code_403> | <code_404> | <code_406> | <code_408> | <code_410> | <code_411> | <code_412> | <code_413> | <code_414> | <code_415>
    | <code_451> | <code_452> | <code_453> | <code_454> | <code_455> | <code_456> | <code_457> | <code_458> | <code_459> | <code_460> | <code_461> | <code_462>
    | <code_500> | <code_501> | <code_502> | <code_503> | <code_504> | <code_505> | <code_extension_4xx> | <code_extension_5xx>)
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<reason_phrase_sent> ::= <reason_phrase> := 'Declined'
# Header fields a response may carry besides the ones of the method (7.1.2, 12)
<cli_reply_headers> ::= <h_date_sent>? <h_server_sent>? <h_extension_sent>? <h_connection_other_sent>?
# RFC 2326
<h_server_sent> ::= 'Server: ' <product> <crlf>
# RFC 2326
<h_public_sent> ::= 'Public: ' <public_methods> <crlf>
# RFC 2326
<h_allow_sent> ::= 'Allow: ' <public_methods> <crlf>
# RFC 2326
<public_methods> ::= <method_sent> (',' <ows> <method_sent>){0,3}
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_sent> ::= <token> := random.choice(['OPTIONS', 'GET_PARAMETER', 'SET_PARAMETER', 'ANNOUNCE', 'REDIRECT'])
# RFC 2326
<h_unsupported_sent> ::= 'Unsupported: ' <option_tag_list> <crlf>
# RFC 2326
<h_www_authenticate_sent> ::= 'WWW-Authenticate: ' <challenge_basic> <crlf>
# RFC 2326
<h_proxy_authenticate_sent> ::= 'Proxy-Authenticate: ' <challenge_basic> <crlf>
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<challenge_basic> ::= 'Basic realm=' <quoted_string>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<h_cseq_echo> ::= 'CSeq: ' <cseq_echoed> <crlf>
# RFC 2326 10 Table 2 (requests of the server), 10.12 (frames), 9 (connection)
<cseq_echoed> ::= <cseq_value> := recall_cseq()

# --------------------------------------------------------------------------------------------
# Requests (6): Request-Line, headers, CRLF, body. Methods are case-sensitive (10).
# --------------------------------------------------------------------------------------------
<req_options_init> ::= <req_options>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_close_init> ::= <req_options_close>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_headers_init> ::= <req_options_headers>
# RFC 2326 10.2 DESCRIBE
<req_describe_init> ::= <req_describe>
# RFC 2326 10.2 DESCRIBE
<req_describe_conditional_init> ::= <req_describe_conditional>
# RFC 2326 10.2 DESCRIBE
<req_describe_unknown_init> ::= <req_describe_unknown>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_init> ::= <req_get_parameter>
# RFC 2326
<req_blocksize_init> ::= <req_blocksize>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_init> ::= <req_set_parameter>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_init> ::= <req_announce>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_publish_init> ::= <req_announce_publish>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<req_extension_init> ::= <req_extension>
# RFC 2326 3.1, 6.1 RTSP-Version
<req_version_init> ::= <req_version>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_init> ::= <req_auth>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_wrong_init> ::= <req_auth_wrong>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_session_ready> ::= <req_announce_session>
# RFC 2326 10.4 SETUP
<req_setup_full_session_ready> ::= <req_setup_full_session>
# RFC 2326 10.2 DESCRIBE
<req_describe_session_ready> ::= <req_describe_session>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_ready> ::= <req_options>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_close_ready> ::= <req_options_close>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_headers_ready> ::= <req_options_headers>
# RFC 2326 10.2 DESCRIBE
<req_describe_ready> ::= <req_describe>
# RFC 2326 10.2 DESCRIBE
<req_describe_conditional_ready> ::= <req_describe_conditional>
# RFC 2326 10.2 DESCRIBE
<req_describe_unknown_ready> ::= <req_describe_unknown>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_ready> ::= <req_get_parameter>
# RFC 2326
<req_blocksize_ready> ::= <req_blocksize>
# RFC 2326
<req_blocksize_session_ready> ::= <req_blocksize_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_ready> ::= <req_set_parameter>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_ready> ::= <req_announce>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_publish_ready> ::= <req_announce_publish>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<req_extension_ready> ::= <req_extension>
# RFC 2326 3.1, 6.1 RTSP-Version
<req_version_ready> ::= <req_version>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_ready> ::= <req_auth>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_wrong_ready> ::= <req_auth_wrong>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_session_playing> ::= <req_announce_session>
# RFC 2326 10.4 SETUP
<req_setup_full_session_playing> ::= <req_setup_full_session>
# RFC 2326 10.2 DESCRIBE
<req_describe_session_playing> ::= <req_describe_session>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_playing> ::= <req_options>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_close_playing> ::= <req_options_close>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_headers_playing> ::= <req_options_headers>
# RFC 2326 10.2 DESCRIBE
<req_describe_playing> ::= <req_describe>
# RFC 2326 10.2 DESCRIBE
<req_describe_conditional_playing> ::= <req_describe_conditional>
# RFC 2326 10.2 DESCRIBE
<req_describe_unknown_playing> ::= <req_describe_unknown>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_playing> ::= <req_get_parameter>
# RFC 2326
<req_blocksize_playing> ::= <req_blocksize>
# RFC 2326
<req_blocksize_session_playing> ::= <req_blocksize_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_playing> ::= <req_set_parameter>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_playing> ::= <req_announce>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_publish_playing> ::= <req_announce_publish>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<req_extension_playing> ::= <req_extension>
# RFC 2326 3.1, 6.1 RTSP-Version
<req_version_playing> ::= <req_version>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_playing> ::= <req_auth>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_wrong_playing> ::= <req_auth_wrong>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_session_recording> ::= <req_announce_session>
# RFC 2326 10.4 SETUP
<req_setup_full_session_recording> ::= <req_setup_full_session>
# RFC 2326 10.2 DESCRIBE
<req_describe_session_recording> ::= <req_describe_session>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_recording> ::= <req_options>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_close_recording> ::= <req_options_close>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<req_options_headers_recording> ::= <req_options_headers>
# RFC 2326 10.2 DESCRIBE
<req_describe_recording> ::= <req_describe>
# RFC 2326 10.2 DESCRIBE
<req_describe_conditional_recording> ::= <req_describe_conditional>
# RFC 2326 10.2 DESCRIBE
<req_describe_unknown_recording> ::= <req_describe_unknown>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_recording> ::= <req_get_parameter>
# RFC 2326
<req_blocksize_recording> ::= <req_blocksize>
# RFC 2326
<req_blocksize_session_recording> ::= <req_blocksize_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_recording> ::= <req_set_parameter>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_recording> ::= <req_announce>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce_publish_recording> ::= <req_announce_publish>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<req_extension_recording> ::= <req_extension>
# RFC 2326 3.1, 6.1 RTSP-Version
<req_version_recording> ::= <req_version>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_recording> ::= <req_auth>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_wrong_recording> ::= <req_auth_wrong>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_unknown_session_ready> ::= <req_play_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause_unknown_session_ready> ::= <req_pause_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record_unknown_session_ready> ::= <req_record_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_unknown_session_ready> ::= <req_teardown_unknown_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_unknown_session_ready> ::= <req_get_parameter_unknown_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_unknown_session_ready> ::= <req_set_parameter_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_unknown_session_playing> ::= <req_play_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause_unknown_session_playing> ::= <req_pause_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record_unknown_session_playing> ::= <req_record_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_unknown_session_playing> ::= <req_teardown_unknown_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_unknown_session_playing> ::= <req_get_parameter_unknown_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_unknown_session_playing> ::= <req_set_parameter_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_unknown_session_recording> ::= <req_play_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause_unknown_session_recording> ::= <req_pause_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record_unknown_session_recording> ::= <req_record_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_unknown_session_recording> ::= <req_teardown_unknown_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_unknown_session_recording> ::= <req_get_parameter_unknown_session>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_unknown_session_recording> ::= <req_set_parameter_unknown_session>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_stream_ready> ::= <req_teardown_stream>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_stream_playing> ::= <req_teardown_stream>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_stream_recording> ::= <req_teardown_stream>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_queued_playing> ::= <req_play_queued>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_init> ::= <req_teardown>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause_ready> ::= <req_pause>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_playing> ::= <req_play>
# RFC 2326 10.4 SETUP
<req_setup_change_playing> ::= <req_setup_change>
# RFC 2326 10.4 SETUP
<req_setup_change_narrow_playing> ::= <req_setup_change_narrow>
# RFC 2326 10.4 SETUP
<req_setup_change_narrow_recording> ::= <req_setup_change_narrow>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_playing> ::= <req_teardown>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record_playing> ::= <req_record>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause_recording> ::= <req_pause>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record_recording> ::= <req_record>
# RFC 2326 10.4 SETUP
<req_setup_change_recording> ::= <req_setup_change>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_recording> ::= <req_teardown>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_recording> ::= <req_play>

# OPTIONS (10.1): may be issued at any time, with the request URI "*" for the server itself (6.2)
<req_options> ::= <method_options> ' ' <uri_options> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <crlf>
# Header fields that may be in any request (6.2, 7.1.2, 8.1, 12): sent in this one exchange, in every state
<req_options_headers> ::= (<method_options> ' ' <uri_options> ' ' <rtsp_version_10> <crlf> <h_cseq_sent>
    <h_require_sent>? <h_proxy_require_sent>? <h_timestamp_sent>? <h_user_agent_sent>? <h_from_sent>? <h_referer_sent>?
    <h_accept_language_sent>? <h_bandwidth_sent>? <h_date_sent>? <h_via_sent>? <h_proxy_authorization_sent>? <h_extension_sent>? <h_connection_other_sent>? <crlf>)

# Connection: close (RFC 9112 9.6): the server closes the connection after the reply
<req_options_close> ::= <method_options> ' ' <uri_options> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_connection_close_sent> <crlf>
# RFC 2326 10.1 OPTIONS, 6.2 (Request-URI "*")
<h_connection_close_sent> ::= 'Connection:' <connection_close_value> <crlf>
# TODO: RFC 9110 7.6.1, 5.6.1 - Connection option lists (nearest <connection_close_value>): the value is the shared list rule <token_list> (elements <ws>? <token>? <ws>?, separated by commas) with one element "close"
#   in any of its 32 casings, none to two other elements before it and after it (some of them empty), and whitespace of spaces and tabs around every element or none at all (obs-fold, a line break inside the value, is left out:
#   the tested servers answer a folded header with 400 and close the connection). Lists of more than three elements and quoted values are left out; other option names come from five fixed tokens (<connection_other_option>).
#   A server either closes after the reply or keeps the connection; both are accepted (<state_closing>).
<connection_close_value> ::= (<connection_elem_other> ','){0,2} <connection_elem_close> (',' <connection_elem_other>){0,2}
# RFC 2326
<connection_elem_close> ::= <ws_sent>? <close_option> <ws_sent>?
# RFC 2326
<connection_elem_other> ::= <ws_sent>? (<connection_other_option> <ws_sent>?)?
# RFC 2326
<ws_sent> ::= r'[ \t]+'
# 15.1/RFC 9110 7.6.1: connection-option = token, compared case-insensitively; "close" in each of its 32 casings
<close_option> ::= ('c' | 'C') ('l' | 'L') ('o' | 'O') ('s' | 'S') ('e' | 'E')
# RFC 2326
<connection_other_option> ::= <token> := random.choice(['keep-alive', 'Keep-Alive', 'upgrade', 'x-foo', 'X-Bar-1'])

# RFC 2326
<h_connection_other_sent> ::= 'Connection:' <connection_elem_other> (',' <connection_elem_other>){0,2} <crlf>

# DESCRIBE (10.2)
<req_describe> ::= (<method_describe> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_accept_sent>?
    <h_accept_encoding_sent>? <h_accept_language_sent>? <h_blocksize_sent>? <crlf>)
# DESCRIBE inside a session (12 Table 3: Session and Blocksize are valid for all methods but SETUP/OPTIONS and OPTIONS/TEARDOWN)
<req_describe_session> ::= (<method_describe> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_accept_sent>? <h_accept_encoding_sent>? <h_accept_language_sent>? <h_blocksize_sent>? <crlf>)
# RFC 2326 10.2 DESCRIBE
<req_describe_conditional> ::= (<method_describe> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_accept_sent>?
    <h_accept_encoding_sent>? <h_if_modified_since_sent> <h_if_match_sent>? <crlf>)
# RFC 2326 10.2 DESCRIBE
<req_describe_unknown> ::= <method_describe> ' ' <unknown_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_accept_sent> <crlf>

# ANNOUNCE (10.3): posts a presentation description
<req_announce_session> ::= (<method_announce> ' ' <publish_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_date_sent>? <h_expires_sent>? <h_last_modified_sent>? <sdp_content_any>)
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<req_announce> ::= (<method_announce> ' ' <publish_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent>
    <h_date_sent>? <h_expires_sent>? <h_last_modified_sent>? <sdp_content_any>)
# A body with a content coding (12.12, 8.1): the coded octets come from the plain description by a converter pair (gzip, deflate)
<sdp_content_any> ::= <sdp_content> | <sdp_content_gzip> | <sdp_content_deflate>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<sdp_content_gzip> ::= 'Content-Type: application/sdp' <crlf> <h_content_base_any_sent>? <h_content_location_any_sent>? 'Content-Encoding: gzip' <crlf> 'Content-Length: ' <content_length_sent> <crlf> <crlf> <sdp_gzip>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_gzip> ::= <body_octet>+ := gzip_encode(<sdp_gzip_plain>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_gzip_plain> ::= <sdp_sent> := gzip_decode(<sdp_gzip>)
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<sdp_content_deflate> ::= 'Content-Type: application/sdp' <crlf> <h_content_base_any_sent>? <h_content_location_any_sent>? 'Content-Encoding: deflate' <crlf> 'Content-Length: ' <content_length_sent> <crlf> <crlf> <sdp_deflate>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_deflate> ::= <body_octet>+ := deflate_encode(<sdp_deflate_plain>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_deflate_plain> ::= <sdp_sent> := deflate_decode(<sdp_deflate>)
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_assignment_content_gzip> ::= 'Content-Type: text/parameters' <crlf> 'Content-Encoding: gzip' <crlf> 'Content-Length: ' <content_length_sent> <crlf> <crlf> <parameter_gzip>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_gzip> ::= <body_octet>+ := gzip_encode(<parameter_gzip_plain>)
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_gzip_plain> ::= <parameter_assignments> := gzip_decode(<parameter_gzip>)
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<sdp_content> ::= 'Content-Type: application/sdp' <crlf> <h_content_base_any_sent>? <h_content_location_any_sent>? <h_content_encoding_sent>? <h_content_language_sent>? 'Content-Length: ' <content_length_sent> <crlf> <crlf> <sdp_sent>
# TODO: RFC 2326 C.1 - descriptions the narrowed ANNOUNCE leaves out (nearest <sdp_publish>): codecs other than H.264 and PCMU, multicast c=, t=, b=, a=range and a=etag lines, session-level aggregate and '*' controls, gzip/deflate bodies;
#   they are sent by <req_announce>; the tested servers answer them with 400, 406 or 415 and close the connection, so the narrowing is the way to the deeper states (Ready, Recording).
# On the way to RECORD (deeper states) the tested servers accept an ANNOUNCE with a description of H.264 and/or PCMU with the Content-Base of the presentation and the controls of their streams
# (other descriptions are refused with 400 or 406, which <req_announce> sends): this narrowing of <sdp_sent> is an exchange of its own.
<req_announce_publish> ::= (<method_announce> ' ' <publish_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <sdp_content_publish>)
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<sdp_content_publish> ::= 'Content-Type: application/sdp' <crlf> <h_content_base_sent> 'Content-Length: ' <content_length_sent> <crlf> <crlf> <sdp_publish>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_publish> ::= 'v=0' <crlf> <sdp_o_sent> 's=' <sdp_name_sent> <crlf> 'c=IN IP4 0.0.0.0' <crlf> 't=0 0' <crlf> <sdp_publish_media>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_publish_media> ::= (<sdp_video_h264> <sdp_pub_control_0> | <sdp_audio_pcmu> <sdp_pub_control_0> | <sdp_video_h264> <sdp_pub_control_0> <sdp_audio_pcmu> <sdp_pub_control_1>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_pub_control_0> ::= 'a=control:' ('streamid=0' | <publish_url> '/streamid=0') <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_pub_control_1> ::= 'a=control:' ('streamid=1' | <publish_url> '/streamid=1') <crlf>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_names_content> ::= 'Content-Type: text/parameters' <crlf> <h_content_encoding_sent>? <h_content_language_sent>? 'Content-Length: ' <content_length_sent> <crlf> <crlf> <parameter_names>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_assignment_content> ::= 'Content-Type: text/parameters' <crlf> <h_content_encoding_sent>? <h_content_language_sent>? 'Content-Length: ' <content_length_sent> <crlf> <crlf> <parameter_assignments>
# RFC 2326
<content_length_sent> ::= <digits>

# SETUP (10.4): the transport parameters are always indicated (C11). Header fields that only SETUP takes (Table 3) are optional in every form.
<setup_extra_headers> ::= <h_cache_control_sent>? <h_blocksize_sent>? <h_if_modified_since_sent>? <h_if_match_sent>? <h_conference_sent>?
# RFC 2326 10.4 SETUP
<req_setup> ::= (<method_setup> ' ' <setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_sent> <setup_extra_headers> <crlf>)
# RFC 2326 10.4 SETUP
<req_setup_record> ::= <method_setup> ' ' <publish_setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_record_sent> <setup_extra_headers> <crlf>
# RFC 2326 10.4 SETUP
<req_setup_full> ::= <method_setup> ' ' <setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_any_sent> <setup_extra_headers> <crlf>
# RFC 2326 10.4 SETUP
<req_setup_full_session> ::= <method_setup> ' ' <setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_any_sent> <h_session_sent> <setup_extra_headers> <crlf>
# The next stream of an announced presentation: RECORD needs every announced stream set up (10.11)
<req_setup_record_again> ::= <method_setup> ' ' <publish_setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_record_sent> <h_session_sent> <setup_extra_headers> <crlf>
# RFC 2326 10.4 SETUP
<req_setup_again> ::= <method_setup> ' ' <setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_sent> <h_session_sent> <setup_extra_headers> <crlf>
# A change of the transport of the stream already set up names that stream (10.4); the whole Transport rule is sent, as the state does not change
<req_setup_second_session> ::= (<method_setup> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_any_sent> <setup_extra_headers> <crlf>)
# RFC 2326 10.4 SETUP
<req_setup_change> ::= (<method_setup> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_any_sent> <h_session_sent> <setup_extra_headers> <crlf>)
# The same two requests with the Transport the tested servers accept (the whole rule above is refused by them with 461 or 400)
<req_setup_second_narrow> ::= (<method_setup> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_sent> <setup_extra_headers> <crlf>)
# RFC 2326 10.4 SETUP
<req_setup_change_narrow> ::= (<method_setup> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_transport_sent> <h_session_sent> <setup_extra_headers> <crlf>)
# RFC 2326 10.4 SETUP
<setup_url_same> ::= <rtsp_scheme> '://' <authority> <setup_path_same>
# RFC 2326 10.4 SETUP
<setup_path_same> ::= <abs_path> := recall_setup_path()
where forall <r> in <reply_2xx_second_session>: new_session_differs(<r>)
where forall <u> in <setup_url_same>: <u>.<setup_path_same> == last_setup_path_before(<u>)

# PLAY (10.5), PAUSE (10.6), RECORD (10.11), TEARDOWN (10.7)
<req_play> ::= (<method_play> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_range_play_sent>? <h_scale_sent>? <h_speed_sent>? <h_blocksize_sent>? <crlf>
    | <method_play> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_range_play_sent>? <h_scale_sent>? <h_speed_sent>? <h_blocksize_sent>? <crlf>)
# A PLAY with a finite range, sent while the previous PLAY runs (10.5: queued behind it)
<req_play_queued> ::= (<method_play> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_range_queued_sent> <crlf>
    | <method_play> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_range_queued_sent> <crlf>)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<h_range_queued_sent> ::= 'Range: ' <range_queued> <crlf>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<range_queued> ::= 'npt=' <npt_finite> | 'npt=' <npt_hhmmss_finite> | 'npt=' <npt_fraction_finite> | 'clock=' <utc_finite>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause> ::= (<method_pause> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_range_pause_sent>? <crlf>
    | <method_pause> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_range_pause_sent>? <crlf>)
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record> ::= (<method_record> ' ' <publish_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    <h_range_record_sent>? <h_scale_sent>? <crlf>
    | <method_record> ' ' <publish_setup_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_range_record_sent>? <crlf>
    | <method_record> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_range_record_sent>? <crlf>)
# TEARDOWN of the presentation URL ends the session (10.7); of a stream URL it stops that stream only and the session stays
<req_teardown> ::= <method_teardown> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <crlf>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_stream> ::= <method_teardown> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <crlf>

# Blocksize (12.7, Table 3) is valid in all methods but OPTIONS and TEARDOWN: one exchange of its own carries it, outside and inside a session
<req_blocksize> ::= <method_get_parameter> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_blocksize_sent> <crlf>
# RFC 2326
<req_blocksize_session> ::= <method_get_parameter> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_blocksize_sent> <crlf>

# GET_PARAMETER (10.8), SET_PARAMETER (10.9)
# Accept and Accept-Encoding are valid for the entity methods DESCRIBE and GET_PARAMETER (12.1, 12.2, Table 3)
<req_get_parameter> ::= (<method_get_parameter> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_accept_sent>? <h_accept_encoding_sent>? <crlf>
    | <method_get_parameter> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_accept_sent>? <h_accept_encoding_sent>? <crlf>
    | <method_get_parameter> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent> <h_accept_sent>? <h_accept_encoding_sent>? <crlf>
    | <method_get_parameter> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
      <parameter_names_content>)
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter> ::= (<method_set_parameter> ' ' <presentation_url_recalled> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_sent>
    (<parameter_assignment_content> | <parameter_assignment_content_gzip>)
    | <method_set_parameter> ' ' <setup_url_same> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> (<parameter_assignment_content> | <parameter_assignment_content_gzip>))
# TODO: RFC 2326 10.8, 10.9 - parameter names and values with a meaning (nearest <parameter_name>): the method is loosely defined by the RFC ("left to the implementation"); free values are sent.
<parameter_names> ::= (<parameter_name> <crlf>){1,3}
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_assignments> ::= <parameter_assignment>{1,3}
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_assignment> ::= <parameter_name> ': ' <parameter_value> <crlf>
# TODO: RFC 2326 10.9 - a SET_PARAMETER that sets a transport parameter (nearest <parameter_assignment>): 10.9 says transport parameters "MUST only be set with the SETUP command", so a request that sets one breaks the MUST and is not sent;
#   the RFC defines no refusal for it. The server that sends one is rejected on the received side (<srv_set_parameter>, no_transport_parameters).
# Transport parameters are set with SETUP only (10.9): no name of the Transport header or of one of its parameters is sent
<parameter_name> ::= r'(?:[Aa](?:[Pp](?:[Pp](?:[Ee](?:[Nn](?:[Dd](?:[_a-z][_a-z]*)|[_a-ce-z][_a-z]*|)|[_a-mo-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-oq-z][_a-z]*|)|[_a-oq-z][_a-z]*|)|[Cc](?:[Ll](?:[Ii](?:[Ee](?:[Nn](?:[Tt](?:[_](?:[Pp](?:[Oo](?:[Rr](?:[Tt](?:[_a-z][_a-z]*)|[_a-su-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-np-z][_a-z]*|)|[_a-oq-z][_a-z]*|)|[a-z][_a-z]*|)|[_a-su-z][_a-z]*|)|[_a-mo-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-hj-z][_a-z]*|)|[_a-km-z][_a-z]*|)|[Dd](?:[Ee](?:[Ss](?:[Tt](?:[Ii](?:[Nn](?:[Aa](?:[Tt](?:[Ii](?:[Oo](?:[Nn](?:[_a-z][_a-z]*)|[_a-mo-z][_a-z]*|)|[_a-np-z][_a-z]*|)|[_a-hj-z][_a-z]*|)|[_a-su-z][_a-z]*|)|[_b-z][_a-z]*|)|[_a-mo-z][_a-z]*|)|[_a-hj-z][_a-z]*|)|[_a-su-z][_a-z]*|)|[_a-rt-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[Ii](?:[Nn](?:[Tt](?:[Ee](?:[Rr](?:[Ll](?:[Ee](?:[Aa](?:[Vv](?:[Ee](?:[Dd](?:[_a-z][_a-z]*)|[_a-ce-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-uw-z][_a-z]*|)|[_b-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-km-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-su-z][_a-z]*|)|[_a-mo-z][_a-z]*|)|[Ll](?:[Aa](?:[Yy](?:[Ee](?:[Rr](?:[Ss](?:[_a-z][_a-z]*)|[_a-rt-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-xz][_a-z]*|)|[_b-z][_a-z]*|)|[Mm](?:[Oo](?:[Dd](?:[Ee](?:[_a-z][_a-z]*)|[_a-df-z][_a-z]*|)|[_a-ce-z][_a-z]*|)|[Uu](?:[Ll](?:[Tt](?:[Ii](?:[Cc](?:[Aa](?:[Ss](?:[Tt](?:[_a-z][_a-z]*)|[_a-su-z][_a-z]*|)|[_a-rt-z][_a-z]*|)|[_b-z][_a-z]*|)|[_abd-z][_a-z]*|)|[_a-hj-z][_a-z]*|)|[_a-su-z][_a-z]*|)|[_a-km-z][_a-z]*|)|[_a-np-tv-z][_a-z]*|)|[Pp](?:[Oo](?:[Rr](?:[Tt](?:[_a-z][_a-z]*)|[_a-su-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-np-z][_a-z]*|)|[Ss](?:[Ee](?:[Rr](?:[Vv](?:[Ee](?:[Rr](?:[_](?:[Pp](?:[Oo](?:[Rr](?:[Tt](?:[_a-z][_a-z]*)|[_a-su-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-np-z][_a-z]*|)|[_a-oq-z][_a-z]*|)|[a-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-df-z][_a-z]*|)|[_a-uw-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[Oo](?:[Uu](?:[Rr](?:[Cc](?:[Ee](?:[_a-z][_a-z]*)|[_a-df-z][_a-z]*|)|[_abd-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-tv-z][_a-z]*|)|[Ss](?:[Rr](?:[Cc](?:[_a-z][_a-z]*)|[_abd-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-df-np-rt-z][_a-z]*|)|[Tt](?:[Rr](?:[Aa](?:[Nn](?:[Ss](?:[Pp](?:[Oo](?:[Rr](?:[Tt](?:[_a-z][_a-z]*)|[_a-su-z][_a-z]*|)|[_a-qs-z][_a-z]*|)|[_a-np-z][_a-z]*|)|[_a-oq-z][_a-z]*|)|[_a-rt-z][_a-z]*|)|[_a-mo-z][_a-z]*|)|[_b-z][_a-z]*|)|[Tt](?:[Ll](?:[_a-z][_a-z]*)|[_a-km-z][_a-z]*|)|[_a-qsu-z][_a-z]*|)|[Uu](?:[Nn](?:[Ii](?:[Cc](?:[Aa](?:[Ss](?:[Tt](?:[_a-z][_a-z]*)|[_a-su-z][_a-z]*|)|[_a-rt-z][_a-z]*|)|[_b-z][_a-z]*|)|[_abd-z][_a-z]*|)|[_a-hj-z][_a-z]*|)|[_a-mo-z][_a-z]*|)|[_be-hjknoqrv-z][_a-z]*)'
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<parameter_value> ::= r'[a-z0-9_.]{1,16}'

# Requests with a session that only an earlier session could have created (12.37): refused with 454
# An object that needs no SETUP (multicast): the state machine starts at Ready (A.1, A.2)
<req_play_without_setup> ::= (<method_play> ' ' <play_target_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent>
    <h_range_play_sent>? <h_scale_sent>? <h_speed_sent>? <h_blocksize_sent>? <crlf>)
# the object that needs no SETUP: PLAY names the presentation, the aggregate control URL of a description or a stream (10.5, C.1.1)
<play_target_url> ::= <presentation_url> | <presentation_url_recalled> | <setup_url>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_play_unknown_session> ::= <method_play> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_unknown> <crlf>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_pause_unknown_session> ::= <method_pause> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_unknown> <crlf>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_record_unknown_session> ::= <method_record> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_unknown> <crlf>
# RFC 2326 10.5-10.7, 10.11 (PLAY, PAUSE, TEARDOWN, RECORD)
<req_teardown_unknown_session> ::= <method_teardown> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_unknown> <crlf>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_get_parameter_unknown_session> ::= <method_get_parameter> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_unknown> <crlf>
# RFC 2326 10.8 GET_PARAMETER, 10.9 SET_PARAMETER
<req_set_parameter_unknown_session> ::= (<method_set_parameter> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_session_unknown>
    <parameter_assignment_content>)

# An extension method (6.1, 10): a server that does not understand it answers 501
<req_extension> ::= <extension_method> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <crlf>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<extension_method> ::= <method_xtest> | <method_xping> | <method_foobar> | <method_dummy_test>
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_xtest> ::= 'XTEST'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_xping> ::= 'X-PING'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_foobar> ::= 'FOOBAR'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_dummy_test> ::= 'DUMMY_TEST'
# Another RTSP version than 1.0 (3.1)
<req_version> ::= <method_options> ' ' <uri_options> ' ' <rtsp_version_other> <crlf> <h_cseq_sent> <crlf>
# TODO: RFC 2326 3.1 - RTSP-Version values: a version other than 1.0 is chosen from the major numbers 0, 1, 2, 3, 10, 99 and the minor numbers 0, 1, 2, 9, 10, 00 (leading zeros included); servers answer 505 or tolerate it.
<rtsp_version_other> ::= <rtsp_version> := other_rtsp_version()
# Credentials (RFC 9110 11.4): the accepting request sends the configured ones
<req_auth> ::= (<method_describe> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_accept_sent>
    <h_authorization_valid> <crlf>)
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<req_auth_wrong> ::= (<method_describe> ' ' <presentation_url> ' ' <rtsp_version_10> <crlf> <h_cseq_sent> <h_accept_sent>
    <h_authorization_wrong> <crlf>)

# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_options> ::= 'OPTIONS'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_describe> ::= 'DESCRIBE'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_announce> ::= 'ANNOUNCE'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_setup> ::= 'SETUP'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_play> ::= 'PLAY'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_pause> ::= 'PAUSE'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_teardown> ::= 'TEARDOWN'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_get_parameter> ::= 'GET_PARAMETER'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_set_parameter> ::= 'SET_PARAMETER'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_record> ::= 'RECORD'
# RFC 2326 6.1 Request-Line (Method, extension-method)
<method_redirect> ::= 'REDIRECT'

# Request-URI = "*" | absolute_URI (6.1); the URL of RTSP (3.2); host and port from the test setup
<uri_options> ::= '*' | <presentation_url>
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<presentation_url> ::= <rtsp_scheme> '://' <authority> <target_path>
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<presentation_url_recalled> ::= <rtsp_scheme> '://' <authority> <presentation_path_recalled>
# RFC 2326 10.4 SETUP
<setup_url> ::= <rtsp_scheme> '://' <authority> <setup_path>
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<publish_url> ::= <rtsp_scheme> '://' <authority> <publish_path>
# The stream a SETUP or RECORD names is the one of the description announced earlier in the session (C.1.1)
<publish_setup_url> ::= <rtsp_scheme> '://' <authority> <publish_setup_path>
# RFC 2326 10.4 SETUP
<publish_setup_path> ::= <abs_path> := publish_default_path()
where forall <u> in <publish_setup_url>: <u>.<publish_setup_path> == announced_stream_path_before(<u>)
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<unknown_url> ::= <rtsp_scheme> '://' <authority> '/' <unknown_name>
# TODO: RFC 2326 3.2, 16 - the schemes rtspu (RTSP over UDP) and rtsps/TLS (nearest <rtsp_scheme>): both change the transport of the control connection (UDP datagrams, TLS records of RFC 8446 on their own port);
#   each is a server setup of its own with a matching endpoint, none of the three servers is set up with one.
<rtsp_scheme> ::= 'rtsp'
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<authority> ::= r'[A-Za-z0-9.:\[\]-]+' := RTSP_AUTHORITY
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<target_path> ::= <abs_path> := pick_target()
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<publish_path> ::= <abs_path> := pick_publish_target()
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<presentation_path_recalled> ::= <abs_path> := recall_presentation_path()
where forall <u> in <presentation_url_recalled>: <u>.<presentation_path_recalled> == presentation_path_before(<u>)
# RFC 2326 10.4 SETUP
<setup_path> ::= <abs_path> := recall_setup_path()
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<unknown_name> ::= r'[a-z]{3,10}'
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<abs_path> ::= r'(/[A-Za-z0-9._~=!$&()*+,;:@%-]*)+'
# RFC 2326 3.1, 6.1 RTSP-Version
<rtsp_version_10> ::= <rtsp_version> := 'RTSP/1.0'
# RFC 2326 3.1, 6.1 RTSP-Version
<rtsp_version> ::= 'RTSP/' r'[0-9]+' '.' r'[0-9]+'

# --------------------------------------------------------------------------------------------
# Header fields that Fandango sends
# --------------------------------------------------------------------------------------------
# CSeq (12.17): one more than the last request
# TODO: RFC 2326 9.2, 12.17 - a request resent without acknowledgement keeps its CSeq (nearest <h_cseq_sent>): the resend exists only over an unreliable
#   transport (TCP forbids it in 9.2); every server endpoint of the test setup is TCP, the same messages over UDP need a server setup of their own with a UDP control endpoint.
<h_cseq_sent> ::= 'CSeq: ' <cseq_next> <crlf>
# RFC 2326 12.17 CSeq
<cseq_next> ::= <cseq_value> := next_cseq()
# Session (12.37): the identifier of the SETUP reply, sent without the timeout parameter (C9)
# A reply without a Session header names a stream identified by other means (dynamic URLs, 12.37): the requests that follow carry none
<h_session_sent> ::= <session_line>{session_count()}
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<session_line> ::= 'Session: ' <session_recalled> <crlf>
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<session_recalled> ::= <session_id> := recall_session()
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<h_session_unknown> ::= 'Session: ' <session_id> <crlf>
# Accept (12.1), Accept-Encoding, Accept-Language (12.2, 12.3)
# TODO: RFC 2326 12.1-12.3 (HTTP: RFC 9110 12.5.1-12.5.4, 12.4.2) - Accept, Accept-Encoding and Accept-Language lists (nearest <accept_value>): the lists of the formal grammar are sent with one to four items, the weight with OWS around ";" as sent by <ows> (one space);
#   media types, subtypes and codings are drawn from short lists of tokens by generators on the leaf tokens (<media_type_token>, <media_subtype_token>, <coding_token>), language subtags are random alphanumerics;
#   longer lists, empty list elements and the tab as OWS are left out (the servers pick a body or a language from the first items; no other behaviour depends on the length).
<h_accept_sent> ::= 'Accept: ' <accept_value> <crlf>
# RFC 2326
<accept_value> ::= <accept_item> (',' <ows> <accept_item>){0,3}
# RFC 2326
<accept_item> ::= <media_range> <weight>?
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<media_range> ::= <media_type_token> '/' <media_subtype_token> <media_range_param>{0,2}
# RFC 2326 12.16 Content-Type (RFC 9110 8.3.1)
<media_type_token> ::= <token> := random.choice(['application', 'application', '*', 'text', 'video', 'audio', 'x-test'])
# RFC 2326
<media_subtype_token> ::= <token> := random.choice(['sdp', 'sdp', '*', 'rtsl', 'mheg', 'parameters', 'x-test', 'octet-stream'])
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<media_range_param> ::= <ows> ';' <ows> <media_range_param_name> '=' (<token> | <quoted_string>)
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<media_range_param_name> ::= r"(?:[Qq](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-PR-Z\^-pr-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)"
# weight = OWS ";" OWS "q=" qvalue; qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
<weight> ::= <ows> ';' <ows> 'q=' <qvalue>
# RFC 2326
<qvalue> ::= ('0' ('.' <qdigit>{0,3})? | '1' ('.' '0'{0,3})?)
# RFC 2326
<qdigit> ::= r'[0-9]'
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<h_accept_encoding_sent> ::= 'Accept-Encoding: ' <accept_encoding_value> <crlf>
# RFC 2326
<accept_encoding_value> ::= <coding_item> (',' <ows> <coding_item>){0,3}
# RFC 2326
<coding_item> ::= <coding_token> <weight>?
# RFC 2326
<coding_token> ::= <token> := random.choice(['gzip', 'identity', 'deflate', '*', 'compress', 'x-gzip', 'br'])
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<h_accept_language_sent> ::= 'Accept-Language: ' <language_item> (',' <ows> <language_item>){0,3} <crlf>
# language-range = (1*8ALPHA *("-" 1*8alphanum)) / "*"
<language_item> ::= <language_range> <weight>?
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<language_range> ::= (r'[A-Za-z]{1,8}' ('-' r'[A-Za-z0-9]{1,8}'){0,3} | '*')
# If-Modified-Since (12.23)
<h_if_modified_since_sent> ::= 'If-Modified-Since: ' <imf_fixdate> <crlf>
# Require, Proxy-Require (12.32, 12.27, 3.8)
<h_require_sent> ::= 'Require: ' <option_tag_list> <crlf>
# RFC 2326 12.32 Require, 12.27 Proxy-Require, 3.8 Option Tags
<h_proxy_require_sent> ::= 'Proxy-Require: ' <option_tag_list> <crlf>
# RFC 2326 12.32 Require, 12.27 Proxy-Require, 3.8 Option Tags
<option_tag_list> ::= <option_tag> (',' <option_tag>){0,2}
# RFC 2326 12.32 Require, 12.27 Proxy-Require, 3.8 Option Tags
<option_tag> ::= r'[a-z]{2,8}\.[a-z]{2,8}\.[a-z]{2,8}'
# Timestamp (12.38), User-Agent, From, Referer, Bandwidth (12.6), Date, Via
<h_timestamp_sent> ::= 'Timestamp: ' <timestamp_number> <crlf>
# RFC 2326 12.41 User-Agent, 12.20 From, 12.30 Referer, 12.43 Via, 8.1 extension-header
<h_user_agent_sent> ::= 'User-Agent: ' <product> <crlf>
# RFC 2326 12.41 User-Agent, 12.20 From, 12.30 Referer, 12.43 Via, 8.1 extension-header
<product> ::= <token> '/' <token>
# TODO: RFC 2326 12.20, 12.30, 12.41, 12.43 - shapes of From, Referer, User-Agent and Via (nearest <h_from_sent>, <h_referer_sent>, <h_user_agent_sent>, <h_via_sent>): servers store or ignore these
#   informational headers; one shape of each (mailbox, absolute http URI, product, protocol and host) is sent; comments, product lists and Via chains are left out.
<h_from_sent> ::= 'From: ' <mailbox> <crlf>
# RFC 2326 12.41 User-Agent, 12.20 From, 12.30 Referer, 12.43 Via, 8.1 extension-header
<mailbox> ::= r'[a-z]{1,8}' '@' r'[a-z]{2,8}' '.' r'[a-z]{2,3}'
# RFC 2326 12.41 User-Agent, 12.20 From, 12.30 Referer, 12.43 Via, 8.1 extension-header
<h_referer_sent> ::= 'Referer: http://' r'[a-z]{2,8}' '.example/' r'[a-z]{1,8}' <crlf>
# RFC 2326 12.6 Bandwidth
<h_bandwidth_sent> ::= 'Bandwidth: ' <digits> <crlf>
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<h_date_sent> ::= 'Date: ' <imf_fixdate> <crlf>
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<h_expires_sent> ::= 'Expires: ' (<imf_fixdate> | <expires_invalid>) <crlf>
# 12.19: a value in any other format, "0" included, counts as already expired
<expires_invalid> ::= '0' | r'[a-z]{3,8}'
# TODO: RFC 2326 12.24, RFC 9110 5.6.7 - the date of Last-Modified (nearest <h_last_modified_sent>): a date in the past (years 1990-2023, days 01-28 of every month) in each of the three HTTP-date formats, built from the parts of the shared date rules with the weekday
#   computed from the date (an equality); a later date is left out because it could not be earlier than Date (C32), and so are the days 29-31.
<h_last_modified_sent> ::= 'Last-Modified: ' (<imf_fixdate_past> | <rfc850_date_past> | <asctime_date_past>) <crlf>
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<imf_fixdate_past> ::= <day_name> ',' ' ' <day_of_month_past> ' ' <month> ' ' <year4_past> ' ' <time_of_day> ' ' 'GMT'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<rfc850_date_past> ::= <day_name_long> ',' ' ' <day_of_month_past> '-' <month> '-' <year2_past> ' ' <time_of_day> ' ' 'GMT'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<asctime_date_past> ::= <day_name> ' ' <month> ' ' <day_of_month_past> ' ' <time_of_day> ' ' <year4_past>
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<day_of_month_past> ::= r'(?:0[1-9]|1[0-9]|2[0-8])'
# RFC 2326
<year4_past> ::= r'[0-9]{4}' := str(random.randint(1990, 2023))
# RFC 2326
<year2_past> ::= r'[0-9]{2}' := "%02d" % random.choice(list(range(90, 100)) + list(range(0, 24)))
where forall <d> in <imf_fixdate_past>: <d>.<day_name> == past_weekday(<d>, "imf")
where forall <d> in <rfc850_date_past>: <d>.<day_name_long> == past_weekday(<d>, "rfc850")
where forall <d> in <asctime_date_past>: <d>.<day_name> == past_weekday(<d>, "asctime")
# TODO: RFC 2326 13 - caching with a proxy cache (nearest <h_via_sent>): a cache is a third party on the path.
# TODO: RFC 2326 12.12, RFC 9110 8.4 - content codings other than gzip and deflate and lists of codings (nearest <h_content_encoding_sent>): ANNOUNCE (gzip, deflate) and SET_PARAMETER (gzip) bodies are coded by a converter pair, compress/x-gzip and coding lists are left out.
# Content-Encoding (12.12), Content-Language (12.13): the body is sent as it is (identity); a compressed body is not produced
<h_content_base_sent> ::= 'Content-Base: ' <publish_url> '/' <crlf>
# RFC 2326
<h_content_location_sent> ::= 'Content-Location: ' <publish_url> '/' <crlf>
# The broad ANNOUNCE (and every description) names its base in any of the forms RFC 1808 resolves differently: with and without the trailing slash, one directory deeper, and (Content-Location only,
# RFC 9110 8.7: absolute or partial URI) as a relative reference to the request URL. The narrowed ANNOUNCE of the publishing path (<req_announce_publish>) sends <h_content_base_sent>.
# TODO: RFC 2326 C.1.1 - a base that names another host or another scheme (nearest <base_any_sent>): the streams it resolves to live on another server, a second connection that the test setup does not hold (a session is one connection).
<h_content_base_any_sent> ::= 'Content-Base: ' <base_any_sent> <crlf>
# RFC 2326
<h_content_location_any_sent> ::= 'Content-Location: ' (<base_any_sent> | <location_relative_sent>) <crlf>
# RFC 2326
<base_any_sent> ::= <publish_url> '/' | <publish_url> | <publish_url> '/' <base_dir_sent> '/' | <publish_url> '/?' <control_query>
# RFC 2326
<location_relative_sent> ::= <base_dir_sent> '/' | './' | '../' <base_dir_sent> '/'
# RFC 2326
<base_dir_sent> ::= r'[a-z]{3,8}'
# RFC 2326
<h_content_encoding_sent> ::= 'Content-Encoding: identity' <crlf>
# RFC 2326
<h_content_language_sent> ::= 'Content-Language: ' <language_range_plain> <crlf>
# RFC 2326 12.1-12.3 Accept, Accept-Encoding, Accept-Language
<language_range_plain> ::= r'[a-z]{2}' ('-' r'[a-z]{2}')?
# RFC 2326 12.41 User-Agent, 12.20 From, 12.30 Referer, 12.43 Via, 8.1 extension-header
<h_via_sent> ::= 'Via: RTSP/1.0 ' <reg_name> <crlf>
# RFC 2326 12.41 User-Agent, 12.20 From, 12.30 Referer, 12.43 Via, 8.1 extension-header
<h_extension_sent> ::= 'X-' r'[A-Za-z]{2,10}' ': ' r'[A-Za-z0-9]{1,10}' <crlf>
# Cache-Control (12.8), Blocksize (12.7), Conference (12.9), If-Match (12.22)
# TODO: RFC 2326 12.8 - cache-directive forms (nearest <h_cache_control_sent>): one to three directives per header, each derived by the shared rule <cache_directive> (every fixed string of the formal grammar, max-age with a delta,
#   and the extension forms with random tokens); nothing of the rule is left out, only longer lists (the number of directives a server evaluates does not change what it does).
<h_cache_control_sent> ::= 'Cache-Control: ' <cache_directive> (',' <ows> <cache_directive>){0,2} <crlf>
# RFC 2326 12.7 Blocksize
<h_blocksize_sent> ::= 'Blocksize: ' <blocksize_value> <crlf>
# 12.7: the size is a positive decimal number; a syntactically invalid value is refused with 416
<blocksize_value> ::= <blocksize_number> | <blocksize_invalid>
# RFC 2326 12.7 Blocksize
<blocksize_number> ::= <digits> := str(random.choice([512, 1024, 1400, 4096, 1, 65535, 100000]))
# RFC 2326 12.7 Blocksize
<blocksize_invalid> ::= (r'[a-z]{1,6}' | '-' <digits> | <digits> '.' <digits> | '0x' r'[0-9a-f]{1,4}')
# RFC 2326 12.9 Conference, 3.3 Conference Identifiers
<h_conference_sent> ::= 'Conference: ' <conference_id> <crlf>
# conference-id = 1*xchar (12.9, 15.1): the first Conference header of a session draws the id from the grammar, every later one repeats it (an equality with the earlier header)
# TODO: RFC 2326 12.9 - the conference identifiers (nearest <conference_id>): the identifier cannot change within a session (3.3), a server that does not know it answers 452 (<code_452>), which every reply class accepts;
#   a second, different identifier within one session is left out.
<conference_id> ::= <xchar>+
where forall <h> in <h_conference_sent>: <h>.<conference_id> == conference_before(<h>)
# RFC 2326
<xchar> ::= <unreserved> | <reserved> | <escape>
# RFC 2326
<unreserved> ::= <alpha> | <digit> | <safe> | <extra>
# RFC 2326
<safe> ::= '$' | '-' | '_' | '.' | '+'
# RFC 2326
<extra> ::= '!' | '*' | "'" | '(' | ')' | ','
# RFC 2326
<reserved> ::= ';' | '/' | '?' | ':' | '@' | '&' | '='
# RFC 2326
<escape> ::= '%' <hex> <hex>
# RFC 2326
<alpha> ::= r'[A-Za-z]'
# RFC 2326
<digit> ::= r'[0-9]'
# RFC 2326
<hex> ::= r'[0-9A-Fa-f]'

# RFC 2326 12.22 If-Match, 12.23 If-Modified-Since
<h_if_match_sent> ::= 'If-Match: ' <if_match_value> <crlf>
# RFC 2326
<if_match_value> ::= '*' | <entity_tag_item> (',' <entity_tag_item>){0,2}
# RFC 2326 12.22 If-Match, 12.23 If-Modified-Since
<entity_tag_item> ::= <entity_tag_recalled> | 'W/' <entity_tag_recalled>
# The tag of the description (a=etag, C.1.8) is recalled; the others never match
<entity_tag_recalled> ::= '"' <etag_recalled> '"'
# RFC 2326
<etag_recalled> ::= <etag_chars> := recall_etag()
# RFC 2326
<etag_chars> ::= r'[\x21\x23-\x7e]+'
where forall <e> in <entity_tag_recalled>: <e>.<etag_recalled> == last_etag_before(<e>)
# Proxy-Authorization (RFC 9110 11.7.2)
<h_proxy_authorization_sent> ::= 'Proxy-Authorization: Basic ' <basic_credentials_valid> <crlf>
# Authorization (RFC 9110 11.6.2)
# TODO: RFC 2326 16, D.2.2 - Digest authentication (nearest <h_authorization_valid>): the Digest scheme is defined by RFC 7616/2617, which refs/spec does not contain and which the allowed
#   sources do not give; the challenge is parsed (<challenge_list>), only Basic credentials are sent.
# TODO: RFC 2326 12.40, 12.27 - Proxy-Require answered by a proxy with 551 (nearest <h_proxy_require_sent>): a proxy is a third party on the path; the servers under test are no proxies.
# TODO: RFC 2326 12.5, RFC 9110 11.6.2 - the Basic credentials (nearest <basic_credentials_valid>): the scheme is defined by RFC 7617, which refs/spec does not contain (manifest: over_budget);
#   the user-pass is sent as base64 of "user:password" from the configured credentials, received Authorization headers (S->C requests) are not parsed beyond <token68>.
<h_authorization_valid> ::= 'Authorization: Basic ' <basic_credentials_valid> <crlf>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<h_authorization_wrong> ::= 'Authorization: Basic ' <basic_credentials_wrong> <crlf>
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<basic_credentials_valid> ::= <token68> := basic_credentials(RTSP_USER, RTSP_PASSWORD)
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<basic_credentials_wrong> ::= <token68> := basic_credentials(RTSP_USER, RTSP_PASSWORD + "x")
# RFC 2326 12.5 Authorization, RFC 9110 11 (authentication)
<token68> ::= r'[A-Za-z0-9._~+/-]+=*'

# Range (12.29, 3.5-3.7): the sent forms are narrowed from the shared rules <range_value>, <ranges_specifier>, <npt_range>, <smpte_range> and <utc_range>
# TODO: RFC 2326 12.29, 3.5-3.7 - Range forms the sent header leaves out (nearest <range_play_value>): byte ranges ("MUST NOT be used", 12.29); npt-sec and hh:mm:ss values beyond a few magnitudes
#   (a start beyond the media is sent as <npt_far>, which the servers refuse with 457 or 416); more than two ranges-specifiers in a list; the end of a finite range is the start plus 3 s (an equality), beyond the media (<npt_beyond>), before the start (<npt_backwards> in integer seconds) or "now" as the start;
#   other ends and a backwards range in hh:mm:ss are left out (they lead to the same refusals).
<h_range_play_sent> ::= 'Range: ' <range_play_value> <crlf>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<range_play_value> ::= <range_play_item> (',' <range_play_item>)? (';time=' <utc_time_param>)?
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_time_param> ::= <utc_start_sent>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<range_play_item> ::= <npt_range_play> | <smpte_range_play> | <utc_range_play>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_range_play> ::= 'npt=' (<npt_time_play> '-' | '-' <npt_time_play> | <npt_finite> | <npt_hhmmss_finite> | <npt_fraction_finite> | <npt_second> '-' <npt_now> | <npt_now> '-' (<npt_second> | <npt_far>) | <npt_beyond> | <npt_backwards>)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_time_play> ::= <npt_second> | <npt_second_fraction> | <npt_far> | <npt_hhmmss_small> | <npt_now>
# the sent values are built from the leaves of the shared rules; a generator sits on a leaf only
<npt_hhmmss_small> ::= <npt_hours_small> ':' <npt_minutes_any> ':' <npt_seconds_any> '.' <npt_fraction_digit>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_far> ::= <npt_int_far>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_int_far> ::= <npt_int> := str(random.choice([100000, 2147483647, 99999999]))
# a finite range whose end lies beyond the media (the server clips it or stops at the end), and one that ends before its start
<npt_beyond> ::= (<npt_second> | <npt_second_fraction> | <npt_hhmmss_small>) '-' (<npt_far> | <npt_hhmmss_far>)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hhmmss_far> ::= <npt_hours_far> ':' <npt_minutes_any> ':' <npt_seconds_any>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_backwards> ::= <npt_late> '-' <npt_early>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_late> ::= <npt_int> := str(random.randint(4, 9))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_early> ::= <npt_int> := str(random.randint(0, 3))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hhmmss_finite> ::= <npt_hhmmss_start> '-' <npt_hhmmss_end>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hhmmss_start> ::= <npt_hours_start> ':' <npt_minutes_start> ':' <npt_seconds_any>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hhmmss_end> ::= <npt_hhmmss>
where forall <r> in <npt_hhmmss_finite>: <r>.<npt_hhmmss_end> == time_plus(<r>.<npt_hhmmss_start>, 3)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_fraction_finite> ::= <npt_fraction_start> '-' <npt_fraction_end>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_fraction_start> ::= <npt_int_small> '.' <npt_fraction_digit_nonzero>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_fraction_end> ::= <npt_sec>
where forall <r> in <npt_fraction_finite>: <r>.<npt_fraction_end> == sec_plus(<r>.<npt_fraction_start>, 3)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_finite> ::= <npt_start> '-' <npt_end>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_start> ::= <npt_int_small>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_end> ::= <npt_sec>
where forall <r> in <npt_finite>: <r>.<npt_end> == str(int(<r>.<npt_start>) + 3)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_second> ::= <npt_int_small>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_second_fraction> ::= <npt_int_small> '.' <npt_fraction_digit>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_int_small> ::= <npt_int> := str(random.randint(0, 5))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_fraction_digit> ::= <npt_fraction_digits> := str(random.randint(0, 9))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_fraction_digit_nonzero> ::= <npt_fraction_digits> := str(random.randint(1, 9))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hours_small> ::= <npt_hours> := str(random.randint(0, 2))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hours_far> ::= <npt_hours> := str(random.choice([10, 24, 99]))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hours_start> ::= <npt_hours> := str(random.choice([0, 0, 1, 12]))
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_minutes_start> ::= <npt_minutes> := "%02d" % random.choice([0, 0, 59, 30])
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_minutes_any> ::= <npt_minutes> := "%02d" % random.randint(0, 59)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_seconds_any> ::= <npt_seconds> := "%02d" % random.randint(0, 59)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_range_play> ::= <smpte_type> '=' (<smpte_time_start> '-' | <smpte_frames_start> '-' | <smpte_finite> | <smpte_frames_finite>)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_time_start> ::= <smpte_hours_zero> ':' <smpte_minutes_zero> ':' <smpte_seconds_small>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_frames_start> ::= <smpte_hours_zero> ':' <smpte_minutes_zero> ':' <smpte_seconds_small> ':' <smpte_frames_small> '.' <smpte_subframes_any>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_hours_zero> ::= <smpte_hours> := "00"
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_minutes_zero> ::= <smpte_minutes> := "00"
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_seconds_small> ::= <smpte_seconds> := "%02d" % random.randint(0, 5)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_frames_small> ::= <smpte_frames> := "%02d" % random.randint(0, 24)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_subframes_any> ::= <smpte_subframes> := "%02d" % random.randint(0, 99)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_finite> ::= <smpte_time_start> '-' <smpte_time_end>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_frames_finite> ::= <smpte_frames_start> '-' <smpte_time_end>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_time_end> ::= <smpte_time>
where forall <r> in <smpte_finite>: <r>.<smpte_time_end> == time_plus(<r>.<smpte_time_start>, 3)
where forall <r> in <smpte_frames_finite>: <r>.<smpte_time_end> == time_plus(<r>.<smpte_frames_start>, 3)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_range_play> ::= 'clock=' (<utc_start_sent> '-' | <utc_finite>)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_finite> ::= <utc_start_sent> '-' <utc_end_sent>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_start_sent> ::= <utc_date_sent> 'T' <utc_clock_sent> ('.' <utc_fraction_sent>)? 'Z'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_date_sent> ::= <utc_date> := random.choice(["20200101", "20200101", "20990101", "19961108"])
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_clock_sent> ::= <utc_clock> := random.choice(["000000", "000000", "142300"])
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_fraction_sent> ::= <utc_fraction> := "25"
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_end_sent> ::= <utc_datetime>
where forall <r> in <utc_finite>: <r>.<utc_end_sent> == utc_plus(<r>.<utc_start_sent>, 10)
# PAUSE has exactly one time point (10.6, C22): a time of any unit of 3.5-3.7
<h_range_pause_sent> ::= 'Range: ' <pause_point> (';time=' <utc_time_param>)? <crlf>
# RFC 2326
<pause_point> ::= 'npt=' <npt_time_play> | <smpte_type> '=' (<smpte_time_start> | <smpte_frames_start>) | 'clock=' <utc_start_sent>
# RECORD: absolute time, open or finite (10.11)
<h_range_record_sent> ::= 'Range: ' <utc_range_record> (';time=' <utc_time_param>)? <crlf>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_range_record> ::= 'clock=' (<utc_start_sent> '-' | <utc_finite>)
# RFC 2326 12.34 Scale
<h_scale_sent> ::= 'Scale: ' <scale_chosen> <crlf>
# TODO: RFC 2326 12.34, 12.35 - Scale and Speed values (nearest <scale_chosen>, <speed_chosen>): a sample of signs, magnitudes and spellings of the shared rule is sent (including the invalid zero speed);
#   the servers answer a value they cannot honour with 406/456 or clamp it, which the replies accept.
<scale_chosen> ::= <scale_value> := random.choice(["1", "2", "0.5", "-1", "1.0", "-3.5", "0", "100", "1.", "-0.25", "0001", "1000000"])
# RFC 2326 12.35 Speed
<h_speed_sent> ::= 'Speed: ' <speed_chosen> <crlf>
# RFC 2326 12.35 Speed
<speed_chosen> ::= <speed_value> := random.choice(["1", "2.5", "1.0", "0.5", "10", "0", "2.", "0.001", "1000000"])

# Transport (12.39). The accepted forms of the servers are put together from the rules the replies share.
<h_transport_sent> ::= 'Transport: ' <transport_sent> <crlf>
# RFC 2326 12.39 Transport
<h_transport_record_sent> ::= 'Transport: ' <transport_record> <crlf>
# RFC 2326 12.39 Transport
<h_transport_any_sent> ::= 'Transport: ' <transport_list> <crlf>
# TODO: RFC 2326 12.39 - transport-specs the accepted request leaves out (nearest <transport_sent>): destination, source, layers, ssrc, port and ttl on a unicast spec, mode lists, other lower transports.
#   They are sent by <req_setup_full> with the full rule <transport_list>; the tested servers refuse them with 461 (<code_461>) or 400, which <reply_err> accepts.
<transport_sent> ::= (<transport_udp_unicast> | <transport_tcp_interleaved> | <transport_udp_unicast_mode>
    | <transport_tcp_unicast_list> | <transport_both_cast>)
# RFC 2326 12.39 Transport
<transport_udp_unicast> ::= <transport_name> '/' <transport_profile> <tp_unicast> <tp_client_port_pair>
# RFC 2326 12.39 Transport
<transport_udp_unicast_mode> ::= <transport_name> '/' <transport_profile> '/' <lower_udp> <tp_unicast> <tp_client_port_pair> <tp_mode_play>
# RFC 2326 12.39 Transport
<transport_tcp_interleaved> ::= <transport_name> '/' <transport_profile> '/' <lower_tcp> <tp_unicast> <tp_interleaved_pair>
# RFC 2326 12.39 Transport
<transport_tcp_unicast_list> ::= <transport_tcp_interleaved> ',' <transport_udp_unicast>
# A client that handles both unicast and multicast sends two full transport-specs (C13)
<transport_both_cast> ::= <transport_udp_unicast> ',' <transport_multicast>
# RFC 2326 12.39 Transport
<transport_multicast> ::= <transport_name> '/' <transport_profile> <tp_multicast> <tp_destination_multicast> <tp_ttl_sent> <tp_port_pair>
# TODO: RFC 2326 12.39 - transport-specs of a recording SETUP the narrowed request leaves out (nearest <transport_record>): destination, source, ssrc, ttl, layers, port, multicast and lists; <req_setup_full> sends the whole rule and the servers refuse those forms for RECORD with 461 or 400.
<transport_record> ::= (<transport_name> '/' <transport_profile> '/' <lower_tcp> <tp_unicast> <tp_interleaved_pair> <tp_mode_record>
    | <transport_name> '/' <transport_profile> <tp_unicast> <tp_client_port_pair> <tp_mode_record>
    | <transport_name> '/' <transport_profile> '/' <lower_tcp> <tp_unicast> <tp_interleaved_pair> <tp_mode_record> <tp_append>)
# RFC 2326 12.39 Transport
<tp_client_port_pair> ::= ';client_port=' <port_even> '-' <port_odd>
# RFC 2326 12.39 Transport
<tp_port_pair> ::= ';port=' <port_even> '-' <port_odd>
# RFC 2326 12.39 Transport
<tp_interleaved_pair> ::= ';interleaved=' <channel_even> '-' <channel_odd>
# RFC 2326 12.39 Transport
<tp_mode_play> ::= ';mode=PLAY'
# RFC 2326 12.39 Transport
<tp_mode_record> ::= ';mode=RECORD'
# RFC 2326 12.39 Transport
<tp_destination_multicast> ::= ';destination=' <multicast_address>
# RFC 2326
<multicast_address> ::= <address> := multicast_address_pick()
# RFC 2326
<multicast_ipv4> ::= <address> := multicast_address_pick(False)
# RFC 2326 12.39 Transport
<tp_ttl_sent> ::= ';ttl=' <ttl_sent>
# RFC 2326
<ttl_sent> ::= <ttl_number> := str(random.randint(1, 255))
# RFC 2326 12.39 Transport
<port_even> ::= <port> := str(random.randrange(20000, 60000, 2))
# RFC 2326 12.39 Transport
<port_odd> ::= <port>
# RFC 2326 12.39 Transport
<channel_even> ::= <channel> := str(random.randrange(0, 100, 2))
# RFC 2326 12.39 Transport
<channel_odd> ::= <channel>
where forall <p> in <tp_client_port_pair>: <p>.<port_odd> == str(int(<p>.<port_even>) + 1)
where forall <p> in <tp_port_pair>: <p>.<port_odd> == str(int(<p>.<port_even>) + 1)
where forall <p> in <tp_interleaved_pair>: <p>.<channel_odd> == str(int(<p>.<channel_even>) + 1)
where forall <m> in <sdp_content>: <m>.<content_length_sent> == str(len(bytes(<m>.<sdp_sent>)))
where forall <m> in <sdp_content_publish>: <m>.<content_length_sent> == str(len(bytes(<m>.<sdp_publish>)))
where forall <m> in <sdp_content_gzip>: <m>.<content_length_sent> == str(len(bytes(<m>.<sdp_gzip>)))
where forall <m> in <sdp_content_deflate>: <m>.<content_length_sent> == str(len(bytes(<m>.<sdp_deflate>)))
where forall <m> in <parameter_assignment_content_gzip>: <m>.<content_length_sent> == str(len(bytes(<m>.<parameter_gzip>)))
where forall <m> in <parameter_names_content>: <m>.<content_length_sent> == str(len(bytes(<m>.<parameter_names>)))
where forall <m> in <parameter_assignment_content>: <m>.<content_length_sent> == str(len(bytes(<m>.<parameter_assignments>)))

# Session description Fandango announces (Appendix C): every control form of C.1.1 (session-level aggregate, relative, absolute, "*", none for a single stream),
# several payload types with their rtpmap/fmtp lines, c=/t=/b= variants, a=range in any unit and a=etag. The SETUP that follows names the streams by these controls
# (<publish_setup_url>: its path is computed from the ANNOUNCE of the session).
# TODO: RFC 2326 C.1.2-C.1.4 - media types and encodings beyond the six listed (nearest <sdp_codec_set>): the description content is the media format (RFC 4566 and the payload RFCs), another protocol;
#   a sample of video and audio codecs with their rtpmap/fmtp lines is sent, the received side takes every line (<sdp_description>).
<sdp_sent> ::= 'v=0' <crlf> <sdp_o_sent> 's=' <sdp_name_sent> <crlf> <sdp_c_sent> <sdp_b_sent>? <sdp_t_sent> <sdp_range_sent>? <sdp_etag_sent>? <sdp_aggregate_sent>? <sdp_media_set>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_c_sent> ::= 'c=IN IP4 0.0.0.0' <crlf> | 'c=IN IP4 ' <multicast_ipv4> '/' <ttl_value> <crlf>
# RFC 2326
<ttl_value> ::= r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_b_sent> ::= 'b=AS:' <digits> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_t_sent> ::= 't=0 0' <crlf> | 't=2873397496 2873404696' <crlf> | 't=2873397496 0' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_range_sent> ::= 'a=range:' <range_play_item> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_etag_sent> ::= 'a=etag:' <etag_text> <crlf>
# RFC 2326
<etag_text> ::= r'[a-z0-9]{1,16}'
# TODO: RFC 2326 C.1.1 - a session-level a=control that names another host or another scheme (nearest <sdp_aggregate_sent>): RECORD/PAUSE/TEARDOWN for it would go to another server, a second connection that the test setup does not hold (a session is one connection).
<sdp_aggregate_sent> ::= 'a=control:' (<publish_url> | <publish_url> '/' | '*' | <aggregate_relative> | <publish_path> '/') <crlf>
# RFC 2326
<aggregate_relative> ::= 'aggregate' | 'presentation' | './' | 'live/' | '../' | '?' <control_query>
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<sdp_o_sent> ::= 'o=' <sdp_user> ' ' <digits> ' ' <digits> ' IN IP4 127.0.0.1' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_user> ::= '-' | r'[a-z]{2,8}'
# RFC 2326 10.3 ANNOUNCE, Appendix C (SDP)
<sdp_name_sent> ::= r'[A-Za-z0-9 ]{1,16}'
# One stream with or without its own a=control (C.3), or two streams that each have one (C.2)
<sdp_media_set> ::= (<sdp_stream_0> | <sdp_codec_set> | <sdp_stream_0> <sdp_stream_1>)
# a=range at media level when the streams differ in duration (C.1.5)
<sdp_stream_0> ::= <sdp_codec_set> <sdp_range_sent>? <sdp_control_0>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_stream_1> ::= <sdp_codec_audio> <sdp_range_sent>? <sdp_control_1>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_control_0> ::= 'a=control:' <control_form_0> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_control_1> ::= 'a=control:' <control_form_1> <crlf>
# TODO: RFC 2326 C.1.1 - a media-level a=control that names another host or another scheme (nearest <control_form_0>, <control_form_1>): the SETUP for it would go to another server, a second connection that the test setup does not hold (a session is one connection).
#   Sent are the leaf names streamid=N / trackID=N, the absolute publish URL, absolute-path, dot-segment and query references and "*".
<control_form_0> ::= 'streamid=0' | 'trackID=0' | <publish_url> '/streamid=0' | '*' | <publish_path> '/streamid=0' | '../streamid=0' | 'streamid=0?' <control_query>
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<control_form_1> ::= 'streamid=1' | 'trackID=1' | <publish_url> '/streamid=1' | <publish_path> '/streamid=1' | '../streamid=1' | 'streamid=1?' <control_query>
# RFC 2326 3.2 RTSP URL, 6.1 Request-URI
<control_query> ::= r'[a-z]{1,6}=[0-9]{1,3}'
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_codec_set> ::= <sdp_codec_video> | <sdp_codec_audio>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_codec_video> ::= <sdp_video_h264> | <sdp_video_h264_b> | <sdp_video_mjpeg>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_codec_audio> ::= <sdp_audio_pcmu> | <sdp_audio_pcma> | <sdp_audio_l16> | <sdp_audio_opus>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_port_sent> ::= '0' | '5004' | '49170'
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_media_c> ::= 'c=IN IP4 0.0.0.0' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_video_h264> ::= ('m=video ' <sdp_port_sent> ' RTP/AVP 96' <crlf> 'a=rtpmap:96 H264/90000' <crlf>
    'a=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z2QADKzZQUH7ARAAAAMAEAAAAwHg8UKZYA==,aOvjyyLA; profile-level-id=64000C' <crlf>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_video_h264_b> ::= ('m=video ' <sdp_port_sent> ' RTP/AVP 97' <crlf> <sdp_media_c>? 'a=rtpmap:97 H264/90000' <crlf>
    'a=fmtp:97 packetization-mode=1; sprop-parameter-sets=Z2QADKzZQUH7ARAAAAMAEAAAAwHg8UKZYA==,aOvjyyLA; profile-level-id=64000C' <crlf>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_video_mjpeg> ::= 'm=video ' <sdp_port_sent> ' RTP/AVP 26' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_audio_pcmu> ::= 'm=audio ' <sdp_port_sent> ' RTP/AVP 0' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_audio_pcma> ::= 'm=audio ' <sdp_port_sent> ' RTP/AVP 8' <crlf> 'a=ptime:20' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_audio_l16> ::= 'm=audio ' <sdp_port_sent> ' RTP/AVP 97' <crlf> 'a=rtpmap:97 L16/44100/2' <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_audio_opus> ::= 'm=audio ' <sdp_port_sent> ' RTP/AVP 98' <crlf> 'a=rtpmap:98 opus/48000/2' <crlf> 'a=fmtp:98 sprop-stereo=1' <crlf>

# --------------------------------------------------------------------------------------------
# Responses (7): Status-Line, headers, CRLF, body. The reply class selects the next state.
# --------------------------------------------------------------------------------------------
<resp_any> ::= <resp_2xx> | <resp_3xx> | <resp_err>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_non_redirect> ::= <resp_2xx> | <resp_err>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_err> ::= <resp_4xx> | <resp_5xx>

# A reply has no body, or a body of the type its Content-Type names (4.4, 12.14, 12.16): SDP (Appendix C) or any other
<resp_2xx> ::= <resp_2xx_with_body> | <resp_204>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_3xx> ::= <resp_3xx_with_body> | <resp_304>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_2xx_with_body> ::= <status_line_2xx> <resp_rest>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_3xx_with_body> ::= <status_line_3xx> <resp_rest>
# 204 and 304 end at the first empty line whatever entity headers they have (4.4); a 204 has no Content-Length (RFC 9110 8.6)
<resp_204> ::= <rtsp_version> ' ' <code_204> ' ' <reason_phrase>? <crlf> <resp_header_no_length>* <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_304> ::= <rtsp_version> ' ' <code_304> ' ' <reason_phrase>? <crlf> <resp_headers_any_length> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_headers_any_length> ::= (<resp_header_no_length> | <rh_content_length_zero> | <rh_content_length_positive>)*
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_4xx> ::= <status_line_4xx> <resp_rest>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_5xx> ::= <status_line_5xx> <resp_rest>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_1xx> ::= <status_line_1xx> <resp_header_no_length>* <crlf>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_line_1xx> ::= <rtsp_version> ' ' (<code_100> | <code_extension_1xx>) ' ' <reason_phrase>? <crlf>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_100> ::= '100'
# TODO: RFC 2326 4.4 rule 3 (nearest <resp_rest>): a body whose end is the server closing the connection is left out. A reply without Content-Length is a reply without body (rule 2, which has precedence:
#   length zero), and 9.2 makes the Content-Length a MUST of the sender whenever a payload is present (C3, C4), so a body without one breaks a mandatory requirement and is no message of any state:
#   <split_stream> hands the bytes behind such a reply to the grammar, which rejects them (a violation of the server). Rule 1 (1xx, 204, 304 end at the empty line) is <resp_headers_nobody>.
<resp_rest> ::= (<resp_headers_nobody> <crlf>
    | <resp_headers_other_body> <crlf> <body_octet>{clen(<resp_headers_other_body>)}
    | <resp_headers_sdp_body> <crlf> (<sdp_description> | <sdp_body_coded> | <body_coded>))
# An SDP reply whose Content-Encoding is gzip or deflate (12.12, RFC 9110 8.4) carries coded octets, which never start with the "v=" of a description: a gzip stream starts with the octet 1F, a zlib
# stream (deflate) with a CMF octet (compression method 8); the converter pair below decodes them, so that the description is parsed like a plain one (its a=control lines are recorded, C.1.1).
# Any other coding is opaque octets. The decoded description is the source of the coded octets (Conversion in the Fandango documentation).
<sdp_body_coded> ::= <coded_first_octet> <body_octet>{clen(<resp_headers_sdp_body>) - 1} := coded_encode(<sdp_body_decoded>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_body_decoded> ::= <sdp_description> := coded_decode(<sdp_body_coded>)
# RFC 2326
<coded_first_octet> ::= rb'[\x08\x18\x1f\x28\x38\x48\x58\x68\x78]'
# RFC 2326
<body_coded> ::= rb'[\x00-\x07\x09-\x17\x19-\x1e\x20-\x27\x29-\x37\x39-\x47\x49-\x57\x59-\x67\x69-\x75\x77\x79-\xff]' <body_octet>{clen(<resp_headers_sdp_body>) - 1}
# 9.2: the server may answer after the client stopped waiting for the answer (its timer expired). The party hands such a reply over behind a marker as a message of its own (<mark_late> in the
# party), accepted between two exchanges in every state and inside an exchange before its reply; the checks on the reply pair it with the request of its CSeq (<exchange_request>).
<server_late_reply> ::= '\x00late\x00' <resp_any>

# Status-Line = RTSP-Version SP Status-Code SP Reason-Phrase CRLF (7.1)
<status_line_2xx> ::= <rtsp_version> ' ' <status_code_2xx> ' ' <reason_phrase>? <crlf>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_line_3xx> ::= <rtsp_version> ' ' <status_code_3xx> ' ' <reason_phrase>? <crlf>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_line_4xx> ::= <rtsp_version> ' ' <status_code_4xx> ' ' <reason_phrase>? <crlf>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_line_5xx> ::= <rtsp_version> ' ' <status_code_5xx> ' ' <reason_phrase>? <crlf>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_code_2xx> ::= <code_200> | <code_201> | <code_250> | <code_extension_2xx>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_code_3xx> ::= <code_300> | <code_301> | <code_302> | <code_303> | <code_305> | <code_extension_3xx>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_code_4xx> ::= (<code_400> | <code_401> | <code_402> | <code_403> | <code_404> | <code_405> | <code_406> | <code_407>
    | <code_408> | <code_410> | <code_411> | <code_412> | <code_413> | <code_414> | <code_415> | <code_451> | <code_452>
    | <code_453> | <code_454> | <code_455> | <code_456> | <code_457> | <code_458> | <code_459> | <code_460> | <code_461>
    | <code_462> | <code_extension_4xx>)
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<status_code_5xx> ::= <code_500> | <code_501> | <code_502> | <code_503> | <code_504> | <code_505> | <code_551> | <code_extension_5xx>
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_200> ::= '200'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_201> ::= '201'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_204> ::= '204'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_250> ::= '250'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_300> ::= '300'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_301> ::= '301'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_302> ::= '302'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_303> ::= '303'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_304> ::= '304'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_305> ::= '305'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_400> ::= '400'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_401> ::= '401'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_402> ::= '402'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_403> ::= '403'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_404> ::= '404'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_405> ::= '405'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_406> ::= '406'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_407> ::= '407'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_408> ::= '408'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_410> ::= '410'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_411> ::= '411'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_412> ::= '412'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_413> ::= '413'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_414> ::= '414'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_415> ::= '415'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_451> ::= '451'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_452> ::= '452'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_453> ::= '453'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_454> ::= '454'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_455> ::= '455'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_456> ::= '456'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_457> ::= '457'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_458> ::= '458'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_459> ::= '459'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_460> ::= '460'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_461> ::= '461'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_462> ::= '462'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_500> ::= '500'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_501> ::= '501'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_502> ::= '502'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_503> ::= '503'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_504> ::= '504'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_505> ::= '505'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_551> ::= '551'
# extension-code = 3DIGIT (7.1.1): an unrecognized code is treated as the x00 of its class
<code_extension_1xx> ::= r'1(?:0[1-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9]|6[0-9]|7[0-9]|8[0-9]|9[0-9])'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_extension_2xx> ::= r'2(?:0[2356789]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[1-9]|6[0-9]|7[0-9]|8[0-9]|9[0-9])'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_extension_3xx> ::= r'3(?:0[6-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9]|6[0-9]|7[0-9]|8[0-9]|9[0-9])'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_extension_4xx> ::= r'4(?:0[9-9]|1[6-9]|2[0-9]|3[0-9]|4[0-9]|5[0-0]|6[3-9]|7[0-9]|8[0-9]|9[0-9])'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<code_extension_5xx> ::= r'5(?:0[6-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[023456789]|6[0-9]|7[0-9]|8[0-9]|9[0-9])'
# RFC 2326 7.1 Status-Line, 7.1.1 Status Code and Reason Phrase, 11 Status Code Definitions
<reason_phrase> ::= r'[^\r\n]+'

# Header fields of replies, in any order (6, 7.1.2, 8.1). A reply with a body has exactly one positive Content-Length (4.4, 12.14).
<resp_headers_nobody> ::= (<resp_header_no_length>*
    | <resp_header_no_length>* <rh_content_length_zero> <resp_header_no_length>*)
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_headers_other_body> ::= (<resp_header_no_type>* <rh_content_length_positive> <resp_header_no_type>*
    | <resp_header_no_type>* <rh_content_type_other> <resp_header_no_type>* <rh_content_length_positive> <resp_header_no_type>*
    | <resp_header_no_type>* <rh_content_length_positive> <resp_header_no_type>* <rh_content_type_other> <resp_header_no_type>*)
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_headers_sdp_body> ::= (<resp_header_no_type>* <rh_content_type_sdp> <resp_header_no_type>* <rh_content_length_positive> <resp_header_no_type>*
    | <resp_header_no_type>* <rh_content_length_positive> <resp_header_no_type>* <rh_content_type_sdp> <resp_header_no_type>*)
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_header_no_length> ::= (<resp_header_no_type> | <rh_content_type_sdp> | <rh_content_type_other>)
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<resp_header_no_type> ::= (<rh_cseq> | <rh_session> | <rh_content_base> | <rh_content_location>
    | <rh_transport> | <rh_range> | <rh_public> | <rh_allow> | <rh_rtp_info> | <rh_www_authenticate>
    | <rh_proxy_authenticate> | <rh_unsupported> | <rh_date> | <rh_timestamp> | <rh_scale> | <rh_speed>
    | <rh_location> | <rh_connection> | <rh_last_modified> | <rh_retry_after> | <rh_content_language>
    | <rh_content_encoding> | <rh_cache_control> | <rh_vary> | <rh_expires> | <rh_generic>)
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_cseq> ::= <name_cseq> ':' <ows> <cseq_reply> <ows> <crlf>
# RFC 2326 12.17 CSeq
<cseq_reply> ::= <cseq_value> := record_cseq(<cseq_src>)
# RFC 2326 12.17 CSeq
<cseq_src> ::= <cseq_value> := record_cseq(<cseq_reply>)
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<rh_session> ::= <name_session> ':' <ows> <session_reply_value> <ows> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_length_zero> ::= <name_content_length> ':' <ows> r'0+' <ows> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_length_positive> ::= <name_content_length> ':' <ows> r'0*[1-9][0-9]{0,9}' <ows> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_generic> ::= <generic_name> ':' <ows> <field_value>? <crlf>

# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_cseq> ::= r'(?i:cseq)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_session> ::= r'(?i:session)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_content_length> ::= r'(?i:content-length)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<generic_name> ::= r"(?:[Aa](?:[Ll](?:[Ll](?:[Oo](?:[Ww](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-VX-Z\^-vx-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Cc](?:[Aa](?:[Cc](?:[Hh](?:[Ee](?:[\-](?:[Cc](?:[Oo](?:[Nn](?:[Tt](?:[Rr](?:[Oo](?:[Ll](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Oo](?:[Nn](?:[Nn](?:[Ee](?:[Cc](?:[Tt](?:[Ii](?:[Oo](?:[Nn](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Tt](?:[Ee](?:[Nn](?:[Tt](?:[\-](?:[Bb](?:[Aa](?:[Ss](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ee](?:[Nn](?:[Cc](?:[Oo](?:[Dd](?:[Ii](?:[Nn](?:[Gg](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ll](?:[Aa](?:[Nn](?:[Gg](?:[Uu](?:[Aa](?:[Gg](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^-tv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ee](?:[Nn](?:[Gg](?:[Tt](?:[Hh](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Oo](?:[Cc](?:[Aa](?:[Tt](?:[Ii](?:[Oo](?:[Nn](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-DF-NP-Z\^-`b-df-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Tt](?:[Yy](?:[Pp](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-XZ\^-xz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ACDF-KM-SU-Z\^-acdf-km-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-SU-Z\^-mo-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ss](?:[Ee](?:[Qq](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-PR-Z\^-pr-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-NP-RT-Z\^-`b-np-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Dd](?:[Aa](?:[Tt](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ee](?:[Xx](?:[Pp](?:[Ii](?:[Rr](?:[Ee](?:[Ss](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-WYZ\^-wyz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ll](?:[Aa](?:[Ss](?:[Tt](?:[\-](?:[Mm](?:[Oo](?:[Dd](?:[Ii](?:[Ff](?:[Ii](?:[Ee](?:[Dd](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-EG-Z\^-eg-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-LN-Z\^-ln-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Oo](?:[Cc](?:[Aa](?:[Tt](?:[Ii](?:[Oo](?:[Nn](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-NP-Z\^-`b-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Pp](?:[Rr](?:[Oo](?:[Xx](?:[Yy](?:[\-](?:[Aa](?:[Uu](?:[Tt](?:[Hh](?:[Ee](?:[Nn](?:[Tt](?:[Ii](?:[Cc](?:[Aa](?:[Tt](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^-tv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-XZ\^-xz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-WYZ\^-wyz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Uu](?:[Bb](?:[Ll](?:[Ii](?:[Cc](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9AC-Z\^-ac-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QSTV-Z\^-qstv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Rr](?:[Aa](?:[Nn](?:[Gg](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ee](?:[Tt](?:[Rr](?:[Yy](?:[\-](?:[Aa](?:[Ff](?:[Tt](?:[Ee](?:[Rr](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-EG-Z\^-eg-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-XZ\^-xz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Tt](?:[Pp](?:[\-](?:[Ii](?:[Nn](?:[Ff](?:[Oo](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-EG-Z\^-eg-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-DF-SU-Z\^-`b-df-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ss](?:[Cc](?:[Aa](?:[Ll](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ee](?:[Ss](?:[Ss](?:[Ii](?:[Oo](?:[Nn](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Pp](?:[Ee](?:[Ee](?:[Dd](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABDF-OQ-Z\^-bdf-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Tt](?:[Ii](?:[Mm](?:[Ee](?:[Ss](?:[Tt](?:[Aa](?:[Mm](?:[Pp](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-LN-Z\^-ln-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-LN-Z\^-ln-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Rr](?:[Aa](?:[Nn](?:[Ss](?:[Pp](?:[Oo](?:[Rr](?:[Tt](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-QS-Z\^-hj-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Uu](?:[Nn](?:[Ss](?:[Uu](?:[Pp](?:[Pp](?:[Oo](?:[Rr](?:[Tt](?:[Ee](?:[Dd](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQ-Z\^-oq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^-tv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Vv](?:[Aa](?:[Rr](?:[Yy](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-XZ\^-xz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ww](?:[Ww](?:[Ww](?:[\-](?:[Aa](?:[Uu](?:[Tt](?:[Hh](?:[Ee](?:[Nn](?:[Tt](?:[Ii](?:[Cc](?:[Aa](?:[Tt](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-TV-Z\^-tv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-VX-Z\^-vx-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-VX-Z\^-vx-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9BF-KM-OQX-Z\^-`bf-km-oqx-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)"
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<field_value> ::= r'[^\r\n \t][^\r\n]*' <field_fold>*
# RFC 2326
<field_fold> ::= <crlf> r'[ \t]+[^\r\n]*'

# Session = "Session" ":" session-id [ ";" "timeout" "=" delta-seconds ] (12.37); the timeout only in replies
<session_reply_value> ::= <session_id_reply> (';' <ows> 'timeout' <ows> '=' <ows> <delta_seconds>)?
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<session_id_reply> ::= <session_id> := record_session(<session_id_src>)
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<session_id_src> ::= <session_id> := record_session(<session_id_reply>)
# RFC 2326 12.37 Session, 3.4 Session Identifiers
<session_id> ::= r'[A-Za-z0-9$_.+-]+'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<delta_seconds> ::= r'[0-9]{1,10}'
# RFC 2326 12.17 CSeq
<cseq_value> ::= r'[0-9]{1,10}'

# Interleaved binary data (10.12): '$', channel, two-byte length; the Client party hands over the frame header only
# Interleaved data the client sends (10.12): '$', the channel, the two-byte length, one packet of the upper layer
<interleaved_frame_sent> ::= (<frame_up_rtp> | <frame_up_rtp_long> | <frame_up_rtcp> | <frame_up_rtcp_sr> | <frame_up_empty>)
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<frame_up_rtp> ::= '$' <channel_up> rb'\x00\x0c' <rtp_header_sent>
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<frame_up_rtp_long> ::= '$' <channel_up> rb'\x00\x14' rb'\x80[\x00-\x7f][\x00-\xff]{18}'
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<frame_up_rtcp> ::= '$' <channel_up> rb'\x00\x08' <rtcp_header_sent>
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<frame_up_rtcp_sr> ::= '$' <channel_up> rb'\x00\x1c' rb'\x80\xc8\x00\x06[\x00-\xff]{24}'
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<frame_up_empty> ::= '$' <channel_up> rb'\x00\x00'
# The channel of RTP is the first of the interleaved pair the SETUP negotiated, the one of RTCP the second (10.12)
<channel_up> ::= <channel_id>
where forall <f> in <frame_up_rtp>: <f>.<channel_up> == negotiated_channel_before(<f>, 0)
where forall <f> in <frame_up_rtp_long>: <f>.<channel_up> == negotiated_channel_before(<f>, 0)
where forall <f> in <frame_up_empty>: <f>.<channel_up> == negotiated_channel_before(<f>, 0)
where forall <f> in <frame_up_rtcp>: <f>.<channel_up> == negotiated_channel_before(<f>, 1)
where forall <f> in <frame_up_rtcp_sr>: <f>.<channel_up> == negotiated_channel_before(<f>, 1)
# RFC 2326
<rtp_header_sent> ::= rb'\x80[\x00-\x7f][\x00-\xff]{10}'
# RFC 2326
<rtcp_header_sent> ::= rb'\x80\xc9\x00\x01[\x00-\xff]{4}'
# TODO: RFC 2326 10.12 - the RTP/RTCP packet inside a frame (nearest <interleaved_frame>): the packet is defined by RFC 3550, another protocol; the Client party drops the payload after cutting the stream
#   by the two-byte length, and hands over at most RTSP_FRAME_LIMIT frame headers per session, so that Fandango does not parse the media flood.
<interleaved_frame> ::= '$' <channel_id> <frame_length>
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<channel_id> ::= rb'[\x00-\xff]'
# RFC 2326 10.12 Embedded (Interleaved) Binary Data
<frame_length> ::= rb'[\x00-\xff]' rb'[\x00-\xff]'

# --------------------------------------------------------------------------------------------
# Lexical rules (15.1)
# --------------------------------------------------------------------------------------------
<crlf> ::= '\r\n'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<ows> ::= <ws>? := ' '
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<ws> ::= r'(?:\r\n)?[ \t]+'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<body_octet> ::= rb'[\x00-\xff]'


# --------------------------------------------------------------------------------------------
# Header fields with a structure the grammar knows (12): one rule for the value, shared by what is sent and received
# --------------------------------------------------------------------------------------------
<rh_content_type_sdp> ::= <name_content_type> ':' <ows> <media_type_sdp> <media_params> <ows> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_type_other> ::= <name_content_type> ':' <ows> <media_type_other> <media_params> <ows> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_base> ::= <name_content_base> ':' <ows> <content_base_uri> <ows> <crlf>
# RFC 2326
<content_base_uri> ::= <uri_reference> := record_base(<content_base_src>)
# RFC 2326
<content_base_src> ::= <uri_reference> := record_base(<content_base_uri>)
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_location> ::= <name_content_location> ':' <ows> <content_location_uri> <ows> <crlf>
# RFC 2326
<content_location_uri> ::= <uri_reference> := record_location(<content_location_src>)
# RFC 2326
<content_location_src> ::= <uri_reference> := record_location(<content_location_uri>)
# RFC 2326 12 Header Field Definitions (received form)
<rh_location> ::= <name_location> ':' <ows> <uri_reference> <ows> <crlf>
# RFC 2326 12.39 Transport
<rh_transport> ::= <name_transport> ':' <ows> <transport_list> <ows> <crlf>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<rh_range> ::= <name_range> ':' <ows> <range_value> <ows> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_public> ::= <name_public> ':' <token_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_allow> ::= <name_allow> ':' <token_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_rtp_info> ::= <name_rtp_info> ':' <ows> <rtp_info_value> <ows> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_www_authenticate> ::= <name_www_authenticate> ':' <challenge_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_proxy_authenticate> ::= <name_proxy_authenticate> ':' <challenge_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_unsupported> ::= <name_unsupported> ':' <token_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_date> ::= <name_date> ':' <ows> <http_date> <ows> <crlf>
# RFC 2326 12.38 Timestamp
<rh_timestamp> ::= <name_timestamp> ':' <ows> <timestamp_value> <ows> <crlf>
# RFC 2326 12.34 Scale
<rh_scale> ::= <name_scale> ':' <ows> <scale_value> <ows> <crlf>
# RFC 2326 12.35 Speed
<rh_speed> ::= <name_speed> ':' <ows> <speed_value> <ows> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_connection> ::= <name_connection> ':' <token_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_last_modified> ::= <name_last_modified> ':' <ows> <http_date> <ows> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_retry_after> ::= <name_retry_after> ':' <ows> (<http_date> | <delta_seconds>) <ows> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_language> ::= <name_content_language> ':' <token_list> <crlf>
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<rh_content_encoding> ::= <name_content_encoding> ':' <token_list> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_cache_control> ::= <name_cache_control> ':' <ows> <cache_directive_list> <ows> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<rh_vary> ::= <name_vary> ':' (<ows> <vary_any> <ows> | <token_list>) <crlf>
# Expires = "Expires" ":" HTTP-date (12.19); a value in another format is treated as already past, so every field value is accepted
<rh_expires> ::= <name_expires> ':' <ows> <field_value> <ows> <crlf>
# RFC 2326 12 Header Field Definitions (received form)
<name_expires> ::= r'(?i:expires)'
# RFC 2326 12 Header Field Definitions (received form)
<name_last_modified> ::= r'(?i:last-modified)'
# RFC 2326 12 Header Field Definitions (received form)
<name_retry_after> ::= r'(?i:retry-after)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_content_language> ::= r'(?i:content-language)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_content_encoding> ::= r'(?i:content-encoding)'
# RFC 2326 12 Header Field Definitions (received form)
<name_cache_control> ::= r'(?i:cache-control)'
# RFC 2326 12 Header Field Definitions (received form)
<name_vary> ::= r'(?i:vary)'
# RFC 2326
<vary_any> ::= '*'
# Cache-Control = "Cache-Control" ":" 1#cache-directive (12.8)
<cache_directive_list> ::= <cache_directive> (<ows> ',' <ows> <cache_directive>)*
# 12.8: cache-directive = cache-request-directive | cache-response-directive; the fixed strings of both (no-cache is in both) are alternatives of their own,
# and cache-extension = token [ "=" ( token | quoted-string ) ] is every other form (a fixed name with a value, a bare max-age, an unknown name)
<cache_directive> ::= (<cache_directive_fixed> | <cache_max_age> | <cache_extension>)
# RFC 2326 12.8 Cache-Control
<cache_directive_fixed> ::= (<cache_no_cache> | <cache_max_stale> | <cache_min_fresh> | <cache_only_if_cached> | <cache_public> | <cache_private> | <cache_no_transform> | <cache_must_revalidate> | <cache_proxy_revalidate>)
# RFC 2326 12.8 Cache-Control
<cache_no_cache> ::= r'(?i:no-cache)'
# RFC 2326 12.8 Cache-Control
<cache_max_stale> ::= r'(?i:max-stale)'
# RFC 2326 12.8 Cache-Control
<cache_min_fresh> ::= r'(?i:min-fresh)'
# RFC 2326 12.8 Cache-Control
<cache_only_if_cached> ::= r'(?i:only-if-cached)'
# RFC 2326 12.8 Cache-Control
<cache_public> ::= r'(?i:public)'
# RFC 2326 12.8 Cache-Control
<cache_private> ::= r'(?i:private)'
# RFC 2326 12.8 Cache-Control
<cache_no_transform> ::= r'(?i:no-transform)'
# RFC 2326 12.8 Cache-Control
<cache_must_revalidate> ::= r'(?i:must-revalidate)'
# RFC 2326 12.8 Cache-Control
<cache_proxy_revalidate> ::= r'(?i:proxy-revalidate)'
# RFC 2326 12.8 Cache-Control
<cache_max_age> ::= r'(?i:max-age)' '=' <delta_seconds>
# RFC 2326 12.8 Cache-Control
<cache_extension> ::= (<cache_extension_name> ('=' <cache_extension_value>)?
    | <cache_directive_fixed_name> '=' <cache_extension_value>
    | r'(?i:max-age)' ('=' <cache_extension_value_non_delta>)?)
# RFC 2326 12.8 Cache-Control
<cache_extension_name> ::= r"(?:[Mm](?:[Aa](?:[Xx](?:[\-](?:[Aa](?:[Gg](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ss](?:[Tt](?:[Aa](?:[Ll](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-RT-Z\^-`b-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-WYZ\^-wyz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ii](?:[Nn](?:[\-](?:[Ff](?:[Rr](?:[Ee](?:[Ss](?:[Hh](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-EG-Z\^-eg-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Uu](?:[Ss](?:[Tt](?:[\-](?:[Rr](?:[Ee](?:[Vv](?:[Aa](?:[Ll](?:[Ii](?:[Dd](?:[Aa](?:[Tt](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-UW-Z\^-uw-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-HJ-TV-Z\^-`b-hj-tv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Nn](?:[Oo](?:[\-](?:[Cc](?:[Aa](?:[Cc](?:[Hh](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Tt](?:[Rr](?:[Aa](?:[Nn](?:[Ss](?:[Ff](?:[Oo](?:[Rr](?:[Mm](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-LN-Z\^-ln-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-EG-Z\^-eg-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-RT-Z\^-rt-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-SU-Z\^-bd-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Oo](?:[Nn](?:[Ll](?:[Yy](?:[\-](?:[Ii](?:[Ff](?:[\-](?:[Cc](?:[Aa](?:[Cc](?:[Hh](?:[Ee](?:[Dd](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-GI-Z\^-gi-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-EG-Z\^-eg-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-XZ\^-xz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Pp](?:[Rr](?:[Ii](?:[Vv](?:[Aa](?:[Tt](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-UW-Z\^-uw-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Oo](?:[Xx](?:[Yy](?:[\-](?:[Rr](?:[Ee](?:[Vv](?:[Aa](?:[Ll](?:[Ii](?:[Dd](?:[Aa](?:[Tt](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-CE-Z\^-ce-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-UW-Z\^-uw-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-XZ\^-xz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-WYZ\^-wyz|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-NP-Z\^-hj-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Uu](?:[Bb](?:[Ll](?:[Ii](?:[Cc](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9ABD-Z\^-bd-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-HJ-Z\^-hj-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9AC-Z\^-ac-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QSTV-Z\^-qstv-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-LQ-Z\^-lq-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)"
# RFC 2326 12.8 Cache-Control
<cache_directive_fixed_name> ::= r'(?i:no-cache|max-stale|min-fresh|only-if-cached|public|private|no-transform|must-revalidate|proxy-revalidate)'
# RFC 2326 12.8 Cache-Control
<cache_extension_value> ::= (<token> | <quoted_string>)
# RFC 2326 12.8 Cache-Control
<cache_extension_value_non_delta> ::= (r"[0-9]*[!#$%&'*+.^_`|~A-Za-z-][!#$%&'*+.^_`|~0-9A-Za-z-]*" | <quoted_string>)

# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_content_type> ::= r'(?i:content-type)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_content_base> ::= r'(?i:content-base)'
# RFC 2326 7 Response, 4.4 Message Length, 8.1 Entity Header Fields, 12.14 Content-Length
<name_content_location> ::= r'(?i:content-location)'
# RFC 2326 12 Header Field Definitions (received form)
<name_location> ::= r'(?i:location)'
# RFC 2326 12 Header Field Definitions (received form)
<name_transport> ::= r'(?i:transport)'
# RFC 2326 12 Header Field Definitions (received form)
<name_range> ::= r'(?i:range)'
# RFC 2326 12 Header Field Definitions (received form)
<name_public> ::= r'(?i:public)'
# RFC 2326 12 Header Field Definitions (received form)
<name_allow> ::= r'(?i:allow)'
# RFC 2326 12 Header Field Definitions (received form)
<name_rtp_info> ::= r'(?i:rtp-info)'
# RFC 2326 12 Header Field Definitions (received form)
<name_www_authenticate> ::= r'(?i:www-authenticate)'
# RFC 2326 12 Header Field Definitions (received form)
<name_proxy_authenticate> ::= r'(?i:proxy-authenticate)'
# RFC 2326 12 Header Field Definitions (received form)
<name_unsupported> ::= r'(?i:unsupported)'
# RFC 2326 12 Header Field Definitions (received form)
<name_date> ::= r'(?i:date)'
# RFC 2326 12 Header Field Definitions (received form)
<name_timestamp> ::= r'(?i:timestamp)'
# RFC 2326 12 Header Field Definitions (received form)
<name_scale> ::= r'(?i:scale)'
# RFC 2326 12 Header Field Definitions (received form)
<name_speed> ::= r'(?i:speed)'
# RFC 2326 12 Header Field Definitions (received form)
<name_connection> ::= r'(?i:connection)'

# Transport = "Transport" ":" 1#transport-spec (12.39)
<transport_list> ::= <transport_spec> (<ows> ',' <ows> <transport_spec>)*
# RFC 2326 12.39 Transport
<transport_spec> ::= <transport_name> '/' <transport_profile> ('/' <lower_transport>)? <transport_param>*
# RFC 2326 12.39 Transport
<transport_name> ::= 'RTP'
# RFC 2326 12.39 Transport
<transport_profile> ::= 'AVP'
# RFC 2326 12.39 Transport
<lower_transport> ::= <lower_tcp> | <lower_udp>
# RFC 2326 12.39 Transport
<lower_tcp> ::= 'TCP'
# RFC 2326 12.39 Transport
<lower_udp> ::= 'UDP'
# RFC 2326 12.39 Transport
<transport_param> ::= (<tp_unicast> | <tp_multicast> | <tp_destination> | <tp_source> | <tp_interleaved> | <tp_append>
    | <tp_ttl> | <tp_layers> | <tp_port> | <tp_client_port> | <tp_server_port> | <tp_ssrc> | <tp_mode>)
# RFC 2326 12.39 Transport
<tp_unicast> ::= ';unicast'
# RFC 2326 12.39 Transport
<tp_multicast> ::= ';multicast'
# RFC 2326 12.39 Transport
<tp_destination> ::= ';destination' ('=' <address>)?
# RFC 2326 12.39 Transport
<tp_source> ::= ';source=' <address>
# RFC 2326 12.39 Transport
<tp_interleaved> ::= ';interleaved=' <channel> ('-' <channel>)?
# RFC 2326 12.39 Transport
<tp_append> ::= ';append'
# RFC 2326 12.39 Transport
<tp_ttl> ::= ';ttl=' <ttl_number>
# RFC 2326
<ttl_number> ::= r'[0-9]{1,3}'
# RFC 2326 12.39 Transport
<tp_layers> ::= ';layers=' r'[0-9]+'
# RFC 2326 12.39 Transport
<tp_port> ::= ';port=' <port> ('-' <port>)?
# RFC 2326 12.39 Transport
<tp_client_port> ::= ';client_port=' <port> ('-' <port>)?
# RFC 2326 12.39 Transport
<tp_server_port> ::= ';server_port=' <port> ('-' <port>)?
# RFC 2326 12.39 Transport
<tp_ssrc> ::= ';ssrc=' r'[0-9A-Fa-f]{8}'
# RFC 2326 12.39 Transport
<tp_mode> ::= ';mode=' (<dquote> <mode_list>? <dquote> | <mode>)
# RFC 2326 12.39 Transport
<mode_list> ::= <mode> (',' <mode>){0,2}
# RFC 2326 12.39 Transport
<mode> ::= <mode_play> | <mode_record> | <mode_other>
# RFC 2326 12.39 Transport
<mode_other> ::= r"(?:[P](?:[L](?:[A](?:[Y](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-XZ\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-KM-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[R](?:[E](?:[C](?:[O](?:[R](?:[D](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-CE-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABD-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-DF-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-OQS-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)"
# RFC 2326 12.39 Transport
<mode_play> ::= 'PLAY'
# RFC 2326 12.39 Transport
<mode_record> ::= 'RECORD'
# RFC 2326 12.39 Transport
<channel> ::= r'[0-9]{1,3}'
# RFC 2326 12.39 Transport
<port> ::= r'[0-9]{1,5}'
# RFC 2326 12.39 Transport
<address> ::= <host>
# RFC 2326 12.39 Transport
<dquote> ::= '"'

# Range = "Range" ":" 1#ranges-specifier [ ";" "time" "=" utc-time ] (12.29, 3.5-3.7)
<range_value> ::= <ranges_specifier> (<ows> ',' <ows> <ranges_specifier>)* (';' 'time' '=' <utc_datetime>)?
# RFC 2326
<ranges_specifier> ::= <npt_range> | <utc_range> | <smpte_range>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_range> ::= 'npt=' (<npt_time> '-' <npt_time>? | '-' <npt_time>)
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_time> ::= <npt_now> | <npt_sec> | <npt_hhmmss>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_now> ::= 'now'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_sec> ::= <npt_int> ('.' <npt_fraction_digits>?)?
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_int> ::= r'[0-9]+'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_fraction_digits> ::= r'[0-9]+'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hhmmss> ::= <npt_hours> ':' <npt_minutes> ':' <npt_seconds> ('.' <npt_fraction_digits>?)?
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_hours> ::= r'[0-9]+'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_minutes> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<npt_seconds> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_range> ::= <smpte_type> '=' <smpte_time> '-' <smpte_time>?
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_type> ::= <smpte_30> | <smpte_30_drop> | <smpte_25>
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_30> ::= 'smpte'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_30_drop> ::= 'smpte-30-drop'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_25> ::= 'smpte-25'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_time> ::= <smpte_hours> ':' <smpte_minutes> ':' <smpte_seconds> (':' <smpte_frames>)? ('.' <smpte_subframes>)?
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_hours> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_minutes> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_seconds> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_frames> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<smpte_subframes> ::= r'[0-9]{1,2}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_range> ::= 'clock=' <utc_datetime> '-' <utc_datetime>?
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_datetime> ::= <utc_date> 'T' <utc_clock> ('.' <utc_fraction>)? 'Z'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_date> ::= r'[0-9]{8}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_clock> ::= r'[0-9]{6}'
# RFC 2326 12.29 Range, 3.5-3.7 (SMPTE, NPT, absolute time)
<utc_fraction> ::= r'[0-9]+'

# Scale, Speed, Timestamp (12.34, 12.35, 12.38)
<scale_value> ::= '-'? r'[0-9]+' ('.' r'[0-9]+'?)?
# RFC 2326 12.35 Speed
<speed_value> ::= r'[0-9]+' ('.' r'[0-9]+'?)?
# RFC 2326 12.38 Timestamp
<timestamp_value> ::= <timestamp_number> (r'[ \t]+' <timestamp_number>)?
# RFC 2326 12.38 Timestamp
<timestamp_number> ::= r'[0-9]+' ('.' r'[0-9]+'?)? | '.' r'[0-9]+'?

# RTP-Info = "RTP-Info" ":" 1#stream-url 1*parameter (12.33)
<rtp_info_value> ::= <rtp_info_entry> (<ows> ',' <ows> <rtp_info_entry>)*
# RFC 2326
<rtp_info_entry> ::= 'url' '=' <rtp_info_url> <rtp_info_param>+
# RFC 2326
<rtp_info_url> ::= r'[^;, \t\r\n]+'
# RFC 2326
<rtp_info_param> ::= ';seq=' r'[0-9]+' | ';rtptime=' r'[0-9]+'

# Challenges (RFC 9110 11.3, 11.6.1, 11.7.1)
# challenge-list = #challenge: empty list elements are accepted (RFC 9110 5.6.1.2)
<challenge_list> ::= <challenge_elem> (',' <challenge_elem>)*
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<challenge_elem> ::= <ws>? | <ws>? <challenge> <ws>?
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<challenge> ::= <auth_scheme> (' '+ (<auth_params> | <token68>)?)?
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<auth_scheme> ::= <token>
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<auth_params> ::= <auth_param_elem> (',' <auth_param_elem>)*
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<auth_param_elem> ::= <ws>? | <ws>? <auth_param> <ws>?
# RFC 9110 11.3 Challenge and Response, 11.6.1, 11.7.1
<auth_param> ::= <token> <ows> '=' <ows> (<token> | <quoted_string>)

# HTTP-date (RFC 9110 5.6.7): the preferred IMF-fixdate and the two obsolete forms a recipient must accept
<http_date> ::= <imf_fixdate> | <rfc850_date> | <asctime_date> | <date_month_first>
# Tolerated deviation "date_month_first": the month before the day, "Sat, Nov 07 2026 17:33:56 GMT" (not a HTTP-date)
<date_month_first> ::= <day_name> ',' ' ' <month> ' ' r'[0-9]{2}' ' ' r'[0-9]{4}' ' ' <time_of_day> ' ' 'GMT'
where forall <x> in <date_month_first>: tolerated("date_month_first")
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<imf_fixdate> ::= <day_name> ',' ' ' <date1> ' ' <time_of_day> ' ' 'GMT'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<rfc850_date> ::= <day_name_long> ',' ' ' <date2> ' ' <time_of_day> ' ' 'GMT'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<asctime_date> ::= <day_name> ' ' <date3> ' ' <time_of_day> ' ' r'[0-9]{4}'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<date1> ::= <day_of_month> ' ' <month> ' ' r'[0-9]{4}'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<day_of_month> ::= r'(?:0[1-9]|[12][0-9]|3[01])'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<date2> ::= <day_of_month> '-' <month> '-' r'[0-9]{2}'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<date3> ::= <month> ' ' (<day_of_month> | ' ' r'[1-9]')
# 00:00:00 - 23:59:60 (leap second)
<time_of_day> ::= r'(?:[01][0-9]|2[0-3])' ':' r'[0-5][0-9]' ':' r'(?:[0-5][0-9]|60)'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<day_name> ::= r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<day_name_long> ::= r'(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)'
# RFC 9110 5.6.7 Date/Time Formats (RFC 2326 12.18 Date, 12.19 Expires)
<month> ::= r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'

# Basic values (RFC 9110 5.6, RFC 3986)
<media_type_sdp> ::= r'(?i:application/sdp)'
# RFC 2326 12.16 Content-Type (RFC 9110 8.3.1)
<media_type_other> ::= r"(?:[Aa](?:[Pp](?:[Pp](?:[Ll](?:[Ii](?:[Cc](?:[Aa](?:[Tt](?:[Ii](?:[Oo](?:[Nn](?:[/](?:[Ss](?:[Dd](?:[Pp](?:[!#-'*+\--9A-Z\^-z|~][!#-'*+\--9A-Z\^-z|~]*)|[!#-'*+\--9A-OQ-Z\^-oq-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-CE-Z\^-ce-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-RT-Z\^-rt-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-MO-Z\^-mo-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-NP-Z\^-np-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-HJ-Z\^-hj-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-SU-Z\^-su-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9B-Z\^-`b-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9ABD-Z\^-bd-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-HJ-Z\^-hj-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-KM-Z\^-km-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-OQ-Z\^-oq-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9A-OQ-Z\^-oq-z|~][!#-'*+\--9A-Z\^-z|~]*|)|[!#-'*+\--9B-Z\^-`b-z|~][!#-'*+\--9A-Z\^-z|~]*)"
# RFC 2326 12.16 Content-Type (RFC 9110 8.3.1)
<media_params> ::= (<ows> ';' <ows> <token> '=' (<token> | <quoted_string>))*
# #element = [ element ] *( OWS "," OWS [ element ] ): a recipient parses and ignores empty list elements (RFC 9110 5.6.1.2)
<token_list> ::= <token_elem> (',' <token_elem>)*
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<token_elem> ::= <ws>? (<token> <ws>?)?
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<token> ::= r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<quoted_string> ::= '"' (<qd_run> | <quoted_pair>)* '"'
# RFC 2326
<qd_run> ::= r'[^"\\\x00-\x08\x0a-\x1f\x7f]+'
# RFC 2326
<quoted_pair> ::= r'\\[\t \x21-\x7e\x80-\xff]'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<uri_reference> ::= r'[^\s]+'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<host> ::= <ip_literal> | <reg_name>
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<ip_literal> ::= '[' r'[0-9A-Fa-f:.]+' ']'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<reg_name> ::= r"[A-Za-z0-9._-]+"


# --------------------------------------------------------------------------------------------
# Session descriptions (Appendix C): SDP (RFC 4566), received by a looser rule than the one Fandango sends with.
# The control URLs the description names are recorded for the SETUP requests that follow (C.1.1).
# --------------------------------------------------------------------------------------------
<sdp_description> ::= (<sdp_v> <sdp_o> <sdp_s> <sdp_i>? <sdp_u>? <sdp_e>* <sdp_p>* <sdp_c>? <sdp_b>* <sdp_time>+ <sdp_z>? <sdp_k>?
    <sdp_session_attr>* <sdp_media>*)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_v> ::= 'v=' <sdp_v_text> <crlf>
# a new description replaces the controls, aggregate control and entity tag of the earlier one
<sdp_v_text> ::= <sdp_text> := reset_description(<sdp_v_src>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_v_src> ::= <sdp_text> := reset_description(<sdp_v_text>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_o> ::= 'o=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_s> ::= 's=' <sdp_text>? <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_i> ::= 'i=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_u> ::= 'u=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_e> ::= 'e=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_p> ::= 'p=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_c> ::= 'c=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_b> ::= 'b=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_time> ::= <sdp_t> <sdp_r>*
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_t> ::= 't=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_r> ::= 'r=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_z> ::= 'z=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_k> ::= 'k=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_session_attr> ::= <sdp_attr_control_aggregate> | <sdp_attr_etag> | <sdp_attr_range> | <sdp_attr_other>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_media> ::= <sdp_m> <sdp_i>? <sdp_c>* <sdp_b>* <sdp_k>? <sdp_media_attr>*
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_m> ::= 'm=' <sdp_text> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_media_attr> ::= <sdp_attr_control> | <sdp_attr_range> | <sdp_attr_other>
# C.1.1: a control attribute at session level is the URL for aggregate control, one in a media section the URL of that stream
<sdp_attr_control_aggregate> ::= 'a=control:' <sdp_aggregate_url> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_aggregate_url> ::= <uri_reference> := record_aggregate(<sdp_aggregate_src>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_aggregate_src> ::= <uri_reference> := record_aggregate(<sdp_aggregate_url>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_attr_control> ::= 'a=control:' <sdp_control_url> <crlf>
# C.1.8: the entity tag of the description, returned in If-Match of a SETUP
<sdp_attr_etag> ::= 'a=etag:' <sdp_etag_value> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_etag_value> ::= <sdp_text> := record_etag(<sdp_etag_src>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_etag_src> ::= <sdp_text> := record_etag(<sdp_etag_value>)
# C.1.5: the range of the presentation, in any unit of 3.5-3.7
<sdp_attr_range> ::= 'a=range:' <ranges_specifier> <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_control_url> ::= <uri_reference> := record_control(<sdp_control_src>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_control_src> ::= <uri_reference> := record_control(<sdp_control_url>)
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_attr_other> ::= 'a=' <sdp_attr_name> (':' <sdp_text>)? <crlf>
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_attr_name> ::= r"(?:[Cc](?:[Oo](?:[Nn](?:[Tt](?:[Rr](?:[Oo](?:[Ll](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-KM-Z\^-km-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-QS-Z\^-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-NP-Z\^-np-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Ee](?:[Tt](?:[Aa](?:[Gg](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-SU-Z\^-su-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[Rr](?:[Aa](?:[Nn](?:[Gg](?:[Ee](?:[!#-'*+\-.0-9A-Z\^-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)|[!#-'*+\-.0-9A-DF-Z\^-df-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-FH-Z\^-fh-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9A-MO-Z\^-mo-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9B-Z\^-`b-z|~][!#-'*+\-.0-9A-Z\^-z|~]*|)|[!#-'*+\-.0-9ABDF-QS-Z\^-bdf-qs-z|~][!#-'*+\-.0-9A-Z\^-z|~]*)"
# RFC 2326 Appendix C (SDP), C.1.1 Control URL
<sdp_text> ::= r'[^\r\n]+'
# RFC 2326 15.1 Base Syntax, RFC 9110 5.6, RFC 3986 3.2.2, RFC 5234 B.1
<digits> ::= r'[0-9]{1,10}'


# --------------------------------------------------------------------------------------------
# Requirements on replies that the grammar cannot express (every one is a MUST of the cited text)
# --------------------------------------------------------------------------------------------
HEADER_LINE = re.compile(r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*?)[ \t]*$")
# Headers whose definition is a comma-separated list (#/1#) may repeat (RFC 9110 5.3); every other header occurs at most once
LIST_HEADERS = ("allow", "public", "transport", "rtp-info", "via", "accept", "accept-encoding", "accept-language", "accept-charset",
                "cache-control", "connection", "content-encoding", "content-language", "require", "proxy-require", "unsupported",
                "vary", "www-authenticate", "proxy-authenticate", "warning", "pragma", "trailer", "upgrade", "te", "if-match", "if-none-match")


def header_pairs(node):
    head = re.sub(r"\r\n[ \t]+", " ", str(node).split("\r\n\r\n", 1)[0])
    pairs = []
    for line in head.split("\r\n"):
        m = HEADER_LINE.match(line)
        if m and not line.startswith("RTSP/"):
            pairs.append((m.group(1).lower(), m.group(2)))
    return pairs


def header_values(node, name):
    return [value for key, value in header_pairs(node) if key == name]


def status_code(node):
    m = re.match(r"RTSP/\d+\.\d+ (\d{3})", str(node))
    return int(m.group(1)) if m else 0


def exchange_request(node):
    """The request a reply answers: the request of its exchange, or, when the reply echoes the CSeq of an earlier request that has had no final reply
    (the server answered after the client's timer expired, 9.2: the reply may come late), that request."""
    late = node
    while late is not None and not (late.symbol.is_non_terminal and late.symbol.name() == "<server_late_reply>"):
        late = late.parent
    if late is not None:
        got = header_values(node, "cseq")
        return unanswered_request(node, got[0]) if len(got) == 1 else None
    current = node
    while current is not None and not (current.symbol.is_non_terminal and current.symbol.name().startswith("<x_")):
        current = current.parent
    own = None
    if current is None:
        for message in reversed(earlier_messages(node)):
            if is_client(message) and re.match(r"[A-Z_-]+ \S+ RTSP/", str(message.msg)):
                own = message.msg
                break
    else:
        for child in current.children:
            if child.symbol.is_non_terminal and child.symbol.name().startswith("<req_"):
                own = child
                break
    if own is None or not str(node).startswith("RTSP/"):
        return own
    got = header_values(node, "cseq")
    sent = header_values(own, "cseq")
    if len(got) != 1 or not sent or got[0] == sent[0]:
        return own
    return unanswered_request(node, got[0]) or own


def unanswered_request(reply, cseq):
    """The last earlier request of the session with this CSeq that no earlier final reply has answered."""
    found = None
    for message in earlier_messages(reply):
        text = str(message.msg)
        if text.startswith("\x00late\x00"):
            text = text[6:]
        if is_client(message) and re.match(r"[A-Z_-]+ \S+ RTSP/", text):
            if header_values(message.msg, "cseq") == [cseq]:
                found = message.msg
        elif is_server(message) and text.startswith("RTSP/"):
            final = re.split(r"(?m)^(?=RTSP/\d)", text)[-1]
            if status_code(final) >= 200 and header_values(final, "cseq") == [cseq]:
                found = None
    return found


def is_client(message):
    name = message.msg.symbol.name() if message.msg.symbol.is_non_terminal else ""
    return name.startswith("<req_") or name.startswith("<cli_reply")


def is_server(message):
    name = message.msg.symbol.name() if message.msg.symbol.is_non_terminal else ""
    return not is_client(message) and not name.startswith("<timer_")


def earlier_messages(node):
    """The messages of the session before the one that holds `node`."""
    ancestors = set()
    current = node
    while current is not None:
        ancestors.add(id(current))
        current = current.parent
    earlier = []
    for message in node.get_root().protocol_msgs():
        if id(message.msg) in ancestors:
            break
        earlier.append(message)
    return earlier


# C1: the CSeq of a reply is the one of the request (12.17)
def cseq_echoed(reply):
    request = exchange_request(reply)
    if request is None:
        return True
    sent = header_values(request, "cseq")
    got = header_values(reply, "cseq")
    return len(got) == 1 and (not sent or got[0] == sent[0])


# C17
def method_unsupported_gets_501(reply):
    """C17: a method the server's Public header (an earlier reply of the session) does not list gets 501 (Notes on Table 2, 10); a method that Public lists may get a 405
    (11.3.1: not allowed for the resource or, after SETUP, for the mode); an interim reply and the authentication challenges (401, 407), which come first, are not the final answer."""
    status = status_code(reply)
    if status < 200 or status in (401, 407):
        return True
    request = exchange_request(reply)
    if request is None:
        return True
    method = str(request).split(" ", 1)[0]
    if method == "OPTIONS":
        return True
    public = None
    for message in earlier_messages(reply):
        if is_server(message) and str(message.msg).startswith("RTSP/"):
            for value in header_values(message.msg, "public"):
                public = (public or set()) | {name.strip() for name in value.split(",")}
    if public is None or method in public:
        return True
    # a request with a Session header may be refused for its session (454, 12.37) or as a bad request: the RFC puts no order on the checks
    if header_values(request, "session") and 400 <= status < 500:
        return True
    return status == 501


def request_uri(request):
    parts = str(request).split(" ", 2)
    return parts[1] if len(parts) > 2 else ""


def cseq_present(message):
    return len(header_values(message, "cseq")) == 1


def server_cseq_before(header):
    """The CSeq of the last request of the server before `header` (12.17)."""
    found = None
    for message in earlier_messages(header):
        if is_server(message) and not str(message.msg).startswith(("RTSP/", "\x00")):
            values = header_values(message.msg, "cseq")
            if values:
                found = values[0]
    return found if found else str(header.children[1])


def next_client_cseq(header):
    """One more than the CSeq of the last request Fandango sent (12.17)."""
    last = 0
    for message in earlier_messages(header):
        if is_client(message) and re.match(r"[A-Z_-]+ \S+ RTSP/", str(message.msg)):
            values = header_values(message.msg, "cseq")
            if values and values[0].isdigit():
                last = int(values[0])
    return str(last + 1)


# C20 (header)
def allow_on_405(reply):
    return status_code(reply) != 405 or bool(header_values(reply, "allow"))


# C29, C30: 401 and 407 replies carry a challenge (RFC 9110 15.5.2, 15.5.8)
def challenge_on_401(reply):
    return status_code(reply) != 401 or bool(header_values(reply, "www-authenticate"))


def challenge_on_407(reply):
    return status_code(reply) != 407 or bool(header_values(reply, "proxy-authenticate"))


# C18: a 551 reply names the options it does not support, and only options of the request (12.32, 12.40)
def unsupported_named(reply):
    if status_code(reply) == 551 and not header_values(reply, "unsupported"):
        return False
    request = exchange_request(reply)
    named = [tag.strip().lower() for value in header_values(reply, "unsupported") for tag in value.split(",")]
    if request is None or not named:
        return True
    required = [tag.strip().lower() for key in ("require", "proxy-require")
                for value in header_values(request, key) for tag in value.split(",")]
    return all(tag in required for tag in named)


# C20: a reply to a request with a Timestamp echoes its value (12.38)
def timestamp_echoed(reply):
    request = exchange_request(reply)
    if request is None or not header_values(request, "timestamp"):
        return True
    got = header_values(reply, "timestamp")
    return bool(got) and got[0].split()[0] == header_values(request, "timestamp")[0].split()[0]


# C21: the reply to a request with a Scale carries the scale the server chose (12.34)
def scale_given(reply):
    request = exchange_request(reply)
    if request is None or not header_values(request, "scale") or not (200 <= status_code(reply) < 300):
        return True
    return bool(header_values(reply, "scale"))


# C31: an origin server with a clock sends Date in every 2xx, 3xx and 4xx reply; the clock is shown by an earlier Date (RFC 9110 6.6.1)
def date_given(reply):
    if not (200 <= status_code(reply) < 500):
        return True
    if header_values(reply, "date"):
        return True
    return not any(is_server(message) and header_values(message.msg, "date") for message in earlier_messages(reply))


# C33: a header that is not a list occurs once (RFC 9110 5.3)
def headers_once(reply):
    keys = [key for key, _ in header_pairs(reply) if key not in LIST_HEADERS]
    return len(keys) == len(set(keys))


# C12: the reply to a SETUP names the one transport the server chose (12.39)
def one_transport(reply):
    """C12: the successful reply to a SETUP names the one transport the server chose (12.39), however many Transport headers carry it."""
    return len(list(reply.find_subtrees("<transport_spec>"))) <= 1


# C4: the SDP body is as long as the Content-Length says (4.4, 12.14)
def sdp_length_ok(reply):
    bodies = list(reply.find_subtrees("<sdp_description>"))
    # a coded body is counted octet by octet (<sdp_body_coded>); the description inside it is the decoded source, whose length the Content-Length does not give
    return not bodies or next(iter(reply.find_subtrees("<sdp_body_coded>")), None) is not None or len(bytes(bodies[0])) == clen(reply)


# C7: a request returns the session identifier of the last reply that gave one (12.37)
def sdp_media_controls(sdp):
    """C35, C36: with more than one media section, every one has its own a=control (Appendix C.2, C.3)."""
    medias = list(sdp.find_subtrees("<sdp_media>"))
    return len(medias) <= 1 or all("a=control:" in str(media) for media in medias)


# C32: Last-Modified is not later than Date (RFC 9110 8.8.2.1)
def last_modified_ok(reply):
    from email.utils import parsedate_to_datetime
    modified, date = header_values(reply, "last-modified"), header_values(reply, "date")
    if not modified or not date:
        return True
    try:
        return parsedate_to_datetime(modified[0]) <= parsedate_to_datetime(date[0])
    except (TypeError, ValueError):
        return True


# C9: the timeout parameter of Session is for replies only (12.37)
def session_without_timeout(request):
    return not any("timeout" in value.lower() for value in header_values(request, "session"))


def gzip_encode(plain):
    import gzip
    return gzip.compress(bytes(plain), mtime=0)


def gzip_decode(coded):
    import gzip
    return gzip.decompress(bytes(coded))


UNDECODABLE_DESCRIPTION = b"v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"


def coded_encode(plain):
    return gzip_encode(plain)


def coded_decode(coded):
    """The description inside a gzip or a deflate (zlib) stream. A body that starts like one but is no such stream (another coding, a cut stream) has no description
    to read controls from: a description without any stands for it."""
    for decode in (gzip_decode, deflate_decode):
        try:
            return decode(coded)
        except Exception:
            pass
    return UNDECODABLE_DESCRIPTION


def deflate_encode(plain):
    import zlib
    return zlib.compress(bytes(plain))


def deflate_decode(coded):
    import zlib
    return zlib.decompress(bytes(coded))


def time_plus(value, seconds):
    """hh:mm:ss (with a SMPTE frame field after it, if any) `seconds` later."""
    parts = str(value).split(":")
    total = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2].split(".")[0]) + seconds
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    parts[0], parts[1], parts[2] = "%02d" % hours, "%02d" % minutes, "%02d" % secs
    return ":".join(parts)


def sec_plus(value, seconds):
    """npt-sec with a fraction, `seconds` later, with the same number of decimals."""
    text = str(value)
    decimals = len(text.split(".")[1]) if "." in text else 0
    return "%.*f" % (decimals, float(text) + seconds)


def utc_plus(value, seconds):
    from datetime import datetime, timedelta
    value = str(value)
    m = re.match(r"^(\d{8}T\d{6})(\.\d+)?Z$", value)
    if not m:
        return value
    moment = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S") + timedelta(seconds=seconds)
    return moment.strftime("%Y%m%dT%H%M%S") + (m.group(2) or "") + "Z"


def multicast_address_pick(ipv6=True):
    choices = ["224.2.0.1", "232.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
               "239.255.%d.%d" % (random.randint(0, 255), random.randint(1, 254))]
    if ipv6:
        choices += ["[ff02::1]", "[ff15::%x]" % random.randint(1, 65535)]
    return random.choice(choices)


def other_rtsp_version():
    while True:
        major, minor = random.choice(["0", "1", "2", "3", "10", "99", "01"]), random.choice(["0", "1", "2", "9", "10", "00", "5"])
        if (int(major), int(minor)) != (1, 0):
            return "RTSP/%s.%s" % (major, minor)


def past_weekday(date, form):
    """The weekday name (short, or long for the RFC 850 form) of the date a Last-Modified value names."""
    import datetime
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    text = str(date)
    if form == "imf":
        m = re.search(r"(\d\d) ([A-Z][a-z]{2}) (\d{4})", text)
        day, month, year = m.group(1), m.group(2), m.group(3)
    elif form == "rfc850":
        m = re.search(r"(\d\d)-([A-Z][a-z]{2})-(\d\d)", text)
        day, month, year = m.group(1), m.group(2), (1900 if int(m.group(3)) >= 90 else 2000) + int(m.group(3))
    else:
        m = re.search(r"^[A-Za-z]{3} ([A-Z][a-z]{2}) (\d\d) \d\d:\d\d:\d\d (\d{4})", text)
        month, day, year = m.group(1), m.group(2), m.group(3)
    names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    name = names[datetime.date(int(year), months.index(month) + 1, int(day)).weekday()]
    return name if form == "rfc850" else name[:3]


def conference_before(header):
    """12.9, 3.3: the identifier of an earlier Conference header of the session; the header's own when the session has none yet."""
    for message in earlier_messages(header):
        if is_client(message):
            found = header_values(str(message.msg), "conference")
            if found:
                return found[0]
    return str(header.children[1])


TRANSPORT_NAMES = ("transport", "unicast", "multicast", "destination", "source", "interleaved", "append", "ttl", "layers", "port",
                   "client_port", "server_port", "ssrc", "mode")


def no_transport_parameters(request):
    """C23: a SET_PARAMETER sets no transport parameter: not in a header, not as a name in the text/parameters body."""
    if header_values(request, "transport"):
        return False
    body = str(request).split("\r\n\r\n", 1)[1] if "\r\n\r\n" in str(request) else ""
    for line in body.split("\r\n"):
        name = re.split(r"[:=;\s]", line.strip(), 1)[0].lower()
        if name in TRANSPORT_NAMES:
            return False
    return True


def new_session_differs(reply):
    """C8: the session a second SETUP opens has an identifier no earlier SETUP reply of the connection gave (12.37)."""
    finals = list(reply.find_subtrees("<resp_2xx>"))
    new = [value.split(";")[0].strip() for value in header_values(finals[0] if finals else reply, "session")]
    if not new:
        return True
    earlier = set()
    method = ""
    for message in earlier_messages(reply):
        text = str(message.msg)
        if text.startswith("\x00late\x00"):
            text = text[6:]
        if is_client(message):
            m = re.match(r"([A-Z_-]+) \S+ RTSP/", text)
            method = m.group(1) if m else method
        elif is_server(message) and method == "SETUP" and text.startswith("RTSP/"):
            # only a SETUP opens a session (10.4): a Session header in another reply (DESCRIBE, OPTIONS) names none
            earlier.update(value.split(";")[0].strip() for value in header_values(text, "session"))
    return not any(identifier in earlier for identifier in new)


def negotiated_channel_before(frame, which):
    """The channel of an interleaved pair the 2xx reply to a SETUP chose (one pair per stream set up, 10.4 and 10.12); `which` 0 is RTP, 1 is RTCP.
    The frames the client has sent so far walk through the pairs, so that every stream gets its frames."""
    pairs, frames = [], 0
    for message in earlier_messages(frame):
        name = message.msg.symbol.name() if message.msg.symbol.is_non_terminal else ""
        if "interleaved_frame_sent" in name or name.startswith("<frame_up"):
            frames += 1
            continue
        text = str(message.msg)
        if is_client(message) or not text.startswith("RTSP/1.0 2"):
            continue
        m = re.search(r"(?im)^transport:.*?interleaved=(\d+)(?:-(\d+))?", text)
        if m:
            first = int(m.group(1))
            pair = (first, int(m.group(2)) if m.group(2) else first + 1)
            if pair not in pairs:
                pairs.append(pair)
    pair = pairs[(frames // 2) % len(pairs)] if pairs else (0, 1)
    return bytes([pair[which] & 0xFF])


def last_etag_before(node):
    """The opaque value of the last a=etag line of a description the server sent (C.1.8)."""
    found = None
    for message in earlier_messages(node):
        if is_server(message):
            for m in re.finditer(r"(?m)^a=etag:(.*?)\r?$", str(message.msg)):
                found = m.group(1)
    return found if found else str(node.children[1])


def announce_parts(message):
    """The header block and the description of an ANNOUNCE Fandango sent: a body with Content-Encoding gzip or deflate (12.12) is decoded first, so that the media
    sections and a=control lines of a coded description are found like those of a plain one."""
    head, _, body = bytes(message).partition(b"\r\n\r\n")
    head = head.decode("latin-1")
    for coding in header_values(head, "content-encoding"):
        try:
            if coding.strip().lower() == "gzip":
                body = gzip_decode(body)
            elif coding.strip().lower() == "deflate":
                body = deflate_decode(body)
        except (OSError, ValueError, EOFError):
            pass
    return head, body.decode("latin-1")


def announce_base(head):
    """C.1.1: the Content-Base, else the Content-Location (a relative reference is resolved against the request URL), else the request URL of an ANNOUNCE Fandango sent."""
    from urllib.parse import urljoin
    request = head.split(" ", 2)[1]
    given = header_values(head, "content-base") or header_values(head, "content-location")
    return urljoin(request, given[0]) if given else request


def announced_stream_path_before(url):
    """C.1.1: the path of the stream the next SETUP names: the a=control of the media section the session announced, resolved as RFC 1808 does against the
    Content-Base, else the Content-Location, else the request URL of the ANNOUNCE ("*" is the entire base, a section without control is the presentation URL)."""
    from urllib.parse import urljoin
    announce, setups = None, 0
    for message in earlier_messages(url):
        if not is_client(message):
            continue
        text = str(message.msg)
        if text.startswith("ANNOUNCE "):
            announce, setups = announce_parts(message.msg), 0
        elif announce and text.startswith("SETUP "):
            setups += 1
    own = str(url.children[-1])
    if announce is None:
        return own
    head, body = announce
    request = head.split(" ", 2)[1]
    base = announce_base(head)
    sections = []
    for line in body.split("\r\n"):
        if line.startswith("m="):
            sections.append(None)
        elif line.startswith("a=control:") and sections:
            sections[-1] = line[len("a=control:"):]
    if not sections or sections[setups % len(sections)] is None:
        return url_path(request) or "/"
    control = sections[setups % len(sections)]
    return url_path(base if control == "*" else urljoin(base, control)) or own


def presentation_path_before(url):
    """The presentation of a session that announced a description and set a stream up for recording is the aggregate control URL of that description, else the
    announced URL (10.7, 10.11, C.1.1: the aggregate control is resolved as RFC 1808 does against the Content-Base, else the Content-Location, else the request URL)."""
    from urllib.parse import urljoin
    announce, recording = None, False
    for message in earlier_messages(url):
        if not is_client(message):
            continue
        text = str(message.msg)
        if text.startswith("ANNOUNCE "):
            announce, recording = announce_parts(message.msg), False
        elif announce and text.startswith("SETUP ") and "mode=RECORD" in text:
            recording = True
    if announce and recording:
        head, body = announce
        request = head.split(" ", 2)[1]
        base = announce_base(head)
        for line in body.split("\r\n"):
            if line.startswith("m="):
                break
            if line.startswith("a=control:"):
                control = line[len("a=control:"):]
                return url_path(base if control == "*" else urljoin(base, control)) or str(url.children[-1])
        return url_path(request) or str(url.children[-1])
    return str(url.children[-1])


def last_setup_path_before(url):
    """The path of the stream the last SETUP of the session named."""
    found = None
    for message in earlier_messages(url):
        m = re.match(r"SETUP rtsp://[^/ ]*(/\S*) RTSP/", str(message.msg))
        if is_client(message) and m:
            found = m.group(1)
    return found if found else str(url.children[-1])


def last_session_before(header):
    found = None
    for message in earlier_messages(header):
        if is_server(message):
            values = header_values(message.msg, "session")
            if values:
                found = values[-1].split(";")[0].strip()
    return found if found else str(header.children[1])


where forall <r> in <resp_1xx>: cseq_echoed(<r>)
where forall <r> in <resp_2xx>: cseq_echoed(<r>)
where forall <r> in <resp_3xx>: cseq_echoed(<r>)
where forall <r> in <resp_4xx>: cseq_echoed(<r>)
where forall <r> in <resp_5xx>: cseq_echoed(<r>)
where forall <r> in <resp_1xx>: method_unsupported_gets_501(<r>)
where forall <r> in <resp_2xx>: method_unsupported_gets_501(<r>)
where forall <r> in <resp_3xx>: method_unsupported_gets_501(<r>)
where forall <r> in <resp_4xx>: method_unsupported_gets_501(<r>)
where forall <r> in <resp_5xx>: method_unsupported_gets_501(<r>)
where forall <q> in <srv_options>: cseq_present(<q>)
where forall <q> in <srv_get_parameter>: cseq_present(<q>)
where forall <q> in <srv_set_parameter>: cseq_present(<q>)
where forall <q> in <srv_announce>: cseq_present(<q>)
where forall <q> in <srv_extension>: cseq_present(<q>)
where forall <q> in <srv_redirect>: cseq_present(<q>)
where forall <h> in <h_cseq_echo>: <h>.<cseq_echoed> == server_cseq_before(<h>)
where forall <h> in <h_cseq_sent>: <h>.<cseq_next> == next_client_cseq(<h>)
where forall <r> in <resp_1xx>: headers_once(<r>)
where forall <r> in <resp_2xx>: headers_once(<r>)
where forall <r> in <resp_3xx>: headers_once(<r>)
where forall <r> in <resp_4xx>: headers_once(<r>)
where forall <r> in <resp_5xx>: headers_once(<r>)
where forall <r> in <resp_1xx>: unsupported_named(<r>)
where forall <r> in <resp_2xx>: unsupported_named(<r>)
where forall <r> in <resp_3xx>: unsupported_named(<r>)
where forall <r> in <resp_4xx>: unsupported_named(<r>)
where forall <r> in <resp_5xx>: unsupported_named(<r>)
where forall <r> in <resp_1xx>: timestamp_echoed(<r>)
where forall <r> in <resp_2xx>: timestamp_echoed(<r>)
where forall <r> in <resp_3xx>: timestamp_echoed(<r>)
where forall <r> in <resp_4xx>: timestamp_echoed(<r>)
where forall <r> in <resp_5xx>: timestamp_echoed(<r>)
where forall <r> in <resp_1xx>: date_given(<r>)
where forall <r> in <resp_2xx>: date_given(<r>)
where forall <r> in <resp_3xx>: date_given(<r>)
where forall <r> in <resp_4xx>: date_given(<r>)
where forall <r> in <resp_5xx>: date_given(<r>)
where forall <r> in <resp_4xx>: allow_on_405(<r>)
where forall <r> in <resp_4xx>: challenge_on_401(<r>)
where forall <r> in <resp_4xx>: challenge_on_407(<r>)
where forall <r> in <resp_2xx>: scale_given(<r>)
where forall <r> in <resp_2xx_with_body>: sdp_length_ok(<r>)
where forall <r> in <resp_3xx_with_body>: sdp_length_ok(<r>)
where forall <r> in <resp_4xx>: sdp_length_ok(<r>)
where forall <r> in <resp_5xx>: sdp_length_ok(<r>)
where forall <r> in <resp_2xx>: one_transport(<r>)
# C24: a REDIRECT names the new location (10.10)
where forall <q> in <srv_redirect>: bool(header_values(<q>, 'location'))
where forall <h> in <session_line>: <h>.<session_recalled> == last_session_before(<h>)
where forall <r> in <resp_1xx>: last_modified_ok(<r>)
where forall <r> in <resp_2xx>: last_modified_ok(<r>)
where forall <r> in <resp_3xx>: last_modified_ok(<r>)
where forall <r> in <resp_4xx>: last_modified_ok(<r>)
where forall <r> in <resp_5xx>: last_modified_ok(<r>)
where forall <q> in <srv_options>: last_modified_ok(<q>)
where forall <q> in <srv_get_parameter>: last_modified_ok(<q>)
where forall <q> in <srv_set_parameter>: last_modified_ok(<q>)
where forall <q> in <srv_announce>: last_modified_ok(<q>)
where forall <q> in <srv_extension>: last_modified_ok(<q>)
where forall <q> in <srv_redirect>: last_modified_ok(<q>)
where forall <q> in <srv_options>: headers_once(<q>)
where forall <q> in <srv_get_parameter>: headers_once(<q>)
where forall <q> in <srv_set_parameter>: headers_once(<q>)
where forall <q> in <srv_announce>: headers_once(<q>)
where forall <q> in <srv_extension>: headers_once(<q>)
where forall <q> in <srv_redirect>: headers_once(<q>)
# C23: transport parameters are set by SETUP only (10.9): neither a header nor a parameter of the body of a SET_PARAMETER names them
where forall <q> in <srv_set_parameter>: no_transport_parameters(<q>)
# C26: the request URI "*" is for methods that need no resource (6.2)
where forall <d> in <sdp_description>: sdp_media_controls(<d>)
where forall <q> in <srv_options>: session_without_timeout(<q>)
where forall <q> in <srv_get_parameter>: session_without_timeout(<q>)
where forall <q> in <srv_set_parameter>: session_without_timeout(<q>)
where forall <q> in <srv_announce>: session_without_timeout(<q>)
where forall <q> in <srv_extension>: session_without_timeout(<q>)
where forall <q> in <srv_redirect>: session_without_timeout(<q>)
