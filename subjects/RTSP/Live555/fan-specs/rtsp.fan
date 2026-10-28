# Real Time Streaming Protocol (RTSP) 1.0, RFC 2326, as a Fandango I/O grammar.
#
# Fandango plays the RTSP client (party Client, client state machine RFC 2326 A.1), the system
# under test the media server (party Server, RFC 2326 A.2), over one persistent TCP connection
# (RFC 2326 9, scheme "rtsp"). Message syntax: RFC 2326 4, 6, 7, 12, 15 and the HTTP/1.1 rules
# it refers to (RFC 9110, RFC 9112); URIs per RFC 3986.
#
# Section references: "2326 x" = RFC 2326, "9110 x" = RFC 9110, "9112 x" = RFC 9112,
# "3986 x" = RFC 3986. "H x" in RFC 2326 refers to RFC 2068, superseded by RFC 9110/9112.

import os
import re
import math
import base64
import random

# ======================================================================================
# Test setup: everything the test setup decides, each value from an environment variable
# ======================================================================================

RTSP_HOST = os.environ.get("RTSP_HOST", "127.0.0.1")              # server host in Request-URIs
RTSP_PORT = os.environ.get("RTSP_PORT", "554")                    # server port in Request-URIs
RTSP_MEDIA_PATH = os.environ.get("RTSP_MEDIA_PATH", "test.mkv")   # presentation the server plays
RTSP_MEDIA_TRACK = os.environ.get("RTSP_MEDIA_TRACK", "track1")   # control path of one of its streams
RTSP_RECORD_PATH = os.environ.get("RTSP_RECORD_PATH", "rec")      # presentation the client records
RTSP_RECORD_TRACK = os.environ.get("RTSP_RECORD_TRACK", "trackID=0")  # control path of its stream
RTSP_AUTH_PATH = os.environ.get("RTSP_AUTH_PATH", "secure")       # presentation that may need credentials
RTSP_USER = os.environ.get("RTSP_USER", "user")                   # valid credentials
RTSP_PASSWORD = os.environ.get("RTSP_PASSWORD", "pass")
RTSP_WRONG_PASSWORD = os.environ.get("RTSP_WRONG_PASSWORD", "wrong-password")  # refused credentials
RTSP_MISSING_PATH = os.environ.get("RTSP_MISSING_PATH", "no-such-presentation")  # unknown resource
RTSP_CLIENT_PORT = int(os.environ.get("RTSP_CLIENT_PORT", "50000"))  # first client RTP port (even)
RTSP_MULTICAST_ADDRESS = os.environ.get("RTSP_MULTICAST_ADDRESS", "224.2.0.1")  # client-chosen group
RTSP_UNKNOWN_OPTION = os.environ.get("RTSP_UNKNOWN_OPTION", "x-fandango-unsupported")  # option-tag the client requires (private, 2326 3.8)
RTSP_UNKNOWN_CONFERENCE = os.environ.get("RTSP_UNKNOWN_CONFERENCE", "fandango-conference")  # conference-id the server does not know
RTSP_CONFERENCE = os.environ.get("RTSP_CONFERENCE", "conf-1")      # pre-established conference (2326 12.9)
RTSP_REPLY_WAIT = os.environ.get("RTSP_REPLY_WAIT", "2")           # seconds the client waits for a reply
RTSP_AUTH_REPLY_WAIT = os.environ.get("RTSP_AUTH_REPLY_WAIT", "3")  # seconds it waits for the reply to wrong credentials
RTSP_TRANSPORT = os.environ.get("RTSP_TRANSPORT", "tcp")            # the driver's endpoint: "tcp" (scheme rtsp) or "udp" (rtspu, 2326 9.2)
TOLERATED = os.environ.get("TOLERATED", "")                       # comma-separated tolerances


# 2326 3.2, 9: the scheme names the transport: rtsp a persistent TCP connection, rtspu
# connectionless UDP; 9.2: over UDP a request without reply may be resent, over TCP never
CONNECTIONLESS = RTSP_TRANSPORT.lower() == "udp"
URL_SCHEME = "rtspu" if CONNECTIONLESS else "rtsp"


def resend_allowed(expiry):
    """2326 9.2: the reply timer's expiry is an occasion to resend the request over UDP only."""
    return CONNECTIONLESS


def url_scheme():
    return random.choice([URL_SCHEME, URL_SCHEME.upper()])


def tolerated(name, deviation=None):
    """Whether the test setup tolerates the server deviation `name` (tolerances.json); `deviation`
    is the tree that shows it."""
    return name in [item.strip() for item in TOLERATED.split(",") if item.strip()]


# ======================================================================================
# Helpers of constraints, generators and computed repetitions
# ======================================================================================

def _name(tree):
    return tree.symbol.name() if tree.symbol.is_non_terminal else ""


MESSAGE_PREFIXES = ("<req_", "<rep_", "<srv_req_", "<interleaved_frame")


def _is_message(tree):
    """Whether `tree` is (part of) a party message: messages are named <req_*>, <rep_*>,
    <srv_req_*> and <interleaved_frame*>; states, replies-in-state rules and wrappers are not."""
    return _name(tree).startswith(MESSAGE_PREFIXES)


def _from_client(message):
    """Whether a party message is one the client sends: its requests, replies and data."""
    return _name(message).startswith(("<req_", "<rep_to_", "<interleaved_frame_sent"))


def has_header(message, name):
    return _first(message, name) is not None


def _first(tree, name):
    for found in tree.find_subtrees(name):
        return found
    return None


def _message_of(tree):
    """The party message holding `tree`: its outermost message-named ancestor."""
    message = None
    node = tree
    while node is not None:
        if _is_message(node):
            message = node
        elif message is not None:
            break
        node = node.parent
    return message


def _messages_before(tree):
    """The party messages of the session before the one holding `tree`, in order."""
    stop = _message_of(tree)
    found = []

    def walk(node):
        if node is stop:
            return True
        if _is_message(node):
            found.append(node)
            return False
        for child in node.children:
            if walk(child):
                return True
        return False

    walk(tree.get_root())
    return found


def content_length(headers):
    """Length of the body a header block announces: its Content-Length, else 0 (2326 4.4, 12.14)."""
    value = _first(headers, "<content_length_value>")
    return int(str(value)) if value is not None else 0


def entity_to_octets(entity):
    """Converter: the octets of a typed body (2326 4.3, see octets_to_entity); identity coding."""
    return bytes(entity)[1:]


def _content_codings(body):
    message = body.parent
    if message is None:
        return []
    codings = []
    for header in message.find_subtrees("<h_content_encoding>"):
        codings += [str(token).strip().lower() for token in header.find_subtrees("<token>")]
    return codings


def _media_type(body):
    message = body.parent
    for value in (message.find_subtrees("<media_type_rcv>") if message is not None else []):
        return str(value).split(";")[0].strip().lower()
    return None


def _lzw_decompress(data):
    """The "compress" coding (9110 8.4.1.1): adaptive LZW of the UNIX compress program."""
    if data[:2] != b"\x1f\x9d":
        raise ValueError("no compress header")
    max_bits, block_mode = data[2] & 0x1F, data[2] & 0x80
    table = [bytes([i]) for i in range(256)] + ([b""] if block_mode else [])
    bits, out, previous = 9, [], None
    position, payload = 0, data[3:]
    total_bits = len(payload) * 8
    group_start = 0
    while position + bits <= total_bits:
        byte, offset = position // 8, position % 8
        chunk = int.from_bytes(payload[byte:byte + 3].ljust(3, b"\0"), "little")
        code = (chunk >> offset) & ((1 << bits) - 1)
        position += bits
        if block_mode and code == 256:
            # clear: a new table; the rest of the current group of codes is padding
            group = bits * 8
            position = group_start + ((position - group_start + group - 1) // group) * group
            table, bits, previous, group_start = table[:257], 9, None, position
            continue
        if code < len(table):
            entry = table[code]
        elif code == len(table) and previous is not None:
            entry = previous + previous[:1]
        else:
            raise ValueError("bad compress code")
        out.append(entry)
        if previous is not None and len(table) < (1 << max_bits):
            table.append(previous + entry[:1])
        previous = entry
        if len(table) >= (1 << bits) and bits < max_bits:
            group = bits * 8
            position = group_start + ((position - group_start + group - 1) // group) * group
            bits, group_start = bits + 1, position
    return b"".join(out)


def _lzw_compress(data):
    """The "compress" coding (9110 8.4.1.1): adaptive LZW as the UNIX compress program writes it
    (16-bit maximum, no block mode); codes grow from 9 bits, each growth after a whole group
    of eight codes."""
    out, table = bytearray(), {bytes([i]): i for i in range(256)}
    bits, acc, used, group_start = 9, 0, 0, 0
    def emit(code):
        nonlocal acc, used
        acc |= code << used
        used += bits
    current = b""
    for byte in data:
        candidate = current + bytes([byte])
        if candidate in table:
            current = candidate
            continue
        emit(table[current])
        if len(table) >= (1 << bits) and bits < 16:
            group = bits * 8
            used = group_start + ((used - group_start + group - 1) // group) * group
            bits, group_start = bits + 1, used
        if len(table) < (1 << 16):
            table[candidate] = len(table)
        current = bytes([byte])
    if current:
        emit(table[current])
    return b"\x1f\x9d\x10" + acc.to_bytes((used + 7) // 8, "little")


def encode_body(plain):
    """Converter: a body of the client in a content coding (9110 8.4.1: gzip, deflate, compress),
    chosen at random; its Content-Encoding names the coding its first octets show (body_coding)."""
    import gzip
    import zlib
    data = bytes(plain)
    coding = random.choice(["gzip", "deflate", "compress"])
    if coding == "gzip":
        return gzip.compress(data, mtime=0)
    if coding == "deflate":
        return zlib.compress(data)
    return _lzw_compress(data)


def _coding_of(data):
    return "gzip" if data[:2] == b"\x1f\x8b" else "compress" if data[:2] == b"\x1f\x9d" else "deflate"


def decode_body(coded):
    """Converter: the body a coded body of the client holds (inverse of encode_body)."""
    import gzip
    import zlib
    data = bytes(coded)
    coding = _coding_of(data)
    try:
        return gzip.decompress(data) if coding == "gzip" else zlib.decompress(data) if coding == "deflate" else _lzw_decompress(data)
    except Exception:
        return data


def _coded_part(tree):
    node = tree
    while node is not None and _first(node, "<coded_octets>") is None:
        node = node.parent
    return _first(node, "<coded_octets>") if node is not None else None


def body_coding(coding):
    """The content coding a coded body of the client is in (9110 8.4: Content-Encoding names it)."""
    coded = _coded_part(coding)
    return _coding_of(bytes(coded)) if coded is not None else str(coding)


def coded_length(length):
    """2326 12.14 (C5, C6): the Content-Length of a coded body is the length of the coded octets."""
    coded = _coded_part(length)
    return len(bytes(coded)) if coded is not None else int(str(length))


def octets_to_entity(body):
    """Converter: the octets of a body, decoded by its content codings (9110 8.4.1: gzip,
    deflate, compress), typed by its Content-Type (2326 12.16): S an SDP description, P
    text/parameters, O any other type, E no body (Content-Length: 0)."""
    import gzip
    import zlib
    data = bytes(body)
    for coding in reversed(_content_codings(body)):
        try:
            if coding in ("gzip", "x-gzip"):
                data = gzip.decompress(data)
            elif coding == "deflate":
                data = zlib.decompress(data)
            elif coding in ("compress", "x-compress"):
                data = _lzw_decompress(data)
        except Exception:
            pass
    if not data:
        return b"E"
    kind = _media_type(body)
    return (b"S" if kind == "application/sdp" else b"P" if kind == "text/parameters" else b"O") + data


def media_controls_complete(sdp):
    """2326 C.2, C.3 (C35, C36): with more than one media section, each has its own a=control."""
    sections = list(sdp.find_subtrees("<sdp_media>"))
    if len(sections) < 2:
        return True
    return all(_first(section, "<sdp_a_control_rcv>") is not None for section in sections)


def frame_length(length):
    """Length of an interleaved frame's data: its two-byte length field (2326 10.12)."""
    return int.from_bytes(bytes(length), "big")


def status_code(reply):
    """Status-Code of a reply's Status-Line (2326 7.1)."""
    while len(reply.children) == 1:
        reply = reply.children[0]
    return int(str(reply.children[2]))


def _first_message(tree):
    """The first party message in `tree`, `tree` itself included."""
    if _is_message(tree):
        return tree
    for child in tree.children:
        found = _first_message(child)
        if found is not None:
            return found
    return None


def _opening_message(tree):
    """The message that opens the exchange `tree` begins with: its first party message; for a
    DESCRIBE with wrong credentials (<auth_request>) the request, which server messages between
    the timer's restart and the request may precede."""
    node = tree
    while not _is_message(node) and node.children:
        if _name(node) == "<auth_request>":
            request = _first(node, "<req_describe_wrong_credentials>")
            return request if request is not None else _first_message(node)
        node = node.children[0]
    return _first_message(tree)


def _exchange_request(reply):
    """The request a reply answers: the other party's message that opened the reply's exchange;
    for pipelined replies the request in the same place of the pipeline (2326 9.1)."""
    message = _message_of(reply)
    if _name(message) in ("<rep_pipelined_first>", "<rep_pipelined_second>",
                          "<rep_pipelined_first_closing>", "<rep_pipelined_second_closing>"):
        node = message.parent
        while node is not None and _name(node) != "<pipelined_exchange>":
            node = node.parent
        wanted = _name(message).replace("<rep_", "<req_").replace("_closing>", ">")
        return _first(node, wanted) if node is not None else None
    # a reply after another reply of its exchange answers the pipelined second request
    node, after_reply = message.parent, False
    while node is not None:
        opening = _opening_message(node.children[0]) if node.children else None
        if opening is not None and opening is not message:
            if _from_client(opening) != _from_client(message):
                if after_reply:
                    for child in node.children[1:]:
                        if _name(child).endswith("_pipelined>"):
                            return child
                return opening
            after_reply = after_reply or _name(opening).startswith("<rep_")
        node = node.parent
    return None


def request_cseq(reply):
    """CSeq value of the request a reply answers (2326 12.17)."""
    request = _exchange_request(reply)
    if request is None:
        return None
    value = _first(request, "<cseq_value>")
    if value is None:
        value = _first(request, "<cseq_value_rcv>")
    return None if value is None else str(value)


def expected_cseq(header):
    """CSeq of a request: one more than the client's previous request's (2326 9.2); any value
    for the first request of the connection."""
    previous = None
    for message in _messages_before(header):
        if _from_client(message):
            value = _first(message, "<cseq_value>")
            if value is not None:
                previous = int(str(value))
    if _name(_message_of(header)).endswith("_resent>") and previous is not None:
        return previous    # 2326 9.2: a resent request carries the original sequence number
    expected = previous + 1 if previous is not None else int(str(_first(header, "<cseq_value>")))
    # the next request follows this one, also before its reply arrives (pipelining, 2326 9.1)
    _recorded["cseq"] = max(_recorded["cseq"], expected)
    return expected


def record_answered_cseq(reply):
    """Records the CSeq of the request a final reply answered, from which the next request's
    CSeq follows (2326 9.2)."""
    value = request_cseq(reply)
    if value is not None and value.isdigit():
        _recorded["cseq"] = max(_recorded["cseq"], int(value))
    return True


def recalled_next_cseq():
    return str(_recorded["cseq"] + 1)


# A received value echoed later: recorded when it arrives, recalled when the client sends it.
# Each session starts from a fresh record (session_begins).
def _fresh_record():
    return {"session": "0", "server_cseq": "0", "channel": 0, "cseq": 0, "announced": False,
            "presentation": None, "channels": set(), "streams": [], "set_up": [],
            "etag": None, "conference": None, "ranges": {}}


_recorded = _fresh_record()


def session_begins(timer):
    """A session (one connection, 2326 9) starts with its first timer start, before any party
    message: nothing an earlier session recorded holds in it."""
    if _first_message(timer.get_root()) is None:
        _recorded.clear()
        _recorded.update(_fresh_record())
    return True


def _request_uri(request):
    return bytes(request).split(b" ", 2)[1].decode("latin-1")


def _uri_path(uri):
    """The path of an rtsp URL without its leading "/" (3986 3.3)."""
    rest = uri.split("://", 1)[-1]
    return rest.split("/", 1)[1] if "/" in rest else ""


def record_reply_effects(headers):
    """Records what a successful reply decided for the target resources: an accepted ANNOUNCE
    makes the record presentation the one to set up; a successful SETUP fixes the session's
    presentation and adds its stream to the session (2326 10.3, 10.4)."""
    request = _exchange_request(headers)
    message = _message_of(headers)
    if request is None or message is None or not _name(message).startswith("<rep_"):
        return True
    try:
        code = status_code(message)
    except Exception:
        return True
    if not 200 <= code < 300:
        return True
    method = bytes(request).split(b" ", 1)[0]
    uri = _request_uri(request)
    if method == b"ANNOUNCE":
        _recorded["announced"] = True
        _recorded["streams"] = [RTSP_RECORD_PATH + "/" + RTSP_RECORD_TRACK]
    if method == b"SETUP":
        record = "/" + RTSP_RECORD_PATH in uri
        _recorded["presentation"] = RTSP_RECORD_PATH if record else RTSP_MEDIA_PATH
    return True


def record_description(sdp):
    """Records the streams a description names (2326 C.1.1: a=control, relative to Content-Base,
    else to the request URL; C.3) and its a=etag (C.1.8): SETUPs address these streams, one
    after another into one session (aggregate control, 2326 1.3), and condition on the tag."""
    message = _message_of(sdp)
    request = _exchange_request(sdp) if message is not None else None
    if message is None or request is None or not _name(message).startswith("<rep_"):
        return True
    header = _first(message, "<h_content_base>")
    base = str(_first(header, "<uri_rcv>")) if header is not None else _request_uri(request)
    streams = []
    for media in sdp.find_subtrees("<sdp_media>"):
        control = _first(media, "<sdp_a_control_rcv>")
        if control is None:
            continue
        value = str(_first(control, "<sdp_value>")).strip()
        if value == "*" or not value:
            continue
        url = value if "://" in value else base[:base.rfind("/") + 1] + value
        streams.append(_uri_path(url))
    if streams:
        _recorded["streams"] = streams
    etag = _first(sdp, "<sdp_a_etag_rcv>")
    if etag is not None:
        _recorded["etag"] = str(_first(etag, "<sdp_value>")).strip()
    # C.1.5 a=range: the range of the presentation, at session level (before the media), else
    # of its first stream with one; PLAY, PAUSE and RECORD choose their Range inside it
    for line in sdp.find_subtrees("<sdp_a_range_rcv>"):
        bounds = _npt_bounds(str(line))
        if bounds is not None:
            _recorded["ranges"][_uri_path(_request_uri(request)).rstrip("/")] = bounds
            break
    return True


def _npt_seconds_of(text):
    """Seconds of an npt-time other than "now" (2326 3.6: npt-sec or npt-hhmmss)."""
    seconds = 0.0
    for part in text.split(":"):
        seconds = seconds * 60 + float(part or 0)
    return seconds


def _npt_bounds(line):
    """(start, end) of an a=range line with an npt-range; end None if open (2326 3.6, C.1.5)."""
    match = re.search(r"npt=([0-9:.]*)-([0-9:.]*)", line, re.IGNORECASE)
    if match is None:
        return None
    start, end = match.groups()
    return (_npt_seconds_of(start) if start else 0.0, _npt_seconds_of(end) if end else None)


def _range_bands():
    """Bounds for a Range inside the presentation of the session (2326 3.6, 12.29; C.1.5): its
    a=range from the description, split into a start band, a pause band and an end band, so that
    a start lies before every pause point and every end, and a pause point inside every range
    played from such a start (10.6: "within the range of the presentation"; 11.3.20 457). The
    bands hold whole seconds; a fraction (< 1 s) stays in the band. Without a recorded end (open
    range, no description) the bands follow the start one second apart."""
    presentation = (_recorded["presentation"] or RTSP_MEDIA_PATH).rstrip("/")
    start, end = _recorded["ranges"].get(presentation, (0.0, None))
    low = math.ceil(start)
    high = math.floor(end) if end is not None else None
    if high is None or high - low < 4:
        return low, low + 1, low + 2, None
    return low, low + (high - low) // 2, low + 3 * (high - low) // 4, high


def range_start():
    low, pause, end, high = _range_bands()
    return str(random.randint(low, pause - 1))


def range_pause_point():
    low, pause, end, high = _range_bands()
    return str(random.randint(pause, end - 1))


def range_end():
    low, pause, end, high = _range_bands()
    return str(random.randint(end, high - 1 if high is not None else end + 30))


def described_stream():
    """A stream the last description named and the session has not set up yet, else any of
    its streams (2326 10.4: one SETUP per stream)."""
    streams = _recorded["streams"] or [RTSP_MEDIA_PATH + "/" + RTSP_MEDIA_TRACK]
    fresh = [stream for stream in streams if stream not in _recorded["set_up"]]
    return random.choice(fresh or streams)


def setup_target():
    """Path of the stream to set up: a described stream not yet set up, the record stream once
    an ANNOUNCE was accepted, else the media stream; now and then the aggregate URL (2326 10.4)."""
    if random.random() < 0.1:
        return _recorded["presentation"] or RTSP_MEDIA_PATH
    if _recorded["streams"] and random.random() < 0.8:
        return described_stream()
    if _recorded["announced"] and random.random() < 0.8:
        return RTSP_RECORD_PATH + "/" + RTSP_RECORD_TRACK
    return RTSP_MEDIA_PATH + "/" + RTSP_MEDIA_TRACK


def setup_mode():
    return "RECORD" if _recorded["announced"] else "PLAY"


def session_target():
    """Path of PLAY, PAUSE, RECORD, TEARDOWN: the aggregate URL of the session's presentation,
    now and then one of its streams (2326 1.3, 10.5)."""
    presentation = _recorded["presentation"] or RTSP_MEDIA_PATH
    if random.random() < 0.15:
        if _recorded["set_up"]:
            return random.choice(_recorded["set_up"])
        track = RTSP_RECORD_TRACK if presentation == RTSP_RECORD_PATH else RTSP_MEDIA_TRACK
        return presentation + "/" + track
    return presentation


def recalled_etag():
    """The entity tag of the description (2326 C.1.8 a=etag), else one the server does not know."""
    return _recorded["etag"] or random.choice(["158bb3e7c7fd62ce67f12b533f06b83a", "v1"])


# SETUP requests that start a new session (sent without Session)
NEW_SESSION_SETUPS = ("<req_setup>", "<req_setup_described>", "<req_setup_unknown_conference>",
                      "<req_setup_announced>", "<req_setup_close>")


def record_session(reply):
    """Records the session identifier, the stream and the interleaved channels a successful
    SETUP reply assigned (2326 12.37, 10.4, 10.12)."""
    value = _first(reply, "<session_id_rcv>")
    if value is not None:
        _recorded["session"] = str(value)
    channels = sorted(interleaved_channels_of(reply))
    if channels:
        _recorded["channel"] = channels[0]
    request = _exchange_request(reply)
    if request is not None and _name(request) in NEW_SESSION_SETUPS:
        _recorded["channels"] = set(channels)
        _recorded["set_up"] = []
    else:
        _recorded["channels"] |= set(channels)
    if request is not None:
        path = _uri_path(_request_uri(request))
        if path not in _recorded["set_up"]:
            _recorded["set_up"].append(path)
        conference = _first(request, "<conference_id>") or _first(request, "<conference_id_unknown>")
        if conference is not None:
            _recorded["conference"] = str(conference)
    return True


def record_play_session(reply):
    """2326 A.2: an object that needs no SETUP plays on a PLAY without session; the session
    identifier its reply may give is the one later requests carry (2326 12.37)."""
    request = _exchange_request(reply)
    value = _first(reply, "<session_id_rcv>")
    if request is not None and _name(request) in ("<req_play_without_setup>", "<req_play_without_setup_any_range>") and value is not None:
        _recorded["session"] = str(value)
    return True


def recalled_session():
    return _recorded["session"]


def assigned_session(tree):
    """Session identifier of the last successful SETUP reply before `tree`, or of a PLAY without
    session that started one (2326 12.37, A.2)."""
    session = None
    for message in _messages_before(tree):
        if _name(message) == "<rep_setup_2xx>" or (_name(message) == "<rep_play_2xx>" and _first(
                _exchange_request(message) or message, "<h_session>") is None):
            value = _first(message, "<session_id_rcv>")
            if value is not None:
                session = str(value)
    return session


def nosetup_session_count(cseq):
    """2326 12.37, A.2 (C9): 1 where a reply of the session gave an identifier (the PLAY reply of an
    object without SETUP), which the request then carries, else 0."""
    return 0 if assigned_session(cseq) is None else 1


def session_for(header):
    """The session identifier a request of the session carries: the one its SETUP reply
    assigned (2326 12.37); the recalled value where no reply of this connection assigned one."""
    assigned = assigned_session(header)
    return assigned if assigned is not None else str(_first(header, "<session_id_sent>"))


def record_server_cseq(request):
    """Records the CSeq of a request of the server, which the client's reply echoes (2326 12.17),
    its Session (12.37) and the option-tags its Require names (12.32)."""
    _recorded["server_cseq"] = str(_first(request, "<cseq_value_rcv>"))
    session = _first(request, "<session_id_rcv>")
    _recorded["server_session"] = str(session) if session is not None else _recorded["session"]
    _recorded["server_tags"] = _server_tags(request)
    return True


def _server_tags(request):
    tags = []
    for field in request.find_subtrees("<h_known_text>"):
        name, _, value = str(field).partition(":")
        if name.strip().lower() == "require":
            tags += [tag.strip() for tag in value.split(",") if tag.strip()]
    return tags


def _answered_server_request(tree):
    request = _exchange_request(tree)
    return request if request is not None and _name(request).startswith("<srv_req_") else None


def request_session(tree):
    """2326 12.37: the Session of the server's request a reply of the client answers."""
    request = _answered_server_request(tree)
    session = _first(request, "<session_id_rcv>") if request is not None else None
    return None if session is None else str(session)


def echoed_session_count(tree):
    """1 where the server's request carried a Session, which the client's reply returns."""
    return 0 if request_session(tree) is None else 1


def recalled_server_session():
    return _recorded.get("server_session", "0")


def required_by_server(tree, more=False):
    """The number of option-tags the server's request requires (2326 12.32): 1 (an Unsupported
    field) or 0 for the field, that number less one for the tags after the first."""
    request = _answered_server_request(tree)
    tags = _server_tags(request) if request is not None else []
    if more:
        return max(len(tags) - 1, 0)
    return 1 if tags else 0


def required_tag_at(tag):
    """The option-tag of the server's Require at the place of `tag` in the client's Unsupported."""
    request = _answered_server_request(tag)
    tags = _server_tags(request) if request is not None else []
    header = tag.parent
    while header is not None and _name(header) != "<h_unsupported_sent>":
        header = header.parent
    listed = list(header.find_subtrees("<option_tag_echo>")) if header is not None else [tag]
    index = next((i for i, other in enumerate(listed) if other is tag), 0)
    return tags[index] if index < len(tags) else str(tag)


def recalled_required_tag():
    tags = _recorded.get("server_tags") or ["play.basic"]
    return random.choice(tags)


def recalled_server_cseq():
    return _recorded["server_cseq"]


def interleaved_channels_of(message):
    channels = set()
    parameters = list(message.find_subtrees("<tp_interleaved>")) + list(message.find_subtrees("<tp_interleaved_rcv>"))
    for parameter in parameters:
        numbers = [int(str(channel)) for channel in parameter.find_subtrees("<channel>")]
        if len(numbers) == 2:
            channels.update(numbers)
        elif numbers:
            # 2326 10.12: RTCP on the channel above RTP unless given
            channels.update((numbers[0], numbers[0] + 1))
    return channels


def session_channels(tree):
    """Channels the SETUP replies of the session set with the interleaved parameter (2326 10.12)."""
    channels = set()
    for message in _messages_before(tree):
        if _name(message) == "<rep_setup_2xx>":
            channels |= interleaved_channels_of(message)
    return channels


def recalled_channel():
    """One of the session's interleaved channels (2326 10.12: RTP or RTCP), else the first."""
    channels = sorted(_recorded["channels"]) or [_recorded["channel"]]
    return bytes([random.choice(channels) % 256])


def _request_timestamp(reply):
    request = _exchange_request(reply)
    sent = [str(value) for value in request.find_subtrees("<timestamp_value>")] if request else []
    return sent[0] if sent else None


def timestamp_echoed(reply):
    """2326 12.38 (C13): a reply to a request with a Timestamp echoes its exact value (a reply
    without Timestamp holds <timestamp_not_echoed>, see timestamp_missing)."""
    sent = _request_timestamp(reply)
    received = [str(value) for value in reply.find_subtrees("<timestamp_value_rcv>")]
    return sent is None or not received or received[0] == sent


def timestamp_missing(headers):
    """1 where a reply's header block has no Timestamp field although its request carried one
    (2326 12.38), else 0: the count of <timestamp_not_echoed> after the header block."""
    if _request_timestamp(headers) is None:
        return 0
    return 0 if _first(headers, "<h_timestamp_rcv>") is not None else 1


def _required_tags(reply):
    request = _exchange_request(reply)
    return {str(tag) for tag in request.find_subtrees("<option_tag_unknown>")} if request else set()


def _shown_unsupported(tree):
    """The option-tags earlier replies of the session listed in Unsupported, which "lists the
    features not supported by the server" (2326 12.40)."""
    shown = set()
    for message in _messages_before(tree):
        if not _from_client(message):
            for header in message.find_subtrees("<h_unsupported>"):
                shown |= {str(tag) for tag in header.find_subtrees("<option_tag_rcv>")}
    return shown


def _answers_options(headers):
    """The status code of a reply that answers its request's options: a 2xx (the server carried
    the request out) or 551 (Option not supported, 2326 11.3.14), else None. Other refusals (401,
    454, 405, ...) reject the request before its options matter; 1xx replies answer nothing."""
    try:
        code = status_code(_message_of(headers))
    except Exception:
        return None
    return code if 200 <= code < 300 or code == 551 else None


def _unsupported_required(headers, tags, code):
    """The option-tags of the request's Require the messages of the session show the server does
    not support: those an earlier reply listed in Unsupported (2326 12.40), and the only option of
    a request that a 551 answers ("An option given in the Require or the Proxy-Require fields was
    not supported", 11.3.14) when the request has one Require option-tag and no Proxy-Require."""
    shown = tags & _shown_unsupported(headers)
    if code == 551 and len(tags) == 1:
        request = _exchange_request(headers)
        if request is not None and _first(request, "<h_proxy_require>") is None:
            shown |= tags
    return shown


def unsupported_listed(headers):
    """2326 12.32 (C21): "The server MUST respond to this header by using the Unsupported header to
    negatively acknowledge those options which are NOT supported": the Unsupported field of a
    2xx or 551 reply to a request with Require lists every option-tag of that Require the session
    shows the server does not support (_unsupported_required). Whether the server supports an
    option-tag is a property of the server that only its messages show, so an option-tag no
    earlier reply of the session refused binds nothing (3.8: anyone may define private tags). A
    reply without Unsupported is judged by require_acknowledged."""
    tags = _required_tags(headers)
    if not tags:
        return True
    code = _answers_options(headers)
    if code is None:
        return True
    listed = {str(tag) for header in headers.find_subtrees("<h_unsupported>")
              for tag in header.find_subtrees("<option_tag_rcv>")}
    if not listed:
        return True
    return _unsupported_required(headers, tags, code) <= listed


def require_acknowledged(headers):
    """2326 12.32 (C21): a 2xx or 551 reply to a request with Require has an Unsupported field
    when the session shows that the server does not support one of its option-tags (an earlier
    reply listed it in Unsupported, 12.40), and a 551 to a request whose only options are those
    of its Require always has one: 551 states that one of them is not supported (11.3.14), which
    12.32 makes the server acknowledge in Unsupported."""
    tags = _required_tags(headers)
    if not tags:
        return True
    code = _answers_options(headers)
    if code is None or _first(headers, "<h_unsupported>") is not None:
        return True
    if code == 551:
        request = _exchange_request(headers)
        if request is not None and _first(request, "<h_proxy_require>") is None:
            return False
    return not _unsupported_required(headers, tags, code)


def scale_answered(headers):
    """2326 12.34 (C17): the header block of a 2xx reply to a PLAY or RECORD with Scale has a Scale
    field (the response MUST contain the scale value the server chose). Scale is an optional
    field (Table 3 "opt."): a server that does not implement it chooses no scale and ignores the
    field like any unknown one (2326 12), so the requirement binds a server that has shown on this
    connection that it implements Scale, by a Scale field in an earlier reply."""
    if not any(not _from_client(message) and _first(message, "<h_scale_rcv>") is not None
               for message in _messages_before(headers)):
        return True
    request = _exchange_request(headers)
    if request is None or _first(request, "<h_scale>") is None:
        return True
    if bytes(request).split(b" ", 1)[0] not in (b"PLAY", b"RECORD"):
        return True
    try:
        code = status_code(_message_of(headers))
    except Exception:
        return True
    if not 200 <= code < 300:
        return True
    return _first(headers, "<h_scale_rcv>") is not None


# 9110 5.3: fields that are no comma-separated lists, by nonterminal and, for those read as
# text (<h_known_text>), by field name
SINGLE_FIELDS = ("<h_content_length>", "<h_content_type>", "<h_session_rcv>", "<h_content_base>",
                 "<h_content_location>", "<h_location>", "<h_scale_rcv>", "<h_speed_rcv>",
                 "<h_timestamp_rcv>", "<h_transport_rcv>", "<h_expires>", "<h_last_modified>")
SINGLE_TEXT_FIELDS = ("date", "server", "retry-after", "bandwidth", "blocksize", "user-agent",
                      "from", "referer", "if-modified-since", "authorization", "conference",
                      "proxy-authorization", "key-mgmt", "host")


def at_most_once(headers):
    """9110 5.3 (C14, C34): no repeated field lines of a field that is no comma-separated list
    (Transport of a reply: the one transport-spec the server chose, 2326 12.39)."""
    for name in SINGLE_FIELDS:
        if sum(1 for _ in headers.find_subtrees(name)) > 1:
            return False
    names = [str(field).split(":", 1)[0].strip().lower() for field in headers.find_subtrees("<h_known_text>")]
    return all(names.count(name) <= 1 for name in SINGLE_TEXT_FIELDS)


def _spec_ids(spec, interleaved, client_port, port):
    """What identifies a transport-spec among those of a request: its first interleaved channel,
    client RTP port or multicast port (2326 12.39)."""
    ids = set()
    for name, kind in ((interleaved, "i"), (client_port, "c"), (port, "c")):
        for node in spec.find_subtrees(name):
            first = _first(node, "<channel>") if kind == "i" else None
            text = str(first) if first is not None else str(node).split("=", 1)[-1]
            digits = "".join(ch for ch in text.split("-")[0] if ch.isdigit())
            if digits:
                ids.add((kind, int(digits)))
    return ids


# the transport-specs a SETUP offers (2326 12.39), in every Transport form of the requests
OFFERED_SPECS = ("<ts_udp_unicast>", "<ts_tcp_interleaved>", "<ts_multicast_server>",
                 "<ts_multicast_client>", "<h_transport_record>")


def _asks_append(spec):
    """Whether an offered transport-spec asks to record (mode RECORD) and append (2326 12.39)."""
    if _first(spec, "<tp_append>") is None:
        return False
    return _first(spec, "<mode_record>") is not None or \
        any(str(mode).upper() == "RECORD" for mode in spec.find_subtrees("<mode_method>"))


def _ids_of(specs):
    """The ids of the given offered transport-specs (see _spec_ids)."""
    return set().union(*[_spec_ids(spec, "<tp_interleaved>", "<client_port_pair>", "<client_port_pair>")
                         for spec in specs]) if specs else set()


def _request_method(message):
    """The method of a request message (2326 6.1: Method SP Request-URI SP RTSP-Version)."""
    return bytes(message).split(b" ", 1)[0].decode("latin-1")


def _server_replies_before(tree):
    """The server's replies earlier in the session."""
    return [message for message in _messages_before(tree)
            if not _from_client(message) and _name(message).startswith("<rep_")]


def _listed_methods(reply, field):
    """The methods of the Public or Allow fields (`field`: <h_public>, <h_allow>) of a reply, one
    set per field (2326 12.28, 12.4: 1#method)."""
    return [{str(method) for method in header.find_subtrees("<method_rcv>")}
            for header in reply.find_subtrees(field)]


def _answered_501(reply, method):
    """Whether a reply is a 501 Not Implemented (2326 10, 11.3.19) to a request of `method`."""
    request = _exchange_request(reply)
    if request is None or _request_method(request) != method:
        return False
    try:
        return status_code(reply) == 501
    except Exception:
        return False


def _has_range(request):
    """Whether a request carries a Range field (2326 12.29; field names are case-insensitive)."""
    return re.search(rb"\r\nrange[ \t]*:", bytes(request), re.IGNORECASE) is not None


def _is_aggregate_of(uri, target):
    """Whether the Request-URI `uri` is the URL `target` itself or the aggregate URL of the
    presentation `target` is a stream of (2326 1.3, C.1.1: stream URLs below the presentation)."""
    path, wanted = _uri_path(uri).rstrip("/"), _uri_path(target).rstrip("/")
    return bool(path) and (wanted == path or wanted.startswith(path + "/"))


def _records_not(tree):
    """Whether earlier replies of the session show that the server does not record (2326 10.11),
    hence does not append, for the resource the request of `tree` addresses: a Public field
    without RECORD (12.28; 1.5: "The server SHOULD list the methods it supports using the Public
    response header"), a 501 to a RECORD that carried no Range (10: the method is not
    implemented; 12.29 lets a 501 refuse a Range format instead), or an Allow field without
    RECORD in a reply to a request whose Request-URI is this request's own URL or its aggregate
    URL (12.4: "the methods supported by the resource identified by the request-URI"). A 405 to
    a RECORD is no evidence: 11.3.1 prescribes it for a RECORD in a session set up for PLAY."""
    request = _exchange_request(tree)
    target = _request_uri(request) if request is not None else None
    for reply in _server_replies_before(tree):
        if any("RECORD" not in methods for methods in _listed_methods(reply, "<h_public>")):
            return True
        earlier = _exchange_request(reply)
        if earlier is None:
            continue
        if _answered_501(reply, "RECORD") and not _has_range(earlier):
            return True
        if target is not None and _is_aggregate_of(_request_uri(earlier), target) \
                and any("RECORD" not in methods for methods in _listed_methods(reply, "<h_allow>")):
            return True
    return False


def append_refused(reply):
    """2326 12.39 (C15): "If appending is requested and the server does not support this, it
    MUST refuse the request rather than overwrite the resource identified by the URI." Whether the
    server supports appending is a property of the server that only its messages show: the
    requirement binds once earlier replies of the session show that it does not record
    (_records_not), and a server that does not record does not append. Then it answers no SETUP
    that asks to append (an offered transport-spec with mode RECORD and append) with a 2xx that
    accepts such a spec for recording; without such evidence every reply passes. The reply's
    Transport indicates the values actually chosen (12.39); a chosen transport without mode has
    the default mode PLAY ("If not provided, the default is PLAY"), and append "is ignored if the
    mode parameter does not contain RECORD": a chosen transport whose mode, explicit or default,
    lacks RECORD records nothing and overwrites nothing. A chosen transport with RECORD accepts an
    asking spec when every offered spec asks to append, or when its interleaved channel, client
    port or multicast port is that of an asking spec and of no offered spec without append. A 2xx
    without Transport (12.39: the server MAY omit it) accepts the request as offered: a violation
    when every offered spec asks to append, no evidence of an asking spec otherwise."""
    request = _exchange_request(reply)
    if request is None:
        return True
    offered = [spec for name in OFFERED_SPECS for spec in request.find_subtrees(name)]
    asking = [spec for spec in offered if _asks_append(spec)]
    if not asking or not _records_not(reply):
        return True
    chosen = _first(reply, "<transport_spec_rcv>")
    if chosen is None:
        return len(asking) < len(offered)
    modes = [str(method).upper() for mode in chosen.find_subtrees("<tp_mode_rcv>")
             for method in mode.find_subtrees("<method_rcv>")]
    if "RECORD" not in modes:
        return True
    if len(asking) == len(offered):
        return False
    chosen_ids = _spec_ids(chosen, "<tp_interleaved_rcv>", "<tp_client_port_rcv>", "<tp_port_rcv>")
    matched = _ids_of(asking) & chosen_ids
    return not matched or bool(matched & _ids_of([spec for spec in offered if not _asks_append(spec)]))


def _is_2xx(message):
    """Whether a server message is a final 2xx reply, keeping the connection or closing it."""
    return _first(message, "<rep_2xx>") is not None or _first(message, "<rep_2xx_closing>") is not None


def new_session_distinct(reply):
    """2326 12.37 (C11): a SETUP that starts a new session for a URL gets an identifier other
    than the sessions of the same presentation still live on this connection (set up and not
    ended by a 2xx TEARDOWN). Checked on every 2xx, however the state's rule names the reply
    (<rep_setup_2xx>, <rep_any> after <req_setup_close>, <rep_2xx_closing>); a session counts as
    set up by any earlier 2xx to a new-session SETUP and as ended by any 2xx to a TEARDOWN."""
    request = _exchange_request(reply)
    if request is None or _name(request) not in NEW_SESSION_SETUPS:
        return True
    value = _first(reply, "<session_id_rcv>")
    if value is None:
        return True
    presentation = _uri_path(_request_uri(request)).split("/", 1)[0]
    live = {}
    for message in _messages_before(reply):
        if _from_client(message) or not _is_2xx(message):
            continue
        answered = _exchange_request(message)
        if answered is None:
            continue
        if _name(answered) in NEW_SESSION_SETUPS:
            old = _first(message, "<session_id_rcv>")
            if old is not None:
                live[str(old)] = _uri_path(_request_uri(answered)).split("/", 1)[0]
        elif _request_method(answered) == "TEARDOWN":
            torn = _first(answered, "<session_id_sent>")
            if torn is not None:
                live.pop(str(torn), None)
    return live.get(str(value)) != presentation


def conference_unchanged(header):
    """2326 12.9 (C27): the conference-id stays the same within the RTSP session."""
    if _name(_message_of(header)) in NEW_SESSION_SETUPS:
        return True
    value = str(_first(header, "<conference_id>"))
    earlier = []
    for message in _messages_before(header):
        if _name(message) in NEW_SESSION_SETUPS:
            earlier = []
        earlier += [str(old) for old in message.find_subtrees("<conference_id>")]
        earlier += [str(old) for old in message.find_subtrees("<conference_id_unknown>")]
    return all(old == value for old in earlier)


def recalled_conference():
    """The conference-id of the session, else the one the test setup gives (2326 12.9)."""
    return _recorded["conference"] or RTSP_CONFERENCE


def cseq_echoed(headers):
    """2326 12.17 (C1): the reply carries the CSeq of the request it answers."""
    return str(_first(headers, "<cseq_value_rcv>")) == request_cseq(headers)


def no_content_length(reply):
    """9110 8.6 (C8): no Content-Length in a 1xx reply."""
    return not has_header(reply, "<h_content_length>")


def no_content_length_in_204(reply):
    """9110 8.6, 2326 4.4 (C7, C8): no Content-Length, hence no body, in a 204 reply."""
    return status_code(reply) != 204 or not has_header(reply, "<h_content_length>")


# 2326 6.1 and Table 2: the methods of RTSP/1.0; a server must implement OPTIONS, SETUP, PLAY
# and TEARDOWN ("required"), the others are "recommended" or "optional"
RTSP_METHODS = ("DESCRIBE", "ANNOUNCE", "GET_PARAMETER", "OPTIONS", "PAUSE", "PLAY", "RECORD",
                "REDIRECT", "SETUP", "SET_PARAMETER", "TEARDOWN")
REQUIRED_METHODS = ("OPTIONS", "SETUP", "PLAY", "TEARDOWN")


def _set_up_for_play(tree):
    """Whether a SETUP of the session earlier got a 2xx whose transport has no mode RECORD: an
    explicit mode without it, or none (2326 12.39: "If not provided, the default is PLAY"); a 2xx
    without Transport takes the mode of the request's offer."""
    for message in _messages_before(tree):
        if _name(message) != "<rep_setup_2xx>":
            continue
        chosen = _first(message, "<transport_spec_rcv>")
        text = bytes(chosen if chosen is not None else (_exchange_request(message) or message))
        if re.search(rb'mode[ \t]*=[ \t]*"?[A-Za-z_, \t]*RECORD', text, re.IGNORECASE) is None:
            return True
    return False


def unimplemented_refused(reply):
    """2326 10, notes on Table 2 (C25, F52): "If a server does not support a particular method,
    it MUST return "501 Not Implemented"". Whether the server supports a method is a property of
    the server that only its messages show: the requirement binds once an earlier reply of the
    session left the method out of its Public field (12.28; 1.5: "The server SHOULD list the
    methods it supports using the Public response header"), for an extension method (6.1) also
    once an earlier reply refused it with 501 (to a method 2326 defines a 501 may refuse a Range
    format instead, 12.29). It concerns the methods a server need not implement: the extension
    methods and those Table 2 calls recommended or optional (DESCRIBE, ANNOUNCE, PAUSE,
    GET_PARAMETER, SET_PARAMETER, RECORD); every server implements the required ones (OPTIONS,
    SETUP, PLAY, TEARDOWN), whether its Public lists them or not. Then the reply is 501 or a
    refusal a server gives before it looks at the method: 401 and 407 (credentials), a 5xx of its
    own failure, load or a gateway (not 505: the request is RTSP/1.0), or 551 to a request with
    Require or Proxy-Require (12.32, 12.27); a 3xx has its own alternative. 405 to a RECORD
    passes in a session set up for PLAY (11.3.1: "also to be used if a RECORD request is issued
    even though the mode parameter in the Transport header only specified PLAY"). Without such
    evidence every reply passes: the server may implement the method."""
    request = _exchange_request(reply)
    if request is None or not _from_client(request):
        return True
    method = _request_method(request)
    if method in REQUIRED_METHODS:
        return True
    code = status_code(reply)
    if code == 551:
        if _required_tags(reply) or _first(request, "<h_proxy_require>") is not None:
            return True
    elif code in (401, 407, 501) or (500 <= code < 600 and code != 505):
        return True
    earlier_replies = _server_replies_before(reply)
    shown = any(method not in methods for earlier in earlier_replies
                for methods in _listed_methods(earlier, "<h_public>"))
    if not shown and method not in RTSP_METHODS:
        shown = any(_answered_501(earlier, method) for earlier in earlier_replies)
    if not shown:
        return True
    return method == "RECORD" and code == 405 and _set_up_for_play(reply)


def challenge_in_401(reply):
    """9110 15.5.2 (C32): a 401 reply carries WWW-Authenticate."""
    return status_code(reply) != 401 or has_header(reply, "<h_www_authenticate>")


def challenge_in_407(reply):
    """9110 15.5.8 (C33): a 407 reply carries Proxy-Authenticate."""
    return status_code(reply) != 407 or has_header(reply, "<h_proxy_authenticate>")


def allow_in_405(reply):
    """2326 11.3.1 (C23): a 405 reply carries Allow."""
    return status_code(reply) != 405 or has_header(reply, "<h_allow>")


def location_in_redirect(request):
    """2326 10.10 (C26): REDIRECT carries Location."""
    return has_header(request, "<h_location>")


EXTENSION_TCHARS = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def extension_method():
    """An extension-method (2326 6.1: token): now and then a familiar X_ name, else a token of
    random tchars; never a method 2326 defines (in any case, so that no server mistakes it for
    one), never starting with "$" (10.12)."""
    while True:
        if random.random() < 0.4:
            name = random.choice(["X_FANDANGO", "X_PROBE", "x-fandango", "Fandango.Test", "x_probe~2"])
        else:
            name = random.choice(EXTENSION_TCHARS.replace("$", "")) + "".join(
                random.choice(EXTENSION_TCHARS) for _ in range(random.randint(0, 11)))
        if name.upper() not in RTSP_METHODS:
            return name


def name_case(canonical):
    """A field name as sent: canonical mostly, lower or upper case now and then (9110 5.1)."""
    return random.choices([canonical, canonical.lower(), canonical.upper()], [8, 1, 1])[0]


def ows_value():
    """Whitespace after a field's colon: mostly one space, now and then none, two or a tab."""
    return random.choices(["", " ", "  ", "\t"], [4, 13, 2, 1])[0]


def auth_space():
    """The 1*SP between auth-scheme and token68 of sent credentials (9110 11.4): mostly one."""
    return random.choices([" ", "  ", "   "], [8, 1, 1])[0]


def basic_credentials(user, password):
    """token68 of the Basic scheme: base64 of user-id ":" password (2326 D.2.2, 9110 11.4)."""
    return base64.b64encode(f"{user}:{password}".encode()).decode()


def random_ntp_like():
    return f"{random.randint(0, 99999)}.{random.randint(0, 999):03d}"


# ======================================================================================
# The session: the client state machine (2326 A.1)
# ======================================================================================
#
# Each state has one alternative per request the client may send in it (2326 A.1: "Messages
# not listed for each state MUST NOT be issued by the client in that state, with the exception
# of messages not affecting state"). The request is followed by what the server may send
# before its final reply (<interim>), then the final reply, whose class selects the next state:
# 2xx the state of the table, 3xx Init, 4xx/5xx no change (2326 A.1).

# 2326 A.1: the client starts in Init; a session opens with the client's first request. A SETUP
# that no description or announcement preceded (<req_setup>) comes only after a first exchange:
# as the shortest way into Ready, Fandango's planner otherwise opens most sessions with it, and a
# server that needs the DESCRIBE first (2326 C.1.1: the description names the streams), such as
# ZLMediaKit, closes those connections; every SETUP form stays in Init
<start> ::= <TimerControl:reply_start> <opening_requesting>
<opening_requesting> ::= <init_opening> | <expired_before_request> <opening_restart> \
    | <server_initiated> <opening_requesting> \
    | <exchange_server_redirect> <opening_requesting> \
    | <exchange_server_redirect_ranged> <opening_requesting>
<opening_restart> ::= <TimerControl:reply_start> <opening_requesting> | ''

# Each request starts the reply timer 1 just before it is sent (see <reply_start>), the final
# reply is followed by its cancel (<reply_done>, <reply_settled>). The timer runs for the reply:
# an expiry that arrives before the request went out (a slow generation, e.g. while the server
# streams; <expired_before_request>) returns to the state, which starts the timer again for its
# next request (<*_requesting>; before the first request <opening_requesting>); it does not end
# the session there. Interleaved data
# (2326 10.12: it arrives in any state, e.g. RTCP) and the server's requests (2326 9: at any
# point of the persistent connection) are accepted between all messages: between exchanges
# (<server_initiated>), within them (<interim>, <reply_done>) and between the timer's start and
# the request (<*_requesting>: a REDIRECT without Range leads to Init, whose request then goes
# out, one with a Range keeps the state, 2326 10.10). A reply that stays away ends the session
# when the timer expires.

# 2326 A.1 Init: SETUP -> Ready on 2xx; the other requests leave Init; session requests without a
# session are refused.
<state_init> ::= <TimerControl:reply_start> <init_requesting> \
    | <server_initiated> <state_init> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <state_init> \
    | ''
<init_requesting> ::= <server_initiated> <init_requesting> \
    | <exchange_server_redirect_ranged> <init_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <state_init> \
    | <init_transition>
<init_transition> ::= <Client:req_setup> <resend_setup>* <interim>* <setup_reply_in_init> \
    | <init_opening>
<init_opening> ::= <Client:req_describe_media> <resend_describe_media>* <interim>* <describe_reply_in_init> \
    | <Client:req_announce_record> <resend_announce_record>* <interim>* <announce_reply_in_init> \
    | <Client:req_play_without_setup> <resend_play_without_setup>* <interim>* <play_without_setup_reply> \
    | <Client:req_play_without_setup_any_range> <resend_play_without_setup_any_range>* <interim>* <play_without_setup_reply> \
    | <close_request> <interim>* <close_reply> \
    | <stateless_request> <interim>* <stateless_reply_in_init> \
    | <no_session_request> <interim>* <no_session_reply> \
    | <Client:req_extension> <resend_extension>* <interim>* <extension_reply_in_init> \
    | <Client:req_extension_close> <resend_extension_close>* <interim>* <extension_close_reply> \
    | <pipelined_exchange>
<setup_reply_in_init> ::= <Server:rep_setup_2xx> <reply_end_ready> \
    | <Server:rep_not_2xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
# 2326 C.1.1, 10.4: the description names the streams (a=control); the SETUP that follows a
# successful DESCRIBE of the presentation addresses one of them (a dependent exchange with its
# own request, <req_setup_described>), also joining a conference (<req_setup_unknown_conference>)
# or closing the connection after the reply (<req_setup_close>); Init's other requests stay
# open in <state_init>
<describe_reply_in_init> ::= <Server:rep_describe_2xx> <reply_end_after_describe> \
    | <Server:rep_not_2xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<setup_after_describe> ::= <TimerControl:reply_start> <setup_after_describe_requesting> \
    | <server_initiated> <setup_after_describe> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <setup_after_describe> \
    | ''
<setup_after_describe_requesting> ::= <server_initiated> <setup_after_describe_requesting> \
    | <exchange_server_redirect_ranged> <setup_after_describe_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <setup_after_describe> \
    | <Client:req_setup_described> <resend_setup_described>* <interim>* <setup_reply_in_init> \
    | <Client:req_setup_unknown_conference> <resend_setup_unknown_conference>* <interim>* <setup_reply_in_init> \
    | <Client:req_setup_close> <resend_setup_close>* <interim>* <close_reply>
# 2326 10.3, 10.11: after the description of the presentation to record is accepted, the client
# sets up its stream for recording (a dependent exchange with its own request,
# <req_setup_announced>); Init's other requests stay open in <state_init>
<announce_reply_in_init> ::= <Server:rep_announce_2xx> <reply_end_after_announce> \
    | <Server:rep_not_2xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<setup_after_announce> ::= <TimerControl:reply_start> <setup_after_announce_requesting> \
    | <server_initiated> <setup_after_announce> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <setup_after_announce> \
    | ''
<setup_after_announce_requesting> ::= <server_initiated> <setup_after_announce_requesting> \
    | <exchange_server_redirect_ranged> <setup_after_announce_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <setup_after_announce> \
    | <Client:req_setup_announced> <resend_setup_announced>* <interim>* <setup_reply_in_init>
# 2326 A.2: an object that needs no SETUP (e.g. multicast) starts in Ready, so PLAY without a
# session plays it (F27) and its two-state machine (Ready, Playing) follows; any other object
# refuses it like the requests below
<play_without_setup_reply> ::= <Server:rep_play_2xx> <reply_end_playing_nosetup> \
    | <Server:rep_not_2xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
# 2326 12.10, 9112 9.6: after a request with "Connection: close" the connection ends (F87)
<close_reply> ::= <Server:rep_any> <reply_end_close> | <exchange_server_redirect> <interim>* <close_reply> \
    | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<stateless_reply_in_init> ::= <Server:rep_any> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# 2326 A.1 Ready: PLAY 2xx -> Playing, RECORD 2xx -> Recording, TEARDOWN 2xx -> Init,
# SETUP 2xx -> Ready
<state_ready> ::= <TimerControl:reply_start> <ready_requesting> \
    | <Client:interleaved_frame_sent> <state_ready> \
    | <server_initiated> <state_ready> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <state_ready> \
    | ''
<ready_requesting> ::= <server_initiated> <ready_requesting> \
    | <exchange_server_redirect_ranged> <ready_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <state_ready> \
    | <ready_transition>
<ready_transition> ::= <pipelined_in_ready> \
    | <Client:req_play> <resend_play>* <interim_session>* <play_reply_in_ready> \
    | <Client:req_play_any_range> <resend_play_any_range>* <interim_session>* <play_reply_in_ready> \
    | <Client:req_record> <resend_record>* <interim_session>* <record_reply_in_ready> \
    | <Client:req_record_any_range> <resend_record_any_range>* <interim_session>* <record_reply_in_ready> \
    | <Client:req_teardown> <resend_teardown>* <interim_session>* <teardown_reply_in_ready> \
    | <Client:req_setup_in_session> <resend_setup_in_session>* <interim_session>* <setup_reply_in_ready> \
    | <session_stateless_request> <interim_session>* <stateless_reply_in_ready> \
    | <session_close_request> <interim_session>* <close_reply> \
    | <Client:req_extension_in_session> <resend_extension_in_session>* <interim_session>* <extension_reply_in_ready> \
    | <Client:req_extension_in_session_close> <resend_extension_in_session_close>* <interim_session>* <extension_close_reply>
<play_reply_in_ready> ::= <Server:rep_play_2xx> <reply_end_playing> \
    | <Server:rep_err> <reply_end_ready> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<record_reply_in_ready> ::= <Server:rep_record_2xx> <reply_end_recording> \
    | <Server:rep_err> <reply_end_ready> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<teardown_reply_in_ready> ::= <Server:rep_teardown_2xx> <reply_end_init> \
    | <Server:rep_err> <reply_end_ready> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
# 2326 12.23: 304 to a conditional SETUP leaves the state unchanged
<setup_reply_in_ready> ::= <Server:rep_setup_2xx> <reply_end_ready> \
    | <Server:rep_err> <reply_end_ready> \
    | <Server:rep_304> <reply_end_ready> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<stateless_reply_in_ready> ::= <Server:rep_not_3xx> <reply_end_ready> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# 2326 A.1 Playing: PAUSE 2xx -> Ready, TEARDOWN 2xx -> Init, PLAY 2xx -> Playing,
# (the session does not end in Playing: while the server streams, the client ends it with a
# request, e.g. TEARDOWN, so that Fandango does not wait for a silence that never comes)
# SETUP 2xx -> Playing (changed transport, F71); A.1/A.2: at the end of the requested range the
# state becomes Ready, after which the client may RECORD (<req_record_after_play>)
<state_playing> ::= <TimerControl:reply_start> <playing_requesting> \
    | <Client:interleaved_frame_sent> <state_playing> \
    | <server_initiated> <state_playing> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <state_playing>
<playing_requesting> ::= <server_initiated> <playing_requesting> \
    | <exchange_server_redirect_ranged> <playing_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <state_playing> \
    | <playing_transition>
<playing_transition> ::= <pipelined_in_playing> \
    | <Client:req_pause> <resend_pause>* <interim_session>* <pause_reply_in_playing> \
    | <Client:req_pause_any_point> <resend_pause_any_point>* <interim_session>* <pause_reply_in_playing> \
    | <Client:req_teardown> <resend_teardown>* <interim_session>* <teardown_reply_in_playing> \
    | <Client:req_play_in_playing> <resend_play_in_playing>* <interim_session>* <play_reply_in_playing> \
    | <Client:req_play_any_range> <resend_play_any_range>* <interim_session>* <play_reply_in_playing> \
    | <Client:req_setup_in_session> <resend_setup_in_session>* <interim_session>* <setup_reply_in_playing> \
    | <Client:req_record_after_play> <resend_record_after_play>* <interim_session>* <record_reply_in_ready> \
    | <session_stateless_request> <interim_session>* <stateless_reply_in_playing> \
    | <session_close_request> <interim_session>* <close_reply> \
    | <Client:req_extension_in_session> <resend_extension_in_session>* <interim_session>* <extension_reply_in_playing> \
    | <Client:req_extension_in_session_close> <resend_extension_in_session_close>* <interim_session>* <extension_close_reply>
<req_play_in_playing> ::= <req_play>
# (either part of the Range split: no other RECORD is sent in Playing)
<req_record_after_play> ::= <req_record> | <req_record_any_range>
<pause_reply_in_playing> ::= <Server:rep_pause_2xx> <reply_end_ready> \
    | <Server:rep_err> <reply_end_playing> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<teardown_reply_in_playing> ::= <Server:rep_teardown_2xx> <reply_end_init> \
    | <Server:rep_err> <reply_end_playing> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<play_reply_in_playing> ::= <Server:rep_play_2xx> <reply_end_playing> \
    | <Server:rep_err> <reply_end_playing> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<setup_reply_in_playing> ::= <Server:rep_setup_2xx> <reply_end_playing> \
    | <Server:rep_err> <reply_end_playing> \
    | <Server:rep_304> <reply_end_playing> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<stateless_reply_in_playing> ::= <Server:rep_not_3xx> <reply_end_playing> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# 2326 A.1 Recording: PAUSE 2xx -> Ready, TEARDOWN 2xx -> Init, RECORD 2xx -> Recording,
# SETUP 2xx -> Recording (changed transport); the client sends the media as interleaved data
# (2326 10.12)
<state_recording> ::= <TimerControl:reply_start> <recording_requesting> \
    | <Client:interleaved_frame_sent> <state_recording> \
    | <server_initiated> <state_recording> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <state_recording> \
    | ''
<recording_requesting> ::= <server_initiated> <recording_requesting> \
    | <exchange_server_redirect_ranged> <recording_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <state_recording> \
    | <recording_transition>
<recording_transition> ::= <pipelined_in_recording> \
    | <Client:req_pause> <resend_pause>* <interim_session>* <pause_reply_in_recording> \
    | <Client:req_pause_any_point> <resend_pause_any_point>* <interim_session>* <pause_reply_in_recording> \
    | <Client:req_teardown> <resend_teardown>* <interim_session>* <teardown_reply_in_recording> \
    | <Client:req_record_in_recording> <resend_record_in_recording>* <interim_session>* <record_reply_in_recording> \
    | <Client:req_record_any_range> <resend_record_any_range>* <interim_session>* <record_reply_in_recording> \
    | <Client:req_setup_in_session> <resend_setup_in_session>* <interim_session>* <setup_reply_in_recording> \
    | <session_stateless_request> <interim_session>* <stateless_reply_in_recording> \
    | <session_close_request> <interim_session>* <close_reply> \
    | <Client:req_extension_in_session> <resend_extension_in_session>* <interim_session>* <extension_reply_in_recording> \
    | <Client:req_extension_in_session_close> <resend_extension_in_session_close>* <interim_session>* <extension_close_reply>
<req_record_in_recording> ::= <req_record>
<pause_reply_in_recording> ::= <Server:rep_pause_2xx> <reply_end_ready> \
    | <Server:rep_err> <reply_end_recording> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<teardown_reply_in_recording> ::= <Server:rep_teardown_2xx> <reply_end_init> \
    | <Server:rep_err> <reply_end_recording> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<record_reply_in_recording> ::= <Server:rep_record_2xx> <reply_end_recording> \
    | <Server:rep_err> <reply_end_recording> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<setup_reply_in_recording> ::= <Server:rep_setup_2xx> <reply_end_recording> \
    | <Server:rep_err> <reply_end_recording> \
    | <Server:rep_304> <reply_end_recording> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<stateless_reply_in_recording> ::= <Server:rep_not_3xx> <reply_end_recording> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# 2326 A.2: the state machine of an object that needs no SETUP: Ready and Playing only; PLAY
# 2xx -> Playing, PAUSE 2xx -> Ready, errors no change, 3xx Init. Its PLAY and PAUSE carry the
# Session the PLAY reply gave, if any (<h_session_nosetup>)
<state_ready_nosetup> ::= <TimerControl:reply_start> <ready_nosetup_requesting> \
    | <server_initiated> <state_ready_nosetup> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <state_ready_nosetup> \
    | ''
<ready_nosetup_requesting> ::= <server_initiated> <ready_nosetup_requesting> \
    | <exchange_server_redirect_ranged> <ready_nosetup_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <state_ready_nosetup> \
    | <pipelined_in_ready_nosetup> \
    | <Client:req_play_nosetup> <resend_play_nosetup>* <interim>* <play_nosetup_reply_in_ready> \
    | <Client:req_play_nosetup_any_range> <resend_play_nosetup_any_range>* <interim>* <play_nosetup_reply_in_ready> \
    | <stateless_request> <interim>* <stateless_reply_in_ready_nosetup> \
    | <nosetup_close_request> <interim>* <close_reply> \
    | <Client:req_extension_nosetup> <resend_extension_nosetup>* <interim>* <extension_reply_in_ready_nosetup> \
    | <Client:req_extension_nosetup_close> <resend_extension_nosetup_close>* <interim>* <extension_close_reply>
<play_nosetup_reply_in_ready> ::= <Server:rep_play_2xx> <reply_end_playing_nosetup> \
    | <Server:rep_err> <reply_end_ready_nosetup> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<stateless_reply_in_ready_nosetup> ::= <Server:rep_not_3xx> <reply_end_ready_nosetup> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<state_playing_nosetup> ::= <TimerControl:reply_start> <playing_nosetup_requesting> \
    | <server_initiated> <state_playing_nosetup> \
    | <exchange_server_redirect> <state_init> \
    | <exchange_server_redirect_ranged> <state_playing_nosetup>
<playing_nosetup_requesting> ::= <server_initiated> <playing_nosetup_requesting> \
    | <exchange_server_redirect_ranged> <playing_nosetup_requesting> \
    | <exchange_server_redirect> <init_requesting> \
    | <expired_before_request> <state_playing_nosetup> \
    | <pipelined_in_playing_nosetup> \
    | <Client:req_pause_nosetup> <resend_pause_nosetup>* <interim>* <pause_nosetup_reply_in_playing> \
    | <Client:req_pause_nosetup_any_point> <resend_pause_nosetup_any_point>* <interim>* <pause_nosetup_reply_in_playing> \
    | <Client:req_play_nosetup> <resend_play_nosetup>* <interim>* <play_nosetup_reply_in_playing> \
    | <Client:req_play_nosetup_any_range> <resend_play_nosetup_any_range>* <interim>* <play_nosetup_reply_in_playing> \
    | <stateless_request> <interim>* <stateless_reply_in_playing_nosetup> \
    | <nosetup_close_request> <interim>* <close_reply> \
    | <Client:req_pause_nosetup_close> <resend_pause_nosetup_close>* <interim>* <close_reply> \
    | <Client:req_extension_nosetup> <resend_extension_nosetup>* <interim>* <extension_reply_in_playing_nosetup> \
    | <Client:req_extension_nosetup_close> <resend_extension_nosetup_close>* <interim>* <extension_close_reply>
<pause_nosetup_reply_in_playing> ::= <Server:rep_pause_2xx> <reply_end_ready_nosetup> \
    | <Server:rep_err> <reply_end_playing_nosetup> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<play_nosetup_reply_in_playing> ::= <Server:rep_play_2xx> <reply_end_playing_nosetup> \
    | <Server:rep_err> <reply_end_playing_nosetup> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<stateless_reply_in_playing_nosetup> ::= <Server:rep_not_3xx> <reply_end_playing_nosetup> \
    | <Server:rep_3xx> <reply_end_init> \
    | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# 2326 9.2: over UDP (RTSP_TRANSPORT) a request whose reply stays away is resent when the reply
# timer expires (<resend_due>), "the same message" with "the original sequence number" (CSeq,
# expected_cseq), as often as the client chooses; over TCP an expiry is no occasion to resend
# (where on <resend_due>): "requests MUST NOT be retransmitted"
<resend_due> ::= <timer_expired>
<resend_setup> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_resent>
<req_setup_resent> ::= <req_setup>
<resend_describe_media> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_describe_media_resent>
<req_describe_media_resent> ::= <req_describe_media>
<resend_announce_record> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_announce_record_resent>
<req_announce_record_resent> ::= <req_announce_record>
<resend_play_without_setup> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_without_setup_resent>
<req_play_without_setup_resent> ::= <req_play_without_setup>
<resend_play_without_setup_any_range> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_without_setup_any_range_resent>
<req_play_without_setup_any_range_resent> ::= <req_play_without_setup_any_range>
<resend_extension> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_extension_resent>
<req_extension_resent> ::= <req_extension>
<resend_extension_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_extension_close_resent>
<req_extension_close_resent> ::= <req_extension_close>
<resend_extension_in_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_extension_in_session_resent>
<req_extension_in_session_resent> ::= <req_extension_in_session>
<resend_extension_in_session_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_extension_in_session_close_resent>
<req_extension_in_session_close_resent> ::= <req_extension_in_session_close>
<resend_extension_nosetup> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_extension_nosetup_resent>
<req_extension_nosetup_resent> ::= <req_extension_nosetup>
<resend_extension_nosetup_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_extension_nosetup_close_resent>
<req_extension_nosetup_close_resent> ::= <req_extension_nosetup_close>
<resend_setup_described> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_described_resent>
<req_setup_described_resent> ::= <req_setup_described>
<resend_setup_unknown_conference> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_unknown_conference_resent>
<req_setup_unknown_conference_resent> ::= <req_setup_unknown_conference>
<resend_setup_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_close_resent>
<req_setup_close_resent> ::= <req_setup_close>
<resend_setup_announced> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_announced_resent>
<req_setup_announced_resent> ::= <req_setup_announced>
<resend_play> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_resent>
<req_play_resent> ::= <req_play>
<resend_record> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_record_resent>
<req_record_resent> ::= <req_record>
<resend_teardown> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_teardown_resent>
<req_teardown_resent> ::= <req_teardown>
<resend_setup_in_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_in_session_resent>
<req_setup_in_session_resent> ::= <req_setup_in_session>
<resend_pause> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_resent>
<req_pause_resent> ::= <req_pause>
<resend_play_any_range> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_any_range_resent>
<req_play_any_range_resent> ::= <req_play_any_range>
<resend_pause_any_point> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_any_point_resent>
<req_pause_any_point_resent> ::= <req_pause_any_point>
<resend_record_any_range> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_record_any_range_resent>
<req_record_any_range_resent> ::= <req_record_any_range>
<resend_play_in_playing> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_in_playing_resent>
<req_play_in_playing_resent> ::= <req_play_in_playing>
<resend_record_after_play> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_record_after_play_resent>
<req_record_after_play_resent> ::= <req_record_after_play>
<resend_record_in_recording> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_record_in_recording_resent>
<req_record_in_recording_resent> ::= <req_record_in_recording>
<resend_play_nosetup> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_nosetup_resent>
<req_play_nosetup_resent> ::= <req_play_nosetup>
<resend_pause_nosetup> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_nosetup_resent>
<req_pause_nosetup_resent> ::= <req_pause_nosetup>
<resend_play_nosetup_any_range> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_nosetup_any_range_resent>
<req_play_nosetup_any_range_resent> ::= <req_play_nosetup_any_range>
<resend_pause_nosetup_any_point> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_nosetup_any_point_resent>
<req_pause_nosetup_any_point_resent> ::= <req_pause_nosetup_any_point>
<resend_pause_nosetup_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_nosetup_close_resent>
<req_pause_nosetup_close_resent> ::= <req_pause_nosetup_close>
<resend_options> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_options_resent>
<req_options_resent> ::= <req_options>
<resend_describe> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_describe_resent>
<req_describe_resent> ::= <req_describe>
<resend_describe_wrong_credentials> ::= <TimerEvent:resend_due> <TimerControl:reply_start_auth> <Client:req_describe_wrong_credentials_resent>
<req_describe_wrong_credentials_resent> ::= <req_describe_wrong_credentials>
<resend_announce> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_announce_resent>
<req_announce_resent> ::= <req_announce>
<resend_get_parameter> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_get_parameter_resent>
<req_get_parameter_resent> ::= <req_get_parameter>
<resend_set_parameter> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_set_parameter_resent>
<req_set_parameter_resent> ::= <req_set_parameter>
<resend_bad_version> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_bad_version_resent>
<req_bad_version_resent> ::= <req_bad_version>
<resend_setup_unsupported_transport> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_unsupported_transport_resent>
<req_setup_unsupported_transport_resent> ::= <req_setup_unsupported_transport>
<resend_get_parameter_in_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_get_parameter_in_session_resent>
<req_get_parameter_in_session_resent> ::= <req_get_parameter_in_session>
<resend_set_parameter_in_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_set_parameter_in_session_resent>
<req_set_parameter_in_session_resent> ::= <req_set_parameter_in_session>
<resend_announce_in_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_announce_in_session_resent>
<req_announce_in_session_resent> ::= <req_announce_in_session>
<resend_options_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_options_close_resent>
<req_options_close_resent> ::= <req_options_close>
<resend_describe_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_describe_close_resent>
<req_describe_close_resent> ::= <req_describe_close>
<resend_get_parameter_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_get_parameter_close_resent>
<req_get_parameter_close_resent> ::= <req_get_parameter_close>
<resend_set_parameter_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_set_parameter_close_resent>
<req_set_parameter_close_resent> ::= <req_set_parameter_close>
<resend_announce_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_announce_close_resent>
<req_announce_close_resent> ::= <req_announce_close>
<resend_teardown_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_teardown_close_resent>
<req_teardown_close_resent> ::= <req_teardown_close>
<resend_play_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_close_resent>
<req_play_close_resent> ::= <req_play_close>
<resend_pause_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_close_resent>
<req_pause_close_resent> ::= <req_pause_close>
<resend_record_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_record_close_resent>
<req_record_close_resent> ::= <req_record_close>
<resend_setup_in_session_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_setup_in_session_close_resent>
<req_setup_in_session_close_resent> ::= <req_setup_in_session_close>
<resend_play_nosetup_close> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_nosetup_close_resent>
<req_play_nosetup_close_resent> ::= <req_play_nosetup_close>
<resend_play_no_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_play_no_session_resent>
<req_play_no_session_resent> ::= <req_play_no_session>
<resend_teardown_no_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_teardown_no_session_resent>
<req_teardown_no_session_resent> ::= <req_teardown_no_session>
<resend_record_no_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_record_no_session_resent>
<req_record_no_session_resent> ::= <req_record_no_session>
<resend_pause_no_session> ::= <TimerEvent:resend_due> <TimerControl:reply_start> <Client:req_pause_no_session_resent>
<req_pause_no_session_resent> ::= <req_pause_no_session>

# 9112 9.6: "A client, server, or proxy MAY close the transport connection at any time": the
# reply to a request may stay away. The client waits RTSP_REPLY_WAIT seconds for it (timer 1):
# its expiry before the reply ends the session; after the reply the client cancels it.
<reply_start> ::= <timer_start>
<reply_cancel> ::= <timer_cancel>
<reply_expired> ::= <timer_expired>
# an expiry that arrives after the timer's start, before the request went out (see <state_init>):
# one rule for all states, the state follows and starts the timer again
<expired_before_request> ::= <TimerEvent:reply_expired>
# the spec's only timer: id 1, running RTSP_REPLY_WAIT seconds (the standard library's
# <timer_id> and <timer_timeout> aliases, overridden)
<timer_id> ::= '1'
<timer_timeout> ::= r'[0-9]+(?:\.[0-9]+)?' := RTSP_REPLY_WAIT
# the same timer, started again for the reply to wrong credentials (<auth_request>), runs
# RTSP_AUTH_REPLY_WAIT seconds (where below); its cancel and expiry are those of timer 1
<reply_start_auth> ::= 'start: ' <timer_id> ' (' <timer_timeout> ')\n'

# 2326 7.1.1 / 9110 15.2: 1xx replies precede the final reply; 2326 10.12: interleaved data of
# either party may be sent at any time on the connection; 2326 9, 10: the server may send its
# requests at any time on a persistent connection, also while a request of the client waits
# for its reply
# (also a REDIRECT with a Range: it takes effect later, the state stays, 2326 10.10). The client
# sends interleaved data only on channels a SETUP of the session set up (2326 10.12): in Ready,
# Playing and Recording (<interim_session>), not in Init or the states of A.2
<interim> ::= <Server:interleaved_frame> | <Server:rep_1xx> | <server_request_exchange> \
    | <exchange_server_redirect_ranged>
<interim_session> ::= <interim> | <Client:interleaved_frame_sent>
# after the final reply (2326 10.10, A.1): interleaved data, requests of the server and REDIRECTs
# that arrive before the client cancels the timer, then the cancel, or the expiry if it comes
# first. Each reply continues with <reply_end_X>, X the state its class selects: a REDIRECT with
# a Range leaves X, an immediate REDIRECT leads to Init (<reply_done>, which accepts all of them,
# then <state_init>); after a reply that ends the connection (<reply_end_close>: the reply to a
# request with "Connection: close", or a reply that carries it, <rep_closing>) nothing follows.
# The first message that tells the two apart decides the alternative. The race between the
# cancel and the expiry is one rule for every state (<reply_settled>), as is the expiry before a
# request (<expired_before_request>): Fandango's planner weighs each place where it takes a step
# by how often it took it, and in a rule of its own per state the rarely taken expiry stayed the
# cheaper way on in each of them, so the planner waited for it after a reply.
<reply_done> ::= <server_initiated> <reply_done> | <exchange_server_redirect_ranged> <reply_done> \
    | <exchange_server_redirect> <reply_done> | <reply_settled>
# the race between the client's cancel and the timer's expiry after the final reply, one rule
# for all states: either message settles the timer
<reply_settled> ::= <TimerControl:reply_cancel> | <TimerEvent:reply_expired>
<reply_end_init> ::= <reply_done> <state_init>
<reply_end_close> ::= <reply_done>
<reply_end_ready> ::= <server_initiated> <reply_end_ready> | <exchange_server_redirect_ranged> <reply_end_ready> \
    | <reply_settled> <state_ready> \
    | <exchange_server_redirect> <reply_done> <state_init>
<reply_end_playing> ::= <server_initiated> <reply_end_playing> | <exchange_server_redirect_ranged> <reply_end_playing> \
    | <reply_settled> <state_playing> \
    | <exchange_server_redirect> <reply_done> <state_init>
<reply_end_recording> ::= <server_initiated> <reply_end_recording> | <exchange_server_redirect_ranged> <reply_end_recording> \
    | <reply_settled> <state_recording> \
    | <exchange_server_redirect> <reply_done> <state_init>
<reply_end_ready_nosetup> ::= <server_initiated> <reply_end_ready_nosetup> | <exchange_server_redirect_ranged> <reply_end_ready_nosetup> \
    | <reply_settled> <state_ready_nosetup> \
    | <exchange_server_redirect> <reply_done> <state_init>
<reply_end_playing_nosetup> ::= <server_initiated> <reply_end_playing_nosetup> | <exchange_server_redirect_ranged> <reply_end_playing_nosetup> \
    | <reply_settled> <state_playing_nosetup> \
    | <exchange_server_redirect> <reply_done> <state_init>
<reply_end_after_describe> ::= <server_initiated> <reply_end_after_describe> | <exchange_server_redirect_ranged> <reply_end_after_describe> \
    | <reply_settled> <setup_after_describe> \
    | <exchange_server_redirect> <reply_done> <state_init>
<reply_end_after_announce> ::= <server_initiated> <reply_end_after_announce> | <exchange_server_redirect_ranged> <reply_end_after_announce> \
    | <reply_settled> <setup_after_announce> \
    | <exchange_server_redirect> <reply_done> <state_init>

# 2326 9.1: the client MAY pipeline its requests; the server answers them in the order received
# (C4). Two requests that leave Init unchanged, then their replies in request order; the first
# reply may arrive before the second request is sent (<pipelined_rest>)
<pipelined_exchange> ::= <Client:req_pipelined_first> <interim>* <pipelined_rest>
<pipelined_rest> ::= <Client:req_pipelined_second> <interim>* <pipelined_replies> \
    | <Server:rep_pipelined_first> <interim>* <pipelined_after_first> \
    | <exchange_server_redirect> <interim>* <pipelined_rest> \
    | <TimerEvent:reply_expired> \
    | <Server:rep_pipelined_first_closing> <reply_end_close>
# after the first reply the client may also leave the second request unsent: the reply settles
# the timer as any final reply does (<reply_settled>), Init stays
<pipelined_after_first> ::= <Client:req_pipelined_second> <interim>* <pipelined_second_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_after_first> \
    | <reply_settled> <state_init>
<pipelined_replies> ::= <Server:rep_pipelined_first> <interim>* <pipelined_second_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_replies> | <TimerEvent:reply_expired> \
    | <Server:rep_pipelined_first_closing> <reply_end_close>
<pipelined_second_reply> ::= <Server:rep_pipelined_second> <reply_end_init> \
    | <exchange_server_redirect> <interim>* <pipelined_second_reply> | <TimerEvent:reply_expired> \
    | <Server:rep_pipelined_second_closing> <reply_end_close>
<req_pipelined_first> ::= <req_options> | <req_get_parameter> | <req_describe>
<req_pipelined_second> ::= <req_options> | <req_get_parameter> | <req_describe>
<rep_pipelined_first> ::= <rep_any>
<rep_pipelined_second> ::= <rep_any>

# 2326 9.1: "A client that supports persistent connections or connectionless mode MAY
# "pipeline" its requests"; the server answers in the order received (C4). In each state, two
# requests one after the other, then their replies in that order: the first reply's class
# selects the state in which the second request's reply rule continues (a dependent second
# request, <req_*_pipelined>). The first reply may also arrive before the second request goes
# out; that is the exchange of the state's own rule.
<pipelined_in_ready> ::= <Client:req_setup_in_session> <Client:req_play_pipelined> <interim_session>* <setup_play_replies_in_ready> \
    | <play_leading> <Client:req_pause_pipelined> <interim_session>* <play_pause_replies_in_ready> \
    | <play_leading> <Client:req_teardown_pipelined> <interim_session>* <play_teardown_replies_in_ready> \
    | <play_leading> <Client:req_get_parameter_pipelined> <interim_session>* <play_get_parameter_replies_in_ready> \
    | <record_leading> <Client:req_teardown_pipelined> <interim_session>* <record_teardown_replies_in_ready>
<setup_play_replies_in_ready> ::= <Server:rep_setup_2xx> <interim_session>* <play_reply_in_ready> \
    | <Server:rep_err> <interim_session>* <play_reply_in_ready> \
    | <Server:rep_304> <interim_session>* <play_reply_in_ready> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<play_pause_replies_in_ready> ::= <Server:rep_play_2xx> <interim_session>* <pause_reply_in_playing> \
    | <Server:rep_err> <interim_session>* <stateless_reply_in_ready> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<play_teardown_replies_in_ready> ::= <Server:rep_play_2xx> <interim_session>* <teardown_reply_in_playing> \
    | <Server:rep_err> <interim_session>* <teardown_reply_in_ready> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<play_get_parameter_replies_in_ready> ::= <Server:rep_play_2xx> <interim_session>* <stateless_reply_in_playing> \
    | <Server:rep_err> <interim_session>* <stateless_reply_in_ready> \
    | <Server:rep_3xx> <interim>* <stateless_reply_in_init> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<record_teardown_replies_in_ready> ::= <Server:rep_record_2xx> <interim_session>* <teardown_reply_in_recording> \
    | <Server:rep_err> <interim_session>* <teardown_reply_in_ready> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<pipelined_in_playing> ::= <pause_leading> <Client:req_play_pipelined> <interim_session>* <pause_play_replies_in_playing> \
    | <pause_leading> <Client:req_teardown_pipelined> <interim_session>* <pause_teardown_replies_in_playing>
<pause_play_replies_in_playing> ::= <Server:rep_pause_2xx> <interim_session>* <play_reply_in_ready> \
    | <Server:rep_err> <interim_session>* <play_reply_in_playing> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<pause_teardown_replies_in_playing> ::= <Server:rep_pause_2xx> <interim_session>* <teardown_reply_in_ready> \
    | <Server:rep_err> <interim_session>* <teardown_reply_in_playing> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<pipelined_in_recording> ::= <pause_leading> <Client:req_record_pipelined> <interim_session>* <pause_record_replies_in_recording> \
    | <pause_leading> <Client:req_teardown_pipelined> <interim_session>* <pause_teardown_replies_in_recording>
<pause_record_replies_in_recording> ::= <Server:rep_pause_2xx> <interim_session>* <record_reply_in_ready> \
    | <Server:rep_err> <interim_session>* <record_reply_in_recording> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<pause_teardown_replies_in_recording> ::= <Server:rep_pause_2xx> <interim_session>* <teardown_reply_in_ready> \
    | <Server:rep_err> <interim_session>* <teardown_reply_in_recording> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<pipelined_in_ready_nosetup> ::= <play_nosetup_leading> <Client:req_pause_nosetup_pipelined> <interim>* <play_pause_replies_in_ready_nosetup>
<play_pause_replies_in_ready_nosetup> ::= <Server:rep_play_2xx> <interim>* <pause_nosetup_reply_in_playing> \
    | <Server:rep_err> <interim>* <stateless_reply_in_ready_nosetup> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<pipelined_in_playing_nosetup> ::= <pause_nosetup_leading> <Client:req_play_nosetup_pipelined> <interim>* <pause_play_replies_in_playing_nosetup>
<pause_play_replies_in_playing_nosetup> ::= <Server:rep_pause_2xx> <interim>* <play_nosetup_reply_in_ready> \
    | <Server:rep_err> <interim>* <play_nosetup_reply_in_playing> \
    | <Server:rep_3xx> <interim>* <no_session_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
# a REDIRECT before the replies: both replies still arrive (further REDIRECTs may come first),
# then the session is in Init
<pipelined_redirected> ::= <Server:rep_any> <interim>* <redirected_reply> \
    | <exchange_server_redirect> <interim>* <pipelined_redirected> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
# PLAY, PAUSE and RECORD in a pipeline, first or second, carry their Range in either part of the
# split (2326 12.29: the request the session continues with or any other form, ";time=" included).
# The first request is the same message as the state's own exchange opens with, so that a reply
# that arrives before the second request continues that exchange.
<play_leading> ::= <Client:req_play> | <Client:req_play_any_range>
<pause_leading> ::= <Client:req_pause> | <Client:req_pause_any_point>
<record_leading> ::= <Client:req_record> | <Client:req_record_any_range>
<play_nosetup_leading> ::= <Client:req_play_nosetup> | <Client:req_play_nosetup_any_range>
<pause_nosetup_leading> ::= <Client:req_pause_nosetup> | <Client:req_pause_nosetup_any_point>
<req_play_pipelined> ::= <req_play> | <req_play_any_range>
<req_pause_pipelined> ::= <req_pause> | <req_pause_any_point>
<req_teardown_pipelined> ::= <req_teardown>
<req_record_pipelined> ::= <req_record> | <req_record_any_range>
<req_get_parameter_pipelined> ::= <req_get_parameter_in_session>
<req_pause_nosetup_pipelined> ::= <req_pause_nosetup> | <req_pause_nosetup_any_point>
<req_play_nosetup_pipelined> ::= <req_play_nosetup> | <req_play_nosetup_any_range>

# requests that do not affect the state (2326 A.1); any reply class. A SETUP with an
# unsupported transport sets nothing up: it is refused (2326 11.3.12)
<stateless_request> ::= <Client:req_options> <resend_options>* | <Client:req_describe> <resend_describe>* \
    | <auth_request> | <Client:req_announce> <resend_announce>* \
    | <Client:req_get_parameter> <resend_get_parameter>* | <Client:req_set_parameter> <resend_set_parameter>* | <Client:req_bad_version> <resend_bad_version>* \
    | <Client:req_setup_unsupported_transport> <resend_setup_unsupported_transport>*
# within a session also the requests that carry its Session: the liveness test GET_PARAMETER
# (2326 10.8, 12.37, F75), SET_PARAMETER and ANNOUNCE of the session's presentation or stream
# (2326 10.3, 10.9; Table 3: Session in all methods but SETUP and OPTIONS), DESCRIBE of the
# presentation
<session_stateless_request> ::= <stateless_request> | <Client:req_describe_media> <resend_describe_media>* \
    | <Client:req_get_parameter_in_session> <resend_get_parameter_in_session>* | <Client:req_set_parameter_in_session> <resend_set_parameter_in_session>* \
    | <Client:req_announce_in_session> <resend_announce_in_session>*

# requests with "Connection: close" (2326 12.10, 9112 9.6): the reply ends the connection (F87)
<close_request> ::= <Client:req_options_close> <resend_options_close>* | <Client:req_describe_close> <resend_describe_close>* \
    | <Client:req_get_parameter_close> <resend_get_parameter_close>* | <Client:req_set_parameter_close> <resend_set_parameter_close>* | <Client:req_announce_close> <resend_announce_close>*
<session_close_request> ::= <close_request> | <Client:req_teardown_close> <resend_teardown_close>* | <Client:req_play_close> <resend_play_close>* \
    | <Client:req_pause_close> <resend_pause_close>* | <Client:req_record_close> <resend_record_close>* | <Client:req_setup_in_session_close> <resend_setup_in_session_close>*
# in the states of A.2: PLAY without SETUP (PAUSE in Playing, above)
<nosetup_close_request> ::= <close_request> | <Client:req_play_nosetup_close> <resend_play_nosetup_close>*

# session requests sent in Init: no session, or one only an earlier session could have
# created (2326 11.3.5 454 Session Not Found, 11.3.6 455; 12.37); no reply class is prescribed
<no_session_request> ::= <Client:req_play_no_session> <resend_play_no_session>* | <Client:req_teardown_no_session> <resend_teardown_no_session>* \
    | <Client:req_record_no_session> <resend_record_no_session>* | <Client:req_pause_no_session> <resend_pause_no_session>*
<no_session_reply> ::= <Server:rep_any> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# DESCRIBE with wrong credentials (9110 11.6.2, 15.5.2): a server may answer it late, e.g. after
# a pause against password guessing; over TCP the spec sets the client no deadline (2326 9.2:
# no retransmission; 9112 9.6). Just before it the client restarts the reply timer with the
# longer RTSP_AUTH_REPLY_WAIT (<reply_start_auth>), between that start and the request it accepts
# what the server may send at any time: interleaved data and requests of the server, REDIRECTs
# with a Range (the state stays, 2326 10.10); an expiry before the request starts the timer
# again, and until it does the server may still send all these (<auth_expired>: e.g. interleaved
# data while playing). A REDIRECT without a Range moves the client to Init before its request
# went out (2326 A.1): it sends none, and the expiry that follows ends the session
# (<stateless_reply_in_X>); after an expiry no timer runs that could end it, so there it is
# not offered.
<auth_request> ::= <TimerControl:reply_start_auth> <auth_requesting>
<auth_requesting> ::= <Client:req_describe_wrong_credentials> <resend_describe_wrong_credentials>* \
    | <server_initiated> <auth_requesting> \
    | <exchange_server_redirect_ranged> <auth_requesting> \
    | <expired_before_request> <auth_expired> \
    | <exchange_server_redirect>
<auth_expired> ::= <server_initiated> <auth_expired> \
    | <exchange_server_redirect_ranged> <auth_expired> \
    | <auth_request>

# an extension method (2326 6.1): any reply, the state unchanged (A.1 defines no transition for
# it); a 3xx redirects (-> Init). A server without the method MUST return 501 Not Implemented
# (2326 10, C25): checked where the session shows that it lacks the method (unimplemented_refused,
# for every method a server need not implement)
<extension_reply_in_init> ::= <Server:rep_extension> <reply_end_init> \
    | <Server:rep_3xx> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<extension_reply_in_ready> ::= <Server:rep_extension> <reply_end_ready> \
    | <Server:rep_3xx> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<extension_reply_in_playing> ::= <Server:rep_extension> <reply_end_playing> \
    | <Server:rep_3xx> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<extension_reply_in_recording> ::= <Server:rep_extension> <reply_end_recording> \
    | <Server:rep_3xx> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<extension_reply_in_ready_nosetup> ::= <Server:rep_extension> <reply_end_ready_nosetup> \
    | <Server:rep_3xx> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<extension_reply_in_playing_nosetup> ::= <Server:rep_extension> <reply_end_playing_nosetup> \
    | <Server:rep_3xx> <reply_end_init> | <redirect_pending> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
# with "Connection: close": the refusal, then the connection ends (F87)
<extension_close_reply> ::= <Server:rep_extension> <reply_end_close> | <Server:rep_3xx> <reply_end_close> \
    | <exchange_server_redirect> <interim>* <close_reply> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>

# requests of the server (2326 10: ANNOUNCE, GET_PARAMETER, SET_PARAMETER, OPTIONS S->C),
# each answered by the client, and interleaved data
<server_initiated> ::= <Server:interleaved_frame> | <server_request_exchange>
<server_request_exchange> ::= <Server:srv_req_announce> <Server:interleaved_frame>* <Client:rep_to_announce> \
    | <Server:srv_req_get_parameter> <Server:interleaved_frame>* <Client:rep_to_get_parameter> \
    | <Server:srv_req_set_parameter> <Server:interleaved_frame>* <Client:rep_to_set_parameter> \
    | <Server:srv_req_options> <Server:interleaved_frame>* <Client:rep_to_options> \
    | <Server:srv_req_extension> <Server:interleaved_frame>* <Client:rep_to_extension>
# 2326 A.1: "Receiving a REDIRECT from the server is equivalent to receiving a 3xx" -> Init;
# 10.10: a REDIRECT with a Range takes effect at that time: until then the session keeps its
# state (and its requests may get 3xx or 454 once it took effect)
# an immediate REDIRECT while a request of the client waits for its reply: the reply (any
# class) still arrives, then the session is in Init (2326 10.10, A.1)
<redirect_pending> ::= <exchange_server_redirect> <interim>* <redirected_reply>
<redirected_reply> ::= <Server:rep_any> <reply_end_init> \
    | <exchange_server_redirect> <interim>* <redirected_reply> | <TimerEvent:reply_expired> \
    | <Server:rep_closing> <reply_end_close>
<exchange_server_redirect> ::= <Server:srv_req_redirect> <Server:interleaved_frame>* <Client:rep_to_redirect>
<exchange_server_redirect_ranged> ::= <Server:srv_req_redirect_ranged> <Server:interleaved_frame>* <Client:rep_to_redirect>

# ======================================================================================
# Basic rules (2326 15, 9110 5.6, 9112 5)
# ======================================================================================

<crlf> ::= '\r\n'
<sp> ::= ' '
# LWS = [CRLF] 1*( SP | HT ) (2326 15); received around field values, folding included
<lws> ::= r'(?:(?:\r\n)?[ \t]+)+'
<ows> ::= <lws>?
# whitespace the client sends where LWS is allowed: none, spaces or a tab
<ows_sent> ::= <wsp_sent>? := ows_value()
<wsp_sent> ::= ' ' | '  ' | '\t'
<digits> ::= r'[0-9]+'
<token> ::= r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
<quoted_string> ::= r'"(?:[^"\\\r\n]|\\.)*"'
# 9110 5.6.1.2: a recipient MUST accept empty list elements: [ element ] *( OWS "," OWS [ element ] );
# received lists are <list_lead>* element (<list_sep> element)* <list_trail>* (at least one element)
<list_lead> ::= ',' <ows>
<list_sep> ::= <ows> ',' <list_comma>* <ows>
<list_comma> ::= <ows> ','
<list_trail> ::= <ows> ','
<octet> ::= rb'[\x00-\xff]'
# runs of 16 and 256 octets: data of counted length in few nodes (bodies, interleaved data)
<block_16> ::= rb'[\x00-\xff]{16}'
<block_256> ::= rb'[\x00-\xff]{256}'
# TEXT without CR and LF (2326 15)
<text> ::= r'[^\x00-\x08\x0a-\x1f\x7f]+'
# a field value the grammar does not structure: TEXT and folding (9112 5.2)
<field_text> ::= <text>? <field_fold>*
<field_fold> ::= r'\r\n[ \t]' <text>?

# ======================================================================================
# Requests of the client (2326 6)
# ======================================================================================

# 2326 6.1: Request-Line = Method SP Request-URI SP RTSP-Version CRLF; the client speaks 1.0
<rtsp_version> ::= 'RTSP/1.0'

# --- Request-URIs (2326 3.2, 6.1; 3986 3): rtsp_URL = ( "rtsp:" | "rtspu:" ) "//" host
# [ ":" port ] [ abs_path ]; scheme and host are case-insensitive (3986 3.1, 3.2.2) ---
# the scheme of the session's transport (RTSP_TRANSPORT): rtsp over TCP, rtspu over UDP (2326 3.2)
<rtsp_scheme> ::= <scheme_tcp> | <scheme_udp> := url_scheme()
<scheme_tcp> ::= 'rtsp' | 'RTSP'
<scheme_udp> ::= 'rtspu' | 'RTSPU'
<server_authority> ::= <host> ':' <port>
<host> ::= r'[0-9A-Za-z.:\[\]-]+' := RTSP_HOST
<port> ::= <digits> := RTSP_PORT
# the presentation the server plays, and one of its streams (2326 1.3, C.1.1)
<media_url> ::= <rtsp_scheme> '://' <server_authority> '/' <media_path>
<media_path> ::= <path_text> := RTSP_MEDIA_PATH
# the presentation the client announces and records (2326 10.3, 10.11)
<record_url> ::= <rtsp_scheme> '://' <server_authority> '/' <record_path>
<record_path> ::= <path_text> := RTSP_RECORD_PATH
<record_track> ::= <path_text> := RTSP_RECORD_TRACK
# a presentation that may need credentials, and one the server does not have
<auth_url> ::= <rtsp_scheme> '://' <server_authority> '/' <auth_path>
<auth_path> ::= <path_text> := RTSP_AUTH_PATH
<missing_url> ::= <rtsp_scheme> '://' <server_authority> '/' <missing_path>
<missing_path> ::= <path_text> := RTSP_MISSING_PATH
<path_text> ::= r"[A-Za-z0-9._~!$&'()*+,;=:@%/-]+"
# 2326 6.1: "*" applies to the server itself, for methods that need no resource
<asterisk_uri> ::= '*'

# --- header fields the client sends (2326 12) ---
# Field names are case-insensitive (9110 5.1): canonical, lower and upper case are sent.
# 2326 12.17: CSeq, in every request; incremented by one per distinct request (2326 9.2)
# (a request resent over UDP carries the CSeq of the original, 2326 9.2, see <resend_*>)
<h_cseq> ::= <name_cseq> ':' <ows_sent> <cseq_value> <crlf>
<name_cseq> ::= 'CSeq' | 'cseq' | 'CSEQ' := name_case("CSeq")
<cseq_value> ::= <digits> := recalled_next_cseq()

# 2326 12.37: Session = "Session" ":" session-id; no timeout parameter in requests
<h_session> ::= <name_session> ':' <ows_sent> <session_id_sent> <crlf>
<name_session> ::= 'Session' | 'session' | 'SESSION' := name_case("Session")
<session_id_sent> ::= r'[A-Za-z0-9$_.+-]+' := recalled_session()
# a session identifier no session of this connection was assigned (2326 12.37: 454)
<h_session_stale> ::= <name_session> ':' <ows_sent> <session_id_stale> <crlf>
<session_id_stale> ::= r'[A-Za-z0-9$_.+-]+' := "stale" + str(random.randint(100000, 999999))

# 2326 12.41: User-Agent = "User-Agent" ":" 1*( product | comment )
<h_user_agent> ::= <name_user_agent> ':' <ows_sent> <product> (<sp> <product>){0,2} <crlf>
<name_user_agent> ::= 'User-Agent' | 'user-agent' | 'USER-AGENT' := name_case("User-Agent")
<product> ::= <token> ('/' <token>)? := random.choice(["fandango/1.3", "rtsp-test", "client/0.1"])

# 2326 12.38: Timestamp = "Timestamp" ":" *(DIGIT) [ "." *(DIGIT) ] [ delay ]
<h_timestamp> ::= <name_timestamp> ':' <ows_sent> <timestamp_value> <crlf>
<name_timestamp> ::= 'Timestamp' | 'timestamp' | 'TIMESTAMP' := name_case("Timestamp")
<timestamp_value> ::= r'[0-9]+(?:\.[0-9]*)?' := random_ntp_like()

# 2326 12.6: Bandwidth = "Bandwidth" ":" 1*DIGIT (bits per second)
<h_bandwidth> ::= <name_bandwidth> ':' <ows_sent> <bandwidth_value> <crlf>
<name_bandwidth> ::= 'Bandwidth' | 'bandwidth' | 'BANDWIDTH' := name_case("Bandwidth")
<bandwidth_value> ::= <digits> := str(random.choice([64000, 384000, 1000000, 4000000]))

# 2326 12.7: Blocksize = "Blocksize" ":" 1*DIGIT (octets, media packet size)
<h_blocksize> ::= <name_blocksize> ':' <ows_sent> <blocksize_value> <crlf>
<name_blocksize> ::= 'Blocksize' | 'blocksize' | 'BLOCKSIZE' := name_case("Blocksize")
<blocksize_value> ::= <digits> := str(random.choice([512, 1024, 1400, 4096]))

# 2326 12.3 / 9110 12.5.4: Accept-Language = 1#( language-range [ weight ] )
<h_accept_language> ::= <name_accept_language> ':' <ows_sent> <language_range> (',' <ows_sent> <language_range>){0,2} <crlf>
<name_accept_language> ::= 'Accept-Language' | 'accept-language' | 'ACCEPT-LANGUAGE' := name_case("Accept-Language")
<language_range> ::= <language_tag> <weight>?
<language_tag> ::= r'[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*|\*' := random.choice(["en", "de", "en-US", "*"])
<weight> ::= ';q=' <qvalue>
<qvalue> ::= r'0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?' := random.choice(["0.5", "1", "0.8"])

# 2326 12.43 / 9110 7.6.3: Via = 1#( received-protocol RWS received-by [ RWS comment ] )
<h_via> ::= <name_via> ':' <ows_sent> <via_entry> (',' <ows_sent> <via_entry>){0,2} <crlf>
<name_via> ::= 'Via' | 'via' | 'VIA' := name_case("Via")
<via_entry> ::= <via_protocol> ' ' <via_host>
<via_protocol> ::= 'RTSP/1.0' | '1.0'
# 9110 7.6.3: received-protocol = [ protocol-name "/" ] protocol-version; received-by = host [ ":" port ]
<via_host> ::= r"[A-Za-z0-9.-]+(?::[0-9]+)?" := random.choice(["proxy.example", "gw1", "relay.example:554"])

# 2326 12.18 / 9110 6.6.1: Date = HTTP-date (IMF-fixdate)
<h_date> ::= <name_date> ':' <ows_sent> <http_date> <crlf>
<name_date> ::= 'Date' | 'date' | 'DATE' := name_case("Date")
<http_date> ::= <day_name> ', ' <date_day> ' ' <month> ' ' <year> ' ' <time_of_day> ' GMT'
<day_name> ::= 'Mon' | 'Tue' | 'Wed' | 'Thu' | 'Fri' | 'Sat' | 'Sun'
<month> ::= 'Jan' | 'Feb' | 'Mar' | 'Apr' | 'May' | 'Jun' | 'Jul' | 'Aug' | 'Sep' | 'Oct' | 'Nov' | 'Dec'
<date_day> ::= r'0[1-9]|1[0-9]|2[0-8]'
<year> ::= r'[0-9]{4}' := str(random.randint(1998, 2030))
<time_of_day> ::= r'[01][0-9]|2[0-3]' ':' r'[0-5][0-9]' ':' r'[0-5][0-9]'

# 2326 12.20 / 9110 10.1.2: From = mailbox
<h_from> ::= <name_from> ':' <ows_sent> <mailbox> <crlf>
<name_from> ::= 'From' | 'from' | 'FROM' := name_case("From")
<mailbox> ::= r'[a-z]+@[a-z]+\.example' := random.choice(["tester@lab.example", "ops@media.example"])

# 2326 12.30 / 9110 10.1.3: Referer = absolute-URI / partial-URI
<h_referer> ::= <name_referer> ':' <ows_sent> <media_url> <crlf>
<name_referer> ::= 'Referer' | 'referer' | 'REFERER' := name_case("Referer")

# 2326 12.8: Cache-Control = 1#cache-directive; request directives no-cache, max-stale,
# min-fresh, max-age, only-if-cached, cache-extension
<h_cache_control> ::= <name_cache_control> ':' <ows_sent> <cache_request_directive> (',' <ows_sent> <cache_request_directive>){0,2} <crlf>
<name_cache_control> ::= 'Cache-Control' | 'cache-control' | 'CACHE-CONTROL' := name_case("Cache-Control")
<cache_request_directive> ::= <cd_no_cache> | <cd_max_stale> | <cd_min_fresh> | <cd_max_age> | <cd_only_if_cached> | <cd_extension>
# cache-extension = token [ "=" ( token | quoted-string ) ]
<cd_extension> ::= <cache_extension_name> ('=' (<cache_extension_token> | <cache_extension_quoted>))?
<cache_extension_name> ::= r'x-[a-z-]+' := random.choice(["x-community", "x-fandango-cache"])
<cache_extension_token> ::= r'[A-Za-z0-9.-]+' := random.choice(["UCI", "1"])
<cache_extension_quoted> ::= r'"[A-Za-z0-9 .-]*"' := random.choice(['"lab group"', '"x"'])
<cd_no_cache> ::= 'no-cache'
<cd_max_stale> ::= 'max-stale' ('=' <delta_seconds>)?
<cd_min_fresh> ::= 'min-fresh=' <delta_seconds>
<cd_max_age> ::= 'max-age=' <delta_seconds>
<cd_only_if_cached> ::= 'only-if-cached'
<delta_seconds> ::= <digits> := str(random.randint(0, 3600))

# 2326 12.27: Proxy-Require = 1#option-tag (only proxies act on it; the origin server ignores it)
<h_proxy_require> ::= <name_proxy_require> ':' <ows_sent> <option_tag> (',' <ows_sent> <option_tag>){0,2} <crlf>
<name_proxy_require> ::= 'Proxy-Require' | 'proxy-require' | 'PROXY-REQUIRE' := name_case("Proxy-Require")
<option_tag> ::= r'[A-Za-z0-9.-]+' := random.choice(["play.basic", "com.example.feature"])

# 2326 12.32: Require = 1#option-tag; private option-tags (2326 3.8) whose support the server's
# replies show (C21: Unsupported, 551)
<h_require_unknown> ::= <name_require> ':' <ows_sent> <option_tag_unknown> (',' <ows_sent> <option_tag_unknown>){0,1} <crlf>
<name_require> ::= 'Require' | 'require' | 'REQUIRE' := name_case("Require")
<option_tag_unknown> ::= r'[A-Za-z0-9.-]+' := RTSP_UNKNOWN_OPTION + random.choice(["", ".a", ".b"])

# 2326 12.10 / 9112 9.6: Connection = 1#connection-option
<h_connection> ::= <name_connection> ':' <ows_sent> <connection_option> <crlf>
<name_connection> ::= 'Connection' | 'connection' | 'CONNECTION' := name_case("Connection")
<connection_option> ::= 'keep-alive' | 'Keep-Alive'

# 2326 8.1: extension-header = message-header, ignored by recipients that do not know it
<h_extension> ::= <extension_name> ':' <ows_sent> <extension_value> <crlf>
<extension_name> ::= r'[Xx]-[A-Za-z0-9-]+' := random.choice(["X-Fandango-Test", "x-trace-id", "X-Extension"])
<extension_value> ::= r'[!-~]+' := random.choice(["1", "abc", "on"])

# 2326 12.1 / 9110 12.5.1: Accept = #( media-range [ weight ] )
<h_accept> ::= <name_accept> ':' <ows_sent> <media_range> (',' <ows_sent> <media_range>){0,2} <crlf>
<name_accept> ::= 'Accept' | 'accept' | 'ACCEPT' := name_case("Accept")
# media-range = ( "*/*" / ( type "/" "*" ) / ( type "/" subtype ) ) parameters, then a weight
<media_range> ::= (<mr_sdp> | <mr_any_application> | <mr_any> | <mr_rtsl> | <mr_mheg> | <mr_other>) <mr_parameter>? <weight>?
<mr_sdp> ::= 'application/sdp'
<mr_any_application> ::= 'application/*'
<mr_any> ::= '*/*'
<mr_rtsl> ::= 'application/rtsl'
<mr_mheg> ::= 'application/mheg'
<mr_other> ::= <mr_type> '/' <mr_subtype>
<mr_type> ::= <token> := random.choice(["text", "application", "video"])
<mr_subtype> ::= <token> := random.choice(["parameters", "x-rtsp-mh", "plain"])
# parameters = *( OWS ";" OWS parameter ), e.g. application/sdp;level=2 (2326 12.1)
<mr_parameter> ::= ';' <mr_parameter_name> '=' <mr_parameter_value>
<mr_parameter_name> ::= <token> := random.choice(["level", "charset"])
<mr_parameter_value> ::= <token> := random.choice(["2", "utf-8"])

# 2326 12.2 / 9110 12.5.3: Accept-Encoding = #( codings [ weight ] ) (F22)
<h_accept_encoding> ::= <name_accept_encoding> ':' <ows_sent> <coding_choice> (',' <ows_sent> <coding_choice>){0,2} <crlf>
<name_accept_encoding> ::= 'Accept-Encoding' | 'accept-encoding' | 'ACCEPT-ENCODING' := name_case("Accept-Encoding")
<coding_choice> ::= <coding> <weight>?
<coding> ::= <coding_identity> | <coding_gzip> | <coding_deflate> | <coding_compress> | <coding_any>
<coding_identity> ::= 'identity'
<coding_gzip> ::= 'gzip'
<coding_deflate> ::= 'deflate'
<coding_compress> ::= 'compress'
<coding_any> ::= '*'

# 2326 12.23: If-Modified-Since = HTTP-date (conditional DESCRIBE and SETUP, 304)
<h_if_modified_since> ::= <name_if_modified_since> ':' <ows_sent> <http_date> <crlf>
<name_if_modified_since> ::= 'If-Modified-Since' | 'if-modified-since' | 'IF-MODIFIED-SINCE' := name_case("If-Modified-Since")

# 2326 12.22 / 9110 13.1.1: If-Match = "*" / 1#entity-tag (SETUP on a description version, C.1.8)
<h_if_match> ::= <name_if_match> ':' <ows_sent> <if_match_value> <crlf>
<name_if_match> ::= 'If-Match' | 'if-match' | 'IF-MATCH' := name_case("If-Match")
<if_match_value> ::= '*' | <entity_tag> (',' <ows_sent> <entity_tag>){0,1}
<entity_tag> ::= 'W/'? '"' <etag_chars> '"'
# the description's a=etag (2326 C.1.8), recorded from the DESCRIBE reply
<etag_chars> ::= r'[!#-~]+' := recalled_etag()

# 2326 12.9: Conference = "Conference" ":" conference-id (SETUP only); an unknown id -> 452
<h_conference> ::= <name_conference> ':' <ows_sent> <conference_id> <crlf>
<name_conference> ::= 'Conference' | 'conference' | 'CONFERENCE' := name_case("Conference")
<conference_id> ::= r'[A-Za-z0-9$_.+!*()-]+' := recalled_conference()
<h_conference_unknown> ::= <name_conference> ':' <ows_sent> <conference_id_unknown> <crlf>
<conference_id_unknown> ::= r'[A-Za-z0-9$_.+!*()-]+' := RTSP_UNKNOWN_CONFERENCE

# 2326 12.5 / 9110 11.6.2: Authorization = credentials; Basic: token68 of user-id:password
# TODO: 2326 1.4, 16 Digest credentials (<h_authorization>): RFC 2069 / RFC 7616 define them and the manifest leaves them out; Digest challenges parse as <challenge>
<h_authorization> ::= <name_authorization> ':' <ows_sent> <basic_scheme> <auth_sp_sent> <basic_token> <crlf>
<name_authorization> ::= 'Authorization' | 'authorization' | 'AUTHORIZATION' := name_case("Authorization")
# 9110 11.1: the auth-scheme is case-insensitive; every case form is sent, the canonical one mostly
<basic_scheme> ::= 'Basic' | 'basic' | 'BASIC' := name_case("Basic")
<basic_token> ::= r'[A-Za-z0-9+/]+=*' := basic_credentials(RTSP_USER, RTSP_PASSWORD)
# 9110 11.4: credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]: one space mostly, now
# and then two or three
<auth_sp_sent> ::= ' ' | '  ' | '   ' := auth_space()
# 2326 12.26 / 9110 11.7.2: Proxy-Authorization = credentials (for a proxy on the path)
<h_proxy_authorization> ::= <name_proxy_authorization> ':' <ows_sent> <basic_scheme> <auth_sp_sent> <basic_token> <crlf>
<name_proxy_authorization> ::= 'Proxy-Authorization' | 'proxy-authorization' | 'PROXY-AUTHORIZATION' := name_case("Proxy-Authorization")
<h_authorization_wrong> ::= <name_authorization> ':' <ows_sent> <basic_scheme> <auth_sp_sent> <basic_token_wrong> <crlf>
<basic_token_wrong> ::= r'[A-Za-z0-9+/]+=*' := basic_credentials(RTSP_USER, RTSP_WRONG_PASSWORD)

# 2326 12.29: Range = 1#ranges-specifier [ ";" "time" "=" utc-time ]; sent as
# <h_range_in_presentation> | <h_range_other> (below), which split it by value
<name_range> ::= 'Range' | 'range' | 'RANGE' := name_case("Range")
<ranges_specifier> ::= <npt_range> | <smpte_range> | <utc_range>
# 2326 12.29: the time parameter: when the operation is to take effect (F82)
<range_time> ::= ';time=' <utc_time>
# 2326 3.6: npt-range = ( npt-time "-" [ npt-time ] ) | ( "-" npt-time )
<npt_range> ::= 'npt=' <npt_time> '-' <npt_time>? | 'npt=-' <npt_time>
<npt_time> ::= <npt_now> | <npt_sec> | <npt_hhmmss>
<npt_now> ::= 'now'
<npt_sec> ::= <npt_seconds> ('.' <fraction_digits>?)?
<npt_seconds> ::= <digits> := str(random.randint(0, 50))
<fraction_digits> ::= r'[0-9]{1,3}'
<npt_hhmmss> ::= <npt_hh> ':' <npt_mm> ':' <npt_ss> ('.' <fraction_digits>?)?
<npt_hh> ::= <digits> := str(random.randint(0, 1))
<npt_mm> ::= r'[0-5]?[0-9]'
<npt_ss> ::= r'[0-5]?[0-9]'
# 2326 3.5: smpte-range = smpte-type "=" smpte-time "-" [ smpte-time ]
<smpte_range> ::= <smpte_type> '=' <smpte_time> '-' <smpte_time>?
<smpte_type> ::= <smpte_30> | <smpte_30_drop> | <smpte_25>
<smpte_30> ::= 'smpte'
<smpte_30_drop> ::= 'smpte-30-drop'
<smpte_25> ::= 'smpte-25'
# smpte-time = 1*2DIGIT ":" 1*2DIGIT ":" 1*2DIGIT [ ":" 1*2DIGIT ] [ "." 1*2DIGIT ]: frames and
# subframes each optional
<smpte_time> ::= r'[0-9]{1,2}' ':' r'[0-5]?[0-9]' ':' r'[0-5]?[0-9]' (':' r'[0-2]?[0-9]')? ('.' r'[0-9]{1,2}')?
# 2326 3.7: utc-range = "clock" "=" utc-time "-" [ utc-time ]; utc-time = utc-date "T" utc-time "Z"
<utc_range> ::= 'clock=' <utc_time> '-' <utc_time>?
<utc_time> ::= <utc_date> 'T' <utc_hms> ('.' <fraction_digits>)? 'Z'
<utc_date> ::= r'[0-9]{8}' := f"{random.randint(1998, 2030)}{random.randint(1, 12):02d}{random.randint(1, 28):02d}"
<utc_hms> ::= r'[0-9]{6}' := f"{random.randint(0, 23):02d}{random.randint(0, 59):02d}{random.randint(0, 59):02d}"

# 2326 10.6: the Range of PAUSE holds exactly one value, the pause point (C19): 'npt=' npt-time
# '-' | smpte-type '=' smpte-time '-' | 'clock=' utc-time '-', sent as
# <h_range_point_in_presentation> | <h_range_point_other> (below)

# The Range field of PLAY, PAUSE and RECORD in two parts, by the values the exchange needs:
# (1) a Range inside the presentation (2326 12.29, 3.6): one npt-range in seconds whose bounds
# lie in the a=range the session's description declared (C.1.5; record_description), the start
# before the end (range_start, range_end: generators that choose the value up front); a pause
# point inside every range played from such a start (10.6, range_pause_point). The server plays
# it: the request that the session continues with (<req_play>, <req_pause>, <req_record>).
<h_range_in_presentation> ::= <name_range> ':' <ows_sent> 'npt=' <npt_start_in> '-' <npt_end_in>? <crlf>
<npt_start_in> ::= <npt_start_seconds> ('.' <fraction_digits>?)?
<npt_start_seconds> ::= <digits> := range_start()
<npt_end_in> ::= <npt_end_seconds> ('.' <fraction_digits>?)?
<npt_end_seconds> ::= <digits> := range_end()
<h_range_point_in_presentation> ::= <name_range> ':' <ows_sent> 'npt=' <npt_point_in> '-' <crlf>
<npt_point_in> ::= <npt_point_seconds> ('.' <fraction_digits>?)?
<npt_point_seconds> ::= <digits> := range_pause_point()
# (2) every other form 12.29 allows: npt with "now" or hh:mm:ss, an npt-range "-" end, SMPTE
# (3.5) and clock (3.7) ranges, two ranges, the ";time=" parameter (scheduled PLAY, RECORD and
# PAUSE, F82; a range or point in seconds is here only with it), with free values that may
# lie outside the presentation (11.3.20: 457 Invalid Range): sent by requests of their own
# (<req_play_any_range>, <req_pause_any_point>, <req_record_any_range>; in the A.2 states
# <req_play_without_setup_any_range>, <req_play_nosetup_any_range>, <req_pause_nosetup_any_point>),
# whose reply may be of any class; the pipelined, "Connection: close" and no-session PLAY, PAUSE
# and RECORD carry either part (<play_leading> ..., <req_*_pipelined>, <play_headers_any> ...).
# Together (1) and (2) are the whole syntax of the field, each message in one of them only.
<h_range_other> ::= <name_range> ':' <ows_sent> <range_other_forms> <crlf>
<range_other_forms> ::= <ranges_specifier_other> <range_time>? \
    | <ranges_specifier> ',' <ows_sent> <ranges_specifier> <range_time>? \
    | <npt_range_seconds> <range_time>
<ranges_specifier_other> ::= <npt_range_other> | <smpte_range> | <utc_range>
<npt_range_other> ::= 'npt=' <npt_now> '-' <npt_time>? | 'npt=' <npt_hhmmss> '-' <npt_time>? \
    | 'npt=' <npt_sec> '-' <npt_now> | 'npt=' <npt_sec> '-' <npt_hhmmss> | 'npt=-' <npt_time>
<npt_range_seconds> ::= 'npt=' <npt_sec> '-' <npt_sec>?
# The PAUSE point likewise: the other point forms with an optional ";time=" (12.29: when the pause
# is to take effect, F82; 10.6 limits the field to one point, not the parameter), and a point in
# seconds only with ";time=", so that the two parts stay disjoint.
<h_range_point_other> ::= <name_range> ':' <ows_sent> <pause_point_other> <crlf>
<pause_point_other> ::= <pause_point_form> <range_time>? | 'npt=' <npt_sec> '-' <range_time>
<pause_point_form> ::= 'npt=' <npt_now> '-' | 'npt=' <npt_hhmmss> '-' | <smpte_type> '=' <smpte_time> '-' | 'clock=' <utc_time> '-'

# 2326 12.34: Scale = "Scale" ":" [ "-" ] 1*DIGIT [ "." *DIGIT ]
<h_scale> ::= <name_scale> ':' <ows_sent> <scale_value> <crlf>
<name_scale> ::= 'Scale' | 'scale' | 'SCALE' := name_case("Scale")
<scale_value> ::= '-'? <scale_int> ('.' <fraction_digits>?)?
<scale_int> ::= <digits> := str(random.choice([1, 1, 2, 4, 0]))

# 2326 12.35: Speed = "Speed" ":" 1*DIGIT [ "." *DIGIT ]
<h_speed> ::= <name_speed> ':' <ows_sent> <speed_int> ('.' <fraction_digits>?)? <crlf>
<name_speed> ::= 'Speed' | 'speed' | 'SPEED' := name_case("Speed")
<speed_int> ::= <digits> := str(random.choice([1, 2, 1]))

# 2326 12.16: Content-Type = media-type; 12.14 Content-Length = 1*DIGIT
<h_content_type_sdp> ::= <name_content_type> ':' <ows_sent> 'application/sdp' <crlf>
<h_content_type_parameters> ::= <name_content_type> ':' <ows_sent> 'text/parameters' <crlf>
<name_content_type> ::= 'Content-Type' | 'content-type' | 'CONTENT-TYPE' := name_case("Content-Type")
<name_content_length> ::= 'Content-Length' | 'content-length' | 'CONTENT-LENGTH' := name_case("Content-Length")

# 2326 12.39: Transport = "Transport" ":" 1#transport-spec, listed in order of preference
<h_transport> ::= <name_transport> ':' <ows_sent> <transport_spec> (',' <ows_sent> <transport_spec>){0,2} <crlf>
<name_transport> ::= 'Transport' | 'transport' | 'TRANSPORT' := name_case("Transport")
# transport-spec = transport-protocol/profile[/lower-transport] *parameter
<transport_spec> ::= <ts_udp_unicast> | <ts_tcp_interleaved> | <ts_multicast_server> | <ts_multicast_client>
# RTP/AVP over UDP (default lower transport), unicast, client_port pair (F62)
<ts_udp_unicast> ::= 'RTP/AVP' <lower_udp>? ';unicast' <tp_destination>? ';client_port=' <client_port_pair> <tp_ssrc>? <tp_mode>? <tp_append>?
<lower_udp> ::= '/UDP'
# RTP/AVP/TCP interleaved over the RTSP connection (F63)
<ts_tcp_interleaved> ::= 'RTP/AVP/TCP' ';unicast'? <tp_interleaved> <tp_mode>? <tp_append>?
<tp_interleaved> ::= ';interleaved=' <channel> <channel_pair_end>?
# the RTCP channel: the client may name any (2326 10.12, 12.39)
<channel_pair_end> ::= '-' <channel_rtcp>
<channel_rtcp> ::= <digits> := str(random.choice([1, 3, 5, 7]))
<channel> ::= <digits> := str(random.choice([0, 2, 4]))
# multicast, address and port chosen by the server (F65), ttl, layers
<ts_multicast_server> ::= 'RTP/AVP' ';multicast' <tp_ttl>? <tp_layers>? <tp_mode>? <tp_append>?
# multicast to a group the client chose (F66, F68)
<ts_multicast_client> ::= 'RTP/AVP' ';multicast' ';destination=' <multicast_address> ';port=' <client_port_pair> <tp_ttl>? <tp_mode>? <tp_append>?
<tp_destination> ::= ';destination' ('=' <unicast_destination>)?
<unicast_destination> ::= r'[0-9.]+' := "127.0.0.1"
<multicast_address> ::= r'[0-9.]+' := RTSP_MULTICAST_ADDRESS
<tp_ttl> ::= ';ttl=' <ttl_value>
<ttl_value> ::= r'[0-9]{1,3}' := str(random.choice([1, 16, 127]))
<tp_layers> ::= ';layers=' <layers_value>
<layers_value> ::= <digits> := str(random.choice([1, 2]))
<tp_ssrc> ::= ';ssrc=' <ssrc_value>
<ssrc_value> ::= r'[0-9A-F]{8}' := "%08X" % random.getrandbits(32)
# mode = <"> 1#mode <">; mode = <"> *Method <"> | Method (2326 12.39)
<tp_mode> ::= ';mode=' (<mode_method> | '"' <mode_method> '"' | '"' <mode_play> ',' <mode_record> '"')
<mode_method> ::= <mode_play> | <mode_record> := setup_mode()
<mode_play> ::= 'PLAY'
<mode_record> ::= 'RECORD'
# append: recorded data appends to the resource (F70, with mode RECORD; a parameter of every
# transport-spec, 2326 12.39)
<tp_append> ::= ';append'
# an even RTP port and the RTCP port above it (2326 12.39, RTP convention)
<client_port_pair> ::= <client_rtp_port> '-' <client_rtcp_port>
<client_rtp_port> ::= <digits> := str(RTSP_CLIENT_PORT + 2 * random.randint(0, 50))
<client_rtcp_port> ::= <digits> := str(RTSP_CLIENT_PORT + 1)

# a transport only an extension defines; the server refuses it with 461 (2326 11.3.12)
<h_transport_unsupported> ::= <name_transport> ':' <ows_sent> <transport_unsupported> <crlf>
<transport_unsupported> ::= 'RTP/SAVP;unicast;client_port=' <client_port_pair> \
    | 'x-fandango/AVP;unicast'

# --- optional header fields of every request, list-valued ones in any order before CSeq,
# the others once each after it (9110 5.3); 2326 Table 3: Require, Proxy-Require (F58, F59),
# Authorization, Proxy-Authorization (F54, F55) in all methods ---
<list_headers> ::= <list_header>{0,2}
<list_header> ::= <list_header_base> | <h_connection>
<list_header_base> ::= <h_via> | <h_accept_language> | <h_cache_control> | <h_require_unknown> | <h_proxy_require>
# the list fields of a request that closes the connection (no "Connection: keep-alive")
<list_headers_close> ::= <list_header_base>{0,2}
<common_headers> ::= <h_authorization>? <h_proxy_authorization>? <general_headers>
<general_headers> ::= <h_user_agent>? <h_timestamp>? <h_bandwidth>? <h_date>? <h_from>? <h_referer>? <h_extension>?

# --- OPTIONS (2326 10.1): server or presentation, any state ---
<req_options> ::= 'OPTIONS' <sp> <options_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <common_headers> <crlf>
<options_uri> ::= <asterisk_uri> | <media_url> | <record_url> | <auth_url>

# --- DESCRIBE (2326 10.2): description of a presentation; Accept, Accept-Encoding,
# Accept-Language negotiate it (F94); credentials where needed (9110 11.6.2). The DESCRIBE of
# the presentation the server plays has its own request: in Init its SETUPs follow it ---
<req_describe> ::= 'DESCRIBE' <sp> <describe_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <describe_headers> <common_headers> <crlf>
<req_describe_media> ::= 'DESCRIBE' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <describe_headers> <common_headers> <crlf>
<describe_uri> ::= <auth_url> | <missing_url> | <record_url>
<describe_headers> ::= <h_accept>? <h_accept_encoding>? <h_if_modified_since>? <h_blocksize>?
# DESCRIBE with credentials the server does not accept
<req_describe_wrong_credentials> ::= 'DESCRIBE' <sp> <auth_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <describe_headers> <h_authorization_wrong> <h_proxy_authorization>? <general_headers> <crlf>

# --- ANNOUNCE C->S (2326 10.3): posts a description (SDP, 2326 C) to the record presentation
# or its stream (Table 2: P,S); within a session with its Session ---
<req_announce> ::= 'ANNOUNCE' <sp> <announce_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_blocksize>? <common_headers> <announce_body>
<req_announce_in_session> ::= 'ANNOUNCE' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <h_blocksize>? <common_headers> <announce_body>
<announce_uri> ::= <record_url> | <record_url> '/' <record_track>
# ANNOUNCE of the presentation to record, followed in Init by the SETUP of its stream
<req_announce_record> ::= 'ANNOUNCE' <sp> <record_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_blocksize>? <common_headers> <announce_body>
# 9110 8.4 (F22): the body as it is, or in a content coding that Content-Encoding names (2326
# 12.12; Table 3: ANNOUNCE, SET_PARAMETER), with Content-Length the length of the coded octets
<announce_body> ::= <h_content_type_sdp> <h_announce_length> <crlf> <sdp_sent> \
    | <h_content_type_sdp> <h_content_encoding_sent> <h_coded_length> <crlf> <sdp_coded>
# converter pair: the coded octets of a description, and the description they hold
<sdp_coded> ::= <coded_octets> := encode_body(<sdp_source>)
<sdp_source> ::= <sdp_sent> := decode_body(<sdp_coded>)
<h_content_encoding_sent> ::= <name_content_encoding> ':' <ows_sent> <content_coding_sent> <crlf>
<name_content_encoding> ::= 'Content-Encoding' | 'content-encoding' | 'CONTENT-ENCODING' := name_case("Content-Encoding")
<content_coding_sent> ::= <coding_gzip> | <coding_deflate> | <coding_compress>
<h_coded_length> ::= <name_content_length> ':' <ows_sent> <coded_length> <crlf>
<coded_length> ::= <digits> := "0"
<coded_octets> ::= rb'[\x00-\xff]+'
<h_announce_length> ::= <name_content_length> ':' <ows_sent> <announce_length> <crlf>
<announce_length> ::= <digits> := "0"

# --- SETUP (2326 10.4): transport of one stream; in Init without a session ---
<req_setup> ::= 'SETUP' <sp> <setup_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <setup_transport> <setup_headers> <common_headers> <crlf>
<setup_uri> ::= <rtsp_scheme> '://' <server_authority> '/' <setup_target>
<setup_target> ::= <path_text> := setup_target()
# the SETUP of a stream the preceding DESCRIBE named (2326 C.1.1 a=control; C.3), offering
# one unicast transport (12.39: the client chooses the transports it offers; the other SETUPs
# offer every form and lists)
<req_setup_described> ::= 'SETUP' <sp> <described_stream_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_transport_unicast> <setup_headers> <common_headers> <crlf>
<h_transport_unicast> ::= <name_transport> ':' <ows_sent> <transport_spec_unicast> <crlf>
# the SETUP of the announced stream for recording: one unicast transport with mode RECORD
# (2326 10.11, 12.39)
<req_setup_announced> ::= 'SETUP' <sp> <record_stream_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_transport_record> <setup_headers> <common_headers> <crlf>
<record_stream_uri> ::= <record_url> '/' <record_track>
<h_transport_record> ::= <name_transport> ':' <ows_sent> <transport_unicast_base> <tp_mode_record> <tp_append>? <crlf>
<transport_unicast_base> ::= 'RTP/AVP/TCP' ';unicast'? <tp_interleaved> | 'RTP/AVP' <lower_udp>? ';unicast;client_port=' <client_port_pair>
<tp_mode_record> ::= ';mode=' (<mode_record> | '"' <mode_record> '"')
<transport_spec_unicast> ::= <ts_udp_unicast> | <ts_tcp_interleaved>
<described_stream_uri> ::= <rtsp_scheme> '://' <server_authority> '/' <described_stream>
<described_stream> ::= <path_text> := described_stream()
<setup_transport> ::= <h_transport>
# conditions (12.22 If-Match on the description's a=etag, 12.23), Blocksize, caching (12.8,
# F92) and the session's conference (12.9, F91)
<setup_headers> ::= <setup_conditions> <h_conference>?
<setup_conditions> ::= <h_if_match>? <h_if_modified_since>? <h_blocksize>? <h_cache_control_setup>?
# 2326 12.8: cache directives of SETUP (media stream caching, F92)
<h_cache_control_setup> ::= <name_cache_control> ':' <ows_sent> <cache_setup_directive> <crlf>
<cache_setup_directive> ::= <cd_no_cache> | <cd_max_age> | <cd_only_if_cached> | <cd_no_transform> | <cd_public> | <cd_private> | <cd_extension>
<cd_no_transform> ::= 'no-transform'
<cd_public> ::= 'public'
<cd_private> ::= 'private'
# SETUP with a transport the server does not support (2326 11.3.12: 461 Unsupported Transport)
<req_setup_unsupported_transport> ::= 'SETUP' <sp> <setup_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_transport_unsupported> <setup_conditions> <common_headers> <crlf>
# SETUP joining a conference the server does not know (2326 12.9, 11.3.3: 452 Conference Not
# Found); its own request, the unknown id given before the other fields
<req_setup_unknown_conference> ::= 'SETUP' <sp> <setup_uri> <sp> <rtsp_version> <crlf> <h_conference_unknown> <list_headers> <h_cseq> <setup_transport> <setup_conditions> <common_headers> <crlf>
# SETUP within a session: with the session (2326 10.4, 12.37); adds a stream or changes transport
<req_setup_in_session> ::= 'SETUP' <sp> <setup_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <setup_transport> <setup_headers> <common_headers> <crlf>

# --- PLAY (2326 10.5): aggregate or stream URL; Range, Scale, Speed ---
<req_play> ::= 'PLAY' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <play_headers> <common_headers> <crlf>
<play_headers> ::= <h_range_in_presentation>? <h_scale>? <h_speed>? <h_blocksize>?
<session_uri> ::= <rtsp_scheme> '://' <server_authority> '/' <session_target>
<session_target> ::= <path_text> := session_target()
# --- PAUSE (2326 10.6): optional pause point ---
<req_pause> ::= 'PAUSE' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <pause_headers> <common_headers> <crlf>
<pause_headers> ::= <h_range_point_in_presentation>? <h_blocksize>?
# --- RECORD (2326 10.11): Range, Scale ---
<req_record> ::= 'RECORD' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <record_headers> <common_headers> <crlf>
<record_headers> ::= <h_range_in_presentation>? <h_scale>? <h_blocksize>?
# --- PLAY, PAUSE, RECORD with a Range in any other form (2326 12.29; see <h_range_other>) ---
<req_play_any_range> ::= 'PLAY' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <h_range_other> <h_scale>? <h_speed>? <h_blocksize>? <common_headers> <crlf>
<req_pause_any_point> ::= 'PAUSE' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <h_range_point_other> <h_blocksize>? <common_headers> <crlf>
<req_record_any_range> ::= 'RECORD' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <h_range_other> <h_scale>? <h_blocksize>? <common_headers> <crlf>
# --- TEARDOWN (2326 10.7) ---
<req_teardown> ::= 'TEARDOWN' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <common_headers> <crlf>

# --- session requests in Init: no Session header, or a stale one ---
<req_play_no_session> ::= 'PLAY' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_stale> <play_headers_any> <common_headers> <crlf>
<req_record_no_session> ::= 'RECORD' <sp> <record_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_stale>? <record_headers_any> <common_headers> <crlf>
<req_pause_no_session> ::= 'PAUSE' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_stale>? <pause_headers_any> <common_headers> <crlf>
# (refused for the session they lack, or ending the connection ("Connection: close"), so either
# part of the Range split, ";time=" included)
<play_headers_any> ::= <h_range_any>? <h_scale>? <h_speed>? <h_blocksize>?
<pause_headers_any> ::= <h_range_point_any>? <h_blocksize>?
<record_headers_any> ::= <h_range_any>? <h_scale>? <h_blocksize>?
<h_range_any> ::= <h_range_in_presentation> | <h_range_other>
<h_range_point_any> ::= <h_range_point_in_presentation> | <h_range_point_other>
<req_teardown_no_session> ::= 'TEARDOWN' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_stale> <common_headers> <crlf>
# PLAY without SETUP and without a session (2326 A.2, objects that need no SETUP); in its
# two-state machine PLAY and PAUSE carry the Session the PLAY reply gave
<req_play_without_setup> ::= 'PLAY' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <play_headers> <common_headers> <crlf>
# (C9: <h_session_nosetup> once if a reply of this session gave an identifier, else not at all)
<req_play_nosetup> ::= 'PLAY' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <play_headers> <common_headers> <crlf>
<req_pause_nosetup> ::= 'PAUSE' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <pause_headers> <common_headers> <crlf>
# the same with a Range in any other form (see <h_range_other>, <h_range_point_other>), ";time="
# included (12.29, F82)
<req_play_without_setup_any_range> ::= 'PLAY' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_range_other> <h_scale>? <h_speed>? <h_blocksize>? <common_headers> <crlf>
<req_play_nosetup_any_range> ::= 'PLAY' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <h_range_other> <h_scale>? <h_speed>? <h_blocksize>? <common_headers> <crlf>
<req_pause_nosetup_any_point> ::= 'PAUSE' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <h_range_point_other> <h_blocksize>? <common_headers> <crlf>
<h_session_nosetup> ::= <h_session>

# --- requests that ask to close the connection after the reply (2326 12.10, 9112 9.6, F87) ---
<h_connection_close> ::= <name_connection> ':' <ows_sent> <connection_close> <crlf>
<connection_close> ::= 'close' | 'Close'
<req_options_close> ::= 'OPTIONS' <sp> <options_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <common_headers> <crlf>
<req_describe_close> ::= 'DESCRIBE' <sp> <describe_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <describe_headers> <common_headers> <crlf>
<req_get_parameter_close> ::= 'GET_PARAMETER' <sp> <parameter_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <common_headers> <get_parameter_entity>
<req_set_parameter_close> ::= 'SET_PARAMETER' <sp> <parameter_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <common_headers> <parameter_settings_body>
<req_announce_close> ::= 'ANNOUNCE' <sp> <announce_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <common_headers> <announce_body>
<req_setup_close> ::= 'SETUP' <sp> <setup_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <setup_transport> <setup_headers> <common_headers> <crlf>
<req_play_close> ::= 'PLAY' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session> <play_headers_any> <common_headers> <crlf>
<req_pause_close> ::= 'PAUSE' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session> <pause_headers_any> <common_headers> <crlf>
<req_record_close> ::= 'RECORD' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session> <record_headers_any> <common_headers> <crlf>
<req_setup_in_session_close> ::= 'SETUP' <sp> <setup_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session> <setup_transport> <setup_headers> <common_headers> <crlf>
<req_play_nosetup_close> ::= 'PLAY' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <play_headers_any> <common_headers> <crlf>
<req_pause_nosetup_close> ::= 'PAUSE' <sp> <media_url> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <pause_headers_any> <common_headers> <crlf>
<req_extension_close> ::= <extension_method> <sp> <extension_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <common_headers> <extension_entity>
<req_extension_in_session_close> ::= <extension_method> <sp> <extension_session_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session>? <common_headers> <extension_entity>
<req_extension_nosetup_close> ::= <extension_method> <sp> <extension_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <common_headers> <extension_entity>
<req_teardown_close> ::= 'TEARDOWN' <sp> <session_uri> <sp> <rtsp_version> <crlf> <list_headers_close> <h_cseq> <h_connection_close> <h_session> <common_headers> <crlf>

# --- GET_PARAMETER (2326 10.8): body of parameter names (text/parameters), none = liveness ---
<req_get_parameter> ::= 'GET_PARAMETER' <sp> <parameter_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_blocksize>? <common_headers> <get_parameter_entity>
<req_get_parameter_in_session> ::= 'GET_PARAMETER' <sp> <parameter_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <h_blocksize>? <common_headers> <get_parameter_entity>
<parameter_uri> ::= <media_url> | <asterisk_uri> | <record_url>
<get_parameter_entity> ::= <crlf> | <parameter_names_body>
<parameter_names_body> ::= <h_content_type_parameters> <h_parameters_length> <crlf> <parameter_names> \
    | <h_content_type_parameters> <h_content_encoding_sent> <h_coded_length> <crlf> <parameter_names_coded>
<parameter_names_coded> ::= <coded_octets> := encode_body(<parameter_names_source>)
<parameter_names_source> ::= <parameter_names> := decode_body(<parameter_names_coded>)
<parameter_names> ::= <parameter_name> <crlf> (<parameter_name> <crlf>){0,2}
<parameter_name> ::= r'[A-Za-z][A-Za-z0-9_.-]*' := random.choice(["packets_received", "jitter", "position", "x-fandango"])
<h_parameters_length> ::= <name_content_length> ':' <ows_sent> <parameters_length> <crlf>
<parameters_length> ::= <digits> := "0"

# --- SET_PARAMETER (2326 10.9): body of "name: value" lines; no transport parameters (C16);
# within a session with its Session ---
<req_set_parameter> ::= 'SET_PARAMETER' <sp> <parameter_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_blocksize>? <common_headers> <parameter_settings_body>
<req_set_parameter_in_session> ::= 'SET_PARAMETER' <sp> <parameter_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session> <h_blocksize>? <common_headers> <parameter_settings_body>
<parameter_settings_body> ::= <h_content_type_parameters> <h_parameters_length> <crlf> <parameter_settings> \
    | <h_content_type_parameters> <h_content_encoding_sent> <h_coded_length> <crlf> <parameter_settings_coded>
<parameter_settings_coded> ::= <coded_octets> := encode_body(<parameter_settings_source>)
<parameter_settings_source> ::= <parameter_settings> := decode_body(<parameter_settings_coded>)
<parameter_settings> ::= <parameter_setting> (<parameter_setting>){0,2}
<parameter_setting> ::= <parameter_name> ':' <ows_sent> <parameter_value> <crlf>
<parameter_value> ::= r'[!-~]+' := random.choice(["1", "on", "Bob"])

# --- extension method (2326 6.1: extension-method = token); a server without it -> 501 (C25) ---
# Request-URI "*" or an absolute URL (6.1); within a session also the session's URL and the
# Session (12.37, Table 3: Session in every method but SETUP and OPTIONS; optional here: the
# method's needs are unknown); in A.2 the Session as its PLAY and PAUSE carry it; entity
# headers and a message body as in any request (2326 4.3, 8.1: Content-Type, Content-Encoding,
# Content-Length with the body's length, C3)
<req_extension> ::= <extension_method> <sp> <extension_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <common_headers> <extension_entity>
<req_extension_in_session> ::= <extension_method> <sp> <extension_session_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session>? <common_headers> <extension_entity>
<req_extension_nosetup> ::= <extension_method> <sp> <extension_uri> <sp> <rtsp_version> <crlf> <list_headers> <h_cseq> <h_session_nosetup>{nosetup_session_count(<h_cseq>)} <common_headers> <extension_entity>
<extension_uri> ::= <asterisk_uri> | <media_url> | <record_url> | <auth_url>
<extension_session_uri> ::= <session_uri> | <asterisk_uri> | <auth_url>
<extension_entity> ::= <crlf> | <parameter_settings_body> | <announce_body>
# extension-method = token, other than the methods 2326 defines (6.1, case-sensitive); a token
# that starts with "$" would open interleaved binary data on the connection instead (10.12).
# The generator picks any such token (letters of both cases, digits, the other tchars).
<extension_method> ::= r"(?!(?:OPTIONS|DESCRIBE|ANNOUNCE|SETUP|PLAY|PAUSE|RECORD|REDIRECT|TEARDOWN|GET_PARAMETER|SET_PARAMETER)\Z)[!#%&'*+.^_`|~0-9A-Za-z-][!#$%&'*+.^_`|~0-9A-Za-z-]*" := extension_method()
# --- an RTSP version the server does not speak (2326 6.1, 505 RTSP Version Not Supported) ---
<req_bad_version> ::= 'OPTIONS' <sp> <media_url> <sp> <unsupported_version> <crlf> <list_headers> <h_cseq> <common_headers> <crlf>
<unsupported_version> ::= 'RTSP/' r'[2-9]' '.' r'[0-9]'

# --- interleaved binary data of the client while recording (2326 10.12): "$", channel, length ---
# (the data: one of a few sizes, each with its two-byte length, correct by construction)
<interleaved_frame_sent> ::= b'$' <channel_byte_sent> <frame_data_sent>
<channel_byte_sent> ::= <octet> := recalled_channel()
<frame_data_sent> ::= <frame_12> | <frame_16> | <frame_32> | <frame_64> | <frame_256>
<frame_12> ::= b'\x00\x0c' <octet>{12}
<frame_16> ::= b'\x00\x10' <block_16>
<frame_32> ::= b'\x00\x20' <block_16>{2}
<frame_64> ::= b'\x00\x40' <block_16>{4}
<frame_256> ::= b'\x01\x00' <block_256>

# ======================================================================================
# SDP descriptions the client sends (ANNOUNCE, 2326 C; SDP syntax RFC 2327/8866 is another
# document: only what 2326 C requires is modeled)
# ======================================================================================

<sdp_sent> ::= <sdp_v> <sdp_o> <sdp_s> <sdp_c>? <sdp_t> <sdp_session_attribute>* <sdp_media_sent>
<sdp_v> ::= 'v=0\r\n'
<sdp_o> ::= 'o=- ' <sdp_number> ' ' <sdp_number> ' IN IP4 ' <unicast_destination> '\r\n'
<sdp_number> ::= <digits> := str(random.randint(0, 99999))
<sdp_s> ::= 's=' <sdp_text> '\r\n'
<sdp_text> ::= r'[ -~]+' := random.choice(["fandango", "test session"])
<sdp_c> ::= 'c=IN IP4 0.0.0.0\r\n'
# 2326 C.1.6: t= start and stop times
<sdp_t> ::= 't=0 0\r\n'
<sdp_session_attribute> ::= <sdp_a_range> | <sdp_a_control_aggregate> | <sdp_a_etag>
# 2326 C.1.5: a=range:<range> with any range of 3.5-3.7 (npt, smpte, clock), at session or media
# level; C.1.1: a=control: "*" or the absolute URL at session level, the stream's URL relative
# or absolute at media level ("may contain either relative and absolute URLs"); C.1.8: a=etag
<sdp_a_range> ::= 'a=range:' <ranges_specifier> '\r\n'
<sdp_a_control_aggregate> ::= 'a=control:' ('*' | <record_url>) '\r\n'
<sdp_a_etag> ::= 'a=etag:' <etag_chars> '\r\n'
# 2326 C.1.2/C.1.3: one stream, payload type, its control URL (C.3)
<sdp_media_sent> ::= 'm=audio 0 RTP/AVP 0\r\n' <sdp_a_range>? 'a=control:' <sdp_stream_control> '\r\n'
<sdp_stream_control> ::= <record_track> | <record_url> '/' <record_track>

# ======================================================================================
# Replies of the client to requests of the server (2326 7)
# ======================================================================================

# Status-Line, CSeq, the Session of the server's request if it carried one (2326 12.37, Table 3:
# Session in requests and replies of all methods but SETUP and OPTIONS), optional general fields
# (2326 7, 12.18 Date, 12.43 Via, 8.1), a body where the reply has one: the values of the
# parameters asked for (2326 10.8). Besides each method's own codes, the codes 2326 7.1.1 Table
# 1 allows for all methods (<client_refusal>): 400 a malformed request, 454 an unknown session,
# 455 a method not valid in the state, 551 with Unsupported listing the option-tags of the
# request's Require the client does not support (2326 12.32)
<rep_to_announce> ::= <reply_ok> <reply_fields_sent> <crlf> | <client_refusal>
<rep_to_get_parameter> ::= <reply_ok> <reply_fields_sent> (<crlf> | <parameter_settings_body>) \
    | <reply_451> <reply_fields_sent> <crlf> | <client_refusal>
<rep_to_set_parameter> ::= (<reply_ok> | <reply_451> | <reply_458>) <reply_fields_sent> <crlf> | <client_refusal>
<rep_to_options> ::= <reply_ok> <h_cseq_echo> <h_public_sent> <reply_headers_sent> <crlf> | <client_refusal>
<rep_to_redirect> ::= <reply_ok> <reply_fields_sent> <crlf> | <client_refusal>
<rep_to_extension> ::= <rtsp_version> <sp> <code_501> <sp> 'Not Implemented' <crlf> <reply_fields_sent> <crlf>
<reply_ok> ::= <rtsp_version> <sp> <code_200> <sp> 'OK' <crlf>
<reply_451> ::= <rtsp_version> <sp> <code_451> <sp> 'Parameter Not Understood' <crlf>
<reply_458> ::= <rtsp_version> <sp> <code_458> <sp> 'Parameter Is Read-Only' <crlf>
<reply_fields_sent> ::= <h_cseq_echo> <h_session_echo>{echoed_session_count(<h_cseq_echo>)} <reply_headers_sent>
<client_refusal> ::= <rtsp_version> <sp> <client_refusal_status> <crlf> <reply_fields_sent> <crlf> \
    | <rtsp_version> <sp> <code_551> <sp> 'Option not supported' <crlf> <reply_fields_sent> <h_unsupported_sent>{required_by_server(<reply_fields_sent>)} <crlf>
<client_refusal_status> ::= <code_400> <sp> 'Bad Request' | <code_454> <sp> 'Session Not Found' \
    | <code_455> <sp> 'Method Not Valid in This State'
# 2326 12.37: the session of the server's request
<h_session_echo> ::= <name_session> ':' <ows_sent> <session_id_echo> <crlf>
<session_id_echo> ::= r'[A-Za-z0-9$_.+-]+' := recalled_server_session()
# 2326 12.40: Unsupported = 1#option-tag: every option-tag the server's Require named
<h_unsupported_sent> ::= <name_unsupported> ':' <ows_sent> <unsupported_tags_sent> <crlf>
<unsupported_tags_sent> ::= <option_tag_echo> <more_option_tag_echo>{required_by_server(<option_tag_echo>, True)}
<more_option_tag_echo> ::= ',' <ows_sent> <option_tag_echo>
<name_unsupported> ::= 'Unsupported' | 'unsupported' | 'UNSUPPORTED' := name_case("Unsupported")
<option_tag_echo> ::= r'[!-+\--~]+' := recalled_required_tag()
<reply_headers_sent> ::= <h_via>? <h_date>? <h_extension>?
# 2326 12.17: the reply carries the CSeq of the request
<h_cseq_echo> ::= <name_cseq> ':' <ows_sent> <cseq_echo> <crlf>
<cseq_echo> ::= <digits> := recalled_server_cseq()
# 2326 12.28: Public lists the methods the client supports
<h_public_sent> ::= 'Public:' <ows_sent> 'OPTIONS, ANNOUNCE, GET_PARAMETER, SET_PARAMETER, REDIRECT' <crlf>

# ======================================================================================
# Replies of the server (2326 7)
# ======================================================================================

# 2326 7.1: Status-Line = RTSP-Version SP Status-Code SP Reason-Phrase CRLF
<rtsp_version_rcv> ::= 'RTSP/' r'[0-9]+' '.' r'[0-9]+'
<reason_phrase> ::= <text>?

# --- status codes (2326 7.1.1, 11; one nonterminal per code) ---
<code_100> ::= '100'
<code_200> ::= '200'
<code_201> ::= '201'
<code_250> ::= '250'
<code_300> ::= '300'
<code_301> ::= '301'
<code_302> ::= '302'
<code_303> ::= '303'
<code_304> ::= '304'
<code_305> ::= '305'
<code_400> ::= '400'
<code_401> ::= '401'
<code_402> ::= '402'
<code_403> ::= '403'
<code_404> ::= '404'
<code_405> ::= '405'
<code_406> ::= '406'
<code_407> ::= '407'
<code_408> ::= '408'
<code_410> ::= '410'
<code_411> ::= '411'
<code_412> ::= '412'
<code_413> ::= '413'
<code_414> ::= '414'
<code_415> ::= '415'
<code_451> ::= '451'
<code_452> ::= '452'
<code_453> ::= '453'
<code_454> ::= '454'
<code_455> ::= '455'
<code_456> ::= '456'
<code_457> ::= '457'
<code_458> ::= '458'
<code_459> ::= '459'
<code_460> ::= '460'
<code_461> ::= '461'
<code_462> ::= '462'
<code_500> ::= '500'
<code_501> ::= '501'
<code_502> ::= '502'
<code_503> ::= '503'
<code_504> ::= '504'
<code_505> ::= '505'
<code_551> ::= '551'
# 2326 7.1.1: extension-code = 3DIGIT, treated as the x00 code of its class (F33)
<code_1xx_ext> ::= r'1(?!00)[0-9][0-9]'
<code_2xx_ext> ::= r'2(?!00|01|50)[0-9][0-9]'
<code_3xx_ext> ::= r'3(?!0[0-5])[0-9][0-9]'
<code_4xx_ext> ::= r'4(?!0[0-8]|1[0-5]|5[1-9]|6[0-2])[0-9][0-9]'
<code_5xx_ext> ::= r'5(?!0[0-5]|51)[0-9][0-9]'

# --- status codes by class (2326 7.1.1) ---
<status_1xx> ::= <code_100> | <code_1xx_ext>
<status_2xx> ::= <code_200> | <code_201> | <code_250> | <code_2xx_ext>
<status_3xx> ::= <code_300> | <code_301> | <code_302> | <code_303> | <code_305> | <code_3xx_ext>
<status_err> ::= <code_400> | <code_401> | <code_402> | <code_403> | <code_404> | <code_405> \
    | <code_406> | <code_407> | <code_408> | <code_410> | <code_411> | <code_412> | <code_413> \
    | <code_414> | <code_415> | <code_451> | <code_452> | <code_453> | <code_454> | <code_455> \
    | <code_456> | <code_457> | <code_458> | <code_459> | <code_460> | <code_461> | <code_462> \
    | <code_4xx_ext> \
    | <code_500> | <code_501> | <code_502> | <code_503> | <code_504> | <code_505> | <code_551> \
    | <code_5xx_ext>

# --- the reply messages; the body is as long as Content-Length says (2326 4.4) ---
# 1xx: no body, ends at the empty line (2326 4.4, C7); the final reply follows it
<rep_1xx> ::= <rtsp_version_rcv> <sp> <status_code_1xx> <sp> <reason_phrase> <crlf> <reply_rest_interim>
<status_code_1xx> ::= <status_1xx>
<rep_2xx> ::= <rtsp_version_rcv> <sp> <status_code> <sp> <reason_phrase> <crlf> <reply_rest>
<rep_err> ::= <rtsp_version_rcv> <sp> <status_code_err> <sp> <reason_phrase> <crlf> <reply_rest>
<rep_3xx> ::= <rtsp_version_rcv> <sp> <status_code_3xx> <sp> <reason_phrase> <crlf> <reply_rest>
<status_code> ::= <status_2xx>
<status_code_err> ::= <status_err>
<status_code_3xx> ::= <status_3xx>
# 304 Not Modified (2326 12.23, conditional DESCRIBE and SETUP): no body (2326 4.4)
<rep_304> ::= <rtsp_version_rcv> <sp> <code_304> <sp> <reason_phrase> <crlf> <reply_rest_bodiless>

# replies by class (2326 7.1.1 Table 1 lists the codes per method; it is no obligation, so
# every class is accepted after every method)
<rep_any> ::= <rep_2xx> | <rep_3xx> | <rep_err> | <rep_304>
<rep_not_3xx> ::= <rep_2xx> | <rep_err> | <rep_304>
<rep_not_2xx> ::= <rep_3xx> | <rep_err> | <rep_304>
<rep_setup_2xx> ::= <rep_2xx>
<rep_describe_2xx> ::= <rep_2xx>
<rep_announce_2xx> ::= <rep_2xx>
<rep_play_2xx> ::= <rep_2xx>
<rep_record_2xx> ::= <rep_2xx>
<rep_pause_2xx> ::= <rep_2xx>
<rep_teardown_2xx> ::= <rep_2xx>
# the reply to an extension method: every class but 3xx, which redirects (C25: see
# unimplemented_refused, on <rep_2xx>, <rep_err>, <rep_304>)
<rep_extension> ::= <rep_not_3xx>
# 9112 9.6: a final reply that carries the "close" connection option (in a Connection field,
# 2326 12.10) ends the connection: "A client that receives a "close" connection option MUST cease
# sending requests on that connection", and "The server MUST NOT process any further requests
# received on that connection", so no reply to a request pipelined behind it follows. A message
# of its own, of any class, accepted wherever a final reply is (followed by <reply_end_close>);
# the replies above carry no "close" (<rsp_header>)
<rep_closing> ::= <rep_2xx_closing> | <rep_3xx_closing> | <rep_err_closing> | <rep_304_closing>
<rep_2xx_closing> ::= <rtsp_version_rcv> <sp> <status_code> <sp> <reason_phrase> <crlf> <reply_rest_closing>
<rep_err_closing> ::= <rtsp_version_rcv> <sp> <status_code_err> <sp> <reason_phrase> <crlf> <reply_rest_closing>
<rep_3xx_closing> ::= <rtsp_version_rcv> <sp> <status_code_3xx> <sp> <reason_phrase> <crlf> <reply_rest_closing>
<rep_304_closing> ::= <rtsp_version_rcv> <sp> <code_304> <sp> <reason_phrase> <crlf> <reply_rest_bodiless_closing>
# the same in the place of a pipelined reply, whose request its place in the pipeline names
<rep_pipelined_first_closing> ::= <rep_closing>
<rep_pipelined_second_closing> ::= <rep_closing>

# ======================================================================================
# Header fields of the server's messages (2326 12); names case-insensitive (9110 5.1)
# ======================================================================================

# 2326 4.4, 12.14: a message without Content-Length has no body and ends at the empty line;
# with Content-Length, the body has that many octets (C5, C6). 2326 12.17: exactly one CSeq
# in every reply (C1, C34). The header block without Content-Length, and the one with it.
# After the header block of a final reply, the deviation a tolerance accepts (empty, counted
# from the request and the block): <timestamp_not_echoed> (2326 12.38, C13)
<reply_rest> ::= <rsp_headers> <timestamp_not_echoed>{timestamp_missing(<rsp_headers>)} <crlf> \
    | <rsp_headers_length> <timestamp_not_echoed>{timestamp_missing(<rsp_headers_length>)} <crlf> <entity_body>
<timestamp_not_echoed> ::= ''
# the body: as many octets as Content-Length says (2326 4.4) ...
<entity_body> ::= <block_256>{content_length(<h_content_length>) // 256} <block_16>{content_length(<h_content_length>) % 256 // 16} <octet>{content_length(<h_content_length>) % 16} := entity_to_octets(<entity>)
# ... and the same data typed by its Content-Type (2326 12.16; converter pair <entity_body> /
# <entity>, the type its first octet): an SDP description (2326 C), parameters (text/parameters,
# 2326 10.8, 10.9), a body the client does not interpret, or none (Content-Length: 0)
<entity> ::= <entity_sdp> | <entity_parameters> | <entity_opaque> | <entity_empty> := octets_to_entity(<entity_body>)
<entity_sdp> ::= 'S' <sdp>
<entity_parameters> ::= 'P' <parameters_rcv>
<entity_opaque> ::= b'O' <opaque_entity>
<entity_empty> ::= 'E'
<opaque_entity> ::= rb'[\x00-\xff]+'
# 2326 10.8, 10.9 (example type text/parameters): lines of a parameter name, with its value
# after ":" in replies and SET_PARAMETER; the last line may lack its line end
<parameters_rcv> ::= <parameter_line_rcv>+ <parameter_last_rcv>? | <parameter_last_rcv>
<parameter_line_rcv> ::= <parameter_rcv>? <sdp_eol>
<parameter_last_rcv> ::= <parameter_rcv>
<parameter_rcv> ::= <parameter_name_rcv> (':' <ows> <parameter_value_rcv>?)?
<parameter_name_rcv> ::= r'[^:\r\n]+'
<parameter_value_rcv> ::= r'[^\r\n \t][^\r\n]*'
# 2326 4.4: 304 replies end at the empty line whatever their header fields (C7)
<reply_rest_bodiless> ::= <rsp_headers> <timestamp_not_echoed>{timestamp_missing(<rsp_headers>)} <crlf> \
    | <rsp_headers_length> <timestamp_not_echoed>{timestamp_missing(<rsp_headers_length>)} <crlf>
# the header block of a reply with "close" (<rep_closing>): the first field that names it is the
# mandatory one; the fields before it carry no "close", those after it any (9112 9.6)
<reply_rest_closing> ::= <rsp_headers_closing> <timestamp_not_echoed>{timestamp_missing(<rsp_headers_closing>)} <crlf> \
    | <rsp_headers_length_closing> <timestamp_not_echoed>{timestamp_missing(<rsp_headers_length_closing>)} <crlf> <entity_body>
<reply_rest_bodiless_closing> ::= <rsp_headers_closing> <timestamp_not_echoed>{timestamp_missing(<rsp_headers_closing>)} <crlf> \
    | <rsp_headers_length_closing> <timestamp_not_echoed>{timestamp_missing(<rsp_headers_length_closing>)} <crlf>
# a 1xx reply is no final reply: a "close" in it ends nothing (9112 9.6 speaks of the final response)
<reply_rest_interim> ::= <rsp_headers> <crlf> | <rsp_headers_length> <crlf> \
    | <rsp_headers_closing> <crlf> | <rsp_headers_length_closing> <crlf>
<rsp_headers> ::= <rsp_header>* <h_cseq_rcv> <rsp_header>*
<rsp_headers_length> ::= <rsp_header>* <h_cseq_rcv> <rsp_header>* <h_content_length> <rsp_header>* \
    | <rsp_header>* <h_content_length> <rsp_header>* <h_cseq_rcv> <rsp_header>*
<rsp_headers_closing> ::= <rsp_header>* <h_cseq_rcv> <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* \
    | <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* <h_cseq_rcv> <rsp_header_any>*
<rsp_headers_length_closing> ::= <rsp_header>* <h_cseq_rcv> <rsp_header>* <h_content_length> <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* \
    | <rsp_header>* <h_content_length> <rsp_header>* <h_cseq_rcv> <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* \
    | <rsp_header>* <h_cseq_rcv> <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* <h_content_length> <rsp_header_any>* \
    | <rsp_header>* <h_content_length> <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* <h_cseq_rcv> <rsp_header_any>* \
    | <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* <h_cseq_rcv> <rsp_header_any>* <h_content_length> <rsp_header_any>* \
    | <rsp_header>* <h_connection_close_rcv> <rsp_header_any>* <h_content_length> <rsp_header_any>* <h_cseq_rcv> <rsp_header_any>*
<h_cseq_rcv> ::= r'(?i:cseq)' ':' <ows> <cseq_value_rcv> <ows> <crlf>
<cseq_value_rcv> ::= <digits>

# the fields of a reply (without "close", see <rep_closing>) and of a request of the server
<rsp_header> ::= <srv_header_common> | <h_connection_keep_rcv> | <h_range_rcv>
<rsp_header_any> ::= <rsp_header> | <h_connection_close_rcv>
<srv_header> ::= <srv_header_no_range> | <h_range_rcv>
<srv_header_no_range> ::= <srv_header_common> | <h_connection_rcv>
<srv_header_common> ::= <h_content_type> | <h_content_base> | <h_content_location> \
    | <h_content_encoding> | <h_content_language> | <h_session_rcv> | <h_transport_rcv> \
    | <h_public> | <h_allow> | <h_rtp_info> | <h_www_authenticate> \
    | <h_proxy_authenticate> | <h_unsupported> | <h_location> | <h_scale_rcv> | <h_speed_rcv> \
    | <h_timestamp_rcv> | <h_cache_control_rcv> | <h_expires> \
    | <h_last_modified> | <h_known_text> | <h_extension_rcv>

# 2326 12.14: Content-Length = "Content-Length" ":" 1*DIGIT
<h_content_length> ::= r'(?i:content-length)' ':' <ows> <content_length_value> <ows> <crlf>
<content_length_value> ::= <digits>
# 2326 12.16 / 9110 8.3: Content-Type = media-type = type "/" subtype *( OWS ";" OWS parameter )
<h_content_type> ::= r'(?i:content-type)' ':' <ows> <media_type_rcv> <ows> <crlf>
<media_type_rcv> ::= <token> '/' <token> (<ows> ';' <ows> <token> '=' (<token> | <quoted_string>))*
# 2326 12.11 Content-Base, 12.15 Content-Location, 12.25 Location: URLs
<h_content_base> ::= r'(?i:content-base)' ':' <ows> <uri_rcv> <ows> <crlf>
<h_content_location> ::= r'(?i:content-location)' ':' <ows> <uri_rcv> <ows> <crlf>
<h_location> ::= r'(?i:location)' ':' <ows> <uri_rcv> <ows> <crlf>
<uri_rcv> ::= r'[!-~]+'
# 2326 12.12 / 9110 8.4: Content-Encoding = 1#content-coding (F22)
<h_content_encoding> ::= r'(?i:content-encoding)' ':' <ows> <list_lead>* <token> (<list_sep> <token>)* <list_trail>* <ows> <crlf>
# 2326 12.13 / 9110 8.5: Content-Language = 1#language-tag (F94)
<h_content_language> ::= r'(?i:content-language)' ':' <ows> <list_lead>* <language_tag_rcv> (<list_sep> <language_tag_rcv>)* <list_trail>* <ows> <crlf>
<language_tag_rcv> ::= r'[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*'
# 2326 12.8: Cache-Control = 1#cache-directive; the response directives (F92)
<h_cache_control_rcv> ::= r'(?i:cache-control)' ':' <ows> <list_lead>* <cache_directive_rcv> (<list_sep> <cache_directive_rcv>)* <list_trail>* <ows> <crlf>
<cache_directive_rcv> ::= <cdr_public> | <cdr_private> | <cdr_no_cache> | <cdr_no_transform> \
    | <cdr_must_revalidate> | <cdr_proxy_revalidate> | <cdr_max_age> | <cdr_extension>
<cdr_public> ::= r'(?i:public)'
<cdr_private> ::= r'(?i:private)' ('=' <quoted_string>)?
<cdr_no_cache> ::= r'(?i:no-cache)' ('=' <quoted_string>)?
<cdr_no_transform> ::= r'(?i:no-transform)'
<cdr_must_revalidate> ::= r'(?i:must-revalidate)'
<cdr_proxy_revalidate> ::= r'(?i:proxy-revalidate)'
<cdr_max_age> ::= r'(?i:max-age)' '=' <digits>
# cache-extension (and the request directives of a server's request)
<cdr_extension> ::= r"(?!(?i:public|private|no-cache|no-transform|must-revalidate|proxy-revalidate|max-age)\Z)[!#$%&'*+.^_`|~0-9A-Za-z-]+" ('=' (<token> | <quoted_string>))?
# 2326 12.19 Expires, 12.24 Last-Modified = HTTP-date; 9110 5.6.7: recipients accept all three
# formats; 2326 12.19: clients MUST treat invalid Expires dates, e.g. "0", as already expired
<h_expires> ::= r'(?i:expires)' ':' <ows> (<http_date_rcv> | <expires_invalid>) <ows> <crlf>
<h_last_modified> ::= r'(?i:last-modified)' ':' <ows> <http_date_rcv> <ows> <crlf>
<http_date_rcv> ::= <imf_fixdate_rcv> | <rfc850_date_rcv> | <asctime_date_rcv>
<imf_fixdate_rcv> ::= r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
<rfc850_date_rcv> ::= r'(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), [0-9]{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT'
<asctime_date_rcv> ::= r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[0-9]{2}| [0-9]) [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}'
<expires_invalid> ::= r'(?!(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT|(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), [0-9]{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:[0-9]{2}| [0-9]) [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4})\Z)[^\r\n \t](?:[^\r\n]*[^\r\n \t])?'


# 2326 12.37: Session = "Session" ":" session-id [ ";" "timeout" "=" delta-seconds ]
<h_session_rcv> ::= r'(?i:session)' ':' <ows> <session_id_rcv> <session_timeout>? <ows> <crlf>
# session-id = 1*( ALPHA | DIGIT | safe ), safe = "$" | "-" | "_" | "." | "+"
<session_id_rcv> ::= r'[A-Za-z0-9$_.+-]+'
<session_timeout> ::= <ows> ';' <ows> r'(?i:timeout)' '=' <timeout_seconds>
<timeout_seconds> ::= <digits>

# 2326 12.39: Transport of a reply: the single transport-spec the server chose (C14)
<h_transport_rcv> ::= r'(?i:transport)' ':' <ows> <list_lead>* <transport_spec_rcv> <list_trail>* <ows> <crlf>
<transport_spec_rcv> ::= <transport_id_rcv> <transport_param_rcv>*
<transport_id_rcv> ::= r'(?i:rtp/avp)' <lower_transport_rcv>? | <transport_id_ext>
<lower_transport_rcv> ::= '/' r'(?i:tcp|udp)'
# transport protocols and profiles only extensions define (e.g. RTP/SAVP)
<transport_id_ext> ::= r'(?!(?i:rtp/avp)(?:/(?i:tcp|udp))?\Z)[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?'
<transport_param_rcv> ::= ';' <transport_parameter>
<transport_parameter> ::= <tp_unicast_rcv> | <tp_multicast_rcv> | <tp_destination_rcv> | <tp_source_rcv> \
    | <tp_interleaved_rcv> | <tp_append_rcv> | <tp_ttl_rcv> | <tp_layers_rcv> | <tp_port_rcv> \
    | <tp_client_port_rcv> | <tp_server_port_rcv> | <tp_ssrc_rcv> | <tp_mode_rcv> | <tp_extension_rcv>
<tp_unicast_rcv> ::= r'(?i:unicast)'
<tp_multicast_rcv> ::= r'(?i:multicast)'
<tp_destination_rcv> ::= r'(?i:destination)' ('=' <address_rcv>)?
# "source" is described in 2326 12.39's text, not its BNF
<tp_source_rcv> ::= r'(?i:source)' '=' <address_rcv>
<address_rcv> ::= r'[A-Za-z0-9.:\[\]-]+'
<tp_interleaved_rcv> ::= r'(?i:interleaved)' '=' <channel> ('-' <channel>)?
<tp_append_rcv> ::= r'(?i:append)'
<tp_ttl_rcv> ::= r'(?i:ttl)' '=' r'[0-9]{1,3}'
<tp_layers_rcv> ::= r'(?i:layers)' '=' <digits>
<tp_port_rcv> ::= r'(?i:port)' '=' <port_range_rcv>
<tp_client_port_rcv> ::= r'(?i:client_port)' '=' <port_range_rcv>
<tp_server_port_rcv> ::= r'(?i:server_port)' '=' <port_range_rcv>
<port_range_rcv> ::= r'[0-9]{1,5}' ('-' r'[0-9]{1,5}')?
<tp_ssrc_rcv> ::= r'(?i:ssrc)' '=' r'[0-9A-Fa-f]{8}'
<tp_mode_rcv> ::= r'(?i:mode)' '=' (<method_rcv> | '"' <method_rcv> (<ows> ',' <ows> <method_rcv>)* '"')
<method_rcv> ::= <token>
# parameters only extensions define
<tp_extension_rcv> ::= r'(?!(?i:unicast|multicast|destination|source|interleaved|append|ttl|layers|port|client_port|server_port|ssrc|mode)\Z)[A-Za-z0-9._-]+' ('=' (r'[^;,\s"]+' | <quoted_string>))?

# 2326 12.28 Public, 12.4 Allow: 1#method
<h_public> ::= r'(?i:public)' ':' <ows> <method_list_rcv> <ows> <crlf>
<h_allow> ::= r'(?i:allow)' ':' <ows> <method_list_rcv> <ows> <crlf>
<method_list_rcv> ::= <list_lead>* <method_rcv> (<list_sep> <method_rcv>)* <list_trail>*

# 2326 12.29: Range of a reply
<h_range_rcv> ::= r'(?i:range)' ':' <ows> <list_lead>* <ranges_specifier_rcv> (<list_sep> <ranges_specifier_rcv>)* <list_trail>* (';' r'(?i:time)' '=' <utc_time_rcv>)? <ows> <crlf>
<ranges_specifier_rcv> ::= <npt_range_rcv> | <smpte_range_rcv> | <utc_range_rcv>
<npt_range_rcv> ::= r'(?i:npt)' '=' (<npt_time_rcv> '-' <npt_time_rcv>? | '-' <npt_time_rcv>)
<npt_time_rcv> ::= r'(?i:now)' | r'[0-9]+(?:\.[0-9]*)?' | r'[0-9]+:[0-9]{1,2}:[0-9]{1,2}(?:\.[0-9]*)?'
<smpte_range_rcv> ::= r'(?i:smpte-30-drop|smpte-25|smpte)' '=' <smpte_time_rcv> '-' <smpte_time_rcv>?
<smpte_time_rcv> ::= r'[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}(?::[0-9]{1,2})?(?:\.[0-9]{1,2})?'
<utc_range_rcv> ::= r'(?i:clock)' '=' <utc_time_rcv> '-' <utc_time_rcv>?
<utc_time_rcv> ::= r'[0-9]{8}T[0-9]{6}(?:\.[0-9]+)?Z'

# 2326 12.33: RTP-Info = 1#stream-url 1*parameter; parameter = ";" "seq" "=" 1*DIGIT |
# ";" "rtptime" "=" 1*DIGIT
<h_rtp_info> ::= r'(?i:rtp-info)' ':' <ows> <list_lead>* <rtp_info_stream> (<list_sep> <rtp_info_stream>)* <list_trail>* <ows> <crlf>
<rtp_info_stream> ::= r'(?i:url)' '=' <rtp_info_url> <rtp_info_param>*
<rtp_info_url> ::= r'[^;,\s]+'
<rtp_info_param> ::= ';' (r'(?i:seq)' '=' <digits> | r'(?i:rtptime)' '=' <digits> | <rtp_info_param_ext>)
<rtp_info_param_ext> ::= r'(?!(?i:seq|rtptime)\Z)[A-Za-z0-9_-]+' ('=' r'[^;,\s]+')?

# 9110 11.6.1 WWW-Authenticate, 11.7.1 Proxy-Authenticate: 1#challenge;
# challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
<h_www_authenticate> ::= r'(?i:www-authenticate)' ':' <ows> <list_lead>* <challenge> (<list_sep> <challenge>)* <list_trail>* <ows> <crlf>
<h_proxy_authenticate> ::= r'(?i:proxy-authenticate)' ':' <ows> <list_lead>* <challenge> (<list_sep> <challenge>)* <list_trail>* <ows> <crlf>
<challenge> ::= <auth_scheme> (r' +' <auth_params>)?
<auth_scheme> ::= <token>
# #auth-param = [ auth-param ] *( OWS "," OWS [ auth-param ] ): empty elements before and between
# the parameters; those after the last one, and a list without any parameter, parse as empty
# elements of the challenge list around it. A leading empty element may have OWS before its comma;
# r' +' takes all spaces after the scheme, so that OWS starts with HTAB or a fold (<lws_nosp>)
<auth_params> ::= <auth_param> (<list_sep> <auth_param>)* \
    | <auth_lead> <list_comma>* <ows> <auth_param> (<list_sep> <auth_param>)* | <token68>
<auth_lead> ::= <lws_nosp>? ','
# LWS that does not start with SP (2326 15)
<lws_nosp> ::= r'(?:\t|\r\n[ \t])(?:[ \t]|\r\n[ \t])*'
<auth_param> ::= <token> <ows> '=' <ows> (<token> | <quoted_string>)
<token68> ::= r'[A-Za-z0-9._~+/-]+=*'

# 2326 12.40: Unsupported = 1#option-tag
<h_unsupported> ::= r'(?i:unsupported)' ':' <ows> <list_lead>* <option_tag_rcv> (<list_sep> <option_tag_rcv>)* <list_trail>* <ows> <crlf>
<option_tag_rcv> ::= r'[!-+\--~]+'

# 2326 12.34 Scale, 12.35 Speed, 12.38 Timestamp of a reply
<h_scale_rcv> ::= r'(?i:scale)' ':' <ows> r'-?[0-9]+(?:\.[0-9]*)?' <ows> <crlf>
<h_speed_rcv> ::= r'(?i:speed)' ':' <ows> r'[0-9]+(?:\.[0-9]*)?' <ows> <crlf>
<h_timestamp_rcv> ::= r'(?i:timestamp)' ':' <ows> <timestamp_value_rcv> (<lws> <delay_rcv>)? <ows> <crlf>
<timestamp_value_rcv> ::= r'[0-9]+(?:\.[0-9]*)?|\.[0-9]*'
<delay_rcv> ::= r'[0-9]+(?:\.[0-9]*)?'

# 2326 12.10: Connection; 9110 7.6.1: Connection = #connection-option, connection-option = token
# (case-insensitive). In a request of the server any options; in a reply either none of them is
# "close" (<h_connection_keep_rcv>) or the field names it (<h_connection_close_rcv>: the options
# before the first "close" are others, those after it any), see <rep_closing>
<h_connection_rcv> ::= r'(?i:connection)' ':' <ows> <list_lead>* <token> (<list_sep> <token>)* <list_trail>* <ows> <crlf>
<h_connection_keep_rcv> ::= r'(?i:connection)' ':' <ows> <list_lead>* <connection_option_rcv> (<list_sep> <connection_option_rcv>)* <list_trail>* <ows> <crlf>
<h_connection_close_rcv> ::= r'(?i:connection)' ':' <ows> <list_lead>* (<connection_option_rcv> <list_sep>)* <connection_close_rcv> (<list_sep> <token>)* <list_trail>* <ows> <crlf>
# a token other than "close": one that does not begin with it, or begins with it and goes on
<connection_option_rcv> ::= r"(?:(?!(?i:close))[!#$%&'*+.^_`|~0-9A-Za-z-]+|(?i:close)[!#$%&'*+.^_`|~0-9A-Za-z-]+)"
<connection_close_rcv> ::= r'(?i:close)'

# known fields the client only reads as text: Date, Server, Via, Retry-After, Vary,
# Accept-Ranges (2326 12.18, 12.36, 12.43, 12.31, 12.42) and request fields (Host 12.21,
# Proxy-Authorization Table 3, ...); longest names first
<h_known_text> ::= r'(?i:proxy-authorization|if-modified-since|accept-encoding|accept-language|accept-ranges|authorization|proxy-require|retry-after|conference|user-agent|bandwidth|blocksize|if-match|key-mgmt|referer|require|accept|server|date|from|host|vary|via)' ':' <field_text> <crlf>
# 2326 8.1: extension-header = message-header; any other field name, unconstrained
<h_extension_rcv> ::= <extension_name_rcv> ':' <field_text> <crlf>
<extension_name_rcv> ::= r"(?!(?i:cseq|content-length|content-type|content-base|content-location|content-encoding|content-language|session|transport|public|allow|range|rtp-info|www-authenticate|proxy-authenticate|unsupported|location|scale|speed|timestamp|connection|date|server|expires|last-modified|cache-control|via|retry-after|vary|accept-ranges|bandwidth|blocksize|user-agent|accept|accept-encoding|accept-language|require|proxy-require|conference|from|referer|if-modified-since|if-match|authorization|key-mgmt|proxy-authorization|host)\Z)[!#$%&'*+.^_`|~0-9A-Za-z-]+"

# ======================================================================================
# SDP descriptions of the server (2326 C): the lines RFC 2326 gives a meaning
# ======================================================================================

# TODO: 2326 C / RFC 8866 (SDP, not in refs/spec): field values other than a=control, a=range, a=etag are read as text in <sdp_value>
<sdp> ::= <sdp_v_rcv> <sdp_session_line>* <sdp_media>*
<sdp_v_rcv> ::= 'v=' <sdp_value> <sdp_eol>
<sdp_session_line> ::= <sdp_a_control_rcv> | <sdp_a_range_rcv> | <sdp_a_etag_rcv> | <sdp_a_other> | <sdp_other_line>
# 2326 C.1.2: one media section per stream, from its m= line
<sdp_media> ::= <sdp_m_rcv> <sdp_media_line>*
<sdp_m_rcv> ::= 'm=' <sdp_value> <sdp_eol>
<sdp_media_line> ::= <sdp_a_control_rcv> | <sdp_a_range_rcv> | <sdp_a_other> | <sdp_other_line>
# 2326 C.1.1: a=control:url ("*" = the base URL)
<sdp_a_control_rcv> ::= 'a=control:' <sdp_value> <sdp_eol>
# 2326 C.1.5: a=range:<range>
<sdp_a_range_rcv> ::= 'a=range:' <ranges_specifier_rcv> <sdp_eol>
# 2326 C.1.8: a=etag:<entity tag>
<sdp_a_etag_rcv> ::= 'a=etag:' <sdp_value> <sdp_eol>
<sdp_a_other> ::= 'a=' <sdp_attribute_name> (':' <sdp_value>?)? <sdp_eol>
<sdp_attribute_name> ::= r'(?!(?:control|range|etag)\Z)[!#-9;-~]+'
# the other SDP lines: type letter, "=", value (v= and m= open the description and its sections)
<sdp_other_line> ::= <sdp_other_type> '=' <sdp_value>? <sdp_eol>
<sdp_other_type> ::= r'[b-ln-uw-z]'
<sdp_value> ::= r'[^\r\n]+'
<sdp_eol> ::= '\r\n' | '\n'

# ======================================================================================
# Requests of the server (2326 10, S->C) and interleaved data
# ======================================================================================

<srv_request_line> ::= <sp> <uri_rcv> <sp> <rtsp_version_rcv> <crlf>
<srv_request_tail> ::= <srv_request_line> <srv_rest>
<srv_rest> ::= <srv_headers> <crlf> | <srv_headers_length> <crlf> <srv_entity_body>
<srv_entity_body> ::= <block_256>{content_length(<srv_rest>) // 256} <block_16>{content_length(<srv_rest>) % 256 // 16} <octet>{content_length(<srv_rest>) % 16} := entity_to_octets(<srv_entity>)
<srv_entity> ::= <entity_sdp> | <entity_parameters> | <entity_opaque> | <entity_empty> := octets_to_entity(<srv_entity_body>)
<srv_headers> ::= <srv_header>* <h_cseq_rcv> <srv_header>*
<srv_headers_length> ::= <srv_header>* <h_cseq_rcv> <srv_header>* <h_content_length> <srv_header>* \
    | <srv_header>* <h_content_length> <srv_header>* <h_cseq_rcv> <srv_header>*
# 2326 10.3: ANNOUNCE S->C updates the session description
<srv_req_announce> ::= 'ANNOUNCE' <srv_request_tail>
# 2326 10.8, 10.9: GET_PARAMETER and SET_PARAMETER S->C (bodies of names and of "name: value"
# lines, <entity_parameters>)
<srv_req_get_parameter> ::= 'GET_PARAMETER' <srv_request_tail>
<srv_req_set_parameter> ::= 'SET_PARAMETER' <srv_request_tail>
# 2326 10.1: OPTIONS S->C
<srv_req_options> ::= 'OPTIONS' <srv_request_tail>
# 2326 10.10: REDIRECT, with the mandatory Location (C26), without and with a Range that says
# when it takes effect; it carries no body
<srv_req_redirect> ::= 'REDIRECT' <srv_request_line> <redirect_headers> <crlf>
<srv_req_redirect_ranged> ::= 'REDIRECT' <srv_request_line> <redirect_headers_ranged> <crlf>
<redirect_headers> ::= <srv_header_no_range>* <h_cseq_rcv> <srv_header_no_range>*
<redirect_headers_ranged> ::= <srv_header_no_range>* <h_cseq_rcv> <srv_header_no_range>* <h_range_rcv> <srv_header_no_range>* \
    | <srv_header_no_range>* <h_range_rcv> <srv_header_no_range>* <h_cseq_rcv> <srv_header_no_range>*
<srv_req_extension> ::= <srv_extension_method> <srv_request_tail>
<srv_extension_method> ::= r'(?!(?:ANNOUNCE|GET_PARAMETER|SET_PARAMETER|OPTIONS|REDIRECT)\Z)[!#%&\'*+.^_`|~0-9A-Za-z-]+'

# 2326 10.12: "$", one-byte channel, two-byte length, the data (an RTP or RTCP packet;
# its format is RFC 3550's)
# TODO: 2326 10.12 / RFC 3550 (out of the manifest): RTP and RTCP packets inside <interleaved_frame> are another protocol
<interleaved_frame> ::= b'$' <channel_byte> <frame_length_rcv> <block_256>{frame_length(<frame_length_rcv>) // 256} <block_16>{frame_length(<frame_length_rcv>) % 256 // 16} <octet>{frame_length(<frame_length_rcv>) % 16}
<channel_byte> ::= <octet>
<frame_length_rcv> ::= <octet> <octet>

# ======================================================================================
# Constraints
# ======================================================================================

# 2326 12.17 (C1): every reply carries the CSeq of the request it answers
where forall <h> in <rsp_headers>: cseq_echoed(<h>)
where forall <h> in <rsp_headers_length>: cseq_echoed(<h>)
where forall <h> in <rsp_headers_closing>: cseq_echoed(<h>)
where forall <h> in <rsp_headers_length_closing>: cseq_echoed(<h>)
# 2326 9.2 (C3): the CSeq of each request is one more than the client's previous request's
where forall <h> in <h_cseq>: int(<h>.<cseq_value>) == expected_cseq(<h>)
# 2326 9.2 (C2, F89): requests are resent over UDP only
where forall <e> in <resend_due>: resend_allowed(<e>)
# 2326 3.2, 9 (F88): the scheme of the session's transport
where forall <s> in <rtsp_scheme>: str(<s>).lower() == URL_SCHEME
where forall <h> in <rsp_headers>: record_answered_cseq(<h>)
where forall <h> in <rsp_headers_length>: record_answered_cseq(<h>)
where forall <h> in <rsp_headers_closing>: record_answered_cseq(<h>)
where forall <h> in <rsp_headers_length_closing>: record_answered_cseq(<h>)
where forall <h> in <rsp_headers>: record_reply_effects(<h>)
where forall <h> in <rsp_headers_length>: record_reply_effects(<h>)
where forall <h> in <rsp_headers_closing>: record_reply_effects(<h>)
where forall <h> in <rsp_headers_length_closing>: record_reply_effects(<h>)
# a session starts from a fresh record of received values
where forall <t> in <reply_start>: session_begins(<t>)
# the restarted reply timer before wrong credentials runs RTSP_AUTH_REPLY_WAIT seconds
where forall <t> in <reply_start_auth>: str(<t>.<timer_timeout>) == RTSP_AUTH_REPLY_WAIT
# 2326 C.1.1, C.3: the streams of a description, which SETUPs address (recorded, recalled by
# <described_stream> and <setup_target>); C.1.8 its a=etag (recalled by <etag_chars>)
where forall <s> in <sdp>: record_description(<s>)
# 2326 12.37 (C9): requests of a session return the identifier its SETUP reply assigned;
# recorded from the reply, recalled by the generator of <session_id_sent>
where forall <r> in <rep_setup_2xx>: record_session(<r>)
where forall <r> in <rep_play_2xx>: record_play_session(<r>)
where forall <h> in <h_session>: str(<h>.<session_id_sent>) == session_for(<h>)
# 2326 12.17: the client's reply echoes the CSeq of the server's request
where forall <q> in <srv_headers>: record_server_cseq(<q>)
where forall <q> in <srv_headers_length>: record_server_cseq(<q>)
where forall <q> in <redirect_headers>: record_server_cseq(<q>)
where forall <q> in <redirect_headers_ranged>: record_server_cseq(<q>)
where forall <e> in <cseq_echo>: str(<e>) == request_cseq(<e>)
# 2326 12.37, 12.32: the client's reply returns the Session of the server's request and lists in
# Unsupported the option-tags of its Require
where forall <s> in <session_id_echo>: str(<s>) == request_session(<s>)
where forall <t> in <option_tag_echo>: str(<t>) == required_tag_at(<t>)
# 2326 4.4 (C7, C8 via 9110 8.6): no Content-Length in 1xx replies
where forall <r> in <rep_1xx>: no_content_length(<r>)
# 2326 12.38 (C13): the reply echoes the request's Timestamp
where forall <h> in <rsp_headers>: timestamp_echoed(<h>)
where forall <h> in <rsp_headers_length>: timestamp_echoed(<h>)
where forall <h> in <rsp_headers_closing>: timestamp_echoed(<h>)
where forall <h> in <rsp_headers_length_closing>: timestamp_echoed(<h>)
# Tolerance "timestamp-not-echoed" (tolerances.json): a reply header block without any Timestamp
# field although the request carried one (<x> is passed so that Fandango reports the failing tree)
where forall <x> in <timestamp_not_echoed>: tolerated("timestamp-not-echoed", <x>)
# 2326 12.32 (C21): the reply to a request with Require lists in Unsupported the option-tags the
# session shows the server does not support (an earlier Unsupported, a 551 to one option)
where forall <h> in <rsp_headers>: unsupported_listed(<h>)
where forall <h> in <rsp_headers_length>: unsupported_listed(<h>)
where forall <h> in <rsp_headers_closing>: unsupported_listed(<h>)
where forall <h> in <rsp_headers_length_closing>: unsupported_listed(<h>)
# ... and a 2xx or 551 reply to such a request has an Unsupported field
where forall <h> in <rsp_headers>: require_acknowledged(<h>)
where forall <h> in <rsp_headers_length>: require_acknowledged(<h>)
where forall <h> in <rsp_headers_closing>: require_acknowledged(<h>)
where forall <h> in <rsp_headers_length_closing>: require_acknowledged(<h>)
# 9110 5.3 (C14, C34): fields that are no lists appear at most once, in replies and in the
# server's requests
where forall <h> in <rsp_headers>: at_most_once(<h>)
where forall <h> in <rsp_headers_length>: at_most_once(<h>)
where forall <h> in <rsp_headers_closing>: at_most_once(<h>)
where forall <h> in <rsp_headers_length_closing>: at_most_once(<h>)
where forall <h> in <srv_headers>: at_most_once(<h>)
where forall <h> in <srv_headers_length>: at_most_once(<h>)
where forall <h> in <redirect_headers>: at_most_once(<h>)
where forall <h> in <redirect_headers_ranged>: at_most_once(<h>)
# 9110 15.5.2 (C32): a 401 reply carries a WWW-Authenticate challenge
where forall <r> in <rep_err>: challenge_in_401(<r>)
where forall <r> in <rep_err_closing>: challenge_in_401(<r>)
# 2326 10, notes on Table 2 (C25, F52): a method the session shows the server lacks (an extension
# method, or one Table 2 does not require) gets 501 (or a refusal a server gives before it looks
# at the method); on every final reply but 3xx, whatever request it answers
where forall <r> in <rep_2xx>: unimplemented_refused(<r>)
where forall <r> in <rep_2xx_closing>: unimplemented_refused(<r>)
where forall <r> in <rep_err>: unimplemented_refused(<r>)
where forall <r> in <rep_err_closing>: unimplemented_refused(<r>)
where forall <r> in <rep_304>: unimplemented_refused(<r>)
where forall <r> in <rep_304_closing>: unimplemented_refused(<r>)
# 9110 15.5.8 (C33): a 407 reply carries a Proxy-Authenticate challenge
where forall <r> in <rep_err>: challenge_in_407(<r>)
where forall <r> in <rep_err_closing>: challenge_in_407(<r>)
# 2326 11.3.1 (C23): a 405 reply carries Allow
where forall <r> in <rep_err>: allow_in_405(<r>)
where forall <r> in <rep_err_closing>: allow_in_405(<r>)
# 2326 12.34 (C17): a 2xx reply to PLAY or RECORD with Scale contains the chosen Scale
where forall <h> in <rsp_headers>: scale_answered(<h>)
where forall <h> in <rsp_headers_length>: scale_answered(<h>)
where forall <h> in <rsp_headers_closing>: scale_answered(<h>)
where forall <h> in <rsp_headers_length_closing>: scale_answered(<h>)
# 2326 12.39 (C15): where the session shows the server does not record (Public without RECORD,
# 501 to a RECORD without Range, Allow without RECORD for the SETUP's own or aggregate URL), hence
# not append, no 2xx that chooses mode RECORD for a
# transport-spec asking to append (or, without Transport, to a SETUP whose every spec asks); on
# every 2xx, since a SETUP's 2xx also arrives as <rep_any> (e.g. after <req_setup_close>);
# append_refused passes the replies to requests that offer no transport-spec asking to append
where forall <r> in <rep_2xx>: append_refused(<r>)
where forall <r> in <rep_2xx_closing>: append_refused(<r>)
# 2326 10.10 (C26): REDIRECT carries Location
where forall <r> in <srv_req_redirect>: location_in_redirect(<r>)
where forall <r> in <srv_req_redirect_ranged>: location_in_redirect(<r>)
# 2326 12.14 (C5, C6): the Content-Length of the client's bodies is their length
where forall <a> in <announce_body>: int(<a>.<h_announce_length>.<announce_length>) == len(bytes(<a>.<sdp_sent>))
where forall <g> in <parameter_names_body>: int(<g>.<h_parameters_length>.<parameters_length>) == len(bytes(<g>.<parameter_names>))
where forall <s> in <parameter_settings_body>: int(<s>.<h_parameters_length>.<parameters_length>) == len(bytes(<s>.<parameter_settings>))
# 9110 8.4, 2326 12.14 (C5, C6; F22): a coded body of the client: Content-Encoding names its
# coding, Content-Length its length
where forall <c> in <content_coding_sent>: str(<c>) == body_coding(<c>)
where forall <l> in <coded_length>: int(<l>) == coded_length(<l>)
# an RTP port pair: RTCP on the port above RTP
where forall <p> in <client_port_pair>: int(<p>.<client_rtcp_port>) == int(<p>.<client_rtp_port>) + 1
# 9110 8.6, 2326 4.4 (C7, C8): a 204 reply has neither Content-Length nor body
where forall <r> in <rep_2xx>: no_content_length_in_204(<r>)
where forall <r> in <rep_2xx_closing>: no_content_length_in_204(<r>)
# 2326 C.2, C.3 (C35, C36): several media sections each carry a=control
where forall <s> in <sdp>: media_controls_complete(<s>)
# 2326 12.37 (C11): a new session gets an identifier of its own; on every 2xx, since a SETUP's
# 2xx also arrives as <rep_any> (after <req_setup_close>); new_session_distinct passes the
# replies to requests other than a new-session SETUP
where forall <r> in <rep_2xx>: new_session_distinct(<r>)
where forall <r> in <rep_2xx_closing>: new_session_distinct(<r>)
# 2326 12.9 (C27): one conference-id per session
where forall <h> in <h_conference>: conference_unchanged(<h>)
