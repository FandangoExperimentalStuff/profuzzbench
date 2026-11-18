# dns.fan -- Domain Name System (RFC 1034, 1035 and the updates listed in refs/spec/manifest.json)
#
# Fandango plays the DNS client ("Client") and tests an authoritative name server ("Server").  One session is one
# connection between the two parties over the transport of the server's endpoint (UDP datagrams, or TCP with the
# two-octet length prefix of RFC 1035 4.2.2 -- see ClientNetworkParty, which strips/adds that prefix so the grammar
# only ever sees whole DNS messages).
#
# Layout of this file
#   1. test setup (the only place that depends on the environment)
#   2. Python helpers (wire decoding used by `where` constraints, generators and converters)
#   3. the party class
#   4. states and exchanges
#   5. requests (sent by Client)
#   6. replies (received from Server)
#   7. shared fields: header flags, counts, names, types, classes, resource records and their RDATA
#   8. constraints on received messages

import collections
import functools
import hashlib
import os
import random
import struct
import threading
import time

# ============================================================================================================
# 1. TEST SETUP -- every value the test setup decides, each read from an environment variable with a default
# ============================================================================================================
# Transport of the server's endpoint: "udp" (one datagram per message) or "tcp" (RFC 1035 4.2.2 length prefix)
TRANSPORT = os.environ.get("DNS_TRANSPORT", "udp")

# Zones the server setup is authoritative for (what a request addresses; each query picks from the lists)
ZONES = os.environ.get("DNS_ZONES", "example.test.,2.0.192.in-addr.arpa.,signed.test.").split(",")
# Owner names the zones hold (existing names of every kind: apex, address, alias chains, wildcard expansion, empty
# non-terminal, delegation, glue, reverse names)
NAMES_PRESENT = os.environ.get(
    "DNS_NAMES_PRESENT",
    "example.test.,host.example.test.,www.example.test.,alias.example.test.,chain1.example.test.,chain2.example.test.,"
    "dangling.example.test.,mail.example.test.,mail2.example.test.,ns1.example.test.,ns2.example.test.,ptr.example.test.,"
    "a.b.c.example.test.,b.c.example.test.,c.example.test.,sub.example.test.,ns.sub.example.test.,x.sub.example.test.,"
    "anything.wild.example.test.,a.b.wild.example.test.,wild.example.test.,*.wild.example.test.,exists.wild.example.test.,c.d.wild.example.test.,"
    "d.wild.example.test.,deleg.wild.example.test.,x.deleg.wild.example.test.,anything.wcname.example.test.,*.wcname.example.test.,wcname.example.test.,"
    "long.example.test.,big.example.test.,out.example.test.,10.2.0.192.in-addr.arpa.,25.2.0.192.in-addr.arpa.,"
    "2.0.192.in-addr.arpa.,signed.test.,host.signed.test.,www.signed.test.,mail.signed.test.,ns1.signed.test.,"
    "secure.signed.test.,ns.secure.signed.test.,insecure.signed.test.,ns.insecure.signed.test.,x.secure.signed.test.,"
    "anything.wild.signed.test.,wild.signed.test.,*.wild.signed.test.",
).split(",")
# Names below the zones that do not exist (NXDOMAIN) and names outside every zone (REFUSED or similar)
NAMES_ABSENT = os.environ.get(
    "DNS_NAMES_ABSENT",
    "nonexistent.example.test.,no.such.name.example.test.,99.2.0.192.in-addr.arpa.,nothere.signed.test.,"
    + "a" * 63 + ".example.test.",
).split(",")
NAMES_OUTSIDE = os.environ.get(
    "DNS_NAMES_OUTSIDE", "www.example.org.,example.,test.,ns.elsewhere.invalid.,.,1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
).split(",")
# Extra zones/names of a setup whose server holds more (comma separated, appended to the lists above)
ZONES += [z for z in os.environ.get("DNS_ZONES_EXTRA", "").split(",") if z]
NAMES_PRESENT += [n for n in os.environ.get("DNS_NAMES_EXTRA", "").split(",") if n]
# Seconds the client waits for the reply of a request the specification lets a server leave unanswered
SILENCE_SECONDS = float(os.environ.get("DNS_SILENCE_SECONDS", "3"))
# The same for AXFR and for the queries of other classes, whose OPT variants Fandango needs seconds to generate (the timer starts before the request); it stays
# below the driver's response timeout (5 s by default), which would otherwise report the expiry as a missing reply
AXFR_SECONDS = float(os.environ.get("DNS_AXFR_SECONDS", "4.5"))
# Over UDP the party class does not transmit an AXFR query (RFC 5936 4.2), so no reply can arrive: the AXFR timer of a UDP setup only has to cover the time Fandango
# needs to generate the request after the timer started
AXFR_UDP_SECONDS = float(os.environ.get("DNS_AXFR_UDP_SECONDS", "1"))
AXFR_START_SECONDS = AXFR_UDP_SECONDS if TRANSPORT == "udp" else AXFR_SECONDS
# Names (comma separated) of tolerated server deviations; see tolerated()
TOLERATED = os.environ.get("TOLERATED", "")


def tolerated(name):
    """A deviation named in the TOLERATED setting of the test setup is accepted by the tolerance rule guarded by it."""
    return name in [t.strip() for t in TOLERATED.split(",") if t.strip()]


# ============================================================================================================
# 2. PYTHON HELPERS
# ============================================================================================================
def byte_to_int(b):
    return int.from_bytes(bytes(b), "big")


# Fandango's parser cannot tell that a message ended when its last token is a regular expression (it keeps
# waiting 0.15 s "for more data"), so the party class ends every received message with this literal marker, which
# the reply rule ends with.  It is transport framing, not part of any DNS message.
END_MARK = b"\xfe\xed\xfe\xed"
# what the party class hands over when the server closes the TCP connection while a request is unanswered (not DNS: a transport event)
CLOSE_MARK = b"\xfe\xfe\xfe\xfe"


def pick_qname():
    """Presentation form of a name a request addresses: present, absent or outside the zones, with ASCII case varied
    (RFC 4343 3: comparisons are case-insensitive)."""
    kind = random.random()
    if kind < 0.6:
        name = random.choice(NAMES_PRESENT)
    elif kind < 0.85:
        name = random.choice(NAMES_ABSENT)
    else:
        name = random.choice(NAMES_OUTSIDE)
    if random.random() < 0.3:
        name = "".join(c.upper() if random.random() < 0.5 else c.lower() for c in name)
    return name


def is_axfr_query(data):
    d = decode(data)
    return d is not None and d["qr"] == 0 and bool(d["questions"]) and d["questions"][0][1] == 252


def pick_zone():
    """A zone name for AXFR: mostly a zone of the setup, sometimes a name that is no zone."""
    if random.random() < 0.8:
        return random.choice(ZONES)
    return random.choice(NAMES_ABSENT + NAMES_OUTSIDE[:2] + ["sub.example.test."])


def wire(text):
    """Uncompressed wire form of a presentation-form name (RFC 1035 3.1)."""
    out = b""
    for label in str(text).rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("latin1")
    return out + b"\x00"


def decode_name(msg, off):
    """(lower-cased dotted name, offset after the name in place, list of pointer targets) or None."""
    labels = []
    end = None
    pointers = []
    hops = 0
    while True:
        if off >= len(msg):
            return None
        length = msg[off]
        if length == 0:
            off += 1
            if end is None:
                end = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                return None
            target = ((length & 0x3F) << 8) | msg[off + 1]
            pointers.append((off, target))
            if end is None:
                end = off + 2
            hops += 1
            if hops > 127 or target >= len(msg):
                return None
            off = target
            continue
        if length & 0xC0:
            return None
        labels.append(msg[off + 1:off + 1 + length].lower())
        off += 1 + length
    return b".".join(labels), end, pointers


@functools.lru_cache(maxsize=8192)
def decode_cached(msg):
    return decode_uncached(msg)


def decode(msg):
    """Decodes a DNS message into a dict (header fields, questions, rrs); None if it does not decode."""
    return decode_cached(bytes(msg))


def decode_uncached(msg):
    if len(msg) < 12:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    out = {"id": ident, "flags": flags, "qr": flags >> 15, "opcode": (flags >> 11) & 15, "aa": (flags >> 10) & 1,
           "tc": (flags >> 9) & 1, "rd": (flags >> 8) & 1, "ra": (flags >> 7) & 1, "z": (flags >> 6) & 1,
           "ad": (flags >> 5) & 1, "cd": (flags >> 4) & 1, "rcode": flags & 15, "qd": qd, "an": an, "ns": ns,
           "ar": ar, "questions": [], "rrs": [], "pointers": [], "len": len(msg), "msg": msg}
    off = 12
    for _ in range(qd):
        n = decode_name(msg, off)
        if n is None or n[1] + 4 > len(msg):
            return None
        out["pointers"] += n[2]
        out["questions"].append((n[0], struct.unpack(">H", msg[n[1]:n[1] + 2])[0],
                                 struct.unpack(">H", msg[n[1] + 2:n[1] + 4])[0], off))
        off = n[1] + 4
    for section, count in (("an", an), ("ns", ns), ("ar", ar)):
        for _ in range(count):
            n = decode_name(msg, off)
            if n is None or n[1] + 10 > len(msg):
                return None
            out["pointers"] += n[2]
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[n[1]:n[1] + 10])
            out["rrs"].append({"section": section, "name": n[0], "type": rtype, "class": rclass, "ttl": ttl,
                               "rdoff": n[1] + 10, "rdlen": rdlen, "start": off})
            off = n[1] + 10 + rdlen
    # a query with more than one OPT RR or an OPT RR whose owner is not the root is no EDNS query (RFC 6891 6.1.1, 6.1.2): its OPT RRs count as none
    if out["qr"] == 0:
        opts = [r for r in out["rrs"] if r["type"] == 41]
        out["odd_opt"] = len(opts) > 1 or any(r["name"] != b"" for r in opts)
    return out


def opt_of(d):
    """The OPT records of a decoded message (none for a query whose OPT RRs break RFC 6891 6.1.1 / 6.1.2: it is no EDNS query)."""
    if d.get("odd_opt"):
        return []
    return [r for r in d["rrs"] if r["type"] == 41]


def full_rcode(d):
    """RCODE with the upper eight bits of an OPT record (RFC 6891 6.1.3)."""
    upper = 0
    for r in opt_of(d):
        upper = (r["ttl"] >> 24) & 0xFF
    return (upper << 4) | d["rcode"]


def message_nodes(tree):
    """(request nodes, reply nodes) of an exchange tree, in order (timer messages are skipped)."""
    cached = getattr(tree, "_mn", None)
    if cached is not None:
        return cached
    reqs, reps = [], []
    stack = collections.deque([tree])
    while stack:
        node = stack.popleft()
        name = str(node.symbol)
        if name.startswith("<request_"):
            reqs.append(node)
        elif name.startswith("<response"):
            reps.append(node)
        else:
            stack.extend(node.children)
    if reps and tree.read_only and exchange_done(tree):
        try:
            tree._mn = (reqs, reps)   # (the messages of an exchange the state rule has left never change)
        except Exception:
            pass
    return reqs, reps


FAST_BYTES = [0, True]   # [number of self-checks done, fast path still trusted]


def node_bytes(node):
    """bytes(node) for a message subtree, without the generic TreeValue aggregation (its leaves are byte strings)."""
    if not FAST_BYTES[1]:
        return bytes(node)
    cached = getattr(node, "_nb", None)
    if cached is not None:
        return cached
    out = []
    stack = [node]
    try:
        while stack:
            n = stack.pop()
            if n.symbol.is_terminal:
                out.append(bytes(n.symbol.value()))
            else:
                stack.extend(reversed(n.children))
        fast = b"".join(out)
    except Exception:
        FAST_BYTES[1] = False
        return bytes(node)
    if FAST_BYTES[0] < 200:
        FAST_BYTES[0] += 1
        if fast != bytes(node):
            FAST_BYTES[1] = False
            return bytes(node)
    if node.read_only:
        try:
            node._nb = fast
        except Exception:
            pass
    return fast


def message_bytes(node):
    data = node_bytes(node)
    return data[:-len(END_MARK)] if data.endswith(END_MARK) else data


def exchange_messages(tree):
    """(request bytes list, reply bytes list) of an exchange tree."""
    reqs, reps = message_nodes(tree)
    return [node_bytes(n) for n in reqs], [message_bytes(n) for n in reps]


# (session history: see below, after pairs)


def pairs(tree):
    """[(decoded request or None, decoded reply or None)] of an exchange: each reply with the request of the same
    ID (RFC 7766 7), else with the first request.  Kept on the exchange node once a reply is in."""
    req_nodes, rep_nodes = message_nodes(tree)
    key = tuple(id(n) for n in req_nodes + rep_nodes)
    cached = getattr(tree, "_pairs_cache", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    dreqs = [decode(node_bytes(n)) for n in req_nodes]
    out = []
    for node in rep_nodes:
        drep = decode(message_bytes(node))
        rq = None
        if drep is not None:
            same = [c for c in dreqs if c is not None and c["id"] == drep["id"]]
            if len(same) > 1 and drep["questions"]:
                # one ID on several requests (the pipelined pair that reuses the ID): the question tells them apart, then RD
                by_q = [c for c in same if c["questions"] and c["questions"][0][:3] == drep["questions"][0][:3]]
                same = by_q or same
                if len(same) > 1:
                    same = [c for c in same if c["rd"] == drep["rd"]] or same
            rq = same[0] if same else None
        if rq is None and dreqs:
            rq = dreqs[0]
        out.append((rq, drep))
    if rep_nodes:
        try:
            tree._pairs_cache = (key, out)
        except Exception:
            pass
    return out


def next_id(e):
    """ID of the first request of the exchange plus one (the second pipelined query's ID)."""
    for node in e.find_subtrees("<request_query>"):
        first = struct.unpack(">H", bytes(node)[:2])[0]
        return struct.pack(">H", (first + 1) & 0xFFFF)
    return b"\x00\x01"


def first_id(e):
    """ID of the first request of the exchange (the ID the second query of the pipelined pair reuses)."""
    for node in e.find_subtrees("<request_query>"):
        return bytes(node)[:2]
    return b"\x00\x00"


def exchange_of(r):
    node = r.parent
    while node is not None and not str(node.symbol).startswith("<exchange_"):
        node = node.parent
    return node


def exchange_requests(node, before=None):
    """The requests of an exchange (direct children, retries excluded) and the IDs of the replies that come before the node `before` in the exchange."""
    reqs = [n for n in node.children if str(n.symbol).startswith("<request_") and not str(n.symbol).startswith("<request_retry")]
    ids = set()
    stack = list(reversed(node.children))
    while stack:
        n = stack.pop()
        if n is before:
            break
        if str(n.symbol) == "<response>":
            ids.add(node_bytes(n)[:2])
        elif not str(n.symbol).startswith("<request_"):
            stack.extend(reversed(n.children))
    return reqs, ids


def exchange_replies(node, before):
    """The replies (bytes) of an exchange that come before the node `before`."""
    out = []
    stack = list(reversed(node.children))
    while stack:
        n = stack.pop()
        if n is before:
            break
        if str(n.symbol) == "<response>":
            out.append(message_bytes(n))
        elif not str(n.symbol).startswith("<request_"):
            stack.extend(reversed(n.children))
    return out


def retry_request(r):
    """The bytes of the request an exchange sends again after the server closed the connection (RFC 7766 6.2.4): the first request that no reply of the
    exchange answered (by ID)."""
    node = exchange_of(r)
    if node is None:
        return b""
    reqs, ids = exchange_requests(node, r)
    datas = [node_bytes(q) for q in reqs]
    if len({d[:2] for d in datas}) < len(datas):
        # the pipelined pair that reuses one ID: each reply before the retry answers one request of its ID and question
        left = list(range(len(datas)))
        for rep in exchange_replies(node, r):
            drep = decode(rep)
            for i in left:
                dq = decode(datas[i])
                if drep is not None and dq is not None and dq["id"] == drep["id"] and (
                        not drep["questions"] or (dq["questions"] and dq["questions"][0][:3] == drep["questions"][0][:3])):
                    left.remove(i)
                    break
        return datas[left[0]] if left else datas[0]
    for data in datas:
        if data[:2] not in ids:
            return data
    return datas[0] if datas else b""


def retry_second_request(r):
    """The second query of a pipelined pair, sent again together with the first."""
    node = exchange_of(r)
    if node is None:
        return b""
    reqs, ids = exchange_requests(node, r)
    return node_bytes(reqs[1]) if len(reqs) > 1 else b""


def previous_states(e):
    """The <state_idle> nodes whose first child is an exchange before e, nearest first (the state rule nests the exchanges)."""
    out = []
    node = e.parent
    while node is not None:
        if str(node.symbol) == "<state_idle>" and node.parent is not None and str(node.parent.symbol) == "<state_idle>":
            out.append(node.parent)
        node = node.parent
    return out


def exchange_key(tree):
    reqs, reps = message_nodes(tree)
    return tuple(id(n) for n in reqs + reps)


def exchange_done(e):
    """True once the state rule has derived the exchange after e: the messages of e never change again."""
    node = e.parent
    while node is not None and str(node.symbol) != "<state_idle>":
        node = node.parent
    return node is not None and len(node.children) > 1


def memo(e, name, compute):
    """Result of compute() for the exchange e, kept on the node while its messages stay the same (a complete exchange never changes)."""
    done = getattr(e, "_done", None)
    if done is not None and name in done:
        return done[name]
    if exchange_done(e):
        if done is None:
            done = {}
            try:
                e._done = done
            except Exception:
                return compute()
        if "_has_reply" not in done:
            done["_has_reply"] = bool(message_nodes(e)[1])
        if not done["_has_reply"] and name != "facts_now":
            done[name] = True   # (no reply in the exchange: nothing to judge)
        else:
            done[name] = compute()
        return done[name]
    reqs, reps = message_nodes(e)
    if not reps:
        # an exchange without a reply (the request Fandango is generating) has nothing to judge: every check that is memoized passes
        return compute() if name == "facts_now" else True
    key = tuple(id(n) for n in reqs + reps)
    cache = getattr(e, "_memo", None)
    if cache is None or cache[0] != key:
        cache = (key, {})
        try:
            e._memo = cache
        except Exception:
            return compute()
    if name not in cache[1]:
        cache[1][name] = compute()
    return cache[1][name]


def under(name, zone):
    """name is zone or a name below it (lower-cased dotted names, the root is b"")."""
    return zone == b"" or name == zone or name.endswith(b"." + zone)


def label_count(name):
    return len([x for x in name.split(b".") if x])


def wire_name(name):
    """Uncompressed wire form of a dotted byte-string name."""
    out = b""
    for label in name.split(b"."):
        if label:
            out += bytes([len(label)]) + label
    return out + b"\x00"


def rdata_names(rp, r):
    """The domain names inside the RDATA of an RR of a decoded reply."""
    t, msg, o, n = r["type"], rp["msg"], r["rdoff"], r["rdlen"]
    out = []
    if n == 0:
        return out
    if t in (2, 3, 4, 5, 7, 8, 9, 12, 47):
        d = decode_name(msg, o)
        if d:
            out.append(d[0])
    elif t == 15 and n >= 3:
        d = decode_name(msg, o + 2)
        if d:
            out.append(d[0])
    elif t in (6, 14):
        d = decode_name(msg, o)
        if d:
            out.append(d[0])
            d2 = decode_name(msg, d[1])
            if d2:
                out.append(d2[0])
    elif t == 46 and n >= 19:
        d = decode_name(msg, o + 18)
        if d:
            out.append(d[0])
    return out


class Facts:
    """What the replies of a session show about the server (the conditions of the requirements that depend on the implementation)."""

    def __init__(self):
        self.opt = False          # a reply carried an OPT: the responder implements EDNS (RFC 6891 7)
        self.no_edns = False      # a plain OPT query was answered FORMERR without OPT: it does not
        self.ra = False           # a reply had RA: the server offers recursion
        self.signers = set()      # zones shown signed (the signer names of RRSIG RRs)
        self.rrsig_seen = False   # an RRSIG RR was in a reply (a DS or DNSKEY RR alone, plain zone data, shows no security awareness)
        self.dnskeys = {}         # owner -> {key tag: ((flags, protocol, algorithm, RDATA), ...)}: the tag does not identify one key (RFC 4034 B)
        self.nsec_names = set()   # owner names and next domain names of the NSEC RRs of the replies
        self.types = {}           # owner -> RR types of authoritative data the replies showed there (wildcard expansions excluded)
        self.ds = {}              # owner -> {(key tag, algorithm, digest type, digest)}
        self.sigkeys = set()      # (signer, key tag, algorithm) of the RRSIG RRs
        self.nsec_pairs = set()   # (owner, next domain name) of the NSEC RRs
        self.nsec_maps = {}       # NSEC owner -> {type bit maps (frozensets)}
        self.datanames = set()    # owner names whose RRsets an RRSIG shows as not synthesized from a wildcard
        self.sigcover = set()     # (owner, covered type) of the RRSIG RRs
        self.nsec_owners = set()   # owners of the NSEC RRs of the replies (an NSEC exists only in a signed zone, also in a reply to a query without DO)
        self.maxlen = 0           # the length of the longest reply of the session: the responder's own size limit is at least that
        self.ds_signers = set()   # (owner, signer) of the RRSIG RRs over DS RRsets: the zone a DS lives in is its signer's
        self.addresses = {}       # name -> {address type: number of RRs of the RRset} of complete authoritative answers
        self.address_names = set()
        self.aliases = set()      # owners of CNAME RRs
        self.cuts = set()         # owners of the NS RRsets of referrals
        self.apexes = set()       # owners of SOA RRs of authoritative replies
        self.answered = set()       # names an authoritative NOERROR reply answered
        self.absent = set()       # names an authoritative reply answered NXDOMAIN
        self.nodata = {}          # name -> query types answered NODATA
        self.targets = set()      # target names of NS and MX RRs
        self.refused = set()      # names a non-authoritative REFUSED reply answered
        self.names = []           # every name the replies mention, in order
        self.nameset = set()

    def copy(self):
        f = Facts.__new__(Facts)
        for k, v in self.__dict__.items():
            if isinstance(v, (set, list)):
                v = v.copy()
            elif isinstance(v, dict):
                v = {a: (b.copy() if isinstance(b, (set, list, dict)) else b) for a, b in v.items()}
            f.__dict__[k] = v
        return f

    def note(self, name):
        if name not in self.nameset and len(self.names) < 400:
            self.nameset.add(name)
            self.names.append(name)

    def add(self, rq, rp):
        if rp is None:
            return
        msg = rp["msg"]
        aa = bool(rp["aa"]) and rp["opcode"] == 0
        if opt_of(rp):
            self.opt = True
        self.maxlen = max(self.maxlen, rp["len"])
        if rp["ra"]:
            self.ra = True
        authority = [r for r in rp["rrs"] if r["section"] == "ns"]
        if rq is not None and rq["opcode"] == 0 and len(rq["questions"]) == 1 and rq["questions"][0][1] != 252:
            qname, qtype, qclass = rq["questions"][0][:3]
            if (opt_of(rq) and rp["rcode"] == 1 and not opt_of(rp) and qclass == 1 and qtype < 128
                    and not any(((r["ttl"] >> 16) & 0xFF) != 0 for r in opt_of(rq))):
                self.no_edns = True
            if qclass == 1:
                if rp["rcode"] == 5 and not rp["aa"]:
                    self.refused.add(qname)
                if aa and not rp["tc"]:
                    if rp["rcode"] == 3 and rp["an"] == 0:
                        self.absent.add(qname)
                    elif rp["rcode"] == 0:
                        if rp["an"] > 0:
                            self.answered.add(qname)
                        elif any(r["type"] == 6 for r in authority):
                            self.answered.add(qname)
                            self.nodata.setdefault(qname, set()).add(qtype)
        acount = {}
        for r in rp["rrs"]:
            t = r["type"]
            if t == 41:
                continue
            self.note(r["name"])
            names = rdata_names(rp, r)
            for n in names:
                self.note(n)
            o = r["rdoff"]
            if t in (1, 28):
                self.address_names.add(r["name"])
                if aa and r["section"] == "an" and not rp["tc"]:
                    acount[(r["name"], t)] = acount.get((r["name"], t), 0) + 1
            elif t == 5:
                self.aliases.add(r["name"])
            elif t == 6:
                if aa:
                    self.apexes.add(r["name"])
            elif t in (2, 15):
                self.targets.update(names)
            if t == 47:
                self.nsec_owners.add(r["name"])
                self.nsec_names.update(n for n in names if n is not None)
                self.nsec_names.add(r["name"])
                if names and names[0] is not None:
                    self.nsec_pairs.add((r["name"], names[0]))
                    end = o + r["rdlen"]
                    after = uncompressed_name_end(msg, o, end)
                    bitmap = type_bitmap(msg, after, end) if after is not None else None
                    if bitmap is not None:
                        self.nsec_maps.setdefault(r["name"], set()).add(frozenset(bitmap))
                        if 2 in bitmap and 6 not in bitmap:
                            self.cuts.add(r["name"])   # RFC 4035 2.3: an NSEC at a name with an NS RRset and no SOA shows a delegation
            if t == 46 and r["rdlen"] >= 19:
                self.rrsig_seen = True
                if names and names[0] is not None:   # (the signer of a signed root zone is the root, b"")
                    self.signers.add(names[0])
                    self.sigkeys.add((names[0], struct.unpack(">H", msg[o + 16:o + 18])[0], msg[o + 2]))
                    covered_type = struct.unpack(">H", msg[o:o + 2])[0]
                    self.sigcover.add((r["name"], covered_type))
                    if covered_type == 43:
                        self.ds_signers.add((r["name"], names[0]))
                    owner_labels = labels_of(r["name"])
                    if owner_labels[:1] == [b"*"]:
                        owner_labels = owner_labels[1:]
                    if covered_type not in (46, 47) and msg[o + 3] == len(owner_labels):
                        self.datanames.add(r["name"])
            elif t == 48 and r["rdlen"] >= 4 and struct.unpack(">H", msg[o:o + 2])[0] & 0x0100:
                # a DNSKEY with the Zone Key bit set holds a zone key and its owner is the name of a signed zone
                # (RFC 4034 2.1.1, RFC 4035 2.1); a DNSKEY without that bit (e.g. a SIG(0) key) shows nothing
                self.signers.add(r["name"])
            if t == 48 and r["rdlen"] >= 4 and not rp["tc"]:
                rdata = msg[o:o + r["rdlen"]]
                flags, proto, alg = struct.unpack(">HBB", rdata[:4])
                by_tag = self.dnskeys.setdefault(r["name"], {})
                tag = key_tag(rdata)
                if (flags, proto, alg, rdata) not in by_tag.get(tag, ()):
                    by_tag[tag] = by_tag.get(tag, ()) + ((flags, proto, alg, rdata),)
            elif t == 43 and r["rdlen"] >= 4 and not rp["tc"]:
                tag, alg, dtype = struct.unpack(">HBB", msg[o:o + 4])
                self.ds.setdefault(r["name"], set()).add((tag, alg, dtype, msg[o + 4:o + r["rdlen"]]))
                self.cuts.add(r["name"])   # RFC 4035 2.4: a DS RRset appears only at the parent side of a zone cut
        for key, n in acount.items():
            by_type = self.addresses.setdefault(key[0], {})
            by_type[key[1]] = max(by_type.get(key[1], 0), n)
        if (not rp["aa"] and rp["rcode"] == 0 and rp["an"] == 0 and rp["opcode"] == 0
                and not any(r["type"] == 6 for r in authority)):
            for r in authority:
                if r["type"] == 2:
                    self.cuts.add(r["name"])
        if rp["opcode"] == 0 and rp["rcode"] == 0 and not rp["tc"]:
            referral = not rp["aa"] and rp["an"] == 0 and any(r["type"] == 2 for r in authority)
            expanded = set()
            for x in rrsigs_of(rp):
                owner_labels = labels_of(x[1])
                if x[4] < len(owner_labels) - (1 if owner_labels[:1] == [b"*"] else 0):
                    expanded.add(x[1])
            for r in rp["rrs"]:
                if r["type"] != 41 and r["name"] not in expanded and (
                        (aa and r["section"] in ("an", "ns")) or (referral and r["section"] == "ns")):
                    self.types.setdefault(r["name"], set()).add(r["type"])


def session_state(e):
    """(pairs, Facts) of the exchanges before e in the session, built once per state node."""
    chain = previous_states(e)
    start = len(chain)
    acc = ()
    facts = None
    for i, st in enumerate(chain):
        c = getattr(st, "_hist", None)
        if c is not None and c[0] == exchange_key(st.children[0]):
            acc, facts, start = c[1], c[2], i
            break
    if facts is None:
        facts = Facts()
    for st in reversed(chain[:start]):
        prev = st.children[0]
        new = tuple((rq, rp) for rq, rp in pairs(prev) if rp is not None)
        facts = facts.copy()
        for rq, rp in new:
            facts.add(rq, rp)
        acc = acc + new
        try:
            st._hist = (exchange_key(prev), acc, facts)
        except Exception:
            pass
    return acc, facts


def facts_now(e):
    """The facts of the session before e plus the replies of e itself."""
    def compute():
        f = session_state(e)[1].copy()
        for rq, rp in pairs(e):
            f.add(rq, rp)
        return f
    return memo(e, "facts_now", compute)


def follow_name(e):
    """Wire form of the QNAME of a dependent request: a name an earlier reply of the session named (owner names, targets of
    CNAME / NS / MX / PTR / SOA records, next domain names); a name of the setup lists while no reply named any."""
    hist, facts = session_state(e)
    nodes = list(e.find_subtrees("<request_follow>"))
    ident = int.from_bytes(bytes(nodes[0])[:2], "big") if nodes else 0   # the request's random ID: the same value whenever the constraint is evaluated
    rng = random.Random(ident * 7919 + len(hist))
    if facts.names and rng.random() < 0.9:
        name = rng.choice(facts.names)
    else:
        name = rng.choice(NAMES_PRESENT + NAMES_ABSENT).lower().rstrip(".").encode("latin1")
    if rng.random() < 0.3:
        name = bytes(c ^ 0x20 if 65 <= (c & 0xDF) <= 90 and rng.random() < 0.5 else c for c in name)
    return wire_name(name)


# ============================================================================================================
# 3. PARTY CLASS -- the driver builds Client and Server from this class when it exists (RFC 1035 4.2)
# ============================================================================================================
class ClientNetworkParty(NetworkParty):
    """UDP: one datagram is one DNS message (the receive buffer is widened to the largest message).
    TCP (RFC 1035 4.2.2, RFC 7766): every message is prefixed with its two-octet length; the stream is cut into
    messages here, so the grammar sees exactly one DNS message per received message.  A server may close a TCP
    connection at any time (RFC 7766 6.2.3, RFC 5936 2.3); the client then reconnects before its next message
    (RFC 7766 6.2.4: queries are retried on a new connection)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stream = b""
        self._closed = False
        self._outstanding = 0    # requests sent minus messages of the server received (a pipelined pair has two outstanding)
        self._reopen_lock = threading.Lock()   # the reconnect thread and send never close and open the connection at the same time
        self.protocol_impl._buffer_size = 65535

    def send(self, message, recipient):
        data = message.to_bytes() if hasattr(message, "to_bytes") else bytes(message)
        if TRANSPORT == "udp" and is_axfr_query(data):
            # RFC 5936 4.2: AXFR sessions over UDP are not defined; the datagram is not transmitted
            return
        if TRANSPORT == "tcp":
            with self._reopen_lock:
                # a reset (BIND answers a message with QR set that way) ends the receive thread without telling the party: the connection is
                # dead, as after a close, and the next message goes out on a new one (RFC 7766 6.2.4)
                if self._closed or not getattr(self.protocol_impl, "_running", True):
                    self.stop()
                    self._stream = b""
                    self._outstanding = 0
                    self._closed = False
                    self.start()
            data = struct.pack(">H", len(data)) + data
        # (counted before the datagram or segment leaves: the reply may be received before send returns)
        self._outstanding += 1
        try:
            super().send(data, recipient)
        except BaseException:
            self._outstanding = max(0, self._outstanding - 1)
            raise

    def reconnect(self):
        time.sleep(0.05)
        with self._reopen_lock:
            if not self._closed:
                return   # (send opened the connection again meanwhile)
            try:
                self.stop()
                self._stream = b""
                self._closed = False
                self.start()
            except Exception:
                self._closed = True

    def receive(self, message, sender):
        if message is None:
            # the server closed the connection: nothing to parse; the party reconnects (a send on a failed
            # reconnect tries again)
            self._closed = True
            if TRANSPORT == "tcp":
                if self._outstanding > 0:
                    # RFC 7766 6.2.4: the connection closed before every outstanding query was answered (one of two pipelined queries
                    # included): the close is handed over as a message of the server (<conn_closed>); the client then sends the
                    # unanswered query again, which reconnects (see send)
                    self._outstanding = 0
                    super().receive(CLOSE_MARK + END_MARK, None)
                else:
                    threading.Thread(target=self.reconnect, daemon=True).start()
            return
        if TRANSPORT != "tcp":
            self._outstanding = max(0, self._outstanding - 1)
            # RFC 2181 4.1: a UDP reply comes from the address the query went to; a datagram from another source is
            # handed over as the message of an unexpected party, which Fandango reports as a violation
            addr = self.protocol_impl.current_remote_addr
            if addr is not None and (addr[0], addr[1]) != (self.ip, self.port):
                super().receive(bytes(message) + END_MARK, "WrongSource")
                return
            super().receive(bytes(message) + END_MARK, sender)
            return
        self._stream += message
        while len(self._stream) >= 2:
            length = struct.unpack(">H", self._stream[:2])[0]
            if len(self._stream) < 2 + length:
                break
            one = self._stream[2:2 + length]
            self._stream = self._stream[2 + length:]
            self._outstanding = max(0, self._outstanding - 1)
            super().receive(one + END_MARK, sender)


# ============================================================================================================
# 4. STATES AND EXCHANGES
# ============================================================================================================
# DNS has no connection state of its own: after the transport is up every message pair is independent (RFC 1035
# 4.2.1/4.2.2; RFC 7766 6.2.1 allows several queries on one TCP connection).  The one protocol state is "idle":
# a client may send any request, the server replies, and the state is idle again.
<start> ::= <state_idle>

# RFC 1035 4.2: a session is a sequence of exchanges; every exchange leads back to the state it started in
# TODO: RFC 7766 6.2.2 (limits on concurrent connections), nearest <state_idle>: needs a second connection at the same time
# TODO: RFC 7766 6.2.3 (idle timeouts), nearest <state_idle>: needs the time between messages, which only timers measure
# TODO: RFC 7766 9 / RFC 7413 (TCP Fast Open), nearest <state_idle>: a TCP option of a specification the manifest leaves out
# TODO: RFC 1034 4.3.5 / RFC 1982 (zone refresh, serial arithmetic, expiry), nearest <state_idle>: a secondary server's timed exchange with its primary (third party)
# TODO: RFC 1034 5.3 / RFC 2308 5-7 / RFC 4035 4-5 (resolver algorithm, caching, validation), nearest <state_idle>: the implementation's exchange with third-party servers
<state_idle> ::= <exchange> <state_idle>?

# every request kind has an exchange of its own; the reply is the shared <response> (any RCODE, errors included)
<exchange> ::= (<exchange_query> | <exchange_query_edns> | <exchange_query_other> | <exchange_iquery> | <exchange_status> |
              <exchange_qdcount_zero> | <exchange_bad_version> | <exchange_two_opt> | <exchange_opt_owner> | <exchange_qdcount_many> |
              <exchange_pipelined> | <exchange_pipelined_same_id> | <exchange_z_set> | <exchange_axfr> |
              <exchange_axfr_z_set> | <exchange_axfr_qr_set> | <exchange_axfr_opcode> | <exchange_axfr_rcode> | <exchange_axfr_qdcount_zero> |
              <exchange_axfr_qdcount_two> | <exchange_axfr_ancount> | <exchange_axfr_nscount> | <exchange_axfr_arcount> | <exchange_follow>)

# RFC 1035 4.1.1 QUERY (opcode 0), RFC 1035 3.2.2 TYPE, 3.2.4 CLASS, RFC 4343 case
<exchange_query> ::= <Client:request_query> <answer>
# RFC 6891 6.1 an OPT pseudo-RR (EDNS(0)) in the additional section of a query, DO bit RFC 3225 3
<exchange_query_edns> ::= <Client:request_query_edns> <answer>
# RFC 1035 3.2.4 / 4.1.1: a question of a class other than IN (CS, CH, HS, *, unassigned).  RFC 1034 / RFC 1035 oblige no server to answer
# such a query (it may refuse by RCODE Refused, but the specification does not require any reply: BIND stays silent on some of them), so
# the silence is accepted with a timer.  The timer starts before the request, runs SILENCE_SECONDS and is cancelled by the reply.
<exchange_query_other> ::= <TimerControl:query_other_start> (<Client:request_query_other> | <Client:request_query_other_edns>) <query_other_reply>
<query_other_reply> ::= <query_other_reply_end> | <Server:conn_closed> <TimerControl:query_other_cancel> <TimerControl:query_other_start> <Client:request_retry_query_other> <query_other_reply_end>
<query_other_reply_end> ::= <Server:response> <TimerControl:query_other_cancel> | <TimerEvent:query_other_expired> <Server:response>? | <Server:conn_closed> <TimerControl:query_other_cancel>
# RFC 3425 3: inverse queries are obsolete; servers SHOULD answer Not Implemented (RFC 1035 4.1.1 IQUERY)
<exchange_iquery> ::= <TimerControl:iquery_start> <Client:request_iquery> <iquery_reply>
<iquery_reply> ::= <iquery_reply_end> | <Server:conn_closed> <TimerControl:iquery_cancel> <TimerControl:iquery_start> <Client:request_retry_iquery> <iquery_reply_end>
<iquery_reply_end> ::= <Server:response> <TimerControl:iquery_cancel> | <TimerEvent:iquery_expired> <Server:response>? | <Server:conn_closed> <TimerControl:iquery_cancel>
# RFC 1035 4.1.1 STATUS (opcode 2): a server status request; the spec defines no reply
<exchange_status> ::= <TimerControl:status_start> <Client:request_status> <status_reply>
<status_reply> ::= <status_reply_end> | <Server:conn_closed> <TimerControl:status_cancel> <TimerControl:status_start> <Client:request_retry_status> <status_reply_end>
<status_reply_end> ::= <Server:response> <TimerControl:status_cancel> | <TimerEvent:status_expired> <Server:response>? | <Server:conn_closed> <TimerControl:status_cancel>
# RFC 9619 4: QDCOUNT = 0 with OPCODE 0 is not malformed per se; the reply is not constrained
<exchange_qdcount_zero> ::= <TimerControl:qdcount_zero_start> <Client:request_qdcount_zero> <qdcount_zero_reply>
<qdcount_zero_reply> ::= <qdcount_zero_reply_end> | <Server:conn_closed> <TimerControl:qdcount_zero_cancel> <TimerControl:qdcount_zero_start> <Client:request_retry_qdcount_zero> <qdcount_zero_reply_end>
<qdcount_zero_reply_end> ::= <Server:response> <TimerControl:qdcount_zero_cancel> | <TimerEvent:qdcount_zero_expired> <Server:response>? | <Server:conn_closed> <TimerControl:qdcount_zero_cancel>
# RFC 9619 4: OPCODE 0 with QDCOUNT > 1 "MUST be treated as an incorrectly formatted message"; the response's RCODE "MUST be set to 1 (FORMERR)"
# The specification obliges no server to answer (it defines the RCODE of a response that is sent), so the silence is accepted with a timer like that of QDCOUNT 0.
<exchange_qdcount_many> ::= <TimerControl:qdcount_many_start> <Client:request_qdcount_many> <qdcount_many_reply>
<qdcount_many_reply> ::= <qdcount_many_reply_end> | <Server:conn_closed> <TimerControl:qdcount_many_cancel> <TimerControl:qdcount_many_start> <Client:request_retry_qdcount_many> <qdcount_many_reply_end>
<qdcount_many_reply_end> ::= <Server:response> <TimerControl:qdcount_many_cancel> | <TimerEvent:qdcount_many_expired> <Server:response>? | <Server:conn_closed> <TimerControl:qdcount_many_cancel>
# RFC 6891 6.1.1: "If a query message with more than one OPT RR is received, a FORMERR (RCODE=1) MUST be returned"; RFC 6891 7: a responder
# without EDNS support also answers FORMERR to any OPT, so no property needs to be shown first: `formerr_reply`
<exchange_two_opt> ::= <Client:request_two_opt> <answer>
# RFC 6891 6.1.2: the NAME of an OPT RR "MUST be 0 (root domain)"; the specification defines no reaction to another name, so every reply is accepted
<exchange_opt_owner> ::= <Client:request_opt_owner> <answer>
# TODO: RFC 9619 4 / RFC 6891 6.1.1 requests with more than two questions or more than two OPT RRs, nearest <exchange_qdcount_many> / <exchange_two_opt>: the same rule, the same FORMERR
# RFC 1035 4.1.1: Z "Must be zero in all queries"; the specification defines no reaction to a query that sets it, so every reply is accepted
<exchange_z_set> ::= <Client:request_z_set> <answer>
# RFC 6891 6.1.3: an unimplemented EDNS VERSION MUST be answered with BADVERS
<exchange_bad_version> ::= <Client:request_bad_version> <answer>

# A reply that arrives after the timer expired (Fandango processes a message only after it has generated and sent the next planned message: a slow
# request is sent late, and the expiry that came first is parsed after it) is accepted behind the expiry: `<TimerEvent:x_expired> <Server:response>?`
# Timers: only for requests whose reply the specification does not require (IQUERY: SHOULD answer NOTIMP, RFC 3425 3;
# STATUS and QDCOUNT = 0: no reply is defined).  Each timer has its own id and runs SILENCE_SECONDS.
<iquery_start> ::= <timer_start>
<iquery_cancel> ::= <timer_cancel>
<iquery_expired> ::= <timer_expired>
<status_start> ::= <timer_start>
<status_cancel> ::= <timer_cancel>
<status_expired> ::= <timer_expired>
<query_other_start> ::= <timer_start>
<query_other_cancel> ::= <timer_cancel>
<query_other_expired> ::= <timer_expired>
<qdcount_many_start> ::= <timer_start>
<qdcount_many_cancel> ::= <timer_cancel>
<qdcount_many_expired> ::= <timer_expired>
<qdcount_zero_start> ::= <timer_start>
<qdcount_zero_cancel> ::= <timer_cancel>
<qdcount_zero_expired> ::= <timer_expired>
where forall <t> in <iquery_start>: str(<t>..<timer_id>) == "1" and str(<t>..<timer_timeout>) == str(SILENCE_SECONDS)
where forall <t> in <iquery_cancel>: str(<t>..<timer_id>) == "1"
where forall <t> in <iquery_expired>: str(<t>..<timer_id>) == "1"
where forall <t> in <status_start>: str(<t>..<timer_id>) == "2" and str(<t>..<timer_timeout>) == str(SILENCE_SECONDS)
where forall <t> in <status_cancel>: str(<t>..<timer_id>) == "2"
where forall <t> in <status_expired>: str(<t>..<timer_id>) == "2"
where forall <t> in <query_other_start>: str(<t>..<timer_id>) == "5" and str(<t>..<timer_timeout>) == str(AXFR_SECONDS)
where forall <t> in <query_other_cancel>: str(<t>..<timer_id>) == "5"
where forall <t> in <query_other_expired>: str(<t>..<timer_id>) == "5"
where forall <t> in <qdcount_many_start>: str(<t>..<timer_id>) == "6" and str(<t>..<timer_timeout>) == str(SILENCE_SECONDS)
where forall <t> in <qdcount_many_cancel>: str(<t>..<timer_id>) == "6"
where forall <t> in <qdcount_many_expired>: str(<t>..<timer_id>) == "6"
where forall <t> in <qdcount_zero_start>: str(<t>..<timer_id>) == "3" and str(<t>..<timer_timeout>) == str(SILENCE_SECONDS)
where forall <t> in <qdcount_zero_cancel>: str(<t>..<timer_id>) == "3"
where forall <t> in <qdcount_zero_expired>: str(<t>..<timer_id>) == "3"

# RFC 1034 3.7 / RFC 1035 3.3: a name an earlier reply of the session named (an owner name, a CNAME / NS / MX / PTR target, an SOA
# name, a next domain name) is queried next; the QNAME is the name of the first request's question taken from those replies
# (follow_name; the setup lists when no reply named anything yet)
<exchange_follow> ::= <Client:request_follow> <answer>

# RFC 7766 6.2.4: "DNS clients SHOULD retry unanswered queries if the connection closes before receiving all outstanding responses" (the server may
# close the connection at any time).  The party class hands the close of the TCP connection over, while a request is unanswered, as the message
# <conn_closed> of the server; the client then sends the unanswered request again (on a new connection, which the party class opens): the retry is
# the request of the exchange once more (`where` equality below); a second close ends the exchange (no specific retry algorithm is specified).
# The retry of the exchanges with a timer (IQUERY, STATUS, QDCOUNT 0, other classes, AXFR) runs the same timer again.
<answer> ::= <Server:response> | <Server:conn_closed> <Client:request_retry> <answer_end>
<answer_end> ::= <Server:response> | <Server:conn_closed>
<conn_closed> ::= <close_mark> <message_end>
<close_mark> ::= b'\xfe\xfe\xfe\xfe'
<request_retry> ::= <request_query> | <request_query_edns> | <request_bad_version> | <request_two_opt> | <request_opt_owner> | <request_z_set>
<request_retry_second> ::= <request_query_second>
# the exchanges with a timer (their reply is not required) send the unanswered request again with the same timer
<request_retry_iquery> ::= <request_iquery>
<request_retry_status> ::= <request_status>
<request_retry_qdcount_zero> ::= <request_qdcount_zero>
<request_retry_qdcount_many> ::= <request_qdcount_many>
<request_retry_query_other> ::= <request_query_other> | <request_query_other_edns>
<request_retry_axfr> ::= <request_axfr> | <request_axfr_edns> | <request_axfr_z_set>
<request_retry_axfr_other> ::= <request_axfr_qr_set> | <request_axfr_rcode> | <request_axfr_ancount> | <request_axfr_nscount> | <request_axfr_arcount> | <request_axfr_opcode> | <request_axfr_qdcount_zero> | <request_axfr_qdcount_two>

# RFC 7766 6.2.1.1: two queries sent back to back on one TCP connection, the replies in either order (RFC 7766 7)
# TODO: RFC 7766 6.2.1.1 more than two outstanding queries, nearest <exchange_pipelined>: two cover reordering; more add no new rule
<exchange_pipelined> ::= <Client:request_query> <Client:request_query_second> <pipelined_replies>
# the replies in either order; the connection may close at any point (RFC 7766 6.2.4): before any reply (both queries are sent again), after one reply
# (the unanswered query is sent again), or before the second query was sent (that one is sent on the new connection, its reply comes, then the first is sent again)
<pipelined_replies> ::= <Server:response> <Server:response> | <Server:response> <Server:conn_closed> <Client:request_retry> <answer_end> | <Server:conn_closed> <pipelined_closed>
<pipelined_closed> ::= <Server:response> <Client:request_retry> <answer_end> | <Client:request_retry> <Client:request_retry_second> <pipelined_end> | <Server:conn_closed>
<pipelined_end> ::= <Server:response> <Server:response> | <Server:response> <Server:conn_closed> | <Server:conn_closed>
# RFC 7766 6.2.1: "clients MUST NOT reuse the DNS Message ID of an in-flight query on that connection": the same two queries, but the second one reuses the
# ID of the outstanding first query.  The specification defines no reaction to the reuse (a server may answer both, one or close the connection), so every
# reply (the replies of <pipelined_replies>) is accepted, and the session goes on in <state_idle>.  Replies of one ID are told apart by their question.
<exchange_pipelined_same_id> ::= <Client:request_query> <Client:request_query_second_same_id> <pipelined_replies>
# RFC 5936 2: zone transfer, over TCP only (RFC 5936 4.2); the reply is a series of messages
<exchange_axfr> ::= <TimerControl:axfr_start> (<Client:request_axfr> | <Client:request_axfr_edns>) <axfr_answer>
# RFC 5936 2.3: the server may close the connection without a response; over UDP the exchange always ends this way
# because the party class does not transmit an AXFR query over UDP (RFC 5936 4.2: AXFR sessions over UDP are not defined)
<axfr_answer> ::= <axfr_reply> | <Server:conn_closed> <TimerControl:axfr_cancel> <TimerControl:axfr_start> <Client:request_retry_axfr> <axfr_reply>
<axfr_reply> ::= <Server:response_axfr_whole> <TimerControl:axfr_cancel> | <Server:response_axfr_first> <axfr_rest> | <Server:response_axfr_error> <TimerControl:axfr_cancel> | <TimerEvent:axfr_expired> | <Server:conn_closed> <TimerControl:axfr_cancel>
# RFC 5936 2.2 / 2.3: after the first message more messages follow, the last one or an error message ends the transfer, or the
# connection is closed at any point (no message follows: the timer expires)
<axfr_rest> ::= <Server:response_axfr_next> <axfr_rest> | <Server:response_axfr_last> <TimerControl:axfr_cancel> | <Server:response_axfr_error> <TimerControl:axfr_cancel> | <TimerEvent:axfr_expired>
# RFC 5936 2.1.1: the AXFR queries that break one MUST of the header values, each in an exchange of its own.  The session goes on in <state_idle>.
# Only Z has a reaction the specification defines (the server MUST ignore it: the transfer follows, <axfr_answer>).  For QR, OPCODE, RCODE, the counts and an ARCOUNT without
# RR it defines none, so every reply is accepted (<axfr_other_answer>): the transfer of a server that ignores the violation (one message or several), a refusal such as
# NOTIMP or FORMERR with or without the question, any other message, silence or the close.
# Z "mbz": the client MUST set the bit to 0 (the server MUST ignore it)
<exchange_axfr_z_set> ::= <TimerControl:axfr_start> <Client:request_axfr_z_set> <axfr_answer>
# QR "MUST be 0": the query with QR = 1 (a response, which a server does not answer)
<exchange_axfr_qr_set> ::= <TimerControl:axfr_start> <Client:request_axfr_qr_set> <axfr_other_answer>
# RCODE "MUST be 0"
<exchange_axfr_rcode> ::= <TimerControl:axfr_start> <Client:request_axfr_rcode> <axfr_other_answer>
# ANCOUNT "MUST be 0" (one answer RR) and NSCOUNT "MUST be 0" (one authority RR)
<exchange_axfr_ancount> ::= <TimerControl:axfr_start> <Client:request_axfr_ancount> <axfr_other_answer>
<exchange_axfr_nscount> ::= <TimerControl:axfr_start> <Client:request_axfr_nscount> <axfr_other_answer>
# ARCOUNT "MUST" be "the number of resource records it places into the Additional section": ARCOUNT 1 without an RR
<exchange_axfr_arcount> ::= <TimerControl:axfr_start> <Client:request_axfr_arcount> <axfr_other_answer>
# OPCODE "MUST be 0": the AXFR question in an IQUERY or a STATUS message
<exchange_axfr_opcode> ::= <TimerControl:axfr_start> <Client:request_axfr_opcode> <axfr_other_answer>
# QDCOUNT "MUST be 1": no question, or two questions (RFC 9619 4: OPCODE 0 and QDCOUNT > 1 is answered with FORMERR if answered)
<exchange_axfr_qdcount_zero> ::= <TimerControl:axfr_start> <Client:request_axfr_qdcount_zero> <axfr_other_answer>
<exchange_axfr_qdcount_two> ::= <TimerControl:axfr_start> <Client:request_axfr_qdcount_two> <axfr_other_answer>
<axfr_other_answer> ::= <axfr_other_reply> | <Server:conn_closed> <TimerControl:axfr_cancel> <TimerControl:axfr_start> <Client:request_retry_axfr_other> <axfr_other_reply>
<axfr_other_reply> ::= <Server:response> <axfr_other_more> | <TimerEvent:axfr_expired> <Server:response>? | <Server:conn_closed> <TimerControl:axfr_cancel>
# a server that ignores the violation sends the transfer, which may be several messages (RFC 5936 2.2): any message may follow until the timer is cancelled
<axfr_other_more> ::= <TimerControl:axfr_cancel> | <Server:response> <axfr_other_more> | <Server:conn_closed> <TimerControl:axfr_cancel>
<axfr_start> ::= <timer_start>
<axfr_cancel> ::= <timer_cancel>
<axfr_expired> ::= <timer_expired>
where forall <t> in <axfr_start>: str(<t>..<timer_id>) == "4" and str(<t>..<timer_timeout>) == str(AXFR_START_SECONDS)
where forall <t> in <axfr_cancel>: str(<t>..<timer_id>) == "4"
where forall <t> in <axfr_expired>: str(<t>..<timer_id>) == "4"


# ============================================================================================================
# 5. REQUESTS -- RFC 1035 4.1: header (4.1.1), question (4.1.2); counts and flags come from the shared fields below
# ============================================================================================================
# the header of every query: QR=0, AA/TC/RA/Z=0 (valid in responses only; Z "must be zero in all queries")
<req_flags_query> ::= <flags_hi_query> <flags_lo_request>

# RFC 1035 4.1.1: the query that breaks the MUST of Z = 0 (the one bit of Z that RFC 4035 leaves: AD and CD are defined, RFC 4035 3.1.6 / 3.2.2), see <exchange_z_set>
<request_z_set> ::= <h_id> <flags_hi_query> <flags_lo_z_set> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_in>
# RFC 1035 4.1.1: standard query with one question
<request_query> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_in>
# the same with a class other than IN (answered or not: see <exchange_query_other>)
<request_query_other> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_other>
<request_query_other_edns> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <arcount_one> <question_other> <rr_opt_request>
# the dependent request: the same header and a question whose QNAME is taken from the earlier replies of the session
<request_follow> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_follow>
<question_follow> ::= <qname_follow> <qtype_sent> <qclass_in>
<qname_follow> ::= <name>
# RFC 6891 6.1.1: the same plus one OPT RR (the only RR a query carries in the additional section)
<request_query_edns> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <arcount_one> <question_in> <rr_opt_request>
# RFC 7766 6.2.1: the second pipelined query must not reuse the ID of the outstanding first one (ID + 1)
<request_query_second> ::= <h_id_second> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_in>
<h_id_second> ::= rb'[\x00-\xff]{2}'
# RFC 7766 6.2.1: the breaking query: the second one with the ID of the first (equality below)
<request_query_second_same_id> ::= <h_id_same> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_in>
<h_id_same> ::= rb'[\x00-\xff]{2}'
# RFC 5936 2.1: AXFR query: ID, QR=0, OPCODE=0, AA..CD "n/a" (RD recommended zero), Z=0, RCODE=0, QDCOUNT=1, ANCOUNT=0,
# NSCOUNT=0, ARCOUNT=0 (no OPT/TSIG), question = zone name, AXFR, class
# TODO: RFC 5936 2.1.5 / 2.2.5 TSIG and SIG(0) in AXFR queries, nearest <request_axfr_edns>: transaction security is the extension (RFC 8945) the manifest leaves out; RFC 5936 2.1.1 ARCOUNT 2 likewise
# TODO: RFC 5936 4.1.1 concurrent AXFR sessions on one connection, nearest <exchange_axfr>: needs interleaved replies of two transfers; sequential sessions are modeled by <state_idle>
<request_axfr> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_axfr>
# RFC 5936 2.1.5: the client MAY include one OPT RR (ARCOUNT 1)
<request_axfr_edns> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <qdcount_one> <count_zero> <count_zero> <arcount_one> <question_axfr> <rr_opt_request>
# RFC 5936 2.1.1: AA, TC, RD, RA, AD and CD are "n/a" in the query (the client RECOMMENDED to send zero, the server ignores them); Z is zero
<flags_hi_axfr_query> ::= rb'[\x00-\x07]'
<flags_lo_axfr_query> ::= rb'[\x00\x10\x20\x30\x80\x90\xa0\xb0]'
<question_axfr> ::= <qname_zone> <type_axfr> <qclass_axfr>
# RFC 5936 2.1.1: the AXFR queries that break one MUST of the header (see <exchange_axfr_z_set>); the other fields are those of <request_axfr>
<request_axfr_z_set> ::= <h_id> <flags_hi_axfr_query> <flags_lo_z_set> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_axfr>
<request_axfr_qr_set> ::= <h_id> <flags_hi_axfr_qr> <flags_lo_axfr_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_axfr>
<request_axfr_rcode> ::= <h_id> <flags_hi_axfr_query> <flags_lo_error> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_axfr>
<request_axfr_ancount> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <qdcount_one> <count_one> <count_zero> <count_zero> <question_axfr> <rr_iquery>
<request_axfr_nscount> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <qdcount_one> <count_zero> <count_one> <count_zero> <question_axfr> <rr_iquery>
<request_axfr_arcount> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <qdcount_one> <count_zero> <count_zero> <arcount_one> <question_axfr>
<request_axfr_opcode> ::= <h_id> <flags_hi_axfr_opcode> <flags_lo_axfr_query> <qdcount_one> <count_zero> <count_zero> <count_zero> <question_axfr>
<request_axfr_qdcount_zero> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <count_zero> <count_zero> <count_zero> <count_zero>
<request_axfr_qdcount_two> ::= <h_id> <flags_hi_axfr_query> <flags_lo_axfr_query> <count_two> <count_zero> <count_zero> <count_zero> <question_axfr> <question_axfr>
# QR = 1 (the other bits of the octet as in <flags_hi_axfr_query>); OPCODE IQUERY or STATUS (the shared <flags_hi_iquery>, <flags_hi_status>)
# TODO: RFC 1035 4.1.1 reserved OPCODEs 3-15 in the AXFR query, nearest <flags_hi_axfr_opcode>: no message is defined for them (4 NOTIFY and 5 UPDATE belong to extensions the manifest leaves out)
<flags_hi_axfr_qr> ::= rb'[\x80-\x87]'
<flags_hi_axfr_opcode> ::= <flags_hi_iquery> | <flags_hi_status>
# RFC 5936 2.1.2: the class of the zone requested
<qclass_axfr> ::= <qclass_sent>
# the zone name: one of the zones of the setup, or a name that is no zone (REFUSED / NOTAUTH expected)
<qname_zone> ::= <name> := wire(<zone_text>)
<zone_text> ::= (<text_label> '.')+ := pick_zone()
# RFC 3425 3 / RFC 1035 4.1.1: IQUERY carries no question and (RFC 1035 6.4) one answer RR
<request_iquery> ::= <h_id> <flags_hi_iquery> <flags_lo_request> <count_zero> <count_one> <count_zero> <count_zero> <rr_iquery>
# RFC 1035 4.1.1: STATUS carries no question
<request_status> ::= <h_id> <flags_hi_status> <flags_lo_request> <count_zero> <count_zero> <count_zero> <count_zero>
# RFC 9619 4: QDCOUNT = 0 (OPCODE 0)
<request_qdcount_zero> ::= <h_id> <req_flags_query> <count_zero> <count_zero> <count_zero> <count_zero>
# RFC 6891 6.1.3: OPT with a VERSION other than 0
<request_bad_version> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <arcount_one> <question_in> <rr_opt_bad_version>

# the requests that break a MUST of the sender, each in an exchange of its own: QDCOUNT 2 with two questions, two OPT RRs (ARCOUNT 2), an OPT RR whose
# owner is not the root
<request_qdcount_many> ::= <h_id> <req_flags_query> <count_two> <count_zero> <count_zero> <count_zero> <question_in> <question_in>
<request_two_opt> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <count_two> <question_in> <rr_opt_request> <rr_opt_request>
# TODO: RFC 6891 6.1.2 a non-root OPT owner combined with DO, a VERSION other than 0, an extended RCODE or options, nearest <rr_opt_owner>: the NAME is the one field that breaks the MUST;
# the specification defines no reaction, and the other fields keep their reply rules (a DO bit or a VERSION the server may or may not honour would make them depend on how it reads the RR)
<request_opt_owner> ::= <h_id> <req_flags_query> <qdcount_one> <count_zero> <count_zero> <arcount_one> <question_in> <rr_opt_owner>
<rr_opt_owner> ::= <opt_owner> <type_opt> <opt_udp_size_sent> <opt_ext_rcode_zero> <opt_version_zero> <opt_flags_do_clear> <opt_rdata_request>
<opt_owner> ::= <label> <root>
# RFC 6891 6.1.2: the OPT RR of a request: root owner name, TYPE 41, CLASS = requestor's UDP payload size, TTL =
# extended RCODE (0 in requests), VERSION 0, DO, Z (zero), RDATA = options
<rr_opt_request> ::= <root> <type_opt> <opt_udp_size_sent> <opt_ext_rcode_sent> <opt_version_zero> <opt_flags_sent> <opt_rdata_request>
<rr_opt_bad_version> ::= <root> <type_opt> <opt_udp_size_sent> <opt_ext_rcode_sent> <opt_version_other> <opt_flags_sent> <opt_rdata_request>
# the RR of the answer section of an IQUERY (RFC 1035 6.4.1: the answer holds the RR whose owner is sought; any type, an MX RR is the example).
# QDCOUNT is 0, so the owner name is the first name of the message (offset 12) and the names inside the RDATA of the other types are
# compression pointers to it (RFC 1035 4.1.4: a pointer alone, or labels ending in a pointer); RDLENGTH is part of each alternative
# (the IQUERY timer starts before the request is generated, so no length equality is solved).  The TTL is a 31-bit value (RFC 2181 8).
# TODO: RFC 1035 4.1.4 pointers to other offsets and names with more labels before the pointer, nearest <rr_iquery>: the offset of a
# suffix depends on the length of the owner name, which needs a length equality (see above); other RR types of RFC 1035 3.3 with a name in the RDATA
<rr_iquery> ::= <rr_a_request> | <rr_ns_iquery> | <rr_cname_iquery> | <rr_ptr_iquery> | <rr_mx_iquery>
<rr_a_request> ::= <qname> <type_a> <class_in> <ttl_sent> <rdlength_four> <rdata_a>
<rr_ns_iquery> ::= <qname> <type_ns> <class_in> <ttl_sent> b'\x00\x02' <pointer_to_owner>
<rr_ptr_iquery> ::= <qname> <type_ptr> <class_in> <ttl_sent> b'\x00\x02' <pointer_to_owner>
<rr_cname_iquery> ::= <qname> <type_cname> <class_in> <ttl_sent> b'\x00\x06' <label_three> <pointer_to_owner>
<rr_mx_iquery> ::= <qname> <type_mx> <class_in> <ttl_sent> b'\x00\x08' <mx_preference> <label_three> <pointer_to_owner>
<pointer_to_owner> ::= b'\xc0\x0c'
<label_three> ::= b'\x03' rb'[\x00-\xff]{3}'
<ttl_sent> ::= <ttl_msb_clear>
# RDLENGTH of an A record (RFC 1035 3.4.1: four octets)
<rdlength_four> ::= b'\x00\x04'

# ============================================================================================================
# 6. REPLIES -- RFC 1035 4.1: a response has the same five sections; the counts of the header drive the sections
# ============================================================================================================
<response> ::= <h_id> <flags_hi_response> <flags_lo> <qdcount> <ancount> <nscount> <arcount> <question>{byte_to_int(<qdcount>)} <rr>{byte_to_int(<ancount>)} <rr>{byte_to_int(<nscount>)} <rr>{byte_to_int(<arcount>)} <message_end>
# the literal marker the party class appends to every received message
<message_end> ::= b'\xfe\xed\xfe\xed'

# RFC 5936 2.2 / 2.2.1: every message of a successful AXFR response: QR=1, OPCODE=0, AA=1, TC=0, RCODE=0; the first
# message begins with the zone SOA and has the question of the query; the last concludes with the same SOA;
# intermediate messages contain no SOA; NSCOUNT=0
<response_axfr_whole> ::= <h_id> <flags_hi_axfr> <flags_lo_axfr> <qdcount_one> <ancount> <nscount_zero> <arcount> <question>{byte_to_int(<qdcount_one>)} <rr_soa> <rr_not_soa>{byte_to_int(<ancount>) - 2} <rr_soa> <rr_ar_axfr>{byte_to_int(<arcount>)} <message_end>
<response_axfr_first> ::= <h_id> <flags_hi_axfr> <flags_lo_axfr> <qdcount_one> <ancount> <nscount_zero> <arcount> <question>{byte_to_int(<qdcount_one>)} <rr_soa> <rr_not_soa>{byte_to_int(<ancount>) - 1} <rr_ar_axfr>{byte_to_int(<arcount>)} <message_end>
<response_axfr_next> ::= <h_id> <flags_hi_axfr> <flags_lo_axfr> <qdcount_axfr_later> <ancount> <nscount_zero> <arcount> <question>{byte_to_int(<qdcount_axfr_later>)} <rr_not_soa>{byte_to_int(<ancount>)} <rr_ar_axfr>{byte_to_int(<arcount>)} <message_end>
<response_axfr_last> ::= <h_id> <flags_hi_axfr> <flags_lo_axfr> <qdcount_axfr_later> <ancount> <nscount_zero> <arcount> <question>{byte_to_int(<qdcount_axfr_later>)} <rr_not_soa>{byte_to_int(<ancount>) - 1} <rr_soa> <rr_ar_axfr>{byte_to_int(<arcount>)} <message_end>
# RFC 5936 2.2: an error ends the transfer: one message with RCODE other than 0 that copies the question (QDCOUNT 1)
<response_axfr_error> ::= <h_id> <flags_hi_axfr_error> <flags_lo_axfr_error> <qdcount_one> <ancount> <nscount_zero> <arcount> <question> <rr>{byte_to_int(<ancount>)} <rr>{byte_to_int(<arcount>)} <message_end>
# AA = 1 (MUST when RCODE is 0), TC = 0, OPCODE 0, RD copied or 0
<flags_hi_axfr> ::= rb'[\x84\x85]'
# (the table of RFC 5936 2.2.1 holds for error messages too: TC = 0, NSCOUNT = 0, Z = AD = 0; AA is free; CD is free: RFC 5936 2.2.1 d) says it MUST be 0, RFC 4035
# 3 and 3.2.2 say a security-aware server MUST copy the CD bit of the query: two MUSTs that conflict, so a message that follows either is accepted)
<flags_hi_axfr_error> ::= rb'[\x80\x81\x84\x85]'
<flags_lo_axfr_error> ::= rb'[\x01-\x0f\x11-\x1f\x81-\x8f\x91-\x9f]'
# Z = 0 (AD also zero, "mbz"), CD 0 or 1 (RFC 5936 2.2.1 d) against RFC 4035 3: both MUSTs, see above), RA = 0 or 1 (RA SHOULD be 0), RCODE = 0
<flags_lo_axfr> ::= rb'[\x00\x10\x80\x90]'
# QDCOUNT is 0 or 1 in messages after the first
<qdcount_axfr_later> ::= <count_zero> | <count_one>
<nscount_zero> ::= <count_zero>
# RFC 5936 2.2: the SOA RR appears in the answer section only (first and last message), never in the additional section
<rr_ar_axfr> ::= <rr_not_soa> | <rr_opt>
<rr_not_soa> ::= <rr_a> | <rr_ns> | <rr_md> | <rr_mf> | <rr_cname> | <rr_mb> | <rr_mg> | <rr_mr> | <rr_null> | <rr_wks> | <rr_ptr> | <rr_hinfo> | <rr_minfo> | <rr_mx> | <rr_txt> | <rr_aaaa> | <rr_ds> | <rr_rrsig> | <rr_nsec> | <rr_dnskey> | <rr_other>

# ============================================================================================================
# 7. SHARED FIELDS
# ============================================================================================================
# --- RFC 1035 4.1.1 header fields ---------------------------------------------------------------------------
# ID: copied from query to reply (checked in section 8)
<h_id> ::= rb'[\x00-\xff]{2}'
# The 16 flag bits are two octets: QR | OPCODE(4) | AA | TC | RD  and  RA | Z | AD | CD | RCODE(4).  They are
# modeled per octet (a regular expression over octet values per combination) because Fandango's guidance in the
# pinned commit cannot serialize a leaf of fewer than eight bits (FandangoConversionError), so single-bit
# nonterminals cannot be used in sent messages.  Python (section 2) decodes the single flags.
# first octet of a query: QR=0, OPCODE QUERY/IQUERY/STATUS (0/1/2), AA = 0 or 1, TC=0, RD = 0 or 1 (RFC 1035 4.1.1: AA is "valid in responses", RD is copied)
# TODO: RFC 1035 4.1.1 reserved OPCODEs 3-15, nearest <flags_hi_query>: RFC 1035 reserves them "for future use" and defines no message for them; 4 (NOTIFY) and 5 (UPDATE) belong to
# extensions (RFC 1996, RFC 2136) that refs/spec/manifest.json leaves out
# TODO: RFC 1035 4.1.1 TC set in a query, nearest <flags_hi_query>: the tested servers refuse it without a reply (PowerDNS drops the query on UDP and closes the TCP connection, which ends the session), only the form with TC clear leads on to deeper states
<flags_hi_query> ::= rb'[\x00\x01\x04\x05]'
<flags_hi_iquery> ::= rb'[\x08\x09\x0c\x0d]'
<flags_hi_status> ::= rb'[\x10\x11\x14\x15]'
# first octet of a response: QR=1; OPCODE (copied from the query), AA, TC, RD (copied) are free
<flags_hi_response> ::= rb'[\x80-\xff]'
# second octet: RA | Z | AD | CD | RCODE.  Z is 0 ("must be zero in all queries and responses"); RA, AD and CD are free;
# one nonterminal per RCODE value (RFC 1035 4.1.1; 9 NotAuth RFC 5936 2.2.1); RA is 0 in a query (RFC 1035 4.1.1: RA is
# set in responses) and its RCODE is 0
# RFC 1035 4.1.1: RA and RCODE are response fields ("set or cleared in a response", "set as part of responses"): the specification does not forbid them in a query and
# a server ignores them, so a query sends them through the shared rules too; Z has its own request (<request_z_set>)
# (CD is an alternative of its own: the CD bit of a query decides what some servers do with the reply, RFC 4035 3, and so a path of the grammar names it)
<flags_lo_ra_clear> ::= <flags_lo_cd_clear> | <flags_lo_cd_set>
<flags_lo_cd_clear> ::= rb'[\x00\x20]'
<flags_lo_cd_set> ::= rb'[\x10\x30]'
<flags_lo_ra_set> ::= rb'[\x80\x90\xa0\xb0]'
<rcode_noerror> ::= <flags_lo_ra_clear> | <flags_lo_ra_set>
<rcode_formerr> ::= rb'[\x01\x11\x21\x31\x81\x91\xa1\xb1]'
<rcode_servfail> ::= rb'[\x02\x12\x22\x32\x82\x92\xa2\xb2]'
<rcode_nxdomain> ::= rb'[\x03\x13\x23\x33\x83\x93\xa3\xb3]'
<rcode_notimp> ::= rb'[\x04\x14\x24\x34\x84\x94\xa4\xb4]'
<rcode_refused> ::= rb'[\x05\x15\x25\x35\x85\x95\xa5\xb5]'
<rcode_notauth> ::= rb'[\x09\x19\x29\x39\x89\x99\xa9\xb9]'
<rcode_other> ::= rb'[\x06-\x08\x0a-\x0f\x16-\x18\x1a-\x1f\x26-\x28\x2a-\x2f\x36-\x38\x3a-\x3f\x86-\x88\x8a-\x8f\x96-\x98\x9a-\x9f\xa6-\xa8\xaa-\xaf\xb6-\xb8\xba-\xbf]'
<rcode_error> ::= <rcode_formerr> | <rcode_servfail> | <rcode_nxdomain> | <rcode_notimp> | <rcode_refused> | <rcode_notauth> | <rcode_other>
<flags_lo> ::= <rcode_noerror> | <rcode_error>
<flags_lo_request> ::= <flags_lo_ra_clear> | <flags_lo_response_only>
<flags_lo_response_only> ::= <flags_lo_ra_set> | <flags_lo_error>
# Z of the breaking queries: the bit 0x40 (AD 0x20 and CD 0x10 stay as in the shared <flags_lo_cd_clear> / <flags_lo_cd_set>)
<flags_lo_z_set> ::= rb'[\x40\x50\x60\x70]'
<flags_lo_error> ::= <rcode_error>

# --- counts (16 bit): zero, one, two and everything else are separate values so a request can narrow them ----
<count_zero> ::= b'\x00\x00'
<count_one> ::= b'\x00\x01'
<count_two> ::= b'\x00\x02'
<count_many> ::= b'\x00' rb'[\x03-\xff]' | rb'[\x01-\xff]' rb'[\x00-\xff]'
<count> ::= <count_zero> | <count_one> | <count_two> | <count_many>
<qdcount> ::= <count>
<ancount> ::= <count>
<nscount> ::= <count>
<arcount> ::= <count>
<qdcount_one> ::= <count_one>
<arcount_one> ::= <count_one>

# --- RFC 1035 4.1.2 question ------------------------------------------------------------------------------------
<question> ::= <qname> <qtype> <qclass>
# the question of a sent query: every TYPE/QTYPE (shared <qtype_sent>) and CLASS/QCLASS (shared <qclass_sent>) value except the reserved
# zero; <question_in> is the class IN form, <question_other> the form with every other class (own exchange: see <exchange_query_other>)
# TODO: RFC 1035 3.2.4 classes other than IN in the pipelined pair (<exchange_pipelined>): a silent server would leave the second reply
# of the pair unmatched; <exchange_query_other> sends them one at a time with the timer
<question_other> ::= <qname> <qtype_sent> <qclass_other_sent>
# the exchanges of requests that must be answered FORMERR/BADVERS use class IN only: the tested servers answer other
# classes with REFUSED/NOTIMP (replies the specification allows) before the format error shows
# TODO: RFC 1035 3.2.4 CS/CH/HS/* in the question of request_bad_version (nearest nonterminal <question_in>): the servers refuse
# these classes (REFUSED) before they report BADVERS
<question_in> ::= <qname> <qtype_sent> <qclass_in>
# RFC 1035 4.1.4: a name may be a pointer to an earlier name: here to the name of the first question (offset 12)
<qclass_in> ::= <class_in>
# QNAME: sent as the wire form of a presentation name the generator picks from the setup lists (converter), parsed
# by the shared name rule
# TODO: RFC 1035 3.1 / RFC 4343 3 names with octets outside letters, digits, hyphen, underscore and asterisk and names of 255 octets, nearest <qname_text>: sent names come from the target lists of the test setup
<qname> ::= <name> := wire(<qname_text>)
<qname_text> ::= (<text_label> '.')+ | '.' := pick_qname()
<text_label> ::= rb'[A-Za-z0-9_*-]+'

# --- RFC 1035 3.1 domain names ------------------------------------------------------------------------------------
# a name is a sequence of labels ended by the root label or a compression pointer (RFC 1035 4.1.4)
<name> ::= <label>* <name_end>
<label> ::= <label_len> <octet>{byte_to_int(<label_len>)}
<label_len> ::= rb'[\x01-\x3f]'
# one octet of a label or of a sent option (a nonterminal, so that the repetition count is generated from the length field)
<octet> ::= rb'[\x00-\xff]'
<name_end> ::= <root> | <pointer>
<root> ::= b'\x00'
# 14-bit offset from the start of the message
<pointer> ::= rb'[\xc0-\xff]' rb'[\x00-\xff]'

# --- TYPE / QTYPE values (RFC 1035 3.2.2, 3.2.3, RFC 3596, 4034, 6891) ---------------------------------------------
<type_a> ::= b'\x00\x01'
<type_ns> ::= b'\x00\x02'
<type_md> ::= b'\x00\x03'
<type_mf> ::= b'\x00\x04'
<type_cname> ::= b'\x00\x05'
<type_soa> ::= b'\x00\x06'
<type_mb> ::= b'\x00\x07'
<type_mg> ::= b'\x00\x08'
<type_mr> ::= b'\x00\x09'
<type_null> ::= b'\x00\x0a'
<type_wks> ::= b'\x00\x0b'
<type_ptr> ::= b'\x00\x0c'
<type_hinfo> ::= b'\x00\x0d'
<type_minfo> ::= b'\x00\x0e'
<type_mx> ::= b'\x00\x0f'
<type_txt> ::= b'\x00\x10'
<type_aaaa> ::= b'\x00\x1c'
<type_opt> ::= b'\x00\x29'
<type_ds> ::= b'\x00\x2b'
<type_rrsig> ::= b'\x00\x2e'
<type_nsec> ::= b'\x00\x2f'
<type_dnskey> ::= b'\x00\x30'
# QTYPEs (RFC 1035 3.2.3): AXFR 252, MAILB 253, MAILA 254, * 255
<type_axfr> ::= b'\x00\xfc'
<type_mailb> ::= b'\x00\xfd'
<type_maila> ::= b'\x00\xfe'
<type_any> ::= b'\x00\xff'
# every other TYPE value (unassigned, assigned beyond this specification, private use): RFC 1035 3.2: any TYPE is
# a valid QTYPE; RDATA of such an RR is opaque (RFC 3597 semantics)
<type_other> ::= rb'[\x01-\xff]' rb'[\x00-\xff]' | b'\x00' rb'[\x11-\x1b\x1d-\x28\x2a\x2c\x2d\x31-\xfb]'
<qtype_rr> ::= <type_a> | <type_ns> | <type_md> | <type_mf> | <type_cname> | <type_soa> | <type_mb> | <type_mg> | <type_mr> | <type_null> | <type_wks> | <type_ptr> | <type_hinfo> | <type_minfo> | <type_mx> | <type_txt> | <type_aaaa> | <type_ds> | <type_rrsig> | <type_nsec> | <type_dnskey>
<qtype_sent> ::= <qtype_rr> | <type_mailb> | <type_maila> | <type_any> | <type_other>
# TYPE 0 is reserved; servers echo it in replies to messages without a usable question, so replies accept it
<type_zero> ::= b'\x00\x00'
<qtype> ::= <qtype_sent> | <type_axfr> | <type_zero>

# --- CLASS / QCLASS values (RFC 1035 3.2.4, 3.2.5) ------------------------------------------------------------------
<class_in> ::= b'\x00\x01'
<class_cs> ::= b'\x00\x02'
<class_ch> ::= b'\x00\x03'
<class_hs> ::= b'\x00\x04'
<class_any> ::= b'\x00\xff'
<class_other> ::= rb'[\x01-\xff]' rb'[\x00-\xff]' | b'\x00' rb'[\x05-\xfe]'
<rclass> ::= <class_in> | <class_cs> | <class_ch> | <class_hs> | <class_other> | <class_zero>
<qclass_sent> ::= <class_in> | <qclass_other_sent>
<qclass_other_sent> ::= <class_cs> | <class_ch> | <class_hs> | <class_any> | <class_other>
<class_zero> ::= b'\x00\x00'
<qclass> ::= <qclass_sent> | <class_zero>

# --- RFC 1035 3.2.1 resource record --------------------------------------------------------------------------------
# RFC 2181 8: a TTL is an unsigned 31-bit number, sent with the most significant bit zero; received values with it set are accepted and treated as zero
<ttl_msb_clear> ::= rb'[\x00-\x7f]' rb'[\x00-\xff]{3}'
<ttl_msb_set> ::= rb'[\x80-\xff]' rb'[\x00-\xff]{3}'
<ttl> ::= <ttl_msb_clear> | <ttl_msb_set>
<rdlength> ::= rb'[\x00-\xff]{2}'
# the types whose RDATA this grammar defines (RFC 1035 3.3, 3.4.1, RFC 3596, 4034 2-5) and OPT (RFC 6891 6.1)
<rr> ::= <rr_plain> | <rr_opt>
<rr_plain> ::= <rr_not_soa> | <rr_soa>

<rr_a> ::= <name> <type_a> <rclass> <ttl> <rdlength> <rdata_a>
<rr_ns> ::= <name> <type_ns> <rclass> <ttl> <rdlength> <name>
<rr_md> ::= <name> <type_md> <rclass> <ttl> <rdlength> <name>
<rr_mf> ::= <name> <type_mf> <rclass> <ttl> <rdlength> <name>
<rr_cname> ::= <name> <type_cname> <rclass> <ttl> <rdlength> <name>
<rr_soa> ::= <name> <type_soa> <rclass> <ttl> <rdlength> <name> <name> <soa_serial> <soa_refresh> <soa_retry> <soa_expire> <soa_minimum>
<rr_mb> ::= <name> <type_mb> <rclass> <ttl> <rdlength> <name>
<rr_mg> ::= <name> <type_mg> <rclass> <ttl> <rdlength> <name>
<rr_mr> ::= <name> <type_mr> <rclass> <ttl> <rdlength> <name>
<rr_null> ::= <name> <type_null> <rclass> <ttl> <rdlength> rb'[\x00-\xff]'{byte_to_int(<rdlength>)}
# TODO: RFC 1035 3.4.2 WKS port bit map, nearest <rr_wks>: kept opaque; the format is obsolete and no tested server returns it
<rr_wks> ::= <name> <type_wks> <rclass> <ttl> <rdlength> <ipv4_address> <wks_protocol> rb'[\x00-\xff]'{byte_to_int(<rdlength>) - 5}
<rr_ptr> ::= <name> <type_ptr> <rclass> <ttl> <rdlength> <name>
<rr_hinfo> ::= <name> <type_hinfo> <rclass> <ttl> <rdlength> <char_string> <char_string>
<rr_minfo> ::= <name> <type_minfo> <rclass> <ttl> <rdlength> <name> <name>
<rr_mx> ::= <name> <type_mx> <rclass> <ttl> <rdlength> <mx_preference> <name>
# TODO: RFC 1035 3.3.14 character-strings, nearest <txt_strings>: a repetition of <char_string> followed by the next RR is
# ambiguous for Fandango's parser (the strings can swallow the start of the next RR), so the RDATA is a length-bounded octet
# string whose character-string structure is checked by `txt_valid`
<rr_txt> ::= <name> <type_txt> <rclass> <ttl> <rdlength> <txt_strings>
<txt_strings> ::= rb'[\x00-\xff]'{byte_to_int(<rdlength>)}
<rr_aaaa> ::= <name> <type_aaaa> <rclass> <ttl> <rdlength> <ipv6_address>
# RFC 4034 5.1 DS
<rr_ds> ::= <name> <type_ds> <rclass> <ttl> <rdlength> <ds_key_tag> <dnssec_algorithm> <ds_digest_type> rb'[\x00-\xff]'{byte_to_int(<rdlength>) - 4}
# RFC 4034 3.1 RRSIG: signer's name is not compressed (3.1.7)
# RFC 4034 3.1: the Signer's Name is an uncompressed name (3.1.7) and the Signature fills the rest of RDATA (3.1.8); RFC 4034 4.1: NSEC RDATA is the
# Next Domain Name (uncompressed, 4.1.1) and the Type Bit Maps that fill the rest (4.1.2).  A repetition bound may name only one nonterminal
# (Fandango: "RepetitionBoundsConstraint requires exactly one or zero searches"), so the rest after the name is bounded by rdata_rest(<name>, fixed
# octets), which reads RDLENGTH from the RR above the name.  The window blocks of the bit maps are checked by `type_bitmap` (a list of blocks cannot be a
# repetition here: it would be ambiguous with the next RR).
<rr_rrsig> ::= <name> <type_rrsig> <rclass> <ttl> <rdlength> <rrsig_type_covered> <dnssec_algorithm> <rrsig_labels> <rrsig_original_ttl> <rrsig_expiration> <rrsig_inception> <rrsig_key_tag> <rrsig_signer_name> <rrsig_signature>
<rrsig_signer_name> ::= <label>* <root>
<rrsig_signature> ::= rb'[\x00-\xff]'{rdata_rest(<rrsig_signer_name>, 18)}
# RFC 4034 4.1 NSEC: next domain name (not compressed) and type bit maps
<rr_nsec> ::= <name> <type_nsec> <rclass> <ttl> <rdlength> <nsec_next_name> <nsec_bitmaps>
<nsec_next_name> ::= <label>* <root>
<nsec_bitmaps> ::= rb'[\x00-\xff]'{rdata_rest(<nsec_next_name>, 0)}
# RFC 4034 2.1 DNSKEY: flags, protocol (MUST be 3), algorithm, public key
<rr_dnskey> ::= <name> <type_dnskey> <rclass> <ttl> <rdlength> <dnskey_flags> <dnskey_protocol> <dnssec_algorithm> rb'[\x00-\xff]'{byte_to_int(<rdlength>) - 4}
# any other type: RDATA is opaque
# TODO: RFC 1035 3.3 / 3.4 RDATA of types this grammar has no rule for (SRV, NAPTR, CAA, TSIG, NSEC3, ...), nearest <rr_other>: they belong to extensions the manifest leaves out; they are accepted opaque and never sent
<rr_other> ::= <name> <type_other> <rclass> <ttl> <rdlength> rb'[\x00-\xff]'{byte_to_int(<rdlength>)}
# RFC 6891 6.1.2 OPT: owner name root; CLASS = UDP payload size; TTL = extended RCODE, VERSION, DO, Z; RDATA options
<rr_opt> ::= <root> <type_opt> <opt_udp_size> <opt_ext_rcode> <opt_version> <opt_flags> <rdlength> <opt_options>{opt_present(<rdlength>)}
# RFC 6891 6.1.2: the RDATA is a sequence of options filling RDLENGTH.  A repetition cannot name itself (Fandango rejects the loop), so the options are
# nested levels, each holding one option and the next level when octets are left after it (`opt_left` counts from RDLENGTH, so the grammar alone decides where
# the options end); after 8 options the rest of the RDATA is a length-bounded octet string, checked by `options_valid`
<opt_options> ::= <edns_option> <opt_options2>{opt_left(<edns_option>)}
<opt_options2> ::= <edns_option> <opt_options3>{opt_left(<edns_option>)}
<opt_options3> ::= <edns_option> <opt_options4>{opt_left(<edns_option>)}
<opt_options4> ::= <edns_option> <opt_options5>{opt_left(<edns_option>)}
<opt_options5> ::= <edns_option> <opt_options6>{opt_left(<edns_option>)}
<opt_options6> ::= <edns_option> <opt_options7>{opt_left(<edns_option>)}
<opt_options7> ::= <edns_option> <opt_options8>{opt_left(<edns_option>)}
<opt_options8> ::= <edns_option> rb'[\x00-\xff]'{opt_rest(<edns_option>)}

# --- RDATA building blocks -----------------------------------------------------------------------------------------
<rdata_a> ::= <ipv4_address>
<ipv4_address> ::= rb'[\x00-\xff]{4}'
<ipv6_address> ::= rb'[\x00-\xff]{16}'
<char_string> ::= <char_string_len> rb'[\x00-\xff]'{byte_to_int(<char_string_len>)}
<char_string_len> ::= rb'[\x00-\xff]'
<mx_preference> ::= rb'[\x00-\xff]{2}'
<soa_serial> ::= rb'[\x00-\xff]{4}'
<soa_refresh> ::= rb'[\x00-\xff]{4}'
<soa_retry> ::= rb'[\x00-\xff]{4}'
<soa_expire> ::= rb'[\x00-\xff]{4}'
<soa_minimum> ::= rb'[\x00-\xff]{4}'
<wks_protocol> ::= rb'[\x00-\xff]'
<ds_key_tag> ::= rb'[\x00-\xff]{2}'
<ds_digest_type> ::= rb'[\x00-\xff]'
<dnssec_algorithm> ::= rb'[\x00-\xff]'
<rrsig_type_covered> ::= rb'[\x00-\xff]{2}'
<rrsig_labels> ::= rb'[\x00-\xff]'
<rrsig_original_ttl> ::= rb'[\x00-\xff]{4}'
<rrsig_expiration> ::= rb'[\x00-\xff]{4}'
<rrsig_inception> ::= rb'[\x00-\xff]{4}'
<rrsig_key_tag> ::= rb'[\x00-\xff]{2}'
<dnskey_flags> ::= rb'[\x00-\xff]{2}'
<dnskey_protocol> ::= b'\x03'
# OPT RDATA fields (RFC 6891 6.1.2-6.1.4)
# the requestor's UDP payload size (RFC 6891 6.1.2): any value (shared rule, received); a sent OPT announces one of the sizes below (values below 512 count as 512,
# RFC 6891 6.2.3: 0, 511 and 512 are the edge; 1232 and 1400 the usual ones; 4096 and 65535 the large ones)
# TODO: RFC 6891 6.1.2 other UDP payload sizes in a sent OPT, nearest <opt_udp_size_sent>: the listed sizes cover the edges (below 512, 512) and the larger limits the replies reach
<opt_udp_size> ::= rb'[\x00-\xff]{2}'
<opt_udp_size_sent> ::= b'\x00\x00' | b'\x01\xff' | b'\x02\x00' | b'\x04\xd0' | b'\x05\x78' | b'\x10\x00' | b'\xff\xff'
<opt_ext_rcode_zero> ::= b'\x00'
<opt_ext_rcode> ::= rb'[\x00-\xff]'
# RFC 6891 6.1.3: the upper eight bits of the extended RCODE; a request carries 0 or any value (the responder ignores it); the sent form is the shared
# field rule or its zero alternative
<opt_ext_rcode_sent> ::= <opt_ext_rcode_zero> | <opt_ext_rcode>
<opt_version_zero> ::= b'\x00'
<opt_version_other> ::= rb'[\x01-\xff]'
<opt_version> ::= <opt_version_zero> | <opt_version_other>
# the last two octets of the OPT TTL: DO (RFC 3225 3) and 15 Z bits ("set to zero by senders and ignored by
# receivers", RFC 6891 6.1.4)
# TODO: RFC 6891 6.1.4 non-zero Z bits in a sent OPT, nearest <opt_flags_sent>: "set to zero by senders"
<opt_flags_do_clear> ::= b'\x00\x00'
<opt_flags_do_set> ::= b'\x80\x00'
<opt_flags_z_set> ::= rb'[\x01-\x7f\x81-\xff]' rb'[\x00-\xff]' | rb'[\x00\x80]' rb'[\x01-\xff]'
<opt_flags> ::= <opt_flags_do_clear> | <opt_flags_do_set> | <opt_flags_z_set>
<opt_flags_sent> ::= <opt_flags_do_clear> | <opt_flags_do_set>
# an option: OPTION-CODE, OPTION-LENGTH, OPTION-DATA (unknown codes are ignored by the recipient, RFC 6891 6.1.2).  Received options are
# <opt_options> in <rr_opt> (checked by `options_valid`); sent options use the codes no registry entry assigns (the assigned codes belong to the
# extensions the manifest leaves out: 0-99 and the 20001-26999 and 65535 around the registered ones are <opt_code_assigned>)
# TODO: RFC 6891 6.1.2 option codes assigned by registries to extensions (NSID, COOKIE, client subnet, padding, ...), nearest <opt_code_assigned>: extensions the manifest leaves out; received ones are accepted by <opt_options>
# the RDLENGTH and options of a sent OPT: none, one, two or three options of the sent form <edns_option_sent> (the shared rule <edns_option> narrowed by the
# grammar to the unassigned OPTION-CODEs and the OPTION-LENGTHs 0-32); the RDATA is the options (the RDLENGTH is the length of what follows it: an equality)
# TODO: RFC 6891 6.1.2 sent options with an assigned OPTION-CODE (NSID, COOKIE, client subnet, padding, ...), nearest <opt_code>: the extensions the manifest leaves out; a server that does not know a code ignores it
# TODO: RFC 6891 6.1.2 more than three options and OPTION-LENGTH above 64, nearest <opt_rdata_request>: only bulk for the same behaviour of the responder
<opt_rdata_request> ::= <rdlength> <edns_option_sent>{0,3}
where forall <r> in <opt_rdata_request>: <r>.<rdlength> == rdlength_of(<r>)
# OPTION-CODE (RFC 6891 6.1.2 / 9): 100-20000 and 27000-65534 are unassigned or experimental (65001-65534), the rest registered
<opt_code_unassigned> ::= b'\x00' rb'[\x64-\xff]' | rb'[\x01-\x4d]' rb'[\x00-\xff]' | b'\x4e' rb'[\x00-\x20]' | b'\x69' rb'[\x78-\xff]' | rb'[\x6a-\xfe]' rb'[\x00-\xff]' | b'\xff' rb'[\x00-\xfe]'
<opt_code_assigned> ::= b'\x00' rb'[\x00-\x63]' | b'\x4e' rb'[\x21-\xff]' | rb'[\x4f-\x68]' rb'[\x00-\xff]' | b'\x69' rb'[\x00-\x77]' | b'\xff\xff'
<opt_code> ::= <opt_code_unassigned> | <opt_code_assigned>
<opt_length> ::= rb'[\x00-\xff]{2}'
# the option structure, shared by the received options (<opt_options>) and the sent ones
<edns_option> ::= <opt_code> <opt_length> rb'[\x00-\xff]'{byte_to_int(<opt_length>)}
# the sent form: the shared rule narrowed to the unassigned codes and the OPTION-LENGTHs 0-32 (the data is the OPTION-LENGTH octets that follow)
<opt_code_sent> ::= <opt_code_unassigned>
<opt_length_sent> ::= b'\x00' rb'[\x00-\x20]'
<edns_option_sent> ::= <opt_code_sent> <opt_length_sent> <octet>{byte_to_int(<opt_length_sent>)}


# ============================================================================================================
# 8. CONSTRAINTS ON RECEIVED MESSAGES (mandatory requirements only) AND THE LENGTH FIELDS OF RESOURCE RECORDS
# ============================================================================================================
def rdata_rest(first, fixed):
    """Octets of RDATA left after `fixed` octets and the name `first` (a bound that names one nonterminal only; RDLENGTH is read from the RR above)."""
    node = first
    while node is not None:
        for c in node.children:
            if str(c.symbol) == "<rdlength>":
                return max(0, byte_to_int(bytes(c)) - fixed - len(bytes(first)))
        node = node.parent
    return 0


def opt_present(rdlength):
    """1 when the RDATA of an OPT RR holds octets (RDLENGTH > 0), else 0."""
    return 1 if byte_to_int(bytes(rdlength)) > 0 else 0


def opt_remaining(node):
    """Octets of OPT RDATA left after the options before the node `node` (RDLENGTH is read from the RR above); options are <edns_option> children of the nested levels above."""
    consumed = 0
    cur = node
    while cur is not None:
        found = None
        for c in cur.children:
            if str(c.symbol) == "<rdlength>":
                found = c
                break
            if c is not node and str(c.symbol) == "<edns_option>":
                consumed += len(bytes(c))
        if found is not None:
            return max(0, byte_to_int(bytes(found)) - consumed)
        cur = cur.parent
    return 0


def opt_left(first):
    """1 when octets of the OPT RDATA are left after the option `first` and the options before it, else 0."""
    return 1 if opt_remaining(first) > len(bytes(first)) else 0


def opt_rest(first):
    """The octets of OPT RDATA left after the option `first` and the options before it."""
    return max(0, opt_remaining(first) - len(bytes(first)))


def rdlength_of(rr):
    """RDLENGTH of an RR tree: the number of octets after the RDLENGTH field (RFC 1035 4.1.3)."""
    node = rr
    while node.children and not any(str(c.symbol) == "<rdlength>" for c in node.children):
        node = node.children[0]
    seen = False
    total = 0
    for child in node.children:
        if seen:
            total += len(bytes(child))
        elif str(child.symbol) == "<rdlength>":
            seen = True
    return struct.pack(">H", total)


# RFC 1035 4.1.3 / RFC 6891 6.1.2: RDLENGTH is the length in octets of RDATA (compressed length where names inside
# RDATA are compressed, RFC 1035 4.1.4)
# (<rr_soa> and <rr_not_soa> are quantified themselves: the AXFR replies use them without <rr_plain>)
where forall <r> in <rr_not_soa>: <r>..<rdlength> == rdlength_of(<r>)
where forall <r> in <rr_soa>: <r>.<rdlength> == rdlength_of(<r>)
where forall <r> in <rr_opt>: <r>.<rdlength> == rdlength_of(<r>)


# TODO: RFC 2181 5.1 / 9 (an RRset that does not fit sets TC; completeness of an RRset), RFC 1035 3.3.9 (additional section processing beyond additional_addresses),
# RFC 4592 (wildcard synthesis where no DNSSEC RRSIG shows it), RFC 5936 3 (zone content of a transfer beyond axfr_dnssec), nearest <response>: what the server holds
# but no reply of the session shows is not known to the grammar; the checks below enforce what the reply and the earlier replies of the session show
# TODO: RFC 2181 4.1 / 4.2 (source address and port of a UDP reply), nearest <response>: the party class checks the source (ClientNetworkParty.receive); the grammar sees no address
# TODO: RFC 6891 6.1.1 (TSIG/SIG(0) last in the additional section), nearest <rr_opt>: the extension the manifest leaves out
# TODO: RFC 4035 3.2.1 (a recursive server sets DO on the queries to its upstream servers), nearest <response>: the implementation's exchange with third-party servers
# (the other half, no DNSSEC RRs in a reply to a query without DO, is no_dnssec_without_do)
# (RFC 7766 6.2.4, the retry of unanswered queries after a close of the TCP connection, is modeled in every exchange: <answer>, <pipelined_replies>, the timer
# exchanges and <axfr_answer>; the retry is sent once, a second close ends the exchange: no specific retry algorithm is specified)
def unsupported_version(rq):
    """A request whose OPT announces an EDNS VERSION above 0 (RFC 6891 6.1.3): the responder may not implement it."""
    return any(((r["ttl"] >> 16) & 0xFF) != 0 for r in opt_of(rq))


def rdata_bytes(rr):
    """The octets after the RDLENGTH field of an RR tree."""
    node = rr
    while node.children and not any(str(c.symbol) == "<rdlength>" for c in node.children):
        node = node.children[0]
    seen = False
    out = b""
    for child in node.children:
        if seen:
            out += bytes(child)
        elif str(child.symbol) == "<rdlength>":
            seen = True
    return out


# RFC 1035 3.3.14: TXT RDATA is one or more character-strings (a length octet and that many octets), filling RDLENGTH
def txt_valid(rr):
    data = rdata_bytes(rr)
    off = 0
    while off < len(data):
        off += 1 + data[off]
    return len(data) > 0 and off == len(data)


# RFC 6891 6.1.2: OPT RDATA is a sequence of {OPTION-CODE, OPTION-LENGTH, OPTION-DATA} filling RDLENGTH
def options_valid(rr):
    data = rdata_bytes(rr)
    off = 0
    while off < len(data):
        if off + 4 > len(data):
            return False
        off += 4 + struct.unpack(">H", data[off + 2:off + 4])[0]
    return off == len(data)


where forall <r> in <rr_txt>: txt_valid(<r>)
where forall <r> in <rr_opt>: options_valid(<r>)


def reply_check(e, check):
    """Applies check(request, reply) to every reply of the exchange whose request and reply both decode (every request kind,
    every exchange: the replies are judged alike)."""
    def compute():
        for rq, rp in pairs(e):
            if rq is not None and rp is not None and not check(rq, rp):
                return False
        return True
    return memo(e, "rc:" + check.__name__, compute)


def reply_check_all(e, check):
    return reply_check(e, check)


# RFC 1035 4.1.4: names are labels ended by the root label or a pointer to an earlier occurrence; a reply whose
# compression pointers loop or leave the message does not decode
def reply_decodes(e):
    return all(rp is not None for rq, rp in pairs(e))


# RFC 1035 4.1.1 ID: "This identifier is copied into the corresponding reply"
def id_matches(rq, rp):
    return rq["id"] == rp["id"]


# RFC 1035 4.1.1 OPCODE: "This value is set by the originator of a query and copied into the response"
def opcode_matches(rq, rp):
    return rq["opcode"] == rp["opcode"]


# RFC 1035 4.1.1 RD: "this bit ... is copied into the response" -- of a QUERY.  A reply to an inverse query (obsolete, RFC 3425 3)
# or to a STATUS request is no answer to a recursion request: the RD of such a reply is not judged.
def rd_matches(rq, rp):
    if rq["opcode"] != 0:
        return True
    # AXFR (RFC 5936 2.2.1): RD of the replies is only RECOMMENDED to be copied
    if rq["questions"] and rq["questions"][0][1] == 252:
        return True
    return rq["rd"] == rp["rd"]


# RFC 6891 6.1.1 / 7: an OPT in the request needs an OPT in the reply (FORMERR from a responder that does not
# implement EDNS carries none: edns_formerr_has_opt); no OPT in the request means no OPT in the reply
def opt_presence(rq, rp):
    if rq.get("odd_opt"):
        return True   # (two OPT RRs: FORMERR is required, with or without an OPT; an OPT owner other than the root: the specification defines no reaction)
    if not opt_of(rq):
        return not opt_of(rp)
    if rp["rcode"] == 1:
        # a FORMERR from a responder that implements EDNS (it carries an OPT) is the minimal response too: header, question, OPT
        return not opt_of(rp) or rq["opcode"] != 0 or not rq["questions"] or rp["qd"] >= 1
    if rq["questions"] and rq["questions"][0][1] == 252:
        # RFC 5936 2.2.5: an OPT RR is SHOULD in the first and MAY in later messages of a transfer
        return len(opt_of(rp)) <= 1
    # the minimal response is header, question section and OPT (RFC 6891 7)
    return len(opt_of(rp)) == 1 and (rq["opcode"] != 0 or not rq["questions"] or rp["qd"] >= 1)


# RFC 6891 6.1.1: at most one OPT RR in a message, in the additional section
def single_opt(rq, rp):
    opts = opt_of(rp)
    return len(opts) <= 1 and all(r["section"] == "ar" for r in opts)


# RFC 3225 3: "The DO bit of the query MUST be copied in the response"
def do_copied(rq, rp):
    rq_opt, rp_opt = opt_of(rq), opt_of(rp)
    if not rq_opt or not rp_opt:
        return True
    return (rq_opt[0]["ttl"] >> 15) & 1 == (rp_opt[0]["ttl"] >> 15) & 1


# RFC 1035 4.2.1: UDP messages are restricted to 512 octets, or the size announced in the request's OPT (RFC 6891
# 6.2.3: announced values below 512 are treated as 512)
def udp_size_limit(rq, rp):
    if TRANSPORT != "udp" or rq.get("odd_opt"):
        return True
    limit = 512
    for r in opt_of(rq):
        limit = max(512, r["class"])
    return rp["len"] <= limit


# RFC 1035 4.1.4: a pointer refers to a prior occurrence of a name in the message
def pointers_backwards(rq, rp):
    return all(target < position for position, target in rp["pointers"])


# RFC 2181 8: a TTL received with the most significant bit set is treated as zero
def eff_ttl(ttl):
    return ttl if ttl < 0x80000000 else 0


# RFC 2308 3: an authoritative negative answer carries the zone's SOA in the authority section
def negative_has_soa(rq, rp):
    if (not rp["aa"] or rp["opcode"] != 0 or rq["opcode"] != 0 or not rq["questions"] or rp["tc"]
            or full_rcode(rp) != rp["rcode"]):
        return True
    nodata = rp["rcode"] == 0 and rp["an"] == 0 and not any(r["type"] == 2 for r in rp["rrs"] if r["section"] == "ns")
    if rp["rcode"] == 3 or nodata:
        return any(r["type"] == 6 for r in rp["rrs"] if r["section"] == "ns")
    return True


# TODO: RFC 2308 3 (the TTL of the negative-answer SOA "is set from" the minimum of the SOA MINIMUM field and the SOA's own TTL), nearest
# <response>: a description, not an obligation (no MUST / SHOULD), so a reply with another TTL breaks no mandatory requirement
# RFC 2181 5.2: all RRs of an RRset carry the same TTL (OPT excluded: its TTL field holds flags)
def rrset_ttl_equal(rq, rp):
    seen = {}
    for r in rp["rrs"]:
        if r["type"] == 41:
            continue
        key = (r["name"], r["type"], r["class"])
        if r["type"] == 46 and r["rdlen"] >= 2:
            key += (rp["msg"][r["rdoff"]:r["rdoff"] + 2],)   # RRSIGs are RRsets per covered type (RFC 4034 3)
        if seen.setdefault(key, eff_ttl(r["ttl"])) != eff_ttl(r["ttl"]):
            return False
    return True


# RFC 2181 10.1: a name that owns a CNAME owns no other data (except DNSSEC RRSIG/NSEC; KEY)
def cname_exclusive(rq, rp):
    owners = {}
    for r in rp["rrs"]:
        owners.setdefault((r["name"], r["class"]), set()).add(r["type"])
    for types in owners.values():
        if 5 in types and (types - {5, 46, 47, 25}):
            return False
    return True


# RFC 3225 1/3: the DNSSEC security RRs (SIG, KEY, NXT of RFC 2535 and, as ordinary RRsets of RFC 4035 3, DNSKEY, RRSIG, NSEC and the NSEC3 records of RFC 5155;
# DS is not one: RFC 4035 3 sets it apart ("DS RRs always require some special processing"), 3.1.4 requires it in a referral only with DO, nothing forbids it without)
# are not returned unless the DO bit is set (or they are queried explicitly)
def no_dnssec_without_do(rq, rp):
    if rq["opcode"] != 0 or not rq["questions"]:
        return True
    # (a single OPT whose owner is not the root is no EDNS OPT: the query has no OPT; with two OPT RRs the DO bit that counts is not defined,
    # so the rule binds only where both have DO clear)
    raw = [r for r in rq["rrs"] if r["type"] == 41]
    if len(raw) > 1:
        do = any((r["ttl"] >> 15) & 1 for r in raw)
    else:
        do = any((r["ttl"] >> 15) & 1 for r in opt_of(rq))
    qtype = rq["questions"][0][1]
    kinds = (24, 25, 30, 46, 47, 48, 50, 51)
    # (RFC 3225 3: the security RRs of the zone data of an AXFR / IXFR answer are part of the zone, no insertion)
    if do or qtype in kinds or qtype in (255, 252, 251):
        return True
    return not any(r["type"] in kinds for r in rp["rrs"])


# RFC 4034 3.1.7 / 4.1.1 (and RFC 3597): the signer's name of an RRSIG and the next domain name of an NSEC are not
# compressed; RFC 4034 4.1.2: the type bit maps of an NSEC are window blocks in increasing order, each 1-32 octets, with
# no empty block and no trailing zero octet; RFC 4035 2.3: the bit maps of an NSEC name the types NSEC and RRSIG
def type_bitmap(msg, start, end):
    types = set()
    off = start
    last = -1
    while off < end:
        if off + 2 > end:
            return None
        window, length = msg[off], msg[off + 1]
        if length < 1 or length > 32 or off + 2 + length > end or window <= last or msg[off + 1 + length] == 0:
            return None
        last = window
        for i in range(length):
            for bit in range(8):
                if msg[off + 2 + i] & (0x80 >> bit):
                    types.add(window * 256 + i * 8 + bit)
        off += 2 + length
    return types


def uncompressed_name_end(msg, off, end):
    while True:
        if off >= end:
            return None
        length = msg[off]
        if length == 0:
            return off + 1
        if length & 0xC0:
            return None
        off += 1 + length


def dnssec_rdata_formats(rq, rp):
    msg = rp["msg"]
    for r in rp["rrs"]:
        end = r["rdoff"] + r["rdlen"]
        if r["type"] == 46:
            if uncompressed_name_end(msg, r["rdoff"] + 18, end) is None:
                return False
        elif r["type"] == 47:
            after = uncompressed_name_end(msg, r["rdoff"], end)
            if after is None:
                return False
            types = type_bitmap(msg, after, end)
            if types is None or not {46, 47} <= types:
                return False
            if not types - {46, 47}:
                return False   # RFC 4035 2.3: an NSEC is never the only RRset at its owner
            if 5 in types and types - {5, 25, 46, 47}:
                return False   # RFC 4035 2.5: nothing but RRSIG, NSEC (and KEY) next to a CNAME
            if 2 in types and 6 not in types and not types <= {2, 43, 46, 47}:
                return False
    return True


def key_tag(rdata):
    """Key tag of a DNSKEY RDATA (RFC 4034 Appendix B; B.1 for algorithm 1: the 16 bits before the last octet of the modulus)."""
    if len(rdata) >= 4 and rdata[3] == 1:
        return struct.unpack(">H", rdata[-3:-1])[0] if len(rdata) >= 5 else 0
    acc = 0
    for i, b in enumerate(rdata):
        acc += b if i & 1 else b << 8
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


# RFC 7766 7: a reply with a Question section repeats the QNAME, QCLASS and QTYPE of the query (QNAME compared
# case-insensitively, RFC 4343 3)
def question_matches(rq, rp):
    if rq["opcode"] != 0 or len(rq["questions"]) != 1 or not rp["questions"]:
        return True
    return rq["questions"][0][:3] == rp["questions"][0][:3]


# RFC 6891 6.1.3: responses are limited to the VERSION level of the request
def edns_version_limited(rq, rp):
    rq_opt, rp_opt = opt_of(rq), opt_of(rp)
    if not rq_opt or not rp_opt:
        return True
    return ((rp_opt[0]["ttl"] >> 16) & 0xFF) <= ((rq_opt[0]["ttl"] >> 16) & 0xFF)


# RFC 9619 4: a reply to OPCODE 0 never has more than one question
def reply_qdcount_one(rq, rp):
    return rp["opcode"] != 0 or rp["qd"] <= 1


# RFC 9471 3.1: a referral carries all available glue of in-domain name servers or sets TC; glue is available where an
# earlier reply of the session carried an address for that server name
def referral_glue(e):
    def compute():
        known = session_state(e)[1].address_names
        for rq, rp in pairs(e):
            if rq is None or rp is None or unsupported_version(rq):
                continue
            authority = [r for r in rp["rrs"] if r["section"] == "ns"]
            if rp["an"] != 0 or rp["aa"] or rp["tc"] or rp["rcode"] != 0 or any(r["type"] == 6 for r in authority):
                continue
            addresses = {r["name"] for r in rp["rrs"] if r["section"] == "ar" and r["type"] in (1, 28)}
            for r in authority:
                if r["type"] != 2:
                    continue
                target = decode_name(rp["msg"], r["rdoff"])
                if target is None:
                    return False
                if target[0] in known and target[0].endswith(b"." + r["name"]) and target[0] not in addresses:
                    return False
        return True
    return memo(e, "referral_glue", compute)


# RFC 1034 4.3.3: wildcards do not apply across zone cuts: a name below a delegation the session has shown (a referral) is never answered
# with data by the delegating server (it is not authoritative for the child zone)
def no_answer_below_cut(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rq["opcode"] != 0 or len(rq["questions"]) != 1 or rq["questions"][0][1] == 252
                    or not rp["aa"] or rp["rcode"] != 0 or rp["an"] == 0):
                continue
            name = rq["questions"][0][0]
            if any(name != c and under(name, c) and c not in facts.apexes for c in facts.cuts):
                return False
        return True
    return memo(e, "no_answer_below_cut", compute)


# RFC 2181 10.2 / 10.3: the target of a PTR, NS or MX record is not an alias: no CNAME owner in the reply or in earlier
# replies of the session carries that name
def targets_not_aliases(e):
    def compute():
        aliases = facts_now(e).aliases
        for rq, rp in pairs(e):
            if rp is None:
                continue
            for r in rp["rrs"]:
                if r["type"] in (2, 12, 15) and any(t in aliases for t in rdata_names(rp, r)):
                    return False
        return True
    return memo(e, "targets_not_aliases", compute)


# RFC 2181 10.3: the target of an NS or MX record has address records: a name the session shows to have none (NXDOMAIN, or no data for
# both A and AAAA) is no target
def targets_have_addresses(e):
    def compute():
        facts = facts_now(e)
        for t in facts.targets:
            if t in facts.absent or {1, 28} <= facts.nodata.get(t, set()):
                return False
        return True
    return memo(e, "targets_have_addresses", compute)


# RFC 3596 3 / RFC 1035 3.3.9: the reply to an NS, SRV or MX query adds the addresses of the target
# that the server has locally: where an authoritative answer of the session showed the address of the target
def additional_addresses(e):
    def compute():
        hist = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or not rp["aa"] or rp["rcode"] != 0 or rp["opcode"] != 0
                    or rq["opcode"] != 0 or not rq["questions"] or rq["questions"][0][1] not in (2, 15, 33)):
                continue   # (RFC 3596 3 names the queries for NS, SRV and MX; a reply to ANY has no additional processing at BIND)
            have = {(r["name"], r["type"]) for r in rp["rrs"] if r["section"] == "ar"}
            limit = 65535
            if TRANSPORT == "udp":
                limit = 512
                for r in opt_of(rq):
                    limit = max(512, r["class"])
            for r in rp["rrs"]:
                if r["section"] == "an" and r["type"] in (2, 15):
                    for t in rdata_names(rp, r):
                        for at, count in hist.addresses.get(t, {}).items():
                            # (RFC 2181 9: the entire RRset of additional data that does not fit is left out, without TC: the whole address RRset
                            # as an earlier authoritative answer showed it, one 16 / 28 octet RR per address, must fit in what is left of the limit)
                            if (t, at) not in have and rp["len"] + count * (16 if at == 1 else 28) <= limit:
                                return False
        return True
    return memo(e, "additional_addresses", compute)


# RFC 6891 7: a FORMERR to an OPT-bearing request carries an OPT where the session shows that the responder implements EDNS
def edns_formerr_has_opt(e):
    def compute():
        if not facts_now(e).opt:
            return True
        for rq, rp in pairs(e):
            if rq is not None and rp is not None and opt_of(rq) and rp["rcode"] == 1 and not opt_of(rp):
                return False
        return True
    return memo(e, "edns_formerr_has_opt", compute)


# RFC 6891 7: a responder that does not implement EDNS (an earlier plain OPT query was answered FORMERR without OPT) answers every query with an OPT
# (an AXFR query with an OPT included, RFC 5936 2.1.5) with FORMERR and sends no OPT
def no_opt_without_edns(e):
    def compute():
        if not session_state(e)[1].no_edns:
            return True
        return all(rp is None or (not opt_of(rp) and (rq is None or not opt_of(rq) or rp["rcode"] == 1)) for rq, rp in pairs(e))
    return memo(e, "no_opt_without_edns", compute)


# RFC 6891 6.1.2: option codes a responder does not understand are ignored: the unassigned codes of sent queries are never answered
# with FORMERR by a responder that implements EDNS (shown by an OPT in this or an earlier reply)
def unknown_options_ignored(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if rq is None or rp is None or not rq["questions"] or rq["questions"][0][2] != 1 or rq["questions"][0][1] >= 128:
                continue   # (other QCLASS values and the TYPE range 128-255 reserved for query/meta types draw FORMERR/REFUSED/NOTIMP at some servers)
            if unsupported_version(rq) or rp["rcode"] != 1 or not (opt_of(rp) or facts.opt):
                continue
            msg = rq["msg"]
            for r in opt_of(rq):
                off, end = r["rdoff"], r["rdoff"] + r["rdlen"]
                while off + 4 <= end:
                    code, length = struct.unpack(">HH", msg[off:off + 4])
                    if 100 <= code <= 20000 or 27000 <= code <= 65534:
                        return False
                    off += 4 + length
        return True
    return memo(e, "unknown_options_ignored", compute)


# RFC 4343 3: names are compared case-insensitively, so a name that an earlier authoritative reply of the session answered is not
# answered with a name error later (whatever the case of the QNAME)
def qname_case_insensitive(e):
    def compute():
        answered = session_state(e)[1].answered
        for rq, rp in pairs(e):
            if rq is None or rp is None or rq["opcode"] != 0 or len(rq["questions"]) != 1 or rq["questions"][0][2] != 1:
                continue
            if rp["aa"] and rp["rcode"] == 3 and rp["an"] == 0 and rq["questions"][0][0] in answered:
                return False
        return True
    return memo(e, "qname_case_insensitive", compute)


# RFC 1034 4.3.4 / RFC 2181 7.1: an SOA added to a reply belongs in the authority section (the Answer section for SOA/ANY queries); it is the SOA of the
# zone the data or the name error comes from: an ancestor of the name the answer ends on (after the CNAME chain of the reply)
def soa_placement(rq, rp):
    if rq["opcode"] != 0 or not rq["questions"]:
        return True
    qtype = rq["questions"][0][1]
    final = final_name(rq, rp)[0]
    for r in rp["rrs"]:
        if r["type"] == 6:
            if r["section"] == "ar":
                return False
            if r["section"] == "an" and qtype not in (6, 255, 252, 251):
                return False
            if r["section"] == "ns" and not under(final, r["name"]):
                return False
    return True


# RFC 1034 4.3.4: the SOA of a negative answer is that of the most specific zone the session shows for the name (no SOA of an enclosing zone where an
# earlier authoritative reply showed the apex of a zone below it that contains the name)
def soa_zone(e):
    def compute():
        apexes = facts_now(e).apexes   # (the replies of this exchange too: a pipelined pair shows the apex in either reply)
        for rq, rp in pairs(e):
            if rq is None or rp is None or rq["opcode"] != 0 or len(rq["questions"]) != 1 or not rp["aa"]:
                continue
            final = final_name(rq, rp)[0]
            ds_query = rq["questions"][0][1] == 43
            for r in rp["rrs"]:
                # (RFC 4035 3.1.4.1: the DS RRset of a zone lives on the parent side of the cut: a DS query for the apex of a zone the
                # session shows is answered from the parent zone, whose SOA is not that of the child)
                if r["type"] == 6 and r["section"] == "ns" and any(
                        under(final, a) and label_count(a) > label_count(r["name"]) and not (ds_query and a == final)
                        for a in apexes):
                    return False
        return True
    return memo(e, "soa_zone", compute)


# RFC 2181 10.1: a name that owns a CNAME owns no other data (except RRSIG, NSEC, KEY): across the replies of the session, not only within one reply
def cname_session(e):
    def compute():
        return not any(5 in t and t - {5, 25, 46, 47} for t in facts_now(e).types.values())
    return memo(e, "cname_session", compute)


# RFC 6604 3: the RCODE of a reply with a CNAME chain is that of the final query cycle: NOERROR when the chain ends in data of the queried type, and
# the answer of the session about the name the chain ends on otherwise: NXDOMAIN where an earlier authoritative reply showed it does not exist,
# NOERROR where one showed it exists (the chain is followed in the reply itself)
def xname_final(e):
    def compute():
        hist = session_state(e)[1]
        for rq, rp in pairs(e):
            if rq is None or rp is None or rq["opcode"] != 0 or not rq["questions"] or rp["tc"] or not rp["aa"]:
                continue
            name, hops = final_name(rq, rp)
            if not hops or any(r["section"] == "an" and r["name"] == name and r["type"] != 5 for r in rp["rrs"]):
                continue
            if (rp["rcode"] == 0 and name in hist.absent) or (rp["rcode"] == 3 and name in hist.answered):
                return False
        return True
    return memo(e, "xname_final", compute)


# RFC 6604 3: the RCODE of a reply with a CNAME chain is that of the final query cycle: NOERROR when the chain ends in data of the
# queried type
def final_name(rq, rp):
    """(the name after the CNAME chain of the answer, the number of CNAMEs followed)"""
    name = rq["questions"][0][0]
    if rq["questions"][0][1] in (5, 255):
        return name, 0   # a CNAME query and an ANY query are answered by the CNAME itself: the chain is not followed
    aliases = {}
    for r in rp["rrs"]:
        if r["section"] == "an" and r["type"] == 5:
            target = decode_name(rp["msg"], r["rdoff"])
            if target is not None:
                aliases[r["name"]] = target[0]
    hops = 0
    while name in aliases and hops < 20:
        name = aliases[name]
        hops += 1
    return name, hops


def xname_rcode(rq, rp):
    if rq["opcode"] != 0 or not rq["questions"] or rp["tc"]:
        return True
    qtype = rq["questions"][0][1]
    name, hops = final_name(rq, rp)
    if hops and rp["rcode"] != 0 and any(r["section"] == "an" and r["name"] == name and (r["type"] == qtype or qtype == 255)
                                         for r in rp["rrs"]):
        return False
    return True


# RFC 4035 3 / 3.2.2: a security-aware name server MUST copy the CD bit of a query into the response; RFC 4035 3.1.6 says it SHOULD clear CD when
# composing an authoritative response, the conflict is not settled, so authoritative replies (AA = 1) are not judged.  Every other reply (a referral, a
# REFUSED, an error) is judged wherever the server is shown security-aware: an OPT with DO in the reply, or an RRSIG RR in the session (a DS or DNSKEY RR alone is zone data a server may serve unaware)
def cd_copied(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if rq is None or rp is None or rq["opcode"] != 0 or rp["aa"] or (rq["questions"] and rq["questions"][0][1] == 252):
                continue   # (the CD bit of an AXFR query is "n/a", RFC 5936 2.1.1; the replies' Z, AD and CD are zero)
            aware = any((r["ttl"] >> 15) & 1 for r in opt_of(rp)) or facts.rrsig_seen
            if aware and rq["cd"] != rp["cd"]:
                return False
        return True
    return memo(e, "cd_copied", compute)


# --- DNSSEC (RFC 4033-4035): what a reply to a DO query from a signed zone must show.  A zone is shown signed by RRSIG signer names and
# of the replies of the session (this reply included; a DNSKEY RRset served as plain data shows no signed zone); names below a known zone cut belong to the child zone.
def do_query(rq):
    return any((r["ttl"] >> 15) & 1 for r in opt_of(rq))


def labels_of(name):
    return [x for x in name.split(b".") if x]


def zone_signed(name, facts):
    """The zone of name is shown signed: a signer name of the session is above it, and no apex shown below the signer contains it (a zone the session shows without a
    signer, served below a signed zone).  A name below a cut the session shows belongs to the child zone: it is signed only where the session shows a signer
    at or below that cut (a signed child zone)."""
    signers = [z for z in facts.signers if under(name, z)]
    if not signers:
        return False
    best = max(signers, key=label_count)
    for c in facts.cuts:
        if name != c and under(name, c) and not under(best, c):
            return False
    return not any(under(name, a) and label_count(a) > label_count(best) for a in facts.apexes)


def zone_shown(name, facts, rp=None):
    """The zone of name is shown signed: zone_signed (an RRSIG signer or a zone key DNSKEY above it), an NSEC in the reply being judged, or an NSEC an earlier reply of
    the session showed in the same zone (a reply to a query without DO shows an NSEC for the NSEC type without any RRSIG), or a DS RRset at or above the name (a secure
    delegation): the zone is the deepest apex the session
    shows above the name, and the NSEC owner is in it, not below one of its cuts nor in a zone below it."""
    if zone_signed(name, facts) or (rp is not None and nsec_shown(rp)):
        return True
    if any(under(name, d) for d in facts.ds):
        return True   # (RFC 4035 2.4: a DS RRset shows the zone below the cut signed, a secure delegation)
    apexes = [a for a in facts.apexes if under(name, a)]
    if not apexes or not facts.nsec_owners:
        return False
    z = max(apexes, key=label_count)
    deeper = [a for a in facts.apexes if label_count(a) > label_count(z)]
    cuts = [c for c in facts.cuts if c != z and under(c, z)]
    return any(under(o, z) and not any(under(o, a) for a in deeper) and not any(o != c and under(o, c) for c in cuts) for o in facts.nsec_owners)


def nsec_shown(rp):
    """An NSEC RR in a reply shows a signed zone (NSEC RRs exist only there)."""
    return any(r["type"] == 47 for r in rp["rrs"])


def rrsigs_of(rp):
    """[(section, owner, covered type, algorithm, labels, signer, record)] of the RRSIG RRs of a reply"""
    c = rp.get("_sigs")
    if c is None:
        c = []
        msg = rp["msg"]
        for r in rp["rrs"]:
            if r["type"] == 46 and r["rdlen"] >= 19:
                o = r["rdoff"]
                signer = decode_name(msg, o + 18)
                c.append((r["section"], r["name"], struct.unpack(">H", msg[o:o + 2])[0], msg[o + 2], msg[o + 3],
                          signer[0] if signer else None, r))
        rp["_sigs"] = c
    return c


def nsec_records(rp):
    """[(owner, next domain name, type set or None, record)] of the NSEC RRs of the authority section"""
    c = rp.get("_nsecs")
    if c is None:
        c = []
        msg = rp["msg"]
        for r in rp["rrs"]:
            if r["type"] == 47 and r["section"] == "ns":
                end = r["rdoff"] + r["rdlen"]
                nxt = decode_name(msg, r["rdoff"])
                after = uncompressed_name_end(msg, r["rdoff"], end)
                types = type_bitmap(msg, after, end) if after is not None else None
                c.append((r["name"], nxt[0] if nxt else None, types, r))
        rp["_nsecs"] = c
    return c


def canonical_key(name):
    return [label for label in reversed(name.split(b".")) if label]


# RFC 4034 6.1: canonical name order (labels from the right, lower case); an NSEC covers the names between its owner and its next domain
# name, the last NSEC wraps around to the apex
def nsec_covers(owner, nxt, name):
    o, n, q = canonical_key(owner), canonical_key(nxt), canonical_key(name)
    return (o < q < n) or (n <= o and (q > o or q < n))


def closest_encloser(name, nsecs):
    """RFC 4035 3.1.3.2: the closest encloser, from the NSEC that covers the name"""
    best = []
    la = labels_of(name)
    for owner, nxt, types, r in nsecs:
        if nxt is not None and nsec_covers(owner, nxt, name):
            for other in (owner, nxt):
                lb = labels_of(other)
                n = 0
                while n < min(len(la), len(lb)) and la[-1 - n] == lb[-1 - n]:
                    n += 1
                if n > len(best):
                    best = la[len(la) - n:]
    return b".".join(best)


# RFC 4035 3.1.1: in a signed zone the RRsets of the Answer section of a DO reply come with their RRSIGs in that section
def signed_answers(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or not rp["aa"] or not rq["questions"] or not do_query(rq)
                    or rq["questions"][0][1] in (251, 252)):
                continue   # (RFC 4035 3.1.5: DNSSEC does not change the zone transfer process, IXFR included)
            covered = {(x[1], x[2]) for x in rrsigs_of(rp) if x[0] == "an"}
            covered_ar = {(x[1], x[2]) for x in rrsigs_of(rp) if x[0] == "ar"}
            limit = 65535
            if TRANSPORT == "udp":
                limit = 512
                for o in opt_of(rq):
                    limit = max(512, o["class"])
            for r in rp["rrs"]:
                # RFC 4035 3.1.1: a signed RRset placed in the Additional section comes with its RRSIGs there; where space does not permit both the RRset and its
                # RRSIGs the RRSIGs may be dropped (an RRSIG RR takes at least 32 octets)
                if (r["section"] == "ar" and r["type"] not in (41, 46) and (r["name"], r["type"]) not in covered_ar and zone_signed(r["name"], facts)
                        and rp["len"] + 32 <= min(limit, facts.maxlen)):
                    return False
            dnames = {r["name"] for r in rp["rrs"] if r["section"] == "an" and r["type"] == 39}
            for r in rp["rrs"]:
                if r["type"] == 5 and any(r["name"] != d and under(r["name"], d) for d in dnames):
                    continue   # RFC 4035 3: a CNAME synthesized from a DNAME is not signed (SHOULD NOT)
                # (RFC 4035 2.4: a DS RRset is always signed)
                if (r["section"] == "an" and r["type"] not in (41, 46) and (r["name"], r["type"]) not in covered
                        and (r["type"] == 43 or zone_shown(r["name"], facts, rp))):
                    return False
        return True
    return memo(e, "signed_answers", compute)


# RFC 4035 3.1.1 / 3.1.4: the SOA, NS, DS and NSEC RRsets of the Authority section of a DO reply come with their RRSIGs: the RRsets of
# the signed zone of an authoritative reply; the DS and NSEC RRsets of a referral (whose NS RRset is not signed, RFC 4035 2.2)
def authority_signed(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or rq["opcode"] != 0 or rp["opcode"] != 0 or not do_query(rq)
                    or any(q[1] in (251, 252) for q in rq["questions"])):
                continue   # (RFC 4035 3.1.5: DNSSEC does not change the zone transfer process)
            sigs = {(x[1], x[2]) for x in rrsigs_of(rp) if x[0] == "ns"}
            for r in rp["rrs"]:
                if r["section"] != "ns":
                    continue
                if rp["aa"]:
                    if (r["type"] in (2, 6, 43, 47) and (r["type"] == 43 or zone_shown(r["name"], facts, rp))
                            and (r["name"], r["type"]) not in sigs):
                        return False
                elif r["type"] in (43, 47) and (r["name"], r["type"]) not in sigs:
                    return False
        return True
    return memo(e, "authority_signed", compute)


# RFC 4035 3.1.3 / 3.1.3.1 / 3.1.3.2 / 3.1.3.4: an authoritative negative answer to a DO query from a signed zone: the SOA and the NSECs
# with their RRSIGs; no data: the NSEC of the name whose type bit map lacks the type (for an empty non-terminal the NSEC covering it; for a
# wildcard the NSEC of the wildcard and the NSEC covering the next closer name); name error: the NSEC covering the name and the NSEC
# covering the wildcard at the closest encloser.  NSEC3 (RFC 5155, left out by the manifest) is accepted without these rules.
def negative_proofs(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or not rp["aa"] or rq["opcode"] != 0 or rp["opcode"] != 0
                    or len(rq["questions"]) != 1 or not do_query(rq) or rp["rcode"] not in (0, 3) or full_rcode(rp) != rp["rcode"]):
                continue   # (an extended RCODE in the OPT of the reply makes it no NOERROR / NXDOMAIN answer)
            qname, qtype, qclass = rq["questions"][0][:3]
            if qtype in (251, 252) or qclass != 1:
                continue   # (a transfer query has no negative answer of this kind)
            name, hops = final_name(rq, rp)
            authority = [r for r in rp["rrs"] if r["section"] == "ns"]
            if any(r["type"] == 50 for r in authority) or not zone_shown(name, facts, rp):
                continue
            if rp["rcode"] == 0 and (any(r["section"] == "an" and r["name"] == name and (r["type"] != 46 or qtype == 46) for r in rp["rrs"])
                                     or (any(r["type"] == 2 for r in authority) and not any(r["type"] == 6 for r in authority))):
                continue   # (a referral: NS and no SOA; an NS RRset next to the SOA is a no-data answer, RFC 2308 2.2)
            nsecs = nsec_records(rp)
            sigs = {(x[1], x[2]) for x in rrsigs_of(rp) if x[0] == "ns"}
            soa = [r for r in authority if r["type"] == 6]
            if not soa or (soa[0]["name"], 6) not in sigs or not nsecs:
                return False
            if any(x[1] is None or x[2] is None or (x[0], 47) not in sigs for x in nsecs):
                return False
            if rp["rcode"] == 3:
                if not any(nsec_covers(x[0], x[1], name) for x in nsecs):
                    return False
                ce = closest_encloser(name, nsecs)
                wildcard = b"*." + ce if ce else b"*"
                if not any(nsec_covers(x[0], x[1], wildcard) for x in nsecs):
                    return False
                continue
            ok = False
            for x in nsecs:
                if x[0] == name:
                    ok = qtype not in x[2]
                    break
            else:
                for y in nsecs:
                    if nsec_covers(y[0], y[1], name) and under(y[1], name):
                        ok = True   # empty non-terminal
                    lab = labels_of(y[0])
                    if lab and lab[0] == b"*":
                        zone = b".".join(lab[1:])
                        if name != zone and under(name, zone):
                            ln = labels_of(name)
                            nc = b".".join(ln[len(ln) - len(lab):])   # next closer name
                            if qtype not in y[2] and any(nsec_covers(z[0], z[1], nc) for z in nsecs):
                                ok = True
            if not ok:
                return False
        return True
    return memo(e, "negative_proofs", compute)


# RFC 4035 3.1.3.3: a wildcard-expanded answer (an RRSIG whose Labels field is smaller than the label count of its owner) to a DO query
# comes with the NSEC (and its RRSIG) proving that no closer match exists
def wildcard_answer(e):
    def compute():
        for rq, rp in pairs(e):
            if rq is None or rp is None or rp["tc"] or not rp["aa"] or rp["rcode"] != 0 or not do_query(rq) or rq["opcode"] != 0:
                continue
            if any(r["type"] == 50 for r in rp["rrs"] if r["section"] == "ns") or any(
                    q[1] in (46, 47) for q in rq["questions"]):
                continue   # (a query for the NSEC or RRSIG type asks for the DNSSEC RRs themselves, which carry no proof of their own expansion)
            nsecs = nsec_records(rp)
            sigs = {(x[1], x[2]) for x in rrsigs_of(rp) if x[0] == "ns"}
            for x in rrsigs_of(rp):
                if x[0] != "an":
                    continue
                owner_labels = labels_of(x[1])
                count = len(owner_labels) - (1 if owner_labels[:1] == [b"*"] else 0)
                if x[4] < count:
                    nc = b".".join(owner_labels[-(x[4] + 1):])
                    if not any(nsec_covers(z[0], z[1], nc) and (z[0], 47) in sigs for z in nsecs):
                        return False
        return True
    return memo(e, "wildcard_answer", compute)


# RFC 4035 3.1.4: a referral to a DO query from a signed zone carries the DS RRset with its RRSIG, or the NSEC (with its RRSIG, its type bit
# map lacking DS) proving there is none, and then the NS RRset comes first; the NS RRset and the glue are not signed (RFC 4035 2.2)
def referral_signed(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or rq["opcode"] != 0 or not do_query(rq) or rp["aa"] or rp["rcode"] != 0
                    or rp["an"] != 0):
                continue
            authority = [r for r in rp["rrs"] if r["section"] == "ns"]
            ns = [r for r in authority if r["type"] == 2]
            if not ns or any(r["type"] == 6 for r in authority):
                continue
            cut = ns[0]["name"]
            types = [r["type"] for r in authority]
            if not (zone_signed(cut, facts) or any(t in (43, 46, 47) for t in types)):
                continue
            sigs = {(x[1], x[2]) for x in rrsigs_of(rp) if x[0] == "ns"}
            if (cut, 2) in sigs:
                return False
            for x in rrsigs_of(rp):
                if x[0] == "ar" and x[2] in (1, 28) and x[1] != cut and under(x[1], cut):
                    return False
            if 50 in types:
                continue
            nsec = [x for x in nsec_records(rp) if x[0] == cut]
            if any(r["type"] == 43 and r["name"] == cut for r in authority):
                if (cut, 43) not in sigs:
                    return False
            elif nsec:
                if nsec[0][2] is None or 43 in nsec[0][2] or 2 not in nsec[0][2] or (cut, 47) not in sigs:
                    return False
                last_ns = max(i for i, r in enumerate(authority) if r["type"] == 2)
                first_nsec = min(i for i, r in enumerate(authority)
                                 if r["type"] == 47 or (r["type"] == 46 and (r["name"], 47) in sigs and r["rdlen"] >= 2
                                                        and struct.unpack(">H", rp["msg"][r["rdoff"]:r["rdoff"] + 2])[0] == 47))
                if last_ns > first_nsec:
                    return False
            else:
                return False
        return True
    return memo(e, "referral_signed", compute)


# RFC 4034 3 / RFC 4035 2.2: an RRSIG has the class and TTL of the RRset it covers, its Original TTL is not below that TTL, its Labels field does not
# exceed the owner's label count (without a leading wildcard label), RRSIG RRsets are not signed; its Signer's Name is the name of the zone of the covered
# RRset: the owner itself for an SOA, DNSKEY or NS RRset (an RRSIG over an NS RRset exists only at the apex: the NS RRset of a delegation is not signed),
# the closest apex the session shows above the owner otherwise (the parent's for a DS RRset and an NSEC at a cut); where the session shows the DNSKEY
# RRset of the signer, Algorithm and Key Tag name a zone key with protocol 3 in it (several keys may share a tag: one of them must match)
def rrsig_rules(e):
    def compute():
        facts = facts_now(e)
        zones = facts.apexes | facts.signers
        for rq, rp in pairs(e):
            if rp is None:
                continue
            msg = rp["msg"]
            by_set = {}
            for r in rp["rrs"]:
                by_set.setdefault((r["name"], r["type"], r["class"]), []).append(r)
            for section, owner, covered, alg, labels, signer, r in rrsigs_of(rp):
                o = r["rdoff"]
                if covered == 46 or signer is None:
                    return False
                original_ttl = struct.unpack(">I", msg[o + 4:o + 8])[0]
                tag = struct.unpack(">H", msg[o + 16:o + 18])[0]
                owner_labels = labels_of(owner)
                if owner_labels[:1] == [b"*"]:
                    owner_labels = owner_labels[1:]
                if labels > len(owner_labels) or not under(owner, signer):
                    return False
                if covered in (2, 6, 48) and signer != owner:
                    return False
                if covered == 2 and owner in facts.cuts:
                    return False
                parent_side = covered == 43 or (covered == 47 and owner in facts.cuts)
                candidates = [z for z in zones if z != b"" and under(owner, z) and not (parent_side and z == owner)]
                if candidates and signer != max(candidates, key=label_count):
                    return False
                if parent_side and signer == owner:
                    return False
                for key, group in by_set.items():
                    if key[0] == owner and key[1] == covered:
                        for c in group:
                            # (the RRset TTL is the Original TTL, or lower where the server lowered it, e.g. BIND's TTL 0 for the SOA of a negative
                            # answer to an SOA query: RFC 4034 3.1.4 defines Original TTL as the TTL in the zone, RFC 4034 3 requires the RRSIG's TTL
                            # to equal the TTL of the RRset it covers)
                            if c["class"] != r["class"] or eff_ttl(c["ttl"]) != eff_ttl(r["ttl"]) or eff_ttl(c["ttl"]) > eff_ttl(original_ttl):
                                return False
        # (RFC 4035 2.2: the NS RRset at a cut and glue address RRsets below it are not signed: no RRSIG of the session covers them, whichever exchange showed it)
        for owner, covered in facts.sigcover:
            if covered == 2 and owner in facts.cuts and owner not in facts.apexes:
                return False
            if covered in (1, 28) and any(owner != c and under(owner, c) and c not in facts.apexes for c in facts.cuts):
                return False
        # (RFC 4034 B / RFC 4035 5.3.1: the Key Tag of every RRSIG of the session, from whichever exchange, against the DNSKEY RRset the session shows for its signer,
        # whichever came first)
        for signer, tag, alg in facts.sigkeys:
            keys = facts.dnskeys.get(signer)
            if keys and not any(k[2] == alg and k[1] == 3 and k[0] & 0x100 for k in keys.get(tag, ())):
                return False
        return True
    return memo(e, "rrsig_rules", compute)


# RFC 4034 3.1.8 / RFC 4035 5.3.1: the Signature of an RRSIG is a signature over the RRSIG RDATA (without the signature) and the canonical form
# (RFC 4034 6.2, 6.3) of the covered RRset, made with the DNSKEY the Key Tag, Algorithm and Signer's Name name.  Verified where the session shows
# that DNSKEY: ECDSAP256SHA256 (13) and RSA/SHA-1, RSA/SHA-256, RSA/SHA-512 (5, 7, 8, 10); other algorithms are not checked.
P256 = (2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1, -3, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def ec_add(P, Q, curve):
    if P is None:
        return Q
    if Q is None:
        return P
    p, a = curve[0], curve[1]
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def ec_mul(k, P, curve):
    result = None
    while k:
        if k & 1:
            result = ec_add(result, P, curve)
        P = ec_add(P, P, curve)
        k >>= 1
    return result


def ecdsa_verify(curve, public, digest, r, s):
    p, a, b, n, gx, gy = curve
    x, y = public
    if not (0 < r < n and 0 < s < n) or (y * y - (x * x * x + a * x + b)) % p != 0:
        return False
    w = pow(s, -1, n)
    e = int.from_bytes(digest, "big")
    point = ec_add(ec_mul(e * w % n, (gx, gy), curve), ec_mul(r * w % n, (x, y), curve), curve)
    return point is not None and point[0] % n == r


RSA_PREFIX = {"sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
              "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
              "sha512": bytes.fromhex("3051300d060960864801650304020305000440")}


def rsa_verify(public, signature, hash_name, digest):
    if len(public) < 3:
        return False
    if public[0] == 0:
        elen, off = int.from_bytes(public[1:3], "big"), 3
    else:
        elen, off = public[0], 1
    exponent, modulus = int.from_bytes(public[off:off + elen], "big"), int.from_bytes(public[off + elen:], "big")
    if modulus == 0:
        return False
    k = (modulus.bit_length() + 7) // 8
    t = RSA_PREFIX[hash_name] + digest
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(k, "big") == expected


NAME_TYPES = (2, 3, 4, 5, 7, 8, 9, 12)


def canonical_rdata(rp, r):
    """RDATA in canonical form (RFC 4034 6.2: names inside lower-cased and uncompressed), None where this grammar cannot tell it."""
    msg, o, n, t = rp["msg"], r["rdoff"], r["rdlen"], r["type"]
    if t in NAME_TYPES:
        d = decode_name(msg, o)
        return wire_name(d[0]) if d else None
    if t == 15:
        d = decode_name(msg, o + 2)
        return msg[o:o + 2] + wire_name(d[0]) if d else None
    if t in (6, 14):
        d1 = decode_name(msg, o)
        d2 = decode_name(msg, d1[1]) if d1 else None
        return wire_name(d1[0]) + wire_name(d2[0]) + msg[d2[1]:o + n] if d2 else None
    if t in (17, 18, 21, 24, 26, 30, 33, 35, 36, 38, 39):
        return None   # RDATA with names this grammar does not parse
    return msg[o:o + n]


def signature_input(rp, sig, group):
    """Data an RRSIG signs, or None; sig is an item of rrsigs_of, group the RRs of the covered RRset."""
    section, owner, covered, alg, labels, signer, r = sig
    msg, o = rp["msg"], r["rdoff"]
    signer_end = uncompressed_name_end(msg, o + 18, o + r["rdlen"])
    if signer_end is None:
        return None, None
    owner_labels = labels_of(owner)
    count = len(owner_labels) - (1 if owner_labels[:1] == [b"*"] else 0)
    owner_wire = wire_name(owner) if labels >= count else wire_name(b".".join([b"*"] + owner_labels[len(owner_labels) - labels:]))
    original_ttl = msg[o + 4:o + 8]
    items = set()
    for g in group:
        rdata = canonical_rdata(rp, g)
        if rdata is None:
            return None, None
        items.add((rdata, owner_wire + struct.pack(">HH", g["type"], g["class"]) + original_ttl + struct.pack(">H", len(rdata)) + rdata))
    data = msg[o:o + 18] + wire_name(signer) + b"".join(x[1] for x in sorted(items))
    return data, msg[signer_end:o + r["rdlen"]]


def signatures_valid(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if rp is None or rp["tc"]:
                continue
            for sig in rrsigs_of(rp):
                section, owner, covered, alg, labels, signer, r = sig
                keys = facts.dnskeys.get(signer)
                if not keys or alg not in (5, 7, 8, 10, 13):
                    continue
                tag = struct.unpack(">H", rp["msg"][r["rdoff"] + 16:r["rdoff"] + 18])[0]
                candidates = [k for k in keys.get(tag, ()) if k[2] == alg]
                if not candidates:
                    continue
                group = [g for g in rp["rrs"] if g["section"] == section and g["name"] == owner and g["type"] == covered and g["class"] == r["class"]]
                if not group:
                    continue
                data, signature = signature_input(rp, sig, group)
                if data is None:
                    continue
                ok = False
                for key in candidates:
                    public = key[3][4:]
                    if alg == 13:
                        if len(public) == 64 and len(signature) == 64:
                            ok = ecdsa_verify(P256, (int.from_bytes(public[:32], "big"), int.from_bytes(public[32:], "big")),
                                              hashlib.sha256(data).digest(), int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
                    else:
                        name = {5: "sha1", 7: "sha1", 8: "sha256", 10: "sha512"}[alg]
                        ok = rsa_verify(public, signature, name, hashlib.new(name, data).digest())
                    if ok:
                        break
                if not ok:
                    return False
        return True
    return memo(e, "signatures_valid", compute)


# RFC 4034 5 / RFC 4035 2.4: a DS RRset is never at a zone apex (an SOA owner the session shows, in whatever order); every DS RR of the session, whichever
# exchange showed it, is compared with the DNSKEYs of its owner the session shows (in whatever order): the DS matches one of them: Key Tag and Algorithm are the key's and the Digest is the digest of owner name and DNSKEY RDATA
# (digest types 1, 2 and 4), found by the digest as well as by the claimed tag
def ds_rules(e):
    def compute():
        facts = facts_now(e)
        # RFC 4035 2.4: a DS RRset is never at the apex of the zone it lives in: its RRSIG is not made by the zone that owns the name (a server
        # that is authoritative for the parent and the child shows the same name as DS owner of the parent and as SOA owner of the child)
        if any(owner == signer for owner, signer in facts.ds_signers):
            return False
        for owner, entries in facts.ds.items():
            keys = facts.dnskeys.get(owner, {})
            if not keys:
                continue   # RFC 4035 2.4: a DS SHOULD name a DNSKEY of the child apex; none shown, nothing to compare
            for tag, alg, dtype, digest in entries:
                hash_name = {1: "sha1", 2: "sha256", 4: "sha384"}.get(dtype)
                named = []
                if hash_name is not None:
                    named = [(t, k) for t, ks in keys.items() for k in ks
                             if hashlib.new(hash_name, wire_name(owner) + k[3]).digest() == digest]
                if named:
                    if not any(t == tag and k[2] == alg for t, k in named):
                        return False   # the digest names a DNSKEY whose tag or algorithm the DS does not carry
                    continue
                if any(k[2] == alg for k in keys.get(tag, ())):
                    if hash_name is not None:
                        return False   # the DNSKEY the tag and algorithm name has another digest
                elif keys.get(tag):
                    return False       # a DNSKEY of that tag is shown, none of that algorithm
        return True
    return memo(e, "ds_rules", compute)


# RFC 4035 2.2: each signed RRset of any section of a reply (authoritative or a referral, Additional section included) has an RRSIG with each algorithm of the
# apex DNSKEY RRset of its signer shown in the session; the apex DNSKEY RRset has one for each algorithm of the DS RRset shown for it
def signing_algorithms(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if rq is None or rp is None or rp["tc"] or rq["opcode"] != 0 or not do_query(rq):
                continue
            sigs = rrsigs_of(rp)
            for section in ("an", "ns", "ar"):
                for name, rtype in {(r["name"], r["type"]) for r in rp["rrs"] if r["section"] == section and r["type"] not in (41, 46)}:
                    mine = [x for x in sigs if x[0] == section and x[1] == name and x[2] == rtype]
                    if not mine:
                        continue
                    got = {x[3] for x in mine}
                    need = {k[2] for ks in facts.dnskeys.get(mine[0][5], {}).values() for k in ks}
                    if need and not need <= got:
                        return False
                    if rtype == 48:
                        ds_algs = {d[1] for d in facts.ds.get(name, [])}
                        if ds_algs and not ds_algs <= got:
                            return False
        return True
    return memo(e, "signing_algorithms", compute)


# RFC 4035 3.1.4.1: a server authoritative for a child zone but (shown by a REFUSED for the parent) not for the parent, without recursion,
# answers a DS query for the child's apex with an authoritative no-data answer (a query with two OPT RRs or an OPT that is not owned by the root is malformed,
# RFC 6891 6.1.1 / 6.1.2: the reply to it is judged by formerr_reply, not here)
def ds_at_child_apex(e):
    def compute():
        hist = session_state(e)[1]
        if hist.ra:
            return True
        for rq, rp in pairs(e):
            if rq is None or rp is None or rq.get("odd_opt") or rq["opcode"] != 0 or len(rq["questions"]) != 1 or rq["questions"][0][1] != 43 or rq["questions"][0][2] != 1:
                continue
            qname = rq["questions"][0][0]
            if rp["tc"] or qname not in hist.apexes or b".".join(labels_of(qname)[1:]) not in hist.refused:
                continue
            if not (rp["aa"] and rp["rcode"] == 0 and rp["an"] == 0 and any(r["type"] == 6 for r in rp["rrs"] if r["section"] == "ns")):
                return False
        return True
    return memo(e, "ds_at_child_apex", compute)


# RFC 4034 4.1.1 / RFC 4035 2.3: glue-only names (names below a zone cut the session shows: a referral, a DS RRset, an NSEC bit map with NS and no SOA) have no NSEC
# and are no next domain name: the NSEC RRs of every reply of the session (any section), compared with the cuts shown so far
def nsec_glue(e):
    def compute():
        facts = facts_now(e)
        return not any(n != c and under(n, c) for n in facts.nsec_names for c in facts.cuts if c not in facts.apexes)
    return memo(e, "nsec_glue", compute)


def zone_of(name, facts):
    """The deepest apex or signer the session shows above name (None when it shows none)."""
    zones = [z for z in facts.apexes | facts.signers if under(name, z)]
    return max(zones, key=label_count) if zones else None


# RFC 4034 4.1.1 / RFC 4035 2.3: the Next Domain Name of an NSEC is the next owner name in canonical order that has authoritative data or a delegation, and
# every such name has an NSEC: no NSEC of the session skips a name the session shows to hold authoritative data (an RRSIG showing it is no wildcard
# expansion) or a delegation in the same zone, and no NSEC owner or next domain name is a name the session shows does not exist (NXDOMAIN)
def nsec_chain(e):
    def compute():
        facts = facts_now(e)
        if not facts.nsec_pairs:
            return True
        names = [n for n in facts.datanames | facts.cuts if not any(n != c and under(n, c) for c in facts.cuts)]
        zones = {}
        for a, c in facts.nsec_pairs:
            if a in facts.absent or c in facts.absent:
                return False
            za = zones.get(a, 0)
            if za == 0:
                za = zones[a] = zone_of(a, facts)
            if za is None:
                continue
            for b in names:
                if b == a or b == c or not under(b, za) or not nsec_covers(a, c, b):
                    continue
                zb = zones.get(b, 0)
                if zb == 0:
                    zb = zones[b] = zone_of(b, facts)
                if zb == za:
                    return False
        return True
    return memo(e, "nsec_chain", compute)


# RFC 4035 2.3 / RFC 4034 4.1.2: the type bit map of an NSEC is the set of the types present at its owner: it names every type the session shows at its owner
# (authoritative data, the NS RRset at a cut) and none the session shows absent (an authoritative no-data answer for it); the NSEC at a delegation has the NS bit.
# Every NSEC the session shows, whichever exchange showed it first.
def nsec_bitmaps(e):
    def compute():
        facts = facts_now(e)
        for owner, maps in facts.nsec_maps.items():
            have = facts.types.get(owner, set())
            absent = facts.nodata.get(owner, set()) - {46, 47, 251, 252, 255}
            for bitmap in maps:
                if not have <= bitmap or absent & bitmap:
                    return False
                if owner in facts.cuts and owner not in facts.apexes and 2 not in bitmap:
                    return False
        return True
    return memo(e, "nsec_bitmaps", compute)


# RFC 4035 2.3 / 2.5: every name that holds authoritative data in a signed zone (a CNAME owner included) has an NSEC (and RRSIG) RRset: the NSEC query,
# to a DO query of the signed zone, for a name the session shows to hold authoritative data is answered with the NSEC
def cname_nsec(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or not rp["aa"] or rp["rcode"] != 0 or not do_query(rq) or rq["opcode"] != 0
                    or len(rq["questions"]) != 1 or rq["questions"][0][1] != 47 or rq["questions"][0][2] != 1):
                continue
            name = rq["questions"][0][0]
            holds = name in facts.aliases or (name in facts.types and facts.types[name] - {46, 47})
            if holds and zone_signed(name, facts) and not any(
                    r["section"] == "an" and r["type"] == 47 and r["name"] == name for r in rp["rrs"]):
                return False
        return True
    return memo(e, "cname_nsec", compute)


# RFC 4035 2.1: a signed zone shown to be a secure entry point (a DS RRset for its apex appeared in the session) or signed (an RRSIG names it as signer)
# has a DNSKEY RRset at its apex
def dnskey_at_apex(e):
    def compute():
        facts = facts_now(e)
        for rq, rp in pairs(e):
            if (rq is None or rp is None or rp["tc"] or not rp["aa"] or rp["rcode"] != 0 or rq["opcode"] != 0 or len(rq["questions"]) != 1
                    or rq["questions"][0][1] != 48 or rq["questions"][0][2] != 1):
                continue
            name = rq["questions"][0][0]
            if (name in facts.ds or name in facts.signers) and name in facts.apexes and not any(r["section"] == "an" and r["type"] == 48 and r["name"] == name for r in rp["rrs"]):
                return False
        return True
    return memo(e, "dnskey_at_apex", compute)


# RFC 4035 3.1.5: DNSSEC does not change the zone transfer process; a server "is not required to verify that a zone is properly signed before sending or
# accepting a zone transfer" (it MAY reject an improperly signed zone), so a transfer is NOT audited for how the zone is signed (RFC 4035 2.2-2.4 bind the
# signer).  What is mandatory: "the RRSIG, NSEC and DS RRs ... MUST be included in zone transfers of the zone in which they are authoritative data".  A complete
# transfer (SOA first and last) therefore includes every RRset, and every RRSIG over one, that the replies of the session showed as authoritative data of the
# zone (RFC 5936 2.2: the transfer is the zone content; a name a wildcard of the transfer may have synthesized is left out).  Only this inclusion check runs.
def axfr_dnssec(e):
    def compute():
        reqs, reps = exchange_messages(e)
        drs = [decode(r) for r in reps]
        if not drs or any(d is None for d in drs) or drs[0]["rcode"] != 0:
            return True
        owners = {}
        covered = {}
        soas = []
        for d in drs:
            for r in d["rrs"]:
                if r["type"] == 41:
                    continue
                owners.setdefault(r["name"], set()).add(r["type"])
                if r["type"] == 6:
                    soas.append(r["name"])
                elif r["type"] == 46 and r["rdlen"] >= 2:
                    covered.setdefault(r["name"], set()).add(struct.unpack(">H", d["msg"][r["rdoff"]:r["rdoff"] + 2])[0])
        if len(soas) < 2:
            return True
        apex = soas[0]
        facts = facts_now(e)
        def in_zone(n):
            deeper = zone_of(n, facts)
            return under(n, apex) and not (deeper is not None and deeper != apex and label_count(deeper) > label_count(apex)) and not any(
                n != c and under(n, c) for c in facts.cuts)

        def synthesized(n):
            labels = labels_of(n)
            return any(b"*." + b".".join(labels[i:]) in owners for i in range(1, len(labels)))   # (possibly synthesized from a wildcard)
        for n, ts in facts.types.items():
            if not in_zone(n):
                continue
            if n not in owners:
                if synthesized(n):
                    continue
                return False
            if not ts <= owners[n]:
                return False
        for n, t in facts.sigcover:
            if n in facts.datanames and n in facts.types and in_zone(n) and not synthesized(n) and t not in covered.get(n, set()):
                return False   # an RRSIG the session showed for an RRset of the zone is part of the zone
        return True
    return memo(e, "axfr_dnssec", compute)


where forall <e> in <exchange>: reply_decodes(<e>)
where forall <e> in <exchange>: qname_case_insensitive(<e>)
where forall <e> in <exchange>: reply_check(<e>, soa_placement)
where forall <e> in <exchange>: reply_check(<e>, dnssec_rdata_formats)
where forall <e> in <exchange>: rrsig_rules(<e>)
where forall <e> in <exchange>: ds_rules(<e>)
where forall <e> in <exchange>: signatures_valid(<e>)
where forall <e> in <exchange>: signed_answers(<e>)
where forall <e> in <exchange>: signing_algorithms(<e>)
where forall <e> in <exchange>: authority_signed(<e>)
where forall <e> in <exchange>: negative_proofs(<e>)
where forall <e> in <exchange>: wildcard_answer(<e>)
where forall <e> in <exchange>: referral_signed(<e>)
where forall <e> in <exchange>: ds_at_child_apex(<e>)
where forall <e> in <exchange>: nsec_glue(<e>)
where forall <e> in <exchange>: nsec_bitmaps(<e>)
where forall <e> in <exchange>: nsec_chain(<e>)
where forall <e> in <exchange>: cname_nsec(<e>)
where forall <e> in <exchange>: dnskey_at_apex(<e>)
where forall <e> in <exchange>: reply_check(<e>, xname_rcode)
where forall <e> in <exchange>: xname_final(<e>)
where forall <e> in <exchange>: cname_session(<e>)
where forall <e> in <exchange>: soa_zone(<e>)
where forall <e> in <exchange>: reply_check_all(<e>, question_matches)
where forall <e> in <exchange>: reply_check(<e>, edns_version_limited)
where forall <e> in <exchange>: cd_copied(<e>)
where forall <e> in <exchange>: referral_glue(<e>)
where forall <e> in <exchange>: targets_not_aliases(<e>)
where forall <e> in <exchange>: no_answer_below_cut(<e>)
where forall <e> in <exchange>: targets_have_addresses(<e>)
where forall <e> in <exchange>: additional_addresses(<e>)
where forall <e> in <exchange>: edns_formerr_has_opt(<e>)
where forall <e> in <exchange>: no_opt_without_edns(<e>)
where forall <e> in <exchange>: unknown_options_ignored(<e>)
where forall <e> in <exchange>: reply_check_all(<e>, reply_qdcount_one)
where forall <e> in <exchange>: reply_check_all(<e>, id_matches)
where forall <e> in <exchange>: reply_check_all(<e>, opcode_matches)
where forall <e> in <exchange>: reply_check(<e>, rd_matches)
where forall <e> in <exchange>: reply_check(<e>, opt_presence)
where forall <e> in <exchange>: reply_check(<e>, single_opt)
where forall <e> in <exchange>: reply_check(<e>, do_copied)
where forall <e> in <exchange>: reply_check(<e>, udp_size_limit)
where forall <e> in <exchange>: reply_check(<e>, pointers_backwards)
where forall <e> in <exchange>: reply_check(<e>, negative_has_soa)
where forall <e> in <exchange>: reply_check(<e>, rrset_ttl_equal)
where forall <e> in <exchange>: reply_check(<e>, cname_exclusive)
where forall <e> in <exchange>: reply_check(<e>, no_dnssec_without_do)


where forall <e> in <exchange_pipelined>: <e>..<h_id_second> == next_id(<e>)
where forall <e> in <exchange_pipelined_same_id>: <e>..<h_id_same> == first_id(<e>)
where forall <r> in <request_retry>: <r> == retry_request(<r>)
where forall <r> in <request_retry_second>: <r> == retry_second_request(<r>)
where forall <r> in <request_retry_iquery>: <r> == retry_request(<r>)
where forall <r> in <request_retry_status>: <r> == retry_request(<r>)
where forall <r> in <request_retry_qdcount_zero>: <r> == retry_request(<r>)
where forall <r> in <request_retry_qdcount_many>: <r> == retry_request(<r>)
where forall <r> in <request_retry_query_other>: <r> == retry_request(<r>)
where forall <r> in <request_retry_axfr>: <r> == retry_request(<r>)
where forall <r> in <request_retry_axfr_other>: <r> == retry_request(<r>)
# the dependent request: the QNAME is a name an earlier reply of the session named
where forall <e> in <exchange_follow>: <e>..<qname_follow> == follow_name(<e>)


# RFC 5936 2.2: the first message of a transfer copies the question of the query; an error message copies it too (RFC 5936 2.2:
# "QDCOUNT MUST be 1 if RCODE indicates an error"); the transfer ends with the SOA it began with
def axfr_checks(e):
    reqs, reps = exchange_messages(e)
    if not reqs or not reps:
        return True
    rq = decode(reqs[0])
    drs = [decode(r) for r in reps]
    if rq is None or any(d is None for d in drs) or not rq["questions"]:
        return True
    first = drs[0]
    if first["rcode"] == 0 and first["questions"] and first["questions"][0][:3] != rq["questions"][0][:3]:
        return False
    # RFC 5936 2.2.1 d): the CD bit of a transfer message "MUST" be 0 (mbz); RFC 4035 3.2.2 says the CD bit of the query MUST be copied.  The two MUSTs
    # conflict only where the query sets CD, so a message sets CD only when the query did.
    if not rq["msg"][3] & 0x10 and any(r[3] & 0x10 for r in reps):
        return False
    for d in drs:
        if d["rcode"] != 0 and (len(d["questions"]) != 1 or d["questions"][0][:3] != rq["questions"][0][:3]):
            return False
    return True


def axfr_soa_matches(e):
    reqs, reps = exchange_messages(e)
    drs = [decode(r) for r in reps]
    if not drs or any(d is None for d in drs) or drs[0]["rcode"] != 0:
        return True
    soas = [(d, r) for d in drs for r in d["rrs"] if r["type"] == 6]
    rq = decode(reqs[0])
    if rq is not None and rq["questions"] and soas and soas[0][1]["name"] != rq["questions"][0][0]:
        return False   # RFC 5936 2.2: the transfer begins with the SOA of the zone named in the query
    if len(soas) < 2:
        return True
    # compare the class, the decoded names and the five 32-bit fields (names may be compressed differently per message)
    def canon(d, r):
        n1 = decode_name(d["msg"], r["rdoff"])
        n2 = decode_name(d["msg"], n1[1])
        return (r["name"], r["class"], r["ttl"], n1[0], n2[0], d["msg"][n2[1]:n2[1] + 20])
    return canon(*soas[0]) == canon(*soas[-1])


where forall <e> in <exchange_axfr>: axfr_checks(<e>)
where forall <e> in <exchange_axfr>: axfr_soa_matches(<e>)
where forall <e> in <exchange_axfr>: axfr_dnssec(<e>)
where forall <e> in <exchange_axfr_z_set>: axfr_checks(<e>)
where forall <e> in <exchange_axfr_z_set>: axfr_soa_matches(<e>)
where forall <e> in <exchange_axfr_z_set>: axfr_dnssec(<e>)


# RFC 6891 6.1.1 / RFC 9619 4: a query with more than one OPT RR, or with OPCODE 0 and QDCOUNT > 1, MUST be answered with RCODE 1 (FORMERR)
def formerr_reply(e):
    def compute():
        return all(rp["rcode"] == 1 for rq, rp in pairs(e) if rq is not None and rp is not None)
    return memo(e, "formerr_reply", compute)


# RFC 6891 6.1.3: a VERSION the responder does not implement MUST be answered with BADVERS (extended RCODE 16); a responder that does not
# implement EDNS answers FORMERR without OPT (RFC 6891 7): BADVERS is required where the reply itself or an earlier reply of the session
# shows that the responder implements EDNS
def bad_version_reply(e):
    def compute():
        if not facts_now(e).opt:
            return True
        return all(full_rcode(rp) == 16 for rq, rp in pairs(e) if rq is not None and rp is not None)
    return memo(e, "bad_version_reply", compute)


where forall <e> in <exchange_bad_version>: bad_version_reply(<e>)
where forall <e> in <exchange_two_opt>: formerr_reply(<e>)
where forall <e> in <exchange_qdcount_many>: formerr_reply(<e>)
where forall <e> in <exchange_axfr_qdcount_two>: formerr_reply(<e>)
