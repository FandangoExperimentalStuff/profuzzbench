# =====================================================================================================================
# DAAP (Digital Audio Access Protocol) -- Fandango protocol spec.   Client = Fandango (a DAAP client), Server = the DAAP
# server under test.  Transport: one TCP connection per session (HTTP/1.1 GET requests, answers of MIME type
# application/x-dmap-tagged).  Sources: refs/spec/bjoernricks-daap.md ("bj"), daap-sourceforge-index.txt ("sf-index"),
# daap-sourceforge-server-info.txt ("sf-server-info"), daap-sourceforge-content-codes.txt ("sf-codes"),
# rfc9110.txt, rfc9112.txt.   daap.fan is built by tools/build_fan.py from tools/src/*.fan (generated parts: DMAP codes).
# =====================================================================================================================

# ---------------------------------------------------- TEST SETUP ----------------------------------------------------
# Everything the test setup decides is configured here, each value from an environment variable with a default.
import os
import re
import random
import base64
import struct

# authority (host[:port]) of the target URI; the Host header of every HTTP/1.1 request carries exactly this (rfc9112 3.2)
DAAP_AUTHORITY = os.environ.get("DAAP_AUTHORITY", "127.0.0.1:3689")
# credentials of the accepting login exchange (HTTP Basic, bj IV.3 Login)
DAAP_USERNAME = os.environ.get("DAAP_USERNAME", "daap")
DAAP_PASSWORD = os.environ.get("DAAP_PASSWORD", "secret")
# targets a request names before an earlier reply of the session has named them (each session picks from these lists)
DAAP_DATABASE_IDS = [int(x) for x in os.environ.get("DAAP_DATABASE_IDS", "1,2").split(",")]
DAAP_CONTAINER_IDS = [int(x) for x in os.environ.get("DAAP_CONTAINER_IDS", "1,2,3,4").split(",")]
DAAP_ITEM_IDS = [int(x) for x in os.environ.get("DAAP_ITEM_IDS", "1,2,3,4,5").split(",")]
DAAP_REVISION_IDS = [int(x) for x in os.environ.get("DAAP_REVISION_IDS", "1,2,5").split(",")]
# the longest body (octets) a reply may announce: the parser expands body lengths into counted repetitions, so an absurd announced length is not parsed
DAAP_MAX_BODY_BYTES = int(os.environ.get("DAAP_MAX_BODY_BYTES", "16777216"))
# seconds the client lets an /update request stay unanswered (bj IV.4: the server may hold it until the database changes)
DAAP_UPDATE_WAIT_S = os.environ.get("DAAP_UPDATE_WAIT_S", "2")
# seconds the client waits, before its first request, for the server to close the connection on its own initiative
DAAP_IDLE_WAIT_S = os.environ.get("DAAP_IDLE_WAIT_S", "0.2")
# comma-separated names of tolerated server deviations (see tolerances.json); empty by default
TOLERATED = os.environ.get("TOLERATED", "")
# ---------------------------------------------------------------------------------------------------------------------

def tolerated(name):
    return name in [x.strip() for x in TOLERATED.split(",")]

# What earlier replies of the session named (recorded while parsing replies, recalled when requests are generated)
SESSION = {}

class ClientNetworkParty(NetworkParty):
    def __init__(self, *args, **kwargs):
        SESSION.clear()
        super().__init__(*args, **kwargs)

    def receive(self, message, sender):
        if message is None:
            # the server closed the connection: delivered to the grammar as a message of the dummy party Closure
            super().receive(b"closed", sender="Closure")
            return
        super().receive(message, sender="Server")

class Closure(FandangoParty):
    """Dummy party: its message <conn_closed> stands for the server closing the TCP connection (rfc9112 9.6)."""
    def __init__(self):
        super().__init__(connection_mode=ConnectionMode.EXTERNAL)

    def start(self):
        pass

    def stop(self):
        pass

def record(kind, values):
    if values:
        SESSION.setdefault(kind, []).extend(values)
    return "1"

def recall(kind, configured):
    values = SESSION.get(kind)
    return str(random.choice(values) if values else random.choice(configured))

def recall_last(kind, configured):
    values = SESSION.get(kind)
    return str(values[-1] if values else random.choice(configured))

def from_be32(tree):
    return int.from_bytes(bytes(tree), "big")

def u32(tree):
    return int(str(tree)).to_bytes(4, "big")

def tlv(data, offset=0, end=None):
    """The (tag, value-bytes) pairs of a run of DMAP chunks."""
    end = len(data) if end is None else end
    items = []
    while offset + 8 <= end:
        length = int.from_bytes(data[offset + 4:offset + 8], "big")
        items.append((data[offset:offset + 4], data[offset + 8:offset + 8 + length]))
        offset += 8 + length
    return items

def listing_ids(chunk):
    """The miid values of the mlit records inside the mlcl of a chunk (avdb, adbs, aply, apso)."""
    ids = []
    for tag, value in tlv(bytes(chunk)[8:]):
        if tag == b"mlcl":
            for itag, ivalue in tlv(value):
                if itag == b"mlit":
                    for ftag, fvalue in tlv(ivalue):
                        if ftag == b"miid" and len(fvalue) == 4:
                            ids.append(int.from_bytes(fvalue, "big"))
    return ids


def dmap_wire(tree):
    return bytes(tree)

def dmap_read(raw):
    """The chunk structure comes from the octets; what the reply names is recorded for the requests that follow."""
    data = bytes(raw)
    tag = data[:4]
    body = data[8:]
    if tag == b"mlog":
        for t, v in tlv(body):
            if t == b"mlid" and len(v) == 4:
                SESSION["sid"] = [int.from_bytes(v, "big")]
    elif tag == b"mupd":
        for t, v in tlv(body):
            if t == b"musr" and len(v) == 4:
                SESSION["rev"] = [int.from_bytes(v, "big")]
    elif tag in (b"avdb", b"adbs", b"apso", b"aply"):
        kind = {b"avdb": "db", b"adbs": "item", b"apso": "item", b"aply": "container"}[tag]
        SESSION[kind] = listing_ids(data) or SESSION.get(kind, [])
    elif tag == b"msrv":
        for t, v in tlv(body):
            if t == b"mslr":
                SESSION["login_required"] = True   # sf-server-info: "If present, the client must log in"
    return data

def body_blocks(length, block, base=10):
    """How many octets of a body of `length` octets are parsed as blocks of `block` octets (greedy: blocks of 1024, then 32,
    then single octets; the last octet is parsed separately)."""
    n = max(int(str(length), base) - 1, 0)
    if n > DAAP_MAX_BODY_BYTES:
        return 0
    if block == 1024:
        return n // 1024
    if block == 32:
        return (n % 1024) // 32
    return n % 32

def valid_credentials():
    return base64.b64encode(f"{DAAP_USERNAME}:{DAAP_PASSWORD}".encode()).decode()

def auth_header_count():
    """After login a client of a server whose server-info showed that login is required sends credentials with every request."""
    return 1 if SESSION.get("login_required") else 0

def expected_session_id(value):
    """The session id the login reply named (the one recorded when it was parsed); a request of a connection no reply named a session for carries what it carries."""
    sessions = SESSION.get("sid")
    return str(sessions[-1]) if sessions else value

def far():
    """A position far beyond the end of any song of the test servers (an unsatisfiable range, rfc9110 14.1.2)."""
    return random.choice([random.randrange(10**5, 10**7), random.randrange(10**7, 10**10)])

def closed_range():
    """byte-range-spec first-last (rfc9110 14.1.2): ranges inside the song, ones that run past its end (the server clamps them),
    and invalid ones whose last-pos is less than the first-pos (rfc9110 14.1.2 calls them invalid)."""
    first = random.choice([0, random.randrange(0, 200), random.randrange(0, 3000), random.randrange(0, 40000)])
    kind = random.choice(["inside", "inside", "inside", "past_end", "inverted", "inverted_far"])
    if kind == "past_end":
        last = first + random.choice([random.randrange(10**5, 10**7), random.randrange(10**7, 10**9)])
    elif kind == "inverted":
        first, last = first + random.randrange(1, 4000), first
    elif kind == "inverted_far":
        first, last = far(), random.randrange(0, 40000)
    else:
        last = first + random.choice([0, random.randrange(0, 200), random.randrange(0, 4000), random.randrange(0, 60000)])
    return f"{first}-{last}"

def open_range():
    return f"{random.choice([0, random.randrange(0, 300), random.randrange(0, 3000), random.randrange(0, 40000)])}-"

def suffix_range():
    return f"-{random.choice([1, random.randrange(1, 300), random.randrange(1, 4000), random.randrange(1, 60000), random.randrange(10**6, 10**9)])}"

def unsatisfiable_range():
    return f"{far()}-"

def dmap_unchunk(raw):
    """The data of the chunked body of a DMAP reply (rfc9112 7.1)."""
    return dechunk(bytes(raw)) or b""

def dmap_chunk_wire(tree):
    """A DMAP body as one chunk of the chunked coding."""
    data = bytes(tree)
    return b"%x\r\n" % len(data) + data + b"\r\n0\r\n\r\n"

def string_blocks(length, block):
    """Blocks of `block` octets (8 or 1) of a string whose length is the big-endian value of `length`."""
    n = int.from_bytes(bytes(length), "big")
    if n > DAAP_MAX_BODY_BYTES:
        return 0
    return n // 8 if block == 8 else n % 8

# ================================= DMAP chunks: tag(4 ASCII) length(4, big endian) data (sf-index "Data Format", bj III) =
# All DMAP data is carried in replies (the server's messages); the client sends none.  Every container is parsed by
# its structure; the length field of every chunk equals the length of its data (self-terminated payload).
<octet> ::= rb'[\x00-\xff]'   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<blk8> ::= rb'[\x00-\xff]{8}'   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<len4> ::= rb'[\x00-\xff]{4}'            # sf-index: bytes 4-7 length of the contents of the chunk (not the whole chunk)
<v_byte> ::= <octet>                      # bj Appendix B type 1: byte, 1 byte
<v_short> ::= rb'[\x00-\xff]{2}'          # type 3: short, 2 bytes
<v_int> ::= rb'[\x00-\xff]{4}'            # type 5: int, 4 bytes
<v_long> ::= rb'[\x00-\xff]{8}'           # type 7: long, 8 bytes
<v_date> ::= rb'[\x00-\xff]{4}'           # type 10: date, 4 byte int, seconds since 1970-01-01
<v_version> ::= rb'[\x00-\xff]{4}'        # type 11: version, 4 bytes (4 single bytes or two shorts)

DMAP_CONTAINERS = {b"mdcl", b"mlcl", b"mlit", b"mbcl", b"mcon", b"msrv", b"mccr", b"mlog", b"mupd", b"mudl", b"avdb", b"abro",
                   b"abal", b"abar", b"abcp", b"abgn", b"adbs", b"aply", b"apso", b"arsv", b"prsv", b"arif"}

def dmap_lengths_ok(raw, top=True, parent=b""):
    """Every chunk below the top-level one has a length field equal to the length of its data (sf-index Data Format: the length of
    the top-level chunk of a reply may be wrong, so it is the one length not checked; bj III, sf-index)."""
    data = bytes(raw)
    if top:
        return len(data) >= 8 and dmap_lengths_ok(data[8:], False, data[:4])
    offset = 0
    while offset < len(data):
        if offset + 8 > len(data):
            return False
        length = int.from_bytes(data[offset + 4:offset + 8], "big")
        end = offset + 8 + length
        if end > len(data):
            return False
        tag = data[offset:offset + 4]
        # the entries of a browse listing (abal, abar, abcp, abgn) are mlit chunks holding a string
        if tag in DMAP_CONTAINERS and parent not in (b"abal", b"abar", b"abcp", b"abgn") \
                and not dmap_lengths_ok(data[offset + 8:end], False, tag):
            return False
        offset = end
    return True

# --- server-info response msrv (bj IV.1, sf-server-info)
<ck_msrv> ::= 'msrv' <len4> <msrv_child>*   # dmap.serverinforesponse
<msrv_child> ::= <ck_mstt> | <ck_mpro> | <ck_apro> | <ck_minm> | <ck_mslr> | <ck_mstm> | <ck_msal> | <ck_msup> | <ck_mspi> | <ck_msex> | <ck_msbr> | <ck_msqy> | <ck_msix> | <ck_msrs> | <ck_msdc> | <ck_msau> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# --- content-codes response mccr (bj IV.2, sf-codes)
<ck_mccr> ::= 'mccr' <len4> <mccr_child>*   # dmap.contentcodesresponse
<mccr_child> ::= <ck_mstt> | <ck_mdcl> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_mdcl> ::= 'mdcl' <len4> <mdcl_child>*   # dmap.dictionary: one entry per code
<mdcl_child> ::= <ck_mcnm> | <ck_mcna> | <ck_mcty> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# --- login response mlog (bj IV.3)
<ck_mlog> ::= 'mlog' <len4> <mlog_child>*   # dmap.loginresponse
<mlog_child> ::= <ck_mstt> | <ck_mlid> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# --- update response mupd (bj IV.4)
<ck_mupd> ::= 'mupd' <len4> <mupd_child>*   # dmap.updateresponse
<mupd_child> ::= <ck_mstt> | <ck_musr> | <ck_muty> | <ck_mudl> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_mudl> ::= 'mudl' <len4> <leaf_or_other>*  # dmap.deletedidlisting (bj Appendix A: "used in updates?"; content not documented)
# --- database list avdb (bj IV.5)
<ck_avdb> ::= 'avdb' <len4> <avdb_child>*   # daap.serverdatabases
<avdb_child> ::= <ck_mstt> | <ck_muty> | <ck_mtco> | <ck_mrco> | <ck_mlcl_db> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_mlcl_db> ::= 'mlcl' <len4> <ck_mlit>*   # dmap.listing of database records
# --- song list adbs / playlist items apso (bj IV.6, IV.8): mikd must be the first field of each mlit record
<ck_adbs> ::= 'adbs' <len4> <songs_child>*  # daap.databasesongs
<ck_apso> ::= 'apso' <len4> <songs_child>*  # daap.playlistsongs
<songs_child> ::= <ck_mstt> | <ck_muty> | <ck_mtco> | <ck_mrco> | <ck_mlcl_song> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_mlcl_song> ::= 'mlcl' <len4> <ck_mlit_song>*   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_mlit_song> ::= 'mlit' <len4> (<ck_mikd> <mlit_field_not_mikd>* | <mlit_field_not_mikd>*)   # bj IV.6: "it is very important that itemtype(mikd) be returned first for each record" (when the record has it)
<mlit_field_not_mikd> ::= <leaf_not_mikd> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# --- playlist list aply (bj IV.7)
<ck_aply> ::= 'aply' <len4> <aply_child>*   # daap.databaseplaylists
<aply_child> ::= <ck_mstt> | <ck_muty> | <ck_mtco> | <ck_mrco> | <ck_mlcl_db> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# --- generic record: any defined field in any order (bj IV.5/IV.7 list the fields; "order of the remaining fields can be arbitrary")
<ck_mlit> ::= 'mlit' <len4> <mlit_field>*   # dmap.listingitem
<mlit_field> ::= <leaf_chunk> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<leaf_or_other> ::= <leaf_chunk> | <ck_mlit> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<leaf_chunk> ::= <ck_mikd> | <leaf_not_mikd>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<leaf_not_mikd> ::= <ck_mstt> | <ck_miid> | <ck_minm> | <ck_mper> | <ck_mcti> | <ck_mpco> | <ck_msts> | <ck_mimc> | <ck_mctc> | <ck_mrco> | <ck_mtco> | <ck_muty> | <ck_asal> | <ck_asar> | <ck_asbt> | <ck_asbr> | <ck_ascm> | <ck_asco> | <ck_ascp> | <ck_asda> | <ck_asdm> | <ck_asdc> | <ck_asdn> | <ck_asdb> | <ck_aseq> | <ck_asfm> | <ck_asgn> | <ck_asdt> | <ck_asrv> | <ck_assr> | <ck_assz> | <ck_asst> | <ck_assp> | <ck_astm> | <ck_astc> | <ck_astn> | <ck_asur> | <ck_asyr> | <ck_asdk> | <ck_asul> | <ck_abpl> | <ck_aeNV> | <ck_aeSP>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# --- browse abro (bj Appendix A; request not documented)
<ck_abro> ::= 'abro' <len4> <abro_child>*   # daap.databasebrowse
<abro_child> ::= <ck_mstt> | <ck_muty> | <ck_mtco> | <ck_mrco> | <ck_abal> | <ck_abar> | <ck_abcp> | <ck_abgn> | <ck_msts> | <ck_other>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_abal> ::= 'abal' <len4> <ck_mlit_str>*   # daap.browsealbumlisting
<ck_abar> ::= 'abar' <len4> <ck_mlit_str>*   # daap.browseartistlisting
<ck_abcp> ::= 'abcp' <len4> <ck_mlit_str>*   # daap.browsecomposerlisting
<ck_abgn> ::= 'abgn' <len4> <ck_mlit_str>*   # daap.browsegenrelisting
<ck_mlit_str> ::= 'mlit' <str_payload>   # one listed name (artist, album, composer, genre) as a string
# --- resolve (bj Appendix A: arsv/prsv daap.resolve, arif daap.resolveinfo; content not documented)
<ck_arsv> ::= 'arsv' <len4> <leaf_or_other>*   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_prsv> ::= 'prsv' <len4> <leaf_or_other>*   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_arif> ::= 'arif' <len4> <leaf_or_other>*   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<ck_mbcl> ::= 'mbcl' <len4> <leaf_or_other>*  # dmap.bag
<ck_mcon> ::= 'mcon' <len4> <leaf_or_other>*  # dmap.container

# the body of a DMAP reply: one root chunk (the top-level chunk the request defines; bj IV)
# The body of a DMAP reply is carried twice: as the Content-Length octets (<body_raw_dmap>, which delimits the message) and as
# the chunk structure parsed from them (<dmap_tree>); the generator pair is the conversion between the two representations.
<body_raw_dmap> ::= <blk1024>{body_blocks(<cl_value>, 1024)} <blk32>{body_blocks(<cl_value>, 32)} <octet>{body_blocks(<cl_value>, 1)} <last_octet>{min(1, int(<cl_value>))} := dmap_wire(<dmap_tree>)   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<dmap_tree> ::= <dmap_body> := dmap_read(<body_raw_dmap>)   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<dmap_body> ::= <ck_msrv> | <ck_mccr> | <ck_mlog> | <ck_mupd> | <ck_avdb> | <ck_adbs> | <ck_aply> | <ck_apso> | <ck_abro> | <ck_arsv> | <ck_prsv> | <ck_arif> | <ck_mcon> | <ck_mbcl>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)


where forall <b> in <body_raw_dmap>: dmap_lengths_ok(<b>)
where forall <b> in <body_chunked_dmap>: dmap_lengths_ok(dmap_unchunk(<b>))
where forall <b> in <body_close_dmap>: dmap_lengths_ok(<b>)

# ---- generated by tools/build_fan.py: one nonterminal per DMAP content code (Appendix A of the DAAP documentation) ----
<ck_mstt> ::= 'mstt' b'\x00\x00\x00\x04' <v_int>   # dmap.status, type 5
<ck_miid> ::= 'miid' b'\x00\x00\x00\x04' <v_int>   # dmap.itemid, type 5
<ck_minm> ::= 'minm' <str_payload>   # dmap.itemname, string (UTF-8)
<ck_mikd> ::= 'mikd' b'\x00\x00\x00\x01' <v_byte>   # dmap.itemkind, type 1
<ck_mper> ::= 'mper' b'\x00\x00\x00\x08' <v_long>   # dmap.persistentid, type 7
<ck_mcti> ::= 'mcti' b'\x00\x00\x00\x04' <v_int>   # dmap.containeritemid, type 5
<ck_mpco> ::= 'mpco' b'\x00\x00\x00\x04' <v_int>   # dmap.parentcontainerid, type 5
<ck_msts> ::= 'msts' <str_payload>   # dmap.statusstring, string (UTF-8)
<ck_mimc> ::= 'mimc' b'\x00\x00\x00\x04' <v_int>   # dmap.itemcount, type 5
<ck_mctc> ::= 'mctc' b'\x00\x00\x00\x04' <v_int>   # dmap.containercount, type 5
<ck_mrco> ::= 'mrco' b'\x00\x00\x00\x04' <v_int>   # dmap.returnedcount, type 5
<ck_mtco> ::= 'mtco' b'\x00\x00\x00\x04' <v_int>   # dmap.specifiedtotalcount, type 5
<ck_msau> ::= 'msau' b'\x00\x00\x00\x01' <v_byte>   # dmap.authenticationmethod, type 1
<ck_mslr> ::= 'mslr' b'\x00\x00\x00\x01' <v_byte>   # dmap.loginrequired, type 1
<ck_mpro> ::= 'mpro' b'\x00\x00\x00\x04' <v_version>   # dmap.protocolversion, type 11
<ck_apro> ::= 'apro' b'\x00\x00\x00\x04' <v_version>   # daap.protocolversion, type 11
<ck_msal> ::= 'msal' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsautologout, type 1
<ck_msup> ::= 'msup' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsupdate, type 1
<ck_mspi> ::= 'mspi' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportspersistentids, type 1
<ck_msex> ::= 'msex' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsextensions, type 1
<ck_msbr> ::= 'msbr' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsbrowse, type 1
<ck_msqy> ::= 'msqy' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsquery, type 1
<ck_msix> ::= 'msix' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsindex, type 1
<ck_msrs> ::= 'msrs' b'\x00\x00\x00\x01' <v_byte>   # dmap.supportsresolve, type 1
<ck_mstm> ::= 'mstm' b'\x00\x00\x00\x04' <v_int>   # dmap.timeoutinterval, type 5
<ck_msdc> ::= 'msdc' b'\x00\x00\x00\x04' <v_int>   # dmap.databasescount, type 5
<ck_mcnm> ::= 'mcnm' b'\x00\x00\x00\x04' <v_int>   # dmap.contentcodesnumber, type 5
<ck_mcna> ::= 'mcna' <str_payload>   # dmap.contentcodesname, string (UTF-8)
<ck_mcty> ::= 'mcty' b'\x00\x00\x00\x02' <v_short>   # dmap.contentcodestype, type 3
<ck_mlid> ::= 'mlid' b'\x00\x00\x00\x04' <v_int>   # dmap.sessionid, type 5
<ck_musr> ::= 'musr' b'\x00\x00\x00\x04' <v_int>   # dmap.serverrevision, type 5
<ck_muty> ::= 'muty' b'\x00\x00\x00\x01' <v_byte>   # dmap.updatetype, type 1
<ck_asal> ::= 'asal' <str_payload>   # daap.songalbum, string (UTF-8)
<ck_asar> ::= 'asar' <str_payload>   # daap.songartist, string (UTF-8)
<ck_asbt> ::= 'asbt' b'\x00\x00\x00\x02' <v_short>   # daap.songbeatsperminute, type 3
<ck_asbr> ::= 'asbr' b'\x00\x00\x00\x02' <v_short>   # daap.songbitrate, type 3
<ck_ascm> ::= 'ascm' <str_payload>   # daap.songcomment, string (UTF-8)
<ck_asco> ::= 'asco' b'\x00\x00\x00\x01' <v_byte>   # daap.songcompilation, type 1
<ck_ascp> ::= 'ascp' <str_payload>   # daap.songcomposer, string (UTF-8)
<ck_asda> ::= 'asda' b'\x00\x00\x00\x04' <v_date>   # daap.songdateadded, type 10
<ck_asdm> ::= 'asdm' b'\x00\x00\x00\x04' <v_date>   # daap.songdatemodified, type 10
<ck_asdc> ::= 'asdc' b'\x00\x00\x00\x02' <v_short>   # daap.songdisccount, type 3
<ck_asdn> ::= 'asdn' b'\x00\x00\x00\x02' <v_short>   # daap.songdiscnumber, type 3
<ck_asdb> ::= 'asdb' b'\x00\x00\x00\x01' <v_byte>   # daap.songdisabled, type 1
<ck_aseq> ::= 'aseq' <str_payload>   # daap.songeqpreset, string (UTF-8)
<ck_asfm> ::= 'asfm' <str_payload>   # daap.songformat, string (UTF-8)
<ck_asgn> ::= 'asgn' <str_payload>   # daap.songgenre, string (UTF-8)
<ck_asdt> ::= 'asdt' <str_payload>   # daap.songdescription, string (UTF-8)
<ck_asrv> ::= 'asrv' b'\x00\x00\x00\x01' <v_byte>   # daap.songrelativevolume, type 1
<ck_assr> ::= 'assr' b'\x00\x00\x00\x04' <v_int>   # daap.songsamplerate, type 5
<ck_assz> ::= 'assz' b'\x00\x00\x00\x04' <v_int>   # daap.songsize, type 5
<ck_asst> ::= 'asst' b'\x00\x00\x00\x04' <v_int>   # daap.songstarttime, type 5
<ck_assp> ::= 'assp' b'\x00\x00\x00\x04' <v_int>   # daap.songstoptime, type 5
<ck_astm> ::= 'astm' b'\x00\x00\x00\x04' <v_int>   # daap.songtime, type 5
<ck_astc> ::= 'astc' b'\x00\x00\x00\x02' <v_short>   # daap.songtrackcount, type 3
<ck_astn> ::= 'astn' b'\x00\x00\x00\x02' <v_short>   # daap.songtracknumber, type 3
<ck_asur> ::= 'asur' b'\x00\x00\x00\x01' <v_byte>   # daap.songuserrating, type 1
<ck_asyr> ::= 'asyr' b'\x00\x00\x00\x02' <v_short>   # daap.songyear, type 3
<ck_asdk> ::= 'asdk' b'\x00\x00\x00\x01' <v_byte>   # daap.songdatakind, type 1
<ck_asul> ::= 'asul' <str_payload>   # daap.songdataurl, string (UTF-8)
<ck_abpl> ::= 'abpl' b'\x00\x00\x00\x01' <v_byte>   # daap.baseplaylist, type 1
<ck_aeNV> ::= 'aeNV' b'\x00\x00\x00\x04' <v_int>   # com.apple.itunes.norm-volume, type 5
<ck_aeSP> ::= 'aeSP' b'\x00\x00\x00\x01' <v_byte>   # com.apple.itunes.smart-playlist, type 1
# a length-prefixed value (strings, unknown chunks): the length is a literal for 0..255 octets (fast to parse), a counted repetition above
<str_payload> ::= (b'\x00\x00\x00\x00'   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
    | b'\x00\x00\x00\x01' rb'[\x00-\xff]{1}'
    | b'\x00\x00\x00\x02' rb'[\x00-\xff]{2}'
    | b'\x00\x00\x00\x03' rb'[\x00-\xff]{3}'
    | b'\x00\x00\x00\x04' rb'[\x00-\xff]{4}'
    | b'\x00\x00\x00\x05' rb'[\x00-\xff]{5}'
    | b'\x00\x00\x00\x06' rb'[\x00-\xff]{6}'
    | b'\x00\x00\x00\x07' rb'[\x00-\xff]{7}'
    | b'\x00\x00\x00\x08' rb'[\x00-\xff]{8}'
    | b'\x00\x00\x00\x09' rb'[\x00-\xff]{9}'
    | b'\x00\x00\x00\x0a' rb'[\x00-\xff]{10}'
    | b'\x00\x00\x00\x0b' rb'[\x00-\xff]{11}'
    | b'\x00\x00\x00\x0c' rb'[\x00-\xff]{12}'
    | b'\x00\x00\x00\x0d' rb'[\x00-\xff]{13}'
    | b'\x00\x00\x00\x0e' rb'[\x00-\xff]{14}'
    | b'\x00\x00\x00\x0f' rb'[\x00-\xff]{15}'
    | b'\x00\x00\x00\x10' rb'[\x00-\xff]{16}'
    | b'\x00\x00\x00\x11' rb'[\x00-\xff]{17}'
    | b'\x00\x00\x00\x12' rb'[\x00-\xff]{18}'
    | b'\x00\x00\x00\x13' rb'[\x00-\xff]{19}'
    | b'\x00\x00\x00\x14' rb'[\x00-\xff]{20}'
    | b'\x00\x00\x00\x15' rb'[\x00-\xff]{21}'
    | b'\x00\x00\x00\x16' rb'[\x00-\xff]{22}'
    | b'\x00\x00\x00\x17' rb'[\x00-\xff]{23}'
    | b'\x00\x00\x00\x18' rb'[\x00-\xff]{24}'
    | b'\x00\x00\x00\x19' rb'[\x00-\xff]{25}'
    | b'\x00\x00\x00\x1a' rb'[\x00-\xff]{26}'
    | b'\x00\x00\x00\x1b' rb'[\x00-\xff]{27}'
    | b'\x00\x00\x00\x1c' rb'[\x00-\xff]{28}'
    | b'\x00\x00\x00\x1d' rb'[\x00-\xff]{29}'
    | b'\x00\x00\x00\x1e' rb'[\x00-\xff]{30}'
    | b'\x00\x00\x00\x1f' rb'[\x00-\xff]{31}'
    | b'\x00\x00\x00\x20' rb'[\x00-\xff]{32}'
    | b'\x00\x00\x00\x21' rb'[\x00-\xff]{33}'
    | b'\x00\x00\x00\x22' rb'[\x00-\xff]{34}'
    | b'\x00\x00\x00\x23' rb'[\x00-\xff]{35}'
    | b'\x00\x00\x00\x24' rb'[\x00-\xff]{36}'
    | b'\x00\x00\x00\x25' rb'[\x00-\xff]{37}'
    | b'\x00\x00\x00\x26' rb'[\x00-\xff]{38}'
    | b'\x00\x00\x00\x27' rb'[\x00-\xff]{39}'
    | b'\x00\x00\x00\x28' rb'[\x00-\xff]{40}'
    | b'\x00\x00\x00\x29' rb'[\x00-\xff]{41}'
    | b'\x00\x00\x00\x2a' rb'[\x00-\xff]{42}'
    | b'\x00\x00\x00\x2b' rb'[\x00-\xff]{43}'
    | b'\x00\x00\x00\x2c' rb'[\x00-\xff]{44}'
    | b'\x00\x00\x00\x2d' rb'[\x00-\xff]{45}'
    | b'\x00\x00\x00\x2e' rb'[\x00-\xff]{46}'
    | b'\x00\x00\x00\x2f' rb'[\x00-\xff]{47}'
    | b'\x00\x00\x00\x30' rb'[\x00-\xff]{48}'
    | b'\x00\x00\x00\x31' rb'[\x00-\xff]{49}'
    | b'\x00\x00\x00\x32' rb'[\x00-\xff]{50}'
    | b'\x00\x00\x00\x33' rb'[\x00-\xff]{51}'
    | b'\x00\x00\x00\x34' rb'[\x00-\xff]{52}'
    | b'\x00\x00\x00\x35' rb'[\x00-\xff]{53}'
    | b'\x00\x00\x00\x36' rb'[\x00-\xff]{54}'
    | b'\x00\x00\x00\x37' rb'[\x00-\xff]{55}'
    | b'\x00\x00\x00\x38' rb'[\x00-\xff]{56}'
    | b'\x00\x00\x00\x39' rb'[\x00-\xff]{57}'
    | b'\x00\x00\x00\x3a' rb'[\x00-\xff]{58}'
    | b'\x00\x00\x00\x3b' rb'[\x00-\xff]{59}'
    | b'\x00\x00\x00\x3c' rb'[\x00-\xff]{60}'
    | b'\x00\x00\x00\x3d' rb'[\x00-\xff]{61}'
    | b'\x00\x00\x00\x3e' rb'[\x00-\xff]{62}'
    | b'\x00\x00\x00\x3f' rb'[\x00-\xff]{63}'
    | b'\x00\x00\x00\x40' rb'[\x00-\xff]{64}'
    | b'\x00\x00\x00\x41' rb'[\x00-\xff]{65}'
    | b'\x00\x00\x00\x42' rb'[\x00-\xff]{66}'
    | b'\x00\x00\x00\x43' rb'[\x00-\xff]{67}'
    | b'\x00\x00\x00\x44' rb'[\x00-\xff]{68}'
    | b'\x00\x00\x00\x45' rb'[\x00-\xff]{69}'
    | b'\x00\x00\x00\x46' rb'[\x00-\xff]{70}'
    | b'\x00\x00\x00\x47' rb'[\x00-\xff]{71}'
    | b'\x00\x00\x00\x48' rb'[\x00-\xff]{72}'
    | b'\x00\x00\x00\x49' rb'[\x00-\xff]{73}'
    | b'\x00\x00\x00\x4a' rb'[\x00-\xff]{74}'
    | b'\x00\x00\x00\x4b' rb'[\x00-\xff]{75}'
    | b'\x00\x00\x00\x4c' rb'[\x00-\xff]{76}'
    | b'\x00\x00\x00\x4d' rb'[\x00-\xff]{77}'
    | b'\x00\x00\x00\x4e' rb'[\x00-\xff]{78}'
    | b'\x00\x00\x00\x4f' rb'[\x00-\xff]{79}'
    | b'\x00\x00\x00\x50' rb'[\x00-\xff]{80}'
    | b'\x00\x00\x00\x51' rb'[\x00-\xff]{81}'
    | b'\x00\x00\x00\x52' rb'[\x00-\xff]{82}'
    | b'\x00\x00\x00\x53' rb'[\x00-\xff]{83}'
    | b'\x00\x00\x00\x54' rb'[\x00-\xff]{84}'
    | b'\x00\x00\x00\x55' rb'[\x00-\xff]{85}'
    | b'\x00\x00\x00\x56' rb'[\x00-\xff]{86}'
    | b'\x00\x00\x00\x57' rb'[\x00-\xff]{87}'
    | b'\x00\x00\x00\x58' rb'[\x00-\xff]{88}'
    | b'\x00\x00\x00\x59' rb'[\x00-\xff]{89}'
    | b'\x00\x00\x00\x5a' rb'[\x00-\xff]{90}'
    | b'\x00\x00\x00\x5b' rb'[\x00-\xff]{91}'
    | b'\x00\x00\x00\x5c' rb'[\x00-\xff]{92}'
    | b'\x00\x00\x00\x5d' rb'[\x00-\xff]{93}'
    | b'\x00\x00\x00\x5e' rb'[\x00-\xff]{94}'
    | b'\x00\x00\x00\x5f' rb'[\x00-\xff]{95}'
    | b'\x00\x00\x00\x60' rb'[\x00-\xff]{96}'
    | b'\x00\x00\x00\x61' rb'[\x00-\xff]{97}'
    | b'\x00\x00\x00\x62' rb'[\x00-\xff]{98}'
    | b'\x00\x00\x00\x63' rb'[\x00-\xff]{99}'
    | b'\x00\x00\x00\x64' rb'[\x00-\xff]{100}'
    | b'\x00\x00\x00\x65' rb'[\x00-\xff]{101}'
    | b'\x00\x00\x00\x66' rb'[\x00-\xff]{102}'
    | b'\x00\x00\x00\x67' rb'[\x00-\xff]{103}'
    | b'\x00\x00\x00\x68' rb'[\x00-\xff]{104}'
    | b'\x00\x00\x00\x69' rb'[\x00-\xff]{105}'
    | b'\x00\x00\x00\x6a' rb'[\x00-\xff]{106}'
    | b'\x00\x00\x00\x6b' rb'[\x00-\xff]{107}'
    | b'\x00\x00\x00\x6c' rb'[\x00-\xff]{108}'
    | b'\x00\x00\x00\x6d' rb'[\x00-\xff]{109}'
    | b'\x00\x00\x00\x6e' rb'[\x00-\xff]{110}'
    | b'\x00\x00\x00\x6f' rb'[\x00-\xff]{111}'
    | b'\x00\x00\x00\x70' rb'[\x00-\xff]{112}'
    | b'\x00\x00\x00\x71' rb'[\x00-\xff]{113}'
    | b'\x00\x00\x00\x72' rb'[\x00-\xff]{114}'
    | b'\x00\x00\x00\x73' rb'[\x00-\xff]{115}'
    | b'\x00\x00\x00\x74' rb'[\x00-\xff]{116}'
    | b'\x00\x00\x00\x75' rb'[\x00-\xff]{117}'
    | b'\x00\x00\x00\x76' rb'[\x00-\xff]{118}'
    | b'\x00\x00\x00\x77' rb'[\x00-\xff]{119}'
    | b'\x00\x00\x00\x78' rb'[\x00-\xff]{120}'
    | b'\x00\x00\x00\x79' rb'[\x00-\xff]{121}'
    | b'\x00\x00\x00\x7a' rb'[\x00-\xff]{122}'
    | b'\x00\x00\x00\x7b' rb'[\x00-\xff]{123}'
    | b'\x00\x00\x00\x7c' rb'[\x00-\xff]{124}'
    | b'\x00\x00\x00\x7d' rb'[\x00-\xff]{125}'
    | b'\x00\x00\x00\x7e' rb'[\x00-\xff]{126}'
    | b'\x00\x00\x00\x7f' rb'[\x00-\xff]{127}'
    | b'\x00\x00\x00\x80' rb'[\x00-\xff]{128}'
    | b'\x00\x00\x00\x81' rb'[\x00-\xff]{129}'
    | b'\x00\x00\x00\x82' rb'[\x00-\xff]{130}'
    | b'\x00\x00\x00\x83' rb'[\x00-\xff]{131}'
    | b'\x00\x00\x00\x84' rb'[\x00-\xff]{132}'
    | b'\x00\x00\x00\x85' rb'[\x00-\xff]{133}'
    | b'\x00\x00\x00\x86' rb'[\x00-\xff]{134}'
    | b'\x00\x00\x00\x87' rb'[\x00-\xff]{135}'
    | b'\x00\x00\x00\x88' rb'[\x00-\xff]{136}'
    | b'\x00\x00\x00\x89' rb'[\x00-\xff]{137}'
    | b'\x00\x00\x00\x8a' rb'[\x00-\xff]{138}'
    | b'\x00\x00\x00\x8b' rb'[\x00-\xff]{139}'
    | b'\x00\x00\x00\x8c' rb'[\x00-\xff]{140}'
    | b'\x00\x00\x00\x8d' rb'[\x00-\xff]{141}'
    | b'\x00\x00\x00\x8e' rb'[\x00-\xff]{142}'
    | b'\x00\x00\x00\x8f' rb'[\x00-\xff]{143}'
    | b'\x00\x00\x00\x90' rb'[\x00-\xff]{144}'
    | b'\x00\x00\x00\x91' rb'[\x00-\xff]{145}'
    | b'\x00\x00\x00\x92' rb'[\x00-\xff]{146}'
    | b'\x00\x00\x00\x93' rb'[\x00-\xff]{147}'
    | b'\x00\x00\x00\x94' rb'[\x00-\xff]{148}'
    | b'\x00\x00\x00\x95' rb'[\x00-\xff]{149}'
    | b'\x00\x00\x00\x96' rb'[\x00-\xff]{150}'
    | b'\x00\x00\x00\x97' rb'[\x00-\xff]{151}'
    | b'\x00\x00\x00\x98' rb'[\x00-\xff]{152}'
    | b'\x00\x00\x00\x99' rb'[\x00-\xff]{153}'
    | b'\x00\x00\x00\x9a' rb'[\x00-\xff]{154}'
    | b'\x00\x00\x00\x9b' rb'[\x00-\xff]{155}'
    | b'\x00\x00\x00\x9c' rb'[\x00-\xff]{156}'
    | b'\x00\x00\x00\x9d' rb'[\x00-\xff]{157}'
    | b'\x00\x00\x00\x9e' rb'[\x00-\xff]{158}'
    | b'\x00\x00\x00\x9f' rb'[\x00-\xff]{159}'
    | b'\x00\x00\x00\xa0' rb'[\x00-\xff]{160}'
    | b'\x00\x00\x00\xa1' rb'[\x00-\xff]{161}'
    | b'\x00\x00\x00\xa2' rb'[\x00-\xff]{162}'
    | b'\x00\x00\x00\xa3' rb'[\x00-\xff]{163}'
    | b'\x00\x00\x00\xa4' rb'[\x00-\xff]{164}'
    | b'\x00\x00\x00\xa5' rb'[\x00-\xff]{165}'
    | b'\x00\x00\x00\xa6' rb'[\x00-\xff]{166}'
    | b'\x00\x00\x00\xa7' rb'[\x00-\xff]{167}'
    | b'\x00\x00\x00\xa8' rb'[\x00-\xff]{168}'
    | b'\x00\x00\x00\xa9' rb'[\x00-\xff]{169}'
    | b'\x00\x00\x00\xaa' rb'[\x00-\xff]{170}'
    | b'\x00\x00\x00\xab' rb'[\x00-\xff]{171}'
    | b'\x00\x00\x00\xac' rb'[\x00-\xff]{172}'
    | b'\x00\x00\x00\xad' rb'[\x00-\xff]{173}'
    | b'\x00\x00\x00\xae' rb'[\x00-\xff]{174}'
    | b'\x00\x00\x00\xaf' rb'[\x00-\xff]{175}'
    | b'\x00\x00\x00\xb0' rb'[\x00-\xff]{176}'
    | b'\x00\x00\x00\xb1' rb'[\x00-\xff]{177}'
    | b'\x00\x00\x00\xb2' rb'[\x00-\xff]{178}'
    | b'\x00\x00\x00\xb3' rb'[\x00-\xff]{179}'
    | b'\x00\x00\x00\xb4' rb'[\x00-\xff]{180}'
    | b'\x00\x00\x00\xb5' rb'[\x00-\xff]{181}'
    | b'\x00\x00\x00\xb6' rb'[\x00-\xff]{182}'
    | b'\x00\x00\x00\xb7' rb'[\x00-\xff]{183}'
    | b'\x00\x00\x00\xb8' rb'[\x00-\xff]{184}'
    | b'\x00\x00\x00\xb9' rb'[\x00-\xff]{185}'
    | b'\x00\x00\x00\xba' rb'[\x00-\xff]{186}'
    | b'\x00\x00\x00\xbb' rb'[\x00-\xff]{187}'
    | b'\x00\x00\x00\xbc' rb'[\x00-\xff]{188}'
    | b'\x00\x00\x00\xbd' rb'[\x00-\xff]{189}'
    | b'\x00\x00\x00\xbe' rb'[\x00-\xff]{190}'
    | b'\x00\x00\x00\xbf' rb'[\x00-\xff]{191}'
    | b'\x00\x00\x00\xc0' rb'[\x00-\xff]{192}'
    | b'\x00\x00\x00\xc1' rb'[\x00-\xff]{193}'
    | b'\x00\x00\x00\xc2' rb'[\x00-\xff]{194}'
    | b'\x00\x00\x00\xc3' rb'[\x00-\xff]{195}'
    | b'\x00\x00\x00\xc4' rb'[\x00-\xff]{196}'
    | b'\x00\x00\x00\xc5' rb'[\x00-\xff]{197}'
    | b'\x00\x00\x00\xc6' rb'[\x00-\xff]{198}'
    | b'\x00\x00\x00\xc7' rb'[\x00-\xff]{199}'
    | b'\x00\x00\x00\xc8' rb'[\x00-\xff]{200}'
    | b'\x00\x00\x00\xc9' rb'[\x00-\xff]{201}'
    | b'\x00\x00\x00\xca' rb'[\x00-\xff]{202}'
    | b'\x00\x00\x00\xcb' rb'[\x00-\xff]{203}'
    | b'\x00\x00\x00\xcc' rb'[\x00-\xff]{204}'
    | b'\x00\x00\x00\xcd' rb'[\x00-\xff]{205}'
    | b'\x00\x00\x00\xce' rb'[\x00-\xff]{206}'
    | b'\x00\x00\x00\xcf' rb'[\x00-\xff]{207}'
    | b'\x00\x00\x00\xd0' rb'[\x00-\xff]{208}'
    | b'\x00\x00\x00\xd1' rb'[\x00-\xff]{209}'
    | b'\x00\x00\x00\xd2' rb'[\x00-\xff]{210}'
    | b'\x00\x00\x00\xd3' rb'[\x00-\xff]{211}'
    | b'\x00\x00\x00\xd4' rb'[\x00-\xff]{212}'
    | b'\x00\x00\x00\xd5' rb'[\x00-\xff]{213}'
    | b'\x00\x00\x00\xd6' rb'[\x00-\xff]{214}'
    | b'\x00\x00\x00\xd7' rb'[\x00-\xff]{215}'
    | b'\x00\x00\x00\xd8' rb'[\x00-\xff]{216}'
    | b'\x00\x00\x00\xd9' rb'[\x00-\xff]{217}'
    | b'\x00\x00\x00\xda' rb'[\x00-\xff]{218}'
    | b'\x00\x00\x00\xdb' rb'[\x00-\xff]{219}'
    | b'\x00\x00\x00\xdc' rb'[\x00-\xff]{220}'
    | b'\x00\x00\x00\xdd' rb'[\x00-\xff]{221}'
    | b'\x00\x00\x00\xde' rb'[\x00-\xff]{222}'
    | b'\x00\x00\x00\xdf' rb'[\x00-\xff]{223}'
    | b'\x00\x00\x00\xe0' rb'[\x00-\xff]{224}'
    | b'\x00\x00\x00\xe1' rb'[\x00-\xff]{225}'
    | b'\x00\x00\x00\xe2' rb'[\x00-\xff]{226}'
    | b'\x00\x00\x00\xe3' rb'[\x00-\xff]{227}'
    | b'\x00\x00\x00\xe4' rb'[\x00-\xff]{228}'
    | b'\x00\x00\x00\xe5' rb'[\x00-\xff]{229}'
    | b'\x00\x00\x00\xe6' rb'[\x00-\xff]{230}'
    | b'\x00\x00\x00\xe7' rb'[\x00-\xff]{231}'
    | b'\x00\x00\x00\xe8' rb'[\x00-\xff]{232}'
    | b'\x00\x00\x00\xe9' rb'[\x00-\xff]{233}'
    | b'\x00\x00\x00\xea' rb'[\x00-\xff]{234}'
    | b'\x00\x00\x00\xeb' rb'[\x00-\xff]{235}'
    | b'\x00\x00\x00\xec' rb'[\x00-\xff]{236}'
    | b'\x00\x00\x00\xed' rb'[\x00-\xff]{237}'
    | b'\x00\x00\x00\xee' rb'[\x00-\xff]{238}'
    | b'\x00\x00\x00\xef' rb'[\x00-\xff]{239}'
    | b'\x00\x00\x00\xf0' rb'[\x00-\xff]{240}'
    | b'\x00\x00\x00\xf1' rb'[\x00-\xff]{241}'
    | b'\x00\x00\x00\xf2' rb'[\x00-\xff]{242}'
    | b'\x00\x00\x00\xf3' rb'[\x00-\xff]{243}'
    | b'\x00\x00\x00\xf4' rb'[\x00-\xff]{244}'
    | b'\x00\x00\x00\xf5' rb'[\x00-\xff]{245}'
    | b'\x00\x00\x00\xf6' rb'[\x00-\xff]{246}'
    | b'\x00\x00\x00\xf7' rb'[\x00-\xff]{247}'
    | b'\x00\x00\x00\xf8' rb'[\x00-\xff]{248}'
    | b'\x00\x00\x00\xf9' rb'[\x00-\xff]{249}'
    | b'\x00\x00\x00\xfa' rb'[\x00-\xff]{250}'
    | b'\x00\x00\x00\xfb' rb'[\x00-\xff]{251}'
    | b'\x00\x00\x00\xfc' rb'[\x00-\xff]{252}'
    | b'\x00\x00\x00\xfd' rb'[\x00-\xff]{253}'
    | b'\x00\x00\x00\xfe' rb'[\x00-\xff]{254}'
    | b'\x00\x00\x00\xff' rb'[\x00-\xff]{255}'
    | <str_payload_long>)
<str_payload_long> ::= <len4_long> <blk8>{string_blocks(<len4_long>, 8)} <octet>{string_blocks(<len4_long>, 1)}   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<len4_long> ::= rb'(?:\x00\x00[\x01-\xff][\x00-\xff]|\x00[\x01-\xff][\x00-\xff]{2}|[\x01-\xff][\x00-\xff]{3})'   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# the last octet of a body is parsed from literals: a message that ends in a regular expression stays open for more data
<last_octet> ::= b'\x00' | b'\x01' | b'\x02' | b'\x03' | b'\x04' | b'\x05' | b'\x06' | b'\x07' | b'\x08' | b'\x09' | b'\x0a' | b'\x0b' | b'\x0c' | b'\x0d' | b'\x0e' | b'\x0f' | b'\x10' | b'\x11' | b'\x12' | b'\x13' | b'\x14' | b'\x15' | b'\x16' | b'\x17' | b'\x18' | b'\x19' | b'\x1a' | b'\x1b' | b'\x1c' | b'\x1d' | b'\x1e' | b'\x1f' | b'\x20' | b'\x21' | b'\x22' | b'\x23' | b'\x24' | b'\x25' | b'\x26' | b'\x27' | b'\x28' | b'\x29' | b'\x2a' | b'\x2b' | b'\x2c' | b'\x2d' | b'\x2e' | b'\x2f' | b'\x30' | b'\x31' | b'\x32' | b'\x33' | b'\x34' | b'\x35' | b'\x36' | b'\x37' | b'\x38' | b'\x39' | b'\x3a' | b'\x3b' | b'\x3c' | b'\x3d' | b'\x3e' | b'\x3f' | b'\x40' | b'\x41' | b'\x42' | b'\x43' | b'\x44' | b'\x45' | b'\x46' | b'\x47' | b'\x48' | b'\x49' | b'\x4a' | b'\x4b' | b'\x4c' | b'\x4d' | b'\x4e' | b'\x4f' | b'\x50' | b'\x51' | b'\x52' | b'\x53' | b'\x54' | b'\x55' | b'\x56' | b'\x57' | b'\x58' | b'\x59' | b'\x5a' | b'\x5b' | b'\x5c' | b'\x5d' | b'\x5e' | b'\x5f' | b'\x60' | b'\x61' | b'\x62' | b'\x63' | b'\x64' | b'\x65' | b'\x66' | b'\x67' | b'\x68' | b'\x69' | b'\x6a' | b'\x6b' | b'\x6c' | b'\x6d' | b'\x6e' | b'\x6f' | b'\x70' | b'\x71' | b'\x72' | b'\x73' | b'\x74' | b'\x75' | b'\x76' | b'\x77' | b'\x78' | b'\x79' | b'\x7a' | b'\x7b' | b'\x7c' | b'\x7d' | b'\x7e' | b'\x7f' | b'\x80' | b'\x81' | b'\x82' | b'\x83' | b'\x84' | b'\x85' | b'\x86' | b'\x87' | b'\x88' | b'\x89' | b'\x8a' | b'\x8b' | b'\x8c' | b'\x8d' | b'\x8e' | b'\x8f' | b'\x90' | b'\x91' | b'\x92' | b'\x93' | b'\x94' | b'\x95' | b'\x96' | b'\x97' | b'\x98' | b'\x99' | b'\x9a' | b'\x9b' | b'\x9c' | b'\x9d' | b'\x9e' | b'\x9f' | b'\xa0' | b'\xa1' | b'\xa2' | b'\xa3' | b'\xa4' | b'\xa5' | b'\xa6' | b'\xa7' | b'\xa8' | b'\xa9' | b'\xaa' | b'\xab' | b'\xac' | b'\xad' | b'\xae' | b'\xaf' | b'\xb0' | b'\xb1' | b'\xb2' | b'\xb3' | b'\xb4' | b'\xb5' | b'\xb6' | b'\xb7' | b'\xb8' | b'\xb9' | b'\xba' | b'\xbb' | b'\xbc' | b'\xbd' | b'\xbe' | b'\xbf' | b'\xc0' | b'\xc1' | b'\xc2' | b'\xc3' | b'\xc4' | b'\xc5' | b'\xc6' | b'\xc7' | b'\xc8' | b'\xc9' | b'\xca' | b'\xcb' | b'\xcc' | b'\xcd' | b'\xce' | b'\xcf' | b'\xd0' | b'\xd1' | b'\xd2' | b'\xd3' | b'\xd4' | b'\xd5' | b'\xd6' | b'\xd7' | b'\xd8' | b'\xd9' | b'\xda' | b'\xdb' | b'\xdc' | b'\xdd' | b'\xde' | b'\xdf' | b'\xe0' | b'\xe1' | b'\xe2' | b'\xe3' | b'\xe4' | b'\xe5' | b'\xe6' | b'\xe7' | b'\xe8' | b'\xe9' | b'\xea' | b'\xeb' | b'\xec' | b'\xed' | b'\xee' | b'\xef' | b'\xf0' | b'\xf1' | b'\xf2' | b'\xf3' | b'\xf4' | b'\xf5' | b'\xf6' | b'\xf7' | b'\xf8' | b'\xf9' | b'\xfa' | b'\xfb' | b'\xfc' | b'\xfd' | b'\xfe' | b'\xff'   # rfc9112 6.3 message body length, 7.1 chunked coding

# fallback for codes the spec does not define (extension codes): excludes every defined code so that it never overlaps their rules
<ck_other> ::= <other_tag> <str_payload>   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<other_tag> ::= rb'(?!(?:mstt|miid|minm|mikd|mper|mcti|mpco|msts|mimc|mctc|mrco|mtco|msau|mslr|mpro|apro|msal|msup|mspi|msex|msbr|msqy|msix|msrs|mstm|msdc|mcnm|mcna|mcty|mlid|musr|muty|asal|asar|asbt|asbr|ascm|asco|ascp|asda|asdm|asdc|asdn|asdb|aseq|asfm|asgn|asdt|asrv|assr|assz|asst|assp|astm|astc|astn|asur|asyr|asdk|asul|abpl|aeNV|aeSP|mdcl|mlcl|mlit|mbcl|mcon|msrv|mccr|mlog|mupd|mudl|avdb|abro|abal|abar|abcp|abgn|adbs|aply|apso|arsv|prsv|arif))[\x00-\xff]{4}'   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)


# =============================================== PROTOCOL STATES AND EXCHANGES =====================================
# sf-index "Request URIs", bj IV: a session is: server-info, content-codes, login (mlog carries the session id), update
# (mupd carries the revision), databases (avdb), items (adbs), containers (aply), container items (apso), stream, artwork,
# logout.  Two protocol states: no session (connected) and logged in.  The server's own initiative message (closing the
# connection) is one shared nonterminal accepted between exchanges in every state.
# TODO: bj Appendix A (abro, abal, abar, abcp, abgn) and msrv msbr (browse): the request that asks for a browse listing is defined nowhere in refs/spec, so it is not sent; the reply roots are accepted (<ck_abro>); nearest nonterminal <exchange_resolve>.
# TODO: bj II ("a client may have up to two connections ... one for the database/playlist updates, the other for streaming", at most 5 sessions): a second connection at the same time is outside the test setup (one connection per session); nearest nonterminal <state_logged_in>.
# TODO: sf-server-info mstm / msal (timeout interval, automatic logout): a logout by timeout depends on the time between messages, which no constraint, generator or timer-free rule can use; the closing of the connection is accepted wherever it can come (<unsolicited>); nearest nonterminal <unsolicited>.
# TODO: sf-index "Basic Form" (gzip content encoding), rfc9110 8.4: the octets of a gzip-coded body are rfc1952 data (manifest: out of scope), so they are carried opaquely (<resp_coded>) and the DMAP chunks inside them are not parsed; nearest nonterminal <resp_coded>.
# TODO: bj IV.4 (the second, "not yet documented" form of /update that waits for changes, and its parameters): only the documented parameters session-id and revision-id are sent (<req_update>); nearest nonterminal <q_update>.
# TODO: sf-server-info msqy / msix / msex (query, index, extensions): the requests that use these capabilities are not defined in refs/spec and are not sent; the capability flags are parsed (<ck_msqy>, <ck_msix>, <ck_msex>); nearest nonterminal <ck_msqy>.
# TODO: bj IV.6 ("it's possible to have other types as well") and Appendix A mikd values other than 2: no other item type is defined, only type=music is sent; nearest nonterminal <q_type>.
# TODO: sf-index /resolve, bj Appendix A (arsv, prsv, arif) and msrv msrs / mspi (resolve, persistent ids): the parameters of /resolve and the content of its reply are not documented ("I haven't yet had a look at this request"); only the session-id is sent and any DMAP reply is accepted; nearest nonterminal <req_resolve>.
# TODO: rfc9110 9.3.3-9.3.8 (POST, PUT, DELETE, CONNECT, OPTIONS, TRACE), 13 (conditional requests), 15.4 (redirection), 15.2 (1xx interim replies), 7.8 (Upgrade): sf-index "All the requests are HTTP GET requests", so DAAP defines no use of them and rfc9110 9.1 makes every method but GET and HEAD optional (no reply is mandated); nearest nonterminal <exchange_head>.
# TODO: rfc9110 14.6 (multipart/byteranges body parts, whose syntax is MIME multipart, rfc2046, not in refs/spec): the octets of a multipart 206 reply are carried opaquely (<resp_blob>); nearest nonterminal <resp_blob>.
# TODO: rfc9112 5.2 obs-fold and 7.1.2 trailer fields in requests, 7.1 chunked requests: DAAP requests have no body, so none is sent; nearest nonterminal <req_headers>.
# a connection nobody has spoken on yet: the server may close it on its own initiative before the first request (idle timeout, refusal;
# rfc9112 9.6).  A server message planned as the very first message of a session never arrives (the server has nothing to say before
# the first request) and Fandango's planner would end such a session with nothing sent (an empty session, which the harness rejects),
# so this one wait is a timer: the client starts it, then the server's close arrives (and the timer is cancelled) or the timer
# expires and the client goes on with the first request (<exchange_idle>).  After the first exchange the shared <unsolicited> is accepted.
<start> ::= <state_new>   # protocol states: bj IV (conversation overview), sf-index Request URIs
<state_new> ::= (<exchange_common> <state_connected>   # protocol states: bj IV (conversation overview), sf-index Request URIs
    | <exchange_login> <state_logged_in>
    | <exchange_login_refused> <state_connected>
    | <exchange_login_credentials> <state_logged_in>
    | <exchange_login_credentials_refused> <state_connected>
    | <exchange_connection_close>
    | <exchange_idle>)

<state_connected> ::= (<exchange_common> <state_connected>   # protocol states: bj IV (conversation overview), sf-index Request URIs
    | <exchange_login> <state_logged_in>
    | <exchange_login_refused> <state_connected>
    | <exchange_login_credentials> <state_logged_in>
    | <exchange_login_credentials_refused> <state_connected>
    | <exchange_connection_close>
    | <unsolicited>)

<state_logged_in> ::= (<exchange_common> <state_logged_in>   # protocol states: bj IV (conversation overview), sf-index Request URIs
    | <exchange_update> <state_logged_in>
    | <exchange_update_unanswered>
    | <exchange_databases> <state_logged_in>
    | <exchange_items> <state_logged_in>
    | <exchange_containers> <state_logged_in>
    | <exchange_container_items> <state_logged_in>
    | <exchange_stream> <state_logged_in>
    | <exchange_stream_range> <state_logged_in>
    | <exchange_stream_multirange> <state_logged_in>
    | <exchange_artwork> <state_logged_in>
    | <exchange_resolve> <state_logged_in>
    | <exchange_credentials_offered> <state_logged_in>
    | <exchange_logout> <state_connected>
    | <exchange_connection_close>
    | <unsolicited>)


# exchanges that need no session and leave the state as it is
<exchange_common> ::= (<exchange_server_info> | <exchange_content_codes> | <exchange_head> | <exchange_http10>)   # protocol states: bj IV (conversation overview), sf-index Request URIs

# before the first request: wait for the server's own close; if it stays away the timer expires and the first request follows
<exchange_idle> ::= <TimerControl:idle_start> (<Closure:conn_closed> <TimerControl:idle_cancel> | <TimerEvent:idle_expired> <state_connected>)   # rfc9112 9.6 (the server closes the connection on its own initiative before the first request), rfc9110 7.8
<idle_start> ::= <timer_start>   # rfc9112 9.6 (the server closes the connection on its own initiative before the first request), rfc9110 7.8
<idle_cancel> ::= <timer_cancel>   # rfc9112 9.6 (the server closes the connection on its own initiative before the first request), rfc9110 7.8
<idle_expired> ::= <timer_expired>   # rfc9112 9.6 (the server closes the connection on its own initiative before the first request), rfc9110 7.8

# the server closes the connection on its own initiative (idle timeout, error handling, Connection: close; rfc9112 9.6)
<unsolicited> ::= <Closure:conn_closed>   # the server closing the connection: rfc9112 9.6, sf-server-info msal/mstm
<conn_closed> ::= 'closed'   # the server closing the connection: rfc9112 9.6, sf-server-info msal/mstm

# ---- exchanges: request, then the reply classes the spec allows (the typed 2xx DMAP reply, or an HTTP refusal)
<exchange_server_info> ::= <Client:req_server_info> <Server:reply_info>        # sf-server-info; reply root msrv
<exchange_content_codes> ::= <Client:req_content_codes> <Server:reply_info>   # sf-codes; reply root mccr
<exchange_login> ::= <Client:req_login> <Server:reply_login>                  # bj IV.3; reply root mlog, names the session
<exchange_login_refused> ::= <Client:req_login> <Server:resp_refusal>   # bj IV.3 Login
<exchange_login_credentials> ::= <Client:req_login_credentials> <Server:reply_login>   # bj IV.3 Login
<exchange_login_credentials_refused> ::= <Client:req_login_credentials> <Server:resp_refusal>   # bj IV.3 Login
# the timer is started before the request, so that a prompt reply never overtakes it
<exchange_update> ::= <TimerControl:update_start> <Client:req_update> <update_answer>                   # bj IV.4; reply root mupd
<update_answer> ::= <Server:reply_info> <TimerControl:update_cancel>   # bj IV.4 Update
<exchange_update_unanswered> ::= <TimerControl:update_start> <Client:req_update> <TimerEvent:update_expired>   # bj IV.4 Update
<update_start> ::= <timer_start>   # bj IV.4 Update
<update_cancel> ::= <timer_cancel>   # bj IV.4 Update
<update_expired> ::= <timer_expired>   # bj IV.4 Update
<exchange_databases> ::= <Client:req_databases> <Server:reply_info>           # bj IV.5; reply root avdb
<exchange_items> ::= <Client:req_items> <Server:reply_info>                    # bj IV.6; reply root adbs
<exchange_containers> ::= <Client:req_containers> <Server:reply_info>          # bj IV.7; reply root aply
<exchange_container_items> ::= <Client:req_container_items> <Server:reply_info>  # bj IV.8; reply root apso
<exchange_stream> ::= <Client:req_stream> <Server:reply_blob>                # bj IV.9
<exchange_stream_range> ::= <Client:req_stream_range> <Server:reply_blob>    # bj IV.9: the range header; 206 carries Content-Range
<exchange_stream_multirange> ::= <Client:req_stream_multirange> <Server:reply_blob>   # several ranges: 206 may be multipart/byteranges
<exchange_artwork> ::= <Client:req_artwork> <Server:reply_blob>             # bj IV.10
<exchange_resolve> ::= <Client:req_resolve> <Server:reply_blob>                # sf-index /resolve
<exchange_logout> ::= <Client:req_logout> <Server:reply_logout>                                          # sf-index /logout
# credentials are offered, in the header form bj IV.3 names, whether or not the server announced that login is required (it may ignore them)
<exchange_credentials_offered> ::= <Client:req_databases_credentials> <Server:reply_info>   # bj IV.3 Login (credentials)
# HTTP-level exchanges
<exchange_head> ::= <Client:req_head> <Server:resp_head>                       # rfc9110 9.3.2: the answer has the header section of the answer to GET and no content; 9.1: a server that does not implement HEAD may refuse
<exchange_http10> ::= <Client:req_server_info_http10> <Server:reply_info_http10>   # rfc9112 9.3 / C10
<exchange_connection_close> ::= <Client:req_connection_close> <Server:reply_info> <Closure:conn_closed>   # rfc9112 9.6

# the timer of /update: fixed id, runs as long as the client lets the request stay unanswered (the server may hold it, bj IV.4)
where all(str(<t>..<timer_id>) == '1' for <t> in *<update_start>)
where all(str(<t>..<timer_timeout>) == DAAP_UPDATE_WAIT_S for <t> in *<update_start>)
where all(str(<c>..<timer_id>) == '1' for <c> in *<update_cancel>)
where all(str(<e>..<timer_id>) == '1' for <e> in *<update_expired>)
# the timer of the idle wait before the first request: fixed id, as long as the client waits for a close the spec lets stay away
where all(str(<t>..<timer_id>) == '2' for <t> in *<idle_start>)
where all(str(<t>..<timer_timeout>) == DAAP_IDLE_WAIT_S for <t> in *<idle_start>)
where all(str(<c>..<timer_id>) == '2' for <c> in *<idle_cancel>)
where all(str(<e>..<timer_id>) == '2' for <e> in *<idle_expired>)
where forall <e> in <exchange_server_info>: reply_root_ok(<e>, "msrv")
where forall <e> in <exchange_content_codes>: reply_root_ok(<e>, "mccr")
where forall <e> in <exchange_login>: reply_root_ok(<e>, "mlog")
where forall <e> in <exchange_login_credentials>: reply_root_ok(<e>, "mlog")
where forall <e> in <exchange_update>: reply_root_ok(<e>, "mupd")
where forall <e> in <exchange_databases>: reply_root_ok(<e>, "avdb")
where forall <e> in <exchange_credentials_offered>: reply_root_ok(<e>, "avdb")
where forall <e> in <exchange_items>: reply_root_ok(<e>, "adbs", "apso")   # bj IV.6 names the root apso, Appendix A and the diagram adbs
where forall <e> in <exchange_containers>: reply_root_ok(<e>, "aply")
where forall <e> in <exchange_container_items>: reply_root_ok(<e>, "apso")
where forall <e> in <exchange_http10>: reply_root_ok(<e>, "msrv")
where forall <e> in <exchange_connection_close>: reply_root_ok(<e>, "msrv")

# ================================================ REQUESTS (sent by Fandango) =====================================
<crlf> ::= '\r\n'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<http_11> ::= 'HTTP/1.1'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<http_10> ::= 'HTTP/1.0'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<get> ::= 'GET'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<head> ::= 'HEAD'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_server_info> ::= '/server-info'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_content_codes> ::= '/content-codes'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_login> ::= '/login'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_logout> ::= '/logout'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_update> ::= '/update'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_databases> ::= '/databases'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<cmd_resolve> ::= '/resolve'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<seg_items> ::= '/items'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<seg_containers> ::= '/containers'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<seg_artwork> ::= '/extra_data/artwork'   # sf-index Request URIs, bj IV, rfc9112 3 request line
<ext_mp3> ::= '.mp3'   # sf-index Request URIs, bj IV, rfc9112 3 request line

<req_server_info> ::= <get> ' ' <cmd_server_info> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<req_content_codes> ::= <get> ' ' <cmd_content_codes> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<req_login> ::= <get> ' ' <cmd_login> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
# credentials sent with the login request (in the header form the spec names, so that it never equals <req_login>) whether or not the server announced that login is required
<req_login_credentials> ::= <get> ' ' <cmd_login> ' ' <http_11> <crlf> <hdr_host> <hdr_authentication> <req_headers_without_host> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<req_logout> ::= <get> ' ' <cmd_logout> '?' <q_session> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<req_update> ::= <get> ' ' <cmd_update> '?' <q_update> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<q_update> ::= <q_session> | <q_session> '&' <q_revision> | <q_revision> '&' <q_session>   # bj IV request parameters (session-id, revision-id, type, meta)
<req_databases> ::= <get> ' ' <cmd_databases> '?' <q_session_revision> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<req_items> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_items> '?' <q_items> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.6-IV.8
<q_items> ::= <q_type> '&' <q_meta_song> '&' <q_session_revision> | <q_session_revision> '&' <q_type> '&' <q_meta_song> | <q_type> '&' <q_session_revision>   # bj IV request parameters (session-id, revision-id, type, meta)
<req_containers> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_containers> '?' <q_meta_container> '&' <q_session_revision> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.6-IV.8
<req_container_items> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_containers> '/' <container_id> <seg_items> '?' <q_type> '&' <q_meta_playlist> '&' <q_session_revision> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.6-IV.8
<req_stream> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_items> '/' <item_id> <ext_mp3> '?' <q_session> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.9-IV.10
<req_stream_range> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_items> '/' <item_id> <ext_mp3> '?' <q_session> ' ' <http_11> <crlf> <req_headers_range> <crlf>   # bj IV.9-IV.10
<req_stream_multirange> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_items> '/' <item_id> <ext_mp3> '?' <q_session> ' ' <http_11> <crlf> <req_headers_ranges> <crlf>   # bj IV.9-IV.10
<req_artwork> ::= <get> ' ' <cmd_databases> '/' <db_id> <seg_items> '/' <item_id> <seg_artwork> '?' <q_session> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.9-IV.10
<req_resolve> ::= <get> ' ' <cmd_resolve> '?' <q_session> ' ' <http_11> <crlf> <req_headers> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<q_session_revision> ::= <q_session> '&' <q_revision> | <q_revision> '&' <q_session>   # bj IV request parameters (session-id, revision-id, type, meta)
# HTTP-level requests
<req_head> ::= <head> ' ' <cmd_server_info> ' ' <http_11> <crlf> <req_headers> <crlf>   # rfc9110 9.3.2, rfc9112 9.3/9.6
<req_server_info_http10> ::= <get> ' ' <cmd_server_info> ' ' <http_10> <crlf> <req_headers_10> <crlf>   # bj IV.1-IV.5, sf-index Request URIs
<req_connection_close> ::= <get> ' ' <cmd_server_info> ' ' <http_11> <crlf> <hdr_host> <hdr_connection_close> <req_headers_without_host> <crlf>   # rfc9110 9.3.2, rfc9112 9.3/9.6
<req_databases_credentials> ::= <get> ' ' <cmd_databases> '?' <q_session_revision> ' ' <http_11> <crlf> <hdr_host> <hdr_authentication> <req_headers_without_host> <crlf>   # bj IV.1-IV.5, sf-index Request URIs

<q_session> ::= 'session-id=' <session_id_value>   # bj IV request parameters (session-id, revision-id, type, meta)
<q_revision> ::= 'revision-id=' <revision_id_value>   # bj IV request parameters (session-id, revision-id, type, meta)
<q_type> ::= 'type=' <item_type_music>   # bj IV request parameters (session-id, revision-id, type, meta)
<item_type_music> ::= 'music'   # bj IV request parameters (session-id, revision-id, type, meta)
<q_meta_song> ::= 'meta=' <meta_song_list>   # bj IV request parameters (session-id, revision-id, type, meta)
<q_meta_container> ::= 'meta=' <meta_container_list>   # bj IV request parameters (session-id, revision-id, type, meta)
<q_meta_playlist> ::= 'meta=' <meta_playlist_list>   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_song_list> ::= <meta_song_name> (',' <meta_song_name>)*   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_container_list> ::= <meta_container_name> (',' <meta_container_name>)*   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_playlist_list> ::= <meta_playlist_name> (',' <meta_playlist_name>)*   # bj IV request parameters (session-id, revision-id, type, meta)
# unsigned decimal integers (bj Appendix C: the session id must be unsigned); values are picked by generators that recall what
# the replies named (recording: dmap_read) and fall back to the configured targets
<session_id_value> ::= r'[0-9]{1,10}' := recall_last("sid", [1])   # bj IV request parameters (session-id, revision-id, type, meta)
<revision_id_value> ::= r'[0-9]{1,10}' := recall_last("rev", DAAP_REVISION_IDS)   # bj IV request parameters (session-id, revision-id, type, meta)
<db_id> ::= r'[0-9]{1,10}' := recall("db", DAAP_DATABASE_IDS)   # bj IV request parameters (session-id, revision-id, type, meta)
<container_id> ::= r'[0-9]{1,10}' := recall("container", DAAP_CONTAINER_IDS)   # bj IV request parameters (session-id, revision-id, type, meta)
<item_id> ::= r'[0-9]{1,10}' := recall("item", DAAP_ITEM_IDS)   # bj IV request parameters (session-id, revision-id, type, meta)
where forall <q> in <q_session>: str(<q>.<session_id_value>) == expected_session_id(str(<q>.<session_id_value>))

# request headers: Host is mandatory in HTTP/1.1 requests and equals the authority of the target URI (rfc9112 3.2); once an earlier
# reply (msrv: mslr) showed that login is required, every request carries the credentials (bj IV.3: "from this point on, a basic
# http authentication header needs to be included with the request")
<req_headers> ::= <hdr_host> <req_headers_without_host>   # rfc9110 9.3.2, rfc9112 9.3/9.6
<req_headers_without_host> ::= <hdr_authorization>{auth_header_count()} <hdr_accept>? <hdr_user_agent>? <hdr_daap_version>? <hdr_accept_language>? <hdr_accept_encoding>?   # rfc9110 9.3.2, rfc9112 9.3/9.6
<req_headers_10> ::= <hdr_host>? <req_headers_without_host>   # rfc9110 9.3.2, rfc9112 9.3/9.6
<req_headers_range> ::= <hdr_host> <req_headers_without_host> <hdr_range>   # rfc9110 9.3.2, rfc9112 9.3/9.6
<req_headers_ranges> ::= <hdr_host> <req_headers_without_host> <hdr_range_set>   # rfc9110 9.3.2, rfc9112 9.3/9.6
<hdr_host> ::= 'Host: ' <host_value> <crlf>   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<host_value> ::= r'[0-9A-Za-z.:\[\]-]+' := DAAP_AUTHORITY   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<hdr_connection_close> ::= 'Connection: close' <crlf>   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
# bj IV.3 names the header "Authentication: base64encodedusernamepassword" (the base64 of username:password); rfc9110 11.6.2 names it Authorization (Basic scheme)
<hdr_authorization> ::= 'Authorization: Basic ' <basic_credentials> <crlf>   # bj IV.3 Login (basic authentication)
<hdr_authentication> ::= 'Authentication: ' <basic_credentials> <crlf>   # bj IV.3 Login (basic authentication)
<basic_credentials> ::= r'[A-Za-z0-9+/]+={0,2}' := valid_credentials()   # bj IV.3 Login (basic authentication)
<hdr_range> ::= 'Range: bytes=' <byte_range_spec> <crlf> | 'Range: ' <range_unit_other> '=' <byte_range_spec> <crlf>   # a unit other than bytes is ignored by the server (rfc9110 14.2)
<range_unit_other> ::= 'items' | 'lines' | 'x-song'            # rfc9110 14.1.2 byte-range-spec / suffix-byte-range-spec
<hdr_range_set> ::= 'Range: bytes=' <byte_range_spec> (',' <ows> <byte_range_spec>)+ <crlf>   # a set of several ranges (rfc9110 14.1.1 range-set)
<byte_range_spec> ::= <range_closed> | <range_open> | <range_suffix> | <range_unsatisfiable> | <range_suffix_zero>   # bj IV.9 (range header), rfc9110 14.1-14.2
<range_closed> ::= r'[0-9]{1,10}-[0-9]{1,10}' := closed_range()   # bj IV.9 (range header), rfc9110 14.1-14.2
<range_open> ::= r'[0-9]{1,5}-' := open_range()   # bj IV.9 (range header), rfc9110 14.1-14.2
<range_suffix> ::= r'-[0-9]{1,9}' := suffix_range()   # bj IV.9 (range header), rfc9110 14.1-14.2
<range_unsatisfiable> ::= r'[0-9]{6,10}-' := unsatisfiable_range()   # first-pos beyond the end of the song: 416 (rfc9110 15.5.17)
<range_suffix_zero> ::= '-0'                                           # suffix-length 0 is unsatisfiable (rfc9110 14.1.2)
<hdr_user_agent> ::= 'User-Agent: ' <user_agent_value> <crlf>      # sf-index sample request
<user_agent_value> ::= 'iTunes/4.0 (Macintosh; N; PPC)' | 'iTunes/12.9.0 (Windows; Microsoft Windows 10 x64)' | 'Rhythmbox/3.4.4' | r'[A-Za-z][A-Za-z0-9._-]{2,14}/[0-9]{1,2}\.[0-9]{1,2}'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<hdr_accept> ::= 'Accept: ' <accept_value> <crlf>   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<accept_value> ::= '*/*' | 'application/x-dmap-tagged' | '*/*, application/x-dmap-tagged;q=0.9'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<hdr_daap_version> ::= 'Client-DAAP-Version: ' <daap_version_value> <crlf>   # sf-index: iTunes sends "1.0"
<daap_version_value> ::= '1.0' | '2.0' | '3.0' | r'[0-9]\.[0-9]'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<hdr_accept_language> ::= 'Accept-Language: ' <accept_language_value> <crlf>   # sf-codes sample request
<accept_language_value> ::= 'en-us, en;q=0.93' | 'en' | 'de;q=0.5, *;q=0.1'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<hdr_accept_encoding> ::= 'Accept-Encoding: ' <accept_encoding_value> <crlf> | 'Accept-Encoding:' <crlf>   # rfc9110 12.5.3: #( codings [ weight ] ), may be empty
<accept_encoding_value> ::= <ae_item> (',' <ows> <ae_item>)*   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_item> ::= <ae_coding> <ae_weight>?   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_coding> ::= <ae_gzip> | <ae_deflate> | <ae_identity> | <ae_any> | <ae_br> | <ae_compress> | <ae_x_gzip>   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_gzip> ::= 'gzip'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_deflate> ::= 'deflate'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_identity> ::= 'identity'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_any> ::= '*'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_br> ::= 'br'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_compress> ::= 'compress'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_x_gzip> ::= 'x-gzip'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2
<ae_weight> ::= ';q=' <qvalue>                                   # rfc9110 12.4.2 weight = OWS ";" OWS "q=" qvalue
<qvalue> ::= '0' | '0.' r'[0-9]{1,3}' | '1' | '1.' r'0{1,3}'   # sf-index Basic Form request headers, rfc9110 5/12, rfc9112 3.2

# meta field names: one nonterminal per name (bj IV.6/IV.7/IV.8 lists)
<meta_song_name> ::= <meta_dmap_itemid> | <meta_dmap_itemname> | <meta_dmap_itemkind> | <meta_dmap_persistentid> | <meta_daap_songalbum> | <meta_daap_songartist> | <meta_daap_songbitrate> | <meta_daap_songbeatsperminute> | <meta_daap_songcomment> | <meta_daap_songcompilation> | <meta_daap_songcomposer> | <meta_daap_songdateadded> | <meta_daap_songdatemodified> | <meta_daap_songdisccount> | <meta_daap_songdiscnumber> | <meta_daap_songdisabled> | <meta_daap_songeqpreset> | <meta_daap_songformat> | <meta_daap_songgenre> | <meta_daap_songdescription> | <meta_daap_songrelativevolume> | <meta_daap_songsamplerate> | <meta_daap_songsize> | <meta_daap_songstarttime> | <meta_daap_songstoptime> | <meta_daap_songtime> | <meta_daap_songtrackcount> | <meta_daap_songtracknumber> | <meta_daap_songuserrating> | <meta_daap_songyear> | <meta_daap_songdatakind> | <meta_daap_songdataurl> | <meta_com_apple_itunes_norm_volume>   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_container_name> ::= <meta_dmap_itemid> | <meta_dmap_itemname> | <meta_dmap_persistentid> | <meta_com_apple_itunes_smart_playlist>   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_playlist_name> ::= <meta_dmap_itemkind> | <meta_dmap_itemid> | <meta_dmap_containeritemid>   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_dmap_itemid> ::= 'dmap.itemid'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_dmap_itemname> ::= 'dmap.itemname'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_dmap_itemkind> ::= 'dmap.itemkind'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_dmap_persistentid> ::= 'dmap.persistentid'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songalbum> ::= 'daap.songalbum'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songartist> ::= 'daap.songartist'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songbitrate> ::= 'daap.songbitrate'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songbeatsperminute> ::= 'daap.songbeatsperminute'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songcomment> ::= 'daap.songcomment'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songcompilation> ::= 'daap.songcompilation'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songcomposer> ::= 'daap.songcomposer'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdateadded> ::= 'daap.songdateadded'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdatemodified> ::= 'daap.songdatemodified'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdisccount> ::= 'daap.songdisccount'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdiscnumber> ::= 'daap.songdiscnumber'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdisabled> ::= 'daap.songdisabled'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songeqpreset> ::= 'daap.songeqpreset'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songformat> ::= 'daap.songformat'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songgenre> ::= 'daap.songgenre'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdescription> ::= 'daap.songdescription'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songrelativevolume> ::= 'daap.songrelativevolume'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songsamplerate> ::= 'daap.songsamplerate'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songsize> ::= 'daap.songsize'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songstarttime> ::= 'daap.songstarttime'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songstoptime> ::= 'daap.songstoptime'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songtime> ::= 'daap.songtime'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songtrackcount> ::= 'daap.songtrackcount'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songtracknumber> ::= 'daap.songtracknumber'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songuserrating> ::= 'daap.songuserrating'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songyear> ::= 'daap.songyear'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdatakind> ::= 'daap.songdatakind'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_daap_songdataurl> ::= 'daap.songdataurl'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_com_apple_itunes_norm_volume> ::= 'com.apple.itunes.norm-volume'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_com_apple_itunes_smart_playlist> ::= 'com.apple.itunes.smart-playlist'   # bj IV request parameters (session-id, revision-id, type, meta)
<meta_dmap_containeritemid> ::= 'dmap.containeritemid'   # bj IV request parameters (session-id, revision-id, type, meta)

# ================================================ REPLIES (received from the server) ===============================
# HTTP/1.1 message syntax (rfc9112 §2.1, §4, §5, §6, §7.1): status-line, field lines, body framing by Content-Length or by
# chunked transfer coding or by connection close.  Header order is free for received messages.
<http_version> ::= 'HTTP/' <digit> '.' <digit>                      # rfc9112 2.3 HTTP-version
<sc_ok> ::= '200'   # rfc9112 2.3 HTTP-version, 4 status-line
<sc_no_content> ::= '204'   # rfc9112 2.3 HTTP-version, 4 status-line
<sc_partial> ::= '206'   # rfc9112 2.3 HTTP-version, 4 status-line
<sc_non2xx> ::= r'[1345][0-9]{2}'                                 # any other status code that is not 2xx
<sc_2xx_other> ::= r'2(?!00|04|06)[0-9]{2}'   # rfc9112 2.3 HTTP-version, 4 status-line
<reason_phrase> ::= r'[\t \x21-\x7e\x80-\xff]'*                     # rfc9112 4: reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ), may be empty
<line_ok> ::= <http_version> ' ' <sc_ok> ' ' <reason_phrase> <crlf>   # rfc9112 2.3 HTTP-version, 4 status-line
<line_204> ::= <http_version> ' ' <sc_no_content> ' ' <reason_phrase> <crlf>   # rfc9112 2.3 HTTP-version, 4 status-line
<line_206> ::= <http_version> ' ' <sc_partial> ' ' <reason_phrase> <crlf>   # rfc9112 2.3 HTTP-version, 4 status-line
<line_2xx_other> ::= <http_version> ' ' <sc_2xx_other> ' ' <reason_phrase> <crlf>   # rfc9112 2.3 HTTP-version, 4 status-line
<line_non2xx> ::= <http_version> ' ' <sc_non2xx> ' ' <reason_phrase> <crlf>   # rfc9112 2.3 HTTP-version, 4 status-line

<ows> ::= r'[ \t]'*                                                 # rfc9110 5.6.3
<hdr_value> ::= <field_content>? (<ows> <crlf> r'[ \t]'+ <field_content>)*   # field-value with obs-fold (rfc9112 5.2)
<field_content> ::= r'[\x21-\x7e\x80-\xff]([\t \x21-\x7e\x80-\xff]*[\x21-\x7e\x80-\xff])?'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
# field-name = token; the framing headers and Content-Type have rules of their own
<hdr_other> ::= <name_other> ':' <ows> <hdr_value> <ows> <crlf>   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<name_other> ::= r"(?i)(?!(?:content-length|transfer-encoding|content-type|content-encoding)(?![-!#$%&'*+.^_`|~0-9A-Za-z]))[-!#$%&'*+.^_`|~0-9A-Za-z]+"   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<hdr_cl> ::= <name_cl> ':' <ows> <cl_value> <ows> <crlf>           # rfc9112 6.2 Content-Length = 1*DIGIT
<name_cl> ::= r'(?i)content-length'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<cl_value> ::= r'[0-9]*[1-9][0-9]*'                              # a positive length: octets follow
<hdr_cl_zero> ::= <name_cl> ':' <ows> <cl_zero> <ows> <crlf>        # Content-Length 0: the message ends with the header section
<cl_zero> ::= r'0+'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<hdr_te> ::= <name_te> ':' <ows> <hdr_value> <ows> <crlf>          # rfc9112 6.1 Transfer-Encoding
<name_te> ::= r'(?i)transfer-encoding'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<hdr_ce> ::= <name_ce> ':' <ows> <hdr_value> <ows> <crlf>          # rfc9110 8.4 Content-Encoding
<name_ce> ::= r'(?i)content-encoding'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<hdr_ct> ::= <name_ct> ':' <ows> <hdr_value> <ows> <crlf>          # rfc9110 8.3 Content-Type
<hdr_ct_dmap> ::= <name_ct> ':' <ows> <mime_dmap> (<mime_semi> <mime_param>?)* <ows> <crlf>     # sf-index: the content type of the data is application/x-dmap-tagged (rfc9110 8.3.1: parameters allowed)
<mime_semi> ::= r'[ \t]*;[ \t]*'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<mime_param> ::= <ext_name> '=' (<ext_name> | <quoted_string>)     # rfc9110 5.6.6 parameter = parameter-name "=" parameter-value (token / quoted-string)
<quoted_string> ::= '"' (<qdtext> | <quoted_pair>)* '"'               # rfc9110 5.6.4
<qdtext> ::= r'[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]'
<quoted_pair> ::= r'\\[\t \x21-\x7e\x80-\xff]'
<name_ct> ::= r'(?i)content-type'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<mime_dmap> ::= r'(?i)application/x-dmap-tagged'   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<hdr_any> ::= <hdr_other> | <hdr_ct> | <hdr_ce>   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4

# --- body by Content-Length: the number of octets is the header's value (blocks of 1024, 32 and 1 octets)
<body_by_cl> ::= <blk1024>{body_blocks(<cl_value>, 1024)} <blk32>{body_blocks(<cl_value>, 32)} <octet>{body_blocks(<cl_value>, 1)} <last_octet>{min(1, int(<cl_value>))}   # rfc9112 6.3 message body length, 7.1 chunked coding
<blk1024> ::= rb'[\x00-\xff]{1024}'   # rfc9112 6.3 message body length, 7.1 chunked coding
<blk32> ::= rb'[\x00-\xff]{32}'   # rfc9112 6.3 message body length, 7.1 chunked coding

# --- chunked transfer coding (rfc9112 7.1)
<chunked_body> ::= <chunk>* <last_chunk> <trailer_line>* <crlf>   # rfc9112 6.3 message body length, 7.1 chunked coding
<chunk> ::= <chunk_size_nz> <chunk_ext>* <crlf> <chunk_data> <crlf>   # rfc9112 6.3 message body length, 7.1 chunked coding
<chunk_size_nz> ::= r'[0-9a-fA-F]*[1-9a-fA-F][0-9a-fA-F]*'   # rfc9112 6.3 message body length, 7.1 chunked coding
<chunk_data> ::= <blk1024>{body_blocks(<chunk_size_nz>, 1024, 16)} <blk32>{body_blocks(<chunk_size_nz>, 32, 16)} <octet>{body_blocks(<chunk_size_nz>, 1, 16)} <last_octet>   # rfc9112 6.3 message body length, 7.1 chunked coding
<last_chunk> ::= r'0+' <chunk_ext>* <crlf>   # rfc9112 6.3 message body length, 7.1 chunked coding
<chunk_ext> ::= <ows> ';' <ows> <ext_name> (<ows> '=' <ows> <ext_value>)?   # rfc9112 7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
<ext_name> ::= r"[-!#$%&'*+.^_`|~0-9A-Za-z]+"   # sf-index Request URIs, bj IV, rfc9112 3 request line
<ext_value> ::= <ext_name> | <quoted_string>                                  # chunk-ext-val = token / quoted-string
<trailer_line> ::= <hdr_other>   # rfc9112 6.3 message body length, 7.1 chunked coding

# --- the reply classes
# Header sections are built so that every message parses one way: Content-Length, Transfer-Encoding and Content-Encoding each have a
# rule of their own and <hdr_y> (any other field line, Content-Type included) never matches them; a reply with a Content-Encoding field
# is a <resp_coded>, one without it a <resp_dmap>, <resp_blob>... (rfc9112 6.1: Content-Length and Transfer-Encoding never together, C9).
<line_2xx_body> ::= <line_ok> | <line_206> | <line_2xx_other>        # a 2xx reply that has content (204 has none)

# (a) typed DMAP reply: 200, Content-Type application/x-dmap-tagged, framed by Content-Length, by chunked coding or by the connection close;
# every framing carries the body twice (octets and chunk structure, a converter pair) so that what the reply names is recorded
<resp_dmap> ::= <head_dmap> <body_raw_dmap> | <head_dmap_te> <body_chunked_dmap> | <head_dmap_close> <body_close_dmap>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_dmap> ::= (<line_ok> <hdr_other>* <hdr_ct_dmap> <hdr_other>* <hdr_cl> <hdr_other>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
    | <line_ok> <hdr_other>* <hdr_cl> <hdr_other>* <hdr_ct_dmap> <hdr_other>* <crlf>)
<head_dmap_te> ::= (<line_ok> <hdr_other>* <hdr_ct_dmap> <hdr_other>* <hdr_te> <hdr_other>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
    | <line_ok> <hdr_other>* <hdr_te> <hdr_other>* <hdr_ct_dmap> <hdr_other>* <crlf>)
<head_dmap_close> ::= <line_ok> <hdr_other>* <hdr_ct_dmap> <hdr_other>* <crlf>   # no Content-Length, no Transfer-Encoding: the body runs until the server closes (rfc9112 6.3)
<body_chunked_dmap> ::= <chunked_body> := dmap_chunk_wire(<dmap_tree_te>)
<dmap_tree_te> ::= <dmap_body> := dmap_read(dmap_unchunk(<body_chunked_dmap>))   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
<body_close_dmap> ::= <close_body> := dmap_wire(<dmap_tree_close>)
<dmap_tree_close> ::= <dmap_body> := dmap_read(<body_close_dmap>)   # DMAP chunks: sf-index Data Format, bj III, Appendix A (codes) and B (types)
# (b) an HTTP refusal: any status that is not 2xx, framed by Content-Length, chunked coding or the connection close
<resp_refusal> ::= <head_cl_non2xx> <body_by_cl> | <head_cl_zero_non2xx> | <head_te_non2xx> <chunked_body> | <head_plain_non2xx> <close_body>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_cl_non2xx> ::= <line_non2xx> <hdr_any>* <hdr_cl> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_cl_zero_non2xx> ::= <line_non2xx> <hdr_any>* <hdr_cl_zero> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_te_non2xx> ::= <line_non2xx> <hdr_any>* <hdr_te> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_plain_non2xx> ::= <line_non2xx> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<close_body> ::= <byte>*   # rfc9112 6.3 message body length, 7.1 chunked coding
# (c) a stream or image: any 2xx with content, any content type, no Content-Encoding, framed by Content-Length, chunked coding or the connection close
<resp_blob> ::= <head_blob> <body_by_cl> | <head_blob_zero>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_blob_zero> ::= <line_2xx_body> <hdr_y>* <hdr_cl_zero> <hdr_y>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_blob> ::= <line_2xx_body> <hdr_y>* <hdr_cl> <hdr_y>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<resp_blob_te> ::= <head_blob_te> <chunked_body>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_blob_te> ::= <line_2xx_body> <hdr_y>* <hdr_te> <hdr_y>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<resp_blob_close> ::= <head_blob_plain> <close_body>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_blob_plain> ::= <line_2xx_body> <hdr_y>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
# (d) no content: 204 (rfc9110 15.3.5: no Content-Length, no content)
<resp_204> ::= <head_204>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_204> ::= <line_204> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
# (e) a content-coded 2xx reply (rfc9110 8.4; the coding, e.g. gzip, is another format: the octets are carried opaquely), framed like any other
<resp_coded> ::= <head_coded_cl> <body_by_cl> | <head_coded_zero> | <head_coded_te> <chunked_body> | <head_coded_close> <close_body>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_coded_cl> ::= <line_2xx_body> <hdr_y>* <hdr_cl> <hdr_y>* <hdr_ce> <hdr_any>* <crlf> | <line_2xx_body> <hdr_y>* <hdr_ce> <hdr_any>* <hdr_cl> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_coded_zero> ::= <line_2xx_body> <hdr_y>* <hdr_cl_zero> <hdr_y>* <hdr_ce> <hdr_any>* <crlf> | <line_2xx_body> <hdr_y>* <hdr_ce> <hdr_any>* <hdr_cl_zero> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_coded_te> ::= <line_2xx_body> <hdr_y>* <hdr_te> <hdr_y>* <hdr_ce> <hdr_any>* <crlf> | <line_2xx_body> <hdr_y>* <hdr_ce> <hdr_any>* <hdr_te> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_coded_close> ::= <line_2xx_body> <hdr_y>* <hdr_ce> <hdr_any>* <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<hdr_y> ::= <hdr_other> | <hdr_ct>   # rfc9112 5 field syntax, 6 Content-Length / Transfer-Encoding, rfc9110 8.3/8.4
<reply_info> ::= <resp_dmap> | <resp_coded> | <resp_refusal>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<reply_login> ::= <resp_dmap> | <resp_coded>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<reply_blob> ::= <resp_blob> | <resp_blob_te> | <resp_blob_close> | <resp_coded> | <resp_204> | <resp_refusal>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<reply_logout> ::= <reply_blob>   # the documents define no reply to /logout (nor to /resolve): every HTTP reply is accepted
# no Transfer-Encoding in replies to HTTP/1.0 requests (rfc9112 6.1; C10)
<reply_info_http10> ::= <resp_dmap_10> | <resp_coded_10> | <resp_refusal_10>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<resp_dmap_10> ::= <head_dmap> <body_raw_dmap> | <head_dmap_close> <body_close_dmap>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<resp_coded_10> ::= <head_coded_cl> <body_by_cl> | <head_coded_zero> | <head_coded_close> <close_body>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<resp_refusal_10> ::= <head_cl_non2xx> <body_by_cl> | <head_cl_zero_non2xx> | <head_plain_non2xx> <close_body>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
# the answer to HEAD: the header section of the answer to GET and no content (rfc9110 9.3.2). A server that does not implement HEAD
# answers with a 4xx/5xx status such as 501 (rfc9110 9.1: the requirement to support HEAD binds general-purpose servers only), so every
# status is accepted; Content-Length and Transfer-Encoding at most one of them (rfc9112 6.2)
<resp_head> ::= <head_head>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<head_head> ::= <line_head> <hdr_any>* (<hdr_cl> <hdr_any>* | <hdr_cl_zero> <hdr_any>* | <hdr_te> <hdr_any>*)? <crlf>   # reply classes: sf-index, bj IV, rfc9110 15, rfc9112 6
<line_head> ::= <http_version> ' ' <sc_head> ' ' <reason_phrase> <crlf>   # rfc9112 2.3 HTTP-version, 4 status-line
<sc_head> ::= r'[1-5][0-9]{2}'   # rfc9112 2.3 HTTP-version, 4 status-line

# ================================================ CONSTRAINTS =====================================================
def split_http(data):
    data = bytes(data)
    end = data.find(b"\r\n\r\n")
    head, body = (data[:end], data[end + 4:]) if end >= 0 else (data, b"")
    lines = head.split(b"\r\n")
    headers = []
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t") and headers:
            headers[-1][1] += b" " + line.strip()
        elif b":" in line:
            name, _, value = line.partition(b":")
            headers.append([name.strip().lower().decode("latin-1"), value.strip()])
    return lines[0].decode("latin-1"), headers, body

def header_names(headers):
    return {name for name, _ in headers}

TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
# rfc9110 11.6.1: WWW-Authenticate = #challenge, challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]: the first non-empty element starts with an auth-scheme token
CHALLENGE = re.compile(rb"^(?:[ \t]*,)*[ \t]*" + TOKEN + rb"(?:[ \t]|,|$)")
CONTENT_RANGE = re.compile(rb"^bytes ([0-9]+)-([0-9]+)/([0-9]+|\*)$", re.IGNORECASE)   # rfc9110 14.1: range unit names are case-insensitive

def multipart_byteranges(headers):
    """rfc9110 14.6: the 206 reply to a request for several ranges may be a multipart/byteranges body (the Content-Range fields are in its parts)."""
    return any(name == "content-type" and value.strip().lower().startswith(b"multipart/byteranges") for name, value in headers)

def has_challenge(headers):
    """rfc9110 11.6.1: a 401 reply carries WWW-Authenticate with at least one challenge."""
    return any(name == "www-authenticate" and CHALLENGE.match(value.strip()) for name, value in headers)

def content_range_ok(headers):
    """rfc9110 14.4 / 15.3.7.1: the 206 reply of a single part carries Content-Range: bytes first-last/complete-length that
    describes the enclosed range (first <= last < complete length; the Content-Length is last - first + 1)."""
    values = [value.strip() for name, value in headers if name == "content-range"]
    lengths = [value.strip() for name, value in headers if name == "content-length"]
    if len(values) != 1:
        return False
    match = CONTENT_RANGE.match(values[0])
    if not match:
        return False
    first, last = int(match.group(1)), int(match.group(2))
    if first > last or (match.group(3) != b"*" and last >= int(match.group(3))):
        return False
    return not lengths or (lengths[0].isdigit() and int(lengths[0]) == last - first + 1)

def request_ranges(node):
    """The number of ranges of the Range header of the request of the exchange the node belongs to (None: no exchange around the node)."""
    while node is not None:
        name = str(getattr(node.symbol, "name", lambda: node.symbol)()).strip("<>")
        if name.startswith("exchange_"):
            data = bytes(node)
            head = data[:data.find(b"\r\n\r\n")] if b"\r\n\r\n" in data else data
            for line in head.split(b"\r\n"):
                if line[:6].lower() == b"range:":
                    return line.count(b",") + 1
            return 0
        node = node.parent
    return None

def single_part_206_ok(node, headers):
    """rfc9110 15.3.7: a 206 of one part carries a valid Content-Range.  A multipart/byteranges 206 (14.6, 15.3.7.2) answers a request for
    several ranges only (a server MUST NOT generate a multipart response to a request for a single range) and carries no Content-Range
    in its header section."""
    if multipart_byteranges(headers):
        ranges = request_ranges(node)
        return (ranges is None or ranges > 1) and not any(name == "content-range" for name, _ in headers)
    return content_range_ok(headers)

def head_ok(head):
    """Header-level requirements on a reply: rfc9110 6.6.1 Date, 15.3.7 Content-Range of 206, 11.6.1 WWW-Authenticate of 401,
    15.3.5 no Content-Length in 204."""
    status, headers, _ = split_http(head)
    parts = status.split(" ")
    try:
        code = int(parts[1])
    except (IndexError, ValueError):
        return False
    names = header_names(headers)
    if 200 <= code < 500:
        # rfc9110 6.6.1: an origin server with a clock MUST send Date; the clock shows once any reply of the session carried one
        if "date" in names:
            SESSION["date_seen"] = True
        elif SESSION.get("date_seen"):
            return False
    if code == 401 and not has_challenge(headers):
        return False
    if code == 206 and not single_part_206_ok(head, headers):
        return False
    if (code == 204 or code < 200) and "content-length" in names:
        return False
    return True

def dechunk(body):
    """The data of a chunked body (rfc9112 7.1); None when it is not well formed."""
    out = b""
    i = 0
    while True:
        eol = body.find(b"\r\n", i)
        if eol < 0:
            return None
        try:
            size = int(body[i:eol].split(b";")[0].strip() or b"x", 16)
        except ValueError:
            return None
        if size == 0:
            return out
        out += body[eol + 2:eol + 2 + size]
        i = eol + 2 + size + 2

def message_content(response):
    """The content of a reply: the body, with the chunked coding removed when Transfer-Encoding says so."""
    _, headers, body = split_http(response)
    if any(name == "transfer-encoding" and b"chunked" in value.lower() for name, value in headers):
        return dechunk(body) or b""
    return body

def coded_body_announced(response):
    """rfc9110 8.4: content that has had a coding applied carries Content-Encoding naming it.  The coding shows from the
    content's first octets only for gzip (rfc1952 magic 1f 8b 08)."""
    _, headers, _ = split_http(response)
    return not message_content(response).startswith(b"\x1f\x8b\x08") or "content-encoding" in header_names(headers)

def root_tag(response):
    return message_content(response)[:4].decode("latin-1")

where forall <h> in <head_dmap>: head_ok(<h>)
where forall <h> in <head_dmap_te>: head_ok(<h>)
where forall <h> in <head_dmap_close>: head_ok(<h>)
where forall <h> in <head_cl_non2xx>: head_ok(<h>)
where forall <h> in <head_te_non2xx>: head_ok(<h>)
where forall <h> in <head_plain_non2xx>: head_ok(<h>)
where forall <h> in <head_cl_zero_non2xx>: head_ok(<h>)
where forall <h> in <head_blob>: head_ok(<h>)
where forall <h> in <head_blob_zero>: head_ok(<h>)
where forall <h> in <head_blob_te>: head_ok(<h>)
where forall <h> in <head_blob_plain>: head_ok(<h>)
where forall <h> in <head_204>: head_ok(<h>)
where forall <h> in <head_coded_cl>: head_ok(<h>)
where forall <h> in <head_coded_zero>: head_ok(<h>)
where forall <h> in <head_coded_te>: head_ok(<h>)
where forall <h> in <head_coded_close>: head_ok(<h>)
where forall <h> in <head_head>: head_ok(<h>)
# rfc9110 8.4 / C11: content that has had a content coding applied (gzip: rfc1952, magic 1f 8b 08) carries a Content-Encoding header, whatever the status and the framing
where forall <r> in <resp_blob>: coded_body_announced(<r>)
where forall <r> in <resp_blob_te>: coded_body_announced(<r>)
where forall <r> in <resp_blob_close>: coded_body_announced(<r>)
where forall <r> in <resp_refusal>: coded_body_announced(<r>)
where forall <r> in <resp_refusal_10>: coded_body_announced(<r>)

def exchange_reply(exchange):
    """(status line, headers, body) of the reply of an exchange (request first, then the reply; timers around them are text without CRLF CRLF)."""
    data = bytes(exchange)
    i = data.find(b"\r\n\r\n")
    if i < 0:
        return ("", [], b"")
    status, headers, body = split_http(data[i + 4:])
    if any(name == "transfer-encoding" and b"chunked" in value.lower() for name, value in headers):
        body = dechunk(body) or b""
    return status, headers, body

def reply_root_ok(exchange, tag, other_tag=None):
    """A typed DMAP reply answers the request that asked for it: its top-level chunk is the one the request defines."""
    status, headers, body = exchange_reply(exchange)
    names = dict(headers)
    if not status.startswith("HTTP/1.") or status.split(" ")[1:2] != ["200"] or "content-encoding" in names:
        return True
    if b"application/x-dmap-tagged" not in names.get("content-type", b"").lower():
        return True
    return body[:4] in (tag.encode(), (other_tag or tag).encode())
