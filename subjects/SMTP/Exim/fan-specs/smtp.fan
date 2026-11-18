# ======================================================================================================
# SMTP (RFC 5321) with the extensions of refs/spec/manifest.json: SIZE, 8BITMIME, STARTTLS, AUTH (PLAIN),
# DSN, ENHANCEDSTATUSCODES, PIPELINING, CHUNKING/BINARYMIME, ETRN.  Fandango plays `Client`, the server
# under test plays `Server`.  Syntax references are to RFC 5321 unless another RFC is named.
# ======================================================================================================
import os, random, base64, re

# ------------------------------------------------------------------------------------------------------
# TEST SETUP (everything the test setup decides lives here; each value comes from an environment variable)
# ------------------------------------------------------------------------------------------------------
def env_list(name, default):
    return [item for item in os.environ.get(name, "").split(",") if item] or default

# Identities the client gives in EHLO/HELO (a domain and an address literal, section 4.1.3)
EHLO_DOMAINS = env_list("SMTP_EHLO_DOMAINS", ["client.example.net", "[127.0.0.1]"])
# Domains for HELO (HELO takes a Domain only, EHLO also an address literal)
HELO_DOMAINS = env_list("SMTP_HELO_DOMAINS", ["client.example.net"])
# The client's own names of the longest length a domain may have, 255 octets (4.5.3.1.2): names of the client's host in the test setup, sent by <req_ehlo_max> and <req_helo_max>
LONG_NAME = ".".join(["c" * 63, "l" * 63, "i" * 63, "e" * 63])
EHLO_LONG_DOMAINS = env_list("SMTP_EHLO_LONG_DOMAINS", [LONG_NAME])
HELO_LONG_DOMAINS = env_list("SMTP_HELO_LONG_DOMAINS", [LONG_NAME])
# Domains the server accepts mail for (targets of RCPT)
LOCAL_DOMAINS = env_list("SMTP_LOCAL_DOMAINS", ["example.test"])
# Local-parts of mailboxes the server setup offers (targets of RCPT, VRFY)
MAIL_USERS = env_list("SMTP_MAIL_USERS", ["postmaster"])
# Names that do not exist on the server (targets of RCPT/VRFY that the server refuses or accepts)
UNKNOWN_USERS = env_list("SMTP_UNKNOWN_USERS", ["nosuchuser", "nobody-here"])
# Domains the server does not serve (relay targets)
REMOTE_DOMAINS = env_list("SMTP_REMOTE_DOMAINS", ["remote.example.org"])
# Mailing-list names for EXPN and domains for ETRN
EXPN_LISTS = env_list("SMTP_EXPN_LISTS", ["postmaster", "list"])
ETRN_TARGETS = env_list("SMTP_ETRN_TARGETS", ["example.test", "@example.test"])
# Topics HELP is asked about: command names and a topic that does not exist
HELP_TOPICS = env_list("SMTP_HELP_TOPICS", ["MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY", "EXPN", "HELO", "EHLO", "HELP", "nosuchtopic"])
# Credentials the server accepts (the accepting AUTH exchange sends only these)
AUTH_USER = os.environ.get("SMTP_AUTH_USER", "testuser")
AUTH_PASSWORD = os.environ.get("SMTP_AUTH_PASSWORD", "secret")
# Deviations of a server that the grammar tolerates (comma-separated names, empty by default)
TOLERATED = env_list("TOLERATED", [])

def tolerated(name):
    return name in TOLERATED

# ------------------------------------------------------------------------------------------------------
# The connection: the server closes it only after a 221 reply to QUIT or a 421 reply (4.1.1.10, 4.2.2).  Any other
# close reaches the grammar as a message no rule derives, so it ends the session as a violation.
# ------------------------------------------------------------------------------------------------------
class ClientNetworkParty(NetworkParty):
    last_data = b""
    first_data = b""
    eof_seen = False
    stopping = False

    def start(self):
        # A server that closes with unread data pending (Postfix after an unannounced BDAT chunk) makes the connection
        # reset instead of ending it.  Fandango's listener then stops without telling the party, and the next request
        # waits for a reply that never comes.  A reset is a close: it is reported like one.
        self.eof_seen = False
        self.stopping = False
        impl = self.protocol_impl
        listen = impl._listen

        def listen_and_report_end():
            listen()
            if not self.stopping and not self.eof_seen and impl._connection is not None:
                self.receive(None, None)

        impl._listen = listen_and_report_end
        super().start()

    def stop(self):
        self.stopping = True
        super().stop()

    def receive(self, message, sender):
        if message is None:
            if self.eof_seen:
                return
            self.eof_seen = True
            # after a 521 greeting the server MAY close the connection instead of answering commands (RFC 7504 section 3)
            if self.last_data[:3] not in (b"221", b"421") and self.first_data[:3] != b"521":
                super().receive(b"<connection closed by the server>\r\n", sender)
            return
        data = message if isinstance(message, bytes) else str(message).encode("utf-8", "replace")
        self.last_data = data.splitlines()[-1] if data.splitlines() else data
        if not self.first_data:
            self.first_data = self.last_data
        super().receive(message, sender)

# ------------------------------------------------------------------------------------------------------
# Helpers of the constraints: they read earlier messages of the session through the tree
# ------------------------------------------------------------------------------------------------------
import datetime

def session_root(node):
    while node.parent is not None:
        node = node.parent
    return node

def message_of(node):
    """The protocol message (a node that has a sender) that contains `node`."""
    while node is not None and node.sender is None:
        node = node.parent
    return node

def symbol_name(node):
    return str(node.symbol).strip("<>")

def messages_before(node):
    """The protocol messages of the session that come before the first message inside `node`."""
    inner = {id(item.msg) for item in node.protocol_msgs()}
    before = []
    for item in session_root(node).protocol_msgs():
        if id(item.msg) in inner:
            break
        before.append(item.msg)
    return before

def history_before(node):
    """The messages of the session before the message that contains `node` (a received or a sent one)."""
    message = message_of(node)
    return messages_before(message if message is not None else node)

def first_message(node):
    for item in node.protocol_msgs():
        return item.msg
    return None

def ehlo_keywords(messages, reset_on_helo=True):
    """The keywords (with parameters) of the last EHLO reply among `messages`, none after a later HELO (a session without
    extensions); None if the session has no EHLO or HELO reply."""
    keywords = None
    for message in messages:
        if reset_on_helo and symbol_name(message) == "rep_helo_ok" and message.sender == "Server":
            keywords = {}
        if symbol_name(message) == "rep_ehlo_ok" and message.sender == "Server":
            lines = str(message).split("\r\n")
            keywords = {}
            for line in lines[1:]:
                words = line[4:].split(" ")
                if words and words[0]:
                    keywords[words[0].upper()] = words[1:]
    return keywords

def offers(node, keyword):
    """Whether the last EHLO reply before `node` announced `keyword`; None if no EHLO was answered yet."""
    keywords = ehlo_keywords(messages_before(node))
    return None if keywords is None else keyword in keywords

def offered_parameters(node, keyword):
    keywords = ehlo_keywords(messages_before(node))
    return None if keywords is None else keywords.get(keyword)

def offers_after_helo(node, keyword):
    """Whether any EHLO reply of the session before `node` announced `keyword`; a later HELO does not take it back."""
    keywords = ehlo_keywords(messages_before(node), False)
    return None if keywords is None else keyword in keywords

def authenticated(node):
    """Whether an AUTH exchange of the session before `node` was answered with 235 (RFC 4954 section 4)."""
    return any(message.sender == "Server" and str(message)[:3] == "235" for message in messages_before(node))

def reply_code(message):
    return str(message)[:3]

def reply_text_ok(text):
    """Enhanced status codes in reply texts, RFC 2034 section 3 / RFC 3463 section 2: the class digit matches the reply code,
    every line of a multiline reply starts with the same code, 3yz replies carry none, and with ENHANCEDSTATUSCODES offered
    every 2yz, 4yz and 5yz text carries one (the greeting and the replies to HELO and EHLO are exempt)."""
    message = message_of(text)
    code = reply_code(message)
    found = re.match(r"([245])\.[0-9]{1,3}\.[0-9]{1,3}(?: |$)", str(text))
    lines = [line[4:] for line in str(message).split("\r\n") if line]
    escs = {(re.match(r"[245]\.[0-9]{1,3}\.[0-9]{1,3}(?= |$)", line) or [None])[0] for line in lines}
    if len(escs) > 1:
        return False
    if found:
        return code[0] != "3" and found.group(1) == code[0]
    if code[0] in "245" and offers_after_helo(message, "ENHANCEDSTATUSCODES"):
        previous = messages_before(message)
        request = previous[-1] if previous else None
        if request is not None and str(request)[:4].upper() in ("EHLO", "HELO"):
            return True
        return False
    return True

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

def weekday_name(day, month, year):
    """The day of the week of a date (RFC 5322 section 3.3: the day-of-week must agree with the date)."""
    return DAYS[datetime.date(int(year), MONTHS.index(str(month)) + 1, int(day)).weekday()]

def xtext_encode(text):
    """xtext of RFC 3461 section 4: printable characters but "+" and "=" stay, the others become "+" and two uppercase hex digits."""
    out = []
    for byte in str(text).encode("utf-8", "surrogateescape"):
        out.append(chr(byte) if 33 <= byte <= 126 and byte not in (43, 61) else "+%02X" % byte)
    return "".join(out)

def xtext_decode(text):
    return re.sub(r"\+([0-9A-F]{2})", lambda match: chr(int(match.group(1), 16)), str(text))

def request_path_address(node):
    """The mailbox inside the forward-path of the RCPT command that contains `node` (without a source route)."""
    message = message_of(node)
    match = re.search(r"<(?:@[^:]*:)?([^>]*)>", str(message))
    return match.group(1) if match else ""

def size_declared(request):
    match = re.search(r" SIZE=([0-9]+)", str(request), re.I)
    return int(match.group(1)) if match else None

def reply_after_request(exchange):
    """The first reply of `exchange`."""
    for item in exchange.protocol_msgs():
        if item.sender == "Server":
            return item.msg
    return None

DSN_ONLY_PARAMS = re.compile(r"^MAIL FROM:<[^>]*>(?: (?:RET|ENVID)=\S*)+$", re.I)

def dsn_mail_refused_for_its_params(exchange):
    """A MAIL with valid RET/ENVID parameters only, refused as a syntax error or for its parameters although DSN is offered."""
    request = str(first_message(exchange)).rstrip("\r\n")
    if not offers(exchange, "DSN") or not DSN_ONLY_PARAMS.match(request) or not simple_address(first_message(exchange)):
        return False
    reply = reply_after_request(exchange)
    return reply_code(reply) in ("501", "555", "504") and re.search(r"ENVID|\bRET\b|DSN", str(reply), re.I) is not None

def bad_dsn_mail_param(request):
    """Whether the MAIL command has an invalid or repeated RET/ENVID value (RFC 3461 section 4.3, 4.4)."""
    text = str(request)
    rets = re.findall(r" RET=(\S*)", text, re.I)
    envids = re.findall(r" ENVID=(\S*)", text, re.I)
    return len(rets) > 1 or len(envids) > 1 or any(value.upper() not in ("FULL", "HDRS") for value in rets) \
        or any(re.search(r"[=]|[+](?![0-9A-F]{2})|[+](?:[01][0-9A-F]|7F|[89A-F][0-9A-F])|[^!-~]", value) for value in envids)

def supported_listed(exchange, keyword, required=False):
    """A command the server answers with 2yz is listed in the EHLO reply unless it is a required command (4.1.1.1, 4.5.1);
    a keyword the EHLO reply lists is never answered with 500 or 502 (4.2.4)."""
    keywords = ehlo_keywords(messages_before(exchange), False)
    if keywords is None:
        return True
    code = reply_code(reply_after_request(exchange))
    if code[0] in "23":
        return required or keyword in keywords
    if code in ("500", "502"):
        # a server may support HELP without arguments (4.1.1.8): a refusal of the argument says nothing about the command
        if keyword == "HELP" and re.match(r"HELP +\S", str(first_message(exchange)), re.I):
            return True
        # 500 5.5.6 is the reply of an AUTH line longer than the server's buffer (RFC 4954 section 6)
        if keyword == "AUTH" and code == "500" and ("5.5.6" in str(reply_after_request(exchange)) or len(str(first_message(exchange))) > 512):
            return True
        return keyword not in keywords
    return True

def listed_not_refused(exchange, keyword):
    """A keyword the EHLO reply lists is never answered with 500 or 502 (4.2.4)."""
    keywords = ehlo_keywords(messages_before(exchange), False)
    return keywords is None or keyword not in keywords or reply_code(reply_after_request(exchange)) not in ("500", "502")

def sendlike_listed(exchange):
    """SEND, SOML and SAML are published in the EHLO reply when implemented (appendix F.6), and a listed one is not refused
    as not implemented (4.2.4)."""
    verb = str(first_message(exchange))[:4].upper()
    keywords = ehlo_keywords(messages_before(exchange), False)
    if keywords is None:
        return True
    code = reply_code(reply_after_request(exchange))
    if code[0] == "2":
        return verb in keywords
    return not (code in ("500", "502") and verb in keywords)

def same_code_on_every_line(reply):
    """Every line of a multiline reply carries the same code (4.2.1)."""
    return len({line[:3] for line in str(reply).split("\r\n") if line}) <= 1

def simple_address(message):
    """Whether the request names the null path or a plain mailbox, so a refusal is not about the address."""
    request = str(message)
    return re.match(r"(?:MAIL FROM|RCPT TO):(?:<>|<[A-Za-z0-9._-]+@[A-Za-z0-9.-]+>)(?: |\r)", request, re.I) is not None

def refused_for_params(exchange, keyword, request_pattern, reply_pattern, codes=("501", "555", "504", "553")):
    """A command with valid parameters of an offered extension is not refused because of them (RFC 3461 section 4.5,
    RFC 4954 section 5): the reply is an error that names the parameter."""
    message = first_message(exchange)
    request = str(message).rstrip("\r\n")
    if not offers(exchange, keyword) or not re.search(request_pattern, request, re.I) or not simple_address(message):
        return False
    reply = reply_after_request(exchange)
    return reply_code(reply) in codes and re.search(reply_pattern, str(reply), re.I) is not None

AUTH_PARAM = re.compile(r" AUTH=(\S+)", re.I)
MAILBOX_SHAPE = re.compile(r"""(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[ !#-\[\]-~]|\\[ -~])*")@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|IPv6:[0-9A-Fa-f:.]+)\])""")

def refused_for_auth_param(exchange):
    """A MAIL whose AUTH parameter is "<>" or a valid <mailbox> (RFC 4954 section 5 names the <mailbox> syntax; an address literal with an unregistered general tag, RFC 5321 section 4.1.3, is not one)
    is not refused for it by a server that announced AUTH (RFC 4954 section 5: the server MUST support the parameter even without authentication)."""
    message = first_message(exchange)
    found = AUTH_PARAM.search(str(message))
    if found is None:
        return False
    value = xtext_decode(found.group(1))
    if value != "<>" and MAILBOX_SHAPE.fullmatch(value) is None:
        return False
    # the refusal names the parameter in the server's own words: "invalid data for AUTH". A reply that echoes the command's text ("... Auth may not follow <>", a
    # cut-off echo of the parameter string) does not say which parameter it refuses, so every stretch of the reply that the command line contains is blanked first
    if not refused_for_params(exchange, "AUTH", r" AUTH=", r"AUTH(?!=)", ("501", "555", "504")):
        return False
    text = str(reply_after_request(exchange))
    request = str(message)
    kept = []
    start = 0
    while start < len(text):
        size = 0
        while start + size < len(text) and text[start:start + size + 1] in request:
            size += 1
        if size >= 6:
            kept.append(" ")
            start += size
        else:
            kept.append(text[start])
            start += 1
    return re.search(r"AUTH(?!=)", "".join(kept), re.I) is not None

def route_refused(exchange):
    """A path with a source route MUST be accepted (4.1.2): no 500/501 for the route."""
    request = str(first_message(exchange))
    return symbol_name(first_message(exchange)).startswith("req_rcpt_route") and reply_code(reply_after_request(exchange)) in ("500", "501")


# --- predicates of the constraints (each is one call, so Fandango evaluates a constraint as a whole)
def auth_in_transaction_ok(exchange):
    """An AUTH command issued during a mail transaction MUST be rejected with a 503 reply (RFC 4954 section 4) by a server that announced AUTH."""
    reply = reply_after_request(exchange)
    return reply is None or not offers(exchange, "AUTH") or reply_code(reply) == "503"

def auth_in_bdat_ok(exchange):
    """An AUTH command issued while a chunked transaction is in progress MUST be rejected with 503 (RFC 4954 section 4) by a server that announced AUTH and CHUNKING;
    otherwise (no announcement: an unannounced BDAT a server took may have ended the transaction) every reply is accepted."""
    reply = reply_after_request(exchange)
    return reply is None or not (offers(exchange, "AUTH") and offers(exchange, "CHUNKING")) or reply_code(reply) == "503"

def auth_repeat_ok(exchange):
    reply = reply_after_request(exchange)
    return reply is None or (not authenticated(exchange)) or reply_code(reply) == "503"


def data_kept(exchange):
    """DATA is not answered 500/502 once CHUNKING was announced (RFC 3030 section 3)."""
    return not (offers_after_helo(exchange, "CHUNKING") and reply_code(reply_after_request(exchange)) in ("500", "502"))

def declared_size_of_transaction(exchange):
    """The SIZE the MAIL command of the open transaction declared, or None."""
    messages = messages_before(exchange)
    for index in range(len(messages) - 1, -1, -1):
        message = messages[index]
        if message.sender == "Server":
            continue
        if symbol_name(message).startswith("req_mail") or symbol_name(message) == "req_oos_mail":
            return size_declared(message)
    return None

def large_data_accepted(exchange):
    """A message of 64K octets is not refused for its size (552) unless the MAIL declared a smaller SIZE (4.5.3.1.7, RFC 1870 5.2)."""
    last = None
    data = None
    for item in exchange.protocol_msgs():
        if item.sender == "Server":
            last = item.msg
        elif symbol_name(item.msg).startswith("data_block") and symbol_name(item.msg) != "data_block_bad_header":
            data = item.msg
    if last is None or data is None or reply_code(last) != "552" or len(bytes(data)) < 65536:
        return True
    declared = declared_size_of_transaction(exchange)
    return declared is not None and declared < len(bytes(data))


# --- the extension parameters and contents the client sends are those of extensions the EHLO reply offered (4.1.1.3, 2.4, RFC 6152 section 3)
def keywords_for_sending(node):
    """The keywords of the last EHLO reply before the message that contains `node` (none after a later HELO); {} if no EHLO was answered."""
    return ehlo_keywords(history_before(node)) or {}

def mail_param_offered(token, keywords):
    key, _, value = token.partition("=")
    key = key.upper()
    if key == "SIZE":
        return "SIZE" in keywords
    if key == "BODY":
        # BODY=7BIT and BODY=8BITMIME belong to 8BITMIME; BODY=BINARYMIME to BINARYMIME, which can only be used with CHUNKING (RFC 3030 section 3)
        if value.upper() == "BINARYMIME":
            return "BINARYMIME" in keywords and "CHUNKING" in keywords
        return "8BITMIME" in keywords
    if key == "AUTH":
        return "AUTH" in keywords
    return "DSN" in keywords

MAIL_PARAM_KEYS = ("SIZE", "BODY", "AUTH", "RET", "ENVID")
RCPT_PARAM_KEYS = ("NOTIFY", "ORCPT")

def offered_mail_params(node):
    """The MAIL parameters of `node` that the last EHLO reply offered, once each (RFC 5321 section 4.1.1.3: the client MUST NOT transmit parameters other than
    those associated with a service extension offered by the server); a parameter of any other keyword is dropped."""
    if node.read_only:
        return str(node)
    keywords = keywords_for_sending(node)
    kept = {}
    for token in str(node).split():
        key = token.partition("=")[0].upper()
        if key in kept:
            continue
        if key in MAIL_PARAM_KEYS:
            if not mail_param_offered(token, keywords):
                continue
        else:
            continue
        kept[key] = token
    # SIZE first: a server that reads the parameters in order may refuse the declared size only when it is the first one (Postfix accepts a SIZE after other parameters)
    return "".join(" " + kept[key] for key in sorted(kept, key=lambda key: (key != "SIZE",)))

def dsn_params_if_offered(node):
    """The repeated DSN parameters of the requests that break RFC 3461 section 4.5 stay only when the last EHLO reply offered DSN (RFC 5321 section 4.1.1.3)."""
    if node.read_only:
        return str(node)
    return str(node) if "DSN" in keywords_for_sending(node) else ""

def offered_max_mail_params(node):
    return offered_mail_params(node)

def offered_rcpt_params(node):
    """The RCPT parameters of `node` (NOTIFY, ORCPT) when the last EHLO reply offered DSN, once each; no parameter of another keyword is sent with RCPT."""
    if node.read_only:
        return str(node)
    if "DSN" not in keywords_for_sending(node):
        return ""
    seen = set()
    result = ""
    for token in str(node).split():
        key = token.partition("=")[0].upper()
        if key in RCPT_PARAM_KEYS and key not in seen:
            seen.add(key)
            result += " " + token
    return result

def offered_max_rcpt_params(node):
    return offered_rcpt_params(node)

TRANSACTION_START = ("req_mail", "req_mail_max", "req_mail_route", "req_send", "req_soml", "req_saml", "req_oos_mail")
TRANSACTION_END = ("req_bdat_first_last", "req_bdat_next_last", "req_bdat_first_binary_last", "req_bdat_next_binary_last")

def last_mail_of_transaction(messages):
    """The index of the MAIL command the open transaction began with and whether it was accepted; (None, False) outside a transaction.
    Only an accepted EHLO or HELO resets the session (RFC 5321 section 4.1.4), a refused one leaves the transaction as it is; the end of the
    mail data (DATA or the last BDAT chunk) ends the transaction."""
    for index in range(len(messages) - 1, -1, -1):
        message = messages[index]
        if message.sender == "Server":
            continue
        name = symbol_name(message)
        answered = index + 1 < len(messages)
        if name in TRANSACTION_START:
            return index, answered and reply_code(messages[index + 1])[0] == "2"
        if name == "req_rset" or (name in ("req_ehlo", "req_helo", "req_ehlo_max", "req_helo_max") and answered and reply_code(messages[index + 1])[0] == "2"):
            return None, False
        if name.startswith("data_block") or name in TRANSACTION_END:
            return None, False
    return None, False

def text_for_content(node):
    """8-bit text is sent only after an accepted MAIL with BODY=8BITMIME, which is sent only when 8BITMIME was offered (RFC 6152 section 3)."""
    if node.read_only:
        return str(node)
    text = str(node)
    if text.isascii():
        return text
    messages = history_before(node)
    index, accepted = last_mail_of_transaction(messages)
    if accepted and "8BITMIME" in keywords_for_sending(node) and re.search(r" BODY=8BITMIME", str(messages[index]), re.I) is not None:
        return text
    return "a" * len(text)

BDAT_RESET = ("req_rset", "req_ehlo", "req_helo", "req_ehlo_max", "req_helo_max", "req_data", "req_oos_data", "req_data_after_bdat")

def bdat_tail_if_announced(node):
    """The end of a chunk that is not the last, a CR or a part of a line (RFC 3030 section 2: a chunk boundary may fall anywhere), is kept after an EHLO reply that announced CHUNKING; a BDAT a server may take for
    command lines has whole lines."""
    if node.read_only:
        return str(node)
    return str(node) if "CHUNKING" in keywords_for_sending(node) else ""

def bdat_lead_value(node):
    """The start of a BDAT chunk that follows a chunk which ended inside a line (RFC 3030 section 2: a chunk boundary may fall anywhere; text sent with BDAT is in canonical form, lines delimited by CRLF): the LF
    after a chunk that ended with the CR, and the rest of the line up to its CRLF (the value the rule generated, or a dot and the CRLF) after a chunk that ended in the middle of a line; empty in every other case.
    Computed from the chunks the session sent before."""
    if node.read_only:
        return str(node)
    if binarymime_for_send(node):
        return ""
    for message in reversed(history_before(node)):
        if message.sender == "Server":
            continue
        name = symbol_name(message)
        if name.startswith("req_bdat"):
            head, _, chunk = str(message).partition("\r\n")
            if head.upper().endswith(" LAST"):
                return ""
            if chunk.endswith("\r"):
                return "\n"
            if chunk and not chunk.endswith("\r\n"):
                return str(node) if re.fullmatch(r"\.(?:[ -\-/-~][ -~]{0,28})?\r\n", str(node)) else ".\r\n"
            if chunk:
                return ""
            continue
        if name in BDAT_RESET or name.startswith("req_mail") or name.startswith("req_send"):
            return ""
    return ""

def text_of_binary(text):
    """The text line (a line of printable characters that does not start with a dot, with its line end) that stands for a binary chunk outside a BINARYMIME transaction: computed from the chunk's octets."""
    line = re.sub(r"[^ -~]", "x", text)[:70] or "x"
    if line[0] == ".":
        line = "x" + line[1:]
    return line + "\r\n"

def ascii_of_binary(text):
    """A binary chunk for a server that did not announce 8BITMIME: its octets above 0x7F become US-ASCII letters (RFC 6152 section 3: no content outside US-ASCII without 8BITMIME); NUL, bare CR and LF stay."""
    return re.sub(r"[^\x00-\x7f]", "x", text)

def binary_chunk_if_allowed(node):
    """Binary content (a chunk with a NUL) only in a transaction that began with an accepted MAIL with BODY=BINARYMIME (RFC 3030 section 3); in any other transaction the chunk is a text line made from it."""
    if node.read_only:
        return str(node)
    text = str(node)
    if binarymime_for_send(node):
        return text if "8BITMIME" in keywords_for_sending(node) else ascii_of_binary(text)
    if "\x00" not in text and text.isascii():
        return text
    return text_of_binary(text)

def binary_first_chunk_if_allowed(node):
    """The same for the first chunk of a message: the header section stays (RFC 5322 section 3.6), the body after the blank line is turned into a text line."""
    if node.read_only:
        return str(node)
    text = str(node)
    head, separator, body = text.partition("\r\n\r\n")
    if binarymime_for_send(node):
        return text if "8BITMIME" in keywords_for_sending(node) else head + separator + ascii_of_binary(body)
    if "\x00" not in text and text.isascii():
        return text
    return head + separator + text_of_binary(body)

def offers_not_refused_with_params(exchange):
    """A command with the ESMTP parameters of an extension the last EHLO reply offered is not answered with 500/502 (4.2.4)."""
    if reply_code(reply_after_request(exchange)) not in ("500", "502") or not within_guaranteed_size(exchange):
        return True
    keywords = ehlo_keywords(messages_before(exchange)) or {}
    tokens = re.findall(r" ([A-Za-z]+=\S*)", str(first_message(exchange)))
    return not any(mail_param_offered(token, keywords) for token in tokens)

def no_path_in_reply(exchange):
    """VRFY/EXPN never return a path: no source route in the reply (3.5.2)."""
    reply = reply_after_request(exchange)
    return str(first_message(exchange))[:4].upper() not in ("VRFY", "EXPN") or re.search(r"<@[^>]*:", str(reply)) is None

def bdat_oos_reply_ok(exchange):
    """A BDAT out of sequence is refused (RFC 3030 section 2), and a server that announced CHUNKING does not answer it 500 or 502 (4.2.4)."""
    return reply_code(reply_after_request(exchange)) != "250" and supported_listed(exchange, "CHUNKING")


def bdat_refusal_single(exchange):
    """After a failed BDAT the receiver accepts and discards the chunk's data before it sends the 4xx/5xx reply (RFC 3030 section 2).  A server whose EHLO reply announced CHUNKING (the EHLO reply that is
    in force) therefore answers the refused BDAT once: a reply to every line of the chunk shows that the chunk was taken for commands.  A server that did not announce CHUNKING may do that."""
    if not offers(exchange, "CHUNKING"):
        return True
    return sum(1 for item in exchange.protocol_msgs() if item.sender == "Server") <= 1

def supported_listed_verb(exchange):  # NOOP while chunking
    """HELP/VRFY/EXPN/NOOP while chunking: the rules of the same command in the other states."""
    verb = str(first_message(exchange))[:4].upper()
    if verb.startswith("X"):
        return True
    return supported_listed(exchange, verb, verb in ("NOOP", "VRFY"))

def max_domain_accepted(exchange):
    """A domain of 255 octets in EHLO/HELO is received without a syntax refusal (4.5.3.1.2)."""
    name = symbol_name(first_message(exchange))
    return name not in ("req_ehlo_max", "req_helo_max") or reply_code(reply_after_request(exchange)) not in ("500", "501", "504")

def within_guaranteed_size(exchange):
    """Whether the request line is no longer than the sizes every server MUST accept: 512 octets (RFC 5321 section 4.5.3.1.4), with an AUTH parameter 512 plus 500
    (RFC 4954 section 5), with the DSN parameters 1036 (RFC 3461 section 5.4).  A longer line is refused legitimately."""
    line = str(first_message(exchange))
    limit = 512
    if re.search(r" AUTH=", line, re.I):
        limit = 1012
    if re.search(r" (?:ENVID|NOTIFY|ORCPT|RET)=", line, re.I):
        limit = max(limit, 1036)
    return len(line) <= limit

def max_refusal_ok(exchange):
    """The largest forms (4.5.3.1: local-part 64, domain 255, path 256 and line 512 octets; RFC 3461 section 5.4) MUST be accepted: a refusal that says
    the line, an argument or a parameter is wrong (500, 501, 504, 555) is a violation unless the MAIL carries parameters of an extension the EHLO reply
    did not offer."""
    name = symbol_name(first_message(exchange))
    if not (name.endswith("_max") or name.endswith("_max_more")):
        return True
    if reply_code(reply_after_request(exchange)) not in ("500", "501", "504", "555") or not within_guaranteed_size(exchange):
        return True
    keywords = ehlo_keywords(messages_before(exchange)) or {}
    tokens = re.findall(r" ([A-Za-z]+=\S*)", str(first_message(exchange)))
    return any(not mail_param_offered(token, keywords) for token in tokens)

def mail_route_refused(exchange):
    """MAIL with a source route in front of a valid mailbox is not refused with a syntax error (4.1.2)."""
    return symbol_name(first_message(exchange)) == "req_mail_route" and reply_code(reply_after_request(exchange)) in ("500", "501")

def long_text_line_accepted(exchange):
    """A text line of 998 octets plus CRLF (1000 octets, 4.5.3.1.6) is not refused as too long.  The message that breaks the header rules of RFC 5322 (<data_block_bad_header>) may be refused for them, so it is not judged."""
    last = reply_after_request(exchange)
    for item in exchange.protocol_msgs():
        if item.sender == "Server":
            last = item.msg
    data = None
    for item in exchange.protocol_msgs():
        if item.sender == "Client" and symbol_name(item.msg).startswith("data_block") and symbol_name(item.msg) != "data_block_bad_header":
            data = item.msg
    if data is None or last is None or reply_code(last) not in ("500", "501"):
        return True
    return re.search(r"(?m)^[^\r\n]{998}\r$", str(data)) is None

def binarymime_for_send(node):
    messages = history_before(node)
    index, accepted = last_mail_of_transaction(messages)
    return accepted and re.search(r" BODY=BINARYMIME", str(messages[index]), re.I) is not None

def data_bm_ok(exchange):
    """DATA after an accepted MAIL with BODY=BINARYMIME MUST be answered with 503 (RFC 3030 section 3): any other first reply (354 above all) breaks it."""
    reply = reply_after_request(exchange)
    return reply is None or not binarymime_for_send(exchange) or reply_code(reply) == "503"

def data_plain_ok(exchange):
    """A refused DATA that stays in the state holds only outside a BINARYMIME transaction: inside one a 503 is <ex_data_503> and any other reply breaks the MUST of RFC 3030 section 3."""
    return reply_after_request(exchange) is None or not binarymime_for_send(exchange)

def data_503_binarymime(exchange):
    """The exchange whose 503 leaves the transaction indeterminate holds only after an accepted MAIL with BODY=BINARYMIME."""
    return reply_after_request(exchange) is None or binarymime_for_send(exchange)

# ------------------------------------------------------------------------------------------------------
# Command argument syntax, RFC 5321 section 4.1.2 (shared by every command and reply that carries the field).  The rules are the
# formal grammar of the spec, without bounds: received messages (greeting, EHLO/HELO and VRFY/EXPN replies) use them as they are.
# Sent messages use the narrowed forms <sent_*> below, which keep the objects within the minimum maxima of 4.5.3.1 (local-part 64,
# domain 255, path 256, command line 512).
# ------------------------------------------------------------------------------------------------------
# Atom = 1*atext  (atext of RFC 5322 section 3.2.3)
<atom> ::= r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
# Dot-string = Atom *("." Atom)
<dot_string> ::= <atom> ('.' <atom>)*
# Quoted-string = DQUOTE *QcontentSMTP DQUOTE; QcontentSMTP = qtextSMTP / quoted-pairSMTP
<quoted_string> ::= '"' <qcontent_smtp>* '"'
<qcontent_smtp> ::= <qtext_smtp> | <quoted_pair_smtp>
# qtextSMTP = %d32-33 / %d35-91 / %d93-126
<qtext_smtp> ::= r'[ !#-\[\]-~]'
# quoted-pairSMTP = %d92 %d32-126
<quoted_pair_smtp> ::= '\\' r'[ -~]'
# Local-part = Dot-string / Quoted-string
<local_part> ::= <dot_string> | <quoted_string>
# Domain = sub-domain *("." sub-domain); sub-domain = Let-dig [Ldh-str]
<domain> ::= <sub_domain> ('.' <sub_domain>)*
<sub_domain> ::= r'[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
# address-literal = "[" ( IPv4-address-literal / IPv6-address-literal / General-address-literal ) "]", section 4.1.3
<address_literal> ::= '[' (<ipv4_address_literal> | <ipv6_address_literal> | <general_address_literal>) ']'
<ipv4_address_literal> ::= <snum> '.' <snum> '.' <snum> '.' <snum>
# Snum = 1*3DIGIT representing a decimal integer value in the range 0 through 255
<snum> ::= r'(25[0-5]|2[0-4][0-9]|[01][0-9][0-9]|[0-9]{1,2})'
<ipv6_address_literal> ::= 'IPv6:' <ipv6_addr>
<ipv6_addr> ::= <ipv6_full> | <ipv6_comp> | <ipv6v4_full> | <ipv6v4_comp>
<ipv6_hex> ::= r'[0-9A-Fa-f]{1,4}'
<ipv6_full> ::= <ipv6_hex> (':' <ipv6_hex>){7}
# IPv6-comp: no more than 6 groups in addition to the "::" (5.1: the groups before and after it together), so one alternative per
# number of groups before the "::"
<ipv6_comp> ::= '::' (<ipv6_hex> (':' <ipv6_hex>){0,5})? \
              | <ipv6_hex> '::' (<ipv6_hex> (':' <ipv6_hex>){0,4})? \
              | <ipv6_hex> (':' <ipv6_hex>){1} '::' (<ipv6_hex> (':' <ipv6_hex>){0,3})? \
              | <ipv6_hex> (':' <ipv6_hex>){2} '::' (<ipv6_hex> (':' <ipv6_hex>){0,2})? \
              | <ipv6_hex> (':' <ipv6_hex>){3} '::' (<ipv6_hex> (':' <ipv6_hex>){0,1})? \
              | <ipv6_hex> (':' <ipv6_hex>){4} '::' <ipv6_hex>? \
              | <ipv6_hex> (':' <ipv6_hex>){5} '::'
<ipv6v4_full> ::= <ipv6_hex> (':' <ipv6_hex>){5} ':' <ipv4_address_literal>
# IPv6v4-comp: no more than 4 groups in addition to the "::" and the IPv4 address
<ipv6v4_comp> ::= '::' (<ipv6_hex> ':'){0,4} <ipv4_address_literal> \
                | <ipv6_hex> '::' (<ipv6_hex> ':'){0,3} <ipv4_address_literal> \
                | <ipv6_hex> (':' <ipv6_hex>){1} '::' (<ipv6_hex> ':'){0,2} <ipv4_address_literal> \
                | <ipv6_hex> (':' <ipv6_hex>){2} '::' (<ipv6_hex> ':'){0,1} <ipv4_address_literal> \
                | <ipv6_hex> (':' <ipv6_hex>){3} '::' <ipv4_address_literal>
# General-address-literal = Standardized-tag ":" 1*dcontent; Standardized-tag = Ldh-str
<general_address_literal> ::= <standardized_tag> ':' <dcontent>+
<standardized_tag> ::= r'([A-Za-z0-9-]*[A-Za-z0-9])'
# dcontent = %d33-90 / %d94-126
<dcontent> ::= r'[!-Z^-~]'
# Mailbox = Local-part "@" ( Domain / address-literal )
<mailbox> ::= <local_part> '@' <domain_or_literal>
<domain_or_literal> ::= <domain> | <address_literal>
# Path = "<" [ A-d-l ":" ] Mailbox ">"  (source routes MUST be accepted, SHOULD NOT be generated)
<path> ::= '<' (<a_d_l> ':')? <mailbox> '>'
# A-d-l = At-domain *( "," At-domain )
<a_d_l> ::= <at_domain> (',' <at_domain>)*
<at_domain> ::= '@' <domain>
<reverse_path> ::= <path> | <null_reverse_path>
<null_reverse_path> ::= '<>'
<forward_path> ::= <path>
# String = Atom / Quoted-string
<string> ::= <atom> | <quoted_string>
# xtext of RFC 3461 section 4: xtext = *( xchar / hexchar ), hexchar = "+" 2(uppercase hex digit)
<xtext> ::= (<xchar> | <hexchar>)*
<xchar> ::= r'[!-*,-<>-~]'
<hexchar> ::= '+' r'[0-9A-F]{2}'
# Mail-parameters = esmtp-param *(SP esmtp-param), Rcpt-parameters likewise; esmtp-param = esmtp-keyword ["=" esmtp-value] (4.1.2): the syntax of every parameter of MAIL and RCPT, one rule that the
# parameter lists of <req_mail> and of every RCPT request take (<mail_param_list>, <rcpt_param_list>).  Its alternatives are the narrowed forms the grammar sends for the extensions of the manifest
# (SIZE, BODY, AUTH, RET, ENVID of MAIL; NOTIFY, ORCPT of RCPT; keyword, "=" and the value syntax of the extension's RFC are an esmtp-keyword, "=" and an esmtp-value) and <esmtp_param_other>, an
# esmtp-param of any other keyword, with or without a value.  The where equalities on the parameter lists (60_constraints.fan) keep only the parameters the last EHLO reply offered, once each.
# TODO: RFC 5321 section 4.1.2 (an esmtp-param of an unregistered or private-use keyword, and an esmtp-value on a keyword whose extension takes none), <esmtp_param_other>: the keyword belongs to an extension that
# refs/spec/manifest.json leaves out (RFC 6531 SMTPUTF8 and the like), whose definition is not in refs/spec: a parameter of it is never sent, the where equality removes <esmtp_param_other> from every sent
# list; the rule is the generic fallback of the shared syntax.
<esmtp_param> ::= <mail_param_size> | <mail_param_body> | <mail_param_auth> | <mail_param_ret> | <mail_param_envid> | <rcpt_param_notify> | <rcpt_param_orcpt> | <esmtp_param_other>
<esmtp_param_other> ::= <esmtp_keyword> ('=' <esmtp_value>)?
# esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-"); the keywords of the narrowed forms above are derived by their own rules (the lookahead keeps the languages apart)
<esmtp_keyword> ::= <esmtp_keyword_text>
<esmtp_keyword_text> ::= r'(?![Ss][Ii][Zz][Ee]\b|[Bb][Oo][Dd][Yy]\b|[Aa][Uu][Tt][Hh]\b|[Rr][Ee][Tt]\b|[Ee][Nn][Vv][Ii][Dd]\b|[Nn][Oo][Tt][Ii][Ff][Yy]\b|[Oo][Rr][Cc][Pp][Tt]\b)[A-Za-z0-9][A-Za-z0-9-]*'
# esmtp-value = 1*(%d33-60 / %d62-126)
<esmtp_value> ::= r'[!-<>-~]+'
<esmtp_params> ::= <esmtp_param> (' ' <esmtp_param>)*
<digits> ::= r'[0-9]{1,20}'
<crlf> ::= '\r\n'

# ------------------------------------------------------------------------------------------------------
# The forms the client sends: the shared rules above, narrowed to keep every object within the maxima of 4.5.3.1 (local-part 64 octets,
# path 256, command line 512; the sent lines stay below these maxima).  The narrowing leaves out atoms of more than 12 characters,
# dot-strings of more than 3 atoms, quoted-strings of more than 20 characters, domains of more than 5 labels or labels of more than 20
# characters, and source routes of more than 4 hops; the forms of full width are sent by <req_mail_max>, <req_rcpt_max> and <req_mail_line>.
# ------------------------------------------------------------------------------------------------------
# TODO: RFC 5321 section 4.1.2 (every local-part, domain, and route the shared rules derive), <sent_local_part>, <sent_domain>, <sent_a_d_l>: the sent
# forms are bounded so that every command line stays within 512 octets (4.5.3.1.4); the servers are tested with the setup's mailboxes
# and the maximum forms.
<sent_atom> ::= r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]{1,12}"
<sent_dot_string> ::= <sent_atom> ('.' <sent_atom>){0,2}
<sent_quoted_string> ::= '"' <qcontent_smtp>{0,20} '"'
<sent_local_part> ::= <sent_dot_string> | <sent_quoted_string>
<sent_domain> ::= <sent_sub_domain> ('.' <sent_sub_domain>){0,4}
<sent_sub_domain> ::= r'[A-Za-z0-9]([A-Za-z0-9-]{0,18}[A-Za-z0-9])?'
# TODO: RFC 5321 section 4.1.3 (General-address-literal, a Standardized-tag ":" 1*dcontent), <sent_address_literal>: a standardized tag MUST be specified in a Standards-Track RFC and registered with IANA, and no tag but IPv6 is, so
# the sent forms carry the IPv4 and IPv6 literals only; the shared <address_literal> (received replies) derives the general form too.
<sent_address_literal> ::= '[' (<ipv4_address_literal> | <ipv6_address_literal>) ']'
<sent_domain_or_literal> ::= <sent_domain> | <sent_address_literal>
<sent_mailbox> ::= <sent_local_part> '@' <sent_domain_or_literal>
<sent_a_d_l> ::= <sent_at_domain> (',' <sent_at_domain>){0,3}
<sent_at_domain> ::= '@' <sent_route_domain>
<sent_route_domain> ::= <sent_route_label> ('.' <sent_route_label>){0,1}
<sent_route_label> ::= r'[A-Za-z0-9]([A-Za-z0-9-]{0,6}[A-Za-z0-9])?'
# the reverse-path of <req_mail> has no source route (a MAIL with a route is <req_mail_route>, and the route of a path is "SHOULD NOT be generated", 4.1.2), so the two requests derive different strings
<sent_plain_path> ::= '<' <sent_mailbox> '>'
<sent_plain_reverse_path> ::= <sent_plain_path> | <null_reverse_path>
# the path of <req_rcpt_any> has an address literal as its domain (a literal is no name of the setup: the other forms of <req_rcpt_any> take a domain name), without a source route (a route is sent by <req_rcpt_route>), so <req_rcpt_any> derives none of the strings of
# <req_rcpt_postmaster>, <req_rcpt_route> and <req_rcpt_max>
# TODO: RFC 5321 section 4.1.2 (a source route in the path of RCPT with a literal, of MAIL with a mailbox of the setup in SEND/SOML/SAML, the A-d-l of <sent_a_d_l>), <sent_literal_path>: the route is sent in a
# request of its own, <req_rcpt_route> and <req_mail_route>, whose refusal with a syntax error is checked (route_refused, mail_route_refused); every other request leaves the route out, so that no
# request derives the strings of another and a refusal of a route is never confused with a refusal of anything else.
# TODO: RFC 5321 section 4.1.2 (a forward-path whose domain is a name that is not one of the setup's domains, with any local-part), <req_rcpt_any>: the names of the setup and the remote domain are sent by <req_rcpt_any> through <rcpt_listed_path>, with <sent_literal_path> as the other
# domain form, the address literal; the names of other domains are not sent, so that no RCPT request derives a string another one derives.
<sent_literal_path> ::= '<' <sent_local_part> '@' <sent_address_literal> '>'
<sent_string> ::= <sent_atom> | <sent_quoted_string>

# ------------------------------------------------------------------------------------------------------
# Replies, section 4.2.  Reply-line = *( Reply-code "-" [ textstring ] CRLF ) Reply-code [ SP textstring ] CRLF
# In a multiline reply the code of every line is the same (4.2.1): each code has its own rule, so the grammar
# enforces it.  A reply text may carry an enhanced status code (RFC 3463 / RFC 2034).
# ------------------------------------------------------------------------------------------------------
# textstring = 1*(%d09 / %d32-126); a text that starts like an enhanced status code is <esc_text>
<reply_text> ::= <esc_text> | <plain_text> | <no_text>
# no text at all (clients MUST accept it, 4.2): every reply line has a <reply_text>, so the constraints see it
<no_text> ::= ''
# status-code = class "." subject "." detail (RFC 3463 section 2); class is 2, 4 or 5
<esc_text> ::= <esc> (' ' <textstring>)?
<esc> ::= <esc_class> '.' <esc_subject> '.' <esc_detail>
<esc_class> ::= <esc_class_2> | <esc_class_4> | <esc_class_5>
<esc_class_2> ::= '2'
<esc_class_4> ::= '4'
<esc_class_5> ::= '5'
<esc_subject> ::= r'[0-9]{1,3}'
# TODO: RFC 5248 / RFC 3463 section 3 (the registry of enumerated status codes X.S.D), <esc_detail>: the registry is not part of refs/spec; every decimal detail is accepted.
<esc_detail> ::= r'[0-9]{1,3}'
<textstring> ::= r'[\t -~]+'
<plain_text> ::= r'(?![245][.][0-9]{1,3}[.][0-9]{1,3}(?:[ \r]|$))[\t -~]+'

# Reply codes (4.2.2, 4.2.3; RFC 4954 section 6 for 235/334/432/454/530/534/535/538, RFC 3207 section 4 for 454/530, RFC 1985 for 253/458/459, RFC 7504 for 521/556)
<c211> ::= '211'
<c214> ::= '214'
<c220> ::= '220'
<c221> ::= '221'
<c235> ::= '235'
<c250> ::= '250'
<c251> ::= '251'
<c252> ::= '252'
<c253> ::= '253'
<c421> ::= '421'
<c432> ::= '432'
<c450> ::= '450'
<c451> ::= '451'
<c452> ::= '452'
<c454> ::= '454'
<c455> ::= '455'
<c458> ::= '458'
<c459> ::= '459'
<c500> ::= '500'
<c501> ::= '501'
<c502> ::= '502'
<c503> ::= '503'
<c504> ::= '504'
<c521> ::= '521'
<c530> ::= '530'
<c534> ::= '534'
<c535> ::= '535'
<c538> ::= '538'
<c550> ::= '550'
<c551> ::= '551'
<c552> ::= '552'
<c553> ::= '553'
<c554> ::= '554'
<c555> ::= '555'
<c556> ::= '556'
<c334> ::= '334'
<c354> ::= '354'

# 211: System status, or system help reply (4.2.2)
<rep_211> ::= (<c211> '-' <reply_text> <crlf>)* <c211> (' ' <reply_text> | <no_text>) <crlf>
# 214: Help message (4.2.2)
<rep_214> ::= (<c214> '-' <reply_text> <crlf>)* <c214> (' ' <reply_text> | <no_text>) <crlf>
# 220: Service ready (4.2.2); as reply to STARTTLS: ready to start TLS (RFC 3207 section 4)
<rep_220> ::= (<c220> '-' <reply_text> <crlf>)* <c220> (' ' <reply_text> | <no_text>) <crlf>
# 221: Service closing transmission channel (4.2.2)
<rep_221> ::= (<c221> '-' <reply_text> <crlf>)* <c221> (' ' <reply_text> | <no_text>) <crlf>
# 235: Authentication succeeded (RFC 4954 section 6)
<rep_235> ::= (<c235> '-' <reply_text> <crlf>)* <c235> (' ' <reply_text> | <no_text>) <crlf>
# 250: Requested mail action okay, completed (4.2.2)
<rep_250> ::= (<c250> '-' <reply_text> <crlf>)* <c250> (' ' <reply_text> | <no_text>) <crlf>
# 251: User not local; will forward (4.2.2, 3.4)
<rep_251> ::= (<c251> '-' <reply_text> <crlf>)* <c251> (' ' <reply_text> | <no_text>) <crlf>
# 252: Cannot VRFY user, but will accept message (4.2.2, 3.5.3)
<rep_252> ::= (<c252> '-' <reply_text> <crlf>)* <c252> (' ' <reply_text> | <no_text>) <crlf>
# 253: ETRN: pending messages for node started (RFC 1985 section 4)
<rep_253> ::= (<c253> '-' <reply_text> <crlf>)* <c253> (' ' <reply_text> | <no_text>) <crlf>
# 421: Service not available, closing transmission channel (4.2.2)
<rep_421> ::= (<c421> '-' <reply_text> <crlf>)* <c421> (' ' <reply_text> | <no_text>) <crlf>
# 432: Password transition is needed (RFC 4954 section 6)
<rep_432> ::= (<c432> '-' <reply_text> <crlf>)* <c432> (' ' <reply_text> | <no_text>) <crlf>
# 450: Mailbox unavailable, temporary (4.2.2)
<rep_450> ::= (<c450> '-' <reply_text> <crlf>)* <c450> (' ' <reply_text> | <no_text>) <crlf>
# 451: Local error in processing (4.2.2)
<rep_451> ::= (<c451> '-' <reply_text> <crlf>)* <c451> (' ' <reply_text> | <no_text>) <crlf>
# 452: Insufficient system storage / too many recipients (4.2.2, 4.5.3.1.10)
<rep_452> ::= (<c452> '-' <reply_text> <crlf>)* <c452> (' ' <reply_text> | <no_text>) <crlf>
# 454: Temporary authentication failure / TLS not available (RFC 4954 section 6, RFC 3207 section 4)
<rep_454> ::= (<c454> '-' <reply_text> <crlf>)* <c454> (' ' <reply_text> | <no_text>) <crlf>
# 455: Server unable to accommodate parameters (4.2.2)
<rep_455> ::= (<c455> '-' <reply_text> <crlf>)* <c455> (' ' <reply_text> | <no_text>) <crlf>
# 458: ETRN: unable to queue messages for node (RFC 1985 section 4)
<rep_458> ::= (<c458> '-' <reply_text> <crlf>)* <c458> (' ' <reply_text> | <no_text>) <crlf>
# 459: ETRN: node not allowed (RFC 1985 section 4)
<rep_459> ::= (<c459> '-' <reply_text> <crlf>)* <c459> (' ' <reply_text> | <no_text>) <crlf>
# 500: Syntax error, command unrecognized (4.2.2)
<rep_500> ::= (<c500> '-' <reply_text> <crlf>)* <c500> (' ' <reply_text> | <no_text>) <crlf>
# 501: Syntax error in parameters or arguments (4.2.2)
<rep_501> ::= (<c501> '-' <reply_text> <crlf>)* <c501> (' ' <reply_text> | <no_text>) <crlf>
# 502: Command not implemented (4.2.2, 4.2.4)
<rep_502> ::= (<c502> '-' <reply_text> <crlf>)* <c502> (' ' <reply_text> | <no_text>) <crlf>
# 503: Bad sequence of commands (4.2.2)
<rep_503> ::= (<c503> '-' <reply_text> <crlf>)* <c503> (' ' <reply_text> | <no_text>) <crlf>
# 504: Command parameter not implemented (4.2.2)
<rep_504> ::= (<c504> '-' <reply_text> <crlf>)* <c504> (' ' <reply_text> | <no_text>) <crlf>
# 521: Host does not accept mail (RFC 7504 section 2)
<rep_521> ::= (<c521> '-' <reply_text> <crlf>)* <c521> (' ' <reply_text> | <no_text>) <crlf>
# 530: Must issue a STARTTLS command first / authentication required (RFC 3207 section 4, RFC 4954 section 6)
<rep_530> ::= (<c530> '-' <reply_text> <crlf>)* <c530> (' ' <reply_text> | <no_text>) <crlf>
# 534: Authentication mechanism is too weak (RFC 4954 section 6)
<rep_534> ::= (<c534> '-' <reply_text> <crlf>)* <c534> (' ' <reply_text> | <no_text>) <crlf>
# 535: Authentication credentials invalid (RFC 4954 section 6)
<rep_535> ::= (<c535> '-' <reply_text> <crlf>)* <c535> (' ' <reply_text> | <no_text>) <crlf>
# 538: Encryption required for requested authentication mechanism (RFC 4954 section 6)
<rep_538> ::= (<c538> '-' <reply_text> <crlf>)* <c538> (' ' <reply_text> | <no_text>) <crlf>
# 550: Mailbox unavailable, permanent (4.2.2)
<rep_550> ::= (<c550> '-' <reply_text> <crlf>)* <c550> (' ' <reply_text> | <no_text>) <crlf>
# 551: User not local; please try forward-path (4.2.2, 3.4)
<rep_551> ::= (<c551> '-' <reply_text> <crlf>)* <c551> (' ' <reply_text> | <no_text>) <crlf>
# 552: Exceeded storage allocation (4.2.2)
<rep_552> ::= (<c552> '-' <reply_text> <crlf>)* <c552> (' ' <reply_text> | <no_text>) <crlf>
# 553: Mailbox name not allowed (4.2.2)
<rep_553> ::= (<c553> '-' <reply_text> <crlf>)* <c553> (' ' <reply_text> | <no_text>) <crlf>
# 554: Transaction failed / no SMTP service here (4.2.2)
<rep_554> ::= (<c554> '-' <reply_text> <crlf>)* <c554> (' ' <reply_text> | <no_text>) <crlf>
# 555: MAIL FROM/RCPT TO parameters not recognized or not implemented (4.2.2)
<rep_555> ::= (<c555> '-' <reply_text> <crlf>)* <c555> (' ' <reply_text> | <no_text>) <crlf>
# 556: Domain does not accept mail (RFC 7504 section 2)
<rep_556> ::= (<c556> '-' <reply_text> <crlf>)* <c556> (' ' <reply_text> | <no_text>) <crlf>
# 354: Start mail input (4.2.2)
<rep_354> ::= (<c354> '-' <reply_text> <crlf>)* <c354> (' ' <reply_text> | <no_text>) <crlf>

# Codes not listed in this document: handled by the first digit only (4.2, 4.3.2).  Every line carries the same code.
<rep_2yz_x> ::= (<code_2yz_x> '-' <reply_text> <crlf>)* <code_2yz_x> (' ' <reply_text> | <no_text>) <crlf>
<rep_4yz_x> ::= (<code_4yz_x> '-' <reply_text> <crlf>)* <code_4yz_x> (' ' <reply_text> | <no_text>) <crlf>
<rep_5yz_x> ::= (<code_5yz_x> '-' <reply_text> <crlf>)* <code_5yz_x> (' ' <reply_text> | <no_text>) <crlf>
# an unrecognized 3yz code (positive intermediate, 4.2.1) other than 334 and 354: the client sends its next command
<rep_3yz_x> ::= (<code_3yz_x> '-' <reply_text> <crlf>)* <code_3yz_x> (' ' <reply_text> | <no_text>) <crlf>
<code_3yz_x> ::= r'3(?!34|54)[0-5][0-9]'
<code_2yz_x> ::= r'2(?!11|14|20|21|35|50|51|52|53)[0-5][0-9]'
<code_4yz_x> ::= r'4(?!21|32|50|51|52|54|55|58|59)[0-5][0-9]'
<code_5yz_x> ::= r'5(?!00|01|02|03|04|21|30|34|35|38|50|51|52|53|54|55|56)[0-5][0-9]'

# ------------------------------------------------------------------------------------------------------
# Replies whose text the client interprets
# ------------------------------------------------------------------------------------------------------
# Greeting (4.2): "220 " (Domain / address-literal) [ SP textstring ] CRLF, or the multiline form with "220-"
<rep_greeting_ok> ::= <greeting_single> | <greeting_multi>
<greeting_single> ::= '220 ' <domain_or_literal> (' ' <textstring>)? <crlf>
<greeting_multi> ::= '220-' <domain_or_literal> (' ' <textstring>)? <crlf> ('220-' <textstring>? <crlf>)* '220' (' ' <textstring>)? <crlf>
# Connection-opening rejection: 554 "No SMTP service here" (4.2.2), 521 (RFC 7504), or any other failure code
# (RFC 5321 section 4.2: the other possible responses upon connection follow the Reply-line syntax, so every reply class is accepted; 421 is <ex_unsolicited_421>)
<rep_greeting_reject> ::= <rep_neg> | <rep_211> | <rep_214> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x> | <rep_334> | <rep_354>

# HELO reply (4.1.1.1, 3.2): "250" SP Domain [ SP text ]; the extended multiline response MUST NOT be returned to HELO
<rep_helo_ok> ::= <c250> (' ' <reply_text> | <no_text>) <crlf>
# EHLO positive reply (4.1.1.1): ehlo-ok-rsp = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
#   / ( "250-" Domain [ SP ehlo-greet ] CRLF *( "250-" ehlo-line CRLF ) "250" SP ehlo-line CRLF )
<rep_ehlo_ok> ::= <ehlo_single> | <ehlo_multi>
<ehlo_single> ::= <c250> ' ' <domain_or_literal> (' ' <ehlo_greet>)? <crlf>
<ehlo_head> ::= <c250> '-' <domain_or_literal> (' ' <ehlo_greet>)? <crlf>
<ehlo_multi> ::= <ehlo_head> (<c250> '-' <ehlo_line> <crlf>)* <c250> ' ' <ehlo_line> <crlf>
# ehlo-greet = 1*(%d0-9 / %d11-12 / %d14-127)
<ehlo_greet> ::= r'[\x00-\x09\x0b\x0c\x0e-\x7f]+'
# ehlo-line = ehlo-keyword *( SP ehlo-param ); ehlo-param = 1*(%d33-126); keywords are case-insensitive (2.4)
<ehlo_line> ::= <kw_size> (' ' <size_limit>)? | <ehlo_keyword> (' ' <ehlo_param>)*
# size-param = [1*DIGIT] (RFC 1870 section 3): the fixed maximum message size, 0 for none announced
<size_limit> ::= r'[0-9]+'
<ehlo_keyword> ::= <kw_8bitmime> | <kw_pipelining> | <kw_chunking> | <kw_binarymime> | <kw_dsn> \
                 | <kw_enhancedstatuscodes> | <kw_starttls> | <kw_auth> | <kw_etrn> | <kw_vrfy> | <kw_expn> | <kw_help> | <kw_other>
<kw_size> ::= r'[Ss][Ii][Zz][Ee]'
# TODO: RFC 2920 sections 3 and 4 (PIPELINING: groups of commands sent before the replies of the earlier ones, group-ending commands), <kw_pipelining>: a group may be sent only
# once the EHLO reply announced PIPELINING (3.1); choosing an alternative by an earlier reply is a where on a sent message, which leaves an alternative that is never satisfiable
# on servers that do not announce the keyword (OpenSMTPD) and makes Fandango's packet search fall back to its slow evolutionary generation (measured: 5 times fewer sessions);
# the keyword is accepted and no pipelined group is sent.
<kw_8bitmime> ::= r'8[Bb][Ii][Tt][Mm][Ii][Mm][Ee]'
<kw_pipelining> ::= r'[Pp][Ii][Pp][Ee][Ll][Ii][Nn][Ii][Nn][Gg]'
<kw_chunking> ::= r'[Cc][Hh][Uu][Nn][Kk][Ii][Nn][Gg]'
<kw_binarymime> ::= r'[Bb][Ii][Nn][Aa][Rr][Yy][Mm][Ii][Mm][Ee]'
<kw_dsn> ::= r'[Dd][Ss][Nn]'
<kw_enhancedstatuscodes> ::= r'[Ee][Nn][Hh][Aa][Nn][Cc][Ee][Dd][Ss][Tt][Aa][Tt][Uu][Ss][Cc][Oo][Dd][Ee][Ss]'
<kw_starttls> ::= r'[Ss][Tt][Aa][Rr][Tt][Tt][Ll][Ss]'
<kw_auth> ::= r'[Aa][Uu][Tt][Hh]'
<kw_etrn> ::= r'[Ee][Tt][Rr][Nn]'
<kw_vrfy> ::= r'[Vv][Rr][Ff][Yy]'
<kw_expn> ::= r'[Ee][Xx][Pp][Nn]'
<kw_help> ::= r'[Hh][Ee][Ll][Pp]'
# TODO: RFC 6531 (SMTPUTF8), RFC 8689 (REQUIRETLS), RFC 9422 (LIMITS), RFC 2645 (ATRN) and further extensions that refs/spec/manifest.json leaves
# out, <kw_other>: their keywords are accepted by this fallback and never sent.
<kw_other> ::= r'(?!(?:[Ss][Ii][Zz][Ee]|8[Bb][Ii][Tt][Mm][Ii][Mm][Ee]|[Pp][Ii][Pp][Ee][Ll][Ii][Nn][Ii][Nn][Gg]|[Cc][Hh][Uu][Nn][Kk][Ii][Nn][Gg]|[Bb][Ii][Nn][Aa][Rr][Yy][Mm][Ii][Mm][Ee]|[Dd][Ss][Nn]|[Ee][Nn][Hh][Aa][Nn][Cc][Ee][Dd][Ss][Tt][Aa][Tt][Uu][Ss][Cc][Oo][Dd][Ee][Ss]|[Ss][Tt][Aa][Rr][Tt][Tt][Ll][Ss]|[Aa][Uu][Tt][Hh]|[Ee][Tt][Rr][Nn]|[Vv][Rr][Ff][Yy]|[Ee][Xx][Pp][Nn]|[Hh][Ee][Ll][Pp])(?:[ \r]|$))[A-Za-z0-9][A-Za-z0-9-]*'
<ehlo_param> ::= r'[!-~]+'

# VRFY / EXPN positive text (3.5.2): the mailbox ("User Name <local-part@domain>" or "local-part@domain") is returned in a normal reply, and free-form text MAY be returned in exceptional circumstances the messages do not
# show: the 250 reply is <rep_250> with any text, and nothing about the mailbox decides what the client sends next
# A 553 reply to VRFY (ambiguous name) lists the candidates, one per line, with the same code (3.5.1)

# ------------------------------------------------------------------------------------------------------
# Commands, section 4.1.1.  Command verbs and keywords are case-insensitive in ABNF (RFC 5234 section 2.3).
# ------------------------------------------------------------------------------------------------------
<v_ehlo> ::= r'[Ee][Hh][Ll][Oo]'
<v_helo> ::= r'[Hh][Ee][Ll][Oo]'
# The verbs MAIL and RCPT have all their case forms (RFC 5234 section 2.3).  The upper-case form is the verb of the two requests that repeat a DSN parameter (<req_mail_dup_param>, <req_rcpt_dup_param>): with the
# parameters left out (no DSN offered) they would be a plain MAIL or RCPT, so the other requests send the other 15 forms and no string is derived by two of them.
<v_mail> ::= r'm[Aa][Ii][Ll]' | r'Ma[Ii][Ll]' | r'MAi[Ll]' | r'MAIl'
<v_mail_dup> ::= 'MAIL'
<v_rcpt> ::= r'r[Cc][Pp][Tt]' | r'Rc[Pp][Tt]' | r'RCp[Tt]' | r'RCPt'
<v_rcpt_dup> ::= 'RCPT'
<v_data> ::= r'[Dd][Aa][Tt][Aa]'
<v_rset> ::= r'[Rr][Ss][Ee][Tt]'
<v_vrfy> ::= r'[Vv][Rr][Ff][Yy]'
<v_expn> ::= r'[Ee][Xx][Pp][Nn]'
<v_help> ::= r'[Hh][Ee][Ll][Pp]'
<v_noop> ::= r'[Nn][Oo][Oo][Pp]'
<v_quit> ::= r'[Qq][Uu][Ii][Tt]'
<v_starttls> ::= r'[Ss][Tt][Aa][Rr][Tt][Tt][Ll][Ss]'
<v_auth> ::= r'[Aa][Uu][Tt][Hh]'
<v_bdat> ::= r'[Bb][Dd][Aa][Tt]'
<v_etrn> ::= r'[Ee][Tt][Rr][Nn]'
<v_turn> ::= r'[Tt][Uu][Rr][Nn]'
<v_send> ::= r'[Ss][Ee][Nn][Dd]'
<v_soml> ::= r'[Ss][Oo][Mm][Ll]'
<v_saml> ::= r'[Ss][Aa][Mm][Ll]'
<v_from> ::= r'[Ff][Rr][Oo][Mm]'
<v_to> ::= r'[Tt][Oo]'
<v_last> ::= r'[Ll][Aa][Ss][Tt]'

# --- EHLO / HELO (4.1.1.1): ehlo = "EHLO" SP ( Domain / address-literal ) CRLF; helo = "HELO" SP Domain CRLF
# The identity is the client's own primary host name, or its address literal (2.3.5): taken from the test setup.
<req_ehlo> ::= <v_ehlo> ' ' <ehlo_identity> <crlf>
<req_helo> ::= <v_helo> ' ' <helo_identity> <crlf>
<ehlo_identity> ::= <ehlo_name>
# the generators below fill leaf nonterminals that have no syntax of their own (a domain, an address literal, a local-part of the setup); the grammar builds the command around them
<ehlo_name> ::= r'[0-9A-Za-z.:\[\]-]+' := random.choice(EHLO_DOMAINS)
# the longest domain, 255 octets (4.5.3.1.2), as the identity of the client
# (the name comes from the test setup like the other identities: EHLO_LONG_DOMAINS, HELO_LONG_DOMAINS)
<req_ehlo_max> ::= <v_ehlo> ' ' <ehlo_long_name> <crlf>
<req_helo_max> ::= <v_helo> ' ' <helo_long_name> <crlf>
<ehlo_long_name> ::= r'[0-9A-Za-z.:\[\]-]{1,255}' := random.choice(EHLO_LONG_DOMAINS)
<helo_long_name> ::= r'[0-9A-Za-z.-]{1,255}' := random.choice(HELO_LONG_DOMAINS)
<helo_identity> ::= <helo_name>
<helo_name> ::= r'[0-9A-Za-z.-]+' := random.choice(HELO_DOMAINS)

# --- MAIL (4.1.1.2): mail = "MAIL FROM:" Reverse-path [ SP Mail-parameters ] CRLF
# TODO: RFC 5321 sections 4.1.1.2, 4.1.2 (invalid arguments and parameters of MAIL, RCPT, EHLO, HELO, STARTTLS, RSET, DATA, QUIT, AUTH and bare-LF
# data, answered 501 or 555 by the server), <req_mail>: such messages break a requirement the client must meet; the grammar never sends them.
# (the reverse-path has no source route: <req_mail_route> is the MAIL with a route, so the two requests derive different strings)
# TODO: RFC 5321 section 4.1.2 (a reverse-path with a source route in front of any mailbox, A-d-l of any length), <req_mail>: the route is sent in front of a mailbox of the setup by <req_mail_route>, and routes SHOULD NOT be generated; so that the
# two requests derive different strings the other forms of route and mailbox are not sent in MAIL.
<req_mail> ::= <v_mail> ' ' <v_from> ':' <sent_plain_reverse_path> <mail_param_list> <crlf>
# the parameter list holds only parameters of extensions the EHLO reply offered (where equality in 60_constraints.fan)
<mail_param_list> ::= (' ' <esmtp_params>)?
# Parameters of the offered extensions: SIZE (RFC 1870), BODY (RFC 6152, RFC 3030), AUTH (RFC 4954), RET and ENVID (RFC 3461); the client MUST NOT
# transmit parameters of an extension the EHLO reply did not offer (4.1.1.3): the where equalities on the parameter lists in 60_constraints.fan
# The parameters of an extension the EHLO reply did not offer are not sent: the MUST NOT of 4.1.1.3 is listed by constraints.json (C8) for MAIL and RCPT alike; after a HELO, Exim refuses
# MAIL parameters with 501 (the refusal the spec allows).
# (the parameter list is <esmtp_params> of 10_syntax.fan: any number of esmtp-params, each one of the forms below or <esmtp_param_other>)
<mail_param_size> ::= <kw_p_size> '=' <size_value>
<kw_p_size> ::= 'SIZE' | 'size' | 'Size'
# size-param = "SIZE=" 1*20DIGIT
# the same language as 1*20DIGIT, split so that about one value in four exceeds the limit of the tested servers (10 to 36 million octets), which a server must refuse with 552 (RFC 1870)
<size_value> ::= r'[0-9]{1,3}' | r'[0-9]{4,5}' | r'[0-9]{6,7}' | r'[0-9]{8,20}'
<mail_param_body> ::= <kw_p_body> '=' <body_type>
<kw_p_body> ::= 'BODY' | 'body' | 'Body'
<body_type> ::= <body_7bit> | <body_8bitmime> | <body_binarymime>
<body_7bit> ::= '7BIT'
<body_8bitmime> ::= '8BITMIME'
<body_binarymime> ::= 'BINARYMIME'
# AUTH=xtext (RFC 4954 section 5); the null identity <> is the xtext "+3C+3E" or the characters "<>", which are xchars too
<mail_param_auth> ::= <kw_p_auth> '=' (<auth_identity> | <auth_null>)
<kw_p_auth> ::= 'AUTH' | 'auth' | 'Auth'
# the identity is the xtext encoding of a mailbox: the decoded form and the encoded form are converted into each other
<auth_identity> ::= <xtext> := xtext_encode(str(<auth_mailbox>))
<auth_mailbox> ::= <sent_mailbox> := xtext_decode(str(<auth_identity>))
<auth_null> ::= '+3C+3E' | '<>'
# RET and ENVID (RFC 3461 section 4.3, 4.4)
<mail_param_ret> ::= <kw_p_ret> '=' <ret_value>
<kw_p_ret> ::= 'RET' | 'ret' | 'Ret'
<ret_value> ::= <ret_full> | <ret_hdrs>
<ret_full> ::= r'[Ff][Uu][Ll][Ll]'
<ret_hdrs> ::= r'[Hh][Dd][Rr][Ss]'
<mail_param_envid> ::= <kw_p_envid> '=' <envid_value>
<kw_p_envid> ::= 'ENVID' | 'envid' | 'Envid'
# ENVID: xtext of at most 100 characters; before the encoding the value consists of printable US-ASCII characters (RFC 3461 section 4.4)
<envid_value> ::= <xtext> := xtext_encode(str(<envid_text>))
<envid_text> ::= <envid_chars> := xtext_decode(str(<envid_value>))
<envid_chars> ::= r'[!-*,-<>-~]{1,100}' | r'[ -~]{1,33}'

# RET or ENVID twice in one MAIL: the request that breaks "RET and ENVID MUST NOT appear more than once each in any single MAIL command" (RFC 3461 section 4.5).  The spec names no reaction, so every reply is accepted
# (<ex_mail_dup_ok>, <ex_mail_dup_err>).  The parameters are sent only when the EHLO reply offered DSN (the client MUST NOT transmit parameters of an extension the server did not offer, 4.1.1.3): the where equality
# empties the list otherwise, which leaves a MAIL without parameters.
<req_mail_dup_param> ::= <v_mail_dup> ' ' <v_from> ':' <sent_plain_reverse_path> <mail_dup_list> <crlf>
<mail_dup_list> ::= (' ' <mail_dup_pair>)?
<mail_dup_pair> ::= <mail_param_ret> ' ' <mail_param_ret> | <mail_param_envid> ' ' <mail_param_envid>

# MAIL with a source route in the reverse-path in front of a valid mailbox, which servers MUST accept (4.1.2 A-d-l)
<req_mail_route> ::= <v_mail> ' ' <v_from> ':' '<' <sent_a_d_l> ':' <valid_mailbox> '>' <crlf>

# MAIL with the largest objects every server must accept (4.5.3.1.1-4.5.3.1.3): a local-part of 64 octets, a domain of 189 octets in a path of
# 256 octets (the domain of 255 octets does not fit into a path of 256: the client's own name of 255 octets is one of the EHLO and HELO identities of the setup)
<req_mail_max> ::= <v_mail> ' ' <v_from> ':' (<max_path_local> | <max_path_total>) <mail_param_list_max> <crlf>
<max_path_local> ::= '<' <max_local_part> '@' <valid_domain> '>'
<max_path_total> ::= '<' <max_local_part> '@' <max_domain_total> '>'
<max_local_part> ::= r'[a-z0-9]{64}'
<max_domain_total> ::= r'[a-z0-9]{63}[.][a-z0-9]{63}[.][a-z0-9]{61}'
# the longest MAIL line: a path of 256 octets with every parameter at its maximum (SIZE, BODY, AUTH= of 122 octets, ENVID= of 100 octets, RET=); with the
# parameters of AUTH and DSN only the line is exactly 512 octets (4.5.3.1.4); the parameters stay only when the EHLO reply offered their extension (4.1.1.3)
<mail_param_list_max> ::= (' ' <mail_params_max>)?
# The parameters are the ordered subsets of SIZE, BODY, AUTH, ENVID, RET (the where equality removes those of an extension the server did not offer, and the rest is still derived: OpenSMTPD, which
# offers no AUTH before TLS, gets SIZE, BODY, ENVID and RET).  With all of them the line is 512 octets (path 256) or longer; the huge AUTH value makes the line 1015 octets at most, below the 1036 octets
# a server MUST accept with the DSN parameters (RFC 3461 section 5.4) and the 1012 of AUTH (RFC 4954 section 5), so a refusal of it is a violation (max_refusal_ok)
<mail_params_max> ::= <mpm_size> (' ' <mpm_body>)? (' ' <mpm_auth>)? (' ' <mpm_envid>)? (' ' <mpm_ret>)? \
                    | <mpm_body> (' ' <mpm_auth>)? (' ' <mpm_envid>)? (' ' <mpm_ret>)? \
                    | <mpm_auth> (' ' <mpm_envid>)? (' ' <mpm_ret>)? \
                    | <mpm_envid> (' ' <mpm_ret>)? \
                    | <mpm_ret>
<mpm_size> ::= 'SIZE=' <max_size_value>
<mpm_body> ::= 'BODY=8BITMIME'
<mpm_auth> ::= 'AUTH=' (<max_auth_value> | <huge_auth_value>)
<mpm_envid> ::= 'ENVID=' <max_envid_value>
<mpm_ret> ::= 'RET=FULL'
<huge_auth_value> ::= r'[a-z0-9]{300}[+]40[a-z0-9]{297}'
<max_size_value> ::= r'[1-9][0-9]{0,6}'
<max_auth_value> ::= r'[a-z0-9]{60}[+]40[a-z0-9]{59}'
<max_envid_value> ::= r'[a-z0-9]{100}'
# --- RCPT (4.1.1.3): rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [ SP Rcpt-parameters ] CRLF
# req_rcpt_any: a mailbox of the setup or an unknown one, in a domain the server serves or in one it does not serve (relay), or a path with an address literal as its domain; the other RCPT requests
# (postmaster, source route, maximum sizes) derive strings of their own
<req_rcpt_any> ::= <v_rcpt> ' ' <v_to> ':' <rcpt_target> <rcpt_param_list> <crlf>
<rcpt_target> ::= <rcpt_listed_path> | <sent_literal_path>
<rcpt_listed_path> ::= '<' <rcpt_local_name> '@' <rcpt_domain_name> '>'
# (the reserved mailbox postmaster is not one of these local-parts: with a domain it is sent by <req_rcpt_postmaster>, so the two requests derive different strings)
<rcpt_local_name> ::= r"(?![Pp][Oo][Ss][Tt][Mm][Aa][Ss][Tt][Ee][Rr]@)[A-Za-z0-9._-]{1,40}" := random.choice([u for u in MAIL_USERS + UNKNOWN_USERS if u.lower() != "postmaster"])
<rcpt_domain_name> ::= r'[0-9A-Za-z.-]{1,60}' := random.choice(LOCAL_DOMAINS + REMOTE_DOMAINS)
<postmaster_bare> ::= '<' <postmaster_word> '>'
<postmaster_word> ::= r'[Pp][Oo][Ss][Tt][Mm][Aa][Ss][Tt][Ee][Rr]'
# rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ): the reserved mailbox postmaster without domain qualification, or in a domain of the setup, MUST be accepted (2.3.5, 4.1.1.3, 4.5.1)
<req_rcpt_postmaster> ::= <v_rcpt> ' ' <v_to> ':' (<postmaster_bare> | <postmaster_domain>) <crlf>
<postmaster_domain> ::= '<' <postmaster_word> '@' <valid_domain> '>'
<valid_path> ::= '<' <valid_mailbox> '>'
<valid_mailbox> ::= <valid_local_part> '@' <valid_domain>
<valid_local_part> ::= <local_user_name>
<local_user_name> ::= r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+" := random.choice(MAIL_USERS)
<valid_domain> ::= <local_domain_name>
<local_domain_name> ::= r'[0-9A-Za-z.-]+' := random.choice(LOCAL_DOMAINS)
# req_rcpt_route: a mailbox of the setup with a source route, which servers MUST accept (4.1.2 A-d-l)
<req_rcpt_route> ::= <v_rcpt> ' ' <v_to> ':' '<' <sent_a_d_l> ':' <valid_mailbox> '>' <crlf>
# RCPT with the largest objects (4.5.3.1): local-part of 64, path of 256 octets; and a line with the largest parameters of RFC 3461 section 5.4
# (NOTIFY of 28 octets, ORCPT of 500 octets), sent only when the EHLO reply offered DSN
<req_rcpt_max> ::= <v_rcpt> ' ' <v_to> ':' (<max_path_local> | <max_path_total>) <rcpt_param_list_max> <crlf>
<rcpt_param_list> ::= (' ' <esmtp_params>)?
# NOTIFY or ORCPT twice in one RCPT: the request that breaks "The NOTIFY and ORCPT parameters MUST NOT appear more than once in any RCPT command" (RFC 3461 section 4.5); every reply is accepted, the parameters are sent
# only when DSN was offered (as for <req_mail_dup_param>)
<req_rcpt_dup_param> ::= <v_rcpt_dup> ' ' <v_to> ':' <rcpt_listed_path> <rcpt_dup_list> <crlf>
<rcpt_dup_list> ::= (' ' <rcpt_dup_pair>)?
<rcpt_dup_pair> ::= <rcpt_param_notify> ' ' <rcpt_param_notify> | <rcpt_param_orcpt> ' ' <rcpt_param_orcpt>
<req_rcpt_dup_param_more> ::= <req_rcpt_dup_param>
<rcpt_param_list_max> ::= (' ' <rcpt_params_max>)?
# or, with an ORCPT that makes the whole line about 1000 octets (RFC 3461 section 5.4: command lines of at least 1036 characters MUST be accepted with the DSN parameters, so a refusal of it is a violation, max_refusal_ok)
<rcpt_params_max> ::= 'NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;' <max_orcpt_value> | 'NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;' <huge_orcpt_value>
<huge_orcpt_value> ::= r'[a-z0-9]{60}[+]40[a-z0-9]{657}'
<max_orcpt_value> ::= r'[a-z0-9]{60}[+]40[a-z0-9]{424}'
# NOTIFY=NEVER / SUCCESS,FAILURE,DELAY (RFC 3461 section 4.1); ORCPT=addr-type ";" xtext (section 4.2)
# TODO: RFC 3461 section 6 (the delivery status notification a NOTIFY/ORCPT/RET/ENVID parameter causes, RFC 3464 report format), <rcpt_param_notify>: the
# report goes to a third party (the reverse path) and is not an exchange of this connection.
<rcpt_param_notify> ::= <kw_p_notify> '=' <notify_value>
<kw_p_notify> ::= 'NOTIFY' | 'notify' | 'Notify'
<notify_value> ::= <notify_never> | <notify_elem> (',' <notify_elem>)*
<notify_never> ::= r'[Nn][Ee][Vv][Ee][Rr]'
<notify_elem> ::= <notify_success> | <notify_failure> | <notify_delay>
<notify_success> ::= r'[Ss][Uu][Cc][Cc][Ee][Ss][Ss]'
<notify_failure> ::= r'[Ff][Aa][Ii][Ll][Uu][Rr][Ee]'
<notify_delay> ::= r'[Dd][Ee][Ll][Aa][Yy]'
<rcpt_param_orcpt> ::= <kw_p_orcpt> '=' <orcpt_value>
<kw_p_orcpt> ::= 'ORCPT' | 'orcpt' | 'Orcpt'
<orcpt_value> ::= <addr_type_rfc822> ';' <orcpt_address>
# the original recipient address of an initial submission is the address of the RCPT command (RFC 3461 section 4.2)
<orcpt_address> ::= <xtext>
# TODO: RFC 3461 section 4.2 (addr-type other than rfc822, defined elsewhere than in refs/spec), <addr_type_rfc822>: only rfc822 is sent.
<addr_type_rfc822> ::= 'rfc822'

# --- DATA (4.1.1.4): data = "DATA" CRLF
# DATA is the one request that starts the mail data, in every transaction.  After an accepted MAIL with BODY=BINARYMIME the server MUST answer it with 503 (RFC 3030 section 3): that is told apart by a where on the
# exchange (<ex_data_503>, <ex_data_oos_503>), never by another form of the request.
<req_data> ::= <v_data> <crlf>
# --- RSET (4.1.1.5), VRFY (4.1.1.6), EXPN (4.1.1.7), HELP (4.1.1.8), NOOP (4.1.1.9), QUIT (4.1.1.10)
<req_rset> ::= <v_rset> <crlf>
<req_vrfy> ::= <v_vrfy> ' ' <vrfy_target> <crlf>
<req_expn> ::= <v_expn> ' ' <expn_target> <crlf>
<vrfy_target> ::= <vrfy_name>
<vrfy_name> ::= r'[!-~]+' := random.choice(MAIL_USERS + UNKNOWN_USERS + ['"%s@%s"' % (u, d) for u in MAIL_USERS for d in LOCAL_DOMAINS])
<expn_target> ::= <expn_name>
<expn_name> ::= r'[!-~]+' := random.choice(EXPN_LISTS + UNKNOWN_USERS)
<req_help> ::= <v_help> (' ' <help_topic>)? <crlf>
<help_topic> ::= <help_name>
<help_name> ::= r'[A-Za-z0-9]+' := random.choice(HELP_TOPICS)
<req_noop> ::= <v_noop> (' ' <sent_string>)? <crlf>
# a command line of exactly 512 octets (4.5.3.1.4): NOOP takes a string argument
<req_noop_max> ::= <v_noop> ' ' <max_noop_arg> <crlf>
<max_noop_arg> ::= r'[a-z0-9]{505}'
<req_quit> ::= <v_quit> <crlf>
# Private-use commands (4.1.5): "X" Ldh-str
<req_unknown_cmd> ::= <unknown_verb> (' ' <sent_string>)? <crlf>
<unknown_verb> ::= r'X[A-Z][A-Z0-9-]{0,8}'
# --- Obsolete mail-start commands (appendix F.6) and TURN (appendix F.1)
# (no source route in the reverse-path: a route is sent by <req_mail_route>, <req_rcpt_route>, which are checked for a refusal of the route (C32))
<req_send> ::= <v_send> ' ' <v_from> ':' <sent_plain_reverse_path> <crlf>
<req_soml> ::= <v_soml> ' ' <v_from> ':' <sent_plain_reverse_path> <crlf>
<req_saml> ::= <v_saml> ' ' <v_from> ':' <sent_plain_reverse_path> <crlf>
<req_turn> ::= <v_turn> <crlf>
# --- ETRN (RFC 1985 section 3): "ETRN" SP ( node-name / "@" domain / "#" queue )
<req_etrn> ::= <v_etrn> ' ' <etrn_target> <crlf>
<etrn_target> ::= <etrn_node> | <etrn_domain> | <etrn_queue>
<etrn_node> ::= <etrn_node_name>
<etrn_node_name> ::= r'[0-9A-Za-z.-]+' := random.choice([t for t in ETRN_TARGETS if not t.startswith("@") and not t.startswith("#")] or ["example.test"])
<etrn_domain> ::= '@' <etrn_domain_name>
<etrn_domain_name> ::= <etrn_domain_leaf>
<etrn_domain_leaf> ::= r'[0-9A-Za-z.-]+' := random.choice([t[1:] for t in ETRN_TARGETS if t.startswith("@")] or ["example.test"])
<etrn_queue> ::= '#' <atom>
# --- STARTTLS (RFC 3207 section 4): "STARTTLS" CRLF; takes no parameters (501)
<req_starttls> ::= <v_starttls> <crlf>

# ------------------------------------------------------------------------------------------------------
# AUTH (RFC 4954 section 4): "AUTH" mechanism [initial-response]; responses are base64 lines or "*"
# initial-response = base64 / "=" ("=" is a zero-length response); base64 syntax of RFC 4648 section 4
# ------------------------------------------------------------------------------------------------------
def b64enc(text):
    return base64.b64encode(str(text).encode("utf-8", "surrogateescape")).decode("ascii")

def b64dec(text):
    return base64.b64decode(str(text).encode("ascii")).decode("utf-8", "surrogateescape")

<sasl_mech_plain> ::= 'PLAIN'
<sasl_mech_external> ::= 'EXTERNAL'
<sasl_mech_unknown> ::= r'[A-Z][A-Z0-9_-]{2,19}' := "X-NOSUCH-MECH"
# base64 = *(4base64-char) [ 2base64-char "==" / 3base64-char "=" ] (RFC 4648 section 4, no line breaks)
<base64_text> ::= <base64_quad>+ (<base64_tail2> | <base64_tail3>)? | <base64_tail2> | <base64_tail3>
<base64_quad> ::= r'[A-Za-z0-9+/]{4}'
<base64_tail2> ::= r'[A-Za-z0-9+/]{2}' '=='
<base64_tail3> ::= r'[A-Za-z0-9+/]{3}' '='
<initial_response_empty> ::= '='

# TODO: RFC 4954 section 4 (an initial response or response line that is not valid base64, answered 501), <req_auth_plain_ir_ok>: such a line breaks the client requirement that
# responses are base64, so it is never sent; <req_auth_plain_ir_bad> sends valid base64 of wrong credentials.
# SASL PLAIN message (RFC 4616 section 2): message = [authzid] NUL authcid NUL passwd
<plain_message_ok> ::= <plain_authzid_ok>? <plain_nul> <plain_authcid_ok> <plain_nul> <plain_passwd_ok> := b64dec(<plain_b64_ok>)
# authzid = the authentication identity itself (RFC 4616 section 2: message = [authzid] NUL authcid NUL passwd)
<plain_authzid_ok> ::= <plain_safe> := AUTH_USER
<plain_b64_ok> ::= <base64_text> := b64enc(<plain_message_ok>)
<plain_authcid_ok> ::= <plain_safe> := AUTH_USER
<plain_passwd_ok> ::= <plain_safe> := AUTH_PASSWORD
# A PLAIN message whose authorization identity differs from the authentication identity (RFC 4616 section 2): the server accepts or refuses it
<plain_message_authz> ::= <plain_authzid_other> <plain_nul> <plain_authcid_ok> <plain_nul> <plain_passwd_ok> := b64dec(<plain_b64_authz>)
<plain_b64_authz> ::= <base64_text> := b64enc(<plain_message_authz>)
<plain_authzid_other> ::= <plain_safe> := AUTH_USER + "-other"
# Wrong credentials: their own nonterminals, used only by the refusing exchange
# TODO: RFC 4616 section 2 (other PLAIN messages: an authzid that differs from the authcid, non-ASCII credentials prepared by SASLprep), <plain_message_ok>:
# SASLprep (RFC 4013) is not in refs/spec; only the setup's identity is sent as authorization identity.
<plain_message_bad> ::= <plain_nul> <plain_authcid_bad> <plain_nul> <plain_passwd_bad> := b64dec(<plain_b64_bad>)
<plain_b64_bad> ::= <base64_text> := b64enc(<plain_message_bad>)
<plain_authcid_bad> ::= <plain_safe> := AUTH_USER + "-wrong"
<plain_passwd_bad> ::= <plain_safe> := AUTH_PASSWORD + "-wrong"
<plain_nul> ::= '\x00'
# SAFE of RFC 4616: any character except NUL
<plain_safe> ::= r'[^\x00]+'

# --- requests
# Initial response with the AUTH command
# The three PLAIN requests with an initial response (valid credentials, an authorization identity, wrong credentials) differ in the case of the verb, which ABNF leaves free (RFC 5234 section 2.3),
# so that no message is derived by two of them and each draws its own replies (235 against the refusal); the credentials are base64 of free text and cannot tell them apart
<req_auth_plain_ir_ok> ::= 'AUTH' ' ' <sasl_mech_plain> ' ' <plain_b64_ok> <crlf>
<req_auth_plain_ir_authz> ::= 'Auth' ' ' <sasl_mech_plain> ' ' <plain_b64_authz> <crlf>
# AUTH PLAIN with the zero-length initial response "=" and with authzid, authcid and passwd of 255 octets each (RFC 4616 section 2: servers MUST accept 255)
<req_auth_plain_empty> ::= <v_auth> ' ' <sasl_mech_plain> ' ' <initial_response_empty> <crlf>
# each component at its maximum in a message of its own (the server refuses the others' wrong credentials): generating and parsing back a message of 767 octets and its base64 text took
# Fandango 0.2 s per candidate request, which made it silent for minutes where it had to pick one of a hundred of them
<plain_message_long> ::= <plain_long_text> <plain_nul> <plain_authcid_bad> <plain_nul> <plain_passwd_bad> := b64dec(<plain_b64_long>)
<plain_b64_long> ::= <base64_text> := b64enc(<plain_message_long>)
<plain_message_long_c> ::= <plain_nul> <plain_long_text> <plain_nul> <plain_passwd_bad> := b64dec(<plain_b64_long_c>)
<plain_b64_long_c> ::= <base64_text> := b64enc(<plain_message_long_c>)
<plain_message_long_p> ::= <plain_nul> <plain_authcid_bad> <plain_nul> <plain_long_text> := b64dec(<plain_b64_long_p>)
<plain_b64_long_p> ::= <base64_text> := b64enc(<plain_message_long_p>)
<plain_long_text> ::= r'[a-z]{255}'
# wrong credentials as the initial response (the line stays within 512 octets: RFC 4954 section 4, the client MUST NOT use the initial response when the AUTH line would be longer)
<req_auth_plain_ir_bad> ::= 'auth' ' ' <sasl_mech_plain> ' ' <plain_b64_bad> <crlf>
# No initial response: the server sends a 334 challenge and the client answers with a response line
<req_auth_plain> ::= <v_auth> ' ' <sasl_mech_plain> <crlf>
<auth_response_ok> ::= <plain_b64_ok> <crlf>
# a response line may be much longer than a command line (RFC 4954 section 4: up to 12288 octets): the wrong credentials, or one component at its maximum of 255 octets (RFC 4616 section 2)
<auth_response_bad> ::= (<plain_b64_bad> | <plain_b64_long> | <plain_b64_long_c> | <plain_b64_long_p>) <crlf>
# "*" cancels the exchange (RFC 4954 section 4)
<auth_response_cancel> ::= '*' <crlf>
# a zero-length response is an empty line (RFC 4954 section 4); a PLAIN message with an authzid is another valid response
<auth_response_empty> ::= <crlf>
<auth_response_authz> ::= <plain_b64_authz> <crlf>
# A response to the challenge of EXTERNAL: the authorization identity in base64, or '=' for none (RFC 4422 appendix A)
<auth_response_external> ::= <ext_authzid_b64>? <crlf>
# Zero-length initial response is sent as a single "=" (EXTERNAL, RFC 4422 appendix A)
<req_auth_external_empty> ::= <v_auth> ' ' <sasl_mech_external> ' ' <initial_response_empty> <crlf>
# EXTERNAL authorization identity: authz-id-string = *( UTF8-char-no-nul ) (RFC 4422 appendix A), sent as base64
<req_auth_external> ::= <v_auth> ' ' <sasl_mech_external> (' ' <ext_authzid_b64>)? <crlf>
<ext_authzid_b64> ::= <base64_text> := b64enc(<ext_authzid>)
<ext_authzid> ::= <ext_authzid_chars> := b64dec(<ext_authzid_b64>)
<ext_authzid_chars> ::= r'[a-z0-9._@-]{1,30}'
# Mechanism the server does not offer: 504
<req_auth_unknown_mech> ::= <v_auth> ' ' <sasl_mech_unknown> <crlf>
# Server challenge (RFC 4954 section 4): "334" SP base64 (possibly empty); the challenge contains only base64
<rep_334> ::= <c334> ' ' <base64_text>? <crlf> | <c334> <crlf>

# ------------------------------------------------------------------------------------------------------
# BDAT (RFC 3030 section 2): "BDAT" SP chunk-size [ SP end-marker ] CRLF, followed by chunk-size octets
# The chunk of the first BDAT starts the message (header section); the following ones continue its body.
# ------------------------------------------------------------------------------------------------------
# One request nonterminal per use: a BDAT in the first position (the chunk starts the message: header section, blank line, body lines),
# in a following position (body lines, possibly none) and out of sequence; each has its own nonterminal (RFC 3030 section 3)
<bdat_command_first_more> ::= <v_bdat> ' ' <bdat_size> <crlf> <bdat_first_chunk>
<bdat_command_first_last> ::= <v_bdat> ' ' <bdat_size> ' ' <v_last> <crlf> <bdat_first_chunk_last>
<bdat_command_next_last> ::= <v_bdat> ' ' <bdat_size> ' ' <v_last> <crlf> <bdat_lead> <bdat_next_chunk_last>
# a BDAT after the first one that is not the last either: a series of more than two chunks (RFC 3030 section 2: any number of BDAT commands)
<bdat_command_next_more> ::= <v_bdat> ' ' <bdat_size> <crlf> <bdat_lead> <bdat_next_chunk>
<req_bdat_first_more> ::= <bdat_command_first_more>
<req_bdat_first_last> ::= <bdat_command_first_last>
<req_bdat_next_last> ::= <bdat_command_next_last>
<req_bdat_next_more> ::= <bdat_command_next_more>
# BDAT out of sequence (no MAIL, no accepted recipient, or after BDAT LAST): the server reads the chunk and refuses it (RFC 3030 section 2)
<req_bdat_oos> ::= <bdat_command_oos>
<bdat_command_oos> ::= <v_bdat> ' ' <bdat_size> ' ' <v_last> <crlf> <bdat_oos_chunk>
# BDAT with a chunk of BODY=BINARYMIME content (RFC 3030 section 3): its own requests, used in the exchanges of the first, the following and the last chunk.  The chunk is
# sent only in a transaction whose accepted MAIL carried BODY=BINARYMIME (which is sent only when BINARYMIME and CHUNKING were offered, C70); otherwise the where equality in
# 60_constraints.fan turns the binary alternative of the slot into a text line computed from it (the header section of a first chunk stays); the lead of the chunk, the rest of a line the chunk before it
# ended in, is set like for a text chunk.
<bdat_command_binary_more> ::= <v_bdat> ' ' <bdat_size> <crlf> <bdat_lead> <bdat_binary_slot>
<bdat_command_binary_last> ::= <v_bdat> ' ' <bdat_size> ' ' <v_last> <crlf> <bdat_lead> <bdat_binary_slot>
# the first chunk of a message holds its header section (exactly one Date and one From, RFC 5322 section 3.6: <orig_date> <originator>) in front of the binary body: BINARYMIME changes the encoding of the body, not the header
<bdat_command_binary_first_more> ::= <v_bdat> ' ' <bdat_size> <crlf> <bdat_binary_first_slot>
<bdat_command_binary_first_last> ::= <v_bdat> ' ' <bdat_size> ' ' <v_last> <crlf> <bdat_binary_first_slot>
<bdat_binary_first_slot> ::= <orig_date> <originator> <crlf> (<bdat_binary_chunk> | <body_lines>)
<req_bdat_first_binary_more> ::= <bdat_command_binary_first_more>
<req_bdat_next_binary_more> ::= <bdat_command_binary_more>
<req_bdat_first_binary_last> ::= <bdat_command_binary_first_last>
<req_bdat_next_binary_last> ::= <bdat_command_binary_last>
<bdat_binary_slot> ::= <bdat_binary_chunk> | <body_lines>
# chunk-size = 1*DIGIT, the exact number of octets that follow the BDAT line
<bdat_size> ::= <digits>
# The chunks: canonical text, lines delimited by CRLF (RFC 3030 section 2).  The first chunk holds the whole header section of the message (exactly one Date and one From, RFC 5322 section 3.6) and the
# blank line, the others body lines.  A chunk boundary may fall anywhere in the data: a chunk that is not the last may end with the CR of a line end (<bdat_cr>) or in the middle of a line (<bdat_fragment>), and the
# chunk after it continues from there: it starts with the LF, or with the rest of the line and its CRLF (<bdat_lead>, set from the earlier chunks of the session by bdat_lead_value), so every message is CRLF-delimited
# text and ends with a line end (the last chunk has whole lines only after its lead).  The last BDAT MAY have zero octets (<bdat_next_chunk_last>, a last chunk after earlier chunks).  A BDAT with a chunk is sent
# whether or not an EHLO reply announced CHUNKING: a server that did not announce it refuses the command and takes the chunk's lines for commands, so the chunk then has whole lines only (no <bdat_tail>), the exchanges
# of the refusals accept one reply or several (RFC 3030 section 2), and a server that closes the connection then is accepted in <s_bdat_bad>.
<bdat_cr> ::= '\r'
<bdat_lf> ::= '\n'
<bdat_fragment> ::= r'[ -~]{1,40}'
# the end of a chunk that is not the last, inside a line: sent only when an EHLO reply announced CHUNKING (a server that did not takes the chunk for command lines and would be left with an unfinished line: where
# equality bdat_tail_if_announced); without the announcement the chunk consists of whole lines
<bdat_tail> ::= (<bdat_cr> | <bdat_fragment>)?
# the rest of the line a chunk ended in the middle of: its first character is a dot that is not the start of a dot-stuffed line (the languages of <bdat_cont> and <body_lines> are disjoint)
<bdat_cont> ::= r'\.([ -\-/-~][ -~]{0,28})?\r\n'
<bdat_lead> ::= (<bdat_lf> | <bdat_cont>)?
<bdat_first_chunk> ::= <fields> <crlf> <body_lines>? <bdat_tail>
<bdat_first_chunk_last> ::= <fields> <crlf> <body_lines>?
<bdat_next_chunk> ::= <body_lines> <bdat_tail>
<bdat_next_chunk_last> ::= <body_lines>?
<bdat_oos_chunk> ::= <body_lines>?
# a chunk of BODY=BINARYMIME content (RFC 3030 section 3): arbitrary octets, NUL, bare CR and LF included, no line structure
<bdat_binary_chunk> ::= <bdat_bin_text>? <bdat_nul> <bdat_bin_text>?
<bdat_nul> ::= '\x00'
<bdat_bin_text> ::= r'[\x01-\xff]{1,60}' | <bdat_bin_long>
# a line of more than 998 octets without a line end, which BINARYMIME content may carry (RFC 3030 section 3: no line length limit)
<bdat_bin_long> ::= r'[\x01-\x09\x0b\x0c\x0e-\xff]{1000,1100}'
where forall <c> in <bdat_command_first_more>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_first_chunk>)))
where forall <c> in <bdat_command_first_last>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_first_chunk_last>)))
where forall <c> in <bdat_command_next_last>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_lead>)) + len(bytes(<c>.<bdat_next_chunk_last>)))
where forall <c> in <bdat_command_next_more>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_lead>)) + len(bytes(<c>.<bdat_next_chunk>)))
where forall <c> in <bdat_command_oos>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_oos_chunk>)))
where forall <c> in <bdat_command_binary_first_more>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_binary_first_slot>)))
where forall <c> in <bdat_command_binary_first_last>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_binary_first_slot>)))
where forall <c> in <bdat_command_binary_more>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_lead>)) + len(bytes(<c>.<bdat_binary_slot>)))
where forall <c> in <bdat_command_binary_last>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_lead>)) + len(bytes(<c>.<bdat_binary_slot>)))

# ------------------------------------------------------------------------------------------------------
# Reply groups: what a request may be answered with (4.2.1, 4.3.2).  Replies of 4yz/5yz and codes not listed in the
# document are handled by their first digit.  421 selects the closing state and is its own exchange.
# (Groups are kept one level deep: a group of replies lists reply rules, never other groups of more than one level.)
# ------------------------------------------------------------------------------------------------------
# Reply groups: every error a command may draw is 4yz or 5yz; codes not listed in the document are handled by their first digit
# (4.2.1, 4.3.2).  421 selects the closing state and is its own exchange (<g_421_*>).
<rep_neg> ::= <rep_450> | <rep_451> | <rep_452> | <rep_455> | <rep_458> | <rep_459> | <rep_432> | <rep_454> \
            | <rep_500> | <rep_501> | <rep_502> | <rep_503> | <rep_504> | <rep_530> | <rep_534> | <rep_535> | <rep_538> \
            | <rep_550> | <rep_551> | <rep_552> | <rep_553> | <rep_554> | <rep_555> | <rep_556> | <rep_521> \
            | <rep_3yz_x> | <rep_4yz_x> | <rep_5yz_x>
<rep_mail_ok> ::= <rep_250> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
# TODO: RFC 5321 section 3.4 (the forward-path in the text of a 251 and a 551 reply), <rep_251>, <rep_551>: the text is not parsed, the
# next request of the session does not depend on it.
<rep_rcpt_ok> ::= <rep_250> | <rep_251> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_252> | <rep_253> | <rep_2yz_x>
# The reserved mailbox postmaster MUST be accepted (2.3.5, 4.1.1.3): a server may block it in extreme cases (4.5.1), which the messages do not show and the spec gives no reply code for.  Every reply is accepted for the
# postmaster RCPT like for any other RCPT (<rep_neg>, <rep_rcpt_ok>); nothing is enforced on it.
# every 2yz reply (the codes of the document and the first-digit fallback): a reply to a command whose success reply is another code (4.3.2: unrecognized codes by their first digit)
<rep_2yz_all> ::= <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
<rep_starttls_ok> ::= <rep_220> | <rep_211> | <rep_214> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
# DATA that is not answered with 354: a refusal, or a 2yz reply
<rep_data_refused> ::= <rep_450> | <rep_451> | <rep_452> | <rep_455> | <rep_458> | <rep_459> | <rep_432> | <rep_454> \
            | <rep_500> | <rep_501> | <rep_502> | <rep_503> | <rep_504> | <rep_530> | <rep_534> | <rep_535> | <rep_538> \
            | <rep_550> | <rep_551> | <rep_552> | <rep_553> | <rep_554> | <rep_555> | <rep_556> | <rep_521> \
            | <rep_3yz_x> | <rep_4yz_x> | <rep_5yz_x> \
            | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
<rep_auth_ok> ::= <rep_235> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
# the reply to a successful BDAT chunk is 250 (RFC 3030 section 2: "MUST be sent for each successful BDAT")
<rep_bdat_ok> ::= <rep_250>
<rep_noop_ok> ::= <rep_250> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
<rep_help_ok> ::= <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
<rep_vrfy_ok> ::= <rep_250> | <rep_251> | <rep_252> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_253> | <rep_2yz_x>
<rep_expn_ok> ::= <rep_250> | <rep_251> | <rep_252> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_253> | <rep_2yz_x>
<rep_noop_max> ::= <rep_250> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x> | <rep_mail_max_neg>
<rep_noop> ::= <rep_250> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x> | <rep_neg>
<rep_help> ::= <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x> | <rep_neg>
<rep_vrfy> ::= <rep_250> | <rep_251> | <rep_252> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_253> | <rep_2yz_x> | <rep_neg>
<rep_expn> ::= <rep_250> | <rep_251> | <rep_252> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_253> | <rep_2yz_x> | <rep_neg>
<rep_etrn> ::= <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_2yz_x> | <rep_neg>
<rep_other_cmd> ::= <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x> | <rep_neg>
<rep_turn_ok> ::= <rep_250> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x>
# RSET and QUIT: "250 OK" / "221" MUST be sent (4.1.1.5, 4.1.1.10); 421 comes through the 421 exchanges
<rep_rset> ::= <rep_250>
<rep_quit> ::= <rep_221>
<rep_data_done> ::= <rep_250> | <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_251> | <rep_252> | <rep_253> | <rep_2yz_x> | <rep_neg>
# the largest forms MUST be accepted (4.5.3.1, RFC 3461 section 5.4): the refusals that say the line, an argument or a parameter is too long or not recognized
# (500, 501, 504, 555) break that unless the MAIL carries parameters of an extension the EHLO reply did not offer (where max_refusal_ok in 60_constraints.fan)
<rep_mail_max_neg> ::= <rep_450> | <rep_451> | <rep_452> | <rep_455> | <rep_458> | <rep_459> | <rep_432> | <rep_454> \
            | <rep_500> | <rep_501> | <rep_502> | <rep_503> | <rep_504> | <rep_530> | <rep_534> | <rep_535> | <rep_538> \
            | <rep_550> | <rep_551> | <rep_552> | <rep_553> | <rep_554> | <rep_555> | <rep_556> | <rep_521> \
            | <rep_3yz_x> | <rep_4yz_x> | <rep_5yz_x>
# while the connection is refused (3.1) the server SHOULD answer every command but QUIT with 503; any reply is accepted
<rep_rejected> ::= <rep_211> | <rep_214> | <rep_220> | <rep_221> | <rep_235> | <rep_250> | <rep_251> | <rep_252> | <rep_253> | <rep_334> | <rep_354> | <rep_2yz_x> | <rep_neg>

# ------------------------------------------------------------------------------------------------------
# Session: connection opening (3.1), then the protocol states.  <end> closes the session.
# ------------------------------------------------------------------------------------------------------
<end> ::= ''
<start> ::= <Server:rep_greeting_ok> <s_greeted> \
          | <Server:rep_greeting_reject> <s_rejected> \
          | <ex_unsolicited_421>

# The exchanges that leave a state alone are one group per state (<g_*_loop>), so a state has one alternative for them and one per transition that leaves it: this keeps the
# number of k-paths Fandango plans over small.  (Writing the loop as a repetition, <g_x_loop>* (...), gave fewer k-paths but made Fandango's packet mounting fail now and then with a
# StepException that stopped the campaign.)
# --- s_greeted: greeted, no EHLO/HELO accepted yet.  A session with mail transactions MUST first be initialized by EHLO
# (4.1.4), so no mail command is sent here; non-mail commands are processed without the initialization.
<s_greeted> ::= <g_greeted_loop> <s_greeted> | <g_init> <s_ready> | <g_turn_end> <end> | <g_end> | <g_421_greeted_all>
<g_greeted_loop> ::= <g_stay> | <ex_etrn> | <ex_rset_early> | <ex_auth_early_ok> | <ex_auth_early_err> | <ex_starttls_err_early>
# TURN accepted and STARTTLS accepted end the session (see the TODOs at <ex_turn_ok> and <ex_starttls_ok>)
<g_turn_end> ::= <ex_turn_ok> | <ex_starttls_ok>
<g_421_greeted_all> ::= <g_421_stay> | <g_421_idle> | <g_421_greeted> | <ex_unsolicited_421>
# --- s_ready: initialized (EHLO/HELO accepted), no mail transaction; EHLO and RSET return here (4.1.4)
<s_ready> ::= <g_ready_loop> <s_ready> | <g_mail_ok> <s_mail> | <ex_bdat_oos> <s_bdat_bad> | <g_turn_end> <end> | <g_end> | <g_421_ready_all>
<g_ready_loop> ::= <g_stay> | <g_init> | <ex_etrn> | <ex_rset> | <g_auth> | <ex_mail_err> | <ex_mail_max_err> | <ex_mail_route_err> | <ex_sendlike_err> \
                 | <g_oos_ready> | <ex_data_oos_go> | <ex_data_oos_err_ready> | <ex_starttls_err> | <ex_mail_dup_err>
<g_mail_ok> ::= <ex_mail_ok> | <ex_mail_max_ok> | <ex_mail_route_ok> | <ex_sendlike_ok> | <ex_mail_dup_ok>
<g_421_ready_all> ::= <g_421_stay> | <g_421_idle> | <g_421_ready> | <g_auth_421> | <ex_data_oos_go_421> | <ex_unsolicited_421>
# --- s_mail: MAIL accepted, reverse-path buffer set, no recipient yet
<s_mail> ::= <g_mail_loop> <s_mail> | <g_init> <s_ready> | <ex_rset> <s_ready> | <ex_data_oos_go> <s_ready> | <ex_data_oos_503> <s_bdat_bad> | <ex_bdat_oos_mail> <s_bdat_bad> | <g_rcpt_ok> <s_rcpt> \
                            | <g_turn_end> <end> | <g_end> | <g_421_mail_all>
<g_mail_loop> ::= <g_stay> | <g_in_mail> | <ex_data_oos_err> | <ex_starttls_err> | <g_rcpt_err> | <ex_rcpt_dup_err>
<g_rcpt_ok> ::= <ex_rcpt_postmaster_ok> | <ex_rcpt_any_ok> | <ex_rcpt_route_ok> | <ex_rcpt_max_ok> | <ex_rcpt_dup_ok>
<g_421_mail_all> ::= <g_421_stay> | <g_421_mail> | <ex_data_oos_go_421> | <ex_unsolicited_421>
# --- s_rcpt: one or more recipients accepted: more recipients, DATA or the first BDAT chunk
<s_rcpt> ::= <g_rcpt_loop> <s_rcpt> | <g_init> <s_ready> | <ex_rset> <s_ready> | <ex_data_go> <s_ready> | <ex_data_503> <s_bdat_bad> | <ex_bdat_first_more> <s_bdat> | <ex_bdat_first_last> <s_ready> \
                            | <g_bdat_first_err> <s_bdat_bad> | <g_turn_end> <end> | <g_end> | <g_421_rcpt_all>
<g_rcpt_loop> ::= <g_stay> | <g_in_rcpt> | <ex_starttls_err> | <ex_rcpt_postmaster_ok_more> | <ex_rcpt_any_ok_more> | <ex_rcpt_route_ok_more> \
                | <ex_rcpt_max_ok_more> | <g_rcpt_err_more> | <ex_data_refused> | <ex_rcpt_dup_ok_more> | <ex_rcpt_dup_err_more>
<g_421_rcpt_all> ::= <g_421_stay> | <g_421_rcpt> | <ex_data_go_421> | <ex_unsolicited_421>
# --- s_bdat: BDAT chunks are being transferred (RFC 3030 section 2): the last chunk, a chunk that is not the last followed by the last, RSET, DATA (503), NOOP, HELP, VRFY, EXPN,
# EHLO, HELO, STARTTLS, QUIT (a refusal leaves the transaction indeterminate, so the next state is <s_bdat_bad>).
# A chunk that is not the last keeps the transaction in <s_bdat> (<ex_bdat_next_more>): any number of chunks, with a RSET or another command between any two of them.
# AUTH is sent while chunking too (<g_in_bdat_ok>, <g_in_bdat_err>; a refused one leaves the transaction indeterminate like any other refused command): a server that announced AUTH and CHUNKING MUST reject it with 503
# (RFC 4954 section 4); a server that did not announce CHUNKING (Postfix and Exim after HELO) may have taken the unannounced BDAT and ended its transaction, and then accepts the AUTH, so any reply is accepted
# there (where auth_in_bdat_ok).
# MAIL and RCPT are not sent while chunking (RFC 5321 section 4.1.4: MAIL MUST NOT be sent inside a transaction).  EHLO and HELO accepted end the
# transaction like RSET.
<s_bdat> ::= <g_stay_bdat_ok> <s_bdat> | <ex_bdat_next_more> <s_bdat> | <g_in_bdat_ok> <s_bdat> | <ex_rset> <s_ready> | <g_bdat_last> <s_ready> | <g_bdat_bad> <s_bdat_bad> | <g_stay_bdat_err> <s_bdat_bad> | <g_in_bdat_err> <s_bdat_bad> | <g_init> <s_ready> \
                               | <g_init_err> <s_bdat_bad> | <g_turn_end> <end> | <g_end> | <g_421_bdat_all>
<g_bdat_last> ::= <ex_bdat_next_last>
<g_bdat_bad> ::= <g_bdat_next_err> | <ex_data_after_bdat> | <ex_starttls_err>
<g_421_bdat_all> ::= <g_421_bdat> | <g_421_stay_bdat> | <ex_unsolicited_421>
# --- s_bdat_bad: after a failed BDAT, a BDAT out of sequence or DATA after BDAT the state is indeterminate and a RSET MUST be sent (RFC 3030 section 2)
# A server that did not announce CHUNKING may close the connection after the refusal of a BDAT whose chunk followed it (RFC 3030 section 2: the chunk is taken for commands sent without waiting for the reply of the BDAT): the close
# reaches the grammar as <rep_closed> (see <ClientNetworkParty>), accepted here only, where the refusal of a BDAT leads.
<s_bdat_bad> ::= <ex_rset> <s_ready> | <g_421_bad> | <ex_unsolicited_421> | <ex_closed>
<ex_closed> ::= <Server:rep_closed> <end>
<rep_closed> ::= '<connection closed by the server>' <crlf>
# --- s_rejected: the server refused the connection (554 / 521): it waits for QUIT and SHOULD answer other commands with 503 (3.1)
<s_rejected> ::= <ex_rejected_cmd> <s_rejected> | <ex_rejected_bdat> <s_rejected> | <g_end> | <g_421_rejected> | <ex_unsolicited_421>

# Exchanges that leave the state alone and are valid in every state (4.1.1): ETRN is not (RFC 1985 section 5: illegal between MAIL and the end of
# the data), it stands in the states between transactions
<g_stay> ::= <ex_noop> | <ex_noop_max> | <ex_help> | <ex_vrfy> | <ex_expn> | <ex_turn> | <ex_unknown_cmd> | <ex_ehlo_err> | <ex_helo_err>
# EHLO and HELO accepted: initialize the session and clear the buffers (4.1.4)
<g_init> ::= <ex_ehlo_ok> | <ex_helo_ok>
# QUIT ends the session (4.1.1.10)
<g_end> ::= <ex_quit>
# EHLO/HELO refused while chunking leaves the transaction indeterminate (RFC 3030 section 2)
<g_init_err> ::= <ex_ehlo_err_bdat> | <ex_helo_err>
# commands that can be used at any time during chunking: answered with success the transaction goes on, refused it is indeterminate (RFC 3030 section 2)
<g_stay_bdat_ok> ::= <Client:req_noop> <Server:rep_noop_ok> | <Client:req_help> <Server:rep_help_ok> | <Client:req_vrfy> <Server:rep_vrfy_ok> | <Client:req_expn> <Server:rep_expn_ok> | <Client:req_unknown_cmd> <Server:rep_2yz_all>
<g_stay_bdat_err> ::= (<Client:req_noop> | <Client:req_help> | <Client:req_vrfy> | <Client:req_expn> | <Client:req_turn> | <Client:req_unknown_cmd>) <Server:rep_neg>
<g_421_stay_bdat> ::= (<Client:req_noop> | <Client:req_help> | <Client:req_vrfy> | <Client:req_expn> | <Client:req_turn> | <Client:req_unknown_cmd> | <Client:req_quit> | <Client:req_ehlo> | <Client:req_ehlo_max> | <Client:req_helo> | <Client:req_helo_max> | <Client:req_starttls>) <Server:rep_421> <end>

# --- EHLO / HELO (4.1.1.1)
<ex_ehlo_ok> ::= (<Client:req_ehlo> | <Client:req_ehlo_max>) (<Server:rep_ehlo_ok> | <Server:rep_211> | <Server:rep_214> | <Server:rep_220> | <Server:rep_221> | <Server:rep_235> | <Server:rep_251> | <Server:rep_252> | <Server:rep_253> | <Server:rep_2yz_x>)
# An EHLO the server does not accept: 501, 500, 502 or 550 "as appropriate" (4.1.4); the table also lists 504, and a reply that is not in the document is handled by its first digit (4.3.2); whether the EHLO
# could have been accepted is not shown by the messages, so every refusal is accepted (as for HELO)
<ex_ehlo_err> ::= (<Client:req_ehlo> | <Client:req_ehlo_max>) <Server:rep_neg>
# (the same refusals while a chunked transfer is open)
<ex_ehlo_err_bdat> ::= (<Client:req_ehlo> | <Client:req_ehlo_max>) <Server:rep_neg>
<ex_helo_ok> ::= (<Client:req_helo> | <Client:req_helo_max>) (<Server:rep_helo_ok> | <Server:rep_211> | <Server:rep_214> | <Server:rep_220> | <Server:rep_221> | <Server:rep_235> | <Server:rep_251> | <Server:rep_252> | <Server:rep_253> | <Server:rep_2yz_x>)
<ex_helo_err> ::= (<Client:req_helo> | <Client:req_helo_max>) <Server:rep_neg>
# --- MAIL (4.1.1.2): accepted or refused; an argument that is not acceptable draws 501
<ex_mail_ok> ::= <Client:req_mail> <Server:rep_mail_ok>
# the MAIL with a parameter twice (RFC 3461 section 4.5): the spec names no reaction, every reply is accepted
<ex_mail_dup_ok> ::= <Client:req_mail_dup_param> <Server:rep_mail_ok>
<ex_mail_dup_err> ::= <Client:req_mail_dup_param> <Server:rep_neg>
<ex_rcpt_dup_ok> ::= <Client:req_rcpt_dup_param> <Server:rep_rcpt_ok>
<ex_rcpt_dup_err> ::= <Client:req_rcpt_dup_param> <Server:rep_neg>
<ex_rcpt_dup_ok_more> ::= <Client:req_rcpt_dup_param_more> <Server:rep_rcpt_ok>
<ex_rcpt_dup_err_more> ::= <Client:req_rcpt_dup_param_more> <Server:rep_neg>
<ex_mail_err> ::= <Client:req_mail> <Server:rep_neg>
<ex_mail_route_ok> ::= <Client:req_mail_route> <Server:rep_mail_ok>
<ex_mail_route_err> ::= <Client:req_mail_route> <Server:rep_neg>
# the largest local-part, domain, path and command line are accepted: no syntax error (4.5.3.1)
<ex_mail_max_ok> ::= <Client:req_mail_max> <Server:rep_mail_ok>
<ex_mail_max_err> ::= <Client:req_mail_max> <Server:rep_mail_max_neg>
<ex_sendlike_ok> ::= (<Client:req_send> | <Client:req_soml> | <Client:req_saml>) <Server:rep_mail_ok>
<ex_sendlike_err> ::= (<Client:req_send> | <Client:req_soml> | <Client:req_saml>) <Server:rep_neg>
# --- RCPT (4.1.1.3): accepted (first / further), refused (4yz/5yz)
<ex_rcpt_postmaster_ok> ::= <Client:req_rcpt_postmaster> <Server:rep_rcpt_ok>
<ex_rcpt_postmaster_ok_more> ::= <Client:req_rcpt_postmaster_more> <Server:rep_rcpt_ok>
<req_rcpt_postmaster_more> ::= <req_rcpt_postmaster>
<ex_rcpt_any_ok> ::= <Client:req_rcpt_any> <Server:rep_rcpt_ok>
<ex_rcpt_route_ok> ::= <Client:req_rcpt_route> <Server:rep_rcpt_ok>
<ex_rcpt_max_ok> ::= <Client:req_rcpt_max> <Server:rep_rcpt_ok>
<ex_rcpt_any_ok_more> ::= <Client:req_rcpt_any_more> <Server:rep_rcpt_ok>
<ex_rcpt_route_ok_more> ::= <Client:req_rcpt_route_more> <Server:rep_rcpt_ok>
<ex_rcpt_max_ok_more> ::= <Client:req_rcpt_max_more> <Server:rep_rcpt_ok>
<req_rcpt_any_more> ::= <req_rcpt_any>
<req_rcpt_route_more> ::= <req_rcpt_route>
<req_rcpt_max_more> ::= <req_rcpt_max>
<g_rcpt_err> ::= <Client:req_rcpt_postmaster> <Server:rep_neg> | <Client:req_rcpt_any> <Server:rep_neg> \
               | <Client:req_rcpt_route> <Server:rep_neg> | <Client:req_rcpt_max> <Server:rep_mail_max_neg>
<g_rcpt_err_more> ::= <Client:req_rcpt_postmaster_more> <Server:rep_neg> | <Client:req_rcpt_any_more> <Server:rep_neg> \
                    | <Client:req_rcpt_route_more> <Server:rep_neg> | <Client:req_rcpt_max_more> <Server:rep_mail_max_neg>
# --- DATA (4.1.1.4): 354, the mail data (7-bit text, 8-bit text, or more than 64K octets), then the final reply; refused DATA keeps the state
<ex_data_go> ::= <Client:req_data> <Server:rep_354> <Client:data_block_any> <Server:rep_data_done> \
               | <Client:req_data_bad_header> <Server:rep_354> <Client:data_block_bad_header> <Server:rep_data_done>
<ex_data_refused> ::= (<Client:req_data> | <Client:req_data_bad_header>) <Server:rep_data_refused>
# DATA after an accepted MAIL with BODY=BINARYMIME: the server MUST answer 503 (RFC 3030 section 3), the state of the transaction is then indeterminate and the client MUST send RSET, so this exchange leads to
# <s_bdat_bad>.  It holds only in such a transaction (where data_503_binarymime on the exchange, true while no reply exists); <ex_data_refused> holds in every other one, and accepts any refusal, 503 included, in the state
# it was sent in.  A reply other than 503 in a BINARYMIME transaction is a violation of the MUST (data_bm_ok, data_plain_ok).
<ex_data_503> ::= (<Client:req_data> | <Client:req_data_bad_header>) <Server:rep_503>
# (the same in <s_mail>, where no recipient was accepted yet: <ex_data_oos_err> keeps the state, <ex_data_oos_503> is the BINARYMIME case)
<ex_data_oos_503> ::= <Client:req_oos_data> <Server:rep_503>
<ex_data_oos_err_ready> ::= <Client:req_oos_data> <Server:rep_data_refused>
# DATA with no MAIL or no RCPT: 503 / 554, or 354 and a failure after the data (4.1.1.4)
<ex_data_oos_go> ::= <Client:req_oos_data> <Server:rep_354> <Client:data_block> <Server:rep_data_done>
<ex_data_oos_err> ::= <Client:req_oos_data> <Server:rep_data_refused>
# --- RSET, QUIT, and commands that take no argument given one (501 SHOULD, 4.3.2)
<ex_rset> ::= <Client:req_rset> <Server:rep_rset>
# before the session is initialized servers SHOULD process RSET normally (not return 503), 4.1.4; the reply MUST be 250 (4.1.1.5)
<ex_rset_early> ::= <Client:req_rset> <Server:rep_rset>
<ex_quit> ::= <Client:req_quit> <Server:rep_quit>
# --- VRFY, EXPN, HELP, NOOP, ETRN, TURN, unknown commands
<ex_vrfy> ::= <Client:req_vrfy> <Server:rep_vrfy>
<ex_expn> ::= <Client:req_expn> <Server:rep_expn>
<ex_help> ::= <Client:req_help> <Server:rep_help>
<ex_noop> ::= <Client:req_noop> <Server:rep_noop>
# the line of 512 octets must be accepted (4.5.3.1.4): no 500/501
<ex_noop_max> ::= <Client:req_noop_max> <Server:rep_noop_max>
<ex_etrn> ::= <Client:req_etrn> <Server:rep_etrn>
# TODO: RFC 5321 appendix F.1 (the dialogue after a TURN accepted with 2yz, in which the roles of the connection are reversed): one session of
# Client and Server cannot play the reversed roles, so the session ends after the accepting reply, <ex_turn_ok>.
<ex_turn> ::= <Client:req_turn> <Server:rep_neg>
<ex_turn_ok> ::= <Client:req_turn> <Server:rep_turn_ok>
<ex_unknown_cmd> ::= <Client:req_unknown_cmd> <Server:rep_other_cmd>
# --- STARTTLS (RFC 3207 section 4): 220 starts the TLS handshake (what follows is another protocol); a parameter draws 501
# TODO: RFC 3207 sections 4 and 5 (TLS handshake and the SMTP dialogue protected by it, including the EHLO reply after it, RFC 3207
# section 4.2, and the certificate checks of RFC 7817), <ex_starttls_ok>: the layer is TLS, another protocol; the session ends here.
<ex_starttls_ok> ::= <Client:req_starttls> <Server:rep_starttls_ok>
<ex_starttls_err> ::= <Client:req_starttls> <Server:rep_neg>
# --- AUTH (RFC 4954), between transactions
# TODO: RFC 4954 section 4 and RFC 4422 section 3.7 (SASL security layer after a successful AUTH, which resets SMTP to the initial state),
# <ex_auth_ir_ok>: a negotiated layer is another protocol. TODO: RFC 4954 mechanisms other than PLAIN and EXTERNAL (LOGIN, CRAM-MD5, ...),
# <sasl_mech_unknown>: their definitions are not in refs/spec; servers announcing them are accepted by <kw_auth>.
<g_auth> ::= <ex_auth_ir_ok> | <ex_auth_ir_bad> | <ex_auth_ir_authz> | <ex_auth_challenge> | <ex_auth_external> | <ex_auth_bad_mech>
<g_auth_421> ::= <ex_auth_challenge_421> | <ex_auth_external_421>
<ex_auth_ir_ok> ::= <Client:req_auth_plain_ir_ok> (<Server:rep_auth_ok> | <Server:rep_neg>)
# a zero-length initial response ('=') and PLAIN messages with components of 255 octets are valid forms the server refuses for their credentials
# (whether the server accepts the credentials is not shown by the messages: a server whose authenticator takes them answers 235, so the 2yz replies are accepted too)
<ex_auth_ir_bad> ::= (<Client:req_auth_plain_ir_bad> | <Client:req_auth_plain_empty>) (<Server:rep_auth_ok> | <Server:rep_neg>)
# a PLAIN message with an authorization identity other than the authentication identity: accepted or refused (RFC 4616 section 2)
<ex_auth_ir_authz> ::= <Client:req_auth_plain_ir_authz> (<Server:rep_auth_ok> | <Server:rep_neg>)
# AUTH without initial response: 334 challenge, then the response line (valid credentials, wrong credentials, or "*" which
# cancels the exchange and is answered with 501, RFC 4954 section 4); a refusal can come in place of the challenge
<ex_auth_challenge> ::= <Client:req_auth_plain> (<Server:rep_334> (<Client:auth_response_ok> (<Server:rep_auth_ok> | <Server:rep_neg>) \
                         | (<Client:auth_response_bad> | <Client:auth_response_empty> | <Client:auth_response_authz>) (<Server:rep_auth_ok> | <Server:rep_neg>) | <Client:auth_response_cancel> <Server:rep_501>) | <Server:rep_neg>)
<ex_auth_challenge_421> ::= <Client:req_auth_plain> <Server:rep_334> (<Client:auth_response_ok> | <Client:auth_response_bad> | <Client:auth_response_empty> | <Client:auth_response_authz> | <Client:auth_response_cancel>) <Server:rep_421> <end>
# EXTERNAL (RFC 4422 appendix A): with an initial response the exchange ends with 235 or a refusal; without one the server sends an empty
# challenge (334) and the client answers with its response line or cancels with "*"
<ex_auth_external> ::= <Client:req_auth_external_empty> (<Server:rep_auth_ok> | <Server:rep_neg>) \
                     | <Client:req_auth_external> (<Server:rep_auth_ok> | <Server:rep_334> (<Client:auth_response_external> (<Server:rep_auth_ok> | <Server:rep_neg>) | <Client:auth_response_cancel> <Server:rep_501>) | <Server:rep_neg>)
<ex_auth_external_421> ::= <Client:req_auth_external> <Server:rep_334> (<Client:auth_response_external> | <Client:auth_response_cancel>) <Server:rep_421> <end>
<ex_auth_bad_mech> ::= <Client:req_auth_unknown_mech> <Server:rep_neg>
# AUTH before the session is initialized
<ex_auth_early_ok> ::= <Client:req_oos_auth> <Server:rep_auth_ok>
<ex_auth_early_err> ::= <Client:req_oos_auth> <Server:rep_neg>
<ex_starttls_err_early> ::= <Client:req_starttls> <Server:rep_neg>

# --- Commands out of sequence: a RCPT without MAIL MUST draw 503 (4.1.1.3); so does a command out of order (4.1.4);
# an AUTH during a mail transaction MUST be rejected with 503 (RFC 4954 section 4).  Each request has its own nonterminal.
# A MAIL inside a transaction is not sent: the client MUST NOT send it (4.1.4).
<g_oos_ready> ::= <Client:req_oos_rcpt> <Server:rep_503>
# (503 when the server announced AUTH: where auth_in_transaction_ok; any refusal otherwise)
<g_in_mail> ::= <Client:req_oos_auth> (<Server:rep_auth_ok> | <Server:rep_neg>)
<g_in_rcpt> ::= <Client:req_oos_auth> (<Server:rep_auth_ok> | <Server:rep_neg>)
<g_in_bdat_ok> ::= <Client:req_oos_auth> <Server:rep_auth_ok>
<g_in_bdat_err> ::= <Client:req_oos_auth> <Server:rep_neg>
<req_oos_rcpt> ::= <req_rcpt_any>
<req_oos_data> ::= <req_data>
<req_oos_auth> ::= <req_auth_plain_ir_ok>
# While the connection is refused, every command but QUIT is refused (3.1)
<ex_rejected_cmd> ::= <Client:req_reject_probe> <Server:rep_rejected>
# BDAT with a chunk while the connection is refused: the server answers the BDAT command once, or the command and the chunk line it takes for a command (one line, so at most two replies)
<ex_rejected_bdat> ::= <Client:req_bdat_rejected> <Server:rep_rejected> <Server:rep_rejected>?
<req_bdat_rejected> ::= <v_bdat> ' ' <bdat_size> ' ' <v_last> <crlf> <bdat_reject_chunk>
<bdat_reject_chunk> ::= <bdat_reject_word> <crlf>
<bdat_reject_word> ::= r'X[A-Z]{1,9}'
where forall <c> in <req_bdat_rejected>: <c>.<bdat_size> == str(len(bytes(<c>.<bdat_reject_chunk>)))
<req_reject_probe> ::= <req_ehlo> | <req_helo> | <req_mail> | <req_noop> | <req_rset> | <req_vrfy> | <req_help> | <req_rcpt_any> | <req_data> | <req_expn> | <req_etrn> | <req_starttls> | <req_auth_plain_ir_ok> \
                     | <req_turn> | <req_unknown_cmd> | <req_send> | <req_soml> | <req_saml> | <req_noop_max> | <req_mail_max> | <req_bdat_oos> | <req_auth_plain_empty> | <req_auth_external_empty> | <req_auth_plain_ir_authz> | <req_auth_plain> | <req_auth_external> | <req_auth_plain_ir_bad> | <req_auth_unknown_mech>

# --- 421 (4.2.2): the server may answer any command with 421 and close the connection, or send it on its own initiative
# (4.2.2, 4.5.3.2).  Each request nonterminal an exchange uses in a state is also the request of its 421 exchange there.
<ex_unsolicited_421> ::= <Server:rep_421> <end>
<g_421_stay> ::= (<Client:req_noop> | <Client:req_noop_max> | <Client:req_help> | <Client:req_vrfy> | <Client:req_expn> | <Client:req_turn> \
                | <Client:req_unknown_cmd> | <Client:req_quit> \
                | <Client:req_ehlo> | <Client:req_ehlo_max> | <Client:req_helo> | <Client:req_helo_max> | <Client:req_starttls>) <Server:rep_421> <end>
<g_421_idle> ::= <Client:req_etrn> <Server:rep_421> <end>
<g_421_greeted> ::= (<Client:req_rset> | <Client:req_oos_auth>) <Server:rep_421> <end>
<g_421_ready> ::= (<Client:req_rset> | <Client:req_auth_plain_empty> | <Client:req_mail> | <Client:req_mail_dup_param> | <Client:req_mail_route> | <Client:req_mail_max> | <Client:req_send> | <Client:req_soml> | <Client:req_saml> \
                | <Client:req_auth_plain_ir_ok> | <Client:req_auth_plain_ir_bad> | <Client:req_auth_plain_ir_authz> | <Client:req_auth_plain> \
                | <Client:req_auth_external_empty> | <Client:req_auth_external> | <Client:req_auth_unknown_mech> \
                | <Client:req_oos_rcpt> | <Client:req_oos_data> | <Client:req_bdat_oos>) <Server:rep_421> <end>
<g_421_mail> ::= (<Client:req_rset> | <Client:req_rcpt_postmaster> | <Client:req_rcpt_any> | <Client:req_rcpt_route> \
                | <Client:req_rcpt_max> | <Client:req_rcpt_dup_param> | <Client:req_oos_auth> | <Client:req_oos_data> | <Client:req_bdat_oos_mail>) <Server:rep_421> <end>
<g_421_rcpt> ::= (<Client:req_rset> | <Client:req_rcpt_postmaster_more> | <Client:req_rcpt_any_more> | <Client:req_rcpt_route_more> \
                | <Client:req_rcpt_max_more> | <Client:req_data> | <Client:req_data_bad_header> | <Client:req_rcpt_dup_param_more> | <Client:req_oos_auth> \
                | <Client:req_bdat_first_more> | <Client:req_bdat_first_binary_more> | <Client:req_bdat_first_last> | <Client:req_bdat_first_binary_last>) <Server:rep_421> <end>
<g_421_bdat> ::= (<Client:req_rset> | <Client:req_bdat_next_last> | <Client:req_bdat_next_binary_last> | <Client:req_bdat_next_more> | <Client:req_bdat_next_binary_more> | <Client:req_data_after_bdat> | <Client:req_oos_auth>) <Server:rep_421> <end>
<g_421_bad> ::= <Client:req_rset> <Server:rep_421> <end>
# 421 as the reply to the end of the mail data
<ex_data_go_421> ::= <Client:req_data> <Server:rep_354> <Client:data_block_any> <Server:rep_421> <end> \
                   | <Client:req_data_bad_header> <Server:rep_354> <Client:data_block_bad_header> <Server:rep_421> <end>
<ex_data_oos_go_421> ::= <Client:req_oos_data> <Server:rep_354> <Client:data_block> <Server:rep_421> <end>
<g_421_rejected> ::= (<Client:req_reject_probe> | <Client:req_bdat_rejected> | <Client:req_quit>) <Server:rep_421> <end>
# ------------------------------------------------------------------------------------------------------
# CHUNKING (RFC 3030 section 2): BDAT is the alternative to DATA after the accepted recipients.  The chunk of the first BDAT starts the
# message, a BDAT that is not the last keeps the transaction in <s_bdat>, BDAT LAST ends it (the session returns to <s_ready>).
# A failed BDAT, a BDAT sent out of sequence and a DATA after BDAT leave the state indeterminate: a RSET MUST follow (<s_bdat_bad>).
# BDAT with a chunk is sent whether or not an EHLO reply announced CHUNKING (the use of an optional feature is sent apart from its negotiation): a server that did not announce it refuses the command and
# answers the lines of the chunk it takes for commands, so the refusal exchanges accept the replies to them (<rep_other_cmd>*), and a server that closes the connection then is accepted in <s_bdat_bad>.
# ------------------------------------------------------------------------------------------------------
<ex_bdat_first_more> ::= (<Client:req_bdat_first_more> | <Client:req_bdat_first_binary_more>) <Server:rep_bdat_ok>
<ex_bdat_first_last> ::= (<Client:req_bdat_first_last> | <Client:req_bdat_first_binary_last>) <Server:rep_bdat_ok>
# a refused BDAT: the refusal, and, where the server did not take the chunk as data (no CHUNKING), the replies to the lines of the chunk taken as commands (RFC 3030 section 2; how many lines the chunk has is not known to the reader)
<g_bdat_first_err> ::= (<Client:req_bdat_first_more> | <Client:req_bdat_first_binary_more> | <Client:req_bdat_first_last> | <Client:req_bdat_first_binary_last>) <Server:rep_neg> <Server:rep_other_cmd>*
<ex_bdat_next_last> ::= (<Client:req_bdat_next_last> | <Client:req_bdat_next_binary_last>) <Server:rep_bdat_ok>
<g_bdat_next_err> ::= (<Client:req_bdat_next_last> | <Client:req_bdat_next_binary_last> | <Client:req_bdat_next_more> | <Client:req_bdat_next_binary_more>) <Server:rep_neg> <Server:rep_other_cmd>*
# a chunk that is not the last after the first one keeps the transaction in <s_bdat>: any number of chunks (RFC 3030 section 2)
<ex_bdat_next_more> ::= (<Client:req_bdat_next_more> | <Client:req_bdat_next_binary_more>) <Server:rep_bdat_ok>
# DATA and BDAT cannot be mixed in a transaction: DATA after BDAT MUST draw 503 (RFC 3030 section 2)
<ex_data_after_bdat> ::= <Client:req_data_after_bdat> <Server:rep_503>
<req_data_after_bdat> ::= <v_data> <crlf>
# BDAT with no transaction (no MAIL, or no recipient accepted) and BDAT after BDAT LAST: 503 (RFC 3030 section 2, RFC 5321 4.1.4)
<ex_bdat_oos> ::= <Client:req_bdat_oos> <Server:rep_neg> <Server:rep_other_cmd>*
<ex_bdat_oos_mail> ::= <Client:req_bdat_oos_mail> <Server:rep_neg> <Server:rep_other_cmd>*
<req_bdat_oos_mail> ::= <req_bdat_oos>

# ------------------------------------------------------------------------------------------------------
# Mail data (4.1.1.4, 4.5.2): the content is an Internet Message (RFC 5322, RFC 6854), sent as CRLF-delimited lines.
# Data transparency (4.5.2): a line that starts with "." is sent with an extra "."; the data ends with "." alone on a line.
# ------------------------------------------------------------------------------------------------------
<data_block> ::= <message_content> '.\r\n'
# the mail data of the DATA exchange is one message type (7-bit text, 8-bit text, or more than 64K octets): a candidate is one of the three, and the large one costs Fandango
# a hundred times the work of the others
<data_block_any> ::= <data_block> | <data_block_large> | <data_block_8bit>

# Mail data that breaks "the only required header fields are the origination date field and the originator address field(s)", exactly one each (RFC 5322 section 3.6): no Date, no From, two Dates or two From fields; sent
# by <ex_data_go> after <req_data_bad_header>, every reply is accepted (the spec names no reaction)
<data_block_bad_header> ::= <fields_bad_header> <crlf> <body_lines>? '.\r\n'
<fields_bad_header> ::= <header_no_date> | <header_no_from> | <header_two_dates> | <header_two_from>
<header_no_date> ::= <originator> <destination_fields>
<header_no_from> ::= <orig_date> <destination_fields>
<header_two_dates> ::= <orig_date> <orig_date> <originator>
<header_two_from> ::= <orig_date> <originator> <originator>
<req_data_bad_header> ::= <req_data>

# 8-bit content (RFC 6152 section 2): the body carries octets with the high-order bit set (UTF-8 text)
<data_block_8bit> ::= <fields> <mime_fields> <crlf> <body_8bit_line>{1,5} '.\r\n'
# 8-bit material is MIME with the content-transfer-encoding 8bit (RFC 6152 section 2), declared by optional header fields (RFC 5322 section 3.6.8)
<mime_fields> ::= 'MIME-Version: 1.0\r\n' 'Content-Type: text/plain; charset=utf-8\r\n' 'Content-Transfer-Encoding: 8bit\r\n'
<body_8bit_line> ::= <body_8bit_text> <body_text_rest>? <crlf>
# without an accepted MAIL with BODY=8BITMIME the text is ASCII (where equality in 60_constraints.fan)
<body_8bit_text> ::= <body_8bit_chars> | <body_ascii_chars>
<body_8bit_chars> ::= r'[\u00e0-\u00ff\u0100-\u017f]{1,10}'
<body_ascii_chars> ::= r'[a-z]{1,10}'

# A message of more than 64K octets (4.5.3.1.7: every server accepts at least 64 kilobytes of content)
<data_block_large> ::= <fields> <crlf> <body_big_line>{67,70} '.\r\n'
# (a line is one terminal, with its line end: Fandango leaves out alternatives that need more nodes than its node limit allows, and 67 lines of three nodes were never chosen)
<body_big_line> ::= r'[A-Za-z0-9 ]{990,998}\r\n'

# message = (fields / obs-fields) [ CRLF body ]  (RFC 5322 section 3.5)
<message_content> ::= <fields> (<crlf> <body_lines>)?
# fields: trace, resent blocks, originator and destination fields (3.6); origination date and From are required exactly once
<fields> ::= <trace_block>? <resent_block>?  <orig_date> <originator> <destination_fields> <identification_fields> <info_fields> <optional_field>{0,2}
# trace = [return] 1*received (RFC 5322 section 3.6.7)
<trace_block> ::= <return_path_field>? <received_field>{1,2}
<destination_fields> ::= <reply_to_field>? <to_field>? <cc_field>? <bcc_field>?
<identification_fields> ::= <message_id_field>? <in_reply_to_field>? <references_field>?
<info_fields> ::= <subject_field>? <comments_field>{0,2} <keywords_field>?

# --- origination date (3.6.1)
<orig_date> ::= <h_date> ':' ' ' <date_time> <crlf>
<h_date> ::= 'Date'
# date-time = [ day-of-week "," ] date time [CFWS]
<date_time> ::= <day_of_week> ',' ' ' <date> ' ' <time_of_day> ' ' <zone>
<day_of_week> ::= <day_name>
<day_name> ::= <day_mon> | <day_tue> | <day_wed> | <day_thu> | <day_fri> | <day_sat> | <day_sun>
<day_mon> ::= 'Mon'
<day_tue> ::= 'Tue'
<day_wed> ::= 'Wed'
<day_thu> ::= 'Thu'
<day_fri> ::= 'Fri'
<day_sat> ::= 'Sat'
<day_sun> ::= 'Sun'
<date> ::= <day> ' ' <month> ' ' <year>
<day> ::= r'([1-9]|1[0-9]|2[0-8])'
<month> ::= <month_jan> | <month_feb> | <month_mar> | <month_apr> | <month_may> | <month_jun> | <month_jul> | <month_aug> | <month_sep> | <month_oct> | <month_nov> | <month_dec>
<month_jan> ::= 'Jan'
<month_feb> ::= 'Feb'
<month_mar> ::= 'Mar'
<month_apr> ::= 'Apr'
<month_may> ::= 'May'
<month_jun> ::= 'Jun'
<month_jul> ::= 'Jul'
<month_aug> ::= 'Aug'
<month_sep> ::= 'Sep'
<month_oct> ::= 'Oct'
<month_nov> ::= 'Nov'
<month_dec> ::= 'Dec'
<year> ::= r'(19[7-9][0-9]|20[0-9][0-9])'
<time_of_day> ::= <hour> ':' <minute> (':' <second>)?
<hour> ::= r'([01][0-9]|2[0-3])'
<minute> ::= r'[0-5][0-9]'
<second> ::= r'[0-5][0-9]'
# zone = (FWS ( "+" / "-" ) 4DIGIT); the minutes are 00-59
<zone> ::= r'[+-]([01][0-9]|2[0-3])[0-5][0-9]'

# --- originator fields (3.6.2, RFC 6854): From carries mailbox-list or address-list (groups); several mailboxes require Sender
<originator> ::= <from_single> <sender_field>? | <from_multi> <sender_field>
<from_single> ::= <h_from> ':' ' ' (<msg_mailbox> | <msg_group_small>) <crlf>
<from_multi> ::= <h_from> ':' ' ' (<msg_mailbox> (',' ' ' <msg_mailbox>){1,2} | <msg_group_large>) <crlf>
<h_from> ::= 'From'
<sender_field> ::= 'Sender' ':' ' ' (<msg_mailbox> | <msg_group_small>) <crlf>
<reply_to_field> ::= 'Reply-To' ':' ' ' <address_list> <crlf>
<to_field> ::= 'To' ':' ' ' <address_list> <crlf>
<cc_field> ::= 'Cc' ':' ' ' <address_list> <crlf>
<bcc_field> ::= 'Bcc' ':' (' ' <address_list>)? <crlf>
<address_list> ::= <msg_address> (',' ' ' <msg_address>){0,2}
<msg_address> ::= <msg_mailbox> | <msg_group_any>
# group = display-name ":" [ group-list ] ";" (a group with at most one mailbox / more mailboxes)
<msg_group_small> ::= <display_name> ':' (<msg_mailbox>)? ';'
<msg_group_large> ::= <display_name> ':' <msg_mailbox> (',' ' ' <msg_mailbox>){1,2} ';'
<msg_group_any> ::= <display_name> ':' (<msg_mailbox> (',' ' ' <msg_mailbox>){0,2})? ';'
<msg_mailbox> ::= <name_addr> | <addr_spec>
<name_addr> ::= (<display_name> ' ')? '<' <addr_spec> '>'
<display_name> ::= <phrase_word> (' ' <phrase_word>){0,2}
<phrase_word> ::= <atom> | <quoted_string>
<addr_spec> ::= <local_part> '@' <msg_domain>
<msg_domain> ::= <dot_string> | '[' <dtext>{0,10} ']'
<dtext> ::= r'[!-Z^-~]'

# --- identification (3.6.4)
<message_id_field> ::= 'Message-ID' ':' ' ' <msg_id> <crlf>
<in_reply_to_field> ::= 'In-Reply-To' ':' ' ' <msg_id> (' ' <msg_id>){0,2} <crlf>
<references_field> ::= 'References' ':' ' ' <msg_id> (' ' <msg_id>){0,2} <crlf>
<msg_id> ::= '<' <dot_string> '@' <msg_domain> '>'
# --- informational (3.6.5)
<subject_field> ::= 'Subject' ':' ' ' <unstructured> <crlf>
<comments_field> ::= 'Comments' ':' ' ' <unstructured> <crlf>
<keywords_field> ::= 'Keywords' ':' ' ' <phrase_word> (',' ' ' <phrase_word>){0,2} <crlf>
# unstructured = (*([FWS] VCHAR) *WSP); folding: CRLF followed by white space
<unstructured> ::= <utext> (<fold> <utext>){0,2}
<fold> ::= '\r\n' r'[ \t]{1,3}'
<utext> ::= r'[!-~][ -~]{0,60}'
# --- resent (3.6.6): Resent-Date and Resent-From are present when the resent fields are used
<resent_block> ::= <resent_date> <resent_from> <resent_sender>? <resent_to>? <resent_cc>? <resent_bcc>? <resent_msg_id>?
<resent_date> ::= 'Resent-Date' ':' ' ' <date_time> <crlf>
<resent_from> ::= 'Resent-From' ':' ' ' <msg_mailbox> (',' ' ' <msg_mailbox>){0,2} <crlf>
<resent_sender> ::= 'Resent-Sender' ':' ' ' <msg_mailbox> <crlf>
<resent_to> ::= 'Resent-To' ':' ' ' <address_list> <crlf>
<resent_cc> ::= 'Resent-Cc' ':' ' ' <address_list> <crlf>
<resent_bcc> ::= 'Resent-Bcc' ':' (' ' <address_list>)? <crlf>
<resent_msg_id> ::= 'Resent-Message-ID' ':' ' ' <msg_id> <crlf>
# --- trace fields (3.6.7, RFC 5321 section 4.4)
<return_path_field> ::= 'Return-Path' ':' ' ' <reverse_path> <crlf>
# TODO: RFC 5321 sections 4.4 and 4.1.1.4 (Received and Return-path lines that the server adds to the message): they are part of the stored
# or forwarded message, not of this connection; only the lines a client may send are derived, <received_field>, <return_path_field>.
<received_field> ::= 'Received' ':' ' ' 'from' ' ' <domain> ' ' 'by' ' ' <domain> (' ' 'with' ' ' <mail_protocol>)? (' ' 'id' ' ' <atom>)? (' ' 'for' ' ' <path>)? ';' ' ' <date_time> <crlf>
# Mail Transmission Types (RFC 5321 section 4.4, RFC 3848)
<mail_protocol> ::= <proto_smtp> | <proto_esmtp> | <proto_esmtpa> | <proto_esmtps> | <proto_esmtpsa> | <proto_lmtp> | <proto_lmtpa> | <proto_lmtps> | <proto_lmtpsa>
<proto_smtp> ::= 'SMTP'
<proto_esmtp> ::= 'ESMTP'
<proto_esmtpa> ::= 'ESMTPA'
<proto_esmtps> ::= 'ESMTPS'
<proto_esmtpsa> ::= 'ESMTPSA'
<proto_lmtp> ::= 'LMTP'
<proto_lmtpa> ::= 'LMTPA'
<proto_lmtps> ::= 'LMTPS'
<proto_lmtpsa> ::= 'LMTPSA'
# --- optional fields (3.6.8): the name differs from every field defined in RFC 5322 (an X- name)
<optional_field> ::= <optional_name> ':' ' ' <unstructured> <crlf>
<optional_name> ::= r'X-[A-Za-z0-9-]{1,20}'

# --- body (3.5): lines of at most 998 characters; a line that starts with "." is sent with a second "." (4.5.2)
<body_lines> ::= <body_line>{1,12}
<body_line> ::= <body_plain_line> | <body_stuffed_line> | <body_long_line>
<body_plain_line> ::= <body_text_first> <body_text_rest>? <crlf> | <crlf>
<body_text_first> ::= r'[\t -\-/-~]'
<body_text_rest> ::= r'[\t -~]{1,76}'
<body_stuffed_line> ::= '..' <body_text_rest>? <crlf>
<body_long_line> ::= r'[A-Za-z0-9 ]{998}' <crlf>

# ------------------------------------------------------------------------------------------------------
# Constraints.  Each one is written once on the nonterminal that all the messages it concerns share.
# ------------------------------------------------------------------------------------------------------
# Enhanced status codes in every reply text (RFC 2034 section 3, RFC 3463): class digit, same code on every line, none on 3yz,
# present on 2yz/4yz/5yz once ENHANCEDSTATUSCODES was announced in the EHLO reply
where forall <t> in <reply_text>: reply_text_ok(<t>)

# TODO: RFC 1870 sections 5.2, 6.1 and 7 (a MAIL that declares a size above the announced fixed maximum, <req_mail>, <req_mail_max>): the 552 reply "may be returned" (6.1) and the lowercase "must" of
# section 7 concerns a minimal server, which the messages do not show, so every reply the spec allows to such a MAIL is accepted (<rep_mail_ok>, <rep_neg>) and no size check is made.

# DSN (RFC 3461 section 4.3, 4.4): MAIL with valid ENVID/RET is not refused for them
where forall <x> in <ex_mail_err>: not dsn_mail_refused_for_its_params(<x>)

# A command the server implements is listed in its EHLO reply (4.1.1.1, 4.5.1, appendix F.6); a listed keyword is never answered 500/502 (4.2.4)
where forall <x> in <ex_help>: supported_listed(<x>, "HELP")
where forall <x> in <ex_expn>: supported_listed(<x>, "EXPN")
where forall <x> in <ex_etrn>: supported_listed(<x>, "ETRN")
where forall <x> in <ex_vrfy>: supported_listed(<x>, "VRFY", True)
where forall <x> in <ex_sendlike_ok>: sendlike_listed(<x>)
where forall <x> in <ex_sendlike_err>: sendlike_listed(<x>)
where forall <x> in <ex_starttls_ok>: supported_listed(<x>, "STARTTLS")
where forall <x> in <ex_starttls_err>: supported_listed(<x>, "STARTTLS")
where forall <x> in <ex_starttls_err_early>: supported_listed(<x>, "STARTTLS")
where forall <x> in <g_auth>: supported_listed(<x>, "AUTH")
where forall <x> in <ex_auth_early_ok>: supported_listed(<x>, "AUTH")
where forall <x> in <ex_auth_early_err>: supported_listed(<x>, "AUTH")
where forall <x> in <ex_bdat_first_more>: supported_listed(<x>, "CHUNKING")
where forall <x> in <ex_bdat_first_last>: supported_listed(<x>, "CHUNKING")
where forall <x> in <ex_bdat_next_last>: supported_listed(<x>, "CHUNKING")
where forall <x> in <g_bdat_first_err>: supported_listed(<x>, "CHUNKING")
where forall <x> in <g_bdat_next_err>: supported_listed(<x>, "CHUNKING")
where forall <x> in <ex_turn>: listed_not_refused(<x>, "TURN")
where forall <x> in <g_in_bdat_ok>: supported_listed(<x>, "AUTH")
where forall <x> in <g_in_bdat_err>: supported_listed(<x>, "AUTH")
# a refused BDAT of a server that announced CHUNKING is answered once: the chunk was accepted and discarded (RFC 3030 section 2)
where forall <x> in <g_bdat_first_err>: bdat_refusal_single(<x>)
where forall <x> in <g_bdat_next_err>: bdat_refusal_single(<x>)
where forall <x> in <ex_bdat_oos>: bdat_refusal_single(<x>)
where forall <x> in <ex_bdat_oos_mail>: bdat_refusal_single(<x>)
where forall <x> in <ex_bdat_oos>: bdat_oos_reply_ok(<x>)
where forall <x> in <ex_bdat_oos_mail>: bdat_oos_reply_ok(<x>)
# a command with the parameters of an extension the server offered is not answered with 500/502 (4.2.4)
where forall <x> in <ex_mail_err>: offers_not_refused_with_params(<x>)
where forall <x> in <ex_mail_max_err>: offers_not_refused_with_params(<x>)
where forall <x> in <g_stay_bdat_ok>: supported_listed_verb(<x>)
where forall <x> in <g_stay_bdat_err>: supported_listed_verb(<x>)
where forall <x> in <ex_ehlo_err>: max_domain_accepted(<x>)
where forall <x> in <ex_ehlo_err_bdat>: max_domain_accepted(<x>)
where forall <x> in <ex_helo_err>: max_domain_accepted(<x>)
where forall <x> in <ex_mail_route_err>: not mail_route_refused(<x>)
where forall <x> in <ex_mail_max_err>: max_refusal_ok(<x>)
where forall <x> in <ex_noop_max>: max_refusal_ok(<x>)
where forall <x> in <g_rcpt_err>: max_refusal_ok(<x>)
where forall <x> in <g_rcpt_err_more>: max_refusal_ok(<x>)
where forall <x> in <ex_data_go>: long_text_line_accepted(<x>)
# DATA after an accepted MAIL with BODY=BINARYMIME MUST be answered with 503 (RFC 3030 section 3) and leaves the transaction indeterminate (RSET follows): <ex_data_503> and <ex_data_oos_503> hold only in such a transaction, the
# exchanges that keep the state hold only outside one
where forall <x> in <ex_data_503>: data_503_binarymime(<x>)
where forall <x> in <ex_data_oos_503>: data_503_binarymime(<x>)
where forall <x> in <ex_data_go>: data_bm_ok(<x>)
where forall <x> in <ex_data_oos_go>: data_bm_ok(<x>)
where forall <x> in <ex_data_go_421>: data_bm_ok(<x>)
where forall <x> in <ex_data_oos_go_421>: data_bm_ok(<x>)
where forall <x> in <ex_data_refused>: data_plain_ok(<x>)
where forall <x> in <ex_data_oos_err>: data_plain_ok(<x>)
where forall <x> in <g_rcpt_err>: offers_not_refused_with_params(<x>)
where forall <x> in <g_rcpt_err_more>: offers_not_refused_with_params(<x>)

# The client MUST NOT transmit parameters other than those associated with a service extension offered in the EHLO response (4.1.1.3), nor 8-bit content
# without 8BITMIME (2.4, RFC 6152 section 3), nor BDAT with a chunk without CHUNKING (RFC 3030 section 2): each field below is set to the value
# its extension allows, computed from the keywords of the last EHLO reply (the value is unchanged when the extension was offered)
where forall <l> in <mail_dup_list>: <l> == dsn_params_if_offered(<l>)
where forall <l> in <rcpt_dup_list>: <l> == dsn_params_if_offered(<l>)
where forall <l> in <mail_param_list>: <l> == offered_mail_params(<l>)
where forall <l> in <mail_param_list_max>: <l> == offered_max_mail_params(<l>)
where forall <l> in <rcpt_param_list>: <l> == offered_rcpt_params(<l>)
where forall <l> in <rcpt_param_list_max>: <l> == offered_max_rcpt_params(<l>)
where forall <t> in <body_8bit_text>: <t> == text_for_content(<t>)
# a chunk ends inside a line only when CHUNKING was announced (the server then reassembles the data): whole lines otherwise
where forall <t> in <bdat_tail>: <t> == bdat_tail_if_announced(<t>)
# the LF that starts the chunk after a chunk that ended with the CR is computed from the chunks sent before (bdat_lead_value, RFC 3030 section 2: canonical CRLF lines)
where forall <c> in <bdat_command_next_last>: <c>.<bdat_lead> == bdat_lead_value(<c>.<bdat_lead>)
where forall <c> in <bdat_command_next_more>: <c>.<bdat_lead> == bdat_lead_value(<c>.<bdat_lead>)
where forall <c> in <bdat_command_binary_more>: <c>.<bdat_lead> == bdat_lead_value(<c>.<bdat_lead>)
where forall <c> in <bdat_command_binary_last>: <c>.<bdat_lead> == bdat_lead_value(<c>.<bdat_lead>)
# binary content (a NUL, any octets) only in a transaction that began with an accepted MAIL with BODY=BINARYMIME (RFC 3030 section 3): in any other transaction the binary chunk becomes a text chunk of the same line (computed from it)
where forall <c> in <bdat_command_binary_more>: <c>.<bdat_binary_slot> == binary_chunk_if_allowed(<c>.<bdat_binary_slot>)
where forall <c> in <bdat_command_binary_last>: <c>.<bdat_binary_slot> == binary_chunk_if_allowed(<c>.<bdat_binary_slot>)
where forall <c> in <bdat_command_binary_first_more>: <c>.<bdat_binary_first_slot> == binary_first_chunk_if_allowed(<c>.<bdat_binary_first_slot>)
where forall <c> in <bdat_command_binary_first_last>: <c>.<bdat_binary_first_slot> == binary_first_chunk_if_allowed(<c>.<bdat_binary_first_slot>)
where forall <x> in <ex_bdat_next_more>: supported_listed(<x>, "CHUNKING")

# AUTH (RFC 4954 section 4): after a successful AUTH a further AUTH MUST be rejected with 503
where forall <x> in <g_auth>: auth_repeat_ok(<x>)
# TODO: RFC 4954 section 4 (an unsupported mechanism is rejected with 504 "the server rejects the AUTH command with a 504 reply", enhanced code 5.5.4 SHOULD), <ex_auth_bad_mech>:
# stated without MUST, so every refusal of <rep_neg> is accepted.
where forall <x> in <ex_auth_external>: auth_repeat_ok(<x>)
where forall <x> in <g_in_mail>: supported_listed(<x>, "AUTH")
where forall <x> in <g_in_rcpt>: supported_listed(<x>, "AUTH")
where forall <x> in <g_in_mail>: auth_in_transaction_ok(<x>)
where forall <x> in <g_in_rcpt>: auth_in_transaction_ok(<x>)
where forall <x> in <g_in_bdat_ok>: auth_in_bdat_ok(<x>)
where forall <x> in <g_in_bdat_err>: auth_in_bdat_ok(<x>)

# Day of week of every date-time agrees with its date (RFC 5322 section 3.3)
where forall <d> in <date_time>: <d>.<day_of_week> == weekday_name(str(<d>.<date>.<day>), str(<d>.<date>.<month>), str(<d>.<date>.<year>))
# The original recipient of ORCPT is the address of the RCPT command (RFC 3461 section 4.2)
where forall <o> in <orcpt_value>: <o>.<orcpt_address> == xtext_encode(request_path_address(<o>))

# RCPT with valid NOTIFY/ORCPT is not refused because of them (RFC 3461 section 4.5)
where forall <x> in <g_rcpt_err>: not refused_for_params(<x>, "DSN", r" (?:NOTIFY|ORCPT)=", r"NOTIFY|ORCPT|DSN")
where forall <x> in <g_rcpt_err_more>: not refused_for_params(<x>, "DSN", r" (?:NOTIFY|ORCPT)=", r"NOTIFY|ORCPT|DSN")
# A server that announced AUTH accepts the AUTH parameter of MAIL without authentication (RFC 4954 section 5); judged only for a value that is a valid <mailbox> or "<>" (RFC 4954 section 5 names the <mailbox> syntax)
where forall <x> in <ex_mail_err>: not refused_for_auth_param(<x>)
# A path with a source route MUST be accepted (4.1.2): RCPT with such a path and a valid mailbox is not answered with a syntax error
where forall <x> in <g_rcpt_err>: not route_refused(<x>)
where forall <x> in <g_rcpt_err_more>: not route_refused(<x>)
# VRFY and EXPN never return a path (3.5.2)
where forall <x> in <ex_vrfy>: no_path_in_reply(<x>)
where forall <x> in <ex_expn>: no_path_in_reply(<x>)
where forall <x> in <g_stay_bdat_ok>: no_path_in_reply(<x>)
where forall <x> in <g_stay_bdat_err>: no_path_in_reply(<x>)
# TODO: RFC 5321 sections 3.5.1 and 3.5.2 (a normal reply to VRFY/EXPN includes the mailbox, one per line for EXPN): 3.5.2 lets free-form text be returned "in circumstances exceptional enough", which the messages do not show,
# so a 250 (and every other 2yz or 551 reply) is accepted with free-form text (<rep_250>, <rep_vrfy>, <rep_expn>) and no mailbox is enforced.
# TODO: RFC 5321 sections 2.3.5 and 4.5.1 (the reserved mailbox postmaster MUST be supported, <req_rcpt_postmaster>, <rcpt_listed_path>): 4.5.1 lets a server block it "in extreme cases" and names no reply code; the condition is not
# shown by the messages, so every reply the spec allows to such a RCPT is accepted (<rep_neg>, <rep_rcpt_ok>).
# TODO: RFC 5321 sections 4.5.3.1.8 and 4.5.3.1.10 (a server MUST buffer at least 100 recipients and answers 452 for too many only once its limit is exhausted, <g_rcpt_err_more>): 452 also means insufficient storage (4.3.2) and
# the reply text is only recommended (4.2), so the messages do not show that a 452 is the limit; every 452 is accepted.
# DATA remains available with CHUNKING (RFC 3030 section 3); after MAIL with BODY=BINARYMIME it is answered with 503
where forall <x> in <ex_data_refused>: data_kept(<x>)
where forall <x> in <ex_data_oos_err>: data_kept(<x>)
where forall <x> in <ex_data_oos_err_ready>: data_kept(<x>)

# Message content of at least 64K octets is accepted (4.5.3.1.7)
where forall <x> in <ex_data_go>: large_data_accepted(<x>)

# In a multiline reply with a code of the unknown kind every line has the same code (4.2.1)
where forall <r> in <rep_2yz_x>: same_code_on_every_line(<r>)
where forall <r> in <rep_4yz_x>: same_code_on_every_line(<r>)
where forall <r> in <rep_5yz_x>: same_code_on_every_line(<r>)

# BINARYMIME is announced only together with CHUNKING (RFC 3030 section 3); DATA after an accepted BODY=BINARYMIME is refused in every DATA exchange
# BINARYMIME is used only with CHUNKING (RFC 3030 section 3): BODY=BINARYMIME is sent only when the last EHLO reply listed both (mail_param_offered)
