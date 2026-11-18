# SSH-2 (Secure Shell Protocol): RFC 4250-4254, 4256, 4344, 4419, 5656, 6668, 8160, 8268, 8308, 8332, 8709, 8731, 9142
# Fandango I/O spec; the driver plays Client, the SSH server is Server.

# ======================================================================================================
# Test setup: everything the test setup decides, read from the environment with a default
# ======================================================================================================
# --- PYTHON BEGIN: test setup
SSH_USER = os.environ.get("SSH_USER", "test")                       # account that exists on the server
SSH_PASSWORD = os.environ.get("SSH_PASSWORD", "test")               # its valid password
SSH_BAD_USERS = os.environ.get("SSH_BAD_USERS", "nosuchuser,guest").split(",")      # accounts that are refused
SSH_BAD_PASSWORDS = os.environ.get("SSH_BAD_PASSWORDS", "wrong,,x" + "y" * 40).split(",")  # passwords that are refused
SSH_EXEC_COMMANDS = os.environ.get("SSH_EXEC_COMMANDS", "echo hello,true,exit 3,echo err >&2,kill -TERM $$,cat").split(",")  # commands the exec request may name
SSH_SUBSYSTEMS = os.environ.get("SSH_SUBSYSTEMS", "sftp,nosuchsubsystem").split(",")  # subsystems the request may name
SSH_ENV_NAMES = os.environ.get("SSH_ENV_NAMES", "LANG,TERM,LC_ALL").split(",")       # environment variables the env request may set
SSH_SERVICES_UNKNOWN = os.environ.get("SSH_SERVICES_UNKNOWN", "ssh-nosuchservice,nosuch@example.com").split(",")
SSH_FORWARD_TARGETS = os.environ.get("SSH_FORWARD_TARGETS", "127.0.0.1:2222,127.0.0.1:2223,127.0.0.1:2224,localhost:9").split(",")  # direct-tcpip targets host:port
SSH_BIND_ADDRESSES = os.environ.get("SSH_BIND_ADDRESSES", "127.0.0.1,localhost,,0.0.0.0,::,::1").split(",")         # tcpip-forward bind addresses
SSH_RSA_KEY_FILE = os.environ.get("SSH_RSA_KEY_FILE", "/work/refs/author/keys/client_rsa")   # the client's RSA key (authorized where the server supports it)
SSH_ECDSA_KEY_FILE = os.environ.get("SSH_ECDSA_KEY_FILE", "/work/refs/author/keys/client_ecdsa")   # the client's ECDSA nistp256 key (authorized on the servers that support it)
SSH_OTHER_RSA_KEY_FILE = os.environ.get("SSH_OTHER_RSA_KEY_FILE", "/work/refs/author/keys/other_rsa")   # a second RSA key that no server authorizes
SSH_CLIENT_KEY_FILE = os.environ.get("SSH_CLIENT_KEY_FILE", "/work/refs/author/keys/client_ed25519")
SECOND_CHANNEL = 4096          # the sender channel number of the short-lived second channel (the first channel uses 0, 1, 2, 7 or 100)
TOLERATED = os.environ.get("TOLERATED", "")                         # comma-separated names of tolerated server deviations

def tolerated(name):
    return name in [t.strip() for t in TOLERATED.split(",") if t.strip()]
# --- PYTHON END

# --- PYTHON BEGIN: transport layer of the SSH binary packet protocol (RFC 4253 sections 6-9), run by the Client party
import os, struct, hashlib, hmac as _hmac, random, secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, padding as _apad, x25519, x448, ed25519, ed448
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.exceptions import InvalidSignature

def u32(n):
    return struct.pack(">I", n)

def u32v(b):
    b = bytes(b)
    return struct.unpack(">I", b)[0] if len(b) == 4 else 0

def sstr(b):
    return u32(len(b)) + b

def mpint(n):
    if n == 0:
        return u32(0)
    return sstr(n.to_bytes((n.bit_length() + 8) // 8, "big"))

class Reader:
    def __init__(self, data, pos=0):
        self.d, self.p = bytes(data), pos
    def byte(self):
        v = self.d[self.p]; self.p += 1; return v
    def u32(self):
        v = struct.unpack(">I", self.d[self.p:self.p + 4])[0]; self.p += 4; return v
    def string(self):
        n = self.u32(); v = self.d[self.p:self.p + n]; self.p += n; return v
    def mpint(self):
        return int.from_bytes(self.string(), "big", signed=True)

def _pi_floor(bits):
    prec = bits + 64
    one = 1 << prec
    def arctan_inv(x):
        total = term = one // x
        x2, n, sign = x * x, 3, -1
        while term:
            term //= x2
            total += sign * (term // n)
            sign, n = -sign, n + 2
        return total
    return (4 * (4 * arctan_inv(5) - arctan_inv(239))) >> 64

_MODP_C = {1024: 129093, 2048: 124476, 3072: 1690314, 4096: 240904, 6144: 929484, 8192: 4743158}
def modp_prime(n):
    # the MODP group primes of RFC 2409 / RFC 3526, defined by 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + C)
    return (1 << n) - (1 << (n - 64)) - 1 + (1 << 64) * (_pi_floor(n - 130) + _MODP_C[n])

_SHA = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
# key exchange methods the client implements: name -> (kind, hash, parameter)
KEX_IMPL = {
    "diffie-hellman-group1-sha1": ("dh", "sha1", 1024),
    "diffie-hellman-group14-sha1": ("dh", "sha1", 2048),
    "diffie-hellman-group14-sha256": ("dh", "sha256", 2048),
    "diffie-hellman-group15-sha512": ("dh", "sha512", 3072),
    "diffie-hellman-group16-sha512": ("dh", "sha512", 4096),
    "diffie-hellman-group17-sha512": ("dh", "sha512", 6144),
    "diffie-hellman-group18-sha512": ("dh", "sha512", 8192),
    "diffie-hellman-group-exchange-sha1": ("gex", "sha1", None),
    "diffie-hellman-group-exchange-sha256": ("gex", "sha256", None),
    "ecdh-sha2-nistp256": ("ecdh", "sha256", ec.SECP256R1),
    "ecdh-sha2-nistp384": ("ecdh", "sha384", ec.SECP384R1),
    "ecdh-sha2-nistp521": ("ecdh", "sha512", ec.SECP521R1),
    # RFC 5656 10.2: RECOMMENDED curves named by their OID (6.1); the hash follows the curve size (6.2.1: b <= 256: SHA-256); the binary curves of the
    # table (sect163k1 ... sect571k1) are not in the cryptography library and their parameters (SEC 2) are not in refs/spec
    "ecdh-sha2-1.2.840.10045.3.1.1": ("ecdh", "sha256", ec.SECP192R1),
    "ecdh-sha2-1.3.132.0.33": ("ecdh", "sha256", ec.SECP224R1),
    "curve25519-sha256": ("x25519", "sha256", None),
    "curve448-sha512": ("x448", "sha512", None),
}
_CURVE_NAME = {"ecdh-sha2-nistp256": "nistp256", "ecdh-sha2-nistp384": "nistp384", "ecdh-sha2-nistp521": "nistp521"}
# ciphers: name -> (key length, block size, mode)
CIPHER_IMPL = {
    "aes128-ctr": (16, 16, "ctr"), "aes192-ctr": (24, 16, "ctr"), "aes256-ctr": (32, 16, "ctr"),
    "aes128-cbc": (16, 16, "cbc"), "aes192-cbc": (24, 16, "cbc"), "aes256-cbc": (32, 16, "cbc"),
    "3des-cbc": (24, 8, "cbc"), "3des-ctr": (24, 8, "ctr"), "blowfish-cbc": (16, 8, "cbc"), "blowfish-ctr": (32, 8, "ctr"),
    "cast128-cbc": (16, 8, "cbc"), "cast128-ctr": (16, 8, "ctr"), "idea-cbc": (16, 8, "cbc"), "idea-ctr": (16, 8, "ctr"),
    "arcfour": (16, 8, "stream"), "none": (0, 8, "none"),
}
# MACs: name -> (hash, key length, tag length)
MAC_IMPL = {
    "hmac-sha1": ("sha1", 20, 20), "hmac-sha1-96": ("sha1", 20, 12), "hmac-md5": ("md5", 16, 16),
    "hmac-md5-96": ("md5", 16, 12), "hmac-sha2-256": ("sha256", 32, 32), "hmac-sha2-512": ("sha512", 64, 64),
    "none": (None, 0, 0),
}
_DH_SECRET = {}   # public value (bytes) -> private key, for the values the generators produced

def _hash(name, data):
    return (hashlib.md5 if name == "md5" else _SHA[name])(data).digest()

def _namelist(b):
    s = bytes(b).decode("ascii", "replace")
    return s.split(",") if s else []


def verify_host_signature(k_s, H, sig_blob, hostkey_alg):
    """The server's signature over the exchange hash H (RFC 4253 8, RFC 5656 3.1, RFC 8332 3, RFC 8709 4); None if the key
    type is not one the client can check."""
    from cryptography.hazmat.primitives.asymmetric import utils as _u
    r = Reader(k_s)
    ktype = r.string()
    sr = Reader(sig_blob)
    salg, sig = sr.string(), sr.string()
    if ktype == b"ssh-ed25519":
        ed25519.Ed25519PublicKey.from_public_bytes(r.string()).verify(sig, H)
        return salg == b"ssh-ed25519" == hostkey_alg
    if ktype == b"ssh-ed448":           # RFC 8709 4: 57-octet key, 114-octet signature
        ed448.Ed448PublicKey.from_public_bytes(r.string()).verify(sig, H)
        return salg == b"ssh-ed448" == hostkey_alg
    if ktype == b"ssh-dss":             # RFC 4253 6.6: p, q, g, y; the signature is r || s (two 160-bit values) over SHA-1
        p_, q_, g_, y_ = r.mpint(), r.mpint(), r.mpint(), r.mpint()
        pub = dsa.DSAPublicNumbers(y_, dsa.DSAParameterNumbers(p_, q_, g_)).public_key()
        if len(sig) != 40:
            raise InvalidSignature()
        pub.verify(_u.encode_dss_signature(int.from_bytes(sig[:20], "big"), int.from_bytes(sig[20:], "big")), H, _hashes.SHA1())
        return salg == b"ssh-dss" == hostkey_alg
    if ktype.startswith(b"ecdsa-sha2-"):
        curve = {b"nistp256": (ec.SECP256R1, _hashes.SHA256), b"nistp384": (ec.SECP384R1, _hashes.SHA384),
                 b"nistp521": (ec.SECP521R1, _hashes.SHA512)}[r.string()]
        pub = ec.EllipticCurvePublicKey.from_encoded_point(curve[0](), r.string())
        rs = Reader(sig)
        pub.verify(_u.encode_dss_signature(rs.mpint(), rs.mpint()), H, ec.ECDSA(curve[1]()))
        return salg == ktype == hostkey_alg
    if ktype == b"ssh-rsa":
        e, n = r.mpint(), r.mpint()
        h = {b"ssh-rsa": _hashes.SHA1, b"rsa-sha2-256": _hashes.SHA256, b"rsa-sha2-512": _hashes.SHA512}[salg]
        rsa.RSAPublicNumbers(e, n).public_key().verify(sig, H, _apad.PKCS1v15(), h())
        return salg == hostkey_alg
    return None

class _EcbCtr:
    """SDCTR mode (RFC 4344 4) over a block cipher that the library offers only in ECB mode."""
    def __init__(self, ecb, iv):
        self.ecb, self.ctr, self.size, self.buf = ecb, int.from_bytes(iv, "big"), len(iv), b""
    def update(self, data):
        while len(self.buf) < len(data):
            self.buf += self.ecb.update(self.ctr.to_bytes(self.size, "big"))
            self.ctr = (self.ctr + 1) % (1 << (8 * self.size))
        stream, self.buf = self.buf[:len(data)], self.buf[len(data):]
        return bytes(a ^ b for a, b in zip(data, stream))

class _Dir:
    def __init__(self):
        self.cipher, self.block, self.mac, self.mac_key, self.mac_len, self.seq = None, 8, None, b"", 0, 0
    def make_cipher(self, name, key, iv, encrypt):
        klen, block, mode = CIPHER_IMPL[name]
        self.block = max(8, block)
        if mode == "none":
            self.cipher = None
            return
        from cryptography.hazmat.decrepit.ciphers import algorithms as dec
        base = name.split("-")[0]
        alg = algorithms.AES(key) if base.startswith("aes") else {
            "3des": dec.TripleDES, "blowfish": dec.Blowfish, "cast128": dec.CAST5, "idea": dec.IDEA, "arcfour": dec.ARC4}[base](key)
        if mode == "stream":
            c = Cipher(alg, mode=None)
        elif mode == "ctr" and not base.startswith("aes"):
            self.cipher = _EcbCtr(Cipher(alg, modes.ECB()).encryptor(), iv)   # counter mode over the block cipher (RFC 4344 4)
            return
        else:
            c = Cipher(alg, modes.CTR(iv) if mode == "ctr" else modes.CBC(iv))
        self.cipher = c.encryptor() if encrypt else c.decryptor()
    def set_mac(self, name, key):
        h, klen, tlen = MAC_IMPL[name]
        self.mac, self.mac_key, self.mac_len = h, key, tlen

class SshSession:
    """Everything the transport layer knows about the connection: identification strings, KEXINIT payloads,
    key exchange state, the cipher and MAC state of each direction."""
    def __init__(self):
        self.reset()
    def reset(self):
        self.v_c = self.v_s = b""
        self.i_c = self.i_s = b""
        self.session_id = None
        self.out, self.inn = _Dir(), _Dir()
        self.pending = None            # keys derived by the last key exchange, switched on by NEWKEYS
        self.kex_msgs = []             # (from client?, payload) of the key exchange messages
        self.rx_raw = b""
        self.rx_plain = b""            # decrypted first block(s) of the packet being received
        self.ident_done = False
        self.ident_buf = b""
        self.sent_ident = False
        self.kex_ok = None
        self.errors = []
        self.remote_channel = 0
        self.remote_channel_2 = 0       # the number the server gave the short-lived second channel (local number SECOND_CHANNEL)
        self.local_channel = 0
        self.last_service = b""
        self.last_pk = (b"", b"")
        self.last_seq_sent = 0
        self.remote_window = 0
        self.remote_maxpacket = 32768
        self.local_window = 0
        self.local_maxpacket = 0
        self.last60 = b""
        self.last_method = b""
        self.changereq_seen = False       # SSH_MSG_USERAUTH_PASSWD_CHANGEREQ received: the password is expired (RFC 4252 8)
        self.pw_expired_try = False       # the last request was a plain password request after that
        self.client_ext = {}              # the extensions of the client's SSH_MSG_EXT_INFO and of the server's (RFC 8308 2.3)
        self.server_ext = {}
        self.sig_algs = None              # the algorithms of the server's server-sig-algs extension (RFC 8308 3.1), once it has sent one
        self.last_pk_signed = False       # the last request was a publickey request with a signature
        self.open_unknown = False         # the last CHANNEL_OPEN named a channel type no server understands (RFC 4254 5.1)
        self.dc_dead = False              # delay-compression announced by both parties without a common algorithm: the server MUST disconnect (RFC 8308 3.2)
        self.dc_effect = False            # delay-compression in effect: both announced it and a common algorithm exists
        self.nfc_effect = False           # no-flow-control announced by both parties, at least one with "p": the window rules do not apply (RFC 8308 3.3)
        self.forwards = []                # the tcpip-forward requests sent so far: [address, port, want_reply] (the port allocated for port 0 is filled in from the reply)
        self.last_global = None
        self.pw_change_try = False        # the last request was a password change request (the password stays expired unless the change succeeded)
        self.rx_count = 0
        self.chan_phase = False           # a CHANNEL_OPEN was sent: a close of the connection is handed to Fandango as <s_closed>
        self.ended = False                # a DISCONNECT was sent or received
        self.rekey_open = False           # a key re-exchange is under way (a close then stays silent, as before)
        self.nk_sent = self.nk_recv = False
    # ---- negotiation (RFC 4253 7.1)
    def negotiated(self):
        def lists(payload):
            r = Reader(payload, 17)
            return [_namelist(r.string()) for _ in range(10)]
        c, s = lists(self.i_c), lists(self.i_s)
        def pick(i):
            for name in c[i]:
                if name in s[i]:
                    return name
            return None
        return {"kex": pick(0), "hostkey": pick(1), "enc_c2s": pick(2), "enc_s2c": pick(3),
                "mac_c2s": pick(4), "mac_s2c": pick(5), "comp_c2s": pick(6), "comp_s2c": pick(7)}
    # ---- RFC 8308 3: extensions announced by both parties
    @staticmethod
    def _extensions(payload):
        r = Reader(payload, 1)
        out = {}
        for _ in range(r.u32()):
            name = r.string()
            out[name] = r.string()
        return out
    def _ext_effect(self):
        c, s = self.client_ext, self.server_ext
        if b"no-flow-control" in c and b"no-flow-control" in s:
            self.nfc_effect = b"p" in (c[b"no-flow-control"], s[b"no-flow-control"])
        if b"delay-compression" in c and b"delay-compression" in s:
            try:
                lc, ls = Reader(c[b"delay-compression"]), Reader(s[b"delay-compression"])
                c2s_c, s2c_c, c2s_s, s2c_s = (_namelist(lc.string()), _namelist(lc.string()), _namelist(ls.string()), _namelist(ls.string()))
                self.dc_dead = not (set(c2s_c) & set(c2s_s) or set(s2c_c) & set(s2c_s))
                self.dc_effect = not self.dc_dead
            except Exception:
                pass
    # ---- sending
    def on_send(self, data):
        data = bytes(data)
        if not self.sent_ident and data.startswith(b"SSH-"):
            self.sent_ident = True
            self.v_c = data.rstrip(b"\r\n")
            return data
        if len(data) < 6:
            return data
        pl, pad = struct.unpack(">I", data[:4])[0], data[4]
        payload = data[5:4 + pl - pad] if 4 + pl <= len(data) and pl >= pad + 1 else data[5:]
        mtype = payload[0] if payload else 0
        self.last_seq_sent = self.out.seq
        if mtype == 7:
            try:
                self.client_ext = self._extensions(payload)
                self._ext_effect()
            except Exception:
                pass
        if mtype == 80:
            try:
                r = Reader(payload, 1); name = r.string(); want = r.byte()
                self.last_global = None
                if name == b"tcpip-forward":
                    self.last_global = [r.string(), r.u32(), want]
                    self.forwards.append(self.last_global)
            except Exception:
                pass
        if mtype == 5:
            try:
                self.last_service = Reader(payload, 1).string()
            except Exception:
                pass
        if mtype in (94, 95):
            try:
                r = Reader(payload, 1); r.u32()
                if mtype == 95:
                    r.u32()
                self.remote_window -= len(r.string())
            except Exception:
                pass
        if mtype == 93 and len(payload) >= 9:
            self.local_window += struct.unpack(">I", payload[5:9])[0]
        if mtype == 50:
            try:
                r = Reader(payload, 1); r.string(); r.string(); method = r.string()
                self.last_method = method
                self.last_pk_signed = False
                if method == b"publickey":
                    self.last_pk_signed = bool(r.byte()); self.last_pk = (r.string(), r.string())
                if method == b"password":
                    flag = r.byte()
                    self.pw_expired_try = bool(self.changereq_seen and flag == 0)     # a plain request after CHANGEREQ
                    self.pw_change_try = bool(flag)                                    # a password change request
                else:
                    self.pw_expired_try = False
                    self.pw_change_try = False
            except Exception:
                pass
        if mtype == 1:
            self.ended = True
        if mtype == 90:
            self.chan_phase = True
            try:
                r = Reader(payload, 1); chtype = r.string(); number = r.u32()
                self.open_unknown = chtype not in (b"session", b"direct-tcpip", b"x11", b"forwarded-tcpip")
                if number != SECOND_CHANNEL:      # the second channel is opened and closed at once: the tracked channel stays the first
                    self.local_channel = number
                    self.local_window, self.local_maxpacket = r.u32(), r.u32()
            except Exception:
                pass
        if mtype == 20:
            self.i_c = payload
            self.kex_msgs = []
            if self.session_id is not None:
                self.rekey_open, self.nk_sent, self.nk_recv = True, False, False
        elif mtype == 21 and self.rekey_open:
            self.nk_sent = True
            self.rekey_open = not self.nk_recv
        elif 30 <= mtype <= 49:
            self.kex_msgs.append((True, payload))
        wire = self._seal(data)
        if mtype == 21 and self.pending:
            self._activate_out()
        return wire
    def _seal(self, plain):
        d = self.out
        mac = b""
        if d.mac:
            mac = _hmac.new(d.mac_key, u32(d.seq) + plain, d.mac).digest()[:d.mac_len]
        d.seq = (d.seq + 1) & 0xFFFFFFFF
        if d.cipher is not None:
            plain = d.cipher.update(plain)
        return plain + mac
    # ---- receiving
    def on_receive(self, chunk):
        """Returns the list of plaintext messages (identification lines or packets without MAC) to hand to Fandango."""
        out = []
        data = bytes(chunk)
        if not self.ident_done:
            self.ident_buf += data
            data = b""
            while b"\n" in self.ident_buf and not self.ident_done:
                line, _, self.ident_buf = self.ident_buf.partition(b"\n")
                line += b"\n"
                out.append(line)
                if line.startswith(b"SSH-"):
                    self.ident_done = True
                    self.v_s = line.rstrip(b"\r\n")
                    data, self.ident_buf = self.ident_buf, b""
            if not self.ident_done:
                return out
        self.rx_raw += data
        d = self.inn
        while True:
            hdr = d.block if d.cipher is not None else 4
            if len(self.rx_plain) < hdr:
                need = hdr - len(self.rx_plain)
                if len(self.rx_raw) < need:
                    break
                part, self.rx_raw = self.rx_raw[:need], self.rx_raw[need:]
                self.rx_plain += d.cipher.update(part) if d.cipher is not None else part
            pl = struct.unpack(">I", self.rx_plain[:4])[0]
            if pl > 1 << 20:
                out.append(self.rx_plain + self.rx_raw)
                self.rx_plain, self.rx_raw = b"", b""
                break
            total = 4 + pl
            rest = total - len(self.rx_plain)
            if len(self.rx_raw) < rest + d.mac_len:
                break
            part, self.rx_raw = self.rx_raw[:rest], self.rx_raw[rest:]
            plain = self.rx_plain + (d.cipher.update(part) if d.cipher is not None else part)
            tag, self.rx_raw = self.rx_raw[:d.mac_len], self.rx_raw[d.mac_len:]
            self.rx_plain = b""
            if d.mac:
                want = _hmac.new(d.mac_key, u32(d.seq) + plain, d.mac).digest()[:d.mac_len]
                if not _hmac.compare_digest(want, tag):
                    self.errors.append("bad MAC on packet %d" % d.seq)
            d.seq = (d.seq + 1) & 0xFFFFFFFF
            self.rx_count += 1
            if self.rx_count >= 1 << 32:
                self.errors.append("sequence number wraps without a key re-exchange")     # RFC 4251 9.3.1
            if len(plain) % max(8, d.block if d.cipher is not None else 8):
                self.errors.append("packet is not a multiple of the cipher block size")     # RFC 4253 6
            out.append(plain)
            pad = plain[4]
            payload = plain[5:4 + pl - pad]
            self._on_payload(payload)
        return out
    def _on_payload(self, payload):
        mtype = payload[0] if payload else 0
        if mtype == 1:
            self.ended = True
        elif mtype == 20 and self.session_id is not None:
            self.rekey_open, self.nk_sent, self.nk_recv = True, False, False
        elif mtype == 21 and self.rekey_open:
            self.nk_recv = True
            self.rekey_open = not self.nk_sent
        if mtype == 60:
            self.last60 = payload
            if self.last_method == b"password":
                self.changereq_seen = True
        if mtype == 51 and self.pw_change_try:
            try:
                r = Reader(payload, 1); r.string()
                if r.byte():                                                           # partial success: the change was accepted (RFC 4252 8)
                    self.changereq_seen = False
            except Exception:
                pass
        if mtype == 52 and self.pw_change_try:
            self.changereq_seen = False
        if mtype == 52 and self.pw_expired_try:
            self.errors.append("USERAUTH_SUCCESS for an expired password")     # RFC 4252 8
        if mtype == 81 and self.last_global and self.last_global[2] and self.last_global[1] == 0 and len(payload) >= 5:
            self.last_global[1] = struct.unpack(">I", payload[1:5])[0]       # RFC 4254 7.1: the port the server allocated for port 0
        if mtype == 7:
            try:
                self.server_ext = self._extensions(payload)
                if b"server-sig-algs" in self.server_ext:
                    self.sig_algs = set(self.server_ext[b"server-sig-algs"].split(b","))
                self._ext_effect()
            except Exception:
                pass
        elif self.dc_dead and mtype != 1:
            self.errors.append("delay-compression without a common algorithm: the server must disconnect")      # RFC 8308 3.2
        if mtype == 93 and len(payload) >= 9 and payload[1:5] != u32(SECOND_CHANNEL):
            self.remote_window += struct.unpack(">I", payload[5:9])[0]
            if self.remote_window > 0xFFFFFFFF and not self.nfc_effect:
                self.errors.append("window adjust raises the window above 2^32 - 1")
        second = mtype == 91 and payload[1:5] == u32(SECOND_CHANNEL)
        if second and len(payload) >= 9:
            self.remote_channel_2 = struct.unpack(">I", payload[5:9])[0]
        if mtype == 91 and len(payload) >= 17 and not second:
            self.remote_window = struct.unpack(">I", payload[9:13])[0]
            self.remote_maxpacket = struct.unpack(">I", payload[13:17])[0]
        if mtype in (94, 95) and payload[1:5] != u32(SECOND_CHANNEL):
            try:
                r = Reader(payload, 1); r.u32()
                if mtype == 95:
                    r.u32()
                n = len(r.string())
                self.local_window -= n
                if (self.local_window < 0 or n > self.local_maxpacket) and not self.nfc_effect:
                    self.errors.append("channel data exceeds the window or the maximum packet size announced by the client")
            except Exception:
                pass
        if mtype == 91 and len(payload) >= 9 and not second:
            self.remote_channel = struct.unpack(">I", payload[5:9])[0]
        if mtype == 20:
            self.i_s = payload
        elif mtype == 21:
            if self.pending:
                self._activate_in()
        elif 30 <= mtype <= 49:
            self.kex_msgs.append((False, payload))
            try:
                self._maybe_finish_kex(mtype)
            except Exception as error:     # an unparsable reply is reported by the grammar, not here
                self.errors.append("kex: %r" % (error,))
    # ---- key exchange (RFC 4253 7.2, 8; RFC 4419; RFC 5656; RFC 8731)
    def _client_msg(self, t):
        for mine, p in reversed(self.kex_msgs):
            if mine and p[0] == t:
                return p
        return None
    def _server_msg(self, t):
        for mine, p in reversed(self.kex_msgs):
            if not mine and p[0] == t:
                return p
        return None
    def _maybe_finish_kex(self, mtype):
        neg = self.negotiated()
        if neg["kex"] == "ecmqv-sha2":
            return          # RFC 5656 5: the key agreement and the HMAC tag of ecmqv-sha2 (SEC 1 5.5) are not computed; the exchange ends with the client's DISCONNECT
        kind, hname, param = KEX_IMPL[neg["kex"]]
        if kind == "gex":
            if mtype != 33:
                return
        elif mtype != 31:
            return
        reply = Reader(self._server_msg(mtype), 1)
        k_s = reply.string()
        h_in = sstr(self.v_c) + sstr(self.v_s) + sstr(self.i_c) + sstr(self.i_s) + sstr(k_s)
        if kind in ("dh", "gex"):
            if kind == "dh":
                p, g = modp_prime(param), 2
                e = Reader(self._client_msg(30), 1).mpint()
            else:
                grp = Reader(self._server_msg(31), 1)
                p, g = grp.mpint(), grp.mpint()
                req = next((p for mine, p in reversed(self.kex_msgs) if mine and p[0] in (34, 30)), None)   # the latest request: a guessed one may precede it
                rq = Reader(req, 1)
                if req[0] == 34:
                    h_in += u32(rq.u32()) + u32(rq.u32()) + u32(rq.u32())
                else:
                    h_in += u32(rq.u32())
                h_in += mpint(p) + mpint(g)
                e = Reader(self._client_msg(32), 1).mpint()
            f = reply.mpint()
            sig_blob = reply.string()
            # fixed groups: RFC 8268 4 amends RFC 4253 8 to the open interval 1 < e, f < p-1 ("MUST NOT be sent or accepted");
            # group exchange: RFC 4419 3 keeps the closed range [1, p-1]
            low, high = (1, p - 1) if kind == "gex" else (2, p - 2)
            if not (low <= f <= high):
                self.errors.append("DH value f out of range")
            if not (low <= e <= high):
                self.errors.append("DH value e out of range")
            x = _DH_SECRET[mpint(e)]
            k = pow(f, x, p)
            if kind == "gex" and not (1 < k < p - 1):
                self.errors.append("shared secret K out of range")
            h_in += mpint(e) + mpint(f)
        else:
            q_c = Reader(self._client_msg(30), 1).string()
            q_s = reply.string()
            sig_blob = reply.string()
            priv = _DH_SECRET[sstr(q_c)]
            if kind == "ecdh":
                pub = ec.EllipticCurvePublicKey.from_encoded_point(param(), q_s)
                k = int.from_bytes(priv.exchange(ec.ECDH(), pub), "big")
            elif kind == "x25519":
                if len(q_s) != 32:
                    self.errors.append("Q_S has the wrong length")
                k = int.from_bytes(priv.exchange(x25519.X25519PublicKey.from_public_bytes(q_s)), "big")
            else:
                if len(q_s) != 56:
                    self.errors.append("Q_S has the wrong length")
                k = int.from_bytes(priv.exchange(x448.X448PublicKey.from_public_bytes(q_s)), "big")
            h_in += sstr(q_c) + sstr(q_s)
        h_in += mpint(k)
        H = _hash(hname, h_in)
        try:
            ok = verify_host_signature(k_s, H, sig_blob, neg["hostkey"].encode())
            if ok is False:
                self.errors.append("host key signature algorithm differs from the negotiated one")
        except InvalidSignature:
            self.errors.append("host key signature over H is invalid")
        self.kex_ok = (H, k_s, k, hname, neg)
        if self.session_id is None:
            self.session_id = H
        self._derive(k, H, hname, neg)
    def _derive(self, k, H, hname, neg):
        def stream(letter, n):
            out = _hash(hname, mpint(k) + H + letter + self.session_id)
            while len(out) < n:
                out += _hash(hname, mpint(k) + H + out)
            return out[:n]
        c2s, s2c = neg["enc_c2s"], neg["enc_s2c"]
        m_c2s, m_s2c = neg["mac_c2s"], neg["mac_s2c"]
        kc, kc_b = CIPHER_IMPL[c2s][0], CIPHER_IMPL[c2s][1]
        ks, ks_b = CIPHER_IMPL[s2c][0], CIPHER_IMPL[s2c][1]
        self.pending = {
            "c2s": (c2s, stream(b"C", kc), stream(b"A", kc_b), m_c2s, stream(b"E", MAC_IMPL[m_c2s][1])),
            "s2c": (s2c, stream(b"D", ks), stream(b"B", ks_b), m_s2c, stream(b"F", MAC_IMPL[m_s2c][1])),
        }
    def _activate_out(self):
        name, key, iv, mname, mkey = self.pending["c2s"]
        self.out.make_cipher(name, key, iv, True)
        self.out.set_mac(mname, mkey)
        if self.pending.get("in_done"):
            self.pending = None
        else:
            self.pending["out_done"] = True
    def _activate_in(self):
        name, key, iv, mname, mkey = self.pending["s2c"]
        self.inn.make_cipher(name, key, iv, False)
        self.inn.set_mac(mname, mkey)
        self.rx_count = 0
        if self.pending.get("out_done"):
            self.pending = None
        else:
            self.pending["in_done"] = True

SSH = SshSession()

class ClientNetworkParty(NetworkParty):
    def start(self):
        SSH.reset()
        super().start()
    def send(self, message, recipient):
        data = message.to_bytes() if hasattr(message, "to_bytes") else bytes(message)
        if os.environ.get("SSH_DEBUG_DUMP"):
            with open(os.environ["SSH_DEBUG_DUMP"], "a") as dump:
                dump.write("%s %s\n" % (getattr(message, "symbol", "?"), data.hex()))
        super().send(SSH.on_send(data), recipient)
    def receive(self, message, sender):
        if message is None:
            # the server closed the connection: in the channel phase, outside a re-exchange and without a DISCONNECT, Fandango
            # gets the token <s_closed> (not an SSH message); before that a close stays unnoticed, as silence
            if SSH.chan_phase and not SSH.ended and not SSH.rekey_open:
                SSH.ended = True
                super().receive(b"\x00\x00\x00\x00\x00\x00", sender)
            return
        # all messages of one read are handed over together: Fandango then parses them in sequence before it plans what
        # the client sends next (separate hand-overs let it plan a client message between a reply and the NEWKEYS or
        # EXT_INFO that the same read carried)
        packets = SSH.on_receive(message)
        if packets:
            super().receive(b"".join(packets), sender)
# --- PYTHON END

# --- PYTHON BEGIN: generators of values for sent messages (each yields the value of one nonterminal)
def _server_lists():
    """The name-lists of the server's KEXINIT, which the client has received before it sends its own."""
    try:
        r = Reader(SSH.i_s, 17)
        return [_namelist(r.string()) for _ in range(10)]
    except Exception:
        return [[] for _ in range(10)]

_WEIGHT = {"diffie-hellman-group14-sha256": 6, "diffie-hellman-group14-sha1": 5, "diffie-hellman-group1-sha1": 3,
           "diffie-hellman-group15-sha512": 2, "diffie-hellman-group16-sha512": 1, "diffie-hellman-group17-sha512": 0.4,
           "diffie-hellman-group18-sha512": 0.4}

def _choose(implemented, index, count=1):
    """Names the client implements that the server also offers, in random order (all of them if it offers none); the large
    fixed groups come up less often (their public values are the largest messages of a session)."""
    server = _server_lists()[index]
    common = [n for n in implemented if n in server] or list(implemented)
    if index == 0 and server and len(common) > 1:
        common = [n for n in common if n != server[0]]   # never the server's own first choice: a guessed packet is a wrong guess
    random.shuffle(common)
    common.sort(key=lambda n: random.random() ** (1.0 / _WEIGHT.get(n, 1)), reverse=True)
    return common

_KEX_FAMILY = {
    "ecdh": ["curve25519-sha256", "curve448-sha512", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"],
    "dh": ["diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group16-sha512",
           "diffie-hellman-group18-sha512", "diffie-hellman-group15-sha512", "diffie-hellman-group17-sha512",
           "diffie-hellman-group1-sha1"],
    "gex": ["diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"],
}
_HOSTKEYS = ["ssh-ed25519", "ssh-ed448", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256",
             "rsa-sha2-512", "ssh-rsa"]
_CIPHERS = ["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc", "3des-ctr", "blowfish-cbc", "blowfish-ctr", "cast128-cbc", "cast128-ctr", "idea-cbc", "idea-ctr", "arcfour", "none"]
_MACS = ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96", "none"]

_PLAN = {}   # per session: the algorithm the client plans to negotiate, chosen once the server's KEXINIT is known

def _plan(key, implemented, index):
    if _PLAN.get("session") is not SSH:
        _PLAN.clear()
        _PLAN["session"] = SSH
    if key not in _PLAN:
        _PLAN[key] = _choose(implemented, index)[0]
    return _PLAN[key]

def gen_kex_name(family):
    return _plan("kex-" + family, _KEX_FAMILY[family], 0).encode()

def gen_kex_first_right(family="ecdh"):
    """RFC 4253 7: a right guess needs the client's first kex name to be the server's first one: taken from the server's KEXINIT when
    the client implements it (then the planned method is that one); otherwise the planned name, which the server will treat as wrong."""
    first = (_server_lists()[0] or [None])[0]
    plan = _plan("kex-" + family, _KEX_FAMILY[family], 0)
    if first in _KEX_FAMILY[family]:
        plan = first
    _ALT["right" if family == "ecdh" else "right-" + family] = plan
    return plan.encode()

def gen_kex_first_hostguess(family="ecdh"):
    """RFC 4253 7: the kex name of the guess is the server's first one when the client implements it (then the planned method is that one,
    which the packet that follows the ignored guess needs), otherwise the planned name."""
    first = (_server_lists()[0] or [None])[0]
    plan = _plan("kex-" + family, _KEX_FAMILY[family], 0)
    if first in _KEX_FAMILY[family]:
        _PLAN["kex-" + family] = plan = first
    return plan.encode()

def gen_hostkey_first_right():
    first = (_server_lists()[1] or [None])[0]
    plan = _plan("hostkey", _HOSTKEYS, 1)
    if first in _HOSTKEYS:
        plan = first
    return plan.encode()

_KEX_OID = ["ecdh-sha2-1.2.840.10045.3.1.1", "ecdh-sha2-1.3.132.0.33"]

def _unannounced():
    """The ECDH-family methods the client implements that the server does not list (RFC 5656 6.3, 10.2; RFC 8731)."""
    server = _server_lists()[0]
    return [n for n in _KEX_FAMILY["ecdh"] + _KEX_OID if n not in server] or list(_KEX_OID)

_ALT = {}   # the method of the last generated right-guess / unannounced KEXINIT, recalled by the Q_C of the packet that follows it (never the session's plan:
            # Fandango also generates candidates it does not send)

def gen_kex_unannounced():
    pick = random.choice(_unannounced())
    _ALT["unann"] = pick
    return pick.encode()

def gen_ecdh_q_unannounced():
    return _ecdh_q(_ALT.get("unann") or _KEX_OID[0])

def gen_ecdh_q_right():
    return _ecdh_q(_ALT.get("right") or _plan("kex-ecdh", _KEX_FAMILY["ecdh"], 0))

def gen_kex_unannounced_other():
    return random.choice(_unannounced()).encode()

def gen_kex_name_other(family):
    return random.choice(_KEX_FAMILY[family]).encode()

def gen_hostkey_name():
    return _plan("hostkey", _HOSTKEYS, 1).encode()

_ECMQV = {}

def gen_hostkey_ecc():
    _ECMQV["curve"] = random.choice(["nistp256", "nistp384", "nistp521"])
    return ("ecdsa-sha2-" + _ECMQV["curve"]).encode()

def gen_ecmqv_q():
    from cryptography.hazmat.primitives import serialization as ser
    curve = {"nistp256": ec.SECP256R1, "nistp384": ec.SECP384R1, "nistp521": ec.SECP521R1}[_ECMQV.get("curve", "nistp256")]
    priv = ec.generate_private_key(curve())
    for _ in range(2000):
        form = ser.PublicFormat.CompressedPoint if random.random() < 0.15 else ser.PublicFormat.UncompressedPoint    # RFC 5656 3.1: point compression MAY be used
        q = priv.public_key().public_bytes(ser.Encoding.X962, form)
        if not (set(q) & {0x20, 0x0A}):
            break
        priv = ec.generate_private_key(curve())
    return q

def gen_hostkey_name_other():
    return random.choice(_HOSTKEYS).encode()

def gen_cipher_name(index):
    return _plan("cipher%d" % index, _CIPHERS, index).encode()

def gen_cipher_name_other():
    return random.choice(_CIPHERS).encode()

def gen_mac_name(index):
    return _plan("mac%d" % index, _MACS, index).encode()

def gen_mac_name_other():
    return random.choice(_MACS).encode()

def gen_cookie():
    return os.urandom(16)

def gen_small_length():
    return u32(random.randint(0, 20))

def gen_lang_tag():
    return random.choice(["en", "de", "en-US", "de-CH-1996", "zh-Hant-TW", "sl-rozaj-biske", "x-private"]).encode()

def gen_comments():
    return random.choice(["fan test client", "x", "comments with spaces and 1 digit", "a" * 60]).encode()

def gen_software_version():
    return random.choice(["FanSSH_1.0", "Fan_9.9", "libssh2_1.11", "x"]).encode()   # no "OpenSSH_" name: OpenSSH then sends eow@openssh.com after an exit-signal and one session of the verify run died of memory (30 GB) parsing that pair

def gen_user():
    return SSH_USER.encode()

def gen_bad_user():
    return random.choice(SSH_BAD_USERS).encode()

def gen_password():
    return SSH_PASSWORD.encode()

def gen_bad_password():
    return random.choice(SSH_BAD_PASSWORDS).encode()

def gen_exec_command():
    return random.choice(SSH_EXEC_COMMANDS).encode()

def gen_text():
    return random.choice(["", "hello", "café", "x" * 30]).encode("utf-8")

def gen_data():
    limit = max(0, min(SSH.remote_window if not SSH.nfc_effect else 32768, SSH.remote_maxpacket, 32768))   # the server's window and maximum packet size (RFC 4254 5.2)
    return _plain(os.urandom(min(limit, random.choice([0, 1, 7, 20, 40, 40, 300, 2000, 32768, 32768]))))

def _plain(data):
    """The octets of random data without the space and the line feed (a generated value that holds one of them counts as a
    value that spans fields or lines)."""
    return bytes(0x21 if b in (0x20, 0x0A) else b for b in data)

_NK = {}    # set once a NEWKEYS of the client has been generated: what is generated after it is sent under the new cipher

def gen_newkeys_type():
    _NK["generated"] = True
    return b"\x15"

def pad_half_allowed():
    """RFC 4253 6: the packet's total must be a multiple of the cipher block size or 8, whichever is larger. The 8 octets that make a total a
    multiple of 8 but not of 16 are legal only while the cipher in use has the block size 8 (none before the first NEWKEYS, 3des, blowfish,
    cast128, idea, arcfour), and, because the next packets are generated before the NEWKEYS is sent, only if the planned cipher has it too."""
    try:
        if not SSH.i_s:
            return False
        planned = CIPHER_IMPL[_plan("cipher2", _CIPHERS, 2)][1]
        return SSH.out.block == 8 and (planned == 8 or not _NK.get("generated"))
    except Exception:
        return False

def gen_pad_half():
    """Empty or 8 random octets: the packet's total is then a multiple of 8 only."""
    return os.urandom(8) if pad_half_allowed() and random.random() < 0.5 else b""

def gen_ignore():
    return _plain(os.urandom(random.choice([0, 1, 7, 20, 60, 300])))

def gen_dh_e():
    """e = g^x mod p for the fixed group of the planned method; x is kept for the derivation of K."""
    kind, hname, param = KEX_IMPL[_plan("kex-dh", _KEX_FAMILY["dh"], 0)]
    return _dh_public(modp_prime(param), 2)

def gen_dh_e_right():
    """e of a guessed SSH_MSG_KEXDH_INIT: the group of the method of the right guess (the planned method when the server's first one is not implemented)."""
    kind, hname, param = KEX_IMPL[_ALT.get("right-dh") or _plan("kex-dh", _KEX_FAMILY["dh"], 0)]
    return _dh_public(modp_prime(param), 2)

def gen_gex_e():
    grp = Reader(SSH._server_msg(31), 1)
    p, g = grp.mpint(), grp.mpint()
    return _dh_public(p, g)

_DH_POOL = {}

def _dh_public(p, g):
    """e = g^x mod p; a few (x, e) pairs per group are made once and drawn from afterwards (a modular exponentiation in a
    4096- or 8192-bit group costs far more than Fandango's generation of a message)."""
    pool = _DH_POOL.setdefault((p, g), [])
    if len(pool) < 3:
        # e = g^x mod p without a space or line feed octet: x, x+s, x+2s, ... are tried by one modular multiplication each
        x = secrets.randbits(512) | 1
        e = pow(g, x, p)
        s = secrets.randbits(256) | 1
        r = pow(g, s, p)
        for _ in range(12000):
            if not (set(mpint(e)[4:]) & {0x20, 0x0A}):
                break
            x, e = x + s, (e * r) % p
        pool.append((x, e))
    x, e = random.choice(pool)
    _DH_SECRET[mpint(e)] = x
    return e.to_bytes((e.bit_length() + 8) // 8, "big")

_GEX = {}

def gex_size(kind):
    """RFC 4419 3: 1024 <= min <= n <= max <= 8192; min, n and max of one request are drawn in this order and recalled."""
    if kind == "min":
        _GEX["min"] = random.choice([1024, 1024, 1536, 2048, 3072, 4096, 8192])
        return u32(_GEX["min"])
    if kind == "n":
        _GEX["n"] = random.choice([n for n in [1024, 1536, 2048, 2048, 2560, 3072, 4096, 6144, 8192] if n >= _GEX.get("min", 1024)] or [8192])
        return u32(_GEX["n"])
    if kind == "n_old":
        return u32(random.choice([1024, 1536, 2048, 2560, 3072, 4096, 6144, 8192]))
    n = _GEX.get("n", 1024)
    return u32(random.choice([m for m in [n, n, 2048, 3072, 4096, 5000, 8192] if m >= n]))

def gen_ext_count():
    return u32(random.choice([1, 1, 2, 3, 5, 8]))

def gen_pk_alg_name():
    return random.choice(["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ssh-rsa", "x-fan@example.com"]).encode()

def gen_ext_name():
    return random.choice(["x-fan@example.com", "x-fan-2@example.com", "unknown-ext@example.org"]).encode()

def gen_unknown_pk_alg():
    return random.choice(["ssh-nosuchalg", "x-fan@example.com"]).encode()

def gen_ecdh_q_invalid():
    """A public value the server must refuse: the all-zero point of curve25519/curve448, a point not on a NIST curve."""
    kind, hname, param = KEX_IMPL[_plan("kex-ecdh", _KEX_FAMILY["ecdh"], 0)]
    return {"x25519": b"\x00" * 32, "x448": b"\x00" * 56}.get(kind, b"\x04" + b"\x01" * 64)

_ECDH_POOL = {}

def gen_ecdh_q(allow_compressed=True):
    return _ecdh_q(_plan("kex-ecdh", _KEX_FAMILY["ecdh"], 0), allow_compressed)

def gen_ecdh_q_compressed():
    """RFC 5656 3.1: the compressed point (a curve25519 / curve448 key has no compressed form: the key itself)."""
    return _ecdh_q(_plan("kex-ecdh", _KEX_FAMILY["ecdh"], 0), True, True)

def _ecdh_q(name, allow_compressed=True, force=False):
    from cryptography.hazmat.primitives import serialization as ser
    kind, hname, param = KEX_IMPL[name]
    pool = _ECDH_POOL.setdefault(name, [])
    while len(pool) < 4:
        if kind == "x25519":
            priv = x25519.X25519PrivateKey.generate()
            q = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        elif kind == "x448":
            priv = x448.X448PrivateKey.generate()
            q = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        else:
            priv = ec.generate_private_key(param())
            q = priv.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
        if not (set(q) & {0x20, 0x0A}):
            pool.append((priv, q))
    priv, q = random.choice(pool)
    if allow_compressed and kind == "ecdh" and (force or random.random() < 0.15):      # RFC 5656 3.1: point compression MAY be used
        compressed = priv.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint)
        if not (set(compressed) & {0x20, 0x0A}):
            q = compressed
    _DH_SECRET[sstr(q)] = priv
    return q

def gen_remote_channel_2():
    return u32(SSH.remote_channel_2)

def gen_remote_channel():
    return u32(SSH.remote_channel)

def gen_random_name():
    return random.choice(["x-none@example.com", "algo" + str(random.randint(0, 99)) + "@fan.example", "nosuch@fan.example"]).encode()

def gen_unknown_service():
    return random.choice(SSH_SERVICES_UNKNOWN).encode()

def gen_new_password():
    return random.choice(["newpass", "N3w!pass"]).encode()

def gen_unknown_method():
    return random.choice(["nosuchmethod", "gssapi-with-mic-x@example.com"]).encode()

def _client_key():
    from cryptography.hazmat.primitives import serialization as ser
    with open(SSH_CLIENT_KEY_FILE, "rb") as f:
        return ser.load_ssh_private_key(f.read(), password=None)

def _pk_blob():
    from cryptography.hazmat.primitives import serialization as ser
    raw_pub = _client_key().public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return sstr(b"ssh-ed25519") + sstr(raw_pub)

def gen_pk_key():
    from cryptography.hazmat.primitives import serialization as ser
    return _client_key().public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)

_OTHER_KEY = []

def _other_key():
    if not _OTHER_KEY:
        _OTHER_KEY.append(ed25519.Ed25519PrivateKey.generate())
    return _OTHER_KEY[0]

def gen_pk_key_other():
    from cryptography.hazmat.primitives import serialization as ser
    return _other_key().public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)

_RSA_KEY = []

def _rsa_key():
    from cryptography.hazmat.primitives import serialization as ser
    if not _RSA_KEY:
        with open(SSH_RSA_KEY_FILE, "rb") as f:
            _RSA_KEY.append(ser.load_pem_private_key(f.read(), password=None))
    return _RSA_KEY[0]

def gen_rsa_e():
    return mpint(_rsa_key().public_key().public_numbers().e)[4:]

def gen_rsa_n():
    return mpint(_rsa_key().public_key().public_numbers().n)[4:]

# keys of other algorithms (RFC 5656 3.1, RFC 4253 6.6, RFC 8709 4) that no server authorizes; generated once per process, the public
# values without the octets the driver counts as structure
def _no_struct(b):
    return not (set(b) & {0x20, 0x0A})

# the DSA domain parameters (p, q, g) of a 1024-bit key, generated once (a parameter search takes seconds); a key is made from them per process
_DSA_PARAMS = (0xc77173fbd871e63c15cfa732ed7c95e5ef83a90fe7488cf10ef3839a90e7b3cf94ba1e69bb6c5f56de470fcdac33bede680c74709c605e18d126575d1bb86c4aca91766afac7f0fef450f77ba726711c4a46d298f4b5a7d42a89d4c6aa0c60debc875690988078079a1d6305221022c0a157053721c6997113bbb42d126b2d87,
               0xa17166dbd3fe324da6d64d2a523e567f0ebebecd,
               0x9a9fb0705965e106fc46b292187499eba971eab2ad714da07b9e2b6e0c13b4821782f7b01d85c6f8ecaa98fce89b33c2a9e19a9912ec873be651970c2c539af9931d0326b9a8693f7746668ffa34e99f70a5d20eb3a2430a2d53daa03eba09ca592553becf281a6ea7439e4aa13c95f0d575ae5ff9520583bf8bd24abd373250)

_FOREIGN = {}

# RFC 5656 3.1: the ECDSA user key formats; per curve: (curve class, hash, octets of r and s, bounds of r and s so that each encodes in that many octets)
_ECDSA = {"p256": (ec.SECP256R1, _hashes.SHA256, 248, 255, b"ecdsa-sha2-nistp256"),
          "p384": (ec.SECP384R1, _hashes.SHA384, 376, 383, b"ecdsa-sha2-nistp384"),
          "p521": (ec.SECP521R1, _hashes.SHA512, 520, 521, b"ecdsa-sha2-nistp521")}

def _foreign_key(kind):
    from cryptography.hazmat.primitives import serialization as ser
    if kind not in _FOREIGN:
        if kind.startswith("ecdsa_"):
            while True:
                key = ec.generate_private_key(_ECDSA[kind[6:]][0]())
                if _no_struct(key.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)):
                    break
        elif kind == "ed448":
            while True:
                key = ed448.Ed448PrivateKey.generate()
                if _no_struct(key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)):
                    break
        else:
            key = dsa.DSAParameterNumbers(*_DSA_PARAMS).parameters().generate_private_key()
        _FOREIGN[kind] = key
    return _FOREIGN[kind]

def _ecdsa_own_key():
    from cryptography.hazmat.primitives import serialization as ser
    if "ecdsa_own" not in _FOREIGN:
        with open(SSH_ECDSA_KEY_FILE, "rb") as f:
            _FOREIGN["ecdsa_own"] = ser.load_ssh_private_key(f.read(), password=None)
    return _FOREIGN["ecdsa_own"]

_Q_FORMAT = {}

def _ecdsa_point(key):
    """RFC 5656 3.1: Q as in SEC 1 2.3.3; point compression MAY be used, so some keys are sent with a compressed point (the server decodes it or refuses the key)."""
    from cryptography.hazmat.primitives import serialization as ser
    form = ser.PublicFormat.CompressedPoint if random.random() < 0.12 else ser.PublicFormat.UncompressedPoint
    return key.public_key().public_bytes(ser.Encoding.X962, form)

def gen_ecdsa_q(curve):
    return _ecdsa_point(_foreign_key("ecdsa_" + curve))

def gen_ecdsa_q_own():
    """The client's ecdsa-sha2-nistp256 user key, which the servers' authorized_keys list."""
    return _ecdsa_point(_ecdsa_own_key())

def gen_ed448_pub():
    from cryptography.hazmat.primitives import serialization as ser
    return _foreign_key("ed448").public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)

def gen_dss(part):
    nums = _foreign_key("dss").public_key().public_numbers()
    value = {"p": nums.parameter_numbers.p, "q": nums.parameter_numbers.q, "g": nums.parameter_numbers.g, "y": nums.y}[part]
    return mpint(value)[4:]

_SIG_CACHE = {}

def _foreign_signature(kind, signed, own=False):
    """ECDSA and DSA signatures are randomized, and a constraint is evaluated more than once: the first signature of a (key, data) pair is kept."""
    key = (kind, own, signed)
    if key not in _SIG_CACHE:
        if len(_SIG_CACHE) > 500:
            _SIG_CACHE.clear()
        _SIG_CACHE[key] = _foreign_signature_new(kind, signed, own)
    return _SIG_CACHE[key]

def _foreign_signature_new(kind, signed, own=False):
    """The signature blob of an ECDSA, DSA or Ed448 user key; its length is fixed (the rules carry it as a literal): the ECDSA values are drawn
    until r and s each encode in the same number of octets."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    if kind.startswith("ecdsa_"):
        _cls, h, lo, hi, alg = _ECDSA[kind[6:]]
        key = _ecdsa_own_key() if own else _foreign_key(kind)
        while True:
            r, s_ = decode_dss_signature(key.sign(signed, ec.ECDSA(h())))
            if 2 ** lo <= r < 2 ** hi and 2 ** lo <= s_ < 2 ** hi:
                return sstr(alg) + sstr(mpint(r) + mpint(s_))
    if kind == "dss":
        r, s_ = decode_dss_signature(_foreign_key("dss").sign(signed, _hashes.SHA1()))
        return sstr(b"ssh-dss") + sstr(r.to_bytes(20, "big") + s_.to_bytes(20, "big"))
    return sstr(b"ssh-ed448") + sstr(_foreign_key("ed448").sign(signed))

_OTHER_RSA = []

def _other_rsa_key():
    """A second RSA key that no server authorizes."""
    from cryptography.hazmat.primitives import serialization as ser
    if not _OTHER_RSA:
        with open(SSH_OTHER_RSA_KEY_FILE, "rb") as f:
            _OTHER_RSA.append(ser.load_pem_private_key(f.read(), password=None))
    return _OTHER_RSA[0]

def gen_rsa_e_other():
    return mpint(_other_rsa_key().public_key().public_numbers().e)[4:]

def gen_rsa_n_other():
    return mpint(_other_rsa_key().public_key().public_numbers().n)[4:]

def gen_pk_key_bad():
    return os.urandom(32)

def pk_sign(message):
    """The signature of RFC 4252 7: over the session identifier and the request up to the signature."""
    signed = sstr(SSH.session_id or b"") + b"".join(bytes(c) for c in message.children[1:-2])
    name = message.symbol.name().strip("<>")
    cnames = [c.symbol.name().strip("<>") for c in message.children if c.symbol.is_non_terminal]
    for cname in cnames:
        if cname.startswith("pk_signature_ecdsa_"):
            return _foreign_signature("ecdsa_" + cname.rsplit("_", 1)[1], signed, own="pk_blob_ecdsa_own" in cnames)
        if cname in ("pk_signature_dss", "pk_signature_ed448"):
            return _foreign_signature(cname.rsplit("_", 1)[1], signed)
    for cname in cnames:
        if cname in ("pk_signature_rsa256", "pk_signature_rsa512", "pk_signature_sshrsa"):
            alg, h = {"pk_signature_rsa256": (b"rsa-sha2-256", _hashes.SHA256), "pk_signature_rsa512": (b"rsa-sha2-512", _hashes.SHA512),
                      "pk_signature_sshrsa": (b"ssh-rsa", _hashes.SHA1)}[cname]
            key = _other_rsa_key() if "pk_blob_rsa_other" in cnames else _rsa_key()
            return sstr(alg) + sstr(key.sign(signed, _apad.PKCS1v15(), h()))
    key = _other_key() if name in ("c_auth_publickey_other_key", "c_auth_hostbased_other_host_key") else _client_key()
    return sstr(b"ssh-ed25519") + sstr(key.sign(signed))

def gen_hostname():
    return random.choice(["localhost.", "client.example.org", "localhost", "host" + str(random.randint(0, 9999)) + ".fan.example.", "client.example.org."]).encode()

def gen_submethods():
    return random.choice(["", "pam", "bsdauth,skey", "x-fan@example.com"]).encode()

def gen_response_count():
    try:
        r = Reader(SSH.last60, 1); r.string(); r.string(); r.string()
        return u32(r.u32())
    except Exception:
        return u32(1)

_RESP = {"src": None, "index": 0}

def gen_response():
    """RFC 4256 3.4: response[n] answers prompt[n]; the prompts are those of the last SSH_MSG_USERAUTH_INFO_REQUEST (recorded by
    SshSession); a prompt that asks for a password gets the password, every other prompt a fixed answer."""
    if _RESP["src"] is not SSH.last60:
        _RESP["src"], _RESP["index"] = SSH.last60, 0
    prompts = []
    try:
        r = Reader(SSH.last60, 1); r.string(); r.string(); r.string()
        for _ in range(r.u32()):
            prompts.append(r.string()); r.byte()
    except Exception:
        pass
    i = _RESP["index"]
    _RESP["index"] += 1
    if i < len(prompts) and b"assword" not in prompts[i]:
        return b"fan-answer"
    return SSH_PASSWORD.encode()

def gen_response_count_wrong():
    r = gen_response_count()
    return u32(u32v(r) + 1)

def gen_local_channel():
    return u32(random.choice([0, 1, 2, 7, 100]))

def gen_window():
    """The window of CHANNEL_OPEN, or of a WINDOW_ADJUST that keeps the client's own window within 2^32 - 1 (RFC 4254 5.2)."""
    choices = [w for w in (2097152, 65536, 1048576, 0, 1, 100, 0x7FFFFFFF, 0xFFFFFFFF) if SSH.local_window + w <= 0xFFFFFFFF]
    return u32(random.choice(choices or [0]))

def gen_maxpacket():
    return u32(random.choice([32768, 16384, 4096, 1024, 512, 0x100000]))

def gen_unknown_request():
    return random.choice(["nosuchrequest@example.com", "x-fan-test"]).encode()

def gen_bind_address():
    return random.choice(SSH_BIND_ADDRESSES).encode()

def gen_bind_port():
    return u32(random.choice([0, 20022, 22222]))

_CANCEL = {}

def gen_cancel_address():
    """RFC 4254 7.1: cancel-tcpip-forward names the address and port of an earlier tcpip-forward (for port 0 the port the server
    allocated); the pair is recorded here and recalled by gen_cancel_port."""
    if SSH.forwards and random.random() < 0.85:
        addr, port, _ = random.choice(SSH.forwards)
    else:
        addr, port = random.choice(SSH_BIND_ADDRESSES).encode(), random.choice([0, 20022, 22222])
    _CANCEL["port"] = port
    return addr

def gen_cancel_port():
    return u32(_CANCEL.get("port", 0))

def gen_unknown_channel_type():
    return random.choice(["nosuchtype", "x-fan@example.com"]).encode()

_FORWARD = {}

def gen_forward_host():
    """Draws one target host:port of the setup's list and records its port for gen_forward_port (the recording/recalling pair)."""
    host, _, port = random.choice(SSH_FORWARD_TARGETS).rpartition(":")
    _FORWARD["port"] = int(port)
    return host.encode()

def gen_forward_port():
    return u32(_FORWARD["port"])

def gen_originator_host():
    return random.choice(["127.0.0.1", "client.example.org"]).encode()

def gen_originator_port():
    return u32(random.choice([0, 40000, 65535]))

def gen_dimension():
    return u32(random.choice([0, 24, 80, 132, 480]))

def gen_term():
    return random.choice(["xterm", "vt100", "dumb"]).encode()

def gen_x11_proto():
    return b"MIT-MAGIC-COOKIE-1"

def gen_x11_cookie():
    return os.urandom(16).hex().encode()

def gen_env_name():
    return random.choice(SSH_ENV_NAMES).encode()

def gen_env_value():
    return random.choice(["C", "en_US.UTF-8", "xterm"]).encode()

def gen_subsystem():
    return random.choice(SSH_SUBSYSTEMS).encode()

def gen_signal():
    return random.choice(["ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE", "QUIT", "SEGV", "TERM", "USR1", "USR2"]).encode()

def gen_seq():
    return u32(random.randint(0, 5))

# --- PYTHON END

# ======================================================================================================
# Constraints shared by all messages (binary packet protocol, RFC 4253 section 6)
# ======================================================================================================
# packet_length = padding_length + payload + padding + 1 (RFC 4253 6)
where forall <l> in <packet_length>: <l> == packet_length_for(<l>.parent.parent)
# sent: the padding makes packet_length || padding_length || payload || padding a multiple of 16 (the block size of every
# cipher the client implements is 8 or 16), at least 4 bytes (RFC 4253 6)
where forall <h> in <c_pkt_head>: <h>.<padding_length> == padding_length_for(<h>.parent)
# received: at least 4 bytes of padding and a total that is a multiple of 8 (RFC 4253 6: "MUST be a multiple of the cipher
# block size or 8, whichever is larger", "MUST be at least four bytes of padding")
where forall <h> in <s_pkt_head>: padding_valid(<h>.parent)
# the unencrypted packet's integrity and the key exchange are checked by ClientNetworkParty (MAC, signature, exchange hash,
# value ranges): a failed check is an error of the packet it concerns (RFC 4253 6.4, 7.2, 8, RFC 4419 3, RFC 5656 4, RFC 8731 3)
where forall <h> in <s_pkt_head>: not SSH.errors
# string length = number of data octets that follow (RFC 4251 5)
where forall <l> in <string_len>: <l> == string_length_of(<l>.parent)

# --- PYTHON BEGIN: grammar helpers
def compat_ident_ok(node):
    lines = bytes(node).split(b"\n")[:-1]     # every line, empty ones included: nothing may precede the identification string
    return not (lines and lines[-1].startswith(b"SSH-1.99-") and len(lines) > 1)

def first_kex_follows_false(node):
    return bytes(node)[-5:-4] == b"\x00"

def name_list_valid(node):
    body = bytes(node)[4:]
    return body == b"" or all(0 < len(n) <= 64 and n.count(b"@") <= 1 for n in body.split(b","))

def guess_was_right():
    """RFC 4253 7: a guess is right when the client's first kex algorithm and first host key algorithm are the server's first ones."""
    def first(payload, k):
        r = Reader(payload, 17)
        for _ in range(k):
            r.string()
        names = _namelist(r.string())
        return names[0] if names else None
    try:
        return first(SSH.i_s, 0) is not None and first(SSH.i_c, 0) == first(SSH.i_s, 0) and first(SSH.i_c, 1) == first(SSH.i_s, 1)
    except Exception:
        return False

def ecmqv_reply_valid(k_s, q_s):
    """RFC 5656 5: every public key of the exchange is validated on the domain parameters of the host key: the host key's own point
    (K_S) and the server's ephemeral key (Q_S)."""
    curves = {b"nistp256": ec.SECP256R1, b"nistp384": ec.SECP384R1, b"nistp521": ec.SECP521R1}
    try:
        r = Reader(k_s)
        name, curve_id, q_k = r.string(), r.string(), r.string()
        curve = curves[curve_id]
        ec.EllipticCurvePublicKey.from_encoded_point(curve(), q_k)
        ec.EllipticCurvePublicKey.from_encoded_point(curve(), q_s)
        return name == b"ecdsa-sha2-" + curve_id
    except Exception:
        return False

def ecmqv_point_valid(q):
    for curve in (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1):
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(curve(), q)
            return True
        except Exception:
            pass
    return False

def name_list_names(node):
    return [n for n in bytes(node)[4:].decode("ascii", "replace").split(",") if n]

def pk_ok_echoes(message):
    fields = [bytes(c.children[1]) for c in message.children if c.symbol.is_non_terminal and c.symbol.name() == "<string>"]
    return tuple(fields[:2]) == SSH.last_pk

def pk_alg_enumerated(message):
    """RFC 8308 3.1: a server that sent server-sig-algs MUST enumerate all public key algorithms it might accept: the algorithm of a publickey request it
    answers with PK_OK, or accepts with SUCCESS (a signed request), has to be in the list."""
    return SSH.sig_algs is None or SSH.last_pk[0] in SSH.sig_algs

def pk_success_enumerated(message):
    return not SSH.last_pk_signed or pk_alg_enumerated(message)

def open_failure_code_ok(message):
    """RFC 4254 5.1: the reason code is 3 if the channel type is not understood."""
    if not SSH.open_unknown:
        return True
    return all(bytes(c) == u32(3) for c in message.children if c.symbol.is_non_terminal and c.symbol.name() == "<open_failure_reason>")

def string_length_of(node):
    return u32(sum(len(bytes(c)) for c in node.children[1:]))

def count_of(node):
    """The number a length or count field gives, as the count of a repetition: a packet holds at most 35000 octets (RFC 4253 6.1), so a field that says more
    is capped (a derivation never builds billions of items from a random 32-bit field)."""
    return min(u32v(node), 40000)

def payload_length(message):
    return sum(len(bytes(c)) for c in message.children[1:-1])

def packet_length_for(message):
    return u32(1 + payload_length(message) + bytes(message.children[0].children[1])[0])

def padding_valid(message):
    pad = bytes(message.children[0].children[1])[0]
    return pad >= 4 and (5 + payload_length(message) + pad) % 8 == 0

def minimal_padding(head):
    """The smallest padding (at least 4 octets) that makes the packet a multiple of 16."""
    p = 16 - ((5 + payload_length(head.parent)) % 16)
    return p + 16 if p < 4 else p

def extra_max(head):
    """The most free blocks of 16 octets the padding may hold: with the minimal part and the 8 octets of <c_pad_half> (when the cipher in use allows
    them) the padding stays within the 255 octets of RFC 4253 6."""
    return 15 if minimal_padding(head) + (8 if pad_half_allowed() else 0) <= 15 else 14

def padding_length_for(message):
    """Padding of a sent packet: the minimal padding that makes the packet a multiple of 16, at least 4 octets, plus the 8 octets of <c_pad_half> and
    the free blocks of 16 octets of <c_pad_extra> (RFC 4253 6: at most 255 octets in all)."""
    p = minimal_padding(message.children[0])
    extra = 0
    try:
        tail = message.children[-1]
        if tail.symbol.name() == "<c_pkt_tail>":
            padding = tail.children[0]
            extra = len(bytes(padding.children[0])) + len(bytes(padding.children[1]))
    except Exception:
        pass
    return bytes([p + extra])

def rest_count(node, extra):
    """Octets of the payload that follow the children of the message up to `node`, plus `extra` more octets."""
    msg = node.parent
    head = msg.children[0]
    upto = [i for i, c in enumerate(msg.children) if c is node]
    used = sum(len(bytes(c)) for c in msg.children[1:upto[0] + 1]) if upto else 0
    return max(0, min(40000, u32v(head.children[0]) - bytes(head.children[1])[0] - 1 - used - extra))
# --- PYTHON END

# RFC 4253 7.1: every algorithm name-list of a KEXINIT names at least one algorithm (the language lists may be empty)
where forall <k> in <kex_algorithms>: len(name_list_names(<k>)) >= 1
where forall <k> in <server_host_key_algorithms>: len(name_list_names(<k>)) >= 1
where forall <k> in <encryption_algorithms_client_to_server>: len(name_list_names(<k>)) >= 1
where forall <k> in <encryption_algorithms_server_to_client>: len(name_list_names(<k>)) >= 1
where forall <k> in <mac_algorithms_client_to_server>: len(name_list_names(<k>)) >= 1
where forall <k> in <mac_algorithms_server_to_client>: len(name_list_names(<k>)) >= 1
where forall <k> in <compression_algorithms_client_to_server>: len(name_list_names(<k>)) >= 1
where forall <k> in <compression_algorithms_server_to_client>: len(name_list_names(<k>)) >= 1
# RFC 4253 7.1: first_kex_packet_follows MUST be FALSE if no guessed packet will be sent; every key exchange method of this
# grammar starts with a client packet, so a server has no first kex packet to send
where forall <k> in <kexinit_payload>: first_kex_follows_false(<k>)
# RFC 4251 5, 6: a name is not empty and at most 64 characters long
where forall <n> in <name_list>: name_list_valid(<n>)
# RFC 8308 2.2: a server must not send the client's indicator
where forall <k> in <kex_algorithms>: "ext-info-c" not in name_list_names(<k>)
# RFC 4253 5.1: a server that identifies as protoversion 1.99 sends no lines before its identification string
where forall <i> in <s_ident>: compat_ident_ok(<i>)

# ======================================================================================================
# Session states. One nonterminal per state, one alternative per transition (RFC 4253 section 4 on).
# ======================================================================================================
<start> ::= <ident_state>

# a timer that starts before the request it guards may run out before the request is sent when the engine stalls (a pause of the driver of 2 s was seen): the expiry
# is accepted between the start and the request, and the cancel that ends the exchange afterwards is harmless
<kex_timer> ::= <TimerControl:t_kex_start> <TimerEvent:t_kex_expired>?
<kex_timer_t> ::= <TimerControl:t_kex_start_t> <TimerEvent:t_kex_expired_t>?
<late_timer> ::= <TimerControl:t_late_start> <TimerEvent:t_late_expired>?
<close_timer> ::= <TimerControl:t_close_start> <TimerEvent:t_close_expired>?
<service_timer> ::= <TimerControl:t_service_start> <TimerEvent:t_service_expired>?
<authsvc_timer> ::= <TimerControl:t_authsvc_start> <TimerEvent:t_authsvc_expired>?
<baduser_timer> ::= <TimerControl:t_baduser_start> <TimerEvent:t_baduser_expired>?

# RFC 4253 4.2: identification string exchange
<ident_state> ::= <Server:s_ident> <ident_kexinit_state>
# RFC 4253 11.2, 11.3: SSH_MSG_IGNORE and SSH_MSG_DEBUG may arrive at any time after the identification exchange; they are
# accepted before each message the client waits for
<ident_kexinit_state> ::= ((<Client:c_ident> <ident_wait_state>
                         | <transport_noise> (<Server:s_kexinit> <Client:c_ident> <kex_choice_state> | <disconnect_end>)))
# after the client's identification string, before the server's KEXINIT (the client's generic messages are allowed from here on, RFC 4253 11)
<ident_wait_state> ::= (<transport_noise> (<Server:s_kexinit> <kex_choice_state> | <disconnect_end>
                                          | <Client:c_ignore> <ident_wait_state> | <Client:c_debug> <ident_wait_state> | <Client:c_unimplemented> <ident_wait_state> | <Client:c_disconnect> <end_state>))
<transport_noise> ::= <server_transport>*

# RFC 4253 7.1: algorithm negotiation; the server's KEXINIT comes first, the client's KEXINIT picks the key exchange family
<kex_choice_state> ::= (<server_transport> <kex_choice_state>
                     | <Client:c_kexinit_ecdh> <ecdh_state>
                     | <Client:c_kexinit_dh> <dh_state>
                     | <Client:c_kexinit_gex> <gex_state>
                     | <Client:c_kexinit_ecdh_guess> <ecdh_guess_state>
                     | <Client:c_kexinit_ecdh_right> <ecdh_right_state>
                     | <Client:c_kexinit_ecdh_hostguess> <ecdh_guess_state>
                     | <disconnect_end>
                     | <kex_timer> <Client:c_kexinit_ecdh_unannounced> <ecdh_unannounced_state>
                     | <Client:c_kexinit_dh_guess> <dh_guess_state>
                     | <Client:c_kexinit_gex_guess> <gex_guess_state>
                     | <Client:c_kexinit_dh_right> <dh_right_state>
                     | <Client:c_kexinit_gex_right> <gex_right_state>
                     | <Client:c_kexinit_dh_hostguess> <dh_guess_state>
                     | <Client:c_kexinit_gex_hostguess> <gex_guess_state>
                     | <kex_timer> <Client:c_kexinit_any> <kex_failed_direct>
                     | <kex_timer> <Client:c_kexinit_nocommon> <kex_failed_direct>
                     | <kex_timer> <Client:c_kexinit_nokex> <kex_failed_direct>
                     | <kex_timer> <Client:c_kexinit_ecmqv> <ecmqv_state>
                     | <Client:c_ignore> <kex_choice_state>
                     | <Client:c_debug> <kex_choice_state>
                     | <Client:c_unimplemented> <kex_choice_state>
                     | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <kex_choice_state> | <disconnect_end>)
                     | <Client:c_disconnect> <end_state>)

# RFC 5656 4, RFC 8731 3 (curve25519-sha256, curve448-sha512): SSH_MSG_KEX_ECDH_INIT / SSH_MSG_KEX_ECDH_REPLY.
# RFC 4253 7.1: if the server does not support what the client's KEXINIT names, the connection fails; the server may disconnect
# or close the connection without a message, so the wait for the reply is limited by a timer.
<ecdh_state> ::= (<kex_timer> <Client:c_ecdh_init> <ecdh_reply_state>
               | <server_transport> <ecdh_state>
                     | <Client:c_ignore> <ecdh_state>
                     | <Client:c_debug> <ecdh_state>
                     | <Client:c_unimplemented> <ecdh_state>
                     | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <ecdh_state> | <disconnect_end>)
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<ecdh_reply_state> ::= <transport_noise> (<Server:s_ecdh_reply> <newkeys_state> | <kex_failed> | <Client:c_ignore> <ecdh_reply_state> | <Client:c_debug> <ecdh_reply_state> | <Client:c_unimplemented> <ecdh_reply_state>)

# RFC 4253 7: first_kex_packet_follows TRUE with a wrong guess (the client's first kex name is not the server's): the guessed
# packet is ignored by the server, then the client sends the packet of the method that was negotiated
<ecdh_guess_state> ::= (<Client:c_ecdh_init_guess> <kex_timer> <Client:c_ecdh_init> <ecdh_reply_state>
                     | <server_transport> <ecdh_guess_state>
                     | <Client:c_ignore> <ecdh_guess_state>
                     | <Client:c_debug> <ecdh_guess_state>
                     | <Client:c_unimplemented> <ecdh_guess_state>
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)

# RFC 4253 7: first_kex_packet_follows TRUE with a guess that is right when the server's first algorithms are the client's (the client's
# lists then start with them): the server uses the guessed packet and replies; otherwise it ignores it and the client sends its
# packet after the timer ran out
<ecdh_right_state> ::= (<kex_timer> <Client:c_ecdh_init_right> <ecdh_right_reply_state>
                     | <server_transport> <ecdh_right_state>
                     | <Client:c_ignore> <ecdh_right_state>
                     | <Client:c_debug> <ecdh_right_state>
                     | <Client:c_unimplemented> <ecdh_right_state>
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<ecdh_right_reply_state> ::= <transport_noise> (<Server:s_ecdh_reply> <newkeys_state> | <TimerEvent:t_kex_expired_guess> <ecdh_state> | <disconnect_end> | <Client:c_ignore> <ecdh_right_reply_state> | <Client:c_debug> <ecdh_right_reply_state> | <Client:c_unimplemented> <ecdh_right_reply_state>)

# an ECDH-family method that the server did not announce: it fails the negotiation, or it implements the method and waits for the client's packet
<ecdh_unannounced_state> ::= (<kex_failed> | <Client:c_ecdh_init_unannounced> <ecdh_reply_state> | <server_transport> <ecdh_unannounced_state>
                     | <Client:c_ignore> <ecdh_unannounced_state>
                     | <Client:c_debug> <ecdh_unannounced_state>
                     | <Client:c_unimplemented> <ecdh_unannounced_state>
                     | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <ecdh_unannounced_state> | <disconnect_end> | <TimerEvent:t_kex_expired> <kex_straggler>* <Server:s_disconnect>? <end_state>)
                     | <Client:c_disconnect> <end_state>)

# the same for the fixed-group and the group exchange methods
<dh_guess_state> ::= (<Client:c_dh_init_guess> <kex_timer> <Client:c_dh_init> <dh_reply_state>
                   | <server_transport> <dh_guess_state>
                     | <Client:c_ignore> <dh_guess_state>
                     | <Client:c_debug> <dh_guess_state>
                     | <Client:c_unimplemented> <dh_guess_state>
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<gex_guess_state> ::= (<Client:c_gex_request_guess> <gex_state>
                    | <server_transport> <gex_guess_state>
                     | <Client:c_ignore> <gex_guess_state>
                     | <Client:c_debug> <gex_guess_state>
                     | <Client:c_unimplemented> <gex_guess_state>
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)

# RFC 4253 8, RFC 8268: fixed-group Diffie-Hellman
<dh_state> ::= (<kex_timer> <Client:c_dh_init> <dh_reply_state>
             | <server_transport> <dh_state>
                     | <Client:c_ignore> <dh_state>
                     | <Client:c_debug> <dh_state>
                     | <Client:c_unimplemented> <dh_state>
                     | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <dh_state> | <disconnect_end>)
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<dh_reply_state> ::= <transport_noise> (<Server:s_dh_reply> <newkeys_state> | <kex_failed> | <Client:c_ignore> <dh_reply_state> | <Client:c_debug> <dh_reply_state> | <Client:c_unimplemented> <dh_reply_state>)

# RFC 4419: group exchange
<gex_state> ::= (<kex_timer> <Client:c_gex_request> <gex_group_state>
              | <kex_timer> <Client:c_gex_request_old> <gex_group_state>
              | <server_transport> <gex_state>
                     | <Client:c_ignore> <gex_state>
                     | <Client:c_debug> <gex_state>
                     | <Client:c_unimplemented> <gex_state>
                     | <kex_timer> <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <gex_state> | <disconnect_end> | <TimerEvent:t_kex_expired> <kex_straggler>* <Server:s_disconnect>? <end_state>)
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<gex_group_state> ::= <transport_noise> (<Server:s_gex_group> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <gex_init_state> | <kex_failed> | <Client:c_ignore> <gex_group_state> | <Client:c_debug> <gex_group_state> | <Client:c_unimplemented> <gex_group_state>)
<gex_init_state> ::= (<kex_timer> <Client:c_gex_init> <gex_reply_state>
                   | <server_transport> <gex_init_state>
                     | <Client:c_ignore> <gex_init_state>
                     | <Client:c_debug> <gex_init_state>
                     | <Client:c_unimplemented> <gex_init_state>
                     | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <gex_init_state> | <disconnect_end>)
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<gex_reply_state> ::= <transport_noise> (<Server:s_gex_reply> <newkeys_state> | <kex_failed> | <Client:c_ignore> <gex_reply_state> | <Client:c_debug> <gex_reply_state> | <Client:c_unimplemented> <gex_reply_state>)

# RFC 4253 7: the right guess for the fixed-group and the group exchange methods: the server uses the guessed packet when the client's first kex and host key
# names are its first ones (a method it does not know, or a first name the client did not offer, makes the guess wrong: the server ignores the packet and the
# client's own packet follows after the timer ran out)
<dh_right_state> ::= (<kex_timer> <Client:c_dh_init_right> <dh_right_reply_state>
                     | <server_transport> <dh_right_state>
                     | <Client:c_ignore> <dh_right_state>
                     | <Client:c_debug> <dh_right_state>
                     | <Client:c_unimplemented> <dh_right_state>
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<dh_right_reply_state> ::= <transport_noise> (<Server:s_dh_reply> <newkeys_state> | <TimerEvent:t_kex_expired_guess> <dh_state> | <disconnect_end> | <Client:c_ignore> <dh_right_reply_state> | <Client:c_debug> <dh_right_reply_state> | <Client:c_unimplemented> <dh_right_reply_state>)
<gex_right_state> ::= (<kex_timer> <Client:c_gex_request_right> <gex_right_reply_state>
                     | <server_transport> <gex_right_state>
                     | <Client:c_ignore> <gex_right_state>
                     | <Client:c_debug> <gex_right_state>
                     | <Client:c_unimplemented> <gex_right_state>
                     | <Client:c_disconnect> <end_state>
                     | <disconnect_end>)
<gex_right_reply_state> ::= <transport_noise> (<Server:s_gex_group> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <gex_init_state> | <TimerEvent:t_kex_expired_guess> <gex_state> | <disconnect_end> | <Client:c_ignore> <gex_right_reply_state> | <Client:c_debug> <gex_right_reply_state> | <Client:c_unimplemented> <gex_right_reply_state>)

# RFC 5656 5: ecmqv-sha2; a server that does not implement it fails the negotiation, one that does waits for SSH_MSG_ECMQV_INIT
<ecmqv_state> ::= (<kex_failed> | <Client:c_ecmqv_init> <ecmqv_reply_state> | <server_transport> <ecmqv_state>
                     | <Client:c_ignore> <ecmqv_state>
                     | <Client:c_debug> <ecmqv_state>
                     | <Client:c_unimplemented> <ecmqv_state>
                     | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <ecmqv_state> | <disconnect_end> | <TimerEvent:t_kex_expired> <kex_straggler>* <Server:s_disconnect>? <end_state>)
                     | <Client:c_disconnect> <end_state>)
<ecmqv_reply_state> ::= <transport_noise> (<Server:s_ecmqv_reply> <transport_noise> <Server:s_newkeys>? (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <Client:c_disconnect> <end_state> | <kex_failed> | <Client:c_ignore> <ecmqv_reply_state> | <Client:c_debug> <ecmqv_reply_state> | <Client:c_unimplemented> <ecmqv_reply_state>)
<kex_failed_direct> ::= <transport_noise> (<kex_failed> | <Client:c_ignore> <kex_failed_direct> | <Client:c_debug> <kex_failed_direct> | <Client:c_unimplemented> <kex_failed_direct>)
# RFC 4253 7.1: no algorithm in common; the connection fails (the server may stay silent or disconnect)
<kex_failed> ::= (<Server:s_disconnect> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <end_state>
               | <Server:s_unimplemented> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <kex_failed_after_unimplemented>
               | <TimerEvent:t_kex_expired> <kex_straggler>* <Server:s_disconnect>? <end_state>)
# the server's messages that arrive after the timer ran out or after an UNIMPLEMENTED (a slow server, or one that answers each of
# two optimistic packets)
<kex_straggler> ::= <Server:s_unimplemented> | <Server:s_kex_late> | <Server:s_newkeys> | <Server:s_ext_info> | <Server:s_kexinit_rekey> | <Server:s_gex_group> | <server_transport>
<kex_failed_after_unimplemented> ::= <kex_straggler>* (<Client:c_disconnect> | <Server:s_disconnect>) <end_state>

# RFC 4253 7.3: NEWKEYS; RFC 8308 2.3: the server's SSH_MSG_EXT_INFO follows its NEWKEYS when the client offered ext-info-c
<newkeys_state> ::= (<transport_noise> (<Server:s_newkeys> <Server:s_ext_info>? (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <Client:c_newkeys> <client_ext_info_state> | <kex_failed>
                                      | <Client:c_ignore> <newkeys_state> | <Client:c_debug> <newkeys_state> | <Client:c_unimplemented> <newkeys_state> | <Client:c_disconnect> <end_state>))
# RFC 8308 2.4: the client's SSH_MSG_EXT_INFO; a server that does not know it answers SSH_MSG_UNIMPLEMENTED (RFC 4253 11.4)
<client_ext_info_state> ::= (<Client:c_ext_info_none> | <Client:c_ext_info_many>) <Server:s_unimplemented>? <service_state> | <service_state>

# RFC 4253 10: service request
<service_state> ::= (<Client:c_service_request_userauth> <service_reply_state>
                  | <Client:c_unrecognized_early> <service_unrecognized_reply>
                  | <disconnect_end>
                  | <server_transport> <service_state>
                  | <rekey_term>
                  | <rekey_server> <service_state>
                  | <Client:c_ignore> <service_state>
                  | <Client:c_debug> <service_state>
                  | <Client:c_unimplemented> <service_state>
                  | <Client:c_disconnect> <end_state>
                  | <service_timer> <Client:c_service_request_unknown> <service_refused_state>
                  | <service_timer> <Client:c_service_request_connection> <service_connection_state>)
# RFC 4253 10: a rejected service request SHOULD be answered with SSH_MSG_DISCONNECT, and the server MUST disconnect
<service_unrecognized_reply> ::= <transport_noise> (<Server:s_unimplemented_for_unrecognized> <service_state> | <disconnect_end>)
# RFC 4253 10: ssh-connection is a reserved service name; before authentication a server accepts it or disconnects
<service_connection_state> ::= <transport_noise> (<Server:s_service_accept> (<TimerControl:t_service_cancel> | <TimerEvent:t_service_expired>) <Client:c_disconnect> <end_state> | <Server:s_disconnect> (<TimerControl:t_service_cancel> | <TimerEvent:t_service_expired>) <end_state>) | <TimerEvent:t_service_expired> (<Server:s_service_accept> | <Server:s_disconnect>)? <end_state>
<service_refused_state> ::= (<Server:s_disconnect> (<TimerControl:t_service_cancel> | <TimerEvent:t_service_expired>) <end_state> | <TimerEvent:t_service_expired> <Server:s_disconnect>? <end_state>
                     | <server_transport> <service_refused_state>)
<service_reply_state> ::= <transport_noise> (<Server:s_service_accept> <auth_state> | <disconnect_end>)

<disconnect_end> ::= <Server:s_disconnect> <end_state>
<end_state> ::= ""

# RFC 4252 5: authentication requests; each reply class selects the next state
# RFC 4252 5.4: the banner may be sent at any time before the authentication succeeds
<auth_state> ::= (<server_initiative> <auth_state>
               | <rekey_term>
               | <Server:s_userauth_banner> <auth_state>
               | <disconnect_end>
               | <Client:c_ignore> <auth_state>
               | <Client:c_debug> <auth_state>
               | <Client:c_unimplemented> <auth_state>
               | <Client:c_disconnect> <end_state>
               | <Client:c_unrecognized_early> <auth_unrecognized_reply>
               | <auth_request_core>
               | <auth_request_pw>
               | <Client:c_auth_publickey_signed> <auth_reply_any>
               | <Client:c_auth_publickey_signed_rsa256> <auth_reply_any>
               | <Client:c_auth_publickey_signed_rsa512> <auth_reply_any>
               | <Client:c_auth_publickey_signed_sshrsa> <auth_reply_any>
               | <Client:c_auth_publickey_signed_foreign> <auth_reply_any>
               | <Client:c_auth_publickey_signed_ecdsa> <auth_reply_any>)
# RFC 4252 5: the requests whose reply class does not depend on what came before: independent of one another, so every state that waits for the
# next request offers them (after a PK_OK and after a PASSWD_CHANGEREQ too)
<auth_request_core> ::= (<Client:c_auth_none> <auth_reply_none>
                     | <authsvc_timer> <Client:c_auth_unknown_service> <auth_reply_unknown_service>
                     | <Client:c_auth_password_bad> <auth_reply_password_refused>
                     | <baduser_timer> <Client:c_auth_bad_user> <auth_reply_bad_user>
                     | <Client:c_auth_unknown_method> <auth_reply_refused>
                     | <Client:c_auth_hostbased> <auth_reply_any>
                     | <Client:c_auth_hostbased_badsig> <auth_reply_refused>
                     | <Client:c_auth_hostbased_unknown_alg> <auth_reply_refused>
                     | <Client:c_auth_hostbased_other_host_key> <auth_reply_refused>
                     | <Client:c_auth_hostbased_foreign> <auth_reply_any>
                     | <Client:c_auth_publickey_unknown_alg> <auth_reply_refused>
                     | <Client:c_auth_publickey_query> <pk_query_reply>
                     | <Client:c_auth_publickey_query_rsa> <pk_query_reply_rsa>
                     | <Client:c_auth_publickey_query_ecdsa> <pk_query_reply_ecdsa>
                     | <Client:c_auth_publickey_query_rsa_other> <pk_bad_reply>
                     | <Client:c_auth_publickey_badsig> <auth_reply_refused>
                     | <Client:c_auth_publickey_badsig_ecdsa> <auth_reply_refused>
                     | <Client:c_auth_publickey_badsig_rsa> <auth_reply_refused>
                     | <Client:c_auth_publickey_other_key> <auth_reply_any>
                     | <Client:c_auth_publickey_other_key_rsa> <auth_reply_any>
                     | <Client:c_auth_publickey_bad> <pk_bad_reply>
                     | <Client:c_auth_publickey_query_foreign> <pk_bad_reply>
                     | <Client:c_auth_kbdint> <kbdint_reply>)
# the password requests: the reply to the plain one may be a CHANGEREQ (RFC 4252 8)
<auth_request_pw> ::= (<Client:c_auth_password_ok> <auth_reply_password>
                    | <Client:c_auth_password_change> <auth_reply_password>
                    | <Client:c_auth_password_change_bad> <auth_reply_password_refused>)
# RFC 4253 11.4: an unrecognized message is answered with SSH_MSG_UNIMPLEMENTED
<unrecognized_reply_passwd_changereq_state> ::= <auth_unsolicited> (<Server:s_unimplemented_for_unrecognized> <passwd_changereq_state> | <disconnect_end>)
<unrecognized_reply_pk_signed_state> ::= <auth_unsolicited> (<Server:s_unimplemented_for_unrecognized> <pk_signed_state> | <disconnect_end>)
<unrecognized_reply_pk_signed_state_ecdsa> ::= <auth_unsolicited> (<Server:s_unimplemented_for_unrecognized> <pk_signed_state_ecdsa> | <disconnect_end>)
<unrecognized_reply_pk_signed_state_rsa> ::= <auth_unsolicited> (<Server:s_unimplemented_for_unrecognized> <pk_signed_state_rsa> | <disconnect_end>)
<auth_unrecognized_reply> ::= <auth_unsolicited> (<Server:s_unimplemented_for_unrecognized> <auth_state> | <disconnect_end>)
# RFC 4252 5: a request that names a service the server does not offer is not accepted; the server may reply with a failure,
# disconnect, or stay silent (timer t_authsvc); the next request would change the service name, so the client ends the session
<auth_reply_unknown_service> ::= <auth_unsolicited> (<Server:s_userauth_failure_not_partial> (<TimerControl:t_authsvc_cancel> | <TimerEvent:t_authsvc_expired>) <Client:c_disconnect> <end_state> | <Server:s_disconnect> (<TimerControl:t_authsvc_cancel> | <TimerEvent:t_authsvc_expired>) <end_state>) | <TimerEvent:t_authsvc_expired> (<Server:s_userauth_failure_not_partial> | <Server:s_disconnect>)? <end_state>
# RFC 4252 5.1: a "none" request is never successful, so a failure to it does not announce partial success
<auth_reply_none> ::= <auth_unsolicited> (<auth_failed_refused> | <auth_succeeded> | <disconnect_end>)
<auth_reply_any> ::= <auth_unsolicited> (<auth_failed> | <auth_succeeded> | <disconnect_end>)
<auth_reply_password> ::= <auth_unsolicited> (<auth_failed> | <auth_succeeded> | <Server:s_userauth_passwd_changereq> <passwd_changereq_state> | <disconnect_end>)
# RFC 4252 8: after SSH_MSG_USERAUTH_PASSWD_CHANGEREQ the password is expired and the server MUST NOT accept it in a plain request
<passwd_changereq_state> ::= (<Client:c_auth_password_expired> <auth_reply_expired>
                           | <Client:c_auth_password_change> <auth_reply_password>
                           | <Client:c_auth_password_change_bad> <auth_reply_password_refused>
                           | <auth_request_core>
                           | <Client:c_auth_publickey_signed> <auth_reply_any>
                           | <Client:c_auth_publickey_signed_rsa256> <auth_reply_any>
                           | <Client:c_auth_publickey_signed_rsa512> <auth_reply_any>
                           | <Client:c_auth_publickey_signed_sshrsa> <auth_reply_any>
                           | <Client:c_auth_publickey_signed_foreign> <auth_reply_any>
                           | <Client:c_auth_publickey_signed_ecdsa> <auth_reply_any>
                           | <auth_idle> <passwd_changereq_state>
                    | <rekey_term>
                    | <rekey_server> <passwd_changereq_state>
                    | <Client:c_unrecognized_early> <unrecognized_reply_passwd_changereq_state>
                    | <Client:c_ignore> <passwd_changereq_state>
                    | <Client:c_debug> <passwd_changereq_state>
                    | <Client:c_unimplemented> <passwd_changereq_state>
                    | <Client:c_disconnect> <end_state>
                           | <disconnect_end>)
# RFC 4252 8: a plain request with the expired password is answered with FAILURE or another CHANGEREQ, never with SUCCESS
<auth_reply_expired> ::= <auth_unsolicited> (<auth_failed_refused> | <Server:s_userauth_passwd_changereq> <passwd_changereq_state> | <disconnect_end>)
# RFC 4252 8: every password request is answered with SUCCESS, FAILURE or CHANGEREQ (never with success for a wrong password)
<auth_reply_password_refused> ::= <auth_unsolicited> (<auth_failed_refused> | <Server:s_userauth_passwd_changereq> <passwd_changereq_state> | <disconnect_end>)
<auth_reply_refused> ::= <auth_unsolicited> (<auth_failed_refused> | <disconnect_end>)
<auth_failed_refused> ::= <Server:s_userauth_failure_not_partial> <auth_state>
# RFC 4252 5: a user name that does not exist is never accepted; the next request would change the user name (the server
# may flush its state or disconnect), so the client ends the session
<auth_reply_bad_user> ::= <auth_unsolicited> (<Server:s_userauth_failure_not_partial> (<TimerControl:t_baduser_cancel> | <TimerEvent:t_baduser_expired>) <Client:c_disconnect> <end_state> | <Server:s_userauth_passwd_changereq> (<TimerControl:t_baduser_cancel> | <TimerEvent:t_baduser_expired>) <passwd_changereq_state> | <Server:s_disconnect> (<TimerControl:t_baduser_cancel> | <TimerEvent:t_baduser_expired>) <end_state>) | <TimerEvent:t_baduser_expired> (<Server:s_userauth_failure_not_partial> | <Server:s_userauth_passwd_changereq> | <Server:s_disconnect>)? <end_state>
<auth_failed> ::= <Server:s_userauth_failure> <auth_state>
# RFC 8308 2.4: the server may send SSH_MSG_EXT_INFO immediately before SSH_MSG_USERAUTH_SUCCESS
# RFC 8308 3.2: the client's trigger message of delay-compression is SSH_MSG_NEWCOMPRESS, sent after USERAUTH_SUCCESS
<auth_succeeded> ::= <Server:s_ext_info>? <Server:s_userauth_success> <auth_success_state>
# RFC 8308 3.2: from USERAUTH_SUCCESS on, until the client's NEWCOMPRESS, the state is the protocol state that every state is: it accepts what the server sends on its
# own initiative (<server_initiative>: IGNORE, DEBUG, global requests, its re-exchange, which returns to this state) and its DISCONNECT; the client does not start a re-exchange
# here (RFC 8308 3.2.1: a party that signaled delay-compression MUST NOT before the trigger message has been sent)
<auth_success_state> ::= <server_initiative> <auth_success_state> | <disconnect_end> | <late_timer> <Client:c_newcompress_after_success> <late_newcompress_reply>
# RFC 4252 5.4 banner; SSH_MSG_DEBUG (RFC 4253 11.3), which a server may send at any time (OpenSSH reports the key options)
<auth_unsolicited> ::= (<Server:s_userauth_banner> | <server_transport>)*
# idle authentication states: the messages the server sends between two exchanges
<auth_idle> ::= <server_transport> | <Server:s_userauth_banner>

# RFC 4252 7: a query without signature is answered with SSH_MSG_USERAUTH_PK_OK, then the signed request follows
<pk_query_reply> ::= <auth_unsolicited> (<Server:s_userauth_pk_ok> <pk_signed_state> | <auth_failed> | <disconnect_end>)
# RFC 4252 7: the server MUST respond to a query with USERAUTH_FAILURE or USERAUTH_PK_OK; whether the key is authorized is not
# shown by the messages, so a key the setup does not authorize may get either
<pk_bad_reply> ::= <auth_unsolicited> (<auth_failed_refused> | <Server:s_userauth_pk_ok> <auth_state> | <disconnect_end>)
<pk_query_reply_rsa> ::= <auth_unsolicited> (<Server:s_userauth_pk_ok> <pk_signed_state_rsa> | <auth_failed> | <disconnect_end>)
<pk_query_reply_ecdsa> ::= <auth_unsolicited> (<Server:s_userauth_pk_ok> <pk_signed_state_ecdsa> | <auth_failed> | <disconnect_end>)
<pk_signed_state_ecdsa> ::= (<Client:c_auth_publickey_signed_after_query_ecdsa> <auth_reply_any>
                    | <auth_request_core>
                    | <auth_request_pw>
                    | <Client:c_auth_publickey_signed> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_rsa256> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_rsa512> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_sshrsa> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_foreign> <auth_reply_any>
                    | <auth_idle> <pk_signed_state_ecdsa>
                    | <rekey_term>
                    | <rekey_server> <pk_signed_state_ecdsa>
                    | <Client:c_unrecognized_early> <unrecognized_reply_pk_signed_state_ecdsa>
                    | <Client:c_ignore> <pk_signed_state_ecdsa>
                    | <Client:c_debug> <pk_signed_state_ecdsa>
                    | <Client:c_unimplemented> <pk_signed_state_ecdsa>
                    | <Client:c_disconnect> <end_state>
                    | <disconnect_end>)
<pk_signed_state_rsa> ::= (<Client:c_auth_publickey_signed_after_query_rsa256> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_after_query_rsa512> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_after_query_sshrsa> <auth_reply_any>
                    | <auth_request_core>
                    | <auth_request_pw>
                    | <Client:c_auth_publickey_signed> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_foreign> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_ecdsa> <auth_reply_any>
                    | <auth_idle> <pk_signed_state_rsa>
                    | <rekey_term>
                    | <rekey_server> <pk_signed_state_rsa>
                    | <Client:c_unrecognized_early> <unrecognized_reply_pk_signed_state_rsa>
                    | <Client:c_ignore> <pk_signed_state_rsa>
                    | <Client:c_debug> <pk_signed_state_rsa>
                    | <Client:c_unimplemented> <pk_signed_state_rsa>
                    | <Client:c_disconnect> <end_state>
                    | <disconnect_end>)
<pk_signed_state> ::= (<Client:c_auth_publickey_signed_after_query> <auth_reply_any>
                    | <auth_request_core>
                    | <auth_request_pw>
                    | <Client:c_auth_publickey_signed_rsa256> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_rsa512> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_sshrsa> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_foreign> <auth_reply_any>
                    | <Client:c_auth_publickey_signed_ecdsa> <auth_reply_any>
                    | <auth_idle> <pk_signed_state>
                    | <rekey_term>
                    | <rekey_server> <pk_signed_state>
                    | <Client:c_unrecognized_early> <unrecognized_reply_pk_signed_state>
                    | <Client:c_ignore> <pk_signed_state>
                    | <Client:c_debug> <pk_signed_state>
                    | <Client:c_unimplemented> <pk_signed_state>
                    | <Client:c_disconnect> <end_state>
                    | <disconnect_end>)

# RFC 4256 3: keyboard-interactive
<kbdint_reply> ::= <auth_unsolicited> (<Server:s_info_request_one> <kbdint_response_one_state> | <Server:s_info_request_many> <kbdint_response_many_state> | <Server:s_info_request_empty> <kbdint_empty_state> | <auth_failed> | <auth_succeeded> | <disconnect_end>)
<kbdint_response_one_state> ::= ((<Client:c_info_response_one_ok> <kbdint_reply>
                          | <Client:c_info_response_one_bad> <kbdint_reply_refused>
                          | <auth_idle> <kbdint_response_one_state>
                    | <Client:c_auth_none_after_info> <auth_reply_none>
                    | <rekey_term>
                    | <rekey_server> <kbdint_response_one_state>
                    | <Client:c_ignore> <kbdint_response_one_state>
                    | <Client:c_debug> <kbdint_response_one_state>
                    | <Client:c_unimplemented> <kbdint_response_one_state>
                    | <Client:c_disconnect> <end_state>
                          | <disconnect_end>))
<kbdint_response_many_state> ::= ((<Client:c_info_response_many_ok> <kbdint_reply>
                          | <Client:c_info_response_many_bad> <kbdint_reply_refused>
                          | <auth_idle> <kbdint_response_many_state>
                    | <Client:c_auth_none_after_info> <auth_reply_none>
                    | <rekey_term>
                    | <rekey_server> <kbdint_response_many_state>
                    | <Client:c_ignore> <kbdint_response_many_state>
                    | <Client:c_debug> <kbdint_response_many_state>
                    | <Client:c_unimplemented> <kbdint_response_many_state>
                    | <Client:c_disconnect> <end_state>
                          | <disconnect_end>))
<kbdint_reply_refused> ::= <auth_unsolicited> (<Server:s_info_request_one> <kbdint_response_one_state> | <Server:s_info_request_many> <kbdint_response_many_state> | <Server:s_info_request_empty> <kbdint_empty_state> | <auth_failed_refused> | <disconnect_end>)

# RFC 4256 3.4: a request without prompts is answered with an empty response
<kbdint_empty_state> ::= (<Client:c_info_response_empty> <kbdint_reply>
                       | <auth_idle> <kbdint_empty_state>
                    | <Client:c_auth_none_after_info> <auth_reply_none>
                    | <rekey_term>
                    | <rekey_server> <kbdint_empty_state>
                    | <Client:c_ignore> <kbdint_empty_state>
                    | <Client:c_debug> <kbdint_empty_state>
                    | <Client:c_unimplemented> <kbdint_empty_state>
                    | <Client:c_disconnect> <end_state>
                       | <disconnect_end>)

# RFC 4254 4: global requests
# the end of the connection in the channel phase: the server's DISCONNECT (RFC 4253 11.1) or the server closing the TCP connection without one.
# <s_closed> is no SSH message: ClientNetworkParty hands Fandango this token when it sees the close (outside a key re-exchange, after a CHANNEL_OPEN, without a DISCONNECT before).
# RFC 4253 11.1 does not require a DISCONNECT before the close, and no rule requires a reply to a channel request or a channel open (RFC 4254 4, 5.1, 5.4: "responds with").
<conn_end> ::= <disconnect_end> | <closed_end>
<closed_end> ::= <Server:s_closed> <end_state>
<connected_state> ::= (<Client:c_global_request_forward_want> <global_reply>
                    | <Client:c_global_request_forward_nowant> <connected_state>
                    | <Client:c_global_request_cancel_want> <global_reply>
                    | <Client:c_global_request_cancel_nowant> <connected_state>
                    | <Client:c_global_request_unknown_want> <global_reply_refused>
                    | <Client:c_global_request_unknown_nowant> <connected_state>
                    | <Client:c_channel_open_session> <open_session_reply>
                    | <Client:c_channel_open_direct_tcpip> <open_tcpip_reply>
                    | <Client:c_channel_open_unknown> <open_unknown_reply>
                    | <Client:c_channel_open_x11> <open_refused_reply>
                    | <Client:c_channel_open_forwarded_tcpip> <open_refused_reply>
                    | <Client:c_unrecognized> <unrecognized_reply>
                    | <late_timer> <Client:c_auth_late> <late_auth_reply>
                    | <Client:c_ignore> <connected_state>
                    | <server_initiative> <connected_state>
                    | <conn_end>
                    | <Client:c_debug> <connected_state>
                    | <Client:c_unimplemented> <connected_state>
                    | <rekey_client> <connected_state>
                    | <rekey_term>
                    | <Client:c_disconnect> <end_state>)
# RFC 4252 5.3: a USERAUTH_REQUEST after USERAUTH_SUCCESS SHOULD be silently ignored; a failure or UNIMPLEMENTED are the other replies
<late_auth_reply> ::= (<TimerEvent:t_late_expired> (<Server:s_userauth_failure> | <Server:s_unimplemented>)? <connected_state>
                    | <Server:s_userauth_failure> (<TimerControl:t_late_cancel> | <TimerEvent:t_late_expired>) <connected_state>
                    | <Server:s_unimplemented> (<TimerControl:t_late_cancel> | <TimerEvent:t_late_expired>) <connected_state>
                    | <Server:s_disconnect> (<TimerControl:t_late_cancel> | <TimerEvent:t_late_expired>) <end_state>
                    | <Server:s_closed> (<TimerControl:t_late_cancel> | <TimerEvent:t_late_expired>) <end_state>)
# RFC 8308 3.2: a server for which delay-compression is not in effect may answer SSH_MSG_NEWCOMPRESS with UNIMPLEMENTED (RFC 4253 11.4), ignore it or disconnect
<late_newcompress_reply> ::= (<Server:s_unimplemented_newcompress> (<TimerControl:t_late_cancel> | <TimerEvent:t_late_expired>) <connected_state>
                           | <TimerEvent:t_late_expired> <Server:s_unimplemented_newcompress>? <connected_state>
                           | <Server:s_disconnect> (<TimerControl:t_late_cancel> | <TimerEvent:t_late_expired>) <end_state>)
<global_reply> ::= <Server:s_request_success> <connected_state> | <Server:s_request_failure> <connected_state> | <conn_end>
<global_reply_refused> ::= <Server:s_request_failure> <connected_state> | <conn_end>

# RFC 4254 5.1: channel open
<open_session_reply> ::= <Server:s_channel_open_confirmation> <channel_state> | <Server:s_channel_open_failure> <connected_state> | <conn_end>
<open_tcpip_reply> ::= <Server:s_channel_open_confirmation_tcpip> <tcpip_channel_state> | <Server:s_channel_open_failure> <connected_state> | <conn_end>
<open_unknown_reply> ::= <Server:s_channel_open_failure_unknown_type> <connected_state> | <conn_end>
# RFC 4253 11.4: an unrecognized message is answered with SSH_MSG_UNIMPLEMENTED
<unrecognized_reply> ::= <Server:s_unimplemented_for_unrecognized> <connected_state> | <conn_end>
<open_refused_reply> ::= <Server:s_channel_open_failure> <connected_state> | <conn_end>

# RFC 4254 5, 6: an open session channel: requests with and without reply
<channel_state> ::= (<Client:c_channel_data> <channel_state>
                  | <Client:c_global_request_forward_nowant> <channel_state>
                  | <Client:c_global_request_cancel_nowant> <channel_state>
                  | <Client:c_global_request_unknown_nowant> <channel_state>
                  | <Server:s_unimplemented> <channel_state>
                  | <Server:s_channel_failure> <channel_state>
                  | <Server:s_channel_success> <channel_state>
                  | <Client:c_channel_extended_data> <channel_state>
                  | <Client:c_channel_window_adjust> <channel_state>
                  | <Client:c_channel_request_pty_req_nowant> <channel_pty_state>
                  | <Client:c_channel_request_env_nowant> <channel_state>
                  | <Client:c_channel_request_shell_nowant> <channel_running>
                  | <Client:c_channel_request_exec_nowant> <channel_running>
                  | <Client:c_channel_request_subsystem_nowant> <channel_running>
                  | <Client:c_channel_request_window_change_nowant> <channel_state>
                  | <Client:c_channel_request_signal_nowant> <channel_state>
                  | <Client:c_channel_request_x11_req_nowant> <channel_state>
                  | <Client:c_channel_request_unknown_nowant> <channel_state>
                  | <Client:c_channel_eof> <channel_eof_state>
                  | <close_timer> <Client:c_channel_close> <channel_closing_state>
                  | <open_second_cs>
                  | <Server:s_channel_window_adjust> <channel_state>
                  | <Server:s_channel_data> <channel_state>
                  | <Server:s_channel_extended_data> <channel_state>
                  | <Server:s_channel_request_other> <channel_state>
                  | <Server:s_channel_request_exit_status> <channel_state>
                  | <Server:s_channel_request_xon_xoff> <channel_state>
                  | <Server:s_channel_request_exit_signal> <channel_state>
                  | <Server:s_channel_request_other_want> <Client:c_channel_failure> <channel_state>
                  | <server_initiative> <channel_state>
                  | <Server:s_channel_eof> <channel_state>
                  | <Server:s_channel_close> <Client:c_channel_close> <connected_state>
                  | <conn_end>
                  | <rekey_client> <channel_state>
                  | <rekey_term>
                  | <Client:c_ignore> <channel_state>
                  | <Client:c_unrecognized> <unrecognized_reply_cs>
                  | <Client:c_debug> <channel_state>
                  | <Client:c_unimplemented> <channel_state>
                  | <Client:c_disconnect> <end_state>
                  | <Client:c_global_request_forward_want> <greply_cs>
                  | <Client:c_global_request_cancel_want> <greply_cs>
                  | <Client:c_global_request_unknown_want> <greply_refused_cs>
                  | <Client:c_channel_request_pty_req_want> <reply_pty_req>
                  | <Client:c_channel_request_env_want> <reply_env>
                  | <Client:c_channel_request_shell_want> <reply_shell>
                  | <Client:c_channel_request_exec_want> <reply_exec>
                  | <Client:c_channel_request_subsystem_want> <reply_subsystem>
                  | <Client:c_channel_request_x11_req_want> <reply_x11_req>
                  | <Client:c_channel_request_unknown_want> <reply_unknown>)
# a reply to a global request; the output of the channel may arrive before it
<greply_cs> ::= <running_output>* (<Server:s_request_success> <channel_state> | <Server:s_request_failure> <channel_state> | <conn_end>)
<greply_refused_cs> ::= <running_output>* (<Server:s_request_failure> <channel_state> | <conn_end>)
<greply_cr> ::= <running_output>* (<Server:s_request_success> <channel_running> | <Server:s_request_failure> <channel_running> | <conn_end>)
<greply_refused_cr> ::= <running_output>* (<Server:s_request_failure> <channel_running> | <conn_end>)
<greply_ct> ::= <running_output>* (<Server:s_request_success> <tcpip_channel_state> | <Server:s_request_failure> <tcpip_channel_state> | <conn_end>)
<greply_refused_ct> ::= <running_output>* (<Server:s_request_failure> <tcpip_channel_state> | <conn_end>)
# RFC 4254 4: a global request is independent of the channel; the server's remaining messages of the closing channel (and its CLOSE) may come before the reply
<closing_output> ::= <running_output> | <Server:s_channel_request_exit_status> | <Server:s_channel_request_xon_xoff> | <Server:s_channel_request_exit_signal> | <Server:s_channel_request_other>
<greply_cl> ::= <closing_output>* (<Server:s_request_success> <channel_closing_state> | <Server:s_request_failure> <channel_closing_state> | <Server:s_channel_close> (<TimerControl:t_close_cancel> | <TimerEvent:t_close_expired>) <global_reply> | <TimerEvent:t_close_expired> <closing_late>* <global_reply> | <conn_end>)
<greply_refused_cl> ::= <closing_output>* (<Server:s_request_failure> <channel_closing_state> | <Server:s_channel_close> (<TimerControl:t_close_cancel> | <TimerEvent:t_close_expired>) <global_reply_refused> | <TimerEvent:t_close_expired> <closing_late>* <global_reply_refused> | <conn_end>)
<reply_pty_req> ::= <chan_adjust> (<Server:s_channel_success> <channel_pty_state> | <Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<reply_env> ::= <chan_adjust> (<Server:s_channel_success> <channel_state> | <Server:s_channel_failure> <channel_state> | <conn_end>)
<reply_shell> ::= <chan_adjust> (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_state> | <conn_end>)
<reply_exec> ::= <chan_adjust> (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_state> | <conn_end>)
<reply_subsystem> ::= <chan_adjust> (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_state> | <conn_end>)
<reply_x11_req> ::= <chan_adjust> (<Server:s_channel_success> <channel_state> | <Server:s_channel_failure> <channel_state> | <conn_end>)
<reply_unknown> ::= <chan_adjust> (<Server:s_channel_failure> <channel_state> | <conn_end>)

# the command or shell runs: the server's output, exit status and close arrive in any order (RFC 4254 5.3, 6.10)
<channel_running> ::= (<Server:s_channel_data> <channel_running>
                    | <Server:s_channel_extended_data> <channel_running>
                    | <Server:s_channel_window_adjust> <channel_running>
                    | <Server:s_channel_eof> <channel_running>
                    | <Server:s_channel_request_exit_status> <channel_running>
                    | <Server:s_channel_request_xon_xoff> <channel_running>
                    | <Server:s_channel_request_exit_signal> <channel_running>
                    | <Server:s_channel_request_other> <channel_running>
                    | <Server:s_channel_close> <Client:c_channel_close> <connected_state>
                    | <conn_end>
                    | <Client:c_channel_data> <channel_running>
                    | <Client:c_global_request_forward_nowant> <channel_running>
                    | <Client:c_global_request_cancel_nowant> <channel_running>
                    | <Client:c_global_request_unknown_nowant> <channel_running>
                    | <Server:s_unimplemented> <channel_running>
                    | <Server:s_channel_failure> <channel_running>
                    | <Server:s_channel_success> <channel_running>
                    | <Client:c_channel_extended_data> <channel_running>
                    | <Client:c_channel_window_adjust> <channel_running>
                    | <Client:c_channel_request_window_change_nowant> <channel_running>
                    | <Client:c_channel_request_signal_nowant> <channel_running>
                    | <Server:s_channel_request_other_want> <Client:c_channel_failure> <channel_running>
                    | <server_initiative> <channel_running>
                    | <open_second_cr>
                    | <Client:c_channel_eof> <channel_eof_state>
                    | <close_timer> <Client:c_channel_close> <channel_closing_state>
                    | <rekey_client> <channel_running>
                    | <rekey_term>
                    | <Client:c_ignore> <channel_running>
                    | <Client:c_unrecognized> <unrecognized_reply_cr>
                    | <Client:c_debug> <channel_running>
                    | <Client:c_unimplemented> <channel_running>
                    | <Client:c_disconnect> <end_state>
                    | <Client:c_channel_request_env_nowant> <channel_running>
                    | <Client:c_channel_request_x11_req_nowant> <channel_running>
                    | <Client:c_channel_request_unknown_nowant> <channel_running>
                    | <Client:c_channel_request_shell_nowant> <channel_running>
                    | <Client:c_channel_request_exec_nowant> <channel_running>
                    | <Client:c_channel_request_subsystem_nowant> <channel_running>
                    | <Client:c_global_request_forward_want> <greply_cr>
                    | <Client:c_global_request_cancel_want> <greply_cr>
                    | <Client:c_global_request_unknown_want> <greply_refused_cr>
                    | <Client:c_channel_request_env_want> <reply_running>
                    | <Client:c_channel_request_x11_req_want> <reply_running>
                    | <Client:c_channel_request_pty_req_want> <reply_running>
                    | <Client:c_channel_request_pty_req_nowant> <channel_running>
                    | <Client:c_channel_request_unknown_want> <reply_running>
                    | <Client:c_channel_request_shell_want> <reply_running>
                    | <Client:c_channel_request_exec_want> <reply_running>
                    | <Client:c_channel_request_subsystem_want> <reply_running>)
# RFC 4254 5.3: the client has sent SSH_MSG_CHANNEL_EOF: it sends no more data on the channel (it may still send window adjusts, requests and
# CLOSE); the server's output, its own EOF and CLOSE go on as before
<channel_eof_state> ::= (<Server:s_channel_data> <channel_eof_state>
                    | <Server:s_channel_extended_data> <channel_eof_state>
                    | <Server:s_channel_window_adjust> <channel_eof_state>
                    | <Server:s_channel_eof> <channel_eof_state>
                    | <Server:s_channel_request_exit_status> <channel_eof_state>
                    | <Server:s_channel_request_xon_xoff> <channel_eof_state>
                    | <Server:s_channel_request_exit_signal> <channel_eof_state>
                    | <Server:s_channel_request_other> <channel_eof_state>
                    | <Server:s_channel_close> <Client:c_channel_close> <connected_state>
                    | <conn_end>
                    | <Client:c_global_request_forward_nowant> <channel_eof_state>
                    | <Client:c_global_request_cancel_nowant> <channel_eof_state>
                    | <Client:c_global_request_unknown_nowant> <channel_eof_state>
                    | <Server:s_unimplemented> <channel_eof_state>
                    | <Server:s_channel_failure> <channel_eof_state>
                    | <Server:s_channel_success> <channel_eof_state>
                    | <Client:c_channel_window_adjust> <channel_eof_state>
                    | <Client:c_channel_request_window_change_nowant> <channel_eof_state>
                    | <Client:c_channel_request_signal_nowant> <channel_eof_state>
                    | <Server:s_channel_request_other_want> <Client:c_channel_failure> <channel_eof_state>
                    | <server_initiative> <channel_eof_state>
                    | <open_second_ce>
                    | <close_timer> <Client:c_channel_close> <channel_closing_state>
                    | <rekey_client> <channel_eof_state>
                    | <rekey_term>
                    | <Client:c_ignore> <channel_eof_state>
                    | <Client:c_unrecognized> <unrecognized_reply_ce>
                    | <Client:c_debug> <channel_eof_state>
                    | <Client:c_unimplemented> <channel_eof_state>
                    | <Client:c_disconnect> <end_state>
                    | <Client:c_channel_request_env_nowant> <channel_eof_state>
                    | <Client:c_channel_request_x11_req_nowant> <channel_eof_state>
                    | <Client:c_channel_request_unknown_nowant> <channel_eof_state>
                    | <Client:c_channel_request_shell_nowant> <channel_eof_state>
                    | <Client:c_channel_request_exec_nowant> <channel_eof_state>
                    | <Client:c_channel_request_subsystem_nowant> <channel_eof_state>
                    | <Client:c_global_request_forward_want> <greply_ce>
                    | <Client:c_global_request_cancel_want> <greply_ce>
                    | <Client:c_global_request_unknown_want> <greply_refused_ce>
                    | <Client:c_channel_request_env_want> <reply_eof>
                    | <Client:c_channel_request_x11_req_want> <reply_eof>
                    | <Client:c_channel_request_pty_req_want> <reply_eof>
                    | <Client:c_channel_request_pty_req_nowant> <channel_eof_state>
                    | <Client:c_channel_request_unknown_want> <reply_eof>
                    | <Client:c_channel_request_shell_want> <reply_eof>
                    | <Client:c_channel_request_exec_want> <reply_eof>
                    | <Client:c_channel_request_subsystem_want> <reply_eof>)
<greply_ce> ::= <running_output>* (<Server:s_request_success> <channel_eof_state> | <Server:s_request_failure> <channel_eof_state> | <conn_end>)
<greply_refused_ce> ::= <running_output>* (<Server:s_request_failure> <channel_eof_state> | <conn_end>)
<reply_eof> ::= <running_output>* (<Server:s_channel_success> <channel_eof_state> | <Server:s_channel_failure> <channel_eof_state> | <conn_end>)
# RFC 4254 6.2: the state after a pty-req (RFC 4254 6.2 does not limit a session to one pty-req: a second one is sent here with want_reply TRUE and with FALSE)
<channel_pty_state> ::= (<open_second_cp>
                  | <Client:c_channel_data> <channel_pty_state>
                  | <Client:c_global_request_forward_nowant> <channel_pty_state>
                  | <Client:c_global_request_cancel_nowant> <channel_pty_state>
                  | <Client:c_global_request_unknown_nowant> <channel_pty_state>
                  | <Server:s_unimplemented> <channel_pty_state>
                  | <Server:s_channel_failure> <channel_pty_state>
                  | <Server:s_channel_success> <channel_pty_state>
                  | <Client:c_channel_extended_data> <channel_pty_state>
                  | <Client:c_channel_window_adjust> <channel_pty_state>
                  | <Client:c_channel_request_env_nowant> <channel_pty_state>
                  | <Client:c_channel_request_shell_nowant> <channel_running>
                  | <Client:c_channel_request_exec_nowant> <channel_running>
                  | <Client:c_channel_request_subsystem_nowant> <channel_running>
                  | <Client:c_channel_request_window_change_nowant> <channel_pty_state>
                  | <Client:c_channel_request_signal_nowant> <channel_pty_state>
                  | <Client:c_channel_request_x11_req_nowant> <channel_pty_state>
                  | <Client:c_channel_request_unknown_nowant> <channel_pty_state>
                  | <Client:c_channel_eof> <channel_eof_state>
                  | <close_timer> <Client:c_channel_close> <channel_closing_state>
                  | <Server:s_channel_window_adjust> <channel_pty_state>
                  | <Server:s_channel_data> <channel_pty_state>
                  | <Server:s_channel_extended_data> <channel_pty_state>
                  | <Server:s_channel_request_other> <channel_pty_state>
                  | <Server:s_channel_request_exit_status> <channel_pty_state>
                  | <Server:s_channel_request_xon_xoff> <channel_pty_state>
                  | <Server:s_channel_request_exit_signal> <channel_pty_state>
                  | <Server:s_channel_request_other_want> <Client:c_channel_failure> <channel_pty_state>
                  | <server_initiative> <channel_pty_state>
                  | <Server:s_channel_eof> <channel_pty_state>
                  | <Server:s_channel_close> <Client:c_channel_close> <connected_state>
                  | <conn_end>
                  | <rekey_client> <channel_pty_state>
                  | <rekey_term>
                  | <Client:c_ignore> <channel_pty_state>
                  | <Client:c_unrecognized> <unrecognized_reply_cs_p>
                  | <Client:c_debug> <channel_pty_state>
                  | <Client:c_unimplemented> <channel_pty_state>
                  | <Client:c_disconnect> <end_state>
                  | <Client:c_global_request_forward_want> <greply_cs_p>
                  | <Client:c_global_request_cancel_want> <greply_cs_p>
                  | <Client:c_global_request_unknown_want> <greply_refused_cs_p>
                  | <Client:c_channel_request_env_want> <reply_env_p>
                  | <Client:c_channel_request_shell_want> <reply_shell_p>
                  | <Client:c_channel_request_exec_want> <reply_exec_p>
                  | <Client:c_channel_request_subsystem_want> <reply_subsystem_p>
                  | <Client:c_channel_request_x11_req_want> <reply_x11_req_p>
                  | <Client:c_channel_request_pty_req_want> <reply_pty_req>
                  | <Client:c_channel_request_pty_req_nowant> <channel_pty_state>
                  | <Client:c_channel_request_unknown_want> <reply_unknown_p>)
<reply_env_p> ::= <chan_adjust> (<Server:s_channel_success> <channel_pty_state> | <Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<reply_shell_p> ::= <chan_adjust> (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<reply_exec_p> ::= <chan_adjust> (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<reply_subsystem_p> ::= <chan_adjust> (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<reply_x11_req_p> ::= <chan_adjust> (<Server:s_channel_success> <channel_pty_state> | <Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<reply_unknown_p> ::= <chan_adjust> (<Server:s_channel_failure> <channel_pty_state> | <conn_end>)
<greply_cs_p> ::= <running_output>* (<Server:s_request_success> <channel_pty_state> | <Server:s_request_failure> <channel_pty_state> | <conn_end>)
<greply_refused_cs_p> ::= <running_output>* (<Server:s_request_failure> <channel_pty_state> | <conn_end>)
<unrecognized_reply_cs_p> ::= <running_output>* (<Server:s_unimplemented_for_unrecognized> <channel_pty_state> | <conn_end>)
# the output of the running program may arrive before the reply to a request
<reply_running> ::= <running_output>* (<Server:s_channel_success> <channel_running> | <Server:s_channel_failure> <channel_running> | <conn_end>)
<running_output> ::= <Server:s_channel_data> | <Server:s_channel_extended_data> | <Server:s_channel_window_adjust> | <Server:s_channel_eof>
# our CLOSE is sent; the server's remaining messages and its CLOSE follow
<channel_closing_state> ::= (<Server:s_channel_data> <channel_closing_state>
                    | <Server:s_channel_extended_data> <channel_closing_state>
                    | <Server:s_channel_eof> <channel_closing_state>
                    | <Server:s_channel_window_adjust> <channel_closing_state>
                    | <Server:s_channel_request_exit_status> <channel_closing_state>
                    | <Server:s_channel_request_xon_xoff> <channel_closing_state>
                    | <Server:s_channel_request_exit_signal> <channel_closing_state>
                    | <Server:s_channel_request_other> <channel_closing_state>
                    | <Server:s_channel_request_other_want> <Client:c_channel_failure> <channel_closing_state>
                    | <server_initiative> <channel_closing_state>
                    | <open_second_cl>
                    | <Server:s_channel_success> <channel_closing_state>
                    | <Server:s_channel_failure> <channel_closing_state>
                    | <Server:s_channel_close> (<TimerControl:t_close_cancel> | <TimerEvent:t_close_expired>) <connected_state>
                    | <rekey_client> <channel_closing_state>
                    | <rekey_term>
                    | <Client:c_unrecognized> <unrecognized_reply_cl>
                    | <Client:c_ignore> <channel_closing_state>
                    | <Client:c_debug> <channel_closing_state>
                    | <Client:c_unimplemented> <channel_closing_state>
                    | <Client:c_disconnect> <end_state>
                    | <Client:c_global_request_forward_nowant> <channel_closing_state>
                    | <Client:c_global_request_cancel_nowant> <channel_closing_state>
                    | <Client:c_global_request_unknown_nowant> <channel_closing_state>
                    | <Client:c_global_request_forward_want> <greply_cl>
                    | <Client:c_global_request_cancel_want> <greply_cl>
                    | <Client:c_global_request_unknown_want> <greply_refused_cl>
                    | <TimerEvent:t_close_expired> <closing_late>* <connected_state>
                    | <conn_end>)

# RFC 4254 7.2: a direct-tcpip channel carries data only
<tcpip_channel_state> ::= (<Client:c_channel_data> <tcpip_channel_state>
                    | <Client:c_global_request_forward_nowant> <tcpip_channel_state>
                    | <Client:c_global_request_cancel_nowant> <tcpip_channel_state>
                    | <Client:c_global_request_unknown_nowant> <tcpip_channel_state>
                    | <Server:s_unimplemented> <tcpip_channel_state>
                    | <Server:s_channel_failure> <tcpip_channel_state>
                    | <Server:s_channel_success> <tcpip_channel_state>
                    | <Client:c_channel_extended_data> <tcpip_channel_state>
                    | <Server:s_channel_extended_data> <tcpip_channel_state>
                    | <Client:c_channel_window_adjust> <tcpip_channel_state>
                    | <Server:s_channel_window_adjust> <tcpip_channel_state>
                    | <Server:s_channel_request_other> <tcpip_channel_state>
                    | <Server:s_channel_request_xon_xoff> <tcpip_channel_state>
                    | <server_initiative> <tcpip_channel_state>
                    | <open_second_ct>
                    | <Client:c_channel_eof> <channel_eof_state>
                    | <close_timer> <Client:c_channel_close> <channel_closing_state>
                    | <Server:s_channel_data> <tcpip_channel_state>
                    | <Server:s_channel_eof> <tcpip_channel_state>
                    | <Server:s_channel_close> <Client:c_channel_close> <connected_state>
                    | <conn_end>
                    | <rekey_client> <tcpip_channel_state>
                    | <rekey_term>
                    | <Client:c_ignore> <tcpip_channel_state>
                    | <Client:c_unrecognized> <unrecognized_reply_ct>
                    | <Client:c_debug> <tcpip_channel_state>
                    | <Client:c_unimplemented> <tcpip_channel_state>
                    | <Client:c_disconnect> <end_state>
                    | <Client:c_channel_request_unknown_nowant> <tcpip_channel_state>
                    | <Server:s_channel_request_other_want> <Client:c_channel_failure> <tcpip_channel_state>
                    | <Client:c_global_request_forward_want> <greply_ct>
                    | <Client:c_global_request_cancel_want> <greply_ct>
                    | <Client:c_global_request_unknown_want> <greply_refused_ct>
                    | <Client:c_channel_request_unknown_want> <reply_tcpip_request>)
# RFC 4254 5.4: a request the recipient does not recognize is answered with SSH_MSG_CHANNEL_FAILURE
<reply_tcpip_request> ::= (<Server:s_channel_data> | <Server:s_channel_window_adjust> | <Server:s_channel_eof>)* (<Server:s_channel_failure> <tcpip_channel_state> | <conn_end>)

# the server's last messages of a closing channel that arrive after the timer ran out
<closing_late> ::= <Server:s_channel_data> | <Server:s_channel_extended_data> | <Server:s_channel_eof> | <Server:s_channel_window_adjust> | <Server:s_channel_request_exit_status> | <Server:s_channel_request_exit_signal> | <Server:s_channel_request_xon_xoff> | <Server:s_channel_request_other> | <Server:s_channel_request_other_want> <Client:c_channel_failure> | <Server:s_channel_close>
# RFC 4253 11.4: an unrecognized message is answered with SSH_MSG_UNIMPLEMENTED; the channel's output may arrive before it
<unrecognized_reply_cs> ::= <running_output>* (<Server:s_unimplemented_for_unrecognized> <channel_state> | <conn_end>)
# RFC 4253 11.4: an unrecognized message is answered with SSH_MSG_UNIMPLEMENTED; the channel's output may arrive before it
<unrecognized_reply_cr> ::= <running_output>* (<Server:s_unimplemented_for_unrecognized> <channel_running> | <conn_end>)
# RFC 4253 11.4: an unrecognized message is answered with SSH_MSG_UNIMPLEMENTED; the channel's output may arrive before it
<unrecognized_reply_ct> ::= <running_output>* (<Server:s_unimplemented_for_unrecognized> <tcpip_channel_state> | <conn_end>)
# RFC 4253 11.4: an unrecognized message is answered with SSH_MSG_UNIMPLEMENTED; the channel's output may arrive before it
<unrecognized_reply_ce> ::= <running_output>* (<Server:s_unimplemented_for_unrecognized> <channel_eof_state> | <conn_end>)
<unrecognized_reply_cl> ::= <running_output>* (<Server:s_unimplemented_for_unrecognized> <channel_closing_state> | <conn_end>)
<chan_adjust> ::= <Server:s_channel_window_adjust>*


# messages the server sends on its own initiative between two exchanges, with the reply each requires (RFC 4253 11.2, 11.3;
# RFC 4254 4)
<server_transport> ::= <Server:s_ignore> | <Server:s_debug>
<server_initiative> ::= <server_transport> | <Server:s_global_request_nowant> | <Server:s_global_request_want> <Client:c_request_failure> | <rekey_server>


# RFC 4253 9: key re-exchange, started by either party in any state after the first key exchange, with any negotiated method (ECDH, fixed-group DH,
# group exchange: RFC 4419 is processed like the first exchange). The session identifier stays and the new keys take effect with NEWKEYS.
# RFC 4253 7.1: until NEWKEYS only transport messages are sent, but the other party may still have channel messages in flight before it has seen
# the KEXINIT. The exchange is self-contained: every state that allows it is followed by it and continues in the state it was started in
# (<rekey_client> <state>); the server's UNIMPLEMENTED answer to a packet it does not know leaves the exchange and continues there too.
# An exchange whose failure ends the connection (a server that stays silent, the client's DISCONNECT) is <rekey_term>: the same chain of messages under timer 8,
# which ends in <end_state> after every failure and after the completed exchange.
# the timer of the exchange may run out before the client's KEXINIT has been generated (a stall of the engine): the KEXINIT follows, and the cancel that ends the exchange is harmless
<rekey_client> ::= <TimerControl:t_kex_start> <rekey_noise>* (<TimerEvent:t_kex_expired> <rekey_noise>*)? <rekey_client_kexinit>
<rekey_client_kexinit> ::= (<Client:c_kexinit_ecdh_rekey> <rekey_kexinit_state>
                         | <Client:c_kexinit_dh_rekey> <rekey_kexinit_dh_state>
                         | <Client:c_kexinit_gex_rekey> <rekey_kexinit_gex_state>)
# the server's output may arrive between the timer's start and the client's KEXINIT (the channels are open)
<rekey_noise> ::= <running_output> | <server_transport>
<rekey_server> ::= <Server:s_kexinit_rekey> <rekey_answer_state>
<rekey_answer_state> ::= (<rekey_answer_kexinit>
                       | <server_transport> <rekey_answer_state>
                       | <Client:c_ignore> <rekey_answer_state> | <Client:c_debug> <rekey_answer_state> | <Client:c_unimplemented> <rekey_answer_state>
                       | <Client:c_unrecognized_kex_c> <transport_noise> <Server:s_unimplemented_for_unrecognized> <rekey_answer_state>)
<rekey_answer_kexinit> ::= (<Client:c_kexinit_ecdh_rekey_after_server> <rekey_ecdh_state>
                         | <Client:c_kexinit_dh_rekey_after_server> <rekey_dh_state>
                         | <Client:c_kexinit_gex_rekey_after_server> <rekey_gex_state>)
# RFC 4253 7.1: what the other party may have sent before it saw the client's KEXINIT: transport messages and channel messages
<rekey_inflight> ::= <server_transport> | <Server:s_global_request_nowant> | <Server:s_channel_data> | <Server:s_channel_extended_data> | <Server:s_channel_window_adjust> | <Server:s_channel_eof> | <Server:s_channel_close> | <Server:s_channel_success> | <Server:s_channel_failure> | <Server:s_channel_request_other> | <Server:s_channel_request_exit_status> | <Server:s_channel_request_exit_signal> | <Server:s_channel_request_xon_xoff>
<rekey_kexinit_done> ::= (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>)
# the server answers a packet it does not know with UNIMPLEMENTED (RFC 4253 11.4); its DISCONNECT, which ends the connection (RFC 4253 11.1), and its
# silence are alternatives of the chains that end in <end_state> (<rekey_term>): this form continues in the state it started in
<rekey_failed> ::= <Server:s_unimplemented> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>)

<rekey_kexinit_state> ::= <rekey_inflight> <rekey_kexinit_state> | <Server:s_kexinit_rekey> <rekey_kexinit_done> <rekey_ecdh_state> | <TimerEvent:t_kex_expired> <rekey_kexinit_state> | <Client:c_ignore> <rekey_kexinit_state> | <Client:c_debug> <rekey_kexinit_state> | <Client:c_unimplemented> <rekey_kexinit_state>
# the client's packet: the timer starts before it, so the client's generic messages (which take time to generate) come before the timer
<rekey_ecdh_state> ::= <kex_timer> <Client:c_ecdh_init_rekey> <rekey_ecdh_reply_state> | <server_transport> <rekey_ecdh_state> | <Client:c_ignore> <rekey_ecdh_state> | <Client:c_debug> <rekey_ecdh_state> | <Client:c_unimplemented> <rekey_ecdh_state> | <Client:c_unrecognized_kex_c> <transport_noise> <Server:s_unimplemented_for_unrecognized> <rekey_ecdh_state>
<rekey_ecdh_reply_state> ::= <transport_noise> (<Server:s_ecdh_reply_rekey> <rekey_newkeys> | <rekey_failed> | <TimerEvent:t_kex_expired> <rekey_ecdh_reply_state> | <Client:c_ignore> <rekey_ecdh_reply_state> | <Client:c_debug> <rekey_ecdh_reply_state> | <Client:c_unimplemented> <rekey_ecdh_reply_state>)
<rekey_kexinit_dh_state> ::= <rekey_inflight> <rekey_kexinit_dh_state> | <Server:s_kexinit_rekey> <rekey_kexinit_done> <rekey_dh_state> | <TimerEvent:t_kex_expired> <rekey_kexinit_dh_state> | <Client:c_ignore> <rekey_kexinit_dh_state> | <Client:c_debug> <rekey_kexinit_dh_state> | <Client:c_unimplemented> <rekey_kexinit_dh_state>
# the client's packet: the timer starts before it, so the client's generic messages (which take time to generate) come before the timer
<rekey_dh_state> ::= <kex_timer> <Client:c_dh_init_rekey> <rekey_dh_reply_state> | <server_transport> <rekey_dh_state> | <Client:c_ignore> <rekey_dh_state> | <Client:c_debug> <rekey_dh_state> | <Client:c_unimplemented> <rekey_dh_state> | <Client:c_unrecognized_kex_c> <transport_noise> <Server:s_unimplemented_for_unrecognized> <rekey_dh_state>
<rekey_dh_reply_state> ::= <transport_noise> (<Server:s_dh_reply_rekey> <rekey_newkeys> | <rekey_failed> | <TimerEvent:t_kex_expired> <rekey_dh_reply_state> | <Client:c_ignore> <rekey_dh_reply_state> | <Client:c_debug> <rekey_dh_reply_state> | <Client:c_unimplemented> <rekey_dh_reply_state>)
<rekey_kexinit_gex_state> ::= <rekey_inflight> <rekey_kexinit_gex_state> | <Server:s_kexinit_rekey> <rekey_kexinit_done> <rekey_gex_state> | <TimerEvent:t_kex_expired> <rekey_kexinit_gex_state> | <Client:c_ignore> <rekey_kexinit_gex_state> | <Client:c_debug> <rekey_kexinit_gex_state> | <Client:c_unimplemented> <rekey_kexinit_gex_state>
# group exchange (RFC 4419) in the continuing form: the request (or the old request) starts timer 1, the server's group ends it, the client's init and the reply follow
<rekey_gex_state> ::= <kex_timer> (<Client:c_gex_request_rekey> | <Client:c_gex_request_old_rekey>) <rekey_gex_group_state> | <server_transport> <rekey_gex_state> | <Client:c_ignore> <rekey_gex_state> | <Client:c_debug> <rekey_gex_state> | <Client:c_unimplemented> <rekey_gex_state> | <Client:c_unrecognized_kex_c> <transport_noise> <Server:s_unimplemented_for_unrecognized> <rekey_gex_state>
<rekey_gex_group_state> ::= <transport_noise> (<Server:s_gex_group_rekey> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <rekey_gex_init_state> | <rekey_failed> | <TimerEvent:t_kex_expired> <rekey_gex_group_state> | <Client:c_ignore> <rekey_gex_group_state> | <Client:c_debug> <rekey_gex_group_state> | <Client:c_unimplemented> <rekey_gex_group_state>)
<rekey_gex_init_state> ::= <kex_timer> <Client:c_gex_init_rekey> <rekey_gex_reply_state> | <server_transport> <rekey_gex_init_state> | <Client:c_ignore> <rekey_gex_init_state> | <Client:c_debug> <rekey_gex_init_state> | <Client:c_unimplemented> <rekey_gex_init_state> | <Client:c_unrecognized_kex_c> <transport_noise> <Server:s_unimplemented_for_unrecognized> <rekey_gex_init_state>
<rekey_gex_reply_state> ::= <transport_noise> (<Server:s_gex_reply_rekey> <rekey_newkeys> | <rekey_failed> | <TimerEvent:t_kex_expired> <rekey_gex_reply_state> | <Client:c_ignore> <rekey_gex_reply_state> | <Client:c_debug> <rekey_gex_reply_state> | <Client:c_unimplemented> <rekey_gex_reply_state>)
<rekey_newkeys> ::= <transport_noise> (<Server:s_newkeys_rekey> (<TimerControl:t_kex_cancel> | <TimerEvent:t_kex_expired>) <Client:c_newkeys_rekey> | <rekey_failed> | <Client:c_ignore> <rekey_newkeys> | <Client:c_debug> <rekey_newkeys> | <Client:c_unimplemented> <rekey_newkeys>)

# the chain that ends the session: every failure ends the connection here (a server that does not know the method or the point form stays silent or
# disconnects; RFC 4253 7.1) and the client may disconnect at any point (RFC 4253 11.1); the completed exchange ends the chain as well. Its timer is timer 8
# server-started: the server's KEXINIT is the only message the two forms share; the terminal form goes on with the timer-8 start (or a DISCONNECT), which the continuing
# form (<rekey_server> <rekey_answer_state>) never sends there, so the forms differ at their second message and no loop lies in a shared prefix
<rekey_term> ::= (<TimerControl:t_kex_start_t> <rekey_noise>* (<TimerEvent:t_kex_expired_t> <rekey_noise>*)? (<Client:c_kexinit_ecdh_rekey> <rekey_t_ki_ecdh> | <Client:c_kexinit_dh_rekey> <rekey_t_ki_dh> | <Client:c_kexinit_gex_rekey> <rekey_t_ki_gex>)
              | <Server:s_kexinit_rekey> <server_transport>? (<Client:c_ignore> | <Client:c_debug>)? (<TimerControl:t_kex_start_t> <rekey_t_pre> | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>))
# the failure of the exchange: the server's DISCONNECT, its UNIMPLEMENTED, or silence under the timer
<rekey_t_fail> ::= <Server:s_disconnect> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) <end_state> | <Server:s_unimplemented> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) <end_state> | <TimerEvent:t_kex_expired_t> <kex_straggler>* <Server:s_disconnect>? <end_state>
<rekey_t_newkeys> ::= <transport_noise> (<Server:s_newkeys_rekey> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) (<Client:c_newkeys_rekey> <rekey_t_end> | <Client:c_disconnect> <end_state>) | <rekey_t_fail> | <Client:c_ignore> <rekey_t_newkeys> | <Client:c_debug> <rekey_t_newkeys> | <Client:c_unimplemented> <rekey_t_newkeys>)

# the server-started terminal chain: timer 8 starts after the server's KEXINIT; until the client's KEXINIT the generic messages of both parties are accepted (RFC 4253 7.1, 11)
<rekey_t_pre> ::= <Client:c_kexinit_ecdh_rekey_after_server> <rekey_t_sa_ecdh> | <Client:c_kexinit_dh_rekey_after_server> <rekey_t_sa_dh> | <Client:c_kexinit_gex_rekey_after_server> <rekey_t_sa_gex> | <TimerEvent:t_kex_expired_t> <rekey_t_pre> | <server_transport> <rekey_t_pre> | <Client:c_ignore> <rekey_t_pre> | <Client:c_debug> <rekey_t_pre> | <Client:c_unimplemented> <rekey_t_pre> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_pre> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_sa_ecdh> ::= <kex_timer_t> <Client:c_ecdh_init> <rekey_t_reply_ecdh> | <server_transport> <rekey_t_sa_ecdh> | <Client:c_ignore> <rekey_t_sa_ecdh> | <Client:c_debug> <rekey_t_sa_ecdh> | <Client:c_unimplemented> <rekey_t_sa_ecdh> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_sa_ecdh> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_sa_gex> ::= <kex_timer_t> (<Client:c_gex_request_rekey> | <Client:c_gex_request_old_rekey>) <rekey_t_group_gex> | <server_transport> <rekey_t_sa_gex> | <Client:c_ignore> <rekey_t_sa_gex> | <Client:c_debug> <rekey_t_sa_gex> | <Client:c_unimplemented> <rekey_t_sa_gex> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_sa_gex> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_sa_dh> ::= <kex_timer_t> <Client:c_dh_init_rekey> <rekey_t_reply_dh> | <server_transport> <rekey_t_sa_dh> | <Client:c_ignore> <rekey_t_sa_dh> | <Client:c_debug> <rekey_t_sa_dh> | <Client:c_unimplemented> <rekey_t_sa_dh> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_sa_dh> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_ki_ecdh> ::= <rekey_inflight> <rekey_t_ki_ecdh> | <Server:s_kexinit_rekey> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) <rekey_t_init_ecdh> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_ki_ecdh> | <Client:c_debug> <rekey_t_ki_ecdh> | <Client:c_unimplemented> <rekey_t_ki_ecdh>
<rekey_t_init_ecdh> ::= <kex_timer_t> <Client:c_ecdh_init> <rekey_t_reply_ecdh> | <server_transport> <rekey_t_init_ecdh> | <Client:c_ignore> <rekey_t_init_ecdh> | <Client:c_debug> <rekey_t_init_ecdh> | <Client:c_unimplemented> <rekey_t_init_ecdh> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_init_ecdh> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_reply_ecdh> ::= <transport_noise> (<Server:s_ecdh_reply_rekey> <rekey_t_newkeys> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_reply_ecdh> | <Client:c_debug> <rekey_t_reply_ecdh> | <Client:c_unimplemented> <rekey_t_reply_ecdh>)
<rekey_t_ki_dh> ::= <rekey_inflight> <rekey_t_ki_dh> | <Server:s_kexinit_rekey> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) <rekey_t_init_dh> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_ki_dh> | <Client:c_debug> <rekey_t_ki_dh> | <Client:c_unimplemented> <rekey_t_ki_dh>
<rekey_t_init_dh> ::= <kex_timer_t> <Client:c_dh_init_rekey> <rekey_t_reply_dh> | <server_transport> <rekey_t_init_dh> | <Client:c_ignore> <rekey_t_init_dh> | <Client:c_debug> <rekey_t_init_dh> | <Client:c_unimplemented> <rekey_t_init_dh> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_init_dh> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_reply_dh> ::= <transport_noise> (<Server:s_dh_reply_rekey> <rekey_t_newkeys> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_reply_dh> | <Client:c_debug> <rekey_t_reply_dh> | <Client:c_unimplemented> <rekey_t_reply_dh>)
# the terminal chain uses the new keys once (RFC 4253 7.2: keys A-F, session id unchanged): an unrecognized message must be answered with UNIMPLEMENTED under them
<rekey_t_end> ::= <rekey_t_bye> | <server_transport> <rekey_t_end> | <Client:c_ignore> <rekey_t_end> | <Client:c_debug> <rekey_t_end> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_end> | <disconnect_end>)
<rekey_t_bye> ::= <Client:c_disconnect> <end_state> | <end_state>
<rekey_t_ki_gex> ::= <rekey_inflight> <rekey_t_ki_gex> | <Server:s_kexinit_rekey> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) <rekey_t_req_gex> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_ki_gex> | <Client:c_debug> <rekey_t_ki_gex> | <Client:c_unimplemented> <rekey_t_ki_gex>
<rekey_t_req_gex> ::= <kex_timer_t> (<Client:c_gex_request_rekey> | <Client:c_gex_request_old_rekey>) <rekey_t_group_gex> | <server_transport> <rekey_t_req_gex> | <Client:c_ignore> <rekey_t_req_gex> | <Client:c_debug> <rekey_t_req_gex> | <Client:c_unimplemented> <rekey_t_req_gex> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_req_gex> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_group_gex> ::= <transport_noise> (<Server:s_gex_group_rekey> (<TimerControl:t_kex_cancel_t> | <TimerEvent:t_kex_expired_t>) <rekey_t_init_gex> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_group_gex> | <Client:c_debug> <rekey_t_group_gex> | <Client:c_unimplemented> <rekey_t_group_gex>)
<rekey_t_init_gex> ::= <kex_timer_t> <Client:c_gex_init_rekey> <rekey_t_reply_gex> | <server_transport> <rekey_t_init_gex> | <Client:c_ignore> <rekey_t_init_gex> | <Client:c_debug> <rekey_t_init_gex> | <Client:c_unimplemented> <rekey_t_init_gex> | <Client:c_unrecognized_kex> <transport_noise> (<Server:s_unimplemented_for_unrecognized> <rekey_t_init_gex> | <disconnect_end>) | <Client:c_disconnect> <end_state> | <Server:s_disconnect> <end_state>
<rekey_t_reply_gex> ::= <transport_noise> (<Server:s_gex_reply_rekey> <rekey_t_newkeys> | <rekey_t_fail> | <Client:c_ignore> <rekey_t_reply_gex> | <Client:c_debug> <rekey_t_reply_gex> | <Client:c_unimplemented> <rekey_t_reply_gex>)
# RFC 4254 5.1: either side may open a channel at any time, also while another channel is open. The second channel is opened with every channel type the client
# knows (session, direct-tcpip; x11, forwarded-tcpip and an unknown type are refused) and a confirmed second channel is closed at once (RFC 8308 3.3: with
# no-flow-control in effect the server MUST refuse it). The first channel's output, its requests and its CLOSE may arrive before the reply; the exchange continues in the state
# it started in, or in <connected_state> when the first channel's CLOSE came first. The numbers of the second channel are SECOND_CHANNEL, so SshSession keeps the first.
<open2_out> ::= <running_output> | <Server:s_channel_request_exit_status> | <Server:s_channel_request_xon_xoff> | <Server:s_channel_request_exit_signal> | <Server:s_channel_request_other>
<open2_chan2> ::= <Server:s_channel_data_2> | <Server:s_channel_extended_data_2> | <Server:s_channel_eof_2> | <Server:s_channel_window_adjust_2>
<open2_ok_req> ::= <Client:c_channel_open_session_2> | <Client:c_channel_open_direct_tcpip_2>
<open2_no_req> ::= <Client:c_channel_open_x11_2> | <Client:c_channel_open_forwarded_tcpip_2> | <Client:c_channel_open_unknown_2>
# the first channel's CLOSE came before the reply: it is answered, the reply decides the rest and the session goes on without a channel
<open2_ok_conn> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <connected_state> | <Server:s_channel_open_failure_2> <connected_state> | <conn_end>)
<open2_no_conn> ::= <open2_out>* (<Server:s_channel_open_failure_2> <connected_state> | <conn_end>)
<open_second_cs> ::= <open2_ok_req> <open2_ok_cs> | <open2_no_req> <open2_no_cs>
<open2_ok_cs> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <channel_state> | <Server:s_channel_open_failure_2> <channel_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_ok_conn>)
<open2_no_cs> ::= <open2_out>* (<Server:s_channel_open_failure_2> <channel_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_no_conn>)
<open_second_cp> ::= <open2_ok_req> <open2_ok_cp> | <open2_no_req> <open2_no_cp>
<open2_ok_cp> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <channel_pty_state> | <Server:s_channel_open_failure_2> <channel_pty_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_ok_conn>)
<open2_no_cp> ::= <open2_out>* (<Server:s_channel_open_failure_2> <channel_pty_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_no_conn>)
<open_second_cr> ::= <open2_ok_req> <open2_ok_cr> | <open2_no_req> <open2_no_cr>
<open2_ok_cr> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <channel_running> | <Server:s_channel_open_failure_2> <channel_running> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_ok_conn>)
<open2_no_cr> ::= <open2_out>* (<Server:s_channel_open_failure_2> <channel_running> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_no_conn>)
<open_second_ce> ::= <open2_ok_req> <open2_ok_ce> | <open2_no_req> <open2_no_ce>
<open2_ok_ce> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <channel_eof_state> | <Server:s_channel_open_failure_2> <channel_eof_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_ok_conn>)
<open2_no_ce> ::= <open2_out>* (<Server:s_channel_open_failure_2> <channel_eof_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_no_conn>)
<open_second_ct> ::= <open2_ok_req> <open2_ok_ct> | <open2_no_req> <open2_no_ct>
<open2_ok_ct> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <tcpip_channel_state> | <Server:s_channel_open_failure_2> <tcpip_channel_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_ok_conn>)
<open2_no_ct> ::= <open2_out>* (<Server:s_channel_open_failure_2> <tcpip_channel_state> | <conn_end> | <Server:s_channel_close> <Client:c_channel_close> <open2_no_conn>)
<open_second_cl> ::= <open2_ok_req> <open2_ok_cl> | <open2_no_req> <open2_no_cl>
<open2_ok_cl> ::= <open2_out>* (<Server:s_channel_open_confirmation_2> (<open2_chan2> | <open2_out>)* <Client:c_channel_close_2> (<open2_chan2> | <open2_out>)* <Server:s_channel_close_2> <channel_closing_state> | <Server:s_channel_open_failure_2> <channel_closing_state> | <conn_end> | <Server:s_channel_close> (<TimerControl:t_close_cancel> | <TimerEvent:t_close_expired>) <open2_ok_conn> | <TimerEvent:t_close_expired> <open2_ok_conn>)
<open2_no_cl> ::= <open2_out>* (<Server:s_channel_open_failure_2> <channel_closing_state> | <conn_end> | <Server:s_channel_close> (<TimerControl:t_close_cancel> | <TimerEvent:t_close_expired>) <open2_no_conn> | <TimerEvent:t_close_expired> <open2_no_conn>)

# ======================================================================================================
# Messages: binary packet protocol (RFC 4253 6): packet_length, padding_length, payload, random padding. The MAC and the
# encryption are applied by ClientNetworkParty: it hands Fandango the unencrypted packet without MAC.
# ======================================================================================================
<c_pkt_head> ::= <packet_length> <padding_length>
<s_pkt_head> ::= <packet_length> <padding_length>
<c_pkt_tail> ::= <c_random_padding>
<s_pkt_tail> ::= <s_random_padding>
<packet_length> ::= <uint32>
<padding_length> ::= <byte>
# RFC 4253 6: at least 4 and at most 255 octets of padding; the padding is 8 octets or none (<c_pad_half>: the total is then a multiple of 8 but not of 16,
# legal while the cipher in use has the block size 8), a free number of blocks of 16 octets and a minimal part that completes the packet to a multiple of 16
<c_random_padding> ::= <c_pad_half> <c_pad_extra> <c_pad_min>
<c_pad_half> ::= <c_pad_half_octets>? := gen_pad_half()
<c_pad_half_octets> ::= <padding_byte>{8}
<c_pad_extra> ::= <c_pad_block>{0,extra_max(<c_pkt_head>)}
<c_pad_block> ::= <padding_byte>{16}
<c_pad_min> ::= <padding_byte>{minimal_padding(<c_pkt_head>)}
<s_random_padding> ::= <padding_byte>{bytes(<s_pkt_head>.<padding_length>)[0]}
# the 256 octet values as literals: a message that ends in a literal is complete, one that ends in a regex may still grow
<padding_byte> ::= b"\x00" | b"\x01" | b"\x02" | b"\x03" | b"\x04" | b"\x05" | b"\x06" | b"\x07" | b"\x08" | b"\x09" | b"\x0a" | b"\x0b" | b"\x0c" | b"\x0d" | b"\x0e" | b"\x0f" | b"\x10" | b"\x11" | b"\x12" | b"\x13" | b"\x14" | b"\x15" | b"\x16" | b"\x17" | b"\x18" | b"\x19" | b"\x1a" | b"\x1b" | b"\x1c" | b"\x1d" | b"\x1e" | b"\x1f" | b"\x20" | b"\x21" | b"\x22" | b"\x23" | b"\x24" | b"\x25" | b"\x26" | b"\x27" | b"\x28" | b"\x29" | b"\x2a" | b"\x2b" | b"\x2c" | b"\x2d" | b"\x2e" | b"\x2f" | b"\x30" | b"\x31" | b"\x32" | b"\x33" | b"\x34" | b"\x35" | b"\x36" | b"\x37" | b"\x38" | b"\x39" | b"\x3a" | b"\x3b" | b"\x3c" | b"\x3d" | b"\x3e" | b"\x3f" | b"\x40" | b"\x41" | b"\x42" | b"\x43" | b"\x44" | b"\x45" | b"\x46" | b"\x47" | b"\x48" | b"\x49" | b"\x4a" | b"\x4b" | b"\x4c" | b"\x4d" | b"\x4e" | b"\x4f" | b"\x50" | b"\x51" | b"\x52" | b"\x53" | b"\x54" | b"\x55" | b"\x56" | b"\x57" | b"\x58" | b"\x59" | b"\x5a" | b"\x5b" | b"\x5c" | b"\x5d" | b"\x5e" | b"\x5f" | b"\x60" | b"\x61" | b"\x62" | b"\x63" | b"\x64" | b"\x65" | b"\x66" | b"\x67" | b"\x68" | b"\x69" | b"\x6a" | b"\x6b" | b"\x6c" | b"\x6d" | b"\x6e" | b"\x6f" | b"\x70" | b"\x71" | b"\x72" | b"\x73" | b"\x74" | b"\x75" | b"\x76" | b"\x77" | b"\x78" | b"\x79" | b"\x7a" | b"\x7b" | b"\x7c" | b"\x7d" | b"\x7e" | b"\x7f" | b"\x80" | b"\x81" | b"\x82" | b"\x83" | b"\x84" | b"\x85" | b"\x86" | b"\x87" | b"\x88" | b"\x89" | b"\x8a" | b"\x8b" | b"\x8c" | b"\x8d" | b"\x8e" | b"\x8f" | b"\x90" | b"\x91" | b"\x92" | b"\x93" | b"\x94" | b"\x95" | b"\x96" | b"\x97" | b"\x98" | b"\x99" | b"\x9a" | b"\x9b" | b"\x9c" | b"\x9d" | b"\x9e" | b"\x9f" | b"\xa0" | b"\xa1" | b"\xa2" | b"\xa3" | b"\xa4" | b"\xa5" | b"\xa6" | b"\xa7" | b"\xa8" | b"\xa9" | b"\xaa" | b"\xab" | b"\xac" | b"\xad" | b"\xae" | b"\xaf" | b"\xb0" | b"\xb1" | b"\xb2" | b"\xb3" | b"\xb4" | b"\xb5" | b"\xb6" | b"\xb7" | b"\xb8" | b"\xb9" | b"\xba" | b"\xbb" | b"\xbc" | b"\xbd" | b"\xbe" | b"\xbf" | b"\xc0" | b"\xc1" | b"\xc2" | b"\xc3" | b"\xc4" | b"\xc5" | b"\xc6" | b"\xc7" | b"\xc8" | b"\xc9" | b"\xca" | b"\xcb" | b"\xcc" | b"\xcd" | b"\xce" | b"\xcf" | b"\xd0" | b"\xd1" | b"\xd2" | b"\xd3" | b"\xd4" | b"\xd5" | b"\xd6" | b"\xd7" | b"\xd8" | b"\xd9" | b"\xda" | b"\xdb" | b"\xdc" | b"\xdd" | b"\xde" | b"\xdf" | b"\xe0" | b"\xe1" | b"\xe2" | b"\xe3" | b"\xe4" | b"\xe5" | b"\xe6" | b"\xe7" | b"\xe8" | b"\xe9" | b"\xea" | b"\xeb" | b"\xec" | b"\xed" | b"\xee" | b"\xef" | b"\xf0" | b"\xf1" | b"\xf2" | b"\xf3" | b"\xf4" | b"\xf5" | b"\xf6" | b"\xf7" | b"\xf8" | b"\xf9" | b"\xfa" | b"\xfb" | b"\xfc" | b"\xfd" | b"\xfe" | b"\xff"

# RFC 4251 5: data type representations
<uint32> ::= <byte>{4}
<boolean_false> ::= b"\x00"
<boolean_true> ::= b"\x01"
<boolean> ::= <boolean_false> | rb'[\x01-\xff]'
<string> ::= <string_len> <string_data>
<string_len> ::= b"\x00" <byte>{3}
<string_data> ::= <byte>{count_of(<string_len>)}
<mpint> ::= <string_len> <mpint_data>
<mpint_data> ::= <byte>{count_of(<string_len>)}
<name> ::= rb'[\x21-\x2b\x2d-\x7e]+'
<name_list> ::= <string_len> (<name> (b"," <name>)*)?
<text_sent> ::= <string_len> <text_value>
<text_value> ::= <text_chunk>? := gen_text()
<text_chunk> ::= rb'[\x00-\xff]+'
<data_sent> ::= <string_len> <data_value>
<data_value> ::= <data_chunk>? := gen_data()
<data_chunk> ::= rb'[\x00-\xff]+'
# RFC 4251 5: mpint: no unnecessary leading octets of 0 or 255
where forall <m> in <mpint_data>: mpint_wellformed(<m>)

# --- PYTHON BEGIN: grammar helpers for received formats
def mpint_wellformed(node):
    b = bytes(node)
    if len(b) >= 2 and ((b[0] == 0 and b[1] < 0x80) or (b[0] == 0xFF and b[1] >= 0x80)):
        return False
    return True
# --- PYTHON END

# RFC 4253 4.2: identification string; lines before it are allowed from the server only
<s_ident> ::= <banner_line>* (<ident_line> | <ident_line_tolerated>)
<c_ident> ::= b"SSH-" <protoversion_20> b"-" <softwareversion_sent> (b" " <comments_sent>)? b"\r\n"
<comments_sent> ::= <comments> := gen_comments()
# RFC 4253 4.2: the identification MUST be terminated by CR LF; a server in 1.99 compatibility mode SHOULD NOT send the CR (5.1)
<ident_line> ::= <ident_line_20> | <ident_line_199>
<ident_line_20> ::= b"SSH-" <protoversion_20> b"-" <softwareversion> (b" " <comments>)? b"\r\n"
<ident_line_199> ::= b"SSH-" <protoversion_199> b"-" <softwareversion> (b" " <comments>)? <ident_end>
<ident_end> ::= b"\r\n" | b"\n"
<protoversion_20> ::= b"2.0"
<protoversion_199> ::= b"1.99"
<softwareversion> ::= rb'[\x21-\x2c\x2e-\x7e]+'
# RFC 4253 4.2: at most 255 characters including CR LF
where forall <i> in <ident_line>: len(bytes(<i>)) <= 255
<softwareversion_sent> ::= <softwareversion> := gen_software_version()
<comments> ::= rb'[\x20-\x7e]+'
# tolerated deviation (TOLERATED=softwareversion-minus): a softwareversion with a minus sign, which RFC 4253 4.2 excludes
<ident_line_tolerated> ::= b"SSH-" <protoversion_20> b"-" <softwareversion_minus> (b" " <comments>)? b"\r\n"
<softwareversion_minus> ::= <sv_char>* b"-" <sv_char_or_minus>*
<sv_char> ::= rb'[\x21-\x2c\x2e-\x7e]'
<sv_char_or_minus> ::= rb'[\x21-\x7e]'
where forall <x> in <ident_line_tolerated>: tolerated("softwareversion-minus")
# a line the server sends before its identification string must not begin with "SSH-"
<banner_line> ::= <banner_text> b"\n" | b"\n"
<banner_text> ::= (<bn_not_s> <banner_char>*
                | b"S" <bn_not_s> <banner_char>*
                | b"SS" <bn_not_h> <banner_char>*
                | b"SSH" <bn_not_dash> <banner_char>*
                | b"S" | b"SS" | b"SSH")
<bn_not_s> ::= rb'[\x00-\x09\x0b-\x52\x54-\xff]'
<bn_not_h> ::= rb'[\x00-\x09\x0b-\x47\x49-\xff]'
<bn_not_dash> ::= rb'[\x00-\x09\x0b-\x2c\x2e-\xff]'
<banner_char> ::= rb'[\x00-\x09\x0b-\xff]'
# Fandango timers (parties TimerControl / TimerEvent): how long the client waits for a message the server may not send.
# Each timer has its own id and runs as long as the client may wait.
<t_kex_start> ::= <timer_start>
<t_kex_cancel> ::= <timer_cancel>
<t_kex_expired> ::= <timer_expired>
# timer 8: the wait of the re-exchange that ends the session (<rekey_term>)
<t_kex_start_t> ::= "start: " <timer_id> " (" <timer_timeout> ")\n"
<t_kex_cancel_t> ::= "cancel: " <timer_id> "\n"
<t_kex_expired_t> ::= "expired: " <timer_id> "\n"
where forall <t> in <t_kex_start_t>: str(<t>..<timer_id>) == '8'
where forall <t> in <t_kex_start_t>: str(<t>..<timer_timeout>) == '2'
where forall <t> in <t_kex_cancel_t>: str(<t>..<timer_id>) == '8'
where forall <t> in <t_kex_expired_t>: str(<t>..<timer_id>) == '8'
<t_service_start> ::= <timer_start>
<t_service_cancel> ::= <timer_cancel>
<t_service_expired> ::= <timer_expired>
# RFC 4253 7: the silence after a guessed packet is what a server does with a WRONG guess; after a right guess the server must reply
<t_kex_expired_guess> ::= <t_kex_expired>
where forall <t> in <t_kex_expired_guess>: not guess_was_right()
<t_close_start> ::= <timer_start>
<t_close_cancel> ::= <timer_cancel>
<t_close_expired> ::= <timer_expired>
where forall <t> in <t_close_start>: str(<t>..<timer_id>) == '5'
where forall <t> in <t_close_start>: str(<t>..<timer_timeout>) == '2'
where forall <t> in <t_close_cancel>: str(<t>..<timer_id>) == '5'
where forall <t> in <t_close_expired>: str(<t>..<timer_id>) == '5'
<t_authsvc_start> ::= <timer_start>
<t_authsvc_cancel> ::= <timer_cancel>
<t_authsvc_expired> ::= <timer_expired>
where forall <t> in <t_authsvc_start>: str(<t>..<timer_id>) == '3'
where forall <t> in <t_authsvc_start>: str(<t>..<timer_timeout>) == '2'
where forall <t> in <t_authsvc_cancel>: str(<t>..<timer_id>) == '3'
where forall <t> in <t_authsvc_expired>: str(<t>..<timer_id>) == '3'
<t_late_start> ::= <timer_start>
<t_late_cancel> ::= <timer_cancel>
<t_late_expired> ::= <timer_expired>
where forall <t> in <t_late_start>: str(<t>..<timer_id>) == '6'
where forall <t> in <t_late_start>: str(<t>..<timer_timeout>) == '1'
where forall <t> in <t_late_cancel>: str(<t>..<timer_id>) == '6'
where forall <t> in <t_late_expired>: str(<t>..<timer_id>) == '6'
<t_baduser_start> ::= <timer_start>
<t_baduser_cancel> ::= <timer_cancel>
<t_baduser_expired> ::= <timer_expired>
where forall <t> in <t_baduser_start>: str(<t>..<timer_id>) == '4'
where forall <t> in <t_baduser_start>: str(<t>..<timer_timeout>) == '2'
where forall <t> in <t_baduser_cancel>: str(<t>..<timer_id>) == '4'
where forall <t> in <t_baduser_expired>: str(<t>..<timer_id>) == '4'
where forall <t> in <t_kex_start>: str(<t>..<timer_id>) == '1'
where forall <t> in <t_kex_start>: str(<t>..<timer_timeout>) == '2'
where forall <t> in <t_kex_cancel>: str(<t>..<timer_id>) == '1'
where forall <t> in <t_kex_expired>: str(<t>..<timer_id>) == '1'
where forall <t> in <t_service_start>: str(<t>..<timer_id>) == '2'
where forall <t> in <t_service_start>: str(<t>..<timer_timeout>) == '2'
where forall <t> in <t_service_cancel>: str(<t>..<timer_id>) == '2'
where forall <t> in <t_service_expired>: str(<t>..<timer_id>) == '2'

# the token for a closed connection (see <closed_end>): length 0, padding length 0, message number 0, which no SSH message uses (RFC 4250 4.1.2 numbers the messages from 1)
<s_closed> ::= b"\x00\x00\x00\x00\x00\x00"

# ---------------------------------------------------------------- transport layer messages (RFC 4253)
<s_kexinit> ::= <s_pkt_head> <kexinit_payload> <s_pkt_tail>
<kexinit_payload> ::= b"\x14" <cookie> <kex_algorithms> <server_host_key_algorithms> <encryption_algorithms_client_to_server> <encryption_algorithms_server_to_client> <mac_algorithms_client_to_server> <mac_algorithms_server_to_client> <compression_algorithms_client_to_server> <compression_algorithms_server_to_client> <languages_client_to_server> <languages_server_to_client> <first_kex_packet_follows> <kexinit_reserved>
<cookie> ::= <byte>{16}
<kex_algorithms> ::= <name_list>
<server_host_key_algorithms> ::= <name_list>
<encryption_algorithms_client_to_server> ::= <name_list>
<encryption_algorithms_server_to_client> ::= <name_list>
<mac_algorithms_client_to_server> ::= <name_list>
<mac_algorithms_server_to_client> ::= <name_list>
<compression_algorithms_client_to_server> ::= <name_list>
<compression_algorithms_server_to_client> ::= <name_list>
<languages_client_to_server> ::= <name_list>
<languages_server_to_client> ::= <name_list>
<first_kex_packet_follows> ::= <boolean>
<kexinit_reserved> ::= <uint32>
<c_kexinit_ecdh> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<kex_list_ecdh> ::= <string_len> (<name_random> b",")? <kex_name_ecdh> (b"," <kex_name_ecdh_other>){0,2} (b"," <ext_info_c>)?
<kex_name_ecdh> ::= <name> := gen_kex_name("ecdh")
<kex_name_ecdh_other> ::= <name> := gen_kex_name_other("ecdh")
<c_kexinit_dh> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_dh> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<kex_list_dh> ::= <string_len> (<name_random> b",")? <kex_name_dh> (b"," <kex_name_dh_other>){0,2} (b"," <ext_info_c>)?
<kex_name_dh> ::= <name> := gen_kex_name("dh")
<kex_name_dh_other> ::= <name> := gen_kex_name_other("dh")
<c_kexinit_gex> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_gex> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<kex_list_gex> ::= <string_len> (<name_random> b",")? <kex_name_gex> (b"," <kex_name_gex_other>){0,2} (b"," <ext_info_c>)?
<kex_name_gex> ::= <name> := gen_kex_name("gex")
<kex_name_gex_other> ::= <name> := gen_kex_name_other("gex")
<c_kexinit_ecdh_rekey> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh_rekey> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_kexinit_ecdh_rekey_after_server> ::= <c_kexinit_ecdh_rekey>
<c_kexinit_dh_rekey> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_dh_rekey> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_kexinit_dh_rekey_after_server> ::= <c_kexinit_dh_rekey>
<c_kexinit_gex_rekey> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_gex_rekey> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_kexinit_gex_rekey_after_server> ::= <c_kexinit_gex_rekey>
<kex_list_dh_rekey> ::= <string_len> (<name_random> b",")? <kex_name_dh> (b"," <kex_name_dh_other>){0,2}
<kex_list_gex_rekey> ::= <string_len> (<name_random> b",")? <kex_name_gex> (b"," <kex_name_gex_other>){0,2}
<c_newcompress_after_success> ::= <c_newcompress>
<s_unimplemented_newcompress> ::= <s_unimplemented_for_unrecognized>
where forall <m> in <s_unimplemented_newcompress>: not SSH.dc_effect
<s_kex_late> ::= <s_pkt_head> (b"\x1f" | b"\x21") <string> <string> <string> <s_pkt_tail>
<s_kexinit_rekey> ::= <s_kexinit>
<s_ecdh_reply_rekey> ::= <s_ecdh_reply>
<c_dh_init_rekey> ::= <c_dh_init>
<s_dh_reply_rekey> ::= <s_dh_reply>
<s_newkeys_rekey> ::= <s_newkeys>
<c_newkeys_rekey> ::= <c_newkeys>
<c_gex_request_rekey> ::= <c_gex_request>
<c_gex_request_old_rekey> ::= <c_gex_request_old>
<s_gex_group_rekey> ::= <s_gex_group>
<c_gex_init_rekey> ::= <c_gex_init>
<s_gex_reply_rekey> ::= <s_gex_reply>
<c_ecdh_init_rekey> ::= <c_pkt_head> b"\x1e" <ecdh_q_c_rekey> <c_pkt_tail>
<ecdh_q_c_rekey> ::= <string_len> <ecdh_q_value_rekey>
<ecdh_q_value_rekey> ::= rb'[\x00-\xff]+' := gen_ecdh_q(False)
<c_kexinit_ecdh_guess> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh_guess> <hostkey_list_guess> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<c_ecdh_init_guess> ::= <c_pkt_head> b"\x1e" <ecdh_q_c> <c_pkt_tail>
<c_kexinit_ecdh_unannounced> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh_unannounced> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_ecdh_init_unannounced> ::= <c_pkt_head> b"\x1e" <ecdh_q_c_unannounced> <c_pkt_tail>
<ecdh_q_c_unannounced> ::= <string_len> <ecdh_q_value_unannounced>
<ecdh_q_value_unannounced> ::= rb'[\x00-\xff]+' := gen_ecdh_q_unannounced()
<ecdh_q_c_right> ::= <string_len> <ecdh_q_value_right>
<ecdh_q_value_right> ::= rb'[\x00-\xff]+' := gen_ecdh_q_right()
<kex_list_ecdh_unannounced> ::= <string_len> <kex_unannounced> (b"," <kex_unannounced_other>){0,2} (b"," <ext_info_c>)?
<kex_unannounced> ::= <name> := gen_kex_unannounced()
<kex_unannounced_other> ::= <name> := gen_kex_unannounced_other()
<c_kexinit_ecdh_hostguess> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh_hostguess> <hostkey_list_guess> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_ecdh_hostguess> ::= <string_len> <kex_first_hostguess> (b"," <kex_name_ecdh_other>){0,2} (b"," <ext_info_c>)?
<kex_first_hostguess> ::= <name> := gen_kex_first_hostguess()
<c_kexinit_ecdh_right> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh_right> <hostkey_list_right> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<c_ecdh_init_right> ::= <c_pkt_head> b"\x1e" <ecdh_q_c_right> <c_pkt_tail>
<c_kexinit_ecmqv> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecmqv> <hostkey_list_ecc> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_ecmqv_init> ::= <c_pkt_head> b"\x1e" <ecmqv_q_c> <c_pkt_tail>
<s_ecmqv_reply> ::= <s_pkt_head> b"\x1f" <host_key_blob> <ecdh_q_s> <string> <s_pkt_tail>
# RFC 5656 4, 5: the host key's point and the server's ephemeral public key must be valid points of the host key's curve (uncompressed or compressed encoding)
where forall <m> in <s_ecmqv_reply>: ecmqv_reply_valid(bytes(<m>.<host_key_blob>)[4:], bytes(<m>.<ecdh_q_s>)[4:])
<c_kexinit_nocommon> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_ecdh> (<name_list_any> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> | <hostkey_list_sent> <name_list_any> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> | <hostkey_list_sent> <cipher_list_c2s> <name_list_any> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> | <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <name_list_any> <mac_list_s2c> <comp_list_none> <comp_list_none> | <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <name_list_any> <comp_list_none> <comp_list_none> | <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <name_list_any> <comp_list_none> | <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <name_list_any>) <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_kexinit_dh_guess> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_dh_guess> <hostkey_list_guess> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_dh_guess> ::= <string_len> <kex_name_dh> (b"," <kex_name_dh_other>){0,2} (b"," <ext_info_c>)?
<c_kexinit_gex_guess> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_gex_guess> <hostkey_list_guess> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_gex_guess> ::= <string_len> <kex_name_gex> (b"," <kex_name_gex_other>){0,2} (b"," <ext_info_c>)?
<c_dh_init_guess> ::= <c_pkt_head> b"\x1e" <dh_e> <c_pkt_tail>
<c_kexinit_dh_right> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_dh_right> <hostkey_list_right> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_dh_right> ::= <string_len> <kex_first_right_dh> (b"," <kex_name_dh_other>){0,2} (b"," <ext_info_c>)?
<kex_first_right_dh> ::= <name> := gen_kex_first_right("dh")
<c_kexinit_dh_hostguess> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_dh_hostguess> <hostkey_list_guess> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_dh_hostguess> ::= <string_len> <kex_first_hostguess_dh> (b"," <kex_name_dh_other>){0,2} (b"," <ext_info_c>)?
<kex_first_hostguess_dh> ::= <name> := gen_kex_first_hostguess("dh")
<c_kexinit_gex_right> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_gex_right> <hostkey_list_right> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_gex_right> ::= <string_len> <kex_first_right_gex> (b"," <kex_name_gex_other>){0,2} (b"," <ext_info_c>)?
<kex_first_right_gex> ::= <name> := gen_kex_first_right("gex")
<c_kexinit_gex_hostguess> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_gex_hostguess> <hostkey_list_guess> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_true> <reserved_zero> <c_pkt_tail>
<kex_list_gex_hostguess> ::= <string_len> <kex_first_hostguess_gex> (b"," <kex_name_gex_other>){0,2} (b"," <ext_info_c>)?
<kex_first_hostguess_gex> ::= <name> := gen_kex_first_hostguess("gex")
<c_dh_init_right> ::= <c_pkt_head> b"\x1e" <dh_e_right> <c_pkt_tail>
<dh_e_right> ::= <string_len> <dh_e_value_right>
<dh_e_value_right> ::= rb'[\x00-\xff]+' := gen_dh_e_right()
<c_gex_request_right> ::= <c_pkt_head> b"\x22" <gex_min> <gex_n> <gex_max> <c_pkt_tail>
<c_gex_request_guess> ::= <c_pkt_head> b"\x22" <gex_min> <gex_n> <gex_max> <c_pkt_tail>
<c_kexinit_nokex> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_any> <hostkey_list_sent> <cipher_list_c2s> <cipher_list_s2c> <mac_list_c2s> <mac_list_s2c> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<c_kexinit_any> ::= <c_pkt_head> b"\x14" <cookie_sent> <kex_list_any> <name_list_any> <name_list_any> <name_list_any> <name_list_any> <name_list_any> <comp_list_none> <comp_list_none> <lang_list_sent> <lang_list_sent> <boolean_false> <reserved_zero> <c_pkt_tail>
<kex_list_ecmqv> ::= <string_len> (<name_random> b",")? <kex_name_ecmqv> (b"," <name_random>)? (b"," <ext_info_c>)?
<kex_name_ecmqv> ::= b"ecmqv-sha2"
<hostkey_list_ecc> ::= <string_len> <hostkey_name_ecc>
# RFC 5656 5: Q_C is a point on the domain parameters of the host key algorithm named in the client's list
<ecmqv_q_c> ::= <string_len> <ecmqv_q_value>
<ecmqv_q_value> ::= rb'[\x00-\xff]+' := gen_ecmqv_q()
<hostkey_name_ecc> ::= <name> := gen_hostkey_ecc()
# a re-exchange does not repeat the indicator (RFC 8308 2.1: first key exchange only)
<kex_list_ecdh_rekey> ::= <string_len> (<name_random> b",")? <kex_name_ecdh> (b"," <kex_name_ecdh_other>){0,2}
# RFC 4253 7.1: the first algorithm of a list that announces a guessed packet is the guessed algorithm
<kex_list_ecdh_guess> ::= <string_len> <kex_name_ecdh> (b"," <kex_name_ecdh_other>){0,2} (b"," <ext_info_c>)?
<hostkey_list_guess> ::= <string_len> <hostkey_name_sent> (b"," <hostkey_name_other>){0,2}
# RFC 4253 7: a guess that may be right: the client's first kex and host key names are the server's first ones when the client implements them
<kex_list_ecdh_right> ::= <string_len> <kex_first_right> (b"," <kex_name_ecdh_other>){0,2} (b"," <ext_info_c>)?
<kex_first_right> ::= <name> := gen_kex_first_right()
<hostkey_list_right> ::= <string_len> <hostkey_first_right> (b"," <hostkey_name_other>){0,2}
<hostkey_first_right> ::= <name> := gen_hostkey_first_right()
<kex_list_any> ::= <string_len> <name_random> (b"," <name_random>){0,3} (b"," <ext_info_c>)?
<name_list_any> ::= <string_len> <name_random> (b"," <name_random>){0,3}
<name_random> ::= <name> := gen_random_name()
<ext_info_c> ::= b"ext-info-c"
<cookie_sent> ::= rb'[\x00-\xff]{16}' := gen_cookie()
<reserved_zero> ::= b"\x00\x00\x00\x00"
<hostkey_list_sent> ::= <string_len> (<name_random> b",")? <hostkey_name_sent> (b"," <hostkey_name_other>){0,2}
<hostkey_name_sent> ::= <name> := gen_hostkey_name()
<hostkey_name_other> ::= <name> := gen_hostkey_name_other()
<cipher_list_c2s> ::= <string_len> (<name_random> b",")? <cipher_name_c2s> (b"," <cipher_name_other>){0,2}
<cipher_list_s2c> ::= <string_len> (<name_random> b",")? <cipher_name_s2c> (b"," <cipher_name_other>){0,2}
<cipher_name_c2s> ::= <name> := gen_cipher_name(2)
<cipher_name_s2c> ::= <name> := gen_cipher_name(3)
<cipher_name_other> ::= <name> := gen_cipher_name_other()
<mac_list_c2s> ::= <string_len> (<name_random> b",")? <mac_name_c2s> (b"," <mac_name_other>){0,2}
<mac_list_s2c> ::= <string_len> (<name_random> b",")? <mac_name_s2c> (b"," <mac_name_other>){0,2}
<mac_name_c2s> ::= <name> := gen_mac_name(4)
<mac_name_s2c> ::= <name> := gen_mac_name(5)
<mac_name_other> ::= <name> := gen_mac_name_other()
<comp_list_none> ::= <string_len> (<name_random> b",")? <comp_none> (b"," <comp_offer>)?
<comp_none> ::= b"none"
# RFC 4253 6.2: "zlib" may be offered after "none"; the server picks the first name of the client's list that it supports, so no compression is switched on
<comp_offer> ::= b"zlib" | b"zlib@openssh.com"
# RFC 4253 7.1: a name-list of language tags (RFC 5646), possibly empty
<lang_list_sent> ::= <string_len> (<lang_tag> (b"," <lang_tag>){0,2})?
<lang_tag> ::= rb'[a-zA-Z0-9-]+' := gen_lang_tag()
# RFC 4253 11.1, RFC 4256 3.1: a single language tag, possibly empty
<lang_tag_sent> ::= <string_len> <lang_tag_value>?
<lang_tag_value> ::= rb'[a-zA-Z0-9-]+' := gen_lang_tag()
# key exchange messages (RFC 4253 8, RFC 4419 3, RFC 5656 4, RFC 8731 3)
<c_ecdh_init> ::= <c_pkt_head> b"\x1e" <ecdh_q_c> <c_pkt_tail>
<ecdh_q_c> ::= <string_len> <ecdh_q_value>
<ecdh_q_value> ::= rb'[\x00-\xff]+' := gen_ecdh_q()

<s_ecdh_reply> ::= <s_pkt_head> b"\x1f" <host_key_blob> <ecdh_q_s> <signature_blob> <s_pkt_tail>
<c_dh_init> ::= <c_pkt_head> b"\x1e" <dh_e> <c_pkt_tail>
<dh_e> ::= <string_len> <dh_e_value>
<dh_e_value> ::= rb'[\x00-\xff]+' := gen_dh_e()
<s_dh_reply> ::= <s_pkt_head> b"\x1f" <host_key_blob> <mpint> <signature_blob> <s_pkt_tail>
<c_gex_request> ::= <c_pkt_head> b"\x22" <gex_min> <gex_n> <gex_max> <c_pkt_tail>
<c_gex_request_old> ::= <c_pkt_head> b"\x1e" <gex_n_old> <c_pkt_tail>
<gex_min> ::= <uint32> := gex_size("min")
<gex_n> ::= <uint32> := gex_size("n")
<gex_n_old> ::= <uint32> := gex_size("n_old")
<gex_max> ::= <uint32> := gex_size("max")
<s_gex_group> ::= <s_pkt_head> b"\x1f" <mpint> <mpint> <s_pkt_tail>
<c_gex_init> ::= <c_pkt_head> b"\x20" <gex_e> <c_pkt_tail>
<gex_e> ::= <string_len> <gex_e_value>
<gex_e_value> ::= rb'[\x00-\xff]+' := gen_gex_e()
<s_gex_reply> ::= <s_pkt_head> b"\x21" <host_key_blob> <mpint> <signature_blob> <s_pkt_tail>
<host_key_blob> ::= <string>
<ecdh_q_s> ::= <string>
<signature_blob> ::= <string>
<c_newkeys> ::= <c_pkt_head> <newkeys_type> <c_pkt_tail>
<s_newkeys> ::= <s_pkt_head> b"\x15" <s_pkt_tail>
<newkeys_type> ::= b"\x15" := gen_newkeys_type()
<c_ext_info_none> ::= <c_pkt_head> b"\x07" <ext_count_zero> <c_pkt_tail>
<c_ext_info_many> ::= <c_pkt_head> b"\x07" <ext_count_sent> <ext_item>{count_of(<ext_count_sent>)} <c_pkt_tail>
<ext_count_zero> ::= b"\x00\x00\x00\x00"
<ext_count_sent> ::= <uint32> := gen_ext_count()
# RFC 8308 3: the extensions a client may send; the value of an extension that is not defined is any sequence of octets
<ext_item> ::= <ext_local> | <ext_server_sig_algs> | <ext_no_flow_control> | <ext_delay_compression> | <ext_elevation>
<ext_server_sig_algs> ::= <ext_name_ssa> <ext_value_ssa>
<ext_name_ssa> ::= <string_len> b"server-sig-algs"
<ext_value_ssa> ::= <string_len> <pk_alg_name> (b"," <pk_alg_name>){0,3}
<pk_alg_name> ::= <name> := gen_pk_alg_name()
<ext_no_flow_control> ::= <ext_name_nfc> <ext_value_nfc>
<ext_name_nfc> ::= <string_len> b"no-flow-control"
<ext_value_nfc> ::= <string_len> (b"p" | b"s")
<ext_delay_compression> ::= <ext_name_dc> <ext_value_dc>
<ext_name_dc> ::= <string_len> b"delay-compression"
<ext_value_dc> ::= <string_len> <comp_list_dc> <comp_list_dc>
# RFC 8308 3.2: the lists of the delay-compression extension name "none" and "zlib"
<comp_list_dc> ::= <string_len> (b"none" | b"zlib" | b"zlib,none" | b"none,zlib")
<ext_elevation> ::= <ext_name_elev> <ext_value_elev>
<ext_name_elev> ::= <string_len> b"elevation"
<ext_value_elev> ::= <string_len> (b"y" | b"n" | b"d")
<ext_local> ::= <ext_local_name> <ext_local_value>
<ext_local_name> ::= <string_len> <ext_local_name_value>
<ext_local_name_value> ::= <byte>* := gen_ext_name()
<ext_local_value> ::= <string_len> <ext_local_value_data>
<ext_local_value_data> ::= <data_chunk>? := gen_ignore()
<s_ext_info> ::= <s_pkt_head> b"\x07" <ext_count> <extension>{count_of(<ext_count>)} <s_pkt_tail>
<ext_count> ::= <uint32>
# RFC 8308 3.1, 3.2: the extensions whose value has a defined syntax are parsed by it; every other extension is a generic pair
<extension> ::= <extension_ssa> | <extension_dc> | <extension_generic>
<extension_ssa> ::= <ext_name_ssa> <name_list>
<extension_dc> ::= <ext_name_dc> <ext_value_dc_recv>
<ext_value_dc_recv> ::= <string_len> <name_list> <name_list>
<extension_generic> ::= <string> <string>
where forall <x> in <extension_generic>: bytes(<x>.<string>[0].<string_data>) not in (b"server-sig-algs", b"delay-compression")
<c_service_request_userauth> ::= <c_pkt_head> b"\x05" <service_userauth> <c_pkt_tail>
<c_service_request_unknown> ::= <c_pkt_head> b"\x05" <service_unknown> <c_pkt_tail>
<c_service_request_connection> ::= <c_pkt_head> b"\x05" <service_connection> <c_pkt_tail>
<s_service_accept> ::= <s_pkt_head> b"\x06" <service_name> <s_pkt_tail>
# RFC 4253 10: the service name is echoed
where forall <m> in <s_service_accept>: bytes(<m>.<service_name>.<service_name_body>) == SSH.last_service
# RFC 4251 6, RFC 4253 10: the service name field of SERVICE_REQUEST, SERVICE_ACCEPT and USERAUTH_REQUEST is <service_name>: a length and a name; the sent forms are
# narrowings of it: the fixed values the exchange requires (ssh-userauth, ssh-connection) and an unknown name (a generated <name>)
<service_name> ::= <string_len> <service_name_body>
<service_name_body> ::= <service_name_char>{count_of(<string_len>)}
<service_name_char> ::= rb'[\x21-\x2b\x2d-\x7e]'
<service_userauth> ::= <service_name>
where forall <s> in <service_userauth>: bytes(<s>) == b"\x00\x00\x00\x0cssh-userauth"
<service_connection> ::= <service_name>
where forall <s> in <service_connection>: bytes(<s>) == b"\x00\x00\x00\x0essh-connection"
<service_unknown> ::= <string_len> <service_unknown_value>
<service_unknown_value> ::= <name> := gen_unknown_service()
<s_disconnect> ::= <s_pkt_head> b"\x01" <disconnect_reason> <string> <string> <s_pkt_tail>
<c_disconnect> ::= <c_pkt_head> b"\x01" <disconnect_reason_sent> <text_sent> <lang_tag_sent> <c_pkt_tail>
<disconnect_reason> ::= <disc_host_not_allowed_to_connect> | <disc_protocol_error> | <disc_key_exchange_failed> | <disc_reserved> | <disc_mac_error> | <disc_compression_error> | <disc_service_not_available> | <disc_protocol_version_not_supported> | <disc_host_key_not_verifiable> | <disc_connection_lost> | <disc_by_application> | <disc_too_many_connections> | <disc_auth_cancelled_by_user> | <disc_no_more_auth_methods_available> | <disc_illegal_user_name> | <disc_other>
<disc_host_not_allowed_to_connect> ::= b"\x00\x00\x00\x01"
<disc_protocol_error> ::= b"\x00\x00\x00\x02"
<disc_key_exchange_failed> ::= b"\x00\x00\x00\x03"
<disc_reserved> ::= b"\x00\x00\x00\x04"
<disc_mac_error> ::= b"\x00\x00\x00\x05"
<disc_compression_error> ::= b"\x00\x00\x00\x06"
<disc_service_not_available> ::= b"\x00\x00\x00\x07"
<disc_protocol_version_not_supported> ::= b"\x00\x00\x00\x08"
<disc_host_key_not_verifiable> ::= b"\x00\x00\x00\x09"
<disc_connection_lost> ::= b"\x00\x00\x00\x0a"
<disc_by_application> ::= b"\x00\x00\x00\x0b"
<disc_too_many_connections> ::= b"\x00\x00\x00\x0c"
<disc_auth_cancelled_by_user> ::= b"\x00\x00\x00\x0d"
<disc_no_more_auth_methods_available> ::= b"\x00\x00\x00\x0e"
<disc_illegal_user_name> ::= b"\x00\x00\x00\x0f"
<disc_other> ::= b"\x00\x00\x00" rb'[\x10-\xff]' | b"\x00\x00" rb'[\x01-\xff]' <byte> | b"\x00" rb'[\x01-\xff]' <byte>{2} | rb'[\x01-\xff]' <byte>{3}
<disconnect_reason_sent> ::= <disc_host_not_allowed_to_connect> | <disc_protocol_error> | <disc_key_exchange_failed> | <disc_reserved> | <disc_mac_error> | <disc_compression_error> | <disc_service_not_available> | <disc_protocol_version_not_supported> | <disc_host_key_not_verifiable> | <disc_connection_lost> | <disc_by_application> | <disc_too_many_connections> | <disc_auth_cancelled_by_user> | <disc_no_more_auth_methods_available> | <disc_illegal_user_name>
<s_debug> ::= <s_pkt_head> b"\x04" <boolean> <string> <string> <s_pkt_tail>
<s_ignore> ::= <s_pkt_head> b"\x02" <string> <s_pkt_tail>
<s_unimplemented> ::= <s_pkt_head> b"\x03" <uint32> <s_pkt_tail>
<s_unimplemented_for_unrecognized> ::= <s_pkt_head> b"\x03" <uint32> <s_pkt_tail>
# RFC 4253 11.4: the reply to an unrecognized message carries its sequence number
where forall <m> in <s_unimplemented_for_unrecognized>: u32v(<m>.<uint32>) == SSH.last_seq_sent
<c_unrecognized> ::= <c_pkt_head> <unrec_type> <ignore_sent> <c_pkt_tail>
<c_unrecognized_early> ::= <c_pkt_head> <unrec_type_early> <ignore_sent> <c_pkt_tail>
<c_unrecognized_kex> ::= <c_pkt_head> <unrec_type_kex> <ignore_sent> <c_pkt_tail>
<c_unrecognized_kex_c> ::= <c_pkt_head> <unrec_type_kex_c> <ignore_sent> <c_pkt_tail>
<unrec_type_kex_c> ::= rb'[\x09-\x13]' | rb'[\x16-\x1d]'
<unrec_type_kex> ::= rb'[\x09-\x13]' | rb'[\x16-\x1d]' | rb'[\x23-\x31]'
<c_ignore> ::= <c_pkt_head> b"\x02" <ignore_sent> <c_pkt_tail>
<c_newcompress> ::= <c_pkt_head> b"\x08" <c_pkt_tail>
<c_debug> ::= <c_pkt_head> b"\x04" <boolean_sent> <text_sent> <lang_tag_sent> <c_pkt_tail>
# RFC 4250 4.1.2: message numbers that are not assigned: transport 9-19, user authentication 54-59,
# connection protocol 83-89 and 101-127, client protocols 128-191, local extensions 192-255
<unrec_type_early> ::= rb'[\x09-\x13]' | rb'[\x16-\x1d]' | rb'[\x23-\x31]' | rb'[\x36-\x3b]' | rb'[\x3e-\x4f]'
<unrec_type> ::= <unrec_type_early> | rb'[\x53-\x59]' | rb'[\x65-\xbf]' | rb'[\xc0-\xff]'
<ignore_sent> ::= <string_len> <ignore_value>
<ignore_value> ::= <data_chunk>? := gen_ignore()
<c_unimplemented> ::= <c_pkt_head> b"\x03" <seq_sent> <c_pkt_tail>
<boolean_sent> ::= <boolean_false> | <boolean_true>
<seq_sent> ::= <uint32> := gen_seq()
# ---------------------------------------------------------------- user authentication (RFC 4252, RFC 4256)
<user_valid> ::= <string_len> <user_value>
<user_value> ::= <byte>* := gen_user()
<user_bad> ::= <string_len> <bad_user_value>
<bad_user_value> ::= <byte>* := gen_bad_user()
<method_none> ::= <string_len> b"none"
<method_password> ::= <string_len> b"password"
<method_publickey> ::= <string_len> b"publickey"
<method_hostbased> ::= <string_len> b"hostbased"
<method_kbdint> ::= <string_len> b"keyboard-interactive"
<method_unknown> ::= <string_len> <method_unknown_value>
<method_unknown_value> ::= <byte>* := gen_unknown_method()
<password_valid> ::= <string_len> <password_value>
<password_value> ::= <byte>* := gen_password()
<password_bad> ::= <string_len> <bad_password_value>
<bad_password_value> ::= <byte>* := gen_bad_password()
<password_new> ::= <string_len> <new_password_value>
<new_password_value> ::= <byte>* := gen_new_password()
<c_auth_none> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_none> <c_pkt_tail>
<c_auth_none_after_info> ::= <c_auth_none>
<c_auth_password_ok> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_password> <boolean_false> <password_valid> <c_pkt_tail>
<c_auth_password_bad> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_password> <boolean_false> <password_bad> <c_pkt_tail>
<c_auth_bad_user> ::= <c_pkt_head> b"\x32" <user_bad> <service_connection> <method_password> <boolean_false> (<password_valid> | <password_bad>) <c_pkt_tail>
<c_auth_password_change> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_password> <boolean_true> <password_valid> <password_new> <c_pkt_tail>
<c_auth_password_change_bad> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_password> <boolean_true> <password_bad> <password_new> <c_pkt_tail>
<c_auth_password_expired> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_password> <boolean_false> <password_valid> <c_pkt_tail>
<c_auth_late> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_none> <c_pkt_tail>
<c_auth_unknown_service> ::= <c_pkt_head> b"\x32" <user_valid> <service_unknown> <method_none> <c_pkt_tail>
<c_auth_unknown_method> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_unknown> <c_pkt_tail>
<c_auth_hostbased> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_hostbased> <pk_alg> <pk_blob> <hostname_sent> <hostbased_user> <pk_signature> <c_pkt_tail>
<pk_alg> ::= <string_len> b"ssh-ed25519"
<pk_alg_unknown> ::= <string_len> <pk_alg_unknown_value>
<pk_alg_unknown_value> ::= rb'[\x00-\xff]+' := gen_unknown_pk_alg()
# RFC 8709 4: the ssh-ed25519 key blob is string "ssh-ed25519" and string key (32 octets)
<pk_blob> ::= <string_len> <pk_blob_alg> <pk_blob_key>
<pk_blob_alg> ::= <string_len> b"ssh-ed25519"
<pk_blob_key> ::= <string_len> <pk_key_value>
<pk_key_value> ::= rb'[\x00-\xff]{32}' := gen_pk_key()
<pk_alg_rsa> ::= <pk_alg_rsa256> | <pk_alg_rsa512> | <pk_alg_sshrsa>
<pk_alg_rsa256> ::= <string_len> b"rsa-sha2-256"
<pk_alg_rsa512> ::= <string_len> b"rsa-sha2-512"
<pk_alg_sshrsa> ::= <string_len> b"ssh-rsa"
# RFC 4253 6.6: the ssh-rsa key blob is string "ssh-rsa", mpint e, mpint n
<pk_blob_rsa> ::= <string_len> <pk_blob_alg_sshrsa> <pk_rsa_e> <pk_rsa_n>
<pk_blob_alg_sshrsa> ::= <string_len> b"ssh-rsa"
<pk_rsa_e> ::= <string_len> <pk_rsa_e_value>
<pk_rsa_e_value> ::= rb'[\x00-\xff]+' := gen_rsa_e()
<pk_rsa_n> ::= <string_len> <pk_rsa_n_value>
<pk_rsa_n_value> ::= rb'[\x00-\xff]+' := gen_rsa_n()
# the signature blob is string algorithm name, string signature value (256 octets for a 2048-bit key)
<pk_signature_rsa256> ::= b"\x00\x00\x01\x14" <pk_signature_value>
<pk_signature_rsa512> ::= b"\x00\x00\x01\x14" <pk_signature_value>
<pk_signature_sshrsa> ::= b"\x00\x00\x01\x0f" <pk_signature_value>
<pk_blob_other> ::= <string_len> <pk_blob_alg> <pk_blob_otherkey>
<pk_blob_otherkey> ::= <string_len> <pk_key_other_value>
<pk_key_other_value> ::= rb'[\x00-\xff]{32}' := gen_pk_key_other()
<pk_blob_bad> ::= <string_len> <pk_blob_alg> <pk_blob_badkey>
<pk_blob_badkey> ::= <string_len> <pk_key_bad_value>
<pk_key_bad_value> ::= rb'[\x00-\xff]{32}' := gen_pk_key_bad()
<hostname_sent> ::= <string_len> <hostname_value>
<hostname_value> ::= <byte>* := gen_hostname()
<pk_signature> ::= b"\x00\x00\x00\x53" <pk_signature_value>
<pk_signature_value> ::= <byte>*
<pk_signature_bad> ::= b"\x00\x00\x00\x53\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x40" <byte>{64}
<c_auth_publickey_unknown_alg> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> <pk_alg_unknown> <pk_blob> <c_pkt_tail>
<c_auth_publickey_query> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> <pk_alg> <pk_blob> <c_pkt_tail>
<c_auth_publickey_bad> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> <pk_alg> <pk_blob_bad> <c_pkt_tail>
<c_auth_publickey_signed> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg> <pk_blob> <pk_signature> <c_pkt_tail>
<c_auth_publickey_other_key> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg> <pk_blob_other> <pk_signature> <c_pkt_tail>
<c_auth_publickey_query_rsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> <pk_alg_rsa> <pk_blob_rsa> <c_pkt_tail>
<c_auth_publickey_signed_rsa256> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_rsa256> <pk_blob_rsa> <pk_signature_rsa256> <c_pkt_tail>
<c_auth_publickey_signed_rsa512> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_rsa512> <pk_blob_rsa> <pk_signature_rsa512> <c_pkt_tail>
<c_auth_publickey_signed_sshrsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_sshrsa> <pk_blob_rsa> <pk_signature_sshrsa> <c_pkt_tail>
<c_auth_publickey_badsig> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg> <pk_blob> <pk_signature_bad> <c_pkt_tail>
<c_auth_publickey_signed_after_query_rsa256> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_rsa256> <pk_blob_rsa> <pk_signature_rsa256> <c_pkt_tail>
<c_auth_publickey_signed_after_query_rsa512> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_rsa512> <pk_blob_rsa> <pk_signature_rsa512> <c_pkt_tail>
<c_auth_publickey_signed_after_query_sshrsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_sshrsa> <pk_blob_rsa> <pk_signature_sshrsa> <c_pkt_tail>
<c_auth_hostbased_badsig> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_hostbased> <pk_alg> <pk_blob> <hostname_sent> <hostbased_user> <pk_signature_bad> <c_pkt_tail>
<c_auth_hostbased_unknown_alg> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_hostbased> <pk_alg_unknown> <pk_blob> <hostname_sent> <hostbased_user> <pk_signature_bad> <c_pkt_tail>
<c_auth_hostbased_other_host_key> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_hostbased> <pk_alg> <pk_blob_other> <hostname_sent> <hostbased_user> <pk_signature> <c_pkt_tail>
<pk_alg_ecdsa_p256> ::= <string_len> b"ecdsa-sha2-nistp256"
<pk_blob_ecdsa_p256> ::= <string_len> <pk_blob_alg_ecdsa_p256> <pk_ecdsa_curve_p256> <pk_ecdsa_q_p256>
<pk_blob_alg_ecdsa_p256> ::= <string_len> b"ecdsa-sha2-nistp256"
<pk_ecdsa_curve_p256> ::= <string_len> b"nistp256"
<pk_ecdsa_q_p256> ::= <string_len> <pk_ecdsa_q_value_p256>
<pk_ecdsa_q_value_p256> ::= rb'[\x00-\xff]+' := gen_ecdsa_q("p256")
<pk_signature_ecdsa_p256> ::= b"\x00\x00\x00\x63" <pk_signature_value>
<pk_alg_ecdsa_p384> ::= <string_len> b"ecdsa-sha2-nistp384"
<pk_blob_ecdsa_p384> ::= <string_len> <pk_blob_alg_ecdsa_p384> <pk_ecdsa_curve_p384> <pk_ecdsa_q_p384>
<pk_blob_alg_ecdsa_p384> ::= <string_len> b"ecdsa-sha2-nistp384"
<pk_ecdsa_curve_p384> ::= <string_len> b"nistp384"
<pk_ecdsa_q_p384> ::= <string_len> <pk_ecdsa_q_value_p384>
<pk_ecdsa_q_value_p384> ::= rb'[\x00-\xff]+' := gen_ecdsa_q("p384")
<pk_signature_ecdsa_p384> ::= b"\x00\x00\x00\x83" <pk_signature_value>
<pk_alg_ecdsa_p521> ::= <string_len> b"ecdsa-sha2-nistp521"
<pk_blob_ecdsa_p521> ::= <string_len> <pk_blob_alg_ecdsa_p521> <pk_ecdsa_curve_p521> <pk_ecdsa_q_p521>
<pk_blob_alg_ecdsa_p521> ::= <string_len> b"ecdsa-sha2-nistp521"
<pk_ecdsa_curve_p521> ::= <string_len> b"nistp521"
<pk_ecdsa_q_p521> ::= <string_len> <pk_ecdsa_q_value_p521>
<pk_ecdsa_q_value_p521> ::= rb'[\x00-\xff]+' := gen_ecdsa_q("p521")
<pk_signature_ecdsa_p521> ::= b"\x00\x00\x00\xa7" <pk_signature_value>
<pk_blob_ecdsa_own> ::= <string_len> <pk_blob_alg_ecdsa_p256> <pk_ecdsa_curve_p256> <pk_ecdsa_q_own>
<pk_ecdsa_q_own> ::= <string_len> <pk_ecdsa_q_own_value>
<pk_ecdsa_q_own_value> ::= rb'[\x00-\xff]+' := gen_ecdsa_q_own()
<pk_blob_rsa_other> ::= <string_len> <pk_blob_alg_sshrsa> <pk_rsa_e_other> <pk_rsa_n_other>
<pk_rsa_e_other> ::= <string_len> <pk_rsa_e_other_value>
<pk_rsa_e_other_value> ::= rb'[\x00-\xff]+' := gen_rsa_e_other()
<pk_rsa_n_other> ::= <string_len> <pk_rsa_n_other_value>
<pk_rsa_n_other_value> ::= rb'[\x00-\xff]+' := gen_rsa_n_other()
<pk_signature_rsa256_bad> ::= b"\x00\x00\x01\x14\x00\x00\x00\x0crsa-sha2-256\x00\x00\x01\x00" <byte>{256}
<pk_signature_rsa512_bad> ::= b"\x00\x00\x01\x14\x00\x00\x00\x0crsa-sha2-512\x00\x00\x01\x00" <byte>{256}
<pk_signature_sshrsa_bad> ::= b"\x00\x00\x01\x0f\x00\x00\x00\x07ssh-rsa\x00\x00\x01\x00" <byte>{256}
<pk_alg_dss> ::= <string_len> b"ssh-dss"
<pk_blob_dss> ::= <string_len> <pk_blob_alg_dss> <pk_dss_p> <pk_dss_q> <pk_dss_g> <pk_dss_y>
<pk_blob_alg_dss> ::= <string_len> b"ssh-dss"
<pk_dss_p> ::= <string_len> <pk_dss_p_value>
<pk_dss_p_value> ::= rb'[\x00-\xff]+' := gen_dss("p")
<pk_dss_q> ::= <string_len> <pk_dss_q_value>
<pk_dss_q_value> ::= rb'[\x00-\xff]+' := gen_dss("q")
<pk_dss_g> ::= <string_len> <pk_dss_g_value>
<pk_dss_g_value> ::= rb'[\x00-\xff]+' := gen_dss("g")
<pk_dss_y> ::= <string_len> <pk_dss_y_value>
<pk_dss_y_value> ::= rb'[\x00-\xff]+' := gen_dss("y")
<pk_signature_dss> ::= b"\x00\x00\x00\x37" <pk_signature_value>
<pk_alg_ed448> ::= <string_len> b"ssh-ed448"
<pk_blob_ed448> ::= <string_len> <pk_blob_alg_ed448> <pk_ed448_key>
<pk_blob_alg_ed448> ::= <string_len> b"ssh-ed448"
<pk_ed448_key> ::= <string_len> <pk_ed448_value>
<pk_ed448_value> ::= rb'[\x00-\xff]{57}' := gen_ed448_pub()
<pk_signature_ed448> ::= b"\x00\x00\x00\x83" <pk_signature_value>
<c_auth_publickey_query_foreign> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> (<pk_alg_ecdsa_p256> <pk_blob_ecdsa_p256> | <pk_alg_ecdsa_p384> <pk_blob_ecdsa_p384> | <pk_alg_ecdsa_p521> <pk_blob_ecdsa_p521> | <pk_alg_dss> <pk_blob_dss> | <pk_alg_ed448> <pk_blob_ed448>) <c_pkt_tail>
<c_auth_publickey_signed_foreign> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> (<pk_alg_ecdsa_p256> <pk_blob_ecdsa_p256> <pk_signature_ecdsa_p256> | <pk_alg_ecdsa_p384> <pk_blob_ecdsa_p384> <pk_signature_ecdsa_p384> | <pk_alg_ecdsa_p521> <pk_blob_ecdsa_p521> <pk_signature_ecdsa_p521> | <pk_alg_dss> <pk_blob_dss> <pk_signature_dss> | <pk_alg_ed448> <pk_blob_ed448> <pk_signature_ed448>) <c_pkt_tail>
<c_auth_publickey_signed_ecdsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_ecdsa_p256> <pk_blob_ecdsa_own> <pk_signature_ecdsa_p256> <c_pkt_tail>
<c_auth_publickey_query_ecdsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> <pk_alg_ecdsa_p256> <pk_blob_ecdsa_own> <c_pkt_tail>
<c_auth_publickey_signed_after_query_ecdsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_ecdsa_p256> <pk_blob_ecdsa_own> <pk_signature_ecdsa_p256> <c_pkt_tail>
<c_auth_publickey_other_key_rsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> (<pk_alg_rsa256> <pk_blob_rsa_other> <pk_signature_rsa256> | <pk_alg_rsa512> <pk_blob_rsa_other> <pk_signature_rsa512> | <pk_alg_sshrsa> <pk_blob_rsa_other> <pk_signature_sshrsa>) <c_pkt_tail>
<c_auth_publickey_badsig_rsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> (<pk_alg_rsa256> <pk_blob_rsa> <pk_signature_rsa256_bad> | <pk_alg_rsa512> <pk_blob_rsa> <pk_signature_rsa512_bad> | <pk_alg_sshrsa> <pk_blob_rsa> <pk_signature_sshrsa_bad>) <c_pkt_tail>
<c_auth_hostbased_foreign> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_hostbased> (<pk_alg_rsa256> <pk_blob_rsa> <hostname_sent> <hostbased_user> <pk_signature_rsa256> | <pk_alg_rsa512> <pk_blob_rsa> <hostname_sent> <hostbased_user> <pk_signature_rsa512> | <pk_alg_sshrsa> <pk_blob_rsa> <hostname_sent> <hostbased_user> <pk_signature_sshrsa> | <pk_alg_ecdsa_p256> <pk_blob_ecdsa_p256> <hostname_sent> <hostbased_user> <pk_signature_ecdsa_p256> | <pk_alg_ecdsa_p384> <pk_blob_ecdsa_p384> <hostname_sent> <hostbased_user> <pk_signature_ecdsa_p384> | <pk_alg_ecdsa_p521> <pk_blob_ecdsa_p521> <hostname_sent> <hostbased_user> <pk_signature_ecdsa_p521> | <pk_alg_ecdsa_p256> <pk_blob_ecdsa_own> <hostname_sent> <hostbased_user> <pk_signature_ecdsa_p256> | <pk_alg_dss> <pk_blob_dss> <hostname_sent> <hostbased_user> <pk_signature_dss> | <pk_alg_ed448> <pk_blob_ed448> <hostname_sent> <hostbased_user> <pk_signature_ed448>) <c_pkt_tail>
<hostbased_user> ::= <user_valid> | <user_bad>
<c_auth_publickey_badsig_ecdsa> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg_ecdsa_p256> <pk_blob_ecdsa_own> <pk_signature_ecdsa_p256_bad> <c_pkt_tail>
<c_auth_publickey_query_rsa_other> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_false> <pk_alg_rsa> <pk_blob_rsa_other> <c_pkt_tail>
<pk_signature_ecdsa_p256_bad> ::= b"\x00\x00\x00\x63\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x48" <byte>{72}
<c_auth_publickey_signed_after_query> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_publickey> <boolean_true> <pk_alg> <pk_blob> <pk_signature> <c_pkt_tail>
<c_auth_kbdint> ::= <c_pkt_head> b"\x32" <user_valid> <service_connection> <method_kbdint> <lang_tag_sent> <submethods_sent> <c_pkt_tail>
<submethods_sent> ::= <string_len> <submethods_value>
<submethods_value> ::= <text_chunk>? := gen_submethods()
# RFC 4252 7: the signature is over the session identifier and the request up to the signature
where forall <m> in <c_auth_publickey_signed>: <m>.<pk_signature>.<pk_signature_value> == pk_sign(<m>)
# RFC 4252 7: a request with a key the user has not authorized, signed correctly by that key's own private key
where forall <m> in <c_auth_publickey_other_key>: <m>.<pk_signature>.<pk_signature_value> == pk_sign(<m>)
# the signatures of the RSA, ECDSA, DSA and Ed448 keys: one rule per signature format, whichever request carries it
where forall <s> in <pk_signature_rsa256>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_rsa512>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_sshrsa>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_ecdsa_p256>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_ecdsa_p384>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_ecdsa_p521>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_dss>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <s> in <pk_signature_ed448>: <s>.<pk_signature_value> == pk_sign(<s>.parent)
where forall <m> in <c_auth_publickey_signed_after_query>: <m>.<pk_signature>.<pk_signature_value> == pk_sign(<m>)
where forall <m> in <c_auth_hostbased_other_host_key>: <m>.<pk_signature>.<pk_signature_value> == pk_sign(<m>)
# RFC 4252 9: the hostbased signature is over the session identifier and the request up to the signature
where forall <m> in <c_auth_hostbased>: <m>.<pk_signature>.<pk_signature_value> == pk_sign(<m>)
<s_userauth_failure> ::= <s_pkt_head> b"\x33" <name_list> <boolean> <s_pkt_tail>
<s_userauth_failure_not_partial> ::= <s_pkt_head> b"\x33" <name_list> <boolean_false> <s_pkt_tail>
# RFC 4252 5.2: the method name "none" must not be listed
where forall <f> in <s_userauth_failure>: "none" not in name_list_names(<f>.<name_list>)
where forall <f> in <s_userauth_failure_not_partial>: "none" not in name_list_names(<f>.<name_list>)
<s_userauth_success> ::= <s_pkt_head> b"\x34" <s_pkt_tail>
# RFC 8308 3.1: SUCCESS after a signed publickey request: the algorithm has to be in the server's server-sig-algs list (when it sent one)
where forall <m> in <s_userauth_success>: pk_success_enumerated(<m>)
<s_userauth_banner> ::= <s_pkt_head> b"\x35" <string> <string> <s_pkt_tail>
<s_userauth_passwd_changereq> ::= <s_pkt_head> b"\x3c" <string> <string> <s_pkt_tail>
<s_userauth_pk_ok> ::= <s_pkt_head> b"\x3c" <string> <string> <s_pkt_tail>
# RFC 4252 7: PK_OK echoes the algorithm name and the key blob of the query
where forall <m> in <s_userauth_pk_ok>: pk_ok_echoes(<m>)
# RFC 8308 3.1: the algorithm the server accepts has to be in its server-sig-algs list (when it sent one)
where forall <m> in <s_userauth_pk_ok>: pk_alg_enumerated(<m>)
<s_info_request_one> ::= <s_pkt_head> b"\x3c" <string> <string> <string> <prompt_count_one> <prompt_item> <s_pkt_tail>
<s_info_request_many> ::= <s_pkt_head> b"\x3c" <string> <string> <string> <prompt_count_many> <prompt_item>{count_of(<prompt_count_many>)} <s_pkt_tail>
<s_info_request_empty> ::= <s_pkt_head> b"\x3c" <string> <string> <string> <prompt_count_zero> <s_pkt_tail>
<prompt_count_zero> ::= b"\x00\x00\x00\x00"
<prompt_count_one> ::= b"\x00\x00\x00\x01"
<prompt_count_many> ::= b"\x00\x00\x00" rb'[\x02-\xff]' | b"\x00\x00" rb'[\x01-\xff]' <byte> | b"\x00" rb'[\x01-\xff]' <byte>{2} | rb'[\x01-\xff]' <byte>{3}
<prompt_item> ::= <string> <boolean>
where forall <i> in <prompt_item>: len(bytes(<i>.<string>.<string_data>)) > 0
<c_info_response_one_ok> ::= <c_pkt_head> b"\x3d" <prompt_count_one> <response_valid> <c_pkt_tail>
<c_info_response_one_bad> ::= <c_pkt_head> b"\x3d" <prompt_count_one> <response_bad> <c_pkt_tail>
<c_info_response_many_ok> ::= <c_pkt_head> b"\x3d" <response_count> <response_valid>{count_of(<response_count>)} <c_pkt_tail>
<c_info_response_many_bad> ::= <c_pkt_head> b"\x3d" <response_count> <response_bad>{count_of(<response_count>)} <c_pkt_tail>
<c_info_response_empty> ::= <c_pkt_head> b"\x3d" <prompt_count_zero> <c_pkt_tail>
<response_count> ::= <uint32> := gen_response_count()
<response_valid> ::= <string_len> <response_value>
<response_value> ::= <text_chunk>? := gen_response()
<response_bad> ::= <string_len> <bad_password_value>
# ---------------------------------------------------------------- connection protocol (RFC 4254)
<local_channel_sent> ::= <uint32> := gen_local_channel()
<remote_channel_sent> ::= <uint32> := gen_remote_channel()
<window_sent> ::= <uint32> := gen_window()
<maxpacket_sent> ::= <uint32> := gen_maxpacket()
<recipient_channel_s> ::= <uint32>
where forall <r> in <recipient_channel_s>: <r> == u32(SSH.local_channel)
# the channel number the server gave in its OPEN_CONFIRMATION (recorded by ClientNetworkParty, recalled by gen_remote_channel)
where forall <r> in <remote_channel_sent>: <r> == u32(SSH.remote_channel)
<local_channel_2_sent> ::= b"\x00\x00\x10\x00"
<recipient_channel_2_s> ::= b"\x00\x00\x10\x00"
<remote_channel_2_sent> ::= <uint32> := gen_remote_channel_2()
# the channel number the server gave the second channel (recorded by ClientNetworkParty, recalled by gen_remote_channel_2)
where forall <r> in <remote_channel_2_sent>: <r> == u32(SSH.remote_channel_2)
<c_channel_open_session_2> ::= <c_pkt_head> b"\x5a" <chtype_session> <local_channel_2_sent> <window_sent> <maxpacket_sent> <c_pkt_tail>
<s_channel_open_confirmation_2> ::= <s_pkt_head> b"\x5b" <recipient_channel_2_s> <uint32> <uint32> <uint32> <s_pkt_tail>
<s_channel_open_failure_2> ::= <s_pkt_head> b"\x5c" <recipient_channel_2_s> <open_failure_reason> <string> <string> <s_pkt_tail>
# RFC 4254 5.1: the reason code is 3 when the channel type is not understood (the unknown type of the second open)
where forall <m> in <s_channel_open_failure_2>: open_failure_code_ok(<m>)
<c_channel_open_direct_tcpip_2> ::= <c_pkt_head> b"\x5a" <chtype_direct_tcpip> <local_channel_2_sent> <window_sent> <maxpacket_sent> <forward_host> <forward_port> <originator_host> <originator_port> <c_pkt_tail>
<c_channel_open_x11_2> ::= <c_pkt_head> b"\x5a" <chtype_x11> <local_channel_2_sent> <window_sent> <maxpacket_sent> <originator_host> <originator_port> <c_pkt_tail>
<c_channel_open_forwarded_tcpip_2> ::= <c_pkt_head> b"\x5a" <chtype_forwarded_tcpip> <local_channel_2_sent> <window_sent> <maxpacket_sent> <bind_address> <bind_port> <originator_host> <originator_port> <c_pkt_tail>
<c_channel_open_unknown_2> ::= <c_pkt_head> b"\x5a" <chtype_unknown> <local_channel_2_sent> <window_sent> <maxpacket_sent> <c_pkt_tail>
<s_channel_data_2> ::= <s_pkt_head> b"\x5e" <recipient_channel_2_s> <string> <s_pkt_tail>
<s_channel_extended_data_2> ::= <s_pkt_head> b"\x5f" <recipient_channel_2_s> <extended_data_type> <string> <s_pkt_tail>
<s_channel_eof_2> ::= <s_pkt_head> b"\x60" <recipient_channel_2_s> <s_pkt_tail>
<s_channel_window_adjust_2> ::= <s_pkt_head> b"\x5d" <recipient_channel_2_s> <uint32> <s_pkt_tail>
<c_channel_close_2> ::= <c_pkt_head> b"\x61" <remote_channel_2_sent> <c_pkt_tail>
<s_channel_close_2> ::= <s_pkt_head> b"\x61" <recipient_channel_2_s> <s_pkt_tail>
# RFC 8308 3.3: when no-flow-control is in effect the server MUST refuse more than one simultaneous channel
where forall <m> in <s_channel_open_confirmation_2>: not SSH.nfc_effect
<req_tcpip_forward> ::= <string_len> b"tcpip-forward"
<req_cancel_tcpip_forward> ::= <string_len> b"cancel-tcpip-forward"
<req_unknown_global> ::= <string_len> <req_unknown_global_value>
<req_unknown_global_value> ::= <byte>* := gen_unknown_request()
<bind_address> ::= <string_len> <bind_address_value>
<bind_address_value> ::= <byte>* := gen_bind_address()
<bind_port> ::= <uint32> := gen_bind_port()
<bind_address_cancel> ::= <string_len> <bind_address_cancel_value>
<bind_address_cancel_value> ::= <byte>* := gen_cancel_address()
<bind_port_cancel> ::= <uint32> := gen_cancel_port()
<c_global_request_forward_want> ::= <c_pkt_head> b"\x50" <req_tcpip_forward> <boolean_true> <bind_address> <bind_port> <c_pkt_tail>
<c_global_request_cancel_want> ::= <c_pkt_head> b"\x50" <req_cancel_tcpip_forward> <boolean_true> <bind_address_cancel> <bind_port_cancel> <c_pkt_tail>
<c_global_request_unknown_want> ::= <c_pkt_head> b"\x50" <req_unknown_global> <boolean_true> <c_pkt_tail>
<c_global_request_forward_nowant> ::= <c_pkt_head> b"\x50" <req_tcpip_forward> <boolean_false> <bind_address> <bind_port> <c_pkt_tail>
<c_global_request_cancel_nowant> ::= <c_pkt_head> b"\x50" <req_cancel_tcpip_forward> <boolean_false> <bind_address_cancel> <bind_port_cancel> <c_pkt_tail>
<c_global_request_unknown_nowant> ::= <c_pkt_head> b"\x50" <req_unknown_global> <boolean_false> <c_pkt_tail>
<s_global_request_nowant> ::= <s_pkt_head> b"\x50" <string> <boolean_false> <byte>{rest_count(<string>, 1)} <s_pkt_tail>
<s_global_request_want> ::= <s_pkt_head> b"\x50" <string> <boolean_nonzero> <byte>{rest_count(<string>, 1)} <s_pkt_tail>
<boolean_nonzero> ::= rb'[\x01-\xff]'
<s_request_success> ::= <s_pkt_head> b"\x51" <byte>{rest_count(<s_pkt_head>, 1)} <s_pkt_tail>
<s_request_failure> ::= <s_pkt_head> b"\x52" <s_pkt_tail>
<c_request_failure> ::= <c_pkt_head> b"\x52" <c_pkt_tail>
<c_channel_open_session> ::= <c_pkt_head> b"\x5a" <chtype_session> <local_channel_sent> <window_sent> <maxpacket_sent> <c_pkt_tail>
<c_channel_open_direct_tcpip> ::= <c_pkt_head> b"\x5a" <chtype_direct_tcpip> <local_channel_sent> <window_sent> <maxpacket_sent> <forward_host> <forward_port> <originator_host> <originator_port> <c_pkt_tail>
<c_channel_open_x11> ::= <c_pkt_head> b"\x5a" <chtype_x11> <local_channel_sent> <window_sent> <maxpacket_sent> <originator_host> <originator_port> <c_pkt_tail>
<c_channel_open_forwarded_tcpip> ::= <c_pkt_head> b"\x5a" <chtype_forwarded_tcpip> <local_channel_sent> <window_sent> <maxpacket_sent> <bind_address> <bind_port> <originator_host> <originator_port> <c_pkt_tail>
<c_channel_open_unknown> ::= <c_pkt_head> b"\x5a" <chtype_unknown> <local_channel_sent> <window_sent> <maxpacket_sent> <c_pkt_tail>
<chtype_session> ::= <string_len> b"session"
<chtype_direct_tcpip> ::= <string_len> b"direct-tcpip"
<chtype_x11> ::= <string_len> b"x11"
<chtype_forwarded_tcpip> ::= <string_len> b"forwarded-tcpip"
<chtype_unknown> ::= <string_len> <chtype_unknown_value>
<chtype_unknown_value> ::= <byte>* := gen_unknown_channel_type()
<forward_host> ::= <string_len> <forward_host_value>
<forward_host_value> ::= <byte>* := gen_forward_host()
<forward_port> ::= <uint32> := gen_forward_port()
<originator_host> ::= <string_len> <originator_host_value>
<originator_host_value> ::= <byte>* := gen_originator_host()
<originator_port> ::= <uint32> := gen_originator_port()
<s_channel_open_confirmation> ::= <s_pkt_head> b"\x5b" <recipient_channel_s> <uint32> <uint32> <uint32> <s_pkt_tail>
<s_channel_open_confirmation_tcpip> ::= <s_pkt_head> b"\x5b" <recipient_channel_s> <uint32> <uint32> <uint32> <s_pkt_tail>
<s_channel_open_failure> ::= <s_pkt_head> b"\x5c" <recipient_channel_s> <open_failure_reason> <string> <string> <s_pkt_tail>
# RFC 4254 5.1: the same for a failure that answers the open of an unknown type
where forall <m> in <s_channel_open_failure>: open_failure_code_ok(<m>)
<s_channel_open_failure_unknown_type> ::= <s_pkt_head> b"\x5c" <recipient_channel_s> <of_unknown_channel_type> <string> <string> <s_pkt_tail>
<open_failure_reason> ::= <of_administratively_prohibited> | <of_connect_failed> | <of_unknown_channel_type> | <of_resource_shortage> | <of_other>
<of_administratively_prohibited> ::= b"\x00\x00\x00\x01"
<of_connect_failed> ::= b"\x00\x00\x00\x02"
<of_unknown_channel_type> ::= b"\x00\x00\x00\x03"
<of_resource_shortage> ::= b"\x00\x00\x00\x04"
<of_other> ::= b"\x00\x00\x00" rb'[\x05-\xff]' | b"\x00\x00" rb'[\x01-\xff]' <byte> | b"\x00" rb'[\x01-\xff]' <byte>{2} | rb'[\x01-\xff]' <byte>{3}
<c_channel_data> ::= <c_pkt_head> b"\x5e" <remote_channel_sent> <data_sent> <c_pkt_tail>
<c_channel_window_adjust> ::= <c_pkt_head> b"\x5d" <remote_channel_sent> <window_sent> <c_pkt_tail>
<c_channel_extended_data> ::= <c_pkt_head> b"\x5f" <remote_channel_sent> <extended_type_sent> <data_sent> <c_pkt_tail>
# RFC 4254 5.2, RFC 4250 4.9.3: data_type_code 1 is stderr; other codes are unassigned
<extended_type_sent> ::= <ext_stderr> | <ext_other>
<c_channel_eof> ::= <c_pkt_head> b"\x60" <remote_channel_sent> <c_pkt_tail>
<c_channel_close> ::= <c_pkt_head> b"\x61" <remote_channel_sent> <c_pkt_tail>
<s_channel_data> ::= <s_pkt_head> b"\x5e" <recipient_channel_s> <string> <s_pkt_tail>
<s_channel_extended_data> ::= <s_pkt_head> b"\x5f" <recipient_channel_s> <extended_data_type> <string> <s_pkt_tail>
<extended_data_type> ::= <ext_stderr> | <ext_other>
<ext_stderr> ::= b"\x00\x00\x00\x01"
<ext_other> ::= b"\x00\x00\x00" rb'[\x02-\xff]' | b"\x00\x00" rb'[\x01-\xff]' <byte> | b"\x00" rb'[\x01-\xff]' <byte>{2} | rb'[\x01-\xff]' <byte>{3}
<s_channel_window_adjust> ::= <s_pkt_head> b"\x5d" <recipient_channel_s> <uint32> <s_pkt_tail>
<s_channel_eof> ::= <s_pkt_head> b"\x60" <recipient_channel_s> <s_pkt_tail>
<s_channel_close> ::= <s_pkt_head> b"\x61" <recipient_channel_s> <s_pkt_tail>
<s_channel_success> ::= <s_pkt_head> b"\x63" <recipient_channel_s> <s_pkt_tail>
<s_channel_failure> ::= <s_pkt_head> b"\x64" <recipient_channel_s> <s_pkt_tail>
<s_channel_request_exit_status> ::= <s_pkt_head> b"\x62" <recipient_channel_s> <rt_exit_status> <boolean_false> <uint32> <s_pkt_tail>
<s_channel_request_other> ::= <s_pkt_head> b"\x62" <recipient_channel_s> <string> <boolean_false> <byte>{rest_count(<string>, 1)} <s_pkt_tail>
<s_channel_request_other_want> ::= <s_pkt_head> b"\x62" <recipient_channel_s> <string> <boolean_nonzero> <byte>{rest_count(<string>, 1)} <s_pkt_tail>
<c_channel_failure> ::= <c_pkt_head> b"\x64" <remote_channel_sent> <c_pkt_tail>
# a request of the server other than exit-status and exit-signal (RFC 4254 5.4: local extensions name@domain)
where forall <r> in <s_channel_request_other>: bytes(<r>.<string>.<string_data>) not in (b"exit-status", b"exit-signal", b"xon-xoff")
where forall <r> in <s_channel_request_other_want>: bytes(<r>.<string>.<string_data>) not in (b"exit-status", b"exit-signal", b"xon-xoff")
<s_channel_request_xon_xoff> ::= <s_pkt_head> b"\x62" <recipient_channel_s> <rt_xon_xoff> <boolean_false> <boolean> <s_pkt_tail>
<s_channel_request_exit_signal> ::= <s_pkt_head> b"\x62" <recipient_channel_s> <rt_exit_signal> <boolean_false> <signal_name> <boolean> <string> <string> <s_pkt_tail>
<rt_exit_status> ::= <string_len> b"exit-status"
<rt_exit_signal> ::= <string_len> b"exit-signal"
<rt_pty_req> ::= <string_len> b"pty-req"
<rt_x11_req> ::= <string_len> b"x11-req"
<rt_env> ::= <string_len> b"env"
<rt_shell> ::= <string_len> b"shell"
<rt_exec> ::= <string_len> b"exec"
<rt_subsystem> ::= <string_len> b"subsystem"
<rt_window_change> ::= <string_len> b"window-change"
<rt_xon_xoff> ::= <string_len> b"xon-xoff"
<rt_signal> ::= <string_len> b"signal"
<rt_unknown> ::= <string_len> <rt_unknown_value>
<rt_unknown_value> ::= <byte>* := gen_unknown_request()
<c_channel_request_pty_req_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_pty_req> <boolean_true> <term_sent> <uint32_dim> <uint32_dim> <uint32_dim> <uint32_dim> <terminal_modes> <c_pkt_tail>
<c_channel_request_pty_req_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_pty_req> <boolean_false> <term_sent> <uint32_dim> <uint32_dim> <uint32_dim> <uint32_dim> <terminal_modes> <c_pkt_tail>
<c_channel_request_x11_req_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_x11_req> <boolean_true> <boolean_sent> <x11_proto> <x11_cookie> <uint32_dim> <c_pkt_tail>
<c_channel_request_x11_req_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_x11_req> <boolean_false> <boolean_sent> <x11_proto> <x11_cookie> <uint32_dim> <c_pkt_tail>
<c_channel_request_env_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_env> <boolean_true> <env_name_sent> <env_value_sent> <c_pkt_tail>
<c_channel_request_env_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_env> <boolean_false> <env_name_sent> <env_value_sent> <c_pkt_tail>
<c_channel_request_shell_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_shell> <boolean_true> <c_pkt_tail>
<c_channel_request_shell_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_shell> <boolean_false> <c_pkt_tail>
<c_channel_request_exec_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_exec> <boolean_true> <exec_command> <c_pkt_tail>
<c_channel_request_exec_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_exec> <boolean_false> <exec_command> <c_pkt_tail>
<c_channel_request_subsystem_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_subsystem> <boolean_true> <subsystem_sent> <c_pkt_tail>
<c_channel_request_subsystem_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_subsystem> <boolean_false> <subsystem_sent> <c_pkt_tail>
<c_channel_request_window_change_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_window_change> <boolean_false> <uint32_dim> <uint32_dim> <uint32_dim> <uint32_dim> <c_pkt_tail>
<c_channel_request_signal_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_signal> <boolean_false> <signal_name> <c_pkt_tail>
<c_channel_request_unknown_want> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_unknown> <boolean_true> <c_pkt_tail>
<c_channel_request_unknown_nowant> ::= <c_pkt_head> b"\x62" <remote_channel_sent> <rt_unknown> <boolean_false> <c_pkt_tail>
<uint32_dim> ::= <uint32> := gen_dimension()
<term_sent> ::= <string_len> <term_value>
<term_value> ::= <byte>* := gen_term()
<x11_proto> ::= <string_len> <x11_proto_value>
<x11_proto_value> ::= <byte>* := gen_x11_proto()
<x11_cookie> ::= <string_len> <x11_cookie_value>
<x11_cookie_value> ::= rb'[0-9a-f]{32}' := gen_x11_cookie()
<env_name_sent> ::= <string_len> <env_name_value>
<env_name_value> ::= <byte>* := gen_env_name()
<env_value_sent> ::= <string_len> <env_value_value>
<env_value_value> ::= <byte>* := gen_env_value()
<exec_command> ::= <string_len> <exec_command_value>
<exec_command_value> ::= <byte>* := gen_exec_command()
<subsystem_sent> ::= <string_len> <subsystem_value>
<subsystem_value> ::= <byte>* := gen_subsystem()
<signal_name> ::= <string_len> <signal_value>
# RFC 4254 6.9: POSIX signal names without the "SIG" prefix, or sig-name@xyz (RFC 4251 6 naming)
<signal_value> ::= <signal_std> | <signal_ext>
<signal_std> ::= b"ABRT" | b"ALRM" | b"FPE" | b"HUP" | b"ILL" | b"INT" | b"KILL" | b"PIPE" | b"QUIT" | b"SEGV" | b"TERM" | b"USR1" | b"USR2"
<signal_ext> ::= <signal_ext_name> b"@" <signal_ext_domain>
<signal_ext_name> ::= <signal_ext_char>*
<signal_ext_domain> ::= <signal_ext_char>*
<signal_ext_char> ::= rb'[\x00-\x3f\x41-\xff]'
# RFC 4254 8: encoded terminal modes: opcode / uint32 argument pairs ending with TTY_OP_END
<terminal_modes> ::= <string_len> <tty_mode>* (<tty_op_end> | <tty_stop>)
# opcodes 160 to 255 stop the parsing; anything may follow (RFC 4254 8)
<tty_stop> ::= rb'[\xa0-\xff]' <byte>*
<tty_op_end> ::= b"\x00"
<tty_mode> ::= <tty_opcode> <uint32> | <tty_unassigned> <uint32>
# opcodes 1 to 159 without an assigned meaning: one uint32 argument each; the server may ignore them
<tty_unassigned> ::= rb'[\x13-\x1d]' | rb'[\x2b-\x31]' | rb'[\x3f-\x45]' | rb'[\x4c-\x59]' | rb'[\x5e-\x7f]' | rb'[\x82-\x9f]'

<tty_opcode> ::= <tty_VFLUSH> | <tty_VSWTCH> | <tty_VINTR> | <tty_VQUIT> | <tty_VERASE> | <tty_VKILL> | <tty_VEOF> | <tty_VEOL> | <tty_VEOL2> | <tty_VSTART> | <tty_VSTOP> | <tty_VSUSP> | <tty_VDSUSP> | <tty_VREPRINT> | <tty_VWERASE> | <tty_VLNEXT> | <tty_VSTATUS> | <tty_VDISCARD> | <tty_IGNPAR> | <tty_PARMRK> | <tty_INPCK> | <tty_ISTRIP> | <tty_INLCR> | <tty_IGNCR> | <tty_ICRNL> | <tty_IUCLC> | <tty_IXON> | <tty_IXANY> | <tty_IXOFF> | <tty_IMAXBEL> | <tty_IUTF8> | <tty_ISIG> | <tty_ICANON> | <tty_XCASE> | <tty_ECHO> | <tty_ECHOE> | <tty_ECHOK> | <tty_ECHONL> | <tty_NOFLSH> | <tty_TOSTOP> | <tty_IEXTEN> | <tty_ECHOCTL> | <tty_ECHOKE> | <tty_PENDIN> | <tty_OPOST> | <tty_OLCUC> | <tty_ONLCR> | <tty_OCRNL> | <tty_ONOCR> | <tty_ONLRET> | <tty_CS7> | <tty_CS8> | <tty_PARENB> | <tty_PARODD> | <tty_TTY_OP_ISPEED> | <tty_TTY_OP_OSPEED>
<tty_VFLUSH> ::= b"\x0f"
<tty_VSWTCH> ::= b"\x10"
<tty_VINTR> ::= b"\x01"
<tty_VQUIT> ::= b"\x02"
<tty_VERASE> ::= b"\x03"
<tty_VKILL> ::= b"\x04"
<tty_VEOF> ::= b"\x05"
<tty_VEOL> ::= b"\x06"
<tty_VEOL2> ::= b"\x07"
<tty_VSTART> ::= b"\x08"
<tty_VSTOP> ::= b"\x09"
<tty_VSUSP> ::= b"\x0a"
<tty_VDSUSP> ::= b"\x0b"
<tty_VREPRINT> ::= b"\x0c"
<tty_VWERASE> ::= b"\x0d"
<tty_VLNEXT> ::= b"\x0e"
<tty_VSTATUS> ::= b"\x11"
<tty_VDISCARD> ::= b"\x12"
<tty_IGNPAR> ::= b"\x1e"
<tty_PARMRK> ::= b"\x1f"
<tty_INPCK> ::= b"\x20"
<tty_ISTRIP> ::= b"\x21"
<tty_INLCR> ::= b"\x22"
<tty_IGNCR> ::= b"\x23"
<tty_ICRNL> ::= b"\x24"
<tty_IUCLC> ::= b"\x25"
<tty_IXON> ::= b"\x26"
<tty_IXANY> ::= b"\x27"
<tty_IXOFF> ::= b"\x28"
<tty_IMAXBEL> ::= b"\x29"
<tty_IUTF8> ::= b"\x2a"
<tty_ISIG> ::= b"\x32"
<tty_ICANON> ::= b"\x33"
<tty_XCASE> ::= b"\x34"
<tty_ECHO> ::= b"\x35"
<tty_ECHOE> ::= b"\x36"
<tty_ECHOK> ::= b"\x37"
<tty_ECHONL> ::= b"\x38"
<tty_NOFLSH> ::= b"\x39"
<tty_TOSTOP> ::= b"\x3a"
<tty_IEXTEN> ::= b"\x3b"
<tty_ECHOCTL> ::= b"\x3c"
<tty_ECHOKE> ::= b"\x3d"
<tty_PENDIN> ::= b"\x3e"
<tty_OPOST> ::= b"\x46"
<tty_OLCUC> ::= b"\x47"
<tty_ONLCR> ::= b"\x48"
<tty_OCRNL> ::= b"\x49"
<tty_ONOCR> ::= b"\x4a"
<tty_ONLRET> ::= b"\x4b"
<tty_CS7> ::= b"\x5a"
<tty_CS8> ::= b"\x5b"
<tty_PARENB> ::= b"\x5c"
<tty_PARODD> ::= b"\x5d"
<tty_TTY_OP_ISPEED> ::= b"\x80"
<tty_TTY_OP_OSPEED> ::= b"\x81"

# ======================================================================================================
# Omissions (each with the spec section and the nearest nonterminal)
# ======================================================================================================
# TODO: RFC 4253 6.2 (payload compression "zlib"; RFC 1950/1951 are left out by refs/spec/manifest.json), nearest <comp_list_none>: the format of the compressed layer is another protocol; only "none" is offered in the KEXINIT lists and in the delay-compression extension, so the switch to the compressed layer is never made
# TODO: RFC 4253 7 (a right guess for the servers under test), nearest <ecdh_right_state>: the right guess (<c_kexinit_ecdh_right>, <c_kexinit_dh_right>, <c_kexinit_gex_right> with <ecdh_right_state>, <dh_right_state>, <gex_right_state>) and the guess that is wrong only in the host key algorithm (<c_kexinit_*_hostguess>) are derived for all three families; the first kex names of the three servers (sntrup761x25519-sha512, mlkem768x25519-sha256, ...) are methods that ClientNetworkParty does not implement (cryptography the protocol's own specification does not define), so on them the guess is wrong in effect (the server ignores it and the client sends its packet after the timer ran out); a guess after the KEXINIT of a re-exchange is not modeled: the combination would copy the re-exchange states
# TODO: RFC 5656 5 (completion of an ecmqv-sha2 exchange), nearest <ecmqv_reply_state>: the negotiation (<c_kexinit_ecmqv> with an ECC host key list), SSH_MSG_ECMQV_INIT (<c_ecmqv_init>) and the server's refusals / SSH_MSG_ECMQV_REPLY are modeled; the ECMQV key agreement itself is defined by SEC 1 and NIST SP 800-56A, which are not in refs/spec, so the exchange ends with the client's DISCONNECT after a reply
# TODO: RFC 4253 6.6 (pgp-sign-rsa, pgp-sign-dss host keys), nearest <host_key_blob>: the key and signature formats are OpenPGP formats (RFC 4880), which are not in refs/spec; ssh-dss, ssh-rsa, ssh-ed25519, ssh-ed448 and ecdsa-sha2-* keys are verified
# TODO: RFC 4344 4, RFC 4253 6.3 (twofish*, serpent* ciphers), nearest <cipher_list_c2s>: the algorithms are not in refs/spec and not in the cryptography library; the other ciphers of both RFCs are implemented
# TODO: RFC 5656 10.2 (the binary-field curves nistk163, nistk233, nistb233, nistk283, nistk409, nistb409, nistt571 with the OIDs 1.3.132.0.1, 26, 27, 16, 36, 37, 38), nearest <kex_list_ecdh_unannounced>: the cryptography library has no binary-field curves and their domain parameters (SEC 2) are not in refs/spec; the OID-named curves nistp192 (1.2.840.10045.3.1.1) and nistp224 (1.3.132.0.33) are offered in <c_kexinit_ecdh_unannounced>
# TODO: RFC 5646 2.1 (language tag syntax), nearest <languages_client_to_server>: received language lists are accepted as name-lists; sent tags are a few valid ones
# TODO: RFC 3629 (UTF-8), nearest <s_disconnect>: description strings of received messages are not checked for UTF-8
# TODO: RFC 8308 3.4 (elevation), nearest <extension>: elevation is a user-level extension whose effect on the session is not defined by the transport; the effect of delay-compression (SshSession._ext_effect, <c_newcompress_after_success>) and of no-flow-control (nfc_effect) is tracked, the zlib layer itself is another protocol
# TODO: RFC 8308 3.2.1 (a client re-exchange in <service_state>, <auth_state> and the authentication sub-states in a session that did not signal delay-compression), nearest <service_state>: the MUST NOT binds the client only after it signaled the extension, which only the client's EXT_INFO shows; offering <rekey_client> there only in sessions that did not signal it would need a copy of each of these states per announced extension, which the rules for building the grammar forbid; the only client-started re-exchange left in them is <rekey_term>, which accepts every reply of the server (DISCONNECT, UNIMPLEMENTED, silence, completion)
# TODO: RFC 4252 4 (authentication timeout), nearest <auth_state>: the time between messages is not observable by Fandango's timers
# TODO: RFC 4252 5.1 (pipelined authentication requests; the client MUST NOT send a subsequent request before the reply), nearest <auth_state>: not generated
# TODO: RFC 4252 5.1 (partial success after a successful request), nearest <auth_reply_any>: either value is accepted, because the chain of required methods is not shown by earlier messages
# TODO: RFC 4254 4 (replies to pipelined global / channel requests in order), nearest <connected_state> and <channel_state>: Fandango generates the second of two consecutive messages after the server has replied to the first, which the engine reports as an unexpected message
# TODO: RFC 4254 6.3.2, 7.2 (x11 and forwarded-tcpip channels opened by the server), nearest <connected_state>: a connection the server opens after a third party connects
# TODO: RFC 4254 5.1 (a second channel that stays open), nearest <open_second_cr>: every channel state offers a second CHANNEL_OPEN (<open_second_cs>, <open_second_cp>, <open_second_cr>, <open_second_ce>, <open_second_ct>, <open_second_cl>: session, direct-tcpip, x11, forwarded-tcpip, unknown type; the first channel's output and CLOSE are accepted before the reply) and closes a confirmed second channel at once; a second channel that stays open would need a state per set of open channels
# TODO: RFC 4253 9 (the re-exchange: the silence of the server and its DISCONNECT inside the continuing form, compressed points), nearest <rekey_term>: the continuing re-exchange (<rekey_client> <state> / <rekey_server> <state>: ECDH, fixed-group DH and group exchange, uncompressed point) goes on in the state it started in, so it takes the server's UNIMPLEMENTED but not its DISCONNECT, which ends the connection (RFC 4253 11.1); the server's silence (the timer's expiry) ends the continuing form in <end_state> too (a stall of the engine can make the expiry arrive after the client's KEXINIT); the DISCONNECT is an alternative of <rekey_term>, which ends in <end_state> after every failure and after the completed exchange: client-started (the first message is the timer-8 start <t_kex_start_t>, the continuing form starts timer 1) and server-started (the server's KEXINIT is the only message shared with <rekey_server>; the next message is the timer-8 start or a DISCONNECT, so the forms differ at their second message and no loop lies in a shared prefix); between the server's own KEXINIT and the client's timer-8 start the terminal form takes one server IGNORE/DEBUG and one client IGNORE/DEBUG, any number of them only the continuing form, because a loop before that start would be shared by both forms (lasting ambiguity)
# TODO: RFC 4253 9, 11.1 (the client's DISCONNECT inside the continuing re-exchange), nearest <rekey_client>: the client sends IGNORE, DEBUG, UNIMPLEMENTED and unrecognized messages in every re-exchange state in which it is the next sender (the terminal chains also in <rekey_t_pre> and <rekey_t_sa_*>) and IGNORE, DEBUG, UNIMPLEMENTED in the states that wait for the server; its DISCONNECT is an alternative of <rekey_term> (see the TODO at <rekey_term>); rekey limits (RFC 4251 9.3, RFC 4344 3.1) need gigabytes of traffic and are not provoked
# TODO: RFC 4253 7.3 (the client's NEWKEYS before the server's), nearest <newkeys_state>: the server's NEWKEYS arrives in the same read as its reply and the engine plans the client's message before it has parsed the rest; the order server NEWKEYS then client NEWKEYS is modeled
# TODO: RFC 5656 3.1 (user keys on other curves than nistp256 that a server authorizes), nearest <pk_alg_ecdsa_p384>: the client's authorized ECDSA key is nistp256 (SSH_ECDSA_KEY_FILE); nistp384 and nistp521 keys and signatures are sent for keys the servers do not authorize (the formats are complete, so the servers refuse by the key list), as are ssh-dss and ssh-ed448 keys
# TODO: RFC 4252 6 (message numbers >= 80 before authentication), RFC 4256 3.4 (INFO_RESPONSE with a wrong num-responses), RFC 5656 4 / RFC 8731 3 (invalid or all-zero Q_C), RFC 8308 2.2 (ext-info-c as the only kex name), nearest <auth_state> and <ecdh_state>: the grammar never produces messages that break a mandatory requirement of the sender, so the recipient's handling is not tested
# TODO: RFC 4253 11 (unrecognized messages in the keyboard-interactive states, in the guess states and in the states that wait for the server's reply under a running timer), nearest <kbdint_response_one_state>: during a keyboard-interactive exchange RFC 4256 3.4 makes the INFO_RESPONSE mandatory ("The client MUST respond") and a server that gets another message there ends the method (MINA answers USERAUTH_FAILURE), so the client does not send one; in the states that wait for the server's reply under a running timer the server's UNIMPLEMENTED can arrive before or after that reply (the order depends on the server), which one nonterminal cannot place; after a KEXINIT with first_kex_packet_follows TRUE the next client packet is the guessed one, which a server ignores (the guess states); the client-turn states of the key exchange and of the re-exchange (<kex_choice_state>, <ecdh_state>, <dh_state>, <gex_state>, <gex_init_state>, <ecdh_unannounced_state>, <ecmqv_state>, <rekey_answer_state>, <rekey_ecdh_state>, <rekey_dh_state>, <rekey_t_init_*>, <rekey_t_req_gex>) send unrecognized messages (<c_unrecognized_kex>: 9-19, 22-29 and 35-49, the numbers RFC 4253 7.1 allows between KEXINIT and NEWKEYS) and accept UNIMPLEMENTED or DISCONNECT
# TODO: RFC 4253 6 (a padding of 8 octets for a cipher whose block size is 16), nearest <c_pad_half>: <c_pad_half> adds 8 octets (a total that is a multiple of 8 but not of 16) only while the cipher in use and the planned cipher have the block size 8 (none before the first NEWKEYS, 3des, blowfish, cast128, idea, arcfour); for the 16-octet block ciphers such a packet would break the sender's MUST that the total is a multiple of the block size
# TODO: RFC 4419 3 (every value of min, n and max between 1024 and 8192), nearest <gex_min>: the three sizes of a request are drawn from fixed sets that hold the bounds 1024 and 8192, min = n, n = max, a wide range and a narrow window; a server chooses its group by comparing the three values with its moduli, so the values between the members of the sets lead to the same choices as their neighbours
# TODO: RFC 5656 3.1, 4 (compressed points in <c_ecdh_init_rekey>), nearest <ecdh_q_c_rekey>: the continuing ECDH re-exchange sends the uncompressed point (Dropbear and MINA stay silent on a compressed one, which would end the exchange, and the continuing exchange cannot end); the compressed point is sent by <rekey_term> (<c_ecdh_init>, the shared <ecdh_q_c>)
# TODO: RFC 4251 7 (the numbers 30-34, 60 and 61 as unrecognized messages), nearest <unrec_type_early>: during the exchange or the method that defines them, 30-34 and 60-61 are read as its messages, so whether they are unrecognized depends on the exchange or the method in progress; the unassigned numbers 35-49 and 62-79 are sent as unrecognized messages in every state (<unrec_type_early> in <service_state>, <auth_state> and the authentication sub-states, <unrec_type_kex> between KEXINIT and NEWKEYS (the continuing re-exchange sends 9-19 and 22-29 only: <unrec_type_kex_c>, because it cannot take the server's DISCONNECT), <unrec_type> after the authentication; a server that stays silent is a finding)


