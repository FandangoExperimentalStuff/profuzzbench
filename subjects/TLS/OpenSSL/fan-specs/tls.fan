# tls.fan -- Transport Layer Security: TLS 1.3 (RFC 9846) and TLS 1.2 (RFC 5246) with RFC 6066, RFC 7301, RFC 9155.
# Fandango plays the TLS client (party Client); the server under test is party Server.
#
# The grammar models the PLAINTEXT of the connection: a ClientNetworkParty (below) applies and removes the record
# protection (RFC 9846 section 5.2, RFC 5246 section 6.2.3) the connection has switched to, so every record the
# grammar sees is a TLSPlaintext (type, legacy_record_version, length, fragment) with the real content type; it also
# puts exactly one handshake message into each received handshake record (RFC 9846 section 5.1 allows coalescing and
# fragmenting).  The party also derives the keys (RFC 9846 section 7, RFC 5246 sections 6.3 and 8.1).
#
# ======================== TEST SETUP (everything the test setup decides is configured here) ========================
import os
import random
import struct

# The server names a ClientHello may address with server_name (RFC 6066 section 3), one is picked per session.
SERVER_NAMES = [name for name in os.environ.get("TLS_SERVER_NAMES", "localhost,example.com").split(",") if name]
# The application protocols a ClientHello may offer with ALPN (RFC 7301 section 3.1), a subset is picked per session.
ALPN_PROTOCOLS = [name for name in os.environ.get("TLS_ALPN_PROTOCOLS", "http/1.1,h2").split(",") if name]
# The credential (PEM files: a certificate and its private key) a server under test accepts as a client certificate
# (its trust store holds it); empty: the party uses only the certificates it generates (RFC 9846 section 4.4.2).
CLIENT_CERT_FILE = os.environ.get("TLS_CLIENT_CERT", "")
CLIENT_KEY_FILE = os.environ.get("TLS_CLIENT_KEY", "")
# The CA a server under test trusts for client certificates (PEM files: its certificate and private key): the party then signs the
# client certificates it generates with it (empty: it signs them with a CA of its own that no server trusts).
CLIENT_CA_CERT_FILE = os.environ.get("TLS_CLIENT_CA_CERT", "")
CLIENT_CA_KEY_FILE = os.environ.get("TLS_CLIENT_CA_KEY", "")
# Names of tolerated server deviations (see tolerances.json); empty by default.
TOLERATED = [name for name in os.environ.get("TOLERATED", "").split(",") if name]
# Seconds Fandango waits for a message the server may leave out (timers).
WAIT_SERVER_MESSAGE_S = os.environ.get("TLS_WAIT_S", "6.0")
# ===================================================================================================================


def tolerated(name):
    return name in TOLERATED


def u(value, size):
    """The big-endian encoding of an integer."""
    return int(value).to_bytes(size, "big")


def blen(tree):
    """The length in bytes of a derivation tree's value."""
    return len(tree.to_bytes())


def rb(tree):
    return tree.to_bytes()


def uv(tree):
    """The integer a big-endian byte string nonterminal holds."""
    return int.from_bytes(tree.to_bytes(), "big")


def cat(trees):
    return b"".join(tree.to_bytes() for tree in trees)


# ---------------------------------------------------------------------------
# Record-layer protection and key schedule (RFC 9846 sections 5 and 7, RFC 5246 sections 6.2.3, 6.3, 8, 5).
# The grammar models the plaintext of every record; the party class below applies and removes the record protection
# the connection has switched to, so what the grammar sees is TLSPlaintext (type, legacy_record_version, length,
# fragment) with the real content type of the TLSInnerPlaintext.
# ---------------------------------------------------------------------------
import hashlib
import hmac as _hmac
import os as _os
import struct as _struct
import threading as _threading

from cryptography.hazmat.primitives.asymmetric import ec as _ec, x25519 as _x25519, x448 as _x448, ed25519 as _ed25519, ed448 as _ed448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM, ChaCha20Poly1305 as _ChaCha, AESCCM as _AESCCM
from cryptography.hazmat.primitives import serialization as _ser

TLS13_SUITES = {  # suite -> (hash, key length, aead)
    0x1301: ("sha256", 16, "aes"),
    0x1302: ("sha384", 32, "aes"),
    0x1303: ("sha256", 32, "chacha"),
    0x1304: ("sha256", 16, "ccm"),
    0x1305: ("sha256", 16, "ccm8"),
}
# TLS 1.2 cipher suites defined by RFC 5246 appendix A.5 that use a block cipher: suite -> (prf hash, key length,
# MAC hash, key exchange)
TLS12_SUITES = {
    0x002F: ("sha256", 16, "sha1", "rsa"), 0x0035: ("sha256", 32, "sha1", "rsa"),
    0x003C: ("sha256", 16, "sha256", "rsa"), 0x003D: ("sha256", 32, "sha256", "rsa"),
    0x0033: ("sha256", 16, "sha1", "dhe"), 0x0039: ("sha256", 32, "sha1", "dhe"),
    0x0067: ("sha256", 16, "sha256", "dhe"), 0x006B: ("sha256", 32, "sha256", "dhe"),
    # DHE_DSS (signed with the server's DSA key) and DH_anon (no certificate, no signature)
    0x0032: ("sha256", 16, "sha1", "dhe_dss"), 0x0038: ("sha256", 32, "sha1", "dhe_dss"),
    0x0040: ("sha256", 16, "sha256", "dhe_dss"), 0x006A: ("sha256", 32, "sha256", "dhe_dss"),
    0x0034: ("sha256", 16, "sha1", "dh_anon"), 0x003A: ("sha256", 32, "sha1", "dh_anon"),
    0x006C: ("sha256", 16, "sha256", "dh_anon"), 0x006D: ("sha256", 32, "sha256", "dh_anon"),
}
# NULL, RC4 (stream ciphers, RFC 5246 section 6.2.3.1) and 3DES (block cipher with 8-byte blocks) suites: suite -> cipher
TLS12_SUITES.update({
    0x0001: ("sha256", 0, "md5", "rsa"), 0x0002: ("sha256", 0, "sha1", "rsa"), 0x003B: ("sha256", 0, "sha256", "rsa"),
    0x0004: ("sha256", 16, "md5", "rsa"), 0x0005: ("sha256", 16, "sha1", "rsa"),
    0x000A: ("sha256", 24, "sha1", "rsa"), 0x0016: ("sha256", 24, "sha1", "dhe"), 0x0013: ("sha256", 24, "sha1", "dhe_dss"),
    0x0018: ("sha256", 16, "md5", "dh_anon"), 0x001B: ("sha256", 24, "sha1", "dh_anon"),
})
# static DH (DH_DSS, DH_RSA): the server's DH parameters are in its certificate (RFC 5246 section 7.4.3)
TLS12_SUITES.update({
    0x0030: ("sha256", 16, "sha1", "dh_dss"), 0x0036: ("sha256", 32, "sha1", "dh_dss"),
    0x003E: ("sha256", 16, "sha256", "dh_dss"), 0x0068: ("sha256", 32, "sha256", "dh_dss"), 0x000D: ("sha256", 24, "sha1", "dh_dss"),
    0x0031: ("sha256", 16, "sha1", "dh_rsa"), 0x0037: ("sha256", 32, "sha1", "dh_rsa"),
    0x003F: ("sha256", 16, "sha256", "dh_rsa"), 0x0069: ("sha256", 32, "sha256", "dh_rsa"), 0x0010: ("sha256", 24, "sha1", "dh_rsa"),
})
DH_STATIC_KINDS = ("dh_dss", "dh_rsa")
TLS12_CIPHER = {0x000D: "3des", 0x0010: "3des", 0x0001: "null", 0x0002: "null", 0x003B: "null", 0x0004: "rc4", 0x0005: "rc4", 0x0018: "rc4",
                0x000A: "3des", 0x0016: "3des", 0x0013: "3des", 0x001B: "3des"}
DH_KINDS = ("dhe", "dhe_dss", "dh_anon")
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
NAMED_GROUPS = {0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001E: "x448"}
CURVES = {0x0017: _ec.SECP256R1, 0x0018: _ec.SECP384R1, 0x0019: _ec.SECP521R1}

# private keys of the key shares the grammar generated, by public value (the recording side of the recording/recalling
# pair; the party recalls them when the server's reply selects one)
KEY_STORE = {}


def _h(name):
    return getattr(hashlib, name)


def hkdf_extract(hash_name, salt, ikm):
    return _hmac.new(salt or bytes(_h(hash_name)().digest_size), ikm, _h(hash_name)).digest()


def hkdf_expand(hash_name, prk, info, length):
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = _hmac.new(prk, block + info + bytes([counter]), _h(hash_name)).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(hash_name, secret, label, context, length):
    full = b"tls13 " + label
    info = _struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(hash_name, secret, info, length)


def derive_secret(hash_name, secret, label, transcript_hash):
    return hkdf_expand_label(hash_name, secret, label, transcript_hash, _h(hash_name)().digest_size)


def tls12_prf(hash_name, secret, label, seed, length):
    seed = label + seed
    out, a = b"", seed
    while len(out) < length:
        a = _hmac.new(secret, a, _h(hash_name)).digest()
        out += _hmac.new(secret, a + seed, _h(hash_name)).digest()
    return out[:length]


def new_key_share(group):
    """A fresh key pair of the named group; the public value (the key_exchange field) and the remembered private key."""
    if group in (0x001D, 0x001E):
        private = (_x25519.X25519PrivateKey if group == 0x001D else _x448.X448PrivateKey).generate()
        public = private.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    else:
        curve = CURVES[group]()
        private = _ec.generate_private_key(curve)
        public = private.public_key().public_bytes(_ser.Encoding.X962, _ser.PublicFormat.UncompressedPoint)
    KEY_STORE[public] = (group, private)
    if len(KEY_STORE) > 4000:
        KEY_STORE.pop(next(iter(KEY_STORE)))
    return public


def shared_secret(group, private, peer_public):
    if group == 0x001D:
        return private.exchange(_x25519.X25519PublicKey.from_public_bytes(peer_public))
    if group == 0x001E:
        return private.exchange(_x448.X448PublicKey.from_public_bytes(peer_public))
    curve = CURVES[group]()
    return private.exchange(_ec.ECDH(), _ec.EllipticCurvePublicKey.from_encoded_point(curve, peer_public))


class Protection:
    """The AEAD state of one direction of the connection."""

    def __init__(self, version, suite, key, iv, secret=None, hash_name=None):
        self.version, self.suite, self.secret, self.hash_name = version, suite, secret, hash_name
        self.sequence = 0
        self.iv = iv
        kind = (TLS13_SUITES if version == 0x0304 else TLS12_SUITES)[suite][2]
        self.tag = 8 if kind == "ccm8" else 16
        self.aead = _AESGCM(key) if kind == "aes" else _AESCCM(key, self.tag) if kind in ("ccm", "ccm8") else _ChaCha(key)
        self.kind = kind

    def nonce(self, explicit=b""):
        seq = _struct.pack(">Q", self.sequence)
        if self.version == 0x0304 or self.kind == "chacha":
            padded = bytes(len(self.iv) - 8) + seq
            return bytes([self.iv[i] ^ padded[i] for i in range(len(self.iv))])
        return self.iv + explicit

    def seal(self, content_type, plaintext, padding=0):
        seq = _struct.pack(">Q", self.sequence)
        if self.version == 0x0304:
            inner = plaintext + bytes([content_type]) + bytes(padding)
            header = b"\x17\x03\x03" + _struct.pack(">H", len(inner) + self.tag)
            body = self.aead.encrypt(self.nonce(), inner, header)
        else:
            header = seq + bytes([content_type]) + b"\x03\x03" + _struct.pack(">H", len(plaintext))
            explicit = seq if self.kind == "aes" else b""
            body = explicit + self.aead.encrypt(self.nonce(seq), plaintext, header)
            header = bytes([content_type]) + b"\x03\x03" + _struct.pack(">H", len(body))
        self.sequence += 1
        return header + body

    def open(self, content_type, fragment):
        """(real content type, plaintext) of a protected record's fragment, or None if it does not authenticate."""
        try:
            if len(fragment) > (1 << 14) + 256:
                return None                                   # TLSCiphertext length exceeds 2^14 + 256 (RFC 9846 section 5.2)
            if self.version == 0x0304:
                header = b"\x17\x03\x03" + _struct.pack(">H", len(fragment))
                inner = self.aead.decrypt(self.nonce(), fragment, header)
                if len(inner) > (1 << 14) + 1:
                    return None                               # TLSInnerPlaintext longer than 2^14 + 1 (section 5.4)
                inner = inner.rstrip(b"\x00")
                result = (inner[-1], inner[:-1]) if inner else None
            else:
                seq = _struct.pack(">Q", self.sequence)
                explicit, body = (fragment[:8], fragment[8:]) if self.kind == "aes" else (b"", fragment)
                header = seq + bytes([content_type]) + b"\x03\x03" + _struct.pack(">H", len(body) - 16)
                nonce = self.nonce(explicit) if self.kind == "aes" else self.nonce(seq)
                result = (content_type, self.aead.decrypt(nonce, body, header))
        except Exception:
            return None
        self.sequence += 1
        return result


def _block_cipher(name, key):
    from cryptography.hazmat.primitives.ciphers import algorithms
    if name == "3des":
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            TripleDES = algorithms.TripleDES
        return TripleDES(key), 8
    return algorithms.AES(key), 16


class CbcProtection:
    """TLS 1.2 block cipher record protection (RFC 5246 section 6.2.3.2): MAC-then-encrypt with an explicit IV."""

    def __init__(self, mac_hash, mac_key, key, truncated=False, cipher="aes"):
        self.mac_hash, self.mac_key, self.key, self.truncated, self.cipher = mac_hash, mac_key, key, truncated, cipher
        self.sequence = 0
        self.version = 0x0303

    def mac(self, content_type, data):
        header = _struct.pack(">QBHH", self.sequence, content_type, 0x0303, len(data))
        digest = _hmac.new(self.mac_key, header + data, _h(self.mac_hash)).digest()
        return digest[:10] if self.truncated else digest   # truncated_hmac (RFC 6066 section 7)

    def seal(self, content_type, plaintext, padding=0):
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        algorithm, block = _block_cipher(self.cipher, self.key)
        body = plaintext + self.mac(content_type, plaintext)
        pad = block - (len(body) + 1) % block
        pad = min(pad + block * padding, 240 + pad % block)  # any padding length up to 255 bytes that fills the block (section 6.2.3.2)
        body += bytes([pad]) * (pad + 1)
        iv = _os.urandom(block)
        encryptor = Cipher(algorithm, modes.CBC(iv)).encryptor()
        fragment = iv + encryptor.update(body) + encryptor.finalize()
        self.sequence += 1
        return bytes([content_type]) + b"\x03\x03" + _struct.pack(">H", len(fragment)) + fragment

    def open(self, content_type, fragment):
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            algorithm, block = _block_cipher(self.cipher, self.key)
            iv, body = fragment[:block], fragment[block:]
            decryptor = Cipher(algorithm, modes.CBC(iv)).decryptor()
            plain = decryptor.update(body) + decryptor.finalize()
            pad = plain[-1]
            if plain[len(plain) - pad - 1:] != bytes([pad]) * (pad + 1):
                return None   # every padding byte equals the padding length (RFC 5246 section 6.2.3.2)
            plain = plain[:len(plain) - pad - 1]
            mac_len = 10 if self.truncated else _h(self.mac_hash)().digest_size
            content, mac = plain[:-mac_len], plain[-mac_len:]
            if not _hmac.compare_digest(mac, self.mac(content_type, content)):
                return None
        except Exception:
            return None
        self.sequence += 1
        return (content_type, content)


class StreamProtection:
    """TLS 1.2 stream cipher record protection (RFC 5246 section 6.2.3.1): the MAC is appended and content and MAC are
    encrypted with a stream cipher (RC4) or sent as they are (the NULL cipher); no padding and no IV."""

    def __init__(self, mac_hash, mac_key, key, truncated=False, cipher="null"):
        self.mac_hash, self.mac_key, self.truncated, self.cipher = mac_hash, mac_key, truncated, cipher
        self.sequence = 0
        self.version = 0x0303
        self.stream = None
        if cipher == "rc4":
            from cryptography.hazmat.primitives.ciphers import Cipher
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
            except ImportError:
                from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
            self.stream = Cipher(ARC4(key), mode=None)
            self.encryptor, self.decryptor = self.stream.encryptor(), self.stream.decryptor()

    def mac(self, content_type, data):
        header = _struct.pack(">QBHH", self.sequence, content_type, 0x0303, len(data))
        digest = _hmac.new(self.mac_key, header + data, _h(self.mac_hash)).digest()
        return digest[:10] if self.truncated else digest

    def seal(self, content_type, plaintext, padding=0):
        body = plaintext + self.mac(content_type, plaintext)
        fragment = self.encryptor.update(body) if self.cipher == "rc4" else body
        self.sequence += 1
        return bytes([content_type]) + b"\x03\x03" + _struct.pack(">H", len(fragment)) + fragment

    def open(self, content_type, fragment):
        try:
            plain = self.decryptor.update(fragment) if self.cipher == "rc4" else fragment
            mac_len = 10 if self.truncated else _h(self.mac_hash)().digest_size
            content, mac = plain[:-mac_len], plain[-mac_len:]
            if not _hmac.compare_digest(mac, self.mac(content_type, content)):
                return None
        except Exception:
            return None
        self.sequence += 1
        return (content_type, content)


# pre-master secrets and Diffie-Hellman private values the grammar generated, by the value the client sends
PMS_STORE = {}
DH_STORE = {}


def parse_vectors(data, sizes):
    """The byte strings of consecutive length-prefixed vectors (prefix sizes in `sizes`); the rest of the data last."""
    out, offset = [], 0
    for size in sizes:
        n = int.from_bytes(data[offset:offset + size], "big")
        out.append(data[offset + size:offset + size + n])
        offset += size + n
    out.append(data[offset:])
    return out


def encrypt_pre_master_secret(certificate_der, version=0x0303):
    """RSAES-PKCS1-v1_5 encryption of a fresh PreMasterSecret under the server's public key (RFC 5246 section 7.4.7.1)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding
    pms = _struct.pack(">H", version) + _os.urandom(46)
    key = x509.load_der_x509_certificate(certificate_der).public_key()
    encrypted = key.encrypt(pms, padding.PKCS1v15())
    PMS_STORE[encrypted] = pms
    if len(PMS_STORE) > 2000:
        PMS_STORE.pop(next(iter(PMS_STORE)))
    return encrypted


def der_item(data, offset):
    """(tag, content, end offset) of the DER TLV at `offset`; None if it does not fit."""
    try:
        tag, length = data[offset], data[offset + 1]
        header = 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
            header = 2 + count
        end = offset + header + length
        if end > len(data):
            return None
        return tag, data[offset + header:end], end
    except IndexError:
        return None


def static_dh_parameters(certificate_der):
    """(p, g, public value) as big-endian bytes of a certificate whose SubjectPublicKeyInfo is a Diffie-Hellman key
    (dhpublicnumber, RFC 3279 section 2.3.3; the x509 reader of the cryptography library cannot load such a key), else None."""
    try:
        _, certificate, _ = der_item(certificate_der, 0)
        _, tbs, _ = der_item(certificate, 0)
        items, offset = [], 0
        while offset < len(tbs):
            tag, content, offset = der_item(tbs, offset)
            items.append((tag, content))
        index = 1 if items[0][0] == 0xA0 else 0              # [0] version, serialNumber, signature, issuer, validity, subject, SPKI
        _, spki = items[index + 5]
        _, algorithm, end = der_item(spki, 0)
        _, bits, _ = der_item(spki, end)
        oid_tag, oid, end = der_item(algorithm, 0)
        if oid not in (bytes.fromhex("2a8648ce3e0201"), bytes.fromhex("2a864886f70d010301")):
            return None                                       # dhpublicnumber (RFC 3279) or PKCS #3 dhKeyAgreement
        _, parameters, _ = der_item(algorithm, end)
        numbers, offset = [], 0
        while offset < len(parameters):
            tag, content, offset = der_item(parameters, offset)
            numbers.append(content.lstrip(b"\x00") or b"\x00")
        _, public, _ = der_item(bits[1:], 0)
        if len(numbers) < 2:
            return None
        return numbers[0], numbers[1], public.lstrip(b"\x00") or b"\x00"
    except Exception:
        return None


def new_dh_share(p, g):
    """A Diffie-Hellman public value g^x mod p of the server's parameters (RFC 5246 section 7.4.7.2)."""
    p_int, g_int = int.from_bytes(p, "big"), int.from_bytes(g, "big")
    x = int.from_bytes(_os.urandom(32), "big") | 1
    public = pow(g_int, x, p_int).to_bytes((p_int.bit_length() + 7) // 8, "big").lstrip(b"\x00") or b"\x01"
    DH_STORE[public] = (x, p_int)
    if len(DH_STORE) > 2000:
        DH_STORE.pop(next(iter(DH_STORE)))
    return public


def traffic_protection(hash_name, version, suite, secret):
    key_len = TLS13_SUITES[suite][1]
    key = hkdf_expand_label(hash_name, secret, b"key", b"", key_len)
    iv = hkdf_expand_label(hash_name, secret, b"iv", b"", 12)
    return Protection(version, suite, key, iv, secret, hash_name)


def parse_handshakes(data):
    """The handshake messages (type, complete bytes) in a handshake fragment; an incomplete tail is ignored."""
    messages, offset = [], 0
    while offset + 4 <= len(data):
        length = int.from_bytes(data[offset + 1:offset + 4], "big")
        if offset + 4 + length > len(data):
            break
        messages.append((data[offset], data[offset:offset + 4 + length]))
        offset += 4 + length
    return messages


def parse_hello(body, is_client):
    """(random, session_id, suites or suite, extensions dict) of a hello body; None if it does not parse."""
    try:
        random = body[2:34]
        sid_len = body[34]
        offset = 35 + sid_len
        if is_client:
            n = int.from_bytes(body[offset:offset + 2], "big")
            suites = [int.from_bytes(body[offset + 2 + i:offset + 4 + i], "big") for i in range(0, n, 2)]
            offset += 2 + n
            offset += 1 + body[offset]
            result = suites
        else:
            result = int.from_bytes(body[offset:offset + 2], "big")
            offset += 3
        extensions = {}
        if offset + 2 <= len(body):
            end = offset + 2 + int.from_bytes(body[offset:offset + 2], "big")
            offset += 2
            while offset + 4 <= end:
                ext_type = int.from_bytes(body[offset:offset + 2], "big")
                ext_len = int.from_bytes(body[offset + 2:offset + 4], "big")
                extensions[ext_type] = body[offset + 4:offset + 4 + ext_len]
                offset += 4 + ext_len
        return random, body[35:35 + sid_len], result, extensions
    except Exception:
        return None


class TlsState:
    """What the connection has negotiated and the keys in force; one per session."""

    def __init__(self):
        self.lock = _threading.RLock()
        self.buffer = b""
        self.version = None          # 0x0304 or 0x0303 once the server hello is seen
        self.suite = None
        self.hash_name = None
        self.transcript = []         # (direction, handshake message bytes) in order
        self.client_hello_msgs = []
        self.send_prot = None
        self.recv_prot = None
        self.secrets = {}
        self.client_random = b""
        self.server_random = b""
        self.server_group = None
        self.hrr_seen = False
        self.hrr_group = None
        self.hrr_suite = None
        self.ccs_received = 0
        self.ccs_second_hello = None  # change_cipher_spec records received before the second ClientHello (after an HRR)
        self.ske_seen = False
        self.sh_ext_types = []
        self.max_fragment = None
        self.overflow_pending = False
        self.nst_messages = []
        self.server_cert_13 = None
        self.hrr_cookie = None
        self.finished_sent = False
        self.server_finished_seen = False
        self.closed = False
        self.tickets = 0
        self.peer_key_exchange = None
        self.client_key_exchange = None
        self.master_secret = None
        self.server_certificate = None
        self.dh_params = None
        self.pending_recv_prot = None  # TLS 1.2: keys that start with the server's ChangeCipherSpec
        self.pending_send_prot = None
        self.alerts_received = []
        self.application_received = 0
        self.hs_buffer = b""
        self.out_hs = b""          # the part of a fragmented handshake message the client has sent so far
        self.handshake_end = None    # length of the transcript when the client Finished of the handshake was sent

    # -- transcript -------------------------------------------------------------------------------------------
    def transcript_hash(self, upto=None):
        messages = self.transcript if upto is None else self.transcript[:upto]
        h = _h(self.hash_name or "sha256")()
        if self.hrr_seen and self.version == 0x0304:
            first = hashlib.new(self.hash_name or "sha256", self.client_hello_msgs[0]).digest()
            h.update(b"\xfe\x00\x00" + bytes([len(first)]) + first)
            messages = [m for m in messages if not (m[0] == "C" and m[1][0] == 1 and m[1] is self.client_hello_msgs[0])]
        for _, message in messages:
            h.update(message)
        return h.digest()

    def add_message(self, direction, message):
        if message[0] == 0:
            return   # HelloRequest is not part of the handshake hash (RFC 5246 section 7.4.1.1)
        self.transcript.append((direction, message))
        if direction == "C" and message[0] == 1:
            if self.hrr_seen and self.ccs_second_hello is None:
                self.ccs_second_hello = self.ccs_received
            self.client_hello_msgs.append(message)

    def ccs_after_hrr_count(self):
        """change_cipher_spec records received after the HelloRetryRequest and before the client's next message."""
        return self.ccs_received if self.ccs_second_hello is None else self.ccs_second_hello

    # -- events -----------------------------------------------------------------------------------------------
    def on_server_hello(self, message):
        body = message[4:]
        parsed = parse_hello(body, False)
        if parsed is None:
            return
        random, _, suite, extensions = parsed
        self.server_random = random
        self.sh_ext_types = list(extensions.keys())
        if 1 in extensions and len(extensions[1]) == 1 and 1 <= extensions[1][0] <= 4:
            self.max_fragment = 1 << (8 + extensions[1][0])
        version = int.from_bytes(extensions.get(43, b"\x03\x03")[:2], "big") if 43 in extensions else 0x0303
        client = parse_hello(self.client_hello_msgs[-1][4:], True) if self.client_hello_msgs else None
        if client:
            self.client_random = client[0]
        if version == 0x0304 and suite in TLS13_SUITES:
            self.version, self.suite = 0x0304, suite
            self.hash_name = TLS13_SUITES[suite][0]
            if random == HRR_RANDOM:
                self.hrr_seen = True
                self.hrr_suite = suite
                if 51 in extensions and len(extensions[51]) >= 2:
                    self.hrr_group = int.from_bytes(extensions[51][:2], "big")
                if 44 in extensions:
                    self.hrr_cookie = extensions[44][2:]
                return
            share = extensions.get(51)
            if share is None or len(share) < 4:
                return
            group = int.from_bytes(share[:2], "big")
            peer = share[4:4 + int.from_bytes(share[2:4], "big")]
            entry = self.find_private(group)
            if entry is None:
                return
            ecdhe = shared_secret(group, entry, peer)
            hn = self.hash_name
            zeros = bytes(_h(hn)().digest_size)
            early = hkdf_extract(hn, None, zeros)
            derived = derive_secret(hn, early, b"derived", _h(hn)(b"").digest())
            hs = hkdf_extract(hn, derived, ecdhe)
            th = self.transcript_hash()
            c_hs = derive_secret(hn, hs, b"c hs traffic", th)
            s_hs = derive_secret(hn, hs, b"s hs traffic", th)
            self.secrets.update(hs=hs, c_hs=c_hs, s_hs=s_hs)
            self.send_prot = traffic_protection(hn, 0x0304, suite, c_hs)
            self.recv_prot = traffic_protection(hn, 0x0304, suite, s_hs)
        elif suite in TLS12_SUITES:
            self.version, self.suite = 0x0303, suite
            self.hash_name = TLS12_SUITES[suite][0]

    def find_private(self, group):
        """The private key of the client's key share of `group` (recalled from what the generator recorded)."""
        if not self.client_hello_msgs:
            return None
        parsed = parse_hello(self.client_hello_msgs[0][4:], True)
        share_list = parsed[3].get(51, b"") if parsed else b""
        offset = 2
        while offset + 4 <= len(share_list):
            g = int.from_bytes(share_list[offset:offset + 2], "big")
            n = int.from_bytes(share_list[offset + 2:offset + 4], "big")
            public = share_list[offset + 4:offset + 4 + n]
            offset += 4 + n
            if g == group and public in KEY_STORE:
                return KEY_STORE[public][1]
        # after a HelloRetryRequest the second ClientHello carries the share
        if len(self.client_hello_msgs) > 1:
            parsed = parse_hello(self.client_hello_msgs[-1][4:], True)
            share_list = parsed[3].get(51, b"") if parsed else b""
            offset = 2
            while offset + 4 <= len(share_list):
                g = int.from_bytes(share_list[offset:offset + 2], "big")
                n = int.from_bytes(share_list[offset + 2:offset + 4], "big")
                public = share_list[offset + 4:offset + 4 + n]
                offset += 4 + n
                if g == group and public in KEY_STORE:
                    return KEY_STORE[public][1]
        return None

    def finished_verify_data(self, direction, upto):
        hn = self.hash_name
        if self.version == 0x0304:
            base = self.secrets["s_hs"] if direction == "S" else self.secrets["c_hs"]
            key = hkdf_expand_label(hn, base, b"finished", b"", _h(hn)().digest_size)
            return _hmac.new(key, self.transcript_hash(upto), _h(hn)).digest()
        label = b"server finished" if direction == "S" else b"client finished"
        return tls12_prf(hn, self.master_secret, label, self.transcript_hash(upto), 12)

    def after_server_finished(self):
        hn = self.hash_name
        th = self.transcript_hash()
        derived = derive_secret(hn, self.secrets["hs"], b"derived", _h(hn)(b"").digest())
        master = hkdf_extract(hn, derived, bytes(_h(hn)().digest_size))
        self.secrets["c_ap"] = derive_secret(hn, master, b"c ap traffic", th)
        self.secrets["s_ap"] = derive_secret(hn, master, b"s ap traffic", th)
        self.secrets["master"] = master
        self.server_finished_seen = True
        self.recv_prot = traffic_protection(hn, 0x0304, self.suite, self.secrets["s_ap"])

    def key_update(self, direction):
        hn = self.hash_name
        label = b"traffic upd"
        if direction == "S":
            self.secrets["s_ap"] = hkdf_expand_label(hn, self.secrets["s_ap"], label, b"", _h(hn)().digest_size)
            self.recv_prot = traffic_protection(hn, 0x0304, self.suite, self.secrets["s_ap"])
        else:
            self.secrets["c_ap"] = hkdf_expand_label(hn, self.secrets["c_ap"], label, b"", _h(hn)().digest_size)
            self.send_prot = traffic_protection(hn, 0x0304, self.suite, self.secrets["c_ap"])

    # -- TLS 1.2 ---------------------------------------------------------------------------------------------
    def on_certificate_12(self, message):
        body = message[4:]
        if len(body) >= 6:
            first = int.from_bytes(body[3:6], "big")
            self.server_certificate = body[6:6 + first]
            if TLS12_SUITES.get(self.suite, (0, 0, 0, ""))[3] in DH_STATIC_KINDS:
                self.dh_params = static_dh_parameters(self.server_certificate)    # (p, g, public value) of the certificate

    def on_server_key_exchange(self, message):
        """The Diffie-Hellman parameters of a DHE_RSA ServerKeyExchange (RFC 5246 section 7.4.3)."""
        if self.version == 0x0303 and TLS12_SUITES.get(self.suite, (0, 0, 0, ""))[3] in DH_KINDS:
            vectors = parse_vectors(message[4:], (2, 2, 2))
            self.dh_params = (vectors[0], vectors[1], vectors[2])

    def on_client_key_exchange(self, message):
        """Called when the client key exchange is sent: derives the master secret and the keys (RFC 5246 section 8.1)."""
        body = message[4:]
        kx = TLS12_SUITES.get(self.suite, (0, 0, 0, ""))[3]
        pms = None
        if not body and kx in DH_STATIC_KINDS and self.dh_params is not None:
            # the implicit ClientDiffieHellmanPublic (RFC 5246 section 7.4.7.2): the client's certificate holds the DH key
            own = _own_certificate(self)
            for direction, m in reversed(self.transcript):
                if direction == "C" and m[0] == 11:
                    entry_length = int.from_bytes(m[7:10], "big")
                    parameters = static_dh_parameters(m[10:10 + entry_length])
                    if parameters is not None and parameters[2] in DH_STORE:
                        x, p = DH_STORE[parameters[2]]
                        z = pow(int.from_bytes(self.dh_params[2], "big"), x, p)
                        pms = z.to_bytes((p.bit_length() + 7) // 8, "big").lstrip(b"\x00")
                    break
        elif kx == "rsa":
            encrypted = parse_vectors(body, (2,))[0]
            pms = PMS_STORE.get(encrypted)
        elif (kx in DH_KINDS or kx in DH_STATIC_KINDS) and self.dh_params is not None:
            public = parse_vectors(body, (2,))[0]
            if public in DH_STORE:
                x, p = DH_STORE[public]
                z = pow(int.from_bytes(self.dh_params[2], "big"), x, p)
                pms = z.to_bytes((p.bit_length() + 7) // 8, "big").lstrip(b"\x00")
        if pms is None:
            return
        self.master_secret = tls12_prf(self.hash_name, pms, b"master secret",
                                       self.client_random + self.server_random, 48)
        self.derive_tls12_keys()

    def derive_tls12_keys(self):
        hn, suite = self.hash_name, self.suite
        _, key_len, mac_hash, _ = TLS12_SUITES[suite]
        mac_len = _h(mac_hash)().digest_size
        block = tls12_prf(hn, self.master_secret, b"key expansion", self.server_random + self.client_random,
                          2 * mac_len + 2 * key_len)
        client_mac, server_mac = block[:mac_len], block[mac_len:2 * mac_len]
        client_key, server_key = block[2 * mac_len:2 * mac_len + key_len], block[2 * mac_len + key_len:]
        truncated = 4 in self.sh_ext_types
        cipher = TLS12_CIPHER.get(suite, "aes")
        protection = CbcProtection if cipher in ("aes", "3des") else StreamProtection
        self.pending_send_prot = protection(mac_hash, client_mac, client_key, truncated, cipher)
        self.pending_recv_prot = protection(mac_hash, server_mac, server_key, truncated, cipher)

    # -- the record layer ------------------------------------------------------------------------------------------
    def incoming(self, data):
        """Plaintext records (as TLSPlaintext bytes) for the raw bytes the server sent; keeps incomplete ones."""
        with self.lock:
            self.buffer += data
            out = []
            while len(self.buffer) >= 5:
                length = int.from_bytes(self.buffer[3:5], "big")
                if len(self.buffer) < 5 + length:
                    break
                ctype, version, fragment = self.buffer[0], self.buffer[1:3], self.buffer[5:5 + length]
                self.buffer = self.buffer[5 + length:]
                out.append(self._plain_record(ctype, version, fragment))
            return b"".join(out)

    def _plain_record(self, ctype, version, fragment):
        protected = self.recv_prot is not None and ctype != 20
        if protected:
            opened = self.recv_prot.open(ctype, fragment)
            if opened is None:
                return bytes([ctype]) + version + _struct.pack(">H", len(fragment)) + fragment  # undecryptable
            ctype, fragment = opened
            if self.version == 0x0304:
                version = b"\x03\x03"
        if ctype == 20 and self.version == 0x0303 and self.pending_recv_prot is not None:
            self.recv_prot, self.pending_recv_prot = self.pending_recv_prot, None
        if ctype == 22:
            self._handshake_received(fragment)
        elif ctype == 21:
            self.alerts_received.append(fragment)
        return bytes([ctype]) + version + _struct.pack(">H", len(fragment)) + fragment

    def _handshake_received(self, message):
        kind = message[0]
        if not (kind in (4, 24) and self.version == 0x0304 and self.server_finished_seen and not self.finished_sent):
            self.add_message("S", message)       # a NewSessionTicket or KeyUpdate before the client's Finished is no part of its hash
        if kind == 2:
            self.on_server_hello(message)
        elif kind == 11 and self.version == 0x0303:
            self.on_certificate_12(message)
        elif kind == 11 and self.version == 0x0304:
            body = message[4:]
            if len(body) >= 8:
                context = body[0]
                entry_len = int.from_bytes(body[4 + context:7 + context], "big")
                self.server_cert_13 = body[7 + context:7 + context + entry_len]
        elif kind == 12:
            self.ske_seen = True
            self.on_server_key_exchange(message)
        elif kind == 8 and self.version == 0x0304:
            from_block = extension_list(message[6:]) or []
            for ext_type, data in from_block:
                if ext_type == 1 and len(data) == 1 and 1 <= data[0] <= 4:
                    self.max_fragment = 1 << (8 + data[0])
        elif kind == 4:
            self.nst_messages.append(message)
        elif kind == 20 and self.version == 0x0304:
            self.after_server_finished()
        elif kind == 24 and self.version == 0x0304 and self.server_finished_seen:
            self.key_update("S")

    def outgoing(self, data):
        """The bytes to put on the wire for the TLSPlaintext records (each with its trailing zero padding) the grammar produced:
        one record, or several in a row when the grammar fragments a message or sends several records at once."""
        with self.lock:
            wire, offset = b"", 0
            while offset < len(data):
                if len(data) - offset < 5:
                    wire += data[offset:]
                    break
                end = offset + 5 + int.from_bytes(data[offset + 3:offset + 5], "big")
                while end < len(data) and data[end] == 0:      # zero padding up to the next record (whose type is never 0)
                    end += 1
                wire += self._outgoing_record(data[offset:end])
                offset = end
            return wire

    def _outgoing_record(self, data):
        if True:
            if len(data) < 5:
                return data
            ctype, version = data[0], data[1:3]
            length = int.from_bytes(data[3:5], "big")
            fragment, padding = data[5:5 + length], len(data) - 5 - length
            completed = []
            if ctype == 22:
                self.out_hs += fragment                       # a handshake message may be fragmented over records (section 5.1)
                completed = parse_handshakes(self.out_hs)
                self.out_hs = self.out_hs[sum(len(m) for _, m in completed):]
                for kind, message in completed:
                    if kind == 1:
                        self.add_message("C", message)
                    elif kind == 20:
                        self.add_message("C", message)
                        if self.version == 0x0304 and self.handshake_end is None:
                            self.handshake_end = len(self.transcript)
                    else:
                        self.add_message("C", message)
                        if kind == 16 and self.version == 0x0303:
                            self.on_client_key_exchange(message)
            wire = data[:5 + length]
            chunks = [fragment]
            # the request that breaks RFC 6066 section 4 (an oversized record, marked by OVERFLOW_MAGIC) is sent unsplit; until the next record is sent the
            # server's reaction to it is awaited (overflow_pending)
            self.overflow_pending = ctype == 23 and fragment.startswith(OVERFLOW_MAGIC)
            if self.max_fragment is not None and ctype != 20 and len(fragment) > self.max_fragment and not self.overflow_pending:
                # RFC 6066 section 4: once a maximum fragment length is negotiated, messages are fragmented immediately
                chunks = [fragment[i:i + self.max_fragment] for i in range(0, len(fragment), self.max_fragment)]
            if self.send_prot is not None and not (ctype == 20 and self.version != 0x0303):
                wire = b"".join(self.send_prot.seal(ctype, chunk, padding if index == len(chunks) - 1 else 0)
                                for index, chunk in enumerate(chunks))
            elif len(chunks) > 1:
                wire = b"".join(bytes([ctype]) + version + _struct.pack(">H", len(chunk)) + chunk for chunk in chunks)
            elif padding > 0:
                wire = data[:5 + length]
            if ctype == 22 and self.version == 0x0304 and self.send_prot is not None:
                for kind, message in completed:
                    if kind == 20:
                        self.finished_sent = True
                        hn = self.hash_name
                        self.send_prot = traffic_protection(hn, 0x0304, self.suite, self.secrets["c_ap"])
                    elif kind == 24:
                        self.key_update("C")
            if ctype == 20 and self.version == 0x0303 and self.pending_send_prot is not None:
                self.send_prot, self.pending_send_prot = self.pending_send_prot, None
            return wire


# ---------------------------------------------------------------------------------------------------------------
# Rewrite of the receive path: reassembles and splits handshake messages so that the grammar sees exactly one
# handshake message per plaintext record (a handshake message may be coalesced with others in one record or
# fragmented over several records, RFC 9846 section 5.1; the record boundaries carry no meaning).
# ---------------------------------------------------------------------------------------------------------------
OVERFLOW_MAGIC = b"\xd0\xd1OVERFLOW\xd2\xd3"      # starts the application data of the request that sends an oversized record unsplit
RECORD_END = b"\xff\xfe"   # marks the end of each plaintext record handed to the grammar


def _incoming(self, data):
    with self.lock:
        self.buffer += data
        out = []
        while len(self.buffer) >= 5:
            length = int.from_bytes(self.buffer[3:5], "big")
            if len(self.buffer) < 5 + length:
                break
            ctype, version, fragment = self.buffer[0], self.buffer[1:3], self.buffer[5:5 + length]
            self.buffer = self.buffer[5 + length:]
            protected = self.recv_prot is not None and ctype != 20
            if protected:
                opened = self.recv_prot.open(ctype, fragment)
                if opened is None:   # a record that does not deprotect: handed over with an invalid content type
                    out.append(b"\xfd" + version + _struct.pack(">H", len(fragment)) + fragment + RECORD_END)
                    continue
                ctype, fragment = opened
                if ctype == 20 or ctype == 0:   # a protected change_cipher_spec is not allowed (RFC 9846 section 5)
                    out.append(b"\xfd" + version + _struct.pack(">H", len(fragment)) + fragment + RECORD_END)
                    continue
                if self.version == 0x0304:
                    version = b"\x03\x03"
            if self.max_fragment is not None and ctype != 20 and len(fragment) > self.max_fragment:
                out.append(b"\xfd" + version + _struct.pack(">H", len(fragment)) + fragment[:0] + RECORD_END)   # exceeds max_fragment_length
                continue
            if ctype in (21, 22) and len(fragment) == 0:   # zero-length Handshake/Alert fragments are not allowed (section 5.1)
                out.append(b"\xfd" + version + _struct.pack(">H", 0) + RECORD_END)
                continue
            if ctype != 22 and getattr(self, "hs_buffer", b""):
                # another record type between the fragments of a handshake message (RFC 9846 section 5.1)
                self.hs_buffer = b""
                out.append(b"\xfd" + version + _struct.pack(">H", 0) + RECORD_END)
                continue
            if ctype == 20:
                self.ccs_received += 1
            if ctype == 20 and self.version == 0x0303 and self.pending_recv_prot is not None:
                self.recv_prot, self.pending_recv_prot = self.pending_recv_prot, None
            if ctype == 22:
                self.hs_buffer = getattr(self, "hs_buffer", b"") + fragment
                broken = False
                for kind, message in parse_handshakes(self.hs_buffer):
                    self.hs_buffer = self.hs_buffer[len(message):]
                    self._handshake_received(message)
                    out.append(b"\x16" + version + _struct.pack(">H", len(message)) + message + RECORD_END)
                    if self.version == 0x0304 and kind in (2, 20, 24) and self.hs_buffer:
                        broken = True          # ServerHello, Finished, KeyUpdate precede a key change: they end a record (section 5.1)
                        break
                if broken:
                    self.hs_buffer = b""
                    out.append(b"\xfd" + version + _struct.pack(">H", 0) + RECORD_END)
            else:
                if ctype == 21:
                    self.alerts_received.append(fragment)
                out.append(bytes([ctype]) + version + _struct.pack(">H", len(fragment)) + fragment + RECORD_END)
        return b"".join(out)


TlsState.incoming = _incoming


def extension_list(data):
    """All (type, data) pairs of an extension block (the bytes after its length), duplicates included; None if malformed."""
    out, offset = [], 0
    while offset < len(data):
        if offset + 4 > len(data):
            return None
        ext_type = int.from_bytes(data[offset:offset + 2], "big")
        length = int.from_bytes(data[offset + 2:offset + 4], "big")
        if offset + 4 + length > len(data):
            return None
        out.append((ext_type, data[offset + 4:offset + 4 + length]))
        offset += 4 + length
    return out


def hello_extension_block(body, is_client):
    """The raw bytes of a hello's extension block (after its 2-byte length), or b"" if the hello has none."""
    try:
        offset = 34
        offset += 1 + body[offset]
        if is_client:
            offset += 2 + int.from_bytes(body[offset:offset + 2], "big")
            offset += 1 + body[offset]
        else:
            offset += 3
        if offset + 2 > len(body):
            return b""
        return body[offset + 2:offset + 2 + int.from_bytes(body[offset:offset + 2], "big")]
    except Exception:
        return b""


def offered_list(ext_data, size_of_length=2, item=2):
    """The items of a vector of fixed-size items (a 2-byte or 1-byte length prefix first)."""
    n = int.from_bytes(ext_data[:size_of_length], "big")
    body = ext_data[size_of_length:size_of_length + n]
    return [int.from_bytes(body[i:i + item], "big") for i in range(0, len(body) - item + 1, item)]


def verify_certificate_verify_13(state, message):
    """RFC 9846 section 4.4.3: the signature over the transcript with the key of the server's end-entity certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    if state.server_cert_13 is None or state.hash_name is None:
        return True
    scheme = int.from_bytes(message[4:6], "big")
    signature = message[8:8 + int.from_bytes(message[6:8], "big")]
    index = None
    for position in range(len(state.transcript)):
        entry = state.transcript[position]
        if entry[0] == "S" and entry[1][0] == 15:
            index = position
            break
    if index is None:
        return True
    content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + state.transcript_hash(index)
    certificate = x509.load_der_x509_certificate(state.server_cert_13)
    key = certificate.public_key()
    try:                                                    # the key type of the scheme (section 4.3.3)
        key_oid = certificate.public_key_algorithm_oid.dotted_string
        if scheme in (0x0804, 0x0805, 0x0806) and key_oid != "1.2.840.113549.1.1.1":
            return False
        if scheme in (0x0809, 0x080A, 0x080B) and key_oid != "1.2.840.113549.1.1.10":
            return False
    except AttributeError:
        pass
    digests = {0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512,
               0x0809: hashes.SHA256, 0x080A: hashes.SHA384, 0x080B: hashes.SHA512,
               0x0403: hashes.SHA256, 0x0503: hashes.SHA384, 0x0603: hashes.SHA512}
    try:
        if scheme in (0x0804, 0x0805, 0x0806, 0x0809, 0x080A, 0x080B) and isinstance(key, rsa.RSAPublicKey):
            digest = digests[scheme]()
            key.verify(signature, content, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
        elif scheme in (0x0403, 0x0503, 0x0603) and isinstance(key, ec.EllipticCurvePublicKey):
            if key.curve.name != {0x0403: "secp256r1", 0x0503: "secp384r1", 0x0603: "secp521r1"}[scheme]:
                return False
            key.verify(signature, content, ec.ECDSA(digests[scheme]()))
        elif scheme == 0x0807 and isinstance(key, _ed25519.Ed25519PublicKey):
            key.verify(signature, content)
        elif scheme == 0x0808 and isinstance(key, _ed448.Ed448PublicKey):
            key.verify(signature, content)
        else:
            return False
    except Exception:
        return False
    return True


# RFC 9846 Table 1: the messages an extension may appear in (CH, SH, EE, CT, CR, NST, HRR); other types are ignorable
EXT_TABLE = {
    0: "CH EE CR", 5: "CH CR CT", 10: "CH EE", 13: "CH CR", 14: "CH EE", 15: "CH EE", 16: "CH EE", 19: "CH EE", 20: "CH EE",
    21: "CH", 27: "CH CR", 28: "CH EE", 34: "CH CR CT", 39: "CH EE", 41: "CH SH", 42: "CH EE NST", 43: "CH SH HRR",
    44: "CH HRR", 45: "CH", 47: "CH CR", 48: "CR", 49: "CH", 50: "CH CR", 51: "CH SH HRR", 52: "CH CR CT", 55: "CH EE",
    56: "CH EE", 57: "CH EE", 58: "CH EE", 0xfd00: "CH", 0xfe0d: "CH HRR EE",
}


def ext_allowed(message, ext_type):
    """False if Table 1 of RFC 9846 does not list the extension for the message (an unlisted type is not defined there)."""
    return ext_type not in EXT_TABLE or message in EXT_TABLE[ext_type].split()


def certificate_entries(body, tls13):
    """[(cert_data, [(ext type, data)])] of a Certificate message body (after the 4-byte header); None if malformed."""
    try:
        offset = 1 + body[0] if tls13 else 0
        total = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        end = offset + total
        if end != len(body):
            return None
        entries = []
        while offset < end:
            length = int.from_bytes(body[offset:offset + 3], "big")
            cert = body[offset + 3:offset + 3 + length]
            offset += 3 + length
            extensions = []
            if tls13:
                ext_len = int.from_bytes(body[offset:offset + 2], "big")
                extensions = extension_list(body[offset + 2:offset + 2 + ext_len])
                if extensions is None or offset + 2 + ext_len > end:
                    return None
                offset += 2 + ext_len
            entries.append((cert, extensions))
        return entries
    except Exception:
        return None


# ---------------------------------------------------------------------------------------------------------------
# The client's own certificates (RFC 9846 sections 4.4.2, 4.4.3, RFC 5246 sections 7.4.6, 7.4.8): self-signed
# certificates with a fresh ECDSA P-256 key or the party's RSA key, built to match the server's CertificateRequest
# ---------------------------------------------------------------------------------------------------------------
CRED_STORE = {}      # certificate DER -> (kind, private key), recorded by the generator, recalled when the message is sent
SIGN_CACHE = {}      # (kind of signature, transcript hash, algorithm) -> signature: a signature is computed once per message
_RSA_KEY = []


# The party's own RSA-3072 key, fixed: its modulus holds no byte 0x20/0x0a (an RSA public key in a certificate would otherwise count as
# generated structure in every certificate, because the bytes are in the DER), and nothing is generated at start-up.  It is a test key
# of the party; the servers never trust it (they trust the CA of the setup, or nothing).
_RSA_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIG/AIBADANBgkqhkiG9w0BAQEFAASCBuYwggbiAgEAAoIBgQDNIh7G+6DO+xL2
kZgomB0o9OFrUlaUOBtb2VFnJWECZdA3gyw9iGbF4XSkyKkTdTuB2pIPRUTJ0Hy9
Su2yp5t8kQeAxKDsQPZb0sb4lD54hA4XdyIXsYBPAhb0Zv0zR5M9uP4Xdlhvs8oN
7kChWAhk3cc5Rv74UklKS6oD2Ho1iSeqSDO+YoAH4K8oKptn+WvMh3oOJSKWmiwF
YXJQ5I1h1ZEwqbcxRli7BguBHBFuwH0PnWhGn7RQ2NojYfI5aHPEDlzjD8URvvb4
ejpU6yeKXNDJN+OgP4uwvj8JCGa0vNUcsGzjNaaEqJ2XphDUkiheNR+XibVC9yir
co1XNf9yHGvXHu6k7a0T4RShPI4nJkHdu/VCqqXlAwTZW+Qt+nDF+zpFiIEBOblp
EJDhJn/NssP9ubv1yNwzfbHBit/VgKgfxl6FsfbOG9hT/AIxKwUa50sXmAuFZXRl
QdVklnYl8EztmgNTqOxHXgnc+GONPX/O84nNm0DOFwlvaZMsJzUCAwEAAQKCAYAA
un59J1sZUBul57Ok1Ij6s/fuH3mB74TFWsdqwkCK3kI158YQAg/VrV8hDcZoLtBD
PfXpKbMhhWECkshKUhaTItdx0Ce9XCQveNdaYvnYD9BcFqP2w4vt+AWc4K0t2pu/
ub63ztMqJx3kv2hrkBV1AIxyGyDCGi9f/gESEKNGlwCaxXcF0f1l1WaLTELVDoeB
6l1QWC64TxQwnAkHi/A93zROz3bhZzxivI5R33glKtz0aXBBcI7gc6fZ0PQgINMV
8Xri6OjzEB1WxZImvzU5cSAfveV5geQMXswBNwqGN7dqJlSDZJHP7CqtHTFUu4eL
8UEC5nyMDkn1Kr0IbHeNnOanFjHwS0dSxvH7SsvMzgTippHr76irSYJFjGmTQncu
PxdTu3Q97OrM7cvT4oz9rQp31IydzW36fFtFEc1Tsgo7PP3cEzLkyvA7+dnXXEbP
xSmdBMxEH21AwyF8kKRMvF7/P8OI1Qy30qtOgSxF/lVZ46cWV69WzSZJSeQq0QcC
gcEA9vGfgGVwI/Agsfe9iC+mlt5LfSYSg9rmeAOcwqpo/VOLFmOCqltxcT0yljCr
gDZbLtRuGFDfnDyrpIZrvAm4dBuukHZJ2Ra84uunhOVmaYqhzB9jgS1OuHedLbil
eFMOlA5zoAk7FAmOl1QH/kTzNpLDWwpFyWlE6ZEyY3Fo1id3Wjx27S8frFMs+FQj
KFnitEJ/d6I3MoJQxX6KN7o6bcAblNwJ8BO4gf7ViQ++6E8cLBfN4Y0J6D6kgXJU
gGjTAoHBANSn99YMbh+vKeUdfszNzP+CMq6OtDf5Af64QTwZyETFRV9CPIE5JGtA
9k3yoahoF/YM/+wROnK6m1tib+OvXGLhTJ0SE14f2rb0W7vobX3pOk4sZasnDAnN
Eb8M87Vkb9xl7+viIOUQTdpc5F1GAzMuCwsPOw6TIOxC7WzRyIt8Vdi1cbJg4IHh
ATaZBfMJ6HhN6ZtXbSatkArd992B8BvpF1l4xEls3cADUV47A+vxQosbDkWiNH8U
xvl4QGiq1wKBwEW4LCcs/H85AZIdduZnRapcsoVv5VRSzjTeGDkhsaisGJ3GlJKS
ZLHq7EhZD2KQdif/k+HLm4ZZ3sABr5MUT36AfkWNEAZ5k/ShQdeUiNiNambeCdLj
vtD3/Gl3M0iIcpo8hkqNsJ9Un2x8LhGM1/n1b7BZcyCNVwZ2lvpaf5XO6LSSU6Vd
Y5zcktq9rntq/UWVbLWTF/BruHA57L4VFv/7eA4MHcYpWzNghls/FdAy3apZQihH
EKAAZ6OgatkiPwKBwH73fpCtQT7nnXLvRlrPcVsIiGwSReW5ZYiIyGIy3pC426+B
Y5Cf5m+nDKgDeqOK6ut8XXy72JLReZp5Tma5t8ZN0Cljtm6XREXB5dducZkgnDA6
b8VdfeGIL9VKzWN7ARKtRi8nBw7cyi7bEXnjKFvxXKSQxmjwTVLirtEu+7bUWIkX
5DdlggXpqojHmna+bq8NjbGy5DeYnwzt9GSrhQmVBNzlrwRL3KYdFQLW54OCu4FE
eSP4MbHCXP5r3sDfZwKBwFYC+scJ/VYU9Rk+jU0PXbd+SxbJlkQrFFnXasjYs2mb
uYb5xQurQ0lbPR9ifbV6nmjRBvL08yuZshXN4gyJ2JX/S1Qe3jaQKMWqkSbTPiS4
3ZCE53WCcYoxYN4TEZaF8tTtUfusa+nqKEZxsMOSplIV7JO8Vgm5o2dvpiNa3InG
oUMEq5UrM8ONapjW6eFyvEIwmQlSlKVYk5oqEQI9+MakEOGcVw+E7Aesqck7IAy/
Ier9Dp9NCzxc7KVf3AALTw==
-----END PRIVATE KEY-----
"""


def rsa_client_key():
    if not _RSA_KEY:
        from cryptography.hazmat.primitives import serialization as _s
        _RSA_KEY.append(_s.load_pem_private_key(_RSA_KEY_PEM, None))
    return _RSA_KEY[0]


def parse_oid_filters(data):
    """[(oid DER content, values DER)] of an oid_filters extension body."""
    filters, offset = [], 2
    while offset < len(data):
        n = data[offset]
        oid = data[offset + 1:offset + 1 + n]
        offset += 1 + n
        m = int.from_bytes(data[offset:offset + 2], "big")
        filters.append((oid, data[offset + 2:offset + 2 + m]))
        offset += 2 + m
    return filters


def _der_oids(values):
    out, offset = [], 0
    if values[:1] == b"\x30":                          # ExtKeyUsageSyntax ::= SEQUENCE OF KeyPurposeId (RFC 5280)
        if values[1] & 0x80:
            offset = 2 + (values[1] & 0x7F)
        else:
            offset = 2
    values = bytes(values)
    while offset + 2 <= len(values) and values[offset] == 6:
        n = values[offset + 1]
        out.append(values[offset + 2:offset + 2 + n])
        offset += 2 + n
    return out


def new_client_certificate(kind, filters=(), sign="rsa256", via=False, breach=False):
    """The DER of a client certificate whose key is of `kind` ("rsa", "ec256", "ec384", "ec521", "ed25519") satisfying the
    oid_filters; `sign` is "rsa256/384/512" (signed by the party's RSA key with RSASSA-PKCS1-v1_5; an RSA key certifies
    itself) or "self" (an ECDSA/EdDSA key certifies itself).  With `breach` the certificate lacks the extensions (Key Usage, Extended Key
    Usage: the two the client recognizes, RFC 9846 section 4.3.5) that the filters name: it does not match the filters."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
    if kind == "cfg":                              # the configured credential (an RSA key and its certificate)
        return configured_credential()[0]
    if kind in ("rsa", "rsa_pss"):                 # rsa_pss: the same RSA key in a certificate with the id-RSASSA-PSS key OID
        key = rsa_client_key()
    elif kind == "ed25519":
        key = _ed.Ed25519PrivateKey.generate()
    elif kind == "ed448":
        key = _ed448.Ed448PrivateKey.generate()
    else:
        key = _ec.generate_private_key({"ec256": _ec.SECP256R1, "ec384": _ec.SECP384R1, "ec521": _ec.SECP521R1}[kind]())
    bits = {0}                                     # digitalSignature
    purposes = []
    for oid, values in filters:
        if oid == b"\x55\x1d\x0f" and len(values) >= 4 and values[0] == 3:      # Key Usage: a BIT STRING
            unused, raw = values[2], values[3:2 + values[1]]
            for index in range(len(raw) * 8 - unused):
                if raw[index // 8] & (0x80 >> (index % 8)):
                    bits.add(index)
        elif oid == b"\x55\x1d\x25":              # Extended Key Usage: the key purpose OIDs
            purposes.append(ExtendedKeyUsageOID.CLIENT_AUTH)
            for content in _der_oids(values):
                if content != b"\x55\x1d\x25\x00":
                    purposes.append(x509.ObjectIdentifier(".".join(_oid_text(content))))
    usage = x509.KeyUsage(digital_signature=0 in bits, content_commitment=1 in bits, key_encipherment=2 in bits,
                          data_encipherment=3 in bits, key_agreement=4 in bits or 7 in bits or 8 in bits,
                          key_cert_sign=5 in bits, crl_sign=6 in bits, encipher_only=7 in bits, decipher_only=8 in bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fandango-client-" + _os.urandom(3).hex())])
    ca = configured_ca()
    self_signed = sign == "self" or (kind == "rsa" and ca is None)
    if self_signed:
        issuer = name
    elif via:                                      # issued by the party's intermediate CA (chains of three certificates)
        issuer = intermediate_name()
    elif ca is not None:
        issuer = ca[1]
    else:
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fandango-Client-CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
               .serial_number(int.from_bytes(_os.urandom(8), "big") >> 1 | 1)
               .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
               )
    named = {oid for oid, _ in filters}
    if not (breach and b"\x55\x1d\x0f" in named):
        builder = builder.add_extension(usage, critical=True)
    if purposes and not breach:
        builder = builder.add_extension(x509.ExtendedKeyUsage(purposes), critical=False)
    hash_class = {"rsa224": hashes.SHA224, "rsa256": hashes.SHA256, "rsa384": hashes.SHA384, "rsa512": hashes.SHA512}.get(sign)
    if kind == "rsa" and self_signed:
        certificate = builder.sign(key, hash_class() if hash_class else hashes.SHA256())
    elif sign == "self":
        certificate = builder.sign(key, None if kind in ("ed25519", "ed448") else {"ec256": hashes.SHA256, "ec384": hashes.SHA384, "ec521": hashes.SHA512}[kind]())
    else:
        certificate = builder.sign(rsa_client_key() if via or ca is None else ca[0], hash_class())
    der = certificate.public_bytes(_ser.Encoding.DER)
    if kind == "rsa_pss":
        der = rsa_pss_certificate(der, rsa_client_key() if via or ca is None else ca[0], hash_class or hashes.SHA256)
    CRED_STORE[der] = (kind, key)
    if len(CRED_STORE) > 2000:
        CRED_STORE.pop(next(iter(CRED_STORE)))
    return der


def intermediate_name():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fandango-Intermediate-CA")])


def intermediate_certificate():
    """The DER of the certificate of the party's intermediate CA (the party's RSA key, basicConstraints CA, keyCertSign), issued by
    the CA of the setup (else by the party's own CA): the middle certificate of a chain of three."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    key = rsa_client_key()
    ca = configured_ca()
    now = datetime.datetime.now(datetime.timezone.utc)
    issuer = ca[1] if ca is not None else x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Fandango-Client-CA")])
    certificate = (x509.CertificateBuilder().subject_name(intermediate_name()).issuer_name(issuer).public_key(key.public_key())
                   .serial_number(int.from_bytes(_os.urandom(8), "big") >> 1 | 1)
                   .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                   .sign(ca[0] if ca is not None else key, hashes.SHA256()))
    return certificate.public_bytes(_ser.Encoding.DER)


_PARTY_CA = []


def ocsp_response_for(der):
    """The DER of an OCSPResponse (RFC 6960, status successful, basic response: the certificate `der` is good) signed by the CA of
    the setup (else the party's RSA key)."""
    import datetime
    from cryptography import x509
    from cryptography.x509 import ocsp
    from cryptography.hazmat.primitives import hashes
    certificate = x509.load_der_x509_certificate(der)
    ca = configured_ca()
    if ca is not None:
        issuer_certificate, issuer_key = ca[2], ca[0]
    else:
        issuer_key = rsa_client_key()
        if not _PARTY_CA:
            _PARTY_CA.append(client_ca_certificate("rsa256"))
        issuer_certificate = x509.load_der_x509_certificate(_PARTY_CA[0])
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    produced = now - datetime.timedelta(seconds=int.from_bytes(_os.urandom(2), "big"))
    builder = (ocsp.OCSPResponseBuilder()
               .add_response(cert=certificate, issuer=issuer_certificate, algorithm=hashes.SHA1(), cert_status=ocsp.OCSPCertStatus.GOOD,
                             this_update=produced, next_update=produced + datetime.timedelta(days=7), revocation_time=None, revocation_reason=None)
               .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_certificate))
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(_ser.Encoding.DER)


def _der_tlv(tag, content):
    n = len(content)
    if n < 128:
        return bytes([tag, n]) + content
    size = (n.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + n.to_bytes(size, "big") + content


def rsa_pss_certificate(der, signing_key, hash_class):
    """The certificate `der` (an rsaEncryption key) with the key's AlgorithmIdentifier replaced by id-RSASSA-PSS (RFC 4055 section
    3.1: the parameters are absent, so the key is not restricted), signed again by `signing_key` with RSASSA-PKCS1-v1_5: the
    x509 builder of the cryptography library cannot issue a certificate with this key type (RFC 9846 section 4.2.3: rsa_pss_pss)."""
    from cryptography.hazmat.primitives.asymmetric import padding
    _, certificate, _ = der_item(der, 0)
    _, tbs, end = der_item(certificate, 0)
    algorithm_start = end
    _, algorithm, end = der_item(certificate, algorithm_start)
    algorithm_der = certificate[algorithm_start:end]
    items, offset = [], 0
    while offset < len(tbs):
        tag, content, next_offset = der_item(tbs, offset)
        items.append((tag, content))
        offset = next_offset
    index = 1 if items[0][0] == 0xA0 else 0
    _, spki = items[index + 5]
    _, _, end = der_item(spki, 0)
    new_algorithm = _der_tlv(0x30, _der_tlv(0x06, bytes.fromhex("2a864886f70d01010a")))
    items[index + 5] = (0x30, new_algorithm + spki[end:])
    new_tbs = _der_tlv(0x30, b"".join(_der_tlv(tag, content) for tag, content in items))
    signature = signing_key.sign(new_tbs, padding.PKCS1v15(), hash_class())
    return _der_tlv(0x30, new_tbs + algorithm_der + _der_tlv(0x03, b"\x00" + signature))


def dh_client_certificate(p, g, signer="rsa256"):
    """A client certificate that holds a Diffie-Hellman key of the parameters (p, g) (dhpublicnumber, RFC 3279 section 2.3.3), issued
    like the party's other certificates and signed with RSA (rsa_fixed_dh, RFC 5246 section 7.4.6): the DER of an RSA certificate
    with the SubjectPublicKeyInfo replaced and the signature made again.  The private value stays in DH_STORE (the key of the
    implicit ClientKeyExchange, section 7.4.7.2)."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    base = new_client_certificate("rsa", [], signer)
    ca = configured_ca()
    signing_key = rsa_client_key() if ca is None else ca[0]
    hash_class = {"rsa256": hashes.SHA256, "rsa384": hashes.SHA384, "rsa512": hashes.SHA512}[signer]
    p_int, g_int = int.from_bytes(p, "big"), int.from_bytes(g, "big")
    public = new_dh_share(p, g)                                       # y = g^x mod p, x kept in DH_STORE
    integer = lambda value: _der_tlv(0x02, (b"\x00" if value[0] & 0x80 else b"") + value)
    q = ((p_int - 1) // 2).to_bytes((p_int.bit_length() + 7) // 8, "big").lstrip(b"\x00")
    domain = _der_tlv(0x30, integer(p.lstrip(b"\x00")) + integer(g.lstrip(b"\x00")) + integer(q))
    algorithm = _der_tlv(0x30, _der_tlv(0x06, bytes.fromhex("2a8648ce3e0201")) + domain)
    spki = _der_tlv(0x30, algorithm + _der_tlv(0x03, b"\x00" + integer(public)))
    _, certificate, _ = der_item(base, 0)
    _, tbs, end = der_item(certificate, 0)
    algorithm_start = end
    _, _, end = der_item(certificate, algorithm_start)
    signature_algorithm = certificate[algorithm_start:end]
    items, offset = [], 0
    while offset < len(tbs):
        tag, content, offset = der_item(tbs, offset)
        items.append((tag, content))
    index = 1 if items[0][0] == 0xA0 else 0
    new_items = [_der_tlv(tag, content) for tag, content in items]
    new_items[index + 5] = spki
    new_tbs = _der_tlv(0x30, b"".join(new_items))
    signature = signing_key.sign(new_tbs, padding.PKCS1v15(), hash_class())
    return _der_tlv(0x30, new_tbs + signature_algorithm + _der_tlv(0x03, b"\x00" + signature))


_CA = []


def configured_ca():
    """(private key, subject Name, certificate) of the CA of the settings CLIENT_CA_CERT_FILE / CLIENT_CA_KEY_FILE, or None."""
    if not CLIENT_CA_CERT_FILE or not CLIENT_CA_KEY_FILE:
        return None
    if not _CA:
        try:
            from cryptography import x509
            certificate = x509.load_pem_x509_certificate(open(CLIENT_CA_CERT_FILE, "rb").read())
            key = _ser.load_pem_private_key(open(CLIENT_CA_KEY_FILE, "rb").read(), None)
            _CA.append((key, certificate.subject, certificate))
        except Exception:
            _CA.append(None)
    return _CA[0]


_CONFIGURED = []


def configured_credential():
    """(DER, key, kind, certificate) of the credential of the settings CLIENT_CERT_FILE / CLIENT_KEY_FILE (an RSA, ECDSA P-256/384/521
    or Ed25519 key), registered as a client credential of that kind."""
    if not _CONFIGURED:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        certificate = x509.load_pem_x509_certificate(open(CLIENT_CERT_FILE, "rb").read())
        key = _ser.load_pem_private_key(open(CLIENT_KEY_FILE, "rb").read(), None)
        if isinstance(key, _rsa.RSAPrivateKey):
            kind = "rsa"
        elif isinstance(key, _ec.EllipticCurvePrivateKey):
            kind = {"secp256r1": "ec256", "secp384r1": "ec384", "secp521r1": "ec521"}[key.curve.name]
        else:
            kind = "ed25519"
        _CONFIGURED.append((certificate.public_bytes(_ser.Encoding.DER), key, kind, certificate))
    der, key, kind, certificate = _CONFIGURED[0]
    CRED_STORE[der] = (kind, key)
    return der, key, kind, certificate


def configured_credential_available():
    """True when the settings name a readable credential."""
    try:
        return bool(CLIENT_CERT_FILE and CLIENT_KEY_FILE) and configured_credential()[2] is not None
    except Exception:
        return False


def client_ca_certificate(sign="rsa256"):
    """The DER of the self-signed certificate of the party's RSA key, the issuer of the client certificates it signs."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fandango-Client-CA")])
    key = rsa_client_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    for _ in range(200):          # the bytes 0x20 and 0x0a would make the value look like text
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(int.from_bytes(_os.urandom(8), "big") >> 1 | 1)
                       .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=365))
                       .sign(key, {"rsa224": hashes.SHA224, "rsa256": hashes.SHA256, "rsa384": hashes.SHA384, "rsa512": hashes.SHA512}[sign]()))
        der = certificate.public_bytes(_ser.Encoding.DER)
        if b" " not in der and b"\n" not in der:
            break
    return der


def _oid_text(content):
    first = content[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return parts


def sign_with(kind, key, content, scheme):
    """A signature over `content` by a client credential; scheme is a TLS 1.3 SignatureScheme (or a TLS 1.2 pair)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    if scheme in (0x0807, 0x0808):
        return key.sign(content)
    digest = {0x0804: hashes.SHA256, 0x0805: hashes.SHA384, 0x0806: hashes.SHA512,
              0x0809: hashes.SHA256, 0x080A: hashes.SHA384, 0x080B: hashes.SHA512,
              0x0403: hashes.SHA256, 0x0503: hashes.SHA384, 0x0603: hashes.SHA512, 0x0303: hashes.SHA224,
              0x0401: hashes.SHA256, 0x0501: hashes.SHA384, 0x0601: hashes.SHA512, 0x0301: hashes.SHA224,
              0x0201: hashes.SHA1, 0x0101: hashes.MD5}[scheme]()
    if scheme in (0x0804, 0x0805, 0x0806, 0x0809, 0x080A, 0x080B):
        return key.sign(content, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
    if scheme in (0x0401, 0x0501, 0x0601, 0x0301, 0x0201, 0x0101):
        return key.sign(content, padding.PKCS1v15(), digest)
    return key.sign(content, _ec.ECDSA(digest))


def _hash_messages(self, messages):
    h = _h(self.hash_name or "sha256")()
    if self.hrr_seen and self.version == 0x0304:
        first = hashlib.new(self.hash_name or "sha256", self.client_hello_msgs[0]).digest()
        h.update(b"\xfe\x00\x00" + bytes([len(first)]) + first)
        messages = [m for m in messages if not (m[0] == "C" and m[1][0] == 1 and m[1] is self.client_hello_msgs[0])]
    for _, message in messages:
        h.update(message)
    return h.digest()


def _post_hs_hash(self):
    """RFC 9846 section 4.4.1: the handshake context of a post-handshake authentication: ClientHello .. client Finished
    and the CertificateRequest with the messages that answer it."""
    base = self.handshake_end or len(self.transcript)
    last_cr = None
    for position in range(base, len(self.transcript)):
        if self.transcript[position][0] == "S" and self.transcript[position][1][0] == 13:
            last_cr = position
    messages = list(self.transcript[:base])
    if last_cr is not None:
        messages += [m for m in self.transcript[last_cr:] if m[1][0] in (13, 11, 15)]
    return _hash_messages(self, messages)


def _post_finished(self):
    hn = self.hash_name
    key = hkdf_expand_label(hn, self.secrets["c_ap"], b"finished", b"", _h(hn)().digest_size)
    return _hmac.new(key, _post_hs_hash(self), _h(hn)).digest()


class _ThreadCell:
    """A cell per thread (the constraints and the generators of Fandango may run in different threads)."""
    def __init__(self):
        self._local = _threading.local()

    def __getitem__(self, index):
        return getattr(self._local, "value", None)

    def __setitem__(self, index, value):
        self._local.value = value


_REQ_OVERRIDE = _ThreadCell()    # a CertificateRequest being checked (a `where` on the received message looks at it before the party's state holds it)


def _last_certificate_request(self):
    if _REQ_OVERRIDE[0] is not None:
        return _REQ_OVERRIDE[0]
    for direction, message in reversed(self.transcript):
        if direction == "S" and message[0] == 13:
            return message
    return None


def _request_extensions(self):
    """{type: data} of the last CertificateRequest (TLS 1.3), and its certificate_request_context."""
    message = _last_certificate_request(self)
    if message is None or (self.version != 0x0304 and _REQ_OVERRIDE[0] is None):
        return {}, b""
    context = message[5:5 + message[4]]
    return dict(extension_list(message[7 + message[4]:]) or []), context


def _client_signing_content(self, post):
    th = _post_hs_hash(self) if post else self.transcript_hash()
    return b"\x20" * 64 + b"TLS 1.3, client CertificateVerify\x00" + th


def _own_certificate(self):
    """(kind, key) of the certificate the client sent last."""
    for direction, message in reversed(self.transcript):
        if direction == "C" and message[0] == 11:
            body = message[4:]
            offset = 1 + body[0] if self.version == 0x0304 else 0
            if int.from_bytes(body[offset:offset + 3], "big") == 0:
                return None
            length = int.from_bytes(body[offset + 3:offset + 6], "big")
            return CRED_STORE.get(body[offset + 6:offset + 6 + length])
    return None


def _client_signature(self, scheme, post):
    credential = _own_certificate(self)
    if credential is None:
        return bytes(64)
    content = _client_signing_content(self, post)
    cache_key = ("13", content, scheme)
    if cache_key not in SIGN_CACHE:
        SIGN_CACHE[cache_key] = sign_with(credential[0], credential[1], content, scheme)
        if len(SIGN_CACHE) > 4000:
            SIGN_CACHE.pop(next(iter(SIGN_CACHE)))
    return SIGN_CACHE[cache_key]


def _client_signature_12(self, algorithm):
    """TLS 1.2 CertificateVerify (RFC 5246 section 7.4.8): the signature over all handshake messages so far."""
    credential = _own_certificate(self)
    if credential is None:
        return bytes(64)
    content = b"".join(m for _, m in self.transcript)
    cache_key = ("12", content, algorithm)
    if cache_key not in SIGN_CACHE:
        scheme = algorithm
        if credential[0] != "rsa":
            from cryptography.hazmat.primitives import hashes
            hash_cls = {1: hashes.MD5, 2: hashes.SHA1, 3: hashes.SHA224, 4: hashes.SHA256, 5: hashes.SHA384, 6: hashes.SHA512}[algorithm >> 8]
            SIGN_CACHE[cache_key] = credential[1].sign(content, _ec.ECDSA(hash_cls()))
        else:
            SIGN_CACHE[cache_key] = sign_with("rsa", credential[1], content, scheme)
        if len(SIGN_CACHE) > 4000:
            SIGN_CACHE.pop(next(iter(SIGN_CACHE)))
    return SIGN_CACHE[cache_key]


TlsState.post_hs_hash = _post_hs_hash
TlsState.post_finished = _post_finished
TlsState.request_extensions = _request_extensions
TlsState.client_signature = _client_signature
TlsState.client_signature_12 = _client_signature_12


rsa_client_key()      # generated at import: the first request that needs it should not wait for it



# ---------------------------------------------------------------------------------------------------------------
# The client party.  The driver defines `Client` on top of this class (ClientNetworkParty), see its readme.
# ---------------------------------------------------------------------------------------------------------------
CLOSE_MARKER = b"\xff\xffCLOSED"   # what the grammar sees when the server closes the connection (no TLS data)


class ClientNetworkParty(NetworkParty):
    def __init__(self, *args, **kwargs):
        self.tls = TlsState()
        super().__init__(*args, **kwargs)

    def send(self, message, recipient):
        if hasattr(message, "to_bytes"):
            data = message.to_bytes()
        elif isinstance(message, str):
            data = message.encode("latin-1")
        else:
            data = bytes(message)
        if os.environ.get("TLS_DEBUG_LOG"):
            with open(os.environ["TLS_DEBUG_LOG"], "ab") as log:
                log.write(b"C " + data.hex().encode() + b"\n")
        super().send(self.tls.outgoing(data), recipient)

    # A server that ends a connection sends its closing alert and closes the transport within a millisecond: the alert is handed to the
    # grammar together with the close when the close follows at once (a fatal alert or close_notify is held for up to 30 ms), so that the
    # grammar's next client message is not planned between the two (the close would then arrive after it, as a message nobody expects).
    def receive(self, message, sender):
        import threading
        lock = self.__dict__.setdefault("_hold_lock", threading.Lock())
        if message is None:
            with lock:
                held, self._held = self.__dict__.get("_held"), None
                if held is not None:
                    # one chunk: the grammar parses the alert and the close as two messages, but nothing is planned between them
                    held[2].cancel()
                    super().receive(held[0] + CLOSE_MARKER, held[1])
                else:
                    super().receive(CLOSE_MARKER, sender)
            return
        if isinstance(message, str):
            message = message.encode("latin-1")
        plain = self.tls.incoming(bytes(message))
        if os.environ.get("TLS_DEBUG_LOG"):
            with open(os.environ["TLS_DEBUG_LOG"], "ab") as log:
                log.write(b"S " + plain.hex().encode() + b"\n")
        if not plain:
            return
        with lock:
            held, self._held = self.__dict__.get("_held"), None
            if held is not None:
                held[2].cancel()
                super().receive(held[0], held[1])
            if closing_alert(plain):
                timer = threading.Timer(0.03, self._release_held)
                self._held = (plain, sender, timer)
                timer.start()
            else:
                super().receive(plain, sender)

    def _release_held(self):
        with self.__dict__["_hold_lock"]:
            held, self._held = self.__dict__.get("_held"), None
            if held is not None:
                try:
                    super().receive(held[0], held[1])
                except Exception:
                    pass


def closing_alert(plain):
    """True when the plaintext records `plain` (each followed by the record marker) hold a fatal alert or close_notify."""
    offset = 0
    while offset + 5 <= len(plain):
        length = int.from_bytes(plain[offset + 3:offset + 5], "big")
        if plain[offset] == 0x15 and length >= 2 and (plain[offset + 5] == 2 or plain[offset + 6] == 0):
            return True
        offset += 5 + length
        if plain[offset:offset + 2] == b"\xff\xfe":
            offset += 2
    return False


def session_state():
    """The TLS state of the running session; None when the grammar runs without a session (offline parsing)."""
    try:
        return FandangoParty.instance("Client").tls
    except Exception:
        return None

# ==================================================================================================================
# Session (RFC 9846 section 2 and appendix A: the client state machine; Fandango is the client)
# A timer is started before the request it guards (the server may answer before Fandango could start it afterwards).
# ==================================================================================================================
<start> ::= <state_start>

# START (RFC 9846 A.1): the client sends a ClientHello, the server answers with ServerHello, HelloRetryRequest or an alert
<state_start> ::= (
      <Client:req_client_hello> (
          <Server:in_server_hello_13> <Server:in_ccs>? <state_wait_server_flight>
        | <Server:in_server_hello_12> <state_wait_server_flight_12>
        | <Server:in_hello_retry_request> <Server:in_ccs>? <state_after_hrr_general>
        | <Server:in_hello_retry_request_cookie> <Server:in_ccs>? <state_after_hrr_general>
        | <Server:in_hello_retry_request_cookie_only> <Server:in_ccs>? <state_after_hrr_general>
        | <exch_alert_flight_13_0>
        | <server_closes> <state_end> )
    | <Client:req_client_hello_13_only> (
          <Server:in_server_hello_13> <Server:in_ccs>? <state_wait_server_flight>
        | <Server:in_hello_retry_request> <Server:in_ccs>? <state_after_hrr_general>
        | <Server:in_hello_retry_request_cookie> <Server:in_ccs>? <state_after_hrr_general>
        | <Server:in_hello_retry_request_cookie_only> <Server:in_ccs>? <state_after_hrr_general>
        | <exch_alert_flight_13_0o>
        | <server_closes> <state_end> )
    | <Client:req_client_hello_hrr> (
          <Server:in_server_hello_13> <Server:in_ccs>? <state_wait_server_flight>
        | <Server:in_hello_retry_request> <Server:in_ccs>? <state_after_hrr>
        | <Server:in_hello_retry_request_cookie> <Server:in_ccs>? <state_after_hrr_cookie>
        | <Server:in_hello_retry_request_cookie_only> <Server:in_ccs>? <state_after_hrr_cookie_only>
        | <exch_alert_flight_13_0o>
        | <server_closes> <state_end> )
    | <Client:req_client_hello_no_overlap> (
          <Server:in_alert_no_overlap> <Server:in_closed>? <state_end> )
    | <Client:req_client_hello_psk_only> (
          <server_closes> <state_end> )
    | <Client:req_unexpected_first_handshake> (
          <Server:in_alert_unexpected_message> <state_closed> )
    | <Client:req_client_hello_12> (
          <Server:in_server_hello_12> <state_wait_server_flight_12>
        | <Server:in_server_hello_12_dh_static> <state_wait_server_flight_12_dh>
        | <exch_alert_flight_12_0>
        | <server_closes_12> <state_end> )
    | <Client:req_client_hello_12_default> (
          <Server:in_server_hello_12> <state_wait_server_flight_12>
        | <Server:in_server_hello_12_dh_static> <state_wait_server_flight_12_dh>
        | <exch_alert_flight_12_0>
        | <server_closes_12> <state_end> )
    | <Client:req_client_hello_12_legacy_hash> (
          <Server:in_server_hello_12> <state_wait_server_flight_12>
        | <Server:in_server_hello_12_dh_static> <state_wait_server_flight_12_dh>
        | <exch_alert_flight_12_0>
        | <server_closes_12> <state_end> ) )

# After a HelloRetryRequest (RFC 9846 sections 4.1.4, 4.2.2): the client sends a second ClientHello.  One state per reply class of the
# HelloRetryRequest, because the second ClientHello differs (key_share of the selected group; with a cookie; the cookie alone).
<state_after_hrr> ::= (
      <Client:req_ccs_compat_before_second_hello>? <Client:req_client_hello_after_hrr> <replies_second_hello>
    | <exch_alert_handshake_13_after_hrr>
    | <server_closes> <state_end> )
<state_after_hrr_cookie> ::= (
      <Client:req_ccs_compat_before_second_hello>? <Client:req_client_hello_after_hrr_cookie> <replies_second_hello>
    | <exch_alert_handshake_13_after_hrr>
    | <server_closes> <state_end> )
<state_after_hrr_cookie_only> ::= (
      <Client:req_ccs_compat_before_second_hello>? <Client:req_client_hello_after_hrr_cookie_only> <replies_second_hello>
    | <exch_alert_handshake_13_after_hrr>
    | <server_closes> <state_end> )
<replies_second_hello> ::= (
      <Server:in_server_hello_13_after_hrr> <Server:in_ccs>? <state_wait_server_flight>
    | <exch_alert_flight_13_0h>
    | <server_closes> <state_end> )
# A HelloRetryRequest after a first ClientHello whose forms the second ClientHello cannot repeat (see the TODO at <req_client_hello_hrr>): the
# client ends the handshake with an alert
<state_after_hrr_general> ::= (
      <exch_alert_handshake_13_after_hrr>
    | <server_closes> <state_end> )

# WAIT_EE .. WAIT_FINISHED (RFC 9846 A.1): the server flight, encrypted with the handshake keys
<state_wait_server_flight> ::= (
      <Server:in_encrypted_extensions> (
          ( <Server:in_certificate_request_13> | <Server:in_certificate_request_13_deprecated> ) (
              <Server:in_certificate_13> (
                  <Server:in_certificate_verify> (
                      <Server:in_finished> <state_client_auth>
                    | <exch_alert_flight_13_5>
                    | <server_closes> <state_end> )
                | <exch_alert_flight_13_4>
                | <server_closes> <state_end> )
            | <exch_alert_flight_13_3>
            | <server_closes> <state_end> )
        | ( <Server:in_certificate_request_13_nu> | <Server:in_certificate_request_13_deprecated_nu> ) (
              <Server:in_certificate_13> (
                  <Server:in_certificate_verify> (
                      <Server:in_finished> <state_client_auth_nu>
                    | <exch_alert_flight_13_5>
                    | <server_closes> <state_end> )
                | <exch_alert_flight_13_4>
                | <server_closes> <state_end> )
            | <exch_alert_flight_13_3>
            | <server_closes> <state_end> )
        | <Server:in_certificate_13> (
              <Server:in_certificate_verify> (
                  <Server:in_finished> <state_client_finished>
                | <exch_alert_flight_13_5>
                | <server_closes> <state_end> )
            | <exch_alert_flight_13_4>
            | <server_closes> <state_end> )
        | <exch_alert_flight_13_2>
        | <server_closes> <state_end> )
    | <exch_alert_flight_13_1>
    | <server_closes> <state_end> )

# The client's second flight (RFC 9846 section 4.4.4, D.4: a compatibility change_cipher_spec may precede it).  The
# server may send application data after its own Finished, before it has the client's (section 2: 0.5-RTT data), and
# NewSessionTicket messages (section 4.6.1) on its own initiative, or close the connection.  The client may instead
# abort with an alert (section 6).
<state_client_finished> ::= (
      <server_early_finished>
    | <Client:req_ccs_compat> <TimerControl:start_ticket> <Client:req_finished_13> <replies_after_finished>
    | <TimerControl:start_ticket> <Client:req_finished_13> <replies_after_finished>
    | <Client:req_ccs_compat> <TimerControl:start_ticket> <Client:req_finished_13_fragmented> <replies_after_finished>
    | <TimerControl:start_ticket> <Client:req_finished_13_fragmented> <replies_after_finished>
    | <exch_alert_handshake_13_before_finished> )

# The server asked for a certificate (RFC 9846 section 4.3.2): the client answers with an empty Certificate message
# (section 4.4.2) or with a Certificate that holds its own certificate, followed by a CertificateVerify (section 4.4.3)
<state_client_auth> ::= (
      <server_early_auth>
    | <Client:req_ccs_compat_after_request>? <TimerControl:start_ticket_after_auth> (
          <Client:req_certificate_empty> <state_after_empty_certificate>
        | <Client:req_certificate_13> <state_after_certificate>
        | <Client:req_certificate_13_filter_breach> <state_after_certificate>
        | <TimerControl:cancel_ticket_after_auth> <exch_alert_handshake_13_before_certificate> ) )

# the same where no certificate of the client fits the CertificateRequest (a request of the _nu rules): only the empty Certificate
<state_client_auth_nu> ::= (
      <server_early_auth_nu>
    | <Client:req_ccs_compat_after_request>? <TimerControl:start_ticket_after_auth> (
          <Client:req_certificate_empty> <state_after_empty_certificate>
        | <TimerControl:cancel_ticket_after_auth> <exch_alert_handshake_13_before_certificate> ) )
<server_early_auth_nu> ::= (
      <Server:in_app_data> <state_client_auth_nu>
    | <Server:in_key_update_not_requested> <state_client_auth_nu>
    | <Server:in_key_update_requested> <Client:req_ccs_compat_after_request>? <TimerControl:start_ticket_after_auth> (
          <Client:req_certificate_empty> <Client:req_finished_13_after_empty_certificate> <Client:req_key_update_answer> <replies_after_finished_after_auth> )
    | <server_closes> <state_end> )

# the server's states after the client's Certificate (RFC 9846 appendix A.2: WAIT_FINISHED after an empty one, WAIT_CV after one
# with certificates): the server may reject it with an alert (certificate_required, bad_certificate, unknown_ca, ...) at once; the
# timer of the ticket is already running (it is started before the first message that can be answered)
<state_after_empty_certificate> ::= (
      <Client:req_finished_13_after_empty_certificate> <replies_after_finished_after_auth>
    | <exch_alert_after_own_13>
    | <server_after_empty_certificate> )
# The client's alerts after its OWN Certificate / CertificateVerify (RFC 9846 section 6: an error alert, user_canceled with the close_notify that
# must follow it, or close_notify, at any time in the handshake): ONE client message each, as the Finished next to it, and the server's closure
# is accepted after it; the ticket timer that runs since the first message of the authentication ends the exchange
<exch_alert_after_own_13> ::= (
      <Client:req_alert_error_hs_13> (
          <server_closes> <TimerControl:cancel_ticket_after_auth> <state_end>
        | <Server:in_closed> <TimerControl:cancel_ticket_after_auth> <state_end>
        | <TimerEvent:expired_ticket_after_auth> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> (
          <server_closes> <TimerControl:cancel_ticket_after_auth> <state_end>
        | <TimerEvent:expired_ticket_after_auth> <state_end> )
    | <Client:req_alert_close_notify_hs_13> (
          <server_closes> <TimerControl:cancel_ticket_after_auth> <state_end>
        | <TimerEvent:expired_ticket_after_auth> <state_end> ) )

<server_after_empty_certificate> ::= (
      <Server:in_app_data> <state_after_empty_certificate>
    | <Server:in_key_update_not_requested> <state_after_empty_certificate>
    | <Server:in_key_update_requested> <Client:req_finished_13_after_empty_certificate> <Client:req_key_update_answer> <replies_after_finished_after_auth>
    | <server_closes> <state_end> )
<state_after_certificate> ::= (
      <Client:req_certificate_verify_13> <state_after_certificate_verify>
    | <exch_alert_after_own_13>
    | <server_after_certificate> )
<server_after_certificate> ::= (
      <Server:in_app_data> <state_after_certificate>
    | <Server:in_key_update_not_requested> <state_after_certificate>
    | <Server:in_key_update_requested> <Client:req_certificate_verify_13> <Client:req_finished_13_after_certificate> <Client:req_key_update_answer> <replies_after_finished_after_auth>
    | <server_closes> <state_end> )
<state_after_certificate_verify> ::= (
      <Client:req_finished_13_after_certificate> <replies_after_finished_after_auth>
    | <exch_alert_after_own_13>
    | <server_after_certificate_verify> )
<server_after_certificate_verify> ::= (
      <Server:in_app_data> <state_after_certificate_verify>
    | <Server:in_key_update_not_requested> <state_after_certificate_verify>
    | <Server:in_key_update_requested> <Client:req_finished_13_after_certificate> <Client:req_key_update_answer> <replies_after_finished_after_auth>
    | <server_closes> <state_end> )

# what the server may send on its own initiative after its Finished, before the client's second flight (RFC 9846 sections 2,
# 4.6.1: NewSessionTicket right after Finished when no client authentication is requested; 4.6.3: KeyUpdate after a Finished
# was sent; 6: alerts at any time)
<server_early_finished> ::= (
      <Server:in_app_data> <state_client_finished>
    | <Server:in_new_session_ticket> <state_client_finished>
    | <Server:in_key_update_not_requested> <state_client_finished>
    | <Server:in_key_update_requested> <TimerControl:start_ticket> <Client:req_finished_13> <Client:req_key_update_answer> <replies_after_finished>
    | <server_closes> <state_end> )
<server_early_auth> ::= (
      <Server:in_app_data> <state_client_auth>
    | <Server:in_key_update_not_requested> <state_client_auth>
    | <Server:in_key_update_requested> <Client:req_ccs_compat_after_request>? <TimerControl:start_ticket_after_auth> (
          <Client:req_certificate_empty> <Client:req_finished_13_after_empty_certificate> <Client:req_key_update_answer> <replies_after_finished_after_auth>
        | <Client:req_certificate_13> <Client:req_certificate_verify_13> <Client:req_finished_13_after_certificate> <Client:req_key_update_answer> <replies_after_finished_after_auth> )
    | <server_closes> <state_end> )

<replies_after_finished> ::= (
      <Server:in_app_data> <replies_after_finished>
    | <Server:in_new_session_ticket>+ (
          <TimerControl:cancel_ticket> <state_connected_13>
        | <TimerEvent:expired_ticket> <state_connected_13>
        | <server_error_closes> <TimerControl:cancel_ticket> <state_end>
        | <Server:in_alert_close_notify> <TimerControl:cancel_ticket> <state_half_closed_13> )
    | <server_error_closes> <TimerControl:cancel_ticket> <state_end>
    | <Server:in_alert_close_notify> <TimerControl:cancel_ticket> <state_half_closed_13>
    | <TimerEvent:expired_ticket> <state_connected_13> )
<replies_after_finished_after_auth> ::= (
      <Server:in_app_data> <replies_after_finished_after_auth>
    | <Server:in_new_session_ticket>+ (
          <TimerControl:cancel_ticket_after_auth> <state_connected_13>
        | <TimerEvent:expired_ticket_after_auth> <state_connected_13>
        | <server_error_closes> <TimerControl:cancel_ticket_after_auth> <state_end>
        | <Server:in_alert_close_notify> <TimerControl:cancel_ticket_after_auth> <state_half_closed_13> )
    | <server_error_closes> <TimerControl:cancel_ticket_after_auth> <state_end>
    | <Server:in_alert_close_notify> <TimerControl:cancel_ticket_after_auth> <state_half_closed_13>
    | <TimerEvent:expired_ticket_after_auth> <state_connected_13> )

# the server closes the connection with an error alert, or user_canceled and close_notify; a close_notify alone closes only its
# write side (the half-closed states of the connected states: the client may go on sending)
<server_error_closes> ::= <Server:in_alert> <Server:in_alert_close_notify>? <Server:in_closed>? | <Server:in_alert_user_canceled> <Server:in_alert_close_notify> <Server:in_closed>?
<server_error_closes_12> ::= <Server:in_alert_12_fatal> <Server:in_alert_close_notify>? <Server:in_closed>? | <Server:in_alert_user_canceled> ( <Server:in_alert_close_notify> <Server:in_closed>? )?

# the server closes the connection (RFC 9846 section 6.1): close_notify, a fatal alert, or user_canceled and close_notify
<server_closes> ::= <Server:in_alert_close_notify> <Server:in_closed>? | <Server:in_alert> <Server:in_alert_close_notify>? <Server:in_closed>? | <Server:in_alert_user_canceled> <Server:in_alert_close_notify> <Server:in_closed>?
# the server's compatibility change_cipher_spec comes right after its first handshake message (RFC 9846 appendix D.4): a server that ends the
# session after that message must have sent it too
where forall <x> in <server_closes>: ccs_compat_ok(<x>)

# Alerts of the client during the handshake (RFC 9846 section 6): an error alert, or user_canceled followed by
# close_notify, or close_notify.  The server closes the connection.
<exch_alert_handshake_13_after_hrr> ::= <exch_alert_handshake_13>
where forall <x> in <exch_alert_handshake_13_after_hrr>: hrr_ccs_ok(<x>)
<exch_alert_handshake_13_before_certificate> ::= <exch_alert_handshake_13>
<exch_alert_handshake_13_before_finished> ::= <exch_alert_handshake_13>
<exch_alert_handshake_13> ::= <TimerControl:start_hsa> (
      <Client:req_alert_error_hs_13> (
          <server_closes> <TimerControl:cancel_hsa> <state_end>
        | <Server:in_closed> <TimerControl:cancel_hsa> <state_end>
        | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> (
          <server_closes> <TimerControl:cancel_hsa> <state_end>
        | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_13> (
          <server_closes> <TimerControl:cancel_hsa> <state_end>
        | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes> <TimerControl:cancel_hsa> <state_end> )

# CONNECTED (RFC 9846 A.1); every exchange continues in the state its reply selects.  The messages the server sends on
# its own initiative are one shared nonterminal, accepted between two exchanges.
<state_connected_13> ::= (
      <exch_app_data_13>
    | <exch_key_update_not_requested>
    | <exch_key_update_requested>
    | <exch_key_update_requested_again>
    | <exch_close_notify_13>
    | <exch_error_alert_13>
    | <exch_unexpected_handshake_13>
    | <exch_user_canceled_13>
    | <server_initiated_13> )

# NewSessionTicket (section 4.6.1), KeyUpdate (4.6.3), a post-handshake CertificateRequest (4.6.2) and closure/error
# alerts (6) at any time after the handshake
<server_initiated_13> ::= (
      <Server:in_new_session_ticket> <state_connected_13>
    | <Server:in_app_data> <state_connected_13>
    | <Server:in_key_update_not_requested> <state_connected_13>
    | <Server:in_key_update_requested> <owed_answer_13>
    | <Server:in_certificate_request_post_hs> (
          <Client:req_certificate_post_empty> <Client:req_finished_post_after_empty> <state_connected_13>
        | <Client:req_certificate_post> <Client:req_certificate_verify_post> <Client:req_finished_post_after_certificate> <state_connected_13> )
    | <Server:in_certificate_request_post_hs_nu> <Client:req_certificate_post_empty> <Client:req_finished_post_after_empty> <state_connected_13>
    | <Server:in_alert_close_notify> <state_half_closed_13>
    | <Server:in_alert> <Server:in_alert_close_notify>? <Server:in_closed>? <state_end>
    | <Server:in_alert_user_canceled> <Server:in_alert_close_notify> <Server:in_closed>? <state_end> )

# The server has closed its write side with close_notify (RFC 9846 section 6.1): the client may still send, and ends with
# its own close_notify; the server usually closes the connection at once
<state_half_closed_13> ::= (
      <Server:in_closed> <state_end>
    | <TimerControl:start_half> <Client:req_app_data_13_half> ( <Server:in_closed> <TimerControl:cancel_half> <state_end> | <TimerEvent:expired_half> <state_half_closed_13> )
    | <TimerControl:start_half_close> <Client:req_alert_close_notify_half> ( <Server:in_closed> <TimerControl:cancel_half_close> <state_end> | <TimerEvent:expired_half_close> <state_end> ) )

# What the server sends in reply: application data (an echo, the output of a command), KeyUpdate messages (those a command makes
# gnutls-serv send: update_requested must be answered before the client's next application data, RFC 9846 section 4.6.3) and a
# post-handshake CertificateRequest (a command of gnutls-serv: section 4.6.2), in TLS 1.2 a HelloRequest (RFC 5246 section
# 7.4.1.1); a close ends the exchange.  gnutls-serv sends the output of a command ("Successfully executed command", application data)
# after the message the command makes it send, in the same flight: the application data is accepted after the KeyUpdate, the CertificateRequest and
# the HelloRequest too, before the timer is cancelled.
<exch_app_data_13> ::= <TimerControl:start_data> ( <Client:req_app_data_13> | <Client:req_app_data_13_split> | <Client:req_app_data_13_large> | <Client:req_app_data_13_overflow> ) <replies_app_data_13>

# The replies to application data (shared by <exch_app_data_13> and <exch_app_data_13_unanswered>)
<replies_app_data_13> ::= (
      <Server:in_key_update_not_requested>? <Server:in_app_data>+ (
          <TimerControl:cancel_data> <state_connected_13>
        | ( <server_error_closes> <TimerControl:cancel_data> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_data> <state_half_closed_13> )
        | <Server:in_key_update_requested> <Server:in_app_data>* ( <TimerControl:cancel_data> <owed_answer_13> | <server_error_closes> <TimerControl:cancel_data> <state_end> )
        | <Server:in_certificate_request_post_hs> <Server:in_app_data>* <TimerControl:cancel_data> (
          <Client:req_certificate_post_empty> <Client:req_finished_post_after_empty> <state_connected_13>
        | <Client:req_certificate_post> <Client:req_certificate_verify_post> <Client:req_finished_post_after_certificate> <state_connected_13> )
        | <Server:in_certificate_request_post_hs_nu> <Server:in_app_data>* <TimerControl:cancel_data> <Client:req_certificate_post_empty> <Client:req_finished_post_after_empty> <state_connected_13> )
    | <Server:in_key_update_not_requested> <TimerControl:cancel_data> <state_connected_13>
    | <Server:in_key_update_requested> <Server:in_app_data>* ( <TimerControl:cancel_data> <owed_answer_13> | <server_error_closes> <TimerControl:cancel_data> <state_end> )
    | <Server:in_certificate_request_post_hs> <Server:in_app_data>* <TimerControl:cancel_data> (
          <Client:req_certificate_post_empty> <Client:req_finished_post_after_empty> <state_connected_13>
        | <Client:req_certificate_post> <Client:req_certificate_verify_post> <Client:req_finished_post_after_certificate> <state_connected_13> )
    | <Server:in_certificate_request_post_hs_nu> <Server:in_app_data>* <TimerControl:cancel_data> <Client:req_certificate_post_empty> <Client:req_finished_post_after_empty> <state_connected_13>
    | <Server:in_key_update_not_requested>? ( <server_error_closes> <TimerControl:cancel_data> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_data> <state_half_closed_13> )
    | <TimerEvent:expired_data> <state_connected_13> )

# RFC 9846 section 4.6.3: the receiver of KeyUpdate(update_requested) MUST send its own KeyUpdate before its next application data.
# The client sends it (<req_key_update_answer>, the sent message meets the requirement), or, as the request that breaks the requirement,
# application data without it: <exch_app_data_13_unanswered>.  The spec makes no reaction mandatory: every reply of an application
# data exchange is accepted, and the session goes on in the state the reply leads to.
<owed_answer_13> ::= (
      <Client:req_key_update_answer> <state_connected_13>
    | <exch_app_data_13_unanswered> )
<exch_app_data_13_unanswered> ::= <TimerControl:start_data> <Client:req_app_data_13_unanswered> <replies_app_data_13>

# KeyUpdate (RFC 9846 section 4.6.3): update_not_requested needs no answer
<exch_key_update_not_requested> ::= <TimerControl:start_ku> <Client:req_key_update_not_requested> (
      <Server:in_key_update_not_requested>? <Server:in_app_data>+ <TimerControl:cancel_ku> <state_connected_13>
    | <Server:in_key_update_not_requested> <TimerControl:cancel_ku> <state_connected_13>
    | <Server:in_key_update_not_requested>? ( <server_error_closes> <TimerControl:cancel_ku> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_ku> <state_half_closed_13> )
    | <TimerEvent:expired_ku> <state_connected_13> )

# update_requested requires an answer (section 4.6.3: "prior to sending its next Application Data record"), and the
# sender must not send another update_requested until it has received a KeyUpdate from the peer: when the server does
# not answer within the wait, the session ends
<exch_key_update_requested> ::= <TimerControl:start_kur> <Client:req_key_update_requested> (
      <Server:in_key_update_not_requested> <TimerControl:cancel_kur> <state_connected_13>
    | ( <server_error_closes> <TimerControl:cancel_kur> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_kur> <state_half_closed_13> )
    | <TimerEvent:expired_kur> <state_end> )

# RFC 9846 section 4.6.3: a sender MUST NOT send another update_requested until it has received a KeyUpdate from the peer.  The request that
# breaks it sends a second update_requested right after the first, while no KeyUpdate of the peer has arrived: both records in one send
# (<req_key_update_requested_again> is the dependent second record; the server answers the first within a millisecond, so two sends would
# race with its answer).  The spec makes no reaction mandatory: every reply is accepted (the answers, application data after them, the
# server's own update_requested, an error alert, close_notify, closure, silence).
<exch_key_update_requested_again> ::= <TimerControl:start_kura> <Client:req_key_update_requested_twice> (
      <Server:in_key_update_not_requested> <Server:in_key_update_not_requested>? <Server:in_app_data>* <TimerControl:cancel_kura> <state_connected_13>
    | <Server:in_key_update_requested> <TimerControl:cancel_kura> <Client:req_key_update_answer> <state_connected_13>
    | <Server:in_key_update_not_requested>? ( <server_error_closes> <TimerControl:cancel_kura> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_kura> <state_half_closed_13> )
    | <TimerEvent:expired_kura> <state_end> )

# Closure (RFC 9846 section 6.1): the server answers with its own close_notify and closes the connection
<exch_close_notify_13> ::= <TimerControl:start_close> <Client:req_alert_close_notify_13> (
      <Server:in_key_update_not_requested>? <Server:in_app_data>* <server_closes> <TimerControl:cancel_close> <state_end>
    | <TimerEvent:expired_close> <state_end> )

# Error alerts (RFC 9846 section 6.2): the receiver closes the connection
# (section 6.2: both parties close the connection immediately on a fatal alert, so a bare close answers it)
<exch_error_alert_13> ::= <TimerControl:start_err> <Client:req_alert_error_13> (
      <Server:in_key_update_not_requested>? <Server:in_app_data>* <server_closes> <TimerControl:cancel_err> <state_end>
    | <Server:in_closed> <TimerControl:cancel_err> <state_end>
    | <TimerEvent:expired_err> <state_end> )

# a client message that is not valid here: the server terminates the connection with unexpected_message
# (RFC 9846 sections 4.2.2, 5)
<exch_unexpected_handshake_13> ::= <TimerControl:start_unexp> <Client:req_unexpected_handshake_13> (
      <Server:in_key_update_not_requested>? <Server:in_alert_unexpected_message> <Server:in_closed>? <TimerControl:cancel_unexp> <state_end>
    | <TimerEvent:expired_unexp> <state_end> )
# user_canceled is followed by close_notify (RFC 9846 section 6.1), after which the server closes; the two records are ONE send: a server that closes
# at once at the user_canceled (gnutls-serv does) would otherwise end the session before the second message
<exch_user_canceled_13> ::= <TimerControl:start_uc> <Client:req_alert_user_canceled_close_notify_13> (
      <Server:in_key_update_not_requested>? <Server:in_app_data>* <server_closes> <TimerControl:cancel_uc> <state_end>
    | <TimerEvent:expired_uc> <state_end> )

<state_closed> ::= <Server:in_closed>? <state_end>
<state_end> ::= ''

# ==================================================================================================================
# TLS 1.2 (RFC 5246 section 7.3): the full handshake
# ==================================================================================================================
# The server flight: Certificate (not sent for anonymous key exchange), CertificateStatus, ServerKeyExchange,
# CertificateRequest, ServerHelloDone.  Warning alerts may come between the messages (RFC 5246 section 7.2.2).
<state_wait_server_flight_12> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_certificate_12> <Server:in_certificate_status>? ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* <state_flight_12_after_certificate>
    | <Server:in_server_key_exchange_anon> (
          ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* <Server:in_server_hello_done> <state_client_flight_dhe>
        | <server_closes_12_flight> <state_end> )
    | <exch_alert_flight_12_1>
    | <server_closes_12_flight> <state_end> )

<state_flight_12_after_certificate> ::= (
      <Server:in_server_key_exchange_dhe> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_certificate_request_12> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
              <Server:in_server_hello_done> <state_client_flight_dhe_auth>
            | <exch_alert_flight_12_4>
            | <server_closes_12_flight> <state_end> )
        | <Server:in_certificate_request_12_nu> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
              <Server:in_server_hello_done> <state_client_flight_dhe_auth_nu>
            | <exch_alert_flight_12_4>
            | <server_closes_12_flight> <state_end> )
        | <Server:in_server_hello_done> <state_client_flight_dhe>
        | <exch_alert_flight_12_3>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_certificate_request_12> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_server_hello_done> <state_client_flight_rsa_auth>
        | <exch_alert_flight_12_4>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_certificate_request_12_nu> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_server_hello_done> <state_client_flight_rsa_auth_nu>
        | <exch_alert_flight_12_4>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_server_key_exchange_anon> (
          ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* <Server:in_server_hello_done> <state_client_flight_dhe>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_server_hello_done> <state_client_flight_rsa>
    | <exch_alert_flight_12_2>
    | <server_closes_12_flight> <state_end> )

# the server flight of a static-DH suite (DH_DSS, DH_RSA; RFC 5246 sections 7.4.2, 7.4.3): the Certificate holds the server's DH
# parameters and public value, no ServerKeyExchange follows; the client's answer is the DH ClientKeyExchange of the DHE flights
# (7.4.7.2), whose public value is computed from the certificate's parameters
<state_wait_server_flight_12_dh> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_certificate_12> <Server:in_certificate_status>? ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* <state_flight_12_dh_after_certificate>
    | <server_closes_12_flight> <state_end> )
<state_flight_12_dh_after_certificate> ::= (
      <Server:in_certificate_request_12_sd_u> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_server_hello_done> <state_client_flight_dhe_auth>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_certificate_request_12_sd_n> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_server_hello_done> <state_client_flight_dhe_auth_nu>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_certificate_request_12_sd_uf> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_server_hello_done> <state_client_flight_dh_fixed_auth>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_certificate_request_12_sd_nf> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
          <Server:in_server_hello_done> <state_client_flight_dh_fixed_auth_nu>
        | <server_closes_12_flight> <state_end> )
    | <Server:in_server_hello_done> <state_client_flight_dhe>
    | <server_closes_12_flight> <state_end> )

<state_client_flight_rsa> ::= (
      <Client:req_client_key_exchange_rsa> <state_client_finish_12>
    | <Client:req_alert_warning_hs_12> <state_client_flight_rsa>
    | <exch_alert_handshake_12_before_key_exchange_rsa>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_rsa> )
<state_client_flight_dhe> ::= (
      <Client:req_client_key_exchange_dhe> <state_client_finish_12>
    | <Client:req_alert_warning_hs_12> <state_client_flight_dhe>
    | <exch_alert_handshake_12_before_key_exchange_dhe>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_dhe> )
# the server's answer to a CertificateURL (RFC 6066 sections 5, 9): a fatal alert (unexpected_message when it did not echo
# client_certificate_url, certificate_unobtainable, bad_certificate_hash_value), or, when it does not require the certificates, a
# warning-level certificate_unobtainable or silence, and the handshake goes on with the ClientKeyExchange (the client has no key
# for the certificates behind the URL, so no CertificateVerify follows); the client may also end the handshake with an alert
<state_after_certificate_url_12_rsa> ::= (
      <server_closes_12_flight> <TimerControl:cancel_url_12> <state_end>
    | <Server:in_alert_12_warning> <TimerControl:cancel_url_12> <state_continue_after_url_12_rsa>
    | <TimerEvent:expired_url_12> ( <exch_alert_handshake_12_after_certificate_url> | <Client:req_client_key_exchange_rsa_after_certificate_url> <state_client_finish_12> ) )
<state_continue_after_url_12_rsa> ::= (
      <Client:req_client_key_exchange_rsa_after_certificate_url> <state_client_finish_12>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_continue_after_url_12_rsa> )
<state_after_certificate_url_12_dhe> ::= (
      <server_closes_12_flight> <TimerControl:cancel_url_12> <state_end>
    | <Server:in_alert_12_warning> <TimerControl:cancel_url_12> <state_continue_after_url_12_dhe>
    | <TimerEvent:expired_url_12> ( <exch_alert_handshake_12_after_certificate_url> | <Client:req_client_key_exchange_dhe_after_certificate_url> <state_client_finish_12> ) )
<state_continue_after_url_12_dhe> ::= (
      <Client:req_client_key_exchange_dhe_after_certificate_url> <state_client_finish_12>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_continue_after_url_12_dhe> )
<exch_alert_handshake_12_after_certificate_url> ::= <exch_alert_handshake_12>
# the server may reject the client's Certificate (RFC 5246 section 7.4.6: bad_certificate, unknown_ca, ...) as soon as it has it
<state_after_empty_certificate_12_rsa> ::= (
      <Client:req_client_key_exchange_rsa_after_certificate> <state_client_finish_12>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_empty_certificate_rsa>
    | <Server:in_alert_12_warning> <state_after_empty_certificate_12_rsa> )
<state_after_certificate_12_rsa> ::= (
      <Client:req_client_key_exchange_rsa_after_real_certificate> <state_after_key_exchange_12_rsa>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_certificate_rsa>
    | <Server:in_alert_12_warning> <state_after_certificate_12_rsa> )
<state_after_key_exchange_12_rsa> ::= (
      <Client:req_certificate_verify_12_rsa> <state_client_finish_12>
    | <TimerControl:start_cvl> <Client:req_certificate_verify_12_legacy_hash> <replies_legacy_certificate_verify_12>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_key_exchange_rsa>
    | <Server:in_alert_12_warning> <state_after_key_exchange_12_rsa> )
<state_client_flight_rsa_auth> ::= (
      <Client:req_certificate_empty_12_rsa> <state_after_empty_certificate_12_rsa>
    | <Client:req_certificate_12_rsa> <state_after_certificate_12_rsa>
    | <Client:req_certificate_empty_cke_12_rsa> <state_client_finish_12>
    | <Client:req_certificate_cke_12_rsa> <state_after_key_exchange_12_rsa>
    | <TimerControl:start_url_12> <Client:req_certificate_url_12_rsa> <state_after_certificate_url_12_rsa>
    | <exch_alert_handshake_12_before_certificate_rsa>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_rsa_auth> )
# the server may reject the client's Certificate (RFC 5246 section 7.4.6: bad_certificate, unknown_ca, ...) as soon as it has it
<state_after_empty_certificate_12_dhe> ::= (
      <Client:req_client_key_exchange_dhe_after_certificate> <state_client_finish_12>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_empty_certificate_dhe>
    | <Server:in_alert_12_warning> <state_after_empty_certificate_12_dhe> )
<state_after_certificate_12_dhe> ::= (
      <Client:req_client_key_exchange_dhe_after_real_certificate> <state_after_key_exchange_12_dhe>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_certificate_dhe>
    | <Server:in_alert_12_warning> <state_after_certificate_12_dhe> )
<state_after_key_exchange_12_dhe> ::= (
      <Client:req_certificate_verify_12_dhe> <state_client_finish_12>
    | <TimerControl:start_cvl> <Client:req_certificate_verify_12_legacy_hash_dhe> <replies_legacy_certificate_verify_12>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_key_exchange_dhe>
    | <Server:in_alert_12_warning> <state_after_key_exchange_12_dhe> )
# the client's turn after a CertificateRequest that nothing the client holds fits (the _nu request rules): only the empty Certificate
<state_client_flight_rsa_auth_nu> ::= (
      <Client:req_certificate_empty_12_rsa> <state_after_empty_certificate_12_rsa>
    | <Client:req_certificate_empty_cke_12_rsa> <state_client_finish_12>
    | <TimerControl:start_url_12> <Client:req_certificate_url_12_rsa> <state_after_certificate_url_12_rsa>
    | <exch_alert_handshake_12_before_certificate_rsa>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_rsa_auth_nu> )
<state_client_flight_dhe_auth_nu> ::= (
      <Client:req_certificate_empty_12_dhe> <state_after_empty_certificate_12_dhe>
    | <Client:req_certificate_empty_cke_12_dhe> <state_client_finish_12>
    | <TimerControl:start_url_12> <Client:req_certificate_url_12_dhe> <state_after_certificate_url_12_dhe>
    | <exch_alert_handshake_12_before_certificate_dhe>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_dhe_auth_nu> )
# static DH (RFC 5246 sections 7.4.6, 7.4.7.2): the request names rsa_fixed_dh, so the client may send a certificate with a DH key of the server's
# parameters; its ClientKeyExchange is then empty (the public value is implicit) and no CertificateVerify follows.  A non-empty ClientKeyExchange
# after such a certificate breaks section 7.4.7.2 (the request that does so is its own nonterminal; the spec makes no reaction mandatory, so
# whatever the server answers is accepted).
<state_client_flight_dh_fixed_auth> ::= (
      <Client:req_certificate_empty_12_dhe> <state_after_empty_certificate_12_dhe>
    | <Client:req_certificate_12_dhe> <state_after_certificate_12_dhe>
    | <Client:req_certificate_empty_cke_12_dhe> <state_client_finish_12>
    | <Client:req_certificate_cke_12_dhe> <state_after_key_exchange_12_dhe>
    | <Client:req_certificate_dh_12> <state_after_certificate_dh_12>
    | <TimerControl:start_url_12> <Client:req_certificate_url_12_dhe> <state_after_certificate_url_12_dhe>
    | <exch_alert_handshake_12_before_certificate_dhe>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_dh_fixed_auth> )
<state_client_flight_dh_fixed_auth_nu> ::= (
      <Client:req_certificate_empty_12_dhe> <state_after_empty_certificate_12_dhe>
    | <Client:req_certificate_empty_cke_12_dhe> <state_client_finish_12>
    | <Client:req_certificate_dh_12> <state_after_certificate_dh_12>
    | <TimerControl:start_url_12> <Client:req_certificate_url_12_dhe> <state_after_certificate_url_12_dhe>
    | <exch_alert_handshake_12_before_certificate_dhe>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_dh_fixed_auth_nu> )
<state_after_certificate_dh_12> ::= (
      <Client:req_client_key_exchange_implicit_12> <state_client_finish_12>
    | <Client:req_client_key_exchange_explicit_after_dh_certificate> <state_client_finish_12>
    | <server_closes_12_flight> <state_end>
    | <exch_alert_handshake_12_after_certificate_dh>
    | <Server:in_alert_12_warning> <state_after_certificate_dh_12> )
<state_client_flight_dhe_auth> ::= (
      <Client:req_certificate_empty_12_dhe> <state_after_empty_certificate_12_dhe>
    | <Client:req_certificate_12_dhe> <state_after_certificate_12_dhe>
    | <Client:req_certificate_empty_cke_12_dhe> <state_client_finish_12>
    | <Client:req_certificate_cke_12_dhe> <state_after_key_exchange_12_dhe>
    | <TimerControl:start_url_12> <Client:req_certificate_url_12_dhe> <state_after_certificate_url_12_dhe>
    | <exch_alert_handshake_12_before_certificate_dhe>
    | <server_closes_12_flight> <state_end>
    | <Server:in_alert_12_warning> <state_client_flight_dhe_auth> )

# Alerts of the client during the TLS 1.2 handshake (RFC 5246 section 7.2): the closure alerts and the error alerts
# the client's alerts after its OWN messages (the exchange of the turns before them: the timer start, then the alert or the server's closure)
<exch_alert_handshake_12_after_empty_certificate_rsa> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_empty_certificate_dhe> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_certificate_rsa> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_certificate_dhe> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_key_exchange_rsa> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_key_exchange_dhe> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_certificate_dh> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_after_ccs> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_before_ccs> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_before_key_exchange_rsa> ::= <exch_alert_handshake_12>

<exch_alert_handshake_12_before_key_exchange_dhe> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_before_certificate_rsa> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12_before_certificate_dhe> ::= <exch_alert_handshake_12>
<exch_alert_handshake_12> ::= <TimerControl:start_hsa_12> (
      <Client:req_alert_error_hs_12> (
          <server_closes_12> <TimerControl:cancel_hsa_12> <state_end>
        | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end>
        | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> (
          <server_closes_12> <TimerControl:cancel_hsa_12> <state_end>
        | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> (
          <server_closes_12> <TimerControl:cancel_hsa_12> <state_end>
        | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12> <TimerControl:cancel_hsa_12> <state_end> )

# After the CertificateVerify that breaks RFC 9155 section 5 (an MD5 or SHA-1 hash, <req_certificate_verify_12_legacy_hash>): the specification makes the server's
# reaction mandatory ("it MUST abort the connection with an illegal_parameter alert"), so only that alert (and the close that follows) is accepted; a server that
# stays silent is a violation (the timer's expiry carries a where that is never true) and so is any other reply
<replies_legacy_certificate_verify_12> ::= (
      <Server:in_alert_illegal_parameter> <Server:in_alert_close_notify>? <Server:in_closed>? <TimerControl:cancel_cvl> <state_end>
    | <TimerEvent:expired_cvl> <state_end> )
where forall <t> in <expired_cvl>: server_aborts_legacy_certificate_verify()
# the client's ChangeCipherSpec and Finished, answered by the server's ChangeCipherSpec and Finished
<state_client_finish_12> ::= (
      <Client:req_ccs_12> <state_after_ccs_12>
    | <exch_alert_handshake_12_before_ccs>
    | <Server:in_alert_12_warning> <state_client_finish_12>
    | <server_closes_12_flight> <state_end> )
<state_after_ccs_12> ::= (
      ( <Client:req_finished_12> | <Client:req_finished_12_fragmented> ) (
          ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* <Server:in_ccs> ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* <Server:in_finished_12> <state_connected_12>
        | <server_closes_12_flight> <state_end> )
    | <exch_alert_handshake_12_after_ccs>
    | <Server:in_alert_12_warning> <state_after_ccs_12>
    | <server_closes_12_flight> <state_end> )

# CONNECTED (TLS 1.2); the messages the server sends on its own initiative are accepted between the exchanges
<state_connected_12> ::= (
      <exch_app_data_12>
    | <exch_close_notify_12>
    | <exch_error_alert_12>
    | <exch_renegotiation_12>
    | <exch_warning_alert_12>
    | <exch_user_canceled_12>
    | <server_initiated_12> )

# user_canceled (a closure alert, RFC 5246 section 7.2.1) and the close_notify that follows it, in one send (see <exch_user_canceled_13>); the server closes
<exch_user_canceled_12> ::= <TimerControl:start_uc_12> <Client:req_alert_user_canceled_close_notify_12> (
      <Server:in_app_data>* <server_closes_12> <TimerControl:cancel_uc_12> <state_end>
    | <TimerEvent:expired_uc_12> <state_end> )

# a warning alert for an error whose level is open (RFC 5246 section 7.2.2): the connection can continue normally
<exch_warning_alert_12> ::= <TimerControl:start_warn_12> <Client:req_alert_warning_12> (
      <server_closes_12> <TimerControl:cancel_warn_12> <state_end>
    | <TimerEvent:expired_warn_12> <state_connected_12> )

# HelloRequest (RFC 5246 section 7.4.1.1: the client may ignore it), warning alerts, closure and error alerts
<server_initiated_12> ::= (
      <Server:in_hello_request> ( <state_connected_12> | <Client:req_alert_no_renegotiation_12> <state_connected_12> )
    | <Server:in_app_data> <state_connected_12>
    | <Server:in_alert_12_warning> <state_connected_12>
    | <Server:in_alert_close_notify> <state_half_closed_12>
    | <Server:in_alert_12_fatal> <Server:in_alert_close_notify>? <Server:in_closed>? <state_end>
    | <Server:in_alert_user_canceled_fatal> <Server:in_alert_close_notify>? <Server:in_closed>? <state_end> )

<state_half_closed_12> ::= (
      <Server:in_closed> <state_end>
    | <TimerControl:start_half_12> <Client:req_app_data_12_half> ( <Server:in_closed> <TimerControl:cancel_half_12> <state_end> | <TimerEvent:expired_half_12> <state_half_closed_12> )
    | <TimerControl:start_half_close_12> <Client:req_alert_close_notify_half_12> ( <Server:in_closed> <TimerControl:cancel_half_close_12> <state_end> | <TimerEvent:expired_half_close_12> <state_end> ) )

# a ClientHello on an established connection starts a new handshake (RFC 5246 sections 7.3, 7.4.1.2); a server that does
# not support it refuses with the no_renegotiation warning (section 7.2.2) or a fatal alert
<exch_renegotiation_12> ::= <TimerControl:start_reneg_12> <Client:req_client_hello_renegotiation_12> (
      <Server:in_alert_12_no_renegotiation> (
          <server_closes_12> <TimerControl:cancel_reneg_12> <state_end>
        | <TimerControl:cancel_reneg_12> <state_connected_12> )
    | <server_closes_12> <TimerControl:cancel_reneg_12> <state_end>
    | <TimerEvent:expired_reneg_12> <state_end> )

<exch_app_data_12> ::= <TimerControl:start_data_12> ( <Client:req_app_data_12> | <Client:req_app_data_12_split> | <Client:req_app_data_12_large> | <Client:req_app_data_12_overflow> ) (
      <Server:in_app_data>+ (
          <TimerControl:cancel_data_12> <state_connected_12>
        | ( <server_error_closes_12> <TimerControl:cancel_data_12> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_data_12> <state_half_closed_12> )
        | <Server:in_hello_request> <Server:in_app_data>* ( <TimerControl:cancel_data_12> ( <state_connected_12> | <Client:req_alert_no_renegotiation_12> <state_connected_12> ) | <server_error_closes_12> <TimerControl:cancel_data_12> <state_end> ) )
    | <Server:in_hello_request> <Server:in_app_data>* ( <TimerControl:cancel_data_12> ( <state_connected_12> | <Client:req_alert_no_renegotiation_12> <state_connected_12> ) | <server_error_closes_12> <TimerControl:cancel_data_12> <state_end> )
    | ( <server_error_closes_12> <TimerControl:cancel_data_12> <state_end> | <Server:in_alert_close_notify> <TimerControl:cancel_data_12> <state_half_closed_12> )
    | <TimerEvent:expired_data_12> <state_connected_12> )
<exch_close_notify_12> ::= <TimerControl:start_close_12> <Client:req_alert_close_notify_12> (
      <Server:in_app_data>* <server_closes_12> <TimerControl:cancel_close_12> <state_end>
    | <TimerEvent:expired_close_12> <state_end> )

<exch_error_alert_12> ::= <TimerControl:start_err_12> <Client:req_alert_error_12> (
      <Server:in_app_data>* <server_closes_12> <TimerControl:cancel_err_12> <state_end>
    | <Server:in_closed> <TimerControl:cancel_err_12> <state_end>
    | <TimerEvent:expired_err_12> <state_end> )

# close_notify, a fatal alert, or user_canceled and close_notify (RFC 5246 section 7.2.1)
# the same where the server's warnings (user_canceled included, RFC 5246 section 7.2.2: generally a warning; "should be followed" by a
# close_notify) are accepted before the alternatives: user_canceled as a warning is the loop's, not this rule's
<server_closes_12_flight> ::= <Server:in_alert_close_notify> <Server:in_closed>? | <Server:in_alert_12_fatal> <Server:in_alert_close_notify>? <Server:in_closed>? | <Server:in_alert_user_canceled_fatal> <Server:in_alert_close_notify>? <Server:in_closed>?
<server_closes_12> ::= <Server:in_alert_close_notify> <Server:in_closed>? | <Server:in_alert_12_fatal> <Server:in_alert_close_notify>? <Server:in_closed>? | <Server:in_alert_user_canceled> ( <Server:in_alert_close_notify> <Server:in_closed>? )?


# ==================================================================================================================
# Timers (the only clock): one fixed id per timer, each runs as long as the spec lets the client wait
# ==================================================================================================================
<start_ticket> ::= <timer_start>
<cancel_ticket> ::= <timer_cancel>
<expired_ticket> ::= <timer_expired>
<start_ticket_after_auth> ::= <timer_start>
<cancel_ticket_after_auth> ::= <timer_cancel>
<expired_ticket_after_auth> ::= <timer_expired>
<start_data> ::= <timer_start>
<cancel_data> ::= <timer_cancel>
<expired_data> ::= <timer_expired>
<start_ku> ::= <timer_start>
<cancel_ku> ::= <timer_cancel>
<expired_ku> ::= <timer_expired>
<start_kura> ::= <timer_start>
<cancel_kura> ::= <timer_cancel>
<expired_kura> ::= <timer_expired>
<start_kur> ::= <timer_start>
<cancel_kur> ::= <timer_cancel>
<expired_kur> ::= <timer_expired>
<start_close> ::= <timer_start>
<cancel_close> ::= <timer_cancel>
<expired_close> ::= <timer_expired>
<start_err> ::= <timer_start>
<cancel_err> ::= <timer_cancel>
<expired_err> ::= <timer_expired>
where forall <t> in <start_ticket>: str(<t>..<timer_id>) == '1'
where forall <t> in <cancel_ticket>: str(<t>..<timer_id>) == '1'
where forall <t> in <expired_ticket>: str(<t>..<timer_id>) == '1'
where forall <t> in <start_ticket_after_auth>: str(<t>..<timer_id>) == '2'
where forall <t> in <cancel_ticket_after_auth>: str(<t>..<timer_id>) == '2'
where forall <t> in <expired_ticket_after_auth>: str(<t>..<timer_id>) == '2'
where forall <t> in <start_data>: str(<t>..<timer_id>) == '3'
where forall <t> in <cancel_data>: str(<t>..<timer_id>) == '3'
where forall <t> in <expired_data>: str(<t>..<timer_id>) == '3'
where forall <t> in <start_ku>: str(<t>..<timer_id>) == '4'
where forall <t> in <cancel_ku>: str(<t>..<timer_id>) == '4'
where forall <t> in <expired_ku>: str(<t>..<timer_id>) == '4'
where forall <t> in <start_kur>: str(<t>..<timer_id>) == '5'
where forall <t> in <cancel_kur>: str(<t>..<timer_id>) == '5'
where forall <t> in <expired_kur>: str(<t>..<timer_id>) == '5'
where forall <t> in <start_close>: str(<t>..<timer_id>) == '6'
where forall <t> in <cancel_close>: str(<t>..<timer_id>) == '6'
where forall <t> in <expired_close>: str(<t>..<timer_id>) == '6'
where forall <t> in <start_err>: str(<t>..<timer_id>) == '7'
where forall <t> in <cancel_err>: str(<t>..<timer_id>) == '7'
where forall <t> in <expired_err>: str(<t>..<timer_id>) == '7'
where forall <t> in <start_data_12>: str(<t>..<timer_id>) == '8'
where forall <t> in <cancel_data_12>: str(<t>..<timer_id>) == '8'
where forall <t> in <expired_data_12>: str(<t>..<timer_id>) == '8'
where forall <t> in <start_close_12>: str(<t>..<timer_id>) == '9'
where forall <t> in <cancel_close_12>: str(<t>..<timer_id>) == '9'
where forall <t> in <expired_close_12>: str(<t>..<timer_id>) == '9'
where forall <t> in <start_err_12>: str(<t>..<timer_id>) == '10'
where forall <t> in <cancel_err_12>: str(<t>..<timer_id>) == '10'
where forall <t> in <expired_err_12>: str(<t>..<timer_id>) == '10'
where forall <t> in <start_unexp>: str(<t>..<timer_id>) == '11'
where forall <t> in <cancel_unexp>: str(<t>..<timer_id>) == '11'
where forall <t> in <expired_unexp>: str(<t>..<timer_id>) == '11'
where forall <t> in <start_uc>: str(<t>..<timer_id>) == '12'
where forall <t> in <cancel_uc>: str(<t>..<timer_id>) == '12'
where forall <t> in <expired_uc>: str(<t>..<timer_id>) == '12'
where forall <t> in <start_hsa>: str(<t>..<timer_id>) == '13'
where forall <t> in <cancel_hsa>: str(<t>..<timer_id>) == '13'
where forall <t> in <expired_hsa>: str(<t>..<timer_id>) == '13'
where forall <t> in <start_hsa_12>: str(<t>..<timer_id>) == '14'
where forall <t> in <cancel_hsa_12>: str(<t>..<timer_id>) == '14'
where forall <t> in <expired_hsa_12>: str(<t>..<timer_id>) == '14'
where forall <t> in <start_reneg_12>: str(<t>..<timer_id>) == '15'
where forall <t> in <cancel_reneg_12>: str(<t>..<timer_id>) == '15'
where forall <t> in <expired_reneg_12>: str(<t>..<timer_id>) == '15'
where forall <t> in <start_half>: str(<t>..<timer_id>) == '16'
where forall <t> in <cancel_half>: str(<t>..<timer_id>) == '16'
where forall <t> in <expired_half>: str(<t>..<timer_id>) == '16'
where forall <t> in <start_half_close>: str(<t>..<timer_id>) == '17'
where forall <t> in <cancel_half_close>: str(<t>..<timer_id>) == '17'
where forall <t> in <expired_half_close>: str(<t>..<timer_id>) == '17'
where forall <t> in <start_half_12>: str(<t>..<timer_id>) == '18'
where forall <t> in <cancel_half_12>: str(<t>..<timer_id>) == '18'
where forall <t> in <expired_half_12>: str(<t>..<timer_id>) == '18'
where forall <t> in <start_half_close_12>: str(<t>..<timer_id>) == '19'
where forall <t> in <cancel_half_close_12>: str(<t>..<timer_id>) == '19'
where forall <t> in <expired_half_close_12>: str(<t>..<timer_id>) == '19'
where forall <t> in <start_warn_12>: str(<t>..<timer_id>) == '20'
where forall <t> in <cancel_warn_12>: str(<t>..<timer_id>) == '20'
where forall <t> in <expired_warn_12>: str(<t>..<timer_id>) == '20'
where forall <t> in <start_url_12>: str(<t>..<timer_id>) == '21'
where forall <t> in <cancel_url_12>: str(<t>..<timer_id>) == '21'
where forall <t> in <expired_url_12>: str(<t>..<timer_id>) == '21'
where forall <t> in <start_uc_12>: str(<t>..<timer_id>) == '22'
where forall <t> in <cancel_uc_12>: str(<t>..<timer_id>) == '22'
where forall <t> in <expired_uc_12>: str(<t>..<timer_id>) == '22'
where forall <t> in <start_cvl>: str(<t>..<timer_id>) == '23'
where forall <t> in <cancel_cvl>: str(<t>..<timer_id>) == '23'
where forall <t> in <expired_cvl>: str(<t>..<timer_id>) == '23'
where forall <t> in <start_kura>: str(<t>..<timer_id>) == '24'
where forall <t> in <cancel_kura>: str(<t>..<timer_id>) == '24'
where forall <t> in <expired_kura>: str(<t>..<timer_id>) == '24'

<start_unexp> ::= <timer_start>
<cancel_unexp> ::= <timer_cancel>
<expired_unexp> ::= <timer_expired>
where forall <t> in <start_unexp>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_uc> ::= <timer_start>
<cancel_uc> ::= <timer_cancel>
<expired_uc> ::= <timer_expired>
where forall <t> in <start_uc>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S

<start_data_12> ::= <timer_start>
<cancel_data_12> ::= <timer_cancel>
<expired_data_12> ::= <timer_expired>
where forall <t> in <start_data_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_warn_12> ::= <timer_start>
<cancel_warn_12> ::= <timer_cancel>
<expired_warn_12> ::= <timer_expired>
where forall <t> in <start_warn_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_url_12> ::= <timer_start>
<cancel_url_12> ::= <timer_cancel>
<expired_url_12> ::= <timer_expired>
where forall <t> in <start_url_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_uc_12> ::= <timer_start>
<cancel_uc_12> ::= <timer_cancel>
<expired_uc_12> ::= <timer_expired>
where forall <t> in <start_uc_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_close_12> ::= <timer_start>
<cancel_close_12> ::= <timer_cancel>
<expired_close_12> ::= <timer_expired>
where forall <t> in <start_close_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_err_12> ::= <timer_start>
<cancel_err_12> ::= <timer_cancel>
<expired_err_12> ::= <timer_expired>
where forall <t> in <start_err_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S

<start_cvl> ::= <timer_start>
<cancel_cvl> ::= <timer_cancel>
<expired_cvl> ::= <timer_expired>
where forall <t> in <start_cvl>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_hsa> ::= <timer_start>
<cancel_hsa> ::= <timer_cancel>
<expired_hsa> ::= <timer_expired>
where forall <t> in <start_hsa>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_hsa_12> ::= <timer_start>
<cancel_hsa_12> ::= <timer_cancel>
<expired_hsa_12> ::= <timer_expired>
where forall <t> in <start_hsa_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_reneg_12> ::= <timer_start>
<cancel_reneg_12> ::= <timer_cancel>
<expired_reneg_12> ::= <timer_expired>
where forall <t> in <start_reneg_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S

<start_half> ::= <timer_start>
<cancel_half> ::= <timer_cancel>
<expired_half> ::= <timer_expired>
where forall <t> in <start_half>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_half_close> ::= <timer_start>
<cancel_half_close> ::= <timer_cancel>
<expired_half_close> ::= <timer_expired>
where forall <t> in <start_half_close>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_half_12> ::= <timer_start>
<cancel_half_12> ::= <timer_cancel>
<expired_half_12> ::= <timer_expired>
where forall <t> in <start_half_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
<start_half_close_12> ::= <timer_start>
<cancel_half_close_12> ::= <timer_cancel>
<expired_half_close_12> ::= <timer_expired>
where forall <t> in <start_half_close_12>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S

where forall <t> in <start_ticket>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_ticket_after_auth>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_data>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_ku>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_kur>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_kura>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_close>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S
where forall <t> in <start_err>: str(<t>..<timer_timeout>) == WAIT_SERVER_MESSAGE_S

# ==================================================================================================================
# Constants: one nonterminal per code (RFC 9846 appendix B, RFC 5246 appendix A, RFC 6066, RFC 7301)
# ==================================================================================================================
# ContentType (RFC 9846 B.1)
<ct_change_cipher_spec> ::= b'\x14'
<ct_alert> ::= b'\x15'
<ct_handshake> ::= b'\x16'
<ct_application_data> ::= b'\x17'

# HandshakeType (RFC 9846 B.3)
<hs_client_hello> ::= b'\x01'
<hs_server_hello> ::= b'\x02'
<hs_new_session_ticket> ::= b'\x04'
<hs_end_of_early_data> ::= b'\x05'
<hs_encrypted_extensions> ::= b'\x08'
<hs_certificate> ::= b'\x0b'
<hs_server_key_exchange> ::= b'\x0c'
<hs_certificate_request> ::= b'\x0d'
<hs_server_hello_done> ::= b'\x0e'
<hs_certificate_verify> ::= b'\x0f'
<hs_client_key_exchange> ::= b'\x10'
<hs_certificate_url> ::= b'\x15'
<hs_certificate_status> ::= b'\x16'
<hs_finished> ::= b'\x14'
<hs_key_update> ::= b'\x18'
<hs_hello_request> ::= b'\x00'

# ProtocolVersion
<version_0301> ::= b'\x03\x01'
<version_0302> ::= b'\x03\x02'
<version_0303> ::= b'\x03\x03'
<version_0304> ::= b'\x03\x04'

# ExtensionType (RFC 9846 B.3.1, RFC 6066, RFC 7301)
<ext_type_server_name> ::= b'\x00\x00'
<ext_type_max_fragment_length> ::= b'\x00\x01'
<ext_type_client_certificate_url> ::= b'\x00\x02'
<ext_type_trusted_ca_keys> ::= b'\x00\x03'
<ext_type_truncated_hmac> ::= b'\x00\x04'
<ext_type_status_request> ::= b'\x00\x05'
<ext_type_supported_groups> ::= b'\x00\x0a'
<ext_type_ec_point_formats> ::= b'\x00\x0b'
<ext_type_signature_algorithms> ::= b'\x00\x0d'
<ext_type_use_srtp> ::= b'\x00\x0e'
<ext_type_heartbeat> ::= b'\x00\x0f'
<ext_type_alpn> ::= b'\x00\x10'
<ext_type_signed_certificate_timestamp> ::= b'\x00\x12'
<ext_type_client_certificate_type> ::= b'\x00\x13'
<ext_type_server_certificate_type> ::= b'\x00\x14'
<ext_type_padding> ::= b'\x00\x15'
<ext_type_pre_shared_key> ::= b'\x00\x29'
<ext_type_early_data> ::= b'\x00\x2a'
<ext_type_supported_versions> ::= b'\x00\x2b'
<ext_type_cookie> ::= b'\x00\x2c'
<ext_type_psk_key_exchange_modes> ::= b'\x00\x2d'
<ext_type_certificate_authorities> ::= b'\x00\x2f'
<ext_type_oid_filters> ::= b'\x00\x30'
<ext_type_post_handshake_auth> ::= b'\x00\x31'
<ext_type_signature_algorithms_cert> ::= b'\x00\x32'
<ext_type_key_share> ::= b'\x00\x33'

# NamedGroup (RFC 9846 section 4.2.7)
<ng_secp256r1> ::= b'\x00\x17'
<ng_secp384r1> ::= b'\x00\x18'
<ng_secp521r1> ::= b'\x00\x19'
<ng_x25519> ::= b'\x00\x1d'
<ng_x448> ::= b'\x00\x1e'
<ng_ffdhe2048> ::= b'\x01\x00'
<ng_ffdhe3072> ::= b'\x01\x01'
<ng_ffdhe4096> ::= b'\x01\x02'
<ng_ffdhe6144> ::= b'\x01\x03'
<ng_ffdhe8192> ::= b'\x01\x04'

<ng_ffdhe_private_use> ::= rb'\x01[\xfc-\xff]'
<ng_ecdhe_private_use> ::= rb'\xfe[\x00-\xff]'
<named_group_defined> ::= <ng_secp256r1> | <ng_secp384r1> | <ng_secp521r1> | <ng_x25519> | <ng_x448> | <ng_ffdhe2048> | <ng_ffdhe3072> | <ng_ffdhe4096> | <ng_ffdhe6144> | <ng_ffdhe8192> | <ng_ffdhe_private_use> | <ng_ecdhe_private_use>
<ng_unassigned> ::= rb'(?!\x00[\x17\x18\x19\x1d\x1e]|\x01[\x00-\x04\xfc-\xff]|\xfe[\x00-\xff])[\x00-\xff]{2}'
<named_group> ::= <named_group_defined> | <ng_unassigned>

# SignatureScheme (RFC 9846 section 4.2.3)
<ss_rsa_pkcs1_sha256> ::= b'\x04\x01'
<ss_rsa_pkcs1_sha384> ::= b'\x05\x01'
<ss_rsa_pkcs1_sha512> ::= b'\x06\x01'
<ss_ecdsa_secp256r1_sha256> ::= b'\x04\x03'
<ss_ecdsa_secp384r1_sha384> ::= b'\x05\x03'
<ss_ecdsa_secp521r1_sha512> ::= b'\x06\x03'
<ss_rsa_pss_rsae_sha256> ::= b'\x08\x04'
<ss_rsa_pss_rsae_sha384> ::= b'\x08\x05'
<ss_rsa_pss_rsae_sha512> ::= b'\x08\x06'
<ss_ed25519> ::= b'\x08\x07'
<ss_ed448> ::= b'\x08\x08'
<ss_rsa_pss_pss_sha256> ::= b'\x08\x09'
<ss_rsa_pss_pss_sha384> ::= b'\x08\x0a'
<ss_rsa_pss_pss_sha512> ::= b'\x08\x0b'
<ss_rsa_pkcs1_sha1> ::= b'\x02\x01'
<ss_ecdsa_sha1> ::= b'\x02\x03'
<ss_rsa_pkcs1_md5> ::= b'\x01\x01'
<ss_ecdsa_md5> ::= b'\x01\x03'

<ss_private_use> ::= rb'[\xfe\xff][\x00-\xff]'
<signature_scheme> ::= <ss_rsa_pkcs1_sha256> | <ss_rsa_pkcs1_sha384> | <ss_rsa_pkcs1_sha512> | <ss_ecdsa_secp256r1_sha256> | <ss_ecdsa_secp384r1_sha384> | <ss_ecdsa_secp521r1_sha512> | <ss_rsa_pss_rsae_sha256> | <ss_rsa_pss_rsae_sha384> | <ss_rsa_pss_rsae_sha512> | <ss_ed25519> | <ss_ed448> | <ss_rsa_pss_pss_sha256> | <ss_rsa_pss_pss_sha384> | <ss_rsa_pss_pss_sha512> | <ss_rsa_pkcs1_sha1> | <ss_ecdsa_sha1> | <ss_rsa_pkcs1_md5> | <ss_ecdsa_md5> | <ss_private_use>
<signature_scheme_sent> ::= <ss_rsa_pkcs1_sha256> | <ss_rsa_pkcs1_sha384> | <ss_rsa_pkcs1_sha512> | <ss_ecdsa_secp256r1_sha256> | <ss_ecdsa_secp384r1_sha384> | <ss_ecdsa_secp521r1_sha512> | <ss_rsa_pss_rsae_sha256> | <ss_rsa_pss_rsae_sha384> | <ss_rsa_pss_rsae_sha512> | <ss_ed25519> | <ss_ed448> | <ss_rsa_pss_pss_sha256> | <ss_rsa_pss_pss_sha384> | <ss_rsa_pss_pss_sha512>

# TLS 1.3 cipher suites (RFC 9846 appendix B.4)
<cs_tls_aes_128_gcm_sha256> ::= b'\x13\x01'
<cs_tls_aes_256_gcm_sha384> ::= b'\x13\x02'
<cs_tls_chacha20_poly1305_sha256> ::= b'\x13\x03'
<cs_tls_aes_128_ccm_sha256> ::= b'\x13\x04'
<cs_tls_aes_128_ccm_8_sha256> ::= b'\x13\x05'
<cipher_suite_tls13> ::= <cs_tls_aes_128_gcm_sha256> | <cs_tls_aes_256_gcm_sha384> | <cs_tls_chacha20_poly1305_sha256> | <cs_tls_aes_128_ccm_sha256> | <cs_tls_aes_128_ccm_8_sha256>

# reserved values (the pattern 0x?a?a) and private use values: no implementation defines them, a receiver ignores them (RFC 9846 section 9.3)
<grease_16> ::= b'\x0a\x0a' | b'\x1a\x1a' | b'\x2a\x2a' | b'\x3a\x3a' | b'\x4a\x4a' | b'\x5a\x5a' | b'\x6a\x6a' | b'\x7a\x7a' | b'\x8a\x8a' | b'\x9a\x9a' | b'\xaa\xaa' | b'\xba\xba' | b'\xca\xca' | b'\xda\xda' | b'\xea\xea' | b'\xfa\xfa'
<level_warning> ::= b'\x01'
<level_fatal> ::= b'\x02'
# AlertDescription (RFC 9846 section 6)
<ad_close_notify> ::= b'\x00'
<ad_unexpected_message> ::= b'\x0a'
<ad_bad_record_mac> ::= b'\x14'
<ad_record_overflow> ::= b'\x16'
<ad_handshake_failure> ::= b'\x28'
<ad_bad_certificate> ::= b'\x2a'
<ad_unsupported_certificate> ::= b'\x2b'
<ad_certificate_revoked> ::= b'\x2c'
<ad_certificate_expired> ::= b'\x2d'
<ad_certificate_unknown> ::= b'\x2e'
<ad_illegal_parameter> ::= b'\x2f'
<ad_unknown_ca> ::= b'\x30'
<ad_access_denied> ::= b'\x31'
<ad_decode_error> ::= b'\x32'
<ad_decrypt_error> ::= b'\x33'
<ad_protocol_version> ::= b'\x46'
<ad_insufficient_security> ::= b'\x47'
<ad_internal_error> ::= b'\x50'
<ad_inappropriate_fallback> ::= b'\x56'
<ad_user_canceled> ::= b'\x5a'
<ad_missing_extension> ::= b'\x6d'
<ad_unsupported_extension> ::= b'\x6e'
<ad_unrecognized_name> ::= b'\x70'
<ad_bad_certificate_status_response> ::= b'\x71'
<ad_unknown_psk_identity> ::= b'\x73'
<ad_certificate_required> ::= b'\x74'
<ad_general_error> ::= b'\x75'
<ad_no_application_protocol> ::= b'\x78'

# the error alerts a client may send: the extension-specific ones of RFC 6066 are left out, a client sends them only for the extension answers it received
<alert_description_error_sent> ::= <ad_unexpected_message> | <ad_bad_record_mac> | <ad_record_overflow> | <ad_handshake_failure> | <ad_bad_certificate> | <ad_unsupported_certificate> | <ad_certificate_revoked> | <ad_certificate_expired> | <ad_certificate_unknown> | <ad_illegal_parameter> | <ad_unknown_ca> | <ad_access_denied> | <ad_decode_error> | <ad_decrypt_error> | <ad_protocol_version> | <ad_insufficient_security> | <ad_internal_error> | <ad_inappropriate_fallback> | <ad_missing_extension> | <ad_unsupported_extension> | <ad_unknown_psk_identity> | <ad_certificate_required> | <ad_general_error> | <ad_no_application_protocol>
# TLS 1.3: every ServerHello is an extended hello, so the client may abort an unsatisfactory OCSP response (RFC 6066 section 8, 11.1)
<alert_description_error_sent_13> ::= <alert_description_error_sent> | <ad_bad_certificate_status_response>
<alert_description_error> ::= <ad_unexpected_message> | <ad_bad_record_mac> | <ad_record_overflow> | <ad_handshake_failure> | <ad_bad_certificate> | <ad_unsupported_certificate> | <ad_certificate_revoked> | <ad_certificate_expired> | <ad_certificate_unknown> | <ad_illegal_parameter> | <ad_unknown_ca> | <ad_access_denied> | <ad_decode_error> | <ad_decrypt_error> | <ad_protocol_version> | <ad_insufficient_security> | <ad_internal_error> | <ad_inappropriate_fallback> | <ad_missing_extension> | <ad_unsupported_extension> | <ad_unrecognized_name> | <ad_bad_certificate_status_response> | <ad_unknown_psk_identity> | <ad_certificate_required> | <ad_general_error> | <ad_no_application_protocol>

# TLS 1.2 cipher suites (RFC 5246 appendix A.5)
<cs12_null_with_null_null> ::= b'\x00\x00'
<cs12_rsa_with_null_md5> ::= b'\x00\x01'
<cs12_rsa_with_null_sha> ::= b'\x00\x02'
<cs12_rsa_with_rc4_128_md5> ::= b'\x00\x04'
<cs12_rsa_with_rc4_128_sha> ::= b'\x00\x05'
<cs12_rsa_with_3des_ede_cbc_sha> ::= b'\x00\x0a'
<cs12_dh_dss_with_3des_ede_cbc_sha> ::= b'\x00\x0d'
<cs12_dh_rsa_with_3des_ede_cbc_sha> ::= b'\x00\x10'
<cs12_dhe_dss_with_3des_ede_cbc_sha> ::= b'\x00\x13'
<cs12_dhe_rsa_with_3des_ede_cbc_sha> ::= b'\x00\x16'
<cs12_dh_anon_with_rc4_128_md5> ::= b'\x00\x18'
<cs12_dh_anon_with_3des_ede_cbc_sha> ::= b'\x00\x1b'
<cs12_rsa_with_aes_128_cbc_sha> ::= b'\x00\x2f'
<cs12_dh_dss_with_aes_128_cbc_sha> ::= b'\x00\x30'
<cs12_dh_rsa_with_aes_128_cbc_sha> ::= b'\x00\x31'
<cs12_dhe_dss_with_aes_128_cbc_sha> ::= b'\x00\x32'
<cs12_dhe_rsa_with_aes_128_cbc_sha> ::= b'\x00\x33'
<cs12_dh_anon_with_aes_128_cbc_sha> ::= b'\x00\x34'
<cs12_rsa_with_aes_256_cbc_sha> ::= b'\x00\x35'
<cs12_dh_dss_with_aes_256_cbc_sha> ::= b'\x00\x36'
<cs12_dh_rsa_with_aes_256_cbc_sha> ::= b'\x00\x37'
<cs12_dhe_dss_with_aes_256_cbc_sha> ::= b'\x00\x38'
<cs12_dhe_rsa_with_aes_256_cbc_sha> ::= b'\x00\x39'
<cs12_dh_anon_with_aes_256_cbc_sha> ::= b'\x00\x3a'
<cs12_rsa_with_null_sha256> ::= b'\x00\x3b'
<cs12_rsa_with_aes_128_cbc_sha256> ::= b'\x00\x3c'
<cs12_rsa_with_aes_256_cbc_sha256> ::= b'\x00\x3d'
<cs12_dh_dss_with_aes_128_cbc_sha256> ::= b'\x00\x3e'
<cs12_dh_rsa_with_aes_128_cbc_sha256> ::= b'\x00\x3f'
<cs12_dhe_dss_with_aes_128_cbc_sha256> ::= b'\x00\x40'
<cs12_dhe_rsa_with_aes_128_cbc_sha256> ::= b'\x00\x67'
<cs12_dh_dss_with_aes_256_cbc_sha256> ::= b'\x00\x68'
<cs12_dh_rsa_with_aes_256_cbc_sha256> ::= b'\x00\x69'
<cs12_dhe_dss_with_aes_256_cbc_sha256> ::= b'\x00\x6a'
<cs12_dhe_rsa_with_aes_256_cbc_sha256> ::= b'\x00\x6b'
<cs12_dh_anon_with_aes_128_cbc_sha256> ::= b'\x00\x6c'
<cs12_dh_anon_with_aes_256_cbc_sha256> ::= b'\x00\x6d'
<cipher_suite_12> ::= <cs12_null_with_null_null> | <cs12_rsa_with_null_md5> | <cs12_rsa_with_null_sha> | <cs12_rsa_with_rc4_128_md5> | <cs12_rsa_with_rc4_128_sha> | <cs12_rsa_with_3des_ede_cbc_sha> | <cs12_dh_dss_with_3des_ede_cbc_sha> | <cs12_dh_rsa_with_3des_ede_cbc_sha> | <cs12_dhe_dss_with_3des_ede_cbc_sha> | <cs12_dhe_rsa_with_3des_ede_cbc_sha> | <cs12_dh_anon_with_rc4_128_md5> | <cs12_dh_anon_with_3des_ede_cbc_sha> | <cs12_rsa_with_aes_128_cbc_sha> | <cs12_dh_dss_with_aes_128_cbc_sha> | <cs12_dh_rsa_with_aes_128_cbc_sha> | <cs12_dhe_dss_with_aes_128_cbc_sha> | <cs12_dhe_rsa_with_aes_128_cbc_sha> | <cs12_dh_anon_with_aes_128_cbc_sha> | <cs12_rsa_with_aes_256_cbc_sha> | <cs12_dh_dss_with_aes_256_cbc_sha> | <cs12_dh_rsa_with_aes_256_cbc_sha> | <cs12_dhe_dss_with_aes_256_cbc_sha> | <cs12_dhe_rsa_with_aes_256_cbc_sha> | <cs12_dh_anon_with_aes_256_cbc_sha> | <cs12_rsa_with_null_sha256> | <cs12_rsa_with_aes_128_cbc_sha256> | <cs12_rsa_with_aes_256_cbc_sha256> | <cs12_dh_dss_with_aes_128_cbc_sha256> | <cs12_dh_rsa_with_aes_128_cbc_sha256> | <cs12_dhe_dss_with_aes_128_cbc_sha256> | <cs12_dhe_rsa_with_aes_128_cbc_sha256> | <cs12_dh_dss_with_aes_256_cbc_sha256> | <cs12_dh_rsa_with_aes_256_cbc_sha256> | <cs12_dhe_dss_with_aes_256_cbc_sha256> | <cs12_dhe_rsa_with_aes_256_cbc_sha256> | <cs12_dh_anon_with_aes_128_cbc_sha256> | <cs12_dh_anon_with_aes_256_cbc_sha256>

# the static-DH suites (DH_DSS, DH_RSA): no ServerKeyExchange, the server's DH parameters come from its certificate
<cipher_suite_12_static_dh> ::= <cs12_dh_dss_with_3des_ede_cbc_sha> | <cs12_dh_rsa_with_3des_ede_cbc_sha> | <cs12_dh_dss_with_aes_128_cbc_sha> | <cs12_dh_rsa_with_aes_128_cbc_sha> | <cs12_dh_dss_with_aes_256_cbc_sha> | <cs12_dh_rsa_with_aes_256_cbc_sha> | <cs12_dh_dss_with_aes_128_cbc_sha256> | <cs12_dh_rsa_with_aes_128_cbc_sha256> | <cs12_dh_dss_with_aes_256_cbc_sha256> | <cs12_dh_rsa_with_aes_256_cbc_sha256>
# every other suite of the registry
<cipher_suite_12_other> ::= <cs12_null_with_null_null> | <cs12_rsa_with_null_md5> | <cs12_rsa_with_null_sha> | <cs12_rsa_with_rc4_128_md5> | <cs12_rsa_with_rc4_128_sha> | <cs12_rsa_with_3des_ede_cbc_sha> | <cs12_dhe_dss_with_3des_ede_cbc_sha> | <cs12_dhe_rsa_with_3des_ede_cbc_sha> | <cs12_dh_anon_with_rc4_128_md5> | <cs12_dh_anon_with_3des_ede_cbc_sha> | <cs12_rsa_with_aes_128_cbc_sha> | <cs12_dhe_dss_with_aes_128_cbc_sha> | <cs12_dhe_rsa_with_aes_128_cbc_sha> | <cs12_dh_anon_with_aes_128_cbc_sha> | <cs12_rsa_with_aes_256_cbc_sha> | <cs12_dhe_dss_with_aes_256_cbc_sha> | <cs12_dhe_rsa_with_aes_256_cbc_sha> | <cs12_dh_anon_with_aes_256_cbc_sha> | <cs12_rsa_with_null_sha256> | <cs12_rsa_with_aes_128_cbc_sha256> | <cs12_rsa_with_aes_256_cbc_sha256> | <cs12_dhe_dss_with_aes_128_cbc_sha256> | <cs12_dhe_rsa_with_aes_128_cbc_sha256> | <cs12_dhe_dss_with_aes_256_cbc_sha256> | <cs12_dhe_rsa_with_aes_256_cbc_sha256> | <cs12_dh_anon_with_aes_128_cbc_sha256> | <cs12_dh_anon_with_aes_256_cbc_sha256>
<cipher_suite_12_usable> ::= <cs12_rsa_with_aes_128_cbc_sha> | <cs12_rsa_with_aes_256_cbc_sha> | <cs12_dhe_rsa_with_aes_128_cbc_sha> | <cs12_dhe_rsa_with_aes_256_cbc_sha> | <cs12_rsa_with_aes_128_cbc_sha256> | <cs12_rsa_with_aes_256_cbc_sha256> | <cs12_dhe_rsa_with_aes_128_cbc_sha256> | <cs12_dhe_rsa_with_aes_256_cbc_sha256>
# every suite of RFC 5246 appendix A.5 whose key exchange (RSA, DHE_RSA, DHE_DSS, DH_anon, DH_DSS, DH_RSA) and cipher (AES-CBC, 3DES, RC4, NULL) the party completes
<cipher_suite_12_completable> ::= <cs12_rsa_with_aes_128_cbc_sha> | <cs12_rsa_with_aes_256_cbc_sha> | <cs12_dhe_rsa_with_aes_128_cbc_sha> | <cs12_dhe_rsa_with_aes_256_cbc_sha> | <cs12_rsa_with_aes_128_cbc_sha256> | <cs12_rsa_with_aes_256_cbc_sha256> | <cs12_dhe_rsa_with_aes_128_cbc_sha256> | <cs12_dhe_rsa_with_aes_256_cbc_sha256> | <cs12_dhe_dss_with_aes_128_cbc_sha> | <cs12_dhe_dss_with_aes_256_cbc_sha> | <cs12_dhe_dss_with_aes_128_cbc_sha256> | <cs12_dhe_dss_with_aes_256_cbc_sha256> | <cs12_dh_anon_with_aes_128_cbc_sha> | <cs12_dh_anon_with_aes_256_cbc_sha> | <cs12_dh_anon_with_aes_128_cbc_sha256> | <cs12_dh_anon_with_aes_256_cbc_sha256> | <cs12_rsa_with_null_md5> | <cs12_rsa_with_null_sha> | <cs12_rsa_with_null_sha256> | <cs12_rsa_with_rc4_128_md5> | <cs12_rsa_with_rc4_128_sha> | <cs12_rsa_with_3des_ede_cbc_sha> | <cs12_dhe_rsa_with_3des_ede_cbc_sha> | <cs12_dhe_dss_with_3des_ede_cbc_sha> | <cs12_dh_anon_with_rc4_128_md5> | <cs12_dh_anon_with_3des_ede_cbc_sha> | <cs12_dh_dss_with_3des_ede_cbc_sha> | <cs12_dh_rsa_with_3des_ede_cbc_sha> | <cs12_dh_dss_with_aes_128_cbc_sha> | <cs12_dh_rsa_with_aes_128_cbc_sha> | <cs12_dh_dss_with_aes_256_cbc_sha> | <cs12_dh_rsa_with_aes_256_cbc_sha> | <cs12_dh_dss_with_aes_128_cbc_sha256> | <cs12_dh_rsa_with_aes_128_cbc_sha256> | <cs12_dh_dss_with_aes_256_cbc_sha256> | <cs12_dh_rsa_with_aes_256_cbc_sha256>

# Alert descriptions only TLS 1.2 uses (RFC 5246 section 7.2)
<ad_decompression_failure> ::= b'\x1e'
<ad_no_renegotiation> ::= b'\x64'
<ad_certificate_unobtainable> ::= b'\x6f'
<ad_bad_certificate_hash_value> ::= b'\x72'

<alert_description_error_12> ::= <alert_description_error> | <ad_decompression_failure> | <ad_certificate_unobtainable> | <ad_bad_certificate_hash_value>

# CertChainType (RFC 6066 section 5)
<cct12_individual_certs> ::= b'\x00'
<cct12_pkipath> ::= b'\x01'

# ClientCertificateType (RFC 5246 section 7.4.4)
<cct_rsa_sign> ::= b'\x01'
<cct_dss_sign> ::= b'\x02'
<cct_rsa_fixed_dh> ::= b'\x03'
<cct_dss_fixed_dh> ::= b'\x04'
<cct_rsa_ephemeral_dh_reserved> ::= b'\x05'
<cct_dss_ephemeral_dh_reserved> ::= b'\x06'
<cct_fortezza_dms_reserved> ::= b'\x14'

# HashAlgorithm and SignatureAlgorithm of TLS 1.2 (RFC 5246 section 7.4.1.4.1)
<hash_none> ::= b'\x00'
<hash_md5> ::= b'\x01'
<hash_sha1> ::= b'\x02'
<hash_sha224> ::= b'\x03'
<hash_sha256> ::= b'\x04'
<hash_sha384> ::= b'\x05'
<hash_sha512> ::= b'\x06'
<hash_algorithm_12> ::= <hash_none> | <hash_md5> | <hash_sha1> | <hash_sha224> | <hash_sha256> | <hash_sha384> | <hash_sha512>
<sigalg_anonymous> ::= b'\x00'
<sigalg_rsa> ::= b'\x01'
<sigalg_dsa> ::= b'\x02'
<sigalg_ecdsa> ::= b'\x03'
<signature_algorithm_enum_12> ::= <sigalg_anonymous> | <sigalg_rsa> | <sigalg_dsa> | <sigalg_ecdsa>

# IdentifierType of trusted_ca_keys (RFC 6066 section 6)
<ia_pre_agreed> ::= b'\x00'
<ia_key_sha1_hash> ::= b'\x01'
<ia_x509_name> ::= b'\x02'
<ia_cert_sha1_hash> ::= b'\x03'

<psk_ke> ::= b'\x00'
<psk_dhe_ke> ::= b'\x01'
<update_not_requested> ::= b'\x00'
<update_requested> ::= b'\x01'
<name_type_host_name> ::= b'\x00'
<compression_null> ::= b'\x00'
<max_fragment_length_code> ::= b'\x01' | b'\x02' | b'\x03' | b'\x04'

# ==================================================================================================================
# Sent messages
# ==================================================================================================================
# TLSPlaintext (RFC 9846 section 5.1); legacy_record_version of an initial ClientHello may be 0x0301
<rec_len> ::= <byte>{2}
<rec_version_initial> ::= <version_0301> | <version_0303>
<rec_version> ::= <version_0303>

# ClientHello (RFC 9846 section 4.2.2, RFC 5246 section 7.4.1.2)
<hs_len> ::= <byte>{3}
<req_client_hello> ::= <req_client_hello_record> | <req_client_hello_split>
<req_client_hello_record> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello>
where forall <e> in <req_client_hello_record>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
# the same ClientHello fragmented over two records (RFC 9846 section 5.1): the handshake header, the version, the random and the
# legacy_session_id in the first, the rest in the second
<req_client_hello_split> ::= <ch_split_head> <ch_split_tail>
<ch_split_head> ::= b'\x16' <rec_version_initial> <rec_len> <hs_client_hello> <hs_len> <ch_split_prefix>
where forall <e> in <ch_split_head>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<ch_split_prefix> ::= <version_0303> <random_bytes> <session_id>
<ch_split_tail> ::= b'\x16' <rec_version> <rec_len> <ch_split_suffix>
where forall <e> in <ch_split_tail>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<ch_split_suffix> ::= <cipher_suites_vec> <compression_methods> <ch_extensions_vec>
where forall <m> in <req_client_hello_split>: <m>..<hs_len> == u(blen(<m>..<ch_split_prefix>) + blen(<m>..<ch_split_suffix>), 3)
<out_client_hello> ::= <hs_client_hello> <hs_len> <client_hello_body>
where forall <e> in <out_client_hello>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body> ::= <version_0303> <random_bytes> <session_id> <cipher_suites_vec> <compression_methods> <ch_extensions_vec>

# ---- the ClientHello that provokes a HelloRetryRequest and the one that answers it (RFC 9846 sections 4.1.2, 4.2.2) --------------
# <req_client_hello_hrr> is the first ClientHello of the class whose forms the second ClientHello can repeat: cipher suites, supported_versions,
# signature_algorithms and supported_groups are one fixed form built from the shared constants (so the second ClientHello repeats them by
# construction, with the same nonterminals), server_name and the random and legacy_session_id are the shared rules whose generators recall the
# first message's values once a HelloRetryRequest has been seen (host_name_value, random_value, session_id_value), and the key_share is
# empty (the groups of the list have no share, which makes a server answer with a HelloRetryRequest).
# TODO: 4.2.2 - every other first ClientHello (<req_client_hello>, <req_client_hello_13_only>, ...) gets an alert as the answer to a
# HelloRetryRequest (<state_after_hrr_general>): their lists (cipher suites, signature schemes, groups, ALPN names, certificate_authorities,
# PSK identities, extension presence) are chosen by the grammar and cannot be repeated by recalled leaves.
<req_client_hello_hrr> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_hrr>
where forall <e> in <req_client_hello_hrr>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_hrr> ::= <hs_client_hello> <hs_len> <client_hello_body_hrr>
where forall <e> in <out_client_hello_hrr>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_hrr> ::= <version_0303> <random_bytes> <session_id_hrr> <cipher_suites_vec_hrr> <compression_methods> <ch_extensions_vec_hrr>
# legacy_session_id of 32 bytes (the shared <session_id> with its length; the empty form is left out of this class)
<session_id_hrr> ::= b'\x20' <sid_bytes_hrr>
<sid_bytes_hrr> ::= rb'[\x00-\xff]{32}' := session_id_value()
<cipher_suites_vec_hrr> ::= <vec_len16> <cs_tls_aes_128_gcm_sha256> <cs_tls_aes_256_gcm_sha384> <cs_tls_chacha20_poly1305_sha256>
where forall <e> in <cipher_suites_vec_hrr>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_extensions_vec_hrr> ::= <vec_len16> <ch_ext_list_hrr>
where forall <e> in <ch_extensions_vec_hrr>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_hrr> ::= <ext_sni> <ext_signature_algorithms_hrr> <ext_supported_versions_hrr> <ext_supported_groups_x25519_first> <ext_key_share_empty>
<ext_signature_algorithms_hrr> ::= <ext_type_signature_algorithms> <ext_len> <signature_scheme_list_vec_hrr>
where forall <e> in <ext_signature_algorithms_hrr>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<signature_scheme_list_vec_hrr> ::= <vec_len16> <ss_rsa_pss_rsae_sha256> <ss_rsa_pss_rsae_sha384> <ss_rsa_pkcs1_sha256> <ss_ecdsa_secp256r1_sha256>
where forall <e> in <signature_scheme_list_vec_hrr>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_versions_hrr> ::= <ext_type_supported_versions> <ext_len> <versions_vec_hrr>
where forall <e> in <ext_supported_versions_hrr>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<versions_vec_hrr> ::= <vec_len8> <version_0304>
where forall <e> in <versions_vec_hrr>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)

# the ClientHello after a HelloRetryRequest: the first one again (the same nonterminals; the recalled values come from the first message),
# changed only as section 4.2.2 permits: the key_share list is one share for the group the HelloRetryRequest selected (the first message's
# empty list again when it names none), the cookie of the HelloRetryRequest is a cookie extension after it (when it carries one), and early_data
# and pre_shared_key do not occur.  One request per reply class of the HelloRetryRequest.
<req_client_hello_after_hrr> ::= b'\x16' <rec_version> <rec_len> <out_client_hello_2>
where forall <e> in <req_client_hello_after_hrr>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_2> ::= <hs_client_hello> <hs_len> <client_hello_body_2>
where forall <e> in <out_client_hello_2>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_2> ::= <version_0303> <random_bytes> <session_id_hrr> <cipher_suites_vec_hrr> <compression_methods> <ch_extensions_vec_2>
<ch_extensions_vec_2> ::= <vec_len16> <ch_ext_list_2>
where forall <e> in <ch_extensions_vec_2>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_2> ::= <ext_sni> <ext_signature_algorithms_hrr> <ext_supported_versions_hrr> <ext_supported_groups_x25519_first> <ext_key_share_2>
<req_client_hello_after_hrr_cookie> ::= b'\x16' <rec_version> <rec_len> <out_client_hello_2_cookie>
where forall <e> in <req_client_hello_after_hrr_cookie>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_2_cookie> ::= <hs_client_hello> <hs_len> <client_hello_body_2_cookie>
where forall <e> in <out_client_hello_2_cookie>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_2_cookie> ::= <version_0303> <random_bytes> <session_id_hrr> <cipher_suites_vec_hrr> <compression_methods> <ch_extensions_vec_2_cookie>
<ch_extensions_vec_2_cookie> ::= <vec_len16> <ch_ext_list_2_cookie>
where forall <e> in <ch_extensions_vec_2_cookie>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_2_cookie> ::= <ext_sni> <ext_signature_algorithms_hrr> <ext_supported_versions_hrr> <ext_supported_groups_x25519_first> <ext_key_share_2> <ext_cookie_2>
<req_client_hello_after_hrr_cookie_only> ::= b'\x16' <rec_version> <rec_len> <out_client_hello_2_cookie_only>
where forall <e> in <req_client_hello_after_hrr_cookie_only>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_2_cookie_only> ::= <hs_client_hello> <hs_len> <client_hello_body_2_cookie_only>
where forall <e> in <out_client_hello_2_cookie_only>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_2_cookie_only> ::= <version_0303> <random_bytes> <session_id_hrr> <cipher_suites_vec_hrr> <compression_methods> <ch_extensions_vec_2_cookie_only>
<ch_extensions_vec_2_cookie_only> ::= <vec_len16> <ch_ext_list_2_cookie_only>
where forall <e> in <ch_extensions_vec_2_cookie_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_2_cookie_only> ::= <ext_sni> <ext_signature_algorithms_hrr> <ext_supported_versions_hrr> <ext_supported_groups_x25519_first> <ext_key_share_empty> <ext_cookie_2>
# key_share (section 4.2.8): one KeyShareEntry of the selected group; its group and key_exchange are generated up front
<ext_key_share_2> ::= <ext_type_key_share> <ext_len> <key_share_vec_2>
where forall <e> in <ext_key_share_2>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_2> ::= <vec_len16> <key_share_entry_2>
where forall <e> in <key_share_vec_2>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<key_share_entry_2> ::= <hrr_group> <key_exchange_len> <hrr_key_exchange>
where forall <e> in <key_share_entry_2>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<hrr_group> ::= rb'[\x00-\xff]{2}' := hrr_group_value()
<hrr_key_exchange> ::= rb'[\x00-\xff]+' := hrr_key_exchange_value()
# cookie (section 4.2.2): opaque cookie<1..2^16-1>, the HelloRetryRequest's cookie, recalled
<ext_cookie_2> ::= <ext_type_cookie> <ext_len> <cookie_vec_2>
where forall <e> in <ext_cookie_2>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<cookie_vec_2> ::= <vec_len16> <hrr_cookie>
where forall <e> in <cookie_vec_2>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<hrr_cookie> ::= rb'[\x00-\xff]+' := hrr_cookie_value()

<random_bytes> ::= rb'[\x00-\xff]{32}' := random_value()
<session_id> ::= <sid_len> <sid_bytes>
where forall <e> in <session_id>: <e>.<sid_len> == u(blen(<e>) - 1, 1)
<sid_len> ::= <byte>
<sid_bytes> ::= <byte>{0,32}
<cipher_suites_vec> ::= <vec_len16> <cipher_suite_list_tls13>
where forall <e> in <cipher_suites_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<vec_len16> ::= <byte>{2}
<vec_len8> ::= <byte>
# the TLS 1.3 suites (RFC 9846 appendix B.4) in several orders and combinations, an unknown value a server ignores
# (section 9.3), and the TLS 1.2 suites this client can complete
<cipher_suite_list_tls13> ::= <cipher_suite_unknown>? <cipher_suites_13_part> <cipher_suite_12_usable>{1,2}
<cipher_suite_unknown> ::= <grease_16>
<cipher_suites_13_part> ::= (<cs_tls_aes_128_gcm_sha256> | <cs_tls_aes_256_gcm_sha384> | <cs_tls_chacha20_poly1305_sha256>
    | <cs_tls_aes_128_gcm_sha256> <cs_tls_aes_256_gcm_sha384>
    | <cs_tls_aes_256_gcm_sha384> <cs_tls_chacha20_poly1305_sha256> <cs_tls_aes_128_gcm_sha256>
    | <cs_tls_aes_128_ccm_sha256> <cs_tls_aes_128_gcm_sha256>
    | <cs_tls_aes_128_gcm_sha256> <cs_tls_aes_128_ccm_8_sha256> <cs_tls_aes_256_gcm_sha384>
    | <cs_tls_aes_128_ccm_sha256> <cs_tls_aes_128_ccm_8_sha256>)
<compression_methods> ::= b'\x01\x00'

<ch_extensions_vec> ::= <vec_len16> <ch_ext_list>
where forall <e> in <ch_extensions_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# the order of extensions is free apart from pre_shared_key, which comes last (RFC 9846 section 4.2)
<ch_ext_list> ::= <ext_sni>? <ext_max_fragment_length>? <ext_status_request>? <ext_signature_algorithms> <ext_signature_algorithms_cert>? <ext_alpn>? <ext_supported_versions> <ch_groups_and_shares> <ext_post_handshake_auth>? <ext_certificate_authorities>? <ext_unknown>? <ch_psk_part>?


# ---- extensions sent in a ClientHello (RFC 9846 section 4.2): extension_type, length, extension_data ----------------
<ext_len> ::= <byte>{2}

# server_name (RFC 6066 section 3): a ServerNameList with one entry per name type (only host_name is defined)
<ext_sni> ::= <ext_type_server_name> <ext_len> <server_name_list_vec>
where forall <e> in <ext_sni>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<server_name_list_vec> ::= <vec_len16> <server_name_entry>
where forall <e> in <server_name_list_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<server_name_entry> ::= <name_type_host_name> <host_name_vec>
<host_name_vec> ::= <vec_len16> <host_name>
where forall <e> in <host_name_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<host_name> ::= rb'[a-z0-9.-]+' := host_name_value()

# signature_algorithms (RFC 9846 section 4.3.3): SignatureSchemeList
<ext_signature_algorithms> ::= <ext_type_signature_algorithms> <ext_len> <signature_scheme_list_vec>
where forall <e> in <ext_signature_algorithms>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<signature_scheme_list_vec> ::= <vec_len16> <signature_scheme_list>
where forall <e> in <signature_scheme_list_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# narrowed to lists that contain an RSASSA-PSS scheme and rsa_pkcs1_sha256: the tested servers hold an RSA certificate signed with
# sha256WithRSAEncryption and refuse the handshake (handshake_failure) when no scheme they can sign a CertificateVerify with is
# offered (RFC 5246 section 7.4.2: in TLS 1.2 all certificates must be signed with a pair of the list)
<signature_scheme_list> ::= <signature_scheme_sent>{0,3} <ss_pss_rsae> <signature_scheme_sent>{0,3} <ss_rsa_pkcs1_sha256> <signature_scheme_sent>{0,2} <ss_private_use>?
<ss_pss_rsae> ::= <ss_rsa_pss_rsae_sha256> | <ss_rsa_pss_rsae_sha384> | <ss_rsa_pss_rsae_sha512>

# application_layer_protocol_negotiation (RFC 7301 section 3.1): ProtocolNameList of ProtocolName<1..2^8-1>
<ext_alpn> ::= <ext_type_alpn> <ext_len> <protocol_name_list_vec>
where forall <e> in <ext_alpn>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<protocol_name_list_vec> ::= <vec_len16> <protocol_name_list>
where forall <e> in <protocol_name_list_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<protocol_name_list> ::= <protocol_name>{1,3}
# ProtocolName = opaque<1..2^8-1> is ONE rule for sent and received messages (<protocol_name>, grammar_d: a length byte and a computed
# repetition of that many octets).  The sent names are narrowed from it by two things only: the generator of the length byte
# (alpn_name_length_value: the length of a name of the setting's list, or a random length) and an equality that sets each octet
# (alpn_name_octet: the octet of the name that length stands for: a name of the setting ALPN_PROTOCOLS, or arbitrary octets).  A name
# no server offers is answered with the fatal no_application_protocol alert (RFC 7301 section 3.2) or by ignoring the extension.
where forall <l> in <protocol_name_list>: forall <o> in <l>..<octet>: <o> == alpn_name_octet(<o>)


# supported_versions in a ClientHello (RFC 9846 section 4.2.1): SelectedVersions<2..254>
<ext_supported_versions> ::= <ext_type_supported_versions> <ext_len> <versions_vec>
where forall <e> in <ext_supported_versions>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<versions_vec> ::= <vec_len8> <versions_list>
where forall <e> in <versions_vec>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)
# TLS 1.3 and TLS 1.2, which the cipher suite list (TLS 1.3 suites and usable TLS 1.2 suites) and the key exchange
# support the client really has
<versions_list> ::= <version_0304> <version_0303> | <version_0303> <version_0304> | <version_0304> <version_grease> <version_0303> | <version_grease> <version_0304> <version_0303> | <version_0304> <version_0303> <version_grease> | <version_grease> <version_grease_b> <version_0304> <version_0303> | <version_0304> <version_grease> <version_0303> <version_grease_b>
<version_grease> ::= <grease_16>
<version_grease_b> ::= b'\xfa\xfa' | b'\xea\xea' | b'\xda\xda'

# supported_groups + key_share (RFC 9846 sections 4.2.7, 4.2.8): the key_share groups are among supported_groups
<ch_groups_and_shares> ::= (
      <ext_supported_groups_x25519_first> <ext_key_share_x25519>
    | <ext_supported_groups_p256_first> <ext_key_share_p256>
    | <ext_supported_groups_x25519_first> <ext_key_share_two>
    | <ext_supported_groups_wide> <ext_key_share_extra>
    | <ext_supported_groups_unknown_first> <ext_key_share_x25519>
    | <ext_supported_groups_x25519_only> <ext_key_share_x25519>
    | <ext_supported_groups_p256_only> <ext_key_share_p256>
    | <ext_supported_groups_tail> <ext_key_share_x25519>
    | <ext_supported_groups_p384_first> <ext_key_share_p384_only>
    | <ext_supported_groups_p521_first> <ext_key_share_p521_only>
    | <ext_supported_groups_p256_p384> <ext_key_share_p256_p384>
    | <ext_supported_groups_x25519_first> <ext_key_share_three>
    | <ext_supported_groups_free> <ext_key_share_x25519>
    | <ext_supported_groups_x448_only> <ext_key_share_x448_only>
    | <ext_supported_groups_p384_p521> <ext_key_share_p384_p521>
    | <ext_supported_groups_p256_x448> <ext_key_share_p256_x448>
    | <ext_supported_groups_any_p256> <ext_key_share_p256>
    | <ext_supported_groups_x25519_first> <ext_key_share_empty>
    | <ext_supported_groups_p256_first> <ext_key_share_p256_x25519>
    | <ext_supported_groups_x25519_first> <ext_key_share_x25519_p384>
    | <ext_supported_groups_x25519_first> <ext_key_share_p256_p384>
    | <ext_supported_groups_four> <ext_key_share_four>
    | <ext_supported_groups_x25519_first> <ext_key_share_p384_only>
    | <ext_supported_groups_any_p384> <ext_key_share_p384_only>
    | <ext_supported_groups_any_p521> <ext_key_share_p521_only>
    | <ext_supported_groups_any_x448> <ext_key_share_x448_only> )
<ext_supported_groups_x25519_first> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_a>
where forall <e> in <ext_supported_groups_x25519_first>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_a> ::= <vec_len16> <ng_x25519> <ng_secp256r1> <ng_secp384r1>
where forall <e> in <named_group_list_vec_a>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_p256_first> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_b>
where forall <e> in <ext_supported_groups_p256_first>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_b> ::= <vec_len16> <ng_secp256r1> <ng_x25519>
where forall <e> in <named_group_list_vec_b>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)

# lists with more groups after the ones a share is sent for (a server picks the first mutually supported group in the client's
# order), and a list that starts with a group no server knows (RFC 9846 sections 4.3.7, 9.3)
<ext_supported_groups_wide> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_wide>
where forall <e> in <ext_supported_groups_wide>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_wide> ::= <vec_len16> <ng_x25519> <ng_secp256r1> <ng_secp384r1> <ng_secp521r1> <ng_x448> <ng_ffdhe2048> <ng_ffdhe_private_use> <ng_private_fe00>
where forall <e> in <named_group_list_vec_wide>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ng_private_fe00> ::= b'\xfe\x00'
<ext_supported_groups_unknown_first> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_unknown_first>
where forall <e> in <ext_supported_groups_unknown_first>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_unknown_first> ::= <vec_len16> <ng_ecdhe_private_use> <ng_x25519> <ng_secp256r1>
where forall <e> in <named_group_list_vec_unknown_first>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_x25519_only> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_x25519_only>
where forall <e> in <ext_supported_groups_x25519_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_x25519_only> ::= <vec_len16> <ng_x25519>
where forall <e> in <named_group_list_vec_x25519_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_p256_only> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_p256_only>
where forall <e> in <ext_supported_groups_p256_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_p256_only> ::= <vec_len16> <ng_secp256r1>
where forall <e> in <named_group_list_vec_p256_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# after the groups a share is sent for: an unassigned and a private-use group (distinct ranges, so no duplicate entry)
<ext_supported_groups_tail> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_tail>
where forall <e> in <ext_supported_groups_tail>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_tail> ::= <vec_len16> <ng_x25519> <ng_secp256r1> <ng_unassigned> <ng_ffdhe_private_use>
where forall <e> in <named_group_list_vec_tail>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# a list with the one group a share is sent for: a server completes the handshake with it (a longer list would let a server
# that prefers another group answer with a HelloRetryRequest)
<ext_supported_groups_p384_first> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_p384_first>
where forall <e> in <ext_supported_groups_p384_first>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_p384_first> ::= <vec_len16> <ng_secp384r1>
where forall <e> in <named_group_list_vec_p384_first>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_p521_first> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_p521_first>
where forall <e> in <ext_supported_groups_p521_first>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_p521_first> ::= <vec_len16> <ng_secp521r1>
where forall <e> in <named_group_list_vec_p521_first>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_p521_only> ::= <ext_type_key_share> <ext_len> <key_share_vec_p521>
where forall <e> in <ext_key_share_p521_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p521> ::= <vec_len16> <key_share_entry_p521>
where forall <e> in <key_share_vec_p521>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# shares for two groups, neither of them x25519
<ext_supported_groups_p256_p384> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_p256_p384>
where forall <e> in <ext_supported_groups_p256_p384>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_p256_p384> ::= <vec_len16> <ng_secp256r1> <ng_secp384r1> <ng_x25519>
where forall <e> in <named_group_list_vec_p256_p384>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_p256_p384> ::= <ext_type_key_share> <ext_len> <key_share_vec_p256_p384>
where forall <e> in <ext_key_share_p256_p384>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p256_p384> ::= <vec_len16> <key_share_entry_p256> <key_share_entry_p384>
where forall <e> in <key_share_vec_p256_p384>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# three shares, in the order of the list
<ext_key_share_three> ::= <ext_type_key_share> <ext_len> <key_share_vec_three>
where forall <e> in <ext_key_share_three>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_three> ::= <vec_len16> <key_share_entry_x25519> <key_share_entry_p256> <key_share_entry_p384>
where forall <e> in <key_share_vec_three>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# the groups a share is sent for, then any groups of the registry (NamedGroup, RFC 9846 appendix B.3.1.4), no group twice
<ext_supported_groups_free> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_free>
where forall <e> in <ext_supported_groups_free>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_free> ::= <vec_len16> <ng_x25519> <ng_free_tail>
where forall <e> in <named_group_list_vec_free>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ng_free_tail> ::= <ng_secp256r1>? <ng_secp384r1>? <ng_secp521r1>? <ng_x448>? <ng_ffdhe2048>? <ng_ffdhe3072>? <ng_ffdhe4096>? <ng_ffdhe6144>? <ng_ffdhe8192>? <ng_ffdhe_private_use>? <ng_ecdhe_private_use>? <ng_unassigned>?
# the other groups with a share: x448 alone (wolfSSL answers it with a HelloRetryRequest, which is accepted), secp384r1 and secp521r1,
# secp256r1 and x448, and any registry group after the one a share is sent for (the shared <named_group> rule)
<ext_supported_groups_x448_only> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_x448_only>
where forall <e> in <ext_supported_groups_x448_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_x448_only> ::= <vec_len16> <ng_x448>
where forall <e> in <named_group_list_vec_x448_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_x448_only> ::= <ext_type_key_share> <ext_len> <key_share_vec_x448>
where forall <e> in <ext_key_share_x448_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_x448> ::= <vec_len16> <key_share_entry_x448>
where forall <e> in <key_share_vec_x448>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_p384_p521> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_p384_p521>
where forall <e> in <ext_supported_groups_p384_p521>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_p384_p521> ::= <vec_len16> <ng_secp384r1> <ng_secp521r1>
where forall <e> in <named_group_list_vec_p384_p521>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_p384_p521> ::= <ext_type_key_share> <ext_len> <key_share_vec_p384_p521>
where forall <e> in <ext_key_share_p384_p521>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p384_p521> ::= <vec_len16> <key_share_entry_p384> <key_share_entry_p521>
where forall <e> in <key_share_vec_p384_p521>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_p256_x448> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_p256_x448>
where forall <e> in <ext_supported_groups_p256_x448>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_p256_x448> ::= <vec_len16> <ng_secp256r1> <ng_x448>
where forall <e> in <named_group_list_vec_p256_x448>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_p256_x448> ::= <ext_type_key_share> <ext_len> <key_share_vec_p256_x448>
where forall <e> in <ext_key_share_p256_x448>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p256_x448> ::= <vec_len16> <key_share_entry_p256> <key_share_entry_x448>
where forall <e> in <key_share_vec_p256_x448>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_p256_x25519> ::= <ext_type_key_share> <ext_len> <key_share_vec_p256_x25519>
where forall <e> in <ext_key_share_p256_x25519>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p256_x25519> ::= <vec_len16> <key_share_entry_p256> <key_share_entry_x25519>
where forall <e> in <key_share_vec_p256_x25519>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_x25519_p384> ::= <ext_type_key_share> <ext_len> <key_share_vec_x25519_p384>
where forall <e> in <ext_key_share_x25519_p384>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_x25519_p384> ::= <vec_len16> <key_share_entry_x25519> <key_share_entry_p384>
where forall <e> in <key_share_vec_x25519_p384>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_four> ::= <ext_type_key_share> <ext_len> <key_share_vec_four>
where forall <e> in <ext_key_share_four>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_four> ::= <vec_len16> <key_share_entry_x25519> <key_share_entry_p256> <key_share_entry_p384> <key_share_entry_p521>
where forall <e> in <key_share_vec_four>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_four> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_four>
where forall <e> in <ext_supported_groups_four>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_four> ::= <vec_len16> <ng_x25519> <ng_secp256r1> <ng_secp384r1> <ng_secp521r1>
where forall <e> in <named_group_list_vec_four>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_any_p384> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_any_p384>
where forall <e> in <ext_supported_groups_any_p384>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_any_p384> ::= <vec_len16> <ng_secp384r1> <ng_tail_p384>
<ng_tail_p384> ::= <ng_x25519>? <ng_secp256r1>? <ng_secp521r1>? <ng_x448>? <ng_ffdhe2048>? <ng_ffdhe3072>? <ng_ffdhe4096>? <ng_ffdhe6144>? <ng_ffdhe8192>? <ng_ffdhe_private_use>? <ng_ecdhe_private_use>? <ng_unassigned>?
where forall <e> in <named_group_list_vec_any_p384>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_any_p521> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_any_p521>
where forall <e> in <ext_supported_groups_any_p521>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_any_p521> ::= <vec_len16> <ng_secp521r1> <ng_tail_p521>
<ng_tail_p521> ::= <ng_x25519>? <ng_secp256r1>? <ng_secp384r1>? <ng_x448>? <ng_ffdhe2048>? <ng_ffdhe3072>? <ng_ffdhe4096>? <ng_ffdhe6144>? <ng_ffdhe8192>? <ng_ffdhe_private_use>? <ng_ecdhe_private_use>? <ng_unassigned>?
where forall <e> in <named_group_list_vec_any_p521>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_any_x448> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_any_x448>
where forall <e> in <ext_supported_groups_any_x448>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_any_x448> ::= <vec_len16> <ng_x448> <ng_tail_x448>
<ng_tail_x448> ::= <ng_x25519>? <ng_secp256r1>? <ng_secp384r1>? <ng_secp521r1>? <ng_ffdhe2048>? <ng_ffdhe3072>? <ng_ffdhe4096>? <ng_ffdhe6144>? <ng_ffdhe8192>? <ng_ffdhe_private_use>? <ng_ecdhe_private_use>? <ng_unassigned>?
where forall <e> in <named_group_list_vec_any_x448>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_groups_any_p256> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_any_p256>
where forall <e> in <ext_supported_groups_any_p256>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_any_p256> ::= <vec_len16> <ng_secp256r1> <ng_tail_p256>
<ng_tail_p256> ::= <ng_x25519>? <ng_secp384r1>? <ng_secp521r1>? <ng_x448>? <ng_ffdhe2048>? <ng_ffdhe3072>? <ng_ffdhe4096>? <ng_ffdhe6144>? <ng_ffdhe8192>? <ng_ffdhe_private_use>? <ng_ecdhe_private_use>? <ng_unassigned>?
where forall <e> in <named_group_list_vec_any_p256>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_key_share_extra> ::= <ext_type_key_share> <ext_len> <key_share_vec_extra>
where forall <e> in <ext_key_share_extra>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_extra> ::= <vec_len16> <key_share_entry_x25519> <key_share_entry_extra>
where forall <e> in <key_share_vec_extra>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<key_share_entry_extra> ::= <key_share_entry_p384> | <key_share_entry_p521> | <key_share_entry_x448> | <key_share_entry_unknown>
<key_share_entry_p384> ::= <ng_secp384r1> <key_exchange_len> <key_exchange_p384>
where forall <e> in <key_share_entry_p384>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<key_exchange_p384> ::= rb'[\x00-\xff]{97}' := clean(lambda: new_key_share(0x0018))
<key_share_entry_p521> ::= <ng_secp521r1> <key_exchange_len> <key_exchange_p521>
where forall <e> in <key_share_entry_p521>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<key_exchange_p521> ::= rb'[\x00-\xff]{133}' := clean(lambda: new_key_share(0x0019))
<key_share_entry_x448> ::= <ng_x448> <key_exchange_len> <key_exchange_x448>
where forall <e> in <key_share_entry_x448>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<key_exchange_x448> ::= rb'[\x00-\xff]{56}' := clean(lambda: new_key_share(0x001E))
<key_share_entry_unknown> ::= <ng_private_fe00> <key_exchange_len> <key_exchange_unknown>
where forall <e> in <key_share_entry_unknown>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<key_exchange_unknown> ::= rb'[\x00-\xff]{1,48}'

<ext_key_share_x25519> ::= <ext_type_key_share> <ext_len> <key_share_vec_x25519>
where forall <e> in <ext_key_share_x25519>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_x25519> ::= <vec_len16> <key_share_entry_x25519>
where forall <e> in <key_share_vec_x25519>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<key_share_entry_x25519> ::= <ng_x25519> <key_exchange_len> <key_exchange_x25519>
where forall <e> in <key_share_entry_x25519>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<key_exchange_len> ::= <byte>{2}
<key_exchange_x25519> ::= rb'[\x00-\xff]{32}' := clean(lambda: new_key_share(0x001D))
<ext_key_share_p256> ::= <ext_type_key_share> <ext_len> <key_share_vec_p256>
where forall <e> in <ext_key_share_p256>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p256> ::= <vec_len16> <key_share_entry_p256>
where forall <e> in <key_share_vec_p256>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<key_share_entry_p256> ::= <ng_secp256r1> <key_exchange_len> <key_exchange_p256>
where forall <e> in <key_share_entry_p256>: <e>.<key_exchange_len> == u(blen(<e>) - 4, 2)
<key_exchange_p256> ::= rb'[\x00-\xff]{65}' := clean(lambda: new_key_share(0x0017))
<ext_key_share_two> ::= <ext_type_key_share> <ext_len> <key_share_vec_two>
where forall <e> in <ext_key_share_two>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_two> ::= <vec_len16> <key_share_entry_x25519> <key_share_entry_p256>
where forall <e> in <key_share_vec_two>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)

# psk_key_exchange_modes (RFC 9846 section 4.2.9)
<ext_psk_modes> ::= <ext_type_psk_key_exchange_modes> <ext_len> <psk_modes_vec>
where forall <e> in <ext_psk_modes>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<psk_modes_vec> ::= <vec_len8> <psk_modes_list>
where forall <e> in <psk_modes_vec>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)
<psk_modes_list> ::= <psk_ke> | <psk_dhe_ke> | <psk_ke> <psk_dhe_ke> | <psk_dhe_ke> <psk_ke>

<ext_key_share_empty> ::= <ext_type_key_share> b'\x00\x02' b'\x00\x00'
<ext_key_share_p384_only> ::= <ext_type_key_share> <ext_len> <key_share_vec_p384>
where forall <e> in <ext_key_share_p384_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<key_share_vec_p384> ::= <vec_len16> <key_share_entry_p384>
where forall <e> in <key_share_vec_p384>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# max_fragment_length (RFC 6066 section 4)
<ext_max_fragment_length> ::= <ext_type_max_fragment_length> b'\x00\x01' <max_fragment_length_code>

# status_request (RFC 6066 section 8): status_type ocsp, ResponderIDs and request extensions (DER, carried opaque)
<ext_status_request> ::= <ext_type_status_request> <ext_len> <status_request_body>
where forall <e> in <ext_status_request>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<status_request_body> ::= <status_type_ocsp> <responder_id_list_vec> <request_extensions_vec>
<responder_id_list_vec> ::= <vec_len16> <responder_id>*
where forall <e> in <responder_id_list_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<responder_id> ::= <vec_len16> <opaque_der>
where forall <e> in <responder_id>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# request_extensions: empty (zero length: no extensions), or the DER of a non-empty Extensions SEQUENCE (RFC 6960: an OCSP nonce)
<request_extensions_vec> ::= <vec_len16> <request_extensions_der>?
where forall <e> in <request_extensions_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<request_extensions_der> ::= rb'[\x00-\xff]{35}' := ocsp_nonce_extensions_der()
<opaque_der> ::= rb'[\x00-\xff]{2,700}' := responder_id_der_value()
<status_type_ocsp> ::= b'\x01'

# signature_algorithms_cert (RFC 9846 section 4.2.3)
<ext_signature_algorithms_cert> ::= <ext_type_signature_algorithms_cert> <ext_len> <signature_scheme_list_cert_vec>
where forall <e> in <ext_signature_algorithms_cert>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
# narrowed to a list that holds the algorithm the tested servers' certificates are signed with (sha256WithRSAEncryption);
# a server without a certificate the client accepts answers handshake_failure
<signature_scheme_list_cert_vec> ::= <vec_len16> <signature_scheme_sent>{0,3} <ss_rsa_pkcs1_sha256> <signature_scheme_sent>{0,3} <signature_scheme_legacy>{0,2}
# the legacy SHA-1 schemes may appear in signature_algorithms_cert with the lowest priority (RFC 9846 section 4.3.3)
<signature_scheme_legacy> ::= <ss_rsa_pkcs1_sha1> | <ss_ecdsa_sha1>
where forall <e> in <signature_scheme_list_cert_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)

# an extension no implementation defines (a reserved type): the server ignores it (RFC 9846 section 9.3)
<ext_unknown> ::= <grease_16> <ext_len> <unknown_ext_data>
where forall <e> in <ext_unknown>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<unknown_ext_data> ::= <byte>{0,12}

# post_handshake_auth (RFC 9846 section 4.2.6)
<ext_post_handshake_auth> ::= <ext_type_post_handshake_auth> b'\x00\x00'

# certificate_authorities (RFC 9846 section 4.2.4): DistinguishedName<1..2^16-1> (DER, RFC 5280)
<ext_certificate_authorities> ::= <ext_type_certificate_authorities> <ext_len> <authorities_vec>
where forall <e> in <ext_certificate_authorities>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<authorities_vec> ::= <vec_len16> <distinguished_name>{1,2}
where forall <e> in <authorities_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<distinguished_name> ::= <vec_len16> <dn_der>
where forall <e> in <distinguished_name>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<dn_der> ::= rb'[\x00-\xff]{1,600}' := dn_der_value()

# PSK part (RFC 9846 sections 4.2.9, 4.2.10, 4.2.11): the modes, optionally early_data and pre_shared_key, which is last
<ch_psk_part> ::= <ext_psk_modes> | <ext_psk_modes> <ext_pre_shared_key> | <ext_psk_modes> <ext_early_data_ch> <ext_pre_shared_key>
<ext_early_data_ch> ::= <ext_type_early_data> b'\x00\x00'
<ext_pre_shared_key> ::= <ext_type_pre_shared_key> <ext_len> (<psk_identities_vec_1> <psk_binders_vec_1> | <psk_identities_vec_2> <psk_binders_vec_2>)
where forall <e> in <ext_pre_shared_key>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<psk_identities_vec_1> ::= <vec_len16> <psk_identity>
where forall <e> in <psk_identities_vec_1>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<psk_identities_vec_2> ::= <vec_len16> <psk_identity> <psk_identity>
where forall <e> in <psk_identities_vec_2>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<psk_identity> ::= <vec_len16> <psk_identity_bytes> <obfuscated_ticket_age>
where forall <e> in <psk_identity>: <e>.<vec_len16> == u(blen(<e>) - 6, 2)
<psk_identity_bytes> ::= rb'[\x00-\xff]{1,32}'
<obfuscated_ticket_age> ::= <byte>{4}
<psk_binders_vec_1> ::= <vec_len16> <psk_binder>
where forall <e> in <psk_binders_vec_1>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<psk_binders_vec_2> ::= <vec_len16> <psk_binder> <psk_binder>
where forall <e> in <psk_binders_vec_2>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<psk_binder> ::= <vec_len8> <psk_binder_bytes>
where forall <e> in <psk_binder>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)
<psk_binder_bytes> ::= rb'[\x00-\xff]{32}' | rb'[\x00-\xff]{48}'

# ---- other client messages (RFC 9846 sections 4.4.4, 4.6.3, 5.1, 6) ---------------------------------------------------
# a compatibility change_cipher_spec (RFC 9846 appendix D.4)
<req_ccs_compat> ::= <ct_change_cipher_spec> <rec_version> <rec_len> b'\x01'
where forall <e> in <req_ccs_compat>: <e>.<rec_len> == u(blen(<e>) - 5, 2)

# Finished (RFC 9846 section 4.4.4); the record may carry padding zeros after the content type (section 5.4)
<req_finished_13> ::= <ct_handshake> <rec_version> <rec_len> <out_finished> <out_padding>
where forall <e> in <req_finished_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_finished> ::= <hs_finished> <hs_len> <verify_data>
where forall <e> in <out_finished>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<verify_data> ::= <byte>+
where forall <f> in <out_finished>: <f>.<verify_data> == client_finished_data()
<out_padding> ::= <padding_zero>{0,8}
<padding_zero> ::= b'\x00'

# Finished fragmented over two records (RFC 9846 section 5.1): the handshake header in the first, verify_data in the second
<req_finished_13_fragmented> ::= <req_finished_13_head> <req_finished_13_tail>
<req_finished_13_head> ::= <ct_handshake> <rec_version> <rec_len> <hs_finished> <hs_len_frag> <out_padding>
where forall <e> in <req_finished_13_head>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<req_finished_13_tail> ::= <ct_handshake> <rec_version> <rec_len> <verify_data_frag> <out_padding>
where forall <e> in <req_finished_13_tail>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<hs_len_frag> ::= <byte>{3}
<verify_data_frag> ::= <byte>+
where forall <f> in <req_finished_13_fragmented>: <f>..<verify_data_frag> == client_finished_data()
where forall <f> in <req_finished_13_fragmented>: <f>..<hs_len_frag> == u(blen(<f>..<verify_data_frag>), 3)

# application_data (RFC 9846 section 5.1)
<req_app_data_13> ::= <ct_application_data> <rec_version> <rec_len> <app_data> <out_padding>
where forall <e> in <req_app_data_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
# The content is opaque to the protocol; what a server does with it depends on its application: it echoes data in lines, and
# the line-oriented test servers read commands from it (gnutls-serv: **REHANDSHAKE** makes it send a HelloRequest in TLS 1.2 and a
# KeyUpdate in TLS 1.3, **REKEY** a KeyUpdate, **REAUTH** a post-handshake CertificateRequest).  Three disjoint forms: bytes
# without a line end, and one line: a first byte other than '*', then at most 62 bytes without a line end, then the line end, or
# one of the commands (a line that starts with '**').
<app_data> ::= <app_data_binary> | <app_data_line>
<app_data_binary> ::= <app_byte>{0,64}
<app_byte> ::= rb'[\x00-\x09\x0b-\xff]'
<app_data_line> ::= <app_line_start> <app_byte>{0,62} b'\n' | b'\n' | <app_data_command>
<app_line_start> ::= rb'[\x00-\x09\x0b-\x29\x2b-\xff]'
<app_data_command> ::= b'**REHANDSHAKE**\n' | b'**REKEY**\n' | b'**REAUTH**\n'

# application data split over two records (section 5.1)
<req_app_data_13_split> ::= <req_app_data_13> <req_app_data_13_second>
<req_app_data_13_second> ::= <req_app_data_13>

# a record of 600 to 1500 bytes: above the smallest negotiable max_fragment_length (RFC 6066 section 4: the party then fragments)
<req_app_data_13_large> ::= <ct_application_data> <rec_version> <rec_len> <app_data_large> <out_padding>
where forall <e> in <req_app_data_13_large>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<app_data_large> ::= rb'[\x00-\xff]{1,6000}' := large_app_data_value()

# the request that breaks the requirement of RFC 6066 section 4 (once a maximum fragment length other than 2^14 is negotiated, the client MUST fragment so that no
# fragment larger than the negotiated length is sent): one record whose plaintext exceeds the negotiated length by more than the record layer's output bound (the
# party sends it unsplit; it carries the marker OVERFLOW_MAGIC) where a maximum fragment length is negotiated (TlsState.max_fragment); where none is, the generator
# returns ordinary short data, so the request breaks nothing.  After it only the record_overflow alert is accepted (the where on every other reply, below).
<req_app_data_13_overflow> ::= <ct_application_data> <rec_version> <rec_len> <app_data_overflow> <out_padding>
where forall <e> in <req_app_data_13_overflow>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<app_data_overflow> ::= rb'[\x00-\xff]{1,6000}' := overflow_app_data_value()

# KeyUpdate (RFC 9846 section 4.6.3)
<req_key_update_not_requested> ::= <ct_handshake> <rec_version> <rec_len> <hs_key_update> b'\x00\x00\x01' <update_not_requested> <out_padding>
where forall <e> in <req_key_update_not_requested>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<req_key_update_requested> ::= <ct_handshake> <rec_version> <rec_len> <hs_key_update> b'\x00\x00\x01' <update_requested> <out_padding>
where forall <e> in <req_key_update_requested>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)

# alerts (RFC 9846 section 6)
<req_alert_close_notify_13> ::= <ct_alert> <rec_version> <rec_len> <level_warning> <ad_close_notify> <out_padding>
where forall <e> in <req_alert_close_notify_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<req_alert_error_13> ::= <ct_alert> <rec_version> <rec_len> <level_fatal> <alert_description_error_sent_13> <out_padding>
where forall <e> in <req_alert_error_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)

# Certificate without certificates (RFC 9846 section 4.4.2): the answer to a CertificateRequest the client cannot satisfy
<req_certificate_empty> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_empty> <out_padding>
where forall <e> in <req_certificate_empty>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_empty> ::= <hs_certificate> <hs_len> b'\x00' b'\x00\x00\x00'
where forall <e> in <out_certificate_empty>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<req_ccs_compat_after_request> ::= <req_ccs_compat>
<req_ccs_compat_before_second_hello> ::= <req_ccs_compat>
<req_finished_13_after_empty_certificate> ::= <req_finished_13>


# ---- messages a client must not send in the state it is in (the server must answer with an alert) -----------------
# a handshake message of a type that is not valid after the handshake (RFC 9846 section 4: a ClientHello after the
# handshake is forbidden, section 4.2.2; the others are not client messages or not expected here)
<req_unexpected_handshake_13> ::= <ct_handshake> <rec_version> <rec_len> <out_unexpected_handshake> <out_padding>
where forall <e> in <req_unexpected_handshake_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_unexpected_handshake> ::= <out_encrypted_extensions_empty> | <out_new_session_ticket> | <out_finished_unexpected>
<out_encrypted_extensions_empty> ::= <hs_encrypted_extensions> b'\x00\x00\x02' b'\x00\x00'
<out_new_session_ticket> ::= <hs_new_session_ticket> <hs_len> <byte>{4} <byte>{4} b'\x00' <vec_len16> <byte>{1,8} b'\x00\x00'
<out_finished_unexpected> ::= <hs_finished> b'\x00\x00\x20' <byte>{32}
# before the ClientHello: a handshake message that is not a ClientHello
<req_unexpected_first_handshake> ::= <ct_handshake> <rec_version> <rec_len> <out_finished_unexpected>
where forall <e> in <req_unexpected_first_handshake>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_alert_close_notify_after_user_canceled> ::= <req_alert_close_notify_13>
<req_alert_user_canceled_close_notify_13> ::= <req_alert_user_canceled_13> <req_alert_close_notify_after_user_canceled>
# user_canceled (RFC 9846 section 6.1), which must be followed by close_notify
<req_alert_user_canceled_13> ::= <ct_alert> <rec_version> <rec_len> <level_warning> <ad_user_canceled> <out_padding>
where forall <e> in <req_alert_user_canceled_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)


# ---- alerts during the handshake and the answer to a server's KeyUpdate (RFC 9846 sections 6, 4.6.3) ------------------------
<req_alert_error_hs_13> ::= <req_alert_error_13>
<req_alert_user_canceled_hs_13> ::= <req_alert_user_canceled_13>
# user_canceled and the close_notify that must follow it (RFC 9846 section 6.1), the two records in one send: used while the server's flight is on its way,
# where nothing may come between the two alerts
<req_alert_user_canceled_close_notify_hs_13> ::= <req_alert_user_canceled_13> <req_alert_close_notify_13>
<req_alert_close_notify_hs_13> ::= <req_alert_close_notify_13>
<req_alert_close_notify_after_user_canceled_hs> ::= <req_alert_close_notify_13>
<req_key_update_answer> ::= <req_key_update_not_requested>
# the requests that break RFC 9846 section 4.6.3 (update_requested again before a KeyUpdate of the peer has arrived; application data before the owed answer)
<req_key_update_requested_again> ::= <req_key_update_requested>
<req_key_update_requested_twice> ::= <req_key_update_requested> <req_key_update_requested_again>
<req_app_data_13_unanswered> ::= <req_app_data_13>

# ---- Certificate with the client's own certificate and CertificateVerify (RFC 9846 sections 4.4.2, 4.4.3) -------------
# the certificate_request_context of the main handshake is empty; the certificate is generated to fit the request
<req_certificate_13> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_13> <out_padding>
where forall <e> in <req_certificate_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_13> ::= <hs_certificate> <hs_len> b'\x00' <cert_list_out>
where forall <e> in <out_certificate_13>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
# the chain: the end-entity certificate and the CA certificate of the party, or a certificate issued by the party's intermediate CA
# followed by the intermediate and (optionally) the root (RFC 9846 section 4.4.2: certificate_list is a chain of any number of entries)
<cert_list_out> ::= <cert_list_len_out> <cert_entry_out> <cert_entry_ca_out>? | <cert_list_len_out> <cert_entry_via_out> <cert_entry_inter_out> <cert_entry_ca_out>?
where forall <e> in <cert_list_out>: <e>.<cert_list_len_out> == u(blen(<e>) - 3, 3)
<cert_list_len_out> ::= <byte>{3}
# CertificateEntry: cert_data and the extensions vector
<cert_entry_out> ::= <cert_len_out> <client_cert_der> <cert_entry_ext_out>
where forall <e> in <cert_entry_out>: <e>.<cert_len_out> == u(blen(<e>.<client_cert_der>), 3)
<cert_entry_via_out> ::= <cert_len_out> <client_cert_der_via> <cert_entry_ext_out>
where forall <e> in <cert_entry_via_out>: <e>.<cert_len_out> == u(blen(<e>.<client_cert_der_via>), 3)
<cert_entry_inter_out> ::= <cert_len_out> <client_inter_der> <cert_entry_ext_none_out>
where forall <e> in <cert_entry_inter_out>: <e>.<cert_len_out> == u(blen(<e>.<client_inter_der>), 3)
# the extensions vector of the entry (RFC 9846 section 4.4.2.1): empty, or the answer to the status_request of the CertificateRequest, a
# CertificateStatus (status_type ocsp, an OCSPResponse signed by the CA of the party, RFC 6066 section 8) when the request carried the
# extension (the generator reads the request, a recalling generator): the extensions of the client's Certificate correspond to those of the
# request.  TODO in tls.fan: signed_certificate_timestamp (RFC 6962, outside the manifest).
<cert_entry_ext_out> ::= rb'[\x00-\xff]+' := cert_entry_extensions()
<cert_entry_ext_none_out> ::= b'\x00\x00'
<cert_len_out> ::= <byte>{3}
<cert_entry_ca_out> ::= <cert_len_out> <client_ca_der_13> <cert_entry_ext_none_out>
where forall <e> in <cert_entry_ca_out>: <e>.<cert_len_out> == u(blen(<e>.<client_ca_der_13>), 3)
<client_ca_der_13> ::= rb'[\x00-\xff]+' := client_ca_certificate_13()
# the generator picks, up front, a certificate (key kind and signer) whose signature and key fit the lists of the CertificateRequest
# (RFC 9846 sections 4.4.2, 4.4.3); the empty Certificate is an alternative of its own (<req_certificate_empty>); the CA entry is the
# trust anchor of the chain, whose own signature is not validated
<client_cert_der> ::= rb'[\x00-\xff]+' := client_certificate_der()
<client_cert_der_via> ::= rb'[\x00-\xff]+' := client_certificate_via_der()
<client_inter_der> ::= rb'[\x00-\xff]+' := client_intermediate_certificate()

# the request that breaks the requirement of RFC 9846 section 4.5.1.2 (the end-entity certificate MUST match the recognized extension OIDs of a
# non-empty oid_filters extension of the CertificateRequest): the same message with a certificate that lacks the extension the filter names
# (client_certificate_breach_der; where the request has no such filter it sends the ordinary certificate and breaks nothing).  The spec makes
# no reaction mandatory (RFC 9846 section 4.3.5: the server MAY continue without client authentication or abort with unsupported_certificate),
# so every reply is accepted.
<req_certificate_13_filter_breach> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_13_breach> <out_padding>
where forall <e> in <req_certificate_13_filter_breach>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_13_breach> ::= <hs_certificate> <hs_len> b'\x00' <cert_list_breach_out>
where forall <e> in <out_certificate_13_breach>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<cert_list_breach_out> ::= <cert_list_len_out> <cert_entry_breach_out> <cert_entry_ca_out>?
where forall <e> in <cert_list_breach_out>: <e>.<cert_list_len_out> == u(blen(<e>) - 3, 3)
<cert_entry_breach_out> ::= <cert_len_out> <client_cert_der_breach> <cert_entry_ext_out>
where forall <e> in <cert_entry_breach_out>: <e>.<cert_len_out> == u(blen(<e>.<client_cert_der_breach>), 3)
<client_cert_der_breach> ::= rb'[\x00-\xff]+' := client_certificate_breach_der()

<req_certificate_verify_13> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_verify> <out_padding>
where forall <e> in <req_certificate_verify_13>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_verify> ::= <hs_certificate_verify> <hs_len> <cv_scheme_out> <cv_sig_len_out> <cv_signature_out>
where forall <e> in <out_certificate_verify>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<cv_scheme_out> ::= <signature_scheme> := client_cv_scheme()
<cv_sig_len_out> ::= <byte>{2}
<cv_signature_out> ::= rb'[\x00-\xff]+'
where forall <m> in <out_certificate_verify>: <m>.<cv_signature_out> == client_cv_signature(rb(<m>.<cv_scheme_out>), False)
where forall <m> in <out_certificate_verify>: <m>.<cv_sig_len_out> == u(blen(<m>.<cv_signature_out>), 2)

<req_finished_13_after_certificate> ::= <req_finished_13>

# ---- post-handshake authentication (RFC 9846 sections 4.6.2, 4.4.2): the answer to a CertificateRequest -------------------
# the certificate_request_context repeats the request's
<cert_ctx_out> ::= <ctx_len_out> <ctx_value_out>
where forall <e> in <cert_ctx_out>: <e>.<ctx_len_out> == u(blen(<e>) - 1, 1)
<ctx_len_out> ::= <byte>
<ctx_value_out> ::= rb'[\x00-\xff]+' := post_hs_context()
where forall <c> in <cert_ctx_out>: <c>.<ctx_value_out> == post_hs_context()

<req_certificate_post_empty> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_post_empty> <out_padding>
where forall <e> in <req_certificate_post_empty>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_post_empty> ::= <hs_certificate> <hs_len> <cert_ctx_out> b'\x00\x00\x00'
where forall <e> in <out_certificate_post_empty>: <e>.<hs_len> == u(blen(<e>) - 4, 3)

<req_certificate_post> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_post> <out_padding>
where forall <e> in <req_certificate_post>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_post> ::= <hs_certificate> <hs_len> <cert_ctx_out> <cert_list_out>
where forall <e> in <out_certificate_post>: <e>.<hs_len> == u(blen(<e>) - 4, 3)

<req_certificate_verify_post> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_verify_post> <out_padding>
where forall <e> in <req_certificate_verify_post>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_certificate_verify_post> ::= <hs_certificate_verify> <hs_len> <cv_scheme_out_post> <cv_sig_len_out_post> <cv_signature_out_post>
where forall <e> in <out_certificate_verify_post>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<cv_scheme_out_post> ::= <signature_scheme> := client_cv_scheme()
<cv_sig_len_out_post> ::= <byte>{2}
<cv_signature_out_post> ::= rb'[\x00-\xff]+'
where forall <m> in <out_certificate_verify_post>: <m>.<cv_signature_out_post> == client_cv_signature(rb(<m>.<cv_scheme_out_post>), True)
where forall <m> in <out_certificate_verify_post>: <m>.<cv_sig_len_out_post> == u(blen(<m>.<cv_signature_out_post>), 2)

# Finished of a post-handshake authentication: the MAC over the handshake context with the client application traffic secret
<req_finished_post> ::= <ct_handshake> <rec_version> <rec_len> <out_finished_post> <out_padding>
where forall <e> in <req_finished_post>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding>), 2)
<out_finished_post> ::= <hs_finished> <hs_len> <verify_data_post>
where forall <e> in <out_finished_post>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<verify_data_post> ::= <byte>+
where forall <f> in <out_finished_post>: <f>.<verify_data_post> == client_post_finished_data()
<req_finished_post_after_empty> ::= <req_finished_post>
<req_finished_post_after_certificate> ::= <req_finished_post>

# ---- a ClientHello that nothing the server supports overlaps with (RFC 9846 section 4.2.1) ----------------------------------
# the supported_groups hold only values of the private use ranges and no key_share is sent, or the cipher suites hold only
# values this client does not define: the server must abort with handshake_failure or insufficient_security
<req_client_hello_no_overlap> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_no_overlap>
where forall <e> in <req_client_hello_no_overlap>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_no_overlap> ::= <hs_client_hello> <hs_len> <client_hello_body_no_overlap>
where forall <e> in <out_client_hello_no_overlap>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_no_overlap> ::= (
      <version_0303> <random_bytes> <session_id> <cipher_suites_vec_13_only> <compression_methods> <ch_extensions_vec_no_overlap>
    | <version_0303> <random_bytes> <session_id> <cipher_suites_vec_unknown> <compression_methods> <ch_extensions_vec_no_overlap_b>
    | <version_0303> <random_bytes> <session_id> <cipher_suites_vec_13_only> <compression_methods> <ch_extensions_vec_no_overlap_c> )
<ch_extensions_vec_no_overlap> ::= <vec_len16> <ch_ext_list_no_overlap>
where forall <e> in <ch_extensions_vec_no_overlap>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_no_overlap> ::= <ext_sni>? <ext_signature_algorithms> <ext_supported_versions_13_only> <ext_supported_groups_private> <ext_key_share_empty>
# no common cipher suite: the suites are reserved values only
<cipher_suites_vec_unknown> ::= <vec_len16> <cipher_suite_unknown>{1,3}
where forall <e> in <cipher_suites_vec_unknown>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_extensions_vec_no_overlap_b> ::= <vec_len16> <ch_ext_list_no_overlap_b>
where forall <e> in <ch_extensions_vec_no_overlap_b>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_no_overlap_b> ::= <ext_sni>? <ext_signature_algorithms> <ext_supported_versions_13_only> <ch_groups_and_shares>
# no common signature algorithm: private use schemes only
<ch_extensions_vec_no_overlap_c> ::= <vec_len16> <ch_ext_list_no_overlap_c>
where forall <e> in <ch_extensions_vec_no_overlap_c>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_no_overlap_c> ::= <ext_sni>? <ext_signature_algorithms_private> <ext_supported_versions_13_only> <ch_groups_and_shares>
<ext_signature_algorithms_private> ::= <ext_type_signature_algorithms> <ext_len> <signature_scheme_list_vec_private>
where forall <e> in <ext_signature_algorithms_private>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<signature_scheme_list_vec_private> ::= <vec_len16> <ss_private_use>{1,3}
where forall <e> in <signature_scheme_list_vec_private>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_versions_13_only> ::= <ext_type_supported_versions> b'\x00\x03' b'\x02' <version_0304>
<ext_supported_groups_private> ::= <ext_type_supported_groups> <ext_len> <named_group_list_vec_private>
where forall <e> in <ext_supported_groups_private>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<named_group_list_vec_private> ::= <vec_len16> (<ng_ffdhe_private_use> | <ng_ecdhe_private_use> | <ng_ffdhe_private_use> <ng_ecdhe_private_use>)
where forall <e> in <named_group_list_vec_private>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)

# after the server's close_notify the client may still send data and then closes with its own close_notify (RFC 9846 section 6.1)
<req_app_data_13_half> ::= <req_app_data_13>
<req_alert_close_notify_half> ::= <req_alert_close_notify_13>

# a ClientHello that offers only psk_ke with a pre_shared_key and leaves out supported_groups, key_share and
# signature_algorithms (RFC 9846 section 9.2): no server can resume the unknown identity, and without a key_share
# it cannot run a full handshake either
<req_client_hello_psk_only> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_psk_only>
where forall <e> in <req_client_hello_psk_only>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_psk_only> ::= <hs_client_hello> <hs_len> <client_hello_body_psk_only>
where forall <e> in <out_client_hello_psk_only>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_psk_only> ::= <version_0303> <random_bytes> <session_id> <cipher_suites_vec_13_only> <compression_methods> <ch_extensions_vec_psk_only>
<ch_extensions_vec_psk_only> ::= <vec_len16> <ch_ext_list_psk_only>
where forall <e> in <ch_extensions_vec_psk_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_psk_only> ::= <ext_sni>? <ext_supported_versions_13_only> <ext_psk_modes_ke> <ext_pre_shared_key>
<ext_psk_modes_ke> ::= <ext_type_psk_key_exchange_modes> <ext_len> <psk_modes_vec_ke>
where forall <e> in <ext_psk_modes_ke>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<psk_modes_vec_ke> ::= <vec_len8> <psk_ke>
where forall <e> in <psk_modes_vec_ke>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)


# ---- a ClientHello of a client that implements TLS 1.3 only (RFC 9846 sections 4.2.1, 4.3.1, 4.3.3) -------------------------
# only TLS 1.3 suites and a supported_versions list without TLS 1.2; RFC 9846 section 4.3.3 lets the legacy SHA-1 schemes
# appear in signature_algorithms for backward compatibility, as the lowest priority (RFC 9155 binds TLS 1.2 clients only)
<req_client_hello_13_only> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_13_only>
where forall <e> in <req_client_hello_13_only>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_13_only> ::= <hs_client_hello> <hs_len> <client_hello_body_13_only>
where forall <e> in <out_client_hello_13_only>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_13_only> ::= <version_0303> <random_bytes> <session_id> <cipher_suites_vec_13_only> <compression_methods> <ch_extensions_vec_13_only>
<cipher_suites_vec_13_only> ::= <vec_len16> <cipher_suite_unknown>? <cipher_suites_13_part>
where forall <e> in <cipher_suites_vec_13_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_extensions_vec_13_only> ::= <vec_len16> <ch_ext_list_13_only>
where forall <e> in <ch_extensions_vec_13_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_13_only> ::= <ext_sni>? <ext_max_fragment_length>? <ext_status_request>? <ext_signature_algorithms_13_only> <ext_signature_algorithms_cert>? <ext_alpn>? <ext_supported_versions_13_only_list> <ch_groups_and_shares> <ext_post_handshake_auth>? <ext_certificate_authorities>? <ext_unknown>? <ch_psk_part>?
<ext_signature_algorithms_13_only> ::= <ext_type_signature_algorithms> <ext_len> <signature_scheme_list_vec_13_only>
where forall <e> in <ext_signature_algorithms_13_only>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<signature_scheme_list_vec_13_only> ::= <vec_len16> <signature_scheme_list> <signature_scheme_legacy>{0,2}
where forall <e> in <signature_scheme_list_vec_13_only>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_versions_13_only_list> ::= <ext_type_supported_versions> <ext_len> <versions_vec_13_only>
where forall <e> in <ext_supported_versions_13_only_list>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<versions_vec_13_only> ::= <vec_len8> <versions_list_13_only>
where forall <e> in <versions_vec_13_only>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)
<versions_list_13_only> ::= <version_0304> | <version_grease> <version_0304> | <version_0304> <version_grease> | <version_grease> <version_grease_b> <version_0304>


# ==================================================================================================================
# Received messages (plaintext view, one handshake message per record).  The end of every message is decided by the
# grammar: a vector's length drives a computed repetition, and what the vector holds is parsed from those bytes by a
# converter pair (the same data as raw bytes and as the parsed list).
# ==================================================================================================================
<octet> ::= rb'[\x00-\xff]'
<octet16> ::= <octet>{16}
<octet256> ::= <octet16>{16}
<in_closed> ::= b'\xff\xffCLOSED'
# what the party appends to every plaintext record it hands over: the end of the TLSPlaintext record
<record_end> ::= b'\xff\xfe'
# TLSPlaintext.legacy_record_version is ignored by the receiver (RFC 9846 section 5.1): any two bytes
<rec_version_in> ::= <octet>{2}
# a SignatureScheme as a received list names it: any registered value (the receiver ignores the ones it does not know)
<signature_scheme_in> ::= <octet>{2}
<rec_len_in> ::= <octet>{2}
<hs_len_in> ::= <octet>{3}
<ext_len_in> ::= <octet>{2}
<ext_vec_len_in> ::= <octet>{2}

# change_cipher_spec (RFC 9846 appendix D.4)
<in_ccs> ::= <ct_change_cipher_spec> <rec_version_in> b'\x00\x01' b'\x01' <record_end>

# ---- ServerHello (RFC 9846 section 4.2.3) -------------------------------------------------------------------------
<in_server_hello_13> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_sh13_msg> <record_end>
where forall <e> in <in_server_hello_13>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_server_hello_13_after_hrr> ::= <in_server_hello_13>
<in_sh13_msg> ::= <hs_server_hello> <hs_len_in> <version_0303> <random_not_hrr> <session_id_in> <cipher_suite_tls13> <compression_null> <in_sh_ext_vec>
where forall <e> in <in_sh13_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_sh13_msg>: server_hello_ok(<m>)
# legacy_session_id_echo<0..32>: the length selects the alternative
<session_id_in> ::= (b'\x00' | b'\x01' <octet>{1} | b'\x02' <octet>{2} | b'\x03' <octet>{3} | b'\x04' <octet>{4} | b'\x05' <octet>{5} | b'\x06' <octet>{6} | b'\x07' <octet>{7} | b'\x08' <octet>{8} | b'\x09' <octet>{9} | b'\x0a' <octet>{10} | b'\x0b' <octet>{11} | b'\x0c' <octet>{12} | b'\x0d' <octet>{13} | b'\x0e' <octet>{14} | b'\x0f' <octet>{15} | b'\x10' <octet>{16} | b'\x11' <octet>{17} | b'\x12' <octet>{18} | b'\x13' <octet>{19} | b'\x14' <octet>{20} | b'\x15' <octet>{21} | b'\x16' <octet>{22} | b'\x17' <octet>{23} | b'\x18' <octet>{24} | b'\x19' <octet>{25} | b'\x1a' <octet>{26} | b'\x1b' <octet>{27} | b'\x1c' <octet>{28} | b'\x1d' <octet>{29} | b'\x1e' <octet>{30} | b'\x1f' <octet>{31} | b'\x20' <octet>{32})
<random_not_hrr> ::= rb'(?!\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c)[\x00-\xff]{32}'
<random_hrr> ::= b'\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c'
<in_sh_ext_vec> ::= <ext_vec_len_in> <in_sh_extension>*
where forall <e> in <in_sh_ext_vec>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)
<in_sh_extension> ::= <in_ext_supported_versions_sh> | <in_ext_key_share_sh> | <in_ext_psk_sh>
<in_ext_supported_versions_sh> ::= <ext_type_supported_versions> b'\x00\x02' <version_0304>
<in_ext_key_share_sh> ::= <ext_type_key_share> <ext_len_in> <named_group> <key_exchange_len_in> <key_exchange_in>
where forall <e> in <in_ext_key_share_sh>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
<key_exchange_len_in> ::= <octet>{2}
<key_exchange_in> ::= <octet256>{uv(<key_exchange_len_in>) // 256} <octet16>{(uv(<key_exchange_len_in>) % 256) // 16} <octet>{uv(<key_exchange_len_in>) % 16}
<in_ext_psk_sh> ::= <ext_type_pre_shared_key> b'\x00\x02' <octet>{2}

# ---- HelloRetryRequest (RFC 9846 section 4.2.4): a ServerHello with the special random ----------------------------------
<in_hello_retry_request> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_hrr_msg> <record_end>
where forall <e> in <in_hello_retry_request>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_hrr_msg> ::= <hs_server_hello> <hs_len_in> <version_0303> <random_hrr> <session_id_in> <cipher_suite_tls13> <compression_null> <in_hrr_ext_vec>
where forall <e> in <in_hrr_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_hrr_msg>: hello_retry_request_ok(<m>)
<in_hrr_ext_vec> ::= <ext_vec_len_in> <in_hrr_extension>*
where forall <e> in <in_hrr_ext_vec>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)
<in_hrr_extension> ::= <in_ext_supported_versions_sh> | <in_ext_key_share_hrr>
<in_ext_key_share_hrr> ::= <ext_type_key_share> b'\x00\x02' <named_group>
<in_ext_cookie> ::= <ext_type_cookie> <ext_len_in> <cookie_len_in> <octet>{uv(<cookie_len_in>)}
where forall <e> in <in_ext_cookie>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
<cookie_len_in> ::= <octet>{2}

# a HelloRetryRequest with a cookie (RFC 9846 section 4.2.2): the client copies the cookie, so this is a reply class of its own
<in_hello_retry_request_cookie> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_hrr_msg_cookie> <record_end>
where forall <e> in <in_hello_retry_request_cookie>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_hrr_msg_cookie> ::= <hs_server_hello> <hs_len_in> <version_0303> <random_hrr> <session_id_in> <cipher_suite_tls13> <compression_null> <in_hrr_ext_vec_cookie>
where forall <e> in <in_hrr_msg_cookie>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_hrr_msg_cookie>: hello_retry_request_ok(<m>)
<in_hrr_ext_vec_cookie> ::= <ext_vec_len_in> <in_hrr_ext_list_cookie>
where forall <e> in <in_hrr_ext_vec_cookie>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)
<in_hrr_ext_list_cookie> ::= (<in_ext_supported_versions_sh> <in_ext_key_share_hrr> <in_ext_cookie> | <in_ext_supported_versions_sh> <in_ext_cookie> <in_ext_key_share_hrr> | <in_ext_key_share_hrr> <in_ext_supported_versions_sh> <in_ext_cookie> | <in_ext_key_share_hrr> <in_ext_cookie> <in_ext_supported_versions_sh> | <in_ext_cookie> <in_ext_supported_versions_sh> <in_ext_key_share_hrr> | <in_ext_cookie> <in_ext_key_share_hrr> <in_ext_supported_versions_sh>)

# a HelloRetryRequest with a cookie and no key_share: the second ClientHello must then repeat the first one's key_share
# unchanged (section 4.2.2), which a ClientHello built for the group of a key_share cannot do: the client answers it with an alert
<in_hello_retry_request_cookie_only> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_hrr_msg_cookie_only> <record_end>
where forall <e> in <in_hello_retry_request_cookie_only>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_hrr_msg_cookie_only> ::= <hs_server_hello> <hs_len_in> <version_0303> <random_hrr> <session_id_in> <cipher_suite_tls13> <compression_null> <in_hrr_ext_vec_cookie_only>
where forall <e> in <in_hrr_msg_cookie_only>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_hrr_msg_cookie_only>: hello_retry_request_ok(<m>)
<in_hrr_ext_vec_cookie_only> ::= <ext_vec_len_in> (<in_ext_supported_versions_sh> <in_ext_cookie> | <in_ext_cookie> <in_ext_supported_versions_sh>)
where forall <e> in <in_hrr_ext_vec_cookie_only>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)

# ---- EncryptedExtensions (RFC 9846 section 4.3.1) ------------------------------------------------------------------
<in_encrypted_extensions> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_ee_msg> <record_end>
where forall <e> in <in_encrypted_extensions>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_ee_msg> ::= <hs_encrypted_extensions> <hs_len_in> <in_ee_ext_vec>
where forall <e> in <in_ee_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_ee_msg>: encrypted_extensions_ok(<m>)
<in_ee_ext_vec> ::= <ext_vec_len_in> <in_ee_extension>*
where forall <e> in <in_ee_ext_vec>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)
<in_ee_extension> ::= <in_ext_sni_empty> | <in_ext_max_fragment_length> | <in_ext_supported_groups_ee> | <in_ext_alpn_ee> | <in_ext_early_data_empty> | <in_ext_other>
<in_ext_sni_empty> ::= <ext_type_server_name> b'\x00\x00'
<in_ext_max_fragment_length> ::= <ext_type_max_fragment_length> b'\x00\x01' <max_fragment_length_code>
<in_ext_supported_groups_ee> ::= <ext_type_supported_groups> <ext_len_in> <list_len_in> <named_group>{uv(<list_len_in>)//2}
where forall <e> in <in_ext_supported_groups_ee>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
<list_len_in> ::= <octet>{2}
<in_ext_alpn_ee> ::= <ext_type_alpn> <ext_len_in> <list_len_in> <protocol_name>
where forall <e> in <in_ext_alpn_ee>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
where forall <e> in <in_ext_alpn_ee>: <e>.<list_len_in> == u(blen(<e>) - 6, 2)
# ProtocolName (RFC 7301 section 3.1: opaque<1..2^8-1>), the rule the sent <protocol_name_list> uses too
<protocol_name> ::= <protocol_name_len> <protocol_name_octets>
<protocol_name_len> ::= rb'[\x01-\xff]' := alpn_name_length_value()
<protocol_name_octets> ::= <octet>{uv(<protocol_name_len>)}
<in_ext_early_data_empty> ::= <ext_type_early_data> b'\x00\x00'
# an extension this grammar does not define (RFC 9846 section 4.2: a client rejects what it did not offer; the ones
# the specification defines for other messages are excluded)
<in_ext_other> ::= <ext_type_other> <ext_len_in> <octet>{uv(<ext_len_in>)}
where forall <e> in <in_ext_other>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
<ext_type_other> ::= rb'(?!\xff\xfe|\x00[\x02\x03\x04\x11\x2f\x30\x32\x05\x0d\x00\x01\x0a\x0d\x10\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x29\x05])[\x00-\xff]{2}'

# ---- Certificate (RFC 9846 section 4.4.2) ----------------------------------------------------------------------------
<in_certificate_13> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_certificate_msg> <record_end>
where forall <e> in <in_certificate_13>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_certificate_msg> ::= <hs_certificate> <hs_len_in> b'\x00' <in_cert_list_vec>
where forall <e> in <in_certificate_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_certificate_msg>: certificate_13_ok(<m>)
where forall <m> in <in_certificate_msg>: certificate_chain_ok(<m>, True)
<in_cert_list_vec> ::= <cert_list_len_in> <in_cert_entry>*
where forall <e> in <in_cert_list_vec>: <e>.<cert_list_len_in> == u(blen(<e>) - 3, 3)
<cert_list_len_in> ::= <octet>{3}
<in_cert_entry> ::= <cert_data_len_in> <cert_data_in> <in_cert_ext_vec>
# the first length byte is not 0xff, which keeps the length of a following entry apart from the end of the record
<cert_data_len_in> ::= rb'[\x00-\xfe][\x00-\xff]{2}'
<cert_data_in> ::= <octet256>{uv(<cert_data_len_in>) // 256} <octet16>{(uv(<cert_data_len_in>) % 256) // 16} <octet>{uv(<cert_data_len_in>) % 16}
# the extensions of a certificate entry (RFC 9846 section 4.4.2: any number, in any order, e.g. status_request, RFC 6066
# section 8): the vector's length drives the bytes, certificate_13_ok parses them (types, lengths, CertificateStatus)
<in_cert_ext_vec> ::= <ext_vec_len_in_nf> <in_cert_ext_block>
<in_cert_ext_block> ::= <octet256>{uv(<ext_vec_len_in_nf>) // 256} <octet16>{(uv(<ext_vec_len_in_nf>) % 256) // 16} <octet>{uv(<ext_vec_len_in_nf>) % 16}
<status_type_ocsp> ::= b'\x01'
<ocsp_len_in> ::= <octet>{3}
<ocsp_response_in> ::= <octet256>{uv(<ocsp_len_in>) // 256} <octet16>{(uv(<ocsp_len_in>) % 256) // 16} <octet>{uv(<ocsp_len_in>) % 16}

# ---- CertificateRequest (RFC 9846 section 4.3.2): in the main handshake its context is zero length ------------------
<in_certificate_request_13> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr_msg> <record_end>
where forall <e> in <in_certificate_request_13>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr_msg> ::= <hs_certificate_request> <hs_len_in> b'\x00' <in_cr_ext_vec>
where forall <e> in <in_cr_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr_msg>: certificate_request_13_ok(<m>)
where forall <m> in <in_cr_msg>: request_usable_13(<m>)
# TOLERANCE wolfssl_deprecated_signature_pairs: a CertificateRequest whose signature_algorithms list holds a pair RFC 9846 section
# 4.3.3 forbids (MD5, SHA-224, DSA).  wolfSSL sends rsa_sha224 in every TLS 1.3 CertificateRequest, which would end every session
# of the server at its server flight; the rule matches only such a message and only where the setting TOLERATED names the tolerance
<in_certificate_request_13_deprecated> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr_msg_deprecated> <record_end>
where forall <e> in <in_certificate_request_13_deprecated>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr_msg_deprecated> ::= <hs_certificate_request> <hs_len_in> b'\x00' <in_cr_ext_vec>
where forall <e> in <in_cr_msg_deprecated>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr_msg_deprecated>: tolerated("wolfssl_deprecated_signature_pairs")
where forall <m> in <in_cr_msg_deprecated>: certificate_request_13_ok(<m>, True)
where forall <m> in <in_cr_msg_deprecated>: request_usable_13(<m>)
# the same requests when no certificate of the party fits their lists (request_usable_13 is false): the client answers with the empty
# Certificate only (RFC 9846 sections 4.4.2, 4.4.3: a certificate and its CertificateVerify scheme must fit the request's lists)
<in_certificate_request_13_nu> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr_msg_nu> <record_end>
where forall <e> in <in_certificate_request_13_nu>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr_msg_nu> ::= <hs_certificate_request> <hs_len_in> b'\x00' <in_cr_ext_vec>
where forall <e> in <in_cr_msg_nu>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr_msg_nu>: certificate_request_13_ok(<m>)
where forall <m> in <in_cr_msg_nu>: not request_usable_13(<m>)
<in_certificate_request_13_deprecated_nu> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr_msg_deprecated_nu> <record_end>
where forall <e> in <in_certificate_request_13_deprecated_nu>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr_msg_deprecated_nu> ::= <hs_certificate_request> <hs_len_in> b'\x00' <in_cr_ext_vec>
where forall <e> in <in_cr_msg_deprecated_nu>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr_msg_deprecated_nu>: tolerated("wolfssl_deprecated_signature_pairs")
where forall <m> in <in_cr_msg_deprecated_nu>: certificate_request_13_ok(<m>, True)
where forall <m> in <in_cr_msg_deprecated_nu>: not request_usable_13(<m>)
<in_cr_ext_vec> ::= <ext_vec_len_in> <in_cr_extension>*
where forall <e> in <in_cr_ext_vec>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)
<in_cr_extension> ::= <in_ext_signature_algorithms_cr> | <in_ext_certificate_authorities> | <in_ext_oid_filters> | <in_ext_signature_algorithms_cert_cr> | <in_ext_status_request_cr> | <in_ext_other>
<in_ext_signature_algorithms_cr> ::= <ext_type_signature_algorithms> <ext_len_in> <list_len_in> <signature_scheme_in>{uv(<list_len_in>)//2}
where forall <e> in <in_ext_signature_algorithms_cr>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
<in_ext_signature_algorithms_cert_cr> ::= <ext_type_signature_algorithms_cert> <ext_len_in> <list_len_in> <signature_scheme_in>{uv(<list_len_in>)//2}
where forall <e> in <in_ext_signature_algorithms_cert_cr>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
# the DistinguishedName list (X.501 DER, RFC 5280) is carried as opaque data: what it says does not change what the client sends next
<in_ext_certificate_authorities> ::= <ext_type_certificate_authorities> <ext_len_in> <octet256>{uv(<ext_len_in>) // 256} <octet16>{(uv(<ext_len_in>) % 256) // 16} <octet>{uv(<ext_len_in>) % 16}
# oid_filters (RFC 9846 section 4.2.5): OIDFilterExtension { OIDFilter filters<0..2^16-1> }, OIDFilter { opaque certificate_extension_oid<1..2^8-1>;
# opaque certificate_extension_values<0..2^16-1> }; the lengths bound the repetitions (the extension's own length and the filters' length by
# `where`, as in the extension vector above); the values are opaque octets (DER of the extension's value, RFC 5280); that no OID occurs twice and
# that anyExtendedKeyUsage is not requested is checked by oid_filters_ok (certificate_request_13_ok)
<in_ext_oid_filters> ::= <ext_type_oid_filters> <ext_len_in> <filters_len_in> <oid_filter_in>*
where forall <e> in <in_ext_oid_filters>: <e>.<ext_len_in> == u(blen(<e>) - 4, 2)
where forall <e> in <in_ext_oid_filters>: <e>.<filters_len_in> == u(blen(<e>) - 6, 2)
<filters_len_in> ::= <octet>{2}
<oid_filter_in> ::= <oid_len_in> <oid_in> <oid_values_len_in> <oid_values_in>
<oid_len_in> ::= rb'[\x01-\xff]'
<oid_in> ::= <octet>{uv(<oid_len_in>)}
<oid_values_len_in> ::= <octet>{2}
<oid_values_in> ::= <octet256>{uv(<oid_values_len_in>) // 256} <octet16>{(uv(<oid_values_len_in>) % 256) // 16} <octet>{uv(<oid_values_len_in>) % 16}
<in_ext_status_request_cr> ::= <ext_type_status_request> b'\x00\x00'

# post-handshake CertificateRequest (RFC 9846 section 4.6.2): a non-empty certificate_request_context; the server may send
# it only to a client that offered post_handshake_auth (section 4.2.6)
<in_certificate_request_post_hs> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr_post_msg> <record_end>
where forall <e> in <in_certificate_request_post_hs>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr_post_msg> ::= <hs_certificate_request> <hs_len_in> <cr_ctx_len_in> <octet>{uv(<cr_ctx_len_in>)} <in_cr_ext_vec>
where forall <e> in <in_cr_post_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
<cr_ctx_len_in> ::= rb'[\x01-\xff]'
where forall <m> in <in_cr_post_msg>: certificate_request_13_ok(<m>)
where forall <m> in <in_cr_post_msg>: request_usable_13(<m>)
<in_certificate_request_post_hs_nu> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr_post_msg_nu> <record_end>
where forall <e> in <in_certificate_request_post_hs_nu>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr_post_msg_nu> ::= <hs_certificate_request> <hs_len_in> <cr_ctx_len_in> <octet>{uv(<cr_ctx_len_in>)} <in_cr_ext_vec>
where forall <e> in <in_cr_post_msg_nu>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr_post_msg_nu>: certificate_request_13_ok(<m>)
where forall <m> in <in_cr_post_msg_nu>: not request_usable_13(<m>)

# ---- CertificateVerify (RFC 9846 section 4.4.3) ------------------------------------------------------------------------
<in_certificate_verify> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cv_msg> <record_end>
where forall <e> in <in_certificate_verify>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cv_msg> ::= <hs_certificate_verify> <hs_len_in> <signature_scheme_in> <signature_len_in> <signature_in>
where forall <e> in <in_cv_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cv_msg>: certificate_verify_ok(<m>)
<signature_len_in> ::= <octet>{2}
<signature_in> ::= <octet256>{uv(<signature_len_in>) // 256} <octet16>{(uv(<signature_len_in>) % 256) // 16} <octet>{uv(<signature_len_in>) % 16}

# ---- Finished (RFC 9846 section 4.4.4) -----------------------------------------------------------------------------------
<in_finished> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_finished_msg> <record_end>
where forall <e> in <in_finished>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
# verify_data has the length of the handshake hash: SHA-256 (32) or SHA-384 (48)
<in_finished_msg> ::= <hs_finished> (b'\x00\x00\x20' <verify_data_in_32> | b'\x00\x00\x30' <verify_data_in_48>)
<verify_data_in_32> ::= <octet>{32}
<verify_data_in_48> ::= <octet>{48}
where forall <m> in <in_finished_msg>: server_finished_ok(rb(<m>)[4:])

# ---- NewSessionTicket (RFC 9846 section 4.6.1) ----------------------------------------------------------------------------
<in_new_session_ticket> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_nst_msg> <record_end>
where forall <e> in <in_new_session_ticket>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_nst_msg> ::= <hs_new_session_ticket> <hs_len_in> <octet>{4} <octet>{4} <nonce_len_in> <nonce_in> <ticket_len_in> <ticket_in> <in_nst_ext_vec>
where forall <e> in <in_nst_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_nst_msg>: new_session_ticket_ok(<m>)
<nonce_len_in> ::= <octet>
<nonce_in> ::= <octet>{uv(<nonce_len_in>)}
<ticket_len_in> ::= <octet>{2}
<ticket_in> ::= <octet256>{uv(<ticket_len_in>) // 256} <octet16>{(uv(<ticket_len_in>) % 256) // 16} <octet>{uv(<ticket_len_in>) % 16}
<in_nst_ext_vec> ::= <ext_vec_len_in> <in_nst_extension>*
where forall <e> in <in_nst_ext_vec>: <e>.<ext_vec_len_in> == u(blen(<e>) - 2, 2)
<in_nst_extension> ::= <in_ext_early_data_nst> | <in_ext_other>
<in_ext_early_data_nst> ::= <ext_type_early_data> b'\x00\x04' <octet>{4}

# ---- KeyUpdate (RFC 9846 section 4.6.3) -------------------------------------------------------------------------------------
<in_key_update_not_requested> ::= <ct_handshake> <rec_version_in> b'\x00\x05' <hs_key_update> b'\x00\x00\x01' <update_not_requested> <record_end>
# update_requested: the receiver answers with its own KeyUpdate (update_not_requested) before its next application data
<in_key_update_requested> ::= <ct_handshake> <rec_version_in> b'\x00\x05' <hs_key_update> b'\x00\x00\x01' <update_requested> <record_end>

# ---- application data and alerts (RFC 9846 sections 5.1, 6) ---------------------------------------------------------------------
<in_app_data> ::= <ct_application_data> <rec_version_in> <rec_len_in> <app_data_in> <record_end>
where forall <e> in <in_app_data>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<app_data_in> ::= <octet256>{uv(<rec_len_in>) // 256} <octet16>{(uv(<rec_len_in>) % 256) // 16} <octet>{uv(<rec_len_in>) % 16}
# Error alerts MUST be sent with AlertLevel fatal and every alert except close_notify and user_canceled is an error alert, and so
# is an unknown one (RFC 9846 section 6, 6.2): <in_alert> takes any description but only the level fatal; close_notify takes the
# level warning (6.1); user_canceled "generally" has level warning (6.1), so it takes any level; the reserved values 21, 41 and
# 60 (decryption_failed_RESERVED, no_certificate_RESERVED, export_restriction_RESERVED) must not be sent (RFC 9846 appendix B, RFC 5246 7.2.2)
<alert_level_in> ::= <octet>
<in_alert_close_notify> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_warning> <ad_close_notify> <record_end>
<in_alert> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_fatal> <alert_description_error_in> <record_end>
<alert_description_error_in> ::= rb'(?!\x00|\x5a|\x15|\x29|\x3c)[\x00-\xff]'
# user_canceled must be followed by close_notify (RFC 9846 section 6.1): the state rules accept it only with that
<in_alert_user_canceled> ::= <ct_alert> <rec_version_in> b'\x00\x02' <alert_level_in> <ad_user_canceled> <record_end>

# the alert a server answers a ClientHello with when nothing offered overlaps with what it supports (RFC 9846 section 4.2.1)
<in_alert_no_overlap> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_fatal> (<ad_handshake_failure> | <ad_insufficient_security>) <record_end>

# alerts the server answers a misbehaving client with (RFC 9846 sections 4.7.3, 5, 6.2)
<in_alert_unexpected_message> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_fatal> <ad_unexpected_message> <record_end>
<in_alert_illegal_parameter> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_fatal> <ad_illegal_parameter> <record_end>

# RFC 6066 section 4: once the client has sent a record that exceeds the negotiated maximum fragment length (the request <req_app_data_13_overflow> /
# <req_app_data_12_overflow>), the only reaction the specification makes mandatory is the record_overflow alert: every other reply (application data,
# KeyUpdate, NewSessionTicket, a post-handshake CertificateRequest, HelloRequest, close_notify, user_canceled, the silence of a timer) is then a violation
# (no_reaction_pending is false while the reaction is awaited, see TlsState.overflow_pending); an alert must carry record_overflow
where forall <x> in <in_app_data>: no_reaction_pending()
where forall <x> in <in_key_update_not_requested>: no_reaction_pending()
where forall <x> in <in_key_update_requested>: no_reaction_pending()
where forall <x> in <in_new_session_ticket>: no_reaction_pending()
where forall <x> in <in_certificate_request_post_hs>: no_reaction_pending()
where forall <x> in <in_certificate_request_post_hs_nu>: no_reaction_pending()
where forall <x> in <in_hello_request>: no_reaction_pending()
where forall <x> in <in_alert_close_notify>: no_reaction_pending()
where forall <x> in <in_alert_user_canceled>: no_reaction_pending()
where forall <x> in <in_alert>: alert_after_oversize_ok(<x>)
where forall <x> in <in_alert_12_fatal>: alert_after_oversize_ok(<x>)
where forall <x> in <expired_data>: no_reaction_pending()
where forall <x> in <expired_data_12>: no_reaction_pending()


# ==================================================================================================================
# Functions of the constraints
# ==================================================================================================================
def first_finished_index(state, direction):
    for index in range(len(state.transcript)):
        entry = state.transcript[index]
        if entry[0] == direction and entry[1][0] == 20:
            return index
    return None


def client_finished_data():
    state = session_state()
    if state is None or state.version != 0x0304 or "c_hs" not in state.secrets:
        return bytes(32)
    index = first_finished_index(state, "C")
    return state.finished_verify_data("C", index)


def server_finished_ok(value):
    state = session_state()
    if state is None or state.hash_name is None or "s_hs" not in state.secrets:
        return True
    index = first_finished_index(state, "S")
    if index is None:
        return True
    return state.finished_verify_data("S", index) == value


# ---- recalling generators: values a second ClientHello repeats from the first one (RFC 9846 section 4.2.2) --------------
def first_client_hello_fields():
    """The fields of the first ClientHello once a HelloRetryRequest has been seen (what the second ClientHello repeats, RFC 9846 section
    4.2.2); None before."""
    state = session_state()
    if state is None or not state.client_hello_msgs or not state.hrr_seen:
        return None
    return parse_hello(state.client_hello_msgs[0][4:], True)


def clean(make, tries=300):
    """A value of `make()` without the bytes 0x20 and 0x0a (the generators' values stay values, not text)."""
    value = make()
    for _ in range(tries):
        if b" " not in value and b"\n" not in value:
            break
        value = make()
    return value


def random_value():
    fields = first_client_hello_fields()
    return fields[0] if fields else clean(lambda: os.urandom(32))


def session_id_value():
    fields = first_client_hello_fields()
    return fields[1] if fields else clean(lambda: os.urandom(32))


def host_name_value():
    fields = first_client_hello_fields()
    if fields and 0 in fields[3] and len(fields[3][0]) > 5:
        return fields[3][0][5:]
    return random.choice(SERVER_NAMES).encode()


def hrr_group_value():
    """The group the HelloRetryRequest selected, as the NamedGroup encoding."""
    state = session_state()
    if state is not None and state.hrr_group is not None:
        return u(state.hrr_group, 2)
    return u(0x001D, 2)


def hrr_key_exchange_value():
    """A fresh key share of the group the HelloRetryRequest selected."""
    state = session_state()
    group = state.hrr_group if state is not None and state.hrr_group is not None else 0x001D
    if group not in (0x001D, 0x0017, 0x0018):
        group = 0x001D
    return clean(lambda: new_key_share(group))


def der(tag, content):
    """A DER TLV (definite length, short or long form)."""
    n = len(content)
    if n < 128:
        head = bytes([tag, n])
    else:
        size = (n.bit_length() + 7) // 8
        head = bytes([tag, 0x80 | size]) + n.to_bytes(size, "big")
    return head + content


def dn_der_value():
    """A DER-encoded X.501 Name (RFC 5280): 1-4 single-valued RDNs of the attributes C, O, OU, CN, L, ST, DC (X.520 upper
    bounds respected) in the string types UTF8String, PrintableString, IA5String and T61String."""
    def make():
        attributes = [(b"\x55\x04\x06", [0x13]), (b"\x55\x04\x0a", [0x0c, 0x13]), (b"\x55\x04\x0b", [0x0c, 0x13]),
                      (b"\x55\x04\x03", [0x0c, 0x13, 0x14]), (b"\x55\x04\x07", [0x0c, 0x13]), (b"\x55\x04\x08", [0x0c, 0x13]),
                      (b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19", [0x16])]
        rdns = b""
        for _ in range(random.choice([1, 1, 2, 3, 4])):
            oid, types = random.choice(attributes)
            kind = random.choice(types)
            if oid == b"\x55\x04\x06":
                text = bytes(random.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(2))
            else:
                text = random.choice(SERVER_NAMES + ["TestCA", "Example-Root", "Fandango", "Org-Unit"]).encode()
            rdns += der(0x31, der(0x30, der(0x06, oid) + der(kind, text)))
        return der(0x30, rdns)
    return clean(make, 400)


def responder_id_der_value():
    """A DER ResponderID (RFC 6960): byKey [2] KeyHash, or byName [1] Name."""
    if random.random() < 0.5:
        return clean(lambda: der(0xa2, der(0x04, os.urandom(20))))
    return clean(lambda: der(0xa1, dn_der_value()), 400)


# ==================================================================================================================
# Checks on received messages against what the client offered (the mandatory requirements of the server)
# ==================================================================================================================
def offered_hello():
    """(random, session_id, cipher suites, [(type, data)] of the extensions) of the latest ClientHello, or None."""
    state = session_state()
    if state is None or not state.client_hello_msgs:
        return None
    body = state.client_hello_msgs[-1][4:]
    fields = parse_hello(body, True)
    if fields is None:
        return None
    return fields[0], fields[1], fields[2], extension_list(hello_extension_block(body, True)) or []


def types_of(extensions):
    return [ext_type for ext_type, _ in extensions]


def state_sh_types():
    state = session_state()
    return state.sh_ext_types if state is not None else []


def key_exchange_valid(share):
    """The key_exchange of a server's key_share: the length of the group's encoding, a valid point for the curves."""
    group, length = int.from_bytes(share[:2], "big"), int.from_bytes(share[2:4], "big")
    value = share[4:4 + length]
    sizes = {0x001D: 32, 0x001E: 56, 0x0017: 65, 0x0018: 97, 0x0019: 133,
             0x0100: 256, 0x0101: 384, 0x0102: 512, 0x0103: 768, 0x0104: 1024}
    if group in sizes and length != sizes[group]:
        return False
    if group in (0x001D, 0x001E) and not any(value):
        return False                                         # the all-zero value gives an all-zero secret (section 7.4.2)
    if group in CURVES:
        from cryptography.hazmat.primitives.asymmetric import ec
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(CURVES[group](), value)
        except Exception:
            return False
    return True


def shared_secret_ok(state, share):
    """RFC 9846 section 7.4.2: the shared secret of an x25519/x448 key_share must not be all zero (nor the exchange invalid)."""
    group = int.from_bytes(share[:2], "big")
    peer = share[4:4 + int.from_bytes(share[2:4], "big")]
    if group not in NAMED_GROUPS:
        return True
    entry = state.find_private(group)
    if entry is None:
        return True
    try:
        return any(shared_secret(group, entry, peer))
    except Exception:
        return False


def server_hello_ok(tree):
    """RFC 9846 section 4.2.3 and 4.3: the checks on a TLS 1.3 ServerHello (also the one after a HelloRetryRequest)."""
    message = tree.to_bytes()
    parsed = parse_hello(message[4:], False)
    block = extension_list(hello_extension_block(message[4:], False))
    if parsed is None or block is None:
        return False
    random_value_, session_id, suite, _ = parsed
    types = types_of(block)
    if len(types) != len(set(types)):                       # no extension twice (section 4.3)
        return False
    if 43 not in types or dict(block)[43] != b"\x03\x04":      # supported_versions with TLS 1.3 (section 4.3.1)
        return False
    offered = offered_hello()
    if offered is None:
        return True
    offered_random, offered_session_id, offered_suites, offered_extensions = offered
    offered_types = types_of(offered_extensions)
    if session_id != offered_session_id:                     # legacy_session_id_echo (section 4.2.3)
        return False
    if suite not in offered_suites or random_value_ == offered_random:
        return False
    if any(t not in offered_types for t in types):           # only extensions the client offered (section 4.3)
        return False
    if 43 in offered_types and 0x0304 not in offered_list(dict(offered_extensions)[43], 1):
        return False                                         # selected_version among the offered versions
    if 41 in types:                                          # the offered PSKs are not valid: none can be selected
        return False                                         # (the binder of an unknown identity cannot verify, 4.3.11)
    if 51 not in types:                                      # without a PSK the key exchange needs a key_share
        return False
    if 51 in types and not key_exchange_valid(dict(block)[51]):
        return False                                         # the key_exchange of the group's encoding (4.3.8.1, 4.3.8.2)
    state = session_state()
    if state is not None and 51 in types and not shared_secret_ok(state, dict(block)[51]):
        return False                                         # an all-zero shared secret is rejected (section 7.4.2)
    if state is not None and state.hrr_seen:                 # after a HelloRetryRequest: same suite and group
        if suite != state.hrr_suite:
            return False
        if 51 in types and state.hrr_group is not None and int.from_bytes(dict(block)[51][:2], "big") != state.hrr_group:
            return False
    elif 51 in types and 51 in offered_types:                # the server's group is one the client sent a share for
        group = int.from_bytes(dict(block)[51][:2], "big")
        shares, data, offset = [], dict(offered_extensions)[51], 2
        while offset + 4 <= len(data):
            shares.append(int.from_bytes(data[offset:offset + 2], "big"))
            offset += 4 + int.from_bytes(data[offset + 2:offset + 4], "big")
        if group not in shares:
            return False
    return True


def hello_retry_request_ok(tree):
    """RFC 9846 section 4.2.4: the extensions of a HelloRetryRequest."""
    message = tree.to_bytes()
    parsed = parse_hello(message[4:], False)
    block = extension_list(hello_extension_block(message[4:], False))
    if parsed is None or block is None:
        return False
    types = types_of(block)
    if len(types) != len(set(types)) or 43 not in types or dict(block)[43] != b"\x03\x04":
        return False
    if 51 not in types and 44 not in types:                  # a HelloRetryRequest must change the ClientHello (4.2.4)
        return False
    state = session_state()
    if state is not None and state.hrr_seen and len(state.transcript) > 2:
        return False                                         # a second HelloRetryRequest is an error (4.2.4)
    offered = offered_hello()
    if offered is None:
        return True
    _, offered_session_id, offered_suites, offered_extensions = offered
    offered_types = types_of(offered_extensions)
    if parsed[1] != offered_session_id:                      # legacy_session_id_echo, as for a ServerHello (section 4.2.4)
        return False
    if parsed[2] not in offered_suites or any(t not in offered_types and t != 44 for t in types):
        return False
    if 51 in types:                                          # selected_group: offered in supported_groups, no share sent
        group = int.from_bytes(dict(block)[51][:2], "big")
        if 10 in offered_types and group not in offered_list(dict(offered_extensions)[10]):
            return False
        data, offset = dict(offered_extensions).get(51, b"\x00\x00"), 2
        while offset + 4 <= len(data):
            if int.from_bytes(data[offset:offset + 2], "big") == group:
                return False
            offset += 4 + int.from_bytes(data[offset + 2:offset + 4], "big")
    return True


def encrypted_extensions_ok(tree):
    """RFC 9846 sections 4.3.1, 4.4.1 and RFC 7301, RFC 6066: the extensions of an EncryptedExtensions message."""
    message = tree.to_bytes()
    block = extension_list(message[6:])
    if block is None:
        return False
    types = types_of(block)
    if len(types) != len(set(types)):
        return False
    if not all(ext_allowed("EE", t) for t in types):         # Table 1: an extension in a message it is not listed for
        return False
    offered = offered_hello()
    if offered is None:
        return True
    _, session_id, _, offered_extensions = offered
    offered_by_type = dict(offered_extensions)
    for ext_type, data in block:
        if ext_type == 10:                                   # the server may send supported_groups unsolicited
            groups = offered_list(data)                      # without duplicates (section 4.2.7)
            if len(groups) != len(set(groups)):
                return False
            continue
        if ext_type not in offered_by_type:
            return False
        if ext_type == 16:                                   # ALPN: the selected protocol is one the client offered
            names, offered_data, offset = [], offered_by_type[16], 2
            while offset < len(offered_data):
                names.append(offered_data[offset + 1:offset + 1 + offered_data[offset]])
                offset += 1 + offered_data[offset]
            if data[3:3 + data[2]] not in names:
                return False
        if ext_type == 1 and data != offered_by_type[1]:     # max_fragment_length: the value the client asked for
            return False
    state = session_state()
    if 42 in types and 41 not in state_sh_types():           # early_data is accepted only with a selected PSK
        return False
    if state is not None and session_id and state.ccs_received == 0:
        return False                                         # compatibility mode: the server sent a change_cipher_spec
    if state is not None and session_id and state.hrr_seen and state.ccs_after_hrr_count() == 0:
        return False                                         # ... right after its first handshake message, the HelloRetryRequest
    return True


def hrr_ccs_ok(tree):
    """RFC 9846 appendix E.4: a server answers a ClientHello with a non-empty legacy_session_id with a change_cipher_spec
    immediately after its first handshake message, which may be a HelloRetryRequest."""
    state = session_state()
    if state is None or not state.hrr_seen:
        return True
    first = first_client_hello_fields()
    if first is None or not first[1]:
        return True
    return state.ccs_after_hrr_count() >= 1


def ccs_compat_ok(tree):
    """RFC 9846 appendix D.4 (middlebox compatibility mode): when the ClientHello's legacy_session_id is non-empty, a TLS 1.3 server
    sends a change_cipher_spec right after its first handshake message (a HelloRetryRequest or the ServerHello); checked whenever the
    server ends the session after that message."""
    state = session_state()
    if state is None or state.version != 0x0304:
        return True
    first = first_client_hello_fields()
    if first is None or not first[1]:
        return True
    if state.ccs_received == 0:
        return False
    return not state.hrr_seen or state.ccs_after_hrr_count() >= 1


def certificate_13_ok(tree):
    """RFC 9846 sections 4.4.2, 4.2, 4.4.2.1: at least one entry; the entry extensions answer extensions of the ClientHello."""
    entries = certificate_entries(tree.to_bytes()[4:], True)
    if not entries:
        return False
    offered = offered_hello()
    by_type = dict(offered[3]) if offered is not None else None
    for _, extensions in entries:
        types = types_of(extensions)
        if len(types) != len(set(types)):                    # no extension twice (section 4.2)
            return False
        for ext_type, data in extensions:
            if not ext_allowed("CT", ext_type):              # Table 1
                return False
            if by_type is not None and ext_type not in by_type:
                return False                                 # only extensions the ClientHello requested (section 4.2)
            if ext_type == 5:                                # CertificateStatus (RFC 6066 section 8, RFC 9846 section 4.4.2.1)
                if len(data) < 5 or data[0] != 1 or int.from_bytes(data[1:4], "big") != len(data) - 4 or len(data) == 4:
                    return False
    return True


def deprecated_pair(value):
    """A TLS 1.2 hash/signature pair with MD5 or SHA-224, or with DSA (RFC 9846 section 4.3.3: MUST NOT be offered)."""
    hi, lo = value >> 8, value & 255
    return (hi in (1, 3) and lo in (1, 2, 3)) or (hi in (2, 4, 5, 6) and lo == 2)


def oid_filters_ok(data):
    """RFC 9846 section 4.2.5: OIDFilter structure, no OID twice, no anyExtendedKeyUsage in an Extended Key Usage request."""
    if len(data) < 2 or int.from_bytes(data[:2], "big") != len(data) - 2:
        return False
    offset, oids = 2, []
    while offset < len(data):
        n = data[offset]
        oid = data[offset + 1:offset + 1 + n]
        offset += 1 + n
        if n == 0 or offset + 2 > len(data):
            return False
        m = int.from_bytes(data[offset:offset + 2], "big")
        values = data[offset + 2:offset + 2 + m]
        offset += 2 + m
        if offset > len(data) or oid in oids:
            return False
        oids.append(oid)
        if oid == b"\x55\x1d\x25" and b"\x55\x1d\x25\x00" in values:
            return False
    return True


def certificate_request_13_ok(tree, deprecated=False):
    """RFC 9846 sections 4.3.2, 4.2.5, 4.6.2: signature_algorithms is present; no duplicates; Table 1; the oid_filters structure;
    a post-handshake CertificateRequest only for a client that offered post_handshake_auth."""
    message = tree.to_bytes()
    context = message[4]
    block = extension_list(message[7 + context:])
    if block is None or 13 not in types_of(block) or len(types_of(block)) != len(set(types_of(block))):
        return False
    listed = False
    for ext_type, data in block:
        if not ext_allowed("CR", ext_type):
            return False
        if ext_type == 48 and not oid_filters_ok(data):
            return False
        if ext_type in (13, 50) and any(deprecated_pair(v) for v in offered_list(data)):
            if not deprecated:
                return False                                 # MD5, SHA-224 and DSA pairs must not be offered (section 4.3.3)
            listed = True
    if deprecated and not listed:                            # the tolerated deviation: such a pair IS listed
        return False
    if context:
        state = session_state()
        if state is not None:                                # the context is unique within the connection (section 4.3.2)
            same = [m for d, m in state.transcript if d == "S" and m[0] == 13 and m[4] == context and m[5:5 + context] == message[5:5 + context]]
            if len(same) > 1:
                return False
        offered = offered_hello()
        if offered is not None and 49 not in types_of(offered[3]):
            return False
    return True


def certificate_verify_ok(tree):
    """RFC 9846 section 4.4.3: the scheme of a server CertificateVerify is one the client offered."""
    message = tree.to_bytes()
    scheme = int.from_bytes(message[4:6], "big")
    if scheme in (0x0201, 0x0203, 0x0401, 0x0501, 0x0601):  # not defined for signed handshake messages (section 4.3.3)
        return False
    state = session_state()                                  # (a scheme outside signature_algorithms is allowed when the server
    return state is None or verify_certificate_verify_13(state, message)   # has no other chain: not visible in the messages)


def offered_hello_versions_include_13(offered_extensions):
    versions = dict(offered_extensions).get(43)
    return versions is not None and 0x0304 in offered_list(versions, 1)


def server_hello_12_ok(tree):
    """RFC 5246 section 7.4.1.3, 7.4.1.4: the server's choices are among the client's offers."""
    message = tree.to_bytes()
    parsed = parse_hello(message[4:], False)
    block = extension_list(hello_extension_block(message[4:], False)) if len(message) > 4 else []
    if parsed is None or block is None:
        return False
    types = types_of(block)
    if len(types) != len(set(types)):
        return False
    offered = offered_hello()
    if offered is None:
        return True
    offered_random, _, offered_suites, offered_extensions = offered
    if parsed[2] not in offered_suites or parsed[0] == offered_random:
        return False
    offered_types = types_of(offered_extensions)
    if 42 in offered_types and offered_hello_versions_include_13(offered_extensions):
        return False                                         # a client that attempts 0-RTT fails on a TLS 1.2 ServerHello (appendix E.3)
    versions = dict(offered_extensions).get(43)
    if versions is not None and 0x0303 not in offered_list(versions, 1):
        return False                                         # only a version of the client's supported_versions (RFC 9846 section 4.3.1)
    if versions is not None and 0x0304 in offered_list(versions, 1) and parsed[0][24:] in (b"DOWNGRD\x01", b"DOWNGRD\x00"):
        return False                                         # downgrade protection (RFC 9846 section 4.2.3)
    offered_types = types_of(offered_extensions)
    if not all(t in offered_types for t in types):           # only extensions the client sent (section 7.4.1.4)
        return False
    offered_by_type, by_type = dict(offered_extensions), dict(block)
    if 1 in by_type and by_type[1] != offered_by_type[1]:    # max_fragment_length: the value requested (RFC 6066 section 4)
        return False
    if 16 in by_type:                                        # ALPN: the selected protocol was offered (RFC 7301 section 3.2)
        names, offered_data, offset = [], offered_by_type[16], 2
        while offset < len(offered_data):
            names.append(offered_data[offset + 1:offset + 1 + offered_data[offset]])
            offset += 1 + offered_data[offset]
        if by_type[16][3:3 + by_type[16][2]] not in names:
            return False
    return True


def new_session_ticket_ok(tree):
    """RFC 9846 section 4.7.1: ticket_lifetime is at most seven days."""
    message = tree.to_bytes()
    if int.from_bytes(message[4:8], "big") > 604800:
        return False
    try:
        offset = 12 + 1 + message[12]
        offset += 2 + int.from_bytes(message[offset:offset + 2], "big")
        block = extension_list(message[offset + 2:])
    except Exception:
        return False
    if block is None or len(types_of(block)) != len(set(types_of(block))) or not all(ext_allowed("NST", t) for t in types_of(block)):
        return False                                         # no extension twice (section 4.2), Table 1
    state = session_state()
    if state is not None:                                    # ticket_age_add is fresh for each ticket (section 4.6.1)
        same = [m for m in state.nst_messages if m[8:12] == message[8:12]]
        if len(same) > 1:
            return False
    return True


def server_key_exchange_ok(tree, anon):
    """RFC 5246 section 7.4.3, RFC 9155: only for DHE_DSS, DHE_RSA and DH_anon (unsigned); signed with a pair the client offered,
    no MD5/SHA-1, a key type that fits the certificate."""
    state = tls12_state()
    if state is None:
        return True
    kx = TLS12_SUITES.get(state.suite, (0, 0, 0, ""))[3]
    if kx not in DH_KINDS or (kx == "dh_anon") != anon:
        return False
    if anon:
        return True
    rest = parse_vectors(tree.to_bytes()[4:], (2, 2, 2))[3]
    scheme = int.from_bytes(rest[:2], "big")
    offered = offered_hello()
    default_pair = offered is not None and 13 not in dict(offered[3])        # no signature_algorithms: RFC 5246 section 7.4.1.4.1 default
    if rest[0] == 1 or (rest[0] == 2 and not default_pair):
        return False
    if offered is not None:
        by_type = dict(offered[3])
        if 13 in by_type and scheme not in offered_list(by_type[13]):
            return False
    state_certificate = state.server_certificate
    if state_certificate is not None:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
        key = x509.load_der_x509_certificate(state_certificate).public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return kx == "dhe" and (rest[1] == 1 or rest[0] == 8)
        if isinstance(key, dsa.DSAPublicKey):
            return kx == "dhe_dss" and rest[1] == 2
        if isinstance(key, ec.EllipticCurvePublicKey):
            return rest[1] == 3
        return False
    return True


def certificate_request_12_ok(tree):
    """No mandatory requirement binds a TLS 1.2 CertificateRequest's pairs (RFC 9155 section 3: SHOULD NOT for MD5 and SHA-1; the
    TLS 1.3 text binds TLS 1.3 implementations, which nothing in this session shows the server to be): every list is accepted."""
    return True


def server_hello_done_ok(tree):
    """RFC 5246 section 7.4.3: a ServerKeyExchange was sent exactly for the key exchanges that use one."""
    state = tls12_state()
    if state is None:
        return True
    return state.ske_seen == (TLS12_SUITES.get(state.suite, (0, 0, 0, ""))[3] in DH_KINDS)


def certificate_status_ok(tree):
    """RFC 6066 section 8: CertificateStatus only after status_request in the ClientHello and the ServerHello."""
    state = tls12_state()
    offered = offered_hello()
    if state is None or offered is None:
        return True
    return 5 in types_of(offered[3]) and 5 in state.sh_ext_types


def hrr_cookie_value():
    state = session_state()
    return state.hrr_cookie if state is not None and state.hrr_cookie else b"\x00"


def cert_pair_code(certificate):
    """The SignatureScheme / hash-signature pair a certificate's signature algorithm corresponds to (None if unknown)."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    oid = certificate.signature_algorithm_oid.dotted_string
    if oid == "1.3.101.112":
        return 0x0807
    if oid == "1.3.101.113":
        return 0x0808
    digest = certificate.signature_hash_algorithm
    hash_id = HASH_IDS.get(type(digest).__name__.lower()) if digest is not None else None
    if hash_id is None:
        return None
    if oid == "1.2.840.113549.1.1.10":                                              # RSASSA-PSS (rsae when the key is rsaEncryption)
        pss = {4: 0x0804, 5: 0x0805, 6: 0x0806}.get(hash_id)
        return pss if certificate.public_key_algorithm_oid.dotted_string == "1.2.840.113549.1.1.1" else (pss + 5 if pss else None)
    if oid.startswith("1.2.840.10045.4"):
        return (hash_id << 8) | 3
    if oid.startswith("1.2.840.10040.4") or oid.startswith("2.16.840.1.101.3.4.3"):
        return (hash_id << 8) | 2
    return (hash_id << 8) | 1


HASH_IDS = {"md5": 1, "sha1": 2, "sha224": 3, "sha256": 4, "sha384": 5, "sha512": 6}


def certificate_chain_ok(tree, tls13):
    """RFC 5246 section 7.4.2, RFC 9846 sections 4.4.2, 4.4.2.2 and RFC 5280: X.509v3, issuer chain, signature algorithms of the
    certificates that are validated (not self-signed ones), the key type and key usage of the end-entity certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    entries = certificate_entries(tree.to_bytes()[4:], tls13)
    if entries is None:
        return False
    try:
        chain = [x509.load_der_x509_certificate(cert) for cert, _ in entries]
    except Exception:
        return False
    if not chain:
        return not tls13
    offered = offered_hello()
    offered_schemes, advertised = [], []
    if offered is not None:
        by_type = dict(offered[3])
        advertised = offered_list(by_type[13]) if 13 in by_type else []
        offered_schemes = offered_list(by_type[50] if 50 in by_type else by_type[13]) if (50 in by_type or 13 in by_type) else []
    for position, certificate in enumerate(chain):
        if certificate.version != x509.Version.v3:                                  # X.509v3 (section 7.4.2)
            return False
        if position + 1 < len(chain) and certificate.issuer != chain[position + 1].subject:
            return False                                                            # each certifies the one before it
        if not tls13:
            code = cert_pair_code(certificate)
            if advertised and code is not None and code not in advertised:          # a pair of the client's signature_algorithms
                return False                                                        # (RFC 5246 section 7.4.2: all certificates)
            continue
        if certificate.issuer == certificate.subject or (position == len(chain) - 1 and position >= 1):
            continue                                                                # self-signed or possible trust anchor: not validated
        digest = certificate.signature_hash_algorithm
        if digest is not None and isinstance(digest, hashes.MD5):
            return False                                                            # MD5 never validates a certificate (section 4.4.2.2)
        if digest is not None and isinstance(digest, hashes.SHA1):
            if not (0x0201 in offered_schemes or 0x0203 in offered_schemes):        # SHA-1 only when advertised
                return False
    if not tls13:
        state = session_state()
        kx = TLS12_SUITES.get(state.suite, (0, 0, 0, ""))[3] if state is not None else ""
        if kx in DH_STATIC_KINDS:                                                   # DH_DSS / DH_RSA: the certificate holds a DH key
            if static_dh_parameters(entries[0][0]) is None:
                return False
        else:
            end_key = chain[0].public_key()
            if kx in ("rsa", "dhe") and not isinstance(end_key, rsa.RSAPublicKey):
                return False                                                        # key of the key exchange (section 7.4.2)
            if kx == "dhe_dss" and not isinstance(end_key, dsa.DSAPublicKey):
                return False
    try:                                                                            # KeyUsage of the end-entity certificate
        usage = chain[0].extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None:
        state = session_state()
        kx = TLS12_SUITES.get(state.suite, (0, 0, 0, ""))[3] if state is not None and not tls13 else "dhe"
        if kx == "rsa" and not usage.key_encipherment:
            return False
        if kx in DH_STATIC_KINDS and not usage.key_agreement:                # RFC 5246 section 7.4.2: DH certificates
            return False
        if kx not in ("rsa", "dh_anon") + DH_STATIC_KINDS and not usage.digital_signature:   # an anonymous exchange does not use the certificate
            return False
    return True


def ocsp_nonce_extensions_der():
    """The DER of Extensions { id-pkix-ocsp-nonce, OCTET STRING { OCTET STRING (16 random bytes) } } (RFC 6960)."""
    nonce = clean(lambda: os.urandom(16))
    value = b"\x04\x12\x04\x10" + nonce
    extension = b"\x06\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x02" + value
    extension = b"\x30" + bytes([len(extension)]) + extension
    return b"\x30" + bytes([len(extension)]) + extension


_ALPN_NAME = {}


def alpn_name_length_value():
    """The length byte of a sent ProtocolName (RFC 7301 section 3.1: opaque<1..2^8-1>): the length of a name of the setting's list or a
    random length; the name of that length (a listed name, or arbitrary octets) is kept for alpn_name_octet."""
    listed = [name.encode() for name in ALPN_PROTOCOLS if 1 <= len(name.encode()) <= 255]
    if listed and random.random() < 0.6:
        name = random.choice(listed)
    else:
        name = bytes(random.choices(range(256), k=random.choice([random.randint(1, 12), random.randint(1, 255)])))
    _ALPN_NAME[len(name)] = name
    return u(len(name), 1)


def alpn_name_octet(octet):
    """The octet of a sent ProtocolName at the position of `octet`: the name that the length byte stands for (alpn_name_length_value)."""
    try:
        octets = octet.parent
        length = int.from_bytes(octets.parent.children[0].to_bytes(), "big")
        position = next(i for i, child in enumerate(octets.children) if child is octet)
        name = _ALPN_NAME.get(length) or bytes(97 + i % 26 for i in range(length))
        return name[position:position + 1]
    except Exception:
        return octet.to_bytes()


# ==================================================================================================================
# The client's certificates and what it signs (RFC 9846 sections 4.4.2, 4.4.3, 4.6.2, RFC 5246 sections 7.4.6, 7.4.8)
# ==================================================================================================================
def _with_request(message, function):
    """`function()` with the CertificateRequest `message` as the one being answered (a `where` on a received message runs before the party's
    state holds it)."""
    _REQ_OVERRIDE[0] = message
    try:
        return function()
    finally:
        _REQ_OVERRIDE[0] = None


def _request_ext():
    """({type: data}, certificate_request_context) of the TLS 1.3 CertificateRequest being answered, or None offline."""
    message = _REQ_OVERRIDE[0]
    if message is not None:
        return dict(extension_list(message[7 + message[4]:]) or []), message[5:5 + message[4]]
    state = session_state()
    if state is None:
        return None
    return state.request_extensions()


def request_view():
    """(signature_algorithms, oid_filters, certificate_request_context) of the CertificateRequest being answered."""
    view = _request_ext()
    if view is None:
        return [], [], b"\x01"
    extensions, context = view
    algs = offered_list(extensions[13]) if 13 in extensions else []
    filters = parse_oid_filters(extensions[48]) if 48 in extensions else []
    return algs, filters, context


KEY_SCHEMES = {"rsa": [0x0804, 0x0805, 0x0806], "rsa_pss": [0x0809, 0x080A, 0x080B], "ec256": [0x0403], "ec384": [0x0503], "ec521": [0x0603], "ed25519": [0x0807], "ed448": [0x0808]}
SELF_SCHEME = {"ec256": 0x0403, "ec384": 0x0503, "ec521": 0x0603, "ed25519": 0x0807, "ed448": 0x0808}


def request_cert_algs():
    """The signature_algorithms_cert (else signature_algorithms) of the CertificateRequest being answered."""
    view = _request_ext()
    if view is None:
        return []
    extensions, _ = view
    if 50 in extensions:
        return offered_list(extensions[50])
    return offered_list(extensions[13]) if 13 in extensions else []


def request_has_status_request(tree=None):
    """True when the CertificateRequest being answered carried status_request (the client may answer it in its CertificateEntry)."""
    state = session_state()
    if state is None:
        return True
    extensions, _ = state.request_extensions()
    return 5 in extensions


def client_certificate_candidates():
    """(key kind, signer) pairs whose certificate is signed with a scheme of the request and whose key can sign a scheme of the request."""
    algs, filters, _ = request_view()
    cert_algs = request_cert_algs()
    out = []
    for kind, schemes in KEY_SCHEMES.items():
        if algs and not any(scheme in algs for scheme in schemes):
            continue
        for signer, code in (("rsa256", 0x0401), ("rsa384", 0x0501), ("rsa512", 0x0601)):
            if not cert_algs or code in cert_algs:
                out.append((kind, signer))
        if kind not in ("rsa", "rsa_pss") and (not cert_algs or SELF_SCHEME[kind] in cert_algs):
            out.append((kind, "self"))
    if not filters and configured_credential_available():
        _, _, kind, certificate = configured_credential()
        if ((not algs or any(s in algs for s in KEY_SCHEMES[kind]))
                and (not cert_algs or cert_pair_code(certificate) in cert_algs)):
            out.append(("cfg", "cfg"))                  # the credential the setting names (the server's trust store holds it)
    return out


_CERT_POOL = {}


def clean_tries(kind, signer):
    """How often a certificate is generated again to get one without the bytes 0x20/0x0a: never for the kinds whose DER always holds
    one (an ECDSA signature or algorithm identifier, the RSASSA-PSS key OID), 400 times for the others (an RSA signature is clean with
    probability 5 %, 400 tries fail once in 10^9): Fandango evaluates many candidates per message and a fresh certificate costs 0.1-0.3 s under load."""
    if kind == "rsa_pss" or (signer == "self" and kind not in ("ed25519", "ed448")):
        return 1
    return 400


def pooled_certificate(key, make, tries):
    """A client certificate for `key`: a recent one again (up to eight are kept, a new one with probability 0.1 once there is one):
    Fandango's coverage-guided generation of a message evaluates many candidates and each fresh RSA signature costs 0.1-0.3 s, which
    made a single message take over a minute when no candidate covered a new path.  The credentials are registered again."""
    pool = _CERT_POOL.setdefault(key, [])
    if pool and (len(pool) >= 8 or random.random() > 0.1):
        der, credential = random.choice(pool)
        if credential is not None:
            CRED_STORE[der] = credential
        return der
    der = clean(make, tries)
    if b" " not in der and b"\n" not in der:        # an unclean certificate (counted as structure) is not kept for reuse
        pool.append((der, CRED_STORE.get(der)))
    return der


_LAST_EE = [None]


def client_certificate_der():
    """The DER of a client certificate whose signature and key fit the signature algorithms of the CertificateRequest and whose
    extensions satisfy its oid_filters (the key: RSA, ECDSA P-256/384/521 or Ed25519), or the configured credential."""
    der = _client_certificate_der()
    _LAST_EE[0] = der
    return der


def client_certificate_via_der():
    """A client certificate issued by the party's intermediate CA (the first certificate of a chain of three)."""
    _, filters, _ = request_view()
    pool = [c for c in client_certificate_candidates() if c[1].startswith("rsa") and c[0] not in ("rsa", "rsa_pss", "cfg")] or [("ec256", "rsa256")]
    kind, signer = random.choice(pool)
    der = pooled_certificate((kind, signer, tuple(filters), "via"), lambda: new_client_certificate(kind, filters, signer, True), 400)
    _LAST_EE[0] = der
    return der


def client_intermediate_certificate():
    return pooled_certificate(("intermediate",), intermediate_certificate, 400)


def cert_entry_extensions():
    """The extensions vector of the client's end-entity CertificateEntry: when the CertificateRequest being answered carried
    status_request and the client answers it, the extension (type status_request, CertificateStatus: status_type ocsp and an
    OCSPResponse for the certificate just chosen); else the empty vector (RFC 9846 section 4.4.2: the extensions of the client's
    Certificate correspond to those of the request)."""
    state = session_state()
    if state is None or state.version != 0x0304 or _LAST_EE[0] is None:
        return b"\x00\x00"
    extensions, _ = state.request_extensions()
    if 5 not in extensions or random.random() >= 0.03:
        return b"\x00\x00"
    response = ocsp_response_value()
    status = b"\x01" + len(response).to_bytes(3, "big") + response
    extension = u(5, 2) + u(len(status), 2) + status
    return u(len(extension), 2) + extension


def ocsp_response_value():
    der = _LAST_EE[0]
    cache = _CERT_POOL.setdefault(("ocsp", der), [])
    if cache and random.random() < 0.9:
        return random.choice(cache)
    value = ocsp_response_for(der)            # its ENUMERATED status 0a 01 00 is always in it: no retries, every response is kept
    cache.append(value)
    return value


def _client_certificate_der(breach=False):
    _, filters, _ = request_view()
    candidates = client_certificate_candidates()
    if ("cfg", "cfg") in candidates and random.random() < 0.85 and not breach:
        return configured_credential()[0]
    pool = [c for c in candidates if c[0] != "cfg"]
    if random.random() < 0.995:                      # a certificate with the id-RSASSA-PSS key OID (whose DER holds the byte 0x0a) is rare
        pool = [c for c in pool if c[0] != "rsa_pss"] or pool
    signed = [c for c in pool if c[1] != "self"]
    if signed:                                       # a self-signed ECDSA certificate always holds 0x20/0x0a bytes (counted as structure)
        pool = signed + ([c for c in pool if c[1] == "self" and c[0] in ("ed25519", "ed448")] if random.random() < 0.3 else [])
    kind, signer = random.choice(pool or [("rsa", "rsa256")])
    return pooled_certificate((kind, signer, tuple(filters), breach), lambda: new_client_certificate(kind, filters, signer, False, breach), clean_tries(kind, signer))


def client_certificate_breach_der():
    """The certificate of the request that breaks RFC 9846 section 4.5.1.2 (the end-entity certificate must match the recognized extension
    OIDs of a non-empty oid_filters extension): where the CertificateRequest being answered carries a filter for Key Usage or Extended
    Key Usage, a certificate without the named extension; else (no filter, or only unrecognized OIDs) the ordinary certificate, so the
    request then breaks nothing."""
    _, filters, _ = request_view()
    if not any(oid in (b"\x55\x1d\x0f", b"\x55\x1d\x25") for oid, _ in filters):
        return client_certificate_der()
    der = _client_certificate_der(True)
    _LAST_EE[0] = der
    return der


def client_certificate_usable_13(tree=None):
    """True when the party has a certificate that fits the CertificateRequest being answered (else the client sends the empty
    Certificate, RFC 9846 section 4.4.2: the certificate and the CertificateVerify scheme must fit its lists)."""
    return session_state() is None or bool(client_certificate_candidates())


def ca_hash_codes_13():
    """The rsa_pkcs1 SignatureSchemes of the request's signature_algorithms_cert (else signature_algorithms) the CA certificate may use
    (the certificates issued by the CA of the setup: the scheme of that CA's own certificate, when the request lists it)."""
    ca = configured_ca()
    if ca is not None:
        code = cert_pair_code(ca[2])
        cert_algs = request_cert_algs()
        return [code] if not cert_algs or code in cert_algs else []
    cert_algs = request_cert_algs()
    return [code for code in (0x0401, 0x0501, 0x0601) if not cert_algs or code in cert_algs]


def client_ca_certificate_13():
    if configured_ca() is not None:
        return configured_ca()[2].public_bytes(_ser.Encoding.DER)
    codes = ca_hash_codes_13()
    sign = {0x0301: "rsa224", 0x0401: "rsa256", 0x0501: "rsa384", 0x0601: "rsa512"}[random.choice(codes or [0x0401])]
    return pooled_certificate(("ca", sign), lambda: client_ca_certificate(sign), 600)


def client_ca_usable_13(tree=None):
    return session_state() is None or bool(ca_hash_codes_13())


def own_credential():
    state = session_state()
    return _own_certificate(state) if state is not None else None


def client_cv_scheme():
    """The SignatureScheme of the client's CertificateVerify: one of the CertificateRequest's signature_algorithms that the
    key of the certificate just sent can sign."""
    credential = own_credential()
    algs, _, _ = request_view()
    schemes = KEY_SCHEMES.get(credential[0], [0x0804]) if credential is not None else [0x0804]
    usable = [scheme for scheme in schemes if scheme in algs] or schemes
    return u(random.choice(usable), 2)


def client_cv_signature(scheme, post):
    state = session_state()
    if state is None or state.hash_name is None:
        return bytes(64)
    return state.client_signature(int.from_bytes(scheme, "big"), post)


def client_post_finished_data():
    state = session_state()
    if state is None or state.version != 0x0304 or "c_ap" not in state.secrets:
        return bytes(32)
    return state.post_finished()


def post_hs_context():
    return request_view()[2] or b"\x01"


def request_view_12():
    """(certificate_types, [signature_and_hash pairs]) of the TLS 1.2 CertificateRequest being answered."""
    state = session_state()
    message = _REQ_OVERRIDE[0]
    if state is not None and message is None:
        for direction, m in reversed(state.transcript):
            if direction == "S" and m[0] == 13:
                message = m
                break
    if message is None:
        return [], []
    body = message[4:]
    n = body[0]
    types = list(body[1:1 + n])
    m = int.from_bytes(body[1 + n:3 + n], "big")
    pairs = [int.from_bytes(body[3 + n + i:5 + n + i], "big") for i in range(0, m, 2)]
    return types, pairs


def client_certificate_candidates_12():
    types, pairs = request_view_12()
    chosen = {4: "rsa256", 5: "rsa384", 6: "rsa512"}          # never SHA-224 (RFC 9846 section 4.3.3: MUST NOT be used)
    rsa_hashes = [h for h in (4, 5, 6) if (h << 8 | 1) in pairs] or ([] if pairs else [4])
    ec_hashes = [h for h in (4, 5, 6) if (h << 8 | 3) in pairs] or ([] if pairs else [4])
    candidates = []
    if configured_credential_available():                         # the credential the setting names
        _, _, kind, certificate = configured_credential()
        sig = 1 if kind == "rsa" else 3
        wanted = 1 if kind == "rsa" else 64
        if (kind in ("rsa", "ec256", "ec384", "ec521") and (wanted in types or not types) and (not pairs or cert_pair_code(certificate) in pairs)
                and (not pairs or any(p & 0xFF == sig and p >> 8 in (4, 5, 6) for p in pairs))):
            candidates.append(("cfg", "cfg"))
    if 1 in types or not types:                                   # rsa_sign: an RSA key, certified with a pair of the list
        candidates += [("rsa", chosen[h]) for h in rsa_hashes]
        if not pairs or any(p in pairs for p in (0x0809, 0x080A, 0x080B)):     # an RSASSA-PSS key (rsa_pss_pss pairs, RFC 9846 section 4.2.3)
            candidates += [("rsa_pss", chosen[h]) for h in rsa_hashes[:1]]
    if (64 in types or not types) and ec_hashes:                  # ecdsa_sign: an ECDSA key, CertificateVerify with a pair (h, ecdsa)
        candidates += [("ec256", chosen[h]) for h in rsa_hashes]
        candidates += [(kind, "self") for kind, h in (("ec256", 4), ("ec384", 5), ("ec521", 6)) if h in ec_hashes]
    return candidates


def client_certificate_der_12():
    candidates = client_certificate_candidates_12()
    if ("cfg", "cfg") in candidates and random.random() < 0.85:
        return configured_credential()[0]
    pool = [c for c in candidates if c[0] != "cfg"]
    if random.random() < 0.995:                      # an id-RSASSA-PSS key OID holds the byte 0x0a (counted as structure): rare
        pool = [c for c in pool if c[0] != "rsa_pss"] or pool
    signed = [c for c in pool if c[1] != "self"]
    if signed:                                       # a self-signed ECDSA certificate always holds 0x20/0x0a bytes (counted as structure)
        pool = signed
    kind, signer = random.choice(pool or [("rsa", "rsa256")])
    return pooled_certificate((kind, signer, ()), lambda: new_client_certificate(kind, [], signer), clean_tries(kind, signer))


def client_certificate_via_der_12():
    """A client certificate issued by the party's intermediate CA (TLS 1.2: the first certificate of a chain of three)."""
    pool = [c for c in client_certificate_candidates_12() if c[1].startswith("rsa") and c[0] not in ("rsa", "rsa_pss", "cfg")] or [("ec256", "rsa256")]
    kind, signer = random.choice(pool)
    der = pooled_certificate((kind, signer, (), "via"), lambda: new_client_certificate(kind, [], signer, True), 400)
    _LAST_EE[0] = der
    return der


def client_certificate_usable_12(tree=None):
    """True when the party has a certificate whose key type is in the certificate_types of the request and that is signed with a
    pair of its supported_signature_algorithms (RFC 5246 sections 7.4.4, 7.4.6)."""
    return session_state() is None or bool(client_certificate_candidates_12())


def ca_hash_codes_12():
    ca = configured_ca()
    if ca is not None:
        code = cert_pair_code(ca[2])
        _, pairs = request_view_12()
        return [code] if not pairs or code in pairs else []
    _, pairs = request_view_12()
    return [code for code in (0x0401, 0x0501, 0x0601) if not pairs or code in pairs]


def client_ca_certificate_12():
    if configured_ca() is not None:
        return configured_ca()[2].public_bytes(_ser.Encoding.DER)
    codes = ca_hash_codes_12()
    sign = {0x0301: "rsa224", 0x0401: "rsa256", 0x0501: "rsa384", 0x0601: "rsa512"}[random.choice(codes or [0x0401])]
    return pooled_certificate(("ca", sign), lambda: client_ca_certificate(sign), 600)


def client_ca_usable_12(tree=None):
    return session_state() is None or bool(ca_hash_codes_12())


def request_usable_13(tree):
    """True when the CertificateRequest (TLS 1.3, the message `tree`) names lists the party's certificates and CertificateVerify schemes fit:
    a certificate whose key can sign a scheme of signature_algorithms and whose signatures (and those of the CA entries) are in
    signature_algorithms_cert (RFC 9846 sections 4.2.3, 4.4.2.2, 4.4.3).  Otherwise the client answers with the empty Certificate only."""
    def check():
        cert_algs = request_cert_algs()
        return bool(client_certificate_candidates()) and bool(ca_hash_codes_13()) and (not cert_algs or 0x0401 in cert_algs)
    return _with_request(tree.to_bytes(), check)


def request_class_12(tree):
    """'u' when the party has a certificate the TLS 1.2 CertificateRequest accepts (key type in certificate_types, every certificate signed with a
    pair of supported_signature_algorithms, RFC 5246 sections 7.4.4, 7.4.6), else 'n'; followed by 'f' when the types name rsa_fixed_dh and
    an RSA pair is listed (the party's own DH certificate fits, section 7.4.6)."""
    def check():
        types, pairs = request_view_12()
        usable = bool(client_certificate_candidates_12()) and bool(ca_hash_codes_12()) and (not pairs or 0x0401 in pairs)
        rsa_hashes = [h for h in (4, 5, 6) if (h << 8 | 1) in pairs] or ([] if pairs else [4])
        return ("u" if usable else "n") + ("f" if 3 in types and rsa_hashes else "")
    return _with_request(tree.to_bytes(), check)


def client_certificate_dh_12():
    """A certificate with a Diffie-Hellman key of the server's parameters (static DH: those of its certificate), certified with RSA."""
    state = session_state()
    if state is None or state.dh_params is None:
        return b"\x30\x03\x02\x01\x00"
    _, pairs = request_view_12()
    rsa_hashes = [h for h in (4, 5, 6) if (h << 8 | 1) in pairs] or [4]
    signer = {4: "rsa256", 5: "rsa384", 6: "rsa512"}[random.choice(rsa_hashes)]
    p, g, _ = state.dh_params
    return pooled_certificate(("dh", p, g, signer), lambda: dh_client_certificate(p, g, signer), 1)


def cv12_algorithm():
    credential = own_credential()
    types, pairs = request_view_12()
    if credential is not None and credential[0] == "rsa_pss":      # the id-RSASSA-PSS key signs with rsa_pss_pss only
        usable = [p for p in pairs if p in (0x0809, 0x080A, 0x080B)]
        return u(random.choice(usable) if usable else 0x0809, 2)
    sig = 1 if credential is None or credential[0] == "rsa" else 3
    usable = [p for p in pairs if p & 0xFF == sig and p >> 8 in (4, 5, 6)]
    if sig == 1:                                                      # RSASSA-PSS pairs of an RSA key (RFC 9846 section 4.3.3)
        usable += [p for p in pairs if p in (0x0804, 0x0805, 0x0806)]
    return u(random.choice(usable) if usable else (0x0403 if sig == 3 else 0x0401), 2)


def cv12_algorithm_legacy():
    """A SignatureAndHashAlgorithm with an MD5 or SHA-1 hash that the key of the client's certificate can sign (RFC 9155 section 2 forbids it in a
    CertificateVerify): rsa_pkcs1 for an RSA key, ecdsa for an EC key."""
    credential = own_credential()
    sig = 1 if credential is None or credential[0] in ("rsa", "rsa_pss") else 3
    return u(random.choice([0x0201, 0x0101] if sig == 1 else [0x0203, 0x0103]), 2)


def overflow_app_data_value():
    """RFC 6066 section 4: where a maximum fragment length below 2^14 is negotiated, an application-data fragment that exceeds it by more than the record
    layer's output bound (5 bytes of header, up to 256 bytes of padding and 32 bytes of MAC: 293) - the request that breaks the requirement to fragment;
    it starts with the marker the party recognises (it is then sent unsplit).  Where nothing is negotiated, ordinary short data (a request that breaks nothing)."""
    allowed = bytes(b for b in range(256) if b not in (0x20, 0x0a))
    state = session_state()
    limit = getattr(state, "max_fragment", None) if state is not None else None
    if limit and limit < 16384:
        size = min(limit + random.randint(300, 600), 6000)
        if size > limit + 293:
            return OVERFLOW_MAGIC + bytes(random.choices(allowed, k=size - len(OVERFLOW_MAGIC)))
    return bytes(random.choices(allowed, k=random.randint(1, 64)))


def no_reaction_pending(tree=None):
    """False while the server's reaction to an oversized record (RFC 6066 section 4) is awaited: the only reaction the specification makes mandatory is the
    record_overflow alert, so every other reply (data, KeyUpdate, close_notify, the silence of the timer) is then a violation."""
    state = session_state()
    return state is None or not getattr(state, "overflow_pending", False)


def alert_after_oversize_ok(tree):
    """An alert received while the reaction to an oversized record is awaited must be record_overflow (RFC 6066 section 4)."""
    if no_reaction_pending():
        return True
    data = tree.to_bytes()
    return len(data) >= 7 and data[6] == 22


def server_aborts_legacy_certificate_verify():
    """RFC 9155 section 5: a server that receives a CertificateVerify with MD5 or SHA-1 MUST abort the connection with an illegal_parameter alert: its silence
    (the timer's expiry) is a violation, so the where on the timer never holds."""
    return False


def client_cv12_signature(algorithm):
    state = session_state()
    if state is None or state.version != 0x0303:
        return bytes(64)
    return state.client_signature_12(int.from_bytes(algorithm, "big"))



def large_app_data_value():
    """Application data of 600 to 1500 bytes, or one that reaches the negotiated max_fragment_length (RFC 6066 section 4: records
    above it are split by the sender), up to 6000 bytes: the echo of a larger one (wolfSSL echoes it) takes Fandango's parser longer than the
    6 s timer (a 16000-byte echo made one 900 s session end with an unexpected timer expiry); records up to the limit of 2^14 (RFC 9846
    section 5.2) are therefore not sent (TODO in tls.fan). No bytes 0x20 and 0x0a (a value, not text)."""
    allowed = bytes(b for b in range(256) if b not in (0x20, 0x0a))
    state = session_state()
    limit = getattr(state, "max_fragment", None) if state is not None else None
    sizes = [random.randint(600, 1500) for _ in range(3)] + [random.randint(1500, 6000), 6000]
    if limit:
        sizes += [limit - 1, limit, limit + 1, random.randint(limit, min(3 * limit, 6000))]
    return bytes(random.choices(allowed, k=random.choice(sizes)))


# developer aid (off unless TLS_TIMING_LOG names a file): the time each generator or check of the grammar takes
if os.environ.get("TLS_TIMING_LOG") or os.environ.get("TLS_CALL_LOG"):
    import time as _time
    import functools as _functools

    def _timed(name, function):
        @_functools.wraps(function)
        def wrapper(*args, **kwargs):
            started = _time.time()
            if os.environ.get("TLS_CALL_LOG") and name in ("client_certificate_der", "client_ca_certificate_13", "client_certificate_usable_13", "client_ca_usable_13", "client_certificate_der_12", "client_cv_scheme", "client_cv_signature"):
                with open(os.environ["TLS_CALL_LOG"], "a") as log:
                    log.write(f"{started:.3f} call {name}\n")
            try:
                return function(*args, **kwargs)
            finally:
                elapsed = _time.time() - started
                if elapsed > 0.05 and os.environ.get("TLS_TIMING_LOG"):
                    with open(os.environ["TLS_TIMING_LOG"], "a") as log:
                        log.write(f"{_time.time():.3f} {name} {elapsed:.3f}\n")
        return wrapper

    _here = (lambda: None).__code__.co_filename
    for _name in [n for n, v in list(globals().items()) if getattr(getattr(v, "__code__", None), "co_filename", None) == _here
                  and not n.startswith("_") and n not in ("tolerated", "u", "blen", "rb", "uv", "cat", "clean", "session_state", "tls12_state")]:
        globals()[_name] = _timed(_name, globals()[_name])

# ==================================================================================================================
# Alerts of the client while it waits for the server's flight (GENERATED by tools/gen_flight.py)
# RFC 9846 section 6 and appendix A.1 (WAIT_SH, WAIT_EE, WAIT_CERT_CR, WAIT_CERT, WAIT_CV, WAIT_FINISHED), RFC 5246 sections 7.2, 7.3:
# the client may send an error alert, user_canceled followed by close_notify, or close_notify at any time during the handshake.  The server's
# flight is a fixed sequence of messages (the nodes below), and the messages that are already on their way when the client's alert is
# planned arrive before it (fa) or after it (fb), each in the order of the flight and each at most once.  The server's closure ends it.
# ==================================================================================================================
<fa13_n0> ::= (
      <Server:in_server_hello_13> <fa13_n1>
    | ( <Server:in_hello_retry_request> | <Server:in_hello_retry_request_cookie> | <Server:in_hello_retry_request_cookie_only> ) <fa13_nh>
    | <Server:in_server_hello_12> <fa12h_g1>
    | <Client:req_alert_error_hs_13> <fb13_n0> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n0> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n0> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n0> ::= ( <Server:in_server_hello_13> <fb13_n1> | ( <Server:in_hello_retry_request> | <Server:in_hello_retry_request_cookie> | <Server:in_hello_retry_request_cookie_only> ) <fb13_nh> | <Server:in_server_hello_12> <fb12h_g1> )?
<fa13_n0o> ::= (
      <Server:in_server_hello_13> <fa13_n1>
    | ( <Server:in_hello_retry_request> | <Server:in_hello_retry_request_cookie> | <Server:in_hello_retry_request_cookie_only> ) <fa13_nh>
    | <Client:req_alert_error_hs_13> <fb13_n0o> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n0o> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n0o> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n0o> ::= ( <Server:in_server_hello_13> <fb13_n1> | ( <Server:in_hello_retry_request> | <Server:in_hello_retry_request_cookie> | <Server:in_hello_retry_request_cookie_only> ) <fb13_nh> )?
<fa13_n0h> ::= (
      <Server:in_server_hello_13_after_hrr> <fa13_n1>
    | <Client:req_alert_error_hs_13> <fb13_n0h> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n0h> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n0h> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n0h> ::= ( <Server:in_server_hello_13_after_hrr> <fb13_n1> )?
<fa13_nh> ::= (
      <Server:in_ccs> <fa13_nend>
    | <Client:req_alert_error_hs_13> <fb13_nh> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_nh> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_nh> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_nh> ::= ( <Server:in_ccs> )?
<fa13_n1> ::= (
      <Server:in_ccs> <fa13_n1b>
    | <Server:in_encrypted_extensions> <fa13_n2>
    | <Client:req_alert_error_hs_13> <fb13_n1> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n1> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n1> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n1> ::= ( <Server:in_ccs> <fb13_n1b> | <Server:in_encrypted_extensions> <fb13_n2> )?
<fa13_n1b> ::= (
      <Server:in_encrypted_extensions> <fa13_n2>
    | <Client:req_alert_error_hs_13> <fb13_n1b> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n1b> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n1b> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n1b> ::= ( <Server:in_encrypted_extensions> <fb13_n2> )?
<fa13_n2> ::= (
      ( <Server:in_certificate_request_13> | <Server:in_certificate_request_13_deprecated> | <Server:in_certificate_request_13_nu> | <Server:in_certificate_request_13_deprecated_nu> ) <fa13_n3>
    | <Server:in_certificate_13> <fa13_n4>
    | <Client:req_alert_error_hs_13> <fb13_n2> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n2> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n2> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n2> ::= ( ( <Server:in_certificate_request_13> | <Server:in_certificate_request_13_deprecated> | <Server:in_certificate_request_13_nu> | <Server:in_certificate_request_13_deprecated_nu> ) <fb13_n3> | <Server:in_certificate_13> <fb13_n4> )?
<fa13_n3> ::= (
      <Server:in_certificate_13> <fa13_n4>
    | <Client:req_alert_error_hs_13> <fb13_n3> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n3> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n3> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n3> ::= ( <Server:in_certificate_13> <fb13_n4> )?
<fa13_n4> ::= (
      <Server:in_certificate_verify> <fa13_n5>
    | <Client:req_alert_error_hs_13> <fb13_n4> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n4> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n4> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n4> ::= ( <Server:in_certificate_verify> <fb13_n5> )?
<fa13_n5> ::= (
      <Server:in_finished> <fa13_nend>
    | <Client:req_alert_error_hs_13> <fb13_n5> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> <fb13_n5> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> <fb13_n5> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fb13_n5> ::= ( <Server:in_finished> )?
<fa13_nend> ::= (
      <Client:req_alert_error_hs_13> ( <server_closes> <flight_cancel_13> | <Server:in_closed> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_user_canceled_close_notify_hs_13> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <Client:req_alert_close_notify_hs_13> ( <server_closes> <flight_cancel_13> | <flight_expired_13> )
    | <server_closes> <flight_cancel_13> )
<fa12_g0> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_server_hello_12> <fa12_g1>
    | <Client:req_alert_error_hs_12> <fb12_g0> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g0> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g0> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g0> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_server_hello_12> <fb12_g1> )?
<fa12_g1> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_certificate_12> <fa12_g2>
    | <Server:in_server_key_exchange_anon> <fa12_g3a>
    | <Client:req_alert_error_hs_12> <fb12_g1> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g1> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g1> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g1> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_certificate_12> <fb12_g2> | <Server:in_server_key_exchange_anon> <fb12_g3a> )?
<fa12_g2> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_certificate_status> <fa12_g2b>
    | ( <Server:in_server_key_exchange_dhe> ) <fa12_g3>
    | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fa12_g4>
    | <Server:in_server_hello_done> <fa12_gend>
    | <Client:req_alert_error_hs_12> <fb12_g2> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g2> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g2> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g2> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_certificate_status> <fb12_g2b> | ( <Server:in_server_key_exchange_dhe> ) <fb12_g3> | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fb12_g4> | <Server:in_server_hello_done> )?
<fa12_g2b> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      ( <Server:in_server_key_exchange_dhe> ) <fa12_g3>
    | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fa12_g4>
    | <Server:in_server_hello_done> <fa12_gend>
    | <Client:req_alert_error_hs_12> <fb12_g2b> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g2b> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g2b> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g2b> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( ( <Server:in_server_key_exchange_dhe> ) <fb12_g3> | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fb12_g4> | <Server:in_server_hello_done> )?
<fa12_g3> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fa12_g4>
    | <Server:in_server_hello_done> <fa12_gend>
    | <Client:req_alert_error_hs_12> <fb12_g3> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g3> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g3> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g3> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fb12_g4> | <Server:in_server_hello_done> )?
<fa12_g3a> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_server_hello_done> <fa12_gend>
    | <Client:req_alert_error_hs_12> <fb12_g3a> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g3a> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g3a> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g3a> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_server_hello_done> )?
<fa12_g4> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_server_hello_done> <fa12_gend>
    | <Client:req_alert_error_hs_12> <fb12_g4> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_g4> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_g4> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_g4> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_server_hello_done> )?
<fa12_gend> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Client:req_alert_error_hs_12> <fb12_gend> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12_gend> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12_gend> ( <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> | <TimerEvent:expired_hsa_12> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa_12> <state_end> )
<fb12_gend> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )*
<fa12h_g1> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_certificate_12> <fa12h_g2>
    | <Server:in_server_key_exchange_anon> <fa12h_g3a>
    | <Client:req_alert_error_hs_12> <fb12h_g1> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_g1> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_g1> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_g1> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_certificate_12> <fb12h_g2> | <Server:in_server_key_exchange_anon> <fb12h_g3a> )?
<fa12h_g2> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_certificate_status> <fa12h_g2b>
    | ( <Server:in_server_key_exchange_dhe> ) <fa12h_g3>
    | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fa12h_g4>
    | <Server:in_server_hello_done> <fa12h_gend>
    | <Client:req_alert_error_hs_12> <fb12h_g2> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_g2> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_g2> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_g2> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_certificate_status> <fb12h_g2b> | ( <Server:in_server_key_exchange_dhe> ) <fb12h_g3> | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fb12h_g4> | <Server:in_server_hello_done> )?
<fa12h_g2b> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      ( <Server:in_server_key_exchange_dhe> ) <fa12h_g3>
    | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fa12h_g4>
    | <Server:in_server_hello_done> <fa12h_gend>
    | <Client:req_alert_error_hs_12> <fb12h_g2b> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_g2b> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_g2b> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_g2b> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( ( <Server:in_server_key_exchange_dhe> ) <fb12h_g3> | ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fb12h_g4> | <Server:in_server_hello_done> )?
<fa12h_g3> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fa12h_g4>
    | <Server:in_server_hello_done> <fa12h_gend>
    | <Client:req_alert_error_hs_12> <fb12h_g3> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_g3> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_g3> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_g3> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( ( <Server:in_certificate_request_12> | <Server:in_certificate_request_12_nu> ) <fb12h_g4> | <Server:in_server_hello_done> )?
<fa12h_g3a> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_server_hello_done> <fa12h_gend>
    | <Client:req_alert_error_hs_12> <fb12h_g3a> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_g3a> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_g3a> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_g3a> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_server_hello_done> )?
<fa12h_g4> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Server:in_server_hello_done> <fa12h_gend>
    | <Client:req_alert_error_hs_12> <fb12h_g4> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_g4> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_g4> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_g4> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* ( <Server:in_server_hello_done> )?
<fa12h_gend> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )* (
      <Client:req_alert_error_hs_12> <fb12h_gend> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <Server:in_closed> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_user_canceled_close_notify_hs_12> <fb12h_gend> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <Client:req_alert_close_notify_hs_12> <fb12h_gend> ( <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> | <TimerEvent:expired_hsa> <state_end> )
    | <server_closes_12_flight> <TimerControl:cancel_hsa> <state_end> )
<fb12h_gend> ::= ( <Server:in_alert_12_warning> | <Server:in_hello_request> )*
<exch_alert_flight_13_0> ::= <TimerControl:start_hsa> <fa13_n0>
<exch_alert_flight_13_0o> ::= <TimerControl:start_hsa> <fa13_n0o>
<exch_alert_flight_13_0h> ::= <TimerControl:start_hsa> <fa13_n0h>
<exch_alert_flight_13_1> ::= <TimerControl:start_hsa> <fa13_n1>
<exch_alert_flight_13_2> ::= <TimerControl:start_hsa> <fa13_n2>
<exch_alert_flight_13_3> ::= <TimerControl:start_hsa> <fa13_n3>
<exch_alert_flight_13_4> ::= <TimerControl:start_hsa> <fa13_n4>
<exch_alert_flight_13_5> ::= <TimerControl:start_hsa> <fa13_n5>
<exch_alert_flight_12_0> ::= <TimerControl:start_hsa_12> <fa12_g0>
<exch_alert_flight_12_1> ::= <TimerControl:start_hsa_12> <fa12_g1>
<exch_alert_flight_12_2> ::= <TimerControl:start_hsa_12> <fa12_g2>
<exch_alert_flight_12_3> ::= <TimerControl:start_hsa_12> <fa12_g3>
<exch_alert_flight_12_4> ::= <TimerControl:start_hsa_12> <fa12_g4>
# the end of the exchange: whatever ended it, a server that answered a ClientHello with a non-empty legacy_session_id has sent the compatibility
# change_cipher_spec right after its first handshake message (RFC 9846 appendix D.4; checked once everything it sent is in)
<flight_cancel_13> ::= <TimerControl:cancel_hsa> <state_end>
<flight_expired_13> ::= <TimerEvent:expired_hsa> <state_end>
where forall <x> in <flight_cancel_13>: ccs_compat_ok(<x>)
where forall <x> in <flight_expired_13>: ccs_compat_ok(<x>)


# ==================================================================================================================
# TLS 1.2 (RFC 5246): sent messages
# ==================================================================================================================
# ClientHello (section 7.4.1.2) offering TLS 1.2 only.  The cipher suites are the ones of RFC 5246 appendix A.5; the list
# is narrowed to contain one the tested servers accept and this client can complete.
<req_client_hello_12> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_12>
where forall <e> in <req_client_hello_12>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_12> ::= <hs_client_hello> <hs_len> <client_hello_body_12>
where forall <e> in <out_client_hello_12>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_12> ::= <version_0303> <random_bytes> <session_id> <cipher_suites_vec_12> <compression_methods_12> (<ch_extensions_vec_12> | <ch_extensions_vec_12_versions_12>)
# the list of CompressionMethod values; null is among them (RFC 5246 section 7.4.1.2)
<compression_methods_12> ::= <vec_len8> <compression_method_list_12>
where forall <e> in <compression_methods_12>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)
<compression_method_list_12> ::= <compression_null> | <compression_null> <compression_private_use> | <compression_private_use> <compression_null> | <compression_private_use> <compression_null> <compression_private_use>
# RFC 5246 defines only null(0); the values 224-255 are private use (the server selects null)
<compression_private_use> ::= rb'[\xe0-\xff]'
<cipher_suites_vec_12> ::= <vec_len16> <cipher_suite_list_12>
where forall <e> in <cipher_suites_vec_12>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<cipher_suite_list_12> ::= <cipher_suite_12_completable>{0,4} <cipher_suite_12_usable> <cipher_suite_12_completable>{0,3}
<ch_extensions_vec_12> ::= <vec_len16> <ch_ext_list_12>
where forall <e> in <ch_extensions_vec_12>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
# a TLS 1.2 client that sends supported_versions (RFC 9846 section 4.2.1: the extension lists every version the client is prepared to
# negotiate; this client is prepared for TLS 1.2 only, and reserved values are ignored): the server negotiates TLS 1.2 from it
<ch_extensions_vec_12_versions_12> ::= <vec_len16> <ch_ext_list_12> <ext_supported_versions_12>
where forall <e> in <ch_extensions_vec_12_versions_12>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ext_supported_versions_12> ::= <ext_type_supported_versions> <ext_len> <versions_vec_12>
where forall <e> in <ext_supported_versions_12>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<versions_vec_12> ::= <vec_len8> <versions_list_12>
where forall <e> in <versions_vec_12>: <e>.<vec_len8> == u(blen(<e>) - 1, 1)
<versions_list_12> ::= <version_0303> | <version_grease> <version_0303> | <version_0303> <version_grease> | <version_grease> <version_grease_b> <version_0303>
<ch_ext_list_12> ::= <ext_sni>? <ext_max_fragment_length>? <ext_trusted_ca_keys>? <ext_truncated_hmac>? <ext_status_request>? <ext_signature_algorithms_12> <ext_signature_algorithms_cert>? <ext_alpn>? <ext_client_certificate_url>? <ext_unknown>?
# signature_algorithms of TLS 1.2 (section 7.4.1.4.1): SignatureAndHashAlgorithm pairs; RFC 9155 forbids offering MD5
# and SHA-1 signature hashes
<ext_signature_algorithms_12> ::= <ext_type_signature_algorithms> <ext_len> <signature_algorithm_list_12_vec>
where forall <e> in <ext_signature_algorithms_12>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
# narrowed to hold rsa_pkcs1_sha256: the tested servers' certificates are signed with sha256WithRSAEncryption (RFC 5246 section 7.4.2: all certificates must be signed with a pair of the list) and they sign a ServerKeyExchange with their RSA key
<signature_algorithm_list_12_vec> ::= <vec_len16> <signature_algorithm_12>{0,3} <signature_algorithm_12_rsa> <signature_algorithm_12>{0,3}
where forall <e> in <signature_algorithm_list_12_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<signature_algorithm_12_rsa> ::= <ss_rsa_pkcs1_sha256>
<signature_algorithm_12> ::= <signature_scheme_sent>
# the pairs RFC 9155 section 2 forbids a TLS 1.2 client to offer or use: MD5 and SHA-1 signature hashes
<signature_algorithm_12_legacy> ::= <ss_rsa_pkcs1_sha1> | <ss_ecdsa_sha1> | <ss_rsa_pkcs1_md5> | <ss_ecdsa_md5>

# the request that breaks the first requirement of RFC 9155 section 2: a TLS 1.2 ClientHello whose signature_algorithms holds an MD5 or SHA-1 pair (after
# rsa_pkcs1_sha256, so the servers that choose in the client's order still sign with SHA-2); RFC 9155 names no reaction a server must show: the replies of <req_client_hello_12>
<req_client_hello_12_legacy_hash> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_12_legacy>
where forall <e> in <req_client_hello_12_legacy_hash>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_12_legacy> ::= <hs_client_hello> <hs_len> <client_hello_body_12_legacy>
where forall <e> in <out_client_hello_12_legacy>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_12_legacy> ::= <version_0303> <random_bytes> <session_id> <cipher_suites_vec_12> <compression_methods_12> <ch_extensions_vec_12_legacy>
<ch_extensions_vec_12_legacy> ::= <vec_len16> <ch_ext_list_12_legacy>
where forall <e> in <ch_extensions_vec_12_legacy>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_12_legacy> ::= <ext_sni>? <ext_max_fragment_length>? <ext_trusted_ca_keys>? <ext_truncated_hmac>? <ext_status_request>? <ext_signature_algorithms_12_legacy> <ext_signature_algorithms_cert>? <ext_alpn>? <ext_client_certificate_url>? <ext_unknown>?
<ext_signature_algorithms_12_legacy> ::= <ext_type_signature_algorithms> <ext_len> <signature_algorithm_list_12_vec_legacy>
where forall <e> in <ext_signature_algorithms_12_legacy>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<signature_algorithm_list_12_vec_legacy> ::= <vec_len16> <signature_algorithm_12>{0,2} <signature_algorithm_12_rsa> <signature_algorithm_12>{0,2} <signature_algorithm_12_legacy> <signature_algorithm_12>{0,1}
where forall <e> in <signature_algorithm_list_12_vec_legacy>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)

# trusted_ca_keys (RFC 6066 section 6) and truncated_hmac (section 7; a TLS 1.2 MAC extension, never sent in TLS 1.3)
<ext_trusted_ca_keys> ::= <ext_type_trusted_ca_keys> <ext_len> <trusted_authorities_vec>
where forall <e> in <ext_trusted_ca_keys>: <e>.<ext_len> == u(blen(<e>) - 4, 2)
<trusted_authorities_vec> ::= <vec_len16> <trusted_authority>{0,2}
where forall <e> in <trusted_authorities_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<trusted_authority> ::= <ia_pre_agreed> | <ia_key_sha1_hash> <sha1_hash_20> | <ia_x509_name> <distinguished_name> | <ia_cert_sha1_hash> <sha1_hash_20>
<sha1_hash_20> ::= rb'[\x00-\xff]{20}'
<ext_truncated_hmac> ::= <ext_type_truncated_hmac> b'\x00\x00'

# ClientKeyExchange (section 7.4.7): the PreMasterSecret encrypted with the server's RSA key (7.4.7.1) ...
<req_client_key_exchange_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_client_key_exchange_rsa>
where forall <e> in <req_client_key_exchange_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_client_key_exchange_rsa_after_certificate> ::= <req_client_key_exchange_rsa>
<out_client_key_exchange_rsa> ::= <hs_client_key_exchange> <hs_len> <encrypted_pre_master_secret_vec>
where forall <e> in <out_client_key_exchange_rsa>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<encrypted_pre_master_secret_vec> ::= <vec_len16> <encrypted_pre_master_secret>
where forall <e> in <encrypted_pre_master_secret_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<encrypted_pre_master_secret> ::= rb'[\x00-\xff]+' := encrypted_pre_master_secret_value()
# ... or the client's Diffie-Hellman public value (7.4.7.2)
<req_client_key_exchange_dhe> ::= <ct_handshake> <rec_version> <rec_len> <out_client_key_exchange_dhe>
where forall <e> in <req_client_key_exchange_dhe>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_client_key_exchange_dhe_after_certificate> ::= <req_client_key_exchange_dhe>
<out_client_key_exchange_dhe> ::= <hs_client_key_exchange> <hs_len> <dh_yc_vec>
where forall <e> in <out_client_key_exchange_dhe>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<dh_yc_vec> ::= <vec_len16> <dh_yc>
where forall <e> in <dh_yc_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<dh_yc> ::= rb'[\x00-\xff]+' := dh_client_public_value()

# Certificate without certificates (section 7.4.6): the answer to a CertificateRequest the client cannot satisfy
<req_certificate_empty_12_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_empty_12>
where forall <e> in <req_certificate_empty_12_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_empty_12_dhe> ::= <req_certificate_empty_12_rsa>

# ... or with the client's own certificate, whose key type fits the CertificateRequest's certificate_types and
# supported_signature_algorithms, then ClientKeyExchange and a CertificateVerify (sections 7.4.6, 7.4.8)
<req_certificate_12_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_12>
where forall <e> in <req_certificate_12_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_12_dhe> ::= <req_certificate_12_rsa>
<out_certificate_12> ::= <hs_certificate> <hs_len> <cert_list_len_out> ( <cert_entry_12> <cert_entry_12_ca>? | <cert_entry_12_via> <cert_entry_12_inter> <cert_entry_12_ca>? )
where forall <e> in <out_certificate_12>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<cert_entry_12> ::= <cert_len_out> <client_cert_der_12>
where forall <e> in <cert_entry_12>: <e>.<cert_len_out> == u(blen(<e>) - 3, 3)
<cert_entry_12_via> ::= <cert_len_out> <client_cert_der_12_via>
where forall <e> in <cert_entry_12_via>: <e>.<cert_len_out> == u(blen(<e>) - 3, 3)
<cert_entry_12_inter> ::= <cert_len_out> <client_inter_der>
where forall <e> in <cert_entry_12_inter>: <e>.<cert_len_out> == u(blen(<e>) - 3, 3)
<cert_entry_12_ca> ::= <cert_len_out> <client_ca_der_12>
where forall <e> in <cert_entry_12_ca>: <e>.<cert_len_out> == u(blen(<e>) - 3, 3)
<client_ca_der_12> ::= rb'[\x00-\xff]+' := client_ca_certificate_12()
# the generator picks, up front, a certificate whose key type is in certificate_types and whose signatures fit the request's pairs
# (RFC 5246 sections 7.4.4, 7.4.6); the empty Certificate is an alternative of its own
where forall <e> in <out_certificate_12>: <e>.<cert_list_len_out> == u(blen(<e>) - 7, 3)
<client_cert_der_12> ::= rb'[\x00-\xff]+' := client_certificate_der_12()
<client_cert_der_12_via> ::= rb'[\x00-\xff]+' := client_certificate_via_der_12()
# the request that breaks RFC 9155 section 2 (a TLS 1.2 client MUST NOT offer or use MD5 or SHA-1 signature hashes): the CertificateVerify with an MD5 or SHA-1
# pair that the certificate's key can sign (RFC 9155 names no reaction a server must show: every reply is accepted, in <state_client_finish_12>)
<req_certificate_verify_12_legacy_hash> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_verify_12_legacy>
where forall <e> in <req_certificate_verify_12_legacy_hash>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_verify_12_legacy_hash_dhe> ::= <req_certificate_verify_12_legacy_hash>
<out_certificate_verify_12_legacy> ::= <hs_certificate_verify> <hs_len> <cv12_algorithm_legacy_out> <cv12_sig_len_out> <cv12_signature_out>
where forall <e> in <out_certificate_verify_12_legacy>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<cv12_algorithm_legacy_out> ::= <signature_algorithm_12_legacy> := cv12_algorithm_legacy()
where forall <m> in <out_certificate_verify_12_legacy>: <m>.<cv12_signature_out> == client_cv12_signature(rb(<m>.<cv12_algorithm_legacy_out>))
where forall <m> in <out_certificate_verify_12_legacy>: <m>.<cv12_sig_len_out> == u(blen(<m>.<cv12_signature_out>), 2)
<req_client_key_exchange_rsa_after_real_certificate> ::= <req_client_key_exchange_rsa>
<req_client_key_exchange_rsa_after_certificate_url> ::= <req_client_key_exchange_rsa>
<req_client_key_exchange_dhe_after_certificate_url> ::= <req_client_key_exchange_dhe>
<req_client_key_exchange_dhe_after_real_certificate> ::= <req_client_key_exchange_dhe>
<req_certificate_verify_12_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_verify_12>
where forall <e> in <req_certificate_verify_12_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_verify_12_dhe> ::= <req_certificate_verify_12_rsa>
<out_certificate_verify_12> ::= <hs_certificate_verify> <hs_len> <cv12_algorithm_out> <cv12_sig_len_out> <cv12_signature_out>
where forall <e> in <out_certificate_verify_12>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<cv12_algorithm_out> ::= <signature_algorithm_12> := cv12_algorithm()
<cv12_sig_len_out> ::= <byte>{2}
<cv12_signature_out> ::= rb'[\x00-\xff]+'
where forall <m> in <out_certificate_verify_12>: <m>.<cv12_signature_out> == client_cv12_signature(rb(<m>.<cv12_algorithm_out>))
where forall <m> in <out_certificate_verify_12>: <m>.<cv12_sig_len_out> == u(blen(<m>.<cv12_signature_out>), 2)
# ---- a client certificate with a static Diffie-Hellman key (rsa_fixed_dh, RFC 5246 sections 7.4.4, 7.4.6) --------------------------------
# After a static-DH server flight whose CertificateRequest names rsa_fixed_dh the client may send a certificate that holds a DH key of the server's
# parameters (certified with RSA); its public value is then implicit: the ClientKeyExchange is sent and EMPTY (section 7.4.7.2) and no
# CertificateVerify follows (7.4.8: only a certificate with signing capability is verified)
<req_certificate_dh_12> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_dh_12>
where forall <e> in <req_certificate_dh_12>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_certificate_dh_12> ::= <hs_certificate> <hs_len> <cert_list_len_out> <cert_entry_12_dh>
where forall <e> in <out_certificate_dh_12>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
where forall <e> in <out_certificate_dh_12>: <e>.<cert_list_len_out> == u(blen(<e>) - 7, 3)
<cert_entry_12_dh> ::= <cert_len_out> <client_cert_der_12_dh>
where forall <e> in <cert_entry_12_dh>: <e>.<cert_len_out> == u(blen(<e>) - 3, 3)
<client_cert_der_12_dh> ::= rb'[\x00-\xff]+' := client_certificate_dh_12()
<req_client_key_exchange_implicit_12> ::= <ct_handshake> <rec_version> <rec_len> <out_client_key_exchange_implicit>
where forall <e> in <req_client_key_exchange_implicit_12>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_key_exchange_implicit> ::= <hs_client_key_exchange> b'\x00\x00\x00'
# the request that breaks 7.4.7.2: after a certificate with a DH key an explicit Yc (the ClientKeyExchange must be empty)
<req_client_key_exchange_explicit_after_dh_certificate> ::= <req_client_key_exchange_dhe>
<out_certificate_empty_12> ::= <hs_certificate> b'\x00\x00\x03' b'\x00\x00\x00'

# ChangeCipherSpec (section 7.1) and Finished (section 7.4.9)
<req_ccs_12> ::= <ct_change_cipher_spec> <rec_version> b'\x00\x01' b'\x01'
<req_finished_12> ::= <ct_handshake> <rec_version> <rec_len> <out_finished_12>
where forall <e> in <req_finished_12>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_finished_12> ::= <hs_finished> b'\x00\x00\x0c' <verify_data_12>
<verify_data_12> ::= rb'[\x00-\xff]{12}'
where forall <f> in <out_finished_12>: <f>.<verify_data_12> == client_finished_12()

# application data and alerts after the handshake (sections 6.2.3, 7.2)
<req_app_data_12> ::= <ct_application_data> <rec_version> <rec_len> <app_data> <out_padding_12>
where forall <e> in <req_app_data_12>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding_12>), 2)
# the padding of a block cipher record (RFC 5246 section 6.2.3.2) may be longer than the minimum: each zero byte here adds one block of padding
<out_padding_12> ::= <padding_zero>{0,6}
<req_alert_close_notify_12> ::= <ct_alert> <rec_version> b'\x00\x02' <level_warning> <ad_close_notify>
<req_alert_error_12> ::= <ct_alert> <rec_version> b'\x00\x02' <level_fatal> <alert_description_error_sent_12>

<req_alert_error_hs_12> ::= <req_alert_error_12>
<req_alert_close_notify_hs_12> ::= <req_alert_close_notify_12>
<req_alert_user_canceled_hs_12> ::= <ct_alert> <rec_version> b'\x00\x02' <level_warning> <ad_user_canceled>
<req_alert_close_notify_after_user_canceled_12> ::= <req_alert_close_notify_12>
# the same in one send (the two records), used while the server's flight is on its way
<req_alert_user_canceled_close_notify_hs_12> ::= <req_alert_user_canceled_hs_12> <req_alert_close_notify_12>

# a ClientHello on an established connection (RFC 5246 sections 7.3, 7.4.1.2): a new handshake; fresh random
<req_client_hello_renegotiation_12> ::= <ct_handshake> <rec_version> <rec_len> <out_client_hello_renegotiation_12>
where forall <e> in <req_client_hello_renegotiation_12>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_renegotiation_12> ::= <hs_client_hello> <hs_len> <client_hello_body_renegotiation_12>
where forall <e> in <out_client_hello_renegotiation_12>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_renegotiation_12> ::= <version_0303> <random_fresh> <session_id> <cipher_suites_vec_12> <compression_methods_12> (<ch_extensions_vec_12> | <ch_extensions_vec_12_versions_12>) | <version_0303> <random_fresh> <session_id> <cipher_suites_vec> <compression_methods> <ch_extensions_vec>
# the renegotiation ClientHello is a TLS 1.2 one (supported_versions of TLS 1.2 forms only) or a TLS 1.3 one (the shared ClientHello rules: suites,
# signature_algorithms, supported_groups, key_share, supported_versions 0x0304 and 0x0303): a server that negotiated TLS 1.2 keeps the version (RFC 9846 section 4.2.2, C3)
<random_fresh> ::= rb'[\x00-\xff]{32}'

<alert_description_error_sent_12> ::= <alert_description_error_sent_13> | <ad_decompression_failure>
# errors whose level the specification leaves open (RFC 5246 section 7.2.2): the sender may treat them as warnings, and the
# connection can then continue
<req_alert_warning_12> ::= <ct_alert> <rec_version> b'\x00\x02' <level_warning> <alert_description_warning_sent_12>
<alert_description_warning_sent_12> ::= <ad_bad_certificate> | <ad_unsupported_certificate> | <ad_certificate_revoked> | <ad_certificate_expired> | <ad_certificate_unknown>
# ==================================================================================================================
# TLS 1.2: received messages
# ==================================================================================================================
<ext_vec_len_in_nf> ::= rb'[\x00-\xfe][\x00-\xff]'

# ServerHello (section 7.4.1.3); the cipher suite is not a TLS 1.3 one, so this is no TLS 1.3 ServerHello
<in_server_hello_12> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_sh12_msg> <record_end>
where forall <e> in <in_server_hello_12>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_sh12_msg> ::= <hs_server_hello> <hs_len_in> <version_0303> <octet>{32} <session_id_in> <cipher_suite_12_other> <compression_null> <in_sh12_ext_vec>?
where forall <e> in <in_sh12_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_sh12_msg>: server_hello_12_ok(<m>)
# the same ServerHello when the suite is a static-DH one (DH_DSS, DH_RSA): the server then sends no ServerKeyExchange (section 7.4.3)
<in_server_hello_12_dh_static> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_sh12_msg_dh_static> <record_end>
where forall <e> in <in_server_hello_12_dh_static>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_sh12_msg_dh_static> ::= <hs_server_hello> <hs_len_in> <version_0303> <octet>{32} <session_id_in> <cipher_suite_12_static_dh> <compression_null> <in_sh12_ext_vec>?
where forall <e> in <in_sh12_msg_dh_static>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_sh12_msg_dh_static>: server_hello_12_ok(<m>)
<in_sh12_ext_vec> ::= <ext_vec_len_in_nf> <in_sh12_extension>*
where forall <e> in <in_sh12_ext_vec>: <e>.<ext_vec_len_in_nf> == u(blen(<e>) - 2, 2)
<in_sh12_extension> ::= <in_ext_sni_empty> | <in_ext_client_certificate_url_empty> | <in_ext_max_fragment_length> | <in_ext_status_request_empty> | <in_ext_alpn_ee> | <in_ext_trusted_ca_keys_empty> | <in_ext_truncated_hmac_empty> | <in_ext_other>
<in_ext_trusted_ca_keys_empty> ::= <ext_type_trusted_ca_keys> b'\x00\x00'
<in_ext_truncated_hmac_empty> ::= <ext_type_truncated_hmac> b'\x00\x00'
<in_ext_status_request_empty> ::= <ext_type_status_request> b'\x00\x00'

# Certificate (section 7.4.2): a list of ASN.1Cert
<in_certificate_12> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_certificate_12_msg> <record_end>
where forall <e> in <in_certificate_12>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_certificate_12_msg> ::= <hs_certificate> <hs_len_in> <in_cert12_list>
where forall <e> in <in_certificate_12_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_certificate_12_msg>: certificate_chain_ok(<m>, False)
<in_cert12_list> ::= <cert_list_len_in> <in_cert12_entry>*
where forall <e> in <in_cert12_list>: <e>.<cert_list_len_in> == u(blen(<e>) - 3, 3)
<in_cert12_entry> ::= <cert_data_len_in> <cert_data_in>

# ServerKeyExchange of a DHE_RSA suite (section 7.4.3): ServerDHParams and the signature over them
<in_server_key_exchange_dhe> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_ske_msg> <record_end>
where forall <e> in <in_server_key_exchange_dhe>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_ske_msg> ::= <hs_server_key_exchange> <hs_len_in> <dh_p_len_in> <dh_p_in> <dh_g_len_in> <dh_g_in> <dh_ys_len_in> <dh_ys_in> <signature_and_hash_12_in> <signature_len_in> <signature_in>
where forall <e> in <in_ske_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_ske_msg>: server_key_exchange_ok(<m>, False)
# ServerKeyExchange of a DH_anon suite: the ServerDHParams and no signature (section 7.4.3)
<in_server_key_exchange_anon> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_ske_anon_msg> <record_end>
where forall <e> in <in_server_key_exchange_anon>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_ske_anon_msg> ::= <hs_server_key_exchange> <hs_len_in> <dh_p_len_in> <dh_p_in> <dh_g_len_in> <dh_g_in> <dh_ys_len_in> <dh_ys_in>
where forall <e> in <in_ske_anon_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_ske_anon_msg>: server_key_exchange_ok(<m>, True)
<dh_p_len_in> ::= <byte>{2}
<dh_p_in> ::= <octet256>{uv(<dh_p_len_in>) // 256} <octet16>{(uv(<dh_p_len_in>) % 256) // 16} <octet>{uv(<dh_p_len_in>) % 16}
<dh_g_len_in> ::= <byte>{2}
<dh_g_in> ::= <octet256>{uv(<dh_g_len_in>) // 256} <octet16>{(uv(<dh_g_len_in>) % 256) // 16} <octet>{uv(<dh_g_len_in>) % 16}
<dh_ys_len_in> ::= <byte>{2}
<dh_ys_in> ::= <octet256>{uv(<dh_ys_len_in>) // 256} <octet16>{(uv(<dh_ys_len_in>) % 256) // 16} <octet>{uv(<dh_ys_len_in>) % 16}

# SignatureAndHashAlgorithm of TLS 1.2 (section 7.4.1.4.1): two enum(255) bytes, any pair is well-formed; what a server may name
# is checked in server_key_exchange_ok and certificate_request_12_ok
<signature_and_hash_12_in> ::= <octet>{2}

# CertificateStatus (RFC 6066 section 8): the server's OCSP response, after a status_request it echoed
<in_certificate_status> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cs_msg> <record_end>
where forall <e> in <in_certificate_status>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cs_msg> ::= <hs_certificate_status> <hs_len_in> <status_type_ocsp> <ocsp_len_in> <ocsp_response_in>
where forall <e> in <in_cs_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cs_msg>: certificate_status_ok(<m>)

# CertificateRequest (section 7.4.4).  The client's answer depends on whether it holds a certificate the request accepts (RFC 5246 sections 7.4.4,
# 7.4.6: the key type is one of certificate_types and every certificate is signed with a pair of supported_signature_algorithms; a server may
# name lists nothing fits): the same syntax is derived by a rule for each class, told apart by the where on the received message (request_class_12:
# u = a certificate fits, n = none, f = the types name rsa_fixed_dh and an RSA pair, so the party's own DH certificate fits).  The client answers a
# request of class n with the empty Certificate only.  <in_certificate_request_12> is class u or uf, _nu is class n or nf; the _sd rules are the
# four classes in a static-DH flight, where a DH certificate with the server's parameters is an answer of its own (7.4.7.2).
<in_certificate_request_12> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr12_msg> <record_end>
where forall <e> in <in_certificate_request_12>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr12_msg> ::= <hs_certificate_request> <hs_len_in> <cr12_types_len_in> <client_certificate_type>{uv(<cr12_types_len_in>)} <cr12_algs_len_in> <signature_and_hash_12_in>{uv(<cr12_algs_len_in>)//2} <cr12_cas_len_in> <cr12_cas_in>
where forall <e> in <in_cr12_msg>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr12_msg>: certificate_request_12_ok(<m>)
where forall <m> in <in_cr12_msg>: request_class_12(<m>) in ("u", "uf")
<in_certificate_request_12_nu> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr12_msg_nu> <record_end>
where forall <e> in <in_certificate_request_12_nu>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr12_msg_nu> ::= <hs_certificate_request> <hs_len_in> <cr12_types_len_in> <client_certificate_type>{uv(<cr12_types_len_in>)} <cr12_algs_len_in> <signature_and_hash_12_in>{uv(<cr12_algs_len_in>)//2} <cr12_cas_len_in> <cr12_cas_in>
where forall <e> in <in_cr12_msg_nu>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr12_msg_nu>: request_class_12(<m>) in ("n", "nf")
<in_certificate_request_12_sd_u> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr12_msg_sd_u> <record_end>
where forall <e> in <in_certificate_request_12_sd_u>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr12_msg_sd_u> ::= <hs_certificate_request> <hs_len_in> <cr12_types_len_in> <client_certificate_type>{uv(<cr12_types_len_in>)} <cr12_algs_len_in> <signature_and_hash_12_in>{uv(<cr12_algs_len_in>)//2} <cr12_cas_len_in> <cr12_cas_in>
where forall <e> in <in_cr12_msg_sd_u>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr12_msg_sd_u>: request_class_12(<m>) == "u"
<in_certificate_request_12_sd_n> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr12_msg_sd_n> <record_end>
where forall <e> in <in_certificate_request_12_sd_n>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr12_msg_sd_n> ::= <hs_certificate_request> <hs_len_in> <cr12_types_len_in> <client_certificate_type>{uv(<cr12_types_len_in>)} <cr12_algs_len_in> <signature_and_hash_12_in>{uv(<cr12_algs_len_in>)//2} <cr12_cas_len_in> <cr12_cas_in>
where forall <e> in <in_cr12_msg_sd_n>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr12_msg_sd_n>: request_class_12(<m>) == "n"
<in_certificate_request_12_sd_uf> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr12_msg_sd_uf> <record_end>
where forall <e> in <in_certificate_request_12_sd_uf>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr12_msg_sd_uf> ::= <hs_certificate_request> <hs_len_in> <cr12_types_len_in> <client_certificate_type>{uv(<cr12_types_len_in>)} <cr12_algs_len_in> <signature_and_hash_12_in>{uv(<cr12_algs_len_in>)//2} <cr12_cas_len_in> <cr12_cas_in>
where forall <e> in <in_cr12_msg_sd_uf>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr12_msg_sd_uf>: request_class_12(<m>) == "uf"
<in_certificate_request_12_sd_nf> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_cr12_msg_sd_nf> <record_end>
where forall <e> in <in_certificate_request_12_sd_nf>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_cr12_msg_sd_nf> ::= <hs_certificate_request> <hs_len_in> <cr12_types_len_in> <client_certificate_type>{uv(<cr12_types_len_in>)} <cr12_algs_len_in> <signature_and_hash_12_in>{uv(<cr12_algs_len_in>)//2} <cr12_cas_len_in> <cr12_cas_in>
where forall <e> in <in_cr12_msg_sd_nf>: <e>.<hs_len_in> == u(blen(<e>) - 4, 3)
where forall <m> in <in_cr12_msg_sd_nf>: request_class_12(<m>) == "nf"
<cr12_types_len_in> ::= <octet>
<cr12_algs_len_in> ::= <octet>{2}
<cr12_cas_len_in> ::= <octet>{2}
<cr12_cas_in> ::= <octet256>{uv(<cr12_cas_len_in>) // 256} <octet16>{(uv(<cr12_cas_len_in>) % 256) // 16} <octet>{uv(<cr12_cas_len_in>) % 16}
<client_certificate_type> ::= <cct_rsa_sign> | <cct_dss_sign> | <cct_rsa_fixed_dh> | <cct_dss_fixed_dh> | <cct_rsa_ephemeral_dh_reserved> | <cct_dss_ephemeral_dh_reserved> | <cct_fortezza_dms_reserved> | <cct_other>
# values the specification does not define (e.g. ecdsa_sign of RFC 8422)
<cct_other> ::= rb'(?!\x01|\x02|\x03|\x04|\x05|\x06|\x14)[\x00-\xff]'

# ServerHelloDone (section 7.4.5)
<in_server_hello_done> ::= <in_server_hello_done_msg> <record_end>
<in_server_hello_done_msg> ::= <ct_handshake> <rec_version_in> b'\x00\x04' <hs_server_hello_done> b'\x00\x00\x00'
where forall <m> in <in_server_hello_done_msg>: server_hello_done_ok(<m>)
# HelloRequest (section 7.4.1.1)
<in_hello_request> ::= <ct_handshake> <rec_version_in> b'\x00\x04' <hs_hello_request> b'\x00\x00\x00' <record_end>

# Finished (section 7.4.9): verify_data has 12 bytes
<in_finished_12> ::= <ct_handshake> <rec_version_in> <rec_len_in> <in_finished_12_msg> <record_end>
where forall <e> in <in_finished_12>: <e>.<rec_len_in> == u(blen(<e>) - 7, 2)
<in_finished_12_msg> ::= <hs_finished> b'\x00\x00\x0c' <verify_data_in_12>
<verify_data_in_12> ::= <octet>{12}
where forall <m> in <in_finished_12_msg>: server_finished_12_ok(rb(<m>)[4:])

# alerts of TLS 1.2 (section 7.2): the error alerts are fatal; an alert whose level the specification leaves to the sender
# may be a warning, after which the connection goes on (section 7.2.2); close_notify and user_canceled are warnings
<in_alert_12_fatal> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_fatal> <alert_description_error_12_in> <record_end>
# any description but the closure alerts and no_renegotiation (always a warning): unknown alerts are errors too (RFC 5246 section 7.2)
<alert_description_error_12_in> ::= rb'(?!\x00|\x5a|\x64|\x15|\x29|\x3c)[\x00-\xff]'
<in_alert_12_warning> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_warning> <alert_description_warning_12> <record_end> | <in_alert_user_canceled_warning>
<in_alert_user_canceled_warning> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_warning> <ad_user_canceled> <record_end>
<in_alert_user_canceled_fatal> ::= <ct_alert> <rec_version_in> b'\x00\x02' <alert_level_not_warning_in> <ad_user_canceled> <record_end>
<alert_level_not_warning_in> ::= rb'[\x00\x02-\xff]'

<in_alert_12_no_renegotiation> ::= <ct_alert> <rec_version_in> b'\x00\x02' <level_warning> <ad_no_renegotiation> <record_end>
# the alerts of RFC 5246 section 7.2.2 that are not fatal-only (and the ones of RFC 6066 section 9): they may be warnings
<alert_description_warning_12> ::= <ad_unrecognized_name> | <ad_bad_certificate> | <ad_unsupported_certificate> | <ad_certificate_revoked> | <ad_certificate_expired> | <ad_certificate_unknown> | <ad_certificate_unobtainable> | <ad_bad_certificate_status_response> | <ad_bad_certificate_hash_value>

# ==================================================================================================================
# TLS 1.2: functions of the constraints and generators
# ==================================================================================================================
def tls12_state():
    state = session_state()
    return state if state is not None and state.version == 0x0303 else None


def client_finished_12():
    state = tls12_state()
    if state is None or state.master_secret is None:
        return bytes(12)
    return state.finished_verify_data("C", first_finished_index(state, "C"))


def server_finished_12_ok(value):
    state = tls12_state()
    if state is None or state.master_secret is None:
        return True
    index = first_finished_index(state, "S")
    return index is None or state.finished_verify_data("S", index) == value


def encrypted_pre_master_secret_value():
    state = tls12_state()
    if state is None or state.server_certificate is None:
        return os.urandom(256)
    return clean(lambda: encrypt_pre_master_secret(state.server_certificate))


def dh_client_public_value():
    state = tls12_state()
    if state is None or state.dh_params is None:
        return os.urandom(256)
    return clean(lambda: new_dh_share(state.dh_params[0], state.dh_params[1]))

<req_app_data_12_half> ::= <req_app_data_12>
<req_alert_close_notify_half_12> ::= <req_alert_close_notify_12>
# the answer to a HelloRequest the client does not want to act on (RFC 5246 sections 7.2.2, 7.4.1.1)
<req_alert_no_renegotiation_12> ::= <ct_alert> <rec_version> b'\x00\x02' <level_warning> <ad_no_renegotiation>

<req_app_data_12_split> ::= <req_app_data_12> <req_app_data_12_second>
<req_app_data_12_second> ::= <req_app_data_12>

# A TLS 1.2 ClientHello that leaves out signature_algorithms (RFC 5246 section 7.4.1.4.1: the server then assumes the default
# pair of the key exchange; RFC 9846 section 4.3.3: TLS 1.2 ClientHellos MAY omit the extension): the extensions field absent, empty,
# or without signature_algorithms.  RFC 9155 section 2 (MUST include) conflicts with both, which makes the requirement's bindingness
# unsettled; the ServerKeyExchange check accepts the SHA-1 default pair of RFC 5246 for such a hello (server_key_exchange_ok), so every
# suite the party completes is offered (one to three of them).
<req_client_hello_12_default> ::= b'\x16' <rec_version_initial> <rec_len> <out_client_hello_12_default>
where forall <e> in <req_client_hello_12_default>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<out_client_hello_12_default> ::= <hs_client_hello> <hs_len> <client_hello_body_12_default>
where forall <e> in <out_client_hello_12_default>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
<client_hello_body_12_default> ::= <version_0303> <random_bytes> <session_id> <cipher_suites_vec_12_default> <compression_methods_12> <ch_extensions_12_default>
<cipher_suites_vec_12_default> ::= <vec_len16> <cipher_suite_12_completable>{1,3}
where forall <e> in <cipher_suites_vec_12_default>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_extensions_12_default> ::= <ch_extensions_none_12> | <ch_extensions_vec_12_default>
<ch_extensions_none_12> ::= b'' | b'\x00\x00'
<ch_extensions_vec_12_default> ::= <vec_len16> <ch_ext_list_12_default>
where forall <e> in <ch_extensions_vec_12_default>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<ch_ext_list_12_default> ::= <ext_sni>? <ext_max_fragment_length>? <ext_trusted_ca_keys>? <ext_truncated_hmac>? <ext_status_request>? <ext_signature_algorithms_cert>? <ext_alpn>? <ext_client_certificate_url>? <ext_unknown>?

# client_certificate_url (RFC 6066 section 5): negotiation only (the CertificateURL message needs the server's echo)
<ext_client_certificate_url> ::= <ext_type_client_certificate_url> b'\x00\x00'
<in_ext_client_certificate_url_empty> ::= <ext_type_client_certificate_url> b'\x00\x00'

<req_app_data_12_large> ::= <ct_application_data> <rec_version> <rec_len> <app_data_large> <out_padding_12>
where forall <e> in <req_app_data_12_large>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding_12>), 2)
# the TLS 1.2 form of the request that breaks RFC 6066 section 4 (see <req_app_data_13_overflow>)
<req_app_data_12_overflow> ::= <ct_application_data> <rec_version> <rec_len> <app_data_overflow> <out_padding_12>
where forall <e> in <req_app_data_12_overflow>: <e>.<rec_len> == u(blen(<e>) - 5 - blen(<e>.<out_padding_12>), 2)


# CertificateURL (RFC 6066 section 5): the client sends it instead of Certificate to name where its certificates can be fetched
# (the server fetches them, which is its exchange with a third party).  A server that did not echo client_certificate_url answers
# with unexpected_message, one that cannot fetch the URL with certificate_unobtainable or bad_certificate_hash_value.
<req_certificate_url_12_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_url_12>
where forall <e> in <req_certificate_url_12_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_url_12_dhe> ::= <req_certificate_url_12_rsa>
<out_certificate_url_12> ::= <hs_certificate_url> <hs_len> ( <cct12_individual_certs> <url_and_hash_list_vec> | <cct12_pkipath> <url_and_hash_list_vec_one> )
where forall <e> in <out_certificate_url_12>: <e>.<hs_len> == u(blen(<e>) - 4, 3)
# URLAndHash url_and_hash_list<1..2^16-1>; a pkipath list has exactly one entry
<url_and_hash_list_vec> ::= <vec_len16> <url_and_hash>{1,3}
where forall <e> in <url_and_hash_list_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<url_and_hash_list_vec_one> ::= <vec_len16> <url_and_hash>
where forall <e> in <url_and_hash_list_vec_one>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<url_and_hash> ::= <url_vec> b'\x01' <sha1_hash_20>
<url_vec> ::= <vec_len16> <url_bytes>
where forall <e> in <url_vec>: <e>.<vec_len16> == u(blen(<e>) - 2, 2)
<url_bytes> ::= rb'http://[a-z0-9.]{1,30}/[a-z0-9]{1,16}[.]cer'


# several handshake messages in one record (RFC 5246 section 6.2.1: handshake messages may be coalesced): the client's Certificate
# and its ClientKeyExchange (neither value depends on the other, unlike CertificateVerify, which signs both)
<req_certificate_cke_12_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_12> <out_client_key_exchange_rsa>
where forall <e> in <req_certificate_cke_12_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_cke_12_dhe> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_12> <out_client_key_exchange_dhe>
where forall <e> in <req_certificate_cke_12_dhe>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_empty_cke_12_rsa> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_empty_12> <out_client_key_exchange_rsa>
where forall <e> in <req_certificate_empty_cke_12_rsa>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_certificate_empty_cke_12_dhe> ::= <ct_handshake> <rec_version> <rec_len> <out_certificate_empty_12> <out_client_key_exchange_dhe>
where forall <e> in <req_certificate_empty_cke_12_dhe>: <e>.<rec_len> == u(blen(<e>) - 5, 2)

# a handshake message fragmented over records (RFC 5246 section 6.2.1): the Finished header in the first record, verify_data in the second
<req_finished_12_fragmented> ::= <req_finished_12_head> <req_finished_12_tail>
<req_finished_12_head> ::= <ct_handshake> <rec_version> <rec_len> <hs_finished> b'\x00\x00\x0c'
where forall <e> in <req_finished_12_head>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<req_finished_12_tail> ::= <ct_handshake> <rec_version> <rec_len> <verify_data_12_frag>
where forall <e> in <req_finished_12_tail>: <e>.<rec_len> == u(blen(<e>) - 5, 2)
<verify_data_12_frag> ::= rb'[\x00-\xff]{12}'
where forall <f> in <req_finished_12_fragmented>: <f>..<verify_data_12_frag> == client_finished_12()

# user_canceled once connected (RFC 5246 sections 7.2.1, 7.2.2: a warning, followed by close_notify)
<req_alert_user_canceled_12> ::= <req_alert_user_canceled_hs_12>
<req_alert_close_notify_after_user_canceled_conn_12> ::= <req_alert_close_notify_12>
<req_alert_user_canceled_close_notify_12> ::= <req_alert_user_canceled_12> <req_alert_close_notify_after_user_canceled_conn_12>

# a warning-level alert about the server's certificate during the handshake (RFC 5246 section 7.2.2): the handshake goes on
<req_alert_warning_hs_12> ::= <req_alert_warning_12>

# ==================================================================================================================
# Omissions (each with the spec section and the nearest nonterminal)
# ==================================================================================================================
# TODO: forms of the client's certificates left out (RFC 9846 sections 4.4.2, 4.4.3; RFC 5246 sections 7.4.6, 7.4.8): the party sends its own RSA-3072, RSASSA-PSS, ECDSA P-256/384/521, Ed25519 and Ed448 certificates (signed by its RSA key, by the CA of the setting, by an intermediate CA of its own, by themselves, or the credential of the setting TLS_CLIENT_CERT), as a chain of one to three certificates (end entity and CA, or end entity, intermediate and root: <cert_list_out>, <out_certificate_12>), and, in TLS 1.3, the CertificateEntry extensions the request asks for (the status_request answer: a CertificateStatus with an OCSPResponse the party signs as the CA of its certificates, <cert_entry_ext_out>), left out: chains of four or more certificates and chains that do not lead to the party's own CA or the setting's CA (the servers answer an untrusted chain with an alert, which every state accepts, so they gain no state), DSA keys (RFC 9846 section 4.2.3: MUST NOT) and dss_fixed_dh certificates (a DH key certified with DSA; the party's CA signs with RSA: see the TODO at <req_certificate_dh_12>), entry extensions other than status_request (signed_certificate_timestamp is RFC 6962, which the manifest leaves out) - nearest nonterminal <client_cert_der>.
# TODO: PSK handshakes with a valid ticket or external PSK, 0-RTT data and EndOfEarlyData (RFC 9846 sections 2.2, 2.3, 4.2.10, 4.2.11, 4.5): they need a PSK from an EARLIER connection (a session is one connection); the grammar offers one bogus PSK (a random identity and binders, optionally with early_data) as the one alternative per request type with the refusal the specification defines (a full handshake), accepts the refusal, and rejects a ServerHello that selects the PSK: a client that really supports what it advertises here (RFC 9846 section 9.3: a client MUST support all non-GREASE parameters it advertises) needs the PSK of an earlier connection - nearest nonterminal <ext_pre_shared_key>.
# TODO: use of NewSessionTicket (resumption, ticket age, SNI match; RFC 9846 sections 4.6.1, 4.2.11.1): needs a second connection - nearest nonterminal <in_new_session_ticket>.
# TODO: finite-field DHE key shares (RFC 9846 section 4.2.8.1): the group primes are defined in RFC 7919, which the manifest leaves out, so no share can be computed (the ffdhe code points are offered in supported_groups) - nearest nonterminal <ng_ffdhe2048>.
# TODO: forms of the first ClientHello that get a second ClientHello (RFC 9846 sections 4.1.2, 4.2.2): the second ClientHello is built from grammar rules (<req_client_hello_after_hrr>, <req_client_hello_after_hrr_cookie>, <req_client_hello_after_hrr_cookie_only>: legacy_version, random, legacy_session_id, cipher_suites, compression_methods and the extensions vector, with the shared extension rules; the key_share is the rule <ext_key_share_2> with one entry for the selected group (the first message's empty list again after a cookie-only HelloRetryRequest), the cookie the rule <ext_cookie_2> after it, early_data and pre_shared_key do not occur) for the first ClientHello <req_client_hello_hrr> only, whose cipher suites, supported_versions, signature_algorithms and supported_groups are one fixed form of the shared constants (repeated by construction) and whose random, legacy_session_id and host name the second message recalls through generators on those leaves (random_value, session_id_value, host_name_value; the cookie through hrr_cookie_value); left out: a second ClientHello for every other first ClientHello (<req_client_hello>, <req_client_hello_13_only>): after a HelloRetryRequest to them the client ends the handshake with an alert (<state_after_hrr_general>), because their lists (suites, groups, signature schemes, ALPN names, certificate_authorities, PSK identities) and the presence of their optional extensions are chosen by the grammar's alternatives, which a generator cannot repeat in a rule of the second message; in the class itself an empty legacy_session_id, the key_share with a share in the first message, ALPN, status_request and the other optional extensions, a changed padding and updated PSK binders / obfuscated ticket age, and a HelloRetryRequest that selects a group the party cannot generate a share for - nearest nonterminal <req_client_hello_after_hrr>.
# TODO: ClientHellos that violate mandatory requirements of the sender and the servers' alerts (RFC 9846 sections 4.2.11, 9.2, 4.2.1, 4.3.1; RFC 9155 section 2): missing supported_versions/signature_algorithms/key_share, pre_shared_key not last, a supported_versions list without TLS 1.3 from a client that offers TLS 1.3 suites, (the requirements of RFC 9155 section 2 are broken by their own requests: <req_client_hello_12_legacy_hash>, a TLS 1.2 ClientHello whose signature_algorithms holds an MD5 or SHA-1 pair, and <req_certificate_verify_12_legacy_hash>, a CertificateVerify with such a pair; the requirement of RFC 6066 section 4 to fragment by <req_app_data_13_overflow> and <req_app_data_12_overflow>, an oversized record where a maximum fragment length is negotiated; the requirement of RFC 9846 section 4.5.1.2 that the client's end-entity certificate match the recognized extension OIDs of an oid_filters extension by <req_certificate_13_filter_breach>, a Certificate without the Key Usage / Extended Key Usage extension that the filter names; the two sender requirements of RFC 9846 section 4.6.3 (a sender MUST NOT send another update_requested until it has received a KeyUpdate from the peer; the receiver of update_requested MUST send its own KeyUpdate prior to its next application data) by <req_key_update_requested_twice>, a second update_requested (<req_key_update_requested_again>) in the same send as the first (<exch_key_update_requested_again>), and <req_app_data_13_unanswered>, application data without the owed answer (<exch_app_data_13_unanswered>, reached through <owed_answer_13> from every position in which a server's update_requested is answered between exchanges: <server_initiated_13> and <replies_app_data_13>)) - the grammar produces no other message that breaks a mandatory requirement of the sender (the TLS 1.2 ClientHello without signature_algorithms is sent as <req_client_hello_12_default>: RFC 9846 section 4.2.3 lets a TLS 1.2 ClientHello omit it) - nearest nonterminal <req_client_hello>.
# TODO: other no-overlap ClientHellos (RFC 9846 section 4.2.1): only <req_client_hello_no_overlap> (supported_groups without a common group and without key_share) is sent; the variants with no common cipher suite or no common signature algorithm use values this grammar treats as reserved, and the tested servers answer all of them with the same alert - nearest nonterminal <req_client_hello_no_overlap>.
# TODO: handshake forms of the record layer left out (RFC 9846 sections 5.1, 5.2, 5.3; RFC 5246 section 6.2.1): sent are the TLS 1.3 Finished fragmented over two records (<req_finished_13_fragmented>), the TLS 1.2 Finished fragmented (<req_finished_12_fragmented>), the TLS 1.2 Certificate and ClientKeyExchange in one record (<req_certificate_cke_12_rsa>, <req_certificate_cke_12_dhe>, the empty-Certificate forms), split and large application data, and records of every size up to the negotiated max_fragment_length and 6000 bytes (records up to the 2^14 of RFC 9846 section 5.2 are left out: the parser of Fandango needs longer than the 6 s timer for the echo of a 16000-byte record, which wolfSSL sends back); left out: a ClientHello fragmented over records, several TLS 1.3 handshake messages in one record (Certificate and CertificateVerify, whose signature covers the Certificate, and the TLS 1.2 CertificateVerify, which signs ClientKeyExchange: the equalities read the transcript, which holds a message once it has been sent), records with a corrupted tag, sequence number wrap; received records are reassembled by the party, and interleaving and key-change boundary violations are rejected (ClientNetworkParty._incoming) - nearest nonterminal <req_finished_13>.
# TODO: alerts of the client (RFC 9846 section 6; RFC 5246 section 7.2): every position has its own alert exchange: while the client waits for the server's flight (WAIT_SH after the first and the second ClientHello, WAIT_EE, WAIT_CERT_CR, WAIT_CERT, WAIT_CV, WAIT_FINISHED, and the TLS 1.2 flight up to the ServerHelloDone: <exch_alert_flight_13_*>, <exch_alert_flight_12_*>, generated by tools/gen_flight.py: the messages of the flight already on their way are accepted in the order of the flight, each at most once, before the alert (<fa13_*>, <fa12_*>) or after it (<fb13_*>, <fb12_*>)), at the client's own turns (<exch_alert_handshake_13_*>, <exch_alert_handshake_12_*>); and right after the client's own Certificate, CertificateVerify, ClientKeyExchange and ChangeCipherSpec (<exch_alert_after_own_13> in <state_after_empty_certificate>, <state_after_certificate>, <state_after_certificate_verify>, ended by the ticket timer that already runs; <exch_alert_handshake_12_after_*> and <exch_alert_handshake_12_before_ccs> in the TLS 1.2 states after the client's messages: one client message per alternative, as the message next to it, and the server's closure accepted after it, so the server's immediate rejection, wolfSSL's within a millisecond, is the reply it accepts); left out: server messages after the server's Finished inside the alert exchange of the flight (NewSessionTicket, 0.5-RTT data, KeyUpdate: the server sends them after the client's Finished, which the exchange has not sent) - nearest nonterminal <state_wait_server_flight>.
# TODO: the extensions and suites of specifications the manifest leaves out are accepted by generic fallbacks only and never sent: ECC suites and curves (RFC 8422), AEAD suites (RFC 5288, RFC 7905), session tickets (RFC 5077), extended master secret (RFC 7627), renegotiation_info (RFC 5746), record_size_limit (RFC 8449), raw public keys (RFC 7250), certificate compression (RFC 8879), ECH (RFC 9849), SCT, heartbeat, padding, use_srtp (RFC 6962, 6520, 7685, 5764); the reserved extension type, cipher suite, group and version values of <grease_16> stand in for them - nearest nonterminal <in_ext_other>.
# TODO: the server's fetch of the certificates behind a CertificateURL (RFC 6066 section 5) is its exchange with a third party; the client sends the message (<req_certificate_url_12_rsa>, <req_certificate_url_12_dhe>: both chain types, URLAndHash lists) in place of Certificate after a TLS 1.2 CertificateRequest, whether or not the server echoed client_certificate_url, and accepts the server's alert (unexpected_message, certificate_unobtainable, bad_certificate_hash_value) or ends the handshake with an alert; it has no key for the certificates behind the URL, so no CertificateVerify follows - nearest nonterminal <hs_certificate_url>.
# TODO: the semantics of OCSP responses and certificate extensions beyond the checks of certificate_chain_ok and certificate_13_ok (RFC 6960, RFC 5280): the OCSP response is carried opaque (<ocsp_response_in>), so the client's bad_certificate_status_response abort is sent only as an alert at the turns of the client - nearest nonterminal <ocsp_response_in>.
# TODO: TLS 1.2 abbreviated handshakes (session resumption by session id, RFC 5246 section 7.3): need a session of an EARLIER connection - nearest nonterminal <state_client_finish_12>.
# TODO: TLS 1.2 renegotiation beyond its refusal (RFC 5246 sections 7.3, 7.4.1.1; RFC 9846 section 4.2.2): <exch_renegotiation_12> sends the renegotiation ClientHello (without supported_versions, and with supported_versions that lists TLS 1.3 and TLS 1.2) and accepts the refusals (no_renegotiation, a fatal alert, the close); a ServerHello that accepts it would start a second handshake whose keys and transcript the party does not model (a TLS 1.3 ServerHello in it is no reply of the exchange: a violation), and secure renegotiation needs RFC 5746, which the manifest leaves out - nearest nonterminal <exch_renegotiation_12>.
# TODO: dss_fixed_dh client certificates (RFC 5246 sections 7.4.4, 7.4.6): the client's DH certificate (<req_certificate_dh_12>, rsa_fixed_dh, with the implicit empty ClientKeyExchange <req_client_key_exchange_implicit_12> and no CertificateVerify, and the one request that breaks section 7.4.7.2, <req_client_key_exchange_explicit_after_dh_certificate>) is certified with RSA; a DH key certified with DSA (dss_fixed_dh) is left out because the party's CA signs with RSA and DSA signing would need a DSA key and CA of its own - nearest nonterminal <req_certificate_dh_12>. The static-DH flights are reached only when a server selects a DH_DSS/DH_RSA suite (none of the tested servers does), so the paths are tested offline (scratch/t6dh.py).
# TODO: TLS 1.0, 1.1 and SSL (RFC 2246, RFC 4346, RFC 8996 are not in the manifest) - nearest nonterminal <version_0301>.
# TODO: the server states of RFC 9846 appendix A.2: the tested party is the client; the server's view is observed through its messages (NEGOTIATED, WAIT_CERT, WAIT_CV, WAIT_FINISHED of the server correspond to the client's messages in <state_client_finished>, <state_client_auth>) - nearest nonterminal <state_start>.
# TODO: server_name with several entries or other name types, and trusted_ca_keys contents beyond the four identifier types (RFC 6066 sections 3, 6): only host_name exists - nearest nonterminal <ext_sni>.
# TODO: a ChangeCipherSpec of TLS 1.2 whose value is not 1, and records of other types in TLS 1.2 states (RFC 5246 section 7.1) - nearest nonterminal <req_ccs_12>.
# TODO: forms left out of the ClientHello where the grammar narrows a shared rule (RFC 9846 sections 4.2.1, 4.2.3, 4.2.7, 4.2.8, 4.3.3): the groups lists put the groups a key share is sent for first or hold only that group (a server picks the first common group; another order makes it send a HelloRetryRequest, which is answered with the second ClientHello; OpenSSL ranks the groups by tuples of its own, so a list that holds a second group for which no share is sent gets a HelloRetryRequest), the shares are x25519, secp256r1, secp384r1, secp521r1 (alone or beside another), three shares, or x25519 and one more group (x448 or an unknown group: a share for x448 alone is answered by wolfSSL with a HelloRetryRequest); finite-field groups appear in supported_groups only (RFC 7919 is not in the manifest); signature_algorithms always hold an RSASSA-PSS scheme (the tested servers hold an RSA certificate and answer handshake_failure otherwise) and rsa_pkcs1_sha256 (the TLS 1.2 membership check of every server certificate needs it), may hold a private-use scheme, and hold the legacy rsa_pkcs1_sha1/ecdsa_sha1 only in the ClientHello of a TLS 1.3-only client (<req_client_hello_13_only>: RFC 9846 section 4.3.3 allows them as the lowest priority; RFC 9155 forbids them for a client that offers TLS 1.2); MD5/SHA-224/DSA pairs are left out (RFC 9846 section 4.3.3 MUST NOT); signature_algorithms_cert always holds rsa_pkcs1_sha256 (a server whose certificate is signed otherwise answers handshake_failure) and may hold the legacy schemes last; supported_versions lists TLS 1.3 and TLS 1.2 (and reserved values) in a ClientHello that offers both, TLS 1.3 alone in the ClientHello of a TLS 1.3-only client; the TLS 1.3 suite list holds the five suites of RFC 9846 appendix B.4 in several combinations - nearest nonterminal <ch_groups_and_shares>.
# TODO: supported_versions forms left out (RFC 9846 section 4.2.1; RFC 9846 section 9.2): a list without 0x0304 beside TLS 1.3 suites, and a list of unknown or reserved versions only, are not sent: a TLS 1.3 ClientHello lists every version the client is prepared to negotiate, at least 0x0304 (RFC 9846 section 4.3.1), and the party supports TLS 1.2 and TLS 1.3 only; lists that hold 0x0303 and no 0x0304 are sent by the TLS 1.2 ClientHello (<ext_supported_versions_12>), so the server's choice of TLS 1.2 from supported_versions is tested; TLS 1.0 and 1.1 are left out (see above) - nearest nonterminal <versions_list>.
# TODO: forms left out of the TLS 1.2 ClientHello (RFC 5246 sections 7.4.1.2, 7.4.1.4.1, 7.4.2): the cipher suite list holds only suites the party completes (RSA, DHE_RSA, DHE_DSS, DH_anon with AES-CBC, 3DES-CBC, RC4 and NULL), the signature_algorithms list always holds rsa_pkcs1_sha256 (the tested servers' certificates are signed with it) except in <req_client_hello_12_default>, the ClientHello without signature_algorithms (RFC 9155 section 2 and RFC 5246 section 7.4.1.4.1 conflict, so the form is sent and the SHA-1 default pair is accepted in the ServerKeyExchange); one to three suites per list, compression_methods always hold null, other values are private-use - nearest nonterminal <cipher_suite_list_12>.
# TODO: ProtocolNameList (RFC 7301 section 3.1) with more than 3 names: the sent list holds 1 to 3 names (lists up to 2^16-1 bytes are left out; a list of up to 3 names already shows the server selecting among several names, one name, or none it supports); every name of the list is the shared ProtocolName rule (opaque<1..2^8-1>) narrowed only by the choice of its octets (a name of the setting ALPN_PROTOCOLS or arbitrary octets) - nearest nonterminal <protocol_name_list>.
# TODO: a ClientHello that breaks the requirement of RFC 7301 section 3.1 ("Empty strings MUST NOT be included and byte strings MUST NOT be truncated") - no breaking request: the sent ProtocolNameList meets the requirement by construction (<protocol_name> is a length byte of 1..255 and exactly that many octets, <protocol_name_list> holds one to three names). The reaction to a list that breaks it, the decode_error alert of RFC 9846 section 6.2, is mandatory only for a server that parses the ALPN extension. ALPN is optional (RFC 7301 section 3.1: the server MAY respond with a ProtocolName; RFC 9846 section 4.2: a server MUST ignore extensions it does not implement), and a server that ignores the extension answers with a ServerHello or HelloRetryRequest. Whether the server processes ALPN is a property that the ClientHello does not show; the ClientHello is a first message, so no earlier message of the session can show it, and a HelloRetryRequest cannot carry ALPN, so it is not shown before a second ClientHello either (a setting of the test setup, ALPN_PROTOCOLS, does not count). The requirement therefore holds in no state in which the client sends a ClientHello, no request breaks it, and every state after a ClientHello accepts every reply the spec allows - nearest nonterminal <protocol_name_list>.
# TODO: a DistinguishedName (RFC 5280 X.501 Name) of the certificate_authorities extension is built from C, O, OU, CN, L, ST and DC attributes (single-valued RDNs, at most four, X.520 upper bounds respected, so no long-form lengths); other attribute types, BMPString names and multi-valued RDNs (whose DER order the encoder would have to sort) are left out - nearest nonterminal <dn_der>.
# TODO: unrecognized_name (RFC 6066 sections 3, 9) is an alert of the server's; the client never sends it - nearest nonterminal <alert_description_error_sent>.
