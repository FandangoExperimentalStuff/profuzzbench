# File Transfer Protocol (RFC 959 with RFC 1123 4.1, 854 (NVT), 2228, 2389, 2428, 2640, 3659, 4217, 7151)
# Fandango plays the party `Client`; the tested FTP server is the party `Server` (control connection only).
#
# ---------------------------------------------------------------------------------------------------------------
# TEST SETUP: everything the test setup decides is configured here, each value from an environment variable.
# ---------------------------------------------------------------------------------------------------------------
import os
import random

def _env_list(name, default):
    return [item for item in os.environ.get(name, default).split(",") if item != ""]

# credentials the servers accept (the accepting login exchange sends only these)
FTP_USER = os.environ.get("FTP_USER", "ftpuser")
FTP_PASS = os.environ.get("FTP_PASS", "ftppass")
FTP_ACCT = os.environ.get("FTP_ACCT", "ftpacct")
# targets a request addresses; each session picks from these lists (the server setups provide these entries)
FTP_FILES = _env_list("FTP_FILES", "hello.txt,subdir/a.txt")
FTP_DIRS = _env_list("FTP_DIRS", "subdir,/,.,..")
FTP_NEW_NAMES = _env_list("FTP_NEW_NAMES", "newdir,renamed.txt,tmp1")
FTP_VIRTUAL_HOSTS = _env_list("FTP_VIRTUAL_HOSTS", "localhost,example.com,127.0.0.1,192.0.2.1,[2001:db8::1]")
FTP_SITE_ARGS = _env_list("FTP_SITE_ARGS", "HELP,UMASK,CHMOD 644 hello.txt,IDLE 600")
FTP_LANGUAGE_TAGS = _env_list("FTP_LANGUAGE_TAGS", "en,en-US,de,fr")
FTP_AUTH_MECHANISMS = _env_list("FTP_AUTH_MECHANISMS", "TLS,GSSAPI,KERBEROS_V4")
FTP_OPTS_ARGS = _env_list("FTP_OPTS_ARGS", "UTF8 ON,UTF8 OFF,UTF8,NLST -a,MODE S")
FTP_HELP_ARGS = _env_list("FTP_HELP_ARGS", "USER,SITE,RETR")
# address family numbers other than 1 (IPv4) and 2 (IPv6) that EPSV asks for (RFC 2428 3: the server answers 522 for an unsupported one)
FTP_OTHER_ADDRESS_FAMILIES = _env_list("FTP_OTHER_ADDRESS_FAMILIES", "3,4,5,6,7,8,9,10,11,12,13,14,15,16")
# the data connection: the address of this host (the server connects to it in active mode, Fandango connects to the server's address in passive mode),
# the ports Fandango listens on for the server's active-mode connection (PORT / EPRT name them), and ports nothing listens on (the server's attempt is refused)
FTP_DATA_ADDRESS = os.environ.get("FTP_DATA_ADDRESS", "127.0.0.1")
FTP_DATA_PORTS = [int(port) for port in _env_list("FTP_DATA_PORTS", "41000,42000,43000")]
FTP_CLOSED_PORTS = [int(port) for port in _env_list("FTP_CLOSED_PORTS", "5000,5001,5100,40000")]
# the bytes Fandango sends on a data connection (the content of an upload; the format of the transferred data is a TODO below)
FTP_DATA_PAYLOAD = os.environ.get("FTP_DATA_PAYLOAD", "fandango data\n").encode()
# seconds Fandango waits to connect to the server's passive port, and for the server to end a data connection
FTP_DATA_CONNECT_S = float(os.environ.get("FTP_DATA_CONNECT_S", "3"))
FTP_DATA_IDLE_S = float(os.environ.get("FTP_DATA_IDLE_S", "30"))
# seconds Fandango waits for a reply the spec lets stay away (timers), and for the greeting after a 120 reply
FTP_REPLY_WAIT_S = os.environ.get("FTP_REPLY_WAIT_S", "6")
# the server deviations the grammar tolerates (names of tolerances.json); empty by default
TOLERATED = [name for name in os.environ.get("TOLERATED", "").split(",") if name]

def tolerated(name):
    return name in TOLERATED

# ---------------------------------------------------------------------------------------------------------------
# Reply codes: one nonterminal per code (RFC 959 4.2), and for each code its generic reply: single line
# 'code SP text CRLF' or multi-line 'code-' first line, middle lines, last line 'code SP' (RFC 959 4.2, RFC 1123 4.1.2.11).
# Codes whose text has a syntax of its own (110, 215, 227, 229, 257, 522) have a reply rule written by hand below.
# ---------------------------------------------------------------------------------------------------------------
<code_110> ::= '110'  # RFC 959 4.2.1; RFC 1123 4.1.3.4: restart marker reply
<code_120> ::= '120'  # RFC 959 4.2.1: service ready in nnn minutes
<code_125> ::= '125'  # RFC 959 4.2.1: data connection already open; transfer starting
<code_150> ::= '150'  # RFC 959 4.2.1: file status okay; about to open data connection
<code_200> ::= '200'  # RFC 959 4.2.1: command okay
<code_202> ::= '202'  # RFC 959 4.2.1: command not implemented, superfluous at this site
<code_211> ::= '211'  # RFC 959 4.2.1; RFC 2389 3.2: system status or help reply
<code_212> ::= '212'  # RFC 959 4.2.1: directory status
<code_213> ::= '213'  # RFC 959 4.2.1; RFC 3659 3.1, 4.1: file status
<code_214> ::= '214'  # RFC 959 4.2.1: help message
<code_215> ::= '215'  # RFC 959 4.2.1: NAME system type
<code_220> ::= '220'  # RFC 959 4.2.1; RFC 7151 3.1: service ready for new user / host ok
<code_221> ::= '221'  # RFC 959 4.2.1: service closing control connection
<code_225> ::= '225'  # RFC 959 4.2.1: data connection open; no transfer in progress
<code_226> ::= '226'  # RFC 959 4.2.1: closing data connection; requested file action successful
<code_227> ::= '227'  # RFC 959 4.2.1: entering passive mode
<code_229> ::= '229'  # RFC 2428 3: entering extended passive mode
<code_230> ::= '230'  # RFC 959 4.2.1: user logged in, proceed
<code_232> ::= '232'  # RFC 2228 5.1: user logged in, authorized by security data exchange
<code_234> ::= '234'  # RFC 2228 5.1; RFC 4217 4.2: security data exchange complete
<code_235> ::= '235'  # RFC 2228 5.1: security data exchange complete (optional ADAT=base64data)
<code_250> ::= '250'  # RFC 959 4.2.1; RFC 3659 7.2: requested file action okay, completed
<code_257> ::= '257'  # RFC 959 4.2.1: "PATHNAME" created
<code_331> ::= '331'  # RFC 959 4.2.1: user name okay, need password
<code_332> ::= '332'  # RFC 959 4.2.1: need account for login
<code_334> ::= '334'  # RFC 2228 5.1: requested security mechanism ok (optional ADAT=base64data)
<code_335> ::= '335'  # RFC 2228 5.1: security data acceptable, more required (optional ADAT=base64data)
<code_336> ::= '336'  # RFC 2228 5.1: username okay, need password; challenge
<code_350> ::= '350'  # RFC 959 4.2.1: requested file action pending further information
<code_421> ::= '421'  # RFC 959 4.2.1: service not available, closing control connection
<code_425> ::= '425'  # RFC 959 4.2.1: can't open data connection
<code_426> ::= '426'  # RFC 959 4.2.1: connection closed; transfer aborted
<code_431> ::= '431'  # RFC 2228 5.1: need some unavailable resource to process security
<code_450> ::= '450'  # RFC 959 4.2.1: requested file action not taken; file unavailable
<code_451> ::= '451'  # RFC 959 4.2.1; RFC 2389 4: requested action aborted; local error in processing
<code_452> ::= '452'  # RFC 959 4.2.1: requested action not taken; insufficient storage space
<code_500> ::= '500'  # RFC 959 4.2.1: syntax error, command unrecognized
<code_501> ::= '501'  # RFC 959 4.2.1: syntax error in parameters or arguments
<code_502> ::= '502'  # RFC 959 4.2.1: command not implemented
<code_503> ::= '503'  # RFC 959 4.2.1: bad sequence of commands
<code_504> ::= '504'  # RFC 959 4.2.1: command not implemented for that parameter
<code_522> ::= '522'  # RFC 2428 2: network protocol not supported
<code_530> ::= '530'  # RFC 959 4.2.1: not logged in
<code_532> ::= '532'  # RFC 959 4.2.1: need account for storing files
<code_533> ::= '533'  # RFC 2228 5.1: command protection level denied for policy reasons
<code_534> ::= '534'  # RFC 2228 5.1: request denied for policy reasons
<code_535> ::= '535'  # RFC 2228 5.1: failed security check
<code_536> ::= '536'  # RFC 2228 5.1: requested PROT level not supported by mechanism
<code_537> ::= '537'  # RFC 2228 5.1: command protection level not supported by security mechanism
<code_631> ::= '631'  # RFC 2228 5.2: integrity protected reply
<code_632> ::= '632'  # RFC 2228 5.2: confidentiality and integrity protected reply
<code_633> ::= '633'  # RFC 2228 5.2: confidentiality protected reply
<code_550> ::= '550'  # RFC 959 4.2.1: requested action not taken; file unavailable
<code_551> ::= '551'  # RFC 959 4.2.1: requested action aborted; page type unknown
<code_552> ::= '552'  # RFC 959 4.2.1: requested file action aborted; exceeded storage allocation
<code_553> ::= '553'  # RFC 959 4.2.1: requested action not taken; file name not allowed
<code_554> ::= '554'  # RFC 1123 4.1.3.4: requested action not taken: invalid REST parameter
<code_555> ::= '555'  # RFC 1123 4.1.3.4: requested action not taken: type or stru mismatch

# RFC 959 4.2: the reply text; NVT: a CR not followed by LF is followed by NUL (RFC 854, RFC 959 5.1)
<reply_text> ::= r'([^\r\n]|\r(?!\n))+'
# RFC 959 4.2: single-line tail 'SP text CRLF'
<reply_tail> ::= <SP> <reply_text>? <CRLF>
# RFC 959 4.2: first line of a multi-line reply: the code is followed by a hyphen
<reply_head> ::= '-' <reply_text>? <CRLF>
# RFC 959 4.2: a middle line of a multi-line reply; 'If an intermediary line begins with a 3-digit number, the Server must pad the front':
# server pads such a line at the front (RFC 959 4.2: 'must pad the front to avoid confusion')
<reply_mid_text> ::= r'(?!\d{3}(?!\d))([^\r\n]|\r(?!\n))+'
# Tolerance pureftpd_unpadded_mid_line: a middle line that begins with a code and a hyphen ('220-text'), which RFC 959 4.2 forbids (the server must pad it)
<reply_mid_unpadded> ::= r'[0-9]{3}-([^\r\n]|\r(?!\n))*'
where forall <x> in <reply_mid_unpadded>: tolerated("pureftpd_unpadded_mid_line")
<reply_mid_line> ::= <reply_mid_text>? <CRLF> | <reply_mid_unpadded> <CRLF>  # RFC 959 4.2 (multi-line replies)

<reply_120> ::= <code_120> <reply_tail> | <code_120> <reply_head> <reply_mid_line>* <code_120> <reply_tail>  # RFC 959 4.2.1
<reply_125> ::= <code_125> <reply_tail> | <code_125> <reply_head> <reply_mid_line>* <code_125> <reply_tail>  # RFC 959 4.2.1
<reply_150> ::= <code_150> <reply_tail> | <code_150> <reply_head> <reply_mid_line>* <code_150> <reply_tail>  # RFC 959 4.2.1
<reply_200> ::= <code_200> <reply_tail> | <code_200> <reply_head> <reply_mid_line>* <code_200> <reply_tail>  # RFC 959 4.2.1
<reply_202> ::= <code_202> <reply_tail> | <code_202> <reply_head> <reply_mid_line>* <code_202> <reply_tail>  # RFC 959 4.2.1
<reply_211> ::= <code_211> <reply_tail> | <code_211> <reply_head> <reply_mid_line>* <code_211> <reply_tail>  # RFC 959 4.2.1; RFC 2389 3.2
<reply_212> ::= <code_212> <reply_tail> | <code_212> <reply_head> <reply_mid_line>* <code_212> <reply_tail>  # RFC 959 4.2.1
<reply_213> ::= <code_213> <reply_tail> | <code_213> <reply_head> <reply_mid_line>* <code_213> <reply_tail>  # RFC 959 4.2.1; RFC 3659 3.1, 4.1
<reply_214> ::= <code_214> <reply_tail> | <code_214> <reply_head> <reply_mid_line>* <code_214> <reply_tail>  # RFC 959 4.2.1
<reply_220> ::= <code_220> <reply_tail> | <code_220> <reply_head> <reply_mid_line>* <code_220> <reply_tail>  # RFC 959 4.2.1; RFC 7151 3.1
<reply_221> ::= <code_221> <reply_tail> | <code_221> <reply_head> <reply_mid_line>* <code_221> <reply_tail>  # RFC 959 4.2.1
<reply_225> ::= <code_225> <reply_tail> | <code_225> <reply_head> <reply_mid_line>* <code_225> <reply_tail>  # RFC 959 4.2.1
<reply_226> ::= <code_226> <reply_tail> | <code_226> <reply_head> <reply_mid_line>* <code_226> <reply_tail>  # RFC 959 4.2.1
<reply_230> ::= <code_230> <reply_tail> | <code_230> <reply_head> <reply_mid_line>* <code_230> <reply_tail>  # RFC 959 4.2.1
<reply_232> ::= <code_232> <reply_tail> | <code_232> <reply_head> <reply_mid_line>* <code_232> <reply_tail>  # RFC 2228 5.1
<reply_234> ::= <code_234> <reply_tail> | <code_234> <reply_head> <reply_mid_line>* <code_234> <reply_tail>  # RFC 2228 5.1; RFC 4217 4.2
<reply_235> ::= <code_235> <reply_tail> | <code_235> <reply_head> <reply_mid_line>* <code_235> <reply_tail>  # RFC 2228 5.1
<reply_250> ::= <code_250> <reply_tail> | <code_250> <reply_head> <reply_mid_line>* <code_250> <reply_tail>  # RFC 959 4.2.1; RFC 3659 7.2
<reply_331> ::= <code_331> <reply_tail> | <code_331> <reply_head> <reply_mid_line>* <code_331> <reply_tail>  # RFC 959 4.2.1
<reply_332> ::= <code_332> <reply_tail> | <code_332> <reply_head> <reply_mid_line>* <code_332> <reply_tail>  # RFC 959 4.2.1
<reply_334> ::= <code_334> <reply_tail> | <code_334> <reply_head> <reply_mid_line>* <code_334> <reply_tail>  # RFC 2228 5.1
<reply_335> ::= <code_335> <reply_tail> | <code_335> <reply_head> <reply_mid_line>* <code_335> <reply_tail>  # RFC 2228 5.1
<reply_336> ::= <code_336> <reply_tail> | <code_336> <reply_head> <reply_mid_line>* <code_336> <reply_tail>  # RFC 2228 5.1
<reply_350> ::= <code_350> <reply_tail> | <code_350> <reply_head> <reply_mid_line>* <code_350> <reply_tail>  # RFC 959 4.2.1
<reply_421> ::= <code_421> <reply_tail> | <code_421> <reply_head> <reply_mid_line>* <code_421> <reply_tail>  # RFC 959 4.2.1
<reply_425> ::= <code_425> <reply_tail> | <code_425> <reply_head> <reply_mid_line>* <code_425> <reply_tail>  # RFC 959 4.2.1
<reply_426> ::= <code_426> <reply_tail> | <code_426> <reply_head> <reply_mid_line>* <code_426> <reply_tail>  # RFC 959 4.2.1
<reply_431> ::= <code_431> <reply_tail> | <code_431> <reply_head> <reply_mid_line>* <code_431> <reply_tail>  # RFC 2228 5.1
<reply_450> ::= <code_450> <reply_tail> | <code_450> <reply_head> <reply_mid_line>* <code_450> <reply_tail>  # RFC 959 4.2.1
<reply_451> ::= <code_451> <reply_tail> | <code_451> <reply_head> <reply_mid_line>* <code_451> <reply_tail>  # RFC 959 4.2.1; RFC 2389 4
<reply_452> ::= <code_452> <reply_tail> | <code_452> <reply_head> <reply_mid_line>* <code_452> <reply_tail>  # RFC 959 4.2.1
<reply_500> ::= <code_500> <reply_tail> | <code_500> <reply_head> <reply_mid_line>* <code_500> <reply_tail>  # RFC 959 4.2.1
<reply_501> ::= <code_501> <reply_tail> | <code_501> <reply_head> <reply_mid_line>* <code_501> <reply_tail>  # RFC 959 4.2.1
<reply_502> ::= <code_502> <reply_tail> | <code_502> <reply_head> <reply_mid_line>* <code_502> <reply_tail>  # RFC 959 4.2.1
<reply_503> ::= <code_503> <reply_tail> | <code_503> <reply_head> <reply_mid_line>* <code_503> <reply_tail>  # RFC 959 4.2.1
<reply_504> ::= <code_504> <reply_tail> | <code_504> <reply_head> <reply_mid_line>* <code_504> <reply_tail>  # RFC 959 4.2.1
<reply_530> ::= <code_530> <reply_tail> | <code_530> <reply_head> <reply_mid_line>* <code_530> <reply_tail>  # RFC 959 4.2.1
<reply_532> ::= <code_532> <reply_tail> | <code_532> <reply_head> <reply_mid_line>* <code_532> <reply_tail>  # RFC 959 4.2.1
<reply_533> ::= <code_533> <reply_tail> | <code_533> <reply_head> <reply_mid_line>* <code_533> <reply_tail>  # RFC 2228 5.1
<reply_534> ::= <code_534> <reply_tail> | <code_534> <reply_head> <reply_mid_line>* <code_534> <reply_tail>  # RFC 2228 5.1
<reply_535> ::= <code_535> <reply_tail> | <code_535> <reply_head> <reply_mid_line>* <code_535> <reply_tail>  # RFC 2228 5.1
<reply_536> ::= <code_536> <reply_tail> | <code_536> <reply_head> <reply_mid_line>* <code_536> <reply_tail>  # RFC 2228 5.1
<reply_537> ::= <code_537> <reply_tail> | <code_537> <reply_head> <reply_mid_line>* <code_537> <reply_tail>  # RFC 2228 5.1
<reply_550> ::= <code_550> <reply_tail> | <code_550> <reply_head> <reply_mid_line>* <code_550> <reply_tail>  # RFC 959 4.2.1
<reply_551> ::= <code_551> <reply_tail> | <code_551> <reply_head> <reply_mid_line>* <code_551> <reply_tail>  # RFC 959 4.2.1
<reply_552> ::= <code_552> <reply_tail> | <code_552> <reply_head> <reply_mid_line>* <code_552> <reply_tail>  # RFC 959 4.2.1
<reply_553> ::= <code_553> <reply_tail> | <code_553> <reply_head> <reply_mid_line>* <code_553> <reply_tail>  # RFC 959 4.2.1
<reply_554> ::= <code_554> <reply_tail> | <code_554> <reply_head> <reply_mid_line>* <code_554> <reply_tail>  # RFC 1123 4.1.3.4
<reply_555> ::= <code_555> <reply_tail> | <code_555> <reply_head> <reply_mid_line>* <code_555> <reply_tail>  # RFC 1123 4.1.3.4
# ---------------------------------------------------------------------------------------------------------------
# Basic tokens shared by sent and received messages
# ---------------------------------------------------------------------------------------------------------------
<SP> ::= ' '        # RFC 959 5.3.1: <SP>
<CRLF> ::= '\r\n'   # RFC 959 5.3.1: <CRLF>; RFC 854 NVT end-of-line

# RFC 959 5.3.2: <char> ::= any of the 128 ASCII characters except <CR> and <LF>; <string> ::= <char> | <char><string>.
# Added by the text: on the control connection (Telnet NVT, RFC 854 / RFC 959 5.1) a CR that is not followed by LF is
# followed by NUL (RFC 2640 3.1: 'When a <CR> character is encountered as part of a pathname it MUST be followed by <NUL>');
# pathnames are UTF-8 encoded Unicode (RFC 2640 3.1, RFC 3659 2.2): the regex lists ASCII except CR/LF, CR NUL and UTF-8 characters.
<string> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+'   # RFC 959 5.3.2; RFC 854; RFC 2640 3.1
<char_iac> ::= b'\xff\xff'   # RFC 3659 2.2: the Telnet IAC character in a pathname MUST be escaped (doubled)
<string_iac> ::= <string>? <char_iac> <string>?   # RFC 3659 2.2: a name with a doubled IAC
# RFC 2640 3.1: pathname = 1*(%x01..%xFF): a name may hold bytes that are no valid UTF-8 (the server must check): one stray byte of the range 0x80-0xFF (0xFF itself is the doubled IAC above)
<byte_raw> ::= b'\x80' | b'\xbf' | b'\xc0' | b'\xc1' | b'\xc3' | b'\xe2' | b'\xf5' | b'\xfe'   # RFC 2640 3.1: a stray continuation byte, an overlong lead byte, a truncated lead byte, a byte beyond U+10FFFF
<string_raw> ::= <string>? <byte_raw> <string>?   # RFC 2640 3.1: a name that is not valid UTF-8

# RFC 2640 3.1: a pathname may hold a line feed; the example 'foo<CR><NUL><LF>boo.bar' names the pathname foo<CR><LF>boo.bar (the CR is followed by NUL, the LF follows it)
<crnul_lf> ::= b'\r\x00\n'
<string_lf> ::= <string>? <crnul_lf> <string>?   # RFC 2640 3.1: a name with a line feed (a server that ends the command line at the LF is a finding)

# RFC 959 5.3.2: <pr-char> ::= printable characters, any ASCII code 33 through 126

# RFC 959 5.3.2: <number> ::= any decimal integer 1 through 255 (the text of 5.3.2 'host-number' also needs octet 0)
<number> ::= r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])' # RFC 959 5.3.2
<decimal_integer> ::= r'[0-9]+'                                # RFC 959 5.3.2: any decimal integer
<digit_string> ::= r'[0-9]+'                                   # RFC 3659 5.3 1*DIGIT

# RFC 959 5.3.2 <pathname> ::= <string>. Sent: the targets of the test setup (generated), or any other name from the rule (the server refuses it).
# RFC 3659 2.2 / RFC 2640 3.1: exactly one SP separates the command from its pathname, further SPs belong to the name.
<pathname> ::= <string> | <string_iac> | <string_raw> | <string_lf>   # RFC 959 5.3.2; RFC 2640 3.1: pathname = 1*(%x01..%xFF)
<dir_target> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_dir()                           # target: directory of the setup
<file_target> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_file()                         # target: file of the setup
<path_target> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_path()                         # target: file or directory of the setup
<new_name_target> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_new_name()                 # name for something the request creates
<arg_dir> ::= <dir_target> | <pathname>                        # RFC 959 5.3.1 CWD, SMNT, RMD
<arg_file> ::= <file_target> | <pathname>                      # RFC 959 5.3.1 RETR, DELE
<arg_path> ::= <path_target> | <pathname>                      # RFC 959 5.3.1 LIST, NLST, STAT, RNFR
<arg_new_name> ::= <new_name_target> | <pathname>              # RFC 959 5.3.1 MKD, STOR, APPE, RNTO
<arg_help> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_from(FTP_HELP_ARGS)               # RFC 959 5.3.1 HELP [<SP> <string>]
<site_known> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_from(FTP_SITE_ARGS)             # SITE commands of the setup
<arg_site> ::= <site_known> | <string>                         # RFC 959 5.3.1 SITE <SP> <string>
<arg_append> ::= <file_target> | <new_name_target> | <pathname>   # RFC 959 4.1.3 APPE: appends to an existing file or creates it
<arg_store> ::= <file_target> | <new_name_target> | <pathname>   # RFC 959 4.1.3 STOR: replaces the contents of an existing file or creates it

def pick_from(values):
    return random.choice(values)

def case_form(name):
    """RFC 2228 3: the mechanism name is case independent: the name as listed, in lower case, or in mixed case."""
    return random.choice([name, name, name.lower(), "".join(random.choice([c.lower(), c.upper()]) for c in name)])

def pick_tls_name():
    return case_form("TLS")

def pick_other_mechanism():
    return case_form(random.choice([m for m in FTP_AUTH_MECHANISMS if m.upper() != "TLS"] or ["GSSAPI"]))

def junk_name():
    """A string of the rule <string> (letters, digits, punctuation, inner spaces, UTF-8 characters, CR NUL): a value that is no target."""
    pieces = []
    for _ in range(random.randint(1, 8)):
        kind = random.random()
        if kind < 0.72:
            pieces.append(random.choice("abcdefghijklmnopqrstuvwxyz0123456789._-"))
        elif kind < 0.86:
            pieces.append(" ")
        elif kind < 0.98:
            pieces.append(random.choice("\u00e9\u0436\u4e2d"))
        elif kind < 0.99:
            pieces.append("\r\x00")
        else:
            pieces.append(b"\xff\xff")
    if any(isinstance(piece, bytes) for piece in pieces):
        return b"".join(piece if isinstance(piece, bytes) else piece.encode("utf-8") for piece in pieces)
    return "".join(pieces)

def pick_dir():
    return random.choice(FTP_DIRS)

def pick_file():
    return random.choice(FTP_FILES)

def pick_path():
    return random.choice(FTP_FILES + FTP_DIRS)

def pick_new_name():
    return random.choice(FTP_NEW_NAMES)
# ---------------------------------------------------------------------------------------------------------------
# Command words: one nonterminal per command; the command word is case independent (RFC 959 5.3.1, RFC 3659, RFC 7151 3.1)
# ---------------------------------------------------------------------------------------------------------------
<cmd_noop> ::= r'[Nn][Oo][Oo][Pp]'  # RFC 959 4.1.3: NOOP
<cmd_syst> ::= r'[Ss][Yy][Ss][Tt]'  # RFC 959 4.1.3: SYST
<cmd_stat> ::= r'[Ss][Tt][Aa][Tt]'  # RFC 959 4.1.3: STAT
<cmd_help> ::= r'[Hh][Ee][Ll][Pp]'  # RFC 959 4.1.3: HELP
<cmd_site> ::= r'[Ss][Ii][Tt][Ee]'  # RFC 959 4.1.3: SITE
<cmd_cwd> ::= r'[Cc][Ww][Dd]'  # RFC 959 4.1.1: CWD
<cmd_cdup> ::= r'[Cc][Dd][Uu][Pp]'  # RFC 959 4.1.1: CDUP
<cmd_smnt> ::= r'[Ss][Mm][Nn][Tt]'  # RFC 959 4.1.1: SMNT
<cmd_stru> ::= r'[Ss][Tt][Rr][Uu]'  # RFC 959 4.1.2: STRU
<cmd_mode> ::= r'[Mm][Oo][Dd][Ee]'  # RFC 959 4.1.2: MODE
<cmd_type> ::= r'[Tt][Yy][Pp][Ee]'  # RFC 959 4.1.2: TYPE
<cmd_allo> ::= r'[Aa][Ll][Ll][Oo]'  # RFC 959 4.1.3: ALLO
<cmd_dele> ::= r'[Dd][Ee][Ll][Ee]'  # RFC 959 4.1.3: DELE
<cmd_rmd> ::= r'[Rr][Mm][Dd]'  # RFC 959 4.1.3: RMD
<cmd_mkd> ::= r'[Mm][Kk][Dd]'  # RFC 959 4.1.3: MKD
<cmd_pwd> ::= r'[Pp][Ww][Dd]'  # RFC 959 4.1.3: PWD
<cmd_xmkd> ::= r'[Xx][Mm][Kk][Dd]'  # RFC 1123 4.1.3.1: XMKD
<cmd_xrmd> ::= r'[Xx][Rr][Mm][Dd]'  # RFC 1123 4.1.3.1: XRMD
<cmd_xpwd> ::= r'[Xx][Pp][Ww][Dd]'  # RFC 1123 4.1.3.1: XPWD
<cmd_xcup> ::= r'[Xx][Cc][Uu][Pp]'  # RFC 1123 4.1.3.1: XCUP
<cmd_xcwd> ::= r'[Xx][Cc][Ww][Dd]'  # RFC 1123 4.1.3.1: XCWD
<cmd_rnfr> ::= r'[Rr][Nn][Ff][Rr]'  # RFC 959 4.1.3: RNFR
<cmd_rnto> ::= r'[Rr][Nn][Tt][Oo]'  # RFC 959 4.1.3: RNTO
<cmd_rest> ::= r'[Rr][Ee][Ss][Tt]'  # RFC 959 4.1.3; RFC 3659 5: REST
<cmd_port> ::= r'[Pp][Oo][Rr][Tt]'  # RFC 959 4.1.2: PORT
<cmd_pasv> ::= r'[Pp][Aa][Ss][Vv]'  # RFC 959 4.1.2: PASV
<cmd_eprt> ::= r'[Ee][Pp][Rr][Tt]'  # RFC 2428 2: EPRT
<cmd_epsv> ::= r'[Ee][Pp][Ss][Vv]'  # RFC 2428 3: EPSV
<cmd_size> ::= r'[Ss][Ii][Zz][Ee]'  # RFC 3659 4.1: SIZE
<cmd_mdtm> ::= r'[Mm][Dd][Tt][Mm]'  # RFC 3659 3.1: MDTM
<cmd_mlst> ::= r'[Mm][Ll][Ss][Tt]'  # RFC 3659 7.1: MLST
<cmd_feat> ::= r'[Ff][Ee][Aa][Tt]'  # RFC 2389 3.1: FEAT
<cmd_lang> ::= r'[Ll][Aa][Nn][Gg]'  # RFC 2640 4.2: LANG
<cmd_pbsz> ::= r'[Pp][Bb][Ss][Zz]'  # RFC 2228 3; RFC 4217 9: PBSZ
<cmd_prot> ::= r'[Pp][Rr][Oo][Tt]'  # RFC 2228 3; RFC 4217 9: PROT
<cmd_ccc> ::= r'[Cc][Cc][Cc]'  # RFC 2228 3; RFC 4217 5: CCC
<cmd_mic> ::= r'[Mm][Ii][Cc]'  # RFC 2228 3: MIC
<cmd_conf> ::= r'[Cc][Oo][Nn][Ff]'  # RFC 2228 3: CONF
<cmd_enc> ::= r'[Ee][Nn][Cc]'  # RFC 2228 3: ENC
<cmd_opts> ::= r'[Oo][Pp][Tt][Ss]'  # RFC 2389 4; RFC 3659 7.9: OPTS
<cmd_host> ::= r'[Hh][Oo][Ss][Tt]'  # RFC 7151 3.1: HOST
<cmd_retr> ::= r'[Rr][Ee][Tt][Rr]'  # RFC 959 4.1.3: RETR
<cmd_stor> ::= r'[Ss][Tt][Oo][Rr]'  # RFC 959 4.1.3: STOR
<cmd_stou> ::= r'[Ss][Tt][Oo][Uu]'  # RFC 959 4.1.3; RFC 1123 4.1.2.9: STOU
<cmd_appe> ::= r'[Aa][Pp][Pp][Ee]'  # RFC 959 4.1.3: APPE
<cmd_list> ::= r'[Ll][Ii][Ss][Tt]'  # RFC 959 4.1.3: LIST
<cmd_nlst> ::= r'[Nn][Ll][Ss][Tt]'  # RFC 959 4.1.3: NLST
<cmd_mlsd> ::= r'[Mm][Ll][Ss][Dd]'  # RFC 3659 7.1: MLSD
<cmd_user> ::= r'[Uu][Ss][Ee][Rr]'  # RFC 959 4.1.1: USER
<cmd_pass> ::= r'[Pp][Aa][Ss][Ss]'  # RFC 959 4.1.1: PASS
<cmd_acct> ::= r'[Aa][Cc][Cc][Tt]'  # RFC 959 4.1.1: ACCT
<cmd_quit> ::= r'[Qq][Uu][Ii][Tt]'  # RFC 959 4.1.1: QUIT
<cmd_rein> ::= r'[Rr][Ee][Ii][Nn]'  # RFC 959 4.1.1: REIN
<cmd_abor> ::= r'[Aa][Bb][Oo][Rr]'  # RFC 959 4.1.3: ABOR
<cmd_auth> ::= r'[Aa][Uu][Tt][Hh]'  # RFC 2228 3; RFC 4217 4: AUTH
<cmd_adat> ::= r'[Aa][Dd][Aa][Tt]'  # RFC 2228 3: ADAT

# ---------------------------------------------------------------------------------------------------------------
# Simple exchanges (one request, the reply set of the command; the state does not change), and their 421 variant
# RFC 959 5.4: the reply table 'must be strictly adhered to'; RFC 959 4.2.1: 421 'may be a reply to any command'.
# ---------------------------------------------------------------------------------------------------------------
<req_noop> ::= <cmd_noop> <CRLF>  # RFC 959 4.1.3
<rep_noop> ::= <reply_200> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_noop> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_noop> ::= r'(?!(200|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_noop> ::= <error_code_noop>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_noop> ::= <error_code_noop>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_noop> ::= <error_code_noop> <reply_tail> | <error_first_noop> <reply_head> <reply_mid_line>* <error_last_noop> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_noop>: str(<r>.<error_first_noop>) == str(<r>.<error_last_noop>)
<exch_noop> ::= <Client:req_noop> <Server:rep_noop>  # RFC 959 4.1.3
<req_syst> ::= <cmd_syst> <CRLF>  # RFC 959 4.1.3
<rep_syst> ::= <reply_215> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_syst> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_syst> ::= r'(?!(215|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_syst> ::= <error_code_syst>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_syst> ::= <error_code_syst>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_syst> ::= <error_code_syst> <reply_tail> | <error_first_syst> <reply_head> <reply_mid_line>* <error_last_syst> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_syst>: str(<r>.<error_first_syst>) == str(<r>.<error_last_syst>)
<exch_syst> ::= <Client:req_syst> <Server:rep_syst>  # RFC 959 4.1.3
<req_stat> ::= <cmd_stat> (<SP> <arg_path>)? <CRLF>  # RFC 959 4.1.3
<rep_stat> ::= <reply_211> | <reply_212> | <reply_213> | <reply_450> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_stat> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_stat> ::= r'(?!(211|212|213|421|450|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_stat> ::= <error_code_stat>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_stat> ::= <error_code_stat>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_stat> ::= <error_code_stat> <reply_tail> | <error_first_stat> <reply_head> <reply_mid_line>* <error_last_stat> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_stat>: str(<r>.<error_first_stat>) == str(<r>.<error_last_stat>)
<exch_stat> ::= <Client:req_stat> <Server:rep_stat>  # RFC 959 4.1.3
<req_help> ::= <cmd_help> (<SP> <arg_help>)? <CRLF>  # RFC 959 4.1.3
<rep_help> ::= <reply_211> | <reply_214> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_help> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_help> ::= r'(?!(211|214|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_help> ::= <error_code_help>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_help> ::= <error_code_help>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_help> ::= <error_code_help> <reply_tail> | <error_first_help> <reply_head> <reply_mid_line>* <error_last_help> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_help>: str(<r>.<error_first_help>) == str(<r>.<error_last_help>)
<exch_help> ::= <Client:req_help> <Server:rep_help>  # RFC 959 4.1.3
<req_site> ::= <cmd_site> <SP> <arg_site> <CRLF>  # RFC 959 4.1.3
<rep_site> ::= <reply_200> | <reply_202> | <reply_211> | <reply_214> | <reply_500> | <reply_501> | <reply_530> | <reply_502> | <reply_421> | <reply_error_site> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.1.3 (the services of SITE are described in a reply to a help request: 211 / 214); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_site> ::= r'(?!(200|202|211|214|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 959 4.1.3 (the services of SITE are described in a reply to a help request: 211 / 214); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_site> ::= <error_code_site>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.1.3 (the services of SITE are described in a reply to a help request: 211 / 214): code of the first line of a multi-line reply
<error_last_site> ::= <error_code_site>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.1.3 (the services of SITE are described in a reply to a help request: 211 / 214): code of the last line of a multi-line reply (equal to the first)
<reply_error_site> ::= <error_code_site> <reply_tail> | <error_first_site> <reply_head> <reply_mid_line>* <error_last_site> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_site>: str(<r>.<error_first_site>) == str(<r>.<error_last_site>)
<exch_site> ::= <Client:req_site> <Server:rep_site> <Server:reply_530>?  # RFC 959 4.1.3; ProFTPD answers a command before login with two 530 replies
<req_cwd> ::= <cmd_cwd> <SP> <arg_dir> <CRLF>  # RFC 959 4.1.1
<rep_cwd> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_cwd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_cwd> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_cwd> ::= <error_code_cwd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_cwd> ::= <error_code_cwd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_cwd> ::= <error_code_cwd> <reply_tail> | <error_first_cwd> <reply_head> <reply_mid_line>* <error_last_cwd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_cwd>: str(<r>.<error_first_cwd>) == str(<r>.<error_last_cwd>)
<exch_cwd> ::= <Client:req_cwd> <Server:rep_cwd>  # RFC 959 4.1.1
<req_cdup> ::= <cmd_cdup> <CRLF>  # RFC 959 4.1.1
<rep_cdup> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_cdup> | <reply_protected>  # RFC 959 4.1.1 (CDUP: 'shall be identical to the reply codes of CWD'; errata 4869); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_cdup> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 4.1.1 (CDUP: 'shall be identical to the reply codes of CWD'; errata 4869); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_cdup> ::= <error_code_cdup>  # RFC 959 4.1.1 (CDUP: 'shall be identical to the reply codes of CWD'; errata 4869): code of the first line of a multi-line reply
<error_last_cdup> ::= <error_code_cdup>  # RFC 959 4.1.1 (CDUP: 'shall be identical to the reply codes of CWD'; errata 4869): code of the last line of a multi-line reply (equal to the first)
<reply_error_cdup> ::= <error_code_cdup> <reply_tail> | <error_first_cdup> <reply_head> <reply_mid_line>* <error_last_cdup> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_cdup>: str(<r>.<error_first_cdup>) == str(<r>.<error_last_cdup>)
<exch_cdup> ::= <Client:req_cdup> <Server:rep_cdup>  # RFC 959 4.1.1
<req_smnt> ::= <cmd_smnt> <SP> <arg_dir> <CRLF>  # RFC 959 4.1.1
<rep_smnt> ::= <reply_202> | <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_smnt> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_smnt> ::= r'(?!(202|250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_smnt> ::= <error_code_smnt>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_smnt> ::= <error_code_smnt>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_smnt> ::= <error_code_smnt> <reply_tail> | <error_first_smnt> <reply_head> <reply_mid_line>* <error_last_smnt> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_smnt>: str(<r>.<error_first_smnt>) == str(<r>.<error_last_smnt>)
<exch_smnt> ::= <Client:req_smnt> <Server:rep_smnt>  # RFC 959 4.1.1
<req_stru> ::= <cmd_stru> <SP> <structure_code> <CRLF>  # RFC 959 4.1.2
<rep_stru> ::= <reply_200> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_502> | <reply_421> | <reply_error_stru> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_stru> ::= r'(?!(200|421|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_stru> ::= <error_code_stru>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_stru> ::= <error_code_stru>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_stru> ::= <error_code_stru> <reply_tail> | <error_first_stru> <reply_head> <reply_mid_line>* <error_last_stru> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_stru>: str(<r>.<error_first_stru>) == str(<r>.<error_last_stru>)
<exch_stru> ::= <Client:req_stru> <Server:rep_stru>  # RFC 959 4.1.2
<req_mode> ::= <cmd_mode> <SP> <mode_code> <CRLF>  # RFC 959 4.1.2
<rep_mode> ::= <reply_200> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_502> | <reply_421> | <reply_error_mode> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_mode> ::= r'(?!(200|421|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_mode> ::= <error_code_mode>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_mode> ::= <error_code_mode>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_mode> ::= <error_code_mode> <reply_tail> | <error_first_mode> <reply_head> <reply_mid_line>* <error_last_mode> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_mode>: str(<r>.<error_first_mode>) == str(<r>.<error_last_mode>)
<exch_mode> ::= <Client:req_mode> <Server:rep_mode>  # RFC 959 4.1.2
<req_type> ::= <cmd_type> <SP> <type_code> <CRLF>  # RFC 959 4.1.2
<rep_type> ::= <reply_200> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_502> | <reply_421> | <reply_error_type> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_type> ::= r'(?!(200|421|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_type> ::= <error_code_type>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_type> ::= <error_code_type>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_type> ::= <error_code_type> <reply_tail> | <error_first_type> <reply_head> <reply_mid_line>* <error_last_type> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_type>: str(<r>.<error_first_type>) == str(<r>.<error_last_type>)
<exch_type> ::= <Client:req_type> <Server:rep_type>  # RFC 959 4.1.2
<req_allo> ::= <cmd_allo> <SP> <decimal_integer> (<SP> <allo_r> <SP> <decimal_integer>)? <CRLF>  # RFC 959 4.1.3
<rep_allo> ::= <reply_200> | <reply_202> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_502> | <reply_421> | <reply_error_allo> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_allo> ::= r'(?!(200|202|421|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_allo> ::= <error_code_allo>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_allo> ::= <error_code_allo>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_allo> ::= <error_code_allo> <reply_tail> | <error_first_allo> <reply_head> <reply_mid_line>* <error_last_allo> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_allo>: str(<r>.<error_first_allo>) == str(<r>.<error_last_allo>)
<exch_allo> ::= <Client:req_allo> <Server:rep_allo>  # RFC 959 4.1.3
<req_dele> ::= <cmd_dele> <SP> <arg_file> <CRLF>  # RFC 959 4.1.3
<rep_dele> ::= <reply_250> | <reply_450> | <reply_550> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_dele> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_dele> ::= r'(?!(250|421|450|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_dele> ::= <error_code_dele>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_dele> ::= <error_code_dele>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_dele> ::= <error_code_dele> <reply_tail> | <error_first_dele> <reply_head> <reply_mid_line>* <error_last_dele> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_dele>: str(<r>.<error_first_dele>) == str(<r>.<error_last_dele>)
<exch_dele> ::= <Client:req_dele> <Server:rep_dele>  # RFC 959 4.1.3
<req_rmd> ::= <cmd_rmd> <SP> <arg_dir> <CRLF>  # RFC 959 4.1.3
<rep_rmd> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_rmd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_rmd> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_rmd> ::= <error_code_rmd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_rmd> ::= <error_code_rmd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_rmd> ::= <error_code_rmd> <reply_tail> | <error_first_rmd> <reply_head> <reply_mid_line>* <error_last_rmd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_rmd>: str(<r>.<error_first_rmd>) == str(<r>.<error_last_rmd>)
<exch_rmd> ::= <Client:req_rmd> <Server:rep_rmd>  # RFC 959 4.1.3
<req_mkd> ::= <cmd_mkd> <SP> <arg_new_name> <CRLF>  # RFC 959 4.1.3
<rep_mkd> ::= <reply_257_mkd> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_mkd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_mkd> ::= r'(?!(257|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_mkd> ::= <error_code_mkd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_mkd> ::= <error_code_mkd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_mkd> ::= <error_code_mkd> <reply_tail> | <error_first_mkd> <reply_head> <reply_mid_line>* <error_last_mkd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_mkd>: str(<r>.<error_first_mkd>) == str(<r>.<error_last_mkd>)
<exch_mkd> ::= <Client:req_mkd> <Server:rep_mkd>  # RFC 959 4.1.3
<req_pwd> ::= <cmd_pwd> <CRLF>  # RFC 959 4.1.3
<rep_pwd> ::= <reply_257> | <reply_500> | <reply_501> | <reply_502> | <reply_550> | <reply_530> | <reply_421> | <reply_error_pwd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_pwd> ::= r'(?!(257|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_pwd> ::= <error_code_pwd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_pwd> ::= <error_code_pwd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_pwd> ::= <error_code_pwd> <reply_tail> | <error_first_pwd> <reply_head> <reply_mid_line>* <error_last_pwd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_pwd>: str(<r>.<error_first_pwd>) == str(<r>.<error_last_pwd>)
<exch_pwd> ::= <Client:req_pwd> <Server:rep_pwd>  # RFC 959 4.1.3
<req_xmkd> ::= <cmd_xmkd> <SP> <arg_new_name> <CRLF>  # RFC 1123 4.1.3.1
<rep_xmkd> ::= <reply_257_mkd> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_xmkd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_xmkd> ::= r'(?!(257|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_xmkd> ::= <error_code_xmkd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_xmkd> ::= <error_code_xmkd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_xmkd> ::= <error_code_xmkd> <reply_tail> | <error_first_xmkd> <reply_head> <reply_mid_line>* <error_last_xmkd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_xmkd>: str(<r>.<error_first_xmkd>) == str(<r>.<error_last_xmkd>)
<exch_xmkd> ::= <Client:req_xmkd> <Server:rep_xmkd>  # RFC 1123 4.1.3.1
<req_xrmd> ::= <cmd_xrmd> <SP> <arg_dir> <CRLF>  # RFC 1123 4.1.3.1
<rep_xrmd> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_xrmd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_xrmd> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_xrmd> ::= <error_code_xrmd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_xrmd> ::= <error_code_xrmd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_xrmd> ::= <error_code_xrmd> <reply_tail> | <error_first_xrmd> <reply_head> <reply_mid_line>* <error_last_xrmd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_xrmd>: str(<r>.<error_first_xrmd>) == str(<r>.<error_last_xrmd>)
<exch_xrmd> ::= <Client:req_xrmd> <Server:rep_xrmd>  # RFC 1123 4.1.3.1
<req_xpwd> ::= <cmd_xpwd> <CRLF>  # RFC 1123 4.1.3.1
<rep_xpwd> ::= <reply_257> | <reply_500> | <reply_501> | <reply_502> | <reply_550> | <reply_530> | <reply_421> | <reply_error_xpwd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_xpwd> ::= r'(?!(257|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_xpwd> ::= <error_code_xpwd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_xpwd> ::= <error_code_xpwd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_xpwd> ::= <error_code_xpwd> <reply_tail> | <error_first_xpwd> <reply_head> <reply_mid_line>* <error_last_xpwd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_xpwd>: str(<r>.<error_first_xpwd>) == str(<r>.<error_last_xpwd>)
<exch_xpwd> ::= <Client:req_xpwd> <Server:rep_xpwd>  # RFC 1123 4.1.3.1
<req_xcup> ::= <cmd_xcup> <CRLF>  # RFC 1123 4.1.3.1
<rep_xcup> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_xcup> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_xcup> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_xcup> ::= <error_code_xcup>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_xcup> ::= <error_code_xcup>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_xcup> ::= <error_code_xcup> <reply_tail> | <error_first_xcup> <reply_head> <reply_mid_line>* <error_last_xcup> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_xcup>: str(<r>.<error_first_xcup>) == str(<r>.<error_last_xcup>)
<exch_xcup> ::= <Client:req_xcup> <Server:rep_xcup>  # RFC 1123 4.1.3.1
<req_xcwd> ::= <cmd_xcwd> <SP> <arg_dir> <CRLF>  # RFC 1123 4.1.3.1
<rep_xcwd> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_xcwd> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_xcwd> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_xcwd> ::= <error_code_xcwd>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_xcwd> ::= <error_code_xcwd>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_xcwd> ::= <error_code_xcwd> <reply_tail> | <error_first_xcwd> <reply_head> <reply_mid_line>* <error_last_xcwd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_xcwd>: str(<r>.<error_first_xcwd>) == str(<r>.<error_last_xcwd>)
<exch_xcwd> ::= <Client:req_xcwd> <Server:rep_xcwd>  # RFC 1123 4.1.3.1
<req_rnfr> ::= <cmd_rnfr> <SP> <arg_path> <CRLF>  # RFC 959 4.1.3
<rep_rnfr> ::= <reply_450> | <reply_550> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_rnfr> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_rnfr> ::= r'(?!(350|421|450|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_rnfr> ::= <error_code_rnfr>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_rnfr> ::= <error_code_rnfr>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_rnfr> ::= <error_code_rnfr> <reply_tail> | <error_first_rnfr> <reply_head> <reply_mid_line>* <error_last_rnfr> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_rnfr>: str(<r>.<error_first_rnfr>) == str(<r>.<error_last_rnfr>)
<exch_rnfr> ::= <Client:req_rnfr> <Server:rep_rnfr>  # RFC 959 4.1.3
<req_rnto> ::= <cmd_rnto> <SP> <arg_new_name> <CRLF>  # RFC 959 4.1.3
<rep_rnto> ::= <reply_250> | <reply_532> | <reply_553> | <reply_500> | <reply_501> | <reply_502> | <reply_503> | <reply_530> | <reply_421> | <reply_error_rnto> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_rnto> ::= r'(?!(250|421|500|501|502|503|530|532|553))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_rnto> ::= <error_code_rnto>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_rnto> ::= <error_code_rnto>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_rnto> ::= <error_code_rnto> <reply_tail> | <error_first_rnto> <reply_head> <reply_mid_line>* <error_last_rnto> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_rnto>: str(<r>.<error_first_rnto>) == str(<r>.<error_last_rnto>)
<exch_rnto> ::= <Client:req_rnto> <Server:rep_rnto> <Server:reply_530>?  # RFC 959 4.1.3; ProFTPD answers a command before login with two 530 replies
<req_rest> ::= <cmd_rest> <SP> <marker> <CRLF>  # RFC 959 4.1.3; RFC 3659 5
<rep_rest> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_554> | <reply_555> | <reply_421> | <reply_error_rest> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.3.4; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_rest> ::= r'(?!(350|421|500|501|502|530|554|555))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.3.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_rest> ::= <error_code_rest>  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.3.4: code of the first line of a multi-line reply
<error_last_rest> ::= <error_code_rest>  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.3.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_rest> ::= <error_code_rest> <reply_tail> | <error_first_rest> <reply_head> <reply_mid_line>* <error_last_rest> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_rest>: str(<r>.<error_first_rest>) == str(<r>.<error_last_rest>)
<exch_rest> ::= <Client:req_rest> <Server:rep_rest>  # RFC 959 4.1.3; RFC 3659 5
<req_port> ::= <cmd_port> <SP> <host_port_data> <CRLF>  # RFC 959 4.1.2
<rep_port> ::= <reply_200> | <reply_500> | <reply_501> | <reply_530> | <reply_502> | <reply_421> | <reply_error_port> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_port> ::= r'(?!(200|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_port> ::= <error_code_port>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_port> ::= <error_code_port>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_port> ::= <error_code_port> <reply_tail> | <error_first_port> <reply_head> <reply_mid_line>* <error_last_port> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_port>: str(<r>.<error_first_port>) == str(<r>.<error_last_port>)
<exch_port> ::= <Client:req_port> <Server:rep_port>  # RFC 959 4.1.2
<rep_port_refused> ::= <reply_500> | <reply_501> | <reply_530> | <reply_502> | <reply_421> | <reply_error_port> | <reply_protected>  # RFC 959 5.4 (command-reply sequences): every reply of the command but the positive one
<exch_port_ok> ::= <Client:req_port> <Server:reply_200>  # RFC 959 4.1.2: positive reply: a data connection is set up (RFC 959 3.2): the server connects to the PORT/EPRT address, where Fandango listens (RFC 959 3.2) -> <state_data_ready>
<exch_port_refused> ::= <Client:req_port> <Server:rep_port_refused>  # RFC 959 4.1.2: no data connection set up
<req_pasv> ::= <cmd_pasv> <CRLF>  # RFC 959 4.1.2
<rep_pasv> ::= <reply_227> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_pasv> | <reply_protected>  # RFC 959 5.4 (command-reply sequences); RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_pasv> ::= r'(?!(227|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (command-reply sequences); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_pasv> ::= <error_code_pasv>  # RFC 959 5.4 (command-reply sequences): code of the first line of a multi-line reply
<error_last_pasv> ::= <error_code_pasv>  # RFC 959 5.4 (command-reply sequences): code of the last line of a multi-line reply (equal to the first)
<reply_error_pasv> ::= <error_code_pasv> <reply_tail> | <error_first_pasv> <reply_head> <reply_mid_line>* <error_last_pasv> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_pasv>: str(<r>.<error_first_pasv>) == str(<r>.<error_last_pasv>)
<exch_pasv> ::= <Client:req_pasv> <Server:rep_pasv>  # RFC 959 4.1.2
<rep_pasv_refused> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_pasv> | <reply_protected>  # RFC 959 5.4 (command-reply sequences): every reply of the command but the positive one
<exch_pasv_ok> ::= <Client:req_pasv> <Server:reply_227> (<DataControl:data_connect> | <DataControl:data_idle>)  # RFC 959 4.1.2: positive reply: a data connection is set up (RFC 959 3.2): Fandango connects to the announced address (RFC 959 3.2, 4.1.2; RFC 2428 3) -> <state_data_ready>
<exch_pasv_refused> ::= <Client:req_pasv> <Server:rep_pasv_refused>  # RFC 959 4.1.2: no data connection set up
<req_eprt> ::= <cmd_eprt> <SP> <eprt_arg> <CRLF>  # RFC 2428 2
<rep_eprt> ::= <reply_200> | <reply_500> | <reply_501> | <reply_502> | <reply_522> | <reply_530> | <reply_421> | <reply_error_eprt> | <reply_protected>  # RFC 2428 2; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_eprt> ::= r'(?!(200|421|500|501|502|522|530))[2-5][0-9]{2}'  # RFC 2428 2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_eprt> ::= <error_code_eprt>  # RFC 2428 2: code of the first line of a multi-line reply
<error_last_eprt> ::= <error_code_eprt>  # RFC 2428 2: code of the last line of a multi-line reply (equal to the first)
<reply_error_eprt> ::= <error_code_eprt> <reply_tail> | <error_first_eprt> <reply_head> <reply_mid_line>* <error_last_eprt> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_eprt>: str(<r>.<error_first_eprt>) == str(<r>.<error_last_eprt>)
<exch_eprt> ::= <Client:req_eprt> <Server:rep_eprt>  # RFC 2428 2
<rep_eprt_refused> ::= <reply_500> | <reply_501> | <reply_502> | <reply_522> | <reply_530> | <reply_421> | <reply_error_eprt> | <reply_protected>  # RFC 2428 2: every reply of the command but the positive one
<exch_eprt_ok> ::= <Client:req_eprt> <Server:reply_200>  # RFC 2428 2: positive reply: a data connection is set up (RFC 959 3.2): the server connects to the PORT/EPRT address, where Fandango listens (RFC 959 3.2) -> <state_data_ready>
<exch_eprt_refused> ::= <Client:req_eprt> <Server:rep_eprt_refused>  # RFC 2428 2: no data connection set up
<req_epsv> ::= <cmd_epsv> (<SP> <epsv_net_prt>)? <CRLF>  # RFC 2428 3
<rep_epsv> ::= <reply_229> | <reply_500> | <reply_501> | <reply_502> | <reply_522> | <reply_530> | <reply_421> | <reply_error_epsv> | <reply_protected>  # RFC 2428 3; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_epsv> ::= r'(?!(229|421|500|501|502|522|530))[2-5][0-9]{2}'  # RFC 2428 3; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_epsv> ::= <error_code_epsv>  # RFC 2428 3: code of the first line of a multi-line reply
<error_last_epsv> ::= <error_code_epsv>  # RFC 2428 3: code of the last line of a multi-line reply (equal to the first)
<reply_error_epsv> ::= <error_code_epsv> <reply_tail> | <error_first_epsv> <reply_head> <reply_mid_line>* <error_last_epsv> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_epsv>: str(<r>.<error_first_epsv>) == str(<r>.<error_last_epsv>)
<exch_epsv> ::= <Client:req_epsv> <Server:rep_epsv>  # RFC 2428 3
<rep_epsv_refused> ::= <reply_500> | <reply_501> | <reply_502> | <reply_522> | <reply_530> | <reply_421> | <reply_error_epsv> | <reply_protected>  # RFC 2428 3: every reply of the command but the positive one
<exch_epsv_ok> ::= <Client:req_epsv> <Server:reply_229> (<DataControl:data_connect> | <DataControl:data_idle>)  # RFC 2428 3: positive reply: a data connection is set up (RFC 959 3.2): Fandango connects to the announced address (RFC 959 3.2, 4.1.2; RFC 2428 3) -> <state_data_ready>
<exch_epsv_refused> ::= <Client:req_epsv> <Server:rep_epsv_refused>  # RFC 2428 3: no data connection set up
<req_size> ::= <cmd_size> <SP> <arg_file> <CRLF>  # RFC 3659 4.1
<rep_size> ::= <reply_213_size> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_size> | <reply_protected>  # RFC 3659 4.1; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_size> ::= r'(?!(213|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 3659 4.1; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_size> ::= <error_code_size>  # RFC 3659 4.1: code of the first line of a multi-line reply
<error_last_size> ::= <error_code_size>  # RFC 3659 4.1: code of the last line of a multi-line reply (equal to the first)
<reply_error_size> ::= <error_code_size> <reply_tail> | <error_first_size> <reply_head> <reply_mid_line>* <error_last_size> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_size>: str(<r>.<error_first_size>) == str(<r>.<error_last_size>)
<exch_size> ::= <Client:req_size> <Server:rep_size>  # RFC 3659 4.1
<req_mdtm> ::= <cmd_mdtm> <SP> <arg_file> <CRLF>  # RFC 3659 3.1
<rep_mdtm> ::= <reply_213_mdtm> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_mdtm> | <reply_protected>  # RFC 3659 3.1; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_mdtm> ::= r'(?!(213|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 3659 3.1; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_mdtm> ::= <error_code_mdtm>  # RFC 3659 3.1: code of the first line of a multi-line reply
<error_last_mdtm> ::= <error_code_mdtm>  # RFC 3659 3.1: code of the last line of a multi-line reply (equal to the first)
<reply_error_mdtm> ::= <error_code_mdtm> <reply_tail> | <error_first_mdtm> <reply_head> <reply_mid_line>* <error_last_mdtm> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_mdtm>: str(<r>.<error_first_mdtm>) == str(<r>.<error_last_mdtm>)
<exch_mdtm> ::= <Client:req_mdtm> <Server:rep_mdtm>  # RFC 3659 3.1
<req_mlst> ::= <cmd_mlst> (<SP> <arg_path>)? <CRLF>  # RFC 3659 7.1
<rep_mlst> ::= <reply_250_mlst> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_421> | <reply_error_mlst> | <reply_protected>  # RFC 3659 7.1-7.2; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_mlst> ::= r'(?!(250|421|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 3659 7.1-7.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_mlst> ::= <error_code_mlst>  # RFC 3659 7.1-7.2: code of the first line of a multi-line reply
<error_last_mlst> ::= <error_code_mlst>  # RFC 3659 7.1-7.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_mlst> ::= <error_code_mlst> <reply_tail> | <error_first_mlst> <reply_head> <reply_mid_line>* <error_last_mlst> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_mlst>: str(<r>.<error_first_mlst>) == str(<r>.<error_last_mlst>)
<exch_mlst> ::= <Client:req_mlst> <Server:rep_mlst>  # RFC 3659 7.1
<req_feat> ::= <cmd_feat> <CRLF>  # RFC 2389 3.1
<rep_feat> ::= <reply_211_feat> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_feat> | <reply_protected>  # RFC 2389 3.2; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_feat> ::= r'(?!(211|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 2389 3.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_feat> ::= <error_code_feat>  # RFC 2389 3.2: code of the first line of a multi-line reply
<error_last_feat> ::= <error_code_feat>  # RFC 2389 3.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_feat> ::= <error_code_feat> <reply_tail> | <error_first_feat> <reply_head> <reply_mid_line>* <error_last_feat> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_feat>: str(<r>.<error_first_feat>) == str(<r>.<error_last_feat>)
<exch_feat> ::= <Client:req_feat> <Server:rep_feat>  # RFC 2389 3.1
<req_lang> ::= <cmd_lang> (<SP> <lang_tag>)? <CRLF>  # RFC 2640 4.2
<rep_lang> ::= <reply_200> | <reply_500> | <reply_501> | <reply_502> | <reply_504> | <reply_530> | <reply_421> | <reply_error_lang> | <reply_protected> | <reply_bare_lang>  # RFC 2640 4.2; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_lang> ::= r'(?!(200|421|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 2640 4.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_lang> ::= <error_code_lang>  # RFC 2640 4.2: code of the first line of a multi-line reply
<error_last_lang> ::= <error_code_lang>  # RFC 2640 4.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_lang> ::= <error_code_lang> <reply_tail> | <error_first_lang> <reply_head> <reply_mid_line>* <error_last_lang> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_lang>: str(<r>.<error_first_lang>) == str(<r>.<error_last_lang>)
<reply_bare_lang> ::= r'(200|500|501|502|504)\r\n'  # RFC 2640 4.2 / RFC 7151 3.1: the SP and the text of the reply are optional (a reply of the code only)
<exch_lang> ::= <Client:req_lang> <Server:rep_lang>  # RFC 2640 4.2
<req_pbsz> ::= <cmd_pbsz> <SP> <pbsz_arg> <CRLF>  # RFC 2228 3; RFC 4217 9
<rep_pbsz> ::= <reply_200> | <reply_503> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_533> | <reply_421> | <reply_error_pbsz> | <reply_protected>  # RFC 2228 8.2; RFC 2228 8.2: the documented codes, 530 (not logged in), 63z after a security exchange; RFC 1123 4.1.2.11: any other 4yz / 5yz
<error_code_pbsz> ::= r'(?!(200|421|500|501|502|503|530|533))[45][0-9]{2}'  # RFC 2228 8.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_pbsz> ::= <error_code_pbsz>  # RFC 2228 8.2: code of the first line of a multi-line reply
<error_last_pbsz> ::= <error_code_pbsz>  # RFC 2228 8.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_pbsz> ::= <error_code_pbsz> <reply_tail> | <error_first_pbsz> <reply_head> <reply_mid_line>* <error_last_pbsz> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_pbsz>: str(<r>.<error_first_pbsz>) == str(<r>.<error_last_pbsz>)
<exch_pbsz> ::= <Client:req_pbsz> <Server:rep_pbsz>  # RFC 2228 3; RFC 4217 9
<req_prot> ::= <cmd_prot> <SP> <prot_code> <CRLF>  # RFC 2228 3; RFC 4217 9
<rep_prot> ::= <reply_200> | <reply_504> | <reply_536> | <reply_503> | <reply_534> | <reply_431> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_533> | <reply_421> | <reply_error_prot> | <reply_protected>  # RFC 2228 8.2; RFC 2228 8.2: the documented codes, 530 (not logged in), 63z after a security exchange; RFC 1123 4.1.2.11: any other 4yz / 5yz
<error_code_prot> ::= r'(?!(200|421|431|500|501|502|503|504|530|533|534|536))[45][0-9]{2}'  # RFC 2228 8.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_prot> ::= <error_code_prot>  # RFC 2228 8.2: code of the first line of a multi-line reply
<error_last_prot> ::= <error_code_prot>  # RFC 2228 8.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_prot> ::= <error_code_prot> <reply_tail> | <error_first_prot> <reply_head> <reply_mid_line>* <error_last_prot> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_prot>: str(<r>.<error_first_prot>) == str(<r>.<error_last_prot>)
<exch_prot> ::= <Client:req_prot> <Server:rep_prot>  # RFC 2228 3; RFC 4217 9
<req_ccc> ::= <cmd_ccc> <CRLF>  # RFC 2228 3; RFC 4217 5
<rep_ccc> ::= <reply_200> | <reply_533> | <reply_534> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_ccc> | <reply_protected>  # RFC 2228 3 (CCC); RFC 4217 5; RFC 2228 8.2: the documented codes, 530 (not logged in), 63z after a security exchange; RFC 1123 4.1.2.11: any other 4yz / 5yz
<error_code_ccc> ::= r'(?!(200|421|500|501|502|530|533|534))[45][0-9]{2}'  # RFC 2228 3 (CCC); RFC 4217 5; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_ccc> ::= <error_code_ccc>  # RFC 2228 3 (CCC); RFC 4217 5: code of the first line of a multi-line reply
<error_last_ccc> ::= <error_code_ccc>  # RFC 2228 3 (CCC); RFC 4217 5: code of the last line of a multi-line reply (equal to the first)
<reply_error_ccc> ::= <error_code_ccc> <reply_tail> | <error_first_ccc> <reply_head> <reply_mid_line>* <error_last_ccc> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_ccc>: str(<r>.<error_first_ccc>) == str(<r>.<error_last_ccc>)
<exch_ccc> ::= <Client:req_ccc> <Server:rep_ccc>  # RFC 2228 3; RFC 4217 5
<req_mic> ::= <cmd_mic> <SP> <base64data> <CRLF>  # RFC 2228 3
<rep_mic> ::= <reply_535> | <reply_533> | <reply_537> | <reply_503> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_mic> | <reply_protected>  # RFC 2228 8.2; RFC 2228 8.2: the documented codes, 530 (not logged in), 63z after a security exchange; RFC 1123 4.1.2.11: any other 4yz / 5yz
<error_code_mic> ::= r'(?!(421|500|501|502|503|530|533|535|537))[45][0-9]{2}'  # RFC 2228 8.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_mic> ::= <error_code_mic>  # RFC 2228 8.2: code of the first line of a multi-line reply
<error_last_mic> ::= <error_code_mic>  # RFC 2228 8.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_mic> ::= <error_code_mic> <reply_tail> | <error_first_mic> <reply_head> <reply_mid_line>* <error_last_mic> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_mic>: str(<r>.<error_first_mic>) == str(<r>.<error_last_mic>)
<exch_mic> ::= <Client:req_mic> <Server:rep_mic>  # RFC 2228 3
<req_conf> ::= <cmd_conf> <SP> <base64data> <CRLF>  # RFC 2228 3
<rep_conf> ::= <reply_535> | <reply_533> | <reply_537> | <reply_503> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_conf> | <reply_protected>  # RFC 2228 8.2; RFC 2228 8.2: the documented codes, 530 (not logged in), 63z after a security exchange; RFC 1123 4.1.2.11: any other 4yz / 5yz
<error_code_conf> ::= r'(?!(421|500|501|502|503|530|533|535|537))[45][0-9]{2}'  # RFC 2228 8.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_conf> ::= <error_code_conf>  # RFC 2228 8.2: code of the first line of a multi-line reply
<error_last_conf> ::= <error_code_conf>  # RFC 2228 8.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_conf> ::= <error_code_conf> <reply_tail> | <error_first_conf> <reply_head> <reply_mid_line>* <error_last_conf> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_conf>: str(<r>.<error_first_conf>) == str(<r>.<error_last_conf>)
<exch_conf> ::= <Client:req_conf> <Server:rep_conf>  # RFC 2228 3
<req_enc> ::= <cmd_enc> <SP> <base64data> <CRLF>  # RFC 2228 3
<rep_enc> ::= <reply_535> | <reply_533> | <reply_537> | <reply_503> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_enc> | <reply_protected>  # RFC 2228 8.2; RFC 2228 8.2: the documented codes, 530 (not logged in), 63z after a security exchange; RFC 1123 4.1.2.11: any other 4yz / 5yz
<error_code_enc> ::= r'(?!(421|500|501|502|503|530|533|535|537))[45][0-9]{2}'  # RFC 2228 8.2; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_enc> ::= <error_code_enc>  # RFC 2228 8.2: code of the first line of a multi-line reply
<error_last_enc> ::= <error_code_enc>  # RFC 2228 8.2: code of the last line of a multi-line reply (equal to the first)
<reply_error_enc> ::= <error_code_enc> <reply_tail> | <error_first_enc> <reply_head> <reply_mid_line>* <error_last_enc> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_enc>: str(<r>.<error_first_enc>) == str(<r>.<error_last_enc>)
<exch_enc> ::= <Client:req_enc> <Server:rep_enc>  # RFC 2228 3
<req_opts_mlst> ::= <cmd_opts> <SP> <opts_mlst_arg> <CRLF>  # RFC 2389 4; RFC 3659 7.9
<rep_opts_mlst> ::= <reply_200> | <reply_451> | <reply_501> | <reply_500> | <reply_502> | <reply_504> | <reply_530> | <reply_421> | <reply_error_opts_mlst> | <reply_protected>  # RFC 2389 4; RFC 3659 7.9; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_opts_mlst> ::= r'(?!(200|421|451|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 2389 4; RFC 3659 7.9; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_opts_mlst> ::= <error_code_opts_mlst>  # RFC 2389 4; RFC 3659 7.9: code of the first line of a multi-line reply
<error_last_opts_mlst> ::= <error_code_opts_mlst>  # RFC 2389 4; RFC 3659 7.9: code of the last line of a multi-line reply (equal to the first)
<reply_error_opts_mlst> ::= <error_code_opts_mlst> <reply_tail> | <error_first_opts_mlst> <reply_head> <reply_mid_line>* <error_last_opts_mlst> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_opts_mlst>: str(<r>.<error_first_opts_mlst>) == str(<r>.<error_last_opts_mlst>)
<exch_opts_mlst> ::= <Client:req_opts_mlst> <Server:rep_opts_mlst>  # RFC 2389 4; RFC 3659 7.9
<req_opts_other> ::= <cmd_opts> <SP> <opts_other_arg> <CRLF>  # RFC 2389 4
<rep_opts_other> ::= <reply_200> | <reply_451> | <reply_501> | <reply_500> | <reply_502> | <reply_504> | <reply_530> | <reply_421> | <reply_error_opts_other> | <reply_protected>  # RFC 2389 4; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_opts_other> ::= r'(?!(200|421|451|500|501|502|504|530))[2-5][0-9]{2}'  # RFC 2389 4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_opts_other> ::= <error_code_opts_other>  # RFC 2389 4: code of the first line of a multi-line reply
<error_last_opts_other> ::= <error_code_opts_other>  # RFC 2389 4: code of the last line of a multi-line reply (equal to the first)
<reply_error_opts_other> ::= <error_code_opts_other> <reply_tail> | <error_first_opts_other> <reply_head> <reply_mid_line>* <error_last_opts_other> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_opts_other>: str(<r>.<error_first_opts_other>) == str(<r>.<error_last_opts_other>)
<exch_opts_other> ::= <Client:req_opts_other> <Server:rep_opts_other>  # RFC 2389 4
<req_host> ::= <cmd_host> <SP> <hostname> <CRLF>  # RFC 7151 3.1
<rep_host> ::= <reply_220> | <reply_504> | <reply_501> | <reply_503> | <reply_500> | <reply_502> | <reply_530> | <reply_421> | <reply_error_host> | <reply_protected> | <reply_bare_host>  # RFC 7151 3.1, 3.2.3; RFC 959 4.2.1 (500, 501, 502, 530); RFC 1123 4.1.2.11 (any other 4yz / 5yz)
<error_code_host> ::= r'(?!(220|421|500|501|502|503|504|530))[2-5][0-9]{2}'  # RFC 7151 3.1, 3.2.3; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_host> ::= <error_code_host>  # RFC 7151 3.1, 3.2.3: code of the first line of a multi-line reply
<error_last_host> ::= <error_code_host>  # RFC 7151 3.1, 3.2.3: code of the last line of a multi-line reply (equal to the first)
<reply_error_host> ::= <error_code_host> <reply_tail> | <error_first_host> <reply_head> <reply_mid_line>* <error_last_host> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_host>: str(<r>.<error_first_host>) == str(<r>.<error_last_host>)
<reply_bare_host> ::= r'(220|504|501|503|500|502)\r\n'  # RFC 2640 4.2 / RFC 7151 3.1: the SP and the text of the reply are optional (a reply of the code only)
<exch_host> ::= <Client:req_host> <Server:rep_host>  # RFC 7151 3.1

# RFC 959 5.4, RFC 2228 8.2, RFC 3659 7.1: commands that need a data connection. Without a data connection the server
# refuses (425) or, when it waits for the client's data connection, stays silent: the timer ends the wait (see timers).
# RFC 959 5.4: the 125 / 150 reply, then (RETR, STOR, STOU, APPE) restart markers (110) before the completion reply
<new_prelim_code> ::= r'(?!(110|120|125|150))1[0-9]{2}'   # RFC 959 4.2, RFC 1123 4.1.2.11: another preliminary (1yz) reply code (class digit 1, function group x0z-x5z)
<new_prelim_first> ::= <new_prelim_code>   # code of the first line of a multi-line reply
<new_prelim_last> ::= <new_prelim_code>   # code of the last line of a multi-line reply (equal to the first)
<reply_new_prelim> ::= <new_prelim_code> <reply_tail> | <new_prelim_first> <reply_head> <reply_mid_line>* <new_prelim_last> <reply_tail>   # RFC 959 4.2: a 1yz reply, single- or multi-line
where forall <r> in <reply_new_prelim>: str(<r>.<new_prelim_first>) == str(<r>.<new_prelim_last>)
<reply_prelim> ::= <reply_125> | <reply_150> | <reply_new_prelim>   # RFC 959 4.2.1 (125, 150); RFC 1123 4.1.2.11 (another 1yz code)
<reply_prelim_marks> ::= <reply_prelim> <reply_110>*   # RFC 959 5.4: 125/150 (110) ; RFC 1123 4.1.3.4: one 110 reply per marker
<reply_bare_150> ::= r'150\r\n'   # RFC 3659 7.2: initial-response = "150" [ SP response-message ] CRLF
<reply_prelim_mlsd> ::= <reply_prelim> | <reply_bare_150>   # RFC 3659 7.2: initial-response
<req_retr> ::= <cmd_retr> <SP> <arg_file> <CRLF>  # RFC 959 4.1.3
<error_code_retr> ::= r'(?!(226|250|421|425|426|450|451|500|501|502|530|534|535|550|554|555))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_retr> ::= <error_code_retr>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_retr> ::= <error_code_retr>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_retr> ::= <error_code_retr> <reply_tail> | <error_first_retr> <reply_head> <reply_mid_line>* <error_last_retr> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_retr>: str(<r>.<error_first_retr>) == str(<r>.<error_last_retr>)
<rep_retr_nodata> ::= <rep_retr_done> | <rep_retr_ended> | <rep_retr_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)
<req_stor> ::= <cmd_stor> <SP> <arg_store> <CRLF>  # RFC 959 4.1.3
<error_code_stor> ::= r'(?!(226|250|421|425|426|450|451|452|500|501|502|530|532|534|535|551|552|553|554|555))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_stor> ::= <error_code_stor>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_stor> ::= <error_code_stor>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_stor> ::= <error_code_stor> <reply_tail> | <error_first_stor> <reply_head> <reply_mid_line>* <error_last_stor> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_stor>: str(<r>.<error_first_stor>) == str(<r>.<error_last_stor>)
<rep_stor_nodata> ::= <rep_stor_done> | <rep_stor_ended> | <rep_stor_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)
<req_stou> ::= <cmd_stou> <CRLF>  # RFC 959 4.1.3; RFC 1123 4.1.2.9
<stou_name> ::= r'[^\r\n]+'   # RFC 1123 4.1.2.9: the unique name 'pppp'
<stou_prelim> ::= <code_125> <SP> 'FILE:' <SP> <stou_name> <CRLF> | <code_150> <SP> 'FILE:' <SP> <stou_name> <CRLF> | <code_125> '-' <SP>? 'FILE:' <SP> <stou_name> <CRLF> <reply_mid_line>* <code_125> <reply_tail> | <code_150> '-' <SP>? 'FILE:' <SP> <stou_name> <CRLF> <reply_mid_line>* <code_150> <reply_tail>   # RFC 1123 4.1.2.9: '125 FILE: pppp' / '150 FILE: pppp'; RFC 959 4.2: the same reply as a multi-line reply whose first line names the file
<error_code_stou> ::= r'(?!(226|250|421|425|426|450|451|452|500|501|502|530|532|534|535|551|552|553|554|555))[345][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_stou> ::= <error_code_stou>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_stou> ::= <error_code_stou>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_stou> ::= <error_code_stou> <reply_tail> | <error_first_stou> <reply_head> <reply_mid_line>* <error_last_stou> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_stou>: str(<r>.<error_first_stou>) == str(<r>.<error_last_stou>)
<error_code_stou_after_prelim> ::= r'(?!(226|250|421|425|426|450|451|452|500|501|502|530|532|534|535|551|552|553|554|555))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_stou_after_prelim> ::= <error_code_stou_after_prelim>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_stou_after_prelim> ::= <error_code_stou_after_prelim>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_stou_after_prelim> ::= <error_code_stou_after_prelim> <reply_tail> | <error_first_stou_after_prelim> <reply_head> <reply_mid_line>* <error_last_stou_after_prelim> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_stou_after_prelim>: str(<r>.<error_first_stou_after_prelim>) == str(<r>.<error_last_stou_after_prelim>)
<stou_prelim_marks> ::= <stou_prelim> <reply_110>*   # RFC 959 5.4, RFC 1123 4.1.2.9: 125/150 FILE: pppp, then restart markers
<rep_stou_nodata> ::= <rep_stou_done> | <rep_stou_ended> | <rep_stou_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)
<req_appe> ::= <cmd_appe> <SP> <arg_append> <CRLF>  # RFC 959 4.1.3
<error_code_appe> ::= r'(?!(226|250|421|425|426|450|451|452|500|501|502|530|532|534|535|550|551|552|553|554|555))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_appe> ::= <error_code_appe>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_appe> ::= <error_code_appe>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_appe> ::= <error_code_appe> <reply_tail> | <error_first_appe> <reply_head> <reply_mid_line>* <error_last_appe> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_appe>: str(<r>.<error_first_appe>) == str(<r>.<error_last_appe>)
<rep_appe_nodata> ::= <rep_appe_done> | <rep_appe_ended> | <rep_appe_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)
<req_list> ::= <cmd_list> (<SP> <arg_path>)? <CRLF>  # RFC 959 4.1.3
<error_code_list> ::= r'(?!(226|250|421|425|426|450|451|500|501|502|530|534|535))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_list> ::= <error_code_list>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_list> ::= <error_code_list>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_list> ::= <error_code_list> <reply_tail> | <error_first_list> <reply_head> <reply_mid_line>* <error_last_list> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_list>: str(<r>.<error_first_list>) == str(<r>.<error_last_list>)
<rep_list_nodata> ::= <rep_list_done> | <rep_list_ended> | <rep_list_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)
<req_nlst> ::= <cmd_nlst> (<SP> <arg_path>)? <CRLF>  # RFC 959 4.1.3
<error_code_nlst> ::= r'(?!(226|250|421|425|426|450|451|500|501|502|530|534|535))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_nlst> ::= <error_code_nlst>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_nlst> ::= <error_code_nlst>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_nlst> ::= <error_code_nlst> <reply_tail> | <error_first_nlst> <reply_head> <reply_mid_line>* <error_last_nlst> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_nlst>: str(<r>.<error_first_nlst>) == str(<r>.<error_last_nlst>)
<rep_nlst_nodata> ::= <rep_nlst_done> | <rep_nlst_ended> | <rep_nlst_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)
<req_mlsd> ::= <cmd_mlsd> (<SP> <arg_path>)? <CRLF>  # RFC 3659 7.1
<error_code_mlsd> ::= r'(?!(226|250|421|425|426|450|451|500|501|502|530|550))[2-5][0-9]{2}'  # RFC 959 5.4; RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_mlsd> ::= <error_code_mlsd>  # RFC 959 5.4: code of the first line of a multi-line reply
<error_last_mlsd> ::= <error_code_mlsd>  # RFC 959 5.4: code of the last line of a multi-line reply (equal to the first)
<reply_error_mlsd> ::= <error_code_mlsd> <reply_tail> | <error_first_mlsd> <reply_head> <reply_mid_line>* <error_last_mlsd> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_mlsd>: str(<r>.<error_first_mlsd>) == str(<r>.<error_last_mlsd>)
<rep_mlsd_nodata> ::= <rep_mlsd_done> | <rep_mlsd_ended> | <rep_mlsd_failed>   # RFC 959 3.2, 5.4: no data connection set up (no PORT/PASV/EPRT/EPSV answered positively): the replies of any transfer command (the default data connection, RFC 959 3.2)

# Exchanges of the transfer commands. In the states where no data connection was set up (RFC 959 3.2: PORT, PASV, EPRT, EPSV answered positively) the
# reply is a refusal (`rep_X_nodata`). In <state_data_ready> (a data connection is pending) the server may wait for the client's data connection, which a
# session of one connection cannot open: the timer ends the wait for a reply the server does not send; the silent alternatives end the session.
<exch_retr> ::= <Client:req_retr> <Server:rep_retr_nodata>  # RFC 959 4.1.3; no data connection set up: refused
<rep_retr_done> ::= <reply_prelim_marks>? (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_retr_ended> ::= <reply_prelim_marks>? (<reply_425> | <reply_426>)   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_retr_failed> ::= <reply_prelim_marks>? (<reply_451> | <reply_450> | <reply_550> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_530> | <reply_554> | <reply_555> | <reply_502> | <reply_421> | <reply_error_retr> | <reply_protected>)  # RFC 959 5.4: the transfer was refused for another reason (file unavailable, syntax, ...): a data connection set up before stays pending
<exch_retr_dr> ::= <TimerControl:transfer_start> <Client:req_retr> (<Server:rep_retr_done> <transfer_tail_data_ready> | <Server:rep_retr_ended> <transfer_tail_logged_in> | <Server:rep_retr_failed> <transfer_tail_data_ready> | <Server:reply_prelim_marks> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 959 4.1.3; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
<exch_stor> ::= <Client:req_stor> <Server:rep_stor_nodata>  # RFC 959 4.1.3; no data connection set up: refused
<rep_stor_done> ::= <reply_prelim_marks>? (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_stor_ended> ::= <reply_prelim_marks>? (<reply_425> | <reply_426>)   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_stor_failed> ::= <reply_prelim_marks>? (<reply_451> | <reply_551> | <reply_552> | <reply_532> | <reply_450> | <reply_452> | <reply_553> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_530> | <reply_554> | <reply_555> | <reply_502> | <reply_421> | <reply_error_stor> | <reply_protected>)  # RFC 959 5.4: the transfer was refused for another reason (file unavailable, syntax, ...): a data connection set up before stays pending
<exch_stor_dr> ::= <TimerControl:transfer_start> <Client:req_stor> (<Server:rep_stor_done> <transfer_tail_data_ready> | <Server:rep_stor_ended> <transfer_tail_logged_in> | <Server:rep_stor_failed> <transfer_tail_data_ready> | <Server:reply_prelim_marks> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 959 4.1.3; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
<exch_stou> ::= <Client:req_stou> <Server:rep_stou_nodata>  # RFC 959 4.1.3; RFC 1123 4.1.2.9; no data connection set up: refused
<rep_stou_done> ::= <reply_new_prelim>? <stou_prelim_marks> (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_stou_ended> ::= (<stou_prelim_marks> | <reply_new_prelim>) (<reply_425> | <reply_426>) | <reply_425> | <reply_426>   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_stou_failed> ::= <reply_new_prelim>? <stou_prelim_marks> (<reply_451> | <reply_551> | <reply_552> | <reply_532> | <reply_450> | <reply_452> | <reply_553> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_530> | <reply_554> | <reply_555> | <reply_502> | <reply_421> | <reply_error_stou_after_prelim> | <reply_protected>) | <reply_new_prelim> (<reply_451> | <reply_551> | <reply_552> | <reply_532> | <reply_450> | <reply_452> | <reply_553> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_530> | <reply_554> | <reply_555> | <reply_502> | <reply_421> | <reply_error_stou> | <reply_protected>) | <reply_451> | <reply_551> | <reply_552> | <reply_532> | <reply_450> | <reply_452> | <reply_553> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_530> | <reply_554> | <reply_555> | <reply_502> | <reply_421> | <reply_error_stou> | <reply_protected>   # RFC 959 5.4: the transfer was refused for another reason: a data connection set up before stays pending
<exch_stou_dr> ::= <TimerControl:transfer_start> <Client:req_stou> (<Server:rep_stou_done> <transfer_tail_data_ready> | <Server:rep_stou_ended> <transfer_tail_logged_in> | <Server:rep_stou_failed> <transfer_tail_data_ready> | (<Server:stou_prelim_marks> | <Server:reply_new_prelim>) <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 959 4.1.3; RFC 1123 4.1.2.9; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
<exch_appe> ::= <Client:req_appe> <Server:rep_appe_nodata>  # RFC 959 4.1.3; no data connection set up: refused
<rep_appe_done> ::= <reply_prelim_marks>? (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_appe_ended> ::= <reply_prelim_marks>? (<reply_425> | <reply_426>)   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_appe_failed> ::= <reply_prelim_marks>? (<reply_451> | <reply_551> | <reply_552> | <reply_532> | <reply_450> | <reply_550> | <reply_452> | <reply_553> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_554> | <reply_555> | <reply_421> | <reply_error_appe> | <reply_protected>)  # RFC 959 5.4: the transfer was refused for another reason (file unavailable, syntax, ...): a data connection set up before stays pending
<exch_appe_dr> ::= <TimerControl:transfer_start> <Client:req_appe> (<Server:rep_appe_done> <transfer_tail_data_ready> | <Server:rep_appe_ended> <transfer_tail_logged_in> | <Server:rep_appe_failed> <transfer_tail_data_ready> | <Server:reply_prelim_marks> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 959 4.1.3; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
<exch_list> ::= <Client:req_list> <Server:rep_list_nodata>  # RFC 959 4.1.3; no data connection set up: refused
<rep_list_done> ::= <reply_prelim>? (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_list_ended> ::= <reply_prelim>? (<reply_425> | <reply_426>)   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_list_failed> ::= <reply_prelim>? (<reply_451> | <reply_450> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_list> | <reply_protected>)  # RFC 959 5.4: the transfer was refused for another reason (file unavailable, syntax, ...): a data connection set up before stays pending
<exch_list_dr> ::= <TimerControl:transfer_start> <Client:req_list> (<Server:rep_list_done> <transfer_tail_data_ready> | <Server:rep_list_ended> <transfer_tail_logged_in> | <Server:rep_list_failed> <transfer_tail_data_ready> | <Server:reply_prelim> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 959 4.1.3; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
<exch_nlst> ::= <Client:req_nlst> <Server:rep_nlst_nodata>  # RFC 959 4.1.3; no data connection set up: refused
<rep_nlst_done> ::= <reply_prelim>? (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_nlst_ended> ::= <reply_prelim>? (<reply_425> | <reply_426>)   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_nlst_failed> ::= <reply_prelim>? (<reply_451> | <reply_450> | <reply_534> | <reply_535> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_nlst> | <reply_protected>)  # RFC 959 5.4: the transfer was refused for another reason (file unavailable, syntax, ...): a data connection set up before stays pending
<exch_nlst_dr> ::= <TimerControl:transfer_start> <Client:req_nlst> (<Server:rep_nlst_done> <transfer_tail_data_ready> | <Server:rep_nlst_ended> <transfer_tail_logged_in> | <Server:rep_nlst_failed> <transfer_tail_data_ready> | <Server:reply_prelim> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 959 4.1.3; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
<exch_mlsd> ::= <Client:req_mlsd> <Server:rep_mlsd_nodata>  # RFC 3659 7.1; no data connection set up: refused
<rep_mlsd_done> ::= <reply_prelim_mlsd>? (<reply_226> | <reply_250>)   # RFC 959 3.2, 5.4: the transfer ended (226/250); a server may still wait for another data connection (Pure-FTPd keeps its passive listener)
<rep_mlsd_ended> ::= <reply_prelim_mlsd>? (<reply_425> | <reply_426>)   # RFC 959 3.2, 5.4: the data connection could not be used (425) or was closed (426): the data connection is used up
<rep_mlsd_failed> ::= <reply_prelim_mlsd>? (<reply_451> | <reply_450> | <reply_550> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_mlsd> | <reply_protected>)  # RFC 959 5.4: the transfer was refused for another reason (file unavailable, syntax, ...): a data connection set up before stays pending
<exch_mlsd_dr> ::= <TimerControl:transfer_start> <Client:req_mlsd> (<Server:rep_mlsd_done> <transfer_tail_data_ready> | <Server:rep_mlsd_ended> <transfer_tail_logged_in> | <Server:rep_mlsd_failed> <transfer_tail_data_ready> | <Server:reply_prelim_mlsd> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)  # RFC 3659 7.1; RFC 959 3.2: a data connection was set up by PASV/EPSV/PORT/EPRT; after a completed transfer (226/250) the state stays <state_data_ready> (a server may keep its passive listener after a transfer, Pure-FTPd does: the next transfer command then waits for a connection; vsftpd and ProFTPD answer 425), after 425/426 the data connection is used up (<state_logged_in>); the server may wait for the client's data connection: silence (the timer expires)
# ---------------------------------------------------------------------------------------------------------------
# Command arguments (sent) and carried formats; the syntax of each field is one rule used by sent and received messages
# ---------------------------------------------------------------------------------------------------------------
# RFC 959 5.3.2 <structure-code> ::= F | R | P (one nonterminal per value; the letter is case independent, 5.3.1)
<structure_f> ::= r'[Ff]'   # RFC 959 3.1.2.1 file structure
<structure_r> ::= r'[Rr]'   # RFC 959 3.1.2.2 record structure
<structure_p> ::= r'[Pp]'   # RFC 959 3.1.2.3 page structure
<structure_code> ::= <structure_f> | <structure_r> | <structure_p>   # RFC 959 5.3.2
# RFC 959 5.3.2 <mode-code> ::= S | B | C
<mode_s> ::= r'[Ss]'   # RFC 959 3.4.1 stream
<mode_b> ::= r'[Bb]'   # RFC 959 3.4.2 block
<mode_c> ::= r'[Cc]'   # RFC 959 3.4.3 compressed
<mode_code> ::= <mode_s> | <mode_b> | <mode_c>                         # RFC 959 5.3.2
# RFC 959 5.3.2 <form-code> ::= N | T | C
<form_n> ::= r'[Nn]'   # RFC 959 3.1.1.5.1 non-print
<form_t> ::= r'[Tt]'   # RFC 959 3.1.1.5.2 telnet format effectors
<form_c> ::= r'[Cc]'   # RFC 959 3.1.1.5.2 carriage control (ASA)
<form_code> ::= <form_n> | <form_t> | <form_c>                         # RFC 959 5.3.2
# RFC 959 5.3.2 <type-code> ::= A [<sp> <form-code>] | E [<sp> <form-code>] | I | L <sp> <byte-size>; <byte-size> ::= <number>
<type_a> ::= r'[Aa]'   # RFC 959 3.1.1.1 ASCII
<type_e> ::= r'[Ee]'   # RFC 959 3.1.1.2 EBCDIC
<type_i> ::= r'[Ii]'   # RFC 959 3.1.1.3 image
<type_l> ::= r'[Ll]'   # RFC 959 3.1.1.4 local byte
<byte_size> ::= r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?)'                                               # RFC 959 5.3.2; 3.1.1.4: the second parameter of L is obligatory
<type_code> ::= <type_a> (<SP> <form_code>)? | <type_e> (<SP> <form_code>)? | <type_i> | <type_l> <SP> <byte_size>   # RFC 959 5.3.2
# RFC 959 5.3.1 ALLO <SP> <decimal-integer> [<SP> R <SP> <decimal-integer>]
<allo_r> ::= r'[Rr]'   # RFC 959 4.1.3 ALLO: maximum record or page size
# RFC 959 5.3.2 <marker> ::= <pr-string>; RFC 3659 5.3 rest = "Rest" SP 1*DIGIT (STREAM mode offset, digits are pr-chars)
<marker> ::= r'[!-~]+' := pick_marker()
def pick_marker():
    return str(random.choice([0, 1, 3, 5, 100, 4096])) if random.random() < 0.7 else "".join(random.choice("0123456789abcXYZ") for _ in range(random.randint(1, 8)))

# RFC 959 5.3.2: <host-port> ::= <host-number>,<port-number>; <host-number> ::= <number>,<number>,<number>,<number>;
# <port-number> ::= <number>,<number>
<host_number> ::= <number> ',' <number> ',' <number> ',' <number>
<port_number> ::= <number> ',' <number>  # RFC 959 5.3.2 (host-port)
<host_port> ::= <host_number> ',' <port_number>  # RFC 959 5.3.2 (host-port)
# Sent PORT: the address of the test host and a port nothing listens on, so that the server's connection attempt is
# refused (a PORT naming a third party would make the server talk to it).
<host_port_data> ::= <data_host_number> ',' <data_port_number>
<data_host_number> ::= <data_octet_1> ',' <data_octet_2> ',' <data_octet_3> ',' <data_octet_4>  # RFC 959 5.3.2 (host-port)
<data_octet_1> ::= <number> := FTP_DATA_ADDRESS.split(".")[0]  # RFC 959 5.3.2 (host-port)
<data_octet_2> ::= <number> := FTP_DATA_ADDRESS.split(".")[1]  # RFC 959 5.3.2 (host-port)
<data_octet_3> ::= <number> := FTP_DATA_ADDRESS.split(".")[2]  # RFC 959 5.3.2 (host-port)
<data_octet_4> ::= <number> := FTP_DATA_ADDRESS.split(".")[3]  # RFC 959 5.3.2 (host-port)
<data_port_number> ::= <port_high> ',' <port_low>  # RFC 959 5.3.2 (host-port)
<port_high> ::= <number> := str(random.choice(FTP_DATA_PORTS + FTP_CLOSED_PORTS) // 256)  # RFC 959 5.3.2 (host-port)
<port_low> ::= <number>   # the low byte of a port of FTP_DATA_PORTS or FTP_CLOSED_PORTS with that high byte (equality below)
where forall <p> in <data_port_number>: str(<p>.<port_low>) == data_port_low(str(<p>.<port_high>))
def data_port_low(high):
    return str(min([port % 256 for port in FTP_DATA_PORTS + FTP_CLOSED_PORTS if str(port // 256) == high] or [0]))

# RFC 2428 2: EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>; <d> is a delimiter, ASCII 33-126
<epsv_delim> ::= r'[!-~]'        # RFC 2428 2: the delimiter is any ASCII character 33-126 (the sent EPRT draws one that does not coincide with the address)
<net_prt> ::= r'[0-9]+'          # RFC 2428 2: an address family number
<net_prt_1> ::= <net_prt> := '1'   # RFC 2428 2: AF number 1, Internet Protocol version 4 (the shared rule, narrowed)
<net_prt_2> ::= <net_prt> := '2'   # RFC 2428 2: AF number 2, Internet Protocol version 6 (the shared rule, narrowed)
<tcp_port> ::= r'[0-9]{1,5}'     # RFC 2428 2: string representation of the TCP port number
<eprt_arg> ::= <eprt_ipv4> | <eprt_ipv6>  # RFC 2428 2 (EPRT)
# the five <d> of one argument are the same delimiter character (the first one is generated, the others equal it)
<eprt_d1> ::= <epsv_delim> := random.choice(["|"] * 24 + [c for c in map(chr, range(33, 127)) if c not in "0123456789abcdefABCDEF.:%"])   # narrowed: a delimiter that cannot coincide with the address
<eprt_d2> ::= <epsv_delim>  # RFC 2428 2 (EPRT)
<eprt_d3> ::= <epsv_delim>  # RFC 2428 2 (EPRT)
<eprt_d4> ::= <epsv_delim>  # RFC 2428 2 (EPRT)
<eprt_ipv4> ::= <eprt_d1> <net_prt_1> <eprt_d2> <eprt_ipv4_addr> <eprt_d3> <eprt_port> <eprt_d4>   # RFC 2428 2, AF 1
<eprt_ipv6> ::= <eprt_d1> <net_prt_2> <eprt_d2> <eprt_ipv6_addr> <eprt_d3> <eprt_port> <eprt_d4>   # RFC 2428 2, AF 2
<eprt_ipv4_addr> ::= r'[0-9]{1,3}(\.[0-9]{1,3}){3}' := FTP_DATA_ADDRESS  # RFC 2428 2 (EPRT)
<eprt_ipv6_addr> ::= r'[0-9A-Fa-f:.]+' := "::1"  # RFC 2428 2 (EPRT)
<eprt_port> ::= <tcp_port> := str(random.choice(FTP_DATA_PORTS + FTP_CLOSED_PORTS))  # RFC 2428 2 (EPRT)
where forall <e> in <eprt_ipv4>: str(<e>.<eprt_d2>) == str(<e>.<eprt_d1>)
where forall <e> in <eprt_ipv4>: str(<e>.<eprt_d3>) == str(<e>.<eprt_d1>)
where forall <e> in <eprt_ipv4>: str(<e>.<eprt_d4>) == str(<e>.<eprt_d1>)
where forall <e> in <eprt_ipv6>: str(<e>.<eprt_d2>) == str(<e>.<eprt_d1>)
where forall <e> in <eprt_ipv6>: str(<e>.<eprt_d3>) == str(<e>.<eprt_d1>)
where forall <e> in <eprt_ipv6>: str(<e>.<eprt_d4>) == str(<e>.<eprt_d1>)
# RFC 2428 3: EPSV [<net-prt>] or EPSV ALL
<net_prt_other> ::= <net_prt> := str(random.choice(FTP_OTHER_ADDRESS_FAMILIES))   # RFC 2428 2: another IANA address family number (the server must answer 522 if it does not support it)
<epsv_net_prt> ::= <net_prt_1> | <net_prt_2> | <net_prt_other>  # RFC 2428 2 (EPRT)

# RFC 2640 4.2: lang-tag = Primary-tag *( "-" Sub-tag)
<lang_tag_text> ::= r'[A-Za-z]{1,8}(-[A-Za-z]{1,8})*'   # RFC 2640 4.2: lang-tag = Primary-tag *( "-" Sub-tag); Primary-tag = 1*8ALPHA, Sub-tag = 1*8ALPHA
<lang_tag> ::= <lang_tag_text> := lang_tag_value()   # a tag of the setup, or any tag of the rule (the server answers 504 for one it does not support)
def lang_tag_value():
    if random.random() < 0.6:
        return random.choice(FTP_LANGUAGE_TAGS)
    return "-".join("".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(random.randint(1, 8))) for _ in range(random.randint(1, 3)))
# RFC 2228 8.1: PBSZ <SP> <decimal-integer>; RFC 4217 9: for TLS the parameter is '0'
<pbsz_size> ::= r'[0-9]+' := str(random.choice([0, 0, 0, 1, 4096, 65536, 2**32 - 1, 2**32 - 2, 2**31, 2**32, 2**64, 10**30]))
# RFC 2228 8.1: PBSZ takes a decimal integer; the sent argument is a decimal integer or any other string (the server answers 501 for one it cannot parse)
<pbsz_arg> ::= <pbsz_size> | <string>
# RFC 2228 8.1: <prot-code> ::= C | S | E | P (RFC 4217 9: only C and P with TLS)
<prot_c> ::= r'[Cc]'   # RFC 2228 3: Clear
<prot_s> ::= r'[Ss]'   # RFC 2228 3: Safe
<prot_e> ::= r'[Ee]'   # RFC 2228 3: Confidential
<prot_p> ::= r'[Pp]'   # RFC 2228 3: Private
<prot_code> ::= <prot_c> | <prot_s> | <prot_e> | <prot_p>  # RFC 2228 8.1 (PROT)
# RFC 2228 8.1 / 9 / 10: <base64data>, base 64 encoding (RFC 2228 10)
<base64_ok> ::= r'([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)' := random_base64()   # RFC 2228 10: base 64 encoding
<base64_bad> ::= r'[A-Za-z0-9+/=]*[!-*,\-.:-<>-@\[-`{-~][A-Za-z0-9+/=]*' := bad_base64()   # RFC 2228 3, 8.1: <base64data> ::= <string>; an argument that cannot be base-64 decoded (a character outside the alphabet): the server answers 501
<base64data> ::= <base64_ok> | <base64_bad>   # RFC 2228 8.1
def bad_base64():
    text = random_base64() + random.choice("!\"#$%&'()*,-.:;<>?@[\\]^_`{|}~")
    position = random.randint(0, len(text) - 1)
    return text[:position] + text[-1] + text[position:-1]
def random_base64():
    import base64
    return base64.b64encode(bytes(random.randint(0, 255) for _ in range(random.randint(1, 24)))).decode("ascii")
# RFC 2389 4: OPTS <SP> command-name [<SP> command-options]
<opts_other_text> ::= r'(?![Mm][Ll][Ss][Tt]([ \r]|$))([\x00-\x09\x0b\x0c\x0e-\x7f\u00a1-\u017f\u0400-\u04ff\u4e00-\u4e5f]|\r\x00)+'   # RFC 2389 4: command-name [SP command-options]
<opts_other_known> ::= <opts_other_text> := pick_from(FTP_OPTS_ARGS)   # RFC 2389 4: arguments of the setup
<opts_other_arg> ::= <opts_other_known> | <opts_other_text>   # RFC 2389 4: OPTS command-name [SP command-options]
# RFC 3659 7.9: mlst-opts = "OPTS" SP "MLST" [ SP 1*( factname ";" ) ]
<opts_mlst_word> ::= r'[Mm][Ll][Ss][Tt]'
<opts_mlst_arg> ::= <opts_mlst_word> (<SP> <opts_mlst_fact>+)?  # RFC 3659 7.9 (OPTS MLST)
<opts_mlst_fact> ::= <fact_name> ';'  # RFC 3659 7.9 (OPTS MLST)
# RFC 7151 3.1: hostname = domain / IP-literal; IP-literal = ("[" IPv6address "]") / IPv4address; IPv6address and IPv4address as in RFC 3986 3.2.2
<host_dec_octet> ::= r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'   # RFC 3986 3.2.2 dec-octet
<host_ipv4> ::= r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}'   # RFC 3986 3.2.2 IPv4address
<host_ipv6_a> ::= r'([0-9A-Fa-f]{1,4}:){6}([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 1 of 9
<host_ipv6_b> ::= r'::([0-9A-Fa-f]{1,4}:){5}([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 2 of 9
<host_ipv6_c> ::= r'([0-9A-Fa-f]{1,4})?::([0-9A-Fa-f]{1,4}:){4}([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 3 of 9
<host_ipv6_d> ::= r'(([0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4})?::([0-9A-Fa-f]{1,4}:){3}([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 4 of 9
<host_ipv6_e> ::= r'(([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})?::([0-9A-Fa-f]{1,4}:){2}([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 5 of 9
<host_ipv6_f> ::= r'(([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 6 of 9
<host_ipv6_g> ::= r'(([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})?::([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})'   # RFC 3986 3.2.2 IPv6address, form 7 of 9
<host_ipv6_h> ::= r'(([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}'   # RFC 3986 3.2.2 IPv6address, form 8 of 9
<host_ipv6_i> ::= r'(([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})?::'   # RFC 3986 3.2.2 IPv6address, form 9 of 9
<host_ipv6> ::= <host_ipv6_a> | <host_ipv6_b> | <host_ipv6_c> | <host_ipv6_d> | <host_ipv6_e> | <host_ipv6_f> | <host_ipv6_g> | <host_ipv6_h> | <host_ipv6_i>   # RFC 3986 3.2.2 IPv6address
<host_ip_literal> ::= '[' <host_ipv6> ']' | <host_ipv4>   # RFC 7151 3.1: IP-literal
<host_domain> ::= r'(?!(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$)[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*'   # RFC 7151 3.1: domain = sub-domain *("." sub-domain); an IPv4 address is the IP-literal
<host_known> ::= <host_domain> := pick_from([h for h in FTP_VIRTUAL_HOSTS if h[0] != "[" and not h.replace(".", "").isdigit()])   # a hostname of the setup
<host_known_literal> ::= <host_ip_literal> := pick_from([h for h in FTP_VIRTUAL_HOSTS if h[0] == "[" or h.replace(".", "").isdigit()])   # an IP literal of the setup
<hostname> ::= <host_known> | <host_known_literal> | <host_domain> | <host_ip_literal>   # RFC 7151 3.1: hostname = domain / IP-literal
# ---------------------------------------------------------------------------------------------------------------
# Replies whose text has a syntax of its own (received messages; single-line forms as defined, or the generic multi-line form)
# ---------------------------------------------------------------------------------------------------------------
# RFC 1123 4.1.3.4 / RFC 959 4.2.2: '110 MARK ssss = rrrr'; the text is exact
<marker_text> ::= r'[!-~]+'
<reply_110> ::= <code_110> <SP> 'MARK' <SP> <marker_text> <SP> '=' <SP> <marker_text> <CRLF>  # RFC 1123 4.1.3.4; RFC 959 4.2.2 (110 MARK)

# RFC 959 4.2.1: '215 NAME system type'; NAME is an official system name (RFC 959 4.1.3: first word of the reply); RFC 959 4.2: any reply may be multi-line
<system_name> ::= r'[A-Za-z0-9][A-Za-z0-9_./-]*'
<reply_215> ::= <code_215> <SP> <system_name> (<SP> <reply_text>)? <CRLF> | <code_215> '-' <system_name> (<SP> <reply_text>)? <CRLF> <reply_mid_line>* <code_215> <reply_tail>   # RFC 959 4.1.3: the first word of the reply is the system name, on the first line of a multi-line reply too

# RFC 959 4.2.1: '227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).'; RFC 959 5.4: a server may substitute text in the replies, RFC 1123 4.1.2.6: the client scans for the first digit
# The text before the numbers has no digit (the first digit starts <host_port>); it and the text after the numbers may hold any other character, parentheses included.
# The parentheses around the numbers are text like any other: they are not a part of the rule, so each reply derives one way.
<text_before_ports> ::= r'([^\r\n0-9]|\r(?!\n))+'
<text_after_ports> ::= r'([^\r\n0-9]|\r(?!\n))([^\r\n]|\r(?!\n))*'   # starts with a non-digit: the last number of <host_port> is the whole digit run
<reply_227> ::= <code_227> <SP> <text_before_ports>? <host_port> <text_after_ports>? <CRLF> | <code_227> <reply_head> <reply_mid_line>* <code_227> <reply_tail>  # RFC 959 4.2.1 (227)

# RFC 2428 3: '229 <text> (<d><d><d><tcp-port><d>)'; the first two fields are blank
<epsv_text> ::= r'(([^\r\n]|\r(?!\n))*([^\r\n ]|\r(?!\n)))'   # RFC 2428 3: <text>, which ends before the SP that precedes the parenthesis; RFC 2428 forbids no character in it (only the 522 text, RFC 2428 2)
<epsv_reply_d1> ::= <epsv_delim>  # RFC 2428 3 (229)
<epsv_reply_d2> ::= <epsv_delim>  # RFC 2428 3 (229)
<epsv_reply_d3> ::= <epsv_delim>  # RFC 2428 3 (229)
<epsv_reply_d4> ::= <epsv_delim>  # RFC 2428 3 (229)
<epsv_reply_arg> ::= <epsv_reply_d1> <epsv_reply_d2> <epsv_reply_d3> <tcp_port> <epsv_reply_d4>   # RFC 2428 3
<reply_229> ::= <code_229> <SP> <epsv_text> <SP> '(' <epsv_reply_arg> ')' <CRLF> | <code_229> <reply_head> <reply_mid_line>* <code_229> <SP> <epsv_text> <SP> '(' <epsv_reply_arg> ')' <CRLF>  # RFC 2428 3 (229)
where forall <a> in <epsv_reply_arg>: str(<a>.<epsv_reply_d2>) == str(<a>.<epsv_reply_d1>)
where forall <a> in <epsv_reply_arg>: str(<a>.<epsv_reply_d3>) == str(<a>.<epsv_reply_d1>)
where forall <a> in <epsv_reply_arg>: str(<a>.<epsv_reply_d4>) == str(<a>.<epsv_reply_d1>)

<paren_free_text> ::= r'([^\r\n()]|\r(?!\n))+'   # the 522 text only: RFC 2428 2 forbids '(' and ')' in it
# RFC 2428 2: '522 <text> (prot1,prot2,...,protn)'; the text must not contain '(' or ')'; comma separated AF numbers
<af_list> ::= <net_prt> (',' <net_prt>)*
<paren_free_head> ::= '-' <paren_free_text>? <CRLF>   # first line of a multi-line 522 reply: no parenthesis (RFC 2428 2: the text MUST NOT contain '(' or ')')
<paren_free_mid_text> ::= r'(?!\d{3}(?!\d))([^\r\n()]|\r(?!\n))+'  # RFC 2428 2 (522)
<paren_free_mid_line> ::= <paren_free_mid_text>? <CRLF>   # middle line of a multi-line 522 reply: no parenthesis
<reply_522> ::= <code_522> <SP> <paren_free_text>? '(' <af_list> ')' <paren_free_text>? <CRLF> | <code_522> <paren_free_head> <paren_free_mid_line>* <code_522> <SP> <paren_free_text>? '(' <af_list> ')' <paren_free_text>? <CRLF>  # RFC 2428 2 (522)

# RFC 959 4.2.1: '257 "PATHNAME" created' (RFC 959 Appendix II: a double quote inside the name is doubled)
<quoted_pathname> ::= r'([^"\r\n]|""|\r(?!\n))+'
<reply_257_text> ::= r' ([^\r\n]|\r(?!\n))*'  # RFC 959 4.2.1, Appendix II (257)
# RFC 959 App. II says the server 'should' return the form 257<space>"<directory-name>"<space><commentary> and 5.4 lets a server substitute text: the quoted pathname may follow text on its line
# (<reply_257_pre>), and a 257 reply may carry no quoted pathname at all (<reply_257_unquoted>); `mkd_path_is_absolute` and the recording of named paths apply where a <quoted_pathname> is there.
<reply_257_pre> ::= r'(?!")([^"\r\n]|\r(?!\n))+'   # text before the quoted pathname (no quote in it, so the first quote opens the pathname)
<reply_257_unquoted> ::= <code_257> (<SP> <reply_text_noquote_nq>)? <CRLF>   # RFC 959 5.4: a 257 reply whose text holds no quoted pathname
<reply_257_single> ::= <code_257> <SP> '"' <quoted_pathname> '"' <reply_257_text>? <CRLF> | <code_257> <SP> <reply_257_pre> '"' <quoted_pathname> '"' <reply_257_text>? <CRLF> | <reply_257_unquoted> | <reply_257_odd>  # RFC 959 4.2.1, Appendix II (257)
# Any other single-line text that holds a quote (an undoubled quote inside the name, no space after the closing quote, a lone quote, text with several quoted strings in which the pathname is not the first):
# the lookaheads exclude exactly what the two strict forms above derive, so every single-line 257 reply has one derivation.
<reply_257_odd> ::= <code_257> <SP> r'(?!"(?:[^"\r\n]|""|\r(?!\n))+"(?: |\r\n))(?!(?:[^"\r\n]|\r(?!\n))+"(?:[^"\r\n]|""|\r(?!\n))+"(?: |\r\n))(?:[^"\r\n]|\r(?!\n))*"(?:[^\r\n]|\r(?!\n))*' <CRLF>   # RFC 959 App. II 'should': a server may substitute text (RFC 959 5.4)
<reply_257> ::= <reply_257_single> | <code_257> <reply_head> <reply_mid_line>* <code_257> <reply_tail>  # RFC 959 4.2.1, Appendix II (257)
# RFC 959 Appendix II: the 257 reply to MKD must always contain the absolute pathname of the created directory
<reply_257_mkd> ::= <reply_257_single> | <code_257> <reply_head> <reply_mid_line>* <code_257> <reply_tail>   # RFC 959 4.2.1, App. II: '257 "PATHNAME" created'; RFC 959 4.2: any line of a multi-line reply is free text (a quote before the line that carries the pathname is possible); `mkd_path_is_absolute` finds the pathname in the text: the quoted string that opens a line, else the first quoted string, and demands that the reply names one (a quoted one, or after a UNIX SYST a token that starts with '/')
<reply_text_noquote_nq> ::= r'([^"\r\n]|\r(?!\n))+'   # a line of a multi-line 257 reply that carries no quote (the pathname sits on exactly one line)

# RFC 3659 3.1/4.1: '213 SP time-val CRLF' (MDTM) and '213 SP 1*DIGIT CRLF' (SIZE), exactly, never multi-line
<time_val> ::= r'[1-9][0-9]{3}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])[0-5][0-9]([0-5][0-9]|60)(\.[0-9]+)?'
<reply_213_mdtm> ::= <code_213> <SP> <time_val> <CRLF>  # RFC 3659 2.3, 3.1, 4.1 (213)
<reply_213_size> ::= <code_213> <SP> <digit_string> <CRLF>  # RFC 3659 2.3, 3.1, 4.1 (213)

# RFC 2389 3.2: feat-response = error-response / no-features / feature-listing
#   no-features = "211" SP *TCHAR CRLF ; feature-listing = "211-" *TCHAR CRLF 1*( SP feature CRLF ) "211 End" CRLF
<reply_211_nofeat> ::= <code_211> <SP> <reply_text>? <CRLF>
<feat_end> ::= r'[Ee][Nn][Dd]'  # RFC 2389 3.2 (FEAT); RFC 3659 7.8; RFC 2640 4.3
# Each documented feature has its line (RFC 3659 3.3, 4.3, 5.4, 6.3, 7.8; RFC 2640 3.2, 4.3; RFC 4217 6; RFC 7151 3.4);
# any other feature label is an `other` line. The label comparison is case independent.
<feat_label> ::= r'(?!([Mm][Dd][Tt][Mm]|[Ss][Ii][Zz][Ee]|[Rr][Ee][Ss][Tt]|[Tt][Vv][Ff][Ss]|[Uu][Tt][Ff]8|[Aa][Uu][Tt][Hh]|[Pp][Bb][Ss][Zz]|[Pp][Rr][Oo][Tt]|[Hh][Oo][Ss][Tt]|[Ll][Aa][Nn][Gg]|[Mm][Ll][Ss][Tt])(?![!-~]))[!-~]+'   # RFC 2389 3.2: feature-label = 1*VCHAR
<feat_params> ::= r'([^\r\n]|\r(?!\n))+'                          # RFC 2389 3.2: feature-parms = 1*TCHAR
<feat_mdtm_line> ::= <SP> r'[Mm][Dd][Tt][Mm]' <CRLF>             # RFC 3659 3.3: a line containing the single word MDTM
<feat_size_line> ::= <SP> r'[Ss][Ii][Zz][Ee]' <CRLF>             # RFC 3659 4.3: a line containing the single word SIZE
<feat_rest_line> ::= <SP> r'[Rr][Ee][Ss][Tt]' <SP> r'[Ss][Tt][Rr][Ee][Aa][Mm]' <CRLF>   # RFC 3659 5.4: exactly the string "REST STREAM"
<feat_tvfs_line> ::= <SP> r'[Tt][Vv][Ff][Ss]' (<SP> <feat_params>)? <CRLF>             # RFC 3659 6.3: a line beginning with TVFS
<feat_utf8_line> ::= <SP> r'[Uu][Tt][Ff]8' <CRLF>                # RFC 2640 3.2: the feature UTF8
<feat_auth_line> ::= <SP> r'[Aa][Uu][Tt][Hh]' (<SP> <feat_params>)? <CRLF>   # RFC 4217 6: AUTH with its mechanisms
<feat_pbsz_line> ::= <SP> r'[Pp][Bb][Ss][Zz]' <CRLF>             # RFC 4217 6
<feat_prot_line> ::= <SP> r'[Pp][Rr][Oo][Tt]' (<SP> <feat_params>)? <CRLF>   # RFC 4217 6
<feat_host_line> ::= <SP> r'[Hh][Oo][Ss][Tt]' <CRLF>             # RFC 7151 3.4
# RFC 2640 4.3: Lang-feat = SP "LANG" SP lang-fact; lang-fact = lang-tag ["*"] *(";" lang-tag ["*"]); at least one lang-tag
<lang_tag_feat> ::= <lang_tag_text> '*'?
<feat_lang_line> ::= <SP> r'[Ll][Aa][Nn][Gg]' <SP> <lang_tag_feat> (';' <lang_tag_feat>)* <CRLF>  # RFC 2389 3.2 (FEAT); RFC 3659 7.8; RFC 2640 4.3
# RFC 3659 7.8: mlst-feat = SP "MLST" [SP factlist]; factlist = 1*( factname ["*"] ";" )
<feat_mlst_label> ::= r'[Mm][Ll][Ss][Tt]'
<feat_fact> ::= (<fact_name> | <fact_other_name>) '*'? ';'  # RFC 2389 3.2 (FEAT); RFC 3659 7.8; RFC 2640 4.3
<feat_mlst_line> ::= <SP> <feat_mlst_label> (<SP> <feat_fact>+)? <CRLF>  # RFC 2389 3.2 (FEAT); RFC 3659 7.8; RFC 2640 4.3
<feat_other_line> ::= <SP> <feat_label> (<SP> <feat_params>)? <CRLF>   # RFC 2389 3.2: SP feature-label [SP feature-parms]
<feat_line> ::= <feat_mdtm_line> | <feat_size_line> | <feat_rest_line> | <feat_tvfs_line> | <feat_utf8_line> | <feat_auth_line> | <feat_pbsz_line> | <feat_prot_line> | <feat_host_line> | <feat_lang_line> | <feat_mlst_line> | <feat_other_line>  # RFC 2389 3.2 (FEAT); RFC 3659 7.8; RFC 2640 4.3
<reply_211_feat> ::= <reply_211_nofeat> | <code_211> '-' <reply_text>? <CRLF> <feat_line>+ <code_211> <SP> <feat_end> <CRLF>  # RFC 2389 3.2 (FEAT); RFC 3659 7.8; RFC 2640 4.3

# RFC 3659 7.2: control-response = "250-" [ response-message ] CRLF 1*( SP entry CRLF ) "250" [ SP response-message ] CRLF
#   entry = [ facts ] SP pathname; facts = 1*( fact ";" ); fact = factname "=" value
<fact_size_name> ::= r'[Ss][Ii][Zz][Ee]'                         # RFC 3659 7.5.7
<fact_modify_name> ::= r'[Mm][Oo][Dd][Ii][Ff][Yy]'               # RFC 3659 7.5.3
<fact_create_name> ::= r'[Cc][Rr][Ee][Aa][Tt][Ee]'               # RFC 3659 7.5.4
<fact_type_name> ::= r'[Tt][Yy][Pp][Ee]'                         # RFC 3659 7.5.1
<fact_unique_name> ::= r'[Uu][Nn][Ii][Qq][Uu][Ee]'               # RFC 3659 7.5.2
<fact_perm_name> ::= r'[Pp][Ee][Rr][Mm]'                         # RFC 3659 7.5.5
<fact_lang_name> ::= r'[Ll][Aa][Nn][Gg]'                         # RFC 3659 7.5.6
<fact_media_type_name> ::= r'[Mm][Ee][Dd][Ii][Aa]-[Tt][Yy][Pp][Ee]'   # RFC 3659 7.5.8
<fact_charset_name> ::= r'[Cc][Hh][Aa][Rr][Ss][Ee][Tt]'          # RFC 3659 7.5.9
<fact_os_name> ::= r'(?![Xx]\.)[A-Za-z0-9][A-Za-z0-9_/-]*\.[A-Za-z0-9,.:!@#$%^&()\-_+?/\\\'"]+'   # RFC 3659 7.6.1: <IANA OS name> "." token
<fact_local_name> ::= r'[Xx]\.[A-Za-z0-9,.:!@#$%^&()\-_+?/\\\'"]+'              # RFC 3659 7.6.2: "X." token
# RFC 3659 7.6.2: 'Implementations may also make available other facts of their own choosing' (received only: a name that is none of the above, without a '.')
<fact_other_name> ::= r'(?!(?:[Ss][Ii][Zz][Ee]|[Mm][Oo][Dd][Ii][Ff][Yy]|[Cc][Rr][Ee][Aa][Tt][Ee]|[Tt][Yy][Pp][Ee]|[Uu][Nn][Ii][Qq][Uu][Ee]|[Pp][Ee][Rr][Mm]|[Ll][Aa][Nn][Gg]|[Mm][Ee][Dd][Ii][Aa]-[Tt][Yy][Pp][Ee]|[Cc][Hh][Aa][Rr][Ss][Ee][Tt])(?![A-Za-z0-9_-]))[A-Za-z0-9_-]+'
<fact_name> ::= <fact_size_name> | <fact_modify_name> | <fact_create_name> | <fact_type_name> | <fact_unique_name> | <fact_perm_name> | <fact_lang_name> | <fact_media_type_name> | <fact_charset_name> | <fact_os_name> | <fact_local_name>  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_token> ::= r'[A-Za-z0-9,.:!@#$%^&()\-_+?/\\\'"]+'                           # RFC 3659 2.1 token
<fact_value> ::= r'[A-Za-z0-9,.:!@#$%^&()\-_+?/\\\'"=]+'                                    # RFC 3659 7.2: value = *SCHAR (a fact may not contain ';')
<fact_size> ::= <fact_size_name> '=' <digit_string> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_modify> ::= <fact_modify_name> '=' <time_val> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_create> ::= <fact_create_name> '=' <time_val> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<type_file> ::= r'[Ff][Ii][Ll][Ee]'      # RFC 3659 7.5.1
<type_cdir> ::= r'[Cc][Dd][Ii][Rr]'      # RFC 3659 7.5.1.2
<type_pdir> ::= r'[Pp][Dd][Ii][Rr]'      # RFC 3659 7.5.1.4
<type_dir> ::= r'[Dd][Ii][Rr]'           # RFC 3659 7.5.1.3
<type_os> ::= r'[Oo][Ss]\.[A-Za-z0-9_/.-]+=[A-Za-z0-9,.:!@#$%^&()\-_+?/\\\'"]+'   # RFC 3659 7.5.1.5
<type_val> ::= <type_file> | <type_cdir> | <type_pdir> | <type_dir> | <type_os>  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_type> ::= <fact_type_name> '=' <type_val> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_unique> ::= <fact_unique_name> '=' <fact_token> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<perm_a> ::= r'[aA]'   # RFC 3659 7.5.5: pvals ''a''
<perm_c> ::= r'[cC]'   # RFC 3659 7.5.5: pvals ''c''
<perm_d> ::= r'[dD]'   # RFC 3659 7.5.5: pvals ''d''
<perm_e> ::= r'[eE]'   # RFC 3659 7.5.5: pvals ''e''
<perm_f> ::= r'[fF]'   # RFC 3659 7.5.5: pvals ''f''
<perm_l> ::= r'[lL]'   # RFC 3659 7.5.5: pvals ''l''
<perm_m> ::= r'[mM]'   # RFC 3659 7.5.5: pvals ''m''
<perm_p> ::= r'[pP]'   # RFC 3659 7.5.5: pvals ''p''
<perm_r> ::= r'[rR]'   # RFC 3659 7.5.5: pvals ''r''
<perm_w> ::= r'[wW]'   # RFC 3659 7.5.5: pvals ''w''
<perm_val> ::= <perm_a> | <perm_c> | <perm_d> | <perm_e> | <perm_f> | <perm_l> | <perm_m> | <perm_p> | <perm_r> | <perm_w>   # RFC 3659 7.5.5: pvals = a / c / d / e / f / l / m / p / r / w
<fact_perm> ::= <fact_perm_name> '=' <perm_val>* ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_lang> ::= <fact_lang_name> '=' <fact_token> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_media_type> ::= <fact_media_type_name> '=' <fact_value> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_charset> ::= <fact_charset_name> '=' <fact_token> ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_os> ::= <fact_os_name> '=' <fact_value>? ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_local> ::= <fact_local_name> '=' <fact_value>? ';'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<fact_other> ::= <fact_other_name> '=' <fact_value>? ';'   # RFC 3659 7.6.2: a fact of the server's own choosing
<mlst_fact> ::= <fact_size> | <fact_modify> | <fact_create> | <fact_type> | <fact_unique> | <fact_perm> | <fact_lang> | <fact_media_type> | <fact_charset> | <fact_os> | <fact_local> | <fact_other>  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<mlst_pathname> ::= r'([^\r\n]|\r(?!\n))+'  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<mlst_entry> ::= <mlst_fact>* <SP> <mlst_pathname>  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<mlst_line> ::= <SP> <mlst_entry> <CRLF>  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)
<reply_250_mlst> ::= <code_250> '-' <reply_text>? <CRLF> <mlst_line>+ <code_250> (<SP> <reply_text>?)? <CRLF>  # RFC 3659 7.2, 7.4-7.6 (MLSx facts)

# RFC 2228 5.2: protected replies 631/632/633: '63z' + base64 text; multi-line: '63z-' base64 on every line before the last
<base64_line> ::= r'([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)'
<reply_631> ::= <code_631> <SP> <base64_line> <CRLF> | <code_631> '-' <base64_line> <CRLF> (<code_631> '-' <base64_line> <CRLF>)* <code_631> <SP> <base64_line> <CRLF>  # RFC 2228 5.2 (protected replies)
<reply_632> ::= <code_632> <SP> <base64_line> <CRLF> | <code_632> '-' <base64_line> <CRLF> (<code_632> '-' <base64_line> <CRLF>)* <code_632> <SP> <base64_line> <CRLF>  # RFC 2228 5.2 (protected replies)
<reply_633> ::= <code_633> <SP> <base64_line> <CRLF> | <code_633> '-' <base64_line> <CRLF> (<code_633> '-' <base64_line> <CRLF>)* <code_633> <SP> <base64_line> <CRLF>  # RFC 2228 5.2 (protected replies)


# RFC 2228 5.2, 8.2: after a successful security data exchange any command can be answered by a protected reply 631, 632 or 633
<reply_protected> ::= <reply_631> | <reply_632> | <reply_633>
# ---------------------------------------------------------------------------------------------------------------
# Timers (Fandango built-in parties TimerControl / TimerEvent): the timer stops the wait for a reply the spec lets stay away.
# ---------------------------------------------------------------------------------------------------------------
# RFC 959 3.2: the server waits for the data connection before it answers; Fandango's timer 1 ends that wait. The id and the duration are
# the values of the leaves of the standard timer messages <timer_start>, <timer_cancel>, <timer_expired> (no constraint over the session tree).
<timer_id> ::= r'[0-9]+' := '1'      # the one timer of the grammar
<timer_timeout> ::= r'[0-9]+([.][0-9]+)?' := FTP_REPLY_WAIT_S      # seconds the client waits for the reply of a transfer command
<transfer_start> ::= <timer_start>  # RFC 959 3.2; Fandango timers (the server may wait for the data connection)
<transfer_cancel> ::= <timer_cancel>  # RFC 959 3.2; Fandango timers (the server may wait for the data connection)
<transfer_expired> ::= <timer_expired>  # RFC 959 3.2; Fandango timers (the server may wait for the data connection)

# ---------------------------------------------------------------------------------------------------------------
# Login (RFC 959 4.1.1, 5.4; RFC 2228 5.1, 8.2): credentials. The accepting exchanges send only the configured values;
# wrong values have request nonterminals of their own, used only by the refusing exchanges.
# ---------------------------------------------------------------------------------------------------------------
# RFC 959 5.3.2: <username> ::= <string>, <password> ::= <string>, <account-information> ::= <string>
<username> ::= <string> | <string_iac>
<password> ::= <string> | <string_iac>  # RFC 959 5.3.2 (<username>, <password>, <account-information>)
<account_information> ::= <string> | <string_iac>  # RFC 959 5.3.2 (<username>, <password>, <account-information>)
<user_valid> ::= <username> := FTP_USER  # RFC 959 4.1.1, 5.3.1 (login)
<user_wrong> ::= <username> := wrong_value(FTP_USER)  # RFC 959 4.1.1, 5.3.1 (login)
<pass_valid> ::= <password> := FTP_PASS  # RFC 959 4.1.1, 5.3.1 (login)
<pass_wrong> ::= <password> := wrong_value(FTP_PASS)  # RFC 959 4.1.1, 5.3.1 (login)
<acct_valid> ::= <account_information> := FTP_ACCT  # RFC 959 4.1.1, 5.3.1 (login)
<acct_wrong> ::= <account_information> := wrong_value(FTP_ACCT)  # RFC 959 4.1.1, 5.3.1 (login)
def wrong_value(valid):
    while True:
        candidate = junk_name()
        if candidate != valid:
            return candidate
<req_user> ::= <cmd_user> <SP> <user_valid> <CRLF>              # RFC 959 5.3.1
<req_user_wrong> ::= <cmd_user> <SP> <user_wrong> <CRLF>        # RFC 959 5.3.1
<req_pass> ::= <cmd_pass> <SP> <pass_valid> <CRLF>              # RFC 959 5.3.1
<req_pass_wrong> ::= <cmd_pass> <SP> <pass_wrong> <CRLF>        # RFC 959 5.3.1
<req_acct> ::= <cmd_acct> <SP> <acct_valid> <CRLF>              # RFC 959 5.3.1
<req_acct_wrong> ::= <cmd_acct> <SP> <acct_wrong> <CRLF>        # RFC 959 5.3.1
# The accepting request carries the configured value (an equality on the nonterminal); the wrong request nonterminal gets a value that is not the configured one from its generator wrong_value()
where forall <r> in <req_user>: str(<r>.<user_valid>) == FTP_USER
where forall <r> in <req_pass>: str(<r>.<pass_valid>) == FTP_PASS
where forall <r> in <req_acct>: str(<r>.<acct_valid>) == FTP_ACCT
<error_code_user> ::= r'(?!(230|232|331|332|336|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (USER); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_user> ::= <error_code_user>  # RFC 959 5.4 (USER); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_user> ::= <error_code_user>  # RFC 959 5.4 (USER); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_user> ::= <error_code_user> <reply_tail> | <error_first_user> <reply_head> <reply_mid_line>* <error_last_user> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_user>: str(<r>.<error_first_user>) == str(<r>.<error_last_user>)
<error_code_pass> ::= r'(?!(202|230|232|332|421|500|501|502|503|530))[2-5][0-9]{2}'  # RFC 959 5.4 (PASS); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_pass> ::= <error_code_pass>  # RFC 959 5.4 (PASS); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_pass> ::= <error_code_pass>  # RFC 959 5.4 (PASS); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_pass> ::= <error_code_pass> <reply_tail> | <error_first_pass> <reply_head> <reply_mid_line>* <error_last_pass> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_pass>: str(<r>.<error_first_pass>) == str(<r>.<error_last_pass>)
<error_code_acct> ::= r'(?!(202|230|421|500|501|502|503|530))[2-5][0-9]{2}'  # RFC 959 5.4 (ACCT); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_acct> ::= <error_code_acct>  # RFC 959 5.4 (ACCT); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_acct> ::= <error_code_acct>  # RFC 959 5.4 (ACCT); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_acct> ::= <error_code_acct> <reply_tail> | <error_first_acct> <reply_head> <reply_mid_line>* <error_last_acct> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_acct>: str(<r>.<error_first_acct>) == str(<r>.<error_last_acct>)
<error_code_greeting> ::= r'(?!(120|220|421))[45][0-9]{2}'  # RFC 959 5.4 (connection establishment); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_greeting> ::= <error_code_greeting>  # RFC 959 5.4 (connection establishment); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_greeting> ::= <error_code_greeting>  # RFC 959 5.4 (connection establishment); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_greeting> ::= <error_code_greeting> <reply_tail> | <error_first_greeting> <reply_head> <reply_mid_line>* <error_last_greeting> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_greeting>: str(<r>.<error_first_greeting>) == str(<r>.<error_last_greeting>)
<error_code_greeting_ok> ::= r'(?!(120|220|421))[23][0-9]{2}'  # RFC 959 5.4 (connection establishment); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_greeting_ok> ::= <error_code_greeting_ok>  # RFC 959 5.4 (connection establishment); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_greeting_ok> ::= <error_code_greeting_ok>  # RFC 959 5.4 (connection establishment); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_greeting_ok> ::= <error_code_greeting_ok> <reply_tail> | <error_first_greeting_ok> <reply_head> <reply_mid_line>* <error_last_greeting_ok> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_greeting_ok>: str(<r>.<error_first_greeting_ok>) == str(<r>.<error_last_greeting_ok>)
<greeting_prelim> ::= <reply_120> | <reply_new_prelim>   # RFC 959 5.4: 120 before the 220 reply; RFC 1123 4.1.2.11 / RFC 959 4.2: another preliminary (1yz) code
<greeting_refused> ::= <Server:reply_error_greeting> <ServerClosed:connection_closed>   # RFC 959 5.4: a server that refuses the connection with another 4yz/5yz reply and closes it
<rep_user_refused> ::= <reply_530> | <reply_500> | <reply_501> | <reply_502> | <reply_421> | <reply_protected> | <reply_error_user>      # RFC 959 5.4 (USER); RFC 959 4.2.1 (421)
<rep_pass_refused> ::= <reply_530> | <reply_500> | <reply_501> | <reply_502> | <reply_503> | <reply_421> | <reply_protected> | <reply_error_pass>   # RFC 959 5.4 (PASS); RFC 959 4.2.1 (421)
<rep_acct_refused> ::= <reply_530> | <reply_500> | <reply_501> | <reply_502> | <reply_503> | <reply_421> | <reply_protected> | <reply_error_acct>   # RFC 959 5.4 (ACCT); RFC 959 4.2.1 (421)
<rep_acct_early> ::= <reply_230> | <reply_202> | <rep_acct_refused>   # RFC 959 4.1.1: ACCT 'may arrive at any time'
<req_acct_early> ::= <req_acct> | <req_acct_wrong>  # RFC 959 4.1.1, 5.3.1 (login)
<exch_user_331> ::= <Client:req_user> (<Server:reply_331> | <Server:reply_336>)       # RFC 959 5.4; RFC 2228 8.2: need password -> Need Password
<exch_user_230> ::= <Client:req_user> (<Server:reply_230> | <Server:reply_232>)       # RFC 959 5.4: logged in without a password
<exch_user_332> ::= <Client:req_user> <Server:reply_332>                              # RFC 959 5.4: need account -> Need Account
<exch_user_refused> ::= <Client:req_user> <Server:rep_user_refused>                   # RFC 959 5.4: failure
<exch_user_wrong_331> ::= <Client:req_user_wrong> (<Server:reply_331> | <Server:reply_336>)   # RFC 959 5.4: the server asks for a password (whether it accepts the name is its own decision)
<exch_user_wrong_230> ::= <Client:req_user_wrong> (<Server:reply_230> | <Server:reply_232>)   # RFC 959 5.4: a server that logs any name in
<exch_user_wrong_332> ::= <Client:req_user_wrong> <Server:reply_332>                          # RFC 959 5.4
<exch_user_wrong_refused> ::= <Client:req_user_wrong> <Server:rep_user_refused>       # RFC 959 5.4: failure
<exch_pass_230> ::= <Client:req_pass> (<Server:reply_230> | <Server:reply_202> | <Server:reply_232>)   # RFC 959 5.4: logged in
<exch_pass_332> ::= <Client:req_pass> <Server:reply_332>                              # RFC 959 5.4: need account
<exch_pass_refused> ::= <Client:req_pass> <Server:rep_pass_refused>                   # RFC 959 5.4: failure
<exch_pass_wrong_230> ::= <Client:req_pass_wrong> (<Server:reply_230> | <Server:reply_202> | <Server:reply_232>)   # RFC 959 5.4: a server that accepts any password
<exch_pass_wrong_332> ::= <Client:req_pass_wrong> <Server:reply_332>                  # RFC 959 5.4
<exch_pass_wrong> ::= <Client:req_pass_wrong> <Server:rep_pass_refused>               # wrong password: refused
<exch_acct_230> ::= <Client:req_acct> (<Server:reply_230> | <Server:reply_202>)       # RFC 959 5.4: account accepted
<exch_acct_valid_refused> ::= <Client:req_acct> <Server:rep_acct_refused>             # RFC 959 5.4: account refused
<exch_acct_wrong_230> ::= <Client:req_acct_wrong> (<Server:reply_230> | <Server:reply_202>)   # RFC 959 5.4: a server that accepts any account
<exch_acct_refused> ::= <Client:req_acct_wrong> <Server:rep_acct_refused>             # wrong account
<exch_acct_early> ::= <Client:req_acct_early> <Server:rep_acct_early>                 # ACCT out of sequence

# QUIT (RFC 959 4.1.1, 5.4): 221 closes the connection
<req_quit> ::= <cmd_quit> <CRLF>
<exch_quit> ::= <Client:req_quit> (<Server:reply_221> | <Server:reply_421>) <ServerClosed:connection_closed>              # RFC 959 5.4; RFC 959 4.2.1 (421)
<error_code_quit> ::= r'(?!(221|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (QUIT); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_quit> ::= <error_code_quit>  # RFC 959 5.4 (QUIT); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_quit> ::= <error_code_quit>  # RFC 959 5.4 (QUIT); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_quit> ::= <error_code_quit> <reply_tail> | <error_first_quit> <reply_head> <reply_mid_line>* <error_last_quit> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_quit>: str(<r>.<error_first_quit>) == str(<r>.<error_last_quit>)
<rep_quit_refused> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_protected> | <reply_error_quit>   # RFC 959 5.4: QUIT is answered 221 or 500; RFC 1123 4.1.2.11: any other 4yz/5yz; the connection stays open
<exch_quit_refused> ::= <Client:req_quit> <Server:rep_quit_refused>   # RFC 959 5.4: 500 (a server that does not close)
# REIN (RFC 959 4.1.1, 5.4): 120 then 220 (or 220): back to the begin state
<req_rein> ::= <cmd_rein> <CRLF>
<error_code_rein> ::= r'(?!(120|220|421|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (REIN); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_rein> ::= <error_code_rein>  # RFC 959 5.4 (REIN); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_rein> ::= <error_code_rein>  # RFC 959 5.4 (REIN); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_rein> ::= <error_code_rein> <reply_tail> | <error_first_rein> <reply_head> <reply_mid_line>* <error_last_rein> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_rein>: str(<r>.<error_first_rein>) == str(<r>.<error_last_rein>)
<exch_rein_ok> ::= <Client:req_rein> (<Server:greeting_prelim> <Server:reply_220> | <Server:reply_220>)   # RFC 959 5.4; RFC 1123 4.1.2.11
<exch_rein_refused> ::= <Client:req_rein> (<Server:reply_500> | <Server:reply_501> | <Server:reply_502> | <Server:reply_530> | <Server:reply_421> | <Server:reply_protected> | <Server:reply_error_rein>)   # RFC 959 5.4: 500, 502
# ABOR (RFC 959 4.1.3, 5.4): 225 or 226 ('426 then 226' when a transfer was aborted)
# RFC 959 4.1.3 / RFC 1123 4.1.2.12: ABOR is sent after the Telnet 'Interrupt Process' and 'Synch' (IAC IP IAC DM); a user-FTP sends no other
# Telnet controls (RFC 1123 4.1.2.12: 'A user-FTP MUST NOT send any Telnet controls other than SYNCH and IP')
<telnet_ip_synch> ::= b'\xff\xf4\xff\xf2'   # RFC 854: IAC IP IAC DM
<req_abor> ::= <telnet_ip_synch>? <cmd_abor> <CRLF>  # RFC 959 4.1.3; RFC 1123 4.1.2.12 (ABOR, Telnet IP/Synch)
<error_code_abor> ::= r'(?!(225|226|421|426|500|501|502|530))[2-5][0-9]{2}'  # RFC 959 5.4 (ABOR); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_abor> ::= <error_code_abor>  # RFC 959 5.4 (ABOR); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_abor> ::= <error_code_abor>  # RFC 959 5.4 (ABOR); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_abor> ::= <error_code_abor> <reply_tail> | <error_first_abor> <reply_head> <reply_mid_line>* <error_last_abor> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_abor>: str(<r>.<error_first_abor>) == str(<r>.<error_last_abor>)
<rep_abor> ::= <rep_abor_final> | <reply_426> <rep_abor_final>   # RFC 959 4.1.3, 5.4: 225/226, or 426 then 226; RFC 1123 4.1.2.11: the reply after the 426 may be another code (426 451)
<exch_abor> ::= <Client:req_abor> <Server:rep_abor>  # RFC 959 4.1.3; RFC 1123 4.1.2.12 (ABOR, Telnet IP/Synch)
# ABOR while a transfer is in progress (RFC 959 4.1.3: 'abort the previous FTP service command and any associated transfer of data'; the server answers 426 then 226): the transfer command was
# answered 125/150 (or not at all) and the timer ended the wait; the client now sends ABOR. The urgent data of the Telnet Synch (RFC 959 4.1.3) cannot be sent (see the TODO at <req_abor>),
# so a server that is busy with the transfer may leave the ABOR unanswered: the timer ends the wait again.
# The final reply of the transfer command itself (RFC 959 4.1.3, 5.4: 226/250, 425/426, 451/450/550 ... or any other 2yz-5yz code, RFC 1123 4.1.2.11) arrives late: after the wait, next to the reply to ABOR/STAT/QUIT, or alone.
<error_code_transfer_late> ::= r'(?!(211|212|213|221|225|226|250|421|425|426|450|451|452|500|501|502|530|532|550|551|552|553|554|555))[2-5][0-9]{2}'  # RFC 959 5.4 (transfer commands); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_transfer_late> ::= <error_code_transfer_late>  # RFC 959 5.4 (transfer commands); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_transfer_late> ::= <error_code_transfer_late>  # RFC 959 5.4 (transfer commands); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_transfer_late> ::= <error_code_transfer_late> <reply_tail> | <error_first_transfer_late> <reply_head> <reply_mid_line>* <error_last_transfer_late> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_transfer_late>: str(<r>.<error_first_transfer_late>) == str(<r>.<error_last_transfer_late>)
<rep_transfer_late_done> ::= <reply_226> | <reply_250>   # RFC 959 5.4: the transfer completed
<rep_transfer_late_ended> ::= <reply_425> | <reply_426>   # RFC 959 5.4: no data connection / connection closed, the transfer is abandoned
<rep_transfer_late_failed> ::= <reply_450> | <reply_451> | <reply_452> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_532> | <reply_550> | <reply_551> | <reply_552> | <reply_553> | <reply_554> | <reply_555> | <reply_error_transfer_late>   # RFC 959 5.4
<rep_transfer_late_pre> ::= <reply_prelim> | <reply_110> | <reply_bare_150>   # RFC 959 6, 4.2, RFC 1123 4.1.3.4, RFC 3659 7.2: one 1yz reply may come after the wait: 125/150 or another 1yz code, a 110 marker (the 150 was read before the wait), the bare 150 of MLSD; each reply is a message of its own, so one reply has one reading
<rep_transfer_late_final> ::= <rep_transfer_late_done> | <rep_transfer_late_ended> | <rep_transfer_late_failed>  # RFC 959 3.2; Fandango timers (the server may wait for the data connection)
<rep_transfer_late_any> ::= <rep_transfer_late_pre>+ <rep_transfer_late_final>? | <rep_transfer_late_final>   # the reply of the pending transfer command, whole or its 1yz replies only: it comes next to the reply to ABOR, STAT or QUIT
# After the timer's expiry in the ABOR / STAT / QUIT exchanges the session ends, but the server's reply may still arrive a moment later (ProFTPD answers STAT during a transfer after about 6 s, the timer's length):
# RFC 959 4.2: any reply of class 1 to 6 (single- or multi-line) and the close after it are accepted there; one reading for every reply.
<late_code> ::= r'[1-6][0-9]{2}'   # RFC 959 4.2: the code of a reply that arrives after the wait ended; first digit the class
<late_first> ::= <late_code>   # RFC 959 4.2: code of the first line of a multi-line reply
<late_last> ::= <late_code>   # RFC 959 4.2: code of the last line of a multi-line reply (equal to the first)
<reply_late> ::= <late_code> <reply_tail> | <late_first> <reply_head> <reply_mid_line>* <late_last> <reply_tail>   # RFC 959 4.2: single- or multi-line reply
where forall <r> in <reply_late>: str(<r>.<late_first>) == str(<r>.<late_last>)
<expired_tail> ::= <Server:reply_late>* <ServerClosed:connection_closed>? <session_end>   # the expiry ends the session; replies that race the expiry, and the close after them, are accepted before it
<transfer_late_prelim> ::= <Server:rep_transfer_late_pre> <transfer_in_progress>   # the 1yz reply of the transfer command arrives after the wait; the final reply follows as <transfer_late>
<rep_transfer_late_shared> ::= <reply_211> | <reply_212> | <reply_213> | <reply_221> | <reply_225>   # RFC 1123 4.1.2.11: another code that follows RFC 959 4.2 may end the transfer after the wait; only the lone late reply of <transfer_late> takes these (the STAT, QUIT and ABOR exchanges keep them for their own replies: one reading there)
<transfer_late> ::= <Server:rep_transfer_late_done> <state_data_ready> | <Server:rep_transfer_late_ended> <state_logged_in> | <Server:rep_transfer_late_failed> <state_data_ready> | <Server:rep_transfer_late_shared> <state_data_ready> | <transfer_late_prelim>   # the transfer ended after the wait: the server's own message, the same states as the exchanges of the transfer commands
<req_abor_transfer> ::= <req_abor>   # the dependent exchange has its own request nonterminal
<rep_abor_final> ::= <reply_225> | <reply_226> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_protected> | <reply_error_abor>   # RFC 959 5.4 (ABOR)
<rep_abor_transfer> ::= <rep_abor_final> | <rep_transfer_late_any> <rep_abor_final>   # RFC 959 4.1.3: 426 then 226; the final reply of the transfer command may come first (226 226 of ProFTPD, 426 451 of Pure-FTPd: RFC 1123 4.1.2.11 lets the server use other codes), alone 225/226 when the transfer had ended
<abor_tail> ::= <TimerControl:transfer_cancel> <state_data_ready> | <ServerClosed:connection_closed> <TimerControl:transfer_cancel> <session_end>  # RFC 959 4.1.3; RFC 1123 4.1.2.12 (ABOR, Telnet IP/Synch)
<exch_abor_transfer> ::= <TimerControl:transfer_start> <Client:req_abor_transfer> (<Server:rep_abor_transfer> <abor_tail> | <TimerEvent:transfer_expired> <expired_tail>)   # RFC 959 4.1.3: ABOR during the transfer; the data connection is closed afterwards
<req_stat_transfer> ::= <req_stat>   # the dependent exchange has its own request nonterminal
<stat_tail> ::= <TimerControl:transfer_cancel> <transfer_after_stat> | <ServerClosed:connection_closed> <TimerControl:transfer_cancel> <session_end>   # RFC 959 4.1.3 (STAT during a transfer); RFC 959 4.2.1: the server may close right after its reply
<rep_stat_transfer> ::= <reply_211> | <reply_212> | <reply_213> | <reply_450> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_421> | <reply_error_stat_transfer> | <reply_protected>   # RFC 959 5.4 (STAT), RFC 1123 4.1.2.11: the reply to STAT during a transfer; the codes of the transfer command's own final reply (226, 425, 426, 451 ...) are left to <rep_transfer_late_final>, so a reply has one reading
<error_code_stat_transfer> ::= r'(?!(211|212|213|226|250|421|425|426|450|451|452|500|501|502|530|532|550|551|552|553|554|555))[2-5][0-9]{2}'  # RFC 959 5.4 (STAT); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_stat_transfer> ::= <error_code_stat_transfer>  # RFC 959 5.4 (STAT); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_stat_transfer> ::= <error_code_stat_transfer>  # RFC 959 5.4 (STAT); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_stat_transfer> ::= <error_code_stat_transfer> <reply_tail> | <error_first_stat_transfer> <reply_head> <reply_mid_line>* <error_last_stat_transfer> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_stat_transfer>: str(<r>.<error_first_stat_transfer>) == str(<r>.<error_last_stat_transfer>)
<exch_stat_transfer> ::= <TimerControl:transfer_start> <Client:req_stat_transfer> <Server:rep_transfer_late_pre>* (<Server:rep_stat_transfer> <stat_tail> | (<Server:rep_transfer_late_done> | <Server:rep_transfer_late_failed>) <Server:rep_stat_transfer> <transfer_tail_data_ready> | <Server:rep_transfer_late_ended> <Server:rep_stat_transfer> <transfer_tail_logged_in> | <Server:rep_transfer_late_final> <TimerEvent:transfer_expired> <expired_tail> | <TimerEvent:transfer_expired> <expired_tail>)   # RFC 959 4.1.3: STAT 'may be sent during a file transfer'; the 1yz replies of the transfer may come first, then the transfer may end (its reply comes before the reply to STAT); a server busy with the transfer may leave STAT unanswered
<rep_quit_refused_transfer> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_protected> | <reply_error_quit_transfer>   # RFC 959 5.4 (QUIT: 500), RFC 1123 4.1.2.11: the refusal of QUIT during a transfer; the codes of the transfer's own final reply and the 221 are left out of the generic reply, so one reply has one reading
<error_code_quit_transfer> ::= r'(?!(221|226|250|421|425|426|451|452|500|501|502|530|532|550|551|552|553|554|555))[2-5][0-9]{2}'  # RFC 959 5.4 (QUIT); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_quit_transfer> ::= <error_code_quit_transfer>  # RFC 959 5.4 (QUIT); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_quit_transfer> ::= <error_code_quit_transfer>  # RFC 959 5.4 (QUIT); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_quit_transfer> ::= <error_code_quit_transfer> <reply_tail> | <error_first_quit_transfer> <reply_head> <reply_mid_line>* <error_last_quit_transfer> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_quit_transfer>: str(<r>.<error_first_quit_transfer>) == str(<r>.<error_last_quit_transfer>)
<req_quit_transfer> ::= <req_quit>   # the dependent exchange has its own request nonterminal
<quit_tail> ::= <TimerControl:transfer_cancel> <ServerClosed:connection_closed> | <ServerClosed:connection_closed> <TimerControl:transfer_cancel>   # RFC 959 4.1.1 (QUIT): the server closes the connection; Fandango cancels the timer
<exch_quit_transfer> ::= <TimerControl:transfer_start> <Client:req_quit_transfer> (<Server:rep_transfer_late_any>? (<Server:reply_221> | <Server:reply_421>) <quit_tail> | <Server:rep_transfer_late_any>? <Server:rep_quit_refused_transfer> <TimerControl:transfer_cancel> <session_end> | <TimerEvent:transfer_expired> <expired_tail>)   # RFC 959 3, 4.1.1: QUIT may be sent during a transfer; the server answers the transfer first, then 221 and closes (500 etc.: the connection stays open, the session ends); a server busy with the transfer may leave it unanswered
<transfer_after_stat> ::= <exch_abor_transfer> | <exch_quit_transfer> | <transfer_late> | <server_421> <session_end> | <server_close> <session_end> | <session_end>   # the transfer is still in progress after the reply to STAT: ABOR, QUIT, the transfer's own reply, 421, a close, or the session ends
<transfer_in_progress> ::= <exch_abor_transfer> | <exch_stat_transfer> | <exch_quit_transfer> | <transfer_late> | <server_421> <session_end> | <server_close> <session_end> | <session_end>   # RFC 959 4.1.3: the transfer is still in progress after the wait: ABOR, STAT, QUIT, the transfer's own reply, 421, a close, or the session ends

# ---------------------------------------------------------------------------------------------------------------
# Security (RFC 2228 3, 8.2; RFC 4217 4): AUTH switches to TLS (234; everything after it is the TLS layer, another protocol)
# or asks for security data (334 -> ADAT).
# ---------------------------------------------------------------------------------------------------------------
# RFC 2228 8.1: <mechanism-name> ::= <string>, written as two disjoint rules so that every AUTH argument parses one way: the name TLS (RFC 4217 4.2, 17; case independent, RFC 2228 3)
# and every other <string> (an argument that is TLS in any case is not derived by the second rule)
<mechanism_tls_name> ::= r'[Tt][Ll][Ss]' := pick_tls_name()   # RFC 4217 4.2, 17: the AUTH argument that requests TLS; the mechanism name is case independent (RFC 2228 3, RFC 4217 17), so 'TLS', 'tls' and mixed case forms are sent
<mechanism_other_name> ::= r'(?![Tt][Ll][Ss](?:\r\n|$))([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+' := pick_other_mechanism()   # RFC 2228 8.1: another <string>, drawn from FTP_AUTH_MECHANISMS (GSSAPI, KERBEROS_V4 ...), which RFC 2228 3 lets answer 234 when it needs no security data
<mechanism_tls> ::= <mechanism_tls_name>   # RFC 4217 4.2: the argument of AUTH TLS
<mechanism_other> ::= <mechanism_other_name>   # RFC 2228 8.1: the argument of AUTH with another mechanism
<req_auth_tls> ::= <cmd_auth> <SP> <mechanism_tls> <CRLF>      # RFC 4217 4: AUTH TLS (a dependent exchange has its own request nonterminal)
<req_auth_other> ::= <cmd_auth> <SP> <mechanism_other> <CRLF>  # RFC 2228 3: AUTH with another mechanism
<req_adat> ::= <cmd_adat> <SP> <base64data> <CRLF>  # RFC 2228 3, 8.2; RFC 4217 4 (AUTH / ADAT)
<error_code_auth_refused> ::= r'(?!(421|431|500|501|502|504|530|533|534))[45][0-9]{2}'  # RFC 2228 8.2 (AUTH); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_auth_refused> ::= <error_code_auth_refused>  # RFC 2228 8.2 (AUTH); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_auth_refused> ::= <error_code_auth_refused>  # RFC 2228 8.2 (AUTH); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_auth_refused> ::= <error_code_auth_refused> <reply_tail> | <error_first_auth_refused> <reply_head> <reply_mid_line>* <error_last_auth_refused> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_auth_refused>: str(<r>.<error_first_auth_refused>) == str(<r>.<error_last_auth_refused>)
<error_code_adat_refused> ::= r'(?!(421|500|501|502|503|530|533|535))[45][0-9]{2}'  # RFC 2228 8.2 (ADAT); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_adat_refused> ::= <error_code_adat_refused>  # RFC 2228 8.2 (ADAT); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_adat_refused> ::= <error_code_adat_refused>  # RFC 2228 8.2 (ADAT); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_adat_refused> ::= <error_code_adat_refused> <reply_tail> | <error_first_adat_refused> <reply_head> <reply_mid_line>* <error_last_adat_refused> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_adat_refused>: str(<r>.<error_first_adat_refused>) == str(<r>.<error_last_adat_refused>)
<rep_auth_refused> ::= <reply_502> | <reply_504> | <reply_534> | <reply_431> | <reply_500> | <reply_501> | <reply_533> | <reply_530> | <reply_421> | <reply_error_auth_refused> | <reply_protected>   # RFC 2228 8.2 (AUTH): the documented codes, 530 (not logged in), 421, 63z after a security exchange
<exch_auth_234> ::= <Client:req_auth_tls> <Server:reply_234>      # RFC 4217 4.2: 234 for AUTH TLS: the connection switches to the TLS layer (another protocol: <state_secured>)
<exch_auth_other_234> ::= <Client:req_auth_other> <Server:reply_234>   # RFC 2228 3, 8.2: 234 for a mechanism that needs no security data: the connection is authenticated, protected commands follow (<state_protected>)
<exch_auth_334> ::= <Client:req_auth_other> <Server:reply_334>      # RFC 2228 8.2: security data needed (another mechanism than TLS)
<exch_auth_refused> ::= <Client:req_auth_other> <Server:rep_auth_refused>   # RFC 2228 8.2: AUTH refused (another mechanism than TLS)
<exch_auth_tls_334> ::= <Client:req_auth_tls> <Server:reply_334>      # RFC 2228 8.2: security data needed (AUTH TLS)
<exch_auth_tls_refused> ::= <Client:req_auth_tls> <Server:rep_auth_refused>   # RFC 2228 8.2: AUTH refused (AUTH TLS)
<exch_adat_235> ::= <Client:req_adat> <Server:reply_235>      # RFC 2228 8.2: exchange complete
<exch_adat_335> ::= <Client:req_adat> <Server:reply_335>      # RFC 2228 8.2: more security data needed
<exch_adat_refused> ::= <Client:req_adat> <Server:rep_adat_refused>   # RFC 2228 8.2 (ADAT): the documented codes, 530, 421, 63z
<req_adat_unexpected> ::= <req_adat>  # RFC 2228 3, 8.2; RFC 4217 4 (AUTH / ADAT)
<exch_adat_unexpected> ::= <Client:req_adat_unexpected> <Server:rep_adat_refused>   # RFC 2228 8.2: ADAT without AUTH is a bad sequence (503)
<rep_adat_refused> ::= <reply_503> | <reply_501> | <reply_535> | <reply_500> | <reply_502> | <reply_533> | <reply_530> | <reply_421> | <reply_error_adat_refused> | <reply_protected>   # RFC 2228 8.2 (ADAT): the documented codes, 530 (not logged in), 421, 63z after a security exchange

# ---------------------------------------------------------------------------------------------------------------
# Command sequences with an intermediate state (RFC 959 5.4, 6): RNFR -> RNTO, REST -> transfer command
# ---------------------------------------------------------------------------------------------------------------
<exch_rnfr_350> ::= <Client:req_rnfr> <Server:reply_350>       # RFC 959 5.4: RNFR accepted -> expects RNTO
<req_rnto_after_rnfr> ::= <req_rnto>                           # the dependent exchange has its own request nonterminal
<exch_rnto_after_rnfr> ::= <Client:req_rnto_after_rnfr> <Server:rep_rnto>   # RFC 959 5.4
<exch_rest_350> ::= <Client:req_rest> <Server:reply_350>       # RFC 959 5.4: REST accepted -> expects a transfer command
<req_retr_after_rest> ::= <req_retr>  # RFC 959 4.1.3, 5.4 (RNFR/RNTO, REST)
<exch_retr_after_rest> ::= <TimerControl:transfer_start> <Client:req_retr_after_rest> (<Server:rep_retr_done> <transfer_tail_data_ready> | <Server:rep_retr_ended> <transfer_tail_logged_in> | <Server:rep_retr_failed> <transfer_tail_data_ready> | <Server:reply_prelim_marks> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)   # RFC 959 3.2, 5.4: the server may wait for the data connection of an earlier PASV/EPSV

<req_stor_after_rest> ::= <req_stor>  # RFC 959 4.1.3, 5.4 (RNFR/RNTO, REST)
<exch_stor_after_rest> ::= <TimerControl:transfer_start> <Client:req_stor_after_rest> (<Server:rep_stor_done> <transfer_tail_data_ready> | <Server:rep_stor_ended> <transfer_tail_logged_in> | <Server:rep_stor_failed> <transfer_tail_data_ready> | <Server:reply_prelim_marks> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)   # RFC 959 3.2, 5.4: the server may wait for the data connection of an earlier PASV/EPSV

<req_stou_after_rest> ::= <req_stou>  # RFC 959 4.1.3, 5.4 (RNFR/RNTO, REST)
<exch_stou_after_rest> ::= <TimerControl:transfer_start> <Client:req_stou_after_rest> (<Server:rep_stou_done> <transfer_tail_data_ready> | <Server:rep_stou_ended> <transfer_tail_logged_in> | <Server:rep_stou_failed> <transfer_tail_data_ready> | (<Server:stou_prelim_marks> | <Server:reply_new_prelim>) <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)   # RFC 959 3.2, 5.4: the server may wait for the data connection of an earlier PASV/EPSV

<req_appe_after_rest> ::= <req_appe>  # RFC 959 4.1.3, 5.4 (RNFR/RNTO, REST)
<exch_appe_after_rest> ::= <TimerControl:transfer_start> <Client:req_appe_after_rest> (<Server:rep_appe_done> <transfer_tail_data_ready> | <Server:rep_appe_ended> <transfer_tail_logged_in> | <Server:rep_appe_failed> <transfer_tail_data_ready> | <Server:reply_prelim_marks> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)   # RFC 959 3.2, 5.4: the server may wait for the data connection of an earlier PASV/EPSV

<req_list_after_rest> ::= <req_list>  # RFC 959 4.1.3, 5.4 (RNFR/RNTO, REST)
<exch_list_after_rest> ::= <TimerControl:transfer_start> <Client:req_list_after_rest> (<Server:rep_list_done> <transfer_tail_data_ready> | <Server:rep_list_ended> <transfer_tail_logged_in> | <Server:rep_list_failed> <transfer_tail_data_ready> | <Server:reply_prelim> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)   # RFC 959 3.2, 5.4: the server may wait for the data connection of an earlier PASV/EPSV

<req_nlst_after_rest> ::= <req_nlst>  # RFC 959 4.1.3, 5.4 (RNFR/RNTO, REST)
<exch_nlst_after_rest> ::= <TimerControl:transfer_start> <Client:req_nlst_after_rest> (<Server:rep_nlst_done> <transfer_tail_data_ready> | <Server:rep_nlst_ended> <transfer_tail_logged_in> | <Server:rep_nlst_failed> <transfer_tail_data_ready> | <Server:reply_prelim> <TimerEvent:transfer_expired> <transfer_in_progress> | <TimerEvent:transfer_expired> <transfer_in_progress>)   # RFC 959 3.2, 5.4: the server may wait for the data connection of an earlier PASV/EPSV

# Targets that earlier replies name are taken from those replies: the pathname of a 257 reply (PWD, MKD) or of an MLST entry
# (RFC 959 4.1.3, RFC 3659 7.2). The pathname of the request equals the one the last such reply named.
<arg_recalled_path> ::= r'([\x01-\x09\x0b\x0c\x0e-\x7f\u00a1-\ud7ff\U00010000-\U0010ffff]|\r\x00)+'
<req_cwd_recalled> ::= <cmd_cwd> <SP> <arg_recalled_path> <CRLF>    # RFC 959 4.1.1
<req_size_recalled> ::= <cmd_size> <SP> <arg_recalled_path> <CRLF>  # RFC 3659 4.1
<exch_cwd_recalled> ::= <Client:req_cwd_recalled> <Server:rep_cwd>  # RFC 959 4.1.1; RFC 3659 4.1, 7.2 (target taken from an earlier reply)
<exch_size_recalled> ::= <Client:req_size_recalled> <Server:rep_size>  # RFC 959 4.1.1; RFC 3659 4.1, 7.2 (target taken from an earlier reply)
where forall <x> in <req_cwd_recalled>: str(<x>.<arg_recalled_path>) == last_named_path(<x>)
where forall <x> in <req_size_recalled>: str(<x>.<arg_recalled_path>) == last_named_path(<x>)

# EPSV ALL (RFC 2428 3, 4): afterwards the server rejects PORT, EPRT and PASV (checked on the replies of those exchanges, see `setup_rejected_after_epsv_all`)
<epsv_all_word> ::= r'[Aa][Ll][Ll]'   # RFC 2428 3: EPSV<space>ALL
<req_epsv_all> ::= <cmd_epsv> <SP> <epsv_all_word> <CRLF>  # RFC 2428 3 (EPSV ALL)
# RFC 2428 3 defines no reply code for EPSV ALL: any positive completion reply (2yz) except 221 (closing) is accepted
<rep_positive_completion> ::= <reply_200> | <reply_202> | <reply_211> | <reply_212> | <reply_213> | <reply_214> | <reply_215> | <reply_220> | <reply_225> | <reply_226> | <reply_227> | <reply_229> | <reply_230> | <reply_232> | <reply_234> | <reply_235> | <reply_250> | <reply_257> | <reply_protected>
<exch_epsv_all_200> ::= <Client:req_epsv_all> <Server:rep_positive_completion>   # RFC 2428 3 -> EPSV ALL in effect
<exch_epsv_all_refused> ::= <Client:req_epsv_all> <Server:rep_epsv_all_refused>  # RFC 2428 3 (EPSV ALL)
<error_code_epsv_all> ::= r'(?!(200|202|211|212|213|214|215|220|225|226|227|229|230|232|234|235|250|257|421|500|501|502|504|522|530))[2-5][0-9]{2}'  # RFC 2428 3 (EPSV ALL has no defined reply); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_epsv_all> ::= <error_code_epsv_all>  # RFC 2428 3 (EPSV ALL has no defined reply); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_epsv_all> ::= <error_code_epsv_all>  # RFC 2428 3 (EPSV ALL has no defined reply); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_epsv_all> ::= <error_code_epsv_all> <reply_tail> | <error_first_epsv_all> <reply_head> <reply_mid_line>* <error_last_epsv_all> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_epsv_all>: str(<r>.<error_first_epsv_all>) == str(<r>.<error_last_epsv_all>)
<rep_epsv_all_refused> ::= <reply_500> | <reply_501> | <reply_502> | <reply_522> | <reply_530> | <reply_504> | <reply_421> | <reply_protected> | <reply_error_epsv_all>  # RFC 2428 3 (EPSV ALL)

# HOST (RFC 7151 3): before authentication; after it the server must answer 503
<error_code_host_after_login> ::= r'(?!(421|500|502|503))[2-5][0-9]{2}'  # RFC 7151 3.3 (HOST); RFC 1123 4.1.2.11: a code of class 2 to 5 (RFC 959 4.2: first digit the class, second the function group) that the table does not list for the command
<error_first_host_after_login> ::= <error_code_host_after_login>  # RFC 7151 3.3 (HOST); RFC 1123 4.1.2.11: code of the first line of a multi-line reply
<error_last_host_after_login> ::= <error_code_host_after_login>  # RFC 7151 3.3 (HOST); RFC 1123 4.1.2.11: code of the last line of a multi-line reply (equal to the first)
<reply_error_host_after_login> ::= <error_code_host_after_login> <reply_tail> | <error_first_host_after_login> <reply_head> <reply_mid_line>* <error_last_host_after_login> <reply_tail>  # error-response; RFC 959 4.2: multi-line form
where forall <r> in <reply_error_host_after_login>: str(<r>.<error_first_host_after_login>) == str(<r>.<error_last_host_after_login>)
<rep_host_after_login> ::= <reply_503> | <reply_500> | <reply_502> | <reply_421> | <reply_error_host_after_login>        # (500, 502: RFC 7151 3.3 unimplemented HOST) RFC 7151 3: 'MUST treat ... as an erroneous sequence of commands and return a 503 reply'
<req_host_after_login> ::= <req_host>  # RFC 7151 3 (HOST)
<exch_host_after_login> ::= <Client:req_host_after_login> <Server:rep_host_after_login>  # RFC 7151 3 (HOST)

# RFC 959 4.2.1: the server may send 421 on its own initiative (service shutting down); the connection is closed afterwards
<server_421> ::= <Server:reply_421> <ServerClosed:connection_closed>
# RFC 959 4.2.1: the server may close the control connection after any reply (a limit of failed logins or errors, an idle timeout): accepted between two exchanges
<server_close> ::= <ServerClosed:connection_closed>

# ---------------------------------------------------------------------------------------------------------------
# Groups of exchanges that do not change the state
# ---------------------------------------------------------------------------------------------------------------
<plain_exchange> ::= <exch_noop> | <exch_syst> | <exch_stat> | <exch_help> | <exch_site> | <exch_cwd> | <exch_cdup> | <exch_smnt> | <exch_stru> | <exch_mode> | <exch_type> | <exch_allo> | <exch_dele> | <exch_rmd> | <exch_mkd> | <exch_pwd> | <exch_xmkd> | <exch_xrmd> | <exch_xpwd> | <exch_xcup> | <exch_xcwd> | <exch_rnfr> | <exch_rnto> | <exch_rest> | <exch_size> | <exch_mdtm> | <exch_mlst> | <exch_feat> | <exch_lang> | <exch_pbsz> | <exch_prot> | <exch_ccc> | <exch_mic> | <exch_conf> | <exch_enc> | <exch_opts_mlst> | <exch_opts_other> | <exch_adat_unexpected> | <exch_cwd_recalled> | <exch_size_recalled>
<setup_exchange> ::= <exch_port> | <exch_pasv> | <exch_eprt> | <exch_epsv>  # RFC 959 5.4 (command-reply sequences)
<transfer_exchange> ::= <exch_retr> | <exch_stor> | <exch_stou> | <exch_appe> | <exch_list> | <exch_nlst> | <exch_mlsd>  # RFC 959 3.2; Fandango timers (the server may wait for the data connection)
<transfer_exchange_dr> ::= <exch_retr_dr> | <exch_stor_dr> | <exch_stou_dr> | <exch_appe_dr> | <exch_list_dr> | <exch_nlst_dr> | <exch_mlsd_dr>  # RFC 959 3.2; Fandango timers (the server may wait for the data connection)
<setup_refused_exchange> ::= <exch_port_refused> | <exch_pasv_refused> | <exch_eprt_refused> | <exch_epsv_refused>  # RFC 959 5.4 (command-reply sequences)

# ---------------------------------------------------------------------------------------------------------------
# States (RFC 959 6; RFC 2228 9; RFC 7151 3): one nonterminal per state, one alternative per transition
# ---------------------------------------------------------------------------------------------------------------
<session_end> ::= ''
# The TLS layer after a 234 reply to AUTH TLS (RFC 4217) is another protocol; the session is modeled up to the exchange that switches to it.
# TODO: RFC 4217 4, 5-13 and RFC 2228 5.2, 6, App. I, II (the TLS layer, the content of MIC/CONF/ENC protected commands, data protection):
#   everything exchanged inside the TLS layer is another protocol; nearest nonterminal <state_secured>.
<state_secured> ::= ''
# RFC 2228 2, 9: after a completed security data exchange (ADAT 235) commands and replies must be integrity protected (MIC / CONF / ENC, 631 / 632 / 633):
# the protected commands, their replies, and the close; what the protected commands contain (the commands themselves) is the content of the mechanism's
# protected channel (RFC 2228 App. I, II), another protocol: 
# TODO: RFC 2228 2, 3, 5.2, 9 (plain FTP commands carried inside MIC/CONF/ENC after a completed ADAT, CCC inside it): nearest nonterminal <state_protected>; the base64 payload is the GSSAPI/Kerberos token format of the mechanism.
<state_protected> ::= (
      <exch_mic> <state_protected>
    | <exch_conf> <state_protected>
    | <exch_enc> <state_protected>
    | <server_421> <session_end>
    | <server_close> <session_end>
    | <session_end>
    )

# RFC 959 6, RFC 2228 9: state Unauthenticated / Begin; also reached by REIN and by a failed login
<state_unauth> ::= (
      <plain_exchange> <state_unauth>
    | <exch_rnfr_350> <state_rnto>
    | <exch_rest_350> <state_rest>
    | <setup_exchange> <state_unauth>
    | <transfer_exchange> <state_unauth>
    | <exch_host> <state_unauth>
    | <exch_abor> <state_unauth>
    | <exch_acct_early> <state_unauth>
    | <exch_user_331> <state_need_pass>
    | <exch_user_230> <state_logged_in>
    | <exch_user_332> <state_need_acct>
    | <exch_user_refused> <state_unauth>
    | <exch_user_wrong_331> <state_need_pass>
    | <exch_user_wrong_230> <state_logged_in>
    | <exch_user_wrong_332> <state_need_acct>
    | <exch_user_wrong_refused> <state_unauth>
    | <exch_auth_refused> <state_unauth>
    | <exch_auth_tls_refused> <state_unauth>
    | <exch_auth_334> <state_need_adat>
    | <exch_auth_tls_334> <state_need_adat>
    | <exch_auth_234> <state_secured>
    | <exch_auth_other_234> <state_protected>
    | <exch_rein_ok> <state_unauth>
    | <exch_rein_refused> <state_unauth>
    | <exch_epsv_all_200> <state_unauth>
    | <exch_epsv_all_refused> <state_unauth>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_unauth>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 959 6, RFC 2228 9: state Need Password (after USER with 331)
<state_need_pass> ::= (
      <exch_pass_230> <state_logged_in>
    | <exch_pass_332> <state_need_acct>
    | <exch_pass_refused> <state_unauth>
    | <exch_pass_wrong_230> <state_logged_in>
    | <exch_pass_wrong_332> <state_need_acct>
    | <exch_pass_wrong> <state_unauth>
    | <exch_user_331> <state_need_pass>
    | <exch_user_230> <state_logged_in>
    | <exch_user_332> <state_need_acct>
    | <exch_user_refused> <state_unauth>
    | <exch_user_wrong_331> <state_need_pass>
    | <exch_user_wrong_230> <state_logged_in>
    | <exch_user_wrong_332> <state_need_acct>
    | <exch_user_wrong_refused> <state_unauth>
    | <exch_rein_ok> <state_unauth>
    | <exch_rein_refused> <state_need_pass>
    | <exch_host> <state_need_pass>
    | <exch_auth_refused> <state_unauth>
    | <exch_auth_tls_refused> <state_unauth>
    | <exch_auth_334> <state_need_adat>
    | <exch_auth_tls_334> <state_need_adat>
    | <exch_auth_234> <state_secured>
    | <exch_auth_other_234> <state_protected>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_need_pass>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 959 6, RFC 2228 9: state Need Account (after 332)
<state_need_acct> ::= (
      <plain_exchange> <state_need_acct>
    | <exch_rnfr_350> <state_rnto>
    | <exch_rest_350> <state_rest>
    | <setup_exchange> <state_need_acct>
    | <transfer_exchange> <state_need_acct>
    | <exch_host> <state_need_acct>
    | <exch_abor> <state_need_acct>
    | <exch_acct_230> <state_logged_in>
    | <exch_acct_wrong_230> <state_logged_in>
    | <exch_acct_valid_refused> <state_unauth>
    | <exch_acct_refused> <state_unauth>
    | <exch_user_331> <state_need_pass>
    | <exch_user_230> <state_logged_in>
    | <exch_user_332> <state_need_acct>
    | <exch_user_refused> <state_unauth>
    | <exch_user_wrong_331> <state_need_pass>
    | <exch_user_wrong_230> <state_logged_in>
    | <exch_user_wrong_332> <state_need_acct>
    | <exch_user_wrong_refused> <state_unauth>
    | <exch_auth_refused> <state_need_acct>
    | <exch_auth_tls_refused> <state_need_acct>
    | <exch_auth_334> <state_need_adat>
    | <exch_auth_tls_334> <state_need_adat>
    | <exch_auth_234> <state_secured>
    | <exch_auth_other_234> <state_protected>
    | <exch_rein_ok> <state_unauth>
    | <exch_rein_refused> <state_need_acct>
    | <exch_epsv_all_200> <state_need_acct>
    | <exch_epsv_all_refused> <state_need_acct>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_need_acct>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 2228 9: state Need Security Data (after AUTH 334)
<state_need_adat> ::= (
      <exch_adat_235> <state_protected>
    | <exch_adat_335> <state_need_adat>
    | <exch_adat_refused> <state_unauth>
    | <exch_auth_334> <state_need_adat>
    | <exch_auth_tls_334> <state_need_adat>
    | <exch_auth_234> <state_secured>
    | <exch_auth_other_234> <state_protected>
    | <exch_auth_refused> <state_unauth>
    | <exch_auth_tls_refused> <state_unauth>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_need_adat>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 959 6, RFC 2228 9: state Authorized / logged in (no data connection set up)
<state_logged_in> ::= (
      <plain_exchange> <state_logged_in>
    | <setup_refused_exchange> <state_logged_in>
    | <exch_port_ok> <state_data_ready>
    | <exch_pasv_ok> <state_data_ready>
    | <exch_eprt_ok> <state_data_ready>
    | <exch_epsv_ok> <state_data_ready>
    | <transfer_exchange> <state_logged_in>
    | <exch_host_after_login> <state_logged_in>
    | <exch_abor> <state_logged_in>
    | <exch_acct_early> <state_logged_in>
    | <exch_rnfr_350> <state_rnto>
    | <exch_rest_350> <state_rest>
    | <exch_epsv_all_200> <state_data_ready>
    | <exch_epsv_all_refused> <state_logged_in>
    | <exch_user_331> <state_need_pass>
    | <exch_user_230> <state_logged_in>
    | <exch_user_332> <state_need_acct>
    | <exch_user_refused> <state_logged_in>
    | <exch_user_wrong_331> <state_need_pass>
    | <exch_user_wrong_230> <state_logged_in>
    | <exch_user_wrong_332> <state_need_acct>
    | <exch_user_wrong_refused> <state_logged_in>
    | <exch_auth_refused> <state_logged_in>
    | <exch_auth_tls_refused> <state_logged_in>
    | <exch_auth_334> <state_need_adat>
    | <exch_auth_tls_334> <state_need_adat>
    | <exch_auth_234> <state_secured>
    | <exch_auth_other_234> <state_protected>
    | <exch_rein_ok> <state_unauth>
    | <exch_rein_refused> <state_logged_in>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_logged_in>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 959 3.2, 6: logged in, after a data connection was set up by PORT, PASV, EPRT or EPSV (positive reply): the transfer command that follows may be answered, or the server waits for the client's data connection (it may keep waiting for one after a transfer (Pure-FTPd keeps its passive listener) and after EPSV ALL (ProFTPD then waits for the passive connection of an EPSV that was not sent))
<state_data_ready> ::= (
      <plain_exchange> <state_data_ready>
    | <setup_refused_exchange> <state_data_ready>
    | <exch_port_ok> <state_data_ready>
    | <exch_pasv_ok> <state_data_ready>
    | <exch_eprt_ok> <state_data_ready>
    | <exch_epsv_ok> <state_data_ready>
    | <transfer_exchange_dr>
    | <exch_rest_350> <state_rest>
    | <exch_rnfr_350> <state_rnto>
    | <exch_host_after_login> <state_data_ready>
    | <exch_abor> <state_data_ready>
    | <exch_acct_early> <state_data_ready>
    | <exch_epsv_all_200> <state_data_ready>
    | <exch_epsv_all_refused> <state_data_ready>
    | <exch_user_331> <state_need_pass>
    | <exch_user_230> <state_data_ready>
    | <exch_user_332> <state_need_acct>
    | <exch_user_refused> <state_data_ready>
    | <exch_user_wrong_331> <state_need_pass>
    | <exch_user_wrong_230> <state_data_ready>
    | <exch_user_wrong_332> <state_need_acct>
    | <exch_user_wrong_refused> <state_data_ready>
    | <exch_auth_refused> <state_data_ready>
    | <exch_auth_tls_refused> <state_data_ready>
    | <exch_auth_334> <state_need_adat>
    | <exch_auth_tls_334> <state_need_adat>
    | <exch_auth_234> <state_secured>
    | <exch_auth_other_234> <state_protected>
    | <exch_rein_ok> <state_unauth>
    | <exch_rein_refused> <state_data_ready>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_data_ready>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 959 5.4 / 6: intermediate state after RNFR 350: the next command is RNTO
<state_rnto> ::= (
      <exch_rnto_after_rnfr> <state_data_ready>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_rnto>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# RFC 959 5.4 / 6, RFC 3659 5: intermediate state after REST 350: the next command is a transfer command
<state_rest> ::= (
      <exch_retr_after_rest>
    | <exch_stor_after_rest>
    | <exch_stou_after_rest>
    | <exch_appe_after_rest>
    | <exch_list_after_rest>
    | <exch_nlst_after_rest>
    | <exch_quit> <session_end>
    | <exch_quit_refused> <state_rest>
    | <server_421> <session_end>
    | <server_close> <session_end>
    )

# the end of a transfer exchange: Fandango cancels the timer; the server may close the connection right after its reply (before the cancel)
<transfer_tail_data_ready> ::= <TimerControl:transfer_cancel> <state_data_ready> | <ServerClosed:connection_closed> <TimerControl:transfer_cancel> <session_end>
# the end of a transfer exchange: Fandango cancels the timer; the server may close the connection right after its reply (before the cancel)
<transfer_tail_logged_in> ::= <TimerControl:transfer_cancel> <state_logged_in> | <ServerClosed:connection_closed> <TimerControl:transfer_cancel> <session_end>
# ---------------------------------------------------------------------------------------------------------------
# Constraints on received messages (the grammar cannot express them); each is checked when the message is complete.
# Only mandatory requirements; a requirement that applies under a condition on the implementation is enforced only where
# earlier messages of the session show the condition.
# ---------------------------------------------------------------------------------------------------------------
import re

def _name(node):
    return str(node.symbol)

def _before(node, names):
    """The nodes named `names` that precede `node` in the session, in session order."""
    found = []
    for descendant in node.get_root().descendants():
        if descendant is node:
            break
        if _name(descendant) in names:
            found.append(descendant)
    return found

def _feat_labels(feat):
    labels = set()
    for line in str(feat).split("\r\n")[1:]:
        if line.startswith(" ") and len(line) > 1:
            labels.add(line[1:].split(" ")[0].upper().rstrip(";*"))
    return labels

def _reply_code(exchange):
    for descendant in exchange.descendants():
        if _name(descendant).startswith(("<code_", "<error_first_", "<error_code_")):     # a generic 4yz/5yz reply has an <error_code_X>
            return str(descendant)
        if _name(descendant).startswith("<reply_bare_"):
            return str(descendant)[:3]                                      # a reply of the code only (RFC 2640 4.2, RFC 7151 3.1)
    return None

def _exempt(code):
    """421 (RFC 959 4.2.1: any command) and a protected reply (RFC 2228 8.2: any command after a security exchange) are replies to every command."""
    return code == "421" or (code or "5")[0] == "6"

_DECLINED = ("500", "502", "530", "421")

def _shows_implemented(exchange):
    """The reply to a command shows that the server implements it where it is not 500 / 502 (RFC 2389 3.2: 'a reply other than a 500 or 502'), nor
    530 (before login every command is answered so), nor 421 or a protected reply."""
    code = _reply_code(exchange)
    return code is not None and code not in _DECLINED and code[0] != "6"

def _transfer_mode_is_stream(node):
    """True unless the session showed the transfer mode changed to B or C (RFC 959 3.4): MODE accepted with 200 and the code B or C last."""
    stream = True
    for exchange in _before(node, ["<exch_mode>", "<exch_rein_ok>"]):
        if _name(exchange) == "<exch_rein_ok>":
            stream = True
        elif _reply_code(exchange) == "200":
            code = (_argument(exchange, "<mode_code>") or "S").upper()
            stream = code == "S"
    return stream

def feat_lists_supported_features(feat):
    """RFC 3659 3.3, 4.3, 5.4, 7.8, RFC 2640 3.2, 4.3, RFC 7151 3.4, RFC 4217 6: FEAT lists what the session showed the server supports (a reply to the
    command other than 500 / 502 / 530 / 421 shows the command is implemented: RFC 2389 3.2 / RFC 3659 give the errors of a recognized command);
    RFC 2640 3.2: a server MUST list UTF8 (a no-features reply has no UTF8 line)."""
    labels = _feat_labels(feat)
    if "UTF8" not in labels:                                              # RFC 2640 3.2
        return False
    if any(_shows_implemented(x) for x in _before(feat, ["<exch_mdtm>"])) and "MDTM" not in labels:      # RFC 3659 3.3
        return False
    if any(_shows_implemented(x) for x in _before(feat, ["<exch_size>", "<exch_size_recalled>"])) and "SIZE" not in labels:      # RFC 3659 4.3
        return False
    if (any(_shows_implemented(x) for x in _before(feat, ["<exch_mlst>", "<exch_mlsd>", "<exch_mlsd_dr>"])) or
            any(_reply_code(x) == "200" for x in _before(feat, ["<exch_opts_mlst>"]))) and "MLST" not in labels:
        return False                                                       # RFC 3659 7.8; RFC 2389 4: OPTS is answered 200 only for a recognized command-name, any other reply (451, 501) is no sign that MLST is implemented
    for exchange in _before(feat, ["<exch_rest_350>", "<exch_rest>"]):    # RFC 3659 5.4: REST in STREAM mode
        marker = _argument(exchange, "<marker>") or ""
        if _reply_code(exchange) == "350" and marker.isdigit() and _transfer_mode_is_stream(exchange) and "REST" not in labels:      # RFC 3659 5.3: in stream mode only 350 shows REST STREAM is supported (an error reply to a valid marker says it is not)
            return False
    for exchange in _before(feat, ["<exch_rest>"]):                       # RFC 3659 5.4: no REST line where REST is unsupported
        marker = _argument(exchange, "<marker>") or ""
        if (_reply_code(exchange) == "502" or (_reply_code(exchange) == "500" and marker.isdigit())) and "REST" in labels and _transfer_mode_is_stream(exchange):
            return False
    if any(_shows_implemented(x) for x in _before(feat, ["<exch_lang>"])) and "LANG" not in labels:       # RFC 2640 4.3: LANG
        return False
    if any(_shows_implemented(x) for x in _before(feat, ["<exch_host>", "<exch_host_after_login>"])) and "HOST" not in labels:
        return False                                                       # RFC 7151 3.4
    if any(_shows_implemented(x) for x in _before(feat, ["<exch_pbsz>"])) and "PBSZ" not in labels:
        return False                                                       # RFC 4217 6
    if any(_shows_implemented(x) for x in _before(feat, ["<exch_prot>"])) and "PROT" not in labels:
        return False                                                       # RFC 4217 6
    if (_before(feat, ["<exch_auth_334>", "<exch_auth_tls_334>", "<exch_auth_234>", "<exch_auth_other_234>"]) or any(_reply_code(x) in ("504", "534", "431", "501", "533") for x in _before(feat, ["<exch_auth_refused>", "<exch_auth_tls_refused>"]))) \
            and "AUTH" not in labels:
        return False                                                       # RFC 4217 6 / RFC 2228
    return True

where forall <f> in <reply_211_feat>: feat_lists_supported_features(<f>)

def _reply_257_lines(text):
    """The text of every line of a reply: the code and the separator ('-' or ' ') cut off."""
    return [line[4:] if len(line) > 3 and line[3] in "- " else line[3:] for line in text.split("\r\n") if line]

def reply_257_quoted_strings(reply):
    """Every closed quoted string of a 257 reply (a doubled quote inside is one quote, RFC 959 App. II); RFC 959 App. II does not say which line or which quoted string carries the pathname."""
    found = []
    for line in _reply_257_lines(str(reply)):
        i = 0
        while i < len(line):
            if line[i] != '"':
                i += 1
                continue
            out = []
            k = i + 1
            while k < len(line):
                if line[k] == '"':
                    if line[k + 1:k + 2] == '"':
                        out.append('"')
                        k += 2
                        continue
                    break
                out.append(line[k])
                k += 1
            if k < len(line):
                found.append("".join(out))
                i = k + 1
            else:
                i += 1                                                     # a lone quote closes nothing
    return found

def mkd_path_is_absolute(reply):
    """RFC 959 Appendix II: the 257 reply to MKD must always contain the absolute pathname of the created directory. The reply contains it where one of its quoted strings is a pathname
    (after a UNIX SYST, whose naming convention defines 'absolute': one starts with '/'); a reply with no quoted string must still contain the pathname in its text: after UNIX a token that starts
    with '/', otherwise the name the client sent in the MKD request or a token that starts with '/'."""
    unix = any(str(name).upper() == "UNIX" for syst in _before(reply, ["<reply_215>"]) for name in [d for d in syst.descendants() if _name(d) == "<system_name>"][:1])
    quoted = reply_257_quoted_strings(reply)
    text = " ".join(_reply_257_lines(str(reply)))
    slash_token = any(w.lstrip('"').startswith("/") for w in text.split())          # an odd quote may hide the pathname from the quoted strings: `5" deep "/a/b"`
    if quoted:
        return (any(q.startswith("/") for q in quoted) or slash_token) if unix else True
    if slash_token:
        return True
    if unix:
        return False
    requests = _before(reply, ["<req_mkd>", "<req_xmkd>"])
    argument = _argument(requests[-1], "<arg_new_name>") if requests else None
    return bool(argument) and argument in text

where forall <r> in <reply_257_mkd>: mkd_path_is_absolute(<r>)

# RFC 2228 8.2 (Kerberos, Appendix II): after 'AUTH KERBEROS_V4' (334) the successful ADAT is answered 235 with 'ADAT=<base64string>' in its text
def adat_235_after_kerberos_carries_data(exchange):
    for auth in reversed(_before(exchange, ["<exch_auth_334>", "<exch_auth_tls_334>"])):
        mechanism = _argument(auth, "<mechanism_other_name>")
        if mechanism is None or mechanism.upper() != "KERBEROS_V4":
            return True
        import re
        return re.search(r"ADAT=[A-Za-z0-9+/]+={0,2}", str(exchange)) is not None
    return True

where forall <x> in <exch_adat_235>: adat_235_after_kerberos_carries_data(<x>)

def last_named_path(node):
    """The pathname the last earlier reply named (a 257 reply, or an MLST entry); '.' while none did. The recalling side of the pair
    whose recording side are the <quoted_pathname> and <mlst_pathname> of those replies (RFC 959 4.2.1, RFC 3659 7.2)."""
    try:
        named = [str(entry) for entry in _before(node, ["<quoted_pathname>", "<mlst_pathname>"])]
        return named[-1].replace('""', '"') if named else "."
    except Exception:
        return "."

def _login_state(node):
    """(logged_in, epsv_all) at `node`, from the exchanges before it (RFC 959 6, RFC 2428 3)."""
    logged_in, epsv_all = False, False
    for exchange in _before(node, ["<exch_user_230>", "<exch_pass_230>", "<exch_acct_230>", "<exch_rein_ok>", "<exch_user_331>",
                                   "<exch_user_332>", "<exch_user_wrong_331>", "<exch_pass_refused>", "<exch_pass_wrong>",
                                   "<exch_pass_332>", "<exch_epsv_all_200>", "<exch_user_wrong_230>", "<exch_user_wrong_332>",
                                   "<exch_pass_wrong_230>", "<exch_pass_wrong_332>", "<exch_acct_wrong_230>", "<exch_acct_refused>",
                                   "<exch_acct_valid_refused>", "<exch_user_refused>", "<exch_user_wrong_refused>", "<exch_auth_334>", "<exch_auth_tls_334>", "<exch_auth_234>", "<exch_auth_other_234>",
                                   "<exch_adat_235>", "<exch_adat_refused>"]):
        name = _name(exchange)
        if name in ("<exch_user_230>", "<exch_pass_230>", "<exch_acct_230>", "<exch_user_wrong_230>", "<exch_pass_wrong_230>", "<exch_acct_wrong_230>"):
            logged_in = True
        elif name == "<exch_epsv_all_200>":
            epsv_all = True
        elif name == "<exch_rein_ok>":
            logged_in, epsv_all = False, False
        else:
            logged_in = False                      # a refused USER/PASS/ACCT, and AUTH 334/234, ADAT 235 / refused (RFC 2228 9: back to Unauthenticated, the user must reauthorize)
    return logged_in, epsv_all

def _argument(exchange, symbol):
    for descendant in exchange.descendants():
        if _name(descendant) == symbol:
            return str(descendant)
    return None

# RFC 2428 2: a valid EPRT command MUST be answered with 200 (an IPv6 address may be refused with 522), where the session showed that the server
# implements EPRT (RFC 2389 3.2: a FEAT line EPRT, or an earlier 200 reply to EPRT)
def _eprt_is_implemented(exchange):
    return any("EPRT" in _feat_labels(feat) for feat in _before(exchange, ["<exch_feat>"])) or \
        any(_reply_code(earlier) == "200" for earlier in _before(exchange, ["<exch_eprt>", "<exch_eprt_ok>"]))

def valid_eprt_gets_200(exchange):
    logged_in, epsv_all = _login_state(exchange)
    if not logged_in or epsv_all or not _eprt_is_implemented(exchange):
        return True
    code = _reply_code(exchange)
    return code in ("200", "522") or _exempt(code)          # 522: the server does not support the requested protocol (RFC 2428 2), IPv4 included

where forall <x> in <exch_eprt>: valid_eprt_gets_200(<x>)
where forall <x> in <exch_eprt_ok>: valid_eprt_gets_200(<x>)
where forall <x> in <exch_eprt_refused>: valid_eprt_gets_200(<x>)

# RFC 2428 3: after 'EPSV ALL' (answered 2yz) 'the server MUST reject all data connection setup commands' (PORT, PASV, EPRT): the reply is a 4yz or 5yz error
def setup_rejected_after_epsv_all(exchange):
    if not _login_state(exchange)[1]:
        return True
    return (_reply_code(exchange) or "5")[0] in ("4", "5", "6")                # (a protected reply: RFC 2228 8.2)

where forall <x> in <exch_port>: setup_rejected_after_epsv_all(<x>)
where forall <x> in <exch_pasv>: setup_rejected_after_epsv_all(<x>)
where forall <x> in <exch_eprt>: setup_rejected_after_epsv_all(<x>)
where forall <x> in <exch_port_ok>: setup_rejected_after_epsv_all(<x>)
where forall <x> in <exch_pasv_ok>: setup_rejected_after_epsv_all(<x>)
where forall <x> in <exch_eprt_ok>: setup_rejected_after_epsv_all(<x>)

# RFC 2428 3: EPSV with a <net-prt> the server does not support: 'the server MUST return the 522 error messages'. The session shows which protocols the server
# supports where an earlier 522 reply listed them (RFC 2428 2: the text of 522 MUST list them); then an EPSV for another protocol is answered 522.
def epsv_net_prt_answered_229_or_522(exchange):
    requested = _argument(exchange, "<epsv_net_prt>")
    if requested is None or not _login_state(exchange)[0]:
        return True
    supported = None
    for reply in _before(exchange, ["<reply_522>"]):
        lists = [str(x) for x in reply.descendants() if _name(x) == "<af_list>"]
        if lists:
            supported = set(lists[-1].split(","))
    if supported is None or requested in supported:
        return True
    return _reply_code(exchange) == "522" or _exempt(_reply_code(exchange))

where forall <x> in <exch_epsv>: epsv_net_prt_answered_229_or_522(<x>)
where forall <x> in <exch_epsv_ok>: epsv_net_prt_answered_229_or_522(<x>)
where forall <x> in <exch_epsv_refused>: epsv_net_prt_answered_229_or_522(<x>)

# RFC 2389 4: 'The OPTS command MUST be implemented whenever the FEAT command is implemented'
def opts_implemented_where_feat_is(exchange):
    for feat in _before(exchange, ["<exch_feat>"]):
        if _reply_code(feat) not in (None, "500", "502"):              # RFC 2389 3.2: FEAT is implemented where its reply is not 500 or 502
            return _reply_code(exchange) not in ("500", "502")
    return True

where forall <x> in <exch_opts_mlst>: opts_implemented_where_feat_is(<x>)
where forall <x> in <exch_opts_other>: opts_implemented_where_feat_is(<x>)

# RFC 3659 7.9: after OPTS MLST 'Facts not included in the "OPTS MLST" command MUST NOT be returned by the server'
def mlst_returns_only_requested_facts(reply):
    for exchange in reversed(_before(reply, ["<exch_opts_mlst>", "<exch_rein_ok>"])):
        if _name(exchange) == "<exch_rein_ok>":
            return True                                                    # RFC 959 4.1.1: REIN resets the parameters
        if _reply_code(exchange) == "200":
            requested = set()
            for fact in exchange.descendants():
                if _name(fact) == "<opts_mlst_fact>":
                    requested.add(str(fact).rstrip(";").lower())
            for fact in reply.descendants():
                if _name(fact) in ("<fact_size>", "<fact_modify>", "<fact_create>", "<fact_type>", "<fact_unique>", "<fact_perm>",
                                   "<fact_lang>", "<fact_media_type>", "<fact_charset>", "<fact_os>", "<fact_local>", "<fact_other>"):
                    if str(fact).split("=")[0].lower() not in requested:
                        return False
            return True
    return True

where forall <r> in <reply_250_mlst>: mlst_returns_only_requested_facts(<r>)

# RFC 3659 7.2: when MLST returns several entries (several Type facts) 'the pathname component of every response MUST be identical'
def mlst_pathnames_identical(reply):
    return len({str(d) for d in reply.descendants() if _name(d) == "<mlst_pathname>"}) <= 1

where forall <r> in <reply_250_mlst>: mlst_pathnames_identical(<r>)

# RFC 959 Appendix II: MKD naming an existing directory must be answered with an 'access denied' error reply (550)
def mkd_of_existing_directory_refused(exchange):
    name = _argument(exchange, "<arg_new_name>")
    if name is None:
        return True
    created = set()
    for earlier in _before(exchange, ["<exch_mkd>", "<exch_xmkd>", "<exch_rmd>", "<exch_xrmd>", "<exch_rnto_after_rnfr>",
                                      "<exch_rnto>", "<exch_dele>", "<exch_rein_ok>", "<exch_cwd>", "<exch_cwd_recalled>",
                                      "<exch_cdup>", "<exch_xcwd>", "<exch_xcup>", "<exch_smnt>", "<exch_site>", "<exch_user_230>", "<exch_user_331>",
                                      "<exch_user_332>", "<exch_user_wrong_331>", "<exch_user_wrong_230>", "<exch_user_wrong_332>", "<exch_user_refused>",
                                      "<exch_user_wrong_refused>"]):
        kind = _name(earlier)
        if kind in ("<exch_mkd>", "<exch_xmkd>"):
            target = _argument(earlier, "<arg_new_name>")
            if _reply_code(earlier) == "257" and target is not None:
                created.add(target)
        else:
            created.clear()           # whatever else happened, the name may mean something else now (another spelling of it, another directory, removed)
    return name not in created or (_reply_code(exchange) or "5")[0] in ("4", "5")   # RFC 959 App. II: an 'access denied' error reply

where forall <x> in <exch_mkd>: mkd_of_existing_directory_refused(<x>)
where forall <x> in <exch_xmkd>: mkd_of_existing_directory_refused(<x>)

# RFC 3659 7.1: MLSD of a name that is not a directory is answered with 501 and no data connection is opened
def _known_file(exchange, path):
    """True where the session showed that `path` names a file of the working directory: SIZE answered 213, with no CWD/DELE/rename since."""
    known = False
    for earlier in _before(exchange, ["<exch_user_331>", "<exch_user_230>", "<exch_user_332>", "<exch_user_wrong_331>", "<exch_user_wrong_230>", "<exch_user_wrong_332>",
                                      "<exch_user_refused>", "<exch_user_wrong_refused>",
                                      "<exch_size>", "<exch_cwd>", "<exch_cwd_recalled>", "<exch_cdup>", "<exch_xcwd>", "<exch_xcup>", "<exch_smnt>",
                                      "<exch_dele>", "<exch_rnto_after_rnfr>", "<exch_rnto>", "<exch_rein_ok>"]):
        if _name(earlier) == "<exch_size>":
            known = known or (_argument(earlier, "<arg_file>") == path and _reply_code(earlier) == "213")
        else:
            known = False
    return known

def _mlsd_is_implemented(exchange):
    """RFC 3659 7.8: the session showed MLSx support: a FEAT line MLST or a 250 MLST reply."""
    return bool(_before(exchange, ["<reply_250_mlst>"])) or any("MLST" in _feat_labels(feat) for feat in _before(exchange, ["<exch_feat>"]))

def mlsd_of_file_gets_501(exchange):
    path = _argument(exchange, "<arg_path>")
    if path is None or not _known_file(exchange, path) or not _mlsd_is_implemented(exchange) or not _login_state(exchange)[0]:
        return True
    return _reply_code(exchange) in ("501", "421")

where forall <x> in <exch_mlsd>: mlsd_of_file_gets_501(<x>)

def mlsd_of_file_is_not_left_unanswered(exchange):
    if not any(_name(d) == "<transfer_expired>" for d in exchange.descendants()):
        return True                                                        # the server answered
    path = _argument(exchange, "<arg_path>")
    return path is None or not (_known_file(exchange, path) and _mlsd_is_implemented(exchange) and _login_state(exchange)[0])

def mlsd_answered_501_for_a_file(exchange):
    if any(_name(d) == "<transfer_expired>" for d in exchange.descendants()):
        return True                                                        # silence: see mlsd_of_file_is_not_left_unanswered
    return mlsd_of_file_gets_501(exchange)

where forall <x> in <exch_mlsd_dr>: mlsd_answered_501_for_a_file(<x>)
where forall <x> in <exch_mlsd_dr>: mlsd_of_file_is_not_left_unanswered(<x>)

# RFC 7151 3.1: a HOST command with an IP literal that does not match the server's address is answered with 504,
# where the session showed that the server implements HOST (a FEAT line HOST, or an earlier reply 220 or 504 to HOST)
def _implements_host(exchange):
    for feat in _before(exchange, ["<exch_feat>"]):
        if "HOST" in _feat_labels(feat):
            return True
    for host in _before(exchange, ["<exch_host>"]):
        if _reply_code(host) in ("220", "504"):
            return True
    return False



# RFC 2228 5.2: a protected reply (631, 632, 633) may only be sent after a successful security data exchange
def security_exchange_succeeded_before(reply):
    return bool(_before(reply, ["<exch_auth_234>", "<exch_auth_other_234>", "<exch_adat_235>"]))

where forall <r> in <reply_631>: security_exchange_succeeded_before(<r>)
where forall <r> in <reply_632>: security_exchange_succeeded_before(<r>)
where forall <r> in <reply_633>: security_exchange_succeeded_before(<r>)

# RFC 4217 6: a server that advertises AUTH TLS MUST advertise PBSZ and PROT as well
def feat_with_auth_tls_lists_pbsz_and_prot(feat):
    advertises_tls = any(line.upper().startswith(" AUTH") and "TLS" in line.upper() for line in str(feat).split("\r\n")[1:])
    return not advertises_tls or {"PBSZ", "PROT"} <= _feat_labels(feat)

where forall <f> in <reply_211_feat>: feat_with_auth_tls_lists_pbsz_and_prot(<f>)


# RFC 2389 4 / RFC 3659 7.9: 'An "opts-good" response (200 reply) MUST be sent when the command-name and any command-options are recognized and
# appropriate': OPTS MLST is recognized where the session showed MLST support (a FEAT line MLST); a logged-in server then answers 200.
def opts_mlst_gets_200_where_mlst_is_supported(exchange):
    if not _login_state(exchange)[0] or not _mlsd_is_implemented(exchange):
        return True
    return _reply_code(exchange) in ("200", "451") or _exempt(_reply_code(exchange))      # 451: RFC 2389 4, a temporary server condition

where forall <x> in <exch_opts_mlst>: opts_mlst_gets_200_where_mlst_is_supported(<x>)

# RFC 2640 4.2: 'lang-ok MUST be sent if Server-FTP supports the Lang command and can support some form of the lang-tag': where an earlier FEAT
# listed LANG with tags, a LANG without a tag, or with a listed primary tag, is answered 200.
def lang_gets_200_where_lang_is_listed(exchange):
    tags = None
    for feat in _before(exchange, ["<exch_feat>"]):
        tags = None
        for line in str(feat).split("\r\n")[1:]:
            if line.upper().startswith(" LANG "):
                tags = {t.rstrip("*").lower() for t in line[6:].split(";")}
    if tags is None:
        return True
    requested = _argument(exchange, "<lang_tag>")
    if not _login_state(exchange)[0]:
        return True                                                        # before login the server may answer 530
    if requested is not None and requested.lower() not in tags:
        return True                                                        # only a tag the FEAT line lists is one the server can support
    return _reply_code(exchange) == "200" or _exempt(_reply_code(exchange))

where forall <x> in <exch_lang>: lang_gets_200_where_lang_is_listed(<x>)



# RFC 959 5.1: the minimum implementation (TYPE ASCII Non-print, MODE Stream, STRU File, NOOP) MUST be implemented by every server: after login
# such a command is not answered 500, 502 or 504.
def minimum_implementation_answered(exchange):
    if not _login_state(exchange)[0]:
        return True
    return _reply_code(exchange) not in ("500", "502", "504")

def type_ascii_nonprint_answered(exchange):
    if _argument(exchange, "<type_a>") is None or _argument(exchange, "<form_t>") is not None or _argument(exchange, "<form_c>") is not None:
        return True
    return minimum_implementation_answered(exchange)

def mode_stream_answered(exchange):
    return _argument(exchange, "<mode_s>") is None or minimum_implementation_answered(exchange)

def stru_file_answered(exchange):
    return _argument(exchange, "<structure_f>") is None or minimum_implementation_answered(exchange)

where forall <x> in <exch_type>: type_ascii_nonprint_answered(<x>)
where forall <x> in <exch_mode>: mode_stream_answered(<x>)
where forall <x> in <exch_stru>: stru_file_answered(<x>)
where forall <x> in <exch_noop>: minimum_implementation_answered(<x>)
# RFC 959 5.1: QUIT is part of the minimum implementation: a QUIT that is correctly formed is not answered 500 / 502 / 504 ('not understood', 'not implemented') once the session shows a login
where forall <x> in <exch_quit_refused>: minimum_implementation_answered(<x>)

# RFC 2228 3: 'the server must use a reply code which is documented as returnable from the command received'. The requirement binds a server that implements the security
# extension; a server that does not may answer the commands as any server answers a command it does not implement (RFC 1123 4.1.2.11: any other 4yz / 5yz code). The generic
# reply (`<reply_error_X>`) of a security command is therefore accepted only while the session has not shown the extension implemented (an earlier AUTH answered 234/334,
# a FEAT reply that lists AUTH, PBSZ or PROT, ADAT 235/335, AUTH refused with 504/534/431/501/533, or PBSZ / PROT / CCC / ADAT / MIC / CONF / ENC answered with any reply that shows the command implemented: not 500, 502, 530, 421, 63z).
# Final decision of the findings review (turn 8): the requirement binds a server that implements THE COMMAND ANSWERED ('Although no security commands are required to be
# implemented'): a reply to PBSZ shows PBSZ implemented, nothing about ADAT or CONF. The trigger is therefore per command: an earlier reply of that command that only a
# server with it gives, a FEAT reply that lists it (AUTH, PBSZ, PROT: RFC 4217 6), and the replies that name it (AUTH 334 asks for ADAT; AUTH 234 starts the PBSZ / PROT dialogue of RFC 4217).
_SECURITY_OWN = {
    "AUTH": ["<exch_auth_refused>", "<exch_auth_tls_refused>"],
    "ADAT": ["<exch_adat_refused>", "<exch_adat_unexpected>"],
    "PBSZ": ["<exch_pbsz>"], "PROT": ["<exch_prot>"], "CCC": ["<exch_ccc>"],
    "MIC": ["<exch_mic>"], "CONF": ["<exch_conf>"], "ENC": ["<exch_enc>"],
}

def _command_implemented_shown(node, command):
    if command == "AUTH":
        if _before(node, ["<exch_auth_234>", "<exch_auth_other_234>", "<exch_auth_334>", "<exch_auth_tls_334>"]):
            return True
        if any(_reply_code(x) in ("504", "534", "431", "501", "533") for x in _before(node, _SECURITY_OWN["AUTH"])):
            return True                                                    # RFC 2228 8.2: refusals only a server that implements AUTH gives
    elif command == "ADAT":
        if _before(node, ["<exch_adat_235>", "<exch_adat_335>", "<exch_auth_334>", "<exch_auth_tls_334>"]):
            return True                                                    # a security data exchange has run; AUTH 334 asks for the ADAT
        if any(_shows_implemented(x) for x in _before(node, _SECURITY_OWN["ADAT"])):
            return True
    else:
        if command in ("PBSZ", "PROT") and _before(node, ["<exch_auth_234>"]):
            return True                                                    # RFC 4217 3: after AUTH TLS the PBSZ / PROT dialogue follows
        if any(_shows_implemented(x) for x in _before(node, _SECURITY_OWN[command])):
            return True
    if command in ("AUTH", "PBSZ", "PROT") and any(command in _feat_labels(feat) for feat in _before(node, ["<reply_211_feat>"])):
        return True                                                        # RFC 4217 6: a server lists AUTH, PBSZ, PROT in FEAT only if it supports them
    return False

def security_reply_documented_where_implemented(exchange, command):
    if not any(_name(d).startswith("<reply_error_") for d in exchange.descendants()):
        return True
    return not _command_implemented_shown(exchange, command)

# RFC 2228 8.2 documents 530 ('Not logged in', RFC 959 4.2.1) for PBSZ and PROT only; for AUTH, ADAT, CCC, MIC, CONF and ENC it is a code of the same kind as any other
# undocumented one: it binds (RFC 2228 3) only where the session shows THAT command implemented (above), so a 530 is accepted until then and rejected afterwards.
def security_530_undocumented_where_implemented(exchange, command):
    return _reply_code(exchange) != "530" or not _command_implemented_shown(exchange, command)

where forall <x> in <exch_auth_refused>: security_reply_documented_where_implemented(<x>, "AUTH")
where forall <x> in <exch_auth_tls_refused>: security_reply_documented_where_implemented(<x>, "AUTH")
where forall <x> in <exch_adat_refused>: security_reply_documented_where_implemented(<x>, "ADAT")
where forall <x> in <exch_adat_unexpected>: security_reply_documented_where_implemented(<x>, "ADAT")
where forall <x> in <exch_pbsz>: security_reply_documented_where_implemented(<x>, "PBSZ")
where forall <x> in <exch_prot>: security_reply_documented_where_implemented(<x>, "PROT")
where forall <x> in <exch_ccc>: security_reply_documented_where_implemented(<x>, "CCC")
where forall <x> in <exch_mic>: security_reply_documented_where_implemented(<x>, "MIC")
where forall <x> in <exch_conf>: security_reply_documented_where_implemented(<x>, "CONF")
where forall <x> in <exch_enc>: security_reply_documented_where_implemented(<x>, "ENC")

where forall <x> in <exch_auth_refused>: security_530_undocumented_where_implemented(<x>, "AUTH")
where forall <x> in <exch_auth_tls_refused>: security_530_undocumented_where_implemented(<x>, "AUTH")
where forall <x> in <exch_adat_refused>: security_530_undocumented_where_implemented(<x>, "ADAT")
where forall <x> in <exch_adat_unexpected>: security_530_undocumented_where_implemented(<x>, "ADAT")
where forall <x> in <exch_ccc>: security_530_undocumented_where_implemented(<x>, "CCC")
where forall <x> in <exch_mic>: security_530_undocumented_where_implemented(<x>, "MIC")
where forall <x> in <exch_conf>: security_530_undocumented_where_implemented(<x>, "CONF")
where forall <x> in <exch_enc>: security_530_undocumented_where_implemented(<x>, "ENC")

# RFC 1123 4.1.2.9: a successful STOU names the file in the 125/150 'FILE: pppp' reply, so a 2yz completion that arrives late (after the wait) needs that reply earlier
_TRANSFER_EXCHANGES = ["<exch_%s_%s>" % (c, k) for c in ("retr", "stor", "stou", "appe", "list", "nlst", "mlsd") for k in ("dr", "after_rest")]

def stou_late_completion_names_file(reply):
    if not str(reply).startswith("2"):
        return True
    exchanges = _before(reply, _TRANSFER_EXCHANGES)
    if not exchanges or _name(exchanges[-1]) not in ("<exch_stou_dr>", "<exch_stou_after_rest>"):
        return True
    for d in exchanges[-1].descendants():
        if d is reply:
            break
        if _name(d) == "<stou_prelim_marks>" or (_name(d) == "<rep_transfer_late_pre>" and re.match(r"1(25|50)[ -] ?FILE: ?\S", str(d))):
            return True
    return False

where forall <r> in <rep_transfer_late_done>: stou_late_completion_names_file(<r>)
where forall <r> in <rep_transfer_late_failed>: stou_late_completion_names_file(<r>)
where forall <r> in <rep_transfer_late_shared>: stou_late_completion_names_file(<r>)

# A late reply of the expiry tail (`<reply_late>`, RFC 959 4.2: any code 1yz-6yz) is no way round two mandatory requirements:
# RFC 2228 5.2 / 8.2: 631, 632, 633 only after a successful security data exchange (`security_exchange_succeeded_before`);
# RFC 1123 4.1.2.9: after STAT or QUIT of a STOU (the codes 226 / 250 are not the STAT reply nor the QUIT refusal, so they are the STOU's own completion) a 226 / 250 needs the
# 125 / 150 'FILE: pppp' reply earlier. The tail of ABOR stays unchecked: RFC 959 5.4 lets 225 / 226 answer ABOR (RFC 1123 4.1.2.11).
def _late_names_file(reply):
    exchanges = _before(reply, _TRANSFER_EXCHANGES)
    if not exchanges or _name(exchanges[-1]) not in ("<exch_stou_dr>", "<exch_stou_after_rest>"):
        return True
    for d in exchanges[-1].descendants():
        if d is reply:
            break
        if _name(d) == "<stou_prelim_marks>" or (_name(d) in ("<rep_transfer_late_pre>", "<reply_late>") and re.match(r"1(25|50)[ -] ?FILE: ?\S", str(d))):
            return True
    return False

def late_reply_is_allowed(reply):
    code = str(reply)[:3]
    if code in ("631", "632", "633"):
        return security_exchange_succeeded_before(reply)
    if code in ("226", "250"):
        node = reply.parent
        while node is not None and _name(node) not in ("<exch_stat_transfer>", "<exch_quit_transfer>", "<exch_abor_transfer>"):
            node = node.parent
        if node is not None and _name(node) != "<exch_abor_transfer>":
            return _late_names_file(reply)
    return True

where forall <r> in <reply_late>: late_reply_is_allowed(<r>)

def no_unimplemented_reply(exchange):
    return _reply_code(exchange) not in ("500", "502", "504")

where forall <x> in <exch_user_refused>: no_unimplemented_reply(<x>)
def port_answered(exchange):
    """RFC 959 5.1: PORT is part of the minimum implementation (except where EPSV ALL made the server reject it, RFC 2428 3)."""
    return _login_state(exchange)[1] or minimum_implementation_answered(exchange)

where forall <x> in <exch_port>: port_answered(<x>)
where forall <x> in <exch_port_ok>: port_answered(<x>)
where forall <x> in <exch_port_refused>: port_answered(<x>)

def retr_stor_of_a_target_answered(exchange):
    """RETR of an existing file and STOR of a new name of the setup (the targets of the test setup that the session names): not answered 500, 502, 504 after login."""
    for symbol, names in (("<arg_file>", FTP_FILES), ("<arg_store>", FTP_NEW_NAMES + FTP_FILES)):
        argument = _argument(exchange, symbol)
        if argument is not None and argument in names:
            return minimum_implementation_answered(exchange)
    return True

where forall <x> in <exch_retr>: retr_stor_of_a_target_answered(<x>)
where forall <x> in <exch_retr_dr>: retr_stor_of_a_target_answered(<x>)
where forall <x> in <exch_stor>: retr_stor_of_a_target_answered(<x>)
where forall <x> in <exch_stor_dr>: retr_stor_of_a_target_answered(<x>)
where forall <x> in <exch_retr_after_rest>: retr_stor_of_a_target_answered(<x>)
where forall <x> in <exch_stor_after_rest>: retr_stor_of_a_target_answered(<x>)
# RFC 959 4.1.3 (SYST) / 4.2.1 (215): the first word of the 215 reply is an official system name from the Assigned Numbers list, today the IANA
# 'Operating System Names' registry (RFC 959 erratum 2410); the registry as fetched is refs/author/iana/os-names.txt.
OPERATING_SYSTEM_NAMES = frozenset((
    'AEGIS', 'AMIGA-OS-1.2', 'AMIGA-OS-1.3', 'AMIGA-OS-2.0', 'AMIGA-OS-2.1', 'AMIGA-OS-3.0',
    'AMIGA-OS-3.1', 'AMIGA-OS-3.5', 'AMIGA-OS-3.9', 'APOLLO', 'AIX/370', 'AIX-PS/2',
    'BEOS-4.5.2', 'BEOS-5.0', 'BS-2000', 'CEDAR', 'CGW', 'CHORUS',
    'CHRYSALIS', 'CMOS', 'CMS', 'COS', 'CPIX', 'CTOS',
    'CTSS', 'CYGWIN', 'DCN', 'DDNOS', 'DOMAIN', 'DOS',
    'ECOS', 'ECOSPRO', 'EDX', 'ELF', 'EMBOS', 'EMMOS',
    'EPOS', 'FOONEX', 'FREEBSD', 'FORTH', 'FUZZ', 'GCOS',
    'GPOS', 'HDOS', 'IMAGEN', 'INSTANT-INTERNET', 'INTERCOM', 'IMPRESS',
    'INTERLISP', 'IOS', 'IRIX', 'ISI-68020', 'ITS', 'KOSOS',
    'LINUX', 'LINUX-1.0', 'LINUX-1.2', 'LINUX-2.0', 'LINUX-2.2', 'LINUX-2.4',
    'LINUX-2.6', 'LISP', 'LISPM', 'LOCUS', 'MACOS', 'MINOS',
    'MOS', 'MPE5', 'MPE/V', 'MPE/IX', 'MSDOS', 'MULTICS',
    'MUSIC', 'MUSIC/SP', 'MVS', 'MVS/SP', 'NETBSD-1.0', 'NETBSD-1.1',
    'NETBSD-1.2', 'NETBSD-1.3', 'NETWARE-3', 'NETWARE-3.11', 'NETWARE-4.0', 'NETWARE-4.1',
    'NETWARE-5.0', 'NEXUS', 'NMS', 'NONSTOP', 'NOS-2', 'NTOS',
    'OPENBSD', 'OPENVME', 'OPENVMS', 'OS/DDP', 'OS/2', 'OS4',
    'OS86', 'OSX', 'PCDOS', 'PERQ/OS', 'PLI', 'PSDOS/MIT',
    'PSOS', 'PRIMOS', 'RISC-OS', 'RISC-OS-3.10', 'RISC-OS-3.50', 'RISC-OS-3.60',
    'RISC-OS-3.70', 'RISC-OS-4.00', 'RMX/RDOS', 'ROS', 'RSX11M', 'RTE-A',
    'SATOPS', 'SINIX', 'SCO-OPEN-DESKTOP-1.0', 'SCO-OPEN-DESKTOP-1.1', 'SCO-OPEN-DESKTOP-2.0', 'SCO-OPEN-DESKTOP-3.0',
    'SCO-OPEN-DESKTOP-LITE-3.0', 'SCO-OPEN-SERVER-3.0', 'SCO-UNIX-3.2.0', 'SCO-UNIX-3.2V2.0', 'SCO-UNIX-3.2V2.1', 'SCO-UNIX-3.2V4.0',
    'SCO-UNIX-3.2V4.1', 'SCO-UNIX-3.2V4.2', 'SCO-XENIX-386-2.3.2', 'SCO-XENIX-386-2.3.3', 'SCO-XENIX-386-2.3.4', 'SCS',
    'SIMP', 'SUN', 'SUN-OS-3.5', 'SUN-OS-4.0', 'SWIFT', 'TAC',
    'TANDEM', 'TENEX', 'THE-MAJOR-BBS', 'TOPS10', 'TOPS20', 'TOS',
    'TP3010', 'TRSDOS', 'ULTRIX', 'UNIX', 'UNIX-BSD', 'UNIX-V1AT',
    'UNIX-V', 'UNIX-V.1', 'UNIX-V.2', 'UNIX-V.3', 'UNIX-PC', 'UNKNOWN',
    'UT2D', 'V', 'VM', 'VM/370', 'VM/CMS', 'VM/SP',
    'VMS', 'VMS/EUNICE', 'VRTX', 'WAITS', 'WANG', 'WIN32',
    'WINDOWS-95', 'WINDOWS-95-OSR1', 'WINDOWS-95-OSR2', 'WINDOWS-98', 'WINDOWS-CE', 'WINDOWS-NT',
    'WINDOWS-NT-2', 'WINDOWS-NT-3', 'WINDOWS-NT-3.5', 'WINDOWS-NT-3.51', 'WINDOWS-NT-4', 'WINDOWS-NT-5',
    'WINDOWS-NT-5.1', 'WINDOWS-NT-6', 'WINDOWS-NT-6.1', 'WORLDGROUP', 'WYSE-WYXWARE', 'X11R3',
    'XDE', 'XENIX',
))

def system_name_is_registered(reply):
    """RFC 959 4.1.3: the first word of a 215 reply is an official operating system name."""
    for descendant in reply.descendants():
        if _name(descendant) == "<system_name>":
            return str(descendant).upper() in OPERATING_SYSTEM_NAMES
    return True

where forall <r> in <reply_215>: system_name_is_registered(<r>)
# ---------------------------------------------------------------------------------------------------------------
# Session: greeting (RFC 959 5.4, 6): 120 then 220, or 220, or 421
# ---------------------------------------------------------------------------------------------------------------
<start> ::= <session>
<session> ::= (
      <Server:reply_220> <state_unauth>
    | <Server:greeting_prelim> <Server:reply_220> <state_unauth>
    | <Server:reply_error_greeting_ok> <state_unauth>   # RFC 1123 4.1.2.11: a 2yz / 3yz greeting code the RFC 959 table does not list
    | <Server:reply_421> <ServerClosed:connection_closed> <session_end>
    | <greeting_refused> <session_end>
    )

# The server closing the control connection (a None message) is the message 'connection closed' of the party ServerClosed.
# The server closes after 221 and 421 (RFC 959 4.2.1) and may close after any other reply (a limit of failed logins or errors, an idle
# time): `<server_close>` accepts the close between two exchanges in every state, the transfer tails before the timer is cancelled.
<connection_closed> ::= 'connection closed'   # RFC 959 4.2.1: 221 / 421 close the control connection

class ServerClosed(FandangoParty):
    def __init__(self):
        super().__init__(connection_mode=ConnectionMode.EXTERNAL)

    def send(self, message, recipient):
        pass

    def start(self):
        pass

    def stop(self):
        pass

# ---------------------------------------------------------------------------------------------------------------
# The data connection (RFC 959 3.2, 4.1.2; RFC 2428 3). The party DataControl is a dummy party of Fandango's side: the message it
# 'sends' makes Fandango open the data connection to the port the server announced (passive mode, <data_connect>); in active mode
# Fandango listens on the ports of FTP_DATA_PORTS from the start of the session and the server connects to the one PORT / EPRT names.
# On every data connection Fandango sends FTP_DATA_PAYLOAD (the content of an upload), shuts down its sending side and reads what the
# server sends until the server closes. The format of the transferred data is a TODO below.
# ---------------------------------------------------------------------------------------------------------------
# RFC 959 3.2, 4.1.2: Fandango connects to the port of the 227 reply (RFC 2428 3: of the 229 reply); the port equals the one the last reply announced
<data_connect> ::= 'data connect ' <data_port> '\n'   # RFC 959 3.2: connect to the announced data port
<data_port> ::= r'[0-9]{1,5}'   # RFC 2428 2: string representation of the TCP port number
where forall <x> in <data_connect>: str(<x>.<data_port>) == last_passive_port(<x>)
# RFC 959 3.2: the connection is made but nothing is sent on it: an upload waits for data (the server answers 125/150 and then nothing), a download is sent into the connection
<data_idle> ::= 'data idle ' <data_port> '\n'   # RFC 959 3.2: connect to the announced data port and keep it open without sending
where forall <x> in <data_idle>: str(<x>.<data_port>) == last_passive_port(<x>)

def last_passive_port(node):
    """The port the last 227 / 229 reply before `node` announced (RFC 959 4.2.1: h1,h2,h3,h4,p1,p2; RFC 2428 3: (|||port|))."""
    found = None
    for descendant in node.get_root().descendants():
        if descendant is node:
            break
        if _name(descendant) in ("<reply_227>", "<reply_229>"):
            found = descendant
    if found is None:
        return "0"
    text = str(found)
    numbers = re.findall(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", text)
    if numbers:
        pick = numbers[0] if text.startswith("227 ") else numbers[-1]   # single line: the first digit starts the numbers (RFC 1123 4.1.2.6); the text after them may hold digits too
        return str(int(pick[4]) * 256 + int(pick[5]))
    ports = re.findall(r"\(\D\d*\D[^|)]*\D(\d+)\D\)", text)
    return ports[-1] if ports else "0"

import socket
import threading

class DataControl(FandangoParty):
    def __init__(self):
        super().__init__(connection_mode=ConnectionMode.CONNECT)
        self._sockets = []
        self._lock = threading.Lock()
        for port in FTP_DATA_PORTS:
            try:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((FTP_DATA_ADDRESS, port))
                listener.listen(4)
                self._sockets.append(listener)
                threading.Thread(target=self._accept, args=(listener,), daemon=True).start()
            except OSError:
                pass

    def start(self):
        pass

    def stop(self):
        with self._lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

    def _accept(self, listener):
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            self._serve(connection)

    def _serve(self, connection):
        with self._lock:
            self._sockets.append(connection)
        threading.Thread(target=self._exchange, args=(connection,), daemon=True).start()

    def _exchange(self, connection):
        try:
            connection.settimeout(FTP_DATA_IDLE_S)
            connection.sendall(FTP_DATA_PAYLOAD)
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            while connection.recv(65536):
                pass
        except OSError:
            pass
        try:
            connection.close()
        except OSError:
            pass

    def send(self, message, recipient):
        match = re.match(r"data (connect|idle) (\d+)", str(message))
        if match is None:
            return
        try:
            connection = socket.create_connection((FTP_DATA_ADDRESS, int(match.group(2))), timeout=FTP_DATA_CONNECT_S)
        except (OSError, ValueError):
            return
        if match.group(1) == "idle":
            with self._lock:
                self._sockets.append(connection)
            return
        self._serve(connection)

class ClientNetworkParty(NetworkParty):
    def receive(self, message, sender):
        if message is None:
            super().receive("connection closed", sender="ServerClosed")
            return
        super().receive(message, sender="Server")
# ---------------------------------------------------------------------------------------------------------------
# Omissions (TODO: spec section, nearest nonterminal, reason)
# ---------------------------------------------------------------------------------------------------------------
# TODO: RFC 959 3.1.1, 3.1.2, 3.4 (representation/structure/mode content), nearest <exch_retr_dr> / <exch_stor_dr> / <exch_list_dr>: the format of the data
#   that crosses the data connection (ASCII/EBCDIC/Image/Local type, record and page structure, stream/block/compressed mode: EOR/EOF escape codes, block
#   headers, compressed byte strings, restart markers in the data stream, page headers and page types). Fandango opens the data connection (<data_connect>, the
#   party DataControl; in active mode it listens on FTP_DATA_PORTS), sends FTP_DATA_PAYLOAD and reads what the server sends, but a data connection is another
#   connection than the session's, so what travels on it is not a message of the session: Fandango's messages are those of the control connection.
# TODO: RFC 959 3.2, 5.2 (active mode with a port that is not one Fandango listens on), nearest <req_port> / <req_eprt>: the sent PORT/EPRT name this host and a port of
#   FTP_DATA_PORTS (the server's connection is accepted) or of FTP_CLOSED_PORTS (the server's attempt is refused, 425).
# TODO: RFC 959 4.1.3 (the TCP urgent data of the Telnet SYNCH that goes with ABOR and STAT sent during a transfer), nearest <req_abor> / <req_abor_transfer>: only the bytes IAC IP IAC DM
#   (<telnet_ip_synch>) are sent; the urgent-data mark is a property of the TCP segment, which no message of the grammar carries. ABOR and STAT during a transfer in progress are modeled
#   (<transfer_in_progress>: after a transfer command answered 125/150 or not at all and the timer expired).
# TODO: RFC 959 5.2 (server-to-server transfer), nearest <req_pasv> / <req_port>: needs a third party (a second server).
# TODO: RFC 3659 7.2, 7.3 (MLSD data response), RFC 3659 7.5.1.2 (type=cdir in MLSD output), RFC 959 4.1.3 (LIST / NLST data),
#   RFC 1123 4.1.2.7 (NLST data holds only pathnames), nearest <exch_mlsd> / <exch_list> / <exch_nlst>: carried on the data connection.
# TODO: RFC 4217 4-13, RFC 2228 2, 5.2, 6, App. I-II (the TLS layer after '234', the GSSAPI / Kerberos protected command and data
#   channels, protected commands MIC/CONF/ENC and 63z replies, PBSZ/PROT/CCC inside the security association, data channel
#   encapsulation), nearest <state_secured>: a layer whose format is defined by another specification (TLS, GSSAPI, Kerberos).
# TODO: RFC 1123 4.1.2.12 (Telnet option negotiation: the server answers DONT/WONT), nearest <telnet_ip_synch>: needs the client
#   to send Telnet option negotiation, which a user-FTP MUST NOT do; the grammar never produces it.
# TODO: RFC 7151 3.1 (HOST with a port number is answered 501), nearest <hostname>: the client MUST NOT send a port number with HOST.
# TODO: RFC 959 3.2 (data connection closing), RFC 959 4.1.3 (STOU unique name returned in 125/150), nearest <rep_stou_done>: the 125/150 reply
#   comes with an established data connection; a refusal (425) carries no name.
# TODO: RFC 2640 4 (LANG: reply text in the negotiated language), nearest <reply_200>: the language of free text cannot be checked.
# TODO: RFC 7151 4 (HOST must match the TLS server_name), nearest <exch_host>: needs the TLS layer.
# TODO: RFC 959 5.1 (minimum implementation), RFC 3659 6 (TVFS path syntax rules), nearest <feat_tvfs_line>: the TVFS rules on names
#   (no '/' inside a name component, '..' handling) are not enforced, only the FEAT line.
# TODO: RFC 959 5.3.2 (<username>, <password>, <account-information>), nearest <user_wrong>: the accepting exchanges send only the configured
#   values (FTP_USER, FTP_PASS, FTP_ACCT); the wrong values come from wrong_value(), a sample of the rule (letters, digits, '._-', spaces,
#   three UTF-8 characters, CR NUL, a doubled IAC), not from every string the rule derives, because a wrong value must differ from the right one.
# TODO: RFC 2428 2 (EPRT with an address family other than 1 and 2), nearest <eprt_arg>: the format of <net-addr> for other families is protocol
#   specific and not defined in refs/spec, so only EPSV asks for another family (<net_prt_other>).
# TODO: RFC 959 5.3.2 (<pathname> targets), nearest <arg_file>: a target is one of the names of the setup (FTP_FILES, FTP_DIRS, FTP_NEW_NAMES);
#   any other name is a string of the rule <pathname> that Fandango derives, which the servers refuse.
# TODO: RFC 959 5.3.2 (<host-port>) and 4.1.2 (PORT), nearest <req_port>: the sent PORT names only FTP_DATA_ADDRESS and a port of FTP_DATA_PORTS or FTP_CLOSED_PORTS
#   (<host_port_data>); left out are other host-numbers and port-numbers (a PORT naming a third
#   party, a privileged port: the servers refuse these with 500/501/504/530 as an FTP-bounce protection, replies the spec allows) because the server would
#   connect to the third party.
# TODO: RFC 2389 4 (OPTS command-name and command-options), nearest <opts_other_known>: besides the rule <opts_other_text> (any text but OPTS MLST), the sent
#   arguments of the setup (FTP_OPTS_ARGS) are drawn so that the commands the servers implement (UTF8, NLST, MODE) are exercised.
# TODO: RFC 2640 4.2 (lang-tag), nearest <lang_tag>: the sent tags are drawn from FTP_LANGUAGE_TAGS or at random from the rule; a sub-tag longer than 8 letters is not sent
#   (the rule does not derive it either).
# TODO: RFC 2428 2 (EPRT delimiter), nearest <eprt_d1>: the sent delimiter is any character of <epsv_delim> that cannot appear in the address ('|' most often);
#   the delimiters a server must also accept but that coincide with address characters (digits, hex letters, '.', ':' ) are left out so that the argument stays unambiguous
#   for the tested servers, which refuse such an argument with 500/501.
# TODO: RFC 2228 8.1 (an ADAT, MIC, CONF or ENC argument that cannot be decoded from base 64 is answered 501), nearest <base64_bad>: the sent bad arguments contain a character
#   outside the base 64 alphabet; other undecodable arguments (a wrong padding or length of otherwise valid characters) are left out, the tested servers answer them like the others.
# TODO: RFC 2428 2, 3 (<net-prt>), nearest <net_prt_other>: EPSV is sent with the families 1 and 2 and with the numbers of FTP_OTHER_ADDRESS_FAMILIES (3 to 16), which the tested
#   servers answer with 522; the other numbers of the rule <net_prt> are left out, because the grammar draws from the setup list (the servers answer them all alike).
# TODO: RFC 959 3.2 (the default data connection: with no PORT/PASV/EPRT/EPSV the server connects to the user's default data port, the port of the control connection), nearest <rep_retr_nodata>
#   (and the other <rep_X_nodata>): the replies of the transfer commands are accepted there (<rep_X_done>, <rep_X_failed>), but no connection is made to the default data
#   port (the server's attempt to the control connection's own port is refused), so the successful transfer on the default data connection is not reached.
# TODO: RFC 4217 17 (TLS-PARM; the synonym the server SHOULD accept: TLS-C; TLS-P, SSL), nearest <mechanism_tls_name>: left out because the same section says 'the client MUST use TLS' (a request for TLS under another
#   name breaks that obligation, which the grammar never produces). The case forms of TLS ('TLS', 'tls', mixed case: RFC 2228 3, RFC 4217 17 'these parameters are case-insensitive') and of the other mechanisms
#   (<mechanism_other_name>, drawn from FTP_AUTH_MECHANISMS) are sent; the parser reads every case form of TLS as the TLS request, so the other-mechanism rule excludes them.
