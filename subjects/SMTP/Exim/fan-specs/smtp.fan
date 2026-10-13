# smtp.fan -- Simple Mail Transfer Protocol (RFC 5321, with errata) as a Fandango
# I/O grammar, with the data formats and service extensions it carries:
#   RFC 5322 (Internet Message Format)          -- the mail data after DATA / BDAT
#   RFC 6532 (internationalized headers)         -- mail data under SMTPUTF8
#   RFC 1870 SIZE, RFC 6152 8BITMIME, RFC 2920 PIPELINING, RFC 3030 CHUNKING/BINARYMIME,
#   RFC 3207 STARTTLS, RFC 4954 AUTH (+ RFC 4616 PLAIN, RFC 4648 base64),
#   RFC 3461 DSN (xtext), RFC 2034/3463 ENHANCEDSTATUSCODES, RFC 1985 ETRN,
#   RFC 6531 SMTPUTF8.
# The parties Client (Fandango) and Server are defined by the driver.
# TODO: RFC 2920 3 -- PIPELINING batches are not sent; every command waits for its reply (nearest: <state_ready>)
# TODO: RFC 2852 DELIVERBY, RFC 6710 MT-PRIORITY, RFC 8689 REQUIRETLS, RFC 4865 FUTURERELEASE, RFC 4141 CONPERM/CONNEG, RFC 3885 MTRK, RFC 4468 BURL, RFC 7293 RRVS -- not modelled beyond the generic esmtp-param / ehlo-line (nearest: <param_other>, <ext_other>)
# TODO: RFC 2195 CRAM-MD5 -- the response computed from the 334 challenge (recording/recalling pair) is not modelled (nearest: <auth_challenge>)
# TODO: RFC 5321 4.5.3.2 -- timeouts are not modelled (nearest: <state_ready>)
# TODO: RFC 5321 4.5.3.1 -- the size limits (local-part 64, domain 255, path 256, command line 512; "SHOULD be avoided") are not enforced on sent paths (nearest: <path>)
# TODO: RFC 3464 -- delivery status notifications travel as ordinary messages; their multipart/report body is not modelled (nearest: <body_part>)
# Every rule carries the section it implements; omissions are marked "# TODO:".

import os
import re
import base64

<start> ::= <state_connect>  # RFC 5321 3.1

# ---- Session initiation (RFC 5321 3.1, 4.3.2 CONNECTION ESTABLISHMENT: S 220, E 554) ----
<state_connect> ::= <Server:greeting> <state_init> \
    | <Server:greeting_refused> <state_rejected> \
    | <Server:greeting_closing> <state_closed>
# RFC 5321 4.2: Greeting
<greeting> ::= '220 ' <server_id> <greeting_tail>? '\r\n' \
    | '220-' <server_id> <greeting_tail>? '\r\n' <greeting_cont>* '220' <reply_tail>? '\r\n'
<greeting_cont> ::= '220-' <line_text>? '\r\n'  # RFC 5321 4.2 *( "220-" [ textstring ] CRLF )
<greeting_tail> ::= ' ' <textstring>  # RFC 5321 4.2 [ SP textstring ]
<server_id> ::= <domain> | <address_literal>  # RFC 5321 4.2 (Domain / address-literal)
<greeting_refused> ::= <r554>  # RFC 5321 3.1: 554 instead of 220, then wait for QUIT
<greeting_closing> ::= <r421>  # RFC 5321 3.8: 421 at connection time
# RFC 5321 3.1: after a 554 greeting the server waits for QUIT and SHOULD answer 503 otherwise.
<state_rejected> ::= <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_rejected> \
    | <ex_rejected_cmd> <state_rejected> \
    | <ex_quit_closing> <state_closed>
<ex_rejected_cmd> ::= <Client:cmd_noop> <Server:rejected_reply>  # RFC 5321 3.1
<rejected_reply> ::= <r503> | <r554>  # RFC 5321 3.1 "SHOULD respond to any commands ... 503"
<state_closed> ::= ''  # RFC 5321 3.8: channel closed after 221 / 421
<state_tls> ::= ''  # TODO: RFC 3207 4.2 -- TLS handshake after 220 is not modelled (nearest: <ex_starttls_ok>)
<state_turned> ::= ''  # TODO: RFC 5321 F.1 -- role reversal after TURN is not modelled (nearest: <ex_turn_ok>)

# ---- Replies (RFC 5321 4.2) --------------------------------------------------------------
# textstring = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII  (RFC 5321 4.2)
# (a text that starts like a status code is parsed as <status_code>, see <line_text>)
<textstring> ::= r'(?![245]\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9]))[\t\x20-\x7e]+'
# RFC 6531 3.7.4.1: UTF-8 in 251/551 mailboxes
<textstring_utf8> ::= r'(?![245]\.[0-9]{1,3}\.[0-9]{1,3}(?![0-9]))[\t\x20-\x7e\x80-\ud7ff\ue000-\U0010ffff]+'
<reply_tail> ::= ' ' <line_text>  # RFC 5321 4.2 [ SP textstring ]
<reply_tail_utf8> ::= ' ' <line_text_utf8>  # RFC 6531 3.7.4
# RFC 2034 4 / RFC 3463 2: status-code prefix of the text; required once announced (constraint below)
<line_text> ::= <status_code> <status_text>? | <textstring>
<line_text_utf8> ::= <status_code> <status_text_utf8>? | <textstring_utf8>
<status_text> ::= ' ' <textstring>  # RFC 2034 4
<status_text_utf8> ::= ' ' <textstring_utf8>  # RFC 6531 3.7.4
# RFC 3463 2: status-code = class "." subject "." detail
<status_code> ::= <status_class> '.' <status_subject> '.' <status_detail>
<status_class> ::= <class_success> | <class_persistent> | <class_permanent>  # RFC 3463 3.1
<class_success> ::= '2'  # RFC 3463 3.1 2.XXX.XXX Success
<class_persistent> ::= '4'  # RFC 3463 3.1 4.XXX.XXX Persistent Transient Failure
<class_permanent> ::= '5'  # RFC 3463 3.1 5.XXX.XXX Permanent Failure
# RFC 3463 3.2 subject = 1*3digit; enumerated values X.0 .. X.7, others undefined but syntactic
<status_subject> ::= <subject_other> | <subject_addressing> | <subject_mailbox> | <subject_mail_system> \
    | <subject_network> | <subject_protocol> | <subject_content> | <subject_security> | <subject_unlisted>
<subject_other> ::= '0'  # RFC 3463 3.2 X.0.XXX Other or Undefined Status
<subject_addressing> ::= '1'  # RFC 3463 3.2 X.1.XXX Addressing Status
<subject_mailbox> ::= '2'  # RFC 3463 3.2 X.2.XXX Mailbox Status
<subject_mail_system> ::= '3'  # RFC 3463 3.2 X.3.XXX Mail System Status
<subject_network> ::= '4'  # RFC 3463 3.2 X.4.XXX Network and Routing Status
<subject_protocol> ::= '5'  # RFC 3463 3.2 X.5.XXX Mail Delivery Protocol Status
<subject_content> ::= '6'  # RFC 3463 3.2 X.6.XXX Message Content or Media Status
<subject_security> ::= '7'  # RFC 3463 3.2 X.7.XXX Security or Policy Status
<subject_unlisted> ::= r'[89]|[1-9][0-9]{1,2}'  # RFC 3463 2 subject = 1*3digit (unregistered)
<status_detail> ::= r'0|[1-9][0-9]{0,2}'  # RFC 3463 2 detail = 1*3digit
# TODO: RFC 3463 3.3-3.9 -- individual detail codes (X.1.1 .. X.7.7) are not one nonterminal each (nearest: <status_detail>)

# RFC 5321 4.1.1.1 ehlo-ok-rsp
<ehlo_ok> ::= '250 ' <server_id> <ehlo_greet_part>? '\r\n' \
    | '250-' <server_id> <ehlo_greet_part>? '\r\n' <ehlo_cont>* '250 ' <ehlo_line> '\r\n'
<ehlo_greet_part> ::= ' ' <ehlo_greet>  # RFC 5321 4.1.1.1 [ SP ehlo-greet ]
<ehlo_greet> ::= r'[\x00-\x09\x0b\x0c\x0e-\x7f]+'  # RFC 5321 4.1.1.1 1*(%d0-9 / %d11-12 / %d14-127)
<ehlo_cont> ::= '250-' <ehlo_line> '\r\n'  # RFC 5321 4.1.1.1 *( "250-" ehlo-line CRLF )
# RFC 5321 4.1.1.1 ehlo-line = ehlo-keyword *( SP ehlo-param ); one nonterminal per keyword,
# the unknown-keyword fallback last.
<ehlo_line> ::= <ext_size> | <ext_8bitmime> | <ext_pipelining> | <ext_dsn> | <ext_etrn> \
    | <ext_enhancedstatuscodes> | <ext_auth> | <ext_starttls> | <ext_chunking> | <ext_binarymime> \
    | <ext_smtputf8> | <ext_other>
<ext_size> ::= <kw_size> <ext_size_param>?  # RFC 1870 4 size-ehlo-param
<ext_size_param> ::= ' ' <size_limit>?  # RFC 1870 4 [SP size-param]
<size_limit> ::= r'[0-9]+'  # RFC 1870 4 size-param ::= [1*DIGIT]
<ext_8bitmime> ::= <kw_8bitmime>  # RFC 6152 2
<ext_pipelining> ::= <kw_pipelining>  # RFC 2920 3
<ext_dsn> ::= <kw_dsn>  # RFC 3461 4
<ext_etrn> ::= <kw_etrn>  # RFC 1985 3
<ext_enhancedstatuscodes> ::= <kw_enhancedstatuscodes>  # RFC 2034 3
<ext_auth> ::= <kw_auth> <ext_auth_mech>+  # RFC 4954 3: AUTH 1*(SP sasl-mech)
<ext_auth_mech> ::= ' ' <sasl_mech>
<ext_starttls> ::= <kw_starttls>  # RFC 3207 4
<ext_chunking> ::= <kw_chunking>  # RFC 3030 2
<ext_binarymime> ::= <kw_binarymime>  # RFC 3030 3
<ext_smtputf8> ::= <kw_smtputf8>  # RFC 6531 3.1
<ext_other> ::= <ehlo_keyword> <ehlo_param_part>*  # RFC 5321 4.1.1.1 generic ehlo-line
<ehlo_param_part> ::= ' ' <ehlo_param>
<ehlo_keyword> ::= r'[A-Za-z0-9][A-Za-z0-9-]*'  # RFC 5321 4.1.1.1 (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
<ehlo_param> ::= r'[\x21-\x7e]+'  # RFC 5321 4.1.1.1 1*(%d33-126)
# EHLO keywords are case-insensitive (RFC 5321 2.4)
<kw_size> ::= r'[Ss][Ii][Zz][Ee]'
<kw_8bitmime> ::= r'8[Bb][Ii][Tt][Mm][Ii][Mm][Ee]'
<kw_pipelining> ::= r'[Pp][Ii][Pp][Ee][Ll][Ii][Nn][Ii][Nn][Gg]'
<kw_dsn> ::= r'[Dd][Ss][Nn]'
<kw_etrn> ::= r'[Ee][Tt][Rr][Nn]'
<kw_enhancedstatuscodes> ::= r'[Ee][Nn][Hh][Aa][Nn][Cc][Ee][Dd][Ss][Tt][Aa][Tt][Uu][Ss][Cc][Oo][Dd][Ee][Ss]'
<kw_auth> ::= r'[Aa][Uu][Tt][Hh]'
<kw_starttls> ::= r'[Ss][Tt][Aa][Rr][Tt][Tt][Ll][Ss]'
<kw_chunking> ::= r'[Cc][Hh][Uu][Nn][Kk][Ii][Nn][Gg]'
<kw_binarymime> ::= r'[Bb][Ii][Nn][Aa][Rr][Yy][Mm][Ii][Mm][Ee]'
<kw_smtputf8> ::= r'[Ss][Mm][Tt][Pp][Uu][Tt][Ff]8'

# RFC 4954 4: continue-req = "334" SP [base64] CRLF
<auth_challenge> ::= <Server:r334> <Client:auth_response>
<r334> ::= '334 ' <base64>? '\r\n'
# RFC 4954 4: the client answers with base64 or cancels with "*"
<auth_response> ::= <base64>? '\r\n' | <auth_cancel> '\r\n'
<auth_cancel> ::= '*'  # RFC 4954 4 cancel-response
# TODO: RFC 4954 4 -- mechanism-specific payloads of continuation responses are generic base64 (nearest: <auth_response>)

# ---- Commands (RFC 5321 4.1.1, 4.1.2) ----------------------------------------------------
# Verbs are case-insensitive (RFC 5321 2.4); one nonterminal per command.
<cmd_ehlo> ::= <verb_ehlo> ' ' <client_id> '\r\n'  # RFC 5321 4.1.1.1 ehlo
<client_id> ::= <domain> | <address_literal>  # ASCII only (RFC 6531 3.7.1, constraint below)
<cmd_helo> ::= <verb_helo> ' ' <domain> '\r\n'  # RFC 5321 4.1.1.1 helo
# RFC 5321 4.1.1.2 mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
<cmd_mail> ::= <verb_mail> ' ' <kw_from> ':' <reverse_path> <mail_parameters>* '\r\n' \
    | <verb_mail> ' ' <kw_from> ':' <path_utf8> <mail_parameters>* ' ' <param_smtputf8> <mail_parameters>* '\r\n'
# RFC 6531 3.4: a UTF-8 reverse-path is sent only together with the SMTPUTF8 parameter
# RFC 5321 4.1.1.3 rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
<cmd_rcpt> ::= <verb_rcpt> ' ' <kw_to> ':' <rcpt_target> <rcpt_parameters>* '\r\n'
<rcpt_target> ::= <postmaster_domain> | <postmaster> | <forward_path> | <target_path> | <path_utf8>
<postmaster_domain> ::= '<' <kw_postmaster> '@' <domain> '>'  # RFC 5321 4.1.1.3
<postmaster> ::= '<' <kw_postmaster> '>'  # RFC 5321 4.1.1.3
<cmd_data> ::= <verb_data> '\r\n'  # RFC 5321 4.1.1.4
<cmd_rset> ::= <verb_rset> '\r\n'  # RFC 5321 4.1.1.5
<cmd_vrfy> ::= <verb_vrfy> ' ' <string> <vrfy_utf8>? '\r\n' | <verb_vrfy> ' ' <atom_utf8> <vrfy_utf8> '\r\n'  # RFC 5321 4.1.1.6; RFC 6531 3.7.4.2
<cmd_expn> ::= <verb_expn> ' ' <string> <vrfy_utf8>? '\r\n' | <verb_expn> ' ' <atom_utf8> <vrfy_utf8> '\r\n'  # RFC 5321 4.1.1.7; RFC 6531 3.7.4.2
<vrfy_utf8> ::= ' ' <kw_smtputf8>  # RFC 6531 3.7.4.2 [ SP "SMTPUTF8" ]
<cmd_help> ::= <verb_help> <help_arg>? '\r\n'  # RFC 5321 4.1.1.8 "HELP" [ SP String ] CRLF
<help_arg> ::= ' ' <string>
<cmd_noop> ::= <verb_noop> <help_arg>? '\r\n'  # RFC 5321 4.1.1.9 "NOOP" [ SP String ] CRLF
<cmd_quit> ::= <verb_quit> '\r\n'  # RFC 5321 4.1.1.10
<cmd_starttls> ::= <verb_starttls> '\r\n'  # RFC 3207 4
# RFC 4954 4: "AUTH" SP sasl-mech [SP initial-response]
<cmd_auth> ::= <verb_auth> ' ' <sasl_mech> <initial_response>? '\r\n' \
    | <verb_auth> ' ' <mech_plain> ' ' <plain_target_response> '\r\n'
# Target resource: RFC 4616 2 message = [authzid] UTF8NUL authcid UTF8NUL passwd, base64-encoded
<plain_target_response> ::= <base64> := base64.b64encode(('\0' + os.environ.get('SMTP_AUTH_USER', 'testuser') + '\0' + os.environ.get('SMTP_AUTH_PASS', 'testpass')).encode()).decode()
<initial_response> ::= ' ' <initial_response_value>
<initial_response_value> ::= <base64> | <empty_response>  # RFC 4954 4 initial-response = base64 / "="
<empty_response> ::= '='
<cmd_etrn> ::= <verb_etrn> ' ' <etrn_node> '\r\n'  # RFC 1985 5
<etrn_node> ::= <domain> | <etrn_hash_node> | <etrn_at_node>  # RFC 1985 5: domain, "#" queue name, "@" subdomains
<etrn_hash_node> ::= '#' <atom>
<etrn_at_node> ::= '@' <domain>
# RFC 3030 2: bdat-cmd = "BDAT" SP chunk-size [ SP end-marker ] CRLF, then chunk-size octets
<cmd_bdat> ::= <verb_bdat> ' ' <chunk_size> '\r\n' <chunk_octet>{int(<chunk_size>)}
<cmd_bdat_last> ::= <verb_bdat> ' ' <chunk_size> ' ' <kw_last> '\r\n' <chunk_octet>{int(<chunk_size>)}
<chunk_size> ::= r'0|[1-9][0-9]{0,2}'  # RFC 3030 2 chunk-size = 1*DIGIT (bounded for testing)
<chunk_octet> ::= r"[\x00-\x7f]"  # RFC 3030 2 chunk octets (7-bit subset, see TODO)
# TODO: RFC 3030 3 -- 8-bit and binary octets in chunks are not generated (nearest: <chunk_octet>)
# TODO: RFC 3030 2 -- the chunks of one transaction are not joined into one RFC 5322 message (nearest: <cmd_bdat>)
# RFC 5321 4.1.5: private-use commands start with "X"
<cmd_private> ::= <verb_private> <help_arg>? '\r\n'
<verb_private> ::= r'[Xx][A-Za-z0-9]{1,8}'
# RFC 5321 F.3: SEND / SOML / SAML FROM:<reverse-path>; F.1 TURN
<cmd_send> ::= <verb_send> ' ' <kw_from> ':' <reverse_path> '\r\n'
<cmd_soml> ::= <verb_soml> ' ' <kw_from> ':' <reverse_path> '\r\n'
<cmd_saml> ::= <verb_saml> ' ' <kw_from> ':' <reverse_path> '\r\n'
<cmd_turn> ::= <verb_turn> '\r\n'
# RFC 5321 4.1.2 String = Atom / Quoted-string
<string> ::= <atom> | <quoted_string>

<verb_ehlo> ::= r'[Ee][Hh][Ll][Oo]'
<verb_helo> ::= r'[Hh][Ee][Ll][Oo]'
<verb_mail> ::= r'[Mm][Aa][Ii][Ll]'
<verb_rcpt> ::= r'[Rr][Cc][Pp][Tt]'
<verb_data> ::= r'[Dd][Aa][Tt][Aa]'
<verb_rset> ::= r'[Rr][Ss][Ee][Tt]'
<verb_vrfy> ::= r'[Vv][Rr][Ff][Yy]'
<verb_expn> ::= r'[Ee][Xx][Pp][Nn]'
<verb_help> ::= r'[Hh][Ee][Ll][Pp]'
<verb_noop> ::= r'[Nn][Oo][Oo][Pp]'
<verb_quit> ::= r'[Qq][Uu][Ii][Tt]'
<verb_starttls> ::= r'[Ss][Tt][Aa][Rr][Tt][Tt][Ll][Ss]'
<verb_auth> ::= r'[Aa][Uu][Tt][Hh]'
<verb_etrn> ::= r'[Ee][Tt][Rr][Nn]'
<verb_bdat> ::= r'[Bb][Dd][Aa][Tt]'
<verb_send> ::= r'[Ss][Ee][Nn][Dd]'
<verb_soml> ::= r'[Ss][Oo][Mm][Ll]'
<verb_saml> ::= r'[Ss][Aa][Mm][Ll]'
<verb_turn> ::= r'[Tt][Uu][Rr][Nn]'
<kw_from> ::= r'[Ff][Rr][Oo][Mm]'
<kw_to> ::= r'[Tt][Oo]'
<kw_last> ::= r'[Ll][Aa][Ss][Tt]'
<kw_postmaster> ::= r'[Pp][Oo][Ss][Tt][Mm][Aa][Ss][Tt][Ee][Rr]'

# ---- SASL (RFC 4954 4, RFC 4422 3.1, RFC 4616) ---------------------------------------------
# sasl-mech = 1*20(UPPER-ALPHA / DIGIT / HYPHEN / UNDERSCORE); one nonterminal per mechanism
<sasl_mech> ::= <mech_plain> | <mech_login> | <mech_cram_md5> | <mech_other>
<mech_plain> ::= 'PLAIN'  # RFC 4616
<mech_login> ::= 'LOGIN'  # draft-murchison-sasl-login (registered, LIMITED)
<mech_cram_md5> ::= 'CRAM-MD5'  # RFC 2195 (registered, LIMITED)
<mech_other> ::= r'[A-Z0-9_-]{1,20}'  # RFC 4422 3.1
# RFC 4648 4: base64 alphabet with padding
<base64> ::= r'([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
# TODO: RFC 4616 2 -- the PLAIN message (authzid NUL authcid NUL passwd) is not decoded from <base64> (nearest: <initial_response_value>)

# ---- Paths and addresses (RFC 5321 4.1.2, 4.1.3) ------------------------------------------
<reverse_path> ::= <path> | <null_path> | <target_path>  # RFC 5321 4.1.2 Reverse-path = Path / "<>"; <target_path> is a known-good mailbox
<null_path> ::= '<>'
<forward_path> ::= <path>  # RFC 5321 4.1.2
<path> ::= '<' <adl_part>? <mailbox> '>'  # RFC 5321 4.1.2 Path = "<" [ A-d-l ":" ] Mailbox ">"
<adl_part> ::= <a_d_l> ':'
<a_d_l> ::= <at_domain> <more_at_domain>*  # RFC 5321 4.1.2 A-d-l = At-domain *( "," At-domain )
<more_at_domain> ::= ',' <at_domain>
<at_domain> ::= '@' <domain>  # RFC 5321 4.1.2
# Target resource: an existing mailbox of the server under test.
<target_path> ::= '<' <mailbox> '>' := '<' + os.environ.get('SMTP_TARGET_MAILBOX', 'postmaster@example.test') + '>'
<mailbox> ::= <local_part> '@' <mail_domain>  # RFC 5321 4.1.2 Mailbox
<mail_domain> ::= <domain> | <address_literal>
<local_part> ::= <dot_string> | <quoted_string>  # RFC 5321 4.1.2 Local-part
<dot_string> ::= <atom> <dot_atom_part>*  # RFC 5321 4.1.2 Dot-string = Atom *("."  Atom)
<dot_atom_part> ::= '.' <atom>
# RFC 6531 3.3: UTF-8 mailboxes, kept apart so that ASCII paths never need SMTPUTF8
<path_utf8> ::= '<' <adl_part>? <mailbox_utf8> '>'
<mailbox_utf8> ::= <atom_utf8> <dot_utf8_part>* '@' <domain_utf8>
<dot_utf8_part> ::= '.' <atom> | '.' <atom_utf8>
<domain_utf8> ::= <sub_domain_utf8> <dot_sub_domain_utf8>*
<dot_sub_domain_utf8> ::= '.' <sub_domain_utf8>
<sub_domain_utf8> ::= <ldh_label> | <u_label>
# RFC 6531 3.3 atext =/ UTF8-non-ascii (at least one non-ASCII character; SMTPUTF8 constraint below)
<atom_utf8> ::= r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]*[\x80-\ud7ff\ue000-\U0010ffff][A-Za-z0-9!#$%&'*+/=?^_`{|}~\x80-\ud7ff\ue000-\U0010ffff-]*"
<atom> ::= r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"  # RFC 5321 4.1.2 Atom = 1*atext (RFC 5322 3.2.3)
# RFC 5321 4.1.2 Quoted-string = DQUOTE *QcontentSMTP DQUOTE
<quoted_string> ::= '"' <qtext_smtp>? <quoted_run>* '"'
<quoted_run> ::= <quoted_pair_smtp> <qtext_smtp>?
<qtext_smtp> ::= r'[\x20\x21\x23-\x5b\x5d-\x7e]+'  # RFC 5321 4.1.2 qtextSMTP = %d32-33 / %d35-91 / %d93-126
# TODO: RFC 6531 3.3 -- qtextSMTP =/ UTF8-non-ascii (UTF-8 quoted local parts) is not generated (nearest: <mailbox_utf8>)
<quoted_pair_smtp> ::= '\\' <qpair_char>  # RFC 5321 4.1.2 quoted-pairSMTP = %d92 %d32-126
<qpair_char> ::= r'[\x20-\x7e]'
# RFC 5321 4.1.2 Domain = sub-domain *("." sub-domain); sub-domain = Let-dig [Ldh-str]
<domain> ::= <sub_domain> <dot_sub_domain>*
<dot_sub_domain> ::= '.' <sub_domain>
<sub_domain> ::= <ldh_label>
<ldh_label> ::= r'[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'  # RFC 5321 4.1.2 Let-dig [Ldh-str], at most 63 octets (2.3.5)
<u_label> ::= r'[A-Za-z0-9-]*[\x80-\ud7ff\ue000-\U0010ffff][A-Za-z0-9\x80-\ud7ff\ue000-\U0010ffff-]*'  # RFC 6531 3.3 sub-domain =/ U-label
# TODO: RFC 5890 -- IDNA2008 validity of U-labels is not checked (nearest: <u_label>)
# RFC 5321 4.1.3 address-literal = "[" ( IPv4-address-literal / IPv6-address-literal / General-address-literal ) "]"
<address_literal> ::= '[' <ipv4_literal> ']' | '[' <ipv6_literal> ']' | '[' <general_literal> ']'
<ipv4_literal> ::= <snum> '.' <snum> '.' <snum> '.' <snum>  # RFC 5321 4.1.3
<snum> ::= r'25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2}'  # RFC 5321 4.1.3 Snum = 1*3DIGIT, value 0 through 255
<ipv6_literal> ::= <kw_ipv6> ':' <ipv6_addr>  # RFC 5321 4.1.3 IPv6-address-literal = "IPv6:" IPv6-addr
<kw_ipv6> ::= r'[Ii][Pp][Vv]6'
<ipv6_addr> ::= <ipv6_full> | <ipv6_comp> | <ipv6v4_full> | <ipv6v4_comp>
<ipv6_hex> ::= r'[0-9A-Fa-f]{1,4}'  # RFC 5321 4.1.3 IPv6-hex = 1*4HEXDIG
<ipv6_group> ::= ':' <ipv6_hex>
<ipv6_full> ::= <ipv6_hex> <ipv6_group>{7}  # RFC 5321 4.1.3 IPv6-full
<ipv6_comp> ::= <ipv6_hexseq>? '::' <ipv6_hexseq>?  # RFC 5321 4.1.3 IPv6-comp (group count constraint below)
<ipv6_hexseq> ::= <ipv6_hex> <ipv6_group>{0,5}
<ipv6v4_full> ::= <ipv6_hex> <ipv6_group>{5} ':' <ipv4_literal>  # RFC 5321 4.1.3 IPv6v4-full
<ipv6v4_comp> ::= <ipv6_hexseq4>? '::' <ipv6v4_tail>? <ipv4_literal>  # RFC 5321 4.1.3 IPv6v4-comp
<ipv6_hexseq4> ::= <ipv6_hex> <ipv6_group>{0,3}
<ipv6v4_tail> ::= <ipv6_hexseq4> ':'
# RFC 5321 4.1.3 General-address-literal = Standardized-tag ":" 1*dcontent
<general_literal> ::= <standardized_tag> ':' <dcontent>
<standardized_tag> ::= r'[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'  # RFC 5321 4.1.3 Ldh-str, registered with IANA
<dcontent> ::= r'[\x21-\x5a\x5e-\x7e]+'  # RFC 5321 4.1.3 dcontent = %d33-90 / %d94-126

# ---- MAIL / RCPT parameters (RFC 5321 4.1.2 esmtp-param; extensions) -----------------------
<mail_parameters> ::= ' ' <mail_param>  # RFC 5321 4.1.2 Mail-parameters = esmtp-param *(SP esmtp-param)
<mail_param> ::= <param_size> | <param_body> | <param_ret> | <param_envid> | <param_auth> \
    | <param_smtputf8> | <param_other>
<param_size> ::= <kw_size> '=' <size_value>  # RFC 1870 6 "SIZE=" size-value
<size_value> ::= r'0|[1-9][0-9]{0,19}'  # RFC 1870 6 size-value ::= 1*20DIGIT
<param_body> ::= <kw_body> '=' <body_value>  # RFC 6152 2; RFC 3030 3
<kw_body> ::= r'[Bb][Oo][Dd][Yy]'
<body_value> ::= <body_7bit> | <body_8bitmime> | <body_binarymime>
<body_7bit> ::= r'7[Bb][Ii][Tt]'  # RFC 6152 2
<body_8bitmime> ::= <kw_8bitmime>  # RFC 6152 2
<body_binarymime> ::= <kw_binarymime>  # RFC 3030 3
<param_ret> ::= <kw_ret> '=' <ret_value>  # RFC 3461 4.3
<kw_ret> ::= r'[Rr][Ee][Tt]'
<ret_value> ::= <ret_full> | <ret_hdrs>
<ret_full> ::= r'[Ff][Uu][Ll][Ll]'  # RFC 3461 4.3
<ret_hdrs> ::= r'[Hh][Dd][Rr][Ss]'  # RFC 3461 4.3
<param_envid> ::= <kw_envid> '=' <xtext>  # RFC 3461 4.4 (length constraint below)
<kw_envid> ::= r'[Ee][Nn][Vv][Ii][Dd]'
<param_auth> ::= <kw_auth> '=' <auth_param_value>  # RFC 4954 5 "AUTH=" (mailbox / "<>") as xtext
<auth_param_value> ::= <xtext> | <null_path>
<param_smtputf8> ::= <kw_smtputf8>  # RFC 6531 3.4 (no value)
<param_other> ::= <esmtp_keyword> <esmtp_value_part>?  # RFC 5321 4.1.2 esmtp-param = esmtp-keyword ["=" esmtp-value]
<esmtp_value_part> ::= '=' <esmtp_value>
<esmtp_keyword> ::= r'[A-Za-z0-9][A-Za-z0-9-]*'  # RFC 5321 4.1.2
<esmtp_value> ::= r'[\x21-\x3c\x3e-\x7e]+'  # RFC 5321 4.1.2 1*(%d33-60 / %d62-126)
<rcpt_parameters> ::= ' ' <rcpt_param>  # RFC 5321 4.1.2 Rcpt-parameters
<rcpt_param> ::= <param_notify> | <param_orcpt> | <param_other>
<param_notify> ::= <kw_notify> '=' <notify_value>  # RFC 3461 4.1
<kw_notify> ::= r'[Nn][Oo][Tt][Ii][Ff][Yy]'
<notify_value> ::= <notify_never> | <notify_item> <notify_more>{0,2}  # RFC 3461 4.1 "NEVER" / 1#( ... )
<notify_more> ::= ',' <notify_item>
<notify_item> ::= <notify_success> | <notify_failure> | <notify_delay>
<notify_never> ::= r'[Nn][Ee][Vv][Ee][Rr]'
<notify_success> ::= r'[Ss][Uu][Cc][Cc][Ee][Ss][Ss]'
<notify_failure> ::= r'[Ff][Aa][Ii][Ll][Uu][Rr][Ee]'
<notify_delay> ::= r'[Dd][Ee][Ll][Aa][Yy]'
<param_orcpt> ::= <kw_orcpt> '=' <addr_type> ';' <xtext>  # RFC 3461 4.2
<kw_orcpt> ::= r'[Oo][Rr][Cc][Pp][Tt]'
<addr_type> ::= <atom>  # RFC 3461 4.2 addr-type = atom (e.g. "rfc822")
# RFC 3461 4 xtext = *( xchar / hexchar ); xchar = "!".."~" except "+" and "="
<xtext> ::= <xchars>? <xtext_run>*
<xtext_run> ::= <hexchar> <xchars>?
<xchars> ::= r'[\x21-\x2a\x2c-\x3c\x3e-\x7e]+'
<hexchar> ::= '+' <hexdig2>
<hexdig2> ::= r'[0-9A-F]{2}'  # RFC 3461 4: 2(%x30-39 / %x41-46)

# ---- States (RFC 5321 3.3, 4.1.4, 4.3.2; RFC 3030 2; RFC 4954 4) --------------------
# One nonterminal per state, one alternative per transition: <exchange> <next state>.
# RFC 5321 3.2 / 4.1.4: greeting received, no EHLO/HELO accepted yet
<state_init> ::= <ex_ehlo_ok> <state_ready> \
    | <ex_ehlo_fail> <state_init> \
    | <ex_helo_ok> <state_ready> \
    | <ex_helo_fail> <state_init> \
    | <ex_rset_ok> <state_init> \
    | <ex_rset_fail> <state_init> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_init> \
    | <ex_starttls_fail> <state_init> \
    | <ex_auth_fail> <state_init> \
    | <ex_mail_ok> <state_mail> \
    | <ex_mail_fail> <state_init> \
    | <ex_rcpt_refused> <state_init> \
    | <ex_data_refused> <state_init> \
    | <ex_bdat_fail> <state_failed> \
    | <ex_bdat_last_fail> <state_failed> \
    | <ex_send_ok> <state_mail> \
    | <ex_send_fail> <state_init> \
    | <ex_soml_ok> <state_mail> \
    | <ex_soml_fail> <state_init> \
    | <ex_saml_ok> <state_mail> \
    | <ex_saml_fail> <state_init> \
    | <ex_turn_ok> <state_turned> \
    | <ex_turn_fail> <state_init> \
    | <ex_noop> <state_init> \
    | <ex_vrfy> <state_init> \
    | <ex_expn> <state_init> \
    | <ex_help> <state_init> \
    | <ex_etrn> <state_init> \
    | <ex_private> <state_init> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 4.1.4 / 3.3: session opened, no mail transaction
<state_ready> ::= <ex_ehlo_ok> <state_ready> \
    | <ex_ehlo_fail> <state_ready> \
    | <ex_helo_ok> <state_ready> \
    | <ex_helo_fail> <state_ready> \
    | <ex_rset_ok> <state_ready> \
    | <ex_rset_fail> <state_ready> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_ready> \
    | <ex_starttls_ok> <state_tls> \
    | <ex_starttls_fail> <state_ready> \
    | <ex_auth_ok> <state_ready_authed> \
    | <ex_auth_fail> <state_ready> \
    | <ex_mail_ok> <state_mail> \
    | <ex_mail_fail> <state_ready> \
    | <ex_rcpt_refused> <state_ready> \
    | <ex_data_refused> <state_ready> \
    | <ex_bdat_fail> <state_failed> \
    | <ex_bdat_last_fail> <state_failed> \
    | <ex_send_ok> <state_mail> \
    | <ex_soml_ok> <state_mail> \
    | <ex_saml_ok> <state_mail> \
    | <ex_send_fail> <state_ready> \
    | <ex_soml_fail> <state_ready> \
    | <ex_saml_fail> <state_ready> \
    | <ex_turn_ok> <state_turned> \
    | <ex_turn_fail> <state_ready> \
    | <ex_noop> <state_ready> \
    | <ex_vrfy> <state_ready> \
    | <ex_expn> <state_ready> \
    | <ex_help> <state_ready> \
    | <ex_etrn> <state_ready> \
    | <ex_private> <state_ready> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 3.3: MAIL accepted, no recipient yet
<state_mail> ::= <ex_ehlo_ok> <state_ready> \
    | <ex_ehlo_fail> <state_mail> \
    | <ex_helo_ok> <state_ready> \
    | <ex_helo_fail> <state_mail> \
    | <ex_rset_ok> <state_ready> \
    | <ex_rset_fail> <state_mail> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_mail> \
    | <ex_starttls_ok> <state_tls> \
    | <ex_starttls_fail> <state_mail> \
    | <ex_auth_refused> <state_mail> \
    | <ex_mail_refused> <state_mail> \
    | <ex_rcpt_ok> <state_rcpt> \
    | <ex_rcpt_fail> <state_mail> \
    | <ex_data_refused> <state_mail> \
    | <ex_bdat_fail> <state_failed> \
    | <ex_bdat_last_fail> <state_failed> \
    | <ex_send_fail> <state_mail> \
    | <ex_soml_fail> <state_mail> \
    | <ex_saml_fail> <state_mail> \
    | <ex_noop> <state_mail> \
    | <ex_vrfy> <state_mail> \
    | <ex_expn> <state_mail> \
    | <ex_help> <state_mail> \
    | <ex_etrn> <state_mail> \
    | <ex_private> <state_mail> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 3.3: at least one recipient accepted
<state_rcpt> ::= <ex_ehlo_ok> <state_ready> \
    | <ex_ehlo_fail> <state_rcpt> \
    | <ex_helo_ok> <state_ready> \
    | <ex_helo_fail> <state_rcpt> \
    | <ex_rset_ok> <state_ready> \
    | <ex_rset_fail> <state_rcpt> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_rcpt> \
    | <ex_starttls_ok> <state_tls> \
    | <ex_starttls_fail> <state_rcpt> \
    | <ex_auth_refused> <state_rcpt> \
    | <ex_mail_refused> <state_rcpt> \
    | <ex_rcpt_ok> <state_rcpt> \
    | <ex_rcpt_fail> <state_rcpt> \
    | <ex_data_go> <state_data> \
    | <ex_data_refused> <state_rcpt> \
    | <ex_bdat_ok> <state_bdat> \
    | <ex_bdat_fail> <state_failed> \
    | <ex_bdat_last_ok> <state_ready> \
    | <ex_bdat_last_fail> <state_failed> \
    | <ex_send_fail> <state_rcpt> \
    | <ex_soml_fail> <state_rcpt> \
    | <ex_saml_fail> <state_rcpt> \
    | <ex_noop> <state_rcpt> \
    | <ex_vrfy> <state_rcpt> \
    | <ex_expn> <state_rcpt> \
    | <ex_help> <state_rcpt> \
    | <ex_etrn> <state_rcpt> \
    | <ex_private> <state_rcpt> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 4.1.1.4: 354 received, mail data follows
<state_data> ::= <ex_content_ok> <state_ready> \
    | <ex_content_fail> <state_ready> \
    | <ex_content_closing> <state_closed>
# RFC 3030 2: BDAT chunks accepted, BDAT LAST pending
<state_bdat> ::= <ex_bdat_ok> <state_bdat> \
    | <ex_bdat_fail> <state_failed> \
    | <ex_bdat_last_ok> <state_ready> \
    | <ex_bdat_last_fail> <state_failed> \
    | <ex_rset_ok> <state_ready> \
    | <ex_rset_fail> <state_bdat> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_bdat> \
    | <ex_data_refused> <state_failed> \
    | <ex_mail_refused> <state_failed> \
    | <ex_rcpt_refused> <state_failed> \
    | <ex_noop> <state_bdat> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_noop_closing> <state_closed>
# RFC 3030 2: failed BDAT, state indeterminate until RSET
<state_failed> ::= <ex_rset_ok> <state_ready> \
    | <ex_rset_fail> <state_failed> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_failed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_quit_closing> <state_closed>
# RFC 5321 4.1.4 / 3.3: session opened, no mail transaction, authenticated (RFC 4954 4)
<state_ready_authed> ::= <ex_ehlo_ok> <state_ready_authed> \
    | <ex_ehlo_fail> <state_ready_authed> \
    | <ex_helo_ok> <state_ready_authed> \
    | <ex_helo_fail> <state_ready_authed> \
    | <ex_rset_ok> <state_ready_authed> \
    | <ex_rset_fail> <state_ready_authed> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_ready_authed> \
    | <ex_starttls_ok> <state_tls> \
    | <ex_starttls_fail> <state_ready_authed> \
    | <ex_auth_refused> <state_ready_authed> \
    | <ex_mail_ok> <state_mail_authed> \
    | <ex_mail_fail> <state_ready_authed> \
    | <ex_rcpt_refused> <state_ready_authed> \
    | <ex_data_refused> <state_ready_authed> \
    | <ex_bdat_fail> <state_failed_authed> \
    | <ex_bdat_last_fail> <state_failed_authed> \
    | <ex_send_ok> <state_mail_authed> \
    | <ex_soml_ok> <state_mail_authed> \
    | <ex_saml_ok> <state_mail_authed> \
    | <ex_send_fail> <state_ready_authed> \
    | <ex_soml_fail> <state_ready_authed> \
    | <ex_saml_fail> <state_ready_authed> \
    | <ex_turn_ok> <state_turned> \
    | <ex_turn_fail> <state_ready_authed> \
    | <ex_noop> <state_ready_authed> \
    | <ex_vrfy> <state_ready_authed> \
    | <ex_expn> <state_ready_authed> \
    | <ex_help> <state_ready_authed> \
    | <ex_etrn> <state_ready_authed> \
    | <ex_private> <state_ready_authed> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 3.3: MAIL accepted, no recipient yet, authenticated
<state_mail_authed> ::= <ex_ehlo_ok> <state_ready_authed> \
    | <ex_ehlo_fail> <state_mail_authed> \
    | <ex_helo_ok> <state_ready_authed> \
    | <ex_helo_fail> <state_mail_authed> \
    | <ex_rset_ok> <state_ready_authed> \
    | <ex_rset_fail> <state_mail_authed> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_mail_authed> \
    | <ex_starttls_ok> <state_tls> \
    | <ex_starttls_fail> <state_mail_authed> \
    | <ex_auth_refused> <state_mail_authed> \
    | <ex_mail_refused> <state_mail_authed> \
    | <ex_rcpt_ok> <state_rcpt_authed> \
    | <ex_rcpt_fail> <state_mail_authed> \
    | <ex_data_refused> <state_mail_authed> \
    | <ex_bdat_fail> <state_failed_authed> \
    | <ex_bdat_last_fail> <state_failed_authed> \
    | <ex_send_fail> <state_mail_authed> \
    | <ex_soml_fail> <state_mail_authed> \
    | <ex_saml_fail> <state_mail_authed> \
    | <ex_noop> <state_mail_authed> \
    | <ex_vrfy> <state_mail_authed> \
    | <ex_expn> <state_mail_authed> \
    | <ex_help> <state_mail_authed> \
    | <ex_etrn> <state_mail_authed> \
    | <ex_private> <state_mail_authed> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 3.3: at least one recipient accepted, authenticated
<state_rcpt_authed> ::= <ex_ehlo_ok> <state_ready_authed> \
    | <ex_ehlo_fail> <state_rcpt_authed> \
    | <ex_helo_ok> <state_ready_authed> \
    | <ex_helo_fail> <state_rcpt_authed> \
    | <ex_rset_ok> <state_ready_authed> \
    | <ex_rset_fail> <state_rcpt_authed> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_rcpt_authed> \
    | <ex_starttls_ok> <state_tls> \
    | <ex_starttls_fail> <state_rcpt_authed> \
    | <ex_auth_refused> <state_rcpt_authed> \
    | <ex_mail_refused> <state_rcpt_authed> \
    | <ex_rcpt_ok> <state_rcpt_authed> \
    | <ex_rcpt_fail> <state_rcpt_authed> \
    | <ex_data_go> <state_data_authed> \
    | <ex_data_refused> <state_rcpt_authed> \
    | <ex_bdat_ok> <state_bdat_authed> \
    | <ex_bdat_fail> <state_failed_authed> \
    | <ex_bdat_last_ok> <state_ready_authed> \
    | <ex_bdat_last_fail> <state_failed_authed> \
    | <ex_send_fail> <state_rcpt_authed> \
    | <ex_soml_fail> <state_rcpt_authed> \
    | <ex_saml_fail> <state_rcpt_authed> \
    | <ex_noop> <state_rcpt_authed> \
    | <ex_vrfy> <state_rcpt_authed> \
    | <ex_expn> <state_rcpt_authed> \
    | <ex_help> <state_rcpt_authed> \
    | <ex_etrn> <state_rcpt_authed> \
    | <ex_private> <state_rcpt_authed> \
    | <ex_ehlo_closing> <state_closed> \
    | <ex_helo_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_vrfy_closing> <state_closed> \
    | <ex_expn_closing> <state_closed> \
    | <ex_help_closing> <state_closed> \
    | <ex_noop_closing> <state_closed> \
    | <ex_etrn_closing> <state_closed> \
    | <ex_private_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_starttls_closing> <state_closed> \
    | <ex_auth_closing> <state_closed> \
    | <ex_send_closing> <state_closed> \
    | <ex_soml_closing> <state_closed> \
    | <ex_saml_closing> <state_closed> \
    | <ex_turn_closing> <state_closed>
# RFC 5321 4.1.1.4: 354 received, mail data follows
<state_data_authed> ::= <ex_content_ok> <state_ready_authed> \
    | <ex_content_fail> <state_ready_authed> \
    | <ex_content_closing> <state_closed>
# RFC 3030 2: BDAT chunks accepted, BDAT LAST pending, authenticated
<state_bdat_authed> ::= <ex_bdat_ok> <state_bdat_authed> \
    | <ex_bdat_fail> <state_failed_authed> \
    | <ex_bdat_last_ok> <state_ready_authed> \
    | <ex_bdat_last_fail> <state_failed_authed> \
    | <ex_rset_ok> <state_ready_authed> \
    | <ex_rset_fail> <state_bdat_authed> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_bdat_authed> \
    | <ex_data_refused> <state_failed_authed> \
    | <ex_mail_refused> <state_failed_authed> \
    | <ex_rcpt_refused> <state_failed_authed> \
    | <ex_noop> <state_bdat_authed> \
    | <ex_bdat_closing> <state_closed> \
    | <ex_bdat_last_closing> <state_closed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_quit_closing> <state_closed> \
    | <ex_data_closing> <state_closed> \
    | <ex_mail_closing> <state_closed> \
    | <ex_rcpt_closing> <state_closed> \
    | <ex_noop_closing> <state_closed>
# RFC 3030 2: failed BDAT, state indeterminate until RSET, authenticated
<state_failed_authed> ::= <ex_rset_ok> <state_ready_authed> \
    | <ex_rset_fail> <state_failed_authed> \
    | <ex_quit> <state_closed> \
    | <ex_quit_fail> <state_failed_authed> \
    | <ex_rset_closing> <state_closed> \
    | <ex_quit_closing> <state_closed>

# ---- Exchanges: one per request and reply class (RFC 5321 4.3.2) ------------------
<ex_ehlo_ok> ::= <Client:cmd_ehlo> <Server:ehlo_ok>  # RFC 5321 4.1.1.1 ehlo-ok-rsp
<ex_ehlo_fail> ::= <Client:cmd_ehlo> <Server:ehlo_fail>  # RFC 5321 4.3.2 EHLO E / 4.1.4
<ex_ehlo_closing> ::= <Client:cmd_ehlo> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_helo_ok> ::= <Client:cmd_helo> <Server:helo_ok>  # RFC 5321 4.3.2 HELO S
<ex_helo_fail> ::= <Client:cmd_helo> <Server:helo_fail>  # RFC 5321 4.3.2 HELO E
<ex_helo_closing> ::= <Client:cmd_helo> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_mail_ok> ::= <Client:cmd_mail> <Server:mail_ok>  # RFC 5321 4.3.2 MAIL S
<ex_mail_fail> ::= <Client:cmd_mail> <Server:mail_fail>  # RFC 5321 4.3.2 MAIL E; RFC 4954 6 530
<ex_mail_refused> ::= <Client:cmd_mail> <Server:mail_refused>  # RFC 5321 4.1.4: MAIL inside a transaction gets 503
<ex_mail_closing> ::= <Client:cmd_mail> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_rcpt_ok> ::= <Client:cmd_rcpt> <Server:rcpt_ok>  # RFC 5321 4.3.2 RCPT S
<ex_rcpt_fail> ::= <Client:cmd_rcpt> <Server:rcpt_fail>  # RFC 5321 4.3.2 RCPT E; RFC 4954 6 530
<ex_rcpt_refused> ::= <Client:cmd_rcpt> <Server:rcpt_refused>  # RFC 5321 4.1.4: RCPT out of order gets 503
<ex_rcpt_closing> ::= <Client:cmd_rcpt> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_data_go> ::= <Client:cmd_data> <Server:data_go>  # RFC 5321 4.3.2 DATA I
<ex_data_refused> ::= <Client:cmd_data> <Server:data_refused>  # RFC 5321 4.3.2 DATA E; RFC 4954 6 530
<ex_data_closing> ::= <Client:cmd_data> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_content_ok> ::= <Client:mail_data> <Server:content_ok>  # RFC 5321 4.3.2 DATA -> data -> S
<ex_content_fail> ::= <Client:mail_data> <Server:content_fail>  # RFC 5321 4.3.2 DATA -> data -> E; 4.2.5
<ex_content_closing> ::= <Client:mail_data> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_bdat_ok> ::= <Client:cmd_bdat> <Server:bdat_ok>  # RFC 3030 2
<ex_bdat_fail> ::= <Client:cmd_bdat> <Server:bdat_fail>  # RFC 3030 2: "the appropriate 5XX or 4XX code" after the chunk
<ex_bdat_closing> ::= <Client:cmd_bdat> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_bdat_last_ok> ::= <Client:cmd_bdat_last> <Server:bdat_ok>  # RFC 3030 2
<ex_bdat_last_fail> ::= <Client:cmd_bdat_last> <Server:bdat_fail>  # RFC 3030 2: "the appropriate 5XX or 4XX code" after the chunk
<ex_bdat_last_closing> ::= <Client:cmd_bdat_last> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_rset_ok> ::= <Client:cmd_rset> <Server:rset_ok>  # RFC 5321 4.3.2 RSET S
<ex_rset_fail> ::= <Client:cmd_rset> <Server:rset_fail>  # RFC 5321 4.3.2 universal replies
<ex_rset_closing> ::= <Client:cmd_rset> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_vrfy> ::= <Client:cmd_vrfy> <Server:vrfy_reply>  # RFC 5321 4.3.2 VRFY
<ex_vrfy_closing> ::= <Client:cmd_vrfy> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_expn> ::= <Client:cmd_expn> <Server:expn_reply>  # RFC 5321 4.3.2 EXPN
<ex_expn_closing> ::= <Client:cmd_expn> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_help> ::= <Client:cmd_help> <Server:help_reply>  # RFC 5321 4.3.2 HELP
<ex_help_closing> ::= <Client:cmd_help> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_noop> ::= <Client:cmd_noop> <Server:noop_reply>  # RFC 5321 4.3.2 NOOP
<ex_noop_closing> ::= <Client:cmd_noop> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_etrn> ::= <Client:cmd_etrn> <Server:etrn_reply>  # RFC 1985 5; unannounced: RFC 5321 4.2.4 502
<ex_etrn_closing> ::= <Client:cmd_etrn> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_private> ::= <Client:cmd_private> <Server:private_reply>  # RFC 5321 4.1.5: unknown X-command gets 500
<ex_private_closing> ::= <Client:cmd_private> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_quit> ::= <Client:cmd_quit> <Server:quit_ok>  # RFC 5321 4.3.2 QUIT S
<ex_quit_fail> ::= <Client:cmd_quit> <Server:quit_fail>  # RFC 5321 4.3.2 universal replies
<ex_quit_closing> ::= <Client:cmd_quit> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_starttls_ok> ::= <Client:cmd_starttls> <Server:starttls_ok>  # RFC 3207 4
<ex_starttls_fail> ::= <Client:cmd_starttls> <Server:starttls_fail>  # RFC 3207 4 (454, 501); refusal when not offered: RFC 5321 4.2.4 500/502, 4.1.4 503 out of sequence
<ex_starttls_closing> ::= <Client:cmd_starttls> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_auth_ok> ::= <Client:cmd_auth> <auth_challenge>* <Server:auth_ok>  # RFC 4954 4, 6
<ex_auth_fail> ::= <Client:cmd_auth> <auth_challenge>* <Server:auth_fail>  # RFC 4954 4, 6; unannounced: RFC 5321 4.2.4 500/502
<ex_auth_refused> ::= <Client:cmd_auth> <Server:auth_refused>  # RFC 4954 4: AUTH after AUTH or in a transaction gets 503
<ex_auth_closing> ::= <Client:cmd_auth> <auth_challenge>* <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_send_ok> ::= <Client:cmd_send> <Server:obsolete_ok>  # RFC 5321 F.3 / F.1
<ex_send_fail> ::= <Client:cmd_send> <Server:obsolete_fail>  # RFC 5321 4.2.4 502; F.3 same replies as MAIL
<ex_send_closing> ::= <Client:cmd_send> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_soml_ok> ::= <Client:cmd_soml> <Server:obsolete_ok>  # RFC 5321 F.3 / F.1
<ex_soml_fail> ::= <Client:cmd_soml> <Server:obsolete_fail>  # RFC 5321 4.2.4 502; F.3 same replies as MAIL
<ex_soml_closing> ::= <Client:cmd_soml> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_saml_ok> ::= <Client:cmd_saml> <Server:obsolete_ok>  # RFC 5321 F.3 / F.1
<ex_saml_fail> ::= <Client:cmd_saml> <Server:obsolete_fail>  # RFC 5321 4.2.4 502; F.3 same replies as MAIL
<ex_saml_closing> ::= <Client:cmd_saml> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel
<ex_turn_ok> ::= <Client:cmd_turn> <Server:obsolete_ok>  # RFC 5321 F.3 / F.1
<ex_turn_fail> ::= <Client:cmd_turn> <Server:obsolete_fail>  # RFC 5321 4.2.4 502; F.3 same replies as MAIL
<ex_turn_closing> ::= <Client:cmd_turn> <Server:closing>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel

# ---- Reply classes (RFC 5321 4.2.1, 4.3.2) ------------------------------------------
<ehlo_fail> ::= <r504> | <r550> | <r502> | <r500> | <r501>  # RFC 5321 4.3.2 EHLO E / 4.1.4
<helo_ok> ::= <r250>  # RFC 5321 4.3.2 HELO S
<helo_fail> ::= <r504> | <r550> | <r502> | <r500> | <r501>  # RFC 5321 4.3.2 HELO E
<mail_ok> ::= <r250>  # RFC 5321 4.3.2 MAIL S
<mail_fail> ::= <r552> | <r451> | <r452> | <r550> | <r553> | <r503> | <r455> | <r555> | <r500> | <r501> | <r530>  # RFC 5321 4.3.2 MAIL E; RFC 4954 6 530
<mail_refused> ::= <r503> | <r500> | <r501> | <r530>  # RFC 5321 4.1.4: MAIL inside a transaction gets 503
<rcpt_ok> ::= <r250> | <r251>  # RFC 5321 4.3.2 RCPT S
<rcpt_fail> ::= <r550> | <r551> | <r552> | <r553> | <r450> | <r451> | <r452> | <r503> | <r455> | <r555> | <r500> | <r501> | <r530>  # RFC 5321 4.3.2 RCPT E; RFC 4954 6 530
<rcpt_refused> ::= <r503> | <r500> | <r501> | <r530>  # RFC 5321 4.1.4: RCPT out of order gets 503
<data_go> ::= <r354>  # RFC 5321 4.3.2 DATA I
<data_refused> ::= <r503> | <r554> | <r500> | <r501> | <r530>  # RFC 5321 4.3.2 DATA E; RFC 4954 6 530
<content_ok> ::= <r250>  # RFC 5321 4.3.2 DATA -> data -> S
<content_fail> ::= <r552> | <r554> | <r451> | <r452> | <r450> | <r550>  # RFC 5321 4.3.2 DATA -> data -> E; 4.2.5
<rset_ok> ::= <r250>  # RFC 5321 4.3.2 RSET S
<rset_fail> ::= <r500> | <r501>  # RFC 5321 4.3.2 universal replies
<vrfy_reply> ::= <r250_u> | <r251_u> | <r252_u> | <r550_u> | <r551_u> | <r553_u> | <r502_u> | <r504_u> | <r500_u> | <r501_u> | <r530_u>  # RFC 5321 4.3.2 VRFY; RFC 6531 3.7.4.2 UTF-8
<expn_reply> ::= <r250_u> | <r252_u> | <r550_u> | <r500_u> | <r502_u> | <r504_u> | <r501_u> | <r530_u>  # RFC 5321 4.3.2 EXPN; RFC 6531 3.7.4.2 UTF-8
<help_reply> ::= <r211> | <r214> | <r502> | <r504> | <r500> | <r501> | <r530>  # RFC 5321 4.3.2 HELP
<noop_reply> ::= <r250> | <r500> | <r501>  # RFC 5321 4.3.2 NOOP
<quit_ok> ::= <r221>  # RFC 5321 4.3.2 QUIT S
<quit_fail> ::= <r500> | <r501>  # RFC 5321 4.3.2 universal replies
<starttls_ok> ::= <r220>  # RFC 3207 4
<starttls_fail> ::= <r454> | <r501> | <r502> | <r500> | <r503>  # RFC 3207 4 (454, 501); refusal when not offered: RFC 5321 4.2.4 500/502, 4.1.4 503 out of sequence
<auth_ok> ::= <r235>  # RFC 4954 4, 6
<auth_fail> ::= <r535> | <r534> | <r538> | <r454> | <r432> | <r501> | <r504> | <r503> | <r502> | <r500>  # RFC 4954 4, 6; unannounced: RFC 5321 4.2.4 500/502
<auth_refused> ::= <r503> | <r500> | <r501> | <r502>  # RFC 4954 4: AUTH after AUTH or in a transaction gets 503
<etrn_reply> ::= <r250> | <r251> | <r252> | <r253> | <r458> | <r459> | <r502> | <r500> | <r501> | <r530>  # RFC 1985 5; unannounced: RFC 5321 4.2.4 502
<bdat_ok> ::= <r250>  # RFC 3030 2
<bdat_fail> ::= <r432> | <r450> | <r451> | <r452> | <r454> | <r455> | <r458> | <r459> | <r500> | <r501> | <r502> | <r503> | <r504> | <r530> | <r534> | <r535> | <r538> | <r550> | <r551> | <r552> | <r553> | <r554> | <r555>  # RFC 3030 2: "the appropriate 5XX or 4XX code" after the chunk
<private_reply> ::= <r500> | <r502> | <r501>  # RFC 5321 4.1.5: unknown X-command gets 500
<obsolete_ok> ::= <r250>  # RFC 5321 F.3 / F.1
<obsolete_fail> ::= <r502> | <r503> | <r550> | <r552> | <r553> | <r451> | <r452> | <r455> | <r555> | <r500> | <r501> | <r530>  # RFC 5321 4.2.4 502; F.3 same replies as MAIL
<closing> ::= <r421>  # RFC 5321 4.2.3 / 3.8: 421 closes the channel

# ---- One nonterminal per reply code (RFC 5321 4.2: Reply-line) ----------------------
# Reply-line = *( Reply-code "-" [ textstring ] CRLF ) Reply-code [ SP textstring ] CRLF
<r211> ::= <r211_cont>* '211' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r211_cont> ::= '211-' <line_text>? '\r\n'
<r214> ::= <r214_cont>* '214' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r214_cont> ::= '214-' <line_text>? '\r\n'
<r220> ::= <r220_cont>* '220' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r220_cont> ::= '220-' <line_text>? '\r\n'
<r221> ::= <r221_cont>* '221' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r221_cont> ::= '221-' <line_text>? '\r\n'
<r235> ::= <r235_cont>* '235' <reply_tail>? '\r\n'  # RFC 4954 6
<r235_cont> ::= '235-' <line_text>? '\r\n'
<r250> ::= <r250_cont>* '250' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r250_cont> ::= '250-' <line_text>? '\r\n'
<r251> ::= <r251_cont>* '251' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r251_cont> ::= '251-' <line_text_utf8>? '\r\n'
<r252> ::= <r252_cont>* '252' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r252_cont> ::= '252-' <line_text>? '\r\n'
<r253> ::= <r253_cont>* '253' <reply_tail>? '\r\n'  # RFC 1985 5
<r253_cont> ::= '253-' <line_text>? '\r\n'
<r354> ::= <r354_cont>* '354' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r354_cont> ::= '354-' <line_text>? '\r\n'
<r421> ::= <r421_cont>* '421' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r421_cont> ::= '421-' <line_text>? '\r\n'
<r432> ::= <r432_cont>* '432' <reply_tail>? '\r\n'  # RFC 4954 6
<r432_cont> ::= '432-' <line_text>? '\r\n'
<r450> ::= <r450_cont>* '450' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r450_cont> ::= '450-' <line_text>? '\r\n'
<r451> ::= <r451_cont>* '451' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r451_cont> ::= '451-' <line_text>? '\r\n'
<r452> ::= <r452_cont>* '452' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r452_cont> ::= '452-' <line_text>? '\r\n'
<r454> ::= <r454_cont>* '454' <reply_tail>? '\r\n'  # RFC 3207 4 / RFC 4954 6
<r454_cont> ::= '454-' <line_text>? '\r\n'
<r455> ::= <r455_cont>* '455' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r455_cont> ::= '455-' <line_text>? '\r\n'
<r458> ::= <r458_cont>* '458' <reply_tail>? '\r\n'  # RFC 1985 5
<r458_cont> ::= '458-' <line_text>? '\r\n'
<r459> ::= <r459_cont>* '459' <reply_tail>? '\r\n'  # RFC 1985 5
<r459_cont> ::= '459-' <line_text>? '\r\n'
<r500> ::= <r500_cont>* '500' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r500_cont> ::= '500-' <line_text>? '\r\n'
<r501> ::= <r501_cont>* '501' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r501_cont> ::= '501-' <line_text>? '\r\n'
<r502> ::= <r502_cont>* '502' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r502_cont> ::= '502-' <line_text>? '\r\n'
<r503> ::= <r503_cont>* '503' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r503_cont> ::= '503-' <line_text>? '\r\n'
<r504> ::= <r504_cont>* '504' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r504_cont> ::= '504-' <line_text>? '\r\n'
<r530> ::= <r530_cont>* '530' <reply_tail>? '\r\n'  # RFC 4954 6 / RFC 3207 4
<r530_cont> ::= '530-' <line_text>? '\r\n'
<r534> ::= <r534_cont>* '534' <reply_tail>? '\r\n'  # RFC 4954 6
<r534_cont> ::= '534-' <line_text>? '\r\n'
<r535> ::= <r535_cont>* '535' <reply_tail>? '\r\n'  # RFC 4954 6
<r535_cont> ::= '535-' <line_text>? '\r\n'
<r538> ::= <r538_cont>* '538' <reply_tail>? '\r\n'  # RFC 4954 6
<r538_cont> ::= '538-' <line_text>? '\r\n'
<r550> ::= <r550_cont>* '550' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r550_cont> ::= '550-' <line_text>? '\r\n'
<r551> ::= <r551_cont>* '551' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r551_cont> ::= '551-' <line_text_utf8>? '\r\n'
<r552> ::= <r552_cont>* '552' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r552_cont> ::= '552-' <line_text>? '\r\n'
<r553> ::= <r553_cont>* '553' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r553_cont> ::= '553-' <line_text>? '\r\n'
<r554> ::= <r554_cont>* '554' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r554_cont> ::= '554-' <line_text>? '\r\n'
<r555> ::= <r555_cont>* '555' <reply_tail>? '\r\n'  # RFC 5321 4.2.3
<r555_cont> ::= '555-' <line_text>? '\r\n'
# RFC 6531 3.7.4.2: VRFY/EXPN replies may carry UTF-8 when the command had SMTPUTF8 (constraint)
<r250_u> ::= <r250_u_cont>* '250' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r250_u_cont> ::= '250-' <line_text_utf8>? '\r\n'
<r251_u> ::= <r251_u_cont>* '251' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r251_u_cont> ::= '251-' <line_text_utf8>? '\r\n'
<r252_u> ::= <r252_u_cont>* '252' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r252_u_cont> ::= '252-' <line_text_utf8>? '\r\n'
<r500_u> ::= <r500_u_cont>* '500' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r500_u_cont> ::= '500-' <line_text_utf8>? '\r\n'
<r501_u> ::= <r501_u_cont>* '501' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r501_u_cont> ::= '501-' <line_text_utf8>? '\r\n'
<r502_u> ::= <r502_u_cont>* '502' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r502_u_cont> ::= '502-' <line_text_utf8>? '\r\n'
<r504_u> ::= <r504_u_cont>* '504' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r504_u_cont> ::= '504-' <line_text_utf8>? '\r\n'
<r530_u> ::= <r530_u_cont>* '530' <reply_tail_utf8>? '\r\n'  # RFC 4954 6 / RFC 3207 4
<r530_u_cont> ::= '530-' <line_text_utf8>? '\r\n'
<r550_u> ::= <r550_u_cont>* '550' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r550_u_cont> ::= '550-' <line_text_utf8>? '\r\n'
<r551_u> ::= <r551_u_cont>* '551' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r551_u_cont> ::= '551-' <line_text_utf8>? '\r\n'
<r553_u> ::= <r553_u_cont>* '553' <reply_tail_utf8>? '\r\n'  # RFC 5321 4.2.3
<r553_u_cont> ::= '553-' <line_text_utf8>? '\r\n'

# ---- Mail data (RFC 5321 4.1.1.4, 4.5.2) carrying an RFC 5322 message -------------------
# The mail data ends with <CRLF>.<CRLF>; the message's last CRLF is the first one of it.
<mail_data> ::= <message> '.\r\n'  # RFC 5321 4.1.1.4
# RFC 5322 3.5 message = (fields / obs-fields) [CRLF body]; the body type is selected by the
# BODY / SMTPUTF8 parameters of the transaction's MAIL (constraint below).
<message> ::= <header_fields> <body_part>?
# RFC 5322 3.5 CRLF body; the 8-bit body (RFC 6152 2) is its own alternative, selected by BODY= (constraint)
<body_part> ::= '\r\n' <body_line>* | '\r\n' <body_line>* <body_line_8bit> <body_any_line>*
<body_line_8bit> ::= <body_text_8bit> '\r\n'
<body_any_line> ::= <body_line> | <body_line_8bit>
<body_line> ::= <body_text>? '\r\n'  # RFC 5322 3.5 *(*998text CRLF)
# RFC 5321 4.5.2: a line starting with "." is sent with the period doubled
<body_text> ::= <stuffed_dot> <body_chars>? | <body_first> <body_chars>?
<stuffed_dot> ::= '..'
<body_first> ::= r'[\x01-\x09\x0b\x0c\x0e-\x2d\x2f-\x7f]'  # RFC 5322 3.5 text (%d1-9 / %d11 / %d12 / %d14-127), not "."
# RFC 6152 2: a line with at least one 8-bit octet (sent as UTF-8), not starting with "."
<body_text_8bit> ::= r'([\x01-\x09\x0b\x0c\x0e-\x2d\x2f-\x7f][\x01-\x09\x0b\x0c\x0e-\x7f]*)?[\x80-\ud7ff\ue000-\U0010ffff][\x01-\x09\x0b\x0c\x0e-\x7f\x80-\ud7ff\ue000-\U0010ffff]{0,900}'
<body_chars> ::= r'[\x01-\x09\x0b\x0c\x0e-\x7f]{1,997}'  # RFC 5322 2.1.1 at most 998 characters per line
# TODO: RFC 3030 3 -- binary (non-UTF-8, NUL, bare CR/LF) octets under BINARYMIME are not generated (nearest: <body_chars>)
# TODO: RFC 2045/2046 -- MIME entity structure of the body is not modelled (nearest: <body_part>)

# RFC 5322 3.6: fields; Date and From are mandatory, all others at most once or repeatable.
# Mandatory fields sit between bounded slots of optional fields; either order.
<header_fields> ::= <pre_block>{0,2} <opt_slot> <orig_date> <opt_slot> <from_field> <opt_slot> \
    | <pre_block>{0,2} <opt_slot> <from_field> <opt_slot> <orig_date> <opt_slot>
<opt_slot> ::= <optional_header>{0,3}
<optional_header> ::= <sender> | <reply_to> | <to> | <cc> | <bcc> | <message_id> | <in_reply_to> \
    | <references> | <subject> | <comments> | <keywords> | <optional_field>
# RFC 5322 3.6: *(trace *optional-field / *(resent-date / resent-from / ...))
<pre_block> ::= <trace_block> | <resent_block>
<trace_block> ::= <return_path>? <received>+  # RFC 5322 3.6.7 trace = [return] 1*received
<resent_block> ::= <resent_date> <resent_from> <resent_opt>{0,3}  # RFC 5322 3.6.6
<resent_opt> ::= <resent_sender> | <resent_to> | <resent_cc> | <resent_bcc> | <resent_msg_id>

# RFC 5322 3.6.1 - 3.6.8 field definitions; field names are case-insensitive (RFC 5322 1.2.2)
<orig_date> ::= <fn_date> ':' <date_time> '\r\n'  # RFC 5322 3.6.1
<from_field> ::= <fn_from> ':' <mailbox_list> '\r\n'  # RFC 5322 3.6.2
<sender> ::= <fn_sender> ':' <mailbox_5322> '\r\n'  # RFC 5322 3.6.2
<reply_to> ::= <fn_reply_to> ':' <address_list> '\r\n'  # RFC 5322 3.6.2
<to> ::= <fn_to> ':' <address_list> '\r\n'  # RFC 5322 3.6.3
<cc> ::= <fn_cc> ':' <address_list> '\r\n'  # RFC 5322 3.6.3
<bcc> ::= <fn_bcc> ':' <bcc_value>? '\r\n'  # RFC 5322 3.6.3 "Bcc:" [address-list / CFWS]
<bcc_value> ::= <address_list> | <cfws>
<message_id> ::= <fn_message_id> ':' <msg_id> '\r\n'  # RFC 5322 3.6.4
<in_reply_to> ::= <fn_in_reply_to> ':' <msg_id>+ '\r\n'  # RFC 5322 3.6.4
<references> ::= <fn_references> ':' <msg_id>+ '\r\n'  # RFC 5322 3.6.4
<subject> ::= <fn_subject> ':' <unstructured> '\r\n'  # RFC 5322 3.6.5
<comments> ::= <fn_comments> ':' <unstructured> '\r\n'  # RFC 5322 3.6.5
<keywords> ::= <fn_keywords> ':' <phrase> <more_phrase>* '\r\n'  # RFC 5322 3.6.5
<more_phrase> ::= ',' <phrase>
<resent_date> ::= <fn_resent_date> ':' <date_time> '\r\n'  # RFC 5322 3.6.6
<resent_from> ::= <fn_resent_from> ':' <mailbox_list> '\r\n'  # RFC 5322 3.6.6
<resent_sender> ::= <fn_resent_sender> ':' <mailbox_5322> '\r\n'  # RFC 5322 3.6.6
<resent_to> ::= <fn_resent_to> ':' <address_list> '\r\n'  # RFC 5322 3.6.6
<resent_cc> ::= <fn_resent_cc> ':' <address_list> '\r\n'  # RFC 5322 3.6.6
<resent_bcc> ::= <fn_resent_bcc> ':' <bcc_value>? '\r\n'  # RFC 5322 3.6.6
<resent_msg_id> ::= <fn_resent_msg_id> ':' <msg_id> '\r\n'  # RFC 5322 3.6.6
<return_path> ::= <fn_return_path> ':' <return_value> '\r\n'  # RFC 5322 3.6.7 return
<return_value> ::= <angle_addr> | <empty_return>  # RFC 5322 3.6.7 path = angle-addr / ([CFWS] "<" [CFWS] ">" [CFWS])
<empty_return> ::= <cfws>? '<' <cfws>? '>' <cfws>?
<received> ::= <fn_received> ':' <received_token>* ';' <date_time> '\r\n'  # RFC 5322 3.6.7
<received_token> ::= <word> | <angle_addr> | <addr_spec> | <domain_5322>  # RFC 5322 3.6.7
# TODO: RFC 5321 4.4 -- the stricter Time-stamp-line / Stamp syntax of SMTP trace lines is not used (nearest: <received>)
# RFC 5322 3.6.8 optional-field = field-name ":" unstructured CRLF; fallback last, unconstrained
<optional_field> ::= <field_name> ':' <unstructured> '\r\n'
<field_name> ::= r'[\x21-\x2d\x2f-\x39\x3b-\x7e][\x21-\x39\x3b-\x7e]{0,75}'  # RFC 5322 3.6.8 1*ftext (first not "." so no stuffing)
# TODO: RFC 5321 4.5.2 -- field names starting with "." (needing transparency) are not generated (nearest: <field_name>)

<fn_date> ::= r'[Dd][Aa][Tt][Ee]'
<fn_from> ::= r'[Ff][Rr][Oo][Mm]'
<fn_sender> ::= r'[Ss][Ee][Nn][Dd][Ee][Rr]'
<fn_reply_to> ::= r'[Rr][Ee][Pp][Ll][Yy]-[Tt][Oo]'
<fn_to> ::= r'[Tt][Oo]'
<fn_cc> ::= r'[Cc][Cc]'
<fn_bcc> ::= r'[Bb][Cc][Cc]'
<fn_message_id> ::= r'[Mm][Ee][Ss][Ss][Aa][Gg][Ee]-[Ii][Dd]'
<fn_in_reply_to> ::= r'[Ii][Nn]-[Rr][Ee][Pp][Ll][Yy]-[Tt][Oo]'
<fn_references> ::= r'[Rr][Ee][Ff][Ee][Rr][Ee][Nn][Cc][Ee][Ss]'
<fn_subject> ::= r'[Ss][Uu][Bb][Jj][Ee][Cc][Tt]'
<fn_comments> ::= r'[Cc][Oo][Mm][Mm][Ee][Nn][Tt][Ss]'
<fn_keywords> ::= r'[Kk][Ee][Yy][Ww][Oo][Rr][Dd][Ss]'
<fn_resent_date> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Dd][Aa][Tt][Ee]'
<fn_resent_from> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Ff][Rr][Oo][Mm]'
<fn_resent_sender> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Ss][Ee][Nn][Dd][Ee][Rr]'
<fn_resent_to> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Tt][Oo]'
<fn_resent_cc> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Cc][Cc]'
<fn_resent_bcc> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Bb][Cc][Cc]'
<fn_resent_msg_id> ::= r'[Rr][Ee][Ss][Ee][Nn][Tt]-[Mm][Ee][Ss][Ss][Aa][Gg][Ee]-[Ii][Dd]'
<fn_return_path> ::= r'[Rr][Ee][Tt][Uu][Rr][Nn]-[Pp][Aa][Tt][Hh]'
<fn_received> ::= r'[Rr][Ee][Cc][Ee][Ii][Vv][Ee][Dd]'

# ---- RFC 5322 3.3 date-time --------------------------------------------------------------
<date_time> ::= <dow_part>? <date> <time> <cfws>?  # RFC 5322 3.3 [ day-of-week "," ] date time [CFWS]
<dow_part> ::= <fws>? <day_name> ','  # RFC 5322 3.3 day-of-week = ([FWS] day-name)
<day_name> ::= <dn_mon> | <dn_tue> | <dn_wed> | <dn_thu> | <dn_fri> | <dn_sat> | <dn_sun>
<dn_mon> ::= 'Mon'
<dn_tue> ::= 'Tue'
<dn_wed> ::= 'Wed'
<dn_thu> ::= 'Thu'
<dn_fri> ::= 'Fri'
<dn_sat> ::= 'Sat'
<dn_sun> ::= 'Sun'
<date> ::= <fws>? <day> <fws> <month> <fws> <year> <fws>  # RFC 5322 3.3 date = day month year
<day> ::= r'[0-9]{1,2}'  # RFC 5322 3.3 1*2DIGIT
<month> ::= <mn_jan> | <mn_feb> | <mn_mar> | <mn_apr> | <mn_may> | <mn_jun> | <mn_jul> | <mn_aug> \
    | <mn_sep> | <mn_oct> | <mn_nov> | <mn_dec>
<mn_jan> ::= 'Jan'
<mn_feb> ::= 'Feb'
<mn_mar> ::= 'Mar'
<mn_apr> ::= 'Apr'
<mn_may> ::= 'May'
<mn_jun> ::= 'Jun'
<mn_jul> ::= 'Jul'
<mn_aug> ::= 'Aug'
<mn_sep> ::= 'Sep'
<mn_oct> ::= 'Oct'
<mn_nov> ::= 'Nov'
<mn_dec> ::= 'Dec'
<year> ::= r'[1-9][0-9]{4}|19[0-9]{2}|[2-9][0-9]{3}'  # RFC 5322 3.3 4*DIGIT, 1900 or later
<time> ::= <time_of_day> <fws> <zone>  # RFC 5322 3.3
<time_of_day> ::= <hour> ':' <minute> <second_part>?
<second_part> ::= ':' <second>
<hour> ::= r'[01][0-9]|2[0-3]'  # RFC 5322 3.3 hour 00-23
<minute> ::= r'[0-5][0-9]'  # RFC 5322 3.3 minute 00-59
<second> ::= r'[0-5][0-9]|60'  # RFC 5322 3.3 second 00-60 (leap second)
<zone> ::= <zone_sign> <zone_hhmm>  # RFC 5322 3.3 zone = (FWS ( "+" / "-" ) 4DIGIT)
<zone_sign> ::= '+' | '-'
<zone_hhmm> ::= r'[0-9]{2}[0-5][0-9]'  # RFC 5322 3.3 zone hhmm, minutes 00-59

# ---- RFC 5322 3.4 addresses ---------------------------------------------------------------
<address_list> ::= <address> <more_address>*  # RFC 5322 3.4
<more_address> ::= ',' <address>
<address> ::= <mailbox_5322> | <group>
<mailbox_list> ::= <mailbox_5322> <more_mailbox>*
<more_mailbox> ::= ',' <mailbox_5322>
<mailbox_5322> ::= <name_addr> | <addr_spec>  # RFC 5322 3.4
<name_addr> ::= <phrase>? <angle_addr>  # RFC 5322 3.4 [display-name] angle-addr
<angle_addr> ::= <cfws>? '<' <addr_spec> '>' <cfws>?
<group> ::= <phrase> ':' <group_list>? ';' <cfws>?  # RFC 5322 3.4 group
<group_list> ::= <mailbox_list> | <cfws>
<addr_spec> ::= <local_part_5322> '@' <domain_5322>  # RFC 5322 3.4.1
<local_part_5322> ::= <dot_atom> | <quoted_string_5322>
<domain_5322> ::= <dot_atom> | <domain_literal>
<domain_literal> ::= <cfws>? '[' <dtext>? ']' <cfws>?  # RFC 5322 3.4.1 (FWS inside omitted)
<dtext> ::= r'[\x21-\x5a\x5e-\x7e]+'  # RFC 5322 3.4.1 dtext = %d33-90 / %d94-126

# ---- RFC 5322 3.2 lexical tokens ------------------------------------------------------------
<phrase> ::= <word>+  # RFC 5322 3.2.5 phrase = 1*word (display-name)
<word> ::= <atom_5322> | <quoted_string_5322>  # RFC 5322 3.2.5
<atom_5322> ::= <cfws>? <atom>  # RFC 5322 3.2.3 atom = [CFWS] 1*atext [CFWS] (trailing CFWS joins the next token)
<dot_atom> ::= <cfws>? <dot_string>  # RFC 5322 3.2.3 dot-atom = [CFWS] dot-atom-text [CFWS]
<quoted_string_5322> ::= <cfws>? '"' <qtext_5322>? <qrun_5322>* '"'  # RFC 5322 3.2.4
<qrun_5322> ::= <quoted_pair_5322> <qtext_5322>?
<qtext_5322> ::= r'[\x20\x21\x23-\x5b\x5d-\x7e]+'  # RFC 5322 3.2.4 qtext plus WSP
<quoted_pair_5322> ::= '\\' <qp_char>  # RFC 5322 3.2.1 quoted-pair = "\" (VCHAR / WSP)
<qp_char> ::= r'[\x20-\x7e\t]'
# RFC 5322 3.2.5 unstructured = *([FWS] VCHAR) *WSP; VCHAR runs are split only at FWS
<unstructured> ::= <unstructured_ascii> | <unstructured_utf8>
<unstructured_ascii> ::= <vchars>? <utext_run>* <wsp>?
<utext_run> ::= <fws> <vchars>
# RFC 6532 3.2: VCHAR =/ UTF8-non-ascii; at least one UTF-8 word (SMTPUTF8 constraint below)
<unstructured_utf8> ::= <vchars>? <utext_run>* <fws>? <vchars_utf8> <utext_any_run>* <wsp>?
<utext_any_run> ::= <fws> <vchars> | <fws> <vchars_utf8>
<vchars_utf8> ::= r'[\x21-\x7e]*[\x80-\ud7ff\ue000-\U0010ffff][\x21-\x7e\x80-\ud7ff\ue000-\U0010ffff]*'
<vchars> ::= r'[\x21-\x7e]+'  # RFC 5322 3.2.5 VCHAR
# RFC 5322 3.2.2 FWS = ([*WSP CRLF] 1*WSP); CFWS = (1*([FWS] comment) [FWS]) / FWS
<fws> ::= <fold>? <wsp>
<fold> ::= <wsp>? '\r\n'
<wsp> ::= r'[ \t]+'  # RFC 5234 B.1 WSP
<cfws> ::= <comment_part>+ <fws>? | <fws>
<comment_part> ::= <fws>? <comment>
<comment> ::= '(' <ctext>? ')'  # RFC 5322 3.2.2 (nested comments omitted)
<ctext> ::= r'[\x21-\x27\x2a-\x5b\x5d-\x7e]{1,20}'  # RFC 5322 3.2.2 ctext
# TODO: RFC 5322 3.2.2 -- nested comments and quoted-pairs inside comments are not generated (nearest: <comment>)
# TODO: RFC 5322 3.6.4 -- no-fold-literal id-right is not generated (nearest: <msg_id>)
<msg_id> ::= <cfws>? '<' <dot_string> '@' <dot_string> '>' <cfws>?  # RFC 5322 3.6.4 msg-id
# TODO: RFC 5322 4 -- obsolete syntax is never generated (RFC 5322 4: MUST NOT be generated)
# TODO: RFC 6532 3.2 -- UTF-8 in atext/ctext/qtext/dtext of structured header fields is not generated (nearest: <unstructured_utf8>)

# ---- Semantic constraints ------------------------------------------------------------------
where len(list(<ipv6_comp>.find_subtrees('<ipv6_hex>'))) <= 6  # RFC 5321 4.1.3 IPv6-comp: no more than 6 groups
where len(list(<ipv6v4_comp>.find_subtrees('<ipv6_hex>'))) <= 4  # RFC 5321 4.1.3 IPv6v4-comp: no more than 4 groups
where len(str(<param_orcpt>)) <= 500 + 6  # RFC 3461 4.2 "the ORCPT parameter MUST NOT exceed 500 characters"
where len(str(<param_envid>.<xtext>)) <= 100  # RFC 3461 4.4 "the ENVID ... MUST NOT exceed 100 characters"
where unique_keywords(<cmd_mail>, '<mail_param>')  # RFC 5321 4.1.2 / RFC 1870 / RFC 3461: each esmtp-keyword at most once
where unique_keywords(<cmd_rcpt>, '<rcpt_param>')  # RFC 5321 4.1.2 / RFC 3461
where unique_keywords(<notify_value>, '<notify_item>')  # RFC 3461 4.1: each NOTIFY value at most once
# RFC 5322 3.3 date-time value ranges and the day-of-week implied by the date
where valid_date(<date_time>)  # RFC 5322 3.3 day within month, day-of-week matches date
# RFC 5322 3.6: fields occurring at most once
where fields_at_most_once(<header_fields>)  # RFC 5322 3.6: sender, reply-to, to, cc, bcc, message-id, in-reply-to, references, subject at most once

# Session rules that relate one message to earlier ones (multi-step walks over the session).
where enhanced_status_codes_ok(<start>)  # RFC 2034 4
where bdat_payload_announced(<start>)  # RFC 3030 2: chunk data only to a server that announced CHUNKING
where utf8_replies_ok(<start>)  # RFC 6531 3.7.4.2: UTF-8 in VRFY/EXPN replies only when requested
where binarymime_data_ok(<start>)  # RFC 3030 3: DATA after BODY=BINARYMIME gets 503
where transaction_types_ok(<start>)  # RFC 6531 3.4, RFC 6152 3, RFC 6532 3: UTF-8 envelope and 8-bit content need the MAIL parameters

import datetime

MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def valid_date(date_time) -> bool:
    """RFC 5322 3.3: the day exists in the month and the day-of-week is the one implied by the date."""
    day = list(date_time.find_subtrees('<day>'))
    month = list(date_time.find_subtrees('<month>'))
    year = list(date_time.find_subtrees('<year>'))
    if not (day and month and year):
        return True
    try:
        date = datetime.date(int(str(year[0])), MONTHS.index(str(month[0])) + 1, int(str(day[0])))
    except ValueError:
        return False
    names = list(date_time.find_subtrees('<day_name>'))
    return not names or str(names[0]) == date.strftime('%a')


def _ehlo_keywords(msg):
    """Upper-cased keywords of the ehlo-lines of an EHLO reply (RFC 5321 4.1.1.1)."""
    return {str(line).split(' ')[0].upper() for line in msg.find_subtrees('<ehlo_line>')}


def _messages(tree):
    return [('Client' if _is_request(str(m.msg.symbol)) else 'Server', str(m.msg.symbol), m.msg)
            for m in tree.protocol_msgs() if str(m.msg)]


def _is_request(symbol):
    """Client messages are the commands, the mail data and the AUTH responses (by symbol, so the
    check also works when parsing a capture, where the parties are not known)."""
    return symbol.startswith('<cmd_') or symbol in ('<mail_data>', '<auth_response>')


# Replies exempt from RFC 2034 4: greeting, replies to HELO/EHLO, and 3xx replies.
_ESC_EXEMPT = {'<greeting>', '<greeting_refused>', '<greeting_closing>', '<ehlo_ok>', '<ehlo_fail>',
               '<helo_ok>', '<helo_fail>', '<data_go>', '<r334>'}


def enhanced_status_codes_ok(tree) -> bool:
    """RFC 2034 4: once ENHANCEDSTATUSCODES is announced, every 2xx/4xx/5xx reply line other than
    the greeting and the replies to HELO/EHLO starts with the same status code, whose class is
    the first digit of the reply code."""
    supported = False
    last_request = None
    for sender, symbol, msg in _messages(tree):
        if sender != 'Server':
            last_request = symbol
            continue
        if symbol == '<ehlo_ok>' and 'ENHANCEDSTATUSCODES' in _ehlo_keywords(msg):
            supported = True
            continue
        if not supported or symbol in _ESC_EXEMPT or last_request in ('<cmd_ehlo>', '<cmd_helo>'):
            continue
        text = str(msg)
        code = text[:3]
        lines = text.count('\r\n')
        line_texts = list(msg.find_subtrees('<line_text>')) + list(msg.find_subtrees('<line_text_utf8>'))
        if len(line_texts) != lines:
            return False
        codes = set()
        for line_text in line_texts:
            status = line_text.find_direct_trees(NonTerminal('<status_code>'))
            if not status:
                return False
            codes.add(str(status[0]))
        if len(codes) != 1 or next(iter(codes))[0] != code[0]:
            return False
    return True


def _mail_params(command):
    """The esmtp-params of a MAIL command, upper-cased (independent of the parse alternative)."""
    params = list(command.find_subtrees('<mail_param>')) + list(command.find_subtrees('<param_smtputf8>'))
    return {str(param).upper() for param in params}


def binarymime_data_ok(tree) -> bool:
    """RFC 3030 3: DATA after a MAIL with BODY=BINARYMIME MUST get 503."""
    binary = False
    last_command = None
    for sender, symbol, msg in _messages(tree):
        if sender != 'Server':
            last_command = msg
            continue
        if symbol == '<mail_ok>':
            binary = 'BODY=BINARYMIME' in _mail_params(last_command)
        elif symbol in ('<ehlo_ok>', '<helo_ok>', '<rset_ok>', '<content_ok>', '<content_fail>'):
            binary = False
        elif symbol == '<data_go>' and binary:
            return False
    return True


def transaction_types_ok(tree) -> bool:
    """The MAIL parameters select what the transaction may carry: SMTPUTF8 (RFC 6531 3.4) for UTF-8
    recipients and UTF-8 header fields (RFC 6532 3), BODY=8BITMIME / BINARYMIME (RFC 6152 3,
    RFC 3030 3) for 8-bit body lines."""
    utf8 = eight_bit = False
    for m in tree.protocol_msgs():
        if not _is_request(str(m.msg.symbol)):
            continue
        msg = m.msg
        symbol = str(msg.symbol)
        if symbol == '<cmd_mail>':
            params = _mail_params(msg)
            utf8 = 'SMTPUTF8' in params
            eight_bit = bool({'BODY=8BITMIME', 'BODY=BINARYMIME'} & params)
        elif symbol == '<cmd_rcpt>' and list(msg.find_subtrees('<path_utf8>')) and not utf8:
            return False
        elif symbol == '<mail_data>':
            if list(msg.find_subtrees('<unstructured_utf8>')) and not utf8:
                return False
            if list(msg.find_subtrees('<body_line_8bit>')) and not eight_bit:
                return False
    return True


def unique_keywords(tree, symbol) -> bool:
    """No keyword occurs twice among the <symbol> elements of tree (esmtp-param keywords, NOTIFY values)."""
    keywords = [str(item).upper().partition('=')[0] for item in tree.find_subtrees(symbol)]
    return len(set(keywords)) == len(keywords)


_SINGLE_FIELDS = ('<sender>', '<reply_to>', '<to>', '<cc>', '<bcc>', '<message_id>', '<in_reply_to>', '<references>', '<subject>')


def fields_at_most_once(fields) -> bool:
    """RFC 5322 3.6 table: these fields occur at most once per message."""
    return all(len(list(fields.find_subtrees(name))) <= 1 for name in _SINGLE_FIELDS)


def bdat_payload_announced(tree) -> bool:
    """RFC 3030 2: "it is important to send the BDAT only to systems that have declared their
    capability"; data sent to another server is parsed as command lines.  BDAT is still sent
    everywhere, but with a zero-octet chunk unless the last EHLO reply announced CHUNKING."""
    chunking = False
    for m in tree.protocol_msgs():
        symbol = str(m.msg.symbol)
        if symbol == '<ehlo_ok>':
            chunking = 'CHUNKING' in _ehlo_keywords(m.msg)
        elif symbol == '<helo_ok>':
            chunking = False
        elif symbol in ('<cmd_bdat>', '<cmd_bdat_last>') and not chunking \
                and any(int(str(size)) > 0 for size in m.msg.find_subtrees('<chunk_size>')):
            return False
    return True


def utf8_replies_ok(tree) -> bool:
    """RFC 6531 3.7.4.2: "an SMTPUTF8-aware SMTP server MUST NOT use UTF-8 strings in replies if the
    SMTP client does not specifically allow such replies by transmitting this parameter with the
    VRFY and EXPN commands"."""
    allowed = False
    for sender, symbol, msg in _messages(tree):
        if sender == 'Client':
            allowed = bool(list(msg.find_subtrees('<vrfy_utf8>')))
        elif symbol in ('<vrfy_reply>', '<expn_reply>') and not str(msg).isascii() and not allowed:
            return False
    return True
