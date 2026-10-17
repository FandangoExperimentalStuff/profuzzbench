# Session Initiation Protocol (SIP), RFC 3261 with the updates listed in
# refs/spec/manifest.json (RFC 3261 errata, 4320, 5621, 5954, 6026, 6141,
# 6878, 8217, 8760; ABNF from RFC 5234).
#
# Fandango plays a user agent client (party Client) over one connection of
# the transport SIP_TRANSPORT names (RFC 3261 §18: every element implements
# UDP and TCP): TCP by default, or UDP (servers/kamailio runs over UDP, the
# other servers over TCP).  Every message the grammar sends carries
# Content-Length (mandatory over TCP, §20.14), so the grammar alone delimits
# every message on both transports.
# The server (party Server) is a registrar, proxy or user agent server.
#
# States (one nonterminal each, one alternative per transition):
#   <state_idle>       no dialog, no pending transaction (§8, §10, §11)
#   <state_invite_*>   the INVITE client transaction (§17.1.1.2, RFC 6026
#                      §7.2: Calling, Proceeding, Accepted, Completed) and
#                      its cancellation (§9)
#   <state_confirmed>  a confirmed INVITE dialog (§12, §13, §14, §15)
# Non-INVITE transactions (§17.1.2) are the exchange nonterminals <exch_*>: a
# request, the provisional replies and the final reply.
# A 401/407 challenge (§22, RFC 8760) is answered inside the exchange by the
# same request with credentials (§8.1.3.5: same Call-ID, CSeq one higher).
#
# Sent messages use the hardcoded account alice / secret; target resources
# come from environment variables (see the generators below).
#
# The tested server's role comes from the environment: SIP_SERVER_ROLE=uas
# (default: the server answers every request itself, as registrar, UAS or
# B2BUA) or proxy (it forwards requests and may fork them, §16).  Rules that
# bind only a proxy (§16.3 step 3 Max-Forwards 0 -> 483, §16.3 step 5
# Proxy-Require -> 420, forked replies with several To tags, §16.7) are
# constraints that read this setting.
#
# Over UDP the client retransmits its pending request when Timer A / E fires
# (<req_retransmit> in <retransmissions_invite>, in the <retransmission_*>
# slots of the exchanges and in every INVITE state where a CANCEL or BYE is
# pending, §17.1.1.2, §17.1.2.2; over TCP at most a CRLF, §7.5), and the server's reactions (its
# latest reply again, or nothing) are accepted where they can come.
# Over UDP the client ACKs every repeated final reply also after its ACK
# (<state_invite_acked>, Timer D), and sends datagrams with octets beyond
# Content-Length and shorter than it (§18.3).
# A received datagram without Content-Length (§18.3) is <datagram_body>.
# Over UDP the client also registers by multicast (§10.2.6, §18.1.1:
# <exch_register_multicast>, Request-URI sip.mcast.net, top Via with maddr
# and ttl=1); the generator of that Via part retargets the Client party so
# that this request (and its copies) goes to the group 224.0.1.75 and its
# socket joins the group for the replies (§18.2.2).
# TODO: SCTP (RFC 4168) and TLS (§26.2) are other protocols; nearest
#   <via_transport>.
# TODO: RFC 3261 §16 the proxy's own exchanges with other elements (the
#   forwarded request, the downstream replies before the best response is
#   chosen, §16.6-§16.10) are third-party exchanges; only what reaches the
#   client is checked; nearest <state_invite_accepted>.
# TODO: SDP (RFC 8866/3264, offer/answer) is another protocol not in
#   refs/spec; the offer we send is a fixed minimal SDP <sdp_offer>, received
#   session descriptions are opaque <body_octet>s (their <body_view> is
#   <opaque_view>).
# TODO: S/MIME bodies (RFC 3261 §23) are CMS (RFC 2630/5652), another
#   protocol; nearest <body_octet>.
# TODO: RFC 5621 multipart bodies: the MIME multipart syntax is RFC 2046,
#   another document not in refs/spec; the multipart rules of RFC 5621 §6-§9
#   are checked on the split body by multipart_rules(); nearest <body_octet>.
# TODO: RFC 3261 §19.1.5 forming a request with another method from a URI's
#   method parameter (a 3xx is recursed on with INVITE, the method
#   parameter is dropped, §8.1.3.4); nearest <req_invite_redirected>.

import gzip
import hashlib
import os
import re
import zlib
from urllib.parse import unquote
import random
import string
import time
from fandango.language.symbols import NonTerminal

########################################################################
# Session and states
########################################################################

# §8.1, §10, §11, §12: a session starts without dialog
<start> ::= <state_idle>

# §8.1.1, §10.2, §11, §13.2.1, §9.1, §15.1.2, §25.1 extension-method
<state_idle> ::= <exch_options> <state_idle_or_end> \
    | <exch_options_require> <state_idle_or_end> \
    | <exch_options_proxy_require> <state_idle_or_end> \
    | <exch_options_unknown_type> <state_idle_or_end> \
    | <exch_options_unknown_encoding> <state_idle_or_end> \
    | <exch_options_optional_body> <state_idle_or_end> \
    | <exch_register> <state_idle_or_end> \
    | <exch_register_bad_wildcard> <state_idle_or_end> \
    | <exch_register_star_with_binding> <state_idle_or_end> \
    | <exch_register_old_cseq> <state_idle_or_end> \
    | <exch_register_unknown_aor> <state_idle_or_end> \
    | <exch_register_multicast> <state_idle_or_end> \
    | <exch_extension> <state_idle_or_end> \
    | <exch_bye_no_dialog> <state_idle_or_end> \
    | <exch_cancel_no_transaction> <state_idle_or_end> \
    | <Client:req_invite> <retransmissions_invite> <state_invite_calling> \
    | <exch_options_datagram_extra> <state_idle_or_end> \
    | <exch_options_datagram_short> <state_idle_or_end> \
    | <Client:resp_stray> <state_idle> \
    | <Client:resp_stray_short> <state_idle> \
    | <Server:keepalive> <state_idle> \
    | <Server:rep_stray> <state_idle> \
    | <Server:rep_stray_invite> <state_idle>

# RFC 6026 §8.9, §17.1.3: a response that matches no client transaction (a
# stray response) is dropped by the UA, which stays in its state; the
# states accept stray responses of methods none of their transactions has
# (every method but INVITE and CANCEL)
<rep_stray> ::= (<status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_stray>

# RFC 6026 §8.9: with no INVITE transaction pending (no dialog: <state_idle>;
# in the dialog every INVITE reply but a 2xx retransmission, which
# <state_confirmed> ACKs again, and every CANCEL reply) a response with the
# CSeq method INVITE or CANCEL is stray too
# with a BYE pending, stray responses of the methods other than INVITE,
# CANCEL and BYE
<rep_stray_other> ::= (<status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_stray_other>
<rep_stray_invite> ::= (<status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_invite> \
    | (<status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_cancel>
# RFC 6026 §8.9: while an INVITE (or CANCEL) transaction is pending, a
# non-2xx reply to an earlier INVITE, or a reply to an earlier CANCEL, is
# stray too (e.g. a Timer G repetition of the 407 that the INVITE now
# pending with credentials answers); where stray_reply and
# not_latest_invite: its CSeq is neither pending nor the latest INVITE's,
# and the regular replies (where answers_pending) are those that are
# (§13.2.2.4: a 2xx of an earlier INVITE is no stray, it is ACKed); over UDP
# a repetition of the latest 300-699 INVITE final is no stray either (where
# not final_retransmitted): its INVITE transaction is still in Completed
# (§17.1.1.2 Timer D), so every such state takes it as
# <rep_invite_final_again> and ACKs it again
<rep_stray_pending> ::= (<status_1xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_invite> \
    | (<status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_cancel>
<rep_stray_in_dialog> ::= (<status_1xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_invite> \
    | (<status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> \
    | <status_5xx> | <status_6xx>) <reply_cancel>

# RFC 6026 §8.9 (replacing §18.1.2): a response that matches none of the
# server's client transactions (a new branch with the server's own sent-by)
# is discarded by every element but a stateless proxy: the server sends
# nothing for it (any message of its own here fails to parse), the session
# goes on
<resp_stray> ::= 'SIP/2.0 486 Busy Here\r\n' <s_via_name> ': SIP/2.0/' <via_transport> ' ' <target_host> ':' <s_port_number> \
    ';branch=z9hG4bK' <stray_branch> '\r\n' \
    <s_from_name> ': <sip:' <target_host> '>;tag=' <stray_branch> '\r\n' \
    <s_to_name> ': <sip:' <local_user> '@' <local_domain> '>;tag=' <stray_branch> '\r\n' \
    <s_callid_new> 'CSeq: 1 INVITE\r\n' <s_content_length_zero> '\r\n'
# §18.3: over UDP a response datagram that ends before the end of its body
# (Content-Length 16 more than the body, datagram_shortfall) MUST be
# discarded: the server sends nothing for it (over TCP the same stray
# response, complete)
<resp_stray_short> ::= 'SIP/2.0 486 Busy Here\r\n' <s_via_name> ': SIP/2.0/' <via_transport> ' ' <target_host> ':' <s_port_number> \
    ';branch=z9hG4bK' <stray_branch> '\r\n' \
    <s_from_name> ': <sip:' <target_host> '>;tag=' <stray_branch> '\r\n' \
    <s_to_name> ': <sip:' <local_user> '@' <local_domain> '>;tag=' <stray_branch> '\r\n' \
    <s_callid_new> 'CSeq: 1 INVITE\r\n' <s_content_type_name> ': text/plain\r\n' <s_content_length_body> '\r\n' <text_body>
<stray_branch> ::= r'[a-zA-Z0-9]{16}' := new_token(16)

# §7.5: CRLFs between messages on a stream are ignored; a server may send a
# double CRLF while the client is to speak (keep-alive)
<keepalive> ::= '\r\n' '\r\n'

# no dialog after at least one exchange: the client may also close the
# connection (§18.3: the TCP connection is not tied to a transaction)
<state_idle_or_end> ::= <state_idle> | ''

# §17.1.1.2 INVITE client transaction, Calling: the INVITE is out, no reply yet
<state_invite_calling> ::= <Server:rep_invite_100> <state_invite_proceeding> \
    | <Server:rep_invite_early> <state_invite_early> \
    | <Server:rep_invite_2xx> <state_invite_accepted> \
    | <Server:rep_invite_redirect> <state_invite_redirect_completed> \
    | <Server:rep_invite_use_proxy> <state_invite_use_proxy_completed> \
    | <Server:rep_invite_failure> <state_invite_completed> \
    | <Server:rep_invite_challenge> <state_invite_challenge_completed> \
    | <Server:rep_stray> <state_invite_calling> \
    | <Server:rep_stray_pending> <state_invite_calling> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_calling>

# §17.1.1.2 Proceeding: a provisional reply came; §9.1 now the INVITE may be
# cancelled; §17.2.3/§9.2 a CANCEL whose top Via differs from the INVITE's
# (other branch, other sent-by) matches no transaction and must not cancel it
<state_invite_proceeding> ::= <Server:rep_invite_100> <state_invite_proceeding> \
    | <Server:rep_invite_early> <state_invite_early> \
    | <Server:rep_invite_2xx> <state_invite_accepted> \
    | <Server:rep_invite_redirect> <state_invite_redirect_completed> \
    | <Server:rep_invite_use_proxy> <state_invite_use_proxy_completed> \
    | <Server:rep_invite_failure> <state_invite_completed> \
    | <Server:rep_invite_challenge> <state_invite_challenge_completed> \
    | <Client:req_cancel> <state_invite_cancelling> \
    | <Client:req_cancel_other_branch> <state_invite_cancelling> \
    | <Client:req_cancel_other_sent_by> <state_invite_cancelling> \
    | <Server:keepalive> <state_invite_proceeding> \
    | <Server:rep_stray> <state_invite_proceeding> \
    | <Server:rep_stray_pending> <state_invite_proceeding> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_proceeding>

# §12.1.2, §13.2.2.1: a 101-199 reply with a To tag created an early dialog;
# besides what Proceeding allows, §15.1.1 the caller MAY end it with BYE
<state_invite_early> ::= <Server:rep_invite_100> <state_invite_early> \
    | <Server:rep_invite_early> <state_invite_early> \
    | <Server:rep_invite_2xx> <state_invite_accepted> \
    | <Server:rep_invite_redirect> <state_invite_redirect_completed> \
    | <Server:rep_invite_use_proxy> <state_invite_use_proxy_completed> \
    | <Server:rep_invite_failure> <state_invite_completed> \
    | <Server:rep_invite_challenge> <state_invite_challenge_completed> \
    | <Client:req_cancel> <state_invite_cancelling> \
    | <Client:req_cancel_other_branch> <state_invite_cancelling> \
    | <Client:req_cancel_other_sent_by> <state_invite_cancelling> \
    | <Client:req_bye_early> <state_invite_early_bye> \
    | <Client:req_invite_merged> <retransmissions_invite> <state_invite_merged> \
    | <Server:keepalive> <state_invite_early> \
    | <Server:rep_stray> <state_invite_early> \
    | <Server:rep_stray_pending> <state_invite_early> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_early>

# §8.2.2.2: the INVITE once more with the same From tag, Call-ID and CSeq
# but a new branch, as if forking had brought it a second way
# (<req_invite_merged>): the UAS MUST check it against its transactions and
# SHOULD answer it 482 (Loop Detected), going on with the first. Both INVITE
# transactions are pending; a reply belongs to the one whose branch its top
# Via carries (§17.1.3): <rep_invite_merged_1xx> / <rep_invite_merged_final>
# (where answers_merged) or the first INVITE's replies (where
# not_merged_reply). Each final reply is ACKed (§17.1.1.3) before the other
# transaction goes on; after the merged one the first goes on in Proceeding
<state_invite_merged> ::= <Server:rep_invite_merged_1xx> <state_invite_merged> \
    | <Server:rep_invite_merged_final> <state_invite_merged_completed> \
    | <Server:rep_invite_1xx> <state_invite_merged> \
    | <Server:rep_invite_2xx> <state_invite_merged_accepted> \
    | <Server:rep_invite_redirect> <state_invite_merged_first_completed> \
    | <Server:rep_invite_use_proxy> <state_invite_merged_first_completed> \
    | <Server:rep_invite_failure> <state_invite_merged_first_completed> \
    | <Server:rep_invite_challenge> <state_invite_merged_first_completed> \
    | <Server:keepalive> <state_invite_merged> \
    | <Server:rep_stray> <state_invite_merged> \
    | <Server:rep_stray_pending> <state_invite_merged> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_merged>
# the merged INVITE got its final reply: ACK it, the first INVITE goes on
<state_invite_merged_completed> ::= <Client:req_ack_failure> <state_invite_proceeding> \
    | <Server:rep_invite_1xx> <state_invite_merged_completed> \
    | <Server:rep_invite_redirect> <state_invite_merged_two_acks> \
    | <Server:rep_invite_use_proxy> <state_invite_merged_two_acks> \
    | <Server:rep_invite_failure> <state_invite_merged_two_acks> \
    | <Server:rep_invite_challenge> <state_invite_merged_two_acks> \
    | <Server:rep_invite_2xx> <state_invite_merged_completed_accepted> \
    | <Server:keepalive> <state_invite_merged_completed> \
    | <Server:rep_stray> <state_invite_merged_completed> \
    | <Server:rep_stray_pending> <state_invite_merged_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_merged_completed>
# the first INVITE got a 2xx (RFC 6026 Accepted) while the merged one is
# pending: its ACK confirms the dialog, the merged reply is still due
<state_invite_merged_accepted> ::= <Client:req_ack_2xx> <state_merged_reply_pending_confirmed> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_invite_merged_accepted> \
    | <Server:rep_invite_merged_1xx> <state_invite_merged_accepted> \
    | <Server:rep_invite_merged_final> <state_invite_merged_accepted_completed> \
    | <Server:keepalive> <state_invite_merged_accepted> \
    | <Server:rep_stray> <state_invite_merged_accepted> \
    | <Server:rep_stray_pending> <state_invite_merged_accepted> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_merged_accepted>
<state_merged_reply_pending_confirmed> ::= <Server:rep_invite_merged_1xx> <state_merged_reply_pending_confirmed> \
    | <Server:rep_invite_merged_final> <Client:req_ack_failure> <state_confirmed> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_merged_reply_pending_confirmed> \
    | <Server:rep_stray> <state_merged_reply_pending_confirmed> \
    | <Server:rep_stray_pending> <state_merged_reply_pending_confirmed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_merged_reply_pending_confirmed>
# the first INVITE got a 300-699 reply while the merged one is pending
<state_invite_merged_first_completed> ::= <Client:req_ack_failure> <state_merged_reply_pending> \
    | <Server:rep_invite_merged_1xx> <state_invite_merged_first_completed> \
    | <Server:rep_invite_merged_final> <state_invite_merged_two_acks> \
    | <Server:keepalive> <state_invite_merged_first_completed> \
    | <Server:rep_stray> <state_invite_merged_first_completed> \
    | <Server:rep_stray_pending> <state_invite_merged_first_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_merged_first_completed>
# both INVITEs got their final reply before the ACKs went out: two ACKs due,
# the earlier reply's first
<state_invite_merged_two_acks> ::= <Client:req_ack_failure> <state_invite_completed> \
    | <Server:keepalive> <state_invite_merged_two_acks> \
    | <Server:rep_stray> <state_invite_merged_two_acks>
# a 2xx and the merged INVITE's 300-699 reply both due for an ACK
<state_invite_merged_completed_accepted> ::= <Client:req_ack_failure> <state_invite_accepted> \
    | <Server:keepalive> <state_invite_merged_completed_accepted> \
    | <Server:rep_stray> <state_invite_merged_completed_accepted>
<state_invite_merged_accepted_completed> ::= <Client:req_ack_2xx> <state_invite_merged_completed_confirmed> \
    | <Server:keepalive> <state_invite_merged_accepted_completed> \
    | <Server:rep_stray> <state_invite_merged_accepted_completed>
<state_invite_merged_completed_confirmed> ::= <Client:req_ack_failure> <state_confirmed> \
    | <Server:keepalive> <state_invite_merged_completed_confirmed> \
    | <Server:rep_stray> <state_invite_merged_completed_confirmed>
<state_merged_reply_pending> ::= <Server:rep_invite_merged_1xx> <state_merged_reply_pending> \
    | <Server:rep_invite_merged_final> <state_invite_completed> \
    | <Server:rep_stray> <state_merged_reply_pending> \
    | <Server:rep_stray_pending> <state_merged_reply_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_merged_reply_pending>

# §15.1.1, §15.1.2: BYE for the early dialog and the INVITE both pending;
# the UAS answers the BYE and (RECOMMENDED) ends the INVITE with 487
<state_invite_early_bye> ::= <Server:rep_invite_1xx> <state_invite_early_bye> \
    | <Client:req_retransmit> <state_invite_early_bye> \
    | <Server:rep_bye_1xx> <state_invite_early_bye> \
    | <Server:rep_bye_final> <state_invite_cancel_answered> \
    | <Server:rep_bye_challenge> <state_invite_cancel_answered> \
    | <Server:rep_invite_redirect> <state_invite_completed_bye_pending> \
    | <Server:rep_invite_use_proxy> <state_invite_completed_bye_pending> \
    | <Server:rep_invite_failure> <state_invite_completed_bye_pending> \
    | <Server:rep_invite_challenge> <state_invite_completed_bye_pending> \
    | <Server:rep_invite_2xx> <state_invite_accepted_bye_pending> \
    | <Server:rep_stray_other> <state_invite_early_bye> \
    | <Server:rep_stray_pending> <state_invite_early_bye> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_early_bye>
# the INVITE got its final reply before the BYE's reply came
<state_invite_completed_bye_pending> ::= <Client:req_ack_failure> <state_bye_reply_pending> \
    | <Client:req_retransmit> <state_invite_completed_bye_pending> \
    | <Server:rep_bye_1xx> <state_invite_completed_bye_pending> \
    | <Server:rep_bye_final> <state_invite_completed> \
    | <Server:rep_bye_challenge> <state_invite_completed> \
    | <Server:keepalive> <state_invite_completed_bye_pending> \
    | <Server:rep_stray_other> <state_invite_completed_bye_pending> \
    | <Server:rep_stray_pending> <state_invite_completed_bye_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_completed_bye_pending>
<state_invite_accepted_bye_pending> ::= <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_invite_accepted_bye_pending> \
    | <Client:req_retransmit> <state_invite_accepted_bye_pending> \
    | <Client:req_ack_2xx> <state_bye_reply_pending> \
    | <Server:rep_bye_1xx> <state_invite_accepted_bye_pending> \
    | <Server:rep_bye_final> <state_invite_accepted> \
    | <Server:rep_bye_challenge> <state_invite_accepted> \
    | <Server:keepalive> <state_invite_accepted_bye_pending> \
    | <Server:rep_stray_other> <state_invite_accepted_bye_pending> \
    | <Server:rep_stray_pending> <state_invite_accepted_bye_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_accepted_bye_pending>
# the INVITE has ended, the BYE's reply is still due (§15: the BYE ends the
# dialog, also one a late 2xx confirmed); every further 2xx is ACKed again
<state_bye_reply_pending> ::= <Server:rep_bye_1xx> <state_bye_reply_pending> \
    | <Client:req_retransmit> <state_bye_reply_pending> \
    | <Server:rep_bye_final> <state_idle_or_end> \
    | <Server:rep_bye_challenge> <state_idle_or_end> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_bye_reply_pending> \
    | <Server:rep_stray_other> <state_bye_reply_pending> \
    | <Server:rep_stray_pending> <state_bye_reply_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_bye_reply_pending>

# RFC 6026 §7.2 Accepted: 2xx received (and retransmitted by the UAS core
# until the ACK, §13.3.1.4); §13.2.2.4 the end-to-end ACK confirms the dialog;
# every further 2xx (retransmission or another fork's) gets its own ACK at
# once (the k-th ACK answers the k-th 2xx, so one ACK stays due)
<state_invite_accepted> ::= <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_invite_accepted> \
    | <Client:req_ack_2xx> <state_confirmed> \
    | <Server:keepalive> <state_invite_accepted> \
    | <Server:rep_stray> <state_invite_accepted> \
    | <Server:rep_stray_pending> <state_invite_accepted> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_accepted>

# §17.1.1.2 Completed: a 300-699 final reply, ACKed hop by hop (§17.1.1.3);
# over UDP the server transaction repeats the final reply until the ACK
# comes (§17.2.1 Timer G), and every repetition is ACKed again
<rep_invite_final_again> ::= (<status_3xx> | <status_4xx_no_challenge> | <status_challenge> | <status_5xx> \
    | <status_6xx>) <reply_invite>
<state_invite_completed> ::= <Client:req_ack_failure> <state_invite_acked> | <Server:keepalive> <state_invite_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_completed> \
    | <Server:rep_stray> <state_invite_completed> \
    | <Server:rep_stray_pending> <state_invite_completed>
# §17.1.1.2 Completed after the ACK (Timer D, at least 32 s over UDP):
# every further repetition of the final reply (the server's Timer G copy
# that crossed the ACK) passes the ACK to the transport again; §17.2.1
# Confirmed: the server absorbs these ACKs and sends nothing for them.
# Over TCP Timer D is 0 and no repetition comes (where final_retransmitted)
<state_invite_acked> ::= <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_acked> \
    | <state_idle_or_end>
<state_invite_challenge_completed> ::= <Client:req_ack_failure> <state_invite_challenged> \
    | <Server:keepalive> <state_invite_challenge_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_challenge_completed> \
    | <Server:rep_stray> <state_invite_challenge_completed> \
    | <Server:rep_stray_pending> <state_invite_challenge_completed>
# §8.1.3.4: after a 3xx the client may recurse on a Contact of the reply
<state_invite_redirect_completed> ::= <Client:req_ack_failure> <state_invite_redirected> \
    | <Server:keepalive> <state_invite_redirect_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_redirect_completed> \
    | <Server:rep_stray> <state_invite_redirect_completed> \
    | <Server:rep_stray_pending> <state_invite_redirect_completed>

# §21.3.4: after 305 (Use Proxy) the client may repeat the INVITE through the
# proxy the Contact names (same Request-URI, the proxy as route)
<state_invite_use_proxy_completed> ::= <Client:req_ack_failure> <state_invite_use_proxy> \
    | <Server:keepalive> <state_invite_use_proxy_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_use_proxy_completed> \
    | <Server:rep_stray> <state_invite_use_proxy_completed> \
    | <Server:rep_stray_pending> <state_invite_use_proxy_completed>
<state_invite_use_proxy> ::= <Client:req_invite_via_proxy> <retransmissions_invite> <state_invite_calling> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_use_proxy> \
    | <state_idle_or_end>

# §22.2/§22.3: after a challenge the INVITE may be sent again with credentials
<state_invite_challenged> ::= <Client:req_invite_auth> <retransmissions_invite> <state_invite_calling> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_challenged> \
    | <state_idle_or_end>
# §8.1.3.4: a new INVITE to a URI of the target set, or give up
<state_invite_redirected> ::= <Client:req_invite_redirected> <retransmissions_invite> <state_invite_calling> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_redirected> \
    | <state_idle_or_end>

# §9.1/§9.2: CANCEL sent, neither its reply nor the INVITE's final reply
# came; RFC 4320 §4.1 a 100 may answer the CANCEL first
<state_invite_cancelling> ::= <Server:rep_invite_1xx> <state_invite_cancelling> \
    | <Client:req_retransmit> <state_invite_cancelling> \
    | <Server:rep_cancel_100> <state_invite_cancelling> \
    | <Server:rep_cancel_final> <state_invite_cancel_answered> \
    | <Server:rep_invite_redirect> <state_invite_completed_cancel_pending> \
    | <Server:rep_invite_use_proxy> <state_invite_completed_cancel_pending> \
    | <Server:rep_invite_failure> <state_invite_completed_cancel_pending> \
    | <Server:rep_invite_challenge> <state_invite_completed_cancel_pending> \
    | <Server:rep_invite_2xx> <state_invite_accepted_cancel_pending> \
    | <Server:rep_stray> <state_invite_cancelling> \
    | <Server:rep_stray_pending> <state_invite_cancelling> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_cancelling>

# §9.2: CANCEL answered, the INVITE ends with 487 (or the 2xx won the race)
<state_invite_cancel_answered> ::= <Server:rep_invite_1xx> <state_invite_cancel_answered> \
    | <Server:rep_invite_redirect> <state_invite_completed> \
    | <Server:rep_invite_use_proxy> <state_invite_completed> \
    | <Server:rep_invite_failure> <state_invite_completed> \
    | <Server:rep_invite_challenge> <state_invite_completed> \
    | <Server:rep_invite_2xx> <state_invite_accepted> \
    | <Server:rep_stray> <state_invite_cancel_answered> \
    | <Server:rep_stray_pending> <state_invite_cancel_answered> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_cancel_answered>

# §9.2: the INVITE got its final reply before the CANCEL's reply came
<state_invite_completed_cancel_pending> ::= <Client:req_ack_failure> <state_cancel_reply_pending> \
    | <Client:req_retransmit> <state_invite_completed_cancel_pending> \
    | <Server:rep_cancel_100> <state_invite_completed_cancel_pending> \
    | <Server:rep_cancel_final> <state_invite_completed> \
    | <Server:keepalive> <state_invite_completed_cancel_pending> \
    | <Server:rep_stray> <state_invite_completed_cancel_pending> \
    | <Server:rep_stray_pending> <state_invite_completed_cancel_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_completed_cancel_pending>
<state_invite_accepted_cancel_pending> ::= <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_invite_accepted_cancel_pending> \
    | <Client:req_retransmit> <state_invite_accepted_cancel_pending> \
    | <Client:req_ack_2xx> <state_cancel_reply_pending_in_dialog> \
    | <Server:rep_cancel_100> <state_invite_accepted_cancel_pending> \
    | <Server:rep_cancel_final> <state_invite_accepted> \
    | <Server:keepalive> <state_invite_accepted_cancel_pending> \
    | <Server:rep_stray> <state_invite_accepted_cancel_pending> \
    | <Server:rep_stray_pending> <state_invite_accepted_cancel_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_invite_accepted_cancel_pending>

# §9.2: the INVITE has ended, the CANCEL's own reply is still due;
# §13.2.2.4 every further 2xx is ACKed again
<state_cancel_reply_pending> ::= <Server:rep_cancel_100> <state_cancel_reply_pending> \
    | <Client:req_retransmit> <state_cancel_reply_pending> \
    | <Server:rep_cancel_final> <state_idle_or_end> \
    | <Server:rep_stray> <state_cancel_reply_pending> \
    | <Server:rep_stray_pending> <state_cancel_reply_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_cancel_reply_pending>
<state_cancel_reply_pending_in_dialog> ::= <Server:rep_cancel_100> <state_cancel_reply_pending_in_dialog> \
    | <Client:req_retransmit> <state_cancel_reply_pending_in_dialog> \
    | <Server:rep_cancel_final> <state_confirmed> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_cancel_reply_pending_in_dialog> \
    | <Server:rep_stray> <state_cancel_reply_pending_in_dialog> \
    | <Server:rep_stray_pending> <state_cancel_reply_pending_in_dialog> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_cancel_reply_pending_in_dialog>

# §12.2, §14 (re-INVITE), §15.1.1 (BYE), §11 (OPTIONS inside a dialog);
# §13.2.2.4 a 2xx retransmission (or the 2xx of another fork) that arrives
# after our ACK is ACKed again; §15.1.2 the callee ends the dialog
<state_confirmed> ::= <exch_bye> <state_idle_or_end> \
    | <exch_reinvite> <state_confirmed> \
    | <exch_options_dialog> <state_confirmed> \
    | <exch_extension_dialog> <state_confirmed> \
    | <exch_options_dialog_out_of_order> <state_confirmed> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_confirmed> \
    | <exch_bye_from_server> <state_idle_or_end> \
    | <exch_bye_from_server_refused> <state_confirmed> \
    | <exch_reinvite_from_server> <state_confirmed> \
    | <exch_reinvite_from_server_refused> <state_confirmed> \
    | <exch_options_from_server> <state_confirmed> \
    | <exch_extension_from_server> <state_confirmed> \
    | <Client:req_bye_fork> <state_fork_bye_pending> \
    | <Server:keepalive> <state_confirmed> \
    | <Server:rep_stray> <state_confirmed> \
    | <Server:rep_stray_in_dialog> <state_confirmed>

# §13.2.2.4: the dialog of a further fork's 2xx (another To tag) is not
# continued: after its ACK the client ends it with BYE (where fork_unended:
# only while such a dialog is not ended; the client's own BYE of the dialog
# it continues comes after); the BYE's replies end it
<state_fork_bye_pending> ::= <Server:rep_bye_1xx> <state_fork_bye_pending> \
    | <Client:req_retransmit> <state_fork_bye_pending> \
    | <Server:rep_bye_final> <state_confirmed> \
    | <Server:rep_bye_challenge> <state_confirmed> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_fork_bye_pending> \
    | <Server:rep_stray_other> <state_fork_bye_pending> \
    | <Server:rep_stray_pending> <state_fork_bye_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_failure> <state_fork_bye_pending>

########################################################################
# Exchanges (transactions, §17; RFC 6026 §7)
########################################################################

# Trying / Proceeding of a non-INVITE exchange (§17.1.2.2): provisional
# replies (RFC 4320 §4.1: 100 only) and RFC 6026 §8.9 stray
# responses (where stray_reply; the exchange's own replies answer a waiting
# request, where answers_pending), e.g. a Timer G repetition of an INVITE's
# final reply that crossed the ACK, or the repeated final of an earlier
# request; in a dialog a 2xx retransmission of the INVITE is ACKed again
# (§13.2.2.4); §7.5 a keep-alive
<pending_options> ::= <Server:rep_options_1xx> | <Server:rep_stray> | <Server:rep_stray_invite> | <Server:keepalive>
<pending_register> ::= <Server:rep_register_1xx> | <Server:rep_stray> | <Server:rep_stray_invite> | <Server:keepalive>
<pending_extension> ::= <Server:rep_extension_1xx> | <Server:rep_stray> | <Server:rep_stray_invite> | <Server:keepalive>
<pending_bye_no_dialog> ::= <Server:rep_bye_1xx> | <Server:rep_stray> | <Server:rep_stray_invite> | <Server:keepalive>
<pending_cancel> ::= <Server:rep_cancel_100> | <Server:rep_stray> | <Server:rep_stray_invite> | <Server:keepalive>
<pending_options_dialog> ::= <Server:rep_options_1xx> | <Server:rep_stray> | <Server:rep_stray_in_dialog> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> | <Server:keepalive>
<pending_extension_dialog> ::= <Server:rep_extension_1xx> | <Server:rep_stray> | <Server:rep_stray_in_dialog> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> | <Server:keepalive>
<pending_bye> ::= <Server:rep_bye_1xx> | <Server:rep_stray> | <Server:rep_stray_in_dialog> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> | <Server:keepalive>

# §17.1.1.2 Timer A, §17.1.2.2 Timer E, §17.1.3/§18.1.1: over UDP the client
# transaction passes its request to the transport again, byte for byte (same
# branch, CSeq, everything), while no final reply has come: an INVITE in
# Calling (until a provisional or final reply) after T1, 2*T1, 4*T1, ... (6
# copies before Timer B = 64*T1), a non-INVITE request (CANCEL and BYE
# included) in Trying after T1, 2*T1, ... capped at T2 and in Proceeding
# every T2 (10 copies before Timer F = 64*T1); T1 = 500 ms, T2 = 4 s
# (§17.1.1.1 Table 4).  Over a reliable transport (TCP) there are no
# retransmissions (§17.1.1.2 "If an unreliable transport is being used"):
# the slot then only waits for the reply, and if the timer fires first it
# carries a bare CRLF, which §7.5 makes the receiver ignore.  The where retransmission_due waits until the copy is due or a reply
# arrives (Fandango then drops the copy and takes the reply).  A CANCEL or
# BYE sent inside the INVITE states stays in Trying / Proceeding while the
# INVITE's replies come: every state where it is pending has the self-loop
# '<Client:req_retransmit> <same state>' (Timer E, every T2 after its 100);
# after Timer F (or 10 copies) and over TCP the loop only waits for the
# server (a CRLF keep-alive if it stays silent for 20 s), and where an ACK
# is due a copy goes out only if it is due already (the ACK is sent at once).  The server's
# reactions to a copy (§17.2.1 Proceeding: the latest provisional again,
# Completed: the final again, which the client ACKs again (Timer D, the
# <rep_invite_final_again> loops), RFC 6026 §7.1 Accepted and §17.2.2
# Trying: nothing; §17.2.2 Proceeding/Completed: the latest reply again,
# absorbed by the client's Completed state as <rep_stray>, §17.1.2.2 Timer
# K) are replies the waiting states accept.
<req_retransmit> ::= <copied_request> | <stream_padding>
<copied_request> ::= <copy_line>+ '\r\n' <body_octet>*
<copy_line> ::= r'[^\r\n]+\r\n'
# §7.5: over a stream a CRLF before a start line is ignored by the receiver;
# it stands for the copy over TCP when the timer fires (no retransmission
# over a reliable transport, §17.1.1.2, §17.1.2.2)
<stream_padding> ::= '\r\n'
<retransmissions_invite> ::= <Client:req_retransmit>{0,6}
<retransmission_bye> ::= <Client:req_retransmit> <pending_bye>*
<retransmission_bye_no_dialog> ::= <Client:req_retransmit> <pending_bye_no_dialog>*
<retransmission_cancel> ::= <Client:req_retransmit> <pending_cancel>*
<retransmission_extension> ::= <Client:req_retransmit> <pending_extension>*
<retransmission_extension_dialog> ::= <Client:req_retransmit> <pending_extension_dialog>*
<retransmission_options> ::= <Client:req_retransmit> <pending_options>*
<retransmission_options_dialog> ::= <Client:req_retransmit> <pending_options_dialog>*
<retransmission_register> ::= <Client:req_retransmit> <pending_register>*

# §11 OPTIONS outside a dialog; §22.2/§22.3 challenge answered once;
# RFC 4320 §4.1 provisional replies to non-INVITE requests are 100 only
<exch_options> ::= <Client:req_options> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final_direct> | <Server:rep_options_redirect> <exch_options_redirected>? | <Server:rep_options_use_proxy> <exch_options_via_proxy>? | <Server:rep_options_challenge> \
     (<Client:req_options_auth> <pending_options>* <retransmission_options>{0,10} \
      (<Server:rep_options_final_direct> | <Server:rep_options_redirect> <exch_options_redirected>? | <Server:rep_options_use_proxy> <exch_options_via_proxy>? | <Server:rep_options_challenge>))?)
# §8.1.3.4: after a 3xx the client may send the request again to the first
# Contact URI not tried (new branch, CSeq one higher, same Call-ID, From, To)
<exch_options_redirected> ::= <Client:req_options_redirected> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final_direct> | <Server:rep_options_redirect> <exch_options_redirected>? \
     | <Server:rep_options_use_proxy> <exch_options_via_proxy>? | <Server:rep_options_challenge>)
# §21.3.4: after a 305 the client may repeat the request through the proxy the
# Contact names (same Request-URI, the proxy as route, new branch, CSeq one
# higher); a further 3xx or 305 may be followed again (§8.1.3.4)
<exch_options_via_proxy> ::= <Client:req_options_via_proxy> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final_direct> | <Server:rep_options_redirect> <exch_options_redirected>? \
     | <Server:rep_options_use_proxy> <exch_options_via_proxy>? | <Server:rep_options_challenge>)

# §18.3 (message-oriented transports, over UDP; over TCP the same requests
# go out without the flaw and the checks do not apply): bytes in the datagram
# beyond the end of the Content-Length-delimited body MUST be discarded, so
# the request is answered as without them (where extra_bytes_discarded: no
# 400); a datagram that ends before the end of the body is an error, a
# request SHOULD get 400 (where short_datagram_refused: no 2xx or 3xx final)
<exch_options_datagram_extra> ::= <Client:req_options_datagram_extra> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final_direct> | <Server:rep_options_redirect> | <Server:rep_options_use_proxy> \
     | <Server:rep_options_challenge>)
<exch_options_datagram_short> ::= <Client:req_options_datagram_short> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final_direct> | <Server:rep_options_challenge>)

# §8.2.2.3 a UAS must refuse an option tag it does not understand with 420
<exch_options_require> ::= <Client:req_options_require> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_420> | <Server:rep_options_challenge> \
     (<Client:req_options_require_auth> <pending_options>* <retransmission_options>{0,10} (<Server:rep_options_420> | <Server:rep_options_challenge>))?)

# §16.3 step 5, §20.29: a proxy refuses an unknown Proxy-Require option tag
# with 420 (before it authorizes, §16.3 step 6); a UAS ignores the field
<exch_options_proxy_require> ::= <Client:req_options_proxy_require> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final> | <Server:rep_options_challenge> \
     (<Client:req_options_proxy_require_auth> <pending_options>* <retransmission_options>{0,10} (<Server:rep_options_final> | <Server:rep_options_challenge>))?)

# §8.2.3: a body of a type or content coding the UAS does not understand,
# not marked optional, is refused with 415 (Accept / Accept-Encoding);
# §20.11 a body with handling=optional may be ignored
<exch_options_unknown_type> ::= <Client:req_options_unknown_type> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final> | <Server:rep_options_challenge> \
     (<Client:req_options_unknown_type_auth> <pending_options>* <retransmission_options>{0,10} (<Server:rep_options_final> | <Server:rep_options_challenge>))?)
<exch_options_unknown_encoding> ::= <Client:req_options_unknown_encoding> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final> | <Server:rep_options_challenge> \
     (<Client:req_options_unknown_encoding_auth> <pending_options>* <retransmission_options>{0,10} (<Server:rep_options_final> | <Server:rep_options_challenge>))?)
<exch_options_optional_body> ::= <Client:req_options_optional_body> <pending_options>* <retransmission_options>{0,10} \
    (<Server:rep_options_final> | <Server:rep_options_challenge> \
     (<Client:req_options_optional_body_auth> <pending_options>* <retransmission_options>{0,10} (<Server:rep_options_final> | <Server:rep_options_challenge>))?)

# §10.2 REGISTER (add, refresh, remove one, remove all, fetch bindings)
<exch_register> ::= <Client:req_register> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_final_direct> | <Server:rep_register_redirect> <exch_register_redirected>? | <Server:rep_register_use_proxy> <exch_register_via_proxy>? | <Server:rep_register_challenge> \
     (<Client:req_register_auth> <pending_register>* <retransmission_register>{0,10} \
      (<Server:rep_register_final_direct> | <Server:rep_register_redirect> <exch_register_redirected>? | <Server:rep_register_use_proxy> <exch_register_via_proxy>? | <Server:rep_register_challenge>))?)
# §8.1.3.4: after a 3xx the client may send the request again to the first
# Contact URI not tried (new branch, CSeq one higher, same Call-ID, From, To)
<exch_register_redirected> ::= <Client:req_register_redirected> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_final_direct> | <Server:rep_register_redirect> <exch_register_redirected>? \
     | <Server:rep_register_use_proxy> <exch_register_via_proxy>? | <Server:rep_register_challenge>)
# §21.3.4: after a 305 the client may repeat the request through the proxy the
# Contact names (same Request-URI, the proxy as route, new branch, CSeq one
# higher); a further 3xx or 305 may be followed again (§8.1.3.4)
<exch_register_via_proxy> ::= <Client:req_register_via_proxy> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_final_direct> | <Server:rep_register_redirect> <exch_register_redirected>? \
     | <Server:rep_register_use_proxy> <exch_register_via_proxy>? | <Server:rep_register_challenge>)

# §10.3 step 6: "*" with an expiration other than zero, or with further
# Contact values, gets 400
<exch_register_bad_wildcard> ::= <Client:req_register_bad_wildcard> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_400> | <Server:rep_register_challenge> \
     (<Client:req_register_bad_wildcard_auth> <pending_register>* <retransmission_register>{0,10} (<Server:rep_register_400> | <Server:rep_register_challenge>))?)
<exch_register_star_with_binding> ::= <Client:req_register_star_with_binding> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_400> | <Server:rep_register_challenge> \
     (<Client:req_register_star_with_binding_auth> <pending_register>* <retransmission_register>{0,10} (<Server:rep_register_400> | <Server:rep_register_challenge>))?)

# §10.3 step 7: an update with a CSeq not higher than the stored binding's
# fails (the retry with credentials is one higher, still not higher than
# the stored CSeq)
<exch_register_old_cseq> ::= <Client:req_register_old_cseq> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_final> | <Server:rep_register_challenge> \
     (<Client:req_register_old_cseq_auth> <pending_register>* <retransmission_register>{0,10} (<Server:rep_register_final> | <Server:rep_register_challenge>))?)

# §10.3 steps 4-5: a REGISTER for another address-of-record (SIP_UNKNOWN_USER):
# 404 if it is not valid for the domain, 403 if the user may not modify its
# bindings, or a third-party registration (step 4) the registrar allows;
# which one applies is the registrar's own data, so every final reply is
# accepted (the 2xx rules of step 8 still hold)
<exch_register_unknown_aor> ::= <Client:req_register_unknown_aor> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_final> | <Server:rep_register_challenge> \
     (<Client:req_register_unknown_aor_auth> <pending_register>* <retransmission_register>{0,10} (<Server:rep_register_final> | <Server:rep_register_challenge>))?)

# §10.2.6: a UA may register by multicast, to the well-known "all SIP
# servers" address sip.mcast.net (224.0.1.75); §18.1.1 the request carries
# maddr (the group) and ttl=1 in its Via; the registrar listening on the
# group answers like any registrar (§10.3), with a challenge first (§22)
<exch_register_multicast> ::= <Client:req_register_multicast> <pending_register>* <retransmission_register>{0,10} \
    (<Server:rep_register_final> | <Server:rep_register_challenge> \
     (<Client:req_register_multicast_auth> <pending_register>* <retransmission_register>{0,10} (<Server:rep_register_final> | <Server:rep_register_challenge>))?)

# §8.2.1 / §25.1 extension method; the UAS answers 405 or 501 if unsupported
<exch_extension> ::= <Client:req_extension> <pending_extension>* <retransmission_extension>{0,10} \
    (<Server:rep_extension_final_direct> | <Server:rep_extension_redirect> <exch_extension_redirected>? | <Server:rep_extension_use_proxy> <exch_extension_via_proxy>? | <Server:rep_extension_challenge> \
     (<Client:req_extension_auth> <pending_extension>* <retransmission_extension>{0,10} \
      (<Server:rep_extension_final_direct> | <Server:rep_extension_redirect> <exch_extension_redirected>? | <Server:rep_extension_use_proxy> <exch_extension_via_proxy>? | <Server:rep_extension_challenge>))?)
# §8.1.3.4: after a 3xx the client may send the request again to the first
# Contact URI not tried (new branch, CSeq one higher, same Call-ID, From, To)
<exch_extension_redirected> ::= <Client:req_extension_redirected> <pending_extension>* <retransmission_extension>{0,10} \
    (<Server:rep_extension_final_direct> | <Server:rep_extension_redirect> <exch_extension_redirected>? \
     | <Server:rep_extension_use_proxy> <exch_extension_via_proxy>? | <Server:rep_extension_challenge>)
# §21.3.4: after a 305 the client may repeat the request through the proxy the
# Contact names (same Request-URI, the proxy as route, new branch, CSeq one
# higher); a further 3xx or 305 may be followed again (§8.1.3.4)
<exch_extension_via_proxy> ::= <Client:req_extension_via_proxy> <pending_extension>* <retransmission_extension>{0,10} \
    (<Server:rep_extension_final_direct> | <Server:rep_extension_redirect> <exch_extension_redirected>? \
     | <Server:rep_extension_use_proxy> <exch_extension_via_proxy>? | <Server:rep_extension_challenge>)

# §15.1.2 / §12.2.2: a BYE that matches no dialog is refused (481, SHOULD)
<exch_bye_no_dialog> ::= <Client:req_bye_no_dialog> <pending_bye_no_dialog>* <retransmission_bye_no_dialog>{0,10} (<Server:rep_bye_final> | <Server:rep_bye_challenge>)

# §9.2: a CANCEL that matches no transaction is refused (481, SHOULD)
<exch_cancel_no_transaction> ::= <Client:req_cancel_no_transaction> <pending_cancel>* <retransmission_cancel>{0,10} <Server:rep_cancel_final>

# §15.1.1: BYE ends the dialog whatever the final reply; §22.2 a challenge
# is answered once with credentials
<exch_bye> ::= <Client:req_bye> <pending_bye>* <retransmission_bye>{0,10} \
    (<Server:rep_bye_final> | <Server:rep_bye_challenge> \
     (<Client:req_bye_auth> <pending_bye>* <retransmission_bye>{0,10} (<Server:rep_bye_final> | <Server:rep_bye_challenge>))?)

# §15.1.2: a BYE from the callee, answered 200 (§8.2.6.2 echoes)
<exch_bye_from_server> ::= <Server:srv_req_bye> <Client:resp_bye_from_server>
# §8.2.2.3: a BYE that requires an option tag (the client supports none)
# gets 420 listing the tags in Unsupported; §8.2.3, §20.11: one with a body
# of a type or content coding the client does not understand that is not
# marked optional gets 415 with Accept and Accept-Encoding; the dialog stays
<exch_bye_from_server_refused> ::= <Server:srv_req_bye> <Client:resp_from_server_refused>
# §14.2: a re-INVITE from the callee, answered 200 with a session description
# (§13.3.1.4: the 2xx is retransmitted until the ACK comes), confirmed by
# the callee's ACK (§13.2.2.4)
<exch_reinvite_from_server> ::= <Server:srv_req_reinvite> <Client:resp_reinvite_from_server>+ <Server:srv_req_ack>
# §8.2.2.3 (420), §8.2.3 (415) as for BYE; the failed re-INVITE changes
# nothing (§14.2), its ACK is hop by hop
<exch_reinvite_from_server_refused> ::= <Server:srv_req_reinvite> <Client:resp_from_server_refused> <Server:srv_req_ack>
# §11.2: OPTIONS from the callee inside the dialog, answered 200
<exch_options_from_server> ::= <Server:srv_req_options> <Client:resp_options_from_server>
# §8.2.1, §21.5.2: any other method from the callee (extensions such as INFO
# or UPDATE, not in refs/spec) is not implemented by this client: 501
<exch_extension_from_server> ::= <Server:srv_req_extension> <Client:resp_extension_from_server>

# §14.1, RFC 6141: re-INVITE, an INVITE client transaction inside the dialog
# (§17.1.1.2 Calling, Proceeding, RFC 6026 Accepted, Completed); 2xx gets an
# end-to-end ACK, others a hop-by-hop ACK; §22.2 a challenge is answered with
# credentials
<exch_reinvite> ::= <Client:req_reinvite> <retransmissions_invite> <state_reinvite_calling>
<exch_reinvite_auth> ::= <Client:req_reinvite_auth> <retransmissions_invite> <state_reinvite_calling>
# §14.2: a re-INVITE of the callee while ours is pending (glare) gets 491,
# acknowledged by the callee
<state_reinvite_calling> ::= <Server:rep_invite_1xx> <state_reinvite_proceeding> \
    | <Server:rep_invite_2xx> <state_reinvite_accepted> \
    | <Server:rep_invite_redirect> <state_reinvite_completed> \
    | <Server:rep_invite_use_proxy> <state_reinvite_completed> \
    | <Server:rep_invite_failure> <state_reinvite_completed> \
    | <Server:rep_invite_challenge> <state_reinvite_challenge_completed> \
    | <Server:srv_req_reinvite> <Client:resp_reinvite_491> <state_reinvite_glare> \
    | <Server:rep_stray> <state_reinvite_calling> \
    | <Server:rep_stray_pending> <state_reinvite_calling> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_calling>
# §9.1 CANCEL after a provisional reply; §14.2 a second re-INVITE while the
# first is pending (the UAS refuses it with 500 and Retry-After)
<state_reinvite_proceeding> ::= <Server:rep_invite_1xx> <state_reinvite_proceeding> \
    | <Server:rep_invite_2xx> <state_reinvite_accepted> \
    | <Server:rep_invite_redirect> <state_reinvite_completed> \
    | <Server:rep_invite_use_proxy> <state_reinvite_completed> \
    | <Server:rep_invite_failure> <state_reinvite_completed> \
    | <Server:rep_invite_challenge> <state_reinvite_challenge_completed> \
    | <Server:srv_req_reinvite> <Client:resp_reinvite_491> <state_reinvite_glare> \
    | <Client:req_cancel> <state_reinvite_cancelling> \
    | <Client:req_reinvite> <retransmissions_invite> <state_reinvite_overlap> \
    | <Server:keepalive> <state_reinvite_proceeding> \
    | <Server:rep_stray> <state_reinvite_proceeding> \
    | <Server:rep_stray_pending> <state_reinvite_proceeding> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_proceeding>
<state_reinvite_accepted> ::= <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_reinvite_accepted> \
    | <Client:req_ack_reinvite_2xx> \
    | <Server:keepalive> <state_reinvite_accepted> \
    | <Server:rep_stray> <state_reinvite_accepted> \
    | <Server:rep_stray_pending> <state_reinvite_accepted> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_accepted>
<state_reinvite_completed> ::= <Client:req_ack_reinvite_failure> <state_reinvite_acked> | <Server:keepalive> <state_reinvite_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_completed> \
    | <Server:rep_stray> <state_reinvite_completed> \
    | <Server:rep_stray_pending> <state_reinvite_completed>
<state_reinvite_challenge_completed> ::= <Client:req_ack_reinvite_failure> <state_reinvite_challenged> \
    | <Server:keepalive> <state_reinvite_challenge_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_challenge_completed> \
    | <Server:rep_stray> <state_reinvite_challenge_completed> \
    | <Server:rep_stray_pending> <state_reinvite_challenge_completed>
# §17.1.1.2 Completed after the ACK (Timer D) of a re-INVITE, as for the
# initial INVITE (<state_invite_acked>): every repetition of the final reply
# that crossed the ACK is ACKed again (where final_retransmitted: UDP only);
# then the dialog goes on
<state_reinvite_acked> ::= <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_acked> | ''
# §22.2: after a challenge to the re-INVITE, the re-INVITE with credentials
# or the dialog goes on; repetitions of the challenge are ACKed again
<state_reinvite_challenged> ::= <exch_reinvite_auth> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_challenged> | ''
# §14.2 glare: our re-INVITE pending, the callee's ACK for our 491 due
<state_reinvite_glare> ::= <Server:srv_req_ack> <state_reinvite_calling> \
    | <Server:rep_invite_1xx> <state_reinvite_glare> \
    | <Server:rep_invite_2xx> <Client:req_ack_reinvite_2xx> <state_reinvite_glare_acked> \
    | (<Server:rep_invite_redirect> | <Server:rep_invite_use_proxy> | <Server:rep_invite_failure> | <Server:rep_invite_challenge>) \
      <Client:req_ack_reinvite_failure> <Server:srv_req_ack> \
    | <Server:rep_stray> <state_reinvite_glare> \
    | <Server:rep_stray_pending> <state_reinvite_glare> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_glare>
# §14.2 glare: our re-INVITE ended with 2xx and is ACKed (every further 2xx
# ACKed again, §13.2.2.4), the callee's ACK for our 491 is due
<state_reinvite_glare_acked> ::= <Server:srv_req_ack> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_reinvite_glare_acked> \
    | <Server:rep_stray> <state_reinvite_glare_acked> \
    | <Server:rep_stray_pending> <state_reinvite_glare_acked> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_glare_acked>
# §14.2: two re-INVITEs pending; when one ends, the other is still pending
<state_reinvite_overlap> ::= <Server:rep_invite_1xx> <state_reinvite_overlap> \
    | <Server:rep_invite_2xx> <state_reinvite_overlap_accepted> \
    | (<Server:rep_invite_redirect> | <Server:rep_invite_use_proxy> | <Server:rep_invite_failure> | <Server:rep_invite_challenge>) \
      <state_reinvite_overlap_completed> \
    | <Server:rep_stray> <state_reinvite_overlap> \
    | <Server:rep_stray_pending> <state_reinvite_overlap> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_overlap>
<state_reinvite_overlap_accepted> ::= <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_reinvite_overlap_accepted> \
    | <Client:req_ack_reinvite_2xx> <state_reinvite_calling> \
    | <Server:keepalive> <state_reinvite_overlap_accepted> \
    | <Server:rep_stray> <state_reinvite_overlap_accepted> \
    | <Server:rep_stray_pending> <state_reinvite_overlap_accepted> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_overlap_accepted>
<state_reinvite_overlap_completed> ::= <Client:req_ack_reinvite_failure> <state_reinvite_calling> \
    | <Server:keepalive> <state_reinvite_overlap_completed> \
    | <Server:rep_stray> <state_reinvite_overlap_completed> \
    | <Server:rep_stray_pending> <state_reinvite_overlap_completed> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_overlap_completed>
# §9.1, RFC 6141 §3.8: the re-INVITE cancelled; it ends with 487, or with 2xx
# if it was (partly) executed; the CANCEL's own reply races with it
<state_reinvite_cancelling> ::= <Server:rep_invite_1xx> <state_reinvite_cancelling> \
    | <Client:req_retransmit> <state_reinvite_cancelling> \
    | <Server:rep_cancel_100> <state_reinvite_cancelling> \
    | <Server:rep_cancel_final> <state_reinvite_cancel_answered> \
    | <Server:rep_invite_redirect> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_invite_use_proxy> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_invite_failure> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_invite_challenge> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_invite_2xx> <state_reinvite_accepted_cancel_pending> \
    | <Server:rep_stray> <state_reinvite_cancelling> \
    | <Server:rep_stray_pending> <state_reinvite_cancelling> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_cancelling>
<state_reinvite_cancel_answered> ::= <Server:rep_invite_1xx> <state_reinvite_cancel_answered> \
    | <Server:rep_invite_redirect> <state_reinvite_completed> \
    | <Server:rep_invite_use_proxy> <state_reinvite_completed> \
    | <Server:rep_invite_failure> <state_reinvite_completed> \
    | <Server:rep_invite_challenge> <state_reinvite_completed> \
    | <Server:rep_invite_2xx> <state_reinvite_accepted> \
    | <Server:rep_stray> <state_reinvite_cancel_answered> \
    | <Server:rep_stray_pending> <state_reinvite_cancel_answered> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_cancel_answered>
<state_reinvite_completed_cancel_pending> ::= <Client:req_ack_reinvite_failure> <state_reinvite_cancel_reply_pending> \
    | <Client:req_retransmit> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_cancel_100> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_cancel_final> <state_reinvite_completed> \
    | <Server:keepalive> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_stray> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_stray_pending> <state_reinvite_completed_cancel_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_completed_cancel_pending>
<state_reinvite_accepted_cancel_pending> ::= <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_reinvite_accepted_cancel_pending> \
    | <Client:req_retransmit> <state_reinvite_accepted_cancel_pending> \
    | <Client:req_ack_reinvite_2xx> <state_reinvite_cancel_reply_pending_acked> \
    | <Server:rep_cancel_100> <state_reinvite_accepted_cancel_pending> \
    | <Server:rep_cancel_final> <state_reinvite_accepted> \
    | <Server:keepalive> <state_reinvite_accepted_cancel_pending> \
    | <Server:rep_stray> <state_reinvite_accepted_cancel_pending> \
    | <Server:rep_stray_pending> <state_reinvite_accepted_cancel_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_accepted_cancel_pending>
<state_reinvite_cancel_reply_pending> ::= <Server:rep_cancel_100> <state_reinvite_cancel_reply_pending> \
    | <Client:req_retransmit> <state_reinvite_cancel_reply_pending> \
    | <Server:rep_cancel_final> \
    | <Server:rep_stray> <state_reinvite_cancel_reply_pending> \
    | <Server:rep_stray_pending> <state_reinvite_cancel_reply_pending> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_cancel_reply_pending>
<state_reinvite_cancel_reply_pending_acked> ::= <Server:rep_cancel_100> <state_reinvite_cancel_reply_pending_acked> \
    | <Client:req_retransmit> <state_reinvite_cancel_reply_pending_acked> \
    | <Server:rep_cancel_final> \
    | <Server:rep_invite_2xx> <Client:req_ack_2xx_again> <state_reinvite_cancel_reply_pending_acked> \
    | <Server:rep_stray> <state_reinvite_cancel_reply_pending_acked> \
    | <Server:rep_stray_pending> <state_reinvite_cancel_reply_pending_acked> \
    | <Server:rep_invite_final_again> <Client:req_ack_reinvite_failure> <state_reinvite_cancel_reply_pending_acked>

# §11, §12.2.1.1: OPTIONS and extension methods inside the dialog
<exch_options_dialog> ::= <Client:req_options_dialog> <pending_options_dialog>* <retransmission_options_dialog>{0,10} \
    (<Server:rep_options_final> | <Server:rep_options_challenge>)
# §12.2.2: a request inside the dialog with a lower CSeq than the last one
# is out of order and refused with 500
<exch_options_dialog_out_of_order> ::= <Client:req_options_dialog_out_of_order> <pending_options_dialog>* <retransmission_options_dialog>{0,10} \
    <Server:rep_options_500>
<exch_extension_dialog> ::= <Client:req_extension_dialog> <pending_extension_dialog>* <retransmission_extension_dialog>{0,10} \
    (<Server:rep_extension_final> | <Server:rep_extension_challenge>)

########################################################################
# Requests the client sends (§7.1, §8.1.1, §25.1)
########################################################################

# §7.1 Request-Line; §8.1.1 mandatory To, From, CSeq, Call-ID, Max-Forwards, Via
<req_options> ::= 'OPTIONS' ' ' <ruri_options> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_contact>? <s_accept>? <s_optional_opt_reg> <s_content_length_zero> '\r\n'
<req_options_auth> ::= 'OPTIONS' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_contact>? <s_accept>? <s_optional_opt_reg> <s_credentials> <s_content_length_zero> '\r\n'
# §8.1.3.4 the OPTIONS again to a Contact URI of the 3xx (§19.1.5 its
# header fields one by one)
<req_options_redirected> ::= 'OPTIONS' ' ' <ruri_redirect> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_contact>? <s_accept>? <s_uri_headers_part> <s_content_length_zero> '\r\n'
# §18.3: the datagram holds the request (Content-Length 0) and further octets
<req_options_datagram_extra> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_content_length_zero> '\r\n' <datagram_extra>
<datagram_extra> ::= '' | <datagram_extra_text>
<datagram_extra_text> ::= r'[A-Za-z0-9]{8,32}'
# §18.3: Content-Length 16 more than the body the datagram holds
<req_options_datagram_short> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_content_type_name> ': text/plain\r\n' <s_content_length_body> '\r\n' <text_body>
<req_options_require> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_require_unknown> <s_content_length_zero> '\r\n'
<req_options_require_auth> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_require_unknown> <s_credentials> <s_content_length_zero> '\r\n'
# §20.29: Proxy-Require with an option tag no element knows, to a callee
# (a proxy forwards the request, a UAS answers it)
<req_options_proxy_require> ::= 'OPTIONS' ' ' <ruri_callee> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_callee> <s_callid_new> <s_cseq_options> \
    <s_proxy_require_unknown> <s_content_length_zero> '\r\n'
<req_options_proxy_require_auth> ::= 'OPTIONS' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_proxy_require_unknown> <s_credentials> <s_content_length_zero> '\r\n'
# §8.2.3, §7.4: a body of an unknown media type (handling required, the
# default, §20.11), an unknown content coding, or an unknown type marked
# handling=optional
<req_options_unknown_type> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_unknown_type_headers> '\r\n' <text_body>
<req_options_unknown_type_auth> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_credentials> <s_unknown_type_headers> '\r\n' <text_body>
<req_options_unknown_encoding> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_unknown_encoding_headers> '\r\n' <text_body>
<req_options_unknown_encoding_auth> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_credentials> <s_unknown_encoding_headers> '\r\n' <text_body>
<req_options_optional_body> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_new> <s_to_server> <s_callid_new> <s_cseq_options> \
    <s_optional_body_headers> '\r\n' <text_body>
<req_options_optional_body_auth> ::= 'OPTIONS' ' ' <ruri_server> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_credentials> <s_optional_body_headers> '\r\n' <text_body>
<req_options_dialog_out_of_order> ::= 'OPTIONS' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_options_lower> \
    <s_route_part> <s_content_length_zero> '\r\n'
<s_cseq_options_lower> ::= 'CSeq: ' <s_cseq_number_lower> ' OPTIONS\r\n'
<s_cseq_number_lower> ::= r'[0-9]{1,9}' := '1'
<req_options_dialog> ::= 'OPTIONS' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_options> \
    <s_route_part> <s_accept>? <s_optional_opt_reg> <s_content_length_zero> '\r\n'

# §10.2: Request-URI names the registrar's domain, To the address-of-record
# (another user's for a third-party registration), From the registering user
<req_register> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_aor> <s_to_register> <s_callid_register> <s_cseq_register> \
    <register_bindings> <s_optional_opt_reg> <s_content_length_zero> '\r\n'
<req_register_auth> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_aor> <s_to_same> <s_callid_register> <s_cseq_register> \
    <register_bindings> <s_optional_opt_reg> <s_credentials> <s_content_length_zero> '\r\n'
<req_options_via_proxy> ::= 'OPTIONS' ' ' <ruri_via_proxy> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_options> \
    <s_proxy_route_part> <s_contact>? <s_accept>? <s_content_length_zero> '\r\n'
<req_register_via_proxy> ::= 'REGISTER' ' ' <ruri_via_proxy> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_aor> <s_to_same> <s_callid_same> <s_cseq_register> \
    <s_proxy_route_part> <register_bindings> <s_content_length_zero> '\r\n'
<req_register_redirected> ::= 'REGISTER' ' ' <ruri_redirect> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_aor> <s_to_same> <s_callid_same> <s_cseq_register> \
    <register_bindings> <s_uri_headers_part> <s_content_length_zero> '\r\n'
<req_register_bad_wildcard> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_star> <s_expires_nonzero> <s_content_length_zero> '\r\n'
<req_register_bad_wildcard_auth> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_star> <s_expires_nonzero> <s_credentials> <s_content_length_zero> '\r\n'
<req_register_star_with_binding> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_star> <s_contact_binding> <s_expires_zero> <s_content_length_zero> '\r\n'
<req_register_star_with_binding_auth> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_star> <s_contact_binding> <s_expires_zero> <s_credentials> <s_content_length_zero> '\r\n'
<req_register_old_cseq> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register_old> \
    <s_contact_binding> <s_content_length_zero> '\r\n'
<req_register_old_cseq_auth> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_binding> <s_credentials> <s_content_length_zero> '\r\n'
<s_cseq_register_old> ::= 'CSeq: ' <s_cseq_number_old> ' REGISTER\r\n'
<s_cseq_number_old> ::= r'[0-9]{1,9}' := '1'
# §10.2.6, §18.1.1: the multicast REGISTER (UDP only; over TCP it is the
# unicast REGISTER to the registrar, see <ruri_multicast>)
<req_register_multicast> ::= 'REGISTER' ' ' <ruri_multicast> ' ' <sip_version> '\r\n' \
    <s_via_multicast> <s_max_forwards> <s_from_aor> <s_to_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_binding> <s_content_length_zero> '\r\n'
<req_register_multicast_auth> ::= 'REGISTER' ' ' <ruri_multicast> ' ' <sip_version> '\r\n' \
    <s_via_multicast> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_register> <s_cseq_register> \
    <s_contact_binding> <s_credentials> <s_content_length_zero> '\r\n'
<req_register_unknown_aor> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_unknown_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_binding> <s_content_length_zero> '\r\n'
<req_register_unknown_aor_auth> ::= 'REGISTER' ' ' <ruri_registrar> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards_70> <s_from_aor> <s_to_unknown_aor> <s_callid_register> <s_cseq_register> \
    <s_contact_binding> <s_credentials> <s_content_length_zero> '\r\n'
# §10.2.1 add or refresh (§10.2.4) one or two bindings, §10.2.2 remove one
# (expires 0) or all ("*" with Expires 0), §10.2.3 fetch (no Contact)
<register_bindings> ::= <reg_add> | <reg_add_two> | <reg_remove_one> | <reg_remove_all> | <reg_fetch>
<reg_add> ::= <s_contact_binding> <s_expires>?
<reg_add_two> ::= <s_contact_binding> <s_contact_binding_second> <s_expires>?
<reg_remove_one> ::= <s_contact_binding_expires_zero>
<reg_remove_all> ::= <s_contact_star> <s_expires_zero>
<reg_fetch> ::= <s_expires>?

# §8.1.1, §13.2.1: INVITE carries a Contact and the offer
<req_invite> ::= 'INVITE' ' ' <ruri_callee> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_new> <s_to_callee> <s_callid_new> <s_cseq_invite> \
    <s_contact> <s_allow>? <s_supported>? <s_optional_invite> <s_expires>? <s_offer_headers> '\r\n' <sdp_offer>
<req_invite_auth> ::= 'INVITE' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_invite> \
    <s_contact> <s_allow>? <s_supported>? <s_optional_invite> <s_expires>? <s_credentials> <s_offer_headers> '\r\n' <sdp_offer>
# §8.2.2.2: the pending INVITE again (Request-URI, From, To, Call-ID, CSeq,
# credentials) with a new branch, as a forking proxy would deliver it twice
<req_invite_merged> ::= 'INVITE' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_invite> \
    <s_contact> <s_credentials_same_part> <s_offer_headers> '\r\n' <sdp_offer>
# §8.1.3.4: a new INVITE to a Contact URI of a 3xx (whole URI without method
# parameter and headers; the headers become header fields), same To, From,
# Call-ID, new branch, CSeq one higher
<req_invite_redirected> ::= 'INVITE' ' ' <ruri_redirect> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_invite> \
    <s_contact> <s_uri_headers_part> <s_offer_headers> '\r\n' <sdp_offer>
<ruri_redirect> ::= <uri_text> := recall('remote_target')
# §21.3.4: after 305 the INVITE is repeated through the proxy the Contact
# names: the proxy as (loose or strict, §12.2.1.1) route to the same
# Request-URI; same To, From, Call-ID, new branch, CSeq one higher
<req_invite_via_proxy> ::= 'INVITE' ' ' <ruri_via_proxy> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_invite> \
    <s_proxy_route_part> <s_contact> <s_offer_headers> '\r\n' <sdp_offer>
<ruri_via_proxy> ::= <uri_text> := recall('remote_target')
<s_proxy_route_part> ::= '' | <s_route>
<s_uri_headers_part> ::= '' | <s_uri_header_field>+
<s_uri_header_field> ::= r'[A-Za-z][-A-Za-z0-9]*' ': ' r'[^\r\n]+' '\r\n'
# §14.1: re-INVITE inside the dialog, new version of the offer
<req_reinvite> ::= 'INVITE' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_invite> \
    <s_route_part> <s_contact> <s_allow>? <s_supported>? <s_optional_invite> <s_offer_headers> '\r\n' <sdp_offer>
<req_reinvite_auth> ::= 'INVITE' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_invite> \
    <s_route_part> <s_contact> <s_allow>? <s_supported>? <s_optional_invite> <s_credentials> <s_offer_headers> '\r\n' <sdp_offer>

# §17.1.1.3: ACK for a non-2xx final reply: Request-URI, Call-ID, From, CSeq
# number and the single Via of the INVITE, To of the reply
<req_ack_failure> ::= 'ACK' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via_same> <s_max_forwards> <s_from_same> <s_to_reply> <s_callid_same> <s_cseq_ack> \
    <s_route_part_same> <s_content_length_zero> '\r\n'
<req_ack_reinvite_failure> ::= 'ACK' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via_same> <s_max_forwards> <s_from_same> <s_to_reply> <s_callid_same> <s_cseq_ack> \
    <s_route_part_same> <s_content_length_zero> '\r\n'
# §13.2.2.4: ACK for 2xx, built like a request inside the dialog, same CSeq
# number, credentials of the INVITE
<req_ack_2xx> ::= 'ACK' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_ack> \
    <s_route_part> <s_credentials_same_part> <s_content_length_zero> '\r\n'
<req_ack_reinvite_2xx> ::= 'ACK' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_ack> \
    <s_route_part> <s_content_length_zero> '\r\n'
# §13.2.2.4: the ACK is passed to the transport again for every
# retransmission of its 2xx (same branch); a 2xx with another To tag (a
# forked dialog) gets its own ACK built from that 2xx
<req_ack_2xx_again> ::= 'ACK' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via_ack> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_ack> \
    <s_route_part> <s_credentials_same_part> <s_content_length_zero> '\r\n'

# §9.1: CANCEL copies Request-URI, Call-ID, To, From, CSeq number, the single
# Via and Route of the INVITE; no Require, no Proxy-Require
<req_cancel> ::= 'CANCEL' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via_same> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_cancel> \
    <s_route_part_same> <s_content_length_zero> '\r\n'
# §17.2.3, §9.2: a CANCEL equal to the INVITE's in Request-URI, Call-ID,
# From, To and CSeq number, but with a new branch, or with the INVITE's
# branch and another sent-by: it matches no transaction
<req_cancel_other_branch> ::= 'CANCEL' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_cancel> \
    <s_route_part_same> <s_content_length_zero> '\r\n'
<req_cancel_other_sent_by> ::= 'CANCEL' ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via_other_sent_by> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_cancel> \
    <s_route_part_same> <s_content_length_zero> '\r\n'
# §9.2: a CANCEL for a transaction the server does not know
<req_cancel_no_transaction> ::= 'CANCEL' ' ' <ruri_callee> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_new> <s_to_callee> <s_callid_new> <s_cseq_cancel> \
    <s_content_length_zero> '\r\n'

# §15.1.1: BYE inside the dialog; §22.2 again with credentials
<req_bye> ::= 'BYE' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_bye> \
    <s_route_part> <s_optional_bye> <s_content_length_zero> '\r\n'
# §15.1.1: BYE for an early dialog (§12.1.2: remote target the Contact of
# the 1xx, To with its tag, route set its reversed Record-Route; CSeq one
# higher than the INVITE's)
<req_bye_early> ::= 'BYE' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_bye> \
    <s_route_part> <s_optional_bye> <s_content_length_zero> '\r\n'
<req_bye_auth> ::= 'BYE' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_bye> \
    <s_route_part> <s_optional_bye> <s_credentials> <s_content_length_zero> '\r\n'
# §13.2.2.4: BYE for the dialog of a further fork (its To tag, Contact as
# remote target, reversed Record-Route; CSeq above the INVITE's)
<req_bye_fork> ::= 'BYE' ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_bye> \
    <s_route_part> <s_content_length_zero> '\r\n'
# §12.2.2: a BYE with a To tag that matches no dialog
<req_bye_no_dialog> ::= 'BYE' ' ' <ruri_callee> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_new> <s_to_callee_tagged> <s_callid_new> <s_cseq_bye> \
    <s_content_length_zero> '\r\n'

# §8.2.6.2: the reply to the callee's BYE copies its Via, From, To, Call-ID
# and CSeq (the To already has the tag of the dialog)
<resp_bye_from_server> ::= 'SIP/2.0 200 OK\r\n' <s_echo_via> <s_echo_from> <s_echo_to> <s_echo_call_id> \
    <s_echo_cseq> <s_content_length_zero> '\r\n'
<s_echo_via> ::= <s_via_name> ': ' <echo_via> '\r\n'
<echo_via> ::= r'[^\r\n]+' := recall('in_via')
<s_echo_from> ::= <s_from_name> ': ' <echo_from> '\r\n'
<echo_from> ::= r'[^\r\n]+' := recall('in_from')
<s_echo_to> ::= <s_to_name> ': ' <echo_to> '\r\n'
<echo_to> ::= r'[^\r\n]+' := recall('in_to')
<s_echo_call_id> ::= <s_callid_name> ': ' <echo_call_id> '\r\n'
<echo_call_id> ::= r'[^\r\n]+' := recall('in_call_id')
<s_echo_cseq> ::= 'CSeq: ' <echo_cseq> '\r\n'
<echo_cseq> ::= r'[0-9]{1,10} [A-Z]+' := recall('in_cseq')
# §13.3.1.4: the 2xx to the callee's re-INVITE carries our Contact and the
# answer (SDP, RFC 8866, not in refs/spec: the fixed-form <sdp_offer>);
# retransmissions repeat it unchanged
<resp_reinvite_from_server> ::= 'SIP/2.0 200 OK\r\n' <s_echo_via> <s_echo_from> <s_echo_to> <s_echo_call_id> \
    <s_echo_cseq> <s_contact> <s_allow>? <s_offer_headers> '\r\n' <sdp_offer>
# §14.2: 491 for the callee's re-INVITE that crosses our pending one
<resp_reinvite_491> ::= 'SIP/2.0 491 Request Pending\r\n' <s_echo_via> <s_echo_from> <s_echo_to> <s_echo_call_id> \
    <s_echo_cseq> <s_content_length_zero> '\r\n'
# §21.5.2: 501 for a method the client does not implement, §8.2.6.2 echoes
<resp_extension_from_server> ::= 'SIP/2.0 501 Not Implemented\r\n' <s_echo_via> <s_echo_from> <s_echo_to_tagged> \
    <s_echo_call_id> <s_echo_cseq> <s_allow> <s_content_length_zero> '\r\n'
<s_echo_to_tagged> ::= <s_to_name> ': ' <echo_to> '\r\n'
# §11.2: the 200 to OPTIONS lists what the client accepts and allows;
# §8.2.2.3 an OPTIONS that requires an option tag (the client supports none)
# gets 420 with the tags in Unsupported
<resp_options_from_server> ::= <resp_options_status> <s_echo_via> <s_echo_from> <s_echo_to> <s_echo_call_id> \
    <s_echo_cseq> <s_allow> <s_accept> <s_accept_encoding_all> <s_supported>? <s_unsupported_part> \
    <s_content_length_zero> '\r\n'
<resp_options_status> ::= <status_line_200> | <status_line_420> | <status_line_415>
<status_line_200> ::= 'SIP/2.0 200 OK\r\n'
<status_line_420> ::= 'SIP/2.0 420 Bad Extension\r\n'
<status_line_415> ::= 'SIP/2.0 415 Unsupported Media Type\r\n'
# §8.2.2.3 420 with Unsupported, §8.2.3 415 with Accept and Accept-Encoding
# (the codings the client understands), §8.2.6.2 echoes
<resp_from_server_refused> ::= <refusal_status> <s_echo_via> <s_echo_from> <s_echo_to> <s_echo_call_id> \
    <s_echo_cseq> <s_accept> <s_accept_encoding_all> <s_unsupported_part> <s_content_length_zero> '\r\n'
<refusal_status> ::= <status_line_420> | <status_line_415>
<s_accept_encoding_all> ::= 'Accept-Encoding: identity, gzip, deflate\r\n'
<s_unsupported_part> ::= '' | <s_unsupported>
<s_unsupported> ::= 'Unsupported: ' <echo_require> '\r\n'
<echo_require> ::= r'[^\r\n]+' := recall('in_require')

# §25.1 extension-method outside and inside a dialog
<req_extension> ::= <extension_method> ' ' <ruri_callee> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_new> <s_to_callee> <s_callid_new> <s_cseq_extension> \
    <s_contact>? <s_optional_common> <s_content_length_zero> '\r\n'
<req_extension_auth> ::= <extension_method_same> ' ' <ruri_same> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_extension> \
    <s_contact>? <s_optional_common> <s_credentials> <s_content_length_zero> '\r\n'
<req_extension_redirected> ::= <extension_method_same> ' ' <ruri_redirect> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_extension> \
    <s_contact>? <s_uri_headers_part> <s_content_length_zero> '\r\n'
<req_extension_via_proxy> ::= <extension_method_same> ' ' <ruri_via_proxy> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_same> <s_to_same> <s_callid_same> <s_cseq_extension> \
    <s_proxy_route_part> <s_contact>? <s_content_length_zero> '\r\n'
<req_extension_dialog> ::= <extension_method> ' ' <ruri_dialog> ' ' <sip_version> '\r\n' \
    <s_via> <s_max_forwards> <s_from_dialog> <s_to_dialog> <s_callid_same> <s_cseq_extension> \
    <s_route_part> <s_optional_common> <s_content_length_zero> '\r\n'
# §7.1, §25.1: Method = INVITEm / ACKm / ... / extension-method (a token);
# names of no RFC 3261 method
<extension_method> ::= r'X[A-Z0-9]{1,12}'
# §8.1.1.5: the CSeq method is the method of the Request-Line (and a retry
# repeats it)
<extension_method_same> ::= r'X[A-Z0-9]{1,12}' := recall('method')

# §7.1: SIP-Version "SIP/2.0" (case-insensitive)
<sip_version> ::= 'SIP/2.0'

########################################################################
# Sent Request-URIs (§19.1)
########################################################################

# §19.1.1 SIP-URI; target resources from the environment
<ruri_server> ::= 'sip:' <target_host> <s_port>?
<ruri_registrar> ::= 'sip:' <target_host> <s_port>?
# §10.2.6: multicast registrations are addressed to sip.mcast.net; a
# multicast request goes over UDP only (§18.1.1), so over TCP the generator
# gives the registrar's own URI
<ruri_multicast> ::= <ruri_mcast_net> | <ruri_registrar> := multicast_ruri()
<ruri_mcast_net> ::= 'sip:sip.mcast.net'
# §19.1.6, §7.1: OPTIONS may also name a telephone number, as tel: URI
# (another scheme, §8.2.2.1: 416 if unsupported) or as SIP URI with user=phone
<ruri_options> ::= <ruri_server> | <ruri_tel> | <ruri_phone>
<ruri_tel> ::= 'tel:' <tel_number>
<ruri_phone> ::= 'sip:' <tel_number> '@' <target_host> ';user=phone'
<tel_number> ::= '+' r'[1-9][0-9]{5,11}'
<ruri_callee> ::= 'sip:' <callee_user> '@' <target_host> <s_port>?
# §12.2.1.1: the remote target (Contact of the dialog-establishing reply);
# recalled from the reply, checked by a where
<ruri_dialog> ::= <uri_text> := recall('remote_target')
# §17.1.1.3, §9.1: the Request-URI of the request this one belongs to
<ruri_same> ::= <uri_text> := recall('request_uri')
<uri_text> ::= r'[a-zA-Z][a-zA-Z0-9+.-]*:[^\s<>"]+'
<target_host> ::= <s_host> := os.environ.get('SIP_SERVER_HOST', '127.0.0.1')
<s_port> ::= ':' <s_port_number>
<s_port_number> ::= r'[0-9]{1,5}' := os.environ.get('SIP_SERVER_PORT', '5060')
<s_host> ::= r'[a-zA-Z0-9.-]+'
# The callees the servers are configured with: answers, rings, busy, unknown
<callee_user> ::= <callee_answer> | <callee_ring> | <callee_busy> | <callee_unknown>
<callee_answer> ::= <s_user> := os.environ.get('SIP_ANSWER_USER', '100')
<callee_ring> ::= <s_user> := os.environ.get('SIP_RING_USER', '200')
<callee_busy> ::= <s_user> := os.environ.get('SIP_BUSY_USER', '300')
<callee_unknown> ::= <s_user> := os.environ.get('SIP_UNKNOWN_USER', '999')
<s_user> ::= r'[a-zA-Z0-9._~-]+'

########################################################################
# Sent header fields (§20), in a fixed order; values precise
########################################################################

# §20.42, §8.1.1.7: Via with the magic-cookie branch; §18.2.1 sent-by
<s_via> ::= <s_via_name> ': ' 'SIP/2.0/' <via_transport> ' ' <local_sent_by> ';branch=z9hG4bK' <s_branch> '\r\n'
<s_via_same> ::= <s_via_name> ': ' 'SIP/2.0/' <via_transport> ' ' <local_sent_by> ';branch=z9hG4bK' <s_branch_same> '\r\n'
# §17.2.3: the same branch with another sent-by (port) is another transaction
<s_via_other_sent_by> ::= <s_via_name> ': ' 'SIP/2.0/' <via_transport> ' ' <local_host> ':' <other_port> ';branch=z9hG4bK' <s_branch_same> '\r\n'
<other_port> ::= r'[0-9]{1,5}' := str(int(os.environ.get('SIP_LOCAL_PORT', '5070')) % 65535 + 1)
# §13.2.2.4: the branch of an ACK sent again for the same 2xx is the same
<s_via_ack> ::= <s_via_name> ': ' 'SIP/2.0/' <via_transport> ' ' <local_sent_by> ';branch=z9hG4bK' <s_branch_ack> '\r\n'
<s_branch_ack> ::= r'[a-zA-Z0-9]{8,24}' := new_token(16)
<s_via_name> ::= 'Via' | 'v'
# §18.1.1: a request sent to a multicast address carries the group in
# maddr and (IPv4) ttl=1 (§20.42); empty over TCP (no multicast)
<s_via_multicast> ::= <s_via_name> ': ' 'SIP/2.0/' <via_transport> ' ' <local_sent_by> ';branch=z9hG4bK' <s_branch> \
    <multicast_scope_part> '\r\n'
<multicast_scope_part> ::= <multicast_scope>{0,1} := multicast_scope()
<multicast_scope> ::= ';maddr=' <multicast_group> ';ttl=1'
<multicast_group> ::= <s_host>
# §18: the transport of the session, from the environment (SIP_TRANSPORT:
# TCP by default, or UDP; the driver's endpoint uses the same one)
<via_transport> ::= 'TCP' | 'UDP' := 'UDP' if os.environ.get('SIP_TRANSPORT', 'TCP').upper() == 'UDP' else 'TCP'
<local_sent_by> ::= <local_host> ':' <local_port>
<contact_transport> ::= 'tcp' | 'udp' := 'udp' if os.environ.get('SIP_TRANSPORT', 'TCP').upper() == 'UDP' else 'tcp'
<local_host> ::= <s_host> := os.environ.get('SIP_LOCAL_HOST', '127.0.0.1')
<local_port> ::= r'[0-9]{1,5}' := os.environ.get('SIP_LOCAL_PORT', '5070')
<s_branch> ::= r'[a-zA-Z0-9]{8,24}' := new_token(16)
<s_branch_same> ::= r'[a-zA-Z0-9]{8,24}' := recall('branch')

# §20.22 Max-Forwards (any value of 0-255 is legal; 70 is recommended)
<s_max_forwards> ::= 'Max-Forwards: ' <s_max_forwards_value> '\r\n'
<s_max_forwards_value> ::= '70' | r'[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]'
# the refusal exchanges use the recommended value, so that a proxy's 483 for
# an exhausted Max-Forwards (§16.3 step 3) cannot stand in for the refusal
<s_max_forwards_70> ::= 'Max-Forwards: 70\r\n'

# §20.20, §8.1.1.3: From with a new tag outside a dialog
<s_from_new> ::= <s_from_name> ': ' <s_display>? '<sip:' <local_user> '@' <local_domain> '>;tag=' <s_from_tag> '\r\n'
<s_from_aor> ::= <s_from_name> ': ' <s_display>? '<sip:' <local_user> '@' <local_domain> '>;tag=' <s_from_tag> '\r\n'
<s_from_same> ::= <s_from_name> ': ' <s_display>? '<sip:' <local_user> '@' <local_domain> '>;tag=' <s_from_tag_same> '\r\n'
<s_from_dialog> ::= <s_from_name> ': ' <s_display>? '<sip:' <local_user> '@' <local_domain> '>;tag=' <s_from_tag_same> '\r\n'
<s_from_name> ::= 'From' | 'f'
<s_from_tag> ::= r'[a-zA-Z0-9]{6,16}' := new_token(10)
<s_from_tag_same> ::= r'[a-zA-Z0-9]{6,16}' := recall('from_tag')
<s_display> ::= '"' r'[a-zA-Z0-9 ]{1,16}' '" ' | r'[a-zA-Z0-9]{1,12}' ' '
<local_user> ::= r'[a-z0-9]+' := 'alice'
<local_domain> ::= <s_host> := os.environ.get('SIP_SERVER_HOST', '127.0.0.1')

# §20.39, §8.1.1.2: To without tag outside a dialog
<s_to_server> ::= <s_to_name> ': ' '<sip:' <target_host> '>' '\r\n'
<s_to_callee> ::= <s_to_name> ': ' <s_display>? '<sip:' <callee_user> '@' <target_host> '>' '\r\n'
<s_to_callee_tagged> ::= <s_to_name> ': ' '<sip:' <callee_user> '@' <target_host> '>;tag=' <s_from_tag> '\r\n'
<s_to_aor> ::= <s_to_name> ': ' '<sip:' <local_user> '@' <local_domain> '>' '\r\n'
# §10.2: a third-party registration names another user's address-of-record
<s_to_register> ::= <s_to_aor> | <s_to_third_party>
<s_to_third_party> ::= <s_to_name> ': ' '<sip:' <third_party_user> '@' <local_domain> '>' '\r\n'
<third_party_user> ::= <s_user> := os.environ.get('SIP_THIRD_PARTY_USER', 'bob')
# §10.3 step 5: an address-of-record the registrar does not serve
<s_to_unknown_aor> ::= <s_to_name> ': ' '<sip:' <callee_unknown> '@' <local_domain> '>' '\r\n'
# §8.1.3.5, §9.1: the To of the request this one repeats or cancels
<s_to_same> ::= <s_to_name> ': ' <to_text_same> '\r\n'
<to_text_same> ::= r'[^\r\n]+' := recall('to')
# §17.1.1.3: the To of the reply being acknowledged
<s_to_reply> ::= <s_to_name> ': ' <to_text_reply> '\r\n'
<to_text_reply> ::= r'[^\r\n]+' := recall('reply_to')
# §12.2.1.1: remote URI and remote tag of the dialog
<s_to_dialog> ::= <s_to_name> ': ' <to_text_dialog> '\r\n'
<to_text_dialog> ::= r'[^\r\n]+' := recall('reply_to')
<s_to_name> ::= 'To' | 't'

# §20.8, §8.1.1.4: Call-ID, new and globally unique outside a dialog
<s_callid_new> ::= <s_callid_name> ': ' <s_callid_value> '\r\n'
<s_callid_value> ::= r'[a-zA-Z0-9]{8,32}' '@' <local_host> := new_token(20) + '@' + os.environ.get('SIP_LOCAL_HOST', '127.0.0.1')
<s_callid_same> ::= <s_callid_name> ': ' <s_callid_value_same> '\r\n'
<s_callid_value_same> ::= r'[a-zA-Z0-9]{8,32}@[a-zA-Z0-9.-]+' := recall('call_id')
# §10.2: one Call-ID for all registrations of this client
<s_callid_register> ::= <s_callid_name> ': ' <s_callid_value_register> '\r\n'
<s_callid_value_register> ::= r'[a-zA-Z0-9]{8,32}@[a-zA-Z0-9.-]+' := register_call_id()
<s_callid_name> ::= 'Call-ID' | 'i'

# §20.16, §8.1.1.5: CSeq number and the method of the Request-Line
<s_cseq_options> ::= 'CSeq: ' <s_cseq_number> ' OPTIONS\r\n'
<s_cseq_register> ::= 'CSeq: ' <s_cseq_number> ' REGISTER\r\n'
<s_cseq_invite> ::= 'CSeq: ' <s_cseq_number> ' INVITE\r\n'
<s_cseq_ack> ::= 'CSeq: ' <s_cseq_number> ' ACK\r\n'
<s_cseq_cancel> ::= 'CSeq: ' <s_cseq_number> ' CANCEL\r\n'
<s_cseq_bye> ::= 'CSeq: ' <s_cseq_number> ' BYE\r\n'
<s_cseq_extension> ::= 'CSeq: ' <s_cseq_number> ' ' <extension_method_same> '\r\n'
<s_cseq_number> ::= r'[0-9]{1,9}' := next_cseq()

# §20.10, §8.1.1.8: Contact, one SIP URI of this client
<s_contact> ::= <s_contact_name> ': ' '<sip:' <local_user> '@' <local_sent_by> ';transport=' <contact_transport> '>' '\r\n'
<s_contact_binding> ::= <s_contact_name> ': ' '<sip:' <local_user> '@' <local_sent_by> ';transport=' <contact_transport> '>' <s_contact_expires>? '\r\n'
<s_contact_binding_second> ::= <s_contact_name> ': ' '<sip:' <local_user> '-2@' <local_sent_by> ';transport=' <contact_transport> '>' <s_contact_expires>? '\r\n'
<s_contact_binding_expires_zero> ::= <s_contact_name> ': ' '<sip:' <local_user> '@' <local_sent_by> ';transport=' <contact_transport> '>;expires=0' '\r\n'
<s_contact_expires> ::= ';expires=' <s_delta_seconds>
<s_contact_star> ::= <s_contact_name> ': *\r\n'
<s_contact_name> ::= 'Contact' | 'm'

# §20.19 Expires
<s_expires> ::= 'Expires: ' <s_delta_seconds> '\r\n'
<s_expires_zero> ::= 'Expires: 0\r\n'
<s_expires_nonzero> ::= 'Expires: ' r'[1-9][0-9]{0,5}' '\r\n'
<s_delta_seconds> ::= r'[0-9]{1,6}'

# §20.34 Route: the route set of the dialog (§12.2.1.1, absent when empty),
# or the Route of the request an ACK or CANCEL belongs to (§9.1, §17.1.1.3)
<s_route_part> ::= '' | <s_route>
<s_route> ::= 'Route: ' <route_text> '\r\n'
<route_text> ::= r'<[^\r\n]+' := recall('route_set')
<s_route_part_same> ::= '' | <s_route_same>
<s_route_same> ::= 'Route: ' <route_text_same> '\r\n'
<route_text_same> ::= r'<[^\r\n]+' := recall('route_set')

# §20.32 Require with an option tag no server knows
<s_require_unknown> ::= 'Require: ' <unknown_option_tag> '\r\n'
# §20.29 Proxy-Require with an option tag no element knows
<s_proxy_require_unknown> ::= 'Proxy-Require: ' <unknown_option_tag> '\r\n'
<unknown_option_tag> ::= r'x-[a-z0-9]{4,10}'

# §20.1, §20.5, §20.37: capabilities
<s_accept> ::= 'Accept: application/sdp\r\n'
<s_allow> ::= 'Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n'
<s_supported> ::= <s_supported_name> ': ' '\r\n'
<s_supported_name> ::= 'Supported' | 'k'

# Optional header fields of Table 2/3 by method ("o" in the column of the
# method, "-" fields left out, §20), each at most once (§7.3.1: only
# comma-separated list fields may repeat).  INVITE: all of them
<s_optional_invite> ::= <s_user_agent>? <s_date>? <s_timestamp>? <s_organization>? <s_subject>? \
    <s_priority>? <s_accept_language>? <s_accept_encoding>? <s_call_info>? <s_alert_info>? <s_in_reply_to>? \
    <s_mime_version>?
# OPTIONS and REGISTER: no Subject, Priority, Alert-Info, In-Reply-To
<s_optional_opt_reg> ::= <s_user_agent>? <s_date>? <s_timestamp>? <s_organization>? <s_accept_language>? \
    <s_accept_encoding>? <s_call_info>? <s_mime_version>?
# BYE: no Organization, Call-Info either
<s_optional_bye> ::= <s_user_agent>? <s_date>? <s_timestamp>? <s_accept_language>? <s_accept_encoding>? \
    <s_mime_version>?
# extension methods (no column in the tables): the fields optional for every
# method
<s_optional_common> ::= <s_user_agent>? <s_date>? <s_timestamp>?
# §20.2 Accept-Encoding: content codings acceptable in the reply
<s_accept_encoding> ::= 'Accept-Encoding: ' <s_coding> (', ' <s_coding>)? '\r\n'
<s_coding> ::= <coding_identity> | <coding_gzip> | <coding_deflate>
<coding_identity> ::= 'identity'
<coding_gzip> ::= 'gzip'
<coding_deflate> ::= 'deflate'
# §20.41
<s_user_agent> ::= 'User-Agent: fandango-sip/' r'[0-9]\.[0-9]' '\r\n'
# §20.17: rfc1123-date in GMT
<s_date> ::= 'Date: ' <s_wkday> ', ' r'[0-2][0-9]|3[01]' ' ' <s_month> ' ' r'20[0-9][0-9]' ' ' r'[01][0-9]|2[0-3]' ':' r'[0-5][0-9]' ':' r'[0-5][0-9]' ' GMT\r\n'
<s_wkday> ::= 'Mon' | 'Tue' | 'Wed' | 'Thu' | 'Fri' | 'Sat' | 'Sun'
<s_month> ::= 'Jan' | 'Feb' | 'Mar' | 'Apr' | 'May' | 'Jun' | 'Jul' | 'Aug' | 'Sep' | 'Oct' | 'Nov' | 'Dec'
# §20.38 Timestamp
<s_timestamp> ::= 'Timestamp: ' r'[0-9]{1,10}' ('.' r'[0-9]{1,6}')? '\r\n'
# §20.25 Organization, §20.36 Subject
<s_organization> ::= 'Organization: ' r'[a-zA-Z0-9][a-zA-Z0-9 ]{0,20}' '\r\n'
<s_subject> ::= <s_subject_name> ': ' r'[a-zA-Z0-9][a-zA-Z0-9 ]{0,20}' '\r\n'
<s_subject_name> ::= 'Subject' | 's'
# §20.26, RFC 6878: Priority values
<s_priority> ::= 'Priority: ' (<prio_emergency> | <prio_urgent> | <prio_normal> | <prio_non_urgent>) '\r\n'
<prio_emergency> ::= 'emergency'
<prio_urgent> ::= 'urgent'
<prio_normal> ::= 'normal'
<prio_non_urgent> ::= 'non-urgent'
# §20.3 Accept-Language
<s_accept_language> ::= 'Accept-Language: ' ('en' | 'de' | 'fr;q=0.5') '\r\n'
# §20.9 Call-Info with purpose icon / info / card
<s_call_info> ::= 'Call-Info: <http://www.example.com/alice/' r'[a-z]{1,8}' '>;purpose=' (<purpose_icon> | <purpose_info> | <purpose_card>) '\r\n'
<purpose_icon> ::= 'icon'
<purpose_info> ::= 'info'
<purpose_card> ::= 'card'
# §20.4 Alert-Info
<s_alert_info> ::= 'Alert-Info: <http://www.example.com/sounds/' r'[a-z]{1,8}' '.wav>\r\n'
# §20.21 In-Reply-To, §20.24 MIME-Version
<s_in_reply_to> ::= 'In-Reply-To: ' r'[a-zA-Z0-9]{8,16}@example\.com' '\r\n'
<s_mime_version> ::= 'MIME-Version: 1.0\r\n'

# §20.14 Content-Length (mandatory over TCP)
<s_content_length_zero> ::= <s_content_length_name> ': 0\r\n'
<s_content_length_name> ::= 'Content-Length' | 'l'
# §20.15, §13.2.1: the offer, an SDP body
<s_offer_headers> ::= <s_content_type_sdp> <s_content_disposition>? <s_content_length_body>
<s_content_type_sdp> ::= <s_content_type_name> ': application/sdp\r\n'
<s_content_type_name> ::= 'Content-Type' | 'c'
# §20.11: Content-Disposition session, handling optional/required
<s_content_disposition> ::= 'Content-Disposition: session' (';handling=' (<handling_optional> | <handling_required>))? '\r\n'
<handling_optional> ::= 'optional'
<handling_required> ::= 'required'
<s_content_length_body> ::= <s_content_length_name> ': ' <s_body_length> '\r\n'
# §8.2.3: bodies the server cannot understand: an unknown media type
# (handling required, explicit or by default, §20.11), an unknown content
# coding (§20.12), an unknown media type marked handling=optional
<s_unknown_type_headers> ::= <s_content_type_name> ': application/' <unknown_subtype> '\r\n' \
    <s_disposition_required>? <s_content_length_body>
<s_disposition_required> ::= 'Content-Disposition: render' (';handling=' <handling_required>)? '\r\n'
<s_unknown_encoding_headers> ::= <s_content_type_name> ': text/plain\r\n' <s_content_encoding_name> ': ' \
    <unknown_coding> '\r\n' <s_content_length_body>
<s_optional_body_headers> ::= <s_content_type_name> ': application/' <unknown_subtype> '\r\n' \
    'Content-Disposition: render;handling=' <handling_optional> '\r\n' <s_content_length_body>
<s_content_encoding_name> ::= 'Content-Encoding' | 'e'
<unknown_subtype> ::= r'x-[a-z0-9]{4,10}'
<unknown_coding> ::= r'x-[a-z0-9]{4,10}'
<text_body> ::= r'[a-zA-Z0-9]{4,16}'
<s_body_length> ::= r'[0-9]{1,5}'
# RFC 8866 (not in refs/spec): a minimal audio offer; a where ties its
# length to <s_body_length>
<sdp_offer> ::= 'v=0\r\n' 'o=- ' <sdp_session_id> ' ' <sdp_session_id> ' IN IP4 ' <local_host> '\r\n' 's=-\r\n' \
    'c=IN IP4 ' <local_host> '\r\n' 't=0 0\r\n' 'm=audio ' <sdp_port> ' RTP/AVP 0\r\n' 'a=rtpmap:0 PCMU/8000\r\n'
<sdp_session_id> ::= r'[1-9][0-9]{0,9}'
<sdp_port> ::= r'[1-9][0-9]{3,4}'

# §22.2, §22.3, RFC 8760 §2.4: credentials answering the latest challenge
# Authorization answers a 401, Proxy-Authorization a 407
<s_credentials> ::= <s_credentials_name> ': ' <s_digest_credentials> '\r\n'
<s_credentials_name> ::= <authorization_name> | <proxy_authorization_name>
<authorization_name> ::= 'Authorization'
<proxy_authorization_name> ::= 'Proxy-Authorization'
<s_digest_credentials> ::= 'Digest username="' <local_user> '", realm="' <s_auth_realm> '", nonce="' <s_auth_nonce> \
    '", uri="' <s_auth_uri> '", response="' <s_auth_response> '", algorithm=' <s_auth_algorithm> \
    <s_auth_qop_part> <s_auth_opaque_part>
<s_auth_realm> ::= r'[^"\\\r\n]+' := recall('realm')
<s_auth_nonce> ::= r'[^"\\\r\n]+' := recall('nonce')
<s_auth_uri> ::= <uri_text> := recall('auth_uri')
<s_auth_response> ::= r'[0-9a-f]{32}|[0-9a-f]{64}'
<s_auth_algorithm> ::= r'[A-Za-z0-9-]+' := recall('algorithm')
# RFC 8760 §2.6 item 8: the UAC always sends qop
<s_auth_qop_part> ::= ', cnonce="' <s_cnonce> '", qop=' <s_qop> ', nc=' <s_nonce_count>
<s_qop> ::= <qop_auth> | <qop_auth_int>
<s_cnonce> ::= r'[a-zA-Z0-9]{8,16}' := new_token(12)
<s_nonce_count> ::= r'[0-9a-f]{8}' := '00000001'
# §22.4: opaque is returned unchanged if the challenge had one
<s_auth_opaque_part> ::= '' | <s_auth_opaque>
<s_auth_opaque> ::= ', opaque="' <s_opaque_value> '"'
<s_opaque_value> ::= r'[^"\\\r\n]+' := recall('opaque')
# §13.2.2.4: the ACK for a 2xx repeats the credentials of the INVITE
<s_credentials_same_part> ::= '' | <s_credentials_same>
<s_credentials_same> ::= <s_credentials_text> '\r\n'
<s_credentials_text> ::= r'(Proxy-)?Authorization: Digest [^\r\n]+' := recall('credentials')

########################################################################
# Replies the client receives (§7.2, §21), by request and reply class
########################################################################

# §15.1.2: the callee's BYE (Request-Line §7.1, fields as in a reply, CSeq
# BYE); recorded whole for the echo in our reply
<srv_req_bye> ::= <srv_bye_message> := record_request(<srv_req_bye_record>)
<srv_req_bye_record> ::= <srv_bye_message> := record_request(<srv_req_bye>)
<srv_bye_message> ::= <leading_crlf>* 'BYE' ' ' <r_uri> ' ' <r_sip_version> '\r\n' <reply_bye>
# §14.2: the callee's re-INVITE, §11.2 its OPTIONS, §13.2.2.4 its ACK to our
# 2xx (fields as in a reply, CSeq of the method)
<srv_req_reinvite> ::= <srv_reinvite_message> := record_request(<srv_req_reinvite_record>)
<srv_req_reinvite_record> ::= <srv_reinvite_message> := record_request(<srv_req_reinvite>)
<srv_reinvite_message> ::= <leading_crlf>* 'INVITE' ' ' <r_uri> ' ' <r_sip_version> '\r\n' <reply_invite>
<srv_req_options> ::= <srv_options_message> := record_request(<srv_req_options_record>)
<srv_req_options_record> ::= <srv_options_message> := record_request(<srv_req_options>)
<srv_options_message> ::= <leading_crlf>* 'OPTIONS' ' ' <r_uri> ' ' <r_sip_version> '\r\n' <reply_options>
<srv_req_ack> ::= <leading_crlf>* 'ACK' ' ' <r_uri> ' ' <r_sip_version> '\r\n' <fields_ack>
# §7.1 extension-method from the callee; the CSeq names the same method
<srv_req_extension> ::= <srv_extension_message> := record_request(<srv_req_extension_record>)
<srv_req_extension_record> ::= <srv_extension_message> := record_request(<srv_req_extension>)
<srv_extension_message> ::= <leading_crlf>* <srv_extension_method> ' ' <r_uri> ' ' <r_sip_version> '\r\n' <reply_extension>
<srv_extension_method> ::= r'(?!(INVITE|ACK|OPTIONS|BYE|CANCEL|REGISTER)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<fields_ack> ::= <r_cseq_ack> <rest_after_cseq> | <r_header>+ <r_cseq_ack> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_ack> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_ack> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_ack> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_ack>
<rest_cl_zero_then_cseq_ack> ::= <r_header>* <r_cseq_ack> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_ack> ::= <r_header>* <r_cseq_ack> <r_header>* '\r\n' <body>
<r_cseq_ack> ::= <cseq_name> <hcolon> <cseq_value> <lws> 'ACK' '\r\n'

# §7.2 Status-Line; §21 one nonterminal per status code.  RFC 4320 §4.1:
# the only provisional reply to a non-INVITE request is 100; §22.1, §9.2 a
# CANCEL is never challenged
<rep_options_1xx> ::= <status_100> <reply_options>
<rep_options_final> ::= (<status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_options>
<rep_options_final_direct> ::= (<status_2xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_options>
<rep_options_redirect> ::= <status_3xx_redirect> <reply_options>
# §21.3.4 305 (Use Proxy): the request is repeated through the proxy the Contact names
<rep_options_use_proxy> ::= <status_305> <reply_options>
# §8.2.2.3: the refusal is 420; refusals of the earlier steps (§8.2.1 405,
# §8.2.2.1 403/404/416, §8.2.2.2 482) or a server failure (§21.5) may come
# instead
<rep_options_420> ::= (<status_420> | <status_earlier_refusal> | <status_5xx>) <reply_options>
<rep_options_challenge> ::= <status_challenge> <reply_options>
# §12.2.2: the refusal of an out-of-order request
<rep_options_500> ::= <status_500> <reply_options>
<rep_register_1xx> ::= <status_100> <reply_register>
<rep_register_final> ::= (<status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_register>
<rep_register_final_direct> ::= (<status_2xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_register>
<rep_register_redirect> ::= <status_3xx_redirect> <reply_register>
# §21.3.4 305 (Use Proxy): the request is repeated through the proxy the Contact names
<rep_register_use_proxy> ::= <status_305> <reply_register>
# §10.3 step 6: the refusal is 400; refusals of the earlier steps (§8.2.1
# 405, step 4 403, step 5 404, §8.2.2.1 416, §8.2.2.2 482) or a server
# failure (§21.5) may come instead
<rep_register_400> ::= (<status_400> | <status_earlier_refusal> | <status_5xx>) <reply_register>
<rep_register_challenge> ::= <status_challenge> <reply_register>
<rep_extension_1xx> ::= <status_100> <reply_extension>
<rep_extension_final> ::= (<status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_extension>
<rep_extension_final_direct> ::= (<status_2xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_extension>
<rep_extension_redirect> ::= <status_3xx_redirect> <reply_extension>
# §21.3.4 305 (Use Proxy): the request is repeated through the proxy the Contact names
<rep_extension_use_proxy> ::= <status_305> <reply_extension>
<rep_extension_challenge> ::= <status_challenge> <reply_extension>
<rep_bye_1xx> ::= <status_100> <reply_bye>
<rep_bye_final> ::= (<status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_bye>
<rep_bye_challenge> ::= <status_challenge> <reply_bye>
<rep_cancel_100> ::= <status_100> <reply_cancel>
<rep_cancel_final> ::= (<status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_cancel>
<rep_invite_1xx> ::= <status_1xx> <reply_invite>
<rep_invite_2xx> ::= <status_2xx> <reply_invite>
# §8.1.3.4: a 3xx lets the client recurse on its Contact URIs
<rep_invite_redirect> ::= <status_3xx_redirect> <reply_invite>
# §21.3.4 305 (Use Proxy): the Contact is a proxy to repeat the request through
<rep_invite_use_proxy> ::= <status_305> <reply_invite>
# §21.1.1: 100 Trying (no dialog); 101-199 with a To tag create an early
# dialog (§12.1, §13.2.2.1)
<rep_invite_100> ::= <status_100> <reply_invite>
<rep_invite_early> ::= <status_1xx_early> <reply_invite>
<rep_invite_failure> ::= (<status_4xx_no_challenge> | <status_5xx> | <status_6xx>) <reply_invite>
# §8.2.2.2: the replies to the merged INVITE (482 expected; no 2xx: the UAS
# goes on with the first INVITE only)
<rep_invite_merged_1xx> ::= <status_1xx> <reply_invite>
<rep_invite_merged_final> ::= (<status_3xx> | <status_4xx_no_challenge> | <status_challenge> | <status_5xx> \
    | <status_6xx>) <reply_invite>
<rep_invite_challenge> ::= <status_challenge> <reply_invite>

# §7.2: Status-Line = SIP-Version SP Status-Code SP Reason-Phrase CRLF
<status_1xx> ::= <leading_crlf>* <r_sip_version> ' ' <code_1xx> ' ' <reason_phrase> '\r\n'
<status_100> ::= <leading_crlf>* <r_sip_version> ' ' <code_100> ' ' <reason_phrase> '\r\n'
<status_2xx> ::= <leading_crlf>* <r_sip_version> ' ' <code_2xx> ' ' <reason_phrase> '\r\n'
<status_3xx> ::= <leading_crlf>* <r_sip_version> ' ' <code_3xx> ' ' <reason_phrase> '\r\n'
<status_3xx_redirect> ::= <leading_crlf>* <r_sip_version> ' ' <code_3xx_redirect> ' ' <reason_phrase> '\r\n'
<status_305> ::= <leading_crlf>* <r_sip_version> ' ' <code_305> ' ' <reason_phrase> '\r\n'
<status_1xx_early> ::= <leading_crlf>* <r_sip_version> ' ' <code_1xx_early> ' ' <reason_phrase> '\r\n'
<status_4xx_no_challenge> ::= <leading_crlf>* <r_sip_version> ' ' <code_4xx> ' ' <reason_phrase> '\r\n'
<status_challenge> ::= <leading_crlf>* <r_sip_version> ' ' (<code_401> | <code_407>) ' ' <reason_phrase> '\r\n'
<status_420> ::= <leading_crlf>* <r_sip_version> ' ' <code_420> ' ' <reason_phrase> '\r\n'
<status_400> ::= <leading_crlf>* <r_sip_version> ' ' <code_400> ' ' <reason_phrase> '\r\n'
<status_earlier_refusal> ::= <leading_crlf>* <r_sip_version> ' ' (<code_403> | <code_404> | <code_405> | <code_416> | <code_482>) ' ' <reason_phrase> '\r\n'
<status_500> ::= <leading_crlf>* <r_sip_version> ' ' <code_500> ' ' <reason_phrase> '\r\n'
<status_5xx> ::= <leading_crlf>* <r_sip_version> ' ' <code_5xx> ' ' <reason_phrase> '\r\n'
<status_6xx> ::= <leading_crlf>* <r_sip_version> ' ' <code_6xx> ' ' <reason_phrase> '\r\n'
# §7.5: CRLFs before the start-line of a message on a stream are ignored
<leading_crlf> ::= '\r\n'
# §7.1: the version string is case-insensitive
<r_sip_version> ::= r'[Ss][Ii][Pp]/2\.0'
# §25.1 Reason-Phrase = *(reserved / unreserved / escaped / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
<reason_phrase> ::= <reason_text>?
<reason_text> ::= r"([-a-zA-Z0-9;/?:@&=+$,_.!~*'() \t\x80-\xff]|%[0-9a-fA-F]{2})+"

# §21.1 Provisional 1xx; §8.1.3.2 unknown codes of a class are accepted
<code_1xx> ::= <code_100> | <code_180> | <code_181> | <code_182> | <code_183> | <code_1xx_other>
<code_1xx_early> ::= <code_180> | <code_181> | <code_182> | <code_183> | <code_1xx_other>
<code_100> ::= '100'
<code_180> ::= '180'
<code_181> ::= '181'
<code_182> ::= '182'
<code_183> ::= '183'
<code_1xx_other> ::= r'1(?!00|8[0-3])[0-9][0-9]'
# §21.2 Successful 2xx
<code_2xx> ::= <code_200> | <code_2xx_other>
<code_200> ::= '200'
<code_2xx_other> ::= r'2(?!00)[0-9][0-9]'
# §21.3 Redirection 3xx
<code_3xx> ::= <code_300> | <code_301> | <code_302> | <code_305> | <code_380> | <code_3xx_other>
<code_3xx_redirect> ::= <code_300> | <code_301> | <code_302> | <code_380> | <code_3xx_other>
<code_300> ::= '300'
<code_301> ::= '301'
<code_302> ::= '302'
<code_305> ::= '305'
<code_380> ::= '380'
<code_3xx_other> ::= r'3(?!0[0125]|80)[0-9][0-9]'
# §21.4 Request Failure 4xx (401 and 407 are challenges, §22)
<code_4xx> ::= <code_400> | <code_402> | <code_403> | <code_404> | <code_405> | <code_406> | <code_408> \
    | <code_410> | <code_413> | <code_414> | <code_415> | <code_416> | <code_420> | <code_421> | <code_423> \
    | <code_480> | <code_481> | <code_482> | <code_483> | <code_484> | <code_485> | <code_486> | <code_487> \
    | <code_488> | <code_491> | <code_493> | <code_4xx_other>
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
<code_413> ::= '413'
<code_414> ::= '414'
<code_415> ::= '415'
<code_416> ::= '416'
<code_420> ::= '420'
<code_421> ::= '421'
<code_423> ::= '423'
<code_480> ::= '480'
<code_481> ::= '481'
<code_482> ::= '482'
<code_483> ::= '483'
<code_484> ::= '484'
<code_485> ::= '485'
<code_486> ::= '486'
<code_487> ::= '487'
<code_488> ::= '488'
<code_491> ::= '491'
<code_493> ::= '493'
<code_4xx_other> ::= r'4(?!0[0-8]|1[03-6]|2[013]|8[0-8]|9[13])[0-9][0-9]'
# §21.5 Server Failure 5xx
<code_5xx> ::= <code_500> | <code_501> | <code_502> | <code_503> | <code_504> | <code_505> | <code_513> | <code_5xx_other>
<code_500> ::= '500'
<code_501> ::= '501'
<code_502> ::= '502'
<code_503> ::= '503'
<code_504> ::= '504'
<code_505> ::= '505'
<code_513> ::= '513'
<code_5xx_other> ::= r'5(?!0[0-5]|13)[0-9][0-9]'
# §21.6 Global Failures 6xx
<code_6xx> ::= <code_600> | <code_603> | <code_604> | <code_606> | <code_6xx_other>
<code_600> ::= '600'
<code_603> ::= '603'
<code_604> ::= '604'
<code_606> ::= '606'
<code_6xx_other> ::= r'6(?!0[0346])[0-9][0-9]'

# §7.3, §7.4, §7.5, §18.3: header fields in any order; CSeq (whose method
# names the transaction, §17.1.3) and Content-Length (mandatory over TCP,
# §20.14) each once between the slots of the other fields; the body is
# exactly Content-Length octets
<reply_options> ::= <r_cseq_options> <rest_after_cseq> | <r_header>+ <r_cseq_options> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_options> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_options> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_options> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_options>
<rest_cl_zero_then_cseq_options> ::= <r_header>* <r_cseq_options> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_options> ::= <r_header>* <r_cseq_options> <r_header>* '\r\n' <body>
<reply_register> ::= <r_cseq_register> <rest_after_cseq> | <r_header>+ <r_cseq_register> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_register> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_register> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_register> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_register>
<rest_cl_zero_then_cseq_register> ::= <r_header>* <r_cseq_register> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_register> ::= <r_header>* <r_cseq_register> <r_header>* '\r\n' <body>
<reply_invite> ::= <r_cseq_invite> <rest_after_cseq> | <r_header>+ <r_cseq_invite> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_invite> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_invite> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_invite> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_invite>
<rest_cl_zero_then_cseq_invite> ::= <r_header>* <r_cseq_invite> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_invite> ::= <r_header>* <r_cseq_invite> <r_header>* '\r\n' <body>
<reply_cancel> ::= <r_cseq_cancel> <rest_after_cseq> | <r_header>+ <r_cseq_cancel> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_cancel> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_cancel> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_cancel> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_cancel>
<rest_cl_zero_then_cseq_cancel> ::= <r_header>* <r_cseq_cancel> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_cancel> ::= <r_header>* <r_cseq_cancel> <r_header>* '\r\n' <body>
<reply_bye> ::= <r_cseq_bye> <rest_after_cseq> | <r_header>+ <r_cseq_bye> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_bye> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_bye> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_bye> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_bye>
<rest_cl_zero_then_cseq_bye> ::= <r_header>* <r_cseq_bye> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_bye> ::= <r_header>* <r_cseq_bye> <r_header>* '\r\n' <body>
<reply_extension> ::= <r_cseq_extension> <rest_after_cseq> | <r_header>+ <r_cseq_extension> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_extension> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_extension> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_extension> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_extension>
<rest_cl_zero_then_cseq_extension> ::= <r_header>* <r_cseq_extension> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_extension> ::= <r_header>* <r_cseq_extension> <r_header>* '\r\n' <body>
<reply_stray> ::= <r_cseq_stray> <rest_after_cseq> | <r_header>+ <r_cseq_stray> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_stray> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_stray> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_stray> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_stray>
<rest_cl_zero_then_cseq_stray> ::= <r_header>* <r_cseq_stray> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_stray> ::= <r_header>* <r_cseq_stray> <r_header>* '\r\n' <body>
<reply_stray_other> ::= <r_cseq_stray_other> <rest_after_cseq> | <r_header>+ <r_cseq_stray_other> <rest_after_cseq> \
    | <r_cl_zero> <rest_cl_zero_then_cseq_stray_other> | <r_header>+ <r_cl_zero> <rest_cl_zero_then_cseq_stray_other> \
    | <r_cl_positive> <rest_cl_positive_then_cseq_stray_other> | <r_header>+ <r_cl_positive> <rest_cl_positive_then_cseq_stray_other>
<rest_cl_zero_then_cseq_stray_other> ::= <r_header>* <r_cseq_stray_other> <r_header>* '\r\n'
<rest_cl_positive_then_cseq_stray_other> ::= <r_header>* <r_cseq_stray_other> <r_header>* '\r\n' <body>
# after the CSeq: the other fields, Content-Length, the other fields, the body;
# §18.3, §20.14: over UDP Content-Length may be missing, the body is then
# every octet up to the end of the datagram (<datagram_body>)
<rest_after_cseq> ::= <r_header>* <r_cl_zero> <r_header>* '\r\n' \
    | <r_header>* <r_cl_positive> <r_header>* '\r\n' <body> \
    | <r_header>* '\r\n' <datagram_body>
# §18.3: "the message body is assumed to include all bytes up to the end of
# the datagram"; Fandango hands the parser the datagrams of the server joined
# (io/packetparser.py) and keeps the longest parse, so where datagram_body_ends
# (UDP only, §20.14: over TCP Content-Length is mandatory) refuses a body that
# holds the start line of a further response, i.e. the next datagram
<datagram_body> ::= <body_octet>*
# §7.4.1, §20.14: the message body, exactly Content-Length octets
<body> ::= <body_octet>{int(<cl_positive_value>)} := body_from_view(<body_view>)
# §27.5, §7: converters between the body octets on the wire and a view of
# them (body_view decodes the content codings, §20.12): a message/sip body
# is one SIP message, parsed with the grammar's own rules (start line,
# <r_header> fields, CSeq and Content-Length); the view of any other body is
# the marker 'opaque' (SDP, multipart and S/MIME syntax are other documents,
# TODOs below). A message/sip body that is no SIP message does not parse:
# the reply is a violation (parameter_derivation)
<body_view> ::= <enclosed_message> | <opaque_view> := body_view(<body>)
<opaque_view> ::= 'opaque'
<enclosed_message> ::= 'message/sip\r\n' <enclosed_start_line> <enclosed_field>* '\r\n' <body_octet>*
<enclosed_start_line> ::= <r_method> ' ' <r_uri> ' ' <r_sip_version> '\r\n' \
    | <status_1xx> | <status_2xx> | <status_3xx> | <status_4xx_no_challenge> | <status_challenge> | <status_5xx> \
    | <status_6xx>
<enclosed_field> ::= <r_header> | <enclosed_cseq> | <r_cl_zero> | <enclosed_content_length>
<enclosed_cseq> ::= <cseq_name> <hcolon> <cseq_value> <lws> <r_method> '\r\n'
<enclosed_content_length> ::= <content_length_name> <hcolon> r'0*[1-9][0-9]*' '\r\n'
<body_octet> ::= r'[\x00-\xff]'

# §20.16 CSeq = "CSeq" HCOLON 1*DIGIT LWS Method, one per method
<r_cseq_options> ::= <cseq_name> <hcolon> <cseq_value> <lws> 'OPTIONS' '\r\n'
<r_cseq_register> ::= <cseq_name> <hcolon> <cseq_value> <lws> 'REGISTER' '\r\n'
<r_cseq_invite> ::= <cseq_name> <hcolon> <cseq_value> <lws> 'INVITE' '\r\n'
<r_cseq_cancel> ::= <cseq_name> <hcolon> <cseq_value> <lws> 'CANCEL' '\r\n'
<r_cseq_bye> ::= <cseq_name> <hcolon> <cseq_value> <lws> 'BYE' '\r\n'
<r_cseq_extension> ::= <cseq_name> <hcolon> <cseq_value> <lws> <r_extension_method> '\r\n'
<r_extension_method> ::= r'[-a-zA-Z0-9.!%*_+`\'~]+'
<r_cseq_stray> ::= <cseq_name> <hcolon> <cseq_value> <lws> <stray_method> '\r\n'
<r_cseq_stray_other> ::= <cseq_name> <hcolon> <cseq_value> <lws> <stray_method_other> '\r\n'
<stray_method_other> ::= r'(?!(INVITE|CANCEL|BYE)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<stray_method> ::= r'(?!(INVITE|CANCEL)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<cseq_name> ::= r'[Cc][Ss][Ee][Qq]'
<cseq_value> ::= r'[0-9]{1,10}'
# §20.14 Content-Length = ( "Content-Length" / "l" ) HCOLON 1*DIGIT
<r_cl_zero> ::= <content_length_name> <hcolon> r'0+' '\r\n'
<r_cl_positive> ::= <content_length_name> <hcolon> <cl_positive_value> '\r\n'
<cl_positive_value> ::= r'0*[1-9][0-9]*'
<content_length_name> ::= r'[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]|[Ll]'

########################################################################
# Received header fields (§20, §25.1), every field of RFC 3261 by name,
# then any extension-header (§7.3.1)
########################################################################

<r_header> ::= <r_via> | <r_from> | <r_to> | <r_call_id> | <r_contact> | <r_max_forwards> | <r_expires> \
    | <r_min_expires> | <r_www_authenticate> | <r_proxy_authenticate> | <r_authentication_info> \
    | <r_authorization> | <r_proxy_authorization> | <r_record_route> | <r_route> | <r_require> \
    | <r_proxy_require> | <r_supported> | <r_unsupported> | <r_allow> | <r_accept> | <r_accept_encoding> \
    | <r_accept_language> | <r_content_type> | <r_content_encoding> | <r_content_language> \
    | <r_content_disposition> | <r_retry_after> | <r_timestamp> | <r_date> | <r_server> | <r_user_agent> \
    | <r_warning> | <r_error_info> | <r_alert_info> | <r_call_info> | <r_in_reply_to> | <r_mime_version> \
    | <r_organization> | <r_priority> | <r_reply_to> | <r_subject> | <r_extension_header>

# §25.1 basic rules
<lws> ::= r'[ \t]*\r\n[ \t]+|[ \t]+'
<sws> ::= <lws>?
<hcolon> ::= <wsp>? ':' <sws>
<wsp> ::= r'[ \t]+'
<comma> ::= <sws> ',' <sws>
<semi> ::= <sws> ';' <sws>
<equal> ::= <sws> '=' <sws>
<slash> ::= <sws> '/' <sws>
<laquot> ::= '<'
<raquot> ::= '>'
<token> ::= r'[-a-zA-Z0-9.!%*_+`\'~]+'
<quoted_string> ::= r'"([^"\\\r\n]|\\[\x00-\x09\x0b\x0c\x0e-\x7f])*"'
<text_utf8> ::= r'[^ \t\r\n]([^\r\n]*[^ \t\r\n])?'
<delta_seconds> ::= r'[0-9]{1,10}'
<digits> ::= r'[0-9]+'
<qvalue> ::= r'0(\.[0-9]{0,3})?|1(\.0{0,3})?'

# §19.1.1, §25.1 SIP-URI / SIPS-URI / absoluteURI (RFC 5954 IPv6reference)
<r_uri> ::= <r_sip_uri> | <r_absolute_uri>
<r_sip_uri> ::= <r_sip_scheme> ':' <r_userinfo>? <r_hostport> <r_uri_parameter>* <r_uri_headers>?
<r_sip_scheme> ::= r'[Ss][Ii][Pp][Ss]?'
<r_userinfo> ::= <r_user> (':' <r_password>)? '@'
<r_user> ::= r"([-a-zA-Z0-9_.!~*'()&=+$,;?/]|%[0-9a-fA-F]{2})+"
<r_password> ::= r"([-a-zA-Z0-9_.!~*'()&=+$,]|%[0-9a-fA-F]{2})+"
<r_hostport> ::= <r_host> (':' <r_port>)?
<r_host> ::= <r_hostname> | <r_ipv6_reference>
<r_hostname> ::= r'[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?)*\.?'
<r_ipv6_reference> ::= r'\[[0-9a-fA-F:.]+\]'
<r_port> ::= r'[0-9]{1,5}'
# §19.1.1 uri-parameters: transport, user, method, ttl, maddr, lr, other
<r_uri_parameter> ::= ';' (<r_transport_param> | <r_user_param> | <r_method_param> | <r_ttl_param> \
    | <r_maddr_param> | <r_lr_param> | <r_other_uri_param>)
<r_transport_param> ::= r'[Tt][Rr][Aa][Nn][Ss][Pp][Oo][Rr][Tt]=' (<transport_udp> | <transport_tcp> | <transport_sctp> | <transport_tls> | <transport_other>)
<transport_udp> ::= r'[Uu][Dd][Pp]'
<transport_tcp> ::= r'[Tt][Cc][Pp]'
<transport_sctp> ::= r'[Ss][Cc][Tt][Pp]'
<transport_tls> ::= r'[Tt][Ll][Ss]'
<transport_other> ::= r'(?!([Uu][Dd][Pp]|[Tt][Cc][Pp]|[Ss][Cc][Tt][Pp]|[Tt][Ll][Ss])(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<r_user_param> ::= 'user=' (<user_phone> | <user_ip> | <user_other>)
<user_phone> ::= 'phone'
<user_ip> ::= 'ip'
<user_other> ::= r'(?!(phone|ip)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<r_method_param> ::= 'method=' <token>
<r_ttl_param> ::= 'ttl=' r'[0-9]{1,3}'
<r_maddr_param> ::= 'maddr=' <r_host>
<r_lr_param> ::= 'lr'
<r_other_uri_param> ::= r"(?!(transport|user|method|ttl|maddr|lr)(?![-\[\]/:&+$a-zA-Z0-9_.!~*'()%]))([-\[\]/:&+$a-zA-Z0-9_.!~*'()]|%[0-9a-fA-F]{2})+" ('=' r"([-\[\]/:&+$a-zA-Z0-9_.!~*'()]|%[0-9a-fA-F]{2})+")?
<r_uri_headers> ::= '?' <r_uri_header> ('&' <r_uri_header>)*
<r_uri_header> ::= r"([-\[\]/?:+$a-zA-Z0-9_.!~*'()]|%[0-9a-fA-F]{2})+" '=' r"([-\[\]/?:+$a-zA-Z0-9_.!~*'()]|%[0-9a-fA-F]{2})*"
# §25.1 absoluteURI (e.g. tel:, http:)
<r_absolute_uri> ::= r'(?![Ss][Ii][Pp][Ss]?(?![-a-zA-Z0-9+.]))[a-zA-Z][-a-zA-Z0-9+.]*' ':' r"([-;/?:@&=+$,a-zA-Z0-9_.!~*'()\[\]]|%[0-9a-fA-F]{2})+"
# RFC 8217 / §20: an addr-spec outside <> must not contain ',', ';' or '?'
<r_bare_uri> ::= <r_sip_scheme> ':' <r_userinfo_bare>? <r_hostport> \
    | r'(?![Ss][Ii][Pp][Ss]?(?![-a-zA-Z0-9+.]))[a-zA-Z][-a-zA-Z0-9+.]*' ':' r"([-/:@&=+$a-zA-Z0-9_.!~*'()\[\]]|%[0-9a-fA-F]{2})+"
<r_userinfo_bare> ::= r"([-a-zA-Z0-9_.!~*'()&=+$/]|%[0-9a-fA-F]{2})+" (':' <r_password>)? '@'
# §25.1 name-addr / addr-spec
<r_name_addr> ::= <r_display_name>? <laquot> <r_uri> <raquot>
<r_display_name> ::= (<token> <lws>)+ | <quoted_string> <sws>
<r_address> ::= <r_name_addr> | <r_bare_uri>
# §25.1 generic-param = token [ EQUAL gen-value ]
<generic_param> ::= <token> (<equal> <gen_value>)?
<gen_value> ::= <token> | <quoted_string> | <r_ipv6_reference>

# §20.42 Via = ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
<r_via> ::= <via_name> <hcolon> <r_via_parm> (<comma> <r_via_parm>)* '\r\n'
<via_name> ::= r'[Vv][Ii][Aa]|[Vv]'
<r_via_parm> ::= <r_sent_protocol> <lws> <r_sent_by> (<semi> <r_via_param>)*
<r_sent_protocol> ::= r'[Ss][Ii][Pp]' <slash> r'2\.0' <slash> <r_transport>
<r_transport> ::= <transport_udp> | <transport_tcp> | <transport_tls> | <transport_sctp> | <transport_other>
<r_sent_by> ::= <r_host> (<colon> <r_port>)?
<colon> ::= <sws> ':' <sws>
<r_via_param> ::= <via_ttl> | <via_maddr> | <via_received> | <via_branch> | <via_extension>
<via_ttl> ::= 'ttl' <equal> r'[0-9]{1,3}'
<via_maddr> ::= 'maddr' <equal> <r_host>
<via_received> ::= 'received' <equal> <r_host>
<via_branch> ::= 'branch' <equal> <token>
<via_extension> ::= r'(?!(ttl|maddr|received|branch)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+' (<equal> <gen_value>)?

# §20.20 From, §20.39 To: address and tag
<r_from> ::= <from_name> <hcolon> <r_address> (<semi> <r_addr_param>)* '\r\n'
<from_name> ::= r'[Ff][Rr][Oo][Mm]|[Ff]'
<r_to> ::= <to_name> <hcolon> <r_to_value> '\r\n'
# the To of the latest reply, recorded for the ACK and requests in the dialog
<r_to_value> ::= <r_to_spec> := record('reply_to', <r_to_record>)
<r_to_record> ::= <r_to_spec> := record('reply_to', <r_to_value>)
<r_to_spec> ::= <r_address> (<semi> <r_addr_param>)*
<to_name> ::= r'[Tt][Oo]|[Tt]'
<r_addr_param> ::= <r_tag_param> | <r_other_addr_param>
<r_tag_param> ::= 'tag' <equal> <token>
<r_other_addr_param> ::= r'(?!tag(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+' (<equal> <gen_value>)?

# §20.8 Call-ID = ( "Call-ID" / "i" ) HCOLON callid; callid = word [ "@" word ]
<r_call_id> ::= <call_id_name> <hcolon> <r_callid> '\r\n'
<call_id_name> ::= r'[Cc][Aa][Ll][Ll]-[Ii][Dd]|[Ii]'
<r_callid> ::= r'[-a-zA-Z0-9.!%*_+`\'~()<>:\\"/\[\]?{}]+(@[-a-zA-Z0-9.!%*_+`\'~()<>:\\"/\[\]?{}]+)?'

# §20.10 Contact = ("Contact" / "m" ) HCOLON ( STAR / (contact-param *(COMMA contact-param)))
<r_contact> ::= <contact_name> <hcolon> (<contact_star> | <r_contact_param> (<comma> <r_contact_param>)*) '\r\n'
<contact_name> ::= r'[Cc][Oo][Nn][Tt][Aa][Cc][Tt]|[Mm]'
<contact_star> ::= '*'
<r_contact_param> ::= <r_contact_address> (<semi> <r_contact_params>)*
# the Contact of the latest reply, recorded as the dialog's remote target
<r_contact_address> ::= <r_address> := record_uri('remote_target', <r_contact_record>)
<r_contact_record> ::= <r_address> := record_uri('remote_target', <r_contact_address>)
<r_contact_params> ::= <c_q> | <c_expires> | <c_other>
<c_q> ::= 'q' <equal> <qvalue>
<c_expires> ::= 'expires' <equal> <delta_seconds>
<c_other> ::= r'(?!(q|expires)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+' (<equal> <gen_value>)?

# §20.22 Max-Forwards, §20.19 Expires, §20.23 Min-Expires
<r_max_forwards> ::= r'[Mm][Aa][Xx]-[Ff][Oo][Rr][Ww][Aa][Rr][Dd][Ss]' <hcolon> <digits> '\r\n'
<r_expires> ::= r'[Ee][Xx][Pp][Ii][Rr][Ee][Ss]' <hcolon> <delta_seconds> '\r\n'
<r_min_expires> ::= r'[Mm][Ii][Nn]-[Ee][Xx][Pp][Ii][Rr][Ee][Ss]' <hcolon> <delta_seconds> '\r\n'

# §20.44 WWW-Authenticate, §20.27 Proxy-Authenticate; RFC 8760 §2.3 challenge
<r_www_authenticate> ::= r'[Ww][Ww][Ww]-[Aa][Uu][Tt][Hh][Ee][Nn][Tt][Ii][Cc][Aa][Tt][Ee]' <hcolon> <r_challenge> '\r\n'
<r_proxy_authenticate> ::= r'[Pp][Rr][Oo][Xx][Yy]-[Aa][Uu][Tt][Hh][Ee][Nn][Tt][Ii][Cc][Aa][Tt][Ee]' <hcolon> <r_challenge> '\r\n'
<r_challenge> ::= <digest_scheme> <lws> <digest_cln> (<comma> <digest_cln>)* | <other_challenge>
<digest_scheme> ::= r'[Dd][Ii][Gg][Ee][Ss][Tt]'
<digest_cln> ::= <dc_realm> | <dc_domain> | <dc_nonce> | <dc_opaque> | <dc_stale> | <dc_algorithm> | <dc_qop> | <dc_extension>
<dc_realm> ::= 'realm' <equal> '"' <dc_realm_value> '"'
<dc_realm_value> ::= <qs_content> := record('realm', <dc_realm_record>)
<dc_realm_record> ::= <qs_content> := record('realm', <dc_realm_value>)
<dc_domain> ::= 'domain' <equal> <quoted_string>
<dc_nonce> ::= 'nonce' <equal> '"' <dc_nonce_value> '"'
<dc_nonce_value> ::= <qs_content> := record('nonce', <dc_nonce_record>)
<dc_nonce_record> ::= <qs_content> := record('nonce', <dc_nonce_value>)
<dc_opaque> ::= 'opaque' <equal> '"' <dc_opaque_value> '"'
<dc_opaque_value> ::= <qs_content> := record('opaque', <dc_opaque_record>)
<dc_opaque_record> ::= <qs_content> := record('opaque', <dc_opaque_value>)
<dc_stale> ::= 'stale' <equal> (<stale_true> | <stale_false>)
<stale_true> ::= r'[Tt][Rr][Uu][Ee]'
<stale_false> ::= r'[Ff][Aa][Ll][Ss][Ee]'
# RFC 8760 §2.7: algorithm MD5 / SHA-256 / SHA-512-256 and their -sess forms
<dc_algorithm> ::= 'algorithm' <equal> (<dc_algorithm_value> | '"' <dc_algorithm_value> '"')
<dc_algorithm_value> ::= <dc_algorithm_name> := record('algorithm', <dc_algorithm_record>)
<dc_algorithm_record> ::= <dc_algorithm_name> := record('algorithm', <dc_algorithm_value>)
<dc_algorithm_name> ::= <alg_md5> | <alg_md5_sess> | <alg_sha256> | <alg_sha256_sess> | <alg_sha512_256> | <alg_sha512_256_sess> | <alg_other>
<alg_md5> ::= r'[Mm][Dd]5'
<alg_md5_sess> ::= r'[Mm][Dd]5-[Ss][Ee][Ss][Ss]'
<alg_sha256> ::= r'[Ss][Hh][Aa]-256'
<alg_sha256_sess> ::= r'[Ss][Hh][Aa]-256-[Ss][Ee][Ss][Ss]'
<alg_sha512_256> ::= r'[Ss][Hh][Aa]-512-256'
<alg_sha512_256_sess> ::= r'[Ss][Hh][Aa]-512-256-[Ss][Ee][Ss][Ss]'
<alg_other> ::= r'(?!([Mm][Dd]5(-[Ss][Ee][Ss][Ss])?|[Ss][Hh][Aa]-(256|512-256)(-[Ss][Ee][Ss][Ss])?)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
# RFC 8760 §2.6: qop-options = "qop" EQUAL LDQUOT qop-value *("," qop-value) RDQUOT
<dc_qop> ::= 'qop' <equal> '"' <qop_value> (<sws> ',' <sws> <qop_value>)* '"'
<qop_value> ::= <qop_auth> | <qop_auth_int> | <qop_other>
<qop_auth> ::= 'auth'
<qop_auth_int> ::= 'auth-int'
<qop_other> ::= r'(?!(auth|auth-int)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<dc_extension> ::= r'(?!(realm|domain|nonce|opaque|stale|algorithm|qop)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+' <equal> (<token> | <quoted_string>)
<qs_content> ::= r'([^"\\\r\n]|\\[\x00-\x09\x0b\x0c\x0e-\x7f])+'
# RFC 8760 §2.6: Basic is never requested; other schemes are extensions
<other_challenge> ::= <other_auth_scheme> <lws> <auth_param> (<comma> <auth_param>)*
<other_auth_scheme> ::= r'(?!([Dd][Ii][Gg][Ee][Ss][Tt]|[Bb][Aa][Ss][Ii][Cc])(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
<auth_param> ::= <token> <equal> (<token> | <quoted_string>)
# §20.6 Authentication-Info, §20.7 Authorization, §20.28 Proxy-Authorization
# §20.6 Authentication-Info = "Authentication-Info" HCOLON ainfo *(COMMA ainfo)
<r_authentication_info> ::= r'[Aa][Uu][Tt][Hh][Ee][Nn][Tt][Ii][Cc][Aa][Tt][Ii][Oo][Nn]-[Ii][Nn][Ff][Oo]' <hcolon> <ainfo> (<comma> <ainfo>)* '\r\n'
# ainfo = nextnonce / message-qop / response-auth / cnonce / nonce-count
<ainfo> ::= <ai_nextnonce> | <ai_qop> | <ai_rspauth> | <ai_cnonce> | <ai_nc> | <ai_extension>
<ai_nextnonce> ::= 'nextnonce' <equal> <quoted_string>
<ai_qop> ::= 'qop' <equal> <token>
<ai_rspauth> ::= 'rspauth' <equal> '"' <rspauth_value>? '"'
<rspauth_value> ::= r'[0-9a-fA-F]+'
<ai_cnonce> ::= 'cnonce' <equal> <quoted_string>
<ai_nc> ::= 'nc' <equal> r'[0-9a-fA-F]{8}'
<ai_extension> ::= r'(?!(nextnonce|qop|rspauth|cnonce|nc)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+' <equal> (<token> | <quoted_string>)
# RFC 8760 §2.6: Basic credentials are not accepted
<r_authorization> ::= r'[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]' <hcolon> <credentials_scheme> <lws> <auth_param> (<comma> <auth_param>)* '\r\n'
<r_proxy_authorization> ::= r'[Pp][Rr][Oo][Xx][Yy]-[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]' <hcolon> <credentials_scheme> <lws> <auth_param> (<comma> <auth_param>)* '\r\n'
<credentials_scheme> ::= r'(?![Bb][Aa][Ss][Ii][Cc](?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'

# §20.30 Record-Route, §20.34 Route
<r_record_route> ::= r'[Rr][Ee][Cc][Oo][Rr][Dd]-[Rr][Oo][Uu][Tt][Ee]' <hcolon> <r_record_route_value> '\r\n'
# §12.1.2: the route set is the Record-Route of the reply in reverse order
<r_record_route_value> ::= <r_route_list> := record_route_set(<r_record_route_record>)
<r_record_route_record> ::= <r_route_list> := record_route_set(<r_record_route_value>)
<r_route_list> ::= <r_route_entry> (<comma> <r_route_entry>)*
<r_route> ::= r'[Rr][Oo][Uu][Tt][Ee]' <hcolon> <r_route_entry> (<comma> <r_route_entry>)* '\r\n'
<r_route_entry> ::= <r_name_addr> (<semi> <generic_param>)*

# §20.32 Require, §20.29 Proxy-Require, §20.37 Supported, §20.40 Unsupported
<r_require> ::= r'[Rr][Ee][Qq][Uu][Ii][Rr][Ee]' <hcolon> <option_tag> (<comma> <option_tag>)* '\r\n'
<r_proxy_require> ::= r'[Pp][Rr][Oo][Xx][Yy]-[Rr][Ee][Qq][Uu][Ii][Rr][Ee]' <hcolon> <option_tag> (<comma> <option_tag>)* '\r\n'
<r_supported> ::= r'[Ss][Uu][Pp][Pp][Oo][Rr][Tt][Ee][Dd]|[Kk]' <hcolon> (<option_tag> (<comma> <option_tag>)*)? '\r\n'
<r_unsupported> ::= r'[Uu][Nn][Ss][Uu][Pp][Pp][Oo][Rr][Tt][Ee][Dd]' <hcolon> <option_tag> (<comma> <option_tag>)* '\r\n'
<option_tag> ::= <token>
# §20.5 Allow = "Allow" HCOLON [Method *(COMMA Method)]
<r_allow> ::= r'[Aa][Ll][Ll][Oo][Ww]' <hcolon> (<r_method> (<comma> <r_method>)*)? '\r\n'
<r_method> ::= <m_invite> | <m_ack> | <m_options> | <m_bye> | <m_cancel> | <m_register> | <m_extension>
<m_invite> ::= 'INVITE'
<m_ack> ::= 'ACK'
<m_options> ::= 'OPTIONS'
<m_bye> ::= 'BYE'
<m_cancel> ::= 'CANCEL'
<m_register> ::= 'REGISTER'
<m_extension> ::= r'(?!(INVITE|ACK|OPTIONS|BYE|CANCEL|REGISTER)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
# §20.1 Accept, §20.2 Accept-Encoding, §20.3 Accept-Language
<r_accept> ::= r'[Aa][Cc][Cc][Ee][Pp][Tt]' <hcolon> (<accept_range> (<comma> <accept_range>)*)? '\r\n'
<accept_range> ::= <media_range> (<semi> <generic_param>)*
<media_range> ::= <token> <slash> <token>
<r_accept_encoding> ::= r'[Aa][Cc][Cc][Ee][Pp][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]' <hcolon> (<encoding> (<comma> <encoding>)*)? '\r\n'
<encoding> ::= <token> (<semi> <generic_param>)*
<r_accept_language> ::= r'[Aa][Cc][Cc][Ee][Pp][Tt]-[Ll][Aa][Nn][Gg][Uu][Aa][Gg][Ee]' <hcolon> (<language> (<comma> <language>)*)? '\r\n'
<language> ::= r'[a-zA-Z]{1,8}(-[a-zA-Z]{1,8})*|\*' (<semi> <generic_param>)*
# §20.15 Content-Type, §20.12 Content-Encoding, §20.13 Content-Language,
# §20.11 Content-Disposition (RFC 5621 §9.4 by-reference)
<r_content_type> ::= r'[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Tt][Yy][Pp][Ee]|[Cc]' <hcolon> <media_type> '\r\n'
<media_type> ::= <token> <slash> <token> (<semi> <generic_param>)*
<r_content_encoding> ::= r'[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]|[Ee]' <hcolon> <token> (<comma> <token>)* '\r\n'
<r_content_language> ::= r'[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Aa][Nn][Gg][Uu][Aa][Gg][Ee]' <hcolon> <language_tag> (<comma> <language_tag>)* '\r\n'
<language_tag> ::= r'[a-zA-Z]{1,8}(-[a-zA-Z]{1,8})*'
<r_content_disposition> ::= r'[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Dd][Ii][Ss][Pp][Oo][Ss][Ii][Tt][Ii][Oo][Nn]' <hcolon> <disp_type> (<semi> <generic_param>)* '\r\n'
<disp_type> ::= <disp_render> | <disp_session> | <disp_icon> | <disp_alert> | <disp_by_reference> | <disp_other>
<disp_render> ::= 'render'
<disp_session> ::= 'session'
<disp_icon> ::= 'icon'
<disp_alert> ::= 'alert'
<disp_by_reference> ::= 'by-reference'
<disp_other> ::= r'(?!(render|session|icon|alert|by-reference)(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'
# §20.33 Retry-After, §20.38 Timestamp, §20.17 Date
<r_retry_after> ::= r'[Rr][Ee][Tt][Rr][Yy]-[Aa][Ff][Tt][Ee][Rr]' <hcolon> <delta_seconds> <comment>? (<semi> <generic_param>)* '\r\n'
<comment> ::= <sws> r'\([^\r\n]*\)'
<r_timestamp> ::= r'[Tt][Ii][Mm][Ee][Ss][Tt][Aa][Mm][Pp]' <hcolon> <timestamp_value> (<lws> <timestamp_delay>)? '\r\n'
<timestamp_value> ::= r'[0-9]+(\.[0-9]*)?'
<timestamp_delay> ::= r'[0-9]*(\.[0-9]*)?'
# §20.17 Date = "Date" HCOLON SIP-date; SIP-date = rfc1123-date
<r_date> ::= r'[Dd][Aa][Tt][Ee]' <hcolon> <rfc1123_date> '\r\n'
<rfc1123_date> ::= r'(?i:mon|tue|wed|thu|fri|sat|sun), [0-9]{2} (?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} (?i:gmt)'
# §20.35 Server, §20.41 User-Agent, §20.25 Organization, §20.36 Subject
<r_server> ::= r'[Ss][Ee][Rr][Vv][Ee][Rr]' <hcolon> <text_utf8> '\r\n'
<r_user_agent> ::= r'[Uu][Ss][Ee][Rr]-[Aa][Gg][Ee][Nn][Tt]' <hcolon> <text_utf8> '\r\n'
<r_organization> ::= r'[Oo][Rr][Gg][Aa][Nn][Ii][Zz][Aa][Tt][Ii][Oo][Nn]' <hcolon> <text_utf8>? '\r\n'
<r_subject> ::= r'[Ss][Uu][Bb][Jj][Ee][Cc][Tt]|[Ss]' <hcolon> <text_utf8>? '\r\n'
# §20.43 Warning: warn-code SP warn-agent SP warn-text
<r_warning> ::= r'[Ww][Aa][Rr][Nn][Ii][Nn][Gg]' <hcolon> <warning_value> (<comma> <warning_value>)* '\r\n'
<warning_value> ::= r'[0-9]{3}' ' ' r'[^ \r\n]+' ' ' <quoted_string>
# §20.18 Error-Info, §20.4 Alert-Info, §20.9 Call-Info
<r_error_info> ::= r'[Ee][Rr][Rr][Oo][Rr]-[Ii][Nn][Ff][Oo]' <hcolon> <info_uri> (<comma> <info_uri>)* '\r\n'
<r_alert_info> ::= r'[Aa][Ll][Ee][Rr][Tt]-[Ii][Nn][Ff][Oo]' <hcolon> <info_uri> (<comma> <info_uri>)* '\r\n'
<r_call_info> ::= r'[Cc][Aa][Ll][Ll]-[Ii][Nn][Ff][Oo]' <hcolon> <info_uri> (<comma> <info_uri>)* '\r\n'
<info_uri> ::= <laquot> <r_uri> <raquot> (<semi> <generic_param>)*
# §20.21 In-Reply-To, §20.24 MIME-Version, §20.26 Priority, §20.31 Reply-To
<r_in_reply_to> ::= r'[Ii][Nn]-[Rr][Ee][Pp][Ll][Yy]-[Tt][Oo]' <hcolon> <r_callid> (<comma> <r_callid>)* '\r\n'
<r_mime_version> ::= r'[Mm][Ii][Mm][Ee]-[Vv][Ee][Rr][Ss][Ii][Oo][Nn]' <hcolon> r'[0-9]+\.[0-9]+' '\r\n'
<r_priority> ::= r'[Pp][Rr][Ii][Oo][Rr][Ii][Tt][Yy]' <hcolon> <token> '\r\n'
<r_reply_to> ::= r'[Rr][Ee][Pp][Ll][Yy]-[Tt][Oo]' <hcolon> <r_address> (<semi> <generic_param>)* '\r\n'
# §7.3.1 extension-header = header-name HCOLON header-value; names of no
# RFC 3261 field (those parse above); compact forms included
<r_extension_header> ::= <extension_header_name> <hcolon> <text_utf8>? '\r\n'
<extension_header_name> ::= r'(?!((?i:via|v|from|f|to|t|call-id|i|contact|m|max-forwards|expires|min-expires|www-authenticate|proxy-authenticate|authentication-info|authorization|proxy-authorization|record-route|route|require|proxy-require|supported|k|unsupported|allow|accept|accept-encoding|accept-language|content-type|c|content-encoding|e|content-language|content-disposition|retry-after|timestamp|date|server|user-agent|warning|error-info|alert-info|call-info|in-reply-to|mime-version|organization|priority|reply-to|subject|s|cseq|content-length|l))(?![-a-zA-Z0-9.!%*_+`\'~]))[-a-zA-Z0-9.!%*_+`\'~]+'

########################################################################
# Constraints (§8.1.1, §8.2.6, §9.1, §12, §13, §17, §20, §22, RFC 8760)
########################################################################

# §18.3, §20.14: a body without Content-Length only over UDP, up to the end
# of the datagram
where forall <b> in <datagram_body>: datagram_body_ends(<b>)

# §17.1.1.2, §17.1.2.2: the copy is the pending request, due on the timer
where forall <r> in <copied_request>: <r> == retransmitted(<r>)
where forall <r> in <req_retransmit>: copy_fits_transport(<r>)
where forall <r> in <req_retransmit>: retransmission_due(<r>)

# §8.2.6.2, §17.1.3: every reply echoes Via, From, Call-ID and the CSeq
# of its request; the To URI, and its tag if the request had one; §17.1.3,
# §17.2.3 the request is found by CSeq number and method
where forall <r> in <rep_options_1xx>: reply_echoes_request(<r>)
where forall <r> in <rep_options_final>: reply_echoes_request(<r>)
where forall <r> in <rep_options_final_direct>: reply_echoes_request(<r>)
where forall <r> in <rep_options_redirect>: reply_echoes_request(<r>)
where forall <r> in <rep_options_use_proxy>: reply_echoes_request(<r>)
where forall <r> in <rep_options_420>: reply_echoes_request(<r>)
where forall <r> in <rep_options_challenge>: reply_echoes_request(<r>)
where forall <r> in <rep_options_500>: reply_echoes_request(<r>)
where forall <r> in <rep_register_1xx>: reply_echoes_request(<r>)
where forall <r> in <rep_register_final>: reply_echoes_request(<r>)
where forall <r> in <rep_register_final_direct>: reply_echoes_request(<r>)
where forall <r> in <rep_register_redirect>: reply_echoes_request(<r>)
where forall <r> in <rep_register_use_proxy>: reply_echoes_request(<r>)
where forall <r> in <rep_register_400>: reply_echoes_request(<r>)
where forall <r> in <rep_register_challenge>: reply_echoes_request(<r>)
where forall <r> in <rep_extension_1xx>: reply_echoes_request(<r>)
where forall <r> in <rep_extension_final>: reply_echoes_request(<r>)
where forall <r> in <rep_extension_final_direct>: reply_echoes_request(<r>)
where forall <r> in <rep_extension_redirect>: reply_echoes_request(<r>)
where forall <r> in <rep_extension_use_proxy>: reply_echoes_request(<r>)
where forall <r> in <rep_extension_challenge>: reply_echoes_request(<r>)
where forall <r> in <rep_bye_1xx>: reply_echoes_request(<r>)
where forall <r> in <rep_bye_final>: reply_echoes_request(<r>)
where forall <r> in <rep_bye_challenge>: reply_echoes_request(<r>)
where forall <r> in <rep_cancel_100>: reply_echoes_request(<r>)
where forall <r> in <rep_cancel_final>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_1xx>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_merged_1xx>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_100>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_early>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_2xx>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_redirect>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_use_proxy>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_failure>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_merged_final>: reply_echoes_request(<r>)
where forall <r> in <rep_invite_challenge>: reply_echoes_request(<r>)

# §8.2.6.1: a 100 (Trying) copies the Timestamp of the request
where forall <r> in <rep_options_1xx>: timestamp_copied(<r>)
where forall <r> in <rep_register_1xx>: timestamp_copied(<r>)
where forall <r> in <rep_extension_1xx>: timestamp_copied(<r>)
where forall <r> in <rep_bye_1xx>: timestamp_copied(<r>)
where forall <r> in <rep_cancel_100>: timestamp_copied(<r>)
where forall <r> in <rep_invite_1xx>: timestamp_copied(<r>)
where forall <r> in <rep_invite_merged_1xx>: timestamp_copied(<r>)
where forall <r> in <rep_invite_100>: timestamp_copied(<r>)
where forall <r> in <rep_invite_early>: timestamp_copied(<r>)

# §8.2.4, §20.32: a reply other than 421 requires only option tags the
# request listed in Supported
where forall <r> in <rep_options_1xx>: require_only_supported(<r>)
where forall <r> in <rep_options_final>: require_only_supported(<r>)
where forall <r> in <rep_options_final_direct>: require_only_supported(<r>)
where forall <r> in <rep_options_redirect>: require_only_supported(<r>)
where forall <r> in <rep_options_use_proxy>: require_only_supported(<r>)
where forall <r> in <rep_options_420>: require_only_supported(<r>)
where forall <r> in <rep_options_challenge>: require_only_supported(<r>)
where forall <r> in <rep_options_500>: require_only_supported(<r>)
where forall <r> in <rep_register_1xx>: require_only_supported(<r>)
where forall <r> in <rep_register_final>: require_only_supported(<r>)
where forall <r> in <rep_register_final_direct>: require_only_supported(<r>)
where forall <r> in <rep_register_redirect>: require_only_supported(<r>)
where forall <r> in <rep_register_use_proxy>: require_only_supported(<r>)
where forall <r> in <rep_register_400>: require_only_supported(<r>)
where forall <r> in <rep_register_challenge>: require_only_supported(<r>)
where forall <r> in <rep_extension_1xx>: require_only_supported(<r>)
where forall <r> in <rep_extension_final>: require_only_supported(<r>)
where forall <r> in <rep_extension_final_direct>: require_only_supported(<r>)
where forall <r> in <rep_extension_redirect>: require_only_supported(<r>)
where forall <r> in <rep_extension_use_proxy>: require_only_supported(<r>)
where forall <r> in <rep_extension_challenge>: require_only_supported(<r>)
where forall <r> in <rep_bye_1xx>: require_only_supported(<r>)
where forall <r> in <rep_bye_final>: require_only_supported(<r>)
where forall <r> in <rep_bye_challenge>: require_only_supported(<r>)
where forall <r> in <rep_cancel_100>: require_only_supported(<r>)
where forall <r> in <rep_cancel_final>: require_only_supported(<r>)
where forall <r> in <rep_invite_1xx>: require_only_supported(<r>)
where forall <r> in <rep_invite_merged_1xx>: require_only_supported(<r>)
where forall <r> in <rep_invite_100>: require_only_supported(<r>)
where forall <r> in <rep_invite_early>: require_only_supported(<r>)
where forall <r> in <rep_invite_2xx>: require_only_supported(<r>)
where forall <r> in <rep_invite_redirect>: require_only_supported(<r>)
where forall <r> in <rep_invite_use_proxy>: require_only_supported(<r>)
where forall <r> in <rep_invite_failure>: require_only_supported(<r>)
where forall <r> in <rep_invite_merged_final>: require_only_supported(<r>)
where forall <r> in <rep_invite_challenge>: require_only_supported(<r>)

# §20.12, §20.2: content codings only those the request accepted (identity
# without Accept-Encoding)
where forall <r> in <rep_options_1xx>: coding_acceptable(<r>)
where forall <r> in <rep_options_final>: coding_acceptable(<r>)
where forall <r> in <rep_options_final_direct>: coding_acceptable(<r>)
where forall <r> in <rep_options_redirect>: coding_acceptable(<r>)
where forall <r> in <rep_options_use_proxy>: coding_acceptable(<r>)
where forall <r> in <rep_options_420>: coding_acceptable(<r>)
where forall <r> in <rep_options_challenge>: coding_acceptable(<r>)
where forall <r> in <rep_options_500>: coding_acceptable(<r>)
where forall <r> in <rep_register_1xx>: coding_acceptable(<r>)
where forall <r> in <rep_register_final>: coding_acceptable(<r>)
where forall <r> in <rep_register_final_direct>: coding_acceptable(<r>)
where forall <r> in <rep_register_redirect>: coding_acceptable(<r>)
where forall <r> in <rep_register_use_proxy>: coding_acceptable(<r>)
where forall <r> in <rep_register_400>: coding_acceptable(<r>)
where forall <r> in <rep_register_challenge>: coding_acceptable(<r>)
where forall <r> in <rep_extension_1xx>: coding_acceptable(<r>)
where forall <r> in <rep_extension_final>: coding_acceptable(<r>)
where forall <r> in <rep_extension_final_direct>: coding_acceptable(<r>)
where forall <r> in <rep_extension_redirect>: coding_acceptable(<r>)
where forall <r> in <rep_extension_use_proxy>: coding_acceptable(<r>)
where forall <r> in <rep_extension_challenge>: coding_acceptable(<r>)
where forall <r> in <rep_bye_1xx>: coding_acceptable(<r>)
where forall <r> in <rep_bye_final>: coding_acceptable(<r>)
where forall <r> in <rep_bye_challenge>: coding_acceptable(<r>)
where forall <r> in <rep_cancel_100>: coding_acceptable(<r>)
where forall <r> in <rep_cancel_final>: coding_acceptable(<r>)
where forall <r> in <rep_invite_1xx>: coding_acceptable(<r>)
where forall <r> in <rep_invite_merged_1xx>: coding_acceptable(<r>)
where forall <r> in <rep_invite_100>: coding_acceptable(<r>)
where forall <r> in <rep_invite_early>: coding_acceptable(<r>)
where forall <r> in <rep_invite_2xx>: coding_acceptable(<r>)
where forall <r> in <rep_invite_redirect>: coding_acceptable(<r>)
where forall <r> in <rep_invite_use_proxy>: coding_acceptable(<r>)
where forall <r> in <rep_invite_failure>: coding_acceptable(<r>)
where forall <r> in <rep_invite_merged_final>: coding_acceptable(<r>)
where forall <r> in <rep_invite_challenge>: coding_acceptable(<r>)

# RFC 4320 §4.2: a transaction-stateful element never sends 408 to a
# non-INVITE request
where forall <r> in <rep_options_final>: no_408_to_non_invite(<r>)
where forall <r> in <rep_options_final_direct>: no_408_to_non_invite(<r>)
where forall <r> in <rep_options_redirect>: no_408_to_non_invite(<r>)
where forall <r> in <rep_options_use_proxy>: no_408_to_non_invite(<r>)
where forall <r> in <rep_register_final>: no_408_to_non_invite(<r>)
where forall <r> in <rep_register_final_direct>: no_408_to_non_invite(<r>)
where forall <r> in <rep_register_redirect>: no_408_to_non_invite(<r>)
where forall <r> in <rep_register_use_proxy>: no_408_to_non_invite(<r>)
where forall <r> in <rep_extension_final>: no_408_to_non_invite(<r>)
where forall <r> in <rep_extension_final_direct>: no_408_to_non_invite(<r>)
where forall <r> in <rep_extension_redirect>: no_408_to_non_invite(<r>)
where forall <r> in <rep_extension_use_proxy>: no_408_to_non_invite(<r>)
where forall <r> in <rep_bye_final>: no_408_to_non_invite(<r>)
where forall <r> in <rep_cancel_final>: no_408_to_non_invite(<r>)

# §8.2.6.2, §12.1.1: a UAS reply other than 100 carries a To tag, the same
# for all replies of the UAS to one request (a forking proxy, §16.7, passes
# on replies of several UASs to an INVITE)
where forall <r> in <rep_options_1xx>: to_tag_consistent(<r>)
where forall <r> in <rep_options_final>: to_tag_consistent(<r>)
where forall <r> in <rep_options_final_direct>: to_tag_consistent(<r>)
where forall <r> in <rep_options_redirect>: to_tag_consistent(<r>)
where forall <r> in <rep_options_use_proxy>: to_tag_consistent(<r>)
where forall <r> in <rep_options_420>: to_tag_consistent(<r>)
where forall <r> in <rep_options_challenge>: to_tag_consistent(<r>)
where forall <r> in <rep_options_500>: to_tag_consistent(<r>)
where forall <r> in <rep_register_1xx>: to_tag_consistent(<r>)
where forall <r> in <rep_register_final>: to_tag_consistent(<r>)
where forall <r> in <rep_register_final_direct>: to_tag_consistent(<r>)
where forall <r> in <rep_register_redirect>: to_tag_consistent(<r>)
where forall <r> in <rep_register_use_proxy>: to_tag_consistent(<r>)
where forall <r> in <rep_register_400>: to_tag_consistent(<r>)
where forall <r> in <rep_register_challenge>: to_tag_consistent(<r>)
where forall <r> in <rep_extension_1xx>: to_tag_consistent(<r>)
where forall <r> in <rep_extension_final>: to_tag_consistent(<r>)
where forall <r> in <rep_extension_final_direct>: to_tag_consistent(<r>)
where forall <r> in <rep_extension_redirect>: to_tag_consistent(<r>)
where forall <r> in <rep_extension_use_proxy>: to_tag_consistent(<r>)
where forall <r> in <rep_extension_challenge>: to_tag_consistent(<r>)
where forall <r> in <rep_bye_1xx>: to_tag_consistent(<r>)
where forall <r> in <rep_bye_final>: to_tag_consistent(<r>)
where forall <r> in <rep_bye_challenge>: to_tag_consistent(<r>)
where forall <r> in <rep_cancel_100>: to_tag_consistent(<r>)
where forall <r> in <rep_cancel_final>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_1xx>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_merged_1xx>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_100>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_early>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_2xx>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_redirect>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_use_proxy>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_failure>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_merged_final>: to_tag_consistent(<r>)
where forall <r> in <rep_invite_challenge>: to_tag_consistent(<r>)

# §8.1.1, §20 Tables 2/3: the mandatory fields once, §7.3.1 fields that are
# no comma-separated list at most once, §20.15 a body needs Content-Type
where forall <r> in <rep_options_1xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_final>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_final_direct>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_redirect>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_use_proxy>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_420>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_challenge>: mandatory_reply_fields(<r>)
where forall <r> in <rep_options_500>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_1xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_final>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_final_direct>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_redirect>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_use_proxy>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_400>: mandatory_reply_fields(<r>)
where forall <r> in <rep_register_challenge>: mandatory_reply_fields(<r>)
where forall <r> in <rep_extension_1xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_extension_final>: mandatory_reply_fields(<r>)
where forall <r> in <rep_extension_final_direct>: mandatory_reply_fields(<r>)
where forall <r> in <rep_extension_redirect>: mandatory_reply_fields(<r>)
where forall <r> in <rep_extension_use_proxy>: mandatory_reply_fields(<r>)
where forall <r> in <rep_extension_challenge>: mandatory_reply_fields(<r>)
where forall <r> in <rep_bye_1xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_bye_final>: mandatory_reply_fields(<r>)
where forall <r> in <rep_bye_challenge>: mandatory_reply_fields(<r>)
where forall <r> in <rep_cancel_100>: mandatory_reply_fields(<r>)
where forall <r> in <rep_cancel_final>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_1xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_merged_1xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_100>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_early>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_2xx>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_redirect>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_use_proxy>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_failure>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_merged_final>: mandatory_reply_fields(<r>)
where forall <r> in <rep_invite_challenge>: mandatory_reply_fields(<r>)
where forall <r> in <srv_req_bye>: mandatory_reply_fields(<r>)
where forall <r> in <srv_req_reinvite>: mandatory_reply_fields(<r>)
where forall <r> in <srv_req_options>: mandatory_reply_fields(<r>)
where forall <r> in <srv_req_extension>: mandatory_reply_fields(<r>)
where forall <r> in <srv_req_ack>: mandatory_reply_fields(<r>)

# §20 Tables 2/3: a field marked "-" for the method and reply class (or
# outside its "where" column) does not appear
where forall <r> in <rep_options_1xx>: fields_applicable(<r>)
where forall <r> in <rep_options_final>: fields_applicable(<r>)
where forall <r> in <rep_options_final_direct>: fields_applicable(<r>)
where forall <r> in <rep_options_redirect>: fields_applicable(<r>)
where forall <r> in <rep_options_use_proxy>: fields_applicable(<r>)
where forall <r> in <rep_options_420>: fields_applicable(<r>)
where forall <r> in <rep_options_challenge>: fields_applicable(<r>)
where forall <r> in <rep_options_500>: fields_applicable(<r>)
where forall <r> in <rep_register_1xx>: fields_applicable(<r>)
where forall <r> in <rep_register_final>: fields_applicable(<r>)
where forall <r> in <rep_register_final_direct>: fields_applicable(<r>)
where forall <r> in <rep_register_redirect>: fields_applicable(<r>)
where forall <r> in <rep_register_use_proxy>: fields_applicable(<r>)
where forall <r> in <rep_register_400>: fields_applicable(<r>)
where forall <r> in <rep_register_challenge>: fields_applicable(<r>)
where forall <r> in <rep_extension_1xx>: fields_applicable(<r>)
where forall <r> in <rep_extension_final>: fields_applicable(<r>)
where forall <r> in <rep_extension_final_direct>: fields_applicable(<r>)
where forall <r> in <rep_extension_redirect>: fields_applicable(<r>)
where forall <r> in <rep_extension_use_proxy>: fields_applicable(<r>)
where forall <r> in <rep_extension_challenge>: fields_applicable(<r>)
where forall <r> in <rep_bye_1xx>: fields_applicable(<r>)
where forall <r> in <rep_bye_final>: fields_applicable(<r>)
where forall <r> in <rep_bye_challenge>: fields_applicable(<r>)
where forall <r> in <rep_cancel_100>: fields_applicable(<r>)
where forall <r> in <rep_cancel_final>: fields_applicable(<r>)
where forall <r> in <rep_invite_1xx>: fields_applicable(<r>)
where forall <r> in <rep_invite_merged_1xx>: fields_applicable(<r>)
where forall <r> in <rep_invite_100>: fields_applicable(<r>)
where forall <r> in <rep_invite_early>: fields_applicable(<r>)
where forall <r> in <rep_invite_2xx>: fields_applicable(<r>)
where forall <r> in <rep_invite_redirect>: fields_applicable(<r>)
where forall <r> in <rep_invite_use_proxy>: fields_applicable(<r>)
where forall <r> in <rep_invite_failure>: fields_applicable(<r>)
where forall <r> in <rep_invite_merged_final>: fields_applicable(<r>)
where forall <r> in <rep_invite_challenge>: fields_applicable(<r>)
where forall <r> in <srv_req_bye>: fields_applicable(<r>)
where forall <r> in <srv_req_reinvite>: fields_applicable(<r>)
where forall <r> in <srv_req_options>: fields_applicable(<r>)
where forall <r> in <srv_req_extension>: fields_applicable(<r>)
where forall <r> in <srv_req_ack>: fields_applicable(<r>)

# §21.4.6 405 carries Allow; §20.44/§20.27, RFC 8760 401/407 carry Digest
# challenges with qop, one per realm and algorithm; §21.4.13, §8.2.3 415
# carries Accept / Accept-Encoding / Accept-Language for what failed;
# §21.4.15, §8.2.2.3 420 lists the unknown Require tags in Unsupported;
# §21.4.16 421 carries Require; §10.3 step 7 423 carries Min-Expires
where forall <r> in <rep_options_final>: status_required_fields(<r>)
where forall <r> in <rep_options_final_direct>: status_required_fields(<r>)
where forall <r> in <rep_options_redirect>: status_required_fields(<r>)
where forall <r> in <rep_options_use_proxy>: status_required_fields(<r>)
where forall <r> in <rep_options_420>: status_required_fields(<r>)
where forall <r> in <rep_options_challenge>: status_required_fields(<r>)
where forall <r> in <rep_options_500>: status_required_fields(<r>)
where forall <r> in <rep_register_final>: status_required_fields(<r>)
where forall <r> in <rep_register_final_direct>: status_required_fields(<r>)
where forall <r> in <rep_register_redirect>: status_required_fields(<r>)
where forall <r> in <rep_register_use_proxy>: status_required_fields(<r>)
where forall <r> in <rep_register_400>: status_required_fields(<r>)
where forall <r> in <rep_register_challenge>: status_required_fields(<r>)
where forall <r> in <rep_extension_final>: status_required_fields(<r>)
where forall <r> in <rep_extension_final_direct>: status_required_fields(<r>)
where forall <r> in <rep_extension_redirect>: status_required_fields(<r>)
where forall <r> in <rep_extension_use_proxy>: status_required_fields(<r>)
where forall <r> in <rep_extension_challenge>: status_required_fields(<r>)
where forall <r> in <rep_bye_final>: status_required_fields(<r>)
where forall <r> in <rep_bye_challenge>: status_required_fields(<r>)
where forall <r> in <rep_cancel_final>: status_required_fields(<r>)
where forall <r> in <rep_invite_2xx>: status_required_fields(<r>)
where forall <r> in <rep_invite_redirect>: status_required_fields(<r>)
where forall <r> in <rep_invite_use_proxy>: status_required_fields(<r>)
where forall <r> in <rep_invite_failure>: status_required_fields(<r>)
where forall <r> in <rep_invite_merged_final>: status_required_fields(<r>)
where forall <r> in <rep_invite_challenge>: status_required_fields(<r>)

# §18.2.1: a sent-by host that is a domain name gets a received parameter
where forall <r> in <rep_options_1xx>: via_received_added(<r>)
where forall <r> in <rep_options_final>: via_received_added(<r>)
where forall <r> in <rep_options_final_direct>: via_received_added(<r>)
where forall <r> in <rep_options_redirect>: via_received_added(<r>)
where forall <r> in <rep_options_use_proxy>: via_received_added(<r>)
where forall <r> in <rep_options_420>: via_received_added(<r>)
where forall <r> in <rep_options_challenge>: via_received_added(<r>)
where forall <r> in <rep_options_500>: via_received_added(<r>)
where forall <r> in <rep_register_1xx>: via_received_added(<r>)
where forall <r> in <rep_register_final>: via_received_added(<r>)
where forall <r> in <rep_register_final_direct>: via_received_added(<r>)
where forall <r> in <rep_register_redirect>: via_received_added(<r>)
where forall <r> in <rep_register_use_proxy>: via_received_added(<r>)
where forall <r> in <rep_register_400>: via_received_added(<r>)
where forall <r> in <rep_register_challenge>: via_received_added(<r>)
where forall <r> in <rep_extension_1xx>: via_received_added(<r>)
where forall <r> in <rep_extension_final>: via_received_added(<r>)
where forall <r> in <rep_extension_final_direct>: via_received_added(<r>)
where forall <r> in <rep_extension_redirect>: via_received_added(<r>)
where forall <r> in <rep_extension_use_proxy>: via_received_added(<r>)
where forall <r> in <rep_extension_challenge>: via_received_added(<r>)
where forall <r> in <rep_bye_1xx>: via_received_added(<r>)
where forall <r> in <rep_bye_final>: via_received_added(<r>)
where forall <r> in <rep_bye_challenge>: via_received_added(<r>)
where forall <r> in <rep_cancel_100>: via_received_added(<r>)
where forall <r> in <rep_cancel_final>: via_received_added(<r>)
where forall <r> in <rep_invite_1xx>: via_received_added(<r>)
where forall <r> in <rep_invite_merged_1xx>: via_received_added(<r>)
where forall <r> in <rep_invite_100>: via_received_added(<r>)
where forall <r> in <rep_invite_early>: via_received_added(<r>)
where forall <r> in <rep_invite_2xx>: via_received_added(<r>)
where forall <r> in <rep_invite_redirect>: via_received_added(<r>)
where forall <r> in <rep_invite_use_proxy>: via_received_added(<r>)
where forall <r> in <rep_invite_failure>: via_received_added(<r>)
where forall <r> in <rep_invite_merged_final>: via_received_added(<r>)
where forall <r> in <rep_invite_challenge>: via_received_added(<r>)

# §20.12: the codings of Content-Encoding are listed in the order applied
where forall <r> in <rep_options_1xx>: codings_in_order(<r>)
where forall <r> in <rep_options_final>: codings_in_order(<r>)
where forall <r> in <rep_options_final_direct>: codings_in_order(<r>)
where forall <r> in <rep_options_redirect>: codings_in_order(<r>)
where forall <r> in <rep_options_use_proxy>: codings_in_order(<r>)
where forall <r> in <rep_options_420>: codings_in_order(<r>)
where forall <r> in <rep_options_challenge>: codings_in_order(<r>)
where forall <r> in <rep_options_500>: codings_in_order(<r>)
where forall <r> in <rep_register_1xx>: codings_in_order(<r>)
where forall <r> in <rep_register_final>: codings_in_order(<r>)
where forall <r> in <rep_register_final_direct>: codings_in_order(<r>)
where forall <r> in <rep_register_redirect>: codings_in_order(<r>)
where forall <r> in <rep_register_use_proxy>: codings_in_order(<r>)
where forall <r> in <rep_register_400>: codings_in_order(<r>)
where forall <r> in <rep_register_challenge>: codings_in_order(<r>)
where forall <r> in <rep_extension_1xx>: codings_in_order(<r>)
where forall <r> in <rep_extension_final>: codings_in_order(<r>)
where forall <r> in <rep_extension_final_direct>: codings_in_order(<r>)
where forall <r> in <rep_extension_redirect>: codings_in_order(<r>)
where forall <r> in <rep_extension_use_proxy>: codings_in_order(<r>)
where forall <r> in <rep_extension_challenge>: codings_in_order(<r>)
where forall <r> in <rep_bye_1xx>: codings_in_order(<r>)
where forall <r> in <rep_bye_final>: codings_in_order(<r>)
where forall <r> in <rep_bye_challenge>: codings_in_order(<r>)
where forall <r> in <rep_cancel_100>: codings_in_order(<r>)
where forall <r> in <rep_cancel_final>: codings_in_order(<r>)
where forall <r> in <rep_invite_1xx>: codings_in_order(<r>)
where forall <r> in <rep_invite_merged_1xx>: codings_in_order(<r>)
where forall <r> in <rep_invite_100>: codings_in_order(<r>)
where forall <r> in <rep_invite_early>: codings_in_order(<r>)
where forall <r> in <rep_invite_2xx>: codings_in_order(<r>)
where forall <r> in <rep_invite_redirect>: codings_in_order(<r>)
where forall <r> in <rep_invite_use_proxy>: codings_in_order(<r>)
where forall <r> in <rep_invite_failure>: codings_in_order(<r>)
where forall <r> in <rep_invite_merged_final>: codings_in_order(<r>)
where forall <r> in <rep_invite_challenge>: codings_in_order(<r>)
where forall <r> in <srv_req_bye>: codings_in_order(<r>)
where forall <r> in <srv_req_reinvite>: codings_in_order(<r>)
where forall <r> in <srv_req_options>: codings_in_order(<r>)
where forall <r> in <srv_req_extension>: codings_in_order(<r>)
where forall <r> in <srv_req_ack>: codings_in_order(<r>)

# RFC 5621 §6.2, §8.2, §9.2: multipart/alternative parts differ in type and
# share the disposition; cid: references point forward
where forall <r> in <rep_options_1xx>: multipart_rules(<r>)
where forall <r> in <rep_options_final>: multipart_rules(<r>)
where forall <r> in <rep_options_final_direct>: multipart_rules(<r>)
where forall <r> in <rep_options_redirect>: multipart_rules(<r>)
where forall <r> in <rep_options_use_proxy>: multipart_rules(<r>)
where forall <r> in <rep_options_420>: multipart_rules(<r>)
where forall <r> in <rep_options_challenge>: multipart_rules(<r>)
where forall <r> in <rep_options_500>: multipart_rules(<r>)
where forall <r> in <rep_register_1xx>: multipart_rules(<r>)
where forall <r> in <rep_register_final>: multipart_rules(<r>)
where forall <r> in <rep_register_final_direct>: multipart_rules(<r>)
where forall <r> in <rep_register_redirect>: multipart_rules(<r>)
where forall <r> in <rep_register_use_proxy>: multipart_rules(<r>)
where forall <r> in <rep_register_400>: multipart_rules(<r>)
where forall <r> in <rep_register_challenge>: multipart_rules(<r>)
where forall <r> in <rep_extension_1xx>: multipart_rules(<r>)
where forall <r> in <rep_extension_final>: multipart_rules(<r>)
where forall <r> in <rep_extension_final_direct>: multipart_rules(<r>)
where forall <r> in <rep_extension_redirect>: multipart_rules(<r>)
where forall <r> in <rep_extension_use_proxy>: multipart_rules(<r>)
where forall <r> in <rep_extension_challenge>: multipart_rules(<r>)
where forall <r> in <rep_bye_1xx>: multipart_rules(<r>)
where forall <r> in <rep_bye_final>: multipart_rules(<r>)
where forall <r> in <rep_bye_challenge>: multipart_rules(<r>)
where forall <r> in <rep_cancel_100>: multipart_rules(<r>)
where forall <r> in <rep_cancel_final>: multipart_rules(<r>)
where forall <r> in <rep_invite_1xx>: multipart_rules(<r>)
where forall <r> in <rep_invite_merged_1xx>: multipart_rules(<r>)
where forall <r> in <rep_invite_100>: multipart_rules(<r>)
where forall <r> in <rep_invite_early>: multipart_rules(<r>)
where forall <r> in <rep_invite_2xx>: multipart_rules(<r>)
where forall <r> in <rep_invite_redirect>: multipart_rules(<r>)
where forall <r> in <rep_invite_use_proxy>: multipart_rules(<r>)
where forall <r> in <rep_invite_failure>: multipart_rules(<r>)
where forall <r> in <rep_invite_merged_final>: multipart_rules(<r>)
where forall <r> in <rep_invite_challenge>: multipart_rules(<r>)
where forall <r> in <srv_req_bye>: multipart_rules(<r>)
where forall <r> in <srv_req_reinvite>: multipart_rules(<r>)
where forall <r> in <srv_req_options>: multipart_rules(<r>)
where forall <r> in <srv_req_extension>: multipart_rules(<r>)
where forall <r> in <srv_req_ack>: multipart_rules(<r>)

# §27.5: a message/sip body is one SIP message
where forall <r> in <rep_options_1xx>: message_sip_body(<r>)
where forall <r> in <rep_options_final>: message_sip_body(<r>)
where forall <r> in <rep_options_final_direct>: message_sip_body(<r>)
where forall <r> in <rep_options_redirect>: message_sip_body(<r>)
where forall <r> in <rep_options_use_proxy>: message_sip_body(<r>)
where forall <r> in <rep_options_420>: message_sip_body(<r>)
where forall <r> in <rep_options_challenge>: message_sip_body(<r>)
where forall <r> in <rep_options_500>: message_sip_body(<r>)
where forall <r> in <rep_register_1xx>: message_sip_body(<r>)
where forall <r> in <rep_register_final>: message_sip_body(<r>)
where forall <r> in <rep_register_final_direct>: message_sip_body(<r>)
where forall <r> in <rep_register_redirect>: message_sip_body(<r>)
where forall <r> in <rep_register_use_proxy>: message_sip_body(<r>)
where forall <r> in <rep_register_400>: message_sip_body(<r>)
where forall <r> in <rep_register_challenge>: message_sip_body(<r>)
where forall <r> in <rep_extension_1xx>: message_sip_body(<r>)
where forall <r> in <rep_extension_final>: message_sip_body(<r>)
where forall <r> in <rep_extension_final_direct>: message_sip_body(<r>)
where forall <r> in <rep_extension_redirect>: message_sip_body(<r>)
where forall <r> in <rep_extension_use_proxy>: message_sip_body(<r>)
where forall <r> in <rep_extension_challenge>: message_sip_body(<r>)
where forall <r> in <rep_bye_1xx>: message_sip_body(<r>)
where forall <r> in <rep_bye_final>: message_sip_body(<r>)
where forall <r> in <rep_bye_challenge>: message_sip_body(<r>)
where forall <r> in <rep_cancel_100>: message_sip_body(<r>)
where forall <r> in <rep_cancel_final>: message_sip_body(<r>)
where forall <r> in <rep_invite_1xx>: message_sip_body(<r>)
where forall <r> in <rep_invite_merged_1xx>: message_sip_body(<r>)
where forall <r> in <rep_invite_100>: message_sip_body(<r>)
where forall <r> in <rep_invite_early>: message_sip_body(<r>)
where forall <r> in <rep_invite_2xx>: message_sip_body(<r>)
where forall <r> in <rep_invite_redirect>: message_sip_body(<r>)
where forall <r> in <rep_invite_use_proxy>: message_sip_body(<r>)
where forall <r> in <rep_invite_failure>: message_sip_body(<r>)
where forall <r> in <rep_invite_merged_final>: message_sip_body(<r>)
where forall <r> in <rep_invite_challenge>: message_sip_body(<r>)
where forall <r> in <srv_req_bye>: message_sip_body(<r>)
where forall <r> in <srv_req_reinvite>: message_sip_body(<r>)
where forall <r> in <srv_req_options>: message_sip_body(<r>)
where forall <r> in <srv_req_extension>: message_sip_body(<r>)
where forall <r> in <srv_req_ack>: message_sip_body(<r>)

# §22.4 / RFC 2617: rspauth of Authentication-Info proves the server knows
# the credentials
where forall <r> in <rep_options_final>: rspauth_valid(<r>)
where forall <r> in <rep_options_final_direct>: rspauth_valid(<r>)
where forall <r> in <rep_options_redirect>: rspauth_valid(<r>)
where forall <r> in <rep_options_use_proxy>: rspauth_valid(<r>)
where forall <r> in <rep_register_final>: rspauth_valid(<r>)
where forall <r> in <rep_register_final_direct>: rspauth_valid(<r>)
where forall <r> in <rep_register_redirect>: rspauth_valid(<r>)
where forall <r> in <rep_register_use_proxy>: rspauth_valid(<r>)
where forall <r> in <rep_extension_final>: rspauth_valid(<r>)
where forall <r> in <rep_extension_final_direct>: rspauth_valid(<r>)
where forall <r> in <rep_extension_redirect>: rspauth_valid(<r>)
where forall <r> in <rep_extension_use_proxy>: rspauth_valid(<r>)
where forall <r> in <rep_bye_final>: rspauth_valid(<r>)
where forall <r> in <rep_cancel_final>: rspauth_valid(<r>)
where forall <r> in <rep_invite_2xx>: rspauth_valid(<r>)

# §16.3 step 3: a proxy answers a request with Max-Forwards 0 (not OPTIONS)
# with 483; §16.3 step 5 an unknown Proxy-Require option tag with 420
where forall <r> in <rep_options_final>: proxy_validation(<r>)
where forall <r> in <rep_options_final_direct>: proxy_validation(<r>)
where forall <r> in <rep_options_redirect>: proxy_validation(<r>)
where forall <r> in <rep_options_use_proxy>: proxy_validation(<r>)
where forall <r> in <rep_options_420>: proxy_validation(<r>)
where forall <r> in <rep_options_500>: proxy_validation(<r>)
where forall <r> in <rep_register_final>: proxy_validation(<r>)
where forall <r> in <rep_register_final_direct>: proxy_validation(<r>)
where forall <r> in <rep_register_redirect>: proxy_validation(<r>)
where forall <r> in <rep_register_use_proxy>: proxy_validation(<r>)
where forall <r> in <rep_register_400>: proxy_validation(<r>)
where forall <r> in <rep_extension_final>: proxy_validation(<r>)
where forall <r> in <rep_extension_final_direct>: proxy_validation(<r>)
where forall <r> in <rep_extension_redirect>: proxy_validation(<r>)
where forall <r> in <rep_extension_use_proxy>: proxy_validation(<r>)
where forall <r> in <rep_bye_final>: proxy_validation(<r>)
where forall <r> in <rep_cancel_final>: proxy_validation(<r>)
where forall <r> in <rep_invite_2xx>: proxy_validation(<r>)
where forall <r> in <rep_invite_redirect>: proxy_validation(<r>)
where forall <r> in <rep_invite_use_proxy>: proxy_validation(<r>)
where forall <r> in <rep_invite_failure>: proxy_validation(<r>)
where forall <r> in <rep_invite_merged_final>: proxy_validation(<r>)
where forall <r> in <rep_options_challenge>: proxy_validation(<r>)
where forall <r> in <rep_register_challenge>: proxy_validation(<r>)
where forall <r> in <rep_extension_challenge>: proxy_validation(<r>)
where forall <r> in <rep_bye_challenge>: proxy_validation(<r>)
where forall <r> in <rep_invite_challenge>: proxy_validation(<r>)

# §8.2.3: a body that is not understood and not optional is refused (415)
where forall <r> in <rep_options_final>: body_refused(<r>)
where forall <r> in <rep_options_final_direct>: body_refused(<r>)
where forall <r> in <rep_options_redirect>: body_refused(<r>)
where forall <r> in <rep_options_use_proxy>: body_refused(<r>)
where forall <r> in <rep_register_final>: body_refused(<r>)
where forall <r> in <rep_register_final_direct>: body_refused(<r>)
where forall <r> in <rep_register_redirect>: body_refused(<r>)
where forall <r> in <rep_register_use_proxy>: body_refused(<r>)
where forall <r> in <rep_extension_final>: body_refused(<r>)
where forall <r> in <rep_extension_final_direct>: body_refused(<r>)
where forall <r> in <rep_extension_redirect>: body_refused(<r>)
where forall <r> in <rep_extension_use_proxy>: body_refused(<r>)
where forall <r> in <rep_bye_final>: body_refused(<r>)
where forall <r> in <rep_cancel_final>: body_refused(<r>)
where forall <r> in <rep_invite_2xx>: body_refused(<r>)

# §14.2: a re-INVITE that arrives while an earlier one of the dialog has no
# final reply yet is refused with 500 and Retry-After 0-10 s
where forall <r> in <rep_invite_2xx>: overlap_refused(<r>)
where forall <r> in <rep_invite_redirect>: overlap_refused(<r>)
where forall <r> in <rep_invite_use_proxy>: overlap_refused(<r>)
where forall <r> in <rep_invite_failure>: overlap_refused(<r>)
where forall <r> in <rep_invite_merged_final>: overlap_refused(<r>)
where forall <r> in <rep_invite_challenge>: overlap_refused(<r>)

# RFC 6026 §8.9: a stray response matches no pending client transaction
where forall <r> in <rep_stray>: stray_reply(<r>)
# §17.2.1: a repeated final reply only over UDP, unchanged
where forall <r> in <rep_invite_final_again>: final_retransmitted(<r>)
where forall <r> in <rep_stray_invite>: stray_reply(<r>)
# §17.1.1.2: a repetition of the final reply right after its ACK is the
# Completed state's (<state_invite_acked>), ACKed again, not a stray one
where forall <r> in <rep_stray_invite>: not final_repeated_after_ack(<r>)
where forall <r> in <rep_stray_pending>: stray_reply(<r>)
where forall <r> in <rep_stray_pending>: not_latest_invite(<r>)
where forall <r> in <rep_stray_pending>: not final_retransmitted(<r>)
where forall <r> in <rep_stray_in_dialog>: not final_repeated_after_ack(<r>)
where forall <r> in <rep_stray_pending>: no_408_to_non_invite(<r>)
# §8.2.2.2, §17.1.3: the replies of the merged INVITE carry its branch, those
# of the first INVITE do not
where forall <r> in <rep_invite_merged_1xx>: answers_merged(<r>)
where forall <r> in <rep_invite_merged_final>: answers_merged(<r>)
where forall <r> in <rep_invite_100>: not answers_merged(<r>)
where forall <r> in <rep_invite_early>: not answers_merged(<r>)
where forall <r> in <rep_invite_1xx>: not answers_merged(<r>)
where forall <r> in <rep_invite_2xx>: not answers_merged(<r>)
where forall <r> in <rep_invite_redirect>: not answers_merged(<r>)
where forall <r> in <rep_invite_use_proxy>: not answers_merged(<r>)
where forall <r> in <rep_invite_failure>: not answers_merged(<r>)
where forall <r> in <rep_invite_challenge>: not answers_merged(<r>)
where forall <r> in <rep_invite_final_again>: not answers_merged(<r>)
# RFC 6026 §8.9: a regular reply answers the latest INVITE or a request still
# waiting for its final reply (else it is <rep_stray_pending>)
where forall <r> in <rep_invite_100>: answers_pending(<r>)
where forall <r> in <rep_invite_early>: answers_pending(<r>)
where forall <r> in <rep_invite_1xx>: answers_pending(<r>)
where forall <r> in <rep_invite_merged_1xx>: answers_pending(<r>)
where forall <r> in <rep_invite_redirect>: answers_pending(<r>)
where forall <r> in <rep_invite_use_proxy>: answers_pending(<r>)
where forall <r> in <rep_invite_failure>: answers_pending(<r>)
where forall <r> in <rep_invite_merged_final>: answers_pending(<r>)
where forall <r> in <rep_invite_challenge>: answers_pending(<r>)
where forall <r> in <rep_cancel_100>: answers_pending(<r>)
where forall <r> in <rep_cancel_final>: answers_pending(<r>)

where forall <r> in <rep_stray_other>: stray_reply(<r>)
where forall <r> in <rep_stray_other>: no_408_to_non_invite(<r>)
where forall <r> in <rep_stray_in_dialog>: stray_reply(<r>)
# RFC 4320 §4.2: no 408 to a non-INVITE request, also late (stray)
where forall <r> in <rep_stray>: no_408_to_non_invite(<r>)
where forall <r> in <rep_stray_invite>: no_408_to_non_invite(<r>)
where forall <r> in <rep_stray_in_dialog>: no_408_to_non_invite(<r>)

# §9.2, §17.2.3: a CANCEL that matches no transaction (other branch, other
# sent-by, no transaction at all) SHOULD get 481; no MUST forbids another
# reply, so every final reply to it is accepted (<rep_cancel_final>), and a
# server that took it for a match may end the INVITE with 487

# §9.2, §15.1.2: a 487 ends an INVITE only after a CANCEL of it (any of the
# CANCELs with its Call-ID and CSeq number) or a BYE of its early dialog
where forall <r> in <rep_invite_failure>: invite_487_cancelled(<r>)

# §12.1.1, §13.3.1.4: the 2xx establishing the dialog carries a Contact with
# one SIP or SIPS URI; RFC 3261 §13.3.1.4 / RFC 3264: it answers our offer
where forall <r> in <rep_invite_2xx>: dialog_reply_fields(<r>)
# §8.2.6.2, §12.1.1: a 101-199 reply has a To tag and, creating an early
# dialog, one Contact with a SIP URI
where forall <r> in <rep_invite_early>: early_dialog_fields(<r>)

# §8.3: a redirect server does not redirect to the Request-URI itself
where forall <r> in <rep_invite_redirect>: redirect_not_to_self(<r>)
where forall <r> in <rep_options_final>: redirect_not_to_self(<r>)
where forall <r> in <rep_options_final_direct>: redirect_not_to_self(<r>)
where forall <r> in <rep_options_redirect>: redirect_not_to_self(<r>)
where forall <r> in <rep_options_use_proxy>: redirect_not_to_self(<r>)
where forall <r> in <rep_register_final>: redirect_not_to_self(<r>)
where forall <r> in <rep_register_final_direct>: redirect_not_to_self(<r>)
where forall <r> in <rep_register_redirect>: redirect_not_to_self(<r>)
where forall <r> in <rep_register_use_proxy>: redirect_not_to_self(<r>)
where forall <r> in <rep_extension_final>: redirect_not_to_self(<r>)
where forall <r> in <rep_extension_final_direct>: redirect_not_to_self(<r>)
where forall <r> in <rep_extension_redirect>: redirect_not_to_self(<r>)
where forall <r> in <rep_extension_use_proxy>: redirect_not_to_self(<r>)
where forall <r> in <rep_bye_final>: redirect_not_to_self(<r>)

# §10.3 step 8: a 2xx to REGISTER lists the current bindings, each with
# expires (step 7: the Contact's expires before Expires, 0 removes; the
# interval itself is the registrar's choice, §10.2.1.1); step 7: 423 only for an expiration > 0, < 3600 and below the
# minimum; steps 5-7: refusals of an unknown address-of-record and of an
# out-of-order CSeq
where forall <r> in <rep_register_final>: register_bindings_listed(<r>)
where forall <r> in <rep_register_final_direct>: register_bindings_listed(<r>)
where forall <r> in <rep_register_redirect>: register_bindings_listed(<r>)
where forall <r> in <rep_register_use_proxy>: register_bindings_listed(<r>)
where forall <r> in <rep_register_final>: register_423_justified(<r>)
where forall <r> in <rep_register_final_direct>: register_423_justified(<r>)
where forall <r> in <rep_register_redirect>: register_423_justified(<r>)
where forall <r> in <rep_register_use_proxy>: register_423_justified(<r>)
where forall <r> in <rep_register_final>: register_refusals(<r>)
where forall <r> in <rep_register_final_direct>: register_refusals(<r>)
where forall <r> in <rep_register_redirect>: register_refusals(<r>)
where forall <r> in <rep_register_use_proxy>: register_refusals(<r>)
# §10.3 step 8: the bindings stored before are listed too
where forall <r> in <rep_register_final>: stored_bindings_listed(<r>)
where forall <r> in <rep_register_final_direct>: stored_bindings_listed(<r>)
where forall <r> in <rep_register_redirect>: stored_bindings_listed(<r>)
where forall <r> in <rep_register_use_proxy>: stored_bindings_listed(<r>)

# §18.1.1: over UDP no request is larger than 1300 bytes
where forall <r> in <req_ack_2xx>: fits_transport(<r>)
where forall <r> in <req_ack_2xx_again>: fits_transport(<r>)
where forall <r> in <req_ack_failure>: fits_transport(<r>)
where forall <r> in <req_ack_reinvite_2xx>: fits_transport(<r>)
where forall <r> in <req_ack_reinvite_failure>: fits_transport(<r>)
where forall <r> in <req_bye>: fits_transport(<r>)
where forall <r> in <req_bye_auth>: fits_transport(<r>)
where forall <r> in <req_bye_early>: fits_transport(<r>)
where forall <r> in <req_bye_no_dialog>: fits_transport(<r>)
where forall <r> in <req_cancel>: fits_transport(<r>)
where forall <r> in <req_cancel_no_transaction>: fits_transport(<r>)
where forall <r> in <req_cancel_other_branch>: fits_transport(<r>)
where forall <r> in <req_cancel_other_sent_by>: fits_transport(<r>)
where forall <r> in <req_extension>: fits_transport(<r>)
where forall <r> in <req_extension_auth>: fits_transport(<r>)
where forall <r> in <req_extension_dialog>: fits_transport(<r>)
where forall <r> in <req_extension_redirected>: fits_transport(<r>)
where forall <r> in <req_extension_via_proxy>: fits_transport(<r>)
where forall <r> in <req_invite>: fits_transport(<r>)
where forall <r> in <req_invite_auth>: fits_transport(<r>)
where forall <r> in <req_invite_merged>: fits_transport(<r>)
where forall <r> in <req_invite_redirected>: fits_transport(<r>)
where forall <r> in <req_invite_via_proxy>: fits_transport(<r>)
where forall <r> in <rep_bye_1xx>: answers_pending(<r>)
where forall <r> in <rep_bye_challenge>: answers_pending(<r>)
where forall <r> in <rep_bye_final>: answers_pending(<r>)
where forall <r> in <rep_extension_1xx>: answers_pending(<r>)
where forall <r> in <rep_extension_challenge>: answers_pending(<r>)
where forall <r> in <rep_extension_final>: answers_pending(<r>)
where forall <r> in <rep_extension_final_direct>: answers_pending(<r>)
where forall <r> in <rep_extension_redirect>: answers_pending(<r>)
where forall <r> in <rep_extension_use_proxy>: answers_pending(<r>)
where forall <r> in <rep_options_1xx>: answers_pending(<r>)
where forall <r> in <rep_options_420>: answers_pending(<r>)
where forall <r> in <rep_options_500>: answers_pending(<r>)
where forall <r> in <rep_options_challenge>: answers_pending(<r>)
where forall <r> in <rep_options_final>: answers_pending(<r>)
where forall <r> in <rep_options_final_direct>: answers_pending(<r>)
where forall <r> in <rep_options_redirect>: answers_pending(<r>)
where forall <r> in <rep_options_use_proxy>: answers_pending(<r>)
where forall <r> in <rep_register_1xx>: answers_pending(<r>)
where forall <r> in <rep_register_400>: answers_pending(<r>)
where forall <r> in <rep_register_challenge>: answers_pending(<r>)
where forall <r> in <rep_register_final>: answers_pending(<r>)
where forall <r> in <rep_register_final_direct>: answers_pending(<r>)
where forall <r> in <rep_register_redirect>: answers_pending(<r>)
where forall <r> in <rep_register_use_proxy>: answers_pending(<r>)
where forall <r> in <req_options>: fits_transport(<r>)
where forall <r> in <req_options_auth>: fits_transport(<r>)
where forall <r> in <req_options_dialog>: fits_transport(<r>)
where forall <r> in <req_options_dialog_out_of_order>: fits_transport(<r>)
where forall <r> in <req_options_optional_body>: fits_transport(<r>)
where forall <r> in <req_options_optional_body_auth>: fits_transport(<r>)
where forall <r> in <req_options_proxy_require>: fits_transport(<r>)
where forall <r> in <req_options_proxy_require_auth>: fits_transport(<r>)
where forall <r> in <req_options_redirected>: fits_transport(<r>)
where forall <r> in <req_options_via_proxy>: fits_transport(<r>)
where forall <r> in <req_options_require>: fits_transport(<r>)
where forall <r> in <req_options_datagram_extra>: fits_transport(<r>)
where forall <r> in <req_options_datagram_short>: fits_transport(<r>)
# §18.3: datagram framing exists over UDP only; over TCP the octets would
# begin the next message, and a short body would make the server wait, so
# there the same messages go out without the flaw (no extra octets,
# Content-Length equal to the body) and the §18.3 checks do not apply
where forall <r> in <datagram_extra>: <r> == datagram_extra(<r>)
where forall <r> in <req_options_datagram_short>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>)) + datagram_shortfall()
where forall <r> in <resp_stray_short>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>)) + datagram_shortfall()
where forall <r> in <rep_options_final_direct>: extra_bytes_discarded(<r>)
where forall <r> in <rep_options_final_direct>: short_datagram_refused(<r>)
where forall <r> in <rep_options_challenge>: short_datagram_refused(<r>)
where forall <r> in <req_options_require_auth>: fits_transport(<r>)
where forall <r> in <req_options_unknown_encoding>: fits_transport(<r>)
where forall <r> in <req_options_unknown_encoding_auth>: fits_transport(<r>)
where forall <r> in <req_options_unknown_type>: fits_transport(<r>)
where forall <r> in <req_options_unknown_type_auth>: fits_transport(<r>)
where forall <r> in <req_register>: fits_transport(<r>)
where forall <r> in <req_register_auth>: fits_transport(<r>)
where forall <r> in <req_register_bad_wildcard>: fits_transport(<r>)
where forall <r> in <req_register_bad_wildcard_auth>: fits_transport(<r>)
where forall <r> in <req_register_old_cseq>: fits_transport(<r>)
where forall <r> in <req_register_old_cseq_auth>: fits_transport(<r>)
where forall <r> in <req_register_redirected>: fits_transport(<r>)
where forall <r> in <req_register_via_proxy>: fits_transport(<r>)
where forall <r> in <req_register_star_with_binding>: fits_transport(<r>)
where forall <r> in <req_register_star_with_binding_auth>: fits_transport(<r>)
where forall <r> in <req_register_unknown_aor>: fits_transport(<r>)
where forall <r> in <req_register_multicast>: fits_transport(<r>)
where forall <r> in <req_register_multicast_auth>: fits_transport(<r>)
where forall <r> in <req_register_unknown_aor_auth>: fits_transport(<r>)
where forall <r> in <req_reinvite>: fits_transport(<r>)
where forall <r> in <req_reinvite_auth>: fits_transport(<r>)

# §13.2.2.4: a further fork's dialog is ended with BYE, before the client
# ends the dialog it continues
where forall <r> in <req_bye_fork>: fork_unended(<r>)
where forall <r> in <req_bye>: not fork_unended(<r>)

# §8.1.1.7: the branch of every new request is unique
where forall <b> in <s_branch>: branch_unique(<b>)

# Sent fields that repeat earlier values: each equals what the history of
# the session decides (§8.1.3.5, §22.2 retry with credentials: same Call-ID,
# To, From, CSeq one higher; §17.1.1.3 ACK for a non-2xx and §9.1 CANCEL copy
# Request-URI, Call-ID, From, CSeq number, top Via and To of the INVITE, the
# ACK takes the To of the reply; §13.2.2.4 ACK for 2xx; §12.2.1.1 requests in
# the dialog: Call-ID, local and remote URI and tag, remote target, route
# set, CSeq one higher; §10.2 REGISTER: same Call-ID, CSeq one higher)
where forall <r> in <s_from_tag_same>: <r> == expect(<r>, 'from_tag')
where forall <r> in <to_text_same>: <r> == expect(<r>, 'to')
where forall <r> in <to_text_reply>: <r> == expect(<r>, 'reply_to')
where forall <r> in <to_text_dialog>: <r> == expect(<r>, 'dialog_to')
where forall <r> in <s_callid_value_same>: <r> == expect(<r>, 'call_id')
where forall <r> in <s_callid_value_register>: <r> == expect(<r>, 'register_call_id')
where forall <r> in <ruri_same>: <r> == expect(<r>, 'request_uri')
where forall <r> in <ruri_dialog>: <r> == expect(<r>, 'remote_target')
where forall <r> in <s_branch_same>: <r> == expect(<r>, 'branch')
where forall <r> in <extension_method_same>: <r> == expect(<r>, 'method')
where forall <r> in <s_route_part>: <r> == expect(<r>, 'route_part')
where forall <r> in <s_route_part_same>: <r> == expect(<r>, 'request_route_part')
where forall <r> in <s_credentials_same_part>: <r> == expect(<r>, 'credentials_part')
where forall <r> in <s_cseq_number>: <r> == expect(<r>, 'cseq')
where forall <r> in <s_cseq_number_lower>: <r> == expect(<r>, 'cseq_lower')
# §10.3 step 7: the out-of-order REGISTER has a CSeq below the stored one
where forall <r> in <s_cseq_number_old>: <r> == expect(<r>, 'cseq_old')
# §8.1.3.4: the redirected INVITE goes to a Contact URI of the 3xx, without
# method parameter and headers; the headers become header fields (§19.1.5)
where forall <r> in <ruri_redirect>: <r> == expect(<r>, 'redirect_target')
# §21.3.4: the 305's proxy as route
where forall <r> in <ruri_via_proxy>: <r> == expect(<r>, 'proxy_ruri')
where forall <r> in <s_proxy_route_part>: <r> == expect(<r>, 'proxy_route_part')
where forall <r> in <s_uri_headers_part>: <r> == expect(<r>, 'redirect_headers')
# §13.2.2.4: an ACK sent again for a 2xx has the branch of the first one
where forall <r> in <s_branch_ack>: <r> == expect(<r>, 'ack_branch')
# §17.2.3: the other sent-by differs from ours
where forall <r> in <other_port>: <r> == expect(<r>, 'other_port')
# §22.2/§22.3, RFC 8760 §2.4: credentials answer the latest challenge: the
# header field of its kind, its realm, nonce, opaque and algorithm, qop if
# offered, the Request-URI as digest-uri
# RFC 8760 §2.4: a UAC that cannot answer any challenge (no Digest challenge
# with a supported algorithm) abandons the request: no retry
where forall <c> in <s_credentials>: challenge_usable(<c>)
where forall <c> in <s_credentials_name>: <c> == expect(<c>, 'credentials_name')
where forall <c> in <s_auth_opaque_part>: <c> == expect(<c>, 'opaque_part')
where forall <c> in <s_qop>: <c> == expect(<c>, 'qop')
where forall <c> in <s_auth_realm>: <c> == expect(<c>, 'realm')
where forall <c> in <s_auth_nonce>: <c> == expect(<c>, 'nonce')
where forall <c> in <s_auth_algorithm>: <c> == expect(<c>, 'algorithm')
where forall <c> in <s_auth_uri>: <c> == expect(<c>, 'auth_uri')

# §8.2.6.2: our reply to the callee's BYE echoes its fields
where forall <x> in <echo_via>: <x> == echo(<x>, 'via')
where forall <x> in <echo_from>: <x> == echo(<x>, 'from')
where forall <x> in <echo_to>: <x> == echo(<x>, 'to')
where forall <x> in <echo_call_id>: <x> == echo(<x>, 'call_id')
where forall <x> in <echo_cseq>: <x> == echo(<x>, 'cseq')
# §8.2.2.3: the callee's OPTIONS with Require gets 420 listing the tags
where forall <x> in <resp_options_status>: <x> == echo(<x>, 'options_status')
where forall <x> in <refusal_status>: <x> == echo(<x>, 'refusal_status')
# §8.2.2.3, §8.2.3, §20.11: the callee's BYE and re-INVITE are refused (420,
# 415) exactly when they require an option tag or carry a body the client
# cannot handle that is not optional
where forall <r> in <resp_from_server_refused>: callee_request_refused(<r>)
where forall <r> in <resp_bye_from_server>: not callee_request_refused(<r>)
where forall <r> in <resp_reinvite_from_server>: not callee_request_refused(<r>)
where forall <x> in <s_unsupported_part>: <x> == echo(<x>, 'unsupported_part')
# §12.2.2: the callee's BYE belongs to the dialog: its Call-ID, our tag as To
# tag; §12.1.1 its Request-URI is our Contact, no Route (our INVITE had no
# Record-Route)
where forall <r> in <srv_req_bye>: server_request_in_dialog(<r>)
where forall <r> in <srv_req_reinvite>: server_request_in_dialog(<r>)
where forall <r> in <srv_req_options>: server_request_in_dialog(<r>)
where forall <r> in <srv_req_extension>: server_request_in_dialog(<r>)
# §8.1.1.5: the CSeq method of the callee's request is its method
where forall <r> in <srv_req_extension>: str(<r>).lstrip('\r\n').split(' ', 1)[0] == _cseq(<r>)[1]
# §13.2.2.4: the callee's ACK has the CSeq number of its re-INVITE;
# §13.2.1 it carries the answer when our 2xx carried the offer
where forall <r> in <srv_req_ack>: ack_matches_server_invite(<r>)
# §8.1.1, §20 Tables 2/3: the callee's requests carry Max-Forwards and Via,
# its re-INVITE a Contact; §7.4.1 its session description is no multipart
# body (our Accept lists application/sdp only)
where forall <r> in <srv_req_bye>: server_request_fields(<r>)
where forall <r> in <srv_req_reinvite>: server_request_fields(<r>)
where forall <r> in <srv_req_options>: server_request_fields(<r>)
where forall <r> in <srv_req_extension>: server_request_fields(<r>)
where forall <r> in <srv_req_ack>: server_request_fields(<r>)
# §20.14: Content-Length of our answer is its length in octets
where forall <r> in <resp_reinvite_from_server>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
# §13.3.1.4: a retransmission of our 2xx is the same message
where forall <r> in <resp_reinvite_from_server>: <r> == same_response(<r>)

# §22.4, RFC 8760 §2.4: the digest response of the credentials
where forall <c> in <s_digest_credentials>: <c>.<s_auth_response> == digest_response(<c>)

# §20.14: Content-Length of the offer is its length in octets
where forall <r> in <req_invite>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_invite_auth>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_invite_merged>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_reinvite>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_reinvite_auth>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_invite_redirected>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_invite_via_proxy>: int(<r>..<s_body_length>) == len(bytes(<r>.<sdp_offer>))
where forall <r> in <req_options_unknown_type>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>))
where forall <r> in <req_options_unknown_type_auth>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>))
where forall <r> in <req_options_unknown_encoding>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>))
where forall <r> in <req_options_unknown_encoding_auth>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>))
where forall <r> in <req_options_optional_body>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>))
where forall <r> in <req_options_optional_body_auth>: int(<r>..<s_body_length>) == len(bytes(<r>.<text_body>))

########################################################################
# Helpers
########################################################################

# Values recorded from received messages (the recording generators above
# and record_*) and recalled by the generators of sent fields.
_HOST = os.environ.get('SIP_SERVER_HOST', '127.0.0.1')
# Defaults until a value has been recorded; the where constraints replace
# them with what the session's history decides.
_RECORDED = {'in_require': 'x', 'remote_target': 'sip:' + _HOST, 'request_uri': 'sip:' + _HOST, 'auth_uri': 'sip:' + _HOST,
             'to': '<sip:' + _HOST + '>', 'reply_to': '<sip:' + _HOST + '>', 'branch': 'a1b2c3d4e5f6',
             'from_tag': 'a1b2c3d4', 'call_id': 'a1b2c3d4e5f6@' + _HOST, 'route_set': '<sip:' + _HOST + ';lr>',
             'realm': _HOST, 'nonce': 'a1b2c3d4', 'opaque': 'a1b2c3d4', 'algorithm': 'MD5',
             'credentials': 'Authorization: Digest username="alice"', 'method': 'XMETHOD',
             'in_via': 'SIP/2.0/TCP ' + _HOST + ';branch=z9hG4bKx', 'in_from': '<sip:' + _HOST + '>;tag=x',
             'in_to': '<sip:alice@' + _HOST + '>;tag=x', 'in_call_id': 'x@' + _HOST, 'in_cseq': '1 BYE'}
_REGISTER_CALL_ID = []
_CSEQ = [random.randrange(1, 1000)]


def record(key, value):
    if str(value):
        _RECORDED[key] = str(value)
    return str(value)


def recall(key):
    return _RECORDED.get(key) or 'x'


def new_token(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def register_call_id():
    if not _REGISTER_CALL_ID:
        _REGISTER_CALL_ID.append(new_token(20) + '@' + os.environ.get('SIP_LOCAL_HOST', '127.0.0.1'))
    return _REGISTER_CALL_ID[0]


def next_cseq():
    _CSEQ[0] += 1
    return str(_CSEQ[0])


def _sym(tree):
    return tree.symbol.name() if hasattr(tree.symbol, 'name') else str(tree.symbol)


def _find(tree, name):
    for t in tree.find_subtrees(NonTerminal(name)):
        return t
    return None


def _messages(tree):
    """The messages (request or reply trees) under tree, in order."""
    return [m.msg for m in tree.protocol_msgs()]


# The messages before a message never change once it is in the session; they
# are computed once per message node (and session root).
_BEFORE_CACHE = {}


def _session_messages_before(node):
    root = node.get_root()
    key = (id(node), id(root))
    hit = _BEFORE_CACHE.get(key)
    if hit is not None and hit[0] is node and hit[1] is root:
        return hit[2]
    out = []
    for m in root.protocol_msgs():
        if m.msg is node:
            break
        # a copy (§17.1.1.2, §17.1.2.2) is the request again, not a request
        if _sym(m.msg) != '<req_retransmit>':
            out.append(m.msg)
    if len(_BEFORE_CACHE) > 4000:
        _BEFORE_CACHE.clear()
    _BEFORE_CACHE[key] = (node, root, out)
    return out



# §17.1.1.1 Table 4
_T1, _T2 = 0.5, 4.0
_TCP_SLOT_WAIT = 1.0
# a silent server: the self-loop of a state sends a CRLF keep-alive (§7.5)
# after this long without any message instead of a copy
_IDLE_KEEPALIVE = 20.0
_COPY_CLOCK = {}
# states where the INVITE's final reply is to be ACKed at once while a CANCEL
# or BYE is pending: a copy only if its timer has already fired
_ACK_DUE_STATES = ('<state_invite_completed_cancel_pending>', '<state_invite_accepted_cancel_pending>',
                   '<state_invite_completed_bye_pending>', '<state_invite_accepted_bye_pending>',
                   '<state_reinvite_completed_cancel_pending>', '<state_reinvite_accepted_cancel_pending>')


def _raw_messages_before(node):
    out = []
    for m in node.get_root().protocol_msgs():
        if m.msg is node:
            break
        out.append(m.msg)
    return out


def _copied(before):
    """The client's latest request that is not an ACK or a copy (§17.1.1.2,
    §17.1.2.2: ACK is no transaction and never retransmitted), its index."""
    for i in range(len(before) - 1, -1, -1):
        m = before[i]
        if _sym(m).startswith('<req_') and _sym(m) != '<req_retransmit>' and _cseq(m)[1] != 'ACK':
            return i, m
    return None, None


def retransmitted(node):
    """The copy: the pending request byte for byte."""
    _, q = _copied(_raw_messages_before(node))
    return str(q) if q is not None else 'OPTIONS sip:copy SIP/2.0' + chr(13) + chr(10) + chr(13) + chr(10)


def _copy_plan(r):
    """When the copy in slot r is due and whether a copy may go out then:
    (q, due, permitted, in_state).  q: the pending request; Timer A / E
    (§17.1.1.2, §17.1.2.2) from the first time its slots were looked at;
    permitted: UDP, fewer than 6 (INVITE) / 10 copies and before Timer B /
    F = 64*T1; in_state: the slot is the self-loop of a state."""
    before = _raw_messages_before(r)
    i, q = _copied(before)
    if q is None:
        return None, 0, False, False
    now = time.time()
    copies = sum(1 for m in before[i + 1:] if _sym(m) == '<req_retransmit>')
    provisional = any(_sym(m).startswith('<rep_') and _status(m) < 200 and _cseq(m) == _cseq(q)
                      for m in before[i + 1:])
    first = _COPY_CLOCK.setdefault(('first', id(q)), now)
    last = _COPY_CLOCK.setdefault(('last', id(q), copies), now)
    if len(_COPY_CLOCK) > 4000:
        _COPY_CLOCK.clear()
    parent = getattr(r, 'parent', None)
    state = _sym(parent) if parent is not None else ''
    in_state = state.startswith('<state_')
    invite = _cseq(q)[1] == 'INVITE'
    if invite:
        due = first + _T1 * (2 ** (copies + 1) - 1)
    elif provisional:
        due = last + _T2
    else:
        due = min(first + _T1 * (2 ** (copies + 1) - 1), last + _T2)
    permitted = (_TRANSPORT == 'UDP' and copies < (6 if invite else 10)
                 and due < first + 64 * _T1)
    if not permitted:
        due = last + (_IDLE_KEEPALIVE if in_state else _TCP_SLOT_WAIT)
    return q, due, permitted, (state if in_state else None)


def copy_fits_transport(r):
    """A copy goes out over UDP only, while its transaction lasts; over a
    reliable transport (and after Timer F) the slot carries a CRLF, which
    the receiver ignores (§7.5, §17.1.1.2, §17.1.2.2)."""
    if str(r) == chr(13) + chr(10):
        if _live_io() is None:
            return _TRANSPORT != 'UDP' or _ancestor_state(r)
        return not _copy_plan(r)[2]
    if _live_io() is None:
        return _TRANSPORT == 'UDP'
    return _copy_plan(r)[2]


def _ancestor_state(r):
    parent = getattr(r, 'parent', None)
    return parent is not None and _sym(parent).startswith('<state_')


def _live_io():
    try:
        from fandango.io import FandangoIO
        io = FandangoIO.instance()
    except Exception:
        return None
    return io if 'Server' in io.parties else None


def retransmission_due(r):
    """Timer A / Timer E: waits until the copy is due (UDP; over TCP the
    slot of an exchange waits at most _TCP_SLOT_WAIT, the self-loop of a
    state _IDLE_KEEPALIVE) or a message arrived, then True; Fandango drops a
    copy generated while a message arrived.  Where an ACK is due the copy is
    valid only if its timer has fired already.  Outside a live session
    (parsing) always True."""
    io = _live_io()
    if io is None:
        return True
    q, due, permitted, state = _copy_plan(r)
    if q is None:
        return True
    if state in _ACK_DUE_STATES:
        return permitted and time.time() >= due
    while time.time() < due:
        if io.received_msg():
            return True
        time.sleep(0.02)
    return True


def datagram_body_ends(b):
    """§18.3: a body without Content-Length runs to the end of the datagram
    (UDP only, §20.14); the datagram of a further response begins with its
    status line, which the body must not hold."""
    return _TRANSPORT == 'UDP' and re.search(r'(^|\r\n)SIP/2\.0 [1-6][0-9][0-9] ', str(b)) is None

def _is_request(msg):
    return _sym(msg).startswith('<req_')


# Parsed header fields of complete messages, by id (the tree is kept to
# check identity); messages already in the session never change.
_INFO_CACHE = {}


def _parse_message(text):
    head = text.lstrip('\r\n').split('\r\n\r\n', 1)[0]
    head = head.replace('\r\n ', ' ').replace('\r\n\t', ' ')
    lines = head.split('\r\n')
    fields = []
    for line in lines[1:]:
        if ':' not in line:
            continue
        name, value = line.split(':', 1)
        fields.append((name.strip().lower(), value.strip()))
    return {'text': text, 'start': lines[0], 'fields': fields}


def _info(msg, cache=True):
    key = id(msg)
    hit = _INFO_CACHE.get(key)
    if hit is not None and hit[0] is msg:
        return hit[1]
    info = _parse_message(str(msg))
    if cache:
        if len(_INFO_CACHE) > 5000:
            _INFO_CACHE.clear()
        _INFO_CACHE[key] = (msg, info)
    return info


def _status(msg):
    start = _info(msg)['start']
    return int(start[8:11]) if len(start) > 11 and start[8:11].isdigit() else 0


def _header_values(msg, names):
    """Values of the header fields of msg whose (lower-case) name is in names."""
    return [v for n, v in _info(msg)['fields'] if n in names]


def _one(msg, names):
    values = _header_values(msg, names)
    return values[0] if len(values) == 1 else None


def _request_uri(msg):
    parts = _info(msg)['start'].split(' ')
    return parts[1] if len(parts) > 1 else ''


def _tag(value):
    if value is None:
        return None
    params = value.split('>', 1)[1] if '>' in value else value
    for p in params.split(';')[1:]:
        k, _, v = p.strip().partition('=')
        if k.strip().lower() == 'tag':
            return v.strip()
    return None


def _uri_of(value):
    if value is None:
        return None
    if '<' in value:
        return value.split('<', 1)[1].split('>', 1)[0].strip()
    return value.split(';', 1)[0].strip()


def _cseq(msg):
    v = _one(msg, ['cseq'])
    if v is None:
        return None, None
    parts = v.split()
    return (int(parts[0]), parts[1]) if len(parts) == 2 and parts[0].isdigit() else (None, None)


def _top_via_branch(msg):
    vias = _header_values(msg, ['via', 'v'])
    if not vias:
        return None
    for p in vias[0].split(',')[0].split(';')[1:]:
        k, _, v = p.strip().partition('=')
        if k.strip().lower() == 'branch':
            return v.strip()
    return None


def _strip_received(via):
    """A Via value without the received parameter a server adds (§18.2.1)
    and without the rport extension parameter (RFC 3581, not in refs)."""
    parts = [p.strip() for p in via.split(';')]
    kept = [parts[0]] + [p for p in parts[1:] if p.split('=')[0].strip().lower() not in ('received', 'rport')]
    return ';'.join(kept).replace(' ', '')


def _request_of(reply, msgs):
    """The request reply answers among msgs (§17.1.3: the CSeq method, then
    the CSeq number; the latest such request)."""
    number, method = _cseq(reply)
    idx = next(i for i, m in enumerate(msgs) if m is reply)
    fallback = None
    same = []
    for m in reversed(msgs[:idx]):
        if _is_request(m) and _cseq(m)[1] == method:
            if _cseq(m)[0] == number:
                same.append(m)
            if fallback is None:
                fallback = m
    branch = _top_via_branch(reply)
    for m in same:
        if _top_via_branch(m) == branch:
            return m
    return same[0] if same else fallback


def _request_answered(r):
    """The request sent before reply r that r answers (CSeq method and number)."""
    number, method = _cseq(r)
    fallback = None
    same = []
    for m in reversed(_session_messages_before(r)):
        if _is_request(m) and _cseq(m)[1] == method:
            if _cseq(m)[0] == number:
                same.append(m)
            if fallback is None:
                fallback = m
    # §17.1.3: of requests with the same CSeq (a merged INVITE) the one whose
    # branch the reply's top Via carries
    branch = _top_via_branch(r)
    for m in same:
        if _top_via_branch(m) == branch:
            return m
    return same[0] if same else fallback


def reply_echoes_request(r):
    for _ in [r]:
        q = _request_answered(r)
        if q is None:
            return False
        # §8.2.6.2 From, Call-ID, CSeq, Via
        rf, qf = _one(r, ['from', 'f']), _one(q, ['from', 'f'])
        if rf is None or _uri_of(rf) != _uri_of(qf) or _tag(rf) != _tag(qf):
            return False
        if _one(r, ['call-id', 'i']) != _one(q, ['call-id', 'i']):
            return False
        if _cseq(r) != _cseq(q):
            return False
        rv = [_strip_received(v) for v in ','.join(_header_values(r, ['via', 'v'])).split(',') if v.strip()]
        qv = [_strip_received(v) for v in ','.join(_header_values(q, ['via', 'v'])).split(',') if v.strip()]
        if rv != qv:
            return False
        # §8.2.6.2 To: same URI; the request's tag if it had one, else a new
        # tag (not required in 100 Trying)
        rt, qt = _one(r, ['to', 't']), _one(q, ['to', 't'])
        if rt is None or _uri_of(rt) != _uri_of(qt):
            return False
        if _tag(qt) is not None and _tag(rt) != _tag(qt):
            return False
        if _tag(qt) is None and _status(r) != 100 and _tag(rt) is None:
            return False
    return True


def timestamp_copied(r):
    """§8.2.6.1: a 100 (Trying) copies the request's Timestamp."""
    q = _request_answered(r)
    stamps = _header_values(q, ['timestamp']) if q is not None else []
    if _status(r) != 100 or not stamps:
        return True
    got = _header_values(r, ['timestamp'])
    return bool(got) and got[0].split()[0] == stamps[0].split()[0]


def require_only_supported(r):
    """§20.32, §8.2.4: a reply other than 421 requires only option tags the
    request listed in Supported."""
    if _status(r) == 421 or not _header_values(r, ['require']):
        return True
    q = _request_answered(r)
    supported = ','.join(_header_values(q, ['supported', 'k'])) if q is not None else ''
    tags = [t.strip() for t in supported.split(',') if t.strip()]
    return all(t.strip() in tags for t in ','.join(_header_values(r, ['require'])).split(','))


def coding_acceptable(r):
    """§20.12, §20.2: only codings the request's Accept-Encoding lists
    (identity alone without one)."""
    q = _request_answered(r)
    accepted = ['identity']
    for v in (_header_values(q, ['accept-encoding']) if q is not None else []):
        accepted += [c.split(';')[0].strip().lower() for c in v.split(',') if c.strip()]
    for coding in ','.join(_header_values(r, ['content-encoding', 'e'])).split(','):
        if coding.strip() and coding.strip().lower() not in accepted:
            return False
    return True


def no_408_to_non_invite(r):
    """RFC 4320 §4.2: no 408 to a non-INVITE request."""
    return _status(r) != 408 or _cseq(r)[1] == 'INVITE'


_ROLE = os.environ.get('SIP_SERVER_ROLE', 'uas').lower()
_TRANSPORT = 'UDP' if os.environ.get('SIP_TRANSPORT', 'TCP').upper() == 'UDP' else 'TCP'


def final_retransmitted(r):
    finals = [m for m in _session_messages_before(r) if _sym(m).startswith('<rep_') and _status(m) >= 300
              and _cseq(m)[1] == 'INVITE']
    return _TRANSPORT == 'UDP' and bool(finals) and str(finals[-1]) == str(r)


def datagram_extra(node):
    """§18.3: the octets after the body: over UDP some, over TCP none."""
    if _TRANSPORT != 'UDP':
        return ''
    return str(node) if str(node) else new_token(16)


def datagram_shortfall():
    """§18.3: how many octets the datagram lacks of its Content-Length."""
    return 16 if _TRANSPORT == 'UDP' else 0


def extra_bytes_discarded(r):
    """§18.3: octets beyond the Content-Length-delimited body of a datagram
    MUST be discarded: the request gets no 400 for them."""
    q = _request_answered(r)
    return _TRANSPORT != 'UDP' or q is None or _sym(q) != '<req_options_datagram_extra>' or _status(r) != 400


def short_datagram_refused(r):
    """§18.3: a request datagram that ends before the end of its body is an
    error (400 SHOULD): it is not answered as a valid request (no 2xx or
    3xx)."""
    q = _request_answered(r)
    return _TRANSPORT != 'UDP' or q is None or _sym(q) != '<req_options_datagram_short>' or _status(r) >= 400


# §10.2.6: sip.mcast.net, the "all SIP servers" group (IPv4)
_MULTICAST_RURI = 'sip:sip.mcast.net'
_MULTICAST_GROUP = os.environ.get('SIP_MULTICAST_GROUP', '224.0.1.75')
_LOCAL_HOST = os.environ.get('SIP_LOCAL_HOST', '127.0.0.1')


def multicast_ruri():
    """§10.2.6: the multicast REGISTER's Request-URI (UDP); over TCP the
    registrar's (§18.1.1: multicast only over UDP)."""
    return _MULTICAST_RURI if _TRANSPORT == 'UDP' else 'sip:' + _HOST


def multicast_scope():
    """§18.1.1: maddr=<group>;ttl=1 in the Via of the multicast request (UDP
    only); retargets the Client party to the group for it."""
    if _TRANSPORT != 'UDP':
        return ''
    _retarget_to_group()
    return ';maddr=' + _MULTICAST_GROUP + ';ttl=1'


def _join_group(impl):
    """§18.1.1, §18.2.2: the datagram leaves with TTL 1 on the interface of
    the local address, and the socket joins the group so that replies sent
    to maddr reach it."""
    import socket
    sock = getattr(impl, '_sock', None)
    if sock is None or getattr(impl, '_joined_sock', None) is sock:
        return
    local = socket.inet_aton(_LOCAL_HOST)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, local)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        socket.inet_aton(_MULTICAST_GROUP) + local)
    except OSError:
        pass
    impl._joined_sock = sock


def _retarget_to_group():
    """As open_data_port() in the FTP example reconfigures its party
    instances: the Client party (the driver's NetworkParty) sends a request
    to sip.mcast.net (or a copy of one) to the group and then goes back to
    its endpoint.  A generator runs for every candidate, not only for the
    message sent, so the retarget is bound to the message being sent."""
    io = _live_io()
    party = io.parties.get('Client') if io is not None else None
    impl = getattr(party, 'protocol_impl', None)
    if impl is None or getattr(impl, '_unicast_send', None) is not None:
        return
    unicast_send = impl.send
    prefix = ('REGISTER ' + _MULTICAST_RURI + ' ').encode()

    def send(message, recipient):
        data = message.to_bytes(encoding='utf-8') if hasattr(message, 'to_bytes') else message
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not data.startswith(prefix):
            return unicast_send(message, recipient)
        _join_group(impl)
        endpoint = impl.ip
        impl.ip = _MULTICAST_GROUP
        try:
            return unicast_send(message, recipient)
        finally:
            impl.ip = endpoint
    impl._unicast_send = unicast_send
    impl.send = send


def fits_transport(r):
    """§18.1.1: a request larger than 1300 bytes (path MTU unknown) goes
    over a congestion-controlled transport such as TCP, never UDP."""
    return _TRANSPORT != 'UDP' or len(bytes(r)) <= 1300


def to_tag_consistent(r):
    if _status(r) == 100:
        return True
    # §16.7 step 5, §13.2.2.4: a forking proxy passes on the 1xx and 2xx
    # replies of several UASs to one INVITE, each with its own To tag
    if _ROLE == 'proxy' and _cseq(r)[1] == 'INVITE':
        return True
    tag = _tag(_one(r, ['to', 't']))
    q = _request_answered(r)
    for m in _session_messages_before(r):
        if _is_request(m) or _sym(m).startswith('<srv_req_') or _status(m) == 100 or _cseq(m) != _cseq(r):
            continue
        if _request_answered(m) is q and _tag(_one(m, ['to', 't'])) != tag:
            return False
    return True


def mandatory_reply_fields(r):
    for names in (['from', 'f'], ['to', 't'], ['call-id', 'i'], ['cseq']):
        if len(_header_values(r, names)) != 1:
            return False
    # §7.3.1: fields whose value is not a comma-separated list appear once
    for names in (['content-type', 'c'], ['max-forwards'], ['expires'], ['min-expires'], ['retry-after'],
                  ['date'], ['server'], ['user-agent'], ['timestamp'], ['mime-version'], ['organization'],
                  ['priority'], ['reply-to'], ['subject', 's'], ['content-disposition'], ['content-length', 'l']):
        if len(_header_values(r, names)) > 1:
            return False
    if not _header_values(r, ['via', 'v']):
        return False
    if _find(r, '<body>') is not None and not _header_values(r, ['content-type', 'c']):
        return False
    return True


# §20 Tables 2 and 3: header field -> rows (where, column of ACK BYE CAN INV
# OPT REG; "-" not applicable; m* is m, other letters o, m, c, t, *)
_METHODS = ['ACK', 'BYE', 'CANCEL', 'INVITE', 'OPTIONS', 'REGISTER']
_TABLE = {
    'accept': [('R', '-o-omo'), ('2xx', '---omo'), ('415', '-c-ccc')],
    'accept-encoding': [('R', '-o-ooo'), ('2xx', '---omo'), ('415', '-c-ccc')],
    'accept-language': [('R', '-o-ooo'), ('2xx', '---omo'), ('415', '-c-ccc')],
    'alert-info': [('R', '---o--'), ('180', '---o--')],
    'allow': [('R', '-o-ooo'), ('2xx', '-o-mmo'), ('r', '-o-ooo'), ('405', '-m-mmm')],
    'authentication-info': [('2xx', '-o-ooo')],
    'authorization': [('R', 'oooooo')],
    'call-id': [('c', 'mmmmmm')],
    'call-info': [('', '---ooo')],
    'contact': [('R', 'o--moo'), ('1xx', '---o--'), ('2xx', '---moo'), ('3xx', '-o-ooo'), ('485', '-o-ooo')],
    'content-disposition': [('', 'oo-ooo')],
    'content-encoding': [('', 'oo-ooo')],
    'content-language': [('', 'oo-ooo')],
    'content-length': [('', 'tttttt')],
    'content-type': [('', '**-***')],
    'cseq': [('c', 'mmmmmm')],
    'date': [('', 'oooooo')],
    'error-info': [('300-699', '-ooooo')],
    'expires': [('', '---o-o')],
    'from': [('c', 'mmmmmm')],
    'in-reply-to': [('R', '---o--')],
    'max-forwards': [('R', 'mmmmmm')],
    'min-expires': [('423', '-----m')],
    'mime-version': [('', 'oo-ooo')],
    'organization': [('', '---ooo')],
    'priority': [('R', '---o--')],
    'proxy-authenticate': [('407', '-m-mmm'), ('401', '-ooooo')],
    'proxy-authorization': [('R', 'oo-ooo')],
    'proxy-require': [('R', '-o-ooo')],
    'record-route': [('R', 'ooooo-'), ('2xx,18x', '-oooo-')],
    'reply-to': [('', '---o--')],
    'require': [('', '-c-ccc')],
    'retry-after': [('404,413,480,486,500,503,600,603', '-ooooo')],
    'route': [('R', 'cccccc')],
    'server': [('r', '-ooooo')],
    'subject': [('R', '---o--')],
    'supported': [('R', '-oomoo'), ('2xx', '-oommo')],
    'timestamp': [('', 'oooooo')],
    'to': [('c', 'mmmmmm')],
    'unsupported': [('420', '-m-mmm')],
    'user-agent': [('', 'oooooo')],
    'via': [('R', 'mmmmmm'), ('rc', 'mmmmmm')],
    'warning': [('r', '-ooooo')],
    'www-authenticate': [('401', '-m-mmm'), ('407', '-o-ooo')],
}
# §7.3.3 compact forms
_FULL_NAMES = {'v': 'via', 'f': 'from', 't': 'to', 'i': 'call-id', 'm': 'contact', 'l': 'content-length',
               'c': 'content-type', 'e': 'content-encoding', 'k': 'supported', 's': 'subject'}


def _where_matches(rows_where, code):
    """Does the "where" column match a request (code None) or a reply?"""
    if code is None:
        return rows_where in ('', 'R', 'c')
    if rows_where in ('', 'r', 'c', 'rc'):
        return True
    if rows_where == 'R':
        return False
    for part in rows_where.split(','):
        if '-' in part:
            low, high = part.split('-')
            if int(low) <= code <= int(high):
                return True
        elif part.endswith('xx'):
            if int(code / 100) == int(part[0]):
                return True
        elif part.endswith('x'):
            if int(code / 10) == int(part[:2]):
                return True
        elif int(part) == code:
            return True
    return False


def fields_applicable(r):
    """§20: "-" (not applicable) in the column of the method in every row
    whose "where" matches the message means the field MUST NOT be there;
    "R" (may only appear in requests) and "r" (may only appear in
    responses) exclude the other kind of message.  A reply code no row
    names is not excluded: a code in the "where" column only "indicates
    response codes with which the header field can be used" (e.g.
    Supported, rows R and 2xx, in a 4xx reply is allowed)."""
    if _sym(r).startswith('<srv_req_'):
        code, method = None, _info(r)['start'].split(' ', 1)[0]
    else:
        code, method = _status(r), _cseq(r)[1]
    column = _METHODS.index(method) if method in _METHODS else None
    for name, _ in _info(r)['fields']:
        rows = _TABLE.get(_FULL_NAMES.get(name, name))
        if rows is None:
            continue
        matching = [m for w, m in rows if _where_matches(w, code)]
        if not matching:
            if code is not None and all(w == 'R' for w, _ in rows):
                return False
            if code is None and any('r' in w for w, _ in rows):
                return False
            continue
        if column is not None and all(m[column] == '-' for m in matching):
            return False
    return True


def _option_tags(msg, names):
    return [t.strip() for t in ','.join(_header_values(msg, names)).split(',') if t.strip()]


def status_required_fields(r):
    code = _status(r)
    if code == 415:
        # §8.2.3, §21.4.13: Accept for an unknown type, Accept-Encoding for an
        # unknown coding, Accept-Language for an unknown language
        q = _request_answered(r)
        have = set(n for n, _ in _info(r)['fields'])
        if not have & {'accept', 'accept-encoding', 'accept-language'}:
            return False
        if q is not None:
            ctype = (_header_values(q, ['content-type', 'c']) or [''])[0].lower()
            if ctype.startswith('application/x-') and 'accept' not in have:
                return False
            if any(c.lower().startswith('x-') for c in _option_tags(q, ['content-encoding', 'e'])) \
                    and 'accept-encoding' not in have:
                return False
            if _header_values(q, ['content-language']) and not _header_values(q, ['content-type', 'c']) \
                    and 'accept-language' not in have:
                return False
        return True
    if code == 420:
        # §8.2.2.3: Unsupported lists the option tags of the request's Require
        # (or, from a proxy, Proxy-Require, §16.3 step 5) it does not know
        q = _request_answered(r)
        listed = _option_tags(r, ['unsupported'])
        if not listed or q is None:
            return bool(listed)
        require, proxy_require = _option_tags(q, ['require']), _option_tags(q, ['proxy-require'])
        if not all(t in require + proxy_require for t in listed):
            return False
        unknown = [t for t in require if t.startswith('x-')]
        punknown = [t for t in proxy_require if t.startswith('x-')]
        return bool(unknown and all(t in listed for t in unknown)) or \
            bool(punknown and all(t in listed for t in punknown))
    need = {405: ['allow'], 401: ['www-authenticate'], 407: ['proxy-authenticate'],
            421: ['require'], 423: ['min-expires']}.get(code)
    if need is None:
        return True
    values = _header_values(r, need)
    if code in (401, 407):
        digests = [_challenge_params_of(v) for v in values if v.lower().startswith('digest')]
        # RFC 8760 §2.3: one challenge per algorithm and realm
        seen = [(d.get('realm'), d.get('algorithm', 'MD5').upper()) for d in digests]
        if len(seen) != len(set(seen)):
            return False
        # RFC 8760 §2.6 item 8: a UAS always sends qop
        return bool(digests) and all('qop' in d for d in digests)
    return bool(values)


def _is_ip(host):
    return bool(re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9a-fA-F:.]+\]', host))


def via_received_added(r):
    """§18.2.1: the server adds received when the sent-by host is a domain
    name (or differs from the source address, here the same host)."""
    q = _request_answered(r)
    qv = _header_values(q, ['via', 'v']) if q is not None else []
    rv = _header_values(r, ['via', 'v'])
    if not qv or not rv:
        return True
    sent_by = qv[0].split(',')[0].split(';')[0].split()[-1]
    host = sent_by if sent_by.startswith('[') else sent_by.split(':')[0]
    if _is_ip(host):
        return True
    return any(p.split('=')[0].strip().lower() == 'received' for p in rv[0].split(',')[0].split(';')[1:])


def _body_text(msg):
    body = _find(msg, '<body>')
    return str(body) if body is not None else ''


def _decoded_body_text(msg):
    """§20.12, §7.4.1: the body with its content codings undone (in reverse
    order of listing); the media-type rules (§27.5, RFC 5621) apply to the
    decoded body. Unknown codings or undecodable data leave it as sent."""
    text = _body_text(msg)
    codings = [c.lower() for c in _option_tags(msg, ['content-encoding', 'e'])]
    data = text.encode('latin-1', errors='replace')
    for coding in reversed(codings):
        try:
            if coding == 'identity':
                continue
            if coding in ('gzip', 'x-gzip'):
                data = gzip.decompress(data)
            elif coding == 'deflate':
                data = zlib.decompress(data)
            else:
                return text
        except Exception:
            return text
    return data.decode('latin-1')


def codings_in_order(r):
    """§20.12: the codings, undone in reverse order of listing, decode."""
    codings = [c.lower() for c in _option_tags(r, ['content-encoding', 'e'])]
    if not codings or _find(r, '<body>') is None:
        return True
    data = _body_text(r).encode('latin-1', errors='replace')
    for coding in reversed(codings):
        try:
            if coding == 'identity':
                continue
            if coding in ('gzip', 'x-gzip'):
                data = gzip.decompress(data)
            elif coding == 'deflate':
                data = zlib.decompress(data)
            else:
                return True
        except Exception:
            return False
    return True


def _split_list(text):
    """Comma-separated values outside quotes and <...>."""
    parts, current, quoted, angle = [], '', False, False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        elif ch == '<' and not quoted:
            angle = True
        elif ch == '>' and not quoted:
            angle = False
        if ch == ',' and not quoted and not angle:
            parts.append(current.strip())
            current = ''
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def _media_params(value):
    params = {}
    for p in value.split(';')[1:]:
        k, _, v = p.partition('=')
        params[k.strip().lower()] = v.strip().strip('"')
    return params


def _part_fields(part):
    head = part.split('\r\n\r\n', 1)[0] if '\r\n\r\n' in part else ''
    fields = {}
    for line in head.replace('\r\n ', ' ').replace('\r\n\t', ' ').split('\r\n'):
        if ':' in line:
            name, value = line.split(':', 1)
            fields[name.strip().lower()] = value.strip()
    return fields


def multipart_rules(r):
    """RFC 5621 §6.2, §8.2: the top-level parts of a multipart/alternative with
    session (or early-session) disposition have distinct types, and share
    the disposition type of the message; §9.2 a cid: reference points to a
    later body part."""
    ctype = (_header_values(r, ['content-type', 'c']) or [''])[0]
    if not ctype.lower().startswith('multipart/') or _find(r, '<body>') is None:
        return True
    boundary = _media_params(ctype).get('boundary')
    if not boundary:
        return False
    chunks = _decoded_body_text(r).split('--' + boundary)
    parts = []
    for chunk in chunks[1:]:
        if chunk.startswith('--'):
            break
        parts.append(chunk[2:] if chunk.startswith('\r\n') else chunk)
    fields = [_part_fields(p) for p in parts]
    disposition = (_header_values(r, ['content-disposition']) or [''])[0].split(';')[0].strip().lower()
    if ctype.split(';')[0].strip().lower() == 'multipart/alternative':
        if disposition in ('session', 'early-session'):
            types = [f.get('content-type', 'text/plain').split(';')[0].strip().lower() for f in fields]
            if len(types) != len(set(types)):
                return False
        if disposition:
            for f in fields:
                if 'content-disposition' in f and f['content-disposition'].split(';')[0].strip().lower() != disposition:
                    return False
    ids = [f.get('content-id', '').strip('<> ') for f in fields]
    for i, part in enumerate(parts):
        for m in re.finditer(r'cid:([^\s>;"]+)', part, re.I):
            if unquote(m.group(1)) in ids[:i + 1]:
                return False
    return True


_SIP_START = re.compile(r'^([-a-zA-Z0-9.!%*_+~]+ [^ \r\n]+ [Ss][Ii][Pp]/2[.]0|[Ss][Ii][Pp]/2[.]0 [1-6][0-9]{2} [^\r\n]*)\r\n')


def body_view(body):
    """§27.5: the view of the body: 'message/sip' CRLF and the enclosed message
    (content codings undone) for a message/sip body, else 'opaque'."""
    try:
        msg = body.get_root()
        ctype = (_header_values(msg, ['content-type', 'c']) or [''])[0]
        if ctype.split(';')[0].strip().lower() == 'message/sip':
            return 'message/sip\r\n' + _decoded_body_text(msg)
    except Exception:
        pass
    return 'opaque'


def body_from_view(view):
    text = str(view)
    return text[len('message/sip\r\n'):] if text.startswith('message/sip\r\n') else 'x'


def message_sip_body(r):
    """§27.5: a message/sip body is one SIP request or response (§7): a
    Request-Line or Status-Line, header fields "name: value" without control
    characters (§7.3, §25.1), To, From, Call-ID and CSeq once each, the CSeq
    method of a request equal to its method (§8.1.1.5), Content-Length (if
    any) equal to the length of its body, and the SIP-Version of the
    enclosed message equal to the version parameter (default "2.0")."""
    ctype = (_header_values(r, ['content-type', 'c']) or [''])[0]
    if ctype.split(';')[0].strip().lower() != 'message/sip' or _find(r, '<body>') is None:
        return True
    params = _media_params(';' + ctype.split(';', 1)[1]) if ';' in ctype else {}
    body = _decoded_body_text(r)
    if not _SIP_START.search(body) or '\r\n\r\n' not in body:
        return False
    head, rest = body.split('\r\n\r\n', 1)
    lines = head.split('\r\n')
    start = lines[0].split(' ')
    is_request = not start[0].upper().startswith('SIP/')
    version = (start[-1] if is_request else start[0]).upper()
    if version != 'SIP/' + params.get('version', '2.0').strip('"').upper():
        return False
    fields = []
    for line in lines[1:]:
        if line[:1] in (' ', '\t') and fields:
            fields[-1] = (fields[-1][0], fields[-1][1] + ' ' + line.strip())
            continue
        if not re.search(r'^[-a-zA-Z0-9.!%*_+`\'~]+[ \t]*:[^\x00-\x08\x0a-\x1f\x7f]*$', line):
            return False
        name, _, value = line.partition(':')
        fields.append((_FULL_NAMES.get(name.strip().lower(), name.strip().lower()), value.strip()))
    names = [n for n, _ in fields]
    if any(names.count(n) != 1 for n in ('to', 'from', 'call-id', 'cseq')):
        return False
    cseq = [v for n, v in fields if n == 'cseq'][0].split()
    if len(cseq) != 2 or not cseq[0].isdigit() or (is_request and cseq[1] != start[0]):
        return False
    lengths = [v for n, v in fields if n == 'content-length']
    size = len(rest.encode('latin-1', errors='replace'))
    return not lengths or (lengths[0].isdigit() and int(lengths[0]) == size)


def rspauth_valid(r):
    """§22.4 / RFC 2617 §3.2.3: rspauth is the digest of the credentials the
    request carried, with A2 = ":" digest-uri."""
    params = {}
    for value in _header_values(r, ['authentication-info']):
        for part in _split_params(value):
            k, _, v = part.partition('=')
            params[k.strip().lower()] = v.strip().strip('"')
    if 'rspauth' not in params:
        return True
    q = _request_answered(r)
    creds = (_header_values(q, ['authorization']) + _header_values(q, ['proxy-authorization'])) if q is not None else []
    if not creds:
        return True
    c = _challenge_params_of(creds[0])
    algorithm = c.get('algorithm', 'MD5')
    ha1 = _h(algorithm, c.get('username', '') + ':' + c.get('realm', '') + ':secret')
    if algorithm.lower().endswith('-sess'):
        ha1 = _h(algorithm, ha1 + ':' + c.get('nonce', '') + ':' + c.get('cnonce', ''))
    qop = params.get('qop', c.get('qop', ''))
    a2 = ':' + c.get('uri', '')
    if qop == 'auth-int':
        a2 += ':' + _h(algorithm, _body_text(r))
    expected = _h(algorithm, ha1 + ':' + c.get('nonce', '') + ':' + c.get('nc', '') + ':' + c.get('cnonce', '')
                  + ':' + qop + ':' + _h(algorithm, a2))
    return params['rspauth'].lower() == expected


def proxy_validation(r):
    """A proxy (SIP_SERVER_ROLE=proxy) validates a request it is to forward
    (Request-URI with a user part): §16.3 step 3 Max-Forwards 0 (not OPTIONS)
    -> 483, step 5 an unknown Proxy-Require option tag -> 420."""
    if _ROLE != 'proxy':
        return True
    q = _request_answered(r)
    if q is None or '@' not in _request_uri(q):
        return True
    max_forwards = _header_values(q, ['max-forwards'])
    if max_forwards and max_forwards[0].strip().isdigit() and int(max_forwards[0]) == 0 \
            and _cseq(q)[1] != 'OPTIONS':
        return _status(r) == 483
    if any(t.startswith('x-') for t in _option_tags(q, ['proxy-require'])):
        return _status(r) == 420
    return True


def body_refused(r):
    """§8.2.3: a body of a type or coding the UAS does not understand, not
    marked optional, is never accepted (2xx)."""
    q = _request_answered(r)
    if q is None or not 200 <= _status(r) < 300:
        return True
    ctype = (_header_values(q, ['content-type', 'c']) or [''])[0].lower()
    if 'handling=optional' in ' '.join(_header_values(q, ['content-disposition'])).lower():
        return True
    unknown_coding = any(c.lower().startswith('x-') for c in _option_tags(q, ['content-encoding', 'e']))
    return not (ctype.startswith('application/x-') or unknown_coding)


def overlap_refused(r):
    """§14.2: a UAS that receives a second INVITE before it sent the final
    response to a first INVITE with a lower CSeq in the same dialog returns
    500 with a Retry-After of 0 to 10 seconds."""
    q = _request_answered(r)
    if q is None or _sym(q) not in ('<req_reinvite>', '<req_reinvite_auth>'):
        return True
    before = _session_messages_before(r)
    earlier = [m for m in before if m is not q and _sym(m) in ('<req_reinvite>', '<req_reinvite_auth>')
               and _cseq(m)[0] is not None and _cseq(q)[0] is not None and _cseq(m)[0] < _cseq(q)[0]
               and before.index(m) < before.index(q)]
    for first in earlier:
        answered = [m for m in before if _sym(m).startswith('<rep_') and _status(m) >= 200 and _cseq(m) == _cseq(first)]
        if not answered:
            retry = _header_values(r, ['retry-after'])
            value = retry[0].split(';')[0].split('(')[0].strip() if retry else ''
            return _status(r) == 500 and value.isdigit() and int(value) <= 10
    return True


def _client_requests_before(r):
    return [m for m in _session_messages_before(r) if _sym(m).startswith('<req_')]


def _waiting(r):
    """The client's requests before r with r's CSeq that got no final reply
    before r."""
    before = _session_messages_before(r)
    waiting = []
    for i, m in enumerate(before):
        if _sym(m).startswith('<req_') and _cseq(m) == _cseq(r) and _cseq(m)[1] != 'ACK':
            if not any(_sym(x).startswith('<rep_') and _status(x) >= 200 and _cseq(x) == _cseq(m)
                       and _top_via_branch(x) == _top_via_branch(m) for x in before[i:]):
                waiting.append(m)
    return waiting


def _latest_invite_number(r):
    invites = [m for m in _client_requests_before(r) if _cseq(m)[1] == 'INVITE']
    return _cseq(invites[-1])[0] if invites else None


def not_latest_invite(r):
    """RFC 6026 §8.9: a stray INVITE reply while an INVITE is pending answers
    an earlier INVITE (not the latest one)."""
    return _cseq(r)[1] != 'INVITE' or _cseq(r)[0] != _latest_invite_number(r)


def answers_pending(r):
    """A regular reply: its request still waits for the final reply, or (an
    INVITE reply) it answers the latest INVITE."""
    if _waiting(r):
        return True
    return _cseq(r)[1] == 'INVITE' and _cseq(r)[0] == _latest_invite_number(r)


def answers_merged(r):
    """§17.1.3: r carries the branch of a merged INVITE (§8.2.2.2)."""
    branch = _top_via_branch(r)
    return any(_sym(m) == '<req_invite_merged>' and _top_via_branch(m) == branch
               for m in _session_messages_before(r))


def final_repeated_after_ack(r):
    """§17.1.1.2: r repeats the latest INVITE final reply and comes right
    after the ACK of that reply."""
    before = _session_messages_before(r)
    return final_retransmitted(r) and bool(before) and _sym(before[-1]) in ('<req_ack_failure>', '<req_ack_reinvite_failure>')


def stray_reply(r):
    """RFC 6026 §8.9: no request of the client with the response's CSeq
    (number and method) is still waiting for its final response (§17.1.3:
    a final reply ends the transaction whose branch it carries)."""
    before = _session_messages_before(r)
    for i, m in enumerate(before):
        if _is_request(m) and _cseq(m) == _cseq(r) and _cseq(m)[1] != 'ACK':
            if not any(_sym(x).startswith('<rep_') and _status(x) >= 200 and _cseq(x) == _cseq(m)
                       and _top_via_branch(x) == _top_via_branch(m) for x in before[i:]):
                return False
    return True


def _top_via(msg):
    vias = _header_values(msg, ['via', 'v'])
    return vias[0].split(',')[0] if vias else ''


def invite_487_cancelled(r):
    """§9.2: 487 answers an INVITE cancelled by a CANCEL. The CANCEL is tied
    to the INVITE by the §17.2.3 matching rules ("The matching transaction is
    the one to be cancelled"): only <req_cancel> (top Via equal to the
    INVITE's) counts; a CANCEL with another branch or sent-by
    (<req_cancel_other_branch>, <req_cancel_other_sent_by>) matches no
    transaction and must leave the INVITE alone (its own reply may be any
    final status, the 481 being a SHOULD)."""
    if _status(r) != 487:
        return True
    q = _request_answered(r)
    if q is None:
        return False
    for m in _session_messages_before(r):
        # §15.1.2: the UAS answers an INVITE whose early dialog a BYE ended
        # with 487 (RECOMMENDED)
        if _sym(m) == '<req_bye_early>' and _one(m, ['call-id', 'i']) == _one(q, ['call-id', 'i']):
            return True
        if _sym(m) == '<req_cancel>' and _one(m, ['call-id', 'i']) == _one(q, ['call-id', 'i']) \
                and _cseq(m)[0] == _cseq(q)[0] and _strip_received(_top_via(m)) == _strip_received(_top_via(q)):
            return True
    return False


def early_dialog_fields(r):
    contacts = _header_values(r, ['contact', 'm'])
    if _tag(_one(r, ['to', 't'])) is None or len(contacts) != 1:
        return False
    uri = _uri_of(contacts[0]) or ''
    return ',' not in uri and uri.lower().startswith('sip')


def redirect_not_to_self(r):
    """§8.3: no 3xx Contact equals the Request-URI of the request."""
    if not 300 <= _status(r) < 400:
        return True
    q = _request_answered(r)
    if q is None:
        return True
    target = _uri_key(_request_uri(q))
    return all(_uri_key(uri) != target for uri, _ in _contact_entries(_header_values(r, ['contact', 'm'])))


def dialog_reply_fields(r):
    contacts = _header_values(r, ['contact', 'm'])
    if len(contacts) != 1 or ',' in (_uri_of(contacts[0]) or ',') or not _uri_of(contacts[0]).lower().startswith('sip'):
        return False
    if _tag(_one(r, ['to', 't'])) is None:
        return False
    # the INVITE carried an offer, so the 2xx carries the answer
    ctype = _header_values(r, ['content-type', 'c'])
    return _find(r, '<body>') is not None and bool(ctype) and 'application/sdp' in ctype[0].lower()


def _contact_entries(values):
    """(URI, parameters) of every Contact value; "*" as ('*', {})."""
    out = []
    for value in values:
        for c in _split_list(value):
            if c == '*':
                out.append(('*', {}))
                continue
            if '<' in c:
                uri, rest = c.split('<', 1)[1].split('>', 1)[0], c.split('>', 1)[1] if '>' in c else ''
            else:
                # §20: parameters after an addr-spec are header parameters
                uri, _, rest = c.partition(';')
                rest = ';' + rest if rest else ''
            out.append((uri.strip(), _media_params(rest)))
    return out


def _uri_key(uri):
    """A URI for comparison (§19.1.4): user, host and port, case-insensitive."""
    u = (uri or '').strip().lower().split('?')[0].split(';')[0]
    return u.split(':', 1)[1] if u.startswith('sip:') or u.startswith('sips:') else u


def _requested_expirations(q):
    """Contact URI key -> requested expiration (Contact expires before the
    Expires header field, §10.2.1.1) or None."""
    header = _header_values(q, ['expires'])
    default = int(header[0]) if header and header[0].strip().isdigit() else None
    out = {}
    for uri, params in _contact_entries(_header_values(q, ['contact', 'm'])):
        if uri != '*':
            value = params.get('expires')
            out[_uri_key(uri)] = int(value) if value is not None and value.isdigit() else default
    return out


def register_bindings_listed(r):
    """§10.3 step 8: a 2xx lists the current bindings, each with expires: the
    ones this request added or refreshed, not the ones it removed (step 7 and
    §10.2.1.1: the registrar chooses the interval by local policy, the
    client's is only a suggestion)."""
    if not 200 <= _status(r) < 300:
        return True
    listed = _contact_entries(_header_values(r, ['contact', 'm']))
    if any(uri == '*' or 'expires' not in params for uri, params in listed):
        return False
    q = _request_answered(r)
    if q is None:
        return True
    keys = {_uri_key(uri): params for uri, params in listed}
    if any(uri == '*' for uri, _ in _contact_entries(_header_values(q, ['contact', 'm']))):
        return not listed
    for key, requested in _requested_expirations(q).items():
        if requested == 0:
            if key in keys:
                return False
        elif key not in keys:
            return False
    return True


def register_423_justified(r):
    """§10.3 step 7: 423 only if the requested expiration is > 0, < 3600 and
    below the minimum (Min-Expires)."""
    for _ in [r]:
        if _status(r) != 423:
            continue
        q = _request_answered(r)
        if q is None:
            return False
        requested = [v for v in _requested_expirations(q).values() if v is not None]
        if not requested:
            header = _header_values(q, ['expires'])
            requested = [int(header[0])] if header and header[0].strip().isdigit() else []
        if not requested:
            return False
        minimum = _header_values(r, ['min-expires'])
        for value in requested:
            if not 0 < value < 3600 or (minimum and minimum[0].strip().isdigit() and value >= int(minimum[0])):
                return False
    return True


_LISTED_MIN_EXPIRES = 900


def stored_bindings_listed(r):
    """§10.3 step 8: a 2xx to REGISTER lists all current bindings of the
    address-of-record, also those our earlier REGISTERs of the session
    created and no later one removed (the ones granted at least 900 s, so
    that none expired during the session)."""
    if not 200 <= _status(r) < 300:
        return True
    q = _request_answered(r)
    if q is None:
        return True
    aor = _uri_key(_uri_of(_one(q, ['to', 't'])))
    entries = _contact_entries(_header_values(q, ['contact', 'm']))
    if any(uri == '*' for uri, _ in entries):
        return True
    removed = [k for k, v in _requested_expirations(q).items() if v == 0]
    listed = [_uri_key(uri) for uri, _ in _contact_entries(_header_values(r, ['contact', 'm']))]
    for binding, granted in _granted_bindings(r).items():
        stored_aor, key = binding
        if stored_aor == aor and key not in removed and granted >= _LISTED_MIN_EXPIRES and key not in listed:
            return False
    return True


def _granted_bindings(r):
    """(AoR, contact) -> the expiration the registrar granted (the expires of
    the Contact in its 2xx) for the bindings our REGISTERs before r hold."""
    before = _session_messages_before(r)
    granted = {}
    for m in before:
        if _sym(m) != '<rep_register_final>' or not 200 <= _status(m) < 300:
            continue
        q = _request_of(m, before)
        if q is None:
            continue
        aor = _uri_key(_uri_of(_one(q, ['to', 't'])))
        if any(uri == '*' for uri, _ in _contact_entries(_header_values(q, ['contact', 'm']))):
            granted = {k: v for k, v in granted.items() if k[0] != aor}
            continue
        listed = {_uri_key(uri): params for uri, params in _contact_entries(_header_values(m, ['contact', 'm']))}
        for key, requested in _requested_expirations(q).items():
            value = listed.get(key, {}).get('expires', '')
            if requested == 0 or not value.isdigit() or int(value) == 0:
                granted.pop((aor, key), None)
            else:
                granted[(aor, key)] = int(value)
    return granted


def _stored_bindings(r):
    """(AoR, contact) -> (Call-ID, CSeq) of the bindings the 2xx replies to
    our REGISTERs before r created, refreshed and removed."""
    before = _session_messages_before(r)
    stored = {}
    for m in before:
        if _sym(m) != '<rep_register_final>' or not 200 <= _status(m) < 300:
            continue
        q = _request_of(m, before)
        if q is None:
            continue
        aor = _uri_key(_uri_of(_one(q, ['to', 't'])))
        entries = _contact_entries(_header_values(q, ['contact', 'm']))
        if any(uri == '*' for uri, _ in entries):
            stored = {k: v for k, v in stored.items() if k[0] != aor}
            continue
        for key, requested in _requested_expirations(q).items():
            if requested == 0:
                stored.pop((aor, key), None)
            else:
                stored[(aor, key)] = (_one(q, ['call-id', 'i']), _cseq(q)[0])
    return stored


def register_refusals(r):
    """§10.3 step 7: an update of a binding with the same Call-ID and a CSeq
    not higher than the stored one fails.  (Steps 4/5, 403 for a user not
    authorized for the address-of-record and 404 for one not valid for the
    domain, depend on the registrar's local authorization data and
    third-party registration policy: any reply is accepted for
    <req_register_unknown_aor>.)"""
    q = _request_answered(r)
    if q is None:
        return True
    code = _status(r)
    if 200 <= code < 300:
        aor = _uri_key(_uri_of(_one(q, ['to', 't'])))
        call_id, number = _one(q, ['call-id', 'i']), _cseq(q)[0]
        stored = _stored_bindings(r)
        for key, requested in _requested_expirations(q).items():
            old = stored.get((aor, key))
            if old is not None and old[0] == call_id and number is not None and number <= old[1]:
                return False
    return True


_BRANCH_COPIES = ('<req_ack_failure>', '<req_ack_reinvite_failure>', '<req_cancel>', '<req_cancel_other_sent_by>',
                  '<req_ack_2xx_again>')


def branch_unique(b):
    """§8.1.1.7: a new branch differs from the branches of all earlier
    requests (only CANCEL and the ACK for a non-2xx copy their request's)."""
    request = _request_node(b)
    branch = 'z9hG4bK' + str(b)
    for m in _session_messages_before(request):
        if _is_request(m) and _sym(m) not in _BRANCH_COPIES and _top_via_branch(m) == branch:
            return False
    return True


def _request_node(node):
    """The request message node belongs to."""
    while node is not None and not _is_request(node):
        node = node.parent
    return node


# The history of a request does not change while Fandango varies the request
# itself; its context is computed once per request node.
_CONTEXT_CACHE = {}


def _context(node):
    request = _request_node(node)
    root = request.get_root()
    key = (id(request), id(root))
    hit = _CONTEXT_CACHE.get(key)
    if hit is not None and hit[0] is request and hit[1] is root:
        return hit[2]
    ctx = _compute_context(request)
    if len(_CONTEXT_CACHE) > 2000:
        _CONTEXT_CACHE.clear()
    _CONTEXT_CACHE[key] = (request, root, ctx)
    return ctx


_INITIAL_INVITES = ('<req_invite>', '<req_invite_auth>', '<req_invite_redirected>', '<req_invite_via_proxy>')


def _compute_context(request):
    """What the history decides for the request."""
    before = _session_messages_before(request)
    ctx = {'request': request, 'before': before, 'name': _sym(request)}
    # the request this one retries (with credentials), acknowledges or cancels
    # (a merged INVITE, §8.2.2.2, is not the INVITE later requests refer to)
    requests = [m for m in before if _is_request(m) and _cseq(m)[1] not in ('ACK', 'CANCEL')
                and _sym(m) != '<req_invite_merged>']
    ctx['invite'] = requests[-1] if requests else None
    ctx['first'] = ctx['invite']
    replies = [m for m in before if _sym(m).startswith('<rep_')]
    finals = [m for m in replies if _status(m) >= 200 and _cseq(m)[1] == 'INVITE']
    ctx['final'] = finals[-1] if finals else None
    # §17.1.1.3: an ACK for a 300-699 reply answers the earliest such reply
    # not yet ACKed (two can be due when a merged INVITE, §8.2.2.2, is
    # pending); ACKs carry the branch of their INVITE
    if ctx['name'] in ('<req_ack_failure>', '<req_ack_reinvite_failure>'):
        acks = {}
        for m in before:
            if _sym(m) in ('<req_ack_failure>', '<req_ack_reinvite_failure>'):
                acks[_top_via_branch(m)] = acks.get(_top_via_branch(m), 0) + 1
        for m in finals:
            if _status(m) < 300:
                continue
            b = _top_via_branch(m)
            if acks.get(b, 0) > 0:
                acks[b] -= 1
                continue
            ctx['final'] = m
            break
    # the INVITE the final reply answers (by CSeq number and branch)
    ctx['acked'] = _request_of(ctx['final'], before) if ctx['final'] is not None else None
    # §13.2.2.4: an ACK for every 2xx (retransmitted or of another fork),
    # built from that 2xx: the k-th ACK of an INVITE's 2xx replies answers its
    # k-th 2xx
    if ctx['name'] in _ALL_ACKS_OF_2XX and ctx['final'] is not None:
        number = _cseq(ctx['final'])[0]
        twoxx = [m for m in replies if _sym(m) == '<rep_invite_2xx>' and _cseq(m)[0] == number]
        acks = [m for m in before if _sym(m) in _ALL_ACKS_OF_2XX and _cseq(m)[0] == number]
        if twoxx:
            ctx['final'] = twoxx[min(len(acks), len(twoxx) - 1)]
    challenges = [m for m in replies if _status(m) in (401, 407)]
    ctx['challenge'] = challenges[-1] if challenges else None
    # the dialog: the 2xx to an initial INVITE (a retransmission changes
    # nothing, the dialog of another fork is ended, see _unended_forks); target refreshes in the
    # order they happened (§12.2.1.2, RFC 6141 §4.7: the 2xx Contact of our
    # re-INVITE; §12.2.2: the Contact of the callee's re-INVITE we accept)
    dialog = None
    for i, m in enumerate(before):
        s = _sym(m)
        if s == '<rep_invite_2xx>':
            q = _request_of(m, before)
            if q is None:
                continue
            if _sym(q) in _INITIAL_INVITES:
                # §13.2.2.4: the client continues the dialog of the first 2xx;
                # further forks' dialogs are ended with <req_bye_fork>
                if dialog is not None and dialog['call_id'] == _one(m, ['call-id', 'i']):
                    continue
                rr = _header_values(m, ['record-route'])
                dialog = {'invite': q, 'call_id': _one(m, ['call-id', 'i']), 'from': _one(q, ['from', 'f']),
                          'to': _one(m, ['to', 't']),
                          'target': _uri_of((_header_values(m, ['contact', 'm']) or [None])[0]),
                          'route': ', '.join(reversed(_split_list(','.join(rr)))) if rr else None}
            elif dialog is not None and _sym(q) in ('<req_reinvite>', '<req_reinvite_auth>') \
                    and _header_values(m, ['contact', 'm']):
                dialog['target'] = _uri_of(_header_values(m, ['contact', 'm'])[0])
        elif s == '<srv_req_reinvite>' and dialog is not None and _header_values(m, ['contact', 'm']) \
                and _one(m, ['call-id', 'i']) == dialog['call_id'] and _accepted_by_client(m, before[i + 1:]):
            dialog['target'] = _uri_of(_header_values(m, ['contact', 'm'])[0])
    # §13.2.2.4: the dialog of a further fork not ended yet
    if ctx['name'] == '<req_bye_fork>' and dialog is not None:
        fork = _unended_forks(before, dialog)
        if fork:
            q = _request_of(fork[0], before)
            contacts = _header_values(fork[0], ['contact', 'm'])
            dialog = {'invite': q, 'call_id': dialog['call_id'], 'from': dialog['from'],
                      'to': _one(fork[0], ['to', 't']),
                      'target': _uri_of(contacts[0]) if contacts else dialog['target'],
                      'route': _route_of_reply(fork[0])}
    # §12.1.2: the early dialog a BYE ends: the latest 101-199 reply with a tag
    if ctx['name'] == '<req_bye_early>':
        early = [m for m in replies if _sym(m) == '<rep_invite_early>']
        q = _request_of(early[-1], before) if early else None
        if q is not None:
            contacts = _header_values(early[-1], ['contact', 'm'])
            dialog = {'invite': q, 'call_id': _one(q, ['call-id', 'i']), 'from': _one(q, ['from', 'f']),
                      'to': _one(early[-1], ['to', 't']),
                      'target': _uri_of(contacts[0]) if contacts else _request_uri(q),
                      'route': _route_of_reply(early[-1])}
    ctx['dialog'] = dialog
    ctx['dialog_cseq'] = None
    if dialog is not None:
        sent = [_cseq(m)[0] for m in before if _is_request(m) and _one(m, ['call-id', 'i']) == dialog['call_id']
                and _cseq(m)[1] not in ('ACK', 'CANCEL')]
        ctx['dialog_cseq'] = max(sent) if sent else None
    return ctx


def _unended_forks(before, dialog):
    """The 2xx of further forks of the dialog's INVITE (another To tag) whose
    dialog no <req_bye_fork> has ended, the first 2xx of each tag."""
    ended = [_tag(_one(m, ['to', 't'])) for m in before if _sym(m) == '<req_bye_fork>']
    seen, forks = [], []
    for m in before:
        if _sym(m) != '<rep_invite_2xx>' or _one(m, ['call-id', 'i']) != dialog['call_id']:
            continue
        tag = _tag(_one(m, ['to', 't']))
        if tag != _tag(dialog['to']) and tag not in ended and tag not in seen:
            seen.append(tag)
            forks.append(m)
    return forks


def fork_unended(r):
    ctx = _context(r)
    dialog = None
    for m in ctx['before']:
        if _sym(m) == '<rep_invite_2xx>':
            q = _request_of(m, ctx['before'])
            if q is not None and _sym(q) in _INITIAL_INVITES and (
                    dialog is None or dialog['call_id'] != _one(m, ['call-id', 'i'])):
                dialog = {'call_id': _one(m, ['call-id', 'i']), 'to': _one(m, ['to', 't'])}
    return dialog is not None and bool(_unended_forks(ctx['before'], dialog))


def _accepted_by_client(request, after):
    """RFC 6141 §4.6: the callee's target refresh counts only once our 2xx
    answered it (an error reply, e.g. 491 in glare, leaves the target)."""
    for m in after:
        if _sym(m) == '<resp_reinvite_from_server>':
            return str(m).startswith('SIP/2.0 2')
        if _sym(m) in ('<resp_reinvite_491>', '<resp_from_server_refused>'):
            return False
    return False


_DIALOG_REQUESTS = ('<req_bye>', '<req_bye_auth>', '<req_bye_early>', '<req_bye_fork>', '<req_reinvite>', '<req_reinvite_auth>', '<req_options_dialog>',
                    '<req_extension_dialog>', '<req_options_dialog_out_of_order>',
                    '<req_ack_2xx>', '<req_ack_reinvite_2xx>', '<req_ack_2xx_again>')
_COPYING_REQUESTS = ('<req_ack_failure>', '<req_ack_reinvite_failure>', '<req_cancel>', '<req_cancel_other_branch>',
                     '<req_cancel_other_sent_by>', '<req_ack_2xx>', '<req_ack_reinvite_2xx>', '<req_ack_2xx_again>',
                     '<req_invite_merged>')
_ACKS = ('<req_ack_failure>', '<req_ack_reinvite_failure>', '<req_ack_2xx>', '<req_ack_reinvite_2xx>',
         '<req_ack_2xx_again>')
# the ACK for the 2xx of the initial INVITE: built from that 2xx
_ACKS_OF_2XX = ('<req_ack_2xx>', '<req_ack_2xx_again>')
_ALL_ACKS_OF_2XX = ('<req_ack_2xx>', '<req_ack_2xx_again>', '<req_ack_reinvite_2xx>')


_RETRIED_INVITES = ('<req_invite_redirected>', '<req_invite_via_proxy>', '<req_options_redirected>',
                    '<req_register_redirected>', '<req_extension_redirected>', '<req_options_via_proxy>',
                    '<req_register_via_proxy>', '<req_extension_via_proxy>')


def _origin(ctx):
    name = ctx['name']
    if name in _DIALOG_REQUESTS and name != '<req_ack_2xx>' and ctx['dialog'] is not None:
        return ctx['dialog']['invite']
    if name.endswith('_auth>') or name in _COPYING_REQUESTS or name in _RETRIED_INVITES:
        return ctx['first']
    return None


def _route_of_reply(reply):
    rr = _header_values(reply, ['record-route']) if reply is not None else []
    return ', '.join(reversed(_split_list(','.join(rr)))) if rr else None


def _routed(target, route):
    """§12.2.1.1: with a loose route set (first URI with lr) the Request-URI is
    the remote target and Route the route set; with a strict one the
    Request-URI is the first route URI (without the parameters a
    Request-URI may not carry, §19.1.1 Table 1) and Route the rest followed
    by the remote target."""
    entries = _split_list(route) if route else []
    if not entries or target is None:
        return target, route
    first = _uri_of(entries[0]) or ''
    uri_part = first.split('?')[0]
    if 'lr' in [p.split('=')[0].strip().lower() for p in uri_part.split(';')[1:]]:
        return target, route
    ruri = ';'.join(p for p in uri_part.split(';') if p.split('=')[0].strip().lower() != 'method')
    return ruri, ', '.join(entries[1:] + ['<' + target + '>'])


def _target_and_route(ctx):
    name, final, dialog = ctx['name'], ctx['final'], ctx['dialog']
    acked = ctx['acked']
    if name in _ACKS_OF_2XX and final is not None and (acked is None or _sym(acked) in _INITIAL_INVITES):
        contacts = _header_values(final, ['contact', 'm'])
        return _routed(_uri_of(contacts[0]) if contacts else None, _route_of_reply(final))
    target = dialog['target'] if dialog is not None else None
    if name in _ALL_ACKS_OF_2XX and final is not None \
            and _header_values(final, ['contact', 'm']):
        target = _uri_of(_header_values(final, ['contact', 'm'])[0])
    return _routed(target, dialog['route'] if dialog is not None else None)


def _redirect_uri(ctx):
    """§8.1.3.4: the first Contact URI of the latest 3xx to the request's
    method not tried before with that method."""
    method = _cseq(ctx['invite'])[1] if ctx['invite'] is not None else 'INVITE'
    redirects = [m for m in ctx['before'] if _sym(m).startswith('<rep_') and 300 <= _status(m) < 400
                 and _cseq(m)[1] == method]
    final = redirects[-1] if redirects else None
    tried = [_request_uri(m) for m in ctx['before'] if _is_request(m) and _cseq(m)[1] == method]
    for uri, _ in _contact_entries(_header_values(final, ['contact', 'm']) if final is not None else []):
        if uri != '*' and uri not in tried:
            return uri
    return None


# §19.1.5 header fields of a URI that are not honored: the ones the request
# itself decides, the "obviously dangerous" From, Call-ID, CSeq, Via,
# Record-Route, Route, the ones that would falsely advertise the client's
# location or capabilities (Accept, Accept-Encoding, Accept-Language, Allow,
# Contact, Organization, Supported, User-Agent), and Require /
# Proxy-Require, which would require extensions the client does not
# support (§8.1.1: MUST NOT); the URI's other header fields are honored
# one by one, an invalid one is dropped
_REDIRECT_FIELDS_KEPT = ('call-id', 'cseq', 'via', 'from', 'to', 'contact', 'content-length', 'content-type',
                         'content-encoding', 'max-forwards', 'body', 'record-route', 'route', 'accept',
                         'accept-encoding', 'accept-language', 'allow', 'organization', 'supported',
                         'user-agent', 'require', 'proxy-require', 'authorization', 'proxy-authorization')


def expect(node, field):
    """The value the history of the session decides for the sent field node."""
    ctx = _context(node)
    origin = _origin(ctx)
    name = ctx['name']
    # an ACK belongs to the INVITE its final reply answers (CSeq number)
    invite = ctx['acked'] if name in _ACKS and ctx['acked'] is not None else ctx['invite']
    dialog = ctx['dialog']
    final = ctx['final']
    own = str(node)
    if field == 'from_tag':
        return _tag(_one(origin, ['from', 'f'])) if origin is not None else own
    if field == 'to':
        return _one(invite, ['to', 't']) if invite is not None else own
    if field == 'reply_to':
        return _one(final, ['to', 't']) if final is not None else own
    if field == 'dialog_to':
        if name in _ACKS_OF_2XX:
            return _one(final, ['to', 't']) if final is not None else own
        return dialog['to'] if dialog is not None else own
    if field == 'call_id':
        return _one(origin, ['call-id', 'i']) if origin is not None else own
    if field == 'register_call_id':
        previous = [m for m in ctx['before'] if _is_request(m) and _cseq(m)[1] == 'REGISTER']
        return _one(previous[-1], ['call-id', 'i']) if previous else own
    if field == 'request_uri':
        return _request_uri(invite) if invite is not None else own
    if field == 'remote_target':
        return _target_and_route(ctx)[0] or own
    if field == 'redirect_target':
        uri = _redirect_uri(ctx)
        if uri is None:
            return own
        # without method parameter and headers
        return ';'.join(p for p in uri.split('?')[0].split(';') if p.split('=')[0].strip().lower() != 'method')
    if field in ('proxy_ruri', 'proxy_route_part'):
        # the latest 305 to the method of the request repeated
        method = _cseq(invite)[1] if invite is not None else 'INVITE'
        used = [m for m in ctx['before'] if _sym(m).startswith('<rep_') and _status(m) == 305 and _cseq(m)[1] == method]
        final = used[-1] if used else final
        contacts = _contact_entries(_header_values(final, ['contact', 'm'])) if final is not None else []
        if not contacts or invite is None:
            return own if field == 'proxy_ruri' else ''
        ruri, route = _routed(_request_uri(invite), '<' + contacts[0][0] + '>')
        if field == 'proxy_ruri':
            return ruri
        return 'Route: ' + route + '\r\n' if route else ''
    if field == 'redirect_headers':
        uri = _redirect_uri(ctx) or ''
        lines = []
        for h in (uri.split('?', 1)[1].split('&') if '?' in uri else []):
            k, _, v = h.partition('=')
            k, v = unquote(k).strip(), unquote(v).strip()
            line = k + ': ' + v + '\r\n'
            if _FULL_NAMES.get(k.lower(), k.lower()) not in _REDIRECT_FIELDS_KEPT and re.fullmatch(r'[A-Za-z][-A-Za-z0-9]*: [^\r\n]+\r\n', line):
                lines.append(line)
        return ''.join(lines)
    if field == 'method':
        if (name.endswith('_auth>') or name in _RETRIED_INVITES) and ctx['first'] is not None:
            return _info(ctx['first'])['start'].split(' ')[0]
        return _info(ctx['request'], False)['start'].split(' ')[0]
    if field == 'branch':
        return (_top_via_branch(invite) or 'z9hG4bK')[7:] if invite is not None else own
    if field == 'ack_branch':
        for m in reversed(ctx['before']):
            if _sym(m) in _ACKS_OF_2XX and final is not None and _cseq(m)[0] == _cseq(final)[0] \
                    and _tag(_one(m, ['to', 't'])) == _tag(_one(final, ['to', 't'])):
                return (_top_via_branch(m) or 'z9hG4bK')[7:]
        return own
    if field == 'other_port':
        return str(int(os.environ.get('SIP_LOCAL_PORT', '5070')) % 65535 + 1)
    if field in ('route_set', 'route_part'):
        route = _target_and_route(ctx)[1]
        if field == 'route_set':
            return route or own
        return 'Route: ' + route + '\r\n' if route else ''
    if field == 'request_route':
        routes = _header_values(invite, ['route']) if invite is not None else []
        return routes[0] if routes else own
    if field == 'request_route_part':
        routes = _header_values(invite, ['route']) if invite is not None else []
        return 'Route: ' + routes[0] + '\r\n' if routes else ''
    if field in ('credentials', 'credentials_part'):
        source = ctx['acked'] if name in _ACKS and ctx['acked'] is not None else invite
        creds = _header_values(source, ['authorization']) if source is not None else []
        pcreds = _header_values(source, ['proxy-authorization']) if source is not None else []
        text = ('Authorization: ' + creds[0]) if creds else (('Proxy-Authorization: ' + pcreds[0]) if pcreds else '')
        if field == 'credentials':
            return text or own
        return text + '\r\n' if text else ''
    if field == 'cseq_lower':
        return str(max(ctx['dialog_cseq'] - 1, 0)) if ctx['dialog_cseq'] is not None else own
    if field in ('cseq', 'cseq_old'):
        if name.startswith('<req_register') and not name.endswith('_auth>'):
            previous = [_cseq(m)[0] for m in ctx['before'] if _is_request(m) and _cseq(m)[1] == 'REGISTER']
            if not previous:
                return own
            return str(max(previous) - 1) if field == 'cseq_old' else str(max(previous) + 1)
        if name.endswith('_auth>') or name in _RETRIED_INVITES:
            return str(_cseq(invite)[0] + 1) if invite is not None else own
        if name in _ACKS:
            return str(_cseq(final)[0]) if final is not None else own
        if name in _COPYING_REQUESTS:
            return str(_cseq(invite)[0]) if invite is not None else own
        if name in _DIALOG_REQUESTS:
            return str(ctx['dialog_cseq'] + 1) if ctx['dialog_cseq'] is not None else own
        return own
    challenge = ctx['challenge']
    params = _challenge_params(challenge)
    if field == 'credentials_name':
        return 'Proxy-Authorization' if challenge is not None and _status(challenge) == 407 else 'Authorization'
    if field in ('realm', 'nonce', 'opaque'):
        return params.get(field) or own
    if field == 'algorithm':
        return params.get('algorithm', 'MD5')
    if field == 'opaque_part':
        return ', opaque="' + params['opaque'] + '"' if 'opaque' in params else ''
    if field == 'qop':
        offered = [q.strip() for q in params.get('qop', 'auth').split(',')]
        return 'auth' if 'auth' in offered or 'auth-int' not in offered else 'auth-int'
    if field == 'auth_uri':
        parts = _info(ctx['request'], False)['start'].split(' ')
        return parts[1] if len(parts) > 1 else own
    raise ValueError(field)


def _challenge_params_of(value):
    params = {}
    for part in _split_params(value[6:]):
        k, _, v = part.partition('=')
        v = v.strip()
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        params[k.strip().lower()] = v
    return params


def _challenge_params(reply):
    """RFC 8760 §2.4: the parameters of the topmost Digest challenge in reply
    whose algorithm the client supports (others are ignored)."""
    if reply is None:
        return {}
    names = ['www-authenticate'] if _status(reply) == 401 else ['proxy-authenticate']
    for value in _header_values(reply, names):
        if value.lower().startswith('digest'):
            params = _challenge_params_of(value)
            if params.get('algorithm', 'MD5').lower() in _HASHES:
                return params
    return {}


def challenge_usable(c):
    return bool(_challenge_params(_context(c)['challenge']))


def _split_params(text):
    parts, current, quoted = [], '', False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == ',' and not quoted:
            parts.append(current.strip())
            current = ''
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def record_request(message):
    info = _parse_message(str(message))
    values = lambda names: [v for n, v in info['fields'] if n in names]
    record('in_via', ', '.join(values(['via', 'v'])))
    for key, names in (('in_from', ['from', 'f']), ('in_to', ['to', 't']), ('in_call_id', ['call-id', 'i']),
                       ('in_cseq', ['cseq'])):
        if values(names):
            record(key, values(names)[0])
    return str(message)


def _latest_server_request(node):
    while node is not None and not _sym(node).startswith('<resp_'):
        node = node.parent
    for m in reversed(_session_messages_before(node)):
        if _sym(m).startswith('<srv_req_'):
            return m
    return None


def echo(node, field):
    q = _latest_server_request(node)
    if q is None:
        return str(node)
    require = [t.strip() for t in ','.join(_header_values(q, ['require'])).split(',') if t.strip()]
    if field in ('options_status', 'refusal_status'):
        code = _refusal(q)
        if code == 420:
            return 'SIP/2.0 420 Bad Extension\r\n'
        if code == 415 or field == 'refusal_status':
            return 'SIP/2.0 415 Unsupported Media Type\r\n'
        return 'SIP/2.0 200 OK\r\n'
    if field == 'unsupported_part':
        return 'Unsupported: ' + ', '.join(require) + '\r\n' if require else ''
    names = {'via': ['via', 'v'], 'from': ['from', 'f'], 'to': ['to', 't'], 'call_id': ['call-id', 'i'],
             'cseq': ['cseq']}[field]
    values = _header_values(q, names)
    if field == 'via':
        return ', '.join(values) if values else str(node)
    return ' '.join(values[0].split()) if field == 'cseq' and values else (values[0] if values else str(node))


_UNDERSTOOD_TYPES = ['application/sdp']
_UNDERSTOOD_CODINGS = ('identity', 'gzip', 'deflate')


def _refusal(q):
    """420 if the callee's request q requires option tags (§8.2.2.3, the
    client supports none; checked first), 415 if its body has a type or a
    content coding the client does not understand and is not marked
    optional (§8.2.3, §20.11 handling=optional), else None."""
    if any(t.strip() for t in ','.join(_header_values(q, ['require'])).split(',')):
        return 420
    ctype = (_header_values(q, ['content-type', 'c']) or [''])[0].split(';')[0].strip().lower()
    codings = [c.lower() for c in _option_tags(q, ['content-encoding', 'e'])]
    if not ctype and not codings:
        return None
    disposition = (_header_values(q, ['content-disposition']) or [''])[0].lower().replace(' ', '')
    if 'handling=optional' in disposition:
        return None
    if ctype and ctype not in _UNDERSTOOD_TYPES:
        return 415
    if any(c not in _UNDERSTOOD_CODINGS for c in codings):
        return 415
    return None


def callee_request_refused(r):
    q = _latest_server_request(r)
    return q is not None and _refusal(q) is not None


def same_response(r):
    """§13.3.1.4: our 2xx to the callee's re-INVITE is retransmitted unchanged."""
    for m in reversed(_session_messages_before(r)):
        if _sym(m) == '<srv_req_reinvite>':
            break
        if _sym(m) == '<resp_reinvite_from_server>' and m is not r:
            return str(m)
    return str(r)


def ack_matches_server_invite(r):
    before = _session_messages_before(r)
    invites = [m for m in before if _sym(m) == '<srv_req_reinvite>']
    if not invites or _cseq(r)[0] != _cseq(invites[-1])[0] \
            or _one(r, ['call-id', 'i']) != _one(invites[-1], ['call-id', 'i']):
        return False
    # the ACK of our 491 (glare) is hop by hop and carries no answer
    refusals = ('<resp_reinvite_491>', '<resp_from_server_refused>')
    if any(_sym(m) in refusals for m in before[before.index(invites[-1]):]):
        return True
    # §13.2.1: a re-INVITE without offer got the offer in our 2xx; the ACK
    # carries the answer
    if _find(invites[-1], '<body>') is None:
        ctype = _header_values(r, ['content-type', 'c'])
        return _find(r, '<body>') is not None and bool(ctype) and 'application/sdp' in ctype[0].lower()
    return True


def server_request_fields(r):
    """§8.1.1: Max-Forwards (once) and Via; §8.1.1.8, §20 Table 2: an INVITE
    carries one Contact.  (A body the client does not understand is
    refused with 415, see _refusal.)"""
    method = _info(r)['start'].split(' ', 1)[0]
    if len(_header_values(r, ['max-forwards'])) != 1 or not _header_values(r, ['via', 'v']):
        return False
    if method == 'INVITE' and len(_contact_entries(_header_values(r, ['contact', 'm']))) != 1:
        return False
    return True


def server_request_in_dialog(r):
    before = _session_messages_before(r)
    ctx_dialog = None
    for m in before:
        if _sym(m) == '<rep_invite_2xx>':
            ctx_dialog = m
    if ctx_dialog is None:
        return False
    if _one(r, ['call-id', 'i']) != _one(ctx_dialog, ['call-id', 'i']):
        return False
    # §12.2.1.1 in the callee's direction: To = our URI and tag (its remote
    # URI and tag), From = its URI and tag (the To of the 2xx)
    if _tag(_one(r, ['to', 't'])) != _tag(_one(ctx_dialog, ['from', 'f'])) \
            or _tag(_one(r, ['from', 'f'])) != _tag(_one(ctx_dialog, ['to', 't'])):
        return False
    if _uri_key(_uri_of(_one(r, ['to', 't']))) != _uri_key(_uri_of(_one(ctx_dialog, ['from', 'f']))) \
            or _uri_key(_uri_of(_one(r, ['from', 'f']))) != _uri_key(_uri_of(_one(ctx_dialog, ['to', 't']))):
        return False
    # §12.2.1.1 in the callee's direction: CSeq one higher than its last request
    previous = [m for m in before if _sym(m).startswith('<srv_req_') and _sym(m) != '<srv_req_ack>'
                and _one(m, ['call-id', 'i']) == _one(r, ['call-id', 'i'])]
    if previous and _cseq(r)[0] != _cseq(previous[-1])[0] + 1:
        return False
    # §12.1.1: the UAS's remote target is the Contact of our INVITE, its route
    # set the INVITE's Record-Route (we send none, so no Route)
    invite = _request_of(ctx_dialog, before)
    contact = _header_values(invite, ['contact', 'm']) if invite is not None else []
    if not contact or _request_uri(r) != _uri_of(contact[0]):
        return False
    return not _header_values(r, ['route'])


def record_uri(key, address):
    record(key, _uri_of(str(address)))
    return str(address)


def record_route_set(value):
    text = str(value)
    record('route_set', ', '.join(x.strip() for x in reversed(text.split(','))))
    return text


_HASHES = {'md5': hashlib.md5, 'md5-sess': hashlib.md5, 'sha-256': hashlib.sha256,
           'sha-256-sess': hashlib.sha256, 'sha-512-256': lambda b: hashlib.new('sha512_256', b),
           'sha-512-256-sess': lambda b: hashlib.new('sha512_256', b)}


def _h(algorithm, text):
    return _HASHES.get(algorithm.lower(), hashlib.md5)(text.encode()).hexdigest()


def digest_response(c):
    """RFC 8760 §2.4 / RFC 3261 §22.4: response of the credentials c for the
    request they are part of (method of its Request-Line, body for auth-int)."""
    request = _request_node(c)
    text = str(request) if request is not None else 'INVITE '
    method = text.split(' ', 1)[0]
    realm = str(_find(c, '<s_auth_realm>'))
    nonce = str(_find(c, '<s_auth_nonce>'))
    uri = str(_find(c, '<s_auth_uri>'))
    algorithm = str(_find(c, '<s_auth_algorithm>')) or 'MD5'
    cnonce = str(_find(c, '<s_cnonce>'))
    nc = str(_find(c, '<s_nonce_count>'))
    qop = str(_find(c, '<s_qop>'))
    ha1 = _h(algorithm, str(_find(c, '<local_user>')) + ':' + realm + ':secret')
    if algorithm.lower().endswith('-sess'):
        ha1 = _h(algorithm, ha1 + ':' + nonce + ':' + cnonce)
    a2 = method + ':' + uri
    if qop == 'auth-int':
        body = text.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in text else ''
        a2 += ':' + _h(algorithm, body)
    return _h(algorithm, ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + _h(algorithm, a2))
