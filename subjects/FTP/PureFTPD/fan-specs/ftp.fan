# File Transfer Protocol (FTP), control connection, as seen by a user-PI
# Version: RFC 959 (STD 9) with verified errata and its updates
# Extensions: none (network protocol, TCP port 21)
# Authors:
# * generated with tools/gen_fan.py
# Sources (plain text copies under refs/):
# * RFC 959  File Transfer Protocol, https://www.rfc-editor.org/rfc/rfc959.txt
#   with errata https://www.rfc-editor.org/errata/rfc959 (3039: numbers 0..255;
#   4869: CDUP answers 250)
# * RFC 1123 section 4.1 (FTP requirements, updates RFC 959)
# * RFC 2228 FTP Security Extensions (AUTH, ADAT, PBSZ, PROT, CCC, MIC, CONF, ENC)
# * RFC 2389 Feature negotiation (FEAT, OPTS)
# * RFC 2428 FTP Extensions for IPv6 and NATs (EPRT, EPSV)
# * RFC 2640 Internationalization (LANG, UTF-8 pathnames)
# * RFC 3659 Extensions to FTP (MDTM, SIZE, REST STREAM, MLST, MLSD, TVFS)
# * RFC 5797 FTP command and extension registry
# * RFC 7151 HOST command for virtual hosts
# Details:
# * Fandango plays the user-PI (party Client) on the control connection; the
#   server-PI is party Server.  Both parties are defined by the driver.
# * Every state is one nonterminal <state_...>; every transition is one
#   alternative "<exchange_...> <next state>".  One exchange nonterminal exists per
#   command and per reply class that selects a different next state.
# * Every command accepts every reply code RFC 959 5.4 (and the updating RFCs)
#   lists for it, and, per RFC 1123 4.1.2.11, any other code of the same first
#   digit (<reply_Nyz_other...>).  421 always closes the session.
# * Replies may be single-line or multi-line (RFC 959 4.2, RFC 2389 2.2) unless a
#   format forbids it (RFC 2389 3.2 no-features, RFC 3659 3.1/4.1 213 replies).
# * Target resources (user, password, account, file, directory, new name,
#   data port, virtual host) come from environment variables FTP_*.
# TODO: RFC 959 3.2, 3.3, 3.4, 3.5 - the data connection (file contents in TYPE
#   A/E/I/L, record and page structure, block and compressed mode, restart
#   markers inside the data stream, LIST/NLST/MLSD listings) is a second TCP
#   connection the two driver parties do not reach; transfer commands are
#   modelled on the control connection only (<exchange_retr_done> etc.).
# TODO: RFC 959 4.1.3 ABOR/STAT during a transfer and the Telnet IP/Synch
#   sequence before ABOR (RFC 959 4.1.3, RFC 1123 4.1.3.3) need urgent TCP data
#   and concurrency; <abor_command> is sent as a plain command.
# TODO: RFC 959 5.2, RFC 1123 4.1.2.12 - Telnet option negotiation on the
#   control connection is not modelled (<reply_text_char> excludes IAC handling).
# TODO: RFC 2228 5.2, 9 - protected (MIC/CONF/ENC) session after the security
#   exchange is a sink state <state_secured>; login inside it is not modelled.
# TODO: RFC 959 3.2, 4.1.2 - after PASV/EPSV the user-DTP must connect before a
#   transfer; no transfer command and no REST is sent from <state_logged_in_passive>
#   (and its EPSV ALL variant) because the driver has no data-connection party.
# TODO: RFC 959 4.1.1 (USER "all transfer parameters unchanged") - the passive and
#   EPSV ALL flags are not carried through <state_need_password> and
#   <state_need_account>; PASV, EPSV and EPSV ALL before login keep
#   <state_not_logged_in>.
# TODO: RFC 1123 4.1.3.4 - REST with the receiver marker rrrr echoed from a
#   "110 MARK ssss = rrrr" reply is not linked to <reply_110_mark>; <marker> is free.
# TODO: RFC 3659 5.3 - STOU (and other commands a server may permit) after REST
#   are not sent from <state_restart_pending>.

import os

# Recording/recalling pair for the directory name of a 257 reply (RFC 959 Appendix II).
REPORTED_PATHS = []


def record_reported_path(path):
    REPORTED_PATHS.append(path)
    return path


def recall_reported_path():
    return REPORTED_PATHS[-1].replace('""', '"') if REPORTED_PATHS else '/'


# ==============================================================================
# Session and states (RFC 959 5.4 connection establishment, 6 state diagrams)
# ==============================================================================
# A session starts with the server's greeting (RFC 959 5.4 "Connection Establishment").
<start> ::= <state_greeting>

# Greeting: 220, or 120 followed later by 220, or 421 (RFC 959 5.4).
<state_greeting> ::= (
    <Server:greeting_ready> <state_not_logged_in>
  | <Server:greeting_delay> <state_greeting_delayed>
  | <Server:greeting_closing> <state_closed_by_server>
)
# After 120 the server sends 220 when ready, or 421 (RFC 959 5.4).
<state_greeting_delayed> ::= (
    <Server:greeting_ready> <state_not_logged_in>
  | <Server:greeting_closing> <state_closed_by_server>
)
# Greeting replies (RFC 959 5.4 connection establishment).
<greeting_ready> ::= <reply_220>
<greeting_delay> ::= <reply_120>
<greeting_closing> ::= <reply_421>

# The control connection is closed after 221 or 421 (RFC 959 4.2.1, 5.4).
<state_closed> ::= ''
# 421: the server closes the control connection; nothing follows (RFC 959 4.2.1).
<state_closed_by_server> ::= <state_closed>

# Connected, no user identified (RFC 959 6, login sequence; RFC 7151 3.2.3 begin B).
<state_not_logged_in> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_not_logged_in>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_not_logged_in>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_pass_logged_in> <state_logged_in>
  | <exchange_pass_need_account> <state_need_account>
  | <exchange_pass_rejected> <state_not_logged_in>
  | <exchange_pass_closing> <state_closed_by_server>
  | <exchange_acct_logged_in> <state_logged_in>
  | <exchange_acct_rejected> <state_not_logged_in>
  | <exchange_acct_closing> <state_closed_by_server>
  | <exchange_cwd_done> <state_not_logged_in>
  | <exchange_cwd_closing> <state_closed_by_server>
  | <exchange_xcwd_done> <state_not_logged_in>
  | <exchange_xcwd_closing> <state_closed_by_server>
  | <exchange_cdup_done> <state_not_logged_in>
  | <exchange_cdup_closing> <state_closed_by_server>
  | <exchange_xcup_done> <state_not_logged_in>
  | <exchange_xcup_closing> <state_closed_by_server>
  | <exchange_smnt_done> <state_not_logged_in>
  | <exchange_smnt_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_not_logged_in>
  | <exchange_rein_closing> <state_closed_by_server>
  | <exchange_port_active> <state_not_logged_in>
  | <exchange_port_done> <state_not_logged_in>
  | <exchange_port_closing> <state_closed_by_server>
  | <exchange_pasv_passive> <state_not_logged_in>
  | <exchange_pasv_done> <state_not_logged_in>
  | <exchange_pasv_closing> <state_closed_by_server>
  | <exchange_type_done> <state_not_logged_in>
  | <exchange_type_closing> <state_closed_by_server>
  | <exchange_stru_done> <state_not_logged_in>
  | <exchange_stru_closing> <state_closed_by_server>
  | <exchange_mode_done> <state_not_logged_in>
  | <exchange_mode_closing> <state_closed_by_server>
  | <exchange_retr_done> <state_not_logged_in>
  | <exchange_retr_closing> <state_closed_by_server>
  | <exchange_stor_done> <state_not_logged_in>
  | <exchange_stor_closing> <state_closed_by_server>
  | <exchange_stou_done> <state_not_logged_in>
  | <exchange_stou_closing> <state_closed_by_server>
  | <exchange_appe_done> <state_not_logged_in>
  | <exchange_appe_closing> <state_closed_by_server>
  | <exchange_allo_done> <state_not_logged_in>
  | <exchange_allo_closing> <state_closed_by_server>
  | <exchange_rest_pending> <state_not_logged_in>
  | <exchange_rest_rejected> <state_not_logged_in>
  | <exchange_rest_closing> <state_closed_by_server>
  | <exchange_rnfr_pending> <state_not_logged_in>
  | <exchange_rnfr_rejected> <state_not_logged_in>
  | <exchange_rnfr_closing> <state_closed_by_server>
  | <exchange_rnto_done> <state_not_logged_in>
  | <exchange_rnto_closing> <state_closed_by_server>
  | <exchange_abor_done> <state_not_logged_in>
  | <exchange_abor_closing> <state_closed_by_server>
  | <exchange_dele_done> <state_not_logged_in>
  | <exchange_dele_closing> <state_closed_by_server>
  | <exchange_rmd_done> <state_not_logged_in>
  | <exchange_rmd_closing> <state_closed_by_server>
  | <exchange_xrmd_done> <state_not_logged_in>
  | <exchange_xrmd_closing> <state_closed_by_server>
  | <exchange_mkd_done> <state_not_logged_in>
  | <exchange_mkd_closing> <state_closed_by_server>
  | <exchange_xmkd_done> <state_not_logged_in>
  | <exchange_xmkd_closing> <state_closed_by_server>
  | <exchange_pwd_done> <state_not_logged_in>
  | <exchange_pwd_closing> <state_closed_by_server>
  | <exchange_xpwd_done> <state_not_logged_in>
  | <exchange_xpwd_closing> <state_closed_by_server>
  | <exchange_list_done> <state_not_logged_in>
  | <exchange_list_closing> <state_closed_by_server>
  | <exchange_nlst_done> <state_not_logged_in>
  | <exchange_nlst_closing> <state_closed_by_server>
  | <exchange_site_done> <state_not_logged_in>
  | <exchange_site_closing> <state_closed_by_server>
  | <exchange_syst_done> <state_not_logged_in>
  | <exchange_syst_closing> <state_closed_by_server>
  | <exchange_stat_done> <state_not_logged_in>
  | <exchange_stat_closing> <state_closed_by_server>
  | <exchange_help_done> <state_not_logged_in>
  | <exchange_help_closing> <state_closed_by_server>
  | <exchange_noop_done> <state_not_logged_in>
  | <exchange_noop_closing> <state_closed_by_server>
  | <exchange_feat_done> <state_not_logged_in>
  | <exchange_feat_closing> <state_closed_by_server>
  | <exchange_opts_done> <state_not_logged_in>
  | <exchange_opts_closing> <state_closed_by_server>
  | <exchange_eprt_active> <state_not_logged_in>
  | <exchange_eprt_done> <state_not_logged_in>
  | <exchange_eprt_closing> <state_closed_by_server>
  | <exchange_epsv_passive> <state_not_logged_in>
  | <exchange_epsv_done> <state_not_logged_in>
  | <exchange_epsv_closing> <state_closed_by_server>
  | <exchange_epsv_all_all_set> <state_not_logged_in>
  | <exchange_epsv_all_rejected> <state_not_logged_in>
  | <exchange_epsv_all_closing> <state_closed_by_server>
  | <exchange_lang_done> <state_not_logged_in>
  | <exchange_lang_closing> <state_closed_by_server>
  | <exchange_mdtm_done> <state_not_logged_in>
  | <exchange_mdtm_closing> <state_closed_by_server>
  | <exchange_size_done> <state_not_logged_in>
  | <exchange_size_closing> <state_closed_by_server>
  | <exchange_mlst_done> <state_not_logged_in>
  | <exchange_mlst_closing> <state_closed_by_server>
  | <exchange_mlsd_done> <state_not_logged_in>
  | <exchange_mlsd_closing> <state_closed_by_server>
  | <exchange_host_done> <state_not_logged_in>
  | <exchange_host_closing> <state_closed_by_server>
  | <exchange_auth_secured> <state_secured>
  | <exchange_auth_adat_needed> <state_security_exchange>
  | <exchange_auth_rejected> <state_not_logged_in>
  | <exchange_auth_closing> <state_closed_by_server>
  | <exchange_adat_secured> <state_secured>
  | <exchange_adat_adat_needed> <state_security_exchange>
  | <exchange_adat_rejected> <state_not_logged_in>
  | <exchange_adat_closing> <state_closed_by_server>
  | <exchange_pbsz_done> <state_not_logged_in>
  | <exchange_pbsz_closing> <state_closed_by_server>
  | <exchange_prot_done> <state_not_logged_in>
  | <exchange_prot_closing> <state_closed_by_server>
  | <exchange_ccc_done> <state_not_logged_in>
  | <exchange_ccc_closing> <state_closed_by_server>
  | <exchange_mic_done> <state_not_logged_in>
  | <exchange_mic_closing> <state_closed_by_server>
  | <exchange_conf_done> <state_not_logged_in>
  | <exchange_conf_closing> <state_closed_by_server>
  | <exchange_enc_done> <state_not_logged_in>
  | <exchange_enc_closing> <state_closed_by_server>
)

# USER accepted with 331/336, PASS expected (RFC 959 6 login diagram; RFC 2228 4).
<state_need_password> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_need_password>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_pass_logged_in> <state_logged_in>
  | <exchange_pass_need_account> <state_need_account>
  | <exchange_pass_rejected> <state_not_logged_in>
  | <exchange_pass_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_not_logged_in>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_need_password>
  | <exchange_rein_closing> <state_closed_by_server>
)

# USER or PASS answered 332, ACCT expected (RFC 959 6 login diagram).
<state_need_account> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_need_account>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_acct_logged_in> <state_logged_in>
  | <exchange_acct_rejected> <state_not_logged_in>
  | <exchange_acct_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_not_logged_in>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_need_account>
  | <exchange_rein_closing> <state_closed_by_server>
)

# AUTH or ADAT answered 334/335, ADAT expected (RFC 2228 3, 9).
<state_security_exchange> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_security_exchange>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_adat_secured> <state_secured>
  | <exchange_adat_adat_needed> <state_security_exchange>
  | <exchange_adat_rejected> <state_security_exchange>
  | <exchange_adat_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_security_exchange>
  | <exchange_rein_closing> <state_closed_by_server>
)

# Security data exchange complete, 234/235 (RFC 2228 3, 5.2).
<state_secured> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_secured>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_pbsz_done> <state_secured>
  | <exchange_pbsz_closing> <state_closed_by_server>
  | <exchange_prot_done> <state_secured>
  | <exchange_prot_closing> <state_closed_by_server>
  | <exchange_ccc_done> <state_secured>
  | <exchange_ccc_closing> <state_closed_by_server>
  | <exchange_mic_done> <state_secured>
  | <exchange_mic_closing> <state_closed_by_server>
  | <exchange_conf_done> <state_secured>
  | <exchange_conf_closing> <state_closed_by_server>
  | <exchange_enc_done> <state_secured>
  | <exchange_enc_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_secured>
  | <exchange_rein_closing> <state_closed_by_server>
)

# User logged in (RFC 959 6).
<state_logged_in> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_logged_in>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_logged_in>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_pass_logged_in> <state_logged_in>
  | <exchange_pass_need_account> <state_need_account>
  | <exchange_pass_rejected> <state_logged_in>
  | <exchange_pass_closing> <state_closed_by_server>
  | <exchange_acct_logged_in> <state_logged_in>
  | <exchange_acct_rejected> <state_logged_in>
  | <exchange_acct_closing> <state_closed_by_server>
  | <exchange_cwd_done> <state_logged_in>
  | <exchange_cwd_closing> <state_closed_by_server>
  | <exchange_xcwd_done> <state_logged_in>
  | <exchange_xcwd_closing> <state_closed_by_server>
  | <exchange_cdup_done> <state_logged_in>
  | <exchange_cdup_closing> <state_closed_by_server>
  | <exchange_xcup_done> <state_logged_in>
  | <exchange_xcup_closing> <state_closed_by_server>
  | <exchange_smnt_done> <state_logged_in>
  | <exchange_smnt_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_logged_in>
  | <exchange_rein_closing> <state_closed_by_server>
  | <exchange_port_active> <state_logged_in>
  | <exchange_port_done> <state_logged_in>
  | <exchange_port_closing> <state_closed_by_server>
  | <exchange_pasv_passive> <state_logged_in_passive>
  | <exchange_pasv_done> <state_logged_in>
  | <exchange_pasv_closing> <state_closed_by_server>
  | <exchange_type_done> <state_logged_in>
  | <exchange_type_closing> <state_closed_by_server>
  | <exchange_stru_done> <state_logged_in>
  | <exchange_stru_closing> <state_closed_by_server>
  | <exchange_mode_done> <state_logged_in>
  | <exchange_mode_closing> <state_closed_by_server>
  | <exchange_retr_done> <state_logged_in>
  | <exchange_retr_closing> <state_closed_by_server>
  | <exchange_stor_done> <state_logged_in>
  | <exchange_stor_closing> <state_closed_by_server>
  | <exchange_stou_done> <state_logged_in>
  | <exchange_stou_closing> <state_closed_by_server>
  | <exchange_appe_done> <state_logged_in>
  | <exchange_appe_closing> <state_closed_by_server>
  | <exchange_allo_done> <state_logged_in>
  | <exchange_allo_closing> <state_closed_by_server>
  | <exchange_rest_pending> <state_restart_pending>
  | <exchange_rest_rejected> <state_logged_in>
  | <exchange_rest_closing> <state_closed_by_server>
  | <exchange_rnfr_pending> <state_rename_pending>
  | <exchange_rnfr_rejected> <state_logged_in>
  | <exchange_rnfr_closing> <state_closed_by_server>
  | <exchange_rnto_done> <state_logged_in>
  | <exchange_rnto_closing> <state_closed_by_server>
  | <exchange_abor_done> <state_logged_in>
  | <exchange_abor_closing> <state_closed_by_server>
  | <exchange_dele_done> <state_logged_in>
  | <exchange_dele_closing> <state_closed_by_server>
  | <exchange_rmd_done> <state_logged_in>
  | <exchange_rmd_closing> <state_closed_by_server>
  | <exchange_xrmd_done> <state_logged_in>
  | <exchange_xrmd_closing> <state_closed_by_server>
  | <exchange_mkd_done> <state_logged_in>
  | <exchange_mkd_closing> <state_closed_by_server>
  | <exchange_xmkd_done> <state_logged_in>
  | <exchange_xmkd_closing> <state_closed_by_server>
  | <exchange_pwd_done> <state_logged_in>
  | <exchange_pwd_closing> <state_closed_by_server>
  | <exchange_xpwd_done> <state_logged_in>
  | <exchange_xpwd_closing> <state_closed_by_server>
  | <exchange_list_done> <state_logged_in>
  | <exchange_list_closing> <state_closed_by_server>
  | <exchange_nlst_done> <state_logged_in>
  | <exchange_nlst_closing> <state_closed_by_server>
  | <exchange_site_done> <state_logged_in>
  | <exchange_site_closing> <state_closed_by_server>
  | <exchange_syst_done> <state_logged_in>
  | <exchange_syst_closing> <state_closed_by_server>
  | <exchange_stat_done> <state_logged_in>
  | <exchange_stat_closing> <state_closed_by_server>
  | <exchange_help_done> <state_logged_in>
  | <exchange_help_closing> <state_closed_by_server>
  | <exchange_noop_done> <state_logged_in>
  | <exchange_noop_closing> <state_closed_by_server>
  | <exchange_feat_done> <state_logged_in>
  | <exchange_feat_closing> <state_closed_by_server>
  | <exchange_opts_done> <state_logged_in>
  | <exchange_opts_closing> <state_closed_by_server>
  | <exchange_eprt_active> <state_logged_in>
  | <exchange_eprt_done> <state_logged_in>
  | <exchange_eprt_closing> <state_closed_by_server>
  | <exchange_epsv_passive> <state_logged_in_passive>
  | <exchange_epsv_done> <state_logged_in>
  | <exchange_epsv_closing> <state_closed_by_server>
  | <exchange_epsv_all_all_set> <state_logged_in_epsv_all>
  | <exchange_epsv_all_rejected> <state_logged_in>
  | <exchange_epsv_all_closing> <state_closed_by_server>
  | <exchange_lang_done> <state_logged_in>
  | <exchange_lang_closing> <state_closed_by_server>
  | <exchange_mdtm_done> <state_logged_in>
  | <exchange_mdtm_closing> <state_closed_by_server>
  | <exchange_size_done> <state_logged_in>
  | <exchange_size_closing> <state_closed_by_server>
  | <exchange_mlst_done> <state_logged_in>
  | <exchange_mlst_closing> <state_closed_by_server>
  | <exchange_mlsd_done> <state_logged_in>
  | <exchange_mlsd_closing> <state_closed_by_server>
  | <exchange_host_done> <state_logged_in>
  | <exchange_host_closing> <state_closed_by_server>
  | <exchange_auth_secured> <state_secured>
  | <exchange_auth_adat_needed> <state_security_exchange>
  | <exchange_auth_rejected> <state_logged_in>
  | <exchange_auth_closing> <state_closed_by_server>
  | <exchange_adat_secured> <state_secured>
  | <exchange_adat_adat_needed> <state_security_exchange>
  | <exchange_adat_rejected> <state_logged_in>
  | <exchange_adat_closing> <state_closed_by_server>
  | <exchange_pbsz_done> <state_logged_in>
  | <exchange_pbsz_closing> <state_closed_by_server>
  | <exchange_prot_done> <state_logged_in>
  | <exchange_prot_closing> <state_closed_by_server>
  | <exchange_ccc_done> <state_logged_in>
  | <exchange_ccc_closing> <state_closed_by_server>
  | <exchange_mic_done> <state_logged_in>
  | <exchange_mic_closing> <state_closed_by_server>
  | <exchange_conf_done> <state_logged_in>
  | <exchange_conf_closing> <state_closed_by_server>
  | <exchange_enc_done> <state_logged_in>
  | <exchange_enc_closing> <state_closed_by_server>
  | <exchange_cwd_reported> <state_logged_in>
)

# RNFR answered 350, RNTO must follow (RFC 959 4.1.3, 6 rename diagram).
<state_rename_pending> ::= (
    <exchange_rnto_done> <state_logged_in>
  | <exchange_rnto_closing> <state_closed_by_server>
)

# REST answered 350, a transfer command must follow (RFC 959 4.1.3, 6; RFC 3659 5.3).
<state_restart_pending> ::= (
    <exchange_retr_done> <state_logged_in>
  | <exchange_retr_closing> <state_closed_by_server>
  | <exchange_stor_done> <state_logged_in>
  | <exchange_stor_closing> <state_closed_by_server>
  | <exchange_appe_done> <state_logged_in>
  | <exchange_appe_closing> <state_closed_by_server>
)

# User logged in (RFC 959 6), server-DTP listening after PASV/EPSV (RFC 959 3.2, 4.1.2; RFC 2428 3).
<state_logged_in_passive> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_logged_in_passive>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in_passive>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_logged_in_passive>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_pass_logged_in> <state_logged_in_passive>
  | <exchange_pass_need_account> <state_need_account>
  | <exchange_pass_rejected> <state_logged_in_passive>
  | <exchange_pass_closing> <state_closed_by_server>
  | <exchange_acct_logged_in> <state_logged_in_passive>
  | <exchange_acct_rejected> <state_logged_in_passive>
  | <exchange_acct_closing> <state_closed_by_server>
  | <exchange_cwd_done> <state_logged_in_passive>
  | <exchange_cwd_closing> <state_closed_by_server>
  | <exchange_xcwd_done> <state_logged_in_passive>
  | <exchange_xcwd_closing> <state_closed_by_server>
  | <exchange_cdup_done> <state_logged_in_passive>
  | <exchange_cdup_closing> <state_closed_by_server>
  | <exchange_xcup_done> <state_logged_in_passive>
  | <exchange_xcup_closing> <state_closed_by_server>
  | <exchange_smnt_done> <state_logged_in_passive>
  | <exchange_smnt_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_logged_in_passive>
  | <exchange_rein_closing> <state_closed_by_server>
  | <exchange_port_active> <state_logged_in>
  | <exchange_port_done> <state_logged_in_passive>
  | <exchange_port_closing> <state_closed_by_server>
  | <exchange_pasv_passive> <state_logged_in_passive>
  | <exchange_pasv_done> <state_logged_in_passive>
  | <exchange_pasv_closing> <state_closed_by_server>
  | <exchange_type_done> <state_logged_in_passive>
  | <exchange_type_closing> <state_closed_by_server>
  | <exchange_stru_done> <state_logged_in_passive>
  | <exchange_stru_closing> <state_closed_by_server>
  | <exchange_mode_done> <state_logged_in_passive>
  | <exchange_mode_closing> <state_closed_by_server>
  | <exchange_allo_done> <state_logged_in_passive>
  | <exchange_allo_closing> <state_closed_by_server>
  | <exchange_rnfr_pending> <state_rename_pending_passive>
  | <exchange_rnfr_rejected> <state_logged_in_passive>
  | <exchange_rnfr_closing> <state_closed_by_server>
  | <exchange_rnto_done> <state_logged_in_passive>
  | <exchange_rnto_closing> <state_closed_by_server>
  | <exchange_abor_done> <state_logged_in_passive>
  | <exchange_abor_closing> <state_closed_by_server>
  | <exchange_dele_done> <state_logged_in_passive>
  | <exchange_dele_closing> <state_closed_by_server>
  | <exchange_rmd_done> <state_logged_in_passive>
  | <exchange_rmd_closing> <state_closed_by_server>
  | <exchange_xrmd_done> <state_logged_in_passive>
  | <exchange_xrmd_closing> <state_closed_by_server>
  | <exchange_mkd_done> <state_logged_in_passive>
  | <exchange_mkd_closing> <state_closed_by_server>
  | <exchange_xmkd_done> <state_logged_in_passive>
  | <exchange_xmkd_closing> <state_closed_by_server>
  | <exchange_pwd_done> <state_logged_in_passive>
  | <exchange_pwd_closing> <state_closed_by_server>
  | <exchange_xpwd_done> <state_logged_in_passive>
  | <exchange_xpwd_closing> <state_closed_by_server>
  | <exchange_site_done> <state_logged_in_passive>
  | <exchange_site_closing> <state_closed_by_server>
  | <exchange_syst_done> <state_logged_in_passive>
  | <exchange_syst_closing> <state_closed_by_server>
  | <exchange_stat_done> <state_logged_in_passive>
  | <exchange_stat_closing> <state_closed_by_server>
  | <exchange_help_done> <state_logged_in_passive>
  | <exchange_help_closing> <state_closed_by_server>
  | <exchange_noop_done> <state_logged_in_passive>
  | <exchange_noop_closing> <state_closed_by_server>
  | <exchange_feat_done> <state_logged_in_passive>
  | <exchange_feat_closing> <state_closed_by_server>
  | <exchange_opts_done> <state_logged_in_passive>
  | <exchange_opts_closing> <state_closed_by_server>
  | <exchange_eprt_active> <state_logged_in>
  | <exchange_eprt_done> <state_logged_in_passive>
  | <exchange_eprt_closing> <state_closed_by_server>
  | <exchange_epsv_passive> <state_logged_in_passive>
  | <exchange_epsv_done> <state_logged_in_passive>
  | <exchange_epsv_closing> <state_closed_by_server>
  | <exchange_epsv_all_all_set> <state_logged_in_epsv_all_passive>
  | <exchange_epsv_all_rejected> <state_logged_in_passive>
  | <exchange_epsv_all_closing> <state_closed_by_server>
  | <exchange_lang_done> <state_logged_in_passive>
  | <exchange_lang_closing> <state_closed_by_server>
  | <exchange_mdtm_done> <state_logged_in_passive>
  | <exchange_mdtm_closing> <state_closed_by_server>
  | <exchange_size_done> <state_logged_in_passive>
  | <exchange_size_closing> <state_closed_by_server>
  | <exchange_mlst_done> <state_logged_in_passive>
  | <exchange_mlst_closing> <state_closed_by_server>
  | <exchange_host_done> <state_logged_in_passive>
  | <exchange_host_closing> <state_closed_by_server>
  | <exchange_auth_secured> <state_secured>
  | <exchange_auth_adat_needed> <state_security_exchange>
  | <exchange_auth_rejected> <state_logged_in_passive>
  | <exchange_auth_closing> <state_closed_by_server>
  | <exchange_adat_secured> <state_secured>
  | <exchange_adat_adat_needed> <state_security_exchange>
  | <exchange_adat_rejected> <state_logged_in_passive>
  | <exchange_adat_closing> <state_closed_by_server>
  | <exchange_pbsz_done> <state_logged_in_passive>
  | <exchange_pbsz_closing> <state_closed_by_server>
  | <exchange_prot_done> <state_logged_in_passive>
  | <exchange_prot_closing> <state_closed_by_server>
  | <exchange_ccc_done> <state_logged_in_passive>
  | <exchange_ccc_closing> <state_closed_by_server>
  | <exchange_mic_done> <state_logged_in_passive>
  | <exchange_mic_closing> <state_closed_by_server>
  | <exchange_conf_done> <state_logged_in_passive>
  | <exchange_conf_closing> <state_closed_by_server>
  | <exchange_enc_done> <state_logged_in_passive>
  | <exchange_enc_closing> <state_closed_by_server>
  | <exchange_cwd_reported> <state_logged_in_passive>
)

# RNFR answered 350, RNTO must follow (RFC 959 4.1.3, 6 rename diagram), server-DTP listening after PASV/EPSV (RFC 959 3.2, 4.1.2; RFC 2428 3).
<state_rename_pending_passive> ::= (
    <exchange_rnto_done> <state_logged_in_passive>
  | <exchange_rnto_closing> <state_closed_by_server>
)

# User logged in (RFC 959 6) after EPSV ALL (RFC 2428 3).
<state_logged_in_epsv_all> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_logged_in_epsv_all>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in_epsv_all>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_logged_in_epsv_all>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_pass_logged_in> <state_logged_in_epsv_all>
  | <exchange_pass_need_account> <state_need_account>
  | <exchange_pass_rejected> <state_logged_in_epsv_all>
  | <exchange_pass_closing> <state_closed_by_server>
  | <exchange_acct_logged_in> <state_logged_in_epsv_all>
  | <exchange_acct_rejected> <state_logged_in_epsv_all>
  | <exchange_acct_closing> <state_closed_by_server>
  | <exchange_cwd_done> <state_logged_in_epsv_all>
  | <exchange_cwd_closing> <state_closed_by_server>
  | <exchange_xcwd_done> <state_logged_in_epsv_all>
  | <exchange_xcwd_closing> <state_closed_by_server>
  | <exchange_cdup_done> <state_logged_in_epsv_all>
  | <exchange_cdup_closing> <state_closed_by_server>
  | <exchange_xcup_done> <state_logged_in_epsv_all>
  | <exchange_xcup_closing> <state_closed_by_server>
  | <exchange_smnt_done> <state_logged_in_epsv_all>
  | <exchange_smnt_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_logged_in_epsv_all>
  | <exchange_rein_closing> <state_closed_by_server>
  | <exchange_port_refused_epsv_all> <state_logged_in_epsv_all>
  | <exchange_port_closing> <state_closed_by_server>
  | <exchange_pasv_refused_epsv_all> <state_logged_in_epsv_all>
  | <exchange_pasv_closing> <state_closed_by_server>
  | <exchange_type_done> <state_logged_in_epsv_all>
  | <exchange_type_closing> <state_closed_by_server>
  | <exchange_stru_done> <state_logged_in_epsv_all>
  | <exchange_stru_closing> <state_closed_by_server>
  | <exchange_mode_done> <state_logged_in_epsv_all>
  | <exchange_mode_closing> <state_closed_by_server>
  | <exchange_retr_done> <state_logged_in_epsv_all>
  | <exchange_retr_closing> <state_closed_by_server>
  | <exchange_stor_done> <state_logged_in_epsv_all>
  | <exchange_stor_closing> <state_closed_by_server>
  | <exchange_stou_done> <state_logged_in_epsv_all>
  | <exchange_stou_closing> <state_closed_by_server>
  | <exchange_appe_done> <state_logged_in_epsv_all>
  | <exchange_appe_closing> <state_closed_by_server>
  | <exchange_allo_done> <state_logged_in_epsv_all>
  | <exchange_allo_closing> <state_closed_by_server>
  | <exchange_rest_pending> <state_restart_pending_epsv_all>
  | <exchange_rest_rejected> <state_logged_in_epsv_all>
  | <exchange_rest_closing> <state_closed_by_server>
  | <exchange_rnfr_pending> <state_rename_pending_epsv_all>
  | <exchange_rnfr_rejected> <state_logged_in_epsv_all>
  | <exchange_rnfr_closing> <state_closed_by_server>
  | <exchange_rnto_done> <state_logged_in_epsv_all>
  | <exchange_rnto_closing> <state_closed_by_server>
  | <exchange_abor_done> <state_logged_in_epsv_all>
  | <exchange_abor_closing> <state_closed_by_server>
  | <exchange_dele_done> <state_logged_in_epsv_all>
  | <exchange_dele_closing> <state_closed_by_server>
  | <exchange_rmd_done> <state_logged_in_epsv_all>
  | <exchange_rmd_closing> <state_closed_by_server>
  | <exchange_xrmd_done> <state_logged_in_epsv_all>
  | <exchange_xrmd_closing> <state_closed_by_server>
  | <exchange_mkd_done> <state_logged_in_epsv_all>
  | <exchange_mkd_closing> <state_closed_by_server>
  | <exchange_xmkd_done> <state_logged_in_epsv_all>
  | <exchange_xmkd_closing> <state_closed_by_server>
  | <exchange_pwd_done> <state_logged_in_epsv_all>
  | <exchange_pwd_closing> <state_closed_by_server>
  | <exchange_xpwd_done> <state_logged_in_epsv_all>
  | <exchange_xpwd_closing> <state_closed_by_server>
  | <exchange_list_done> <state_logged_in_epsv_all>
  | <exchange_list_closing> <state_closed_by_server>
  | <exchange_nlst_done> <state_logged_in_epsv_all>
  | <exchange_nlst_closing> <state_closed_by_server>
  | <exchange_site_done> <state_logged_in_epsv_all>
  | <exchange_site_closing> <state_closed_by_server>
  | <exchange_syst_done> <state_logged_in_epsv_all>
  | <exchange_syst_closing> <state_closed_by_server>
  | <exchange_stat_done> <state_logged_in_epsv_all>
  | <exchange_stat_closing> <state_closed_by_server>
  | <exchange_help_done> <state_logged_in_epsv_all>
  | <exchange_help_closing> <state_closed_by_server>
  | <exchange_noop_done> <state_logged_in_epsv_all>
  | <exchange_noop_closing> <state_closed_by_server>
  | <exchange_feat_done> <state_logged_in_epsv_all>
  | <exchange_feat_closing> <state_closed_by_server>
  | <exchange_opts_done> <state_logged_in_epsv_all>
  | <exchange_opts_closing> <state_closed_by_server>
  | <exchange_eprt_refused_epsv_all> <state_logged_in_epsv_all>
  | <exchange_eprt_closing> <state_closed_by_server>
  | <exchange_epsv_passive> <state_logged_in_epsv_all_passive>
  | <exchange_epsv_done> <state_logged_in_epsv_all>
  | <exchange_epsv_closing> <state_closed_by_server>
  | <exchange_epsv_all_all_set> <state_logged_in_epsv_all>
  | <exchange_epsv_all_rejected> <state_logged_in_epsv_all>
  | <exchange_epsv_all_closing> <state_closed_by_server>
  | <exchange_lang_done> <state_logged_in_epsv_all>
  | <exchange_lang_closing> <state_closed_by_server>
  | <exchange_mdtm_done> <state_logged_in_epsv_all>
  | <exchange_mdtm_closing> <state_closed_by_server>
  | <exchange_size_done> <state_logged_in_epsv_all>
  | <exchange_size_closing> <state_closed_by_server>
  | <exchange_mlst_done> <state_logged_in_epsv_all>
  | <exchange_mlst_closing> <state_closed_by_server>
  | <exchange_mlsd_done> <state_logged_in_epsv_all>
  | <exchange_mlsd_closing> <state_closed_by_server>
  | <exchange_host_done> <state_logged_in_epsv_all>
  | <exchange_host_closing> <state_closed_by_server>
  | <exchange_auth_secured> <state_secured>
  | <exchange_auth_adat_needed> <state_security_exchange>
  | <exchange_auth_rejected> <state_logged_in_epsv_all>
  | <exchange_auth_closing> <state_closed_by_server>
  | <exchange_adat_secured> <state_secured>
  | <exchange_adat_adat_needed> <state_security_exchange>
  | <exchange_adat_rejected> <state_logged_in_epsv_all>
  | <exchange_adat_closing> <state_closed_by_server>
  | <exchange_pbsz_done> <state_logged_in_epsv_all>
  | <exchange_pbsz_closing> <state_closed_by_server>
  | <exchange_prot_done> <state_logged_in_epsv_all>
  | <exchange_prot_closing> <state_closed_by_server>
  | <exchange_ccc_done> <state_logged_in_epsv_all>
  | <exchange_ccc_closing> <state_closed_by_server>
  | <exchange_mic_done> <state_logged_in_epsv_all>
  | <exchange_mic_closing> <state_closed_by_server>
  | <exchange_conf_done> <state_logged_in_epsv_all>
  | <exchange_conf_closing> <state_closed_by_server>
  | <exchange_enc_done> <state_logged_in_epsv_all>
  | <exchange_enc_closing> <state_closed_by_server>
  | <exchange_cwd_reported> <state_logged_in_epsv_all>
)

# RNFR answered 350, RNTO must follow (RFC 959 4.1.3, 6 rename diagram) after EPSV ALL (RFC 2428 3).
<state_rename_pending_epsv_all> ::= (
    <exchange_rnto_done> <state_logged_in_epsv_all>
  | <exchange_rnto_closing> <state_closed_by_server>
)

# REST answered 350, a transfer command must follow (RFC 959 4.1.3, 6; RFC 3659 5.3) after EPSV ALL (RFC 2428 3).
<state_restart_pending_epsv_all> ::= (
    <exchange_retr_done> <state_logged_in_epsv_all>
  | <exchange_retr_closing> <state_closed_by_server>
  | <exchange_stor_done> <state_logged_in_epsv_all>
  | <exchange_stor_closing> <state_closed_by_server>
  | <exchange_appe_done> <state_logged_in_epsv_all>
  | <exchange_appe_closing> <state_closed_by_server>
)

# User logged in (RFC 959 6) after EPSV ALL (RFC 2428 3), server-DTP listening after PASV/EPSV (RFC 959 3.2, 4.1.2; RFC 2428 3).
<state_logged_in_epsv_all_passive> ::= (
    <exchange_quit_closed> <state_closed>
  | <exchange_quit_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_quit_closing> <state_closed_by_server>
  | <exchange_user_logged_in> <state_logged_in_epsv_all_passive>
  | <exchange_user_need_password> <state_need_password>
  | <exchange_user_need_account> <state_need_account>
  | <exchange_user_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_user_closing> <state_closed_by_server>
  | <exchange_pass_logged_in> <state_logged_in_epsv_all_passive>
  | <exchange_pass_need_account> <state_need_account>
  | <exchange_pass_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_pass_closing> <state_closed_by_server>
  | <exchange_acct_logged_in> <state_logged_in_epsv_all_passive>
  | <exchange_acct_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_acct_closing> <state_closed_by_server>
  | <exchange_cwd_done> <state_logged_in_epsv_all_passive>
  | <exchange_cwd_closing> <state_closed_by_server>
  | <exchange_xcwd_done> <state_logged_in_epsv_all_passive>
  | <exchange_xcwd_closing> <state_closed_by_server>
  | <exchange_cdup_done> <state_logged_in_epsv_all_passive>
  | <exchange_cdup_closing> <state_closed_by_server>
  | <exchange_xcup_done> <state_logged_in_epsv_all_passive>
  | <exchange_xcup_closing> <state_closed_by_server>
  | <exchange_smnt_done> <state_logged_in_epsv_all_passive>
  | <exchange_smnt_closing> <state_closed_by_server>
  | <exchange_rein_reset> <state_not_logged_in>
  | <exchange_rein_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_rein_closing> <state_closed_by_server>
  | <exchange_port_refused_epsv_all> <state_logged_in_epsv_all_passive>
  | <exchange_port_closing> <state_closed_by_server>
  | <exchange_pasv_refused_epsv_all> <state_logged_in_epsv_all_passive>
  | <exchange_pasv_closing> <state_closed_by_server>
  | <exchange_type_done> <state_logged_in_epsv_all_passive>
  | <exchange_type_closing> <state_closed_by_server>
  | <exchange_stru_done> <state_logged_in_epsv_all_passive>
  | <exchange_stru_closing> <state_closed_by_server>
  | <exchange_mode_done> <state_logged_in_epsv_all_passive>
  | <exchange_mode_closing> <state_closed_by_server>
  | <exchange_allo_done> <state_logged_in_epsv_all_passive>
  | <exchange_allo_closing> <state_closed_by_server>
  | <exchange_rnfr_pending> <state_rename_pending_epsv_all_passive>
  | <exchange_rnfr_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_rnfr_closing> <state_closed_by_server>
  | <exchange_rnto_done> <state_logged_in_epsv_all_passive>
  | <exchange_rnto_closing> <state_closed_by_server>
  | <exchange_abor_done> <state_logged_in_epsv_all_passive>
  | <exchange_abor_closing> <state_closed_by_server>
  | <exchange_dele_done> <state_logged_in_epsv_all_passive>
  | <exchange_dele_closing> <state_closed_by_server>
  | <exchange_rmd_done> <state_logged_in_epsv_all_passive>
  | <exchange_rmd_closing> <state_closed_by_server>
  | <exchange_xrmd_done> <state_logged_in_epsv_all_passive>
  | <exchange_xrmd_closing> <state_closed_by_server>
  | <exchange_mkd_done> <state_logged_in_epsv_all_passive>
  | <exchange_mkd_closing> <state_closed_by_server>
  | <exchange_xmkd_done> <state_logged_in_epsv_all_passive>
  | <exchange_xmkd_closing> <state_closed_by_server>
  | <exchange_pwd_done> <state_logged_in_epsv_all_passive>
  | <exchange_pwd_closing> <state_closed_by_server>
  | <exchange_xpwd_done> <state_logged_in_epsv_all_passive>
  | <exchange_xpwd_closing> <state_closed_by_server>
  | <exchange_site_done> <state_logged_in_epsv_all_passive>
  | <exchange_site_closing> <state_closed_by_server>
  | <exchange_syst_done> <state_logged_in_epsv_all_passive>
  | <exchange_syst_closing> <state_closed_by_server>
  | <exchange_stat_done> <state_logged_in_epsv_all_passive>
  | <exchange_stat_closing> <state_closed_by_server>
  | <exchange_help_done> <state_logged_in_epsv_all_passive>
  | <exchange_help_closing> <state_closed_by_server>
  | <exchange_noop_done> <state_logged_in_epsv_all_passive>
  | <exchange_noop_closing> <state_closed_by_server>
  | <exchange_feat_done> <state_logged_in_epsv_all_passive>
  | <exchange_feat_closing> <state_closed_by_server>
  | <exchange_opts_done> <state_logged_in_epsv_all_passive>
  | <exchange_opts_closing> <state_closed_by_server>
  | <exchange_eprt_refused_epsv_all> <state_logged_in_epsv_all_passive>
  | <exchange_eprt_closing> <state_closed_by_server>
  | <exchange_epsv_passive> <state_logged_in_epsv_all_passive>
  | <exchange_epsv_done> <state_logged_in_epsv_all_passive>
  | <exchange_epsv_closing> <state_closed_by_server>
  | <exchange_epsv_all_all_set> <state_logged_in_epsv_all_passive>
  | <exchange_epsv_all_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_epsv_all_closing> <state_closed_by_server>
  | <exchange_lang_done> <state_logged_in_epsv_all_passive>
  | <exchange_lang_closing> <state_closed_by_server>
  | <exchange_mdtm_done> <state_logged_in_epsv_all_passive>
  | <exchange_mdtm_closing> <state_closed_by_server>
  | <exchange_size_done> <state_logged_in_epsv_all_passive>
  | <exchange_size_closing> <state_closed_by_server>
  | <exchange_mlst_done> <state_logged_in_epsv_all_passive>
  | <exchange_mlst_closing> <state_closed_by_server>
  | <exchange_host_done> <state_logged_in_epsv_all_passive>
  | <exchange_host_closing> <state_closed_by_server>
  | <exchange_auth_secured> <state_secured>
  | <exchange_auth_adat_needed> <state_security_exchange>
  | <exchange_auth_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_auth_closing> <state_closed_by_server>
  | <exchange_adat_secured> <state_secured>
  | <exchange_adat_adat_needed> <state_security_exchange>
  | <exchange_adat_rejected> <state_logged_in_epsv_all_passive>
  | <exchange_adat_closing> <state_closed_by_server>
  | <exchange_pbsz_done> <state_logged_in_epsv_all_passive>
  | <exchange_pbsz_closing> <state_closed_by_server>
  | <exchange_prot_done> <state_logged_in_epsv_all_passive>
  | <exchange_prot_closing> <state_closed_by_server>
  | <exchange_ccc_done> <state_logged_in_epsv_all_passive>
  | <exchange_ccc_closing> <state_closed_by_server>
  | <exchange_mic_done> <state_logged_in_epsv_all_passive>
  | <exchange_mic_closing> <state_closed_by_server>
  | <exchange_conf_done> <state_logged_in_epsv_all_passive>
  | <exchange_conf_closing> <state_closed_by_server>
  | <exchange_enc_done> <state_logged_in_epsv_all_passive>
  | <exchange_enc_closing> <state_closed_by_server>
  | <exchange_cwd_reported> <state_logged_in_epsv_all_passive>
)

# RNFR answered 350, RNTO must follow (RFC 959 4.1.3, 6 rename diagram) after EPSV ALL (RFC 2428 3), server-DTP listening after PASV/EPSV (RFC 959 3.2, 4.1.2; RFC 2428 3).
<state_rename_pending_epsv_all_passive> ::= (
    <exchange_rnto_done> <state_logged_in_epsv_all_passive>
  | <exchange_rnto_closing> <state_closed_by_server>
)

# ==============================================================================
# Exchanges: one command and the replies of one reply class (RFC 959 5.4)
# ==============================================================================

# USER exchanges (RFC 959 4.1.1, 5.3.2, 5.4; RFC 2228 4, 8.2).
<exchange_user_logged_in> ::= <Client:user_command> <Server:user_reply_logged_in>
<user_reply_logged_in> ::= <reply_230> | <reply_232> | <reply_2yz_other_230_232>
<exchange_user_need_password> ::= <Client:user_command> <Server:user_reply_need_password>
<user_reply_need_password> ::= <reply_331> | <reply_336>
<exchange_user_need_account> ::= <Client:user_command> <Server:user_reply_need_account>
<user_reply_need_account> ::= <reply_332> | <reply_3yz_other_331_332_336>
<exchange_user_rejected> ::= <Client:user_command> <Server:user_reply_rejected>
<user_reply_rejected> ::= <reply_530> | <reply_500> | <reply_501> | <reply_4yz_other_421> | <reply_5yz_other_500_501_530>
<exchange_user_closing> ::= <Client:user_command> <Server:user_reply_closing>
<user_reply_closing> ::= <reply_421>

# PASS exchanges (RFC 959 4.1.1, 5.3.2, 5.4).
<exchange_pass_logged_in> ::= <Client:pass_command> <Server:pass_reply_logged_in>
<pass_reply_logged_in> ::= <reply_230> | <reply_202> | <reply_2yz_other_202_230>
<exchange_pass_need_account> ::= <Client:pass_command> <Server:pass_reply_need_account>
<pass_reply_need_account> ::= <reply_332> | <reply_3yz_other_332>
<exchange_pass_rejected> ::= <Client:pass_command> <Server:pass_reply_rejected>
<pass_reply_rejected> ::= <reply_530> | <reply_500> | <reply_501> | <reply_503> | <reply_4yz_other_421> | <reply_5yz_other_500_501_503_530>
<exchange_pass_closing> ::= <Client:pass_command> <Server:pass_reply_closing>
<pass_reply_closing> ::= <reply_421>

# ACCT exchanges (RFC 959 4.1.1, 5.3.2, 5.4).
<exchange_acct_logged_in> ::= <Client:acct_command> <Server:acct_reply_logged_in>
<acct_reply_logged_in> ::= <reply_230> | <reply_202> | <reply_2yz_other_202_230>
<exchange_acct_rejected> ::= <Client:acct_command> <Server:acct_reply_rejected>
<acct_reply_rejected> ::= <reply_530> | <reply_500> | <reply_501> | <reply_503> | <reply_4yz_other_421> | <reply_5yz_other_500_501_503_530>
<exchange_acct_closing> ::= <Client:acct_command> <Server:acct_reply_closing>
<acct_reply_closing> ::= <reply_421>

# CWD exchanges (RFC 959 4.1.1, 5.4).
<exchange_cwd_done> ::= <Client:cwd_command> <Server:cwd_reply_done>
<cwd_reply_done> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_cwd_closing> ::= <Client:cwd_command> <Server:cwd_reply_closing>
<cwd_reply_closing> ::= <reply_421>

# XCWD exchanges (RFC 1123 4.1.3.1 (experimental CWD)).
<exchange_xcwd_done> ::= <Client:xcwd_command> <Server:xcwd_reply_done>
<xcwd_reply_done> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_xcwd_closing> ::= <Client:xcwd_command> <Server:xcwd_reply_closing>
<xcwd_reply_closing> ::= <reply_421>

# CDUP exchanges (RFC 959 4.1.1, 5.4 (errata 4869: 250)).
<exchange_cdup_done> ::= <Client:cdup_command> <Server:cdup_reply_done>
<cdup_reply_done> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_cdup_closing> ::= <Client:cdup_command> <Server:cdup_reply_closing>
<cdup_reply_closing> ::= <reply_421>

# XCUP exchanges (RFC 1123 4.1.3.1 (experimental CDUP)).
<exchange_xcup_done> ::= <Client:xcup_command> <Server:xcup_reply_done>
<xcup_reply_done> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_xcup_closing> ::= <Client:xcup_command> <Server:xcup_reply_closing>
<xcup_reply_closing> ::= <reply_421>

# SMNT exchanges (RFC 959 4.1.1, 5.4).
<exchange_smnt_done> ::= <Client:smnt_command> <Server:smnt_reply_done>
<smnt_reply_done> ::= <reply_202> | <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_202_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_smnt_closing> ::= <Client:smnt_command> <Server:smnt_reply_closing>
<smnt_reply_closing> ::= <reply_421>

# REIN exchanges (RFC 959 4.1.1, 5.4; RFC 7151 3.2.1).
# REIN: 220, possibly after 120, resets the session (RFC 959 5.4).
<exchange_rein_reset> ::= <Client:rein_command> <Server:reply_120>? <Server:rein_reply_reset>
<rein_reply_reset> ::= <reply_rein_ready> | <reply_2yz_other_220>
<exchange_rein_rejected> ::= <Client:rein_command> <Server:rein_reply_rejected>
<rein_reply_rejected> ::= <reply_500> | <reply_502> | <reply_4yz_other_421> | <reply_5yz_other_500_502>
<exchange_rein_closing> ::= <Client:rein_command> <Server:rein_reply_closing>
<rein_reply_closing> ::= <reply_421>

# QUIT exchanges (RFC 959 4.1.1, 5.4).
<exchange_quit_closed> ::= <Client:quit_command> <Server:quit_reply_closed>
<quit_reply_closed> ::= <reply_221> | <reply_2yz_other_221>
<exchange_quit_rejected> ::= <Client:quit_command> <Server:quit_reply_rejected>
<quit_reply_rejected> ::= <reply_500> | <reply_4yz_other_421> | <reply_5yz_other_500>
<exchange_quit_closing> ::= <Client:quit_command> <Server:quit_reply_closing>
<quit_reply_closing> ::= <reply_421>

# PORT exchanges (RFC 959 4.1.2, 5.3.2, 5.4).
<exchange_port_active> ::= <Client:port_command> <Server:port_reply_active>
<port_reply_active> ::= <reply_200> | <reply_2yz_other_200>
<exchange_port_done> ::= <Client:port_command> <Server:port_reply_done>
<port_reply_done> ::= <reply_500> | <reply_501> | <reply_530> | <reply_4yz_other_421> | <reply_5yz_other_500_501_530>
<exchange_port_closing> ::= <Client:port_command> <Server:port_reply_closing>
<port_reply_closing> ::= <reply_421>
# PORT after EPSV ALL MUST be rejected (RFC 2428 3).
<exchange_port_refused_epsv_all> ::= <Client:port_command> <Server:port_reply_refused_epsv_all>
<port_reply_refused_epsv_all> ::= <reply_500> | <reply_501> | <reply_530> | <reply_4yz_other_421> | <reply_5yz_other_500_501_530>

# PASV exchanges (RFC 959 4.1.2, 5.4; RFC 1123 4.1.2.6).
<exchange_pasv_passive> ::= <Client:pasv_command> <Server:pasv_reply_passive>
<pasv_reply_passive> ::= <reply_227_pasv>
<exchange_pasv_done> ::= <Client:pasv_command> <Server:pasv_reply_done>
<pasv_reply_done> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_2yz_other_227> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530>
<exchange_pasv_closing> ::= <Client:pasv_command> <Server:pasv_reply_closing>
<pasv_reply_closing> ::= <reply_421>
# PASV after EPSV ALL MUST be rejected (RFC 2428 3).
<exchange_pasv_refused_epsv_all> ::= <Client:pasv_command> <Server:pasv_reply_refused_epsv_all>
<pasv_reply_refused_epsv_all> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530>

# TYPE exchanges (RFC 959 4.1.2, 5.3.2, 5.4; RFC 1123 4.1.2.1).
<exchange_type_done> ::= <Client:type_command> <Server:type_reply_done>
<type_reply_done> ::= <reply_200> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_2yz_other_200> | <reply_4yz_other_421> | <reply_5yz_other_500_501_504_530>
<exchange_type_closing> ::= <Client:type_command> <Server:type_reply_closing>
<type_reply_closing> ::= <reply_421>

# STRU exchanges (RFC 959 4.1.2, 5.3.2, 5.4).
<exchange_stru_done> ::= <Client:stru_command> <Server:stru_reply_done>
<stru_reply_done> ::= <reply_200> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_2yz_other_200> | <reply_4yz_other_421> | <reply_5yz_other_500_501_504_530>
<exchange_stru_closing> ::= <Client:stru_command> <Server:stru_reply_closing>
<stru_reply_closing> ::= <reply_421>

# MODE exchanges (RFC 959 4.1.2, 5.3.2, 5.4).
<exchange_mode_done> ::= <Client:mode_command> <Server:mode_reply_done>
<mode_reply_done> ::= <reply_200> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_2yz_other_200> | <reply_4yz_other_421> | <reply_5yz_other_500_501_504_530>
<exchange_mode_closing> ::= <Client:mode_command> <Server:mode_reply_closing>
<mode_reply_closing> ::= <reply_421>

# RETR exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.3.4; RFC 2228 8.2).
# RETR: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_retr_done> ::= <Client:retr_command> (
    <Server:retr_reply_done>
  | <Server:retr_reply_preliminary> <Server:reply_110_mark>* <Server:retr_reply_completion>
)
<retr_reply_done> ::= <reply_450> | <reply_550> | <reply_500> | <reply_501> | <reply_530> | <reply_534> | <reply_535> | <reply_554> | <reply_555> | <reply_4yz_other_421_450> | <reply_5yz_other_500_501_530_534_535_550_554_555>
# RETR: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_retr_closing> ::= <Client:retr_command> (<Server:retr_reply_preliminary> <Server:reply_110_mark>*)? <Server:retr_reply_closing>
<retr_reply_closing> ::= <reply_421>
<retr_reply_preliminary> ::= <reply_125> | <reply_150> | <reply_1yz_other_110_125_150>
<retr_reply_completion> ::= <reply_226> | <reply_250> | <reply_425> | <reply_426> | <reply_451> | <reply_2yz_other_226_250> | <reply_4yz_other_421_425_426_451> | <reply_5yz_other>

# STOR exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.3.4; RFC 2228 8.2).
# STOR: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_stor_done> ::= <Client:stor_command> (
    <Server:stor_reply_done>
  | <Server:stor_reply_preliminary> <Server:reply_110_mark>* <Server:stor_reply_completion>
)
<stor_reply_done> ::= <reply_532> | <reply_450> | <reply_452> | <reply_553> | <reply_500> | <reply_501> | <reply_530> | <reply_534> | <reply_535> | <reply_554> | <reply_555> | <reply_4yz_other_421_450_452> | <reply_5yz_other_500_501_530_532_534_535_553_554_555>
# STOR: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_stor_closing> ::= <Client:stor_command> (<Server:stor_reply_preliminary> <Server:reply_110_mark>*)? <Server:stor_reply_closing>
<stor_reply_closing> ::= <reply_421>
<stor_reply_preliminary> ::= <reply_125> | <reply_150> | <reply_1yz_other_110_125_150>
<stor_reply_completion> ::= <reply_226> | <reply_250> | <reply_425> | <reply_426> | <reply_451> | <reply_551> | <reply_552> | <reply_2yz_other_226_250> | <reply_4yz_other_421_425_426_451> | <reply_5yz_other_551_552>

# STOU exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.9; RFC 2228 8.2).
# STOU: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_stou_done> ::= <Client:stou_command> (
    <Server:stou_reply_done>
  | <Server:stou_reply_preliminary> <Server:reply_110_mark>* <Server:stou_reply_completion>
)
<stou_reply_done> ::= <reply_532> | <reply_450> | <reply_452> | <reply_553> | <reply_500> | <reply_501> | <reply_530> | <reply_534> | <reply_535> | <reply_4yz_other_421_450_452> | <reply_5yz_other_500_501_530_532_534_535_553>
# STOU: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_stou_closing> ::= <Client:stou_command> (<Server:stou_reply_preliminary> <Server:reply_110_mark>*)? <Server:stou_reply_closing>
<stou_reply_closing> ::= <reply_421>
<stou_reply_preliminary> ::= <reply_125_stou> | <reply_150_stou> | <reply_1yz_other_110_125_150>
<stou_reply_completion> ::= <reply_226> | <reply_250> | <reply_425> | <reply_426> | <reply_451> | <reply_551> | <reply_552> | <reply_2yz_other_226_250> | <reply_4yz_other_421_425_426_451> | <reply_5yz_other_551_552>

# APPE exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.3.4; RFC 2228 8.2).
# APPE: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_appe_done> ::= <Client:appe_command> (
    <Server:appe_reply_done>
  | <Server:appe_reply_preliminary> <Server:reply_110_mark>* <Server:appe_reply_completion>
)
<appe_reply_done> ::= <reply_532> | <reply_450> | <reply_550> | <reply_452> | <reply_553> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_534> | <reply_535> | <reply_554> | <reply_555> | <reply_4yz_other_421_450_452> | <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555>
# APPE: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_appe_closing> ::= <Client:appe_command> (<Server:appe_reply_preliminary> <Server:reply_110_mark>*)? <Server:appe_reply_closing>
<appe_reply_closing> ::= <reply_421>
<appe_reply_preliminary> ::= <reply_125> | <reply_150> | <reply_1yz_other_110_125_150>
<appe_reply_completion> ::= <reply_226> | <reply_250> | <reply_425> | <reply_426> | <reply_451> | <reply_551> | <reply_552> | <reply_2yz_other_226_250> | <reply_4yz_other_421_425_426_451> | <reply_5yz_other_551_552>

# ALLO exchanges (RFC 959 4.1.3, 5.3.2, 5.4).
<exchange_allo_done> ::= <Client:allo_command> <Server:allo_reply_done>
<allo_reply_done> ::= <reply_200> | <reply_202> | <reply_500> | <reply_501> | <reply_504> | <reply_530> | <reply_2yz_other_200_202> | <reply_4yz_other_421> | <reply_5yz_other_500_501_504_530>
<exchange_allo_closing> ::= <Client:allo_command> <Server:allo_reply_closing>
<allo_reply_closing> ::= <reply_421>

# REST exchanges (RFC 959 4.1.3, 5.3.2, 5.4; RFC 3659 5).
<exchange_rest_pending> ::= <Client:rest_command> <Server:rest_reply_pending>
<rest_reply_pending> ::= <reply_350> | <reply_3yz_other_350>
<exchange_rest_rejected> ::= <Client:rest_command> <Server:rest_reply_rejected>
<rest_reply_rejected> ::= <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530>
<exchange_rest_closing> ::= <Client:rest_command> <Server:rest_reply_closing>
<rest_reply_closing> ::= <reply_421>

# RNFR exchanges (RFC 959 4.1.3, 5.4).
<exchange_rnfr_pending> ::= <Client:rnfr_command> <Server:rnfr_reply_pending>
<rnfr_reply_pending> ::= <reply_350> | <reply_3yz_other_350>
<exchange_rnfr_rejected> ::= <Client:rnfr_command> <Server:rnfr_reply_rejected>
<rnfr_reply_rejected> ::= <reply_450> | <reply_550> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_4yz_other_421_450> | <reply_5yz_other_500_501_502_530_550>
<exchange_rnfr_closing> ::= <Client:rnfr_command> <Server:rnfr_reply_closing>
<rnfr_reply_closing> ::= <reply_421>

# RNTO exchanges (RFC 959 4.1.3, 5.4).
<exchange_rnto_done> ::= <Client:rnto_command> <Server:rnto_reply_done>
<rnto_reply_done> ::= <reply_250> | <reply_532> | <reply_553> | <reply_500> | <reply_501> | <reply_502> | <reply_503> | <reply_530> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_503_530_532_553>
<exchange_rnto_closing> ::= <Client:rnto_command> <Server:rnto_reply_closing>
<rnto_reply_closing> ::= <reply_421>

# ABOR exchanges (RFC 959 4.1.3, 5.4).
<exchange_abor_done> ::= <Client:abor_command> <Server:abor_reply_done>
<abor_reply_done> ::= <reply_225> | <reply_226> | <reply_500> | <reply_501> | <reply_502> | <reply_2yz_other_225_226> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502>
<exchange_abor_closing> ::= <Client:abor_command> <Server:abor_reply_closing>
<abor_reply_closing> ::= <reply_421>

# DELE exchanges (RFC 959 4.1.3, 5.4).
<exchange_dele_done> ::= <Client:dele_command> <Server:dele_reply_done>
<dele_reply_done> ::= <reply_250> | <reply_450> | <reply_550> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_2yz_other_250> | <reply_4yz_other_421_450> | <reply_5yz_other_500_501_502_530_550>
<exchange_dele_closing> ::= <Client:dele_command> <Server:dele_reply_closing>
<dele_reply_closing> ::= <reply_421>

# RMD exchanges (RFC 959 4.1.3, 5.4).
<exchange_rmd_done> ::= <Client:rmd_command> <Server:rmd_reply_done>
<rmd_reply_done> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_rmd_closing> ::= <Client:rmd_command> <Server:rmd_reply_closing>
<rmd_reply_closing> ::= <reply_421>

# XRMD exchanges (RFC 1123 4.1.3.1 (experimental RMD)).
<exchange_xrmd_done> ::= <Client:xrmd_command> <Server:xrmd_reply_done>
<xrmd_reply_done> ::= <reply_250> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_250> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_xrmd_closing> ::= <Client:xrmd_command> <Server:xrmd_reply_closing>
<xrmd_reply_closing> ::= <reply_421>

# MKD exchanges (RFC 959 4.1.3, 5.4, Appendix II).
<exchange_mkd_done> ::= <Client:mkd_command> <Server:mkd_reply_done>
<mkd_reply_done> ::= <reply_257_path> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_257> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_mkd_closing> ::= <Client:mkd_command> <Server:mkd_reply_closing>
<mkd_reply_closing> ::= <reply_421>

# XMKD exchanges (RFC 1123 4.1.3.1 (experimental MKD); RFC 959 Appendix II).
<exchange_xmkd_done> ::= <Client:xmkd_command> <Server:xmkd_reply_done>
<xmkd_reply_done> ::= <reply_257_path> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_550> | <reply_2yz_other_257> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_530_550>
<exchange_xmkd_closing> ::= <Client:xmkd_command> <Server:xmkd_reply_closing>
<xmkd_reply_closing> ::= <reply_421>

# PWD exchanges (RFC 959 4.1.3, 5.4, Appendix II).
<exchange_pwd_done> ::= <Client:pwd_command> <Server:pwd_reply_done>
<pwd_reply_done> ::= <reply_257_path> | <reply_500> | <reply_501> | <reply_502> | <reply_550> | <reply_2yz_other_257> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_550>
<exchange_pwd_closing> ::= <Client:pwd_command> <Server:pwd_reply_closing>
<pwd_reply_closing> ::= <reply_421>

# XPWD exchanges (RFC 1123 4.1.3.1 (experimental PWD); RFC 959 Appendix II).
<exchange_xpwd_done> ::= <Client:xpwd_command> <Server:xpwd_reply_done>
<xpwd_reply_done> ::= <reply_257_path> | <reply_500> | <reply_501> | <reply_502> | <reply_550> | <reply_2yz_other_257> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_550>
<exchange_xpwd_closing> ::= <Client:xpwd_command> <Server:xpwd_reply_closing>
<xpwd_reply_closing> ::= <reply_421>

# LIST exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.7; RFC 2228 8.2).
# LIST: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_list_done> ::= <Client:list_command> (
    <Server:list_reply_done>
  | <Server:list_reply_preliminary> <Server:list_reply_completion>
)
<list_reply_done> ::= <reply_450> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_534> | <reply_535> | <reply_4yz_other_421_450> | <reply_5yz_other_500_501_502_530_534_535>
# LIST: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_list_closing> ::= <Client:list_command> (<Server:list_reply_preliminary>)? <Server:list_reply_closing>
<list_reply_closing> ::= <reply_421>
<list_reply_preliminary> ::= <reply_125> | <reply_150> | <reply_1yz_other_110_125_150>
<list_reply_completion> ::= <reply_226> | <reply_250> | <reply_425> | <reply_426> | <reply_451> | <reply_2yz_other_226_250> | <reply_4yz_other_421_425_426_451> | <reply_5yz_other>

# NLST exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.7; RFC 2228 8.2).
# NLST: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_nlst_done> ::= <Client:nlst_command> (
    <Server:nlst_reply_done>
  | <Server:nlst_reply_preliminary> <Server:nlst_reply_completion>
)
<nlst_reply_done> ::= <reply_450> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_534> | <reply_535> | <reply_4yz_other_421_450> | <reply_5yz_other_500_501_502_530_534_535>
# NLST: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_nlst_closing> ::= <Client:nlst_command> (<Server:nlst_reply_preliminary>)? <Server:nlst_reply_closing>
<nlst_reply_closing> ::= <reply_421>
<nlst_reply_preliminary> ::= <reply_125> | <reply_150> | <reply_1yz_other_110_125_150>
<nlst_reply_completion> ::= <reply_226> | <reply_250> | <reply_425> | <reply_426> | <reply_451> | <reply_2yz_other_226_250> | <reply_4yz_other_421_425_426_451> | <reply_5yz_other>

# SITE exchanges (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.8).
<exchange_site_done> ::= <Client:site_command> <Server:site_reply_done>
<site_reply_done> ::= <reply_200> | <reply_202> | <reply_500> | <reply_501> | <reply_530> | <reply_2yz_other_200_202> | <reply_4yz_other_421> | <reply_5yz_other_500_501_530>
<exchange_site_closing> ::= <Client:site_command> <Server:site_reply_closing>
<site_reply_closing> ::= <reply_421>

# SYST exchanges (RFC 959 4.1.3, 5.4).
<exchange_syst_done> ::= <Client:syst_command> <Server:syst_reply_done>
<syst_reply_done> ::= <reply_215> | <reply_500> | <reply_501> | <reply_502> | <reply_2yz_other_215> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502>
<exchange_syst_closing> ::= <Client:syst_command> <Server:syst_reply_closing>
<syst_reply_closing> ::= <reply_421>

# STAT exchanges (RFC 959 4.1.3, 5.4).
<exchange_stat_done> ::= <Client:stat_command> <Server:stat_reply_done>
<stat_reply_done> ::= <reply_211> | <reply_212> | <reply_213> | <reply_450> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_2yz_other_211_212_213> | <reply_4yz_other_421_450> | <reply_5yz_other_500_501_502_530>
<exchange_stat_closing> ::= <Client:stat_command> <Server:stat_reply_closing>
<stat_reply_closing> ::= <reply_421>

# HELP exchanges (RFC 959 4.1.3, 5.4).
<exchange_help_done> ::= <Client:help_command> <Server:help_reply_done>
<help_reply_done> ::= <reply_211> | <reply_214> | <reply_500> | <reply_501> | <reply_502> | <reply_2yz_other_211_214> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502>
<exchange_help_closing> ::= <Client:help_command> <Server:help_reply_closing>
<help_reply_closing> ::= <reply_421>

# NOOP exchanges (RFC 959 4.1.3, 5.4).
<exchange_noop_done> ::= <Client:noop_command> <Server:noop_reply_done>
<noop_reply_done> ::= <reply_200> | <reply_500> | <reply_2yz_other_200> | <reply_4yz_other_421> | <reply_5yz_other_500>
<exchange_noop_closing> ::= <Client:noop_command> <Server:noop_reply_closing>
<noop_reply_closing> ::= <reply_421>

# FEAT exchanges (RFC 2389 3).
<exchange_feat_done> ::= <Client:feat_command> <Server:feat_reply_done>
<feat_reply_done> ::= <reply_211_feat_listing> | <reply_211_feat_none> | <reply_500> | <reply_501> | <reply_502> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502>
<exchange_feat_closing> ::= <Client:feat_command> <Server:feat_reply_closing>
<feat_reply_closing> ::= <reply_421>

# OPTS exchanges (RFC 2389 4; RFC 3659 7.9).
<exchange_opts_done> ::= <Client:opts_command> <Server:opts_reply_done>
<opts_reply_done> ::= <reply_200_opts_mlst> | <reply_451> | <reply_501> | <reply_500> | <reply_502> | <reply_4yz_other_421_451> | <reply_5yz_other_500_501_502>
<exchange_opts_closing> ::= <Client:opts_command> <Server:opts_reply_closing>
<opts_reply_closing> ::= <reply_421>

# EPRT exchanges (RFC 2428 2).
<exchange_eprt_active> ::= <Client:eprt_command> <Server:eprt_reply_active>
<eprt_reply_active> ::= <reply_200> | <reply_2yz_other_200>
<exchange_eprt_done> ::= <Client:eprt_command> <Server:eprt_reply_done>
<eprt_reply_done> ::= <reply_500> | <reply_501> | <reply_522_protocols> | <reply_4yz_other_421> | <reply_5yz_other_500_501_522>
<exchange_eprt_closing> ::= <Client:eprt_command> <Server:eprt_reply_closing>
<eprt_reply_closing> ::= <reply_421>
# EPRT after EPSV ALL MUST be rejected (RFC 2428 3).
<exchange_eprt_refused_epsv_all> ::= <Client:eprt_command> <Server:eprt_reply_refused_epsv_all>
<eprt_reply_refused_epsv_all> ::= <reply_522_protocols> | <reply_500> | <reply_501> | <reply_4yz_other_421> | <reply_5yz_other_500_501_522>

# EPSV exchanges (RFC 2428 3).
<exchange_epsv_passive> ::= <Client:epsv_command> <Server:epsv_reply_passive>
<epsv_reply_passive> ::= <reply_229_epsv>
<exchange_epsv_done> ::= <Client:epsv_command> <Server:epsv_reply_done>
<epsv_reply_done> ::= <reply_500> | <reply_501> | <reply_522_protocols> | <reply_2yz_other_229> | <reply_4yz_other_421> | <reply_5yz_other_500_501_522>
<exchange_epsv_closing> ::= <Client:epsv_command> <Server:epsv_reply_closing>
<epsv_reply_closing> ::= <reply_421>

# EPSV ALL exchanges (RFC 2428 3, 4).
<exchange_epsv_all_all_set> ::= <Client:epsv_all_command> <Server:epsv_all_reply_all_set>
<epsv_all_reply_all_set> ::= <reply_200> | <reply_229_epsv> | <reply_2yz_other_200_229>
<exchange_epsv_all_rejected> ::= <Client:epsv_all_command> <Server:epsv_all_reply_rejected>
<epsv_all_reply_rejected> ::= <reply_500> | <reply_501> | <reply_4yz_other_421> | <reply_5yz_other_500_501>
<exchange_epsv_all_closing> ::= <Client:epsv_all_command> <Server:epsv_all_reply_closing>
<epsv_all_reply_closing> ::= <reply_421>

# LANG exchanges (RFC 2640 4.1, 4.2).
<exchange_lang_done> ::= <Client:lang_command> <Server:lang_reply_done>
<lang_reply_done> ::= <reply_200_lang> | <reply_500> | <reply_501> | <reply_502> | <reply_504> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_504>
<exchange_lang_closing> ::= <Client:lang_command> <Server:lang_reply_closing>
<lang_reply_closing> ::= <reply_421>

# MDTM exchanges (RFC 3659 3).
<exchange_mdtm_done> ::= <Client:mdtm_command> <Server:mdtm_reply_done>
<mdtm_reply_done> ::= <reply_213_mdtm> | <reply_550> | <reply_500> | <reply_501> | <reply_4yz_other_421> | <reply_5yz_other_500_501_550>
<exchange_mdtm_closing> ::= <Client:mdtm_command> <Server:mdtm_reply_closing>
<mdtm_reply_closing> ::= <reply_421>

# SIZE exchanges (RFC 3659 4).
<exchange_size_done> ::= <Client:size_command> <Server:size_reply_done>
<size_reply_done> ::= <reply_213_size> | <reply_550> | <reply_500> | <reply_501> | <reply_4yz_other_421> | <reply_5yz_other_500_501_550>
<exchange_size_closing> ::= <Client:size_command> <Server:size_reply_closing>
<size_reply_closing> ::= <reply_421>

# MLST exchanges (RFC 3659 7).
<exchange_mlst_done> ::= <Client:mlst_command> <Server:mlst_reply_done>
<mlst_reply_done> ::= <reply_250_mlst> | <reply_500> | <reply_501> | <reply_550> | <reply_4yz_other_421> | <reply_5yz_other_500_501_550>
<exchange_mlst_closing> ::= <Client:mlst_command> <Server:mlst_reply_closing>
<mlst_reply_closing> ::= <reply_421>

# MLSD exchanges (RFC 3659 7).
# MLSD: an immediate reply, or a preliminary reply, restart markers and the completion reply (RFC 959 5.4, 6 file transfer diagram).
<exchange_mlsd_done> ::= <Client:mlsd_command> (
    <Server:mlsd_reply_done>
  | <Server:mlsd_reply_preliminary> <Server:mlsd_reply_completion>
)
<mlsd_reply_done> ::= <reply_500> | <reply_501> | <reply_550> | <reply_4yz_other_421> | <reply_5yz_other_500_501_550>
# MLSD: 421 before or after the preliminary reply closes the session (RFC 959 5.4).
<exchange_mlsd_closing> ::= <Client:mlsd_command> (<Server:mlsd_reply_preliminary>)? <Server:mlsd_reply_closing>
<mlsd_reply_closing> ::= <reply_421>
<mlsd_reply_preliminary> ::= <reply_150_mlsd>
<mlsd_reply_completion> ::= <reply_226_mlsd> | <reply_4yz_other_421> | <reply_5yz_other>

# HOST exchanges (RFC 7151 3).
<exchange_host_done> ::= <Client:host_command> <Server:host_reply_done>
<host_reply_done> ::= <reply_220_host> | <reply_500> | <reply_501> | <reply_502> | <reply_503> | <reply_504> | <reply_530> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_503_504_530>
<exchange_host_closing> ::= <Client:host_command> <Server:host_reply_closing>
<host_reply_closing> ::= <reply_421>

# AUTH exchanges (RFC 2228 3, 8.2).
<exchange_auth_secured> ::= <Client:auth_command> <Server:auth_reply_secured>
<auth_reply_secured> ::= <reply_234_security>
<exchange_auth_adat_needed> ::= <Client:auth_command> <Server:auth_reply_adat_needed>
<auth_reply_adat_needed> ::= <reply_334_adat>
<exchange_auth_rejected> ::= <Client:auth_command> <Server:auth_reply_rejected>
<auth_reply_rejected> ::= <reply_502> | <reply_504> | <reply_534> | <reply_431> | <reply_500> | <reply_501> | <reply_533> | <reply_4yz_other_421_431> | <reply_5yz_other_500_501_502_504_533_534>
<exchange_auth_closing> ::= <Client:auth_command> <Server:auth_reply_closing>
<auth_reply_closing> ::= <reply_421>

# ADAT exchanges (RFC 2228 3, 8.2).
<exchange_adat_secured> ::= <Client:adat_command> <Server:adat_reply_secured>
<adat_reply_secured> ::= <reply_235_adat>
<exchange_adat_adat_needed> ::= <Client:adat_command> <Server:adat_reply_adat_needed>
<adat_reply_adat_needed> ::= <reply_335_adat>
<exchange_adat_rejected> ::= <Client:adat_command> <Server:adat_reply_rejected>
<adat_reply_rejected> ::= <reply_503> | <reply_501> | <reply_535> | <reply_500> | <reply_502> | <reply_533> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_503_533_535>
<exchange_adat_closing> ::= <Client:adat_command> <Server:adat_reply_closing>
<adat_reply_closing> ::= <reply_421>

# PBSZ exchanges (RFC 2228 3, 8.2).
<exchange_pbsz_done> ::= <Client:pbsz_command> <Server:pbsz_reply_done>
<pbsz_reply_done> ::= <reply_200> | <reply_503> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_533> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_503_530_533>
<exchange_pbsz_closing> ::= <Client:pbsz_command> <Server:pbsz_reply_closing>
<pbsz_reply_closing> ::= <reply_421>

# PROT exchanges (RFC 2228 3, 8.2).
<exchange_prot_done> ::= <Client:prot_command> <Server:prot_reply_done>
<prot_reply_done> ::= <reply_200> | <reply_504> | <reply_536> | <reply_503> | <reply_534> | <reply_431> | <reply_500> | <reply_501> | <reply_502> | <reply_530> | <reply_533> | <reply_4yz_other_421_431> | <reply_5yz_other_500_501_502_503_504_530_533_534_536>
<exchange_prot_closing> ::= <Client:prot_command> <Server:prot_reply_closing>
<prot_reply_closing> ::= <reply_421>

# CCC exchanges (RFC 2228 3, 8.2).
<exchange_ccc_done> ::= <Client:ccc_command> <Server:ccc_reply_done>
<ccc_reply_done> ::= <reply_200> | <reply_500> | <reply_501> | <reply_502> | <reply_533> | <reply_534> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_533_534>
<exchange_ccc_closing> ::= <Client:ccc_command> <Server:ccc_reply_closing>
<ccc_reply_closing> ::= <reply_421>

# MIC exchanges (RFC 2228 3, 5.2, 8.2).
<exchange_mic_done> ::= <Client:mic_command> <Server:mic_reply_done>
<mic_reply_done> ::= <reply_631_protected> | <reply_632_protected> | <reply_633_protected> | <reply_535> | <reply_533> | <reply_500> | <reply_501> | <reply_502> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_533_535>
<exchange_mic_closing> ::= <Client:mic_command> <Server:mic_reply_closing>
<mic_reply_closing> ::= <reply_421>

# CONF exchanges (RFC 2228 3, 5.2, 8.2).
<exchange_conf_done> ::= <Client:conf_command> <Server:conf_reply_done>
<conf_reply_done> ::= <reply_631_protected> | <reply_632_protected> | <reply_633_protected> | <reply_535> | <reply_533> | <reply_500> | <reply_501> | <reply_502> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_533_535>
<exchange_conf_closing> ::= <Client:conf_command> <Server:conf_reply_closing>
<conf_reply_closing> ::= <reply_421>

# ENC exchanges (RFC 2228 3, 5.2, 8.2).
<exchange_enc_done> ::= <Client:enc_command> <Server:enc_reply_done>
<enc_reply_done> ::= <reply_631_protected> | <reply_632_protected> | <reply_633_protected> | <reply_535> | <reply_533> | <reply_500> | <reply_501> | <reply_502> | <reply_4yz_other_421> | <reply_5yz_other_500_501_502_533_535>
<exchange_enc_closing> ::= <Client:enc_command> <Server:enc_reply_closing>
<enc_reply_closing> ::= <reply_421>

# ==============================================================================
# Commands sent by the user-PI (RFC 959 4.1, 5.3)
# ==============================================================================
# Command codes are case-insensitive (RFC 959 5.3.1; RFC 2389 2.1; RFC 3659 2.1).
<kw_abor> ::= <letter_a> <letter_b> <letter_o> <letter_r>
<kw_acct> ::= <letter_a> <letter_c> <letter_c> <letter_t>
<kw_adat> ::= <letter_a> <letter_d> <letter_a> <letter_t>
<kw_allo> ::= <letter_a> <letter_l> <letter_l> <letter_o>
<kw_appe> ::= <letter_a> <letter_p> <letter_p> <letter_e>
<kw_auth> ::= <letter_a> <letter_u> <letter_t> <letter_h>
<kw_ccc> ::= <letter_c> <letter_c> <letter_c>
<kw_cdup> ::= <letter_c> <letter_d> <letter_u> <letter_p>
<kw_conf> ::= <letter_c> <letter_o> <letter_n> <letter_f>
<kw_cwd> ::= <letter_c> <letter_w> <letter_d>
<kw_dele> ::= <letter_d> <letter_e> <letter_l> <letter_e>
<kw_enc> ::= <letter_e> <letter_n> <letter_c>
<kw_eprt> ::= <letter_e> <letter_p> <letter_r> <letter_t>
<kw_epsv> ::= <letter_e> <letter_p> <letter_s> <letter_v>
<kw_feat> ::= <letter_f> <letter_e> <letter_a> <letter_t>
<kw_help> ::= <letter_h> <letter_e> <letter_l> <letter_p>
<kw_host> ::= <letter_h> <letter_o> <letter_s> <letter_t>
<kw_lang> ::= <letter_l> <letter_a> <letter_n> <letter_g>
<kw_list> ::= <letter_l> <letter_i> <letter_s> <letter_t>
<kw_mdtm> ::= <letter_m> <letter_d> <letter_t> <letter_m>
<kw_mic> ::= <letter_m> <letter_i> <letter_c>
<kw_mkd> ::= <letter_m> <letter_k> <letter_d>
<kw_mlsd> ::= <letter_m> <letter_l> <letter_s> <letter_d>
<kw_mlst> ::= <letter_m> <letter_l> <letter_s> <letter_t>
<kw_mode> ::= <letter_m> <letter_o> <letter_d> <letter_e>
<kw_nlst> ::= <letter_n> <letter_l> <letter_s> <letter_t>
<kw_noop> ::= <letter_n> <letter_o> <letter_o> <letter_p>
<kw_opts> ::= <letter_o> <letter_p> <letter_t> <letter_s>
<kw_pass> ::= <letter_p> <letter_a> <letter_s> <letter_s>
<kw_pasv> ::= <letter_p> <letter_a> <letter_s> <letter_v>
<kw_pbsz> ::= <letter_p> <letter_b> <letter_s> <letter_z>
<kw_port> ::= <letter_p> <letter_o> <letter_r> <letter_t>
<kw_prot> ::= <letter_p> <letter_r> <letter_o> <letter_t>
<kw_pwd> ::= <letter_p> <letter_w> <letter_d>
<kw_quit> ::= <letter_q> <letter_u> <letter_i> <letter_t>
<kw_rein> ::= <letter_r> <letter_e> <letter_i> <letter_n>
<kw_rest> ::= <letter_r> <letter_e> <letter_s> <letter_t>
<kw_retr> ::= <letter_r> <letter_e> <letter_t> <letter_r>
<kw_rmd> ::= <letter_r> <letter_m> <letter_d>
<kw_rnfr> ::= <letter_r> <letter_n> <letter_f> <letter_r>
<kw_rnto> ::= <letter_r> <letter_n> <letter_t> <letter_o>
<kw_site> ::= <letter_s> <letter_i> <letter_t> <letter_e>
<kw_size> ::= <letter_s> <letter_i> <letter_z> <letter_e>
<kw_smnt> ::= <letter_s> <letter_m> <letter_n> <letter_t>
<kw_stat> ::= <letter_s> <letter_t> <letter_a> <letter_t>
<kw_stor> ::= <letter_s> <letter_t> <letter_o> <letter_r>
<kw_stou> ::= <letter_s> <letter_t> <letter_o> <letter_u>
<kw_stru> ::= <letter_s> <letter_t> <letter_r> <letter_u>
<kw_syst> ::= <letter_s> <letter_y> <letter_s> <letter_t>
<kw_type> ::= <letter_t> <letter_y> <letter_p> <letter_e>
<kw_user> ::= <letter_u> <letter_s> <letter_e> <letter_r>
<kw_xcup> ::= <letter_x> <letter_c> <letter_u> <letter_p>
<kw_xcwd> ::= <letter_x> <letter_c> <letter_w> <letter_d>
<kw_xmkd> ::= <letter_x> <letter_m> <letter_k> <letter_d>
<kw_xpwd> ::= <letter_x> <letter_p> <letter_w> <letter_d>
<kw_xrmd> ::= <letter_x> <letter_r> <letter_m> <letter_d>

# USER command (RFC 959 4.1.1, 5.3.2, 5.4; RFC 2228 4, 8.2).
<user_command> ::= <kw_user> <sp> <username> <crlf>

# PASS command (RFC 959 4.1.1, 5.3.2, 5.4).
<pass_command> ::= <kw_pass> <sp> <password> <crlf>

# ACCT command (RFC 959 4.1.1, 5.3.2, 5.4).
<acct_command> ::= <kw_acct> <sp> <account_information> <crlf>

# CWD command (RFC 959 4.1.1, 5.4).
<cwd_command> ::= <kw_cwd> <sp> <pathname> <crlf>

# XCWD command (RFC 1123 4.1.3.1 (experimental CWD)).
<xcwd_command> ::= <kw_xcwd> <sp> <pathname> <crlf>

# CDUP command (RFC 959 4.1.1, 5.4 (errata 4869: 250)).
<cdup_command> ::= <kw_cdup> <crlf>

# XCUP command (RFC 1123 4.1.3.1 (experimental CDUP)).
<xcup_command> ::= <kw_xcup> <crlf>

# SMNT command (RFC 959 4.1.1, 5.4).
<smnt_command> ::= <kw_smnt> <sp> <pathname> <crlf>

# REIN command (RFC 959 4.1.1, 5.4; RFC 7151 3.2.1).
<rein_command> ::= <kw_rein> <crlf>

# QUIT command (RFC 959 4.1.1, 5.4).
<quit_command> ::= <kw_quit> <crlf>

# PORT command (RFC 959 4.1.2, 5.3.2, 5.4).
<port_command> ::= <kw_port> <sp> <host_port> <crlf>

# PASV command (RFC 959 4.1.2, 5.4; RFC 1123 4.1.2.6).
<pasv_command> ::= <kw_pasv> <crlf>

# TYPE command (RFC 959 4.1.2, 5.3.2, 5.4; RFC 1123 4.1.2.1).
<type_command> ::= <kw_type> <sp> <type_code> <crlf>

# STRU command (RFC 959 4.1.2, 5.3.2, 5.4).
<stru_command> ::= <kw_stru> <sp> <structure_code> <crlf>

# MODE command (RFC 959 4.1.2, 5.3.2, 5.4).
<mode_command> ::= <kw_mode> <sp> <mode_code> <crlf>

# RETR command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.3.4; RFC 2228 8.2).
<retr_command> ::= <kw_retr> <sp> <pathname> <crlf>

# STOR command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.3.4; RFC 2228 8.2).
<stor_command> ::= <kw_stor> <sp> <pathname> <crlf>

# STOU command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.9; RFC 2228 8.2).
<stou_command> ::= <kw_stou> <crlf>

# APPE command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.3.4; RFC 2228 8.2).
<appe_command> ::= <kw_appe> <sp> <pathname> <crlf>

# ALLO command (RFC 959 4.1.3, 5.3.2, 5.4).
<allo_command> ::= <kw_allo> <sp> <allo_size> (<sp> <allo_record_flag> <sp> <allo_record_size>)? <crlf>

# REST command (RFC 959 4.1.3, 5.3.2, 5.4; RFC 3659 5).
<rest_command> ::= <kw_rest> <sp> <marker> <crlf>

# RNFR command (RFC 959 4.1.3, 5.4).
<rnfr_command> ::= <kw_rnfr> <sp> <pathname> <crlf>

# RNTO command (RFC 959 4.1.3, 5.4).
<rnto_command> ::= <kw_rnto> <sp> <pathname> <crlf>

# ABOR command (RFC 959 4.1.3, 5.4).
<abor_command> ::= <kw_abor> <crlf>

# DELE command (RFC 959 4.1.3, 5.4).
<dele_command> ::= <kw_dele> <sp> <pathname> <crlf>

# RMD command (RFC 959 4.1.3, 5.4).
<rmd_command> ::= <kw_rmd> <sp> <pathname> <crlf>

# XRMD command (RFC 1123 4.1.3.1 (experimental RMD)).
<xrmd_command> ::= <kw_xrmd> <sp> <pathname> <crlf>

# MKD command (RFC 959 4.1.3, 5.4, Appendix II).
<mkd_command> ::= <kw_mkd> <sp> <pathname> <crlf>

# XMKD command (RFC 1123 4.1.3.1 (experimental MKD); RFC 959 Appendix II).
<xmkd_command> ::= <kw_xmkd> <sp> <pathname> <crlf>

# PWD command (RFC 959 4.1.3, 5.4, Appendix II).
<pwd_command> ::= <kw_pwd> <crlf>

# XPWD command (RFC 1123 4.1.3.1 (experimental PWD); RFC 959 Appendix II).
<xpwd_command> ::= <kw_xpwd> <crlf>

# LIST command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.7; RFC 2228 8.2).
<list_command> ::= <kw_list> (<sp> <pathname>)? <crlf>

# NLST command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.7; RFC 2228 8.2).
<nlst_command> ::= <kw_nlst> (<sp> <pathname>)? <crlf>

# SITE command (RFC 959 4.1.3, 5.4; RFC 1123 4.1.2.8).
<site_command> ::= <kw_site> <sp> <string> <crlf>

# SYST command (RFC 959 4.1.3, 5.4).
<syst_command> ::= <kw_syst> <crlf>

# STAT command (RFC 959 4.1.3, 5.4).
<stat_command> ::= <kw_stat> (<sp> <pathname>)? <crlf>

# HELP command (RFC 959 4.1.3, 5.4).
<help_command> ::= <kw_help> (<sp> <help_topic>)? <crlf>

# NOOP command (RFC 959 4.1.3, 5.4).
<noop_command> ::= <kw_noop> <crlf>

# FEAT command (RFC 2389 3).
<feat_command> ::= <kw_feat> <crlf>

# OPTS command (RFC 2389 4; RFC 3659 7.9).
<opts_command> ::= <kw_opts> <sp> <opts_mlst_argument> <crlf>

# EPRT command (RFC 2428 2).
<eprt_command> ::= <kw_eprt> <sp> <eprt_argument> <crlf>

# EPSV command (RFC 2428 3).
<epsv_command> ::= <kw_epsv> (<sp> <net_prt>)? <crlf>

# EPSV ALL command (RFC 2428 3, 4).
<epsv_all_command> ::= <kw_epsv> <sp> <epsv_all_flag> <crlf>

# LANG command (RFC 2640 4.1, 4.2).
<lang_command> ::= <kw_lang> (<sp> <lang_tag>)? <crlf>

# MDTM command (RFC 3659 3).
<mdtm_command> ::= <kw_mdtm> <sp> <pathname> <crlf>

# SIZE command (RFC 3659 4).
<size_command> ::= <kw_size> <sp> <pathname> <crlf>

# MLST command (RFC 3659 7).
<mlst_command> ::= <kw_mlst> (<sp> <pathname>)? <crlf>

# MLSD command (RFC 3659 7).
<mlsd_command> ::= <kw_mlsd> (<sp> <pathname>)? <crlf>

# HOST command (RFC 7151 3).
<host_command> ::= <kw_host> <sp> <hostname> <crlf>

# AUTH command (RFC 2228 3, 8.2).
<auth_command> ::= <kw_auth> <sp> <mechanism_name> <crlf>

# ADAT command (RFC 2228 3, 8.2).
<adat_command> ::= <kw_adat> <sp> <base64data> <crlf>

# PBSZ command (RFC 2228 3, 8.2).
<pbsz_command> ::= <kw_pbsz> <sp> <pbsz_size> <crlf>

# PROT command (RFC 2228 3, 8.2).
<prot_command> ::= <kw_prot> <sp> <prot_code> <crlf>

# CCC command (RFC 2228 3, 8.2).
<ccc_command> ::= <kw_ccc> <crlf>

# MIC command (RFC 2228 3, 5.2, 8.2).
<mic_command> ::= <kw_mic> <sp> <base64data> <crlf>

# CONF command (RFC 2228 3, 5.2, 8.2).
<conf_command> ::= <kw_conf> <sp> <base64data> <crlf>

# ENC command (RFC 2228 3, 5.2, 8.2).
<enc_command> ::= <kw_enc> <sp> <base64data> <crlf>

# ==============================================================================
# Command arguments (RFC 959 5.3.2 and the updating RFCs)
# ==============================================================================

# <username>, <password>, <account-information> ::= <string> (RFC 959 5.3.2);
# the configured test account is a target resource.
<username> ::= <username_target> | <string>
<username_target> ::= <string> := os.environ.get('FTP_USER', 'anonymous')
<password> ::= <password_target> | <string>
<password_target> ::= <string> := os.environ.get('FTP_PASS', 'guest')
<account_information> ::= <account_target> | <string>
<account_target> ::= <string> := os.environ.get('FTP_ACCT', 'account')

# <string> ::= <char> | <char><string>; <char> is any ASCII character but CR and
# LF (RFC 959 5.3.2).
<string> ::= <string_char>+
<string_char> ::= r'[\x00-\x09\x0b\x0c\x0e-\x7f]'

# <pathname> (RFC 959 5.3.2; RFC 2640 3.1: pathname = 1*(%x01..%xFF), UTF-8,
# only one SP before it, CR sent as CR NUL).  Existing file, existing directory
# and a fresh name are target resources.
<pathname> ::= <path_target_file> | <path_target_dir> | <path_target_new> | <path_string>
<path_target_file> ::= <path_char>+ := os.environ.get('FTP_FILE', 'readme.txt')
<path_target_dir> ::= <path_char>+ := os.environ.get('FTP_DIR', 'pub')
<path_target_new> ::= <path_char>+ := os.environ.get('FTP_NEW', 'new.txt')
<path_string> ::= <path_char>+
# RFC 2640 3.1: any octet 0x01..0xFF (UTF-8) but CR and LF.
# TODO: RFC 2640 3.1 - <CR><NUL> and bare <LF> inside <path_string> are not sent.
<path_char> ::= r'[^\x00\r\n]'

# HELP [<SP> <string>] (RFC 959 4.1.3): a command name or free text.
<help_topic> ::= <help_command_name> | <string>
<help_command_name> ::= <kw_abor> | <kw_acct> | <kw_adat> | <kw_allo> | <kw_appe> | <kw_auth> | <kw_ccc> | <kw_cdup> | <kw_conf> | <kw_cwd> | <kw_dele> | <kw_enc> | <kw_eprt> | <kw_epsv> | <kw_feat> | <kw_help> | <kw_host> | <kw_lang> | <kw_list> | <kw_mdtm> | <kw_mic> | <kw_mkd> | <kw_mlsd> | <kw_mlst> | <kw_mode> | <kw_nlst> | <kw_noop> | <kw_opts> | <kw_pass> | <kw_pasv> | <kw_pbsz> | <kw_port> | <kw_prot> | <kw_pwd> | <kw_quit> | <kw_rein> | <kw_rest> | <kw_retr> | <kw_rmd> | <kw_rnfr> | <kw_rnto> | <kw_site> | <kw_size> | <kw_smnt> | <kw_stat> | <kw_stor> | <kw_stou> | <kw_stru> | <kw_syst> | <kw_type> | <kw_user> | <kw_xcup> | <kw_xcwd> | <kw_xmkd> | <kw_xpwd> | <kw_xrmd>

# <host-port> ::= <host-number>,<port-number> (RFC 959 5.3.2); the data port the
# client listens on is a target resource.
<host_port> ::= <host_port_target> | <host_number> ',' <port_number>
<host_port_target> ::= <host_number> ',' <port_number> := (
    os.environ.get('FTP_DATA_HOST', '127,0,0,1') + ','
    + os.environ.get('FTP_DATA_PORT', '7,209'))
<host_number> ::= <byte_number> ',' <byte_number> ',' <byte_number> ',' <byte_number>
<port_number> ::= <byte_number> ',' <byte_number>
# <number> ::= any decimal integer 0 through 255 (RFC 959 5.3.2, errata 3039).
<byte_number> ::= (
    <digit>
  | <nonzero_digit> <digit>
  | '1' <digit> <digit>
  | '2' <digit_0_to_4> <digit>
  | '25' <digit_0_to_5>
)
<nonzero_digit> ::= r'[1-9]'
<digit_0_to_4> ::= r'[0-4]'
<digit_0_to_5> ::= r'[0-5]'

# <type-code> ::= A [<sp> <form-code>] | E [<sp> <form-code>] | I | L <sp> <byte-size>
# (RFC 959 3.1.1, 5.3.2; RFC 1123 4.1.2.1 TYPE L 8).
<type_code> ::= (
    <type_ascii> (<sp> <form_code>)?
  | <type_ebcdic> (<sp> <form_code>)?
  | <type_image>
  | <type_local> <sp> <byte_size>
)
<type_ascii> ::= 'A'
<type_ebcdic> ::= 'E'
<type_image> ::= 'I'
<type_local> ::= 'L'
<byte_size> ::= <byte_number>
# <form-code> ::= N | T | C (RFC 959 3.1.1.5, 5.3.2).
<form_code> ::= <form_non_print> | <form_telnet> | <form_carriage_control>
<form_non_print> ::= 'N'
<form_telnet> ::= 'T'
<form_carriage_control> ::= 'C'
# <structure-code> ::= F | R | P (RFC 959 3.1.2, 5.3.2).
<structure_code> ::= <structure_file> | <structure_record> | <structure_page>
<structure_file> ::= 'F'
<structure_record> ::= 'R'
<structure_page> ::= 'P'
# <mode-code> ::= S | B | C (RFC 959 3.4, 5.3.2).
<mode_code> ::= <mode_stream> | <mode_block> | <mode_compressed>
<mode_stream> ::= 'S'
<mode_block> ::= 'B'
<mode_compressed> ::= 'C'

# ALLO <SP> <decimal-integer> [<SP> R <SP> <decimal-integer>] (RFC 959 4.1.3, 5.3.2).
<allo_size> ::= <decimal_integer>
<allo_record_flag> ::= 'R'
<allo_record_size> ::= <decimal_integer>
<decimal_integer> ::= <digit>+

# REST <SP> <marker>, <marker> ::= <pr-string> (RFC 959 5.3.2); in STREAM mode the
# marker is an octet count, 1*DIGIT (RFC 3659 5.3).
<marker> ::= <marker_stream_offset> | <marker_printable>
<marker_stream_offset> ::= <digit>+
<marker_printable> ::= <pr_char>+
# <pr-char> ::= printable characters, any ASCII code 33 through 126 (RFC 959 5.3.2).
<pr_char> ::= r'[!-~]'

# OPTS MLST [SP 1*(factname ";")] (RFC 2389 4; RFC 3659 7.9).
<opts_mlst_argument> ::= <kw_mlst> (<sp> <mlst_fact_request>+)?
<mlst_fact_request> ::= <factname> ';'

# EPRT <SP> <d><net-prt><d><net-addr><d><tcp-port><d> (RFC 2428 2).  The four
# delimiters are equal and do not occur in the address.
<eprt_argument> ::= <eprt_target> | <eprt_ipv4> | <eprt_ipv6> | <eprt_other_family>
<eprt_target> ::= <eprt_ipv4> := (
    '|1|' + os.environ.get('FTP_DATA_ADDR', '127.0.0.1') + '|'
    + os.environ.get('FTP_DATA_TCP_PORT', '2001') + '|')
<eprt_ipv4> ::= <eprt_d1> <net_prt_ipv4> <eprt_d2> <ipv4_address> <eprt_d3> <tcp_port> <eprt_d4>
<eprt_ipv6> ::= <eprt_d1> <net_prt_ipv6> <eprt_d2> <ipv6_address> <eprt_d3> <tcp_port> <eprt_d4>
<eprt_other_family> ::= <eprt_d1> <net_prt_other> <eprt_d2> <eprt_other_address> <eprt_d3> <tcp_port> <eprt_d4>
# The same delimiter four times, not occurring in the address (RFC 2428 2).
where forall <a> in <eprt_ipv4>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d2>)
where forall <a> in <eprt_ipv4>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d3>)
where forall <a> in <eprt_ipv4>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d4>)
where forall <a> in <eprt_ipv4>: str(<a>.<eprt_d1>) not in str(<a>.<ipv4_address>)
where forall <a> in <eprt_ipv6>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d2>)
where forall <a> in <eprt_ipv6>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d3>)
where forall <a> in <eprt_ipv6>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d4>)
where forall <a> in <eprt_ipv6>: str(<a>.<eprt_d1>) not in str(<a>.<ipv6_address>)
where forall <a> in <eprt_other_family>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d2>)
where forall <a> in <eprt_other_family>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d3>)
where forall <a> in <eprt_other_family>: str(<a>.<eprt_d1>) == str(<a>.<eprt_d4>)
where forall <a> in <eprt_other_family>: str(<a>.<eprt_d1>) not in str(<a>.<eprt_other_address>)
<eprt_d1> ::= <eprt_delimiter>
<eprt_d2> ::= <eprt_delimiter>
<eprt_d3> ::= <eprt_delimiter>
<eprt_d4> ::= <eprt_delimiter>
# The delimiter MUST be one of the ASCII characters in range 33-126 (RFC 2428 2).
<eprt_delimiter> ::= r'[!-~]'
<eprt_other_address> ::= <pr_char>+
# <net-prt>: an IANA address family number; 1 is IPv4, 2 is IPv6 (RFC 2428 2).
<net_prt> ::= <net_prt_ipv4> | <net_prt_ipv6> | <net_prt_other>
<net_prt_ipv4> ::= '1'
<net_prt_ipv6> ::= '2'
<net_prt_other> ::= <nonzero_digit> <digit>+ | r'[3-9]'
# dotted decimal (RFC 2428 2).
<ipv4_address> ::= <byte_number> '.' <byte_number> '.' <byte_number> '.' <byte_number>
# IPv6 string representations (RFC 2428 2): eight groups, or '::' compression.
<ipv6_address> ::= <ipv6_full> | <ipv6_compressed>
<ipv6_full> ::= <h16> (':' <h16>){7}
<ipv6_compressed> ::= (<h16> (':' <h16>){0,6})? '::' (<h16> (':' <h16>){0,6})?
<h16> ::= <hex_digit>{1,4}
<hex_digit> ::= r'[0-9A-Fa-f]'
# <tcp-port>: decimal TCP port number (RFC 2428 2).
<tcp_port> ::= <digit>{1,5}
where int(<tcp_port>) <= 65535
# EPSV<space>ALL (RFC 2428 3).
<epsv_all_flag> ::= 'ALL'

# lang-tag = Primary-tag *( "-" Sub-tag ), 1*8ALPHA each (RFC 2640 4.2).
<lang_tag> ::= <lang_subtag> ('-' <lang_subtag>)*
<lang_subtag> ::= <alpha>{1,8}

# hostname = domain / IP-literal (RFC 7151 3.1); the virtual host is a target.
<hostname> ::= <hostname_target> | <domain> | <ip_literal>
<hostname_target> ::= <domain> := os.environ.get('FTP_HOST', 'localhost')
<domain> ::= <sub_domain> ('.' <sub_domain>)*
<sub_domain> ::= <let_dig> | <let_dig> <ldh_char>* <let_dig>
<let_dig> ::= r'[A-Za-z0-9]'
<ldh_char> ::= r'[A-Za-z0-9-]'
<ip_literal> ::= '[' <ipv6_address> ']' | <ipv4_address>

# <mechanism-name> ::= <string>; <base64data> (RFC 2228 8.1, 9).
<mechanism_name> ::= <string>
<base64data> ::= <base64_quad>+ | <base64_quad>* <base64_final>
<base64_quad> ::= <base64_char>{4}
<base64_final> ::= <base64_char>{2} '==' | <base64_char>{3} '='
<base64_char> ::= r'[A-Za-z0-9+/]'
# PBSZ <decimal-integer>, 1 to (2^32)-1 (RFC 2228 8.1).
<pbsz_size> ::= <nonzero_digit> <digit>{0,9}
# <prot-code> ::= C | S | E | P (RFC 2228 8.1).
<prot_code> ::= <prot_clear> | <prot_safe> | <prot_confidential> | <prot_private>
<prot_clear> ::= 'C'
<prot_safe> ::= 'S'
<prot_confidential> ::= 'E'
<prot_private> ::= 'P'

# PWD, then CWD back to the directory the 257 reply reported: the returned
# name is usable as the argument of a later command (RFC 959 Appendix II).
<exchange_cwd_reported> ::= (
    <Client:pwd_command> <Server:pwd_reply_reported>
    <Client:cwd_reported_command> <Server:cwd_reply_done>
)
<pwd_reply_reported> ::= <reply_257_reported>
# The CWD argument equals the reported name with doubled quotes undone (RFC 959
# Appendix II); recall_reported_path() yields it, record_reported_path() keeps it.
where forall <e> in <exchange_cwd_reported>: str(<e>..<recalled_path>) == str(<e>..<reported_path>).replace('""', '"')
<cwd_reported_command> ::= <kw_cwd> <sp> <recalled_path> <crlf>
<recalled_path> ::= <path_char>+ := recall_reported_path()

# ==============================================================================
# Replies sent by the server-PI (RFC 959 4.2)
# ==============================================================================

# A reply is a code, SP and one line of text; a multi-line reply starts with the
# code and '-', ends with the same code and SP (RFC 959 4.2).  Intermediary
# lines never begin with three digits: "If an intermediary line begins with a
# 3-digit number, the Server must pad the front to avoid confusion." (RFC 959 4.2)
<reply_text_line> ::= (
    <crlf>
  | <reply_line_nondigit> <reply_text> <crlf>
  | <digit> <crlf>
  | <digit> <reply_line_nondigit> <reply_text> <crlf>
  | <digit> <digit> <crlf>
  | <digit> <digit> <reply_line_nondigit> <reply_text> <crlf>
)
<reply_line_nondigit> ::= r'[^0-9\r\n]'
# Reply text: any characters but CR and LF (RFC 959 4.2; UTF-8 per RFC 2640 3).
<reply_text> ::= <reply_text_char>*
<reply_text_char> ::= r'[^\r\n]'
<hyphen> ::= '-'

# 110 MARK ssss = rrrr (RFC 1123 4.1.3.4, correcting RFC 959 4.2.1).
<reply_110_mark> ::= <code_110> <sp> 'MARK' <sp> <mark_sender> ' = ' <mark_receiver> <crlf>
<mark_sender> ::= <pr_char>+
<mark_receiver> ::= <pr_char>+

# 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2) (RFC 959 4.1.2, 4.2.1); the format
# is not well standardized, the client scans for the first digit (RFC 1123 4.1.2.6).
<reply_227_pasv> ::= <code_227> <sp> <pasv_prefix_char>* <host_number> ',' <port_number> <pasv_suffix>
<pasv_prefix_char> ::= r'[^0-9\r\n]'
<pasv_suffix> ::= <crlf> | <pasv_prefix_char> <reply_text> <crlf>

# 229 <text> (<d><d><d><tcp-port><d>) (RFC 2428 3): the text before the
# parenthesis, three equal delimiters, the port and a fourth delimiter.
<reply_229_epsv> ::= <code_229> <sp> <epsv_text_char>* '(' <epsv_d1> <epsv_d2> <epsv_d3> <tcp_port> <epsv_d4> ')' <crlf>
<epsv_text_char> ::= r'[^(\r\n]'
# The same delimiter in all four positions (RFC 2428 3: the string needed by EPRT).
where forall <r> in <reply_229_epsv>: str(<r>.<epsv_d1>) == str(<r>.<epsv_d2>)
where forall <r> in <reply_229_epsv>: str(<r>.<epsv_d1>) == str(<r>.<epsv_d3>)
where forall <r> in <reply_229_epsv>: str(<r>.<epsv_d1>) == str(<r>.<epsv_d4>)
<epsv_d1> ::= <eprt_delimiter>
<epsv_d2> ::= <eprt_delimiter>
<epsv_d3> ::= <eprt_delimiter>
<epsv_d4> ::= <eprt_delimiter>

# 522 <text without parentheses> (prot1,prot2,...,protn) (RFC 2428 2).
<reply_522_protocols> ::= <code_522> <sp> <protocol_text_char>* '(' <net_prt> (',' <net_prt>)* ')' <crlf>
<protocol_text_char> ::= r'[^()\r\n]'

# 257 "PATHNAME" commentary, embedded quotes doubled (RFC 959 Appendix II).
<reply_257_path> ::= (
    <code_257> <sp> <quoted_pathname> (<sp> <reply_text>)? <crlf>
  | <code_257> <hyphen> <quoted_pathname> (<sp> <reply_text>)? <crlf> <reply_text_line>* <code_257> <sp> <reply_text> <crlf>
)
<quoted_pathname> ::= '"' <quoted_path_char>* '"'
# 257 reply whose directory name is recorded for the echoing CWD (RFC 959 Appendix II).
<reply_257_reported> ::= (
    <code_257> <sp> '"' <reported_path> '"' (<sp> <reply_text>)? <crlf>
  | <code_257> <hyphen> '"' <reported_path> '"' (<sp> <reply_text>)? <crlf> <reply_text_line>* <code_257> <sp> <reply_text> <crlf>
)
<reported_path> ::= <quoted_path_char>+ := record_reported_path(str(<reported_path_param>))
<reported_path_param> ::= <quoted_path_char>+ := record_reported_path(str(<reported_path>))
<quoted_path_char> ::= <quoted_path_plain> | <quoted_path_quote>
<quoted_path_plain> ::= r'[^"\r\n]'
<quoted_path_quote> ::= '""'

# FEAT replies (RFC 2389 3.2): "211" SP *TCHAR CRLF, or
# "211-" *TCHAR CRLF 1*( SP feature CRLF ) "211 End" CRLF.
<reply_211_feat_none> ::= <code_211> <sp> <tchar>* <crlf>
<reply_211_feat_listing> ::= <code_211> <hyphen> <tchar>* <crlf> <feature_line>+ <code_211> <sp> <feat_end> <crlf>
<feat_end> ::= <letter_e> <letter_n> <letter_d>
# One line per feature; unknown features are allowed (RFC 2389 3.2).
<feature_line> ::= <sp> <feature> <crlf>
<feature> ::= (
    <feature_mdtm> | <feature_size> | <feature_rest_stream> | <feature_tvfs>
  | <feature_mlst> | <feature_lang> | <feature_utf8> | <feature_host> | <feature_other>
)
# MDTM, SIZE, REST STREAM, TVFS feature lines (RFC 3659 3.4, 4.4, 5.4, 6.2).
<feature_mdtm> ::= <kw_mdtm>
<feature_size> ::= <kw_size>
<feature_rest_stream> ::= <kw_rest> <sp> <letter_s> <letter_t> <letter_r> <letter_e> <letter_a> <letter_m>
<feature_tvfs> ::= <letter_t> <letter_v> <letter_f> <letter_s>
# mlst-feat = SP "MLST" [SP factlist]; factlist = 1*( factname ["*"] ";" ) (RFC 3659 7.8).
<feature_mlst> ::= <kw_mlst> (<sp> <mlst_feat_fact>+)?
<mlst_feat_fact> ::= <factname> <mlst_default_mark>? ';'
<mlst_default_mark> ::= '*'
# Lang-feat = SP "LANG" SP lang-fact; lang-fact = lang-tag ["*"] *(";" lang-tag ["*"]) (RFC 2640 4.3).
<feature_lang> ::= <kw_lang> <sp> <lang_tag> <lang_current_mark>? (';' <lang_tag> <lang_current_mark>?)*
<lang_current_mark> ::= '*'
# UTF8 feature (RFC 2640 3.3).
<feature_utf8> ::= <letter_u> <letter_t> <letter_f> '8'
# HOST feature (RFC 7151 3.4).
<feature_host> ::= <kw_host>
# feature = feature-label [ SP feature-parms ] (RFC 2389 3.2).
<feature_other> ::= <vchar>+ (<sp> <tchar>+)?

# OPTS MLST response "200 MLST OPTS" [ SP 1*( factname ";" ) ] (RFC 3659 7.9.1).
<reply_200_opts_mlst> ::= <code_200> <sp> <kw_mlst> <sp> <kw_opts> (<sp> <mlst_fact_request>+)? <crlf>

# lang-ok = "200" [SP *(%x00..%xFF) ] CRLF (RFC 2640 4.2).
<reply_200_lang> ::= (
    <code_200> (<sp> <reply_text>)? <crlf>
  | <code_200> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_200> <sp> <reply_text> <crlf>
)

# host-ok = "220" [ SP *TCHAR ] CRLF (RFC 7151 3.1).
<reply_220_host> ::= (
    <code_220> (<sp> <tchar>*)? <crlf>
  | <code_220> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_220> <sp> <reply_text> <crlf>
)
# REIN answers 220 like the greeting (RFC 959 5.4).
<reply_rein_ready> ::= <reply_220>

# mdtm-response = "213" SP time-val CRLF, no multi-line (RFC 3659 3.1).
<reply_213_mdtm> ::= <code_213> <sp> <time_val> <crlf>
# time-val = 14DIGIT [ "." 1*DIGIT ] (RFC 3659 2.3).
<time_val> ::= <time_year> <time_month> <time_day> <time_hour> <time_minute> <time_second> ('.' <time_fraction>)?
<time_year> ::= <digit>{4}
<time_month> ::= <digit>{2}
<time_day> ::= <digit>{2}
<time_hour> ::= <digit>{2}
<time_minute> ::= <digit>{2}
<time_second> ::= <digit>{2}
<time_fraction> ::= <digit>+
# Ranges of the time-val fields (RFC 3659 2.3).
where int(<time_year>) >= 1000
where int(<time_month>) >= 1
where int(<time_month>) <= 12
where int(<time_day>) >= 1
where int(<time_day>) <= 31
where int(<time_hour>) <= 23
where int(<time_minute>) <= 59
where int(<time_second>) <= 60

# size-response = "213" SP 1*DIGIT CRLF, no multi-line (RFC 3659 4.1).
<reply_213_size> ::= <code_213> <sp> <digit>+ <crlf>

# MLST control-response (RFC 3659 7.2): "250-" [ response-message ] CRLF
# 1*( SP entry CRLF ) "250" [ SP response-message ] CRLF.
<reply_250_mlst> ::= <code_250> <hyphen> <tchar>* <crlf> <mlst_entry_line>+ <code_250> (<sp> <tchar>*)? <crlf>
<mlst_entry_line> ::= <sp> <mlst_entry> <crlf>
# entry = [ facts ] SP pathname; facts = 1*( fact ";" ) (RFC 3659 7.2).
<mlst_entry> ::= <mlst_fact_item>* <sp> <mlst_pathname>
<mlst_fact_item> ::= <mlst_fact> ';'
<mlst_pathname> ::= <path_char>+
# Facts in any order; unknown facts last (RFC 3659 7.2, 7.5).
<mlst_fact> ::= (
    <fact_size> | <fact_modify> | <fact_create> | <fact_type> | <fact_unique>
  | <fact_perm> | <fact_lang> | <fact_media_type> | <fact_charset> | <fact_other>
)
# size-fact = "Size" "=" 1*DIGIT (RFC 3659 7.5.7).
<fact_size> ::= <factname_size> '=' <digit>+
# modify-fact, create-fact = time-val (RFC 3659 7.5.3, 7.5.4).
<fact_modify> ::= <factname_modify> '=' <time_val>
<fact_create> ::= <factname_create> '=' <time_val>
# type-fact = "Type" "=" type-val (RFC 3659 7.5.1).
<fact_type> ::= <factname_type> '=' <type_val>
<type_val> ::= <type_val_file> | <type_val_cdir> | <type_val_pdir> | <type_val_dir> | <type_val_os>
<type_val_file> ::= <letter_f> <letter_i> <letter_l> <letter_e>
<type_val_cdir> ::= <letter_c> <letter_d> <letter_i> <letter_r>
<type_val_pdir> ::= <letter_p> <letter_d> <letter_i> <letter_r>
<type_val_dir> ::= <letter_d> <letter_i> <letter_r>
# os-type = "OS." os-name "=" os-kind (RFC 3659 7.5.1.5).
<type_val_os> ::= <letter_o> <letter_s> '.' <token> '=' <token>
# unique-fact = "Unique" "=" token (RFC 3659 7.5.2).
<fact_unique> ::= <factname_unique> '=' <token>
# perm-fact = "Perm" "=" *pvals (RFC 3659 7.5.5).
<fact_perm> ::= <factname_perm> '=' <perm_value>*
<perm_value> ::= <perm_append> | <perm_create> | <perm_delete> | <perm_enter> | <perm_rename> | <perm_list> | <perm_mkdir> | <perm_purge> | <perm_read> | <perm_write>
<perm_append> ::= 'a'
<perm_create> ::= 'c'
<perm_delete> ::= 'd'
<perm_enter> ::= 'e'
<perm_rename> ::= 'f'
<perm_list> ::= 'l'
<perm_mkdir> ::= 'm'
<perm_purge> ::= 'p'
<perm_read> ::= 'r'
<perm_write> ::= 'w'
# lang-fact = "Lang" "=" token (RFC 3659 7.5.6).
<fact_lang> ::= <factname_lang> '=' <token>
# Media-Type fact (RFC 3659 7.5.8).
<fact_media_type> ::= <factname_media_type> '=' <token> '/' <token>
# charset-type = "Charset" "=" token (RFC 3659 7.5.9).
<fact_charset> ::= <factname_charset> '=' <token>
# os-depend-fact / local-fact / other: factname "=" value, value = *SCHAR (RFC 3659 7.2).
<fact_other> ::= <factname_other> '=' <schar>*
<factname> ::= (
    <factname_size> | <factname_modify> | <factname_create> | <factname_type>
  | <factname_unique> | <factname_perm> | <factname_lang> | <factname_media_type>
  | <factname_charset> | <factname_os_depend> | <factname_local>
)
<factname_size> ::= <letter_s> <letter_i> <letter_z> <letter_e>
<factname_modify> ::= <letter_m> <letter_o> <letter_d> <letter_i> <letter_f> <letter_y>
<factname_create> ::= <letter_c> <letter_r> <letter_e> <letter_a> <letter_t> <letter_e>
<factname_type> ::= <letter_t> <letter_y> <letter_p> <letter_e>
<factname_unique> ::= <letter_u> <letter_n> <letter_i> <letter_q> <letter_u> <letter_e>
<factname_perm> ::= <letter_p> <letter_e> <letter_r> <letter_m>
<factname_lang> ::= <letter_l> <letter_a> <letter_n> <letter_g>
<factname_media_type> ::= <letter_m> <letter_e> <letter_d> <letter_i> <letter_a> '-' <letter_t> <letter_y> <letter_p> <letter_e>
<factname_charset> ::= <letter_c> <letter_h> <letter_a> <letter_r> <letter_s> <letter_e> <letter_t>
# os-depend-fact = <IANA assigned OS name> "." token (RFC 3659 7.2).
<factname_os_depend> ::= <alpha>+ '.' <token>
# local-fact = "X." token (RFC 3659 7.2).
<factname_local> ::= <letter_x> '.' <token>
<factname_other> ::= <rchar>+
# token = 1*RCHAR (RFC 3659 2.1).
<token> ::= <rchar>+

# MLSD: initial-response "150" [ SP response-message ] CRLF, final-response
# "226" SP response-message CRLF (RFC 3659 7.2).
<reply_150_mlsd> ::= (
    <code_150> (<sp> <tchar>*)? <crlf>
  | <code_150> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_150> <sp> <reply_text> <crlf>
)
<reply_226_mlsd> ::= (
    <code_226> <sp> <tchar>* <crlf>
  | <code_226> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_226> <sp> <reply_text> <crlf>
)

# STOU: "125 FILE: pppp" / "150 FILE: pppp" (RFC 1123 4.1.2.9).
<reply_125_stou> ::= <code_125> <sp> 'FILE: ' <stou_pathname> <crlf>
<reply_150_stou> ::= <code_150> <sp> 'FILE: ' <stou_pathname> <crlf>
<stou_pathname> ::= <path_char>+

# Security replies (RFC 2228 5.1): 234; 235/334/335 [ADAT=base64data].
<reply_234_security> ::= <reply_234>
<reply_334_adat> ::= <code_334> <sp> <adat_reply_data> <crlf> | <reply_334>
<reply_235_adat> ::= <code_235> <sp> <adat_reply_data> <crlf> | <reply_235>
<reply_335_adat> ::= <code_335> <sp> <adat_reply_data> <crlf> | <reply_335>
<adat_reply_data> ::= 'ADAT=' <base64data>
# Protected replies 631/632/633: base64 text; each line before the last is the
# code, '-' and a base64 fragment (RFC 2228 5.2).
<reply_631_protected> ::= (<code_631> <hyphen> <base64data> <crlf>)* <code_631> <sp> <base64data> <crlf>
<reply_632_protected> ::= (<code_632> <hyphen> <base64data> <crlf>)* <code_632> <sp> <base64data> <crlf>
<reply_633_protected> ::= (<code_633> <hyphen> <base64data> <crlf>)* <code_633> <sp> <base64data> <crlf>

<code_110> ::= '110'
<code_120> ::= '120'
<code_125> ::= '125'
<code_150> ::= '150'
<code_200> ::= '200'
<code_202> ::= '202'
<code_211> ::= '211'
<code_212> ::= '212'
<code_213> ::= '213'
<code_214> ::= '214'
<code_215> ::= '215'
<code_220> ::= '220'
<code_221> ::= '221'
<code_225> ::= '225'
<code_226> ::= '226'
<code_227> ::= '227'
<code_229> ::= '229'
<code_230> ::= '230'
<code_232> ::= '232'
<code_234> ::= '234'
<code_235> ::= '235'
<code_250> ::= '250'
<code_257> ::= '257'
<code_331> ::= '331'
<code_332> ::= '332'
<code_334> ::= '334'
<code_335> ::= '335'
<code_336> ::= '336'
<code_350> ::= '350'
<code_421> ::= '421'
<code_425> ::= '425'
<code_426> ::= '426'
<code_431> ::= '431'
<code_450> ::= '450'
<code_451> ::= '451'
<code_452> ::= '452'
<code_500> ::= '500'
<code_501> ::= '501'
<code_502> ::= '502'
<code_503> ::= '503'
<code_504> ::= '504'
<code_522> ::= '522'
<code_530> ::= '530'
<code_532> ::= '532'
<code_533> ::= '533'
<code_534> ::= '534'
<code_535> ::= '535'
<code_536> ::= '536'
<code_550> ::= '550'
<code_551> ::= '551'
<code_552> ::= '552'
<code_553> ::= '553'
<code_554> ::= '554'
<code_555> ::= '555'
<code_631> ::= '631'
<code_632> ::= '632'
<code_633> ::= '633'

# Replies with free text, one rule per code (RFC 959 4.2, 4.2.1).
# 120: Service ready in nnn minutes (RFC 959 4.2.1).
<reply_120> ::= (
    <code_120> <sp> <reply_text> <crlf>
  | <code_120> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_120> <sp> <reply_text> <crlf>
)
# 125: Data connection already open; transfer starting (RFC 959 4.2.1).
<reply_125> ::= (
    <code_125> <sp> <reply_text> <crlf>
  | <code_125> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_125> <sp> <reply_text> <crlf>
)
# 150: File status okay; about to open data connection (RFC 959 4.2.1).
<reply_150> ::= (
    <code_150> <sp> <reply_text> <crlf>
  | <code_150> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_150> <sp> <reply_text> <crlf>
)
# 200: Command okay (RFC 959 4.2.1).
<reply_200> ::= (
    <code_200> <sp> <reply_text> <crlf>
  | <code_200> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_200> <sp> <reply_text> <crlf>
)
# 202: Command not implemented, superfluous at this site (RFC 959 4.2.1).
<reply_202> ::= (
    <code_202> <sp> <reply_text> <crlf>
  | <code_202> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_202> <sp> <reply_text> <crlf>
)
# 211: System status, or system help reply (RFC 959 4.2.1).
<reply_211> ::= (
    <code_211> <sp> <reply_text> <crlf>
  | <code_211> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_211> <sp> <reply_text> <crlf>
)
# 212: Directory status (RFC 959 4.2.1).
<reply_212> ::= (
    <code_212> <sp> <reply_text> <crlf>
  | <code_212> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_212> <sp> <reply_text> <crlf>
)
# 213: File status (RFC 959 4.2.1).
<reply_213> ::= (
    <code_213> <sp> <reply_text> <crlf>
  | <code_213> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_213> <sp> <reply_text> <crlf>
)
# 214: Help message (RFC 959 4.2.1).
<reply_214> ::= (
    <code_214> <sp> <reply_text> <crlf>
  | <code_214> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_214> <sp> <reply_text> <crlf>
)
# 215: NAME system type (RFC 959 4.2.1).
<reply_215> ::= (
    <code_215> <sp> <reply_text> <crlf>
  | <code_215> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_215> <sp> <reply_text> <crlf>
)
# 220: Service ready for new user (RFC 959 4.2.1).
<reply_220> ::= (
    <code_220> <sp> <reply_text> <crlf>
  | <code_220> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_220> <sp> <reply_text> <crlf>
)
# 221: Service closing control connection (RFC 959 4.2.1).
<reply_221> ::= (
    <code_221> <sp> <reply_text> <crlf>
  | <code_221> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_221> <sp> <reply_text> <crlf>
)
# 225: Data connection open; no transfer in progress (RFC 959 4.2.1).
<reply_225> ::= (
    <code_225> <sp> <reply_text> <crlf>
  | <code_225> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_225> <sp> <reply_text> <crlf>
)
# 226: Closing data connection (RFC 959 4.2.1).
<reply_226> ::= (
    <code_226> <sp> <reply_text> <crlf>
  | <code_226> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_226> <sp> <reply_text> <crlf>
)
# 230: User logged in, proceed (RFC 959 4.2.1).
<reply_230> ::= (
    <code_230> <sp> <reply_text> <crlf>
  | <code_230> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_230> <sp> <reply_text> <crlf>
)
# 232: User logged in, authorized by security data exchange (RFC 2228 5.1).
<reply_232> ::= (
    <code_232> <sp> <reply_text> <crlf>
  | <code_232> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_232> <sp> <reply_text> <crlf>
)
# 234: Security data exchange complete (RFC 2228 5.1).
<reply_234> ::= (
    <code_234> <sp> <reply_text> <crlf>
  | <code_234> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_234> <sp> <reply_text> <crlf>
)
# 235: Security data exchange completed successfully (RFC 2228 5.1).
<reply_235> ::= (
    <code_235> <sp> <reply_text> <crlf>
  | <code_235> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_235> <sp> <reply_text> <crlf>
)
# 250: Requested file action okay, completed (RFC 959 4.2.1).
<reply_250> ::= (
    <code_250> <sp> <reply_text> <crlf>
  | <code_250> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_250> <sp> <reply_text> <crlf>
)
# 331: User name okay, need password (RFC 959 4.2.1).
<reply_331> ::= (
    <code_331> <sp> <reply_text> <crlf>
  | <code_331> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_331> <sp> <reply_text> <crlf>
)
# 332: Need account for login (RFC 959 4.2.1).
<reply_332> ::= (
    <code_332> <sp> <reply_text> <crlf>
  | <code_332> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_332> <sp> <reply_text> <crlf>
)
# 334: Requested security mechanism is ok (RFC 2228 5.1).
<reply_334> ::= (
    <code_334> <sp> <reply_text> <crlf>
  | <code_334> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_334> <sp> <reply_text> <crlf>
)
# 335: Security data is acceptable, more is required (RFC 2228 5.1).
<reply_335> ::= (
    <code_335> <sp> <reply_text> <crlf>
  | <code_335> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_335> <sp> <reply_text> <crlf>
)
# 336: Username okay, need password, challenge (RFC 2228 5.1).
<reply_336> ::= (
    <code_336> <sp> <reply_text> <crlf>
  | <code_336> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_336> <sp> <reply_text> <crlf>
)
# 350: Requested file action pending further information (RFC 959 4.2.1).
<reply_350> ::= (
    <code_350> <sp> <reply_text> <crlf>
  | <code_350> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_350> <sp> <reply_text> <crlf>
)
# 421: Service not available, closing control connection (RFC 959 4.2.1).
<reply_421> ::= (
    <code_421> <sp> <reply_text> <crlf>
  | <code_421> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_421> <sp> <reply_text> <crlf>
)
# 425: Can't open data connection (RFC 959 4.2.1).
<reply_425> ::= (
    <code_425> <sp> <reply_text> <crlf>
  | <code_425> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_425> <sp> <reply_text> <crlf>
)
# 426: Connection closed; transfer aborted (RFC 959 4.2.1).
<reply_426> ::= (
    <code_426> <sp> <reply_text> <crlf>
  | <code_426> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_426> <sp> <reply_text> <crlf>
)
# 431: Need some unavailable resource to process security (RFC 2228 5.1).
<reply_431> ::= (
    <code_431> <sp> <reply_text> <crlf>
  | <code_431> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_431> <sp> <reply_text> <crlf>
)
# 450: Requested file action not taken, file unavailable (RFC 959 4.2.1).
<reply_450> ::= (
    <code_450> <sp> <reply_text> <crlf>
  | <code_450> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_450> <sp> <reply_text> <crlf>
)
# 451: Requested action aborted: local error in processing (RFC 959 4.2.1).
<reply_451> ::= (
    <code_451> <sp> <reply_text> <crlf>
  | <code_451> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_451> <sp> <reply_text> <crlf>
)
# 452: Requested action not taken, insufficient storage (RFC 959 4.2.1).
<reply_452> ::= (
    <code_452> <sp> <reply_text> <crlf>
  | <code_452> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_452> <sp> <reply_text> <crlf>
)
# 500: Syntax error, command unrecognized (RFC 959 4.2.1).
<reply_500> ::= (
    <code_500> <sp> <reply_text> <crlf>
  | <code_500> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_500> <sp> <reply_text> <crlf>
)
# 501: Syntax error in parameters or arguments (RFC 959 4.2.1).
<reply_501> ::= (
    <code_501> <sp> <reply_text> <crlf>
  | <code_501> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_501> <sp> <reply_text> <crlf>
)
# 502: Command not implemented (RFC 959 4.2.1).
<reply_502> ::= (
    <code_502> <sp> <reply_text> <crlf>
  | <code_502> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_502> <sp> <reply_text> <crlf>
)
# 503: Bad sequence of commands (RFC 959 4.2.1).
<reply_503> ::= (
    <code_503> <sp> <reply_text> <crlf>
  | <code_503> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_503> <sp> <reply_text> <crlf>
)
# 504: Command not implemented for that parameter (RFC 959 4.2.1).
<reply_504> ::= (
    <code_504> <sp> <reply_text> <crlf>
  | <code_504> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_504> <sp> <reply_text> <crlf>
)
# 530: Not logged in (RFC 959 4.2.1).
<reply_530> ::= (
    <code_530> <sp> <reply_text> <crlf>
  | <code_530> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_530> <sp> <reply_text> <crlf>
)
# 532: Need account for storing files (RFC 959 4.2.1).
<reply_532> ::= (
    <code_532> <sp> <reply_text> <crlf>
  | <code_532> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_532> <sp> <reply_text> <crlf>
)
# 533: Command protection level denied for policy reasons (RFC 2228 5.1).
<reply_533> ::= (
    <code_533> <sp> <reply_text> <crlf>
  | <code_533> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_533> <sp> <reply_text> <crlf>
)
# 534: Request denied for policy reasons (RFC 2228 5.1).
<reply_534> ::= (
    <code_534> <sp> <reply_text> <crlf>
  | <code_534> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_534> <sp> <reply_text> <crlf>
)
# 535: Failed security check (RFC 2228 5.1).
<reply_535> ::= (
    <code_535> <sp> <reply_text> <crlf>
  | <code_535> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_535> <sp> <reply_text> <crlf>
)
# 536: Requested PROT level not supported by mechanism (RFC 2228 5.1).
<reply_536> ::= (
    <code_536> <sp> <reply_text> <crlf>
  | <code_536> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_536> <sp> <reply_text> <crlf>
)
# 550: Requested action not taken, file unavailable (RFC 959 4.2.1).
<reply_550> ::= (
    <code_550> <sp> <reply_text> <crlf>
  | <code_550> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_550> <sp> <reply_text> <crlf>
)
# 551: Requested action aborted: page type unknown (RFC 959 4.2.1).
<reply_551> ::= (
    <code_551> <sp> <reply_text> <crlf>
  | <code_551> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_551> <sp> <reply_text> <crlf>
)
# 552: Requested file action aborted, exceeded storage allocation (RFC 959 4.2.1).
<reply_552> ::= (
    <code_552> <sp> <reply_text> <crlf>
  | <code_552> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_552> <sp> <reply_text> <crlf>
)
# 553: Requested action not taken, file name not allowed (RFC 959 4.2.1).
<reply_553> ::= (
    <code_553> <sp> <reply_text> <crlf>
  | <code_553> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_553> <sp> <reply_text> <crlf>
)
# 554: Requested action not taken: invalid REST parameter (RFC 1123 4.1.3.4).
<reply_554> ::= (
    <code_554> <sp> <reply_text> <crlf>
  | <code_554> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_554> <sp> <reply_text> <crlf>
)
# 555: Requested action not taken: type or stru mismatch (RFC 1123 4.1.3.4).
<reply_555> ::= (
    <code_555> <sp> <reply_text> <crlf>
  | <code_555> <hyphen> <reply_text> <crlf> <reply_text_line>* <code_555> <sp> <reply_text> <crlf>
)

# Codes a command's table does not list: any code of the same first digit whose
# second digit has a defined function (RFC 959 4.2: x0z..x5z), "a server-FTP MAY
# use a different reply code when needed" (RFC 1123 4.1.2.11).  A multi-line reply
# ends with the code it started with (RFC 959 4.2).
<reply_1yz_other_110_125_150> ::= <reply_1yz_other_110_125_150_code> <sp> <reply_text> <crlf> | <reply_1yz_other_110_125_150_multiline>
<reply_1yz_other_110_125_150_multiline> ::= <reply_1yz_other_110_125_150_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_1yz_other_110_125_150_code_last> <sp> <reply_text> <crlf>
<reply_1yz_other_110_125_150_code> ::= '10' <digit> | '11' r'[123456789]' | '12' r'[012346789]' | '13' <digit> | '14' <digit> | '15' r'[123456789]'
<reply_1yz_other_110_125_150_code_last> ::= <reply_1yz_other_110_125_150_code>
where forall <r> in <reply_1yz_other_110_125_150_multiline>: str(<r>.<reply_1yz_other_110_125_150_code>) == str(<r>.<reply_1yz_other_110_125_150_code_last>)
<reply_2yz_other_200> ::= <reply_2yz_other_200_code> <sp> <reply_text> <crlf> | <reply_2yz_other_200_multiline>
<reply_2yz_other_200_multiline> ::= <reply_2yz_other_200_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_200_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_200_code> ::= '20' r'[123456789]' | '21' <digit> | '22' <digit> | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_200_code_last> ::= <reply_2yz_other_200_code>
where forall <r> in <reply_2yz_other_200_multiline>: str(<r>.<reply_2yz_other_200_code>) == str(<r>.<reply_2yz_other_200_code_last>)
<reply_2yz_other_200_202> ::= <reply_2yz_other_200_202_code> <sp> <reply_text> <crlf> | <reply_2yz_other_200_202_multiline>
<reply_2yz_other_200_202_multiline> ::= <reply_2yz_other_200_202_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_200_202_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_200_202_code> ::= '20' r'[13456789]' | '21' <digit> | '22' <digit> | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_200_202_code_last> ::= <reply_2yz_other_200_202_code>
where forall <r> in <reply_2yz_other_200_202_multiline>: str(<r>.<reply_2yz_other_200_202_code>) == str(<r>.<reply_2yz_other_200_202_code_last>)
<reply_2yz_other_200_229> ::= <reply_2yz_other_200_229_code> <sp> <reply_text> <crlf> | <reply_2yz_other_200_229_multiline>
<reply_2yz_other_200_229_multiline> ::= <reply_2yz_other_200_229_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_200_229_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_200_229_code> ::= '20' r'[123456789]' | '21' <digit> | '22' r'[012345678]' | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_200_229_code_last> ::= <reply_2yz_other_200_229_code>
where forall <r> in <reply_2yz_other_200_229_multiline>: str(<r>.<reply_2yz_other_200_229_code>) == str(<r>.<reply_2yz_other_200_229_code_last>)
<reply_2yz_other_202_230> ::= <reply_2yz_other_202_230_code> <sp> <reply_text> <crlf> | <reply_2yz_other_202_230_multiline>
<reply_2yz_other_202_230_multiline> ::= <reply_2yz_other_202_230_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_202_230_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_202_230_code> ::= '20' r'[013456789]' | '21' <digit> | '22' <digit> | '23' r'[123456789]' | '24' <digit> | '25' <digit>
<reply_2yz_other_202_230_code_last> ::= <reply_2yz_other_202_230_code>
where forall <r> in <reply_2yz_other_202_230_multiline>: str(<r>.<reply_2yz_other_202_230_code>) == str(<r>.<reply_2yz_other_202_230_code_last>)
<reply_2yz_other_202_250> ::= <reply_2yz_other_202_250_code> <sp> <reply_text> <crlf> | <reply_2yz_other_202_250_multiline>
<reply_2yz_other_202_250_multiline> ::= <reply_2yz_other_202_250_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_202_250_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_202_250_code> ::= '20' r'[013456789]' | '21' <digit> | '22' <digit> | '23' <digit> | '24' <digit> | '25' r'[123456789]'
<reply_2yz_other_202_250_code_last> ::= <reply_2yz_other_202_250_code>
where forall <r> in <reply_2yz_other_202_250_multiline>: str(<r>.<reply_2yz_other_202_250_code>) == str(<r>.<reply_2yz_other_202_250_code_last>)
<reply_2yz_other_211_212_213> ::= <reply_2yz_other_211_212_213_code> <sp> <reply_text> <crlf> | <reply_2yz_other_211_212_213_multiline>
<reply_2yz_other_211_212_213_multiline> ::= <reply_2yz_other_211_212_213_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_211_212_213_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_211_212_213_code> ::= '20' <digit> | '21' r'[0456789]' | '22' <digit> | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_211_212_213_code_last> ::= <reply_2yz_other_211_212_213_code>
where forall <r> in <reply_2yz_other_211_212_213_multiline>: str(<r>.<reply_2yz_other_211_212_213_code>) == str(<r>.<reply_2yz_other_211_212_213_code_last>)
<reply_2yz_other_211_214> ::= <reply_2yz_other_211_214_code> <sp> <reply_text> <crlf> | <reply_2yz_other_211_214_multiline>
<reply_2yz_other_211_214_multiline> ::= <reply_2yz_other_211_214_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_211_214_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_211_214_code> ::= '20' <digit> | '21' r'[02356789]' | '22' <digit> | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_211_214_code_last> ::= <reply_2yz_other_211_214_code>
where forall <r> in <reply_2yz_other_211_214_multiline>: str(<r>.<reply_2yz_other_211_214_code>) == str(<r>.<reply_2yz_other_211_214_code_last>)
<reply_2yz_other_215> ::= <reply_2yz_other_215_code> <sp> <reply_text> <crlf> | <reply_2yz_other_215_multiline>
<reply_2yz_other_215_multiline> ::= <reply_2yz_other_215_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_215_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_215_code> ::= '20' <digit> | '21' r'[012346789]' | '22' <digit> | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_215_code_last> ::= <reply_2yz_other_215_code>
where forall <r> in <reply_2yz_other_215_multiline>: str(<r>.<reply_2yz_other_215_code>) == str(<r>.<reply_2yz_other_215_code_last>)
<reply_2yz_other_220> ::= <reply_2yz_other_220_code> <sp> <reply_text> <crlf> | <reply_2yz_other_220_multiline>
<reply_2yz_other_220_multiline> ::= <reply_2yz_other_220_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_220_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_220_code> ::= '20' <digit> | '21' <digit> | '22' r'[123456789]' | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_220_code_last> ::= <reply_2yz_other_220_code>
where forall <r> in <reply_2yz_other_220_multiline>: str(<r>.<reply_2yz_other_220_code>) == str(<r>.<reply_2yz_other_220_code_last>)
<reply_2yz_other_221> ::= <reply_2yz_other_221_code> <sp> <reply_text> <crlf> | <reply_2yz_other_221_multiline>
<reply_2yz_other_221_multiline> ::= <reply_2yz_other_221_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_221_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_221_code> ::= '20' <digit> | '21' <digit> | '22' r'[023456789]' | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_221_code_last> ::= <reply_2yz_other_221_code>
where forall <r> in <reply_2yz_other_221_multiline>: str(<r>.<reply_2yz_other_221_code>) == str(<r>.<reply_2yz_other_221_code_last>)
<reply_2yz_other_225_226> ::= <reply_2yz_other_225_226_code> <sp> <reply_text> <crlf> | <reply_2yz_other_225_226_multiline>
<reply_2yz_other_225_226_multiline> ::= <reply_2yz_other_225_226_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_225_226_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_225_226_code> ::= '20' <digit> | '21' <digit> | '22' r'[01234789]' | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_225_226_code_last> ::= <reply_2yz_other_225_226_code>
where forall <r> in <reply_2yz_other_225_226_multiline>: str(<r>.<reply_2yz_other_225_226_code>) == str(<r>.<reply_2yz_other_225_226_code_last>)
<reply_2yz_other_226_250> ::= <reply_2yz_other_226_250_code> <sp> <reply_text> <crlf> | <reply_2yz_other_226_250_multiline>
<reply_2yz_other_226_250_multiline> ::= <reply_2yz_other_226_250_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_226_250_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_226_250_code> ::= '20' <digit> | '21' <digit> | '22' r'[012345789]' | '23' <digit> | '24' <digit> | '25' r'[123456789]'
<reply_2yz_other_226_250_code_last> ::= <reply_2yz_other_226_250_code>
where forall <r> in <reply_2yz_other_226_250_multiline>: str(<r>.<reply_2yz_other_226_250_code>) == str(<r>.<reply_2yz_other_226_250_code_last>)
<reply_2yz_other_227> ::= <reply_2yz_other_227_code> <sp> <reply_text> <crlf> | <reply_2yz_other_227_multiline>
<reply_2yz_other_227_multiline> ::= <reply_2yz_other_227_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_227_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_227_code> ::= '20' <digit> | '21' <digit> | '22' r'[012345689]' | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_227_code_last> ::= <reply_2yz_other_227_code>
where forall <r> in <reply_2yz_other_227_multiline>: str(<r>.<reply_2yz_other_227_code>) == str(<r>.<reply_2yz_other_227_code_last>)
<reply_2yz_other_229> ::= <reply_2yz_other_229_code> <sp> <reply_text> <crlf> | <reply_2yz_other_229_multiline>
<reply_2yz_other_229_multiline> ::= <reply_2yz_other_229_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_229_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_229_code> ::= '20' <digit> | '21' <digit> | '22' r'[012345678]' | '23' <digit> | '24' <digit> | '25' <digit>
<reply_2yz_other_229_code_last> ::= <reply_2yz_other_229_code>
where forall <r> in <reply_2yz_other_229_multiline>: str(<r>.<reply_2yz_other_229_code>) == str(<r>.<reply_2yz_other_229_code_last>)
<reply_2yz_other_230_232> ::= <reply_2yz_other_230_232_code> <sp> <reply_text> <crlf> | <reply_2yz_other_230_232_multiline>
<reply_2yz_other_230_232_multiline> ::= <reply_2yz_other_230_232_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_230_232_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_230_232_code> ::= '20' <digit> | '21' <digit> | '22' <digit> | '23' r'[13456789]' | '24' <digit> | '25' <digit>
<reply_2yz_other_230_232_code_last> ::= <reply_2yz_other_230_232_code>
where forall <r> in <reply_2yz_other_230_232_multiline>: str(<r>.<reply_2yz_other_230_232_code>) == str(<r>.<reply_2yz_other_230_232_code_last>)
<reply_2yz_other_250> ::= <reply_2yz_other_250_code> <sp> <reply_text> <crlf> | <reply_2yz_other_250_multiline>
<reply_2yz_other_250_multiline> ::= <reply_2yz_other_250_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_250_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_250_code> ::= '20' <digit> | '21' <digit> | '22' <digit> | '23' <digit> | '24' <digit> | '25' r'[123456789]'
<reply_2yz_other_250_code_last> ::= <reply_2yz_other_250_code>
where forall <r> in <reply_2yz_other_250_multiline>: str(<r>.<reply_2yz_other_250_code>) == str(<r>.<reply_2yz_other_250_code_last>)
<reply_2yz_other_257> ::= <reply_2yz_other_257_code> <sp> <reply_text> <crlf> | <reply_2yz_other_257_multiline>
<reply_2yz_other_257_multiline> ::= <reply_2yz_other_257_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_2yz_other_257_code_last> <sp> <reply_text> <crlf>
<reply_2yz_other_257_code> ::= '20' <digit> | '21' <digit> | '22' <digit> | '23' <digit> | '24' <digit> | '25' r'[012345689]'
<reply_2yz_other_257_code_last> ::= <reply_2yz_other_257_code>
where forall <r> in <reply_2yz_other_257_multiline>: str(<r>.<reply_2yz_other_257_code>) == str(<r>.<reply_2yz_other_257_code_last>)
<reply_3yz_other_331_332_336> ::= <reply_3yz_other_331_332_336_code> <sp> <reply_text> <crlf> | <reply_3yz_other_331_332_336_multiline>
<reply_3yz_other_331_332_336_multiline> ::= <reply_3yz_other_331_332_336_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_3yz_other_331_332_336_code_last> <sp> <reply_text> <crlf>
<reply_3yz_other_331_332_336_code> ::= '30' <digit> | '31' <digit> | '32' <digit> | '33' r'[0345789]' | '34' <digit> | '35' <digit>
<reply_3yz_other_331_332_336_code_last> ::= <reply_3yz_other_331_332_336_code>
where forall <r> in <reply_3yz_other_331_332_336_multiline>: str(<r>.<reply_3yz_other_331_332_336_code>) == str(<r>.<reply_3yz_other_331_332_336_code_last>)
<reply_3yz_other_332> ::= <reply_3yz_other_332_code> <sp> <reply_text> <crlf> | <reply_3yz_other_332_multiline>
<reply_3yz_other_332_multiline> ::= <reply_3yz_other_332_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_3yz_other_332_code_last> <sp> <reply_text> <crlf>
<reply_3yz_other_332_code> ::= '30' <digit> | '31' <digit> | '32' <digit> | '33' r'[013456789]' | '34' <digit> | '35' <digit>
<reply_3yz_other_332_code_last> ::= <reply_3yz_other_332_code>
where forall <r> in <reply_3yz_other_332_multiline>: str(<r>.<reply_3yz_other_332_code>) == str(<r>.<reply_3yz_other_332_code_last>)
<reply_3yz_other_350> ::= <reply_3yz_other_350_code> <sp> <reply_text> <crlf> | <reply_3yz_other_350_multiline>
<reply_3yz_other_350_multiline> ::= <reply_3yz_other_350_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_3yz_other_350_code_last> <sp> <reply_text> <crlf>
<reply_3yz_other_350_code> ::= '30' <digit> | '31' <digit> | '32' <digit> | '33' <digit> | '34' <digit> | '35' r'[123456789]'
<reply_3yz_other_350_code_last> ::= <reply_3yz_other_350_code>
where forall <r> in <reply_3yz_other_350_multiline>: str(<r>.<reply_3yz_other_350_code>) == str(<r>.<reply_3yz_other_350_code_last>)
<reply_4yz_other_421> ::= <reply_4yz_other_421_code> <sp> <reply_text> <crlf> | <reply_4yz_other_421_multiline>
<reply_4yz_other_421_multiline> ::= <reply_4yz_other_421_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_4yz_other_421_code_last> <sp> <reply_text> <crlf>
<reply_4yz_other_421_code> ::= '40' <digit> | '41' <digit> | '42' r'[023456789]' | '43' <digit> | '44' <digit> | '45' <digit>
<reply_4yz_other_421_code_last> ::= <reply_4yz_other_421_code>
where forall <r> in <reply_4yz_other_421_multiline>: str(<r>.<reply_4yz_other_421_code>) == str(<r>.<reply_4yz_other_421_code_last>)
<reply_4yz_other_421_425_426_451> ::= <reply_4yz_other_421_425_426_451_code> <sp> <reply_text> <crlf> | <reply_4yz_other_421_425_426_451_multiline>
<reply_4yz_other_421_425_426_451_multiline> ::= <reply_4yz_other_421_425_426_451_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_4yz_other_421_425_426_451_code_last> <sp> <reply_text> <crlf>
<reply_4yz_other_421_425_426_451_code> ::= '40' <digit> | '41' <digit> | '42' r'[0234789]' | '43' <digit> | '44' <digit> | '45' r'[023456789]'
<reply_4yz_other_421_425_426_451_code_last> ::= <reply_4yz_other_421_425_426_451_code>
where forall <r> in <reply_4yz_other_421_425_426_451_multiline>: str(<r>.<reply_4yz_other_421_425_426_451_code>) == str(<r>.<reply_4yz_other_421_425_426_451_code_last>)
<reply_4yz_other_421_431> ::= <reply_4yz_other_421_431_code> <sp> <reply_text> <crlf> | <reply_4yz_other_421_431_multiline>
<reply_4yz_other_421_431_multiline> ::= <reply_4yz_other_421_431_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_4yz_other_421_431_code_last> <sp> <reply_text> <crlf>
<reply_4yz_other_421_431_code> ::= '40' <digit> | '41' <digit> | '42' r'[023456789]' | '43' r'[023456789]' | '44' <digit> | '45' <digit>
<reply_4yz_other_421_431_code_last> ::= <reply_4yz_other_421_431_code>
where forall <r> in <reply_4yz_other_421_431_multiline>: str(<r>.<reply_4yz_other_421_431_code>) == str(<r>.<reply_4yz_other_421_431_code_last>)
<reply_4yz_other_421_450> ::= <reply_4yz_other_421_450_code> <sp> <reply_text> <crlf> | <reply_4yz_other_421_450_multiline>
<reply_4yz_other_421_450_multiline> ::= <reply_4yz_other_421_450_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_4yz_other_421_450_code_last> <sp> <reply_text> <crlf>
<reply_4yz_other_421_450_code> ::= '40' <digit> | '41' <digit> | '42' r'[023456789]' | '43' <digit> | '44' <digit> | '45' r'[123456789]'
<reply_4yz_other_421_450_code_last> ::= <reply_4yz_other_421_450_code>
where forall <r> in <reply_4yz_other_421_450_multiline>: str(<r>.<reply_4yz_other_421_450_code>) == str(<r>.<reply_4yz_other_421_450_code_last>)
<reply_4yz_other_421_450_452> ::= <reply_4yz_other_421_450_452_code> <sp> <reply_text> <crlf> | <reply_4yz_other_421_450_452_multiline>
<reply_4yz_other_421_450_452_multiline> ::= <reply_4yz_other_421_450_452_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_4yz_other_421_450_452_code_last> <sp> <reply_text> <crlf>
<reply_4yz_other_421_450_452_code> ::= '40' <digit> | '41' <digit> | '42' r'[023456789]' | '43' <digit> | '44' <digit> | '45' r'[13456789]'
<reply_4yz_other_421_450_452_code_last> ::= <reply_4yz_other_421_450_452_code>
where forall <r> in <reply_4yz_other_421_450_452_multiline>: str(<r>.<reply_4yz_other_421_450_452_code>) == str(<r>.<reply_4yz_other_421_450_452_code_last>)
<reply_4yz_other_421_451> ::= <reply_4yz_other_421_451_code> <sp> <reply_text> <crlf> | <reply_4yz_other_421_451_multiline>
<reply_4yz_other_421_451_multiline> ::= <reply_4yz_other_421_451_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_4yz_other_421_451_code_last> <sp> <reply_text> <crlf>
<reply_4yz_other_421_451_code> ::= '40' <digit> | '41' <digit> | '42' r'[023456789]' | '43' <digit> | '44' <digit> | '45' r'[023456789]'
<reply_4yz_other_421_451_code_last> ::= <reply_4yz_other_421_451_code>
where forall <r> in <reply_4yz_other_421_451_multiline>: str(<r>.<reply_4yz_other_421_451_code>) == str(<r>.<reply_4yz_other_421_451_code_last>)
<reply_5yz_other> ::= <reply_5yz_other_code> <sp> <reply_text> <crlf> | <reply_5yz_other_multiline>
<reply_5yz_other_multiline> ::= <reply_5yz_other_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_code> ::= '50' <digit> | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_code_last> ::= <reply_5yz_other_code>
where forall <r> in <reply_5yz_other_multiline>: str(<r>.<reply_5yz_other_code>) == str(<r>.<reply_5yz_other_code_last>)
<reply_5yz_other_500> ::= <reply_5yz_other_500_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_multiline>
<reply_5yz_other_500_multiline> ::= <reply_5yz_other_500_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_code> ::= '50' r'[123456789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_500_code_last> ::= <reply_5yz_other_500_code>
where forall <r> in <reply_5yz_other_500_multiline>: str(<r>.<reply_5yz_other_500_code>) == str(<r>.<reply_5yz_other_500_code_last>)
<reply_5yz_other_500_501> ::= <reply_5yz_other_500_501_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_multiline>
<reply_5yz_other_500_501_multiline> ::= <reply_5yz_other_500_501_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_code> ::= '50' r'[23456789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_code_last> ::= <reply_5yz_other_500_501_code>
where forall <r> in <reply_5yz_other_500_501_multiline>: str(<r>.<reply_5yz_other_500_501_code>) == str(<r>.<reply_5yz_other_500_501_code_last>)
<reply_5yz_other_500_501_502> ::= <reply_5yz_other_500_501_502_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_multiline>
<reply_5yz_other_500_501_502_multiline> ::= <reply_5yz_other_500_501_502_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_code_last> ::= <reply_5yz_other_500_501_502_code>
where forall <r> in <reply_5yz_other_500_501_502_multiline>: str(<r>.<reply_5yz_other_500_501_502_code>) == str(<r>.<reply_5yz_other_500_501_502_code_last>)
<reply_5yz_other_500_501_502_503_504_530> ::= <reply_5yz_other_500_501_502_503_504_530_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_503_504_530_multiline>
<reply_5yz_other_500_501_502_503_504_530_multiline> ::= <reply_5yz_other_500_501_502_503_504_530_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_503_504_530_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_503_504_530_code> ::= '50' r'[56789]' | '51' <digit> | '52' <digit> | '53' r'[123456789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_503_504_530_code_last> ::= <reply_5yz_other_500_501_502_503_504_530_code>
where forall <r> in <reply_5yz_other_500_501_502_503_504_530_multiline>: str(<r>.<reply_5yz_other_500_501_502_503_504_530_code>) == str(<r>.<reply_5yz_other_500_501_502_503_504_530_code_last>)
<reply_5yz_other_500_501_502_503_504_530_533_534_536> ::= <reply_5yz_other_500_501_502_503_504_530_533_534_536_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_503_504_530_533_534_536_multiline>
<reply_5yz_other_500_501_502_503_504_530_533_534_536_multiline> ::= <reply_5yz_other_500_501_502_503_504_530_533_534_536_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_503_504_530_533_534_536_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_503_504_530_533_534_536_code> ::= '50' r'[56789]' | '51' <digit> | '52' <digit> | '53' r'[125789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_503_504_530_533_534_536_code_last> ::= <reply_5yz_other_500_501_502_503_504_530_533_534_536_code>
where forall <r> in <reply_5yz_other_500_501_502_503_504_530_533_534_536_multiline>: str(<r>.<reply_5yz_other_500_501_502_503_504_530_533_534_536_code>) == str(<r>.<reply_5yz_other_500_501_502_503_504_530_533_534_536_code_last>)
<reply_5yz_other_500_501_502_503_530_532_553> ::= <reply_5yz_other_500_501_502_503_530_532_553_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_503_530_532_553_multiline>
<reply_5yz_other_500_501_502_503_530_532_553_multiline> ::= <reply_5yz_other_500_501_502_503_530_532_553_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_503_530_532_553_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_503_530_532_553_code> ::= '50' r'[456789]' | '51' <digit> | '52' <digit> | '53' r'[13456789]' | '54' <digit> | '55' r'[012456789]'
<reply_5yz_other_500_501_502_503_530_532_553_code_last> ::= <reply_5yz_other_500_501_502_503_530_532_553_code>
where forall <r> in <reply_5yz_other_500_501_502_503_530_532_553_multiline>: str(<r>.<reply_5yz_other_500_501_502_503_530_532_553_code>) == str(<r>.<reply_5yz_other_500_501_502_503_530_532_553_code_last>)
<reply_5yz_other_500_501_502_503_530_533> ::= <reply_5yz_other_500_501_502_503_530_533_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_503_530_533_multiline>
<reply_5yz_other_500_501_502_503_530_533_multiline> ::= <reply_5yz_other_500_501_502_503_530_533_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_503_530_533_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_503_530_533_code> ::= '50' r'[456789]' | '51' <digit> | '52' <digit> | '53' r'[12456789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_503_530_533_code_last> ::= <reply_5yz_other_500_501_502_503_530_533_code>
where forall <r> in <reply_5yz_other_500_501_502_503_530_533_multiline>: str(<r>.<reply_5yz_other_500_501_502_503_530_533_code>) == str(<r>.<reply_5yz_other_500_501_502_503_530_533_code_last>)
<reply_5yz_other_500_501_502_503_533_535> ::= <reply_5yz_other_500_501_502_503_533_535_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_503_533_535_multiline>
<reply_5yz_other_500_501_502_503_533_535_multiline> ::= <reply_5yz_other_500_501_502_503_533_535_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_503_533_535_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_503_533_535_code> ::= '50' r'[456789]' | '51' <digit> | '52' <digit> | '53' r'[01246789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_503_533_535_code_last> ::= <reply_5yz_other_500_501_502_503_533_535_code>
where forall <r> in <reply_5yz_other_500_501_502_503_533_535_multiline>: str(<r>.<reply_5yz_other_500_501_502_503_533_535_code>) == str(<r>.<reply_5yz_other_500_501_502_503_533_535_code_last>)
<reply_5yz_other_500_501_502_504> ::= <reply_5yz_other_500_501_502_504_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_504_multiline>
<reply_5yz_other_500_501_502_504_multiline> ::= <reply_5yz_other_500_501_502_504_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_504_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_504_code> ::= '50' r'[356789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_504_code_last> ::= <reply_5yz_other_500_501_502_504_code>
where forall <r> in <reply_5yz_other_500_501_502_504_multiline>: str(<r>.<reply_5yz_other_500_501_502_504_code>) == str(<r>.<reply_5yz_other_500_501_502_504_code_last>)
<reply_5yz_other_500_501_502_504_533_534> ::= <reply_5yz_other_500_501_502_504_533_534_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_504_533_534_multiline>
<reply_5yz_other_500_501_502_504_533_534_multiline> ::= <reply_5yz_other_500_501_502_504_533_534_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_504_533_534_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_504_533_534_code> ::= '50' r'[356789]' | '51' <digit> | '52' <digit> | '53' r'[01256789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_504_533_534_code_last> ::= <reply_5yz_other_500_501_502_504_533_534_code>
where forall <r> in <reply_5yz_other_500_501_502_504_533_534_multiline>: str(<r>.<reply_5yz_other_500_501_502_504_533_534_code>) == str(<r>.<reply_5yz_other_500_501_502_504_533_534_code_last>)
<reply_5yz_other_500_501_502_530> ::= <reply_5yz_other_500_501_502_530_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_530_multiline>
<reply_5yz_other_500_501_502_530_multiline> ::= <reply_5yz_other_500_501_502_530_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_530_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_530_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' r'[123456789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_530_code_last> ::= <reply_5yz_other_500_501_502_530_code>
where forall <r> in <reply_5yz_other_500_501_502_530_multiline>: str(<r>.<reply_5yz_other_500_501_502_530_code>) == str(<r>.<reply_5yz_other_500_501_502_530_code_last>)
<reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555> ::= <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_multiline>
<reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_multiline> ::= <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' r'[136789]' | '54' <digit> | '55' r'[126789]'
<reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code_last> ::= <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code>
where forall <r> in <reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_multiline>: str(<r>.<reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code>) == str(<r>.<reply_5yz_other_500_501_502_530_532_534_535_550_553_554_555_code_last>)
<reply_5yz_other_500_501_502_530_534_535> ::= <reply_5yz_other_500_501_502_530_534_535_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_530_534_535_multiline>
<reply_5yz_other_500_501_502_530_534_535_multiline> ::= <reply_5yz_other_500_501_502_530_534_535_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_530_534_535_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_530_534_535_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' r'[1236789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_530_534_535_code_last> ::= <reply_5yz_other_500_501_502_530_534_535_code>
where forall <r> in <reply_5yz_other_500_501_502_530_534_535_multiline>: str(<r>.<reply_5yz_other_500_501_502_530_534_535_code>) == str(<r>.<reply_5yz_other_500_501_502_530_534_535_code_last>)
<reply_5yz_other_500_501_502_530_550> ::= <reply_5yz_other_500_501_502_530_550_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_530_550_multiline>
<reply_5yz_other_500_501_502_530_550_multiline> ::= <reply_5yz_other_500_501_502_530_550_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_530_550_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_530_550_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' r'[123456789]' | '54' <digit> | '55' r'[123456789]'
<reply_5yz_other_500_501_502_530_550_code_last> ::= <reply_5yz_other_500_501_502_530_550_code>
where forall <r> in <reply_5yz_other_500_501_502_530_550_multiline>: str(<r>.<reply_5yz_other_500_501_502_530_550_code>) == str(<r>.<reply_5yz_other_500_501_502_530_550_code_last>)
<reply_5yz_other_500_501_502_533_534> ::= <reply_5yz_other_500_501_502_533_534_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_533_534_multiline>
<reply_5yz_other_500_501_502_533_534_multiline> ::= <reply_5yz_other_500_501_502_533_534_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_533_534_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_533_534_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' r'[01256789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_533_534_code_last> ::= <reply_5yz_other_500_501_502_533_534_code>
where forall <r> in <reply_5yz_other_500_501_502_533_534_multiline>: str(<r>.<reply_5yz_other_500_501_502_533_534_code>) == str(<r>.<reply_5yz_other_500_501_502_533_534_code_last>)
<reply_5yz_other_500_501_502_533_535> ::= <reply_5yz_other_500_501_502_533_535_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_533_535_multiline>
<reply_5yz_other_500_501_502_533_535_multiline> ::= <reply_5yz_other_500_501_502_533_535_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_533_535_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_533_535_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' r'[01246789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_502_533_535_code_last> ::= <reply_5yz_other_500_501_502_533_535_code>
where forall <r> in <reply_5yz_other_500_501_502_533_535_multiline>: str(<r>.<reply_5yz_other_500_501_502_533_535_code>) == str(<r>.<reply_5yz_other_500_501_502_533_535_code_last>)
<reply_5yz_other_500_501_502_550> ::= <reply_5yz_other_500_501_502_550_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_502_550_multiline>
<reply_5yz_other_500_501_502_550_multiline> ::= <reply_5yz_other_500_501_502_550_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_502_550_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_502_550_code> ::= '50' r'[3456789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' r'[123456789]'
<reply_5yz_other_500_501_502_550_code_last> ::= <reply_5yz_other_500_501_502_550_code>
where forall <r> in <reply_5yz_other_500_501_502_550_multiline>: str(<r>.<reply_5yz_other_500_501_502_550_code>) == str(<r>.<reply_5yz_other_500_501_502_550_code_last>)
<reply_5yz_other_500_501_503_530> ::= <reply_5yz_other_500_501_503_530_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_503_530_multiline>
<reply_5yz_other_500_501_503_530_multiline> ::= <reply_5yz_other_500_501_503_530_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_503_530_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_503_530_code> ::= '50' r'[2456789]' | '51' <digit> | '52' <digit> | '53' r'[123456789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_503_530_code_last> ::= <reply_5yz_other_500_501_503_530_code>
where forall <r> in <reply_5yz_other_500_501_503_530_multiline>: str(<r>.<reply_5yz_other_500_501_503_530_code>) == str(<r>.<reply_5yz_other_500_501_503_530_code_last>)
<reply_5yz_other_500_501_504_530> ::= <reply_5yz_other_500_501_504_530_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_504_530_multiline>
<reply_5yz_other_500_501_504_530_multiline> ::= <reply_5yz_other_500_501_504_530_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_504_530_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_504_530_code> ::= '50' r'[2356789]' | '51' <digit> | '52' <digit> | '53' r'[123456789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_504_530_code_last> ::= <reply_5yz_other_500_501_504_530_code>
where forall <r> in <reply_5yz_other_500_501_504_530_multiline>: str(<r>.<reply_5yz_other_500_501_504_530_code>) == str(<r>.<reply_5yz_other_500_501_504_530_code_last>)
<reply_5yz_other_500_501_522> ::= <reply_5yz_other_500_501_522_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_522_multiline>
<reply_5yz_other_500_501_522_multiline> ::= <reply_5yz_other_500_501_522_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_522_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_522_code> ::= '50' r'[23456789]' | '51' <digit> | '52' r'[013456789]' | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_522_code_last> ::= <reply_5yz_other_500_501_522_code>
where forall <r> in <reply_5yz_other_500_501_522_multiline>: str(<r>.<reply_5yz_other_500_501_522_code>) == str(<r>.<reply_5yz_other_500_501_522_code_last>)
<reply_5yz_other_500_501_530> ::= <reply_5yz_other_500_501_530_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_530_multiline>
<reply_5yz_other_500_501_530_multiline> ::= <reply_5yz_other_500_501_530_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_530_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_530_code> ::= '50' r'[23456789]' | '51' <digit> | '52' <digit> | '53' r'[123456789]' | '54' <digit> | '55' <digit>
<reply_5yz_other_500_501_530_code_last> ::= <reply_5yz_other_500_501_530_code>
where forall <r> in <reply_5yz_other_500_501_530_multiline>: str(<r>.<reply_5yz_other_500_501_530_code>) == str(<r>.<reply_5yz_other_500_501_530_code_last>)
<reply_5yz_other_500_501_530_532_534_535_553> ::= <reply_5yz_other_500_501_530_532_534_535_553_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_530_532_534_535_553_multiline>
<reply_5yz_other_500_501_530_532_534_535_553_multiline> ::= <reply_5yz_other_500_501_530_532_534_535_553_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_530_532_534_535_553_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_530_532_534_535_553_code> ::= '50' r'[23456789]' | '51' <digit> | '52' <digit> | '53' r'[136789]' | '54' <digit> | '55' r'[012456789]'
<reply_5yz_other_500_501_530_532_534_535_553_code_last> ::= <reply_5yz_other_500_501_530_532_534_535_553_code>
where forall <r> in <reply_5yz_other_500_501_530_532_534_535_553_multiline>: str(<r>.<reply_5yz_other_500_501_530_532_534_535_553_code>) == str(<r>.<reply_5yz_other_500_501_530_532_534_535_553_code_last>)
<reply_5yz_other_500_501_530_532_534_535_553_554_555> ::= <reply_5yz_other_500_501_530_532_534_535_553_554_555_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_530_532_534_535_553_554_555_multiline>
<reply_5yz_other_500_501_530_532_534_535_553_554_555_multiline> ::= <reply_5yz_other_500_501_530_532_534_535_553_554_555_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_530_532_534_535_553_554_555_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_530_532_534_535_553_554_555_code> ::= '50' r'[23456789]' | '51' <digit> | '52' <digit> | '53' r'[136789]' | '54' <digit> | '55' r'[0126789]'
<reply_5yz_other_500_501_530_532_534_535_553_554_555_code_last> ::= <reply_5yz_other_500_501_530_532_534_535_553_554_555_code>
where forall <r> in <reply_5yz_other_500_501_530_532_534_535_553_554_555_multiline>: str(<r>.<reply_5yz_other_500_501_530_532_534_535_553_554_555_code>) == str(<r>.<reply_5yz_other_500_501_530_532_534_535_553_554_555_code_last>)
<reply_5yz_other_500_501_530_534_535_550_554_555> ::= <reply_5yz_other_500_501_530_534_535_550_554_555_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_530_534_535_550_554_555_multiline>
<reply_5yz_other_500_501_530_534_535_550_554_555_multiline> ::= <reply_5yz_other_500_501_530_534_535_550_554_555_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_530_534_535_550_554_555_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_530_534_535_550_554_555_code> ::= '50' r'[23456789]' | '51' <digit> | '52' <digit> | '53' r'[1236789]' | '54' <digit> | '55' r'[1236789]'
<reply_5yz_other_500_501_530_534_535_550_554_555_code_last> ::= <reply_5yz_other_500_501_530_534_535_550_554_555_code>
where forall <r> in <reply_5yz_other_500_501_530_534_535_550_554_555_multiline>: str(<r>.<reply_5yz_other_500_501_530_534_535_550_554_555_code>) == str(<r>.<reply_5yz_other_500_501_530_534_535_550_554_555_code_last>)
<reply_5yz_other_500_501_550> ::= <reply_5yz_other_500_501_550_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_501_550_multiline>
<reply_5yz_other_500_501_550_multiline> ::= <reply_5yz_other_500_501_550_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_501_550_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_501_550_code> ::= '50' r'[23456789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' r'[123456789]'
<reply_5yz_other_500_501_550_code_last> ::= <reply_5yz_other_500_501_550_code>
where forall <r> in <reply_5yz_other_500_501_550_multiline>: str(<r>.<reply_5yz_other_500_501_550_code>) == str(<r>.<reply_5yz_other_500_501_550_code_last>)
<reply_5yz_other_500_502> ::= <reply_5yz_other_500_502_code> <sp> <reply_text> <crlf> | <reply_5yz_other_500_502_multiline>
<reply_5yz_other_500_502_multiline> ::= <reply_5yz_other_500_502_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_500_502_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_500_502_code> ::= '50' r'[13456789]' | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' <digit>
<reply_5yz_other_500_502_code_last> ::= <reply_5yz_other_500_502_code>
where forall <r> in <reply_5yz_other_500_502_multiline>: str(<r>.<reply_5yz_other_500_502_code>) == str(<r>.<reply_5yz_other_500_502_code_last>)
<reply_5yz_other_551_552> ::= <reply_5yz_other_551_552_code> <sp> <reply_text> <crlf> | <reply_5yz_other_551_552_multiline>
<reply_5yz_other_551_552_multiline> ::= <reply_5yz_other_551_552_code> <hyphen> <reply_text> <crlf> <reply_text_line>* <reply_5yz_other_551_552_code_last> <sp> <reply_text> <crlf>
<reply_5yz_other_551_552_code> ::= '50' <digit> | '51' <digit> | '52' <digit> | '53' <digit> | '54' <digit> | '55' r'[03456789]'
<reply_5yz_other_551_552_code_last> ::= <reply_5yz_other_551_552_code>
where forall <r> in <reply_5yz_other_551_552_multiline>: str(<r>.<reply_5yz_other_551_552_code>) == str(<r>.<reply_5yz_other_551_552_code_last>)

# ==============================================================================
# Lexical elements (RFC 959 5.3.1; RFC 5234 core rules as used by RFC 2389, 3659)
# ==============================================================================
# Telnet end-of-line (RFC 959 5.3.1, 4.2).
<crlf> ::= '\r\n'
<sp> ::= ' '
<digit> ::= r'[0-9]'
<alpha> ::= r'[A-Za-z]'
# VCHAR = %x21-7E; TCHAR = VCHAR / SP / HTAB (RFC 2389 2.1).
<vchar> ::= r'[!-~]'
<tchar> ::= r'[\t -~]'
# RCHAR: ALPHA / DIGIT / , . : ! @ # $ % ^ & ( ) - _ + ? / \ ' DQUOTE; SCHAR = RCHAR / "=" (RFC 3659 2.1).
<rchar> ::= r'[A-Za-z0-9,.:!@#$%^&()\-_+?/\\\'"]'
<schar> ::= <rchar> | '='
# Case-insensitive letters of command codes and keywords (RFC 959 5.3.1).
<letter_a> ::= 'A' | 'a'
<letter_b> ::= 'B' | 'b'
<letter_c> ::= 'C' | 'c'
<letter_d> ::= 'D' | 'd'
<letter_e> ::= 'E' | 'e'
<letter_f> ::= 'F' | 'f'
<letter_g> ::= 'G' | 'g'
<letter_h> ::= 'H' | 'h'
<letter_i> ::= 'I' | 'i'
<letter_k> ::= 'K' | 'k'
<letter_l> ::= 'L' | 'l'
<letter_m> ::= 'M' | 'm'
<letter_n> ::= 'N' | 'n'
<letter_o> ::= 'O' | 'o'
<letter_p> ::= 'P' | 'p'
<letter_q> ::= 'Q' | 'q'
<letter_r> ::= 'R' | 'r'
<letter_s> ::= 'S' | 's'
<letter_t> ::= 'T' | 't'
<letter_u> ::= 'U' | 'u'
<letter_v> ::= 'V' | 'v'
<letter_w> ::= 'W' | 'w'
<letter_x> ::= 'X' | 'x'
<letter_y> ::= 'Y' | 'y'
<letter_z> ::= 'Z' | 'z'
